//! Private-swap relayer (#238): withdraw to a fresh address, swap on a public
//! DEX, re-deposit into the user's shielded balance.
//!
//! # The flow
//!
//! A user holds a shielded note of `asset_in`. They want to end up holding a
//! shielded note of `asset_out` without the public trade pointing back at the
//! wallet that funded the original deposit. The relayer composes four steps:
//!
//! 1. **Withdraw to a fresh address.** Spend the note (its nullifier is burned
//!    on-chain) and withdraw the value to a brand-new ephemeral [`Keypair`]
//!    generated per swap. The withdrawal nullifier severs the link between the
//!    user's deposit and this fresh address — nothing on-chain ties the two.
//!    For an SPL `asset_in` this is the `withdraw_spl` path to an ephemeral
//!    token account; for native SOL it is the existing `withdraw`.
//! 2. **Swap.** Trade `asset_in -> asset_out` on public liquidity from the
//!    fresh address. The routing lives behind the [`SwapProvider`] trait; this
//!    module ships only a [`MockSwapProvider`]. The real Jupiter v6 router is
//!    issue #239 and is out of scope here.
//! 3. **Fee.** Apply `fee_bps` to the swap output; the relayer keeps that cut
//!    and the user receives the remainder. The exact fee *mechanism* (Jupiter's
//!    `platformFeeBps` taken inside the route vs. a separate transfer of the
//!    relayer's cut) is decided in #239. Here `fee_bps` is an abstract
//!    parameter applied to the gross output.
//! 4. **Re-deposit.** Deposit the net output back into the shielded pool to the
//!    user's chosen re-shield recipient, producing a fresh note of `asset_out`.
//!    The on-chain deposit shows the ephemeral fresh address as the depositor,
//!    not the user.
//!
//! # Honest privacy limits
//!
//! This orchestration does NOT claim full trade privacy. Two limits are
//! load-bearing and must not be overstated:
//!
//! * **The DEX amount stays public.** The swap executes on a public AMM/route,
//!   so the traded amount (and therefore the approximate note value) is visible
//!   on-chain. Hiding the amount — e.g. splitting into uniform denominations or
//!   batching across users — is later work.
//! * **A single relayer sees both legs.** One relayer observes the withdraw
//!   leg and the re-deposit leg, so it can link them internally even though the
//!   chain cannot. Splitting the two legs across non-colluding parties (MPC /
//!   2-party relaying) is a follow-up; do not treat the single-relayer version
//!   as unlinkable against the relayer itself.

use crate::privacy::types::{AssetId, Note, Nullifier, ShieldedAddress, NATIVE_SOL_ASSET};
use solana_sdk::signature::{Keypair, Signer};
use thiserror::Error;

/// Errors raised while orchestrating a private swap.
#[derive(Error, Debug)]
pub enum RelayerError {
    /// The note carried a zero or otherwise unusable amount.
    #[error("invalid input amount: {0}")]
    InvalidAmount(u64),

    /// `fee_bps` exceeded 10_000 (100%), which would consume the whole output.
    #[error("fee_bps {0} exceeds 10000 (100%)")]
    FeeTooHigh(u16),

    /// The configured swap provider failed to route or quote the trade.
    #[error("swap provider failed: {0}")]
    SwapFailed(String),

    /// The aggregator returned no route for the requested pair/amount. Distinct
    /// from a transport error: the request succeeded but there is no liquidity
    /// path (the common case on devnet — see [`crate::relayer::jupiter`]).
    #[error("no swap route for the requested pair/amount: {0}")]
    NoRoute(String),

    /// An HTTP/transport error talking to the swap aggregator (DNS, TLS,
    /// timeout, non-2xx status), as opposed to a well-formed "no route" answer.
    #[error("swap aggregator request failed: {0}")]
    HttpError(String),

    /// Submitting one of the on-chain legs (withdraw or deposit) failed.
    #[error("on-chain submission failed: {0}")]
    SubmissionFailed(String),
}

/// Crate-local result alias for relayer orchestration.
pub type Result<T> = std::result::Result<T, RelayerError>;

/// The result of executing a swap on public liquidity: how much `asset_out`
/// the route produced for the given `amount_in` of `asset_in`. This is the
/// *gross* output, before the relayer fee is taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapResult {
    /// Amount of `asset_out` produced, in that asset's smallest unit.
    pub out_amount: u64,
}

/// Routes a swap on public liquidity.
///
/// The real implementation (Jupiter v6, #239 — [`crate::relayer::jupiter`])
/// lives behind this trait so the orchestration can be exercised end-to-end
/// with [`MockSwapProvider`] and no network. Implementations receive the in/out
/// asset ids (mints; native SOL is [`NATIVE_SOL_ASSET`]), the input amount, and
/// the per-swap ephemeral `signer`, and return the gross output.
///
/// # Why `signer` is on the method, not the provider
///
/// The fresh ephemeral [`Keypair`] is generated per swap inside
/// [`PrivateSwapRelayer::execute`] — it is the same address the withdraw leg
/// funded, and the swap must be signed *and submitted from it* so the public
/// trade originates at the unlinkable address rather than any relayer-owned
/// wallet. Construction-time injection cannot see a value that does not exist
/// until the swap begins, so the keypair is threaded through the call. The
/// [`MockSwapProvider`] simply ignores it.
#[async_trait::async_trait]
pub trait SwapProvider: Send + Sync {
    /// Swap `amount` of `asset_in` for `asset_out`, signing and submitting the
    /// public trade from the per-swap ephemeral `signer`, and report the gross
    /// output.
    async fn swap(
        &self,
        asset_in: AssetId,
        asset_out: AssetId,
        amount: u64,
        signer: &Keypair,
    ) -> Result<SwapResult>;
}

/// Deterministic stub [`SwapProvider`] for tests and #239's scaffolding.
///
/// Returns `amount * rate_num / rate_den` as the gross output, so the
/// orchestration can be asserted without a live DEX. A 1:1 rate
/// (`rate_num == rate_den`) models a stable pair; other ratios model a price.
pub struct MockSwapProvider {
    rate_num: u64,
    rate_den: u64,
}

impl MockSwapProvider {
    /// Mock that returns the input unchanged (1:1 rate).
    pub fn identity() -> Self {
        Self {
            rate_num: 1,
            rate_den: 1,
        }
    }

    /// Mock with an explicit `out = in * num / den` rate. `den` must be
    /// non-zero; this is a test helper so it panics rather than erroring.
    pub fn with_rate(rate_num: u64, rate_den: u64) -> Self {
        assert!(rate_den != 0, "rate denominator must be non-zero");
        Self { rate_num, rate_den }
    }
}

#[async_trait::async_trait]
impl SwapProvider for MockSwapProvider {
    async fn swap(
        &self,
        _asset_in: AssetId,
        _asset_out: AssetId,
        amount: u64,
        _signer: &Keypair,
    ) -> Result<SwapResult> {
        let out_amount = (amount as u128 * self.rate_num as u128 / self.rate_den as u128) as u64;
        Ok(SwapResult { out_amount })
    }
}

/// Which on-chain leg the relayer is asking the submitter to settle, and
/// against which asset. The submitter branches on this to pick the native
/// (`withdraw` / `deposit`) vs. SPL (`withdraw_spl` / `deposit_spl`) path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithdrawLeg {
    /// Native-SOL leg — uses the existing `withdraw` / `deposit` instructions.
    Native,
    /// SPL leg for the given mint — uses `withdraw_spl` / `deposit_spl`.
    Spl(AssetId),
}

impl WithdrawLeg {
    /// Classify an [`AssetId`] into the leg the on-chain program needs.
    pub fn for_asset(asset: AssetId) -> Self {
        if asset == NATIVE_SOL_ASSET {
            WithdrawLeg::Native
        } else {
            WithdrawLeg::Spl(asset)
        }
    }
}

/// A record of one settled on-chain leg. The submitter returns this so the
/// orchestrator (and tests) can assert what was actually submitted — which
/// asset, which path, how much, and to/from which fresh address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmittedLeg {
    /// Native vs. SPL path actually taken.
    pub leg: WithdrawLeg,
    /// Amount moved on this leg, in the asset's smallest unit.
    pub amount: u64,
    /// The ephemeral fresh address involved in this leg (withdraw recipient on
    /// the withdraw leg, deposit signer on the deposit leg).
    pub fresh_address: [u8; 32],
    /// On-chain transaction signature (or a mock token in tests).
    pub signature: String,
}

/// Settles the relayer's on-chain legs.
///
/// Composing the *real* on-chain submission needs a live validator and the
/// bridge authority key, so it sits behind this trait. The orchestration is
/// unit-tested with [`MockSubmitter`]; the production implementation wraps the
/// [`crate::bridge`] withdraw/deposit instruction builders and an RPC client.
#[async_trait::async_trait]
pub trait Submitter: Send + Sync {
    /// Withdraw `amount` of the note's asset to the fresh ephemeral address,
    /// spending `nullifier`. `proof` is the Groth16 withdrawal proof bytes.
    /// Branches native vs. SPL on `leg`.
    async fn submit_withdraw_to_fresh(
        &self,
        leg: WithdrawLeg,
        nullifier: Nullifier,
        amount: u64,
        fresh_address: [u8; 32],
        proof: Vec<u8>,
    ) -> Result<SubmittedLeg>;

    /// Deposit `amount` of `asset_out` from the fresh ephemeral address back
    /// into the shielded pool, creating a note for `recipient` with
    /// `randomness`. Branches native vs. SPL on `leg`.
    async fn submit_deposit_from_fresh(
        &self,
        leg: WithdrawLeg,
        amount: u64,
        fresh_address: [u8; 32],
        recipient: ShieldedAddress,
        randomness: [u8; 32],
    ) -> Result<SubmittedLeg>;
}

/// One private-swap order.
#[derive(Debug, Clone)]
pub struct PrivateSwapRequest {
    /// The shielded note being spent. Its `asset_id`/`amount` drive the
    /// withdraw leg; its `randomness`/`recipient` derive the nullifier.
    pub input_note: Note,
    /// The asset the user wants to end up holding (mint, or [`NATIVE_SOL_ASSET`]).
    pub asset_out: AssetId,
    /// The user's re-shield recipient for the output note. Distinct from the
    /// input note's recipient — this is the user's *new* shielded address.
    pub reshield_recipient: ShieldedAddress,
    /// Blinding randomness for the output note's commitment.
    pub reshield_randomness: [u8; 32],
    /// Relayer fee in basis points, applied to the gross swap output.
    pub fee_bps: u16,
    /// Groth16 withdrawal proof bytes for spending `input_note`. Generated by
    /// the caller (the proving key / ceremony is out of scope here); the
    /// relayer forwards it to the withdraw leg unmodified.
    pub withdraw_proof: Vec<u8>,
}

/// The outcome of a completed private swap.
#[derive(Debug, Clone)]
pub struct PrivateSwapResult {
    /// The withdraw-to-fresh-address leg.
    pub withdraw_leg: SubmittedLeg,
    /// The re-deposit leg.
    pub deposit_leg: SubmittedLeg,
    /// Gross output of the swap, before the relayer fee.
    pub gross_out_amount: u64,
    /// Relayer fee taken, in `asset_out`'s smallest unit.
    pub relayer_fee: u64,
    /// Net output re-shielded to the user (`gross - fee`).
    pub net_out_amount: u64,
    /// The fresh ephemeral address used for this swap. Present so callers can
    /// confirm the link-severing property; it shares no signer with the user.
    pub fresh_address: [u8; 32],
    /// The output note produced for the user.
    pub output_note: Note,
}

/// Orchestrates a single private swap by composing a [`SwapProvider`] and a
/// [`Submitter`]. Generic over both so the same logic runs against the mocks in
/// tests and the real Jupiter router + on-chain submitter in production.
pub struct PrivateSwapRelayer<S: SwapProvider, T: Submitter> {
    swap_provider: S,
    submitter: T,
}

impl<S: SwapProvider, T: Submitter> PrivateSwapRelayer<S, T> {
    /// Build a relayer over a swap provider and an on-chain submitter.
    pub fn new(swap_provider: S, submitter: T) -> Self {
        Self {
            swap_provider,
            submitter,
        }
    }

    /// Apply `fee_bps` to `gross`, returning `(fee, net)`. Rounds the fee down,
    /// so the user is never short-changed by rounding.
    fn split_fee(gross: u64, fee_bps: u16) -> (u64, u64) {
        let fee = (gross as u128 * fee_bps as u128 / 10_000u128) as u64;
        (fee, gross - fee)
    }

    /// Execute one private swap end to end.
    ///
    /// Composes: derive nullifier -> withdraw to a fresh ephemeral keypair ->
    /// swap on the provider -> take the relayer fee -> re-deposit the net to the
    /// user's shielded recipient. Returns a [`PrivateSwapResult`] describing
    /// every leg.
    pub async fn execute(&self, request: PrivateSwapRequest) -> Result<PrivateSwapResult> {
        let amount_in = request.input_note.amount;
        if amount_in == 0 {
            return Err(RelayerError::InvalidAmount(0));
        }
        if request.fee_bps > 10_000 {
            return Err(RelayerError::FeeTooHigh(request.fee_bps));
        }

        let asset_in = request.input_note.asset_id;
        let asset_out = request.asset_out;
        let in_leg = WithdrawLeg::for_asset(asset_in);
        let out_leg = WithdrawLeg::for_asset(asset_out);

        // A brand-new keypair per swap — nothing on-chain links it to the user.
        // This is the relayer-layer expression of the link-severing property
        // that the withdrawal nullifier enforces on-chain.
        let ephemeral = Keypair::new();
        let fresh_address = ephemeral.pubkey().to_bytes();

        // Step 1: withdraw the spent note to the fresh address. The nullifier
        // is derived exactly as the on-chain `withdraw` expects (poseidon over
        // the note commitment and its blinding randomness, which doubles as the
        // spend secret on the single-note path — mirrors `demo_flow.rs`).
        let commitment = request.input_note.commitment();
        let nullifier = Nullifier::derive(&commitment, &request.input_note.randomness);
        let withdraw_leg = self
            .submitter
            .submit_withdraw_to_fresh(
                in_leg,
                nullifier,
                amount_in,
                fresh_address,
                request.withdraw_proof.clone(),
            )
            .await?;

        // Step 2: swap on public liquidity from the fresh address. The provider
        // signs and submits the public trade from `ephemeral`, so the trade
        // originates at the unlinkable fresh address.
        let swap = self
            .swap_provider
            .swap(asset_in, asset_out, amount_in, &ephemeral)
            .await?;
        let gross_out_amount = swap.out_amount;

        // Step 3: take the relayer's cut from the gross output.
        let (relayer_fee, net_out_amount) = Self::split_fee(gross_out_amount, request.fee_bps);

        // Step 4: re-deposit the net output into the shielded pool to the
        // user's new recipient, producing a fresh `asset_out` note.
        let deposit_leg = self
            .submitter
            .submit_deposit_from_fresh(
                out_leg,
                net_out_amount,
                fresh_address,
                request.reshield_recipient.clone(),
                request.reshield_randomness,
            )
            .await?;

        let output_note = Note::new(
            request.reshield_recipient,
            net_out_amount,
            request.reshield_randomness,
            asset_out,
        );

        Ok(PrivateSwapResult {
            withdraw_leg,
            deposit_leg,
            gross_out_amount,
            relayer_fee,
            net_out_amount,
            fresh_address,
            output_note,
        })
    }
}

/// In-memory [`Submitter`] for tests: records every leg it is asked to settle
/// and returns deterministic mock signatures. No validator or RPC needed.
#[derive(Default)]
pub struct MockSubmitter {
    legs: std::sync::Mutex<Vec<SubmittedLeg>>,
}

impl MockSubmitter {
    /// A fresh recording submitter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every leg this submitter has settled, in submission order.
    pub fn recorded(&self) -> Vec<SubmittedLeg> {
        self.legs.lock().expect("mock submitter lock").clone()
    }

    fn record(&self, leg: SubmittedLeg) -> SubmittedLeg {
        self.legs
            .lock()
            .expect("mock submitter lock")
            .push(leg.clone());
        leg
    }
}

#[async_trait::async_trait]
impl Submitter for MockSubmitter {
    async fn submit_withdraw_to_fresh(
        &self,
        leg: WithdrawLeg,
        nullifier: Nullifier,
        amount: u64,
        fresh_address: [u8; 32],
        proof: Vec<u8>,
    ) -> Result<SubmittedLeg> {
        if proof.is_empty() {
            return Err(RelayerError::SubmissionFailed(
                "empty withdrawal proof".into(),
            ));
        }
        Ok(self.record(SubmittedLeg {
            leg,
            amount,
            fresh_address,
            signature: format!("mock-withdraw-{}", nullifier.to_hex()),
        }))
    }

    async fn submit_deposit_from_fresh(
        &self,
        leg: WithdrawLeg,
        amount: u64,
        fresh_address: [u8; 32],
        recipient: ShieldedAddress,
        _randomness: [u8; 32],
    ) -> Result<SubmittedLeg> {
        Ok(self.record(SubmittedLeg {
            leg,
            amount,
            fresh_address,
            signature: format!("mock-deposit-{}", recipient.to_hex()),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native_note(amount: u64) -> Note {
        Note::new_native(ShieldedAddress::from_bytes([7u8; 32]), amount, [3u8; 32])
    }

    fn spl_note(mint: AssetId, amount: u64) -> Note {
        Note::new(
            ShieldedAddress::from_bytes([7u8; 32]),
            amount,
            [3u8; 32],
            mint,
        )
    }

    fn request(input_note: Note, asset_out: AssetId, fee_bps: u16) -> PrivateSwapRequest {
        PrivateSwapRequest {
            input_note,
            asset_out,
            reshield_recipient: ShieldedAddress::from_bytes([9u8; 32]),
            reshield_randomness: [5u8; 32],
            fee_bps,
            // Non-empty so the mock submitter's "empty proof" guard passes;
            // real proof generation/verification is out of scope for #238.
            withdraw_proof: vec![1u8; 192],
        }
    }

    #[tokio::test]
    async fn composes_withdraw_swap_fee_redeposit_end_to_end() {
        let relayer = PrivateSwapRelayer::new(MockSwapProvider::identity(), MockSubmitter::new());
        // 1:1 swap of 1_000_000 with a 50 bps relayer fee.
        let req = request(native_note(1_000_000), NATIVE_SOL_ASSET, 50);
        let out = relayer.execute(req).await.expect("swap executes");

        // Gross output is the 1:1 swap of the input amount.
        assert_eq!(out.gross_out_amount, 1_000_000);
        // 50 bps of 1_000_000 = 5_000 fee; user nets 995_000.
        assert_eq!(out.relayer_fee, 5_000);
        assert_eq!(out.net_out_amount, 995_000);
        // The re-shielded note carries the net amount and the user's recipient.
        assert_eq!(out.output_note.amount, 995_000);
        assert_eq!(
            out.output_note.recipient,
            ShieldedAddress::from_bytes([9u8; 32])
        );

        // Both legs were submitted, withdraw then deposit.
        assert_eq!(out.withdraw_leg.amount, 1_000_000);
        assert_eq!(out.deposit_leg.amount, 995_000);
    }

    #[tokio::test]
    async fn relayer_fee_is_deducted_from_gross_output() {
        // 250 bps (2.5%) on a 2:1 swap of 400 -> gross 800, fee 20, net 780.
        let relayer =
            PrivateSwapRelayer::new(MockSwapProvider::with_rate(2, 1), MockSubmitter::new());
        let out = relayer
            .execute(request(native_note(400), NATIVE_SOL_ASSET, 250))
            .await
            .expect("swap executes");
        assert_eq!(out.gross_out_amount, 800);
        assert_eq!(out.relayer_fee, 20);
        assert_eq!(out.net_out_amount, 780);
        assert_eq!(out.relayer_fee + out.net_out_amount, out.gross_out_amount);
    }

    #[tokio::test]
    async fn zero_fee_passes_full_output_to_user() {
        let relayer = PrivateSwapRelayer::new(MockSwapProvider::identity(), MockSubmitter::new());
        let out = relayer
            .execute(request(native_note(123_456), NATIVE_SOL_ASSET, 0))
            .await
            .expect("swap executes");
        assert_eq!(out.relayer_fee, 0);
        assert_eq!(out.net_out_amount, out.gross_out_amount);
    }

    #[tokio::test]
    async fn fresh_ephemeral_address_severs_the_link() {
        let relayer = PrivateSwapRelayer::new(MockSwapProvider::identity(), MockSubmitter::new());
        let r1 = relayer
            .execute(request(native_note(1_000), NATIVE_SOL_ASSET, 0))
            .await
            .expect("swap 1");
        let r2 = relayer
            .execute(request(native_note(1_000), NATIVE_SOL_ASSET, 0))
            .await
            .expect("swap 2");

        // A new keypair per swap: the two fresh addresses differ, and neither
        // is the all-zero / input recipient.
        assert_ne!(r1.fresh_address, r2.fresh_address);
        assert_ne!(r1.fresh_address, [0u8; 32]);
        // The withdraw and deposit legs of one swap share that swap's fresh
        // address — both legs surface at the unlinkable address, not the user.
        assert_eq!(r1.withdraw_leg.fresh_address, r1.fresh_address);
        assert_eq!(r1.deposit_leg.fresh_address, r1.fresh_address);
    }

    #[tokio::test]
    async fn native_in_native_out_takes_the_native_path() {
        let submitter = MockSubmitter::new();
        let relayer = PrivateSwapRelayer::new(MockSwapProvider::identity(), submitter);
        relayer
            .execute(request(native_note(1_000), NATIVE_SOL_ASSET, 0))
            .await
            .expect("swap executes");
        let legs = relayer.submitter.recorded();
        assert_eq!(legs.len(), 2);
        assert_eq!(legs[0].leg, WithdrawLeg::Native);
        assert_eq!(legs[1].leg, WithdrawLeg::Native);
    }

    #[tokio::test]
    async fn spl_in_spl_out_takes_the_spl_path_per_mint() {
        let mint_in: AssetId = [0x11u8; 32];
        let mint_out: AssetId = [0x22u8; 32];
        let relayer = PrivateSwapRelayer::new(MockSwapProvider::identity(), MockSubmitter::new());
        relayer
            .execute(request(spl_note(mint_in, 5_000), mint_out, 0))
            .await
            .expect("swap executes");
        let legs = relayer.submitter.recorded();
        // Withdraw leg routes on the input mint; deposit leg on the output mint.
        assert_eq!(legs[0].leg, WithdrawLeg::Spl(mint_in));
        assert_eq!(legs[1].leg, WithdrawLeg::Spl(mint_out));
    }

    #[tokio::test]
    async fn spl_in_native_out_routes_each_leg_independently() {
        let mint_in: AssetId = [0x33u8; 32];
        let relayer = PrivateSwapRelayer::new(MockSwapProvider::identity(), MockSubmitter::new());
        relayer
            .execute(request(spl_note(mint_in, 9_000), NATIVE_SOL_ASSET, 0))
            .await
            .expect("swap executes");
        let legs = relayer.submitter.recorded();
        assert_eq!(legs[0].leg, WithdrawLeg::Spl(mint_in));
        assert_eq!(legs[1].leg, WithdrawLeg::Native);
    }

    #[tokio::test]
    async fn zero_amount_note_is_rejected() {
        let relayer = PrivateSwapRelayer::new(MockSwapProvider::identity(), MockSubmitter::new());
        let err = relayer
            .execute(request(native_note(0), NATIVE_SOL_ASSET, 0))
            .await
            .expect_err("zero amount must error");
        assert!(matches!(err, RelayerError::InvalidAmount(0)));
    }

    #[tokio::test]
    async fn fee_over_100_percent_is_rejected() {
        let relayer = PrivateSwapRelayer::new(MockSwapProvider::identity(), MockSubmitter::new());
        let err = relayer
            .execute(request(native_note(1_000), NATIVE_SOL_ASSET, 10_001))
            .await
            .expect_err("fee > 100% must error");
        assert!(matches!(err, RelayerError::FeeTooHigh(10_001)));
    }

    #[test]
    fn withdraw_leg_classifies_native_vs_spl() {
        assert_eq!(
            WithdrawLeg::for_asset(NATIVE_SOL_ASSET),
            WithdrawLeg::Native
        );
        let mint: AssetId = [0xABu8; 32];
        assert_eq!(WithdrawLeg::for_asset(mint), WithdrawLeg::Spl(mint));
    }
}
