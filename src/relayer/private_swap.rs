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
//! 3. **Fee.** The relayer fee is realized **once**, inside the swap route, by
//!    the swap provider (Jupiter's `platformFeeBps`, credited to the relayer's
//!    fee account) — so the swap output is already net of it. The orchestrator
//!    does **not** take a second cut; doing so double-charged the user.
//!    `request.fee_bps` is the declared fee the provider is configured to
//!    realize.
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

use crate::privacy::types::{AssetId, Note, ShieldedAddress, NATIVE_SOL_ASSET};
use solana_sdk::signature::{Keypair, Signer};
use thiserror::Error;

/// The protocol withdrawal fee in basis points, mirrored from the on-chain
/// program (`programs/paraloom` `WITHDRAWAL_FEE_BPS`). Every withdraw — including
/// the relayer's withdraw-to-fresh leg — credits this fee to the settling
/// validator, so the fresh address receives `amount - fee`, never the gross
/// note value. The swap leg must trade that realized amount.
const WITHDRAWAL_FEE_BPS: u64 = 25;

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
    /// Withdraw `amount` lamports of the caller's native-SOL note to the fresh
    /// ephemeral `fresh_address` via a v3 `transact`. The submitter takes the
    /// note's v3 spend witness (`sk`, `blinding`, `note_pubkey`, `leaf_index`),
    /// reads the membership path, proves, POSTs to the transact ingress, and
    /// waits for the validator co-sign quorum to settle it. `leg` must be
    /// `Native` (SPL withdraw is unavailable on the native-only v3 program).
    #[allow(clippy::too_many_arguments)]
    async fn submit_withdraw_to_fresh(
        &self,
        leg: WithdrawLeg,
        amount: u64,
        sk: [u8; 32],
        blinding: [u8; 32],
        note_pubkey: [u8; 32],
        leaf_index: u64,
        fresh_address: [u8; 32],
    ) -> Result<SubmittedLeg>;

    /// Deposit `amount` of `asset_out` from the fresh ephemeral address back
    /// into the shielded pool, creating a note for `recipient` with
    /// `randomness`. Branches native vs. SPL on `leg`.
    ///
    /// `signer` is the per-swap ephemeral [`Keypair`] — the same key the
    /// withdraw leg funded and the swap leg traded from. On-chain `deposit` /
    /// `deposit_spl` require the depositor (the funds' owner) to sign, and that
    /// owner is the fresh address, so the orchestrator threads its keypair
    /// through here. [`MockSubmitter`] ignores it, exactly as
    /// [`MockSwapProvider`] ignores the swap signer.
    async fn submit_deposit_from_fresh(
        &self,
        leg: WithdrawLeg,
        amount: u64,
        signer: &Keypair,
        recipient: ShieldedAddress,
        randomness: [u8; 32],
    ) -> Result<SubmittedLeg>;
}

/// One private-swap order.
#[derive(Debug, Clone)]
pub struct PrivateSwapRequest {
    /// Amount of the input note, in the asset's smallest unit. Drives the
    /// withdraw leg.
    pub amount_in: u64,
    /// The input note's asset (mint, or [`NATIVE_SOL_ASSET`]).
    pub asset_in: AssetId,
    /// v3 spend private key of the input note.
    pub in_sk: [u8; 32],
    /// v3 blinding of the input note.
    pub in_blinding: [u8; 32],
    /// v3 spend public key of the input note (`v3_pubkey(in_sk)`).
    pub in_note_pubkey: [u8; 32],
    /// The input note's leaf index in the on-chain incremental tree.
    pub in_leaf_index: u64,
    /// The asset the user wants to end up holding (mint, or [`NATIVE_SOL_ASSET`]).
    pub asset_out: AssetId,
    /// The user's re-shield recipient for the output note (native re-shield
    /// only; SPL re-shield needs a program redeploy). Distinct from the input
    /// note — this is the user's *new* shielded address.
    pub reshield_recipient: ShieldedAddress,
    /// Blinding randomness for the output note's commitment.
    pub reshield_randomness: [u8; 32],
    /// Relayer fee in basis points, applied to the gross swap output.
    pub fee_bps: u16,
}

/// The outcome of a completed private swap.
#[derive(Debug, Clone)]
pub struct PrivateSwapResult {
    /// The withdraw-to-fresh-address leg.
    pub withdraw_leg: SubmittedLeg,
    /// The re-deposit leg.
    pub deposit_leg: SubmittedLeg,
    /// Swap output reaching the ephemeral address, already net of any fee the
    /// provider realized inside the route.
    pub gross_out_amount: u64,
    /// Fee taken by the orchestrator. Always 0: the relayer fee is realized once
    /// by the swap provider in-route, not deducted again here.
    pub relayer_fee: u64,
    /// Net output re-shielded to the user. Equals `gross_out_amount` now that the
    /// orchestrator takes no second cut.
    pub net_out_amount: u64,
    /// The fresh ephemeral address used for this swap. Present so callers can
    /// confirm the link-severing property; it shares no signer with the user.
    pub fresh_address: [u8; 32],
    /// The output note produced for the user.
    pub output_note: Note,
}

/// The outcome of a swap-out-only private swap (no re-shield).
///
/// Produced by [`PrivateSwapRelayer::execute_swap_out`]. The swapped
/// `asset_out` sits at `fresh_address` — an address unlinkable to the note's
/// depositor, whose key the caller (the user) holds.
#[derive(Debug, Clone)]
pub struct SwapOutResult {
    /// The withdraw-to-fresh-address leg that funded the swap.
    pub withdraw_leg: SubmittedLeg,
    /// Gross swap output delivered to `fresh_address`, in `asset_out`'s smallest
    /// unit. Already net of any fee the provider realized inside the route.
    pub gross_out_amount: u64,
    /// The fresh ephemeral address holding the swap output. Shares no signer
    /// with the note's depositor.
    pub fresh_address: [u8; 32],
    /// The asset now held at `fresh_address` (mint, or [`NATIVE_SOL_ASSET`]).
    pub asset_out: AssetId,
}

/// Orchestrates a single private swap by composing a [`SwapProvider`] and a
/// [`Submitter`]. Generic over both so the same logic runs against the mocks in
/// tests and the real Jupiter router + on-chain submitter in production.
pub struct PrivateSwapRelayer<S: SwapProvider, T: Submitter> {
    swap_provider: S,
    submitter: T,
    /// Lamports a native-SOL input leg retains on the fresh address to pay the
    /// swap's own on-chain costs — rent for the wrapped-SOL account and the
    /// output token ATA the router creates, plus a transaction-fee margin. A
    /// native swap trades `amount - this`, never the full note: the trade cannot
    /// spend the very lamports it must keep to pay for itself. Default 0 (mock
    /// providers have no rent); real Solana submitters set the on-chain figure.
    native_swap_overhead_lamports: u64,
}

impl<S: SwapProvider, T: Submitter> PrivateSwapRelayer<S, T> {
    /// Build a relayer over a swap provider and an on-chain submitter.
    pub fn new(swap_provider: S, submitter: T) -> Self {
        Self {
            swap_provider,
            submitter,
            native_swap_overhead_lamports: 0,
        }
    }

    /// Set the native-SOL swap overhead reserve (see the field docs). Real
    /// Solana swaps need ~0.005 SOL to cover two token-account rents plus fees;
    /// mock-backed tests leave it at the default 0.
    pub fn with_native_swap_overhead(mut self, lamports: u64) -> Self {
        self.native_swap_overhead_lamports = lamports;
        self
    }

    /// Shared first half of every private swap: withdraw the spent note to
    /// `ephemeral` via a v3 transact, then swap the realized (post-fee, post-
    /// overhead) amount on the provider from that same fresh address. Returns
    /// the settled withdraw leg and the gross swap output. Both [`execute`] (the
    /// full round-trip) and [`execute_swap_out`] (the swap-out-only flow) build
    /// on this, so the fee/overhead accounting lives in exactly one place.
    ///
    /// [`execute`]: Self::execute
    /// [`execute_swap_out`]: Self::execute_swap_out
    async fn withdraw_then_swap(
        &self,
        request: &PrivateSwapRequest,
        ephemeral: &Keypair,
    ) -> Result<(SubmittedLeg, u64)> {
        let amount_in = request.amount_in;
        if amount_in == 0 {
            return Err(RelayerError::InvalidAmount(0));
        }
        if request.fee_bps > 10_000 {
            return Err(RelayerError::FeeTooHigh(request.fee_bps));
        }

        let asset_in = request.asset_in;
        let asset_out = request.asset_out;
        let in_leg = WithdrawLeg::for_asset(asset_in);
        let fresh_address = ephemeral.pubkey().to_bytes();

        // Step 1: withdraw the spent note to the fresh address via a v3
        // transact. The submitter takes the note's v3 spend witness, proves the
        // withdrawal to `fresh_address`, and waits for the quorum to settle it;
        // the nullifier burn severs the deposit -> fresh-address link on-chain.
        let withdraw_leg = self
            .submitter
            .submit_withdraw_to_fresh(
                in_leg,
                amount_in,
                request.in_sk,
                request.in_blinding,
                request.in_note_pubkey,
                request.in_leaf_index,
                fresh_address,
            )
            .await?;

        // Step 2: swap on public liquidity from the fresh address. The provider
        // signs and submits the public trade from `ephemeral`, so the trade
        // originates at the unlinkable fresh address.
        //
        // The on-chain withdraw deducts the protocol withdrawal fee
        // (`WITHDRAWAL_FEE_BPS`, credited to the settling validator), so the
        // fresh address holds `amount_in - fee`, not the gross note value.
        // Swapping the gross amount would exceed the fresh address's balance and
        // fail *after* the nullifier is already burned, stranding the funds —
        // so the swap trades the realized post-fee amount.
        let withdrawal_fee = amount_in
            .checked_mul(WITHDRAWAL_FEE_BPS)
            .map(|x| x / 10_000)
            .ok_or(RelayerError::InvalidAmount(amount_in))?;
        let withdrawn = amount_in
            .checked_sub(withdrawal_fee)
            .filter(|&a| a > 0)
            .ok_or(RelayerError::InvalidAmount(amount_in))?;

        // On a native-SOL input leg the fresh address also pays the swap's rent
        // and fees out of the same lamports, so trade the realized amount minus
        // the overhead reserve — never the full note (see
        // `native_swap_overhead_lamports`).
        let swap_amount = if asset_in == NATIVE_SOL_ASSET {
            withdrawn
                .checked_sub(self.native_swap_overhead_lamports)
                .filter(|&a| a > 0)
                .ok_or(RelayerError::InvalidAmount(amount_in))?
        } else {
            withdrawn
        };
        let swap = self
            .swap_provider
            .swap(asset_in, asset_out, swap_amount, ephemeral)
            .await?;
        Ok((withdraw_leg, swap.out_amount))
    }

    /// Execute one private swap end to end.
    ///
    /// Composes: derive nullifier -> withdraw to a fresh ephemeral keypair ->
    /// swap on the provider -> take the relayer fee -> re-deposit the net to the
    /// user's shielded recipient. Returns a [`PrivateSwapResult`] describing
    /// every leg.
    ///
    /// # Availability
    ///
    /// The re-deposit leg re-shields `asset_out`. On the native-only v3 program
    /// the submitter only accepts a native-SOL re-deposit, so a non-native
    /// `asset_out` (e.g. USDC) fails at the deposit leg — re-shielding a token
    /// needs the SPL redeploy. Until then, [`execute_swap_out`] delivers the
    /// swapped token to the unlinkable fresh address without re-shielding it.
    ///
    /// [`execute_swap_out`]: Self::execute_swap_out
    pub async fn execute(&self, request: PrivateSwapRequest) -> Result<PrivateSwapResult> {
        // A brand-new keypair per swap — nothing on-chain links it to the user.
        // This is the relayer-layer expression of the link-severing property
        // that the withdrawal nullifier enforces on-chain.
        let ephemeral = Keypair::new();
        let fresh_address = ephemeral.pubkey().to_bytes();
        let out_leg = WithdrawLeg::for_asset(request.asset_out);

        let (withdraw_leg, gross_out_amount) =
            self.withdraw_then_swap(&request, &ephemeral).await?;

        // Step 3: the swap output is ALREADY net of the relayer's fee — it is
        // realized inside the route by the swap provider (Jupiter's
        // `platformFeeBps`, credited to the relayer's fee account). The
        // orchestrator does NOT take a second cut here; applying `fee_bps` again
        // double-charged the user (audit). `request.fee_bps` is the declared fee
        // the provider is configured to realize, validated for bounds above.
        let relayer_fee = 0u64;
        let net_out_amount = gross_out_amount;

        // Step 4: re-deposit the net output into the shielded pool to the
        // user's new recipient, producing a fresh `asset_out` note.
        let deposit_leg = self
            .submitter
            .submit_deposit_from_fresh(
                out_leg,
                net_out_amount,
                &ephemeral,
                request.reshield_recipient.clone(),
                request.reshield_randomness,
            )
            .await?;

        let output_note = Note::new(
            request.reshield_recipient,
            net_out_amount,
            request.reshield_randomness,
            request.asset_out,
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

    /// Execute the swap-out half of a private swap: withdraw the spent note to a
    /// caller-supplied fresh address and swap it there, **without** re-shielding
    /// the output. The swapped `asset_out` is left at `fresh`, an address that
    /// shares no signer with the note's depositor — a private buy whose output
    /// the user controls but the chain cannot link to their shielded deposit.
    ///
    /// This is the capability the native-only v3 program supports today for a
    /// token `asset_out`: [`execute`]'s re-deposit leg cannot re-shield an SPL
    /// token until the SPL redeploy, but the swap output itself is real and
    /// unlinkable. Re-shielding it into a fresh note is the round-trip
    /// [`execute`] provides once a native `asset_out` (or the SPL redeploy)
    /// applies.
    ///
    /// `fresh` is supplied by the caller (not generated here) so the party who
    /// will spend the output — the user, not the relayer — holds its key. The
    /// withdraw leg funds `fresh`; the swap is signed and submitted from it.
    ///
    /// [`execute`]: Self::execute
    pub async fn execute_swap_out(
        &self,
        request: PrivateSwapRequest,
        fresh: &Keypair,
    ) -> Result<SwapOutResult> {
        let (withdraw_leg, gross_out_amount) = self.withdraw_then_swap(&request, fresh).await?;
        Ok(SwapOutResult {
            withdraw_leg,
            gross_out_amount,
            fresh_address: fresh.pubkey().to_bytes(),
            asset_out: request.asset_out,
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
    #[allow(clippy::too_many_arguments)]
    async fn submit_withdraw_to_fresh(
        &self,
        leg: WithdrawLeg,
        amount: u64,
        sk: [u8; 32],
        _blinding: [u8; 32],
        _note_pubkey: [u8; 32],
        leaf_index: u64,
        fresh_address: [u8; 32],
    ) -> Result<SubmittedLeg> {
        Ok(self.record(SubmittedLeg {
            leg,
            amount,
            fresh_address,
            signature: format!("mock-withdraw-sk{}-leaf{leaf_index}", hex::encode(sk)),
        }))
    }

    async fn submit_deposit_from_fresh(
        &self,
        leg: WithdrawLeg,
        amount: u64,
        signer: &Keypair,
        recipient: ShieldedAddress,
        _randomness: [u8; 32],
    ) -> Result<SubmittedLeg> {
        Ok(self.record(SubmittedLeg {
            leg,
            amount,
            fresh_address: signer.pubkey().to_bytes(),
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
        // The orchestration tests exercise execute's amount/leg/fee logic with a
        // mock submitter, so the v3 spend witness is dummy here (the real
        // OnChainSubmitter is what proves against it). amount_in/asset_in come
        // from the note so the existing native_note/spl_note helpers still drive.
        PrivateSwapRequest {
            amount_in: input_note.amount,
            asset_in: input_note.asset_id,
            in_sk: [1u8; 32],
            in_blinding: [2u8; 32],
            in_note_pubkey: [3u8; 32],
            in_leaf_index: 0,
            asset_out,
            reshield_recipient: ShieldedAddress::from_bytes([9u8; 32]),
            reshield_randomness: [5u8; 32],
            fee_bps,
        }
    }

    #[tokio::test]
    async fn composes_withdraw_swap_fee_redeposit_end_to_end() {
        let relayer = PrivateSwapRelayer::new(MockSwapProvider::identity(), MockSubmitter::new());
        // 1:1 swap of 1_000_000. The on-chain withdraw deducts the 25bps protocol
        // fee, so 997_500 reaches the fresh address and is what the swap trades;
        // the mock provider takes no fee and the orchestrator no second cut, so
        // that realized amount is re-shielded in full.
        let withdrawn = 1_000_000 - 1_000_000 * 25 / 10_000; // 997_500
        let req = request(native_note(1_000_000), NATIVE_SOL_ASSET, 50);
        let out = relayer.execute(req).await.expect("swap executes");

        assert_eq!(out.gross_out_amount, withdrawn);
        assert_eq!(out.relayer_fee, 0);
        assert_eq!(out.net_out_amount, withdrawn);
        // The re-shielded note carries the realized output and the user's recipient.
        assert_eq!(out.output_note.amount, withdrawn);
        assert_eq!(
            out.output_note.recipient,
            ShieldedAddress::from_bytes([9u8; 32])
        );

        // Both legs were submitted, withdraw then deposit. The withdraw leg
        // submits the gross note value (the fee is taken on-chain); the deposit
        // re-shields the realized post-fee output.
        assert_eq!(out.withdraw_leg.amount, 1_000_000);
        assert_eq!(out.deposit_leg.amount, withdrawn);
    }

    #[tokio::test]
    async fn native_overhead_reserve_shrinks_the_swap_not_the_withdraw() {
        // 1:1 swap so gross output == the amount actually handed to the provider.
        let relayer = PrivateSwapRelayer::new(MockSwapProvider::identity(), MockSubmitter::new())
            .with_native_swap_overhead(5_000);
        let out = relayer
            .execute(request(native_note(1_000_000), NATIVE_SOL_ASSET, 0))
            .await
            .expect("swap executes");
        // The full note is withdrawn to the fresh address...
        assert_eq!(out.withdraw_leg.amount, 1_000_000);
        // ...but only `realized - overhead` is swapped, leaving lamports for
        // rent/fees: 1_000_000 - 2_500 (25bps withdraw fee) - 5_000 overhead.
        assert_eq!(out.gross_out_amount, 1_000_000 - 2_500 - 5_000);
    }

    #[tokio::test]
    async fn native_overhead_does_not_touch_an_spl_input_leg() {
        let mint = [4u8; 32];
        // The overhead is a native-SOL concern; an SPL input swaps its full amount.
        let relayer = PrivateSwapRelayer::new(MockSwapProvider::identity(), MockSubmitter::new())
            .with_native_swap_overhead(5_000);
        let out = relayer
            .execute(request(spl_note(mint, 1_000_000), NATIVE_SOL_ASSET, 0))
            .await
            .expect("swap executes");
        // The 25bps withdraw fee still applies, but the native overhead reserve
        // does not touch an SPL leg: 1_000_000 - 2_500, with no 5_000 subtracted.
        assert_eq!(out.gross_out_amount, 1_000_000 - 2_500);
    }

    #[tokio::test]
    async fn native_overhead_at_or_above_amount_is_rejected() {
        let relayer = PrivateSwapRelayer::new(MockSwapProvider::identity(), MockSubmitter::new())
            .with_native_swap_overhead(1_000);
        let err = relayer
            .execute(request(native_note(1_000), NATIVE_SOL_ASSET, 0))
            .await
            .expect_err("overhead consuming the whole note must fail, not swap 0");
        assert!(matches!(err, RelayerError::InvalidAmount(1_000)));
    }

    #[tokio::test]
    async fn orchestrator_takes_no_second_fee_from_the_swap_output() {
        // 2:1 swap of 400. The 25bps withdraw fee leaves 399 on the fresh
        // address (400 - 1), so the provider trades 399 -> gross 798. Even with a
        // non-zero request fee_bps, the orchestrator no longer deducts a second
        // cut (the fee is realized by the swap provider), so the full realized
        // output is re-shielded — closing the double-charge.
        let relayer =
            PrivateSwapRelayer::new(MockSwapProvider::with_rate(2, 1), MockSubmitter::new());
        let out = relayer
            .execute(request(native_note(400), NATIVE_SOL_ASSET, 250))
            .await
            .expect("swap executes");
        assert_eq!(out.gross_out_amount, (400 - 1) * 2);
        assert_eq!(out.relayer_fee, 0);
        assert_eq!(out.net_out_amount, (400 - 1) * 2);
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

    #[tokio::test]
    async fn swap_out_withdraws_and_swaps_without_redeposit() {
        let relayer = PrivateSwapRelayer::new(MockSwapProvider::identity(), MockSubmitter::new());
        let fresh = Keypair::new();
        let usdc: AssetId = [0x55u8; 32];
        // Re-shielding a token is impossible on the native-only v3 program, so
        // the swap-out flow delivers USDC to the fresh address and stops.
        let out = relayer
            .execute_swap_out(request(native_note(1_000_000), usdc, 0), &fresh)
            .await
            .expect("swap-out executes");
        // 25bps withdraw fee: 997_500 reaches the fresh address, swapped 1:1.
        assert_eq!(out.gross_out_amount, 1_000_000 - 2_500);
        assert_eq!(out.asset_out, usdc);
        assert_eq!(out.fresh_address, fresh.pubkey().to_bytes());
        // Only the withdraw leg is submitted — there is no re-deposit leg.
        let legs = relayer.submitter.recorded();
        assert_eq!(legs.len(), 1);
        assert_eq!(legs[0].leg, WithdrawLeg::Native);
        assert_eq!(legs[0].fresh_address, fresh.pubkey().to_bytes());
    }

    #[tokio::test]
    async fn swap_out_honors_the_native_overhead_reserve() {
        let relayer = PrivateSwapRelayer::new(MockSwapProvider::identity(), MockSubmitter::new())
            .with_native_swap_overhead(5_000);
        let out = relayer
            .execute_swap_out(
                request(native_note(1_000_000), NATIVE_SOL_ASSET, 0),
                &Keypair::new(),
            )
            .await
            .expect("swap-out executes");
        // The whole note is withdrawn, but the swap trades realized minus
        // overhead: 1_000_000 - 2_500 (fee) - 5_000 (overhead).
        assert_eq!(out.withdraw_leg.amount, 1_000_000);
        assert_eq!(out.gross_out_amount, 1_000_000 - 2_500 - 5_000);
    }

    #[tokio::test]
    async fn swap_out_rejects_zero_amount() {
        let relayer = PrivateSwapRelayer::new(MockSwapProvider::identity(), MockSubmitter::new());
        let err = relayer
            .execute_swap_out(
                request(native_note(0), NATIVE_SOL_ASSET, 0),
                &Keypair::new(),
            )
            .await
            .expect_err("zero amount must error");
        assert!(matches!(err, RelayerError::InvalidAmount(0)));
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
