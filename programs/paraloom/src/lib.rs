//! Paraloom Solana Program
//!
//! Handles deposits into and withdrawals from the Paraloom privacy layer

use anchor_lang::prelude::*;
use anchor_lang::solana_program::bpf_loader_upgradeable;
use anchor_spl::token::{transfer, Mint, Token, TokenAccount, Transfer};

mod groth16;
mod quorum;
pub mod transfer_fixture_data;
mod transfer_verifier;
mod transfer_vk_data;
pub mod withdraw_fixture_data;
mod withdraw_verifier;
mod withdraw_vk_data;

declare_id!("8gPsRSm1CAw38mfzc1bcLMUXyFN7LnS8k6CV5hPUTWrP");

pub const MIN_VALIDATOR_STAKE: u64 = 1_000_000_000; // 1 SOL for devnet testing

/// Upper bound on the withdrawal proof blob. A BN254 Groth16 proof in the
/// `alt_bn128` wire form is exactly 256 bytes (see
/// [`withdraw_verifier::WIRE_PROOF_LEN`]); the cap rejects oversized blobs that
/// would only bloat the transaction (flagged alongside #178).
pub const MAX_PROOF_LEN: usize = 256;

/// Withdrawal fee, in basis points of the withdrawn amount (25 bps = 0.25%).
/// The fee is credited to the validator that settles the withdrawal — the
/// signer that gathered the BFT quorum and submitted the proof — so the
/// people running the network are the people earning from it. No founder
/// account sits in the withdraw path. The fee stays in the vault and is
/// pulled out by the earner through `claim_rewards`.
pub const WITHDRAWAL_FEE_BPS: u64 = 25;

/// Verify a BPFLoaderUpgradeable `ProgramData` account's upgrade authority
/// matches `expected` (#204). Closes the init front-run race: only the wallet
/// holding the program's upgrade authority can call the `initialize_*`
/// instructions. Parses the canonical
/// `bincode(UpgradeableLoaderState::ProgramData)` layout manually so this gate
/// adds no extra dependency to the on-chain binary:
///
/// ```text
///   bytes  0..4   : u32 LE enum tag (= 3 for `ProgramData`)
///   bytes  4..12  : u64 LE slot                (unused here)
///   byte  12      : `Option<Pubkey>` discriminator (1 = Some, 0 = None)
///   bytes 13..45  : 32-byte upgrade authority pubkey (when Some)
/// ```
fn check_upgrade_authority(program_data: &UncheckedAccount, expected: &Pubkey) -> Result<()> {
    require!(
        program_data.owner == &bpf_loader_upgradeable::id(),
        BridgeError::UnauthorizedInit
    );
    let data = program_data.try_borrow_data()?;
    require!(data.len() >= 45, BridgeError::UnauthorizedInit);
    let tag = u32::from_le_bytes(data[0..4].try_into().unwrap());
    require!(tag == 3, BridgeError::UnauthorizedInit); // ProgramData variant
    require!(data[12] == 1, BridgeError::UnauthorizedInit); // Some(_)
    let authority_bytes: [u8; 32] = data[13..45].try_into().unwrap();
    let actual = Pubkey::from(authority_bytes);
    require!(&actual == expected, BridgeError::UnauthorizedInit);
    Ok(())
}

/// Reject a non-canonical nullifier encoding (audit: on-chain replay via a
/// non-injective field lift). The proof's public input is
/// `Fr::from_le_bytes_mod_order(nullifier)`, which maps both `n` and `n + p`
/// (`p` = the BN254 scalar modulus) to the same field element, while the replay
/// defence — the nullifier PDA seed — keys on the *raw* bytes. So a spent note
/// could be settled a second time under `n + p`. Requiring the raw bytes to be
/// the canonical little-endian encoding of their reduced field element restores
/// the 1:1 byte↔field correspondence the off-chain code already maintains.
fn require_canonical_nullifier(nullifier: &[u8; 32]) -> Result<()> {
    use ark_ff::{BigInteger, PrimeField};
    let reduced = ark_bn254::Fr::from_le_bytes_mod_order(nullifier);
    let canonical = reduced.into_bigint().to_bytes_le();
    require!(
        canonical.as_slice() == nullifier.as_slice(),
        BridgeError::NonCanonicalNullifier
    );
    Ok(())
}

#[program]
pub mod paraloom_program {
    use super::*;

    /// Initialize the bridge state.
    ///
    /// `program_version` is recorded so an L2 binary can verify it is
    /// talking to the on-chain program version it was compiled
    /// against (#69 follow-up to audit #9). Version mismatches are an
    /// L2 startup precondition; mismatched binaries refuse to send
    /// instructions rather than risk a silently incompatible call.
    pub fn initialize(
        ctx: Context<Initialize>,
        program_version: u32,
        initial_merkle_root: [u8; 32],
    ) -> Result<()> {
        check_upgrade_authority(&ctx.accounts.program_data, &ctx.accounts.authority.key())?;
        let bridge_state = &mut ctx.accounts.bridge_state;
        bridge_state.program_version = program_version;
        bridge_state.authority = ctx.accounts.authority.key();
        bridge_state.total_deposited = 0;
        bridge_state.total_withdrawn = 0;
        bridge_state.deposit_count = 0;
        bridge_state.withdrawal_count = 0;
        bridge_state.paused = false;
        bridge_state.merkle_root = initial_merkle_root;

        msg!(
            "Bridge initialized with merkle root, program_version={}",
            program_version
        );
        Ok(())
    }

    /// Update Merkle root
    pub fn update_merkle_root(
        ctx: Context<UpdateMerkleRoot>,
        new_merkle_root: [u8; 32],
    ) -> Result<()> {
        let bridge_state = &mut ctx.accounts.bridge_state;
        bridge_state.merkle_root = new_merkle_root;

        msg!("Merkle root updated");
        Ok(())
    }

    /// Deposit SOL into the privacy pool
    pub fn deposit(
        ctx: Context<Deposit>,
        amount: u64,
        recipient: [u8; 32],
        randomness: [u8; 32],
    ) -> Result<()> {
        let bridge_state = &mut ctx.accounts.bridge_state;

        require!(!bridge_state.paused, BridgeError::BridgePaused);
        require!(amount > 0, BridgeError::InvalidAmount);

        let transfer_ix = anchor_lang::solana_program::system_instruction::transfer(
            &ctx.accounts.depositor.key(),
            &ctx.accounts.bridge_vault.key(),
            amount,
        );

        anchor_lang::solana_program::program::invoke(
            &transfer_ix,
            &[
                ctx.accounts.depositor.to_account_info(),
                ctx.accounts.bridge_vault.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
        )?;

        bridge_state.total_deposited += amount;
        bridge_state.deposit_count += 1;

        emit!(DepositEvent {
            depositor: ctx.accounts.depositor.key(),
            amount,
            recipient,
            randomness,
            timestamp: Clock::get()?.unix_timestamp,
            deposit_id: bridge_state.deposit_count,
        });

        msg!("Deposit successful: {} lamports", amount);
        Ok(())
    }

    /// Withdraw SOL from the privacy pool.
    ///
    /// Replay protection has two layers:
    ///  1. The nullifier-keyed PDA (`seeds = [b"nullifier", nullifier]`)
    ///     is `init`'d as part of this call. A second submission with
    ///     the same nullifier — the bit-pattern uniquely identifying
    ///     the spent note — fails on-chain because the PDA already
    ///     exists. This is the primary defense.
    ///  2. The caller commits to an `expiration_slot` at construction
    ///     time. The program rejects the call if the current Solana
    ///     slot is past it, so a request that leaks (e.g. through a
    ///     stale RPC, a forked program state, or a long-running
    ///     mempool) cannot be submitted indefinitely.
    pub fn withdraw(
        ctx: Context<Withdraw>,
        nullifier: [u8; 32],
        amount: u64,
        expiration_slot: u64,
        proof: Vec<u8>,
    ) -> Result<()> {
        let bridge_state = &mut ctx.accounts.bridge_state;

        require!(!bridge_state.paused, BridgeError::BridgePaused);
        require!(amount > 0, BridgeError::InvalidAmount);
        require!(!proof.is_empty(), BridgeError::InvalidProof);
        require!(proof.len() <= MAX_PROOF_LEN, BridgeError::ProofTooLarge);

        let current_slot = Clock::get()?.slot;
        require!(
            current_slot <= expiration_slot,
            BridgeError::WithdrawalExpired
        );

        // Reject a non-canonical nullifier so a spent note cannot be re-settled
        // under a different raw encoding that lifts to the same field element.
        require_canonical_nullifier(&nullifier)?;

        // Settlement requires a supermajority of registered validators to
        // co-sign this transaction (#260) — no single key can settle alone.
        quorum::verify_validator_quorum(
            ctx.program_id,
            &ctx.accounts.validator_registry,
            ctx.remaining_accounts,
        )?;

        // Verify the Groth16 withdrawal proof on-chain (#165). The proof is
        // bound to the program's published Merkle root and this withdrawal's
        // nullifier + amount, so the settling validator cannot forge a
        // withdrawal or redirect it to a different amount even though it holds
        // the settlement authority.
        require!(
            withdraw_verifier::verify_withdrawal(
                &bridge_state.merkle_root,
                &nullifier,
                amount,
                &proof,
            ),
            BridgeError::InvalidProof
        );

        let vault_balance = ctx.accounts.bridge_vault.lamports();
        require!(vault_balance >= amount, BridgeError::InsufficientFunds);

        // The settling validator earns a fee for gathering quorum and
        // submitting this withdrawal. `has_one`-style seeds bind the
        // `validator_account` to the `authority` signer, so the earner is
        // exactly the validator that settled — no founder account, no
        // third party. The fee is a cut of the amount: the recipient
        // receives `amount - fee`, and `fee` stays in the vault as a claim
        // recorded against the validator's `pending_rewards`.
        let validator_account = &mut ctx.accounts.validator_account;
        require!(validator_account.is_active, BridgeError::ValidatorNotActive);

        let fee = amount
            .checked_mul(WITHDRAWAL_FEE_BPS)
            .and_then(|v| v.checked_div(10_000))
            .ok_or(BridgeError::InvalidAmount)?;
        // A fee of 0 (dust withdrawals below 1/WITHDRAWAL_FEE_BPS) is fine;
        // the recipient simply receives the full amount. `fee < amount` is
        // guaranteed since the rate is well under 100%.
        let payout = amount - fee;

        let nullifier_account = &mut ctx.accounts.nullifier_account;
        nullifier_account.nullifier = nullifier;
        nullifier_account.used_at = Clock::get()?.unix_timestamp;
        nullifier_account.withdrawal_id = bridge_state.withdrawal_count + 1;

        let vault_bump = ctx.bumps.bridge_vault;
        let seeds = &[b"bridge_vault".as_ref(), &[vault_bump]];
        let signer_seeds = &[&seeds[..]];

        anchor_lang::system_program::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.bridge_vault.to_account_info(),
                    to: ctx.accounts.recipient.to_account_info(),
                },
                signer_seeds,
            ),
            payout,
        )?;

        // Credit the fee to the settling validator (claimed later via
        // `claim_rewards`) and record the settlement against its activity.
        validator_account.pending_rewards += fee;
        validator_account.successful_verifications += 1;
        validator_account.last_active = Clock::get()?.unix_timestamp;

        bridge_state.total_withdrawn += amount;
        bridge_state.withdrawal_count += 1;

        emit!(WithdrawalEvent {
            recipient: ctx.accounts.recipient.key(),
            amount,
            nullifier,
            timestamp: Clock::get()?.unix_timestamp,
            withdrawal_id: bridge_state.withdrawal_count,
        });

        msg!(
            "Withdrawal successful: {} lamports to recipient, {} fee to validator {}",
            payout,
            fee,
            validator_account.validator
        );
        Ok(())
    }

    /// Settle a shielded → shielded transfer **without releasing funds**.
    ///
    /// Unlike `withdraw`, which always pays a recipient, a transfer spends
    /// two input notes and creates two output notes that stay inside the
    /// privacy pool. The program therefore:
    ///  1. Records both input nullifiers as PDAs (`seeds = [b"nullifier",
    ///     nullifier]`) — the same namespace `withdraw` uses, so a note can
    ///     never be spent twice across either path. Anchor's `init` fails if
    ///     a nullifier PDA already exists, which is the cross-transaction
    ///     double-spend defense.
    ///  2. Advances the Merkle root to the value the consensus leader
    ///     computed after appending the two output commitments (the same
    ///     off-chain-root model as `deposit` + `update_merkle_root`).
    ///
    /// Fixed 2-in/2-out (matching `MAX_INPUTS`/`MAX_OUTPUTS` in the circuit).
    /// A single-note spend pads the second input with a random dummy
    /// nullifier, so every transaction has a uniform shape and leaks nothing
    /// about how many real notes were spent.
    ///
    /// As with `withdraw`, the Groth16 proof is verified on-chain (#194) via
    /// `alt_bn128` against the current Merkle root and the transfer's
    /// nullifiers + output commitments; the `has_one = authority` gate binds
    /// settlement to the consensus leader.
    pub fn shielded_transfer(
        ctx: Context<ShieldedTransfer>,
        nullifiers: [[u8; 32]; 2],
        output_commitments: [[u8; 32]; 2],
        new_merkle_root: [u8; 32],
        proof: Vec<u8>,
    ) -> Result<()> {
        let bridge_state = &mut ctx.accounts.bridge_state;

        require!(!bridge_state.paused, BridgeError::BridgePaused);
        require!(!proof.is_empty(), BridgeError::InvalidProof);
        require!(proof.len() <= MAX_PROOF_LEN, BridgeError::ProofTooLarge);
        // Reject non-canonical nullifiers so a spent note cannot be re-settled
        // under a different raw encoding lifting to the same field element; this
        // also keeps the distinctness check below from being bypassed by
        // `n` vs `n + p` for the same note.
        require_canonical_nullifier(&nullifiers[0])?;
        require_canonical_nullifier(&nullifiers[1])?;

        // Two equal input nullifiers would target the same PDA twice in one
        // transaction; reject with a clear error instead of Anchor's opaque
        // "account already initialized".
        require!(
            nullifiers[0] != nullifiers[1],
            BridgeError::DuplicateNullifier
        );

        // Settlement requires a supermajority of registered validators to
        // co-sign this transaction (#260) — no single key can settle alone.
        quorum::verify_validator_quorum(
            ctx.program_id,
            &ctx.accounts.validator_registry,
            ctx.remaining_accounts,
        )?;

        // Verify the Groth16 transfer proof on-chain (#194) against the current
        // (pre-update) Merkle root and the transfer's nullifiers + output
        // commitments, before recording any state. As with `withdraw`, this
        // means the settling validator cannot forge a transfer even though it
        // holds the settlement authority.
        require!(
            transfer_verifier::verify_transfer(
                &bridge_state.merkle_root,
                &nullifiers,
                &output_commitments,
                &proof,
            ),
            BridgeError::InvalidProof
        );

        let now = Clock::get()?.unix_timestamp;

        // `withdrawal_id = 0` marks these nullifiers as transfer-spent rather
        // than withdrawal-spent (transfers release nothing, so there is no
        // withdrawal id to record).
        let nullifier_account_0 = &mut ctx.accounts.nullifier_account_0;
        nullifier_account_0.nullifier = nullifiers[0];
        nullifier_account_0.used_at = now;
        nullifier_account_0.withdrawal_id = 0;

        let nullifier_account_1 = &mut ctx.accounts.nullifier_account_1;
        nullifier_account_1.nullifier = nullifiers[1];
        nullifier_account_1.used_at = now;
        nullifier_account_1.withdrawal_id = 0;

        bridge_state.merkle_root = new_merkle_root;

        emit!(ShieldedTransferEvent {
            nullifiers,
            output_commitments,
            new_merkle_root,
            timestamp: now,
        });

        msg!("Shielded transfer settled");
        Ok(())
    }

    /// Deposit an SPL token into the privacy pool (#237).
    ///
    /// The asset-aware twin of [`deposit`]: instead of moving native SOL into
    /// the single `bridge_vault`, it moves `amount` of one SPL `mint` into a
    /// per-asset vault — a program-owned `TokenAccount` PDA keyed by the mint
    /// (`seeds = [b"asset_vault", mint]`). One vault per mint keeps each
    /// asset's custody isolated; the first depositor of a mint creates the
    /// vault (`init_if_needed`) and every later deposit reuses it.
    ///
    /// The deposited `asset_id` is the mint pubkey itself (the #235 convention:
    /// an SPL asset's id == its mint's 32 bytes; native SOL is the all-zero
    /// [`NATIVE_SOL_ASSET`]). A deposit is public — it reveals which asset and
    /// how much entered the pool — exactly as the native deposit does; the
    /// shielding happens later when the note is spent under a proof.
    ///
    /// Counters and the emitted event mirror [`deposit`] so the L2 indexes SPL
    /// and native deposits through the same path; only the value-movement
    /// (system transfer -> token CPI) and the vault differ.
    pub fn deposit_spl(
        ctx: Context<DepositSpl>,
        amount: u64,
        recipient: [u8; 32],
        randomness: [u8; 32],
    ) -> Result<()> {
        let bridge_state = &mut ctx.accounts.bridge_state;

        require!(!bridge_state.paused, BridgeError::BridgePaused);
        require!(amount > 0, BridgeError::InvalidAmount);

        // Move the tokens depositor -> per-asset vault. The depositor signs
        // the transfer (it owns the source token account), so no PDA signer is
        // needed on the deposit leg.
        transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.depositor_token.to_account_info(),
                    to: ctx.accounts.asset_vault.to_account_info(),
                    authority: ctx.accounts.depositor.to_account_info(),
                },
            ),
            amount,
        )?;

        bridge_state.total_deposited += amount;
        bridge_state.deposit_count += 1;

        emit!(DepositSplEvent {
            depositor: ctx.accounts.depositor.key(),
            asset_id: ctx.accounts.mint.key().to_bytes(),
            amount,
            recipient,
            randomness,
            timestamp: Clock::get()?.unix_timestamp,
            deposit_id: bridge_state.deposit_count,
        });

        msg!(
            "SPL deposit successful: {} of mint {}",
            amount,
            ctx.accounts.mint.key()
        );
        Ok(())
    }

    /// Withdraw an SPL token from the privacy pool (#237).
    ///
    /// The asset-aware twin of [`withdraw`]: it releases `amount` of one SPL
    /// `mint` from that mint's per-asset vault to a recipient token account,
    /// applying the identical replay, expiry, and fee rules as the native
    /// path:
    ///  * the nullifier PDA (`seeds = [b"nullifier", nullifier]`) is `init`'d
    ///    here, sharing the namespace with `withdraw`/`shielded_transfer`, so a
    ///    note can never be spent twice across any path;
    ///  * the request is rejected past its `expiration_slot`;
    ///  * the same 25 bps [`WITHDRAWAL_FEE_BPS`] cut is taken — the recipient
    ///    token account receives `amount - fee`, and `fee` stays in the vault
    ///    credited to the settling validator's `pending_rewards`. Because the
    ///    fee is SPL tokens sitting in a per-asset vault rather than lamports,
    ///    `pending_rewards` accrues in that asset's smallest unit;
    ///    `claim_rewards` for SPL fees is a follow-up (this PR keeps fee
    ///    accounting at parity with the native path).
    ///
    /// Value leaves the vault under a PDA signer (`asset_vault_authority`, the
    /// token account's owner), not the depositor. As with the native `withdraw`,
    /// settlement requires a validator quorum (#260) and the Groth16 proof is
    /// verified on-chain (#165) against the published Merkle root.
    pub fn withdraw_spl(
        ctx: Context<WithdrawSpl>,
        nullifier: [u8; 32],
        amount: u64,
        expiration_slot: u64,
        proof: Vec<u8>,
    ) -> Result<()> {
        let bridge_state = &mut ctx.accounts.bridge_state;

        require!(!bridge_state.paused, BridgeError::BridgePaused);
        require!(amount > 0, BridgeError::InvalidAmount);
        require!(!proof.is_empty(), BridgeError::InvalidProof);
        require!(proof.len() <= MAX_PROOF_LEN, BridgeError::ProofTooLarge);

        let current_slot = Clock::get()?.slot;
        require!(
            current_slot <= expiration_slot,
            BridgeError::WithdrawalExpired
        );

        // Reject a non-canonical nullifier (same replay defence as the native
        // withdraw); the raw bytes must canonically encode their field element.
        require_canonical_nullifier(&nullifier)?;

        // Settlement requires a supermajority of registered validators to
        // co-sign this transaction (#260), exactly as the native `withdraw` —
        // no single key can drain a per-asset vault alone.
        quorum::verify_validator_quorum(
            ctx.program_id,
            &ctx.accounts.validator_registry,
            ctx.remaining_accounts,
        )?;

        // Verify the Groth16 withdrawal proof on-chain (#165), bound to the
        // published Merkle root and this withdrawal's nullifier + amount, so a
        // settling validator cannot release tokens for a note that does not
        // exist. (Notes of every asset share the off-chain commitment tree and
        // the published `merkle_root`.)
        require!(
            withdraw_verifier::verify_withdrawal(
                &bridge_state.merkle_root,
                &nullifier,
                amount,
                &proof,
            ),
            BridgeError::InvalidProof
        );

        require!(
            ctx.accounts.asset_vault.amount >= amount,
            BridgeError::InsufficientFunds
        );

        // Same fee/validator binding as the native withdraw: the settling
        // validator is bound by seeds to the `authority` signer and earns the
        // fee for gathering quorum and submitting the withdrawal.
        let validator_account = &mut ctx.accounts.validator_account;
        require!(validator_account.is_active, BridgeError::ValidatorNotActive);

        let fee = amount
            .checked_mul(WITHDRAWAL_FEE_BPS)
            .and_then(|v| v.checked_div(10_000))
            .ok_or(BridgeError::InvalidAmount)?;
        let payout = amount - fee;

        let nullifier_account = &mut ctx.accounts.nullifier_account;
        nullifier_account.nullifier = nullifier;
        nullifier_account.used_at = Clock::get()?.unix_timestamp;
        nullifier_account.withdrawal_id = bridge_state.withdrawal_count + 1;

        // The vault's token authority is the program PDA `asset_vault_authority`;
        // it signs the release. The fee tokens are left behind in the vault.
        let authority_bump = ctx.bumps.asset_vault_authority;
        let seeds = &[b"asset_vault_authority".as_ref(), &[authority_bump]];
        let signer_seeds = &[&seeds[..]];

        transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.asset_vault.to_account_info(),
                    to: ctx.accounts.recipient_token.to_account_info(),
                    authority: ctx.accounts.asset_vault_authority.to_account_info(),
                },
                signer_seeds,
            ),
            payout,
        )?;

        // Credit the retained fee to the settling validator and record the
        // settlement against its activity — parity with the native path.
        validator_account.pending_rewards += fee;
        validator_account.successful_verifications += 1;
        validator_account.last_active = Clock::get()?.unix_timestamp;

        bridge_state.total_withdrawn += amount;
        bridge_state.withdrawal_count += 1;

        emit!(WithdrawalSplEvent {
            recipient: ctx.accounts.recipient_token.key(),
            asset_id: ctx.accounts.mint.key().to_bytes(),
            amount,
            nullifier,
            timestamp: Clock::get()?.unix_timestamp,
            withdrawal_id: bridge_state.withdrawal_count,
        });

        msg!(
            "SPL withdrawal successful: {} of mint {} to recipient, {} fee to validator {}",
            payout,
            ctx.accounts.mint.key(),
            fee,
            validator_account.validator
        );
        Ok(())
    }

    /// Pause the bridge
    pub fn pause(ctx: Context<Pause>) -> Result<()> {
        let bridge_state = &mut ctx.accounts.bridge_state;
        bridge_state.paused = true;

        msg!("Bridge paused");
        Ok(())
    }

    /// Unpause the bridge
    pub fn unpause(ctx: Context<Pause>) -> Result<()> {
        let bridge_state = &mut ctx.accounts.bridge_state;
        bridge_state.paused = false;

        msg!("Bridge unpaused");
        Ok(())
    }

    /// Rotate the bridge settlement authority to a new key.
    ///
    /// `initialize` (#204) pins the bridge authority to the program's upgrade
    /// authority at genesis, to close the init front-run race. But ongoing
    /// settlement (`withdraw` / `shielded_transfer` / `update_merkle_root`,
    /// all `has_one = authority`) is performed by a node-resident validator
    /// key — which must NOT be the upgrade authority sitting on a public
    /// host. This hands settlement control from the genesis authority to the
    /// operating validator (a staked, slashable key), keeping the upgrade
    /// authority offline. Gated `has_one = authority`: only the current
    /// authority can rotate it.
    pub fn set_bridge_authority(
        ctx: Context<SetBridgeAuthority>,
        new_authority: Pubkey,
    ) -> Result<()> {
        let bridge_state = &mut ctx.accounts.bridge_state;
        let previous = bridge_state.authority;
        bridge_state.authority = new_authority;

        msg!(
            "Bridge authority rotated: {} -> {}",
            previous,
            new_authority
        );
        Ok(())
    }

    /// Register a validator
    pub fn register_validator(ctx: Context<RegisterValidator>, stake_amount: u64) -> Result<()> {
        require!(
            stake_amount >= MIN_VALIDATOR_STAKE,
            BridgeError::InsufficientStake
        );

        let validator_account = &mut ctx.accounts.validator_account;
        let validator_registry = &mut ctx.accounts.validator_registry;

        let transfer_ix = anchor_lang::solana_program::system_instruction::transfer(
            &ctx.accounts.validator.key(),
            &validator_account.to_account_info().key(),
            stake_amount,
        );

        anchor_lang::solana_program::program::invoke(
            &transfer_ix,
            &[
                ctx.accounts.validator.to_account_info(),
                validator_account.to_account_info(),
                ctx.accounts.system_program.to_account_info(),
            ],
        )?;

        validator_account.validator = ctx.accounts.validator.key();
        validator_account.stake_amount = stake_amount;
        validator_account.reputation_score = 1000;
        validator_account.total_tasks_verified = 0;
        validator_account.successful_verifications = 0;
        validator_account.registered_at = Clock::get()?.unix_timestamp;
        validator_account.last_active = Clock::get()?.unix_timestamp;
        validator_account.is_active = true;
        validator_account.pending_rewards = 0;
        validator_account.total_earnings = 0;
        validator_account.times_slashed = 0;

        validator_registry.total_validators += 1;
        validator_registry.active_validators += 1;

        emit!(ValidatorRegisteredEvent {
            validator: ctx.accounts.validator.key(),
            stake_amount,
            timestamp: Clock::get()?.unix_timestamp,
        });

        msg!(
            "Validator registered: {} with stake {}",
            ctx.accounts.validator.key(),
            stake_amount
        );
        Ok(())
    }

    /// Unregister a validator
    pub fn unregister_validator(ctx: Context<UnregisterValidator>) -> Result<()> {
        let validator_account = &mut ctx.accounts.validator_account;
        let validator_registry = &mut ctx.accounts.validator_registry;

        require!(validator_account.is_active, BridgeError::ValidatorNotActive);

        let stake_amount = validator_account.stake_amount;
        **validator_account
            .to_account_info()
            .try_borrow_mut_lamports()? -= stake_amount;
        **ctx
            .accounts
            .validator
            .to_account_info()
            .try_borrow_mut_lamports()? += stake_amount;

        validator_account.is_active = false;
        // Stake lamports were just returned to the wallet; zero the recorded
        // amount so `status`/`list` and the explorer don't show a phantom
        // stake on an unregistered account.
        validator_account.stake_amount = 0;

        validator_registry.active_validators -= 1;

        emit!(ValidatorUnregisteredEvent {
            validator: ctx.accounts.validator.key(),
            stake_returned: stake_amount,
            timestamp: Clock::get()?.unix_timestamp,
        });

        msg!("Validator unregistered: {}", ctx.accounts.validator.key());
        Ok(())
    }

    /// Update validator reputation
    pub fn update_reputation(
        ctx: Context<UpdateReputation>,
        validator: Pubkey,
        new_reputation: u64,
    ) -> Result<()> {
        let validator_account = &mut ctx.accounts.validator_account;

        require!(
            validator_account.validator == validator,
            BridgeError::InvalidValidator
        );
        require!(validator_account.is_active, BridgeError::ValidatorNotActive);

        validator_account.reputation_score = new_reputation;
        validator_account.last_active = Clock::get()?.unix_timestamp;

        msg!(
            "Validator reputation updated: {} -> {}",
            validator,
            new_reputation
        );
        Ok(())
    }

    /// Distribute withdrawal fee to leader
    pub fn distribute_fee(
        ctx: Context<DistributeFee>,
        leader: Pubkey,
        fee_amount: u64,
    ) -> Result<()> {
        let validator_account = &mut ctx.accounts.validator_account;

        require!(
            validator_account.validator == leader,
            BridgeError::InvalidValidator
        );
        require!(validator_account.is_active, BridgeError::ValidatorNotActive);

        validator_account.pending_rewards += fee_amount;

        msg!(
            "Fee distributed to leader {}: {} lamports",
            leader,
            fee_amount
        );
        Ok(())
    }

    /// Claim pending rewards
    pub fn claim_rewards(ctx: Context<ClaimRewards>) -> Result<()> {
        let validator_account = &mut ctx.accounts.validator_account;

        require!(
            validator_account.pending_rewards > 0,
            BridgeError::InvalidAmount
        );

        let reward_amount = validator_account.pending_rewards;

        let vault_bump = ctx.bumps.bridge_vault;
        let seeds = &[b"bridge_vault".as_ref(), &[vault_bump]];
        let signer_seeds = &[&seeds[..]];

        anchor_lang::system_program::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.to_account_info(),
                anchor_lang::system_program::Transfer {
                    from: ctx.accounts.bridge_vault.to_account_info(),
                    to: ctx.accounts.validator.to_account_info(),
                },
                signer_seeds,
            ),
            reward_amount,
        )?;

        validator_account.pending_rewards = 0;
        validator_account.total_earnings += reward_amount;

        emit!(RewardClaimedEvent {
            validator: ctx.accounts.validator.key(),
            amount: reward_amount,
            timestamp: Clock::get()?.unix_timestamp,
        });

        msg!("Rewards claimed: {} lamports", reward_amount);
        Ok(())
    }

    /// Slash validator
    pub fn slash_validator(
        ctx: Context<SlashValidator>,
        validator: Pubkey,
        slash_percentage: u8, // 1-100
    ) -> Result<()> {
        let validator_account = &mut ctx.accounts.validator_account;

        require!(
            validator_account.validator == validator,
            BridgeError::InvalidValidator
        );
        require!(
            slash_percentage > 0 && slash_percentage <= 100,
            BridgeError::InvalidAmount
        );

        let slash_amount =
            (validator_account.stake_amount as u128 * slash_percentage as u128 / 100) as u64;

        let old_stake = validator_account.stake_amount;
        validator_account.stake_amount =
            validator_account.stake_amount.saturating_sub(slash_amount);
        validator_account.times_slashed += 1;

        **validator_account
            .to_account_info()
            .try_borrow_mut_lamports()? -= slash_amount;
        **ctx
            .accounts
            .bridge_vault
            .to_account_info()
            .try_borrow_mut_lamports()? += slash_amount;

        emit!(ValidatorSlashedEvent {
            validator,
            slash_amount,
            slash_percentage,
            old_stake,
            new_stake: validator_account.stake_amount,
            timestamp: Clock::get()?.unix_timestamp,
        });

        msg!(
            "Validator slashed: {} ({}% = {} lamports)",
            validator,
            slash_percentage,
            slash_amount
        );
        Ok(())
    }

    /// Initialize validator registry
    pub fn initialize_validator_registry(ctx: Context<InitializeValidatorRegistry>) -> Result<()> {
        check_upgrade_authority(&ctx.accounts.program_data, &ctx.accounts.authority.key())?;
        let registry = &mut ctx.accounts.validator_registry;
        registry.authority = ctx.accounts.authority.key();
        registry.total_validators = 0;
        registry.active_validators = 0;
        registry.minimum_stake = MIN_VALIDATOR_STAKE;

        msg!("Validator registry initialized");
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + BridgeState::INIT_SPACE,
        seeds = [b"bridge_state"],
        bump
    )]
    pub bridge_state: Account<'info, BridgeState>,

    #[account(mut)]
    pub authority: Signer<'info>,

    /// Program's BPFLoaderUpgradeable `ProgramData` account (#204). Binds
    /// `initialize` to the program's upgrade authority — without this gate
    /// anyone could win the race between `program deploy` and the first
    /// `initialize` call and permanently become `bridge_state.authority`
    /// (no `set_authority` instruction exists). The seeds constraint pins
    /// this account to the canonical PDA derived under BPFLoaderUpgradeable;
    /// the upgrade-authority match is verified inside the instruction body
    /// via [`check_upgrade_authority`].
    ///
    /// CHECK: validated by seeds + `check_upgrade_authority` body call.
    #[account(
        seeds = [crate::ID.as_ref()],
        bump,
        seeds::program = bpf_loader_upgradeable::id(),
    )]
    pub program_data: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(
        mut,
        seeds = [b"bridge_state"],
        bump
    )]
    pub bridge_state: Account<'info, BridgeState>,

    #[account(
        mut,
        seeds = [b"bridge_vault"],
        bump
    )]
    pub bridge_vault: SystemAccount<'info>,

    #[account(mut)]
    pub depositor: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(nullifier: [u8; 32])]
pub struct Withdraw<'info> {
    // `has_one = authority` binds the signer to the authority recorded at
    // `initialize` (the bridge authority / consensus leader). Without it any
    // signer could settle a withdrawal — see #178.
    #[account(
        mut,
        seeds = [b"bridge_state"],
        bump,
        has_one = authority
    )]
    pub bridge_state: Account<'info, BridgeState>,

    #[account(
        mut,
        seeds = [b"bridge_vault"],
        bump
    )]
    pub bridge_vault: SystemAccount<'info>,

    /// Nullifier account
    #[account(
        init,
        payer = authority,
        space = 8 + NullifierAccount::INIT_SPACE,
        seeds = [b"nullifier", nullifier.as_ref()],
        bump
    )]
    pub nullifier_account: Account<'info, NullifierAccount>,

    #[account(mut)]
    pub recipient: SystemAccount<'info>,

    // The settling validator's on-chain account, bound by seeds to the
    // `authority` signer: only a registered validator can settle a
    // withdrawal, and the withdrawal fee is credited here. The PDA must
    // already exist (the validator registered via `register_validator`),
    // so `withdraw` fails for any signer without a validator account.
    #[account(
        mut,
        seeds = [b"validator", authority.key().as_ref()],
        bump
    )]
    pub validator_account: Account<'info, ValidatorAccount>,

    /// The validator registry; its `active_validators` count sets the quorum
    /// threshold (#260). Settlement must be co-signed by a supermajority of
    /// registered validators, passed as `(wallet, validator PDA)` pairs in
    /// `remaining_accounts`.
    #[account(seeds = [b"validator_registry"], bump)]
    pub validator_registry: Account<'info, ValidatorRegistry>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(nullifiers: [[u8; 32]; 2])]
pub struct ShieldedTransfer<'info> {
    // `has_one = authority` binds settlement to the bridge authority /
    // consensus leader, exactly as `Withdraw` does (#178).
    #[account(
        mut,
        seeds = [b"bridge_state"],
        bump,
        has_one = authority
    )]
    pub bridge_state: Account<'info, BridgeState>,

    /// First input nullifier. Shares the `b"nullifier"` namespace with
    /// `withdraw`, so `init` fails on a replay across either path.
    #[account(
        init,
        payer = authority,
        space = 8 + NullifierAccount::INIT_SPACE,
        seeds = [b"nullifier", nullifiers[0].as_ref()],
        bump
    )]
    pub nullifier_account_0: Account<'info, NullifierAccount>,

    /// Second input nullifier (a random dummy when only one real note is
    /// spent).
    #[account(
        init,
        payer = authority,
        space = 8 + NullifierAccount::INIT_SPACE,
        seeds = [b"nullifier", nullifiers[1].as_ref()],
        bump
    )]
    pub nullifier_account_1: Account<'info, NullifierAccount>,

    /// Validator registry; sets the quorum threshold (#260). The transfer must
    /// be co-signed by a supermajority of registered validators, passed as
    /// `(wallet, validator PDA)` pairs in `remaining_accounts`.
    #[account(seeds = [b"validator_registry"], bump)]
    pub validator_registry: Account<'info, ValidatorRegistry>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct DepositSpl<'info> {
    #[account(
        mut,
        seeds = [b"bridge_state"],
        bump
    )]
    pub bridge_state: Account<'info, BridgeState>,

    /// The SPL mint being deposited. Its pubkey IS the asset id (#235).
    pub mint: Account<'info, Mint>,

    /// Program-owned PDA that owns every per-asset vault. A single
    /// deterministic authority for all asset vaults; it never signs on the
    /// deposit leg (the depositor signs that), but it is set as the vault's
    /// `authority` here so the withdraw leg can sign releases.
    ///
    /// CHECK: a PDA used only as the token-account authority; constrained by
    /// its seeds. Holds no data and is never deserialized.
    #[account(
        seeds = [b"asset_vault_authority"],
        bump
    )]
    pub asset_vault_authority: UncheckedAccount<'info>,

    /// The per-asset vault: a program-owned token account for this one mint.
    /// `init_if_needed` so the first depositor of a mint creates it and every
    /// later deposit reuses it. Owned by `asset_vault_authority`.
    #[account(
        init_if_needed,
        payer = depositor,
        token::mint = mint,
        token::authority = asset_vault_authority,
        seeds = [b"asset_vault", mint.key().as_ref()],
        bump
    )]
    pub asset_vault: Account<'info, TokenAccount>,

    /// The depositor's source token account for `mint`.
    #[account(
        mut,
        token::mint = mint,
        token::authority = depositor
    )]
    pub depositor_token: Account<'info, TokenAccount>,

    #[account(mut)]
    pub depositor: Signer<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
#[instruction(nullifier: [u8; 32])]
pub struct WithdrawSpl<'info> {
    // `has_one = authority` binds the signer to the bridge authority recorded
    // at `initialize` — same #178 settlement guard as the native withdraw.
    #[account(
        mut,
        seeds = [b"bridge_state"],
        bump,
        has_one = authority
    )]
    pub bridge_state: Account<'info, BridgeState>,

    /// The SPL mint being withdrawn. Its pubkey IS the asset id (#235) and
    /// keys the vault PDA below.
    pub mint: Account<'info, Mint>,

    /// Program PDA that owns the vault and signs the release.
    ///
    /// CHECK: a PDA used only as the token-account authority; constrained by
    /// its seeds. Holds no data and is never deserialized.
    #[account(
        seeds = [b"asset_vault_authority"],
        bump
    )]
    pub asset_vault_authority: UncheckedAccount<'info>,

    /// The per-asset vault tokens are released from. Must already exist (a
    /// deposit created it); keyed by the mint exactly as `DepositSpl`.
    #[account(
        mut,
        token::mint = mint,
        token::authority = asset_vault_authority,
        seeds = [b"asset_vault", mint.key().as_ref()],
        bump
    )]
    pub asset_vault: Account<'info, TokenAccount>,

    /// Nullifier account — shares the `b"nullifier"` namespace with the native
    /// `withdraw` and `shielded_transfer`, so `init` fails on a replay across
    /// any path.
    #[account(
        init,
        payer = authority,
        space = 8 + NullifierAccount::INIT_SPACE,
        seeds = [b"nullifier", nullifier.as_ref()],
        bump
    )]
    pub nullifier_account: Account<'info, NullifierAccount>,

    /// The recipient's destination token account for `mint`.
    #[account(
        mut,
        token::mint = mint
    )]
    pub recipient_token: Account<'info, TokenAccount>,

    // The settling validator's account, bound by seeds to the `authority`
    // signer — same binding and fee-crediting as the native withdraw.
    #[account(
        mut,
        seeds = [b"validator", authority.key().as_ref()],
        bump
    )]
    pub validator_account: Account<'info, ValidatorAccount>,

    /// The validator registry, against which the settlement quorum is verified
    /// (#260) — same gate as the native `withdraw`. The co-signers are passed as
    /// `(wallet, validator PDA)` pairs in `remaining_accounts`.
    #[account(seeds = [b"validator_registry"], bump)]
    pub validator_registry: Account<'info, ValidatorRegistry>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Pause<'info> {
    #[account(
        mut,
        seeds = [b"bridge_state"],
        bump,
        has_one = authority
    )]
    pub bridge_state: Account<'info, BridgeState>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct SetBridgeAuthority<'info> {
    #[account(
        mut,
        seeds = [b"bridge_state"],
        bump,
        has_one = authority
    )]
    pub bridge_state: Account<'info, BridgeState>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct UpdateMerkleRoot<'info> {
    #[account(
        mut,
        seeds = [b"bridge_state"],
        bump,
        has_one = authority
    )]
    pub bridge_state: Account<'info, BridgeState>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeValidatorRegistry<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + ValidatorRegistry::INIT_SPACE,
        seeds = [b"validator_registry"],
        bump
    )]
    pub validator_registry: Account<'info, ValidatorRegistry>,

    #[account(mut)]
    pub authority: Signer<'info>,

    /// Same upgrade-authority gate as `Initialize` (#204) — closes the init
    /// front-run race for the validator registry.
    ///
    /// CHECK: validated by seeds + `check_upgrade_authority` body call.
    #[account(
        seeds = [crate::ID.as_ref()],
        bump,
        seeds::program = bpf_loader_upgradeable::id(),
    )]
    pub program_data: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RegisterValidator<'info> {
    #[account(
        init,
        payer = validator,
        space = 8 + ValidatorAccount::INIT_SPACE,
        seeds = [b"validator", validator.key().as_ref()],
        bump
    )]
    pub validator_account: Account<'info, ValidatorAccount>,

    #[account(
        mut,
        seeds = [b"validator_registry"],
        bump
    )]
    pub validator_registry: Account<'info, ValidatorRegistry>,

    #[account(mut)]
    pub validator: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UnregisterValidator<'info> {
    #[account(
        mut,
        seeds = [b"validator", validator.key().as_ref()],
        bump,
        has_one = validator
    )]
    pub validator_account: Account<'info, ValidatorAccount>,

    #[account(
        mut,
        seeds = [b"validator_registry"],
        bump
    )]
    pub validator_registry: Account<'info, ValidatorRegistry>,

    #[account(mut)]
    pub validator: Signer<'info>,
}

#[derive(Accounts)]
pub struct UpdateReputation<'info> {
    #[account(
        mut,
        seeds = [b"validator", validator_account.validator.as_ref()],
        bump
    )]
    pub validator_account: Account<'info, ValidatorAccount>,

    #[account(
        seeds = [b"validator_registry"],
        bump,
        has_one = authority
    )]
    pub validator_registry: Account<'info, ValidatorRegistry>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct DistributeFee<'info> {
    #[account(
        mut,
        seeds = [b"validator", validator_account.validator.as_ref()],
        bump
    )]
    pub validator_account: Account<'info, ValidatorAccount>,

    #[account(
        seeds = [b"validator_registry"],
        bump,
        has_one = authority
    )]
    pub validator_registry: Account<'info, ValidatorRegistry>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct ClaimRewards<'info> {
    #[account(
        mut,
        seeds = [b"validator", validator.key().as_ref()],
        bump,
        has_one = validator
    )]
    pub validator_account: Account<'info, ValidatorAccount>,

    #[account(
        mut,
        seeds = [b"bridge_vault"],
        bump
    )]
    pub bridge_vault: SystemAccount<'info>,

    #[account(mut)]
    pub validator: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SlashValidator<'info> {
    #[account(
        mut,
        seeds = [b"validator", validator_account.validator.as_ref()],
        bump
    )]
    pub validator_account: Account<'info, ValidatorAccount>,

    #[account(
        mut,
        seeds = [b"bridge_vault"],
        bump
    )]
    pub bridge_vault: SystemAccount<'info>,

    #[account(
        seeds = [b"validator_registry"],
        bump,
        has_one = authority
    )]
    pub validator_registry: Account<'info, ValidatorRegistry>,

    pub authority: Signer<'info>,
}

#[account]
#[derive(InitSpace)]
pub struct BridgeState {
    /// Semver-encoded program version: major(8) | minor(8) | patch(8) |
    /// reserved(8). v0.4.0 → 0x00040000. Placed first so the L2 can
    /// read it from the raw account at a fixed offset (8 + 0..4) after
    /// Anchor's 8-byte account discriminator, without deserialising
    /// the rest of the struct.
    pub program_version: u32,
    pub authority: Pubkey,
    pub total_deposited: u64,
    pub total_withdrawn: u64,
    pub deposit_count: u64,
    pub withdrawal_count: u64,
    pub paused: bool,
    pub merkle_root: [u8; 32],
}

#[account]
#[derive(InitSpace)]
pub struct NullifierAccount {
    pub nullifier: [u8; 32],
    pub used_at: i64,
    pub withdrawal_id: u64,
}

#[account]
#[derive(InitSpace)]
pub struct ValidatorRegistry {
    pub authority: Pubkey,
    pub total_validators: u64,
    pub active_validators: u64,
    pub minimum_stake: u64,
}

#[account]
#[derive(InitSpace)]
pub struct ValidatorAccount {
    pub validator: Pubkey,
    pub stake_amount: u64,
    pub reputation_score: u64,
    pub total_tasks_verified: u64,
    pub successful_verifications: u64,
    pub registered_at: i64,
    pub last_active: i64,
    pub is_active: bool,
    pub pending_rewards: u64,
    pub total_earnings: u64,
    pub times_slashed: u64,
}

#[event]
pub struct DepositEvent {
    pub depositor: Pubkey,
    pub amount: u64,
    pub recipient: [u8; 32],
    pub randomness: [u8; 32],
    pub timestamp: i64,
    pub deposit_id: u64,
}

#[event]
pub struct WithdrawalEvent {
    pub recipient: Pubkey,
    pub amount: u64,
    pub nullifier: [u8; 32],
    pub timestamp: i64,
    pub withdrawal_id: u64,
}

#[event]
pub struct DepositSplEvent {
    pub depositor: Pubkey,
    /// The deposited asset's id == the SPL mint's pubkey bytes (#235).
    pub asset_id: [u8; 32],
    pub amount: u64,
    pub recipient: [u8; 32],
    pub randomness: [u8; 32],
    pub timestamp: i64,
    pub deposit_id: u64,
}

#[event]
pub struct WithdrawalSplEvent {
    /// The recipient's destination token account.
    pub recipient: Pubkey,
    /// The withdrawn asset's id == the SPL mint's pubkey bytes (#235).
    pub asset_id: [u8; 32],
    pub amount: u64,
    pub nullifier: [u8; 32],
    pub timestamp: i64,
    pub withdrawal_id: u64,
}

#[event]
pub struct ShieldedTransferEvent {
    pub nullifiers: [[u8; 32]; 2],
    pub output_commitments: [[u8; 32]; 2],
    pub new_merkle_root: [u8; 32],
    pub timestamp: i64,
}

#[event]
pub struct ValidatorRegisteredEvent {
    pub validator: Pubkey,
    pub stake_amount: u64,
    pub timestamp: i64,
}

#[event]
pub struct ValidatorUnregisteredEvent {
    pub validator: Pubkey,
    pub stake_returned: u64,
    pub timestamp: i64,
}

#[event]
pub struct ValidatorSlashedEvent {
    pub validator: Pubkey,
    pub slash_amount: u64,
    pub slash_percentage: u8,
    pub old_stake: u64,
    pub new_stake: u64,
    pub timestamp: i64,
}

#[event]
pub struct RewardClaimedEvent {
    pub validator: Pubkey,
    pub amount: u64,
    pub timestamp: i64,
}

#[error_code]
pub enum BridgeError {
    #[msg("Bridge is paused")]
    BridgePaused,

    #[msg("Invalid amount")]
    InvalidAmount,

    #[msg("Invalid proof")]
    InvalidProof,

    #[msg("Proof exceeds maximum length")]
    ProofTooLarge,

    #[msg("Insufficient funds in bridge")]
    InsufficientFunds,

    #[msg("Nullifier already used")]
    NullifierAlreadyUsed,

    #[msg("Insufficient stake amount")]
    InsufficientStake,

    #[msg("Validator not active")]
    ValidatorNotActive,

    #[msg("Invalid validator")]
    InvalidValidator,

    #[msg("Withdrawal request expired (current slot > expiration_slot)")]
    WithdrawalExpired,

    #[msg("Duplicate input nullifier in transfer")]
    DuplicateNullifier,

    #[msg("Nullifier is not a canonical field element (>= BN254 scalar modulus)")]
    NonCanonicalNullifier,

    #[msg("Initialize signer must be the program's upgrade authority")]
    UnauthorizedInit,

    #[msg("Validator quorum not met for settlement")]
    QuorumNotMet,
}
