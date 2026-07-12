//! Paraloom Solana Program
//!
//! Handles deposits into and withdrawals from the Paraloom privacy layer

use anchor_lang::prelude::*;
use anchor_lang::solana_program::bpf_loader_upgradeable;

mod groth16;
pub mod merkle_tree;
mod quorum;
pub mod transact_fixture_data;
mod transact_verifier;
mod transact_vk_data;

declare_id!("8gPsRSm1CAw38mfzc1bcLMUXyFN7LnS8k6CV5hPUTWrP");

pub const MIN_VALIDATOR_STAKE: u64 = 1_000_000_000; // 1 SOL for devnet testing

/// Slots a validator's stake stays locked after it unregisters (or is slashed
/// below the minimum) before it can be withdrawn. ~1 day at ~2.5 slots/s. The
/// window keeps the stake reachable by slashing while any misbehavior it
/// co-signed can still be proven, so quorum stake is real at-risk capital and
/// not free to weaponize (register → co-sign → instantly unregister).
pub const UNBONDING_SLOTS: u64 = 216_000;

/// Upper bound on the settlement proof blob. A BN254 Groth16 proof in the
/// `alt_bn128` wire form is exactly 256 bytes (see
/// [`transact_verifier::WIRE_PROOF_LEN`]); the cap rejects oversized blobs that
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
    require_canonical_field(nullifier, BridgeError::NonCanonicalNullifier)
}

/// Reject a 32-byte value that is not the canonical little-endian encoding of
/// its reduced BN254 scalar field element. `Fr::from_le_bytes_mod_order` is
/// non-injective (it maps both `n` and `n + p` to the same element), so any
/// value later keyed on its raw bytes, appended to the tree, or matched against
/// a stored root must be canonical for the byte↔field correspondence the
/// off-chain verifier maintains to hold on chain as well.
fn require_canonical_field(value: &[u8; 32], error: BridgeError) -> Result<()> {
    use ark_ff::{BigInteger, PrimeField};
    let reduced = ark_bn254::Fr::from_le_bytes_mod_order(value);
    let canonical = reduced.into_bigint().to_bytes_le();
    // `require!` only accepts a literal error variant, so return explicitly to
    // let the caller pass the field-specific error code.
    if canonical.as_slice() != value.as_slice() {
        return Err(error.into());
    }
    Ok(())
}

/// Asset id of native SOL (#235): the all-zero 32 bytes. SPL assets use their
/// mint's pubkey bytes instead.
pub const NATIVE_SOL_ASSET: [u8; 32] = [0u8; 32];

/// External-data hash binding a `transact` settlement to its destination and
/// signed external amount (circuit v3, finding D). The prover computes the
/// same hash off-chain and feeds it as the `ext_data_hash` public input, so a
/// settling validator cannot redirect the payout or change the amount even
/// though it holds the settlement authority.
fn transact_ext_data_hash(recipient: &Pubkey, ext_amount: i64) -> [u8; 32] {
    anchor_lang::solana_program::hash::hashv(&[recipient.as_ref(), &ext_amount.to_le_bytes()])
        .to_bytes()
}

/// Little-endian BN254 field encoding of the signed `ext_amount`, matching the
/// circuit's `public_amount` (`sumOut - sumIn`): a withdrawal (`ext_amount <
/// 0`) encodes as `p - |ext_amount|`. Deriving `public_amount` on-chain from
/// `ext_amount` — instead of accepting it as a free argument — binds the funds
/// actually moved to the balance the owner proved. A free `public_amount`
/// would let a submitter prove a small net spend yet withdraw a larger
/// `ext_amount`, stealing the difference.
fn public_amount_bytes(ext_amount: i64) -> [u8; 32] {
    use ark_ff::{BigInteger, PrimeField};
    let magnitude = ark_bn254::Fr::from(ext_amount.unsigned_abs());
    let field = if ext_amount < 0 {
        -magnitude
    } else {
        magnitude
    };
    let mut out = [0u8; 32];
    let le = field.into_bigint().to_bytes_le();
    out[..le.len()].copy_from_slice(&le);
    out
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

    /// Deposit SOL and append the resulting note commitment to the on-chain
    /// tree (circuit v3, #350).
    ///
    /// The v3 deposit: moves `amount` into the vault and appends the note
    /// commitment — computed on-chain as `Poseidon(4)([amount, pubkey, blinding,
    /// asset])` — to the program-owned Merkle tree. Computing the commitment
    /// here binds the appended leaf to the amount actually deposited, so a
    /// depositor cannot append a leaf claiming more value than it paid in. The
    /// emitted event carries the leaf index so the wallet learns where its note
    /// landed. Permissionless (the depositor's own funds), no proof or quorum —
    /// a deposit only *adds* value and creates a note the depositor controls.
    pub fn deposit_note(
        ctx: Context<DepositNote>,
        amount: u64,
        pubkey: [u8; 32],
        blinding: [u8; 32],
    ) -> Result<()> {
        require!(!ctx.accounts.bridge_state.paused, BridgeError::BridgePaused);
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

        let commitment =
            crate::merkle_tree::commitment(amount, &pubkey, &blinding, &NATIVE_SOL_ASSET)?;
        let mut tree = ctx.accounts.merkle_tree.load_mut()?;
        let leaf_index = tree.next_index;
        tree.append(commitment)?;

        let bridge_state = &mut ctx.accounts.bridge_state;
        bridge_state.total_deposited = bridge_state
            .total_deposited
            .checked_add(amount)
            .ok_or(BridgeError::InvalidAmount)?;
        bridge_state.deposit_count = bridge_state.deposit_count.saturating_add(1);

        emit!(DepositNoteEvent {
            depositor: ctx.accounts.depositor.key(),
            amount,
            commitment,
            leaf_index,
            timestamp: Clock::get()?.unix_timestamp,
        });

        msg!("Deposit note appended at leaf {}", leaf_index);
        Ok(())
    }

    /// Unified v3 settlement: spend two input notes, create two output notes,
    /// and move `ext_amount` lamports across the pool boundary (#350).
    ///
    /// This is the circuit-v3 money path. Unlike `withdraw`/`shielded_transfer`
    /// (which advance an *off-chain* root the leader supplies), `transact`
    /// proves membership against the program's own on-chain incremental tree
    /// and appends the two output commitments itself, so the tree the proof is
    /// checked against and the tree the outputs land in are the same account —
    /// an attacker cannot cite a root the program never published (audit #1).
    ///
    /// `ext_amount` is the signed external flow: `< 0` withdraws `|ext_amount|`
    /// from the vault to `recipient` (minus the validator fee), `== 0` is a
    /// pure shielded transfer that moves no external funds. Deposits keep using
    /// `deposit_note`, so `ext_amount > 0` is rejected here.
    ///
    /// Settlement is quorum-gated exactly like `withdraw` (#260): the signer
    /// must be a registered validator and a supermajority of validators must
    /// co-sign, passed as `(wallet, validator PDA)` pairs in
    /// `remaining_accounts`. No single key can settle alone.
    pub fn transact(
        ctx: Context<Transact>,
        nullifiers: [[u8; 32]; 2],
        output_commitments: [[u8; 32]; 2],
        root: [u8; 32],
        ext_amount: i64,
        proof: Vec<u8>,
    ) -> Result<()> {
        let bridge_state = &mut ctx.accounts.bridge_state;

        require!(!bridge_state.paused, BridgeError::BridgePaused);
        require!(!proof.is_empty(), BridgeError::InvalidProof);
        require!(proof.len() <= MAX_PROOF_LEN, BridgeError::ProofTooLarge);

        // Deposits are public and go through `deposit_note`; `transact` only
        // spends existing notes (withdraw or internal transfer).
        require!(ext_amount <= 0, BridgeError::InvalidAmount);

        // Both nullifiers must be canonical field elements and distinct. The
        // circuit already enforces distinctness, and the two nullifier PDAs
        // are `init`ed (so a repeat across transactions fails), but rejecting a
        // duplicate here gives a clear error instead of a PDA collision.
        require_canonical_nullifier(&nullifiers[0])?;
        require_canonical_nullifier(&nullifiers[1])?;
        require!(
            nullifiers[0] != nullifiers[1],
            BridgeError::DuplicateNullifier
        );

        // Parity with the off-chain verifier: the output commitments and the
        // tree root are BN254 field elements, so reject any non-canonical
        // encoding before it is proof-checked, appended to the tree, or matched
        // against the root ring buffer. Not security-critical on its own
        // (commitments are not PDA seeds like nullifiers, and `is_known_root`
        // already rejects an unknown root), but it fails fast and keeps the
        // on-chain input validation at parity with off-chain. (#418)
        require_canonical_field(
            &output_commitments[0],
            BridgeError::NonCanonicalFieldElement,
        )?;
        require_canonical_field(
            &output_commitments[1],
            BridgeError::NonCanonicalFieldElement,
        )?;
        require_canonical_field(&root, BridgeError::NonCanonicalFieldElement)?;

        // The proof proves the spent notes are members of `root`; that root
        // must be one the program actually published (ring buffer), so a spend
        // cannot be proven against a fabricated tree state (audit #1).
        require!(
            ctx.accounts.merkle_tree.load()?.is_known_root(root),
            BridgeError::UnknownMerkleRoot
        );

        // Bind the settlement to the recipient and signed amount (finding D),
        // and derive `public_amount` from `ext_amount` so the funds moved can
        // never exceed the balance the owner proved (see `public_amount_bytes`).
        let ext_data_hash = transact_ext_data_hash(&ctx.accounts.recipient.key(), ext_amount);
        let public_amount = public_amount_bytes(ext_amount);

        // Supermajority co-sign (#260) — no single key settles.
        quorum::verify_validator_quorum(
            ctx.program_id,
            &ctx.accounts.validator_registry,
            // The settling `authority` is excluded from its own quorum, so a
            // supermajority of *independent* validator stake must co-sign.
            &ctx.accounts.authority.key(),
            if ctx.accounts.validator_account.is_active {
                ctx.accounts.validator_account.stake_amount
            } else {
                0
            },
            ctx.remaining_accounts,
        )?;

        // Verify the v3 Groth16 proof against the eight public inputs, in the
        // circuit's `new_input` order.
        require!(
            transact_verifier::verify_transact(
                &root,
                &public_amount,
                &ext_data_hash,
                &NATIVE_SOL_ASSET,
                &nullifiers[0],
                &nullifiers[1],
                &output_commitments[0],
                &output_commitments[1],
                &proof,
            ),
            BridgeError::InvalidProof
        );

        // Record both input nullifiers (double-spend defense). The PDAs are
        // `init`ed in `Transact`, so a note already spent on either the
        // `withdraw`, `shielded_transfer` or `transact` path fails here.
        let now = Clock::get()?.unix_timestamp;
        let settlement_id = bridge_state.withdrawal_count.saturating_add(1);
        let nf0 = &mut ctx.accounts.nullifier_account_0;
        nf0.nullifier = nullifiers[0];
        nf0.used_at = now;
        nf0.withdrawal_id = settlement_id;
        let nf1 = &mut ctx.accounts.nullifier_account_1;
        nf1.nullifier = nullifiers[1];
        nf1.used_at = now;
        nf1.withdrawal_id = settlement_id;

        // Append both output commitments to the on-chain tree. `root` (the
        // pre-append root the proof was checked against) is untouched; the new
        // notes extend the tree for future spends.
        let mut tree = ctx.accounts.merkle_tree.load_mut()?;
        tree.append(output_commitments[0])?;
        let new_root = tree.append(output_commitments[1])?;
        drop(tree);

        // Move external funds. `ext_amount < 0` withdraws from the vault; the
        // settling validator earns the same 25 bps fee as `withdraw`.
        let validator_account = &mut ctx.accounts.validator_account;
        require!(validator_account.is_active, BridgeError::ValidatorNotActive);

        let mut fee = 0u64;
        if ext_amount < 0 {
            let gross = ext_amount.unsigned_abs();
            let vault_balance = ctx.accounts.bridge_vault.lamports();
            require!(vault_balance >= gross, BridgeError::InsufficientFunds);

            fee = gross
                .checked_mul(WITHDRAWAL_FEE_BPS)
                .and_then(|v| v.checked_div(10_000))
                .ok_or(BridgeError::InvalidAmount)?;
            let payout = gross - fee;

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
            validator_account.pending_rewards = validator_account
                .pending_rewards
                .checked_add(fee)
                .ok_or(BridgeError::InvalidAmount)?;

            // Maintain the public withdrawal-volume aggregate, mirroring
            // `total_deposited` on the deposit side. Checked, though a vault
            // balance this large is unreachable.
            bridge_state.total_withdrawn = bridge_state
                .total_withdrawn
                .checked_add(gross)
                .ok_or(BridgeError::InvalidAmount)?;
        }

        // Every settled transact is one verified task; keep the pair
        // (`total_tasks_verified`, `successful_verifications`) both live so a
        // derived success rate is well-defined rather than dividing by zero.
        validator_account.total_tasks_verified =
            validator_account.total_tasks_verified.saturating_add(1);
        validator_account.successful_verifications =
            validator_account.successful_verifications.saturating_add(1);
        validator_account.last_active = now;
        // NOTE: this is the monotonic *settlement* counter (it seeds
        // `settlement_id` for every transact, including pure shielded transfers
        // where `ext_amount == 0`), not a count of withdrawals only.
        bridge_state.withdrawal_count = settlement_id;

        emit!(TransactEvent {
            nullifier0: nullifiers[0],
            nullifier1: nullifiers[1],
            out_commitment0: output_commitments[0],
            out_commitment1: output_commitments[1],
            new_root,
            ext_amount,
            fee,
            recipient: ctx.accounts.recipient.key(),
            timestamp: now,
            settlement_id,
        });

        msg!(
            "Transact settled: ext_amount {}, fee {} to validator {}",
            ext_amount,
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
    /// settlement (`transact`, `has_one = authority`) is performed by a
    /// node-resident validator key — which must NOT be the upgrade authority
    /// sitting on a public
    /// host. This hands settlement control from the genesis authority to the
    /// operating validator (a staked, slashable key), keeping the upgrade
    /// authority offline. Gated on the COLD registry authority (not the current
    /// bridge authority), so the cold key always manages the hot settlement key
    /// and a compromised hot key cannot rotate control away.
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

        validator_registry.total_validators = validator_registry.total_validators.saturating_add(1);
        validator_registry.active_validators =
            validator_registry.active_validators.saturating_add(1);
        validator_registry.total_active_stake = validator_registry
            .total_active_stake
            .saturating_add(stake_amount);

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
        // Deactivate immediately so the validator stops counting toward the
        // settlement quorum at once (preserving the invariant
        // `total_active_stake == Σ active-PDA stake`), but do NOT return the
        // lamports yet: they enter an unbonding window during which the stake
        // is still slashable, and are released by `withdraw_unbonded_stake`
        // after `UNBONDING_SLOTS`. This makes quorum stake real at-risk capital
        // rather than something an attacker can register, co-sign with, and
        // instantly reclaim.
        let now_slot = Clock::get()?.slot;
        validator_account.is_active = false;
        validator_account.stake_amount = 0;
        validator_account.unbonding_amount = validator_account
            .unbonding_amount
            .saturating_add(stake_amount);
        validator_account.unbonding_slot = now_slot.saturating_add(UNBONDING_SLOTS);

        validator_registry.active_validators =
            validator_registry.active_validators.saturating_sub(1);
        validator_registry.total_active_stake = validator_registry
            .total_active_stake
            .saturating_sub(stake_amount);

        emit!(ValidatorUnregisteredEvent {
            validator: ctx.accounts.validator.key(),
            // Nothing is returned now — the stake is unbonding.
            stake_returned: 0,
            timestamp: Clock::get()?.unix_timestamp,
        });

        msg!(
            "Validator unregistered; stake unbonding until slot {}: {}",
            validator_account.unbonding_slot,
            ctx.accounts.validator.key()
        );
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
        validator_account.total_earnings = validator_account
            .total_earnings
            .checked_add(reward_amount)
            .ok_or(BridgeError::InvalidAmount)?;

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

        // Slash the stake that is actually at risk: the active stake for a
        // live validator, or the unbonding balance if the validator has already
        // left the active set. Basing an inactive slash on `unbonding_amount`
        // (rather than the recorded `stake_amount`, which is zeroed on exit)
        // keeps stake slashable through the unbonding window and means a
        // phantom `stake_amount` on an inactive account is never charged — so a
        // rent-only PDA cannot be made to debit more lamports than it holds.
        // `old_stake` here is the pre-slash at-risk amount: active stake for a
        // live validator, or the unbonding balance once it has left the set.
        let old_stake = if validator_account.is_active {
            validator_account.stake_amount
        } else {
            validator_account.unbonding_amount
        };
        let slash_amount = (old_stake as u128 * slash_percentage as u128 / 100) as u64;
        validator_account.times_slashed = validator_account.times_slashed.saturating_add(1);

        if validator_account.is_active {
            validator_account.stake_amount = old_stake.saturating_sub(slash_amount);
            // A slash that drops stake below the registry minimum deactivates
            // the validator: registration requires `stake >= minimum_stake`, so
            // a validator below that bar must stop settling and stop counting
            // toward the BFT quorum.
            if validator_account.stake_amount < ctx.accounts.validator_registry.minimum_stake {
                validator_account.is_active = false;
                let registry = &mut ctx.accounts.validator_registry;
                registry.active_validators = registry.active_validators.saturating_sub(1);
                registry.total_active_stake = registry.total_active_stake.saturating_sub(old_stake);
                // The unslashed remainder would otherwise be stranded — a
                // deactivated validator cannot `unregister` — so route it into
                // unbonding, reclaimable after the delay. The slashed portion
                // has already gone to the vault below.
                let residual = validator_account.stake_amount;
                validator_account.unbonding_amount =
                    validator_account.unbonding_amount.saturating_add(residual);
                validator_account.unbonding_slot =
                    Clock::get()?.slot.saturating_add(UNBONDING_SLOTS);
                validator_account.stake_amount = 0;
            } else {
                // Still active: only the slashed portion leaves the total.
                let registry = &mut ctx.accounts.validator_registry;
                registry.total_active_stake =
                    registry.total_active_stake.saturating_sub(slash_amount);
            }
        } else {
            // Already unbonding: burn the slashed portion of the withheld stake.
            validator_account.unbonding_amount = validator_account
                .unbonding_amount
                .saturating_sub(slash_amount);
        }

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
        registry.total_active_stake = 0;

        msg!("Validator registry initialized");
        Ok(())
    }

    /// Initialize the on-chain commitment Merkle tree (circuit v3, #350).
    ///
    /// Creates the program-owned tree account and seeds it with the empty-tree
    /// state. Gated to the program's upgrade authority, like the other
    /// `initialize_*` instructions (#204). After this the `transact` path
    /// appends output commitments and recomputes the root on-chain, so no
    /// settled transaction can install an attacker-chosen root.
    pub fn initialize_merkle_tree(ctx: Context<InitializeMerkleTree>) -> Result<()> {
        check_upgrade_authority(&ctx.accounts.program_data, &ctx.accounts.authority.key())?;
        ctx.accounts.merkle_tree.load_init()?.initialize()?;
        msg!("Merkle tree initialized");
        Ok(())
    }

    /// Migrate and reset the validator registry for the ceremony-key redeploy.
    ///
    /// The registry PDA deployed before the stake-weighted quorum (#329) is 8
    /// bytes shorter than the current [`ValidatorRegistry`] layout, so the
    /// redeployed program cannot even load it as a typed account. This
    /// one-shot instruction — gated to the program's upgrade authority, like
    /// [`initialize`] (#204) — grows the PDA to the current size and rebuilds
    /// its counters from EXACTLY the active validator accounts passed in
    /// `remaining_accounts`: the real co-signer set for the redeployed program.
    /// Stale registrations are dropped simply by not being passed, so the
    /// stake-weighted quorum denominator reflects only validators that actually
    /// co-sign. Validator stake and the validator PDAs themselves are untouched.
    ///
    /// The account is taken untyped ([`UncheckedAccount`]) precisely because
    /// the pre-migration bytes do not deserialize into the current struct; its
    /// address is pinned by the seeds constraint and its identity re-checked
    /// against the `ValidatorRegistry` discriminator in the body.
    ///
    /// PRECONDITION — pass every currently-active validator PDA. An `is_active`
    /// PDA left out of `remaining_accounts` is NOT deactivated here; it stays
    /// active on-chain but uncounted, which drives the stake-weighted quorum
    /// denominator stale-low and, if that orphan later co-signs, trips the
    /// `counted_stake <= eligible_stake` check (settlement bricks — fail-closed,
    /// never a theft). Completeness cannot be enforced on-chain (the program
    /// cannot enumerate all PDAs), so it is the upgrade authority's
    /// responsibility; reconcile any active-but-excluded PDA with
    /// [`deactivate_validator`] before relying on the rebuilt denominator.
    pub fn reset_validator_registry(ctx: Context<ResetValidatorRegistry>) -> Result<()> {
        check_upgrade_authority(&ctx.accounts.program_data, &ctx.accounts.authority.key())?;

        let registry_ai = ctx.accounts.validator_registry.to_account_info();

        // Confirm the pinned PDA actually is a ValidatorRegistry, so a wrong
        // account cannot be reshaped into one.
        {
            let data = registry_ai.try_borrow_data()?;
            require!(data.len() >= 8, BridgeError::UnauthorizedInit);
            require!(
                data[0..8] == *ValidatorRegistry::DISCRIMINATOR,
                BridgeError::UnauthorizedInit
            );
        }

        // Grow to the current layout, topping up rent for the extra bytes.
        let new_len = 8 + ValidatorRegistry::INIT_SPACE;
        let rent = Rent::get()?;
        let min_balance = rent.minimum_balance(new_len);
        let current = registry_ai.lamports();
        if min_balance > current {
            let delta = min_balance - current;
            let ix = anchor_lang::solana_program::system_instruction::transfer(
                &ctx.accounts.authority.key(),
                &registry_ai.key(),
                delta,
            );
            anchor_lang::solana_program::program::invoke(
                &ix,
                &[
                    ctx.accounts.authority.to_account_info(),
                    registry_ai.clone(),
                    ctx.accounts.system_program.to_account_info(),
                ],
            )?;
        }
        registry_ai.resize(new_len)?;

        // Rebuild counters from the passed active validator PDAs.
        let mut total_active_stake: u64 = 0;
        let mut active: u64 = 0;
        let mut seen: Vec<Pubkey> = Vec::new();
        for acc in ctx.remaining_accounts.iter() {
            require!(acc.owner == &crate::ID, BridgeError::UnauthorizedInit);
            let data = acc.try_borrow_data()?;
            require!(data.len() >= 8, BridgeError::UnauthorizedInit);
            require!(
                data[0..8] == *ValidatorAccount::DISCRIMINATOR,
                BridgeError::UnauthorizedInit
            );
            let validator = ValidatorAccount::try_deserialize(&mut &data[..])?;
            // The PDA must be the canonical account for the key it claims.
            let (expected, _) = Pubkey::find_program_address(
                &[b"validator", validator.validator.as_ref()],
                &crate::ID,
            );
            require!(&expected == acc.key, BridgeError::UnauthorizedInit);
            require!(validator.is_active, BridgeError::UnauthorizedInit);
            // Reject a PDA passed twice so it cannot double-count into the stake
            // total and inflate the quorum denominator.
            require!(!seen.contains(acc.key), BridgeError::UnauthorizedInit);
            seen.push(*acc.key);
            total_active_stake = total_active_stake.saturating_add(validator.stake_amount);
            active = active.saturating_add(1);
        }

        // Write the rebuilt registry.
        let registry = ValidatorRegistry {
            authority: ctx.accounts.authority.key(),
            total_validators: active,
            active_validators: active,
            minimum_stake: MIN_VALIDATOR_STAKE,
            total_active_stake,
        };
        let mut data = registry_ai.try_borrow_mut_data()?;
        let mut cursor = std::io::Cursor::new(&mut data[..]);
        registry.try_serialize(&mut cursor)?;

        msg!(
            "Validator registry reset: {} active validators, {} total stake",
            active,
            total_active_stake
        );
        Ok(())
    }

    /// Deactivate a single validator so it can no longer be counted toward the
    /// settlement quorum, keeping the registry invariant
    /// `total_active_stake == Σ active-PDA stake` intact. Admin-only (the
    /// registry authority). This reconciles validators dropped from the active
    /// set — e.g. `is_active` PDAs left behind by an earlier
    /// `reset_validator_registry` that rebuilt the counters but did not
    /// deactivate the excluded accounts, which would otherwise still clear a
    /// stale-low quorum denominator. It does not move the staked lamports; those
    /// are returned through `unregister_validator`.
    pub fn deactivate_validator(ctx: Context<DeactivateValidator>) -> Result<()> {
        let was_active = ctx.accounts.validator_account.is_active;
        let stake = ctx.accounts.validator_account.stake_amount;
        let who = ctx.accounts.validator_account.validator;
        if was_active {
            let now_slot = Clock::get()?.slot;
            let v = &mut ctx.accounts.validator_account;
            v.is_active = false;
            // Route the stake into unbonding rather than stranding it: a
            // deactivated validator can't `unregister` (that requires
            // is_active), so without this its lamports would have no exit and be
            // frozen forever. Reclaimable via `withdraw_unbonded_stake` after
            // the delay, same as unregister.
            v.unbonding_amount = v.unbonding_amount.saturating_add(stake);
            v.unbonding_slot = now_slot.saturating_add(UNBONDING_SLOTS);
            v.stake_amount = 0;
            let registry = &mut ctx.accounts.validator_registry;
            registry.total_active_stake = registry.total_active_stake.saturating_sub(stake);
            registry.active_validators = registry.active_validators.saturating_sub(1);
        }
        msg!("Validator deactivated: {}", who);
        Ok(())
    }

    /// Withdraw stake that has finished unbonding. Self-signed; returns the
    /// withheld `unbonding_amount` from the validator PDA to the wallet once
    /// `unbonding_slot` has passed. The registry counters were already updated
    /// when the stake left the active set (unregister / deactivating slash), so
    /// this only moves lamports.
    ///
    /// This is the validator's true end of life, so the PDA is `close`d here:
    /// its rent is refunded to the wallet and the `[b"validator", wallet]`
    /// address is freed, so the same wallet can `register_validator` again later
    /// (#392 — the `init` in `RegisterValidator` would otherwise fail with
    /// `AccountAlreadyInUse` against the leftover husk, and its rent stayed
    /// locked). Only reachable once the stake has unbonded, which only happens
    /// after the validator has left the active set (`unbonding_amount > 0`
    /// implies `!is_active`), so an active validator's PDA is never closed out
    /// from under it.
    pub fn withdraw_unbonded_stake(ctx: Context<WithdrawUnbondedStake>) -> Result<()> {
        let validator_account = &mut ctx.accounts.validator_account;
        let amount = validator_account.unbonding_amount;
        require!(amount > 0, BridgeError::NothingUnbonding);
        require!(
            Clock::get()?.slot >= validator_account.unbonding_slot,
            BridgeError::UnbondingNotElapsed
        );
        // The staked lamports live in the PDA itself; `unbonding_amount` is
        // always the delta above the account's rent-exempt minimum, so this
        // debit cannot drop the PDA below rent exemption.
        **validator_account
            .to_account_info()
            .try_borrow_mut_lamports()? -= amount;
        **ctx
            .accounts
            .validator
            .to_account_info()
            .try_borrow_mut_lamports()? += amount;
        validator_account.unbonding_amount = 0;

        emit!(UnbondedStakeWithdrawnEvent {
            validator: validator_account.validator,
            amount,
            timestamp: Clock::get()?.unix_timestamp,
        });
        msg!(
            "Unbonded stake withdrawn: {} ({} lamports)",
            validator_account.validator,
            amount
        );
        Ok(())
    }

    /// One-time migration: grow an existing `ValidatorAccount` PDA to the
    /// current layout. The added unbonding fields zero-fill (resize clears the
    /// tail), which reads as "nothing pending". Upgrade-authority gated (#204),
    /// mirroring the registry migration; idempotent (a no-op once the account
    /// is already the new size).
    pub fn migrate_validator_account(
        ctx: Context<MigrateValidatorAccount>,
        _validator: Pubkey,
    ) -> Result<()> {
        check_upgrade_authority(&ctx.accounts.program_data, &ctx.accounts.authority.key())?;
        let ai = ctx.accounts.validator_account.to_account_info();
        {
            let data = ai.try_borrow_data()?;
            require!(data.len() >= 8, BridgeError::UnauthorizedInit);
            require!(
                data[0..8] == *ValidatorAccount::DISCRIMINATOR,
                BridgeError::UnauthorizedInit
            );
        }
        let new_len = 8 + ValidatorAccount::INIT_SPACE;
        let old_len = ai.data_len();
        if old_len < new_len {
            let rent = Rent::get()?;
            // Top up the INCREMENTAL rent for the added bytes, unconditionally.
            // A `min_balance(new_len) > current` guard never fires on a staked
            // PDA (the stake dwarfs the rent delta), which would leave the
            // account funded only to the OLD rent floor once the stake is
            // withdrawn — reverting a later `withdraw_unbonded_stake` or a full
            // slash for dropping below rent-exemption. Adding the delta keeps
            // the stake fully withdrawable on top of the new rent floor.
            let extra_rent = rent
                .minimum_balance(new_len)
                .saturating_sub(rent.minimum_balance(old_len));
            if extra_rent > 0 {
                let ix = anchor_lang::solana_program::system_instruction::transfer(
                    &ctx.accounts.authority.key(),
                    &ai.key(),
                    extra_rent,
                );
                anchor_lang::solana_program::program::invoke(
                    &ix,
                    &[
                        ctx.accounts.authority.to_account_info(),
                        ai.clone(),
                        ctx.accounts.system_program.to_account_info(),
                    ],
                )?;
            }
            ai.resize(new_len)?;
        }
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
pub struct DepositNote<'info> {
    #[account(mut, seeds = [b"bridge_state"], bump)]
    pub bridge_state: Account<'info, BridgeState>,

    #[account(mut, seeds = [b"bridge_vault"], bump)]
    pub bridge_vault: SystemAccount<'info>,

    #[account(mut, seeds = [b"merkle_tree"], bump)]
    pub merkle_tree: AccountLoader<'info, crate::merkle_tree::IncrementalMerkleTree>,

    #[account(mut)]
    pub depositor: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ResetValidatorRegistry<'info> {
    /// The registry PDA. Taken untyped because the pre-migration bytes are a
    /// byte shorter than the current `ValidatorRegistry` and would fail typed
    /// deserialization; the body reallocs it and re-checks its discriminator.
    ///
    /// CHECK: address pinned by seeds; identity + realloc validated in the body.
    #[account(mut, seeds = [b"validator_registry"], bump)]
    pub validator_registry: UncheckedAccount<'info>,

    #[account(mut)]
    pub authority: Signer<'info>,

    /// Upgrade-authority gate (#204), same as `Initialize` /
    /// `InitializeValidatorRegistry`.
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
#[instruction(nullifiers: [[u8; 32]; 2])]
pub struct Transact<'info> {
    // `has_one = authority` binds settlement to the bridge authority /
    // consensus leader, exactly as `Withdraw` does (#178).
    #[account(
        mut,
        seeds = [b"bridge_state"],
        bump,
        has_one = authority
    )]
    pub bridge_state: Account<'info, BridgeState>,

    /// The on-chain incremental tree the proof proves membership against and
    /// the two output commitments are appended to (#350).
    #[account(
        mut,
        seeds = [b"merkle_tree"],
        bump
    )]
    pub merkle_tree: AccountLoader<'info, merkle_tree::IncrementalMerkleTree>,

    #[account(
        mut,
        seeds = [b"bridge_vault"],
        bump
    )]
    pub bridge_vault: SystemAccount<'info>,

    /// First input nullifier. Shares the `b"nullifier"` namespace with
    /// `withdraw`/`shielded_transfer`, so `init` fails on a replay across any
    /// spend path.
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

    /// Destination for a withdrawal (`ext_amount < 0`). Bound into the proof
    /// via `ext_data_hash`, so the settling validator cannot redirect it.
    #[account(mut)]
    pub recipient: SystemAccount<'info>,

    /// The settling validator's account, bound by seeds to the `authority`
    /// signer: only a registered validator can settle, and the fee is credited
    /// here (mirrors `Withdraw`).
    #[account(
        mut,
        seeds = [b"validator", authority.key().as_ref()],
        bump
    )]
    pub validator_account: Account<'info, ValidatorAccount>,

    /// Validator registry; sets the quorum threshold (#260). Settlement must be
    /// co-signed by a supermajority, passed as `(wallet, validator PDA)` pairs
    /// in `remaining_accounts`.
    #[account(seeds = [b"validator_registry"], bump)]
    pub validator_registry: Account<'info, ValidatorRegistry>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Pause<'info> {
    #[account(
        mut,
        seeds = [b"bridge_state"],
        bump
    )]
    pub bridge_state: Account<'info, BridgeState>,

    // Freeze/rotate power is gated on the COLD registry authority, NOT the hot
    // `bridge_state.authority` (the node-resident settlement key). Settlement
    // (`transact`) stays bound to the hot key but is quorum-gated; pause/unpause
    // and rotation are not quorum-gated, so a compromise of the deliberately-hot
    // key must not be able to freeze the bridge or rotate itself in. Requiring
    // the cold authority keeps those capabilities off the settlement host.
    #[account(
        seeds = [b"validator_registry"],
        bump,
        has_one = authority
    )]
    pub validator_registry: Account<'info, ValidatorRegistry>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct SetBridgeAuthority<'info> {
    #[account(
        mut,
        seeds = [b"bridge_state"],
        bump
    )]
    pub bridge_state: Account<'info, BridgeState>,

    // Rotation is a cold-authority operation (see `Pause`): the cold registry
    // authority manages the hot settlement key, so a compromised hot key cannot
    // rotate control away and lock out recovery.
    #[account(
        seeds = [b"validator_registry"],
        bump,
        has_one = authority
    )]
    pub validator_registry: Account<'info, ValidatorRegistry>,

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
pub struct InitializeMerkleTree<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + crate::merkle_tree::MERKLE_TREE_SIZE,
        seeds = [b"merkle_tree"],
        bump
    )]
    pub merkle_tree: AccountLoader<'info, crate::merkle_tree::IncrementalMerkleTree>,

    #[account(mut)]
    pub authority: Signer<'info>,

    /// Upgrade-authority gate (#204), same as the other `initialize_*`.
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
pub struct DeactivateValidator<'info> {
    #[account(
        mut,
        seeds = [b"validator", validator_account.validator.as_ref()],
        bump
    )]
    pub validator_account: Account<'info, ValidatorAccount>,

    #[account(
        mut,
        seeds = [b"validator_registry"],
        bump,
        has_one = authority
    )]
    pub validator_registry: Account<'info, ValidatorRegistry>,

    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct WithdrawUnbondedStake<'info> {
    #[account(
        mut,
        seeds = [b"validator", validator.key().as_ref()],
        bump,
        has_one = validator,
        close = validator
    )]
    pub validator_account: Account<'info, ValidatorAccount>,

    #[account(mut)]
    pub validator: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(validator: Pubkey)]
pub struct MigrateValidatorAccount<'info> {
    /// The validator PDA to grow. Untyped because pre-migration bytes are
    /// shorter than the current `ValidatorAccount`; the body re-checks the
    /// discriminator and reallocs.
    ///
    /// CHECK: address pinned by seeds; identity + realloc validated in the body.
    #[account(mut, seeds = [b"validator", validator.as_ref()], bump)]
    pub validator_account: UncheckedAccount<'info>,

    #[account(mut)]
    pub authority: Signer<'info>,

    /// Upgrade-authority gate (#204), same as the registry migration.
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
        mut,
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
    /// DEPRECATED / RESERVED. The legacy off-chain-root shielded path
    /// (`update_merkle_root` / `withdraw` / `shielded_transfer`) was removed;
    /// all shielded settlement now goes through `transact`, which proves
    /// membership against the program-owned incremental `merkle_tree` account
    /// and its `is_known_root` ring buffer. This field is written only once, at
    /// `initialize`, and read nowhere. It is retained solely to keep the
    /// `BridgeState` account layout byte-compatible with already-deployed
    /// state; do not reintroduce a reader.
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
    /// Sum of `stake_amount` over all currently-active validators. The BFT
    /// quorum is weighted by this (a supermajority of stake, not of head count)
    /// so a permissionless registry cannot be Sybil-forged with many tiny
    /// validators. Maintained on register / unregister / slash.
    pub total_active_stake: u64,
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
    /// Lamports withheld after `unregister_validator` or a deactivating slash,
    /// pending release by `withdraw_unbonded_stake` (0 when nothing is pending).
    pub unbonding_amount: u64,
    /// Earliest slot at which withheld `unbonding_amount` may be withdrawn.
    pub unbonding_slot: u64,
}

/// Emitted by `deposit_note` (circuit v3): the appended note commitment and its
/// tree position, so the wallet learns where its note landed.
#[event]
pub struct DepositNoteEvent {
    pub depositor: Pubkey,
    pub amount: u64,
    pub commitment: [u8; 32],
    pub leaf_index: u64,
    pub timestamp: i64,
}

#[event]
pub struct TransactEvent {
    pub nullifier0: [u8; 32],
    pub nullifier1: [u8; 32],
    pub out_commitment0: [u8; 32],
    pub out_commitment1: [u8; 32],
    pub new_root: [u8; 32],
    pub ext_amount: i64,
    pub fee: u64,
    pub recipient: Pubkey,
    pub timestamp: i64,
    pub settlement_id: u64,
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
pub struct UnbondedStakeWithdrawnEvent {
    pub validator: Pubkey,
    pub amount: u64,
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

    #[msg("Value is not a canonical field element (>= BN254 scalar modulus)")]
    NonCanonicalFieldElement,

    #[msg("Initialize signer must be the program's upgrade authority")]
    UnauthorizedInit,

    #[msg("Validator quorum not met for settlement")]
    QuorumNotMet,

    #[msg("Unbonding period has not elapsed yet")]
    UnbondingNotElapsed,

    #[msg("No unbonding stake is pending withdrawal")]
    NothingUnbonding,

    #[msg("Merkle root is not in the on-chain root history")]
    UnknownMerkleRoot,
}
