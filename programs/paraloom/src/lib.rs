//! Paraloom Solana Program
//!
//! Handles deposits into and withdrawals from the Paraloom privacy layer

use anchor_lang::prelude::*;

declare_id!("DSysqF2oYAuDRLfPajMnRULce2MjC3AtTszCkcDv1jco");

pub const MIN_VALIDATOR_STAKE: u64 = 1_000_000_000; // 1 SOL for devnet testing

/// Upper bound on the withdrawal proof blob. A BLS12-381 Groth16 proof is
/// 192 bytes; the cap leaves headroom while rejecting oversized blobs that
/// would only bloat the transaction (flagged alongside #178).
pub const MAX_PROOF_LEN: usize = 256;

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
        let bridge_state = &mut ctx.accounts.bridge_state;
        bridge_state.program_version = program_version;
        bridge_state.authority = ctx.accounts.authority.key();
        bridge_state.total_deposited = 0;
        bridge_state.total_withdrawn = 0;
        bridge_state.deposit_count = 0;
        bridge_state.withdrawal_count = 0;
        bridge_state.paused = false;
        bridge_state.merkle_root = initial_merkle_root;

        msg!("Bridge initialized with merkle root, program_version={}", program_version);
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

        let vault_balance = ctx.accounts.bridge_vault.lamports();
        require!(vault_balance >= amount, BridgeError::InsufficientFunds);

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
            amount,
        )?;

        bridge_state.total_withdrawn += amount;
        bridge_state.withdrawal_count += 1;

        emit!(WithdrawalEvent {
            recipient: ctx.accounts.recipient.key(),
            amount,
            nullifier,
            timestamp: Clock::get()?.unix_timestamp,
            withdrawal_id: bridge_state.withdrawal_count,
        });

        msg!("Withdrawal successful: {} lamports", amount);
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
    /// As with `withdraw`, the Groth16 proof is recorded but **not** verified
    /// on-chain — verification is the L2 validator quorum's job (#194); the
    /// `has_one = authority` gate binds settlement to the consensus leader.
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
        // Two equal input nullifiers would target the same PDA twice in one
        // transaction; reject with a clear error instead of Anchor's opaque
        // "account already initialized".
        require!(
            nullifiers[0] != nullifiers[1],
            BridgeError::DuplicateNullifier
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
        **validator_account.to_account_info().try_borrow_mut_lamports()? -= stake_amount;
        **ctx
            .accounts
            .validator
            .to_account_info()
            .try_borrow_mut_lamports()? += stake_amount;

        validator_account.is_active = false;

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
        require!(slash_percentage > 0 && slash_percentage <= 100, BridgeError::InvalidAmount);

        let slash_amount = (validator_account.stake_amount as u128 * slash_percentage as u128 / 100) as u64;

        let old_stake = validator_account.stake_amount;
        validator_account.stake_amount = validator_account.stake_amount.saturating_sub(slash_amount);
        validator_account.times_slashed += 1;

        **validator_account.to_account_info().try_borrow_mut_lamports()? -= slash_amount;
        **ctx.accounts.bridge_vault.to_account_info().try_borrow_mut_lamports()? += slash_amount;

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

    #[account(mut)]
    pub authority: Signer<'info>,

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
}
