//! Paraloom Solana Program
//!
//! Handles deposits into and withdrawals from the Paraloom privacy layer

use anchor_lang::prelude::*;

declare_id!("DSysqF2oYAuDRLfPajMnRULce2MjC3AtTszCkcDv1jco");

pub const MIN_VALIDATOR_STAKE: u64 = 1_000_000_000; // 1 SOL for devnet testing

#[program]
pub mod paraloom_program {
    use super::*;

    /// Initialize the bridge state
    pub fn initialize(ctx: Context<Initialize>, initial_merkle_root: [u8; 32]) -> Result<()> {
        let bridge_state = &mut ctx.accounts.bridge_state;
        bridge_state.authority = ctx.accounts.authority.key();
        bridge_state.total_deposited = 0;
        bridge_state.total_withdrawn = 0;
        bridge_state.deposit_count = 0;
        bridge_state.withdrawal_count = 0;
        bridge_state.paused = false;
        bridge_state.merkle_root = initial_merkle_root;

        msg!("Bridge initialized with merkle root");
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

    /// Withdraw SOL from the privacy pool
    pub fn withdraw(
        ctx: Context<Withdraw>,
        nullifier: [u8; 32],
        amount: u64,
        proof: Vec<u8>,
    ) -> Result<()> {
        let bridge_state = &mut ctx.accounts.bridge_state;

        require!(!bridge_state.paused, BridgeError::BridgePaused);
        require!(amount > 0, BridgeError::InvalidAmount);
        require!(!proof.is_empty(), BridgeError::InvalidProof);

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
}
