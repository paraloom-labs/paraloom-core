//! Paraloom Solana Program
//!
//! Handles deposits into and withdrawals from the Paraloom privacy layer

use anchor_lang::prelude::*;

declare_id!("DSysqF2oYAuDRLfPajMnRULce2MjC3AtTszCkcDv1jco");

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

    /// Update Merkle root (called by authority when new deposits are processed)
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
    /// User sends SOL, receives shielded note off-chain
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
    /// User provides zkSNARK proof, receives SOL
    /// NOTE: Nullifier account is initialized via `init` constraint in Withdraw struct.
    /// If nullifier already exists, transaction will fail (prevents double-spending).
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

        // Mark nullifier as used
        let nullifier_account = &mut ctx.accounts.nullifier_account;
        nullifier_account.nullifier = nullifier;
        nullifier_account.used_at = Clock::get()?.unix_timestamp;
        nullifier_account.withdrawal_id = bridge_state.withdrawal_count + 1;

        // Transfer SOL from vault to recipient
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

    /// Pause the bridge (emergency)
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

    /// Nullifier account - must not exist (prevents double-spending)
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
}
