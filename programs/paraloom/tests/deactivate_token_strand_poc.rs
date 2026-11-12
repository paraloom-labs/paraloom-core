//! Regression test for Issue #1579 (Bounty 2):
//! `deactivate_validator` permanently strands dual-stake token half.
//!
//! When an admin deactivates a validator (`deactivate_validator`), the validator's
//! SOL stake was moved to `unbonding_amount`, but `token_stake_amount` was not
//! moved to `token_unbonding_amount` (and not zeroed).
//!
//! Because a deactivated validator has `is_active == false`, it is permanently
//! blocked from calling `unregister_validator`. When `withdraw_unbonded_stake` is
//! called post-delay, it only transfers `token_unbonding_amount` (which was 0)
//! and closes the validator PDA. As a result, the validator's SPL token stake
//! remained permanently trapped in `stake_token_vault` with no way to recover it,
//! and the validator suffered complete forfeiture of their token stake.
//!
//! This test reproduces and verifies the fix:
//! 1. Registers a validator with both SOL and SPL token stakes.
//! 2. Admin calls `deactivate_validator`.
//! 3. Asserts that `token_stake_amount` is zeroed and moved to `token_unbonding_amount`.
//! 4. Warps past the unbonding delay and calls `withdraw_unbonded_stake`.
//! 5. Asserts that the validator successfully reclaims their full SPL token stake,
//!    reclaims their SOL stake and rent refund, and the vault has 0 leftover stranded tokens.

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::{
    accounts, instruction, ValidatorAccount, ValidatorRegistry, MIN_VALIDATOR_STAKE,
    UNBONDING_SLOTS,
};
use solana_program_test::{processor, tokio, ProgramTest, ProgramTestContext};
use solana_sdk::{
    instruction::Instruction,
    program_pack::Pack,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

mod common;
use common::{
    add_program_data, add_stake_mint, entry, funded_validator, init_validator_registry_ix,
    register_validator_ix, stake_vault_pdas, withdraw_unbonded_ix, TEST_TOKEN_FUND,
};

const TOKEN_STAKE: u64 = paraloom_program::RECOMMENDED_MIN_TOKEN_STAKE;

async fn send(
    ctx: &mut ProgramTestContext,
    signer: &Keypair,
    ix: Instruction,
) {
    let blockhash = ctx.banks_client.get_latest_blockhash().await.unwrap();
    let mut tx = Transaction::new_with_payer(&[ix], Some(&signer.pubkey()));
    tx.sign(&[signer], blockhash);
    ctx.banks_client
        .process_transaction(tx)
        .await
        .expect("transaction must succeed");
}

async fn get_token_balance(ctx: &mut ProgramTestContext, account: Pubkey) -> u64 {
    let raw = ctx
        .banks_client
        .get_account(account)
        .await
        .unwrap()
        .expect("token account exists");
    let token = spl_token::state::Account::unpack(&raw.data).expect("unpack token account");
    token.amount
}

#[tokio::test]
async fn test_deactivate_validator_dual_stake_token_unbonding_and_withdrawal() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let stake_mint = add_stake_mint(&mut pt, upgrade_authority.pubkey());
    let (validator, validator_token) = funded_validator(&mut pt, stake_mint);
    let mut ctx = pt.start_with_context().await;

    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (vault_pda, _) = stake_vault_pdas(program_id);
    let (validator_pda, _) =
        Pubkey::find_program_address(&[b"validator", validator.pubkey().as_ref()], &program_id);

    // 1. Initialize validator registry
    send(
        &mut ctx,
        &upgrade_authority,
        init_validator_registry_ix(
            program_id,
            upgrade_authority.pubkey(),
            program_data_pda,
            stake_mint,
        ),
    )
    .await;

    // Verify initial token balance
    let initial_validator_token = get_token_balance(&mut ctx, validator_token).await;
    assert_eq!(initial_validator_token, TEST_TOKEN_FUND);

    // 2. Register validator with dual stake: SOL + SPL token
    send(
        &mut ctx,
        &validator,
        register_validator_ix(
            program_id,
            validator.pubkey(),
            stake_mint,
            validator_token,
            MIN_VALIDATOR_STAKE,
            TOKEN_STAKE,
        ),
    )
    .await;

    // Verify validator account and token vault balances post-registration
    let val_acc_raw = ctx.banks_client.get_account(validator_pda).await.unwrap().unwrap();
    let val_acc = ValidatorAccount::try_deserialize(&mut val_acc_raw.data.as_slice()).unwrap();
    assert!(val_acc.is_active);
    assert_eq!(val_acc.stake_amount, MIN_VALIDATOR_STAKE);
    assert_eq!(val_acc.token_stake_amount, TOKEN_STAKE);
    assert_eq!(val_acc.unbonding_amount, 0);
    assert_eq!(val_acc.token_unbonding_amount, 0);

    let vault_tokens = get_token_balance(&mut ctx, vault_pda).await;
    assert_eq!(vault_tokens, TOKEN_STAKE, "vault holds the deposited token stake");

    let val_tokens_after_reg = get_token_balance(&mut ctx, validator_token).await;
    assert_eq!(val_tokens_after_reg, initial_validator_token - TOKEN_STAKE);

    // 3. Admin deactivates validator
    send(
        &mut ctx,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::DeactivateValidator {}.data(),
            accounts: accounts::DeactivateValidator {
                validator_account: validator_pda,
                validator_registry: registry_pda,
                authority: upgrade_authority.pubkey(),
            }
            .to_account_metas(None),
        },
    )
    .await;

    // 4. Verify post-deactivation state:
    // Both SOL stake AND dual-stake tokens must be moved into unbonding!
    let val_acc_raw = ctx.banks_client.get_account(validator_pda).await.unwrap().unwrap();
    let val_acc = ValidatorAccount::try_deserialize(&mut val_acc_raw.data.as_slice()).unwrap();
    assert!(!val_acc.is_active, "validator must be inactive");
    assert_eq!(val_acc.stake_amount, 0, "SOL stake must be 0");
    assert_eq!(
        val_acc.unbonding_amount, MIN_VALIDATOR_STAKE,
        "SOL stake must be in unbonding_amount"
    );
    assert_eq!(
        val_acc.token_stake_amount, 0,
        "dual-stake token_stake_amount must be 0 (not left stranded)"
    );
    assert_eq!(
        val_acc.token_unbonding_amount, TOKEN_STAKE,
        "dual-stake token_stake_amount must be moved to token_unbonding_amount"
    );
    assert!(
        val_acc.unbonding_slot >= UNBONDING_SLOTS,
        "unbonding_slot must be set"
    );

    // 5. Warp slot past unbonding delay
    ctx.warp_to_slot(val_acc.unbonding_slot)
        .expect("warp to unbonding slot");

    // 6. Validator withdraws unbonded stake
    let sol_balance_before = ctx.banks_client.get_balance(validator.pubkey()).await.unwrap();
    send(
        &mut ctx,
        &validator,
        withdraw_unbonded_ix(program_id, validator.pubkey(), stake_mint, validator_token),
    )
    .await;

    // 7. Verify validator received their full token stake back
    let final_validator_tokens = get_token_balance(&mut ctx, validator_token).await;
    assert_eq!(
        final_validator_tokens, initial_validator_token,
        "validator must recover 100% of their deposited token stake"
    );

    // Verify vault is emptied of this validator's stake
    let final_vault_tokens = get_token_balance(&mut ctx, vault_pda).await;
    assert_eq!(
        final_vault_tokens, 0,
        "vault must have 0 stranded tokens left"
    );

    // Verify SOL stake returned
    let sol_balance_after = ctx.banks_client.get_balance(validator.pubkey()).await.unwrap();
    assert!(
        sol_balance_after > sol_balance_before,
        "validator received back unbonded SOL stake and PDA rent"
    );

    // Verify validator PDA was closed
    let closed_pda = ctx.banks_client.get_account(validator_pda).await.unwrap();
    assert!(
        closed_pda.is_none() || closed_pda.unwrap().lamports == 0,
        "validator PDA must be closed"
    );
}
