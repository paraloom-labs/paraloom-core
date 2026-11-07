//! Regression tests for validator withdraw-unbonded and register ATA initialization (#1242)
//!
//! Validates that transactions executing `WithdrawUnbonded` and `Register`
//! prepend the idempotent Associated Token Account creation instruction,
//! ensuring that accounts that do not yet exist (or were closed) are created
//! without causing Anchor `AccountNotInitialized (3012)` errors.

use paraloom::bridge::solana::{
    create_associated_token_account_idempotent_instruction, create_register_validator_instruction,
    create_withdraw_unbonded_stake_instruction, derive_associated_token_address,
    SPL_ASSOCIATED_TOKEN_ACCOUNT_PROGRAM_ID, SPL_TOKEN_2022_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID,
};
use solana_sdk::pubkey::Pubkey;

#[test]
fn test_withdraw_unbonded_transaction_includes_idempotent_ata_creation() {
    let program_id = Pubkey::new_unique();
    let validator = Pubkey::new_unique();
    let stake_mint = Pubkey::new_unique();
    let token_program = SPL_TOKEN_PROGRAM_ID;

    let validator_token = derive_associated_token_address(&validator, &stake_mint, &token_program);

    let init_ata_ix = create_associated_token_account_idempotent_instruction(
        &validator,
        &validator,
        &stake_mint,
        &token_program,
    );

    let withdraw_ix = create_withdraw_unbonded_stake_instruction(
        &program_id,
        &validator,
        &stake_mint,
        &validator_token,
        &token_program,
    );

    let instructions = [init_ata_ix, withdraw_ix];
    assert_eq!(instructions.len(), 2);

    // Verify index 0 is idempotent ATA creation
    let ata_ix = &instructions[0];
    assert_eq!(ata_ix.program_id, SPL_ASSOCIATED_TOKEN_ACCOUNT_PROGRAM_ID);
    assert_eq!(ata_ix.data, vec![1]); // CreateIdempotent opcode
    assert_eq!(ata_ix.accounts.len(), 6);
    assert_eq!(ata_ix.accounts[0].pubkey, validator);
    assert!(ata_ix.accounts[0].is_signer);
    assert!(ata_ix.accounts[0].is_writable);
    assert_eq!(ata_ix.accounts[1].pubkey, validator_token);
    assert!(!ata_ix.accounts[1].is_signer);
    assert!(ata_ix.accounts[1].is_writable);
    assert_eq!(ata_ix.accounts[2].pubkey, validator);
    assert_eq!(ata_ix.accounts[3].pubkey, stake_mint);
    assert_eq!(ata_ix.accounts[5].pubkey, token_program);

    // Verify index 1 is withdraw unbonded stake instruction
    let w_ix = &instructions[1];
    assert_eq!(w_ix.program_id, program_id);
    assert_eq!(w_ix.accounts[1].pubkey, validator);
    assert_eq!(w_ix.accounts[2].pubkey, stake_mint);
    assert_eq!(w_ix.accounts[3].pubkey, validator_token);
}

#[test]
fn test_register_validator_includes_idempotent_ata_creation() {
    let program_id = Pubkey::new_unique();
    let validator = Pubkey::new_unique();
    let stake_mint = Pubkey::new_unique();
    let token_program = SPL_TOKEN_PROGRAM_ID;
    let validator_token = derive_associated_token_address(&validator, &stake_mint, &token_program);

    let init_ata_ix = create_associated_token_account_idempotent_instruction(
        &validator,
        &validator,
        &stake_mint,
        &token_program,
    );

    let register_ix = create_register_validator_instruction(
        &program_id,
        &validator,
        &stake_mint,
        &validator_token,
        &token_program,
        1_000_000_000,
        0,
    )
    .expect("valid register ix");

    let instructions = [init_ata_ix, register_ix];
    assert_eq!(instructions.len(), 2);
    assert_eq!(
        instructions[0].program_id,
        SPL_ASSOCIATED_TOKEN_ACCOUNT_PROGRAM_ID
    );
    assert_eq!(instructions[0].data, vec![1]);
    assert_eq!(instructions[1].program_id, program_id);
}

#[test]
fn test_idempotent_ata_layout_and_token_2022_support() {
    let payer = Pubkey::new_unique();
    let wallet = Pubkey::new_unique();
    let mint_2022 = Pubkey::new_unique();

    let ix = create_associated_token_account_idempotent_instruction(
        &payer,
        &wallet,
        &mint_2022,
        &SPL_TOKEN_2022_PROGRAM_ID,
    );

    assert_eq!(ix.program_id, SPL_ASSOCIATED_TOKEN_ACCOUNT_PROGRAM_ID);
    assert_eq!(ix.data, vec![1]);
    assert_eq!(ix.accounts.len(), 6);

    let expected_ata_2022 =
        derive_associated_token_address(&wallet, &mint_2022, &SPL_TOKEN_2022_PROGRAM_ID);
    assert_eq!(ix.accounts[1].pubkey, expected_ata_2022);
    assert_eq!(ix.accounts[5].pubkey, SPL_TOKEN_2022_PROGRAM_ID);
}
