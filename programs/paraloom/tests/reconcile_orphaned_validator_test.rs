//! On-chain test for `reconcile_orphaned_validator` (#1625).
//!
//! Reconciles an active validator account that was left out of `reset_validator_registry`:
//! it flips `is_active` to false and routes its stake into unbonding WITHOUT
//! double-decrementing `total_active_stake` or `active_validators`.

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::{accounts, instruction, ValidatorAccount, ValidatorRegistry};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{
    account::Account, instruction::AccountMeta, instruction::Instruction, signature::Keypair,
    signature::Signer, system_program, transaction::Transaction,
};

mod common;
use common::{add_program_data, add_stake_mint, add_token_account, entry};

const MIN_VALIDATOR_STAKE: u64 = 1_000_000_000;

fn register_ix(
    program_id: Pubkey,
    registry_pda: Pubkey,
    validator: Pubkey,
    stake_mint: Pubkey,
    validator_token: Pubkey,
) -> (Instruction, Pubkey) {
    let (validator_pda, _) =
        Pubkey::find_program_address(&[b"validator", validator.as_ref()], &program_id);
    let ix = Instruction {
        program_id,
        data: instruction::RegisterValidator {
            stake_amount: MIN_VALIDATOR_STAKE,
            token_stake_amount: paraloom_program::RECOMMENDED_MIN_TOKEN_STAKE,
        }
        .data(),
        accounts: accounts::RegisterValidator {
            validator_account: validator_pda,
            validator_registry: registry_pda,
            validator,
            stake_mint,
            validator_token_account: validator_token,
            stake_token_vault: Pubkey::find_program_address(&[b"stake_token_vault"], &program_id).0,
            token_program: spl_token::id(),
            system_program: system_program::ID,
        }
        .to_account_metas(None),
    };
    (ix, validator_pda)
}

#[tokio::test]
async fn reconcile_orphaned_validator_does_not_double_decrement_registry() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);

    // Validator B: will be registered but LEFT OUT of the reset.
    let validator_b = Keypair::new();
    pt.add_account(
        validator_b.pubkey(),
        Account {
            lamports: 5 * MIN_VALIDATOR_STAKE,
            data: vec![],
            owner: system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );

    // Validator A: registered and KEPT through the reset.
    let validator_a = Keypair::new();
    pt.add_account(
        validator_a.pubkey(),
        Account {
            lamports: 5 * MIN_VALIDATOR_STAKE,
            data: vec![],
            owner: system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );

    let stake_mint = add_stake_mint(&mut pt, Pubkey::new_unique());
    let token_a = add_token_account(
        &mut pt,
        stake_mint,
        validator_a.pubkey(),
        common::TEST_TOKEN_FUND,
    );
    let token_b = add_token_account(
        &mut pt,
        stake_mint,
        validator_b.pubkey(),
        common::TEST_TOKEN_FUND,
    );

    let (mut banks, _payer, blockhash) = pt.start().await;
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);

    // Initialize registry.
    let init_ix = Instruction {
        program_id,
        data: instruction::InitializeValidatorRegistry {}.data(),
        accounts: accounts::InitializeValidatorRegistry {
            stake_mint,
            stake_token_vault: Pubkey::find_program_address(&[b"stake_token_vault"], &program_id).0,
            stake_vault_authority: Pubkey::find_program_address(
                &[b"stake_vault_authority"],
                &program_id,
            )
            .0,
            token_program: spl_token::id(),
            rent: solana_sdk::sysvar::rent::ID,
            validator_registry: registry_pda,
            authority: upgrade_authority.pubkey(),
            program_data: program_data_pda,
            system_program: system_program::ID,
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[init_ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    banks.process_transaction(tx).await.unwrap();

    // Register Validator A and Validator B.
    let (reg_a, pda_a) = register_ix(
        program_id,
        registry_pda,
        validator_a.pubkey(),
        stake_mint,
        token_a,
    );
    let mut tx = Transaction::new_with_payer(&[reg_a], Some(&validator_a.pubkey()));
    tx.sign(&[&validator_a], blockhash);
    banks.process_transaction(tx).await.unwrap();

    let (reg_b, pda_b) = register_ix(
        program_id,
        registry_pda,
        validator_b.pubkey(),
        stake_mint,
        token_b,
    );
    let mut tx = Transaction::new_with_payer(&[reg_b], Some(&validator_b.pubkey()));
    tx.sign(&[&validator_b], blockhash);
    banks.process_transaction(tx).await.unwrap();

    // Verify both are counted before reset.
    let raw = banks.get_account(registry_pda).await.unwrap().unwrap();
    let before = ValidatorRegistry::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(before.active_validators, 2);
    assert_eq!(before.total_active_stake, 2 * MIN_VALIDATOR_STAKE);

    // Reset registry keeping ONLY Validator A.
    let mut reset_metas = accounts::ResetValidatorRegistry {
        validator_registry: registry_pda,
        authority: upgrade_authority.pubkey(),
        program_data: program_data_pda,
        system_program: system_program::ID,
    }
    .to_account_metas(None);
    reset_metas.push(AccountMeta::new_readonly(pda_a, false));
    let reset_ix = Instruction {
        program_id,
        data: instruction::ResetValidatorRegistry {
            stake_mint,
            expected_active_validators: 1,
        }
        .data(),
        accounts: reset_metas,
    };
    let mut tx = Transaction::new_with_payer(&[reset_ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    banks.process_transaction(tx).await.unwrap();

    // Verify post-reset: registry only counts Validator A.
    let raw = banks.get_account(registry_pda).await.unwrap().unwrap();
    let post_reset = ValidatorRegistry::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(post_reset.active_validators, 1);
    assert_eq!(post_reset.total_active_stake, MIN_VALIDATOR_STAKE);

    // Validator B is still active on-chain (orphaned).
    let raw_b = banks.get_account(pda_b).await.unwrap().unwrap();
    let val_b_before = ValidatorAccount::try_deserialize(&mut raw_b.data.as_slice()).unwrap();
    assert!(val_b_before.is_active);
    assert_eq!(val_b_before.stake_amount, MIN_VALIDATOR_STAKE);

    // Reconcile orphaned Validator B with reconcile_orphaned_validator!
    let reconcile_ix = Instruction {
        program_id,
        data: instruction::ReconcileOrphanedValidator {}.data(),
        accounts: accounts::DeactivateValidator {
            validator_account: pda_b,
            validator_registry: registry_pda,
            authority: upgrade_authority.pubkey(),
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[reconcile_ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    banks.process_transaction(tx).await.unwrap();

    // Verify Validator B is now deactivated and unbonding (funds safe).
    let raw_b = banks.get_account(pda_b).await.unwrap().unwrap();
    let val_b_after = ValidatorAccount::try_deserialize(&mut raw_b.data.as_slice()).unwrap();
    assert!(!val_b_after.is_active, "orphaned validator must be deactivated");
    assert_eq!(val_b_after.stake_amount, 0);
    assert_eq!(val_b_after.unbonding_amount, MIN_VALIDATOR_STAKE);
    assert_eq!(
        val_b_after.token_unbonding_amount,
        paraloom_program::RECOMMENDED_MIN_TOKEN_STAKE
    );

    // CRITICAL INVARIANT: The registry counters must NOT be double-decremented!
    let raw = banks.get_account(registry_pda).await.unwrap().unwrap();
    let post_reconcile = ValidatorRegistry::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(
        post_reconcile.active_validators, 1,
        "active_validators must remain 1 for Validator A (not double-decremented to 0)"
    );
    assert_eq!(
        post_reconcile.total_active_stake, MIN_VALIDATOR_STAKE,
        "total_active_stake must remain 1 SOL for Validator A (not double-decremented to 0)"
    );
}
