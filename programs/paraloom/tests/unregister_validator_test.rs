//! Eighth on-chain unit test for #71. Symmetric counterpart to
//! register_validator: pins that unregister flips `is_active` to
//! false and decrements `active_validators` while leaving
//! `total_validators` recorded — the consensus pipeline reads the
//! active count for quorum and a regression that decremented the
//! wrong field would silently misbehave for both quorum math and
//! the long-tail validator-history log.
//!
//! Registry init runs as the upgrade authority (#204); register +
//! unregister are validator-signed (auto-payer).

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::{accounts, instruction, ValidatorAccount, ValidatorRegistry};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{
    instruction::Instruction,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

mod common;
use common::{add_program_data, add_stake_mint, entry, funded_validator};

const MIN_VALIDATOR_STAKE: u64 = 1_000_000_000;

async fn send(
    banks_client: &mut solana_program_test::BanksClient,
    recent_blockhash: anchor_lang::solana_program::hash::Hash,
    signer: &Keypair,
    ix: Instruction,
) {
    let mut tx = Transaction::new_with_payer(&[ix], Some(&signer.pubkey()));
    tx.sign(&[signer], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();
}

#[tokio::test]
async fn unregister_clears_active_and_decrements_registry() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let stake_mint = add_stake_mint(&mut pt, Pubkey::new_unique());
    let (validator, validator_token) = funded_validator(&mut pt, stake_mint);
    let (mut banks_client, _payer, recent_blockhash) = pt.start().await;

    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (validator_pda, _) =
        Pubkey::find_program_address(&[b"validator", validator.pubkey().as_ref()], &program_id);

    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::InitializeValidatorRegistry {}.data(),
            accounts: accounts::InitializeValidatorRegistry {
                stake_mint,
                stake_token_vault: Pubkey::find_program_address(
                    &[b"stake_token_vault"],
                    &program_id,
                )
                .0,
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
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;
    send(
        &mut banks_client,
        recent_blockhash,
        &validator,
        Instruction {
            program_id,
            data: instruction::RegisterValidator {
                token_stake_amount: paraloom_program::RECOMMENDED_MIN_TOKEN_STAKE,
                stake_amount: MIN_VALIDATOR_STAKE,
            }
            .data(),
            accounts: accounts::RegisterValidator {
                stake_mint,
                validator_token_account: validator_token,
                stake_token_vault: Pubkey::find_program_address(
                    &[b"stake_token_vault"],
                    &program_id,
                )
                .0,
                token_program: spl_token::id(),
                validator_account: validator_pda,
                validator_registry: registry_pda,
                validator: validator.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;
    send(
        &mut banks_client,
        recent_blockhash,
        &validator,
        Instruction {
            program_id,
            data: instruction::UnregisterValidator {}.data(),
            accounts: accounts::UnregisterValidator {
                validator_account: validator_pda,
                validator_registry: registry_pda,
                validator: validator.pubkey(),
            }
            .to_account_metas(None),
        },
    )
    .await;

    let registry_raw = banks_client
        .get_account(registry_pda)
        .await
        .unwrap()
        .unwrap();
    let registry = ValidatorRegistry::try_deserialize(&mut registry_raw.data.as_slice()).unwrap();
    assert_eq!(registry.active_validators, 0);
    assert_eq!(registry.total_validators, 1);

    let acc_raw = banks_client
        .get_account(validator_pda)
        .await
        .unwrap()
        .unwrap();
    let acc = ValidatorAccount::try_deserialize(&mut acc_raw.data.as_slice()).unwrap();
    assert!(!acc.is_active);
}

#[tokio::test]
async fn orphaned_validator_unregister_succeeds_without_underflow_when_registry_floors() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let stake_mint = add_stake_mint(&mut pt, Pubkey::new_unique());
    let (validator_a, validator_a_token) = funded_validator(&mut pt, stake_mint);
    let (validator_b, validator_b_token) = funded_validator(&mut pt, stake_mint);
    let (mut banks_client, _payer, recent_blockhash) = pt.start().await;

    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (validator_a_pda, _) =
        Pubkey::find_program_address(&[b"validator", validator_a.pubkey().as_ref()], &program_id);
    let (validator_b_pda, _) =
        Pubkey::find_program_address(&[b"validator", validator_b.pubkey().as_ref()], &program_id);

    // 1. Initialize registry.
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::InitializeValidatorRegistry {}.data(),
            accounts: accounts::InitializeValidatorRegistry {
                stake_mint,
                stake_token_vault: Pubkey::find_program_address(
                    &[b"stake_token_vault"],
                    &program_id,
                )
                .0,
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
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;

    // 2. Register both Validator A and Validator B.
    send(
        &mut banks_client,
        recent_blockhash,
        &validator_a,
        Instruction {
            program_id,
            data: instruction::RegisterValidator {
                token_stake_amount: paraloom_program::RECOMMENDED_MIN_TOKEN_STAKE,
                stake_amount: MIN_VALIDATOR_STAKE,
            }
            .data(),
            accounts: accounts::RegisterValidator {
                stake_mint,
                validator_token_account: validator_a_token,
                stake_token_vault: Pubkey::find_program_address(
                    &[b"stake_token_vault"],
                    &program_id,
                )
                .0,
                token_program: spl_token::id(),
                validator_account: validator_a_pda,
                validator_registry: registry_pda,
                validator: validator_a.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;

    send(
        &mut banks_client,
        recent_blockhash,
        &validator_b,
        Instruction {
            program_id,
            data: instruction::RegisterValidator {
                token_stake_amount: paraloom_program::RECOMMENDED_MIN_TOKEN_STAKE,
                stake_amount: MIN_VALIDATOR_STAKE,
            }
            .data(),
            accounts: accounts::RegisterValidator {
                stake_mint,
                validator_token_account: validator_b_token,
                stake_token_vault: Pubkey::find_program_address(
                    &[b"stake_token_vault"],
                    &program_id,
                )
                .0,
                token_program: spl_token::id(),
                validator_account: validator_b_pda,
                validator_registry: registry_pda,
                validator: validator_b.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;

    // 3. Reset registry passing ONLY validator A, leaving validator B as an orphaned active PDA.
    let mut reset_metas = accounts::ResetValidatorRegistry {
        validator_registry: registry_pda,
        authority: upgrade_authority.pubkey(),
        program_data: program_data_pda,
        system_program: solana_sdk::system_program::ID,
    }
    .to_account_metas(None);
    reset_metas.push(solana_sdk::instruction::AccountMeta::new_readonly(validator_a_pda, false));

    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::ResetValidatorRegistry {
                stake_mint,
                expected_active_validators: 1,
            }
            .data(),
            accounts: reset_metas,
        },
    )
    .await;

    // 4. Validator A unregisters, reducing active_validators from 1 to 0.
    send(
        &mut banks_client,
        recent_blockhash,
        &validator_a,
        Instruction {
            program_id,
            data: instruction::UnregisterValidator {}.data(),
            accounts: accounts::UnregisterValidator {
                validator_account: validator_a_pda,
                validator_registry: registry_pda,
                validator: validator_a.pubkey(),
            }
            .to_account_metas(None),
        },
    )
    .await;

    let registry_raw = banks_client
        .get_account(registry_pda)
        .await
        .unwrap()
        .unwrap();
    let registry = ValidatorRegistry::try_deserialize(&mut registry_raw.data.as_slice()).unwrap();
    assert_eq!(registry.active_validators, 0);
    assert_eq!(registry.total_active_stake, 0);

    // 5. Validator B is an orphaned active PDA (not counted in the floored registry).
    // It self-unregisters without admin intervention. active_validators saturates at 0
    // without underflowing/panicking, and stake is successfully routed to unbonding.
    send(
        &mut banks_client,
        recent_blockhash,
        &validator_b,
        Instruction {
            program_id,
            data: instruction::UnregisterValidator {}.data(),
            accounts: accounts::UnregisterValidator {
                validator_account: validator_b_pda,
                validator_registry: registry_pda,
                validator: validator_b.pubkey(),
            }
            .to_account_metas(None),
        },
    )
    .await;

    let registry_raw = banks_client
        .get_account(registry_pda)
        .await
        .unwrap()
        .unwrap();
    let registry = ValidatorRegistry::try_deserialize(&mut registry_raw.data.as_slice()).unwrap();
    assert_eq!(registry.active_validators, 0, "active_validators must floor at 0 without underflow");
    assert_eq!(registry.total_active_stake, 0, "total_active_stake must floor at 0 without underflow");

    let acc_raw = banks_client
        .get_account(validator_b_pda)
        .await
        .unwrap()
        .unwrap();
    let acc_b = ValidatorAccount::try_deserialize(&mut acc_raw.data.as_slice()).unwrap();
    assert!(!acc_b.is_active, "orphaned validator must be deactivated on unregister");
    assert_eq!(acc_b.stake_amount, 0, "active stake must be zeroed");
    assert_eq!(acc_b.unbonding_amount, MIN_VALIDATOR_STAKE, "SOL stake routed to unbonding");
    assert_eq!(
        acc_b.token_unbonding_amount,
        paraloom_program::RECOMMENDED_MIN_TOKEN_STAKE,
        "token stake routed to unbonding"
    );
}
