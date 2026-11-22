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
    instruction::{AccountMeta, Instruction},
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

/// Regression test for issue #1630:
/// When `reset_validator_registry` excludes an active validator, that orphan validator
/// remains `is_active = true` on-chain (the #1623 premise). When it subsequently calls
/// `unregister_validator`, the registry counters must NOT be double-decremented, because
/// its stake was already excluded from the rebuilt total.
#[tokio::test]
async fn unregister_reset_excluded_orphan_does_not_decrement_registry() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let stake_mint = add_stake_mint(&mut pt, Pubkey::new_unique());

    let (val_a, token_a) = funded_validator(&mut pt, stake_mint);
    let (val_b, token_b) = funded_validator(&mut pt, stake_mint);
    let (val_c, token_c) = funded_validator(&mut pt, stake_mint);

    let (mut banks_client, _payer, recent_blockhash) = pt.start().await;

    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (pda_a, _) =
        Pubkey::find_program_address(&[b"validator", val_a.pubkey().as_ref()], &program_id);
    let (pda_b, _) =
        Pubkey::find_program_address(&[b"validator", val_b.pubkey().as_ref()], &program_id);
    let (pda_c, _) =
        Pubkey::find_program_address(&[b"validator", val_c.pubkey().as_ref()], &program_id);

    // 1. Initialize registry
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

    // 2. Register validators A, B, and C (1 SOL each)
    let validators = [
        (&val_a, token_a, pda_a),
        (&val_b, token_b, pda_b),
        (&val_c, token_c, pda_c),
    ];
    for (val, token, pda) in validators {
        send(
            &mut banks_client,
            recent_blockhash,
            val,
            Instruction {
                program_id,
                data: instruction::RegisterValidator {
                    token_stake_amount: paraloom_program::RECOMMENDED_MIN_TOKEN_STAKE,
                    stake_amount: MIN_VALIDATOR_STAKE,
                }
                .data(),
                accounts: accounts::RegisterValidator {
                    stake_mint,
                    validator_token_account: token,
                    stake_token_vault: Pubkey::find_program_address(
                        &[b"stake_token_vault"],
                        &program_id,
                    )
                    .0,
                    token_program: spl_token::id(),
                    validator_account: pda,
                    validator_registry: registry_pda,
                    validator: val.pubkey(),
                    system_program: solana_sdk::system_program::ID,
                }
                .to_account_metas(None),
            },
        )
        .await;
    }

    // Before reset: 3 active validators, 3 SOL total stake
    let reg_raw = banks_client
        .get_account(registry_pda)
        .await
        .unwrap()
        .unwrap();
    let reg = ValidatorRegistry::try_deserialize(&mut reg_raw.data.as_slice()).unwrap();
    assert_eq!(reg.active_validators, 3);
    assert_eq!(reg.total_active_stake, 3 * MIN_VALIDATOR_STAKE);

    // 3. Reset registry keeping only A and B (expected_active_validators = 2). C is excluded (orphan).
    let mut reset_metas = accounts::ResetValidatorRegistry {
        validator_registry: registry_pda,
        authority: upgrade_authority.pubkey(),
        program_data: program_data_pda,
        system_program: solana_sdk::system_program::ID,
    }
    .to_account_metas(None);
    reset_metas.push(AccountMeta::new_readonly(pda_a, false));
    reset_metas.push(AccountMeta::new_readonly(pda_b, false));

    let reset_ix = Instruction {
        program_id,
        data: instruction::ResetValidatorRegistry {
            stake_mint,
            expected_active_validators: 2,
        }
        .data(),
        accounts: reset_metas,
    };
    send(&mut banks_client, recent_blockhash, &upgrade_authority, reset_ix).await;

    // After reset: 2 active validators, 2 SOL total stake
    let reg_raw = banks_client
        .get_account(registry_pda)
        .await
        .unwrap()
        .unwrap();
    let reg = ValidatorRegistry::try_deserialize(&mut reg_raw.data.as_slice()).unwrap();
    assert_eq!(reg.active_validators, 2);
    assert_eq!(reg.total_active_stake, 2 * MIN_VALIDATOR_STAKE);

    // C is still active on-chain (orphan premise #1623)
    let c_raw = banks_client.get_account(pda_c).await.unwrap().unwrap();
    let c_acc = ValidatorAccount::try_deserialize(&mut c_raw.data.as_slice()).unwrap();
    assert!(c_acc.is_active);

    // 4. Orphan C calls unregister_validator
    send(
        &mut banks_client,
        recent_blockhash,
        &val_c,
        Instruction {
            program_id,
            data: instruction::UnregisterValidator {}.data(),
            accounts: accounts::UnregisterValidator {
                validator_account: pda_c,
                validator_registry: registry_pda,
                validator: val_c.pubkey(),
            }
            .to_account_metas(None),
        },
    )
    .await;

    // C's stake entered unbonding and C is deactivated
    let c_raw = banks_client.get_account(pda_c).await.unwrap().unwrap();
    let c_acc = ValidatorAccount::try_deserialize(&mut c_raw.data.as_slice()).unwrap();
    assert!(!c_acc.is_active);
    assert_eq!(c_acc.stake_amount, 0);
    assert_eq!(c_acc.unbonding_amount, MIN_VALIDATOR_STAKE);

    // CRITICAL BUG FIX CHECK (#1630):
    // Registry active counters MUST NOT be decremented by the orphan exit.
    // They must remain 2 active validators and 2 SOL total stake!
    let reg_raw = banks_client
        .get_account(registry_pda)
        .await
        .unwrap()
        .unwrap();
    let reg = ValidatorRegistry::try_deserialize(&mut reg_raw.data.as_slice()).unwrap();
    assert_eq!(
        reg.active_validators, 2,
        "orphan unregister must not double-decrement active_validators"
    );
    assert_eq!(
        reg.total_active_stake, 2 * MIN_VALIDATOR_STAKE,
        "orphan unregister must not double-decrement total_active_stake"
    );

    // 5. When a kept validator (A) unregisters, it DOES decrement the counters
    send(
        &mut banks_client,
        recent_blockhash,
        &val_a,
        Instruction {
            program_id,
            data: instruction::UnregisterValidator {}.data(),
            accounts: accounts::UnregisterValidator {
                validator_account: pda_a,
                validator_registry: registry_pda,
                validator: val_a.pubkey(),
            }
            .to_account_metas(None),
        },
    )
    .await;

    let reg_raw = banks_client
        .get_account(registry_pda)
        .await
        .unwrap()
        .unwrap();
    let reg = ValidatorRegistry::try_deserialize(&mut reg_raw.data.as_slice()).unwrap();
    assert_eq!(
        reg.active_validators, 1,
        "kept validator unregister must decrement active_validators"
    );
    assert_eq!(
        reg.total_active_stake, MIN_VALIDATOR_STAKE,
        "kept validator unregister must decrement total_active_stake"
    );
}
