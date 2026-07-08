//! Sixth on-chain unit test for #71. Closes the slashing pipeline
//! the L2 Byzantine-consensus test (#124) only covered up to the
//! evidence-record step: `slash_validator` is what actually
//! reduces a misbehaving validator's stake. Pins three contracts
//! the consensus pipeline relies on: stake_amount drops by the
//! percentage, times_slashed increments, slashed lamports land in
//! bridge_vault.
//!
//! Registry init and `slash_validator` run as the upgrade authority
//! (#204 + `has_one = authority`); register stays validator-signed.

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
use common::{add_program_data, entry};

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
async fn slash_reduces_stake_and_credits_vault() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (validator_pda, _) =
        Pubkey::find_program_address(&[b"validator", payer.pubkey().as_ref()], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(&[b"bridge_vault"], &program_id);

    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::InitializeValidatorRegistry {}.data(),
            accounts: accounts::InitializeValidatorRegistry {
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
        &payer,
        Instruction {
            program_id,
            data: instruction::RegisterValidator {
                stake_amount: MIN_VALIDATOR_STAKE,
            }
            .data(),
            accounts: accounts::RegisterValidator {
                validator_account: validator_pda,
                validator_registry: registry_pda,
                validator: payer.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::SlashValidator {
                validator: payer.pubkey(),
                slash_percentage: 50,
            }
            .data(),
            accounts: accounts::SlashValidator {
                validator_account: validator_pda,
                bridge_vault: vault_pda,
                validator_registry: registry_pda,
                authority: upgrade_authority.pubkey(),
            }
            .to_account_metas(None),
        },
    )
    .await;

    let acc_raw = banks_client
        .get_account(validator_pda)
        .await
        .unwrap()
        .unwrap();
    let acc = ValidatorAccount::try_deserialize(&mut acc_raw.data.as_slice()).unwrap();
    // The 50% slash drops stake below the minimum, deactivating the validator;
    // the unslashed remainder (MIN/2) is routed into unbonding (a deactivated
    // validator can't `unregister` to reclaim it), so active stake is now zero.
    assert_eq!(acc.stake_amount, 0);
    assert_eq!(acc.unbonding_amount, MIN_VALIDATOR_STAKE / 2);
    assert!(acc.unbonding_slot > 0, "unbonding slot must be set");
    assert_eq!(acc.times_slashed, 1);

    // A 50% slash drops stake to MIN/2, below the registry minimum, so the
    // validator is deactivated and stops counting toward the quorum.
    assert!(
        !acc.is_active,
        "a slash below the minimum stake must deactivate the validator"
    );
    let reg_raw = banks_client
        .get_account(registry_pda)
        .await
        .unwrap()
        .unwrap();
    let reg = ValidatorRegistry::try_deserialize(&mut reg_raw.data.as_slice()).unwrap();
    assert_eq!(
        reg.active_validators, 0,
        "deactivating a slashed validator must decrement active_validators"
    );

    let vault = banks_client
        .get_account(vault_pda)
        .await
        .unwrap()
        .expect("bridge_vault must exist after slash");
    assert_eq!(vault.lamports, MIN_VALIDATOR_STAKE / 2);
}

#[tokio::test]
async fn slash_above_minimum_keeps_validator_active() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (validator_pda, _) =
        Pubkey::find_program_address(&[b"validator", payer.pubkey().as_ref()], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(&[b"bridge_vault"], &program_id);

    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::InitializeValidatorRegistry {}.data(),
            accounts: accounts::InitializeValidatorRegistry {
                validator_registry: registry_pda,
                authority: upgrade_authority.pubkey(),
                program_data: program_data_pda,
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;

    // Register with twice the minimum stake so a moderate slash stays above it.
    send(
        &mut banks_client,
        recent_blockhash,
        &payer,
        Instruction {
            program_id,
            data: instruction::RegisterValidator {
                stake_amount: 2 * MIN_VALIDATOR_STAKE,
            }
            .data(),
            accounts: accounts::RegisterValidator {
                validator_account: validator_pda,
                validator_registry: registry_pda,
                validator: payer.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;

    // 25% slash: 2*MIN -> 1.5*MIN, still >= the minimum, so the validator stays
    // active and keeps counting toward the quorum.
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::SlashValidator {
                validator: payer.pubkey(),
                slash_percentage: 25,
            }
            .data(),
            accounts: accounts::SlashValidator {
                validator_account: validator_pda,
                bridge_vault: vault_pda,
                validator_registry: registry_pda,
                authority: upgrade_authority.pubkey(),
            }
            .to_account_metas(None),
        },
    )
    .await;

    let acc_raw = banks_client
        .get_account(validator_pda)
        .await
        .unwrap()
        .unwrap();
    let acc = ValidatorAccount::try_deserialize(&mut acc_raw.data.as_slice()).unwrap();
    assert_eq!(acc.stake_amount, 2 * MIN_VALIDATOR_STAKE * 75 / 100);
    assert!(
        acc.is_active,
        "a slash that leaves stake above the minimum must keep the validator active"
    );

    let reg_raw = banks_client
        .get_account(registry_pda)
        .await
        .unwrap()
        .unwrap();
    let reg = ValidatorRegistry::try_deserialize(&mut reg_raw.data.as_slice()).unwrap();
    assert_eq!(
        reg.active_validators, 1,
        "a validator still above the minimum must keep counting toward the quorum"
    );
}
