//! Sixth on-chain unit test for #71. Closes the slashing pipeline
//! the L2 Byzantine-consensus test (#124) only covered up to the
//! evidence-record step: `slash_validator` is what actually
//! reduces a misbehaving validator's stake. Pins three contracts
//! the consensus pipeline relies on: stake_amount drops by the
//! percentage, times_slashed increments, slashed lamports land in
//! bridge_vault.

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::{accounts, instruction, ValidatorAccount};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{instruction::Instruction, signature::Signer, transaction::Transaction};

mod common;
use common::entry;

const MIN_VALIDATOR_STAKE: u64 = 1_000_000_000;

#[tokio::test]
async fn slash_reduces_stake_and_credits_vault() {
    let program_id = paraloom_program::ID;
    let pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (validator_pda, _) =
        Pubkey::find_program_address(&[b"validator", payer.pubkey().as_ref()], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(&[b"bridge_vault"], &program_id);

    let ixs = [
        Instruction {
            program_id,
            data: instruction::InitializeValidatorRegistry {}.data(),
            accounts: accounts::InitializeValidatorRegistry {
                validator_registry: registry_pda,
                authority: payer.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
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
                authority: payer.pubkey(),
            }
            .to_account_metas(None),
        },
    ];
    for ix in ixs {
        let mut tx = Transaction::new_with_payer(&[ix], Some(&payer.pubkey()));
        tx.sign(&[&payer], recent_blockhash);
        banks_client.process_transaction(tx).await.unwrap();
    }

    let acc_raw = banks_client
        .get_account(validator_pda)
        .await
        .unwrap()
        .unwrap();
    let acc = ValidatorAccount::try_deserialize(&mut acc_raw.data.as_slice()).unwrap();
    assert_eq!(acc.stake_amount, MIN_VALIDATOR_STAKE / 2);
    assert_eq!(acc.times_slashed, 1);

    let vault = banks_client
        .get_account(vault_pda)
        .await
        .unwrap()
        .expect("bridge_vault must exist after slash");
    assert_eq!(vault.lamports, MIN_VALIDATOR_STAKE / 2);
}
