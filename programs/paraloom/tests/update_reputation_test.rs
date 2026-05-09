//! Tenth on-chain unit test for #71. Pins `update_reputation`:
//! the handler stamps `reputation_score` to the supplied value.
//! The L2 reads `reputation_score` to gate consensus eligibility
//! (`min_reputation_for_consensus`); a regression that wrote to
//! the wrong field, or that ignored the input, would silently
//! either include slashed validators in quorum or exclude
//! healthy ones.

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::{accounts, instruction, ValidatorAccount};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{instruction::Instruction, signature::Signer, transaction::Transaction};

mod common;
use common::entry;

const MIN_VALIDATOR_STAKE: u64 = 1_000_000_000;

#[tokio::test]
async fn update_reputation_overwrites_score() {
    let program_id = paraloom_program::ID;
    let pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (validator_pda, _) =
        Pubkey::find_program_address(&[b"validator", payer.pubkey().as_ref()], &program_id);

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
            data: instruction::UpdateReputation {
                validator: payer.pubkey(),
                new_reputation: 750,
            }
            .data(),
            accounts: accounts::UpdateReputation {
                validator_account: validator_pda,
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
    // Default reputation after register is 1000; the handler must
    // overwrite it with the supplied value rather than ignore the
    // call.
    assert_eq!(acc.reputation_score, 750);
}
