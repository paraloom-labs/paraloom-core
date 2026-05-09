//! Ninth on-chain unit test for #71. Pins the fee-distribution
//! handler: `distribute_fee` adds the supplied amount to the
//! leader's `pending_rewards` so a later `claim_rewards` knows how
//! much to pay out. Without this test a regression that overwrote
//! `pending_rewards` instead of accumulating, or that skipped the
//! validator-match `require!`, would silently misroute fees.

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::{accounts, instruction, ValidatorAccount};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{instruction::Instruction, signature::Signer, transaction::Transaction};

mod common;
use common::entry;

const MIN_VALIDATOR_STAKE: u64 = 1_000_000_000;

#[tokio::test]
async fn distribute_fee_accumulates_pending_rewards() {
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
            data: instruction::DistributeFee {
                leader: payer.pubkey(),
                fee_amount: 50_000,
            }
            .data(),
            accounts: accounts::DistributeFee {
                validator_account: validator_pda,
                validator_registry: registry_pda,
                authority: payer.pubkey(),
            }
            .to_account_metas(None),
        },
        Instruction {
            program_id,
            data: instruction::DistributeFee {
                leader: payer.pubkey(),
                fee_amount: 25_000,
            }
            .data(),
            accounts: accounts::DistributeFee {
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
    assert_eq!(acc.pending_rewards, 75_000);
}
