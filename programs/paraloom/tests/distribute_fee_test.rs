//! Ninth on-chain unit test for #71. Pins the fee-distribution
//! handler: `distribute_fee` adds the supplied amount to the
//! leader's `pending_rewards` so a later `claim_rewards` knows how
//! much to pay out. Without this test a regression that overwrote
//! `pending_rewards` instead of accumulating, or that skipped the
//! validator-match `require!`, would silently misroute fees.
//!
//! Registry init and `distribute_fee` are now upgrade-authority gated
//! (#204 + `has_one = authority`); validator registration stays
//! permissionless and is signed by the validator (the auto-payer).

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::{accounts, instruction, ValidatorAccount};
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
async fn distribute_fee_accumulates_pending_rewards() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    // The validator account is keyed off the validator (the auto-payer here),
    // not the registry authority — distinct from the registry's authority.
    let (validator_pda, _) =
        Pubkey::find_program_address(&[b"validator", payer.pubkey().as_ref()], &program_id);

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
    for fee in [50_000u64, 25_000u64] {
        send(
            &mut banks_client,
            recent_blockhash,
            &upgrade_authority,
            Instruction {
                program_id,
                data: instruction::DistributeFee {
                    leader: payer.pubkey(),
                    fee_amount: fee,
                }
                .data(),
                accounts: accounts::DistributeFee {
                    validator_account: validator_pda,
                    validator_registry: registry_pda,
                    authority: upgrade_authority.pubkey(),
                }
                .to_account_metas(None),
            },
        )
        .await;
    }

    let acc_raw = banks_client
        .get_account(validator_pda)
        .await
        .unwrap()
        .unwrap();
    let acc = ValidatorAccount::try_deserialize(&mut acc_raw.data.as_slice()).unwrap();
    assert_eq!(acc.pending_rewards, 75_000);
}
