//! Thirteenth on-chain unit test for #71. Closes the fee pipeline
//! distribute_fee_test (#141) only set up: claim_rewards transfers
//! pending_rewards out of bridge_vault, zeros pending, and
//! accumulates total_earnings. Vault is pre-funded by a direct
//! system transfer (claim_rewards does not touch bridge_state, so
//! the lighter setup path skips Initialize + Deposit).
//!
//! Registry init and `distribute_fee` run as the upgrade authority
//! (#204); register + claim stay validator-signed (the auto-payer).

use anchor_lang::prelude::*;
use anchor_lang::solana_program::system_instruction;
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
const FEE: u64 = 50_000;

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
async fn claim_rewards_drains_pending_and_accumulates_earnings() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    let (vault_pda, _) = Pubkey::find_program_address(&[b"bridge_vault"], &program_id);
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (validator_pda, _) =
        Pubkey::find_program_address(&[b"validator", payer.pubkey().as_ref()], &program_id);

    // Pre-fund the vault above the rent-exempt minimum so claim
    // can transfer out without leaving it underfunded.
    send(
        &mut banks_client,
        recent_blockhash,
        &payer,
        system_instruction::transfer(&payer.pubkey(), &vault_pda, 2_000_000_000),
    )
    .await;
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
            data: instruction::DistributeFee {
                leader: payer.pubkey(),
                fee_amount: FEE,
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
    send(
        &mut banks_client,
        recent_blockhash,
        &payer,
        Instruction {
            program_id,
            data: instruction::ClaimRewards {}.data(),
            accounts: accounts::ClaimRewards {
                validator_account: validator_pda,
                bridge_vault: vault_pda,
                validator: payer.pubkey(),
                system_program: solana_sdk::system_program::ID,
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
    assert_eq!(acc.pending_rewards, 0);
    assert_eq!(acc.total_earnings, FEE);
}
