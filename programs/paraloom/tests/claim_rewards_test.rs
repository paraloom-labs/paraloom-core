//! claim_rewards over the real reward flow: a withdrawal credits the settling
//! validator its 25 bps fee into `pending_rewards`, then `claim_rewards`
//! transfers that out of `bridge_vault`, zeros pending, and accumulates
//! `total_earnings`. The fee is credited by `withdraw` itself (the only path
//! that mints pending rewards) — the former `distribute_fee` admin shortcut was
//! removed as an unbacked drain surface.

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::withdraw_fixture_data as fx;
use paraloom_program::{accounts, instruction, ValidatorAccount};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    signature::{Keypair, Signer},
    transaction::Transaction,
};

mod common;
use common::{add_program_data, entry};

const NULLIFIER: [u8; 32] = fx::FIXTURE_NULLIFIER;
const WITHDRAW_AMOUNT: u64 = fx::FIXTURE_AMOUNT;
const EXPECTED_FEE: u64 = WITHDRAW_AMOUNT * 25 / 10_000;
const MIN_VALIDATOR_STAKE: u64 = 1_000_000_000;

fn fixture_proof() -> Vec<u8> {
    let mut p = Vec::with_capacity(256);
    p.extend_from_slice(&fx::FIXTURE_PROOF_A);
    p.extend_from_slice(&fx::FIXTURE_PROOF_B);
    p.extend_from_slice(&fx::FIXTURE_PROOF_C);
    p
}

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

    let (state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(&[b"bridge_vault"], &program_id);
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (nullifier_pda, _) = Pubkey::find_program_address(&[b"nullifier", &NULLIFIER], &program_id);
    let (validator_pda, _) = Pubkey::find_program_address(
        &[b"validator", upgrade_authority.pubkey().as_ref()],
        &program_id,
    );
    let recipient = Pubkey::new_from_array(fx::FIXTURE_RECIPIENT);

    // initialize → registry → register the settling authority as a validator.
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::Initialize {
                program_version: 0x0004_0000,
                initial_merkle_root: fx::FIXTURE_ROOT,
            }
            .data(),
            accounts: accounts::Initialize {
                bridge_state: state_pda,
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
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::RegisterValidator {
                stake_amount: MIN_VALIDATOR_STAKE,
            }
            .data(),
            accounts: accounts::RegisterValidator {
                validator_account: validator_pda,
                validator_registry: registry_pda,
                validator: upgrade_authority.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;

    // Deposit 2 SOL so the vault stays rent-exempt through the payout + claim.
    send(
        &mut banks_client,
        recent_blockhash,
        &payer,
        Instruction {
            program_id,
            data: instruction::Deposit {
                amount: 2_000_000_000,
                recipient: [1u8; 32],
                randomness: [2u8; 32],
            }
            .data(),
            accounts: accounts::Deposit {
                bridge_state: state_pda,
                bridge_vault: vault_pda,
                depositor: payer.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;

    // Withdraw — credits EXPECTED_FEE to the settling validator's pending_rewards.
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::Withdraw {
                nullifier: NULLIFIER,
                amount: WITHDRAW_AMOUNT,
                expiration_slot: u64::MAX,
                proof: fixture_proof(),
            }
            .data(),
            accounts: {
                let mut metas = accounts::Withdraw {
                    bridge_state: state_pda,
                    bridge_vault: vault_pda,
                    nullifier_account: nullifier_pda,
                    recipient,
                    validator_account: validator_pda,
                    validator_registry: registry_pda,
                    authority: upgrade_authority.pubkey(),
                    system_program: solana_sdk::system_program::ID,
                }
                .to_account_metas(None);
                // Quorum co-signers (#260): the sole registered validator,
                // co-signing as a (wallet, PDA) pair.
                metas.push(AccountMeta::new_readonly(upgrade_authority.pubkey(), true));
                metas.push(AccountMeta::new_readonly(validator_pda, false));
                metas
            },
        },
    )
    .await;

    // The fee is now pending; nothing claimed yet.
    let before = banks_client
        .get_account(validator_pda)
        .await
        .unwrap()
        .unwrap();
    let before = ValidatorAccount::try_deserialize(&mut before.data.as_slice()).unwrap();
    assert_eq!(before.pending_rewards, EXPECTED_FEE);
    assert_eq!(before.total_earnings, 0);

    // claim_rewards — pays pending out of the vault, zeros it, accumulates earnings.
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::ClaimRewards {}.data(),
            accounts: accounts::ClaimRewards {
                validator_account: validator_pda,
                bridge_vault: vault_pda,
                validator: upgrade_authority.pubkey(),
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
    assert_eq!(acc.total_earnings, EXPECTED_FEE);
}
