//! Adversarial on-chain test for the settlement quorum (#260).
//!
//! With two active validators registered, the BFT threshold is
//! `floor(2*2/3)+1 = 2`. A withdraw co-signed by only one validator must be
//! rejected with `QuorumNotMet` *even though the proof is valid and the settling
//! validator is registered* — the quorum check is the gate. The positive
//! control settles the same withdraw once both validators co-sign, proving the
//! rejection is specifically the missing quorum and nothing else.

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::withdraw_fixture_data as fx;
use paraloom_program::{accounts, instruction};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    signature::{Keypair, Signer},
    system_instruction,
    transaction::Transaction,
};

mod common;
use common::{add_program_data, entry};

const NULLIFIER: [u8; 32] = fx::FIXTURE_NULLIFIER;
const WITHDRAW_AMOUNT: u64 = fx::FIXTURE_AMOUNT;
const MIN_VALIDATOR_STAKE: u64 = 1_000_000_000;

/// The 256-byte alt_bn128 wire proof from the fixture.
fn fixture_proof() -> Vec<u8> {
    let mut p = Vec::with_capacity(256);
    p.extend_from_slice(&fx::FIXTURE_PROOF_A);
    p.extend_from_slice(&fx::FIXTURE_PROOF_B);
    p.extend_from_slice(&fx::FIXTURE_PROOF_C);
    p
}

#[tokio::test]
async fn withdraw_is_rejected_without_a_validator_quorum() {
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

    // A second, independent validator. Funded so it can stake and sign.
    let validator2 = Keypair::new();
    let (validator2_pda, _) =
        Pubkey::find_program_address(&[b"validator", validator2.pubkey().as_ref()], &program_id);

    let recipient = Pubkey::new_from_array(fx::FIXTURE_RECIPIENT);

    async fn send(
        banks_client: &mut solana_program_test::BanksClient,
        recent_blockhash: anchor_lang::solana_program::hash::Hash,
        signer: &Keypair,
        ix: Instruction,
    ) -> std::result::Result<(), solana_program_test::BanksClientError> {
        let mut tx = Transaction::new_with_payer(&[ix], Some(&signer.pubkey()));
        tx.sign(&[signer], recent_blockhash);
        banks_client.process_transaction(tx).await
    }

    // initialize + registry + register the settling authority as validator 1.
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
    .await
    .unwrap();

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
    .await
    .unwrap();

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
    .await
    .unwrap();

    // Fund validator 2 and register it, bringing the active set to two — so the
    // quorum threshold becomes 2.
    send(
        &mut banks_client,
        recent_blockhash,
        &payer,
        system_instruction::transfer(&payer.pubkey(), &validator2.pubkey(), 2_000_000_000),
    )
    .await
    .unwrap();

    send(
        &mut banks_client,
        recent_blockhash,
        &validator2,
        Instruction {
            program_id,
            data: instruction::RegisterValidator {
                stake_amount: MIN_VALIDATOR_STAKE,
            }
            .data(),
            accounts: accounts::RegisterValidator {
                validator_account: validator2_pda,
                validator_registry: registry_pda,
                validator: validator2.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await
    .unwrap();

    // Deposit so the vault can cover the withdraw.
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
    .await
    .unwrap();

    // The withdraw instruction, parameterised by the quorum co-signers appended
    // as remaining accounts.
    let withdraw_ix = |quorum: &[(&Keypair, Pubkey)]| {
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
        for (wallet, pda) in quorum {
            metas.push(AccountMeta::new_readonly(wallet.pubkey(), true));
            metas.push(AccountMeta::new_readonly(*pda, false));
        }
        Instruction {
            program_id,
            data: instruction::Withdraw {
                nullifier: NULLIFIER,
                amount: WITHDRAW_AMOUNT,
                expiration_slot: u64::MAX,
                proof: fixture_proof(),
            }
            .data(),
            accounts: metas,
        }
    };

    // Case A — only one of the two validators co-signs. The proof is valid and
    // the settling validator is registered, but the quorum is not met.
    let one_signer = withdraw_ix(&[(&upgrade_authority, validator_pda)]);
    let mut tx = Transaction::new_with_payer(&[one_signer], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], recent_blockhash);
    let result = banks_client.process_transaction(tx).await;
    assert!(
        result.is_err(),
        "a single co-signer must not meet the 2-of-2 quorum"
    );

    // Case B — both validators co-sign. Same withdraw, now the quorum is met and
    // it settles (proving Case A failed specifically on the quorum).
    let two_signers = withdraw_ix(&[
        (&upgrade_authority, validator_pda),
        (&validator2, validator2_pda),
    ]);
    let mut tx = Transaction::new_with_payer(&[two_signers], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority, &validator2], recent_blockhash);
    banks_client
        .process_transaction(tx)
        .await
        .expect("a full 2-of-2 quorum must settle the withdraw");
}
