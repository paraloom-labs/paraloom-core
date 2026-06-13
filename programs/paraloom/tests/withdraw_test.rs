//! Eleventh on-chain unit test for #71. Happy-path withdraw:
//! initialize → register validator → deposit → withdraw. Pins the
//! recipient transfer (now net of the validator fee), the L2-visible
//! counters, the nullifier PDA the replay layer relies on, and the
//! fee credited to the settling validator's `pending_rewards`.
//! Replay-rejection is a separate PR.
//!
//! Init + withdraw both run as the program upgrade authority (#204);
//! the deposit ix is permissionless and signed by the auto-payer.
//! Settlement now requires the signer to be a registered, active
//! validator — the withdrawal fee is credited to that validator.

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::withdraw_fixture_data as fx;
use paraloom_program::{accounts, instruction, BridgeState, NullifierAccount, ValidatorAccount};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{
    instruction::Instruction,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

mod common;
use common::{add_program_data, entry};

// The withdrawal proof, root, nullifier and amount come from the on-chain
// verifier fixture so the proof actually verifies against the program's root.
const NULLIFIER: [u8; 32] = fx::FIXTURE_NULLIFIER;
const WITHDRAW_AMOUNT: u64 = fx::FIXTURE_AMOUNT;

/// The 256-byte alt_bn128 wire proof from the fixture.
fn fixture_proof() -> Vec<u8> {
    let mut p = Vec::with_capacity(256);
    p.extend_from_slice(&fx::FIXTURE_PROOF_A);
    p.extend_from_slice(&fx::FIXTURE_PROOF_B);
    p.extend_from_slice(&fx::FIXTURE_PROOF_C);
    p
}
// 25 bps of 1 SOL = 0.0025 SOL.
const EXPECTED_FEE: u64 = WITHDRAW_AMOUNT * 25 / 10_000;
const MIN_VALIDATOR_STAKE: u64 = 1_000_000_000;

#[tokio::test]
async fn withdraw_pays_recipient_net_and_credits_validator_fee() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    let (state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(&[b"bridge_vault"], &program_id);
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (nullifier_pda, _) = Pubkey::find_program_address(&[b"nullifier", &NULLIFIER], &program_id);
    // The bridge authority (= upgrade authority) settles the withdrawal, so it
    // is also the validator whose account is bound and credited.
    let (validator_pda, _) = Pubkey::find_program_address(
        &[b"validator", upgrade_authority.pubkey().as_ref()],
        &program_id,
    );

    let recipient = Keypair::new();

    // Helper to land a single ix signed by `signer` (also tx payer).
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

    // 1. initialize — must be signed by the upgrade authority (#204).
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

    // 2. initialize the validator registry — upgrade-authority gated (#204).
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

    // 3. register the settling authority as a validator (stakes 1 SOL).
    //    Without this the withdraw below fails: the validator_account PDA
    //    would not exist.
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

    // 4. deposit — permissionless; 2 SOL so the vault stays above the
    //    rent-exempt minimum after the withdraw + retained fee.
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

    // 5. withdraw — signed by the bridge authority (`has_one = authority`),
    //    which is also the registered validator that earns the fee.
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
            accounts: accounts::Withdraw {
                bridge_state: state_pda,
                bridge_vault: vault_pda,
                nullifier_account: nullifier_pda,
                recipient: recipient.pubkey(),
                validator_account: validator_pda,
                authority: upgrade_authority.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;

    let state_raw = banks_client.get_account(state_pda).await.unwrap().unwrap();
    let state = BridgeState::try_deserialize(&mut state_raw.data.as_slice()).unwrap();
    assert_eq!(state.total_withdrawn, WITHDRAW_AMOUNT);
    assert_eq!(state.withdrawal_count, 1);

    // The recipient receives the amount net of the validator fee.
    let recipient_acc = banks_client
        .get_account(recipient.pubkey())
        .await
        .unwrap()
        .expect("recipient funded by the withdraw");
    assert_eq!(recipient_acc.lamports, WITHDRAW_AMOUNT - EXPECTED_FEE);

    // The fee lands in the settling validator's pending_rewards (claimable
    // later via claim_rewards) and the settlement is recorded.
    let val_raw = banks_client
        .get_account(validator_pda)
        .await
        .unwrap()
        .unwrap();
    let val = ValidatorAccount::try_deserialize(&mut val_raw.data.as_slice()).unwrap();
    assert_eq!(val.pending_rewards, EXPECTED_FEE);
    assert_eq!(val.successful_verifications, 1);

    let nul_raw = banks_client
        .get_account(nullifier_pda)
        .await
        .unwrap()
        .expect("nullifier PDA must exist after withdraw");
    let nul = NullifierAccount::try_deserialize(&mut nul_raw.data.as_slice()).unwrap();
    assert_eq!(nul.nullifier, NULLIFIER);
    assert_eq!(nul.withdrawal_id, 1);
}
