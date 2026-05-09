//! Eleventh on-chain unit test for #71. Happy-path withdraw:
//! initialize → deposit → withdraw. Pins the recipient transfer,
//! the L2-visible counters, and the nullifier PDA the replay layer
//! relies on. Replay-rejection is a separate PR.

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::{accounts, instruction, BridgeState, NullifierAccount};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{instruction::Instruction, signature::Signer, transaction::Transaction};

mod common;
use common::entry;

const NULLIFIER: [u8; 32] = [42u8; 32];

#[tokio::test]
async fn withdraw_credits_recipient_and_advances_counters() {
    let program_id = paraloom_program::ID;
    let pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    let (state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(&[b"bridge_vault"], &program_id);
    let (nullifier_pda, _) = Pubkey::find_program_address(&[b"nullifier", &NULLIFIER], &program_id);

    let ixs = [
        Instruction {
            program_id,
            data: instruction::Initialize {
                program_version: 0x0004_0000,
                initial_merkle_root: [0u8; 32],
            }
            .data(),
            accounts: accounts::Initialize {
                bridge_state: state_pda,
                authority: payer.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
        Instruction {
            program_id,
            // 2 SOL so vault stays above the rent-exempt minimum
            // (~890_880 lamports) after the 1 SOL withdraw — a
            // smaller margin trips InsufficientFundsForRent.
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
        Instruction {
            program_id,
            data: instruction::Withdraw {
                nullifier: NULLIFIER,
                amount: 1_000_000_000,
                expiration_slot: u64::MAX,
                proof: vec![1, 2, 3, 4],
            }
            .data(),
            accounts: accounts::Withdraw {
                bridge_state: state_pda,
                bridge_vault: vault_pda,
                nullifier_account: nullifier_pda,
                recipient: payer.pubkey(),
                authority: payer.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    ];
    for ix in ixs {
        let mut tx = Transaction::new_with_payer(&[ix], Some(&payer.pubkey()));
        tx.sign(&[&payer], recent_blockhash);
        banks_client.process_transaction(tx).await.unwrap();
    }

    let state_raw = banks_client.get_account(state_pda).await.unwrap().unwrap();
    let state = BridgeState::try_deserialize(&mut state_raw.data.as_slice()).unwrap();
    assert_eq!(state.total_withdrawn, 1_000_000_000);
    assert_eq!(state.withdrawal_count, 1);

    let nul_raw = banks_client
        .get_account(nullifier_pda)
        .await
        .unwrap()
        .expect("nullifier PDA must exist after withdraw");
    let nul = NullifierAccount::try_deserialize(&mut nul_raw.data.as_slice()).unwrap();
    assert_eq!(nul.nullifier, NULLIFIER);
    assert_eq!(nul.withdrawal_id, 1);
}
