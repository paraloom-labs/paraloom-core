//! Second on-chain unit test for #71. Drives `initialize` then
//! `deposit` through `solana-program-test` and pins the state
//! changes the L2 reads to update its shielded pool: `deposit_count`
//! must tick to 1, `total_deposited` must equal the transferred
//! amount, and the bridge_vault PDA must hold those lamports.

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::{accounts, instruction, BridgeState};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{instruction::Instruction, signature::Signer, transaction::Transaction};

mod common;
use common::entry;

#[tokio::test]
async fn deposit_credits_vault_and_advances_counters() {
    let program_id = paraloom_program::ID;
    let pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    let (bridge_state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (bridge_vault_pda, _) = Pubkey::find_program_address(&[b"bridge_vault"], &program_id);

    let init_ix = Instruction {
        program_id,
        data: instruction::Initialize {
            program_version: 0x0004_0000,
            initial_merkle_root: [0u8; 32],
        }
        .data(),
        accounts: accounts::Initialize {
            bridge_state: bridge_state_pda,
            authority: payer.pubkey(),
            system_program: solana_sdk::system_program::ID,
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[init_ix], Some(&payer.pubkey()));
    tx.sign(&[&payer], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();

    let amount: u64 = 1_000_000;
    let deposit_ix = Instruction {
        program_id,
        data: instruction::Deposit {
            amount,
            recipient: [1u8; 32],
            randomness: [2u8; 32],
        }
        .data(),
        accounts: accounts::Deposit {
            bridge_state: bridge_state_pda,
            bridge_vault: bridge_vault_pda,
            depositor: payer.pubkey(),
            system_program: solana_sdk::system_program::ID,
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[deposit_ix], Some(&payer.pubkey()));
    tx.sign(&[&payer], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();

    let state_raw = banks_client
        .get_account(bridge_state_pda)
        .await
        .unwrap()
        .unwrap();
    let state = BridgeState::try_deserialize(&mut state_raw.data.as_slice()).unwrap();
    assert_eq!(state.total_deposited, amount);
    assert_eq!(state.deposit_count, 1);

    let vault = banks_client
        .get_account(bridge_vault_pda)
        .await
        .unwrap()
        .expect("vault PDA must exist after deposit");
    assert_eq!(vault.lamports, amount);
}
