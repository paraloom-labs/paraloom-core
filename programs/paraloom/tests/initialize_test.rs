//! First on-chain unit test for #71. Drives the `initialize`
//! instruction through `solana-program-test`'s in-process
//! `BanksClient`, then deserialises the freshly created
//! `BridgeState` PDA and asserts each field landed at the value the
//! handler promised. Acts as a regression pin for the bridge_state
//! seed, the program_version layout (audit #9 / #69), and the
//! initial counters / paused flag the L2 reads at startup.
//!
//! Init now requires the signer to be the program's upgrade authority
//! (#204); the harness in `common::add_program_data` seeds a fake
//! `ProgramData` PDA whose `upgrade_authority_address` is a fresh keypair
//! returned alongside, used to sign init below.

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::{accounts, instruction, BridgeState};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{instruction::Instruction, signature::Signer, transaction::Transaction};

mod common;
use common::{add_program_data, entry};

#[tokio::test]
async fn initialize_persists_bridge_state_fields() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let (mut banks_client, _payer, recent_blockhash) = pt.start().await;

    let (bridge_state_pda, _bump) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);

    let initial_merkle_root = [7u8; 32];
    let program_version = 0x0004_0000_u32;

    let ix = Instruction {
        program_id,
        data: instruction::Initialize {
            program_version,
            initial_merkle_root,
        }
        .data(),
        accounts: accounts::Initialize {
            bridge_state: bridge_state_pda,
            authority: upgrade_authority.pubkey(),
            program_data: program_data_pda,
            system_program: solana_sdk::system_program::ID,
        }
        .to_account_metas(None),
    };

    let mut tx = Transaction::new_with_payer(&[ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();

    let raw = banks_client
        .get_account(bridge_state_pda)
        .await
        .unwrap()
        .expect("bridge_state PDA must exist after initialize");
    let state = BridgeState::try_deserialize(&mut raw.data.as_slice()).unwrap();

    assert_eq!(state.program_version, program_version);
    assert_eq!(state.authority, upgrade_authority.pubkey());
    assert_eq!(state.total_deposited, 0);
    assert_eq!(state.total_withdrawn, 0);
    assert_eq!(state.deposit_count, 0);
    assert_eq!(state.withdrawal_count, 0);
    assert!(!state.paused);
    assert_eq!(state.merkle_root, initial_merkle_root);
}
