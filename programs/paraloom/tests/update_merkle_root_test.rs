//! Fourth on-chain unit test for #71. Pins the contract that
//! `update_merkle_root` actually replaces `BridgeState.merkle_root`.
//! The L2 reads this field to anchor every withdrawal proof; a
//! handler regression that silently kept the old root would let
//! verifiers accept stale Merkle paths against a tree the on-chain
//! state has already moved past. First test to use the shared
//! `tests/common` adapter shipped in the previous PR.

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::{accounts, instruction, BridgeState};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{instruction::Instruction, signature::Signer, transaction::Transaction};

mod common;
use common::entry;

#[tokio::test]
async fn update_merkle_root_replaces_state_field() {
    let program_id = paraloom_program::ID;
    let pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    let (bridge_state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);

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

    let new_root = [42u8; 32];
    let update_ix = Instruction {
        program_id,
        data: instruction::UpdateMerkleRoot {
            new_merkle_root: new_root,
        }
        .data(),
        accounts: accounts::UpdateMerkleRoot {
            bridge_state: bridge_state_pda,
            authority: payer.pubkey(),
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[update_ix], Some(&payer.pubkey()));
    tx.sign(&[&payer], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();

    let raw = banks_client
        .get_account(bridge_state_pda)
        .await
        .unwrap()
        .unwrap();
    let state = BridgeState::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(state.merkle_root, new_root);
}
