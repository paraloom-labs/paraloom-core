//! On-chain test for `initialize_merkle_tree` (circuit v3, #350): the tree
//! account is created, seeded with the empty-tree state, and its root is the
//! depth-level zero-subtree hash and is recognised by `is_known_root`.
//!
//! Upgrade-authority gated like the other `initialize_*` instructions (#204).

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::merkle_tree::{IncrementalMerkleTree, TREE_DEPTH, ZERO_HASHES};
use paraloom_program::{accounts, instruction};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{
    instruction::Instruction, signature::Signer, system_program, transaction::Transaction,
};

mod common;
use common::{add_program_data, entry};

#[tokio::test]
async fn initialize_merkle_tree_seeds_empty_root() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let (mut banks, _payer, blockhash) = pt.start().await;

    let (tree_pda, _) = Pubkey::find_program_address(&[b"merkle_tree"], &program_id);

    let ix = Instruction {
        program_id,
        data: instruction::InitializeMerkleTree {}.data(),
        accounts: accounts::InitializeMerkleTree {
            merkle_tree: tree_pda,
            authority: upgrade_authority.pubkey(),
            program_data: program_data_pda,
            system_program: system_program::ID,
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    banks.process_transaction(tx).await.unwrap();

    let raw = banks.get_account(tree_pda).await.unwrap().unwrap();
    let tree = IncrementalMerkleTree::try_deserialize(&mut raw.data.as_slice()).unwrap();

    assert_eq!(tree.next_index, 0);
    assert_eq!(
        tree.root, ZERO_HASHES[TREE_DEPTH],
        "empty root is the zero hash"
    );
    assert!(tree.is_known_root(ZERO_HASHES[TREE_DEPTH]));
    assert!(!tree.is_known_root([0u8; 32]));
    // Every filled subtree seeded with its level's zero hash.
    for i in 0..TREE_DEPTH {
        assert_eq!(tree.filled_subtrees[i], ZERO_HASHES[i]);
    }
}

#[tokio::test]
async fn initialize_merkle_tree_rejects_non_upgrade_authority() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, _upgrade_authority) = add_program_data(&mut pt, program_id);
    let (mut banks, payer, blockhash) = pt.start().await;

    let (tree_pda, _) = Pubkey::find_program_address(&[b"merkle_tree"], &program_id);

    // The payer is not the upgrade authority — init must be rejected.
    let ix = Instruction {
        program_id,
        data: instruction::InitializeMerkleTree {}.data(),
        accounts: accounts::InitializeMerkleTree {
            merkle_tree: tree_pda,
            authority: payer.pubkey(),
            program_data: program_data_pda,
            system_program: system_program::ID,
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[ix], Some(&payer.pubkey()));
    tx.sign(&[&payer], blockhash);
    assert!(banks.process_transaction(tx).await.is_err());
}
