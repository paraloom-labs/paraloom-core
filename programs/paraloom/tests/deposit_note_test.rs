//! On-chain test for `deposit_note` (circuit v3, #350): a deposit moves SOL
//! into the vault and appends the note commitment to the on-chain tree, so the
//! root advances and the new root is recognised by `is_known_root`.

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::merkle_tree::{IncrementalMerkleTree, TREE_DEPTH, ZERO_HASHES};
use paraloom_program::{accounts, instruction, BridgeState};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{
    instruction::Instruction, signature::Signer, system_program, transaction::Transaction,
};

mod common;
use common::{add_program_data, entry};

const AMOUNT: u64 = 1_000_000_000;

async fn init_tree_and_state(
    banks: &mut solana_program_test::BanksClient,
    program_id: Pubkey,
    upgrade_authority: &solana_sdk::signature::Keypair,
    program_data_pda: Pubkey,
    blockhash: solana_sdk::hash::Hash,
) {
    // Bridge state (for the paused flag + counters).
    let (bridge_state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let init_state = Instruction {
        program_id,
        data: instruction::Initialize {
            program_version: 1,
            initial_merkle_root: [0u8; 32],
        }
        .data(),
        accounts: accounts::Initialize {
            bridge_state: bridge_state_pda,
            authority: upgrade_authority.pubkey(),
            program_data: program_data_pda,
            system_program: system_program::ID,
        }
        .to_account_metas(None),
    };
    // Merkle tree.
    let (tree_pda, _) = Pubkey::find_program_address(&[b"merkle_tree"], &program_id);
    let init_tree = Instruction {
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
    let mut tx =
        Transaction::new_with_payer(&[init_state, init_tree], Some(&upgrade_authority.pubkey()));
    tx.sign(&[upgrade_authority], blockhash);
    banks.process_transaction(tx).await.unwrap();
}

#[tokio::test]
async fn deposit_note_appends_and_advances_root() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let (mut banks, payer, blockhash) = pt.start().await;

    init_tree_and_state(
        &mut banks,
        program_id,
        &upgrade_authority,
        program_data_pda,
        blockhash,
    )
    .await;

    let (bridge_state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (bridge_vault_pda, _) = Pubkey::find_program_address(&[b"bridge_vault"], &program_id);
    let (tree_pda, _) = Pubkey::find_program_address(&[b"merkle_tree"], &program_id);

    let vault_before = banks
        .get_account(bridge_vault_pda)
        .await
        .unwrap()
        .map(|a| a.lamports)
        .unwrap_or(0);

    // pubkey/blinding are arbitrary field-element bytes for this test.
    let mut pubkey = [0u8; 32];
    pubkey[0] = 7;
    let mut blinding = [0u8; 32];
    blinding[0] = 9;

    let deposit = Instruction {
        program_id,
        data: instruction::DepositNote {
            amount: AMOUNT,
            pubkey,
            blinding,
        }
        .data(),
        accounts: accounts::DepositNote {
            bridge_state: bridge_state_pda,
            bridge_vault: bridge_vault_pda,
            merkle_tree: tree_pda,
            depositor: payer.pubkey(),
            system_program: system_program::ID,
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[deposit], Some(&payer.pubkey()));
    tx.sign(&[&payer], blockhash);
    banks.process_transaction(tx).await.unwrap();

    // The tree advanced by one leaf, to a new, known root ≠ the empty root.
    let raw = banks.get_account(tree_pda).await.unwrap().unwrap();
    let tree = IncrementalMerkleTree::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(tree.next_index, 1, "one leaf appended");
    assert_ne!(
        tree.root, ZERO_HASHES[TREE_DEPTH],
        "root advanced from empty"
    );
    assert!(tree.is_known_root(tree.root), "new root is known");

    // The deposit reached the vault.
    let vault_after = banks
        .get_account(bridge_vault_pda)
        .await
        .unwrap()
        .unwrap()
        .lamports;
    assert_eq!(
        vault_after - vault_before,
        AMOUNT,
        "deposit reached the vault"
    );

    // The deposit counter ticked.
    let sraw = banks.get_account(bridge_state_pda).await.unwrap().unwrap();
    let state = BridgeState::try_deserialize(&mut sraw.data.as_slice()).unwrap();
    assert_eq!(state.deposit_count, 1);
}

#[tokio::test]
async fn deposit_note_two_deposits_advance_index() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let (mut banks, payer, blockhash) = pt.start().await;

    init_tree_and_state(
        &mut banks,
        program_id,
        &upgrade_authority,
        program_data_pda,
        blockhash,
    )
    .await;

    let (bridge_state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (bridge_vault_pda, _) = Pubkey::find_program_address(&[b"bridge_vault"], &program_id);
    let (tree_pda, _) = Pubkey::find_program_address(&[b"merkle_tree"], &program_id);

    for k in 1u8..=2 {
        let mut pubkey = [0u8; 32];
        pubkey[0] = k;
        let mut blinding = [0u8; 32];
        blinding[0] = 100 + k;
        let deposit = Instruction {
            program_id,
            data: instruction::DepositNote {
                amount: AMOUNT,
                pubkey,
                blinding,
            }
            .data(),
            accounts: accounts::DepositNote {
                bridge_state: bridge_state_pda,
                bridge_vault: bridge_vault_pda,
                merkle_tree: tree_pda,
                depositor: payer.pubkey(),
                system_program: system_program::ID,
            }
            .to_account_metas(None),
        };
        let mut tx = Transaction::new_with_payer(&[deposit], Some(&payer.pubkey()));
        tx.sign(&[&payer], blockhash);
        banks.process_transaction(tx).await.unwrap();
    }

    let raw = banks.get_account(tree_pda).await.unwrap().unwrap();
    let tree = IncrementalMerkleTree::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(tree.next_index, 2, "two leaves appended");
    assert!(tree.is_known_root(tree.root));
}

#[tokio::test]
async fn deposit_note_rejects_a_non_canonical_field_input() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let (mut banks, payer, blockhash) = pt.start().await;

    init_tree_and_state(
        &mut banks,
        program_id,
        &upgrade_authority,
        program_data_pda,
        blockhash,
    )
    .await;

    let (bridge_state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (bridge_vault_pda, _) = Pubkey::find_program_address(&[b"bridge_vault"], &program_id);
    let (tree_pda, _) = Pubkey::find_program_address(&[b"merkle_tree"], &program_id);

    // A blinding >= the BN254 scalar modulus is non-canonical: the Poseidon
    // syscall would silently reduce it mod p, committing a leaf the wallet's
    // raw-byte witness could never reproduce and bricking the note. All-0xFF is
    // 2^256 - 1, well above p, so `deposit_note` must reject it before hashing.
    let mut pubkey = [0u8; 32];
    pubkey[0] = 7;
    let blinding = [0xFFu8; 32];

    let deposit = Instruction {
        program_id,
        data: instruction::DepositNote {
            amount: AMOUNT,
            pubkey,
            blinding,
        }
        .data(),
        accounts: accounts::DepositNote {
            bridge_state: bridge_state_pda,
            bridge_vault: bridge_vault_pda,
            merkle_tree: tree_pda,
            depositor: payer.pubkey(),
            system_program: system_program::ID,
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[deposit], Some(&payer.pubkey()));
    tx.sign(&[&payer], blockhash);
    let result = banks.process_transaction(tx).await;
    assert!(
        result.is_err(),
        "a non-canonical blinding must be rejected before hashing"
    );

    // The transaction reverted: no leaf was appended.
    let raw = banks.get_account(tree_pda).await.unwrap().unwrap();
    let tree = IncrementalMerkleTree::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(tree.next_index, 0, "no leaf appended on a rejected deposit");
}
