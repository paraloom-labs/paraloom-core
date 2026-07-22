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
use common::{add_program_data, add_stake_mint, entry};

const AMOUNT: u64 = 1_000_000_000;

async fn init_tree_and_state(
    banks: &mut solana_program_test::BanksClient,
    program_id: Pubkey,
    upgrade_authority: &solana_sdk::signature::Keypair,
    program_data_pda: Pubkey,
    blockhash: solana_sdk::hash::Hash,
    stake_mint: Pubkey,
    deposit_cap: u64,
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
    // Validator registry — its `authority` is the cold key that gates the
    // deposit cap. `set_deposit_cap` below opens the pool (which `initialize`
    // leaves closed at cap 0) to `deposit_cap`, so the deposits under test are
    // not rejected by the TVL cap.
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let init_registry = Instruction {
        program_id,
        data: instruction::InitializeValidatorRegistry {}.data(),
        accounts: accounts::InitializeValidatorRegistry {
            stake_mint,
            stake_token_vault: Pubkey::find_program_address(&[b"stake_token_vault"], &program_id).0,
            stake_vault_authority: Pubkey::find_program_address(
                &[b"stake_vault_authority"],
                &program_id,
            )
            .0,
            token_program: spl_token::id(),
            rent: solana_sdk::sysvar::rent::ID,
            validator_registry: registry_pda,
            authority: upgrade_authority.pubkey(),
            program_data: program_data_pda,
            system_program: system_program::ID,
        }
        .to_account_metas(None),
    };
    let set_cap = Instruction {
        program_id,
        data: instruction::SetDepositCap {
            new_cap: deposit_cap,
        }
        .data(),
        accounts: accounts::SetDepositCap {
            bridge_state: bridge_state_pda,
            validator_registry: registry_pda,
            authority: upgrade_authority.pubkey(),
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(
        &[init_state, init_tree, init_registry, set_cap],
        Some(&upgrade_authority.pubkey()),
    );
    tx.sign(&[upgrade_authority], blockhash);
    banks.process_transaction(tx).await.unwrap();
}

#[tokio::test]
async fn deposit_note_appends_and_advances_root() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let stake_mint = add_stake_mint(&mut pt, Pubkey::new_unique());
    let (mut banks, payer, blockhash) = pt.start().await;

    init_tree_and_state(
        &mut banks,
        program_id,
        &upgrade_authority,
        program_data_pda,
        blockhash,
        stake_mint,
        1_000_000_000_000, // 1000 SOL cap — well above the 1–2 SOL these deposit
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
    let stake_mint = add_stake_mint(&mut pt, Pubkey::new_unique());
    let (mut banks, payer, blockhash) = pt.start().await;

    init_tree_and_state(
        &mut banks,
        program_id,
        &upgrade_authority,
        program_data_pda,
        blockhash,
        stake_mint,
        1_000_000_000_000, // 1000 SOL cap — well above the 1–2 SOL these deposit
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
    let stake_mint = add_stake_mint(&mut pt, Pubkey::new_unique());
    let (mut banks, payer, blockhash) = pt.start().await;

    init_tree_and_state(
        &mut banks,
        program_id,
        &upgrade_authority,
        program_data_pda,
        blockhash,
        stake_mint,
        1_000_000_000_000, // 1000 SOL cap — well above the 1–2 SOL these deposit
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

/// The TVL cap bounds the vault's current balance: a deposit that would land
/// exactly on the cap is accepted, and the next one — which would push the
/// balance past it — is rejected, with no leaf appended. This is the ceiling
/// that bounds total funds-at-risk to `deposit_cap`.
#[tokio::test]
async fn deposit_note_enforces_the_deposit_cap() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let stake_mint = add_stake_mint(&mut pt, Pubkey::new_unique());
    let (mut banks, payer, blockhash) = pt.start().await;

    // Cap set to exactly one deposit: the first fills the vault to the cap, the
    // second must be refused.
    init_tree_and_state(
        &mut banks,
        program_id,
        &upgrade_authority,
        program_data_pda,
        blockhash,
        stake_mint,
        AMOUNT,
    )
    .await;

    let (bridge_state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (bridge_vault_pda, _) = Pubkey::find_program_address(&[b"bridge_vault"], &program_id);
    let (tree_pda, _) = Pubkey::find_program_address(&[b"merkle_tree"], &program_id);

    let deposit_ix = |pk: u8, bl: u8| {
        let mut pubkey = [0u8; 32];
        pubkey[0] = pk;
        let mut blinding = [0u8; 32];
        blinding[0] = bl;
        Instruction {
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
        }
    };

    // First deposit fills the vault to exactly the cap — accepted.
    let mut tx = Transaction::new_with_payer(&[deposit_ix(7, 9)], Some(&payer.pubkey()));
    tx.sign(&[&payer], blockhash);
    banks.process_transaction(tx).await.unwrap();

    // Second deposit would push the vault past the cap — rejected.
    let mut tx = Transaction::new_with_payer(&[deposit_ix(8, 10)], Some(&payer.pubkey()));
    tx.sign(&[&payer], blockhash);
    let result = banks.process_transaction(tx).await;
    assert!(result.is_err(), "a deposit past the cap must be rejected");

    // Only the first deposit's leaf landed.
    let raw = banks.get_account(tree_pda).await.unwrap().unwrap();
    let tree = IncrementalMerkleTree::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(tree.next_index, 1, "only the in-cap deposit was appended");
}

/// Raising the cap is a cold-authority operation: a signer that is not the
/// registry authority cannot lift the loss ceiling, even though the bridge is
/// otherwise permissionless to deposit into.
#[tokio::test]
async fn set_deposit_cap_requires_the_cold_authority() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let stake_mint = add_stake_mint(&mut pt, Pubkey::new_unique());
    let (mut banks, _payer, blockhash) = pt.start().await;

    // Registry authority is `upgrade_authority`; the pool opens to AMOUNT.
    init_tree_and_state(
        &mut banks,
        program_id,
        &upgrade_authority,
        program_data_pda,
        blockhash,
        stake_mint,
        AMOUNT,
    )
    .await;

    let (bridge_state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);

    // An impostor (a funded key that is NOT the registry authority) tries to
    // raise the cap. `has_one = authority` on the registry must reject it.
    let impostor = solana_sdk::signature::Keypair::new();
    let fund = solana_sdk::system_instruction::transfer(
        &upgrade_authority.pubkey(),
        &impostor.pubkey(),
        1_000_000_000,
    );
    let mut tx = Transaction::new_with_payer(&[fund], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    banks.process_transaction(tx).await.unwrap();

    let steal = Instruction {
        program_id,
        data: instruction::SetDepositCap { new_cap: u64::MAX }.data(),
        accounts: accounts::SetDepositCap {
            bridge_state: bridge_state_pda,
            validator_registry: registry_pda,
            authority: impostor.pubkey(),
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[steal], Some(&impostor.pubkey()));
    tx.sign(&[&impostor], blockhash);
    let result = banks.process_transaction(tx).await;
    assert!(
        result.is_err(),
        "a non-cold-authority signer must not be able to raise the cap"
    );

    // The cap is unchanged.
    let raw = banks.get_account(bridge_state_pda).await.unwrap().unwrap();
    let state = BridgeState::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(
        state.deposit_cap, AMOUNT,
        "cap must be unchanged after a rejected set"
    );
}
