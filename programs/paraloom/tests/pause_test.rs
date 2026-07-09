//! Third on-chain unit test for #71. Pins the pause-flag contract:
//! `pause` flips `BridgeState.paused`, and a subsequent `deposit_note`
//! against the paused bridge fails on the handler's
//! `require!(!paused, BridgePaused)` rather than silently
//! succeeding. Without this test a regression that lost the require
//! line would only surface when an admin needed pause for an
//! incident and discovered deposits were still landing.
//!
//! Init + pause both run as the upgrade authority (#204).

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::{accounts, instruction, BridgeState};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{instruction::Instruction, signature::Signer, transaction::Transaction};

mod common;
use common::{add_program_data, entry};

#[tokio::test]
async fn pause_flips_flag_and_blocks_deposit() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    let (bridge_state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (bridge_vault_pda, _) = Pubkey::find_program_address(&[b"bridge_vault"], &program_id);
    let (tree_pda, _) = Pubkey::find_program_address(&[b"merkle_tree"], &program_id);
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);

    let init_ix = Instruction {
        program_id,
        data: instruction::Initialize {
            program_version: 0x0004_0000,
            initial_merkle_root: [0u8; 32],
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
    // Initialize the on-chain tree so the paused `deposit_note` below fails on
    // the `BridgePaused` guard rather than on a missing tree account.
    let init_tree_ix = Instruction {
        program_id,
        data: instruction::InitializeMerkleTree {}.data(),
        accounts: accounts::InitializeMerkleTree {
            merkle_tree: tree_pda,
            authority: upgrade_authority.pubkey(),
            program_data: program_data_pda,
            system_program: solana_sdk::system_program::ID,
        }
        .to_account_metas(None),
    };
    // Initialize the validator registry — its `authority` is the cold key that
    // now gates pause/unpause.
    let init_registry_ix = Instruction {
        program_id,
        data: instruction::InitializeValidatorRegistry {}.data(),
        accounts: accounts::InitializeValidatorRegistry {
            validator_registry: registry_pda,
            authority: upgrade_authority.pubkey(),
            program_data: program_data_pda,
            system_program: solana_sdk::system_program::ID,
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(
        &[init_ix, init_tree_ix, init_registry_ix],
        Some(&upgrade_authority.pubkey()),
    );
    tx.sign(&[&upgrade_authority], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();

    let pause_ix = Instruction {
        program_id,
        data: instruction::Pause {}.data(),
        accounts: accounts::Pause {
            bridge_state: bridge_state_pda,
            validator_registry: registry_pda,
            authority: upgrade_authority.pubkey(),
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[pause_ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();

    let raw = banks_client
        .get_account(bridge_state_pda)
        .await
        .unwrap()
        .unwrap();
    let state = BridgeState::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert!(state.paused);

    let deposit_ix = Instruction {
        program_id,
        data: instruction::DepositNote {
            amount: 1_000_000,
            pubkey: [1u8; 32],
            blinding: [2u8; 32],
        }
        .data(),
        accounts: accounts::DepositNote {
            bridge_state: bridge_state_pda,
            bridge_vault: bridge_vault_pda,
            merkle_tree: tree_pda,
            depositor: payer.pubkey(),
            system_program: solana_sdk::system_program::ID,
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[deposit_ix], Some(&payer.pubkey()));
    tx.sign(&[&payer], recent_blockhash);
    let result = banks_client.process_transaction(tx).await;
    assert!(result.is_err(), "deposit must fail when paused");
}
