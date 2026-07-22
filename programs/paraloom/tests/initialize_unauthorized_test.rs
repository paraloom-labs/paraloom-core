//! Negative tests for #204 — init front-run gate.
//!
//! `Initialize` and `InitializeValidatorRegistry` may only be invoked by the
//! program's BPFLoaderUpgradeable upgrade authority. The harness in
//! `common::add_program_data` seeds a fake `ProgramData` PDA whose
//! `upgrade_authority_address` is `upgrade_authority`. Here a different,
//! freshly funded keypair signs the init; the on-chain
//! `check_upgrade_authority` body call must reject the transaction with
//! `BridgeError::UnauthorizedInit`. Pins the gate against silent regression
//! that would re-open the race-condition surface @PerkinsFund flagged.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::system_program;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::{accounts, instruction};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{
    account::Account,
    instruction::Instruction,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

mod common;
use common::{add_program_data, add_stake_mint, entry};

/// Returns an `(impostor, banks_client, recent_blockhash, program_data_pda)`
/// where `impostor` is a fresh keypair funded as a signer but **not** the
/// upgrade authority seeded by `add_program_data`.
async fn setup_with_impostor() -> (
    Pubkey,
    Keypair,
    solana_program_test::BanksClient,
    anchor_lang::solana_program::hash::Hash,
    Pubkey,
    Pubkey,
) {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, _real_upgrade_authority) = add_program_data(&mut pt, program_id);

    let impostor = Keypair::new();
    pt.add_account(
        impostor.pubkey(),
        Account {
            lamports: 100_000_000_000,
            data: vec![],
            owner: system_program::id(),
            executable: false,
            rent_epoch: 0,
        },
    );

    let stake_mint = add_stake_mint(&mut pt, Pubkey::new_unique());
    let (banks_client, _payer, recent_blockhash) = pt.start().await;
    (
        program_id,
        impostor,
        banks_client,
        recent_blockhash,
        program_data_pda,
        stake_mint,
    )
}

#[tokio::test]
async fn initialize_with_non_upgrade_authority_signer_fails() {
    let (program_id, impostor, mut banks_client, recent_blockhash, program_data_pda, stake_mint) =
        setup_with_impostor().await;

    let (bridge_state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);

    let ix = Instruction {
        program_id,
        data: instruction::Initialize {
            program_version: 0x0004_0000,
            initial_merkle_root: [0u8; 32],
        }
        .data(),
        accounts: accounts::Initialize {
            bridge_state: bridge_state_pda,
            authority: impostor.pubkey(),
            program_data: program_data_pda,
            system_program: system_program::id(),
        }
        .to_account_metas(None),
    };

    let mut tx = Transaction::new_with_payer(&[ix], Some(&impostor.pubkey()));
    tx.sign(&[&impostor], recent_blockhash);
    let result = banks_client.process_transaction(tx).await;
    assert!(
        result.is_err(),
        "initialize must reject a signer that is not the program upgrade authority"
    );

    // PDA must not exist — front-run win blocked.
    let post = banks_client.get_account(bridge_state_pda).await.unwrap();
    assert!(
        post.is_none(),
        "bridge_state must not be created on a rejected init"
    );
}

#[tokio::test]
async fn initialize_validator_registry_with_non_upgrade_authority_signer_fails() {
    let (program_id, impostor, mut banks_client, recent_blockhash, program_data_pda, stake_mint) =
        setup_with_impostor().await;

    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);

    let ix = Instruction {
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
            authority: impostor.pubkey(),
            program_data: program_data_pda,
            system_program: system_program::id(),
        }
        .to_account_metas(None),
    };

    let mut tx = Transaction::new_with_payer(&[ix], Some(&impostor.pubkey()));
    tx.sign(&[&impostor], recent_blockhash);
    let result = banks_client.process_transaction(tx).await;
    assert!(
        result.is_err(),
        "initialize_validator_registry must reject a non-upgrade-authority signer"
    );

    let post = banks_client.get_account(registry_pda).await.unwrap();
    assert!(
        post.is_none(),
        "validator_registry must not be created on a rejected init"
    );
}
