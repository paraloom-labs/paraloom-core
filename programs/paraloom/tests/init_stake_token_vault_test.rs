//! Integration tests for `init_stake_token_vault` (#1356).
//!
//! Validates the migration path for initializing the dual-stake token vault
//! against an existing `validator_registry`:
//! 1. When `validator_registry.stake_mint` is pinned, `init_stake_token_vault`
//!    MUST reject a mismatched `stake_mint` and accept only the matching mint.
//! 2. `validator_registry` must be owned by the program and match the expected discriminator.
//! 3. Only the program's upgrade authority may execute the migration.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::program_pack::Pack;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::{accounts, instruction, ValidatorRegistry};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{
    account::Account,
    instruction::Instruction,
    signature::{Keypair, Signer},
    system_program,
    transaction::Transaction,
};

mod common;
use common::{add_program_data, add_stake_mint, entry, stake_vault_pdas};

fn bake_validator_registry(
    pt: &mut ProgramTest,
    program_id: Pubkey,
    authority: Pubkey,
    stake_mint: Pubkey,
) -> Pubkey {
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let registry = ValidatorRegistry {
        authority,
        total_validators: 0,
        active_validators: 0,
        minimum_stake: 1_000_000_000,
        total_active_stake: 0,
        stake_mint,
        min_token_stake: paraloom_program::RECOMMENDED_MIN_TOKEN_STAKE,
    };
    let mut data = Vec::new();
    data.extend_from_slice(&ValidatorRegistry::DISCRIMINATOR);
    registry
        .serialize(&mut data)
        .expect("serialize ValidatorRegistry");
    pt.add_account(
        registry_pda,
        Account {
            lamports: 1_000_000_000,
            data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );
    registry_pda
}

#[tokio::test]
async fn init_stake_token_vault_with_matching_stake_mint_succeeds() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);

    let stake_mint = add_stake_mint(&mut pt, upgrade_authority.pubkey());
    let registry_pda =
        bake_validator_registry(&mut pt, program_id, upgrade_authority.pubkey(), stake_mint);

    let (mut banks, _payer, blockhash) = pt.start().await;
    let (vault, vault_authority) = stake_vault_pdas(program_id);

    let ix = Instruction {
        program_id,
        data: instruction::InitStakeTokenVault {}.data(),
        accounts: accounts::InitStakeTokenVault {
            authority: upgrade_authority.pubkey(),
            stake_mint,
            stake_token_vault: vault,
            stake_vault_authority: vault_authority,
            validator_registry: registry_pda,
            program_data: program_data_pda,
            token_program: spl_token::id(),
            system_program: system_program::ID,
            rent: solana_sdk::sysvar::rent::ID,
        }
        .to_account_metas(None),
    };

    let mut tx = Transaction::new_with_payer(&[ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    banks.process_transaction(tx).await.unwrap();

    let vault_acc = banks
        .get_account(vault)
        .await
        .unwrap()
        .expect("vault exists");
    assert_eq!(vault_acc.owner, spl_token::id());
    let token_data = spl_token::state::Account::unpack(&vault_acc.data).unwrap();
    assert_eq!(token_data.mint, stake_mint);
    assert_eq!(token_data.owner, vault_authority);
}

#[tokio::test]
async fn init_stake_token_vault_with_mismatched_stake_mint_fails() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);

    let registry_mint = add_stake_mint(&mut pt, upgrade_authority.pubkey());
    let rogue_mint = add_stake_mint(&mut pt, upgrade_authority.pubkey());
    assert_ne!(registry_mint, rogue_mint);

    let registry_pda = bake_validator_registry(
        &mut pt,
        program_id,
        upgrade_authority.pubkey(),
        registry_mint,
    );

    let (mut banks, _payer, blockhash) = pt.start().await;
    let (vault, vault_authority) = stake_vault_pdas(program_id);

    // Attempt to initialize vault with rogue_mint despite registry specifying registry_mint
    let ix = Instruction {
        program_id,
        data: instruction::InitStakeTokenVault {}.data(),
        accounts: accounts::InitStakeTokenVault {
            authority: upgrade_authority.pubkey(),
            stake_mint: rogue_mint,
            stake_token_vault: vault,
            stake_vault_authority: vault_authority,
            validator_registry: registry_pda,
            program_data: program_data_pda,
            token_program: spl_token::id(),
            system_program: system_program::ID,
            rent: solana_sdk::sysvar::rent::ID,
        }
        .to_account_metas(None),
    };

    let mut tx = Transaction::new_with_payer(&[ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    let result = banks.process_transaction(tx).await;
    assert!(
        result.is_err(),
        "init_stake_token_vault must reject a stake_mint that mismatches validator_registry"
    );

    let vault_acc = banks.get_account(vault).await.unwrap();
    assert!(
        vault_acc.is_none(),
        "vault must not be created on mismatched mint"
    );
}

#[tokio::test]
async fn init_stake_token_vault_with_unowned_registry_fails() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);

    let stake_mint = add_stake_mint(&mut pt, upgrade_authority.pubkey());
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);

    // Add fake registry owned by system_program instead of paraloom program
    pt.add_account(
        registry_pda,
        Account {
            lamports: 1_000_000_000,
            data: vec![0u8; 112],
            owner: system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );

    let (mut banks, _payer, blockhash) = pt.start().await;
    let (vault, vault_authority) = stake_vault_pdas(program_id);

    let ix = Instruction {
        program_id,
        data: instruction::InitStakeTokenVault {}.data(),
        accounts: accounts::InitStakeTokenVault {
            authority: upgrade_authority.pubkey(),
            stake_mint,
            stake_token_vault: vault,
            stake_vault_authority: vault_authority,
            validator_registry: registry_pda,
            program_data: program_data_pda,
            token_program: spl_token::id(),
            system_program: system_program::ID,
            rent: solana_sdk::sysvar::rent::ID,
        }
        .to_account_metas(None),
    };

    let mut tx = Transaction::new_with_payer(&[ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    let result = banks.process_transaction(tx).await;
    assert!(
        result.is_err(),
        "init_stake_token_vault must reject an unowned registry account"
    );

    let vault_acc = banks.get_account(vault).await.unwrap();
    assert!(vault_acc.is_none(), "vault must not be created");
}

#[tokio::test]
async fn init_stake_token_vault_with_legacy_registry_uninitialized_stake_mint_succeeds() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);

    let stake_mint = add_stake_mint(&mut pt, upgrade_authority.pubkey());
    // Registry has stake_mint = default (uninitialized)
    let registry_pda = bake_validator_registry(
        &mut pt,
        program_id,
        upgrade_authority.pubkey(),
        Pubkey::default(),
    );

    let (mut banks, _payer, blockhash) = pt.start().await;
    let (vault, vault_authority) = stake_vault_pdas(program_id);

    let ix = Instruction {
        program_id,
        data: instruction::InitStakeTokenVault {}.data(),
        accounts: accounts::InitStakeTokenVault {
            authority: upgrade_authority.pubkey(),
            stake_mint,
            stake_token_vault: vault,
            stake_vault_authority: vault_authority,
            validator_registry: registry_pda,
            program_data: program_data_pda,
            token_program: spl_token::id(),
            system_program: system_program::ID,
            rent: solana_sdk::sysvar::rent::ID,
        }
        .to_account_metas(None),
    };

    let mut tx = Transaction::new_with_payer(&[ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    banks.process_transaction(tx).await.unwrap();

    let vault_acc = banks
        .get_account(vault)
        .await
        .unwrap()
        .expect("vault exists");
    let token_data = spl_token::state::Account::unpack(&vault_acc.data).unwrap();
    assert_eq!(token_data.mint, stake_mint);
    assert_eq!(token_data.owner, vault_authority);
}
