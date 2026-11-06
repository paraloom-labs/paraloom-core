//! On-chain test for `init_stake_token_vault`:
//! Upgrade-authority gated migration that creates the shared `stake_token_vault` PDA
//! for a registry that predates the vault, and verifies that `stake_mint` matches
//! `validator_registry.stake_mint`.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::program_pack::Pack;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::{accounts, instruction, ValidatorRegistry};
use solana_program_test::{tokio, ProgramTest};
use solana_sdk::{
    account::Account,
    instruction::Instruction,
    signature::{Keypair, Signer},
    system_program,
    transaction::Transaction,
};

mod common;
use common::{add_program_data, add_stake_mint, program_test, stake_vault_pdas};

fn bake_validator_registry(
    pt: &mut ProgramTest,
    program_id: Pubkey,
    authority: Pubkey,
    stake_mint: Pubkey,
) -> Pubkey {
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let reg = ValidatorRegistry {
        authority,
        total_validators: 0,
        active_validators: 0,
        minimum_stake: 1_000_000_000,
        total_active_stake: 0,
        stake_mint,
        min_token_stake: paraloom_program::RECOMMENDED_MIN_TOKEN_STAKE,
    };
    let mut data = Vec::new();
    reg.try_serialize(&mut data).unwrap();

    pt.add_account(
        registry_pda,
        Account {
            lamports: 10_000_000,
            data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );
    registry_pda
}

#[tokio::test]
async fn init_stake_token_vault_succeeds_when_mint_matches_registry() {
    let program_id = paraloom_program::ID;
    let mut pt = program_test(program_id);
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);

    let stake_mint = add_stake_mint(&mut pt, upgrade_authority.pubkey());
    let registry_pda =
        bake_validator_registry(&mut pt, program_id, upgrade_authority.pubkey(), stake_mint);

    let (banks, _payer, blockhash) = pt.start().await;

    let (vault, vault_authority) = stake_vault_pdas(program_id);

    // Assert vault does not exist yet
    assert!(banks.get_account(vault).await.unwrap().is_none());

    let ix = Instruction {
        program_id,
        data: instruction::InitStakeTokenVault {}.data(),
        accounts: accounts::InitStakeTokenVault {
            validator_registry: registry_pda,
            authority: upgrade_authority.pubkey(),
            stake_mint,
            stake_token_vault: vault,
            stake_vault_authority: vault_authority,
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

    // Verify vault is created and correctly configured
    let vault_acc = banks.get_account(vault).await.unwrap().expect("vault account exists");
    assert_eq!(vault_acc.owner, spl_token::id());
    let token_data = spl_token::state::Account::unpack(&vault_acc.data).unwrap();
    assert_eq!(token_data.mint, stake_mint);
    assert_eq!(token_data.owner, vault_authority);
    assert_eq!(token_data.amount, 0);
}

#[tokio::test]
async fn init_stake_token_vault_fails_when_mint_mismatches_registry() {
    let program_id = paraloom_program::ID;
    let mut pt = program_test(program_id);
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);

    let registry_mint = add_stake_mint(&mut pt, upgrade_authority.pubkey());
    let wrong_mint = add_stake_mint(&mut pt, upgrade_authority.pubkey());
    let registry_pda =
        bake_validator_registry(&mut pt, program_id, upgrade_authority.pubkey(), registry_mint);

    let (banks, _payer, blockhash) = pt.start().await;

    let (vault, vault_authority) = stake_vault_pdas(program_id);

    // Call init_stake_token_vault with wrong_mint
    let ix = Instruction {
        program_id,
        data: instruction::InitStakeTokenVault {}.data(),
        accounts: accounts::InitStakeTokenVault {
            validator_registry: registry_pda,
            authority: upgrade_authority.pubkey(),
            stake_mint: wrong_mint,
            stake_token_vault: vault,
            stake_vault_authority: vault_authority,
            program_data: program_data_pda,
            token_program: spl_token::id(),
            system_program: system_program::ID,
            rent: solana_sdk::sysvar::rent::ID,
        }
        .to_account_metas(None),
    };

    let mut tx = Transaction::new_with_payer(&[ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    let res = banks.process_transaction(tx).await;
    assert!(res.is_err(), "init_stake_token_vault must reject mismatched stake_mint");

    // Assert vault was not created
    assert!(banks.get_account(vault).await.unwrap().is_none());
}

#[tokio::test]
async fn init_stake_token_vault_fails_with_unauthorized_signer() {
    let program_id = paraloom_program::ID;
    let mut pt = program_test(program_id);
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);

    let impostor = Keypair::new();
    pt.add_account(
        impostor.pubkey(),
        Account {
            lamports: 10_000_000_000,
            data: vec![],
            owner: system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );

    let stake_mint = add_stake_mint(&mut pt, upgrade_authority.pubkey());
    let registry_pda =
        bake_validator_registry(&mut pt, program_id, upgrade_authority.pubkey(), stake_mint);

    let (banks, _payer, blockhash) = pt.start().await;

    let (vault, vault_authority) = stake_vault_pdas(program_id);

    let ix = Instruction {
        program_id,
        data: instruction::InitStakeTokenVault {}.data(),
        accounts: accounts::InitStakeTokenVault {
            validator_registry: registry_pda,
            authority: impostor.pubkey(),
            stake_mint,
            stake_token_vault: vault,
            stake_vault_authority: vault_authority,
            program_data: program_data_pda,
            token_program: spl_token::id(),
            system_program: system_program::ID,
            rent: solana_sdk::sysvar::rent::ID,
        }
        .to_account_metas(None),
    };

    let mut tx = Transaction::new_with_payer(&[ix], Some(&impostor.pubkey()));
    tx.sign(&[&impostor], blockhash);
    let res = banks.process_transaction(tx).await;
    assert!(res.is_err(), "init_stake_token_vault must reject non-upgrade-authority signer");

    // Assert vault was not created
    assert!(banks.get_account(vault).await.unwrap().is_none());
}
