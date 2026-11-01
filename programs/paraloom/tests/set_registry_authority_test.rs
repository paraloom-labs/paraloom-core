//! Tests for `set_registry_authority` and `set_asset_deposit_cap` authority gating (#1299).
//!
//! Verifies that:
//! 1. `set_asset_deposit_cap` is gated on `validator_registry.authority` rather
//!    than BPF ProgramData upgrade authority, ensuring SPL TVL limits remain
//!    manageable even after `--final` program immutability.
//! 2. `set_registry_authority` rotates `validator_registry.authority` to a new
//!    key (e.g. cold key, multisig, or DAO governance PDA).
//! 3. Non-authority signers cannot rotate the registry authority.
//! 4. Rotating to `Pubkey::default()` is rejected with `InvalidValidator`.
//! 5. Once rotated, the new authority can set SPL deposit caps, and the old
//!    authority is rejected.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::{account_info::AccountInfo, system_program};
use anchor_lang::{AccountDeserialize, AccountSerialize, InstructionData, ToAccountMetas};
use paraloom_program::{
    accounts, instruction, AssetConfig, ValidatorRegistry, MIN_VALIDATOR_STAKE,
    RECOMMENDED_MIN_TOKEN_STAKE,
};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{
    instruction::Instruction,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

mod common;
use common::{add_program_data, add_stake_mint, entry, init_validator_registry_ix};

fn asset_vault_pdas(program_id: Pubkey, mint: Pubkey) -> (Pubkey, Pubkey, Pubkey) {
    let (vault, _) =
        Pubkey::find_program_address(&[b"asset_vault", mint.as_ref()], &program_id);
    let (authority, _) = Pubkey::find_program_address(&[b"asset_vault_authority"], &program_id);
    let (config, _) =
        Pubkey::find_program_address(&[b"asset_config", mint.as_ref()], &program_id);
    (vault, authority, config)
}

fn serialize_account<T: AccountSerialize>(val: &T, space: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(space);
    val.try_serialize(&mut buf).expect("serialize anchor account");
    if buf.len() < space {
        buf.resize(space, 0);
    }
    buf
}

#[tokio::test]
async fn set_registry_authority_rotates_and_gates_asset_deposit_cap() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let mint = add_stake_mint(&mut pt, Pubkey::new_unique());

    let (banks_client, payer, recent_blockhash) = pt.start().await;

    let (bridge_state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (tree_pda, _) = Pubkey::find_program_address(&[b"merkle_tree"], &program_id);
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (asset_vault, asset_vault_authority, asset_config) = asset_vault_pdas(program_id, mint);

    // Initialize core bridge state, merkle tree, validator registry, and asset vault.
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
            system_program: solana_sdk::system_program::ID,
        }
        .to_account_metas(None),
    };
    let init_tree = Instruction {
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
    let init_registry = init_validator_registry_ix(
        program_id,
        upgrade_authority.pubkey(),
        program_data_pda,
        mint,
    );
    let init_vault = Instruction {
        program_id,
        data: instruction::InitAssetVault {}.data(),
        accounts: accounts::InitAssetVault {
            authority: upgrade_authority.pubkey(),
            mint,
            asset_vault,
            asset_vault_authority,
            asset_config,
            program_data: program_data_pda,
            token_program: spl_token::id(),
            system_program: solana_sdk::system_program::ID,
            rent: solana_sdk::sysvar::rent::ID,
        }
        .to_account_metas(None),
    };

    let mut init_tx = Transaction::new_with_payer(
        &[init_state, init_tree, init_registry, init_vault],
        Some(&upgrade_authority.pubkey()),
    );
    init_tx.sign(&[&upgrade_authority], recent_blockhash);
    banks_client.process_transaction(init_tx).await.unwrap();

    // 1. Initial registry authority is `upgrade_authority`.
    //    An unauthorized caller cannot rotate registry authority.
    let unauthorized = Keypair::new();
    let new_authority = Keypair::new();

    let impostor_rotate_ix = Instruction {
        program_id,
        data: instruction::SetRegistryAuthority {
            new_authority: new_authority.pubkey(),
        }
        .data(),
        accounts: accounts::SetRegistryAuthority {
            validator_registry: registry_pda,
            authority: unauthorized.pubkey(),
        }
        .to_account_metas(None),
    };
    let mut impostor_tx =
        Transaction::new_with_payer(&[impostor_rotate_ix], Some(&payer.pubkey()));
    impostor_tx.sign(&[&payer, &unauthorized], recent_blockhash);
    let res = banks_client.process_transaction(impostor_tx).await;
    assert!(res.is_err(), "unauthorized signer must not rotate registry authority");

    // 2. Reject rotating to default pubkey.
    let default_rotate_ix = Instruction {
        program_id,
        data: instruction::SetRegistryAuthority {
            new_authority: Pubkey::default(),
        }
        .data(),
        accounts: accounts::SetRegistryAuthority {
            validator_registry: registry_pda,
            authority: upgrade_authority.pubkey(),
        }
        .to_account_metas(None),
    };
    let mut default_tx =
        Transaction::new_with_payer(&[default_rotate_ix], Some(&upgrade_authority.pubkey()));
    default_tx.sign(&[&upgrade_authority], recent_blockhash);
    let res = banks_client.process_transaction(default_tx).await;
    assert!(res.is_err(), "rotating to Pubkey::default must be rejected");

    // 3. Authorized rotation to `new_authority`.
    let valid_rotate_ix = Instruction {
        program_id,
        data: instruction::SetRegistryAuthority {
            new_authority: new_authority.pubkey(),
        }
        .data(),
        accounts: accounts::SetRegistryAuthority {
            validator_registry: registry_pda,
            authority: upgrade_authority.pubkey(),
        }
        .to_account_metas(None),
    };
    let mut rotate_tx =
        Transaction::new_with_payer(&[valid_rotate_ix], Some(&upgrade_authority.pubkey()));
    rotate_tx.sign(&[&upgrade_authority], recent_blockhash);
    banks_client.process_transaction(rotate_tx).await.unwrap();

    let reg_raw = banks_client.get_account(registry_pda).await.unwrap().unwrap();
    let reg = ValidatorRegistry::try_deserialize(&mut reg_raw.data.as_slice()).unwrap();
    assert_eq!(reg.authority, new_authority.pubkey());

    // 4. Old authority can no longer call set_asset_deposit_cap.
    let old_auth_cap_ix = Instruction {
        program_id,
        data: instruction::SetAssetDepositCap {
            new_cap: 10_000_000,
        }
        .data(),
        accounts: accounts::SetAssetDepositCap {
            asset_config,
            validator_registry: registry_pda,
            authority: upgrade_authority.pubkey(),
        }
        .to_account_metas(None),
    };
    let mut old_cap_tx =
        Transaction::new_with_payer(&[old_auth_cap_ix], Some(&upgrade_authority.pubkey()));
    old_cap_tx.sign(&[&upgrade_authority], recent_blockhash);
    let res = banks_client.process_transaction(old_cap_tx).await;
    assert!(res.is_err(), "old authority must be rejected after rotation");

    // 5. New authority can call set_asset_deposit_cap.
    // Fund new authority first.
    let fund_ix = solana_sdk::system_instruction::transfer(
        &payer.pubkey(),
        &new_authority.pubkey(),
        100_000_000,
    );
    let mut fund_tx = Transaction::new_with_payer(&[fund_ix], Some(&payer.pubkey()));
    fund_tx.sign(&[&payer], recent_blockhash);
    banks_client.process_transaction(fund_tx).await.unwrap();

    let new_auth_cap_ix = Instruction {
        program_id,
        data: instruction::SetAssetDepositCap {
            new_cap: 10_000_000,
        }
        .data(),
        accounts: accounts::SetAssetDepositCap {
            asset_config,
            validator_registry: registry_pda,
            authority: new_authority.pubkey(),
        }
        .to_account_metas(None),
    };
    let mut new_cap_tx =
        Transaction::new_with_payer(&[new_auth_cap_ix], Some(&new_authority.pubkey()));
    new_cap_tx.sign(&[&new_authority], recent_blockhash);
    banks_client.process_transaction(new_cap_tx).await.unwrap();

    let cfg_raw = banks_client.get_account(asset_config).await.unwrap().unwrap();
    let cfg = AssetConfig::try_deserialize(&mut cfg_raw.data.as_slice()).unwrap();
    assert_eq!(cfg.deposit_cap, 10_000_000);
}

#[test]
fn set_asset_deposit_cap_works_under_registry_authority_even_if_program_is_immutable() {
    let program_id = paraloom_program::ID;
    let cold_registry_authority = Pubkey::new_unique();
    let spl_mint = Pubkey::new_unique();
    let stake_mint = Pubkey::new_unique();

    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (asset_config_pda, asset_bump) =
        Pubkey::find_program_address(&[b"asset_config", spl_mint.as_ref()], &program_id);

    let mut registry_bytes = serialize_account(
        &ValidatorRegistry {
            authority: cold_registry_authority,
            total_validators: 4,
            active_validators: 4,
            minimum_stake: MIN_VALIDATOR_STAKE,
            total_active_stake: 4 * MIN_VALIDATOR_STAKE,
            stake_mint,
            min_token_stake: RECOMMENDED_MIN_TOKEN_STAKE,
        },
        8 + ValidatorRegistry::INIT_SPACE,
    );
    let mut asset_bytes = serialize_account(
        &AssetConfig {
            mint: spl_mint,
            deposit_cap: 1_000_000_000,
            total_deposited: 0,
            deposit_count: 0,
            bump: asset_bump,
        },
        AssetConfig::SPACE,
    );

    let mut l_reg = 1_000_000u64;
    let mut l_auth = 1_000_000u64;
    let mut l_ac = 1_000_000u64;
    let mut empty_auth = [];
    let sys_id = system_program::ID;

    // 1. set_asset_deposit_cap succeeds under validator_registry.authority
    // without requiring ProgramData upgrade authority.
    {
        let ac_ai = AccountInfo::new(
            &asset_config_pda,
            false,
            true,
            &mut l_ac,
            &mut asset_bytes,
            &program_id,
            false,
            0,
        );
        let reg_ai = AccountInfo::new(
            &registry_pda,
            false,
            false,
            &mut l_reg,
            &mut registry_bytes,
            &program_id,
            false,
            0,
        );
        let auth_ai = AccountInfo::new(
            &cold_registry_authority,
            true,
            false,
            &mut l_auth,
            &mut empty_auth,
            &sys_id,
            false,
            0,
        );
        let ix = instruction::SetAssetDepositCap { new_cap: 0 }.data();
        entry(&program_id, &[ac_ai, reg_ai, auth_ai], &ix).unwrap();
    }
    assert_eq!(
        AssetConfig::try_deserialize(&mut asset_bytes.as_slice())
            .unwrap()
            .deposit_cap,
        0
    );

    // 2. set_registry_authority rotates registry authority to a new key.
    let rotated_authority = Pubkey::new_unique();
    {
        let reg_ai = AccountInfo::new(
            &registry_pda,
            false,
            true,
            &mut l_reg,
            &mut registry_bytes,
            &program_id,
            false,
            0,
        );
        let auth_ai = AccountInfo::new(
            &cold_registry_authority,
            true,
            false,
            &mut l_auth,
            &mut empty_auth,
            &sys_id,
            false,
            0,
        );
        let ix = instruction::SetRegistryAuthority {
            new_authority: rotated_authority,
        }
        .data();
        entry(&program_id, &[reg_ai, auth_ai], &ix).unwrap();
    }
    assert_eq!(
        ValidatorRegistry::try_deserialize(&mut registry_bytes.as_slice())
            .unwrap()
            .authority,
        rotated_authority
    );

    // 3. New authority can set the SPL cap.
    {
        let ac_ai = AccountInfo::new(
            &asset_config_pda,
            false,
            true,
            &mut l_ac,
            &mut asset_bytes,
            &program_id,
            false,
            0,
        );
        let reg_ai = AccountInfo::new(
            &registry_pda,
            false,
            false,
            &mut l_reg,
            &mut registry_bytes,
            &program_id,
            false,
            0,
        );
        let auth_ai = AccountInfo::new(
            &rotated_authority,
            true,
            false,
            &mut l_auth,
            &mut empty_auth,
            &sys_id,
            false,
            0,
        );
        let ix = instruction::SetAssetDepositCap {
            new_cap: 5_000_000,
        }
        .data();
        entry(&program_id, &[ac_ai, reg_ai, auth_ai], &ix).unwrap();
    }
    assert_eq!(
        AssetConfig::try_deserialize(&mut asset_bytes.as_slice())
            .unwrap()
            .deposit_cap,
        5_000_000
    );
}
