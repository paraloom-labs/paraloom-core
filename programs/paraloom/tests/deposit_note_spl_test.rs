//! On-chain test for `deposit_note_spl` (#779): shielding an SPL token moves it
//! into that mint's `asset_vault`, appends the note commitment (asset = mint
//! bytes) to the same on-chain tree the native path uses, and enforces the
//! per-asset fail-closed deposit cap. Also exercises `init_asset_vault` +
//! `set_asset_deposit_cap`, the enabling instructions.

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::merkle_tree::{IncrementalMerkleTree, TREE_DEPTH, ZERO_HASHES};
use paraloom_program::{accounts, instruction, AssetConfig};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{
    account::Account,
    instruction::Instruction,
    signature::{Keypair, Signer},
    system_program,
    transaction::Transaction,
};

mod common;
use common::{add_program_data, add_stake_mint, add_token_account, entry};

const DEPOSIT: u64 = 1_000_000;
const DEPOSITOR_FUND: u64 = 10_000_000;

fn asset_vault_pdas(program_id: Pubkey, mint: Pubkey) -> (Pubkey, Pubkey, Pubkey) {
    let (vault, _) =
        Pubkey::find_program_address(&[b"asset_vault", mint.as_ref()], &program_id);
    let (authority, _) = Pubkey::find_program_address(&[b"asset_vault_authority"], &program_id);
    let (config, _) =
        Pubkey::find_program_address(&[b"asset_config", mint.as_ref()], &program_id);
    (vault, authority, config)
}

/// Init bridge_state + merkle_tree + the asset vault/config for `mint`, then open
/// its cap to `cap`. All signed by the upgrade authority.
async fn init_spl_pool(
    banks: &mut solana_program_test::BanksClient,
    program_id: Pubkey,
    upgrade_authority: &Keypair,
    program_data_pda: Pubkey,
    blockhash: solana_sdk::hash::Hash,
    mint: Pubkey,
    cap: u64,
) {
    let (bridge_state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (tree_pda, _) = Pubkey::find_program_address(&[b"merkle_tree"], &program_id);
    let (asset_vault, asset_vault_authority, asset_config) = asset_vault_pdas(program_id, mint);

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
            system_program: system_program::ID,
            rent: solana_sdk::sysvar::rent::ID,
        }
        .to_account_metas(None),
    };
    let set_cap = Instruction {
        program_id,
        data: instruction::SetAssetDepositCap { new_cap: cap }.data(),
        accounts: accounts::SetAssetDepositCap {
            asset_config,
            authority: upgrade_authority.pubkey(),
            program_data: program_data_pda,
        }
        .to_account_metas(None),
    };
    // init the vault in one transaction, then open the cap in a SEPARATE one.
    // set_asset_deposit_cap mutates the asset_config the init just created, and
    // a later instruction in the same transaction does not observe that create
    // reliably under solana-program-test; on mainnet these are separate
    // cold-authority operations anyway.
    let mut tx = Transaction::new_with_payer(
        &[init_state, init_tree, init_vault],
        Some(&upgrade_authority.pubkey()),
    );
    tx.sign(&[upgrade_authority], blockhash);
    banks.process_transaction(tx).await.unwrap();

    let mut cap_tx = Transaction::new_with_payer(&[set_cap], Some(&upgrade_authority.pubkey()));
    cap_tx.sign(&[upgrade_authority], blockhash);
    banks.process_transaction(cap_tx).await.unwrap();
}

fn deposit_spl_ix(
    program_id: Pubkey,
    mint: Pubkey,
    depositor: Pubkey,
    depositor_token_account: Pubkey,
    amount: u64,
) -> Instruction {
    let (bridge_state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (tree_pda, _) = Pubkey::find_program_address(&[b"merkle_tree"], &program_id);
    let (asset_vault, _, asset_config) = asset_vault_pdas(program_id, mint);
    let mut pubkey = [0u8; 32];
    pubkey[0] = 7;
    let mut blinding = [0u8; 32];
    blinding[0] = 9;
    Instruction {
        program_id,
        data: instruction::DepositNoteSpl {
            amount,
            pubkey,
            blinding,
        }
        .data(),
        accounts: accounts::DepositNoteSpl {
            bridge_state: bridge_state_pda,
            asset_config,
            mint,
            asset_vault,
            depositor_token_account,
            merkle_tree: tree_pda,
            depositor,
            token_program: spl_token::id(),
        }
        .to_account_metas(None),
    }
}

fn token_balance(account: &Account) -> u64 {
    use anchor_lang::solana_program::program_pack::Pack;
    spl_token::state::Account::unpack(&account.data).unwrap().amount
}

#[tokio::test]
async fn deposit_note_spl_appends_and_moves_tokens() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let mint = add_stake_mint(&mut pt, Pubkey::new_unique());

    // A depositor with SOL for fees and a baked token balance of `mint`.
    let depositor = Keypair::new();
    pt.add_account(
        depositor.pubkey(),
        Account {
            lamports: 1_000_000_000,
            data: vec![],
            owner: system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );
    let depositor_token = add_token_account(&mut pt, mint, depositor.pubkey(), DEPOSITOR_FUND);

    let (mut banks, _payer, blockhash) = pt.start().await;
    init_spl_pool(
        &mut banks,
        program_id,
        &upgrade_authority,
        program_data_pda,
        blockhash,
        mint,
        DEPOSIT * 10, // cap comfortably above the deposit
    )
    .await;

    let (asset_vault, _, asset_config) = asset_vault_pdas(program_id, mint);
    let (tree_pda, _) = Pubkey::find_program_address(&[b"merkle_tree"], &program_id);

    let vault_before = token_balance(&banks.get_account(asset_vault).await.unwrap().unwrap());

    let ix = deposit_spl_ix(program_id, mint, depositor.pubkey(), depositor_token, DEPOSIT);
    let mut tx = Transaction::new_with_payer(&[ix], Some(&depositor.pubkey()));
    tx.sign(&[&depositor], blockhash);
    banks.process_transaction(tx).await.unwrap();

    // Tree advanced by one leaf to a new, known, non-empty root.
    let raw = banks.get_account(tree_pda).await.unwrap().unwrap();
    let tree = IncrementalMerkleTree::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(tree.next_index, 1, "one leaf appended");
    assert_ne!(tree.root, ZERO_HASHES[TREE_DEPTH], "root advanced from empty");
    assert!(tree.is_known_root(tree.root), "new root is known");

    // Tokens moved from the depositor into the asset vault.
    let vault_after = token_balance(&banks.get_account(asset_vault).await.unwrap().unwrap());
    assert_eq!(vault_after - vault_before, DEPOSIT, "vault received the deposit");
    let depositor_after =
        token_balance(&banks.get_account(depositor_token).await.unwrap().unwrap());
    assert_eq!(depositor_after, DEPOSITOR_FUND - DEPOSIT, "depositor debited");

    // Per-asset accounting ticked.
    let craw = banks.get_account(asset_config).await.unwrap().unwrap();
    let config = AssetConfig::try_deserialize(&mut craw.data.as_slice()).unwrap();
    assert_eq!(config.mint, mint);
    assert_eq!(config.total_deposited, DEPOSIT);
    assert_eq!(config.deposit_count, 1);
}

#[tokio::test]
async fn deposit_note_spl_enforces_cap() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let mint = add_stake_mint(&mut pt, Pubkey::new_unique());

    let depositor = Keypair::new();
    pt.add_account(
        depositor.pubkey(),
        Account {
            lamports: 1_000_000_000,
            data: vec![],
            owner: system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );
    let depositor_token = add_token_account(&mut pt, mint, depositor.pubkey(), DEPOSITOR_FUND);

    let (mut banks, _payer, blockhash) = pt.start().await;
    // Cap one unit below the deposit, so it must be rejected.
    init_spl_pool(
        &mut banks,
        program_id,
        &upgrade_authority,
        program_data_pda,
        blockhash,
        mint,
        DEPOSIT - 1,
    )
    .await;

    let ix = deposit_spl_ix(program_id, mint, depositor.pubkey(), depositor_token, DEPOSIT);
    let mut tx = Transaction::new_with_payer(&[ix], Some(&depositor.pubkey()));
    tx.sign(&[&depositor], blockhash);
    let result = banks.process_transaction(tx).await;
    assert!(result.is_err(), "a deposit past the per-asset cap must be rejected");

    // No leaf appended and no tokens moved.
    let (asset_vault, _, _) = asset_vault_pdas(program_id, mint);
    let (tree_pda, _) = Pubkey::find_program_address(&[b"merkle_tree"], &program_id);
    let raw = banks.get_account(tree_pda).await.unwrap().unwrap();
    let tree = IncrementalMerkleTree::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(tree.next_index, 0, "no leaf appended on a rejected deposit");
    let vault = token_balance(&banks.get_account(asset_vault).await.unwrap().unwrap());
    assert_eq!(vault, 0, "vault untouched on a rejected deposit");
}

#[tokio::test]
async fn deposit_note_spl_closed_until_cap_opened() {
    // A freshly created asset vault has cap 0 (deposits closed) until
    // `set_asset_deposit_cap` opens it — the fail-closed default.
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let mint = add_stake_mint(&mut pt, Pubkey::new_unique());

    let depositor = Keypair::new();
    pt.add_account(
        depositor.pubkey(),
        Account {
            lamports: 1_000_000_000,
            data: vec![],
            owner: system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );
    let depositor_token = add_token_account(&mut pt, mint, depositor.pubkey(), DEPOSITOR_FUND);

    let (mut banks, _payer, blockhash) = pt.start().await;
    // Open with cap 0 == leave closed.
    init_spl_pool(
        &mut banks,
        program_id,
        &upgrade_authority,
        program_data_pda,
        blockhash,
        mint,
        0,
    )
    .await;

    let ix = deposit_spl_ix(program_id, mint, depositor.pubkey(), depositor_token, DEPOSIT);
    let mut tx = Transaction::new_with_payer(&[ix], Some(&depositor.pubkey()));
    tx.sign(&[&depositor], blockhash);
    let result = banks.process_transaction(tx).await;
    assert!(result.is_err(), "deposits are closed at cap 0");
}
