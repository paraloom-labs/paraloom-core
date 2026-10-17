//! On-chain test for the validator dual-stake (SOL + PARALOOM-token). Register
//! locks BOTH collaterals — SOL into the validator PDA, the token into the
//! shared vault — and a slash burns the token half from the vault alongside the
//! SOL slash. Uses a mock SPL mint as the stand-in for the real PARALOOM mint.

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::{accounts, instruction, ValidatorAccount};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{
    account::Account,
    instruction::Instruction,
    program_pack::Pack,
    signature::{Keypair, Signer},
    system_program,
    transaction::Transaction,
};

mod common;
use common::{add_program_data, add_stake_mint, add_token_account, entry, stake_vault_pdas};

const SOL_STAKE: u64 = 1_000_000_000; // == MIN_VALIDATOR_STAKE
/// Both registries now start at the recommended floor, so a registration
/// that is meant to succeed has to clear it.
const TOKEN_STAKE: u64 = paraloom_program::RECOMMENDED_MIN_TOKEN_STAKE;
const TOKEN_FUND: u64 = TOKEN_STAKE * 2;

#[tokio::test]
async fn register_locks_both_stakes_and_slash_burns_the_token() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);

    // A validator funded with SOL and a token balance to stake.
    let validator = Keypair::new();
    pt.add_account(
        validator.pubkey(),
        Account {
            lamports: 10_000_000_000,
            data: vec![],
            owner: system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );
    let stake_mint = add_stake_mint(&mut pt, upgrade_authority.pubkey());
    let validator_token = add_token_account(&mut pt, stake_mint, validator.pubkey(), TOKEN_FUND);

    let (mut banks, _payer, blockhash) = pt.start().await;

    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (vault, vault_authority) = stake_vault_pdas(program_id);
    let (validator_pda, _) =
        Pubkey::find_program_address(&[b"validator", validator.pubkey().as_ref()], &program_id);
    let (slashed_funds_vault, _) =
        Pubkey::find_program_address(&[b"slashed_funds_vault"], &program_id);

    // 1. Initialize the registry — pins `stake_mint` and creates the vault.
    let init_registry = Instruction {
        program_id,
        data: instruction::InitializeValidatorRegistry {}.data(),
        accounts: accounts::InitializeValidatorRegistry {
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
    let mut tx = Transaction::new_with_payer(&[init_registry], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    banks.process_transaction(tx).await.unwrap();

    // 2. Register with the dual stake.
    let register = Instruction {
        program_id,
        data: instruction::RegisterValidator {
            stake_amount: SOL_STAKE,
            token_stake_amount: TOKEN_STAKE,
        }
        .data(),
        accounts: accounts::RegisterValidator {
            stake_mint,
            validator_account: validator_pda,
            validator_registry: registry_pda,
            validator: validator.pubkey(),
            validator_token_account: validator_token,
            stake_token_vault: vault,
            token_program: spl_token::id(),
            system_program: system_program::ID,
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[register], Some(&validator.pubkey()));
    tx.sign(&[&validator], blockhash);
    banks.process_transaction(tx).await.unwrap();

    // The token half moved into the vault and is accounted on the PDA.
    let raw = banks.get_account(validator_pda).await.unwrap().unwrap();
    let va = ValidatorAccount::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(va.token_stake_amount, TOKEN_STAKE, "token stake recorded");
    assert_eq!(va.stake_amount, SOL_STAKE, "SOL stake recorded");

    let vault_raw = banks.get_account(vault).await.unwrap().unwrap();
    let vault_state = spl_token::state::Account::unpack(&vault_raw.data).unwrap();
    assert_eq!(vault_state.amount, TOKEN_STAKE, "token locked in the vault");
    // The validator's own balance dropped by exactly the staked token amount.
    let vt_raw = banks.get_account(validator_token).await.unwrap().unwrap();
    let vt_state = spl_token::state::Account::unpack(&vt_raw.data).unwrap();
    assert_eq!(
        vt_state.amount,
        TOKEN_FUND - TOKEN_STAKE,
        "token debited from validator"
    );

    // 3. Slash 50% — burns half the token stake from the vault.
    let slash = Instruction {
        program_id,
        data: instruction::SlashValidator {
            validator: validator.pubkey(),
            slash_percentage: 50,
        }
        .data(),
        accounts: accounts::SlashValidator {
            validator_account: validator_pda,
            slashed_funds_vault,
            validator_registry: registry_pda,
            stake_mint,
            stake_token_vault: vault,
            stake_vault_authority: vault_authority,
            token_program: spl_token::id(),
            authority: upgrade_authority.pubkey(),
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[slash], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    banks.process_transaction(tx).await.unwrap();

    // Half the token stake was burned from the vault (total supply-reducing).
    let vault_raw = banks.get_account(vault).await.unwrap().unwrap();
    let vault_state = spl_token::state::Account::unpack(&vault_raw.data).unwrap();
    assert_eq!(
        vault_state.amount,
        TOKEN_STAKE / 2,
        "half the token stake burned on the 50% slash"
    );
}

/// Register must reject a token stake below the minimum even when the SOL stake
/// is sufficient — both halves of the dual-stake are required.
#[tokio::test]
async fn register_rejects_token_stake_below_minimum() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);

    let validator = Keypair::new();
    pt.add_account(
        validator.pubkey(),
        Account {
            lamports: 10_000_000_000,
            data: vec![],
            owner: system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );
    let stake_mint = add_stake_mint(&mut pt, upgrade_authority.pubkey());
    let validator_token = add_token_account(&mut pt, stake_mint, validator.pubkey(), TOKEN_FUND);

    let (mut banks, _payer, blockhash) = pt.start().await;

    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (vault, vault_authority) = stake_vault_pdas(program_id);
    let (validator_pda, _) =
        Pubkey::find_program_address(&[b"validator", validator.pubkey().as_ref()], &program_id);

    let init_registry = Instruction {
        program_id,
        data: instruction::InitializeValidatorRegistry {}.data(),
        accounts: accounts::InitializeValidatorRegistry {
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
    let mut tx = Transaction::new_with_payer(&[init_registry], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    banks.process_transaction(tx).await.unwrap();

    // Open the token gate: raise the floor from 0 (default) to 1e6, so a 0 token
    // stake is now below the minimum. Also exercises `set_min_token_stake`.
    let set_min = Instruction {
        program_id,
        data: instruction::SetMinTokenStake { new_min: 1_000_000 }.data(),
        accounts: accounts::SetMinTokenStake {
            validator_registry: registry_pda,
            authority: upgrade_authority.pubkey(),
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[set_min], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    banks.process_transaction(tx).await.unwrap();

    // SOL stake fine, token stake = 0 (< configured min_token_stake) → rejected.
    let register = Instruction {
        program_id,
        data: instruction::RegisterValidator {
            stake_amount: SOL_STAKE,
            token_stake_amount: 0,
        }
        .data(),
        accounts: accounts::RegisterValidator {
            stake_mint,
            validator_account: validator_pda,
            validator_registry: registry_pda,
            validator: validator.pubkey(),
            validator_token_account: validator_token,
            stake_token_vault: vault,
            token_program: spl_token::id(),
            system_program: system_program::ID,
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[register], Some(&validator.pubkey()));
    tx.sign(&[&validator], blockhash);
    let result = banks.process_transaction(tx).await;
    assert!(
        result.is_err(),
        "a token stake below the minimum must be rejected"
    );
}

#[tokio::test]
async fn deactivate_validator_routes_token_stake_into_unbonding_and_preserves_exit() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);

    let validator = Keypair::new();
    pt.add_account(
        validator.pubkey(),
        Account {
            lamports: 10_000_000_000,
            data: vec![],
            owner: system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );
    let stake_mint = add_stake_mint(&mut pt, upgrade_authority.pubkey());
    let validator_token = add_token_account(&mut pt, stake_mint, validator.pubkey(), TOKEN_FUND);

    let mut ctx = pt.start_with_context().await;
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (vault, vault_authority) = stake_vault_pdas(program_id);
    let (validator_pda, _) =
        Pubkey::find_program_address(&[b"validator", validator.pubkey().as_ref()], &program_id);
    let (slashed_funds_vault, _) =
        Pubkey::find_program_address(&[b"slashed_funds_vault"], &program_id);

    // 1. Initialize registry and register dual-staked validator.
    let init_registry = Instruction {
        program_id,
        data: instruction::InitializeValidatorRegistry {}.data(),
        accounts: accounts::InitializeValidatorRegistry {
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
    let bh = ctx.get_new_latest_blockhash().await.unwrap();
    let mut tx = Transaction::new_with_payer(&[init_registry], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], bh);
    ctx.banks_client.process_transaction(tx).await.unwrap();

    let register = Instruction {
        program_id,
        data: instruction::RegisterValidator {
            stake_amount: SOL_STAKE,
            token_stake_amount: TOKEN_STAKE,
        }
        .data(),
        accounts: accounts::RegisterValidator {
            stake_mint,
            validator_account: validator_pda,
            validator_registry: registry_pda,
            validator: validator.pubkey(),
            validator_token_account: validator_token,
            stake_token_vault: vault,
            token_program: spl_token::id(),
            system_program: system_program::ID,
        }
        .to_account_metas(None),
    };
    let bh = ctx.get_new_latest_blockhash().await.unwrap();
    let mut tx = Transaction::new_with_payer(&[register], Some(&validator.pubkey()));
    tx.sign(&[&validator], bh);
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // 2. Deactivate validator via admin instruction.
    let deactivate = Instruction {
        program_id,
        data: instruction::DeactivateValidator {}.data(),
        accounts: accounts::DeactivateValidator {
            validator_account: validator_pda,
            validator_registry: registry_pda,
            authority: upgrade_authority.pubkey(),
        }
        .to_account_metas(None),
    };
    let bh = ctx.get_new_latest_blockhash().await.unwrap();
    let mut tx = Transaction::new_with_payer(&[deactivate], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], bh);
    ctx.banks_client.process_transaction(tx).await.unwrap();

    let raw = ctx
        .banks_client
        .get_account(validator_pda)
        .await
        .unwrap()
        .unwrap();
    let va = ValidatorAccount::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert!(!va.is_active);
    assert_eq!(va.stake_amount, 0);
    assert_eq!(va.unbonding_amount, SOL_STAKE);
    assert_eq!(
        va.token_stake_amount, 0,
        "deactivate_validator must move token_stake_amount out of active stake"
    );
    assert_eq!(
        va.token_unbonding_amount, TOKEN_STAKE,
        "deactivate_validator must route token_stake_amount into token_unbonding_amount"
    );

    // 3. A 25% slash during unbonding must burn 25% of the unbonding token stake.
    let slash = Instruction {
        program_id,
        data: instruction::SlashValidator {
            validator: validator.pubkey(),
            slash_percentage: 25,
        }
        .data(),
        accounts: accounts::SlashValidator {
            validator_account: validator_pda,
            slashed_funds_vault,
            validator_registry: registry_pda,
            stake_mint,
            stake_token_vault: vault,
            stake_vault_authority: vault_authority,
            token_program: spl_token::id(),
            authority: upgrade_authority.pubkey(),
        }
        .to_account_metas(None),
    };
    let bh = ctx.get_new_latest_blockhash().await.unwrap();
    let mut tx = Transaction::new_with_payer(&[slash], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], bh);
    ctx.banks_client.process_transaction(tx).await.unwrap();

    // 4. Warp past UNBONDING_SLOTS and withdraw unbonded stake: remaining 75%
    // of TOKEN_STAKE must return to validator_token rather than being stranded
    // in stake_token_vault when validator_account closes.
    ctx.warp_to_slot(va.unbonding_slot + 1).unwrap();
    let withdraw = Instruction {
        program_id,
        data: instruction::WithdrawUnbondedStake {}.data(),
        accounts: accounts::WithdrawUnbondedStake {
            validator_account: validator_pda,
            validator: validator.pubkey(),
            stake_mint,
            validator_token_account: validator_token,
            stake_token_vault: vault,
            stake_vault_authority: vault_authority,
            token_program: spl_token::id(),
        }
        .to_account_metas(None),
    };
    let bh = ctx.get_new_latest_blockhash().await.unwrap();
    let mut tx = Transaction::new_with_payer(&[withdraw], Some(&validator.pubkey()));
    tx.sign(&[&validator], bh);
    ctx.banks_client.process_transaction(tx).await.unwrap();

    let vt_raw = ctx
        .banks_client
        .get_account(validator_token)
        .await
        .unwrap()
        .unwrap();
    let vt_state = spl_token::state::Account::unpack(&vt_raw.data).unwrap();
    assert_eq!(
        vt_state.amount,
        TOKEN_FUND - TOKEN_STAKE / 4,
        "unslashed 75% of token stake must be returned on withdraw_unbonded_stake"
    );
}

#[tokio::test]
async fn slash_deactivates_validator_when_token_stake_drops_below_min_token_stake() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);

    let validator = Keypair::new();
    pt.add_account(
        validator.pubkey(),
        Account {
            lamports: 10_000_000_000,
            data: vec![],
            owner: system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );
    let stake_mint = add_stake_mint(&mut pt, upgrade_authority.pubkey());
    let validator_token = add_token_account(&mut pt, stake_mint, validator.pubkey(), TOKEN_FUND);

    let (mut banks, _payer, blockhash) = pt.start().await;
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (vault, vault_authority) = stake_vault_pdas(program_id);
    let (validator_pda, _) =
        Pubkey::find_program_address(&[b"validator", validator.pubkey().as_ref()], &program_id);
    let (slashed_funds_vault, _) =
        Pubkey::find_program_address(&[b"slashed_funds_vault"], &program_id);

    let init_registry = Instruction {
        program_id,
        data: instruction::InitializeValidatorRegistry {}.data(),
        accounts: accounts::InitializeValidatorRegistry {
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
    let mut tx = Transaction::new_with_payer(&[init_registry], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    banks.process_transaction(tx).await.unwrap();

    // Register with 2x minimum SOL stake (2 SOL) and 1x minimum token stake.
    let register = Instruction {
        program_id,
        data: instruction::RegisterValidator {
            stake_amount: SOL_STAKE * 2,
            token_stake_amount: TOKEN_STAKE,
        }
        .data(),
        accounts: accounts::RegisterValidator {
            stake_mint,
            validator_account: validator_pda,
            validator_registry: registry_pda,
            validator: validator.pubkey(),
            validator_token_account: validator_token,
            stake_token_vault: vault,
            token_program: spl_token::id(),
            system_program: system_program::ID,
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[register], Some(&validator.pubkey()));
    tx.sign(&[&validator], blockhash);
    banks.process_transaction(tx).await.unwrap();

    // Slash 20%: SOL drops from 2 SOL to 1.6 SOL (still >= 1 SOL minimum_stake),
    // but token_stake_amount drops from TOKEN_STAKE to 0.8 * TOKEN_STAKE
    // (< min_token_stake). The validator must be deactivated and its residual
    // SOL + token collateral routed into unbonding.
    let slash = Instruction {
        program_id,
        data: instruction::SlashValidator {
            validator: validator.pubkey(),
            slash_percentage: 20,
        }
        .data(),
        accounts: accounts::SlashValidator {
            validator_account: validator_pda,
            slashed_funds_vault,
            validator_registry: registry_pda,
            stake_mint,
            stake_token_vault: vault,
            stake_vault_authority: vault_authority,
            token_program: spl_token::id(),
            authority: upgrade_authority.pubkey(),
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[slash], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    banks.process_transaction(tx).await.unwrap();

    let raw = banks.get_account(validator_pda).await.unwrap().unwrap();
    let va = ValidatorAccount::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert!(
        !va.is_active,
        "dropping below min_token_stake must deactivate the validator even when SOL stake remains above minimum_stake"
    );
    assert_eq!(va.stake_amount, 0);
    assert_eq!(va.token_stake_amount, 0);
    assert_eq!(va.unbonding_amount, (SOL_STAKE * 2) * 80 / 100);
    assert_eq!(va.token_unbonding_amount, TOKEN_STAKE * 80 / 100);
}

