//! On-chain test for `reset_validator_registry`, the registry migration used at
//! the ceremony-key redeploy. Registers two validators, then exercises the
//! expected-count guard (#739/#741): a reset passing only ONE PDA but declaring
//! two active validators must revert (and leave the registry untouched), while a
//! reset that passes one and declares one succeeds — the property that lets the
//! redeploy drop stale registrations so the stake-weighted quorum denominator
//! reflects only the real co-signer set, without a short list silently
//! understating it. Also asserts the upgrade-authority gate rejects a
//! non-authority caller.
//!
//! (The realloc-from-the-shorter-legacy-layout path cannot be exercised here —
//! ProgramTest always creates the registry at the current size — so this test
//! pins the security-relevant rebuild/count logic; the size migration is
//! covered by the live devnet dry-run at deploy.)

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::{accounts, instruction, ValidatorRegistry};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{
    account::Account, instruction::AccountMeta, instruction::Instruction, signature::Keypair,
    signature::Signer, system_program, transaction::Transaction,
};

mod common;
use common::{add_program_data, add_stake_mint, add_token_account, entry};

const MIN_VALIDATOR_STAKE: u64 = 1_000_000_000;

fn register_ix(
    program_id: Pubkey,
    registry_pda: Pubkey,
    validator: Pubkey,
    stake_mint: Pubkey,
    validator_token: Pubkey,
) -> (Instruction, Pubkey) {
    let (validator_pda, _) =
        Pubkey::find_program_address(&[b"validator", validator.as_ref()], &program_id);
    let ix = Instruction {
        program_id,
        data: instruction::RegisterValidator {
            stake_amount: MIN_VALIDATOR_STAKE,
            token_stake_amount: paraloom_program::RECOMMENDED_MIN_TOKEN_STAKE,
        }
        .data(),
        accounts: accounts::RegisterValidator {
            validator_account: validator_pda,
            validator_registry: registry_pda,
            validator,
            stake_mint,
            validator_token_account: validator_token,
            stake_token_vault: Pubkey::find_program_address(&[b"stake_token_vault"], &program_id).0,
            token_program: spl_token::id(),
            system_program: system_program::ID,
        }
        .to_account_metas(None),
    };
    (ix, validator_pda)
}

#[tokio::test]
async fn reset_rebuilds_registry_from_passed_validators_only() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);

    // A second validator that is registered but will be LEFT OUT of the reset.
    let validator_b = Keypair::new();
    pt.add_account(
        validator_b.pubkey(),
        Account {
            lamports: 5 * MIN_VALIDATOR_STAKE,
            data: vec![],
            owner: system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );

    // Validator A: registered and KEPT through the reset. A funded keypair with
    // a token balance so it can lock the dual-stake.
    let validator_a = Keypair::new();
    pt.add_account(
        validator_a.pubkey(),
        Account {
            lamports: 5 * MIN_VALIDATOR_STAKE,
            data: vec![],
            owner: system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );
    let stake_mint = add_stake_mint(&mut pt, Pubkey::new_unique());
    let token_a = add_token_account(
        &mut pt,
        stake_mint,
        validator_a.pubkey(),
        common::TEST_TOKEN_FUND,
    );
    let token_b = add_token_account(
        &mut pt,
        stake_mint,
        validator_b.pubkey(),
        common::TEST_TOKEN_FUND,
    );
    let (mut banks, _payer, blockhash) = pt.start().await;
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);

    // Init registry.
    let init_ix = Instruction {
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
    let mut tx = Transaction::new_with_payer(&[init_ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    banks.process_transaction(tx).await.unwrap();

    // Register validator A (payer) and validator B.
    let (reg_a, pda_a) = register_ix(
        program_id,
        registry_pda,
        validator_a.pubkey(),
        stake_mint,
        token_a,
    );
    let mut tx = Transaction::new_with_payer(&[reg_a], Some(&validator_a.pubkey()));
    tx.sign(&[&validator_a], blockhash);
    banks.process_transaction(tx).await.unwrap();

    let (reg_b, _pda_b) = register_ix(
        program_id,
        registry_pda,
        validator_b.pubkey(),
        stake_mint,
        token_b,
    );
    let mut tx = Transaction::new_with_payer(&[reg_b], Some(&validator_b.pubkey()));
    tx.sign(&[&validator_b], blockhash);
    banks.process_transaction(tx).await.unwrap();

    // Both counted before the reset.
    let raw = banks.get_account(registry_pda).await.unwrap().unwrap();
    let before = ValidatorRegistry::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(before.active_validators, 2);
    assert_eq!(before.total_active_stake, 2 * MIN_VALIDATOR_STAKE);

    // The omission guard fires on a short list: pass ONLY validator A's PDA but
    // DECLARE two active validators. The rebuild sees one, the declaration says
    // two, so the reset must revert rather than silently understate the quorum
    // denominator (#739/#741).
    let mut short_metas = accounts::ResetValidatorRegistry {
        validator_registry: registry_pda,
        authority: upgrade_authority.pubkey(),
        program_data: program_data_pda,
        system_program: system_program::ID,
        stake_token_vault: Pubkey::find_program_address(&[b"stake_token_vault"], &program_id).0,
    }
    .to_account_metas(None);
    short_metas.push(AccountMeta::new_readonly(pda_a, false));
    let short_ix = Instruction {
        program_id,
        data: instruction::ResetValidatorRegistry {
            stake_mint,
            expected_active_validators: 2,
        }
        .data(),
        accounts: short_metas,
    };
    let mut tx = Transaction::new_with_payer(&[short_ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    assert!(
        banks.process_transaction(tx).await.is_err(),
        "a short remaining_accounts list must fail the expected-count guard"
    );
    // The rejected reset left the registry untouched: still two active.
    let raw = banks.get_account(registry_pda).await.unwrap().unwrap();
    let unchanged = ValidatorRegistry::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(
        unchanged.active_validators, 2,
        "a rejected reset must not mutate the registry"
    );

    // A deliberately-declared subset still works: dropping a stale registration
    // is legitimate, the reset just has to declare the count it resets to. Pass
    // ONLY validator A and declare one.
    let mut reset_metas = accounts::ResetValidatorRegistry {
        validator_registry: registry_pda,
        authority: upgrade_authority.pubkey(),
        program_data: program_data_pda,
        system_program: system_program::ID,
        stake_token_vault: Pubkey::find_program_address(&[b"stake_token_vault"], &program_id).0,
    }
    .to_account_metas(None);
    reset_metas.push(AccountMeta::new_readonly(pda_a, false));
    let reset_ix = Instruction {
        program_id,
        data: instruction::ResetValidatorRegistry {
            stake_mint,
            expected_active_validators: 1,
        }
        .data(),
        accounts: reset_metas,
    };
    let mut tx = Transaction::new_with_payer(&[reset_ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    banks.process_transaction(tx).await.unwrap();

    // Only validator A survives in the rebuilt counters.
    let raw = banks.get_account(registry_pda).await.unwrap().unwrap();
    let after = ValidatorRegistry::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(
        after.active_validators, 1,
        "only the passed validator counts"
    );
    assert_eq!(after.total_validators, 1);
    assert_eq!(after.total_active_stake, MIN_VALIDATOR_STAKE);
    assert_eq!(after.minimum_stake, MIN_VALIDATOR_STAKE);

    // The token half of the dual-stake has to come back closed too. A reset
    // to zero would leave registration open to anyone holding no tokens at
    // all, for the whole window until someone remembered to set the floor —
    // and registration is permissionless, so that window is exploitable.
    assert_ne!(
        after.min_token_stake, 0,
        "reset must not reopen the dual-stake token gate"
    );
    assert_eq!(
        after.min_token_stake,
        paraloom_program::RECOMMENDED_MIN_TOKEN_STAKE,
        "reset re-establishes the recommended floor"
    );
    assert_eq!(
        before.min_token_stake, after.min_token_stake,
        "the floor a fresh registry starts at survives the migration"
    );
}

#[tokio::test]
async fn reset_rejects_non_upgrade_authority() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let stake_mint = add_stake_mint(&mut pt, Pubkey::new_unique());
    let (mut banks, payer, blockhash) = pt.start().await;
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);

    let init_ix = Instruction {
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
    let mut tx = Transaction::new_with_payer(&[init_ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    banks.process_transaction(tx).await.unwrap();

    // The payer is NOT the upgrade authority; the reset must be rejected.
    let reset_ix = Instruction {
        program_id,
        data: instruction::ResetValidatorRegistry {
            stake_mint,
            // Rejected on the upgrade-authority gate before the guard runs.
            expected_active_validators: 1,
        }
        .data(),
        accounts: accounts::ResetValidatorRegistry {
            validator_registry: registry_pda,
            authority: payer.pubkey(),
            program_data: program_data_pda,
            system_program: system_program::ID,
            stake_token_vault: Pubkey::find_program_address(&[b"stake_token_vault"], &program_id)
                .0,
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[reset_ix], Some(&payer.pubkey()));
    tx.sign(&[&payer], blockhash);
    let err = banks.process_transaction(tx).await;
    assert!(err.is_err(), "non-authority reset must fail");
}

/// Shared setup for the #974 mint-guard tests: a registry initialized with
/// `stake_mint` (which also creates the singleton `stake_token_vault` with
/// that mint) and one registered validator. Returns the banks client, the
/// upgrade authority, the blockhash, the registry PDA and the validator PDA.
async fn setup_registry_with_one_validator(
    stake_mint_authority: Pubkey,
) -> (
    solana_program_test::BanksClient,
    Keypair,
    solana_sdk::hash::Hash,
    Pubkey,
    Pubkey,
    Pubkey,
) {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);

    let validator = Keypair::new();
    pt.add_account(
        validator.pubkey(),
        Account {
            lamports: 5 * MIN_VALIDATOR_STAKE,
            data: vec![],
            owner: system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );
    let stake_mint = add_stake_mint(&mut pt, stake_mint_authority);
    let validator_token = add_token_account(
        &mut pt,
        stake_mint,
        validator.pubkey(),
        common::TEST_TOKEN_FUND,
    );
    let (mut banks, _payer, blockhash) = pt.start().await;
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);

    let init_ix = Instruction {
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
    let mut tx = Transaction::new_with_payer(&[init_ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    banks.process_transaction(tx).await.unwrap();

    let (reg_ix, validator_pda) = register_ix(
        program_id,
        registry_pda,
        validator.pubkey(),
        stake_mint,
        validator_token,
    );
    let mut tx = Transaction::new_with_payer(&[reg_ix], Some(&validator.pubkey()));
    tx.sign(&[&validator], blockhash);
    banks.process_transaction(tx).await.unwrap();

    (
        banks,
        upgrade_authority,
        blockhash,
        registry_pda,
        validator_pda,
        stake_mint,
    )
}

fn reset_ix_with_mint(
    program_id: Pubkey,
    registry_pda: Pubkey,
    authority: Pubkey,
    program_data_pda: Pubkey,
    stake_mint: Pubkey,
    validator_pda: Pubkey,
) -> Instruction {
    let mut metas = accounts::ResetValidatorRegistry {
        validator_registry: registry_pda,
        authority,
        program_data: program_data_pda,
        system_program: system_program::ID,
        stake_token_vault: Pubkey::find_program_address(&[b"stake_token_vault"], &program_id).0,
    }
    .to_account_metas(None);
    metas.push(AccountMeta::new_readonly(validator_pda, false));
    Instruction {
        program_id,
        data: instruction::ResetValidatorRegistry {
            stake_mint,
            expected_active_validators: 1,
        }
        .data(),
        accounts: metas,
    }
}

#[tokio::test]
async fn reset_rejects_stake_mint_that_differs_from_stake_token_vault_mint() {
    // #974 (Bug 2): the singleton stake_token_vault's SPL mint is fixed at
    // creation. A reset that pins a DIFFERENT mint into the registry desyncs
    // the two and permanently bricks the dual-stake instructions, so it must
    // be rejected against the vault's actual mint — not against the
    // registry's stored value, which is the very field being overwritten.
    let program_id = paraloom_program::ID;
    let (mut banks, upgrade_authority, blockhash, registry_pda, validator_pda, stake_mint) =
        setup_registry_with_one_validator(Pubkey::new_unique()).await;
    let (program_data_pda, _) =
        Pubkey::find_program_address(&[program_id.as_ref()], &solana_sdk::bpf_loader_upgradeable::id());

    // A foreign mint (a real, initialized mint account — just not the
    // vault's) must be refused, and the registry left untouched.
    let foreign_mint = Pubkey::new_unique();
    let bad_ix = reset_ix_with_mint(
        program_id,
        registry_pda,
        upgrade_authority.pubkey(),
        program_data_pda,
        foreign_mint,
        validator_pda,
    );
    let mut tx = Transaction::new_with_payer(&[bad_ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    assert!(
        banks.process_transaction(tx).await.is_err(),
        "reset pinning a mint that differs from the stake_token_vault mint must fail"
    );
    let raw = banks.get_account(registry_pda).await.unwrap().unwrap();
    let unchanged = ValidatorRegistry::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(
        unchanged.stake_mint, stake_mint,
        "a rejected reset must leave the pinned mint untouched"
    );
    assert_eq!(unchanged.active_validators, 1);

    // Control: a reset pinning the vault's own mint still succeeds.
    let good_ix = reset_ix_with_mint(
        program_id,
        registry_pda,
        upgrade_authority.pubkey(),
        program_data_pda,
        stake_mint,
        validator_pda,
    );
    let mut tx = Transaction::new_with_payer(&[good_ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    banks
        .process_transaction(tx)
        .await
        .expect("reset pinning the vault's mint must succeed");
    let raw = banks.get_account(registry_pda).await.unwrap().unwrap();
    let after = ValidatorRegistry::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(after.stake_mint, stake_mint);
    assert_eq!(after.active_validators, 1);
}

#[tokio::test]
async fn reset_rejects_default_stake_mint() {
    // #974 (Bug 2): Pubkey::default() can never be a real vault mint; pinning
    // it would break every dual-stake instruction's mint checks.
    let program_id = paraloom_program::ID;
    let (mut banks, upgrade_authority, blockhash, registry_pda, validator_pda, stake_mint) =
        setup_registry_with_one_validator(Pubkey::new_unique()).await;
    let (program_data_pda, _) =
        Pubkey::find_program_address(&[program_id.as_ref()], &solana_sdk::bpf_loader_upgradeable::id());

    let bad_ix = reset_ix_with_mint(
        program_id,
        registry_pda,
        upgrade_authority.pubkey(),
        program_data_pda,
        Pubkey::default(),
        validator_pda,
    );
    let mut tx = Transaction::new_with_payer(&[bad_ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    assert!(
        banks.process_transaction(tx).await.is_err(),
        "reset pinning the default mint must fail"
    );
    let raw = banks.get_account(registry_pda).await.unwrap().unwrap();
    let unchanged = ValidatorRegistry::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(unchanged.stake_mint, stake_mint);
}
