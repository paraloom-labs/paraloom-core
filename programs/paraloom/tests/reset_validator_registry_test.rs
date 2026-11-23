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
use paraloom_program::{accounts, instruction, ValidatorAccount, ValidatorRegistry};
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
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[reset_ix], Some(&payer.pubkey()));
    tx.sign(&[&payer], blockhash);
    let err = banks.process_transaction(tx).await;
    assert!(err.is_err(), "non-authority reset must fail");
}

#[tokio::test]
async fn unregister_reset_excluded_orphan_preserves_registry_counters() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);

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

    // Register validator A and validator B.
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

    let (reg_b, pda_b) = register_ix(
        program_id,
        registry_pda,
        validator_b.pubkey(),
        stake_mint,
        token_b,
    );
    let mut tx = Transaction::new_with_payer(&[reg_b], Some(&validator_b.pubkey()));
    tx.sign(&[&validator_b], blockhash);
    banks.process_transaction(tx).await.unwrap();

    // Verify both are counted before reset.
    let raw = banks.get_account(registry_pda).await.unwrap().unwrap();
    let reg_before = ValidatorRegistry::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(reg_before.active_validators, 2);
    assert_eq!(reg_before.total_active_stake, 2 * MIN_VALIDATOR_STAKE);
    assert_eq!(reg_before.active_keys.len(), 2);

    // Reset registry including ONLY validator A.
    let mut reset_metas = accounts::ResetValidatorRegistry {
        validator_registry: registry_pda,
        authority: upgrade_authority.pubkey(),
        program_data: program_data_pda,
        system_program: system_program::ID,
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

    // Verify registry counters after reset: only validator A is active.
    let raw = banks.get_account(registry_pda).await.unwrap().unwrap();
    let reg_after = ValidatorRegistry::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(reg_after.active_validators, 1);
    assert_eq!(reg_after.total_active_stake, MIN_VALIDATOR_STAKE);
    assert_eq!(reg_after.active_keys, vec![validator_a.pubkey()]);

    // Validator B is an excluded orphan (is_active is still true on-chain).
    let raw_b = banks.get_account(pda_b).await.unwrap().unwrap();
    let acc_b_before = ValidatorAccount::try_deserialize(&mut raw_b.data.as_slice()).unwrap();
    assert!(acc_b_before.is_active);

    // Now validator B (the reset-excluded orphan) calls unregister_validator.
    let unreg_b_ix = Instruction {
        program_id,
        data: instruction::UnregisterValidator {}.data(),
        accounts: accounts::UnregisterValidator {
            validator_account: pda_b,
            validator_registry: registry_pda,
            validator: validator_b.pubkey(),
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[unreg_b_ix], Some(&validator_b.pubkey()));
    tx.sign(&[&validator_b], blockhash);
    banks.process_transaction(tx).await.unwrap();

    // Crucial assertion: unregistering the orphan deactivates it and routes its
    // stake into unbonding, BUT does NOT double-decrement the registry counters!
    let raw_b = banks.get_account(pda_b).await.unwrap().unwrap();
    let acc_b_after = ValidatorAccount::try_deserialize(&mut raw_b.data.as_slice()).unwrap();
    assert!(!acc_b_after.is_active);
    assert_eq!(acc_b_after.unbonding_amount, MIN_VALIDATOR_STAKE);

    let raw = banks.get_account(registry_pda).await.unwrap().unwrap();
    let reg_after_b = ValidatorRegistry::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(
        reg_after_b.active_validators, 1,
        "orphan unregister must not decrement active_validators below the reset count"
    );
    assert_eq!(
        reg_after_b.total_active_stake, MIN_VALIDATOR_STAKE,
        "orphan unregister must not subtract stake from registry"
    );
    assert_eq!(reg_after_b.active_keys, vec![validator_a.pubkey()]);

    // Finally, validator A (which IS in the active set) calls unregister_validator.
    let unreg_a_ix = Instruction {
        program_id,
        data: instruction::UnregisterValidator {}.data(),
        accounts: accounts::UnregisterValidator {
            validator_account: pda_a,
            validator_registry: registry_pda,
            validator: validator_a.pubkey(),
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[unreg_a_ix], Some(&validator_a.pubkey()));
    tx.sign(&[&validator_a], blockhash);
    banks.process_transaction(tx).await.unwrap();

    let raw = banks.get_account(registry_pda).await.unwrap().unwrap();
    let reg_final = ValidatorRegistry::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(reg_final.active_validators, 0);
    assert_eq!(reg_final.total_active_stake, 0);
    assert!(reg_final.active_keys.is_empty());
}

#[tokio::test]
async fn deactivate_reset_excluded_orphan_preserves_registry_counters() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);

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

    // Register validator A and validator B.
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

    let (reg_b, pda_b) = register_ix(
        program_id,
        registry_pda,
        validator_b.pubkey(),
        stake_mint,
        token_b,
    );
    let mut tx = Transaction::new_with_payer(&[reg_b], Some(&validator_b.pubkey()));
    tx.sign(&[&validator_b], blockhash);
    banks.process_transaction(tx).await.unwrap();

    // Reset registry including ONLY validator A.
    let mut reset_metas = accounts::ResetValidatorRegistry {
        validator_registry: registry_pda,
        authority: upgrade_authority.pubkey(),
        program_data: program_data_pda,
        system_program: system_program::ID,
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

    // Verify registry counters after reset: only validator A is active.
    let raw = banks.get_account(registry_pda).await.unwrap().unwrap();
    let reg_after = ValidatorRegistry::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(reg_after.active_validators, 1);
    assert_eq!(reg_after.total_active_stake, MIN_VALIDATOR_STAKE);

    // Authority deactivates validator B (the reset-excluded orphan).
    let deact_b_ix = Instruction {
        program_id,
        data: instruction::DeactivateValidator {}.data(),
        accounts: accounts::DeactivateValidator {
            validator_account: pda_b,
            validator_registry: registry_pda,
            authority: upgrade_authority.pubkey(),
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[deact_b_ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    banks.process_transaction(tx).await.unwrap();

    // Registry counters must remain untouched.
    let raw = banks.get_account(registry_pda).await.unwrap().unwrap();
    let reg_after_b = ValidatorRegistry::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(
        reg_after_b.active_validators, 1,
        "orphan deactivate must not decrement active_validators"
    );
    assert_eq!(
        reg_after_b.total_active_stake, MIN_VALIDATOR_STAKE,
        "orphan deactivate must not decrement total_active_stake"
    );

    // Authority deactivates validator A (which was active in registry).
    let deact_a_ix = Instruction {
        program_id,
        data: instruction::DeactivateValidator {}.data(),
        accounts: accounts::DeactivateValidator {
            validator_account: pda_a,
            validator_registry: registry_pda,
            authority: upgrade_authority.pubkey(),
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[deact_a_ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    banks.process_transaction(tx).await.unwrap();

    let raw = banks.get_account(registry_pda).await.unwrap().unwrap();
    let reg_final = ValidatorRegistry::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(reg_final.active_validators, 0);
    assert_eq!(reg_final.total_active_stake, 0);
    assert!(reg_final.active_keys.is_empty());
}
