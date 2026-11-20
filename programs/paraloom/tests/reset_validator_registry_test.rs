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
use solana_program_test::{processor, tokio, ProgramTest, ProgramTestBanksClientExt};
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
async fn reconcile_orphaned_validator_preserves_registry_counters() {
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
    let (mut banks, payer, blockhash) = pt.start().await;
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

    // Reset registry keeping ONLY validator A.
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

    // Registry counters after reset: 1 active validator, 1 SOL active stake.
    let raw = banks.get_account(registry_pda).await.unwrap().unwrap();
    let after_reset = ValidatorRegistry::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(after_reset.active_validators, 1);
    assert_eq!(after_reset.total_active_stake, MIN_VALIDATOR_STAKE);

    // Validator B is still active on its PDA (an orphan excluded by reset).
    let raw_b = banks.get_account(pda_b).await.unwrap().unwrap();
    let acc_b_before = ValidatorAccount::try_deserialize(&mut raw_b.data.as_slice()).unwrap();
    assert!(acc_b_before.is_active);
    assert_eq!(acc_b_before.stake_amount, MIN_VALIDATOR_STAKE);

    // Non-authority cannot reconcile:
    let reconcile_bad_auth = Instruction {
        program_id,
        data: instruction::ReconcileOrphanedValidator {}.data(),
        accounts: accounts::DeactivateValidator {
            validator_account: pda_b,
            validator_registry: registry_pda,
            authority: payer.pubkey(),
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[reconcile_bad_auth], Some(&payer.pubkey()));
    tx.sign(&[&payer], blockhash);
    assert!(
        banks.process_transaction(tx).await.is_err(),
        "non-authority reconcile must fail"
    );

    // Authority reconciles validator B using reconcile_orphaned_validator:
    let reconcile_ix = Instruction {
        program_id,
        data: instruction::ReconcileOrphanedValidator {}.data(),
        accounts: accounts::DeactivateValidator {
            validator_account: pda_b,
            validator_registry: registry_pda,
            authority: upgrade_authority.pubkey(),
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[reconcile_ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    banks.process_transaction(tx).await.unwrap();

    // Validator B is now inactive and routed to unbonding:
    let raw_b = banks.get_account(pda_b).await.unwrap().unwrap();
    let acc_b_after = ValidatorAccount::try_deserialize(&mut raw_b.data.as_slice()).unwrap();
    assert!(!acc_b_after.is_active, "is_active cleared");
    assert_eq!(acc_b_after.stake_amount, 0, "active stake zeroed");
    assert_eq!(
        acc_b_after.unbonding_amount, MIN_VALIDATOR_STAKE,
        "stake routed to unbonding"
    );
    assert!(acc_b_after.unbonding_slot >= paraloom_program::UNBONDING_SLOTS);

    // Registry counters are PRESERVED (NOT double-decremented!):
    let raw = banks.get_account(registry_pda).await.unwrap().unwrap();
    let after_reconcile = ValidatorRegistry::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(
        after_reconcile.active_validators, 1,
        "reconcile_orphaned_validator must NOT decrement active_validators"
    );
    assert_eq!(
        after_reconcile.total_active_stake, MIN_VALIDATOR_STAKE,
        "reconcile_orphaned_validator must NOT double-decrement total_active_stake"
    );

    // Reconciling an already-inactive validator reverts with ValidatorNotActive:
    let new_blockhash = banks.get_new_latest_blockhash(&blockhash).await.unwrap();
    let reconcile_again = Instruction {
        program_id,
        data: instruction::ReconcileOrphanedValidator {}.data(),
        accounts: accounts::DeactivateValidator {
            validator_account: pda_b,
            validator_registry: registry_pda,
            authority: upgrade_authority.pubkey(),
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[reconcile_again], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], new_blockhash);
    assert!(
        banks.process_transaction(tx).await.is_err(),
        "reconciling already-inactive validator must fail"
    );
}
