//! Sixth on-chain unit test for #71. Closes the slashing pipeline
//! the L2 Byzantine-consensus test (#124) only covered up to the
//! evidence-record step: `slash_validator` is what actually
//! reduces a misbehaving validator's stake. Pins three contracts
//! the consensus pipeline relies on: stake_amount drops by the
//! percentage, times_slashed increments, slashed lamports land in
//! bridge_vault.
//!
//! Registry init and `slash_validator` run as the upgrade authority
//! (#204 + `has_one = authority`); register stays validator-signed.

use anchor_lang::prelude::*;
use anchor_lang::{Discriminator, InstructionData, ToAccountMetas};
use paraloom_program::{accounts, instruction, ValidatorAccount, ValidatorRegistry};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{
    account::Account,
    instruction::Instruction,
    rent::Rent,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

mod common;
use common::{add_program_data, entry};

const MIN_VALIDATOR_STAKE: u64 = 1_000_000_000;

async fn send(
    banks_client: &mut solana_program_test::BanksClient,
    recent_blockhash: anchor_lang::solana_program::hash::Hash,
    signer: &Keypair,
    ix: Instruction,
) {
    let mut tx = Transaction::new_with_payer(&[ix], Some(&signer.pubkey()));
    tx.sign(&[signer], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();
}

/// Like [`send`] but returns the raw result so a test can assert a slash does
/// not revert (e.g. no lamport underflow) rather than unwrapping.
async fn send_result(
    banks_client: &mut solana_program_test::BanksClient,
    recent_blockhash: anchor_lang::solana_program::hash::Hash,
    signer: &Keypair,
    ix: Instruction,
) -> std::result::Result<(), solana_program_test::BanksClientError> {
    let mut tx = Transaction::new_with_payer(&[ix], Some(&signer.pubkey()));
    tx.sign(&[signer], recent_blockhash);
    banks_client.process_transaction(tx).await
}

#[tokio::test]
async fn slash_reduces_stake_and_credits_vault() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (validator_pda, _) =
        Pubkey::find_program_address(&[b"validator", payer.pubkey().as_ref()], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(&[b"bridge_vault"], &program_id);

    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::InitializeValidatorRegistry {}.data(),
            accounts: accounts::InitializeValidatorRegistry {
                validator_registry: registry_pda,
                authority: upgrade_authority.pubkey(),
                program_data: program_data_pda,
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;
    send(
        &mut banks_client,
        recent_blockhash,
        &payer,
        Instruction {
            program_id,
            data: instruction::RegisterValidator {
                stake_amount: MIN_VALIDATOR_STAKE,
            }
            .data(),
            accounts: accounts::RegisterValidator {
                validator_account: validator_pda,
                validator_registry: registry_pda,
                validator: payer.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::SlashValidator {
                validator: payer.pubkey(),
                slash_percentage: 50,
            }
            .data(),
            accounts: accounts::SlashValidator {
                validator_account: validator_pda,
                bridge_vault: vault_pda,
                validator_registry: registry_pda,
                authority: upgrade_authority.pubkey(),
            }
            .to_account_metas(None),
        },
    )
    .await;

    let acc_raw = banks_client
        .get_account(validator_pda)
        .await
        .unwrap()
        .unwrap();
    let acc = ValidatorAccount::try_deserialize(&mut acc_raw.data.as_slice()).unwrap();
    // The 50% slash drops stake below the minimum, deactivating the validator;
    // the unslashed remainder (MIN/2) is routed into unbonding (a deactivated
    // validator can't `unregister` to reclaim it), so active stake is now zero.
    assert_eq!(acc.stake_amount, 0);
    assert_eq!(acc.unbonding_amount, MIN_VALIDATOR_STAKE / 2);
    assert!(acc.unbonding_slot > 0, "unbonding slot must be set");
    assert_eq!(acc.times_slashed, 1);

    // A 50% slash drops stake to MIN/2, below the registry minimum, so the
    // validator is deactivated and stops counting toward the quorum.
    assert!(
        !acc.is_active,
        "a slash below the minimum stake must deactivate the validator"
    );
    let reg_raw = banks_client
        .get_account(registry_pda)
        .await
        .unwrap()
        .unwrap();
    let reg = ValidatorRegistry::try_deserialize(&mut reg_raw.data.as_slice()).unwrap();
    assert_eq!(
        reg.active_validators, 0,
        "deactivating a slashed validator must decrement active_validators"
    );
    assert_eq!(
        reg.total_validators, 0,
        "deactivating a slashed validator must decrement total_validators"
    );

    let vault = banks_client
        .get_account(vault_pda)
        .await
        .unwrap()
        .expect("bridge_vault must exist after slash");
    assert_eq!(vault.lamports, MIN_VALIDATOR_STAKE / 2);
}

#[tokio::test]
async fn slash_above_minimum_keeps_validator_active() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (validator_pda, _) =
        Pubkey::find_program_address(&[b"validator", payer.pubkey().as_ref()], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(&[b"bridge_vault"], &program_id);

    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::InitializeValidatorRegistry {}.data(),
            accounts: accounts::InitializeValidatorRegistry {
                validator_registry: registry_pda,
                authority: upgrade_authority.pubkey(),
                program_data: program_data_pda,
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;

    // Register with twice the minimum stake so a moderate slash stays above it.
    send(
        &mut banks_client,
        recent_blockhash,
        &payer,
        Instruction {
            program_id,
            data: instruction::RegisterValidator {
                stake_amount: 2 * MIN_VALIDATOR_STAKE,
            }
            .data(),
            accounts: accounts::RegisterValidator {
                validator_account: validator_pda,
                validator_registry: registry_pda,
                validator: payer.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;

    // 25% slash: 2*MIN -> 1.5*MIN, still >= the minimum, so the validator stays
    // active and keeps counting toward the quorum.
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::SlashValidator {
                validator: payer.pubkey(),
                slash_percentage: 25,
            }
            .data(),
            accounts: accounts::SlashValidator {
                validator_account: validator_pda,
                bridge_vault: vault_pda,
                validator_registry: registry_pda,
                authority: upgrade_authority.pubkey(),
            }
            .to_account_metas(None),
        },
    )
    .await;

    let acc_raw = banks_client
        .get_account(validator_pda)
        .await
        .unwrap()
        .unwrap();
    let acc = ValidatorAccount::try_deserialize(&mut acc_raw.data.as_slice()).unwrap();
    assert_eq!(acc.stake_amount, 2 * MIN_VALIDATOR_STAKE * 75 / 100);
    assert!(
        acc.is_active,
        "a slash that leaves stake above the minimum must keep the validator active"
    );

    let reg_raw = banks_client
        .get_account(registry_pda)
        .await
        .unwrap()
        .unwrap();
    let reg = ValidatorRegistry::try_deserialize(&mut reg_raw.data.as_slice()).unwrap();
    assert_eq!(
        reg.active_validators, 1,
        "a validator still above the minimum must keep counting toward the quorum"
    );
    assert_eq!(
        reg.total_validators, 1,
        "a validator still above the minimum must stay in the registry total"
    );
}

/// Regression (audit fix B4): an INACTIVE (unbonding) validator must be
/// slashable from its `unbonding_amount`. Before the fix the slash was gated on
/// `is_active` and did nothing to unbonding stake, so stake in the unbonding
/// window was not actually at risk (violating the M3 rationale). Here a
/// validator unregisters (stake -> unbonding, is_active=false), then a 100%
/// slash burns the whole unbonding balance into the bridge vault. A second slash
/// on the now-empty account is a clean no-op (nothing left to burn), proving the
/// unbonding-path slash saturates instead of underflowing.
#[tokio::test]
async fn slash_inactive_validator_burns_unbonding() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (validator_pda, _) =
        Pubkey::find_program_address(&[b"validator", payer.pubkey().as_ref()], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(&[b"bridge_vault"], &program_id);

    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::InitializeValidatorRegistry {}.data(),
            accounts: accounts::InitializeValidatorRegistry {
                validator_registry: registry_pda,
                authority: upgrade_authority.pubkey(),
                program_data: program_data_pda,
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;
    send(
        &mut banks_client,
        recent_blockhash,
        &payer,
        Instruction {
            program_id,
            data: instruction::RegisterValidator {
                stake_amount: MIN_VALIDATOR_STAKE,
            }
            .data(),
            accounts: accounts::RegisterValidator {
                validator_account: validator_pda,
                validator_registry: registry_pda,
                validator: payer.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;
    // Unregister: stake leaves the active set into the unbonding window and the
    // validator is deactivated.
    send(
        &mut banks_client,
        recent_blockhash,
        &payer,
        Instruction {
            program_id,
            data: instruction::UnregisterValidator {}.data(),
            accounts: accounts::UnregisterValidator {
                validator_account: validator_pda,
                validator_registry: registry_pda,
                validator: payer.pubkey(),
            }
            .to_account_metas(None),
        },
    )
    .await;

    let acc_raw = banks_client
        .get_account(validator_pda)
        .await
        .unwrap()
        .unwrap();
    let acc = ValidatorAccount::try_deserialize(&mut acc_raw.data.as_slice()).unwrap();
    assert!(!acc.is_active, "unregister deactivates");
    assert_eq!(acc.stake_amount, 0);
    assert_eq!(acc.unbonding_amount, MIN_VALIDATOR_STAKE);

    // 100% slash of the inactive validator: the whole unbonding balance is burnt
    // to the vault.
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::SlashValidator {
                validator: payer.pubkey(),
                slash_percentage: 100,
            }
            .data(),
            accounts: accounts::SlashValidator {
                validator_account: validator_pda,
                bridge_vault: vault_pda,
                validator_registry: registry_pda,
                authority: upgrade_authority.pubkey(),
            }
            .to_account_metas(None),
        },
    )
    .await;

    let acc_raw = banks_client
        .get_account(validator_pda)
        .await
        .unwrap()
        .unwrap();
    let acc = ValidatorAccount::try_deserialize(&mut acc_raw.data.as_slice()).unwrap();
    assert_eq!(
        acc.unbonding_amount, 0,
        "a 100% slash must burn the entire unbonding balance"
    );
    assert_eq!(acc.times_slashed, 1);
    assert!(
        !acc.is_active,
        "slashing an inactive validator keeps it inactive"
    );

    let vault = banks_client
        .get_account(vault_pda)
        .await
        .unwrap()
        .expect("bridge_vault must exist after the slash");
    assert_eq!(
        vault.lamports, MIN_VALIDATOR_STAKE,
        "the slashed unbonding stake must land in the bridge vault"
    );

    // A second slash on the drained account is a clean no-op: old_stake reads the
    // (now zero) unbonding balance, so slash_amount saturates to 0 and no
    // lamports move — no underflow.
    let vault_before = vault.lamports;
    let second = send_result(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::SlashValidator {
                validator: payer.pubkey(),
                slash_percentage: 50,
            }
            .data(),
            accounts: accounts::SlashValidator {
                validator_account: validator_pda,
                bridge_vault: vault_pda,
                validator_registry: registry_pda,
                authority: upgrade_authority.pubkey(),
            }
            .to_account_metas(None),
        },
    )
    .await;
    assert!(
        second.is_ok(),
        "a slash on a drained unbonding account must not underflow: {second:?}"
    );
    let vault_after = banks_client
        .get_account(vault_pda)
        .await
        .unwrap()
        .unwrap()
        .lamports;
    assert_eq!(
        vault_after, vault_before,
        "the no-op slash must move nothing"
    );
}

/// Regression (audit fix B4): the inactive slash is based on `unbonding_amount`,
/// never the recorded `stake_amount`. A rent-only ghost PDA — inactive, a
/// phantom `stake_amount`, but nothing unbonding and only rent lamports in
/// custody — must not be made to debit more lamports than it holds. Basing the
/// slash on the phantom `stake_amount` would compute `slash_amount = stake/2`
/// and underflow the account's lamports; basing it on `unbonding_amount` (0)
/// yields a 0 debit and a clean success.
#[tokio::test]
async fn slash_rent_only_ghost_does_not_underflow() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);

    let ghost_wallet = Keypair::new().pubkey();
    let (validator_pda, _) =
        Pubkey::find_program_address(&[b"validator", ghost_wallet.as_ref()], &program_id);
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(&[b"bridge_vault"], &program_id);

    // Seed a raw current-layout (129-byte) ghost: correct discriminator,
    // is_active = false, a PHANTOM stake_amount = MIN, unbonding_amount = 0, and
    // funded with the rent minimum only (no stake lamports in custody).
    let acct_len = 8 + ValidatorAccount::INIT_SPACE;
    let mut data = ValidatorAccount::DISCRIMINATOR.to_vec();
    data.resize(acct_len, 0);
    // Body field offsets within the 8-byte-discriminator-prefixed account:
    //   validator [8..40], stake_amount [40..48], is_active [88],
    //   unbonding_amount [113..121].
    data[8..40].copy_from_slice(ghost_wallet.as_ref());
    data[40..48].copy_from_slice(&MIN_VALIDATOR_STAKE.to_le_bytes()); // phantom stake
    data[88] = 0; // is_active = false
    let rent_only = Rent::default().minimum_balance(acct_len);
    pt.add_account(
        validator_pda,
        Account {
            lamports: rent_only,
            data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );

    let (mut banks_client, _payer, recent_blockhash) = pt.start().await;

    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::InitializeValidatorRegistry {}.data(),
            accounts: accounts::InitializeValidatorRegistry {
                validator_registry: registry_pda,
                authority: upgrade_authority.pubkey(),
                program_data: program_data_pda,
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;

    // Sanity: the ghost deserializes with the phantom stake and no unbonding.
    let acc_raw = banks_client
        .get_account(validator_pda)
        .await
        .unwrap()
        .unwrap();
    let acc = ValidatorAccount::try_deserialize(&mut acc_raw.data.as_slice()).unwrap();
    assert!(!acc.is_active);
    assert_eq!(
        acc.stake_amount, MIN_VALIDATOR_STAKE,
        "phantom stake seeded"
    );
    assert_eq!(acc.unbonding_amount, 0);

    // Slash the ghost 50%. With the fix this reads unbonding_amount (0) -> a 0
    // debit; without it, stake_amount/2 would underflow the rent-only balance.
    let res = send_result(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::SlashValidator {
                validator: ghost_wallet,
                slash_percentage: 50,
            }
            .data(),
            accounts: accounts::SlashValidator {
                validator_account: validator_pda,
                bridge_vault: vault_pda,
                validator_registry: registry_pda,
                authority: upgrade_authority.pubkey(),
            }
            .to_account_metas(None),
        },
    )
    .await;
    assert!(
        res.is_ok(),
        "slashing a rent-only ghost must not underflow its lamports: {res:?}"
    );

    let acc_raw = banks_client
        .get_account(validator_pda)
        .await
        .unwrap()
        .expect("ghost account must still exist");
    assert_eq!(
        acc_raw.lamports, rent_only,
        "no lamports may leave a rent-only ghost when nothing is unbonding"
    );
    let acc = ValidatorAccount::try_deserialize(&mut acc_raw.data.as_slice()).unwrap();
    assert_eq!(acc.unbonding_amount, 0, "still nothing unbonding");
    assert_eq!(acc.times_slashed, 1, "the slash was recorded");
}
