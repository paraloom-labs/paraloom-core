//! Sixth on-chain unit test for #71. Closes the slashing pipeline
//! the L2 Byzantine-consensus test (#124) only covered up to the
//! evidence-record step: `slash_validator` is what actually
//! reduces a misbehaving validator's stake. Pins three contracts
//! the consensus pipeline relies on: stake_amount drops by the
//! percentage, times_slashed increments, slashed lamports land in
//! the slashed-funds vault (#728).
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
use common::{
    add_program_data, add_stake_mint, entry, funded_validator, init_validator_registry_ix,
    register_validator_ix, reset_validator_registry_ix, slash_validator_ix,
    slash_validator_with_roster_ix,
};

const MIN_VALIDATOR_STAKE: u64 = 1_000_000_000;
const TOKEN_STAKE: u64 = paraloom_program::RECOMMENDED_MIN_TOKEN_STAKE;

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
    let stake_mint = add_stake_mint(&mut pt, upgrade_authority.pubkey());
    let (validator, validator_token) = funded_validator(&mut pt, stake_mint);
    let (mut banks_client, _payer, recent_blockhash) = pt.start().await;

    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (validator_pda, _) =
        Pubkey::find_program_address(&[b"validator", validator.pubkey().as_ref()], &program_id);
    // #728: slashed SOL now lands in the dead-end slashed-funds vault, not the
    // deposit-cap-measured bridge vault.
    let (vault_pda, _) = Pubkey::find_program_address(&[b"slashed_funds_vault"], &program_id);

    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        init_validator_registry_ix(
            program_id,
            upgrade_authority.pubkey(),
            program_data_pda,
            stake_mint,
        ),
    )
    .await;
    send(
        &mut banks_client,
        recent_blockhash,
        &validator,
        register_validator_ix(
            program_id,
            validator.pubkey(),
            stake_mint,
            validator_token,
            MIN_VALIDATOR_STAKE,
            TOKEN_STAKE,
        ),
    )
    .await;
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        slash_validator_ix(
            program_id,
            validator.pubkey(),
            stake_mint,
            upgrade_authority.pubkey(),
            50,
        ),
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

    let vault = banks_client
        .get_account(vault_pda)
        .await
        .unwrap()
        .expect("slashed_funds_vault must exist after slash");
    assert_eq!(vault.lamports, MIN_VALIDATOR_STAKE / 2);
}

#[tokio::test]
async fn slash_above_minimum_keeps_validator_active() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let stake_mint = add_stake_mint(&mut pt, upgrade_authority.pubkey());
    let (validator, validator_token) = funded_validator(&mut pt, stake_mint);
    let (mut banks_client, _payer, recent_blockhash) = pt.start().await;

    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (validator_pda, _) =
        Pubkey::find_program_address(&[b"validator", validator.pubkey().as_ref()], &program_id);
    // #728: slashed SOL now lands in the dead-end slashed-funds vault, not the
    // deposit-cap-measured bridge vault.
    let (vault_pda, _) = Pubkey::find_program_address(&[b"slashed_funds_vault"], &program_id);

    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        init_validator_registry_ix(
            program_id,
            upgrade_authority.pubkey(),
            program_data_pda,
            stake_mint,
        ),
    )
    .await;

    // Register with twice the minimum stake so a moderate slash stays above it.
    send(
        &mut banks_client,
        recent_blockhash,
        &validator,
        register_validator_ix(
            program_id,
            validator.pubkey(),
            stake_mint,
            validator_token,
            2 * MIN_VALIDATOR_STAKE,
            TOKEN_STAKE,
        ),
    )
    .await;

    // 25% slash: 2*MIN -> 1.5*MIN, still >= the minimum, so the validator stays
    // active and keeps counting toward the quorum.
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        slash_validator_ix(
            program_id,
            validator.pubkey(),
            stake_mint,
            upgrade_authority.pubkey(),
            25,
        ),
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
    let stake_mint = add_stake_mint(&mut pt, upgrade_authority.pubkey());
    let (validator, validator_token) = funded_validator(&mut pt, stake_mint);
    let (mut banks_client, _payer, recent_blockhash) = pt.start().await;

    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (validator_pda, _) =
        Pubkey::find_program_address(&[b"validator", validator.pubkey().as_ref()], &program_id);
    // #728: slashed SOL now lands in the dead-end slashed-funds vault, not the
    // deposit-cap-measured bridge vault.
    let (vault_pda, _) = Pubkey::find_program_address(&[b"slashed_funds_vault"], &program_id);

    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        init_validator_registry_ix(
            program_id,
            upgrade_authority.pubkey(),
            program_data_pda,
            stake_mint,
        ),
    )
    .await;
    send(
        &mut banks_client,
        recent_blockhash,
        &validator,
        register_validator_ix(
            program_id,
            validator.pubkey(),
            stake_mint,
            validator_token,
            MIN_VALIDATOR_STAKE,
            TOKEN_STAKE,
        ),
    )
    .await;
    // Unregister: stake leaves the active set into the unbonding window and the
    // validator is deactivated.
    send(
        &mut banks_client,
        recent_blockhash,
        &validator,
        Instruction {
            program_id,
            data: instruction::UnregisterValidator {}.data(),
            accounts: accounts::UnregisterValidator {
                validator_account: validator_pda,
                validator_registry: registry_pda,
                validator: validator.pubkey(),
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
        slash_validator_ix(
            program_id,
            validator.pubkey(),
            stake_mint,
            upgrade_authority.pubkey(),
            100,
        ),
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
        .expect("slashed_funds_vault must exist after the slash");
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
        slash_validator_ix(
            program_id,
            validator.pubkey(),
            stake_mint,
            upgrade_authority.pubkey(),
            50,
        ),
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
    // #728: slashed SOL now lands in the dead-end slashed-funds vault, not the
    // deposit-cap-measured bridge vault.
    let (vault_pda, _) = Pubkey::find_program_address(&[b"slashed_funds_vault"], &program_id);

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

    let stake_mint = add_stake_mint(&mut pt, upgrade_authority.pubkey());
    let (mut banks_client, _payer, recent_blockhash) = pt.start().await;

    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        init_validator_registry_ix(
            program_id,
            upgrade_authority.pubkey(),
            program_data_pda,
            stake_mint,
        ),
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
        slash_validator_ix(
            program_id,
            ghost_wallet,
            stake_mint,
            upgrade_authority.pubkey(),
            50,
        ),
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

/// Regression (Issue #1631): slashing an orphan excluded by `reset_validator_registry`
/// in the deactivating branch must NOT decrement the registry's counters when the
/// caller supplies the active roster in `remaining_accounts`, preventing settlement quorum halts.
#[tokio::test]
async fn slash_orphan_deactivating_branch_preserves_registry_counters_and_quorum() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let stake_mint = add_stake_mint(&mut pt, upgrade_authority.pubkey());

    // Register 3 validators: A, B, and C at MIN_VALIDATOR_STAKE.
    let (val_a, token_a) = funded_validator(&mut pt, stake_mint);
    let (val_b, token_b) = funded_validator(&mut pt, stake_mint);
    let (val_c, token_c) = funded_validator(&mut pt, stake_mint);

    let (mut banks_client, _payer, recent_blockhash) = pt.start().await;

    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (pda_a, _) =
        Pubkey::find_program_address(&[b"validator", val_a.pubkey().as_ref()], &program_id);
    let (pda_b, _) =
        Pubkey::find_program_address(&[b"validator", val_b.pubkey().as_ref()], &program_id);
    let (pda_c, _) =
        Pubkey::find_program_address(&[b"validator", val_c.pubkey().as_ref()], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(&[b"slashed_funds_vault"], &program_id);

    // 1. Init registry.
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        init_validator_registry_ix(
            program_id,
            upgrade_authority.pubkey(),
            program_data_pda,
            stake_mint,
        ),
    )
    .await;

    // 2. Register validators A, B, C.
    for (v, t) in [(&val_a, token_a), (&val_b, token_b), (&val_c, token_c)] {
        send(
            &mut banks_client,
            recent_blockhash,
            v,
            register_validator_ix(
                program_id,
                v.pubkey(),
                stake_mint,
                t,
                MIN_VALIDATOR_STAKE,
                TOKEN_STAKE,
            ),
        )
        .await;
    }

    // 3. Reset registry keeping ONLY A and B (expected_active_validators = 2).
    // C is now an active-but-excluded orphan.
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        reset_validator_registry_ix(
            program_id,
            upgrade_authority.pubkey(),
            program_data_pda,
            stake_mint,
            2,
            &[pda_a, pda_b],
        ),
    )
    .await;

    let reg_raw = banks_client
        .get_account(registry_pda)
        .await
        .unwrap()
        .unwrap();
    let reg = ValidatorRegistry::try_deserialize(&mut reg_raw.data.as_slice()).unwrap();
    assert_eq!(reg.active_validators, 2);
    assert_eq!(reg.total_active_stake, 2 * MIN_VALIDATOR_STAKE);

    let c_raw = banks_client.get_account(pda_c).await.unwrap().unwrap();
    let c_acc = ValidatorAccount::try_deserialize(&mut c_raw.data.as_slice()).unwrap();
    assert!(c_acc.is_active, "C is still active (the orphan premise)");
    assert_eq!(c_acc.stake_amount, MIN_VALIDATOR_STAKE);

    // 4. Admin slashes orphan C by 100% (deactivating branch), providing the active roster [pda_a, pda_b].
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        slash_validator_with_roster_ix(
            program_id,
            val_c.pubkey(),
            stake_mint,
            upgrade_authority.pubkey(),
            100,
            &[pda_a, pda_b],
        ),
    )
    .await;

    // Verify C was deactivated and slashed properly:
    let c_raw = banks_client.get_account(pda_c).await.unwrap().unwrap();
    let c_acc = ValidatorAccount::try_deserialize(&mut c_raw.data.as_slice()).unwrap();
    assert!(!c_acc.is_active, "100% slash deactivates the validator");
    assert_eq!(c_acc.stake_amount, 0);
    assert_eq!(c_acc.unbonding_amount, 0);
    assert_eq!(c_acc.times_slashed, 1);

    // CRITICAL: Registry counters MUST NOT have been decremented!
    let reg_raw = banks_client
        .get_account(registry_pda)
        .await
        .unwrap()
        .unwrap();
    let reg = ValidatorRegistry::try_deserialize(&mut reg_raw.data.as_slice()).unwrap();
    assert_eq!(
        reg.active_validators, 2,
        "slashing an orphan must not decrement active_validators"
    );
    assert_eq!(
        reg.total_active_stake,
        2 * MIN_VALIDATOR_STAKE,
        "slashing an orphan must not decrement total_active_stake"
    );

    // Slashed funds reached the vault:
    let vault = banks_client.get_account(vault_pda).await.unwrap().unwrap();
    assert_eq!(vault.lamports, MIN_VALIDATOR_STAKE);
}

/// Regression (Issue #1631): slashing an orphan in the non-deactivating branch
/// must NOT decrement `total_active_stake` when the roster is supplied.
#[tokio::test]
async fn slash_orphan_non_deactivating_branch_preserves_registry_counters_and_quorum() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let stake_mint = add_stake_mint(&mut pt, upgrade_authority.pubkey());

    let (val_a, token_a) = funded_validator(&mut pt, stake_mint);
    let (val_b, token_b) = funded_validator(&mut pt, stake_mint);
    let (val_d, token_d) = funded_validator(&mut pt, stake_mint);

    let (mut banks_client, _payer, recent_blockhash) = pt.start().await;

    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (pda_a, _) =
        Pubkey::find_program_address(&[b"validator", val_a.pubkey().as_ref()], &program_id);
    let (pda_b, _) =
        Pubkey::find_program_address(&[b"validator", val_b.pubkey().as_ref()], &program_id);
    let (pda_d, _) =
        Pubkey::find_program_address(&[b"validator", val_d.pubkey().as_ref()], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(&[b"slashed_funds_vault"], &program_id);

    // 1. Init registry.
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        init_validator_registry_ix(
            program_id,
            upgrade_authority.pubkey(),
            program_data_pda,
            stake_mint,
        ),
    )
    .await;

    // 2. Register A & B with 1 SOL, D with 2 SOL.
    for (v, t, amt) in [
        (&val_a, token_a, MIN_VALIDATOR_STAKE),
        (&val_b, token_b, MIN_VALIDATOR_STAKE),
        (&val_d, token_d, 2 * MIN_VALIDATOR_STAKE),
    ] {
        send(
            &mut banks_client,
            recent_blockhash,
            v,
            register_validator_ix(
                program_id,
                v.pubkey(),
                stake_mint,
                t,
                amt,
                TOKEN_STAKE,
            ),
        )
        .await;
    }

    // 3. Reset registry keeping ONLY A and B (expected_active_validators = 2).
    // D is an orphan with 2 SOL stake.
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        reset_validator_registry_ix(
            program_id,
            upgrade_authority.pubkey(),
            program_data_pda,
            stake_mint,
            2,
            &[pda_a, pda_b],
        ),
    )
    .await;

    let reg_raw = banks_client
        .get_account(registry_pda)
        .await
        .unwrap()
        .unwrap();
    let reg = ValidatorRegistry::try_deserialize(&mut reg_raw.data.as_slice()).unwrap();
    assert_eq!(reg.active_validators, 2);
    assert_eq!(reg.total_active_stake, 2 * MIN_VALIDATOR_STAKE);

    // 4. Admin slashes D by 25% (2 SOL * 0.75 = 1.5 SOL >= MIN_VALIDATOR_STAKE).
    // D stays active (non-deactivating branch).
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        slash_validator_with_roster_ix(
            program_id,
            val_d.pubkey(),
            stake_mint,
            upgrade_authority.pubkey(),
            25,
            &[pda_a, pda_b],
        ),
    )
    .await;

    // Verify D is still active and stake is 1.5 SOL:
    let d_raw = banks_client.get_account(pda_d).await.unwrap().unwrap();
    let d_acc = ValidatorAccount::try_deserialize(&mut d_raw.data.as_slice()).unwrap();
    assert!(d_acc.is_active, "D remains active above minimum stake");
    assert_eq!(d_acc.stake_amount, 2 * MIN_VALIDATOR_STAKE * 75 / 100);
    assert_eq!(d_acc.times_slashed, 1);

    // CRITICAL: Registry counters MUST NOT have been decremented!
    let reg_raw = banks_client
        .get_account(registry_pda)
        .await
        .unwrap()
        .unwrap();
    let reg = ValidatorRegistry::try_deserialize(&mut reg_raw.data.as_slice()).unwrap();
    assert_eq!(
        reg.active_validators, 2,
        "slashing an orphan must not decrement active_validators"
    );
    assert_eq!(
        reg.total_active_stake,
        2 * MIN_VALIDATOR_STAKE,
        "non-deactivating slash of orphan must not decrement total_active_stake"
    );

    // Slashed 0.5 SOL reached vault:
    let vault = banks_client.get_account(vault_pda).await.unwrap().unwrap();
    assert_eq!(vault.lamports, 2 * MIN_VALIDATOR_STAKE * 25 / 100);
}

/// A slash on an in-roster validator with explicit roster provided correctly decrements registry counters.
#[tokio::test]
async fn slash_roster_member_with_explicit_roster_decrements_registry() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let stake_mint = add_stake_mint(&mut pt, upgrade_authority.pubkey());

    let (val_a, token_a) = funded_validator(&mut pt, stake_mint);
    let (val_b, token_b) = funded_validator(&mut pt, stake_mint);

    let (mut banks_client, _payer, recent_blockhash) = pt.start().await;

    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (pda_a, _) =
        Pubkey::find_program_address(&[b"validator", val_a.pubkey().as_ref()], &program_id);
    let (pda_b, _) =
        Pubkey::find_program_address(&[b"validator", val_b.pubkey().as_ref()], &program_id);

    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        init_validator_registry_ix(
            program_id,
            upgrade_authority.pubkey(),
            program_data_pda,
            stake_mint,
        ),
    )
    .await;

    for (v, t) in [(&val_a, token_a), (&val_b, token_b)] {
        send(
            &mut banks_client,
            recent_blockhash,
            v,
            register_validator_ix(
                program_id,
                v.pubkey(),
                stake_mint,
                t,
                MIN_VALIDATOR_STAKE,
                TOKEN_STAKE,
            ),
        )
        .await;
    }

    // Slash A 50% (deactivating), passing [pda_a, pda_b] where A is present.
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        slash_validator_with_roster_ix(
            program_id,
            val_a.pubkey(),
            stake_mint,
            upgrade_authority.pubkey(),
            50,
            &[pda_a, pda_b],
        ),
    )
    .await;

    let a_raw = banks_client.get_account(pda_a).await.unwrap().unwrap();
    let a_acc = ValidatorAccount::try_deserialize(&mut a_raw.data.as_slice()).unwrap();
    assert!(!a_acc.is_active);

    // Because A was in the roster, registry counters ARE decremented:
    let reg_raw = banks_client
        .get_account(registry_pda)
        .await
        .unwrap()
        .unwrap();
    let reg = ValidatorRegistry::try_deserialize(&mut reg_raw.data.as_slice()).unwrap();
    assert_eq!(reg.active_validators, 1);
    assert_eq!(reg.total_active_stake, MIN_VALIDATOR_STAKE);
}

/// Slashes passing an invalid/unauthorized account in remaining_accounts revert.
#[tokio::test]
async fn slash_with_invalid_roster_account_reverts() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let stake_mint = add_stake_mint(&mut pt, upgrade_authority.pubkey());
    let (val_a, token_a) = funded_validator(&mut pt, stake_mint);

    let fake_acc = Keypair::new().pubkey();
    pt.add_account(
        fake_acc,
        Account {
            lamports: 1_000_000,
            data: vec![0; 100],
            owner: solana_sdk::system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );

    let (mut banks_client, _payer, recent_blockhash) = pt.start().await;

    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        init_validator_registry_ix(
            program_id,
            upgrade_authority.pubkey(),
            program_data_pda,
            stake_mint,
        ),
    )
    .await;

    send(
        &mut banks_client,
        recent_blockhash,
        &val_a,
        register_validator_ix(
            program_id,
            val_a.pubkey(),
            stake_mint,
            token_a,
            MIN_VALIDATOR_STAKE,
            TOKEN_STAKE,
        ),
    )
    .await;

    // Slash passing a non-program account in remaining_accounts -> must fail
    let res = send_result(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        slash_validator_with_roster_ix(
            program_id,
            val_a.pubkey(),
            stake_mint,
            upgrade_authority.pubkey(),
            50,
            &[fake_acc],
        ),
    )
    .await;
    assert!(
        res.is_err(),
        "slash with invalid account in remaining_accounts must revert"
    );
}
