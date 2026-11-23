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
    register_validator_ix, slash_validator_ix,
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

#[tokio::test]
async fn slash_reset_excluded_orphan_does_not_double_decrement_registry_counters() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let stake_mint = add_stake_mint(&mut pt, upgrade_authority.pubkey());
    let (val_a, token_a) = funded_validator(&mut pt, stake_mint);
    let (val_b, token_b) = funded_validator(&mut pt, stake_mint);
    let (val_c_orphan, token_c) = funded_validator(&mut pt, stake_mint);
    let (val_d_orphan, token_d) = funded_validator(&mut pt, stake_mint);
    let (mut banks_client, _payer, recent_blockhash) = pt.start().await;

    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (pda_a, _) =
        Pubkey::find_program_address(&[b"validator", val_a.pubkey().as_ref()], &program_id);
    let (pda_b, _) =
        Pubkey::find_program_address(&[b"validator", val_b.pubkey().as_ref()], &program_id);
    let (pda_c, _) =
        Pubkey::find_program_address(&[b"validator", val_c_orphan.pubkey().as_ref()], &program_id);
    let (pda_d, _) =
        Pubkey::find_program_address(&[b"validator", val_d_orphan.pubkey().as_ref()], &program_id);

    // Initialize registry
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

    // Register A (1 SOL), B (1 SOL), C (1 SOL), D (2 SOL)
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
    send(
        &mut banks_client,
        recent_blockhash,
        &val_b,
        register_validator_ix(
            program_id,
            val_b.pubkey(),
            stake_mint,
            token_b,
            MIN_VALIDATOR_STAKE,
            TOKEN_STAKE,
        ),
    )
    .await;
    send(
        &mut banks_client,
        recent_blockhash,
        &val_c_orphan,
        register_validator_ix(
            program_id,
            val_c_orphan.pubkey(),
            stake_mint,
            token_c,
            MIN_VALIDATOR_STAKE,
            TOKEN_STAKE,
        ),
    )
    .await;
    send(
        &mut banks_client,
        recent_blockhash,
        &val_d_orphan,
        register_validator_ix(
            program_id,
            val_d_orphan.pubkey(),
            stake_mint,
            token_d,
            2 * MIN_VALIDATOR_STAKE,
            TOKEN_STAKE,
        ),
    )
    .await;

    // 4 active validators, 5 SOL total before reset
    let raw = banks_client.get_account(registry_pda).await.unwrap().unwrap();
    let reg_before = ValidatorRegistry::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(reg_before.active_validators, 4);
    assert_eq!(reg_before.total_active_stake, 5 * MIN_VALIDATOR_STAKE);

    // Reset registry declaring 2 active validators and passing ONLY [A, B].
    // C and D are omitted from remaining_accounts.
    let mut reset_metas = accounts::ResetValidatorRegistry {
        validator_registry: registry_pda,
        authority: upgrade_authority.pubkey(),
        program_data: program_data_pda,
        system_program: solana_sdk::system_program::ID,
    }
    .to_account_metas(None);
    reset_metas.push(solana_sdk::instruction::AccountMeta::new_readonly(pda_a, false));
    reset_metas.push(solana_sdk::instruction::AccountMeta::new_readonly(pda_b, false));
    let reset_ix = Instruction {
        program_id,
        data: instruction::ResetValidatorRegistry {
            stake_mint,
            expected_active_validators: 2,
        }
        .data(),
        accounts: reset_metas,
    };
    send(&mut banks_client, recent_blockhash, &upgrade_authority, reset_ix).await;

    // Post-reset registry: active_validators = 2, total_active_stake = 2 SOL
    let raw = banks_client.get_account(registry_pda).await.unwrap().unwrap();
    let reg_post_reset = ValidatorRegistry::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(reg_post_reset.active_validators, 2);
    assert_eq!(reg_post_reset.total_active_stake, 2 * MIN_VALIDATOR_STAKE);

    // C and D are orphans with is_active = true
    let raw_c = banks_client.get_account(pda_c).await.unwrap().unwrap();
    let acc_c = ValidatorAccount::try_deserialize(&mut raw_c.data.as_slice()).unwrap();
    assert!(acc_c.is_active);

    let raw_d = banks_client.get_account(pda_d).await.unwrap().unwrap();
    let acc_d = ValidatorAccount::try_deserialize(&mut raw_d.data.as_slice()).unwrap();
    assert!(acc_d.is_active);

    // 1) Test deactivating branch: slash orphan C by 100% (dropping below minimum_stake)
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        slash_validator_ix(
            program_id,
            val_c_orphan.pubkey(),
            stake_mint,
            upgrade_authority.pubkey(),
            100,
        ),
    )
    .await;

    let raw = banks_client.get_account(registry_pda).await.unwrap().unwrap();
    let reg_after_c = ValidatorRegistry::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(
        reg_after_c.active_validators, 2,
        "slashing reset-excluded orphan must not decrement registry active_validators"
    );
    assert_eq!(
        reg_after_c.total_active_stake, 2 * MIN_VALIDATOR_STAKE,
        "slashing reset-excluded orphan must not decrement registry total_active_stake"
    );

    // 2) Test non-deactivating branch: slash orphan D (2 SOL) by 25% (stays active at 1.5 SOL >= min_stake)
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        slash_validator_ix(
            program_id,
            val_d_orphan.pubkey(),
            stake_mint,
            upgrade_authority.pubkey(),
            25,
        ),
    )
    .await;

    let raw = banks_client.get_account(registry_pda).await.unwrap().unwrap();
    let reg_after_d = ValidatorRegistry::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(
        reg_after_d.active_validators, 2,
        "non-deactivating slash of reset-excluded orphan must not decrement registry active_validators"
    );
    assert_eq!(
        reg_after_d.total_active_stake, 2 * MIN_VALIDATOR_STAKE,
        "non-deactivating slash of reset-excluded orphan must not decrement registry total_active_stake"
    );

    // Verify account states of C and D
    let raw_c_final = banks_client.get_account(pda_c).await.unwrap().unwrap();
    let acc_c_final = ValidatorAccount::try_deserialize(&mut raw_c_final.data.as_slice()).unwrap();
    assert!(!acc_c_final.is_active);
    assert_eq!(acc_c_final.stake_amount, 0);
    assert_eq!(acc_c_final.times_slashed, 1);

    let raw_d_final = banks_client.get_account(pda_d).await.unwrap().unwrap();
    let acc_d_final = ValidatorAccount::try_deserialize(&mut raw_d_final.data.as_slice()).unwrap();
    assert!(acc_d_final.is_active);
    assert_eq!(acc_d_final.stake_amount, 1_500_000_000);
    assert_eq!(acc_d_final.times_slashed, 1);
}
