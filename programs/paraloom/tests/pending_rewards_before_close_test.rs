//! #434 regression: `withdraw_unbonded_stake` closes the validator PDA (#392),
//! which drops `pending_rewards` with it. If a validator still has unclaimed
//! settlement fees, closing would permanently forfeit them. The fix rejects the
//! withdrawal while `pending_rewards > 0`, so the validator must `claim_rewards`
//! first (claimable even while inactive).
//!
//! This pre-seeds an exited-and-unbonded validator PDA that still carries a
//! pending reward and asserts the withdrawal is rejected with
//! `PendingRewardsUnclaimed`. The `pending_rewards == 0` success path is already
//! covered by `withdraw_unbonded_stake_test` (registration leaves it zero).

use anchor_lang::prelude::*;
use anchor_lang::{AccountSerialize, InstructionData, ToAccountMetas};
use paraloom_program::{accounts, instruction, BridgeError, ValidatorAccount};
use solana_program_test::{processor, tokio, BanksClientError, ProgramTest};
use solana_sdk::{
    account::Account,
    instruction::{Instruction, InstructionError},
    signature::{Keypair, Signer},
    transaction::{Transaction, TransactionError},
};

mod common;
use common::{add_program_data, add_stake_mint, add_token_account, bake_stake_vault, entry};

fn custom_code(err: BanksClientError) -> u32 {
    let tx_err = match err {
        BanksClientError::TransactionError(e) => e,
        BanksClientError::SimulationError { err, .. } => err,
        other => panic!("expected a transaction error, got {other:?}"),
    };
    match tx_err {
        TransactionError::InstructionError(_, InstructionError::Custom(code)) => code,
        other => panic!("expected a custom instruction error, got {other:?}"),
    }
}

#[tokio::test]
async fn withdraw_unbonded_stake_rejects_while_rewards_are_unclaimed() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (_program_data_pda, _upgrade_authority) = add_program_data(&mut pt, program_id);

    // The validator wallet self-signs the withdrawal and pays the fee; fund it
    // as a plain system account so it can.
    let validator = Keypair::new();
    pt.add_account(
        validator.pubkey(),
        Account {
            lamports: 10_000_000_000,
            data: vec![],
            owner: solana_sdk::system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );

    let (validator_pda, _) =
        Pubkey::find_program_address(&[b"validator", validator.pubkey().as_ref()], &program_id);

    // Pre-seed an exited validator PDA: inactive, its stake fully unbonded and
    // the unbonding window already elapsed (`unbonding_slot = 0`), but with an
    // UNCLAIMED settlement fee still recorded.
    let seeded = ValidatorAccount {
        validator: validator.pubkey(),
        stake_amount: 0,
        reputation_score: 1000,
        total_tasks_verified: 0,
        successful_verifications: 0,
        registered_at: 0,
        last_active: 0,
        is_active: false,
        pending_rewards: 1,
        total_earnings: 0,
        times_slashed: 0,
        unbonding_amount: 1_000_000_000,
        unbonding_slot: 0,
        token_stake_amount: 0,
        token_unbonding_amount: 0,
    };
    let mut data = Vec::new();
    seeded
        .try_serialize(&mut data)
        .expect("serialize validator");
    // Lamports cover the account rent plus the unbonded stake the withdrawal
    // would pay out.
    pt.add_account(
        validator_pda,
        Account {
            lamports: 2_000_000_000,
            data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );

    let stake_mint = add_stake_mint(&mut pt, Pubkey::new_unique());
    let validator_token = add_token_account(&mut pt, stake_mint, validator.pubkey(), 1_000_000);
    bake_stake_vault(&mut pt, stake_mint, program_id, 1_000_000_000);
    let (mut banks_client, _payer, recent_blockhash) = pt.start().await;

    // The unbonding checks pass (amount > 0, slot elapsed), so the reward guard
    // is what must reject this — otherwise the close would forfeit the reward.
    let ix = Instruction {
        program_id,
        data: instruction::WithdrawUnbondedStake {}.data(),
        accounts: accounts::WithdrawUnbondedStake {
            stake_mint,
            validator_account: validator_pda,
            validator: validator.pubkey(),
            validator_token_account: validator_token,
            stake_token_vault: Pubkey::find_program_address(&[b"stake_token_vault"], &program_id).0,
            stake_vault_authority: Pubkey::find_program_address(
                &[b"stake_vault_authority"],
                &program_id,
            )
            .0,
            token_program: spl_token::id(),
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[ix], Some(&validator.pubkey()));
    tx.sign(&[&validator], recent_blockhash);
    let err = banks_client
        .process_transaction(tx)
        .await
        .expect_err("withdraw must be rejected while rewards are unclaimed");
    assert_eq!(
        custom_code(err),
        u32::from(BridgeError::PendingRewardsUnclaimed),
        "must fail with PendingRewardsUnclaimed, not close the account"
    );

    // The account was NOT closed — it still exists with the reward intact.
    let raw = banks_client
        .get_account(validator_pda)
        .await
        .unwrap()
        .expect("validator PDA must still exist (not closed)");
    let acc = ValidatorAccount::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(acc.pending_rewards, 1, "reward preserved for a later claim");
}
