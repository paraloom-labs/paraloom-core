//! On-chain test for the validator-stake unbonding lifecycle.
//!
//! `unregister_validator` no longer refunds the stake immediately: it moves the
//! staked lamports into an unbonding window (`unbonding_amount` /
//! `unbonding_slot`) during which the stake is still slashable, and only
//! `withdraw_unbonded_stake` — after `UNBONDING_SLOTS` have elapsed — releases
//! the lamports back to the validator wallet. This exercises the full cycle:
//! register → unregister (no refund, fields set) → early withdraw rejected
//! (`UnbondingNotElapsed`) → warp past the window → withdraw succeeds (wallet
//! credited, `unbonding_amount` cleared) → second withdraw rejected
//! (`NothingUnbonding`).
//!
//! Uses `start_with_context()` so the slot can be warped past the unbonding
//! window without waiting ~216k real slots.

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::{
    accounts, instruction, BridgeError, ValidatorAccount, ValidatorRegistry, MIN_VALIDATOR_STAKE,
    UNBONDING_SLOTS,
};
use solana_program_test::{processor, tokio, BanksClientError, ProgramTest, ProgramTestContext};
use solana_sdk::{
    instruction::{Instruction, InstructionError},
    signature::{Keypair, Signer},
    transaction::{Transaction, TransactionError},
};

mod common;
use common::{add_program_data, entry};

/// Send `ix` signed by `signer` (also the fee payer) on a fresh blockhash and
/// return the raw result so callers can assert success or a specific error.
/// A fresh blockhash per call avoids BanksClient replaying a deduped signature
/// when the same instruction is submitted twice.
async fn send(
    ctx: &mut ProgramTestContext,
    signer: &Keypair,
    ix: Instruction,
) -> std::result::Result<(), BanksClientError> {
    let blockhash = ctx.get_new_latest_blockhash().await.expect("new blockhash");
    let mut tx = Transaction::new_with_payer(&[ix], Some(&signer.pubkey()));
    tx.sign(&[signer], blockhash);
    ctx.banks_client.process_transaction(tx).await
}

/// Extract the Anchor custom error code from a failed transaction.
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

async fn balance(ctx: &mut ProgramTestContext, key: Pubkey) -> u64 {
    ctx.banks_client
        .get_balance(key)
        .await
        .expect("get balance")
}

async fn load_validator(ctx: &mut ProgramTestContext, pda: Pubkey) -> ValidatorAccount {
    let raw = ctx
        .banks_client
        .get_account(pda)
        .await
        .expect("rpc")
        .expect("validator account exists");
    ValidatorAccount::try_deserialize(&mut raw.data.as_slice()).expect("deserialize validator")
}

#[tokio::test]
async fn stake_unbonds_then_withdraws_after_delay() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let mut ctx = pt.start_with_context().await;

    // `ctx.payer` doubles as the validator wallet: it self-signs register,
    // unregister and withdraw. Clone it out so we can hold `&mut ctx` alongside.
    let validator = ctx.payer.insecure_clone();

    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (validator_pda, _) =
        Pubkey::find_program_address(&[b"validator", validator.pubkey().as_ref()], &program_id);

    // 1. Registry init (upgrade authority, #204).
    send(
        &mut ctx,
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
    .await
    .expect("init registry");

    // 2. Register — PDA holds the stake.
    send(
        &mut ctx,
        &validator,
        Instruction {
            program_id,
            data: instruction::RegisterValidator {
                stake_amount: MIN_VALIDATOR_STAKE,
            }
            .data(),
            accounts: accounts::RegisterValidator {
                validator_account: validator_pda,
                validator_registry: registry_pda,
                validator: validator.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await
    .expect("register");

    let pda_after_register = balance(&mut ctx, validator_pda).await;
    let acc = load_validator(&mut ctx, validator_pda).await;
    assert_eq!(acc.stake_amount, MIN_VALIDATOR_STAKE);
    assert!(acc.is_active);
    // PDA custody includes the staked lamports on top of its rent reserve.
    assert!(
        pda_after_register >= MIN_VALIDATOR_STAKE,
        "PDA must hold the staked lamports"
    );

    // 3. Unregister — no refund; stake enters the unbonding window.
    let wallet_before_unregister = balance(&mut ctx, validator.pubkey()).await;
    send(
        &mut ctx,
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
    .await
    .expect("unregister");

    let acc = load_validator(&mut ctx, validator_pda).await;
    assert!(!acc.is_active, "unregister must deactivate");
    assert_eq!(acc.stake_amount, 0, "active stake zeroed");
    assert_eq!(
        acc.unbonding_amount, MIN_VALIDATOR_STAKE,
        "the full stake must be unbonding"
    );
    assert!(
        acc.unbonding_slot >= UNBONDING_SLOTS,
        "unbonding_slot = registration-era slot + UNBONDING_SLOTS"
    );

    // The wallet was NOT credited by the unregister (it only paid the fee).
    let wallet_after_unregister = balance(&mut ctx, validator.pubkey()).await;
    assert!(
        wallet_after_unregister <= wallet_before_unregister,
        "unregister must not refund the stake"
    );

    // The registry counters dropped immediately.
    let registry_raw = ctx
        .banks_client
        .get_account(registry_pda)
        .await
        .unwrap()
        .unwrap();
    let registry = ValidatorRegistry::try_deserialize(&mut registry_raw.data.as_slice()).unwrap();
    assert_eq!(registry.active_validators, 0);
    assert_eq!(registry.total_active_stake, 0);

    // 4. Withdraw before the window elapses — rejected.
    let err = send(
        &mut ctx,
        &validator,
        Instruction {
            program_id,
            data: instruction::WithdrawUnbondedStake {}.data(),
            accounts: accounts::WithdrawUnbondedStake {
                validator_account: validator_pda,
                validator: validator.pubkey(),
            }
            .to_account_metas(None),
        },
    )
    .await
    .expect_err("early withdraw must fail");
    assert_eq!(
        custom_code(err),
        u32::from(BridgeError::UnbondingNotElapsed),
        "early withdraw must fail with UnbondingNotElapsed"
    );

    // 5. Warp past the unbonding window.
    let unbonding_slot = acc.unbonding_slot;
    ctx.warp_to_slot(unbonding_slot)
        .expect("warp to unbonding slot");

    // 6. Withdraw succeeds — wallet credited, unbonding cleared.
    let wallet_before_withdraw = balance(&mut ctx, validator.pubkey()).await;
    let pda_before_withdraw = balance(&mut ctx, validator_pda).await;
    send(
        &mut ctx,
        &validator,
        Instruction {
            program_id,
            data: instruction::WithdrawUnbondedStake {}.data(),
            accounts: accounts::WithdrawUnbondedStake {
                validator_account: validator_pda,
                validator: validator.pubkey(),
            }
            .to_account_metas(None),
        },
    )
    .await
    .expect("withdraw after delay");

    let acc = load_validator(&mut ctx, validator_pda).await;
    assert_eq!(acc.unbonding_amount, 0, "unbonding cleared after withdraw");

    let wallet_after_withdraw = balance(&mut ctx, validator.pubkey()).await;
    let pda_after_withdraw = balance(&mut ctx, validator_pda).await;
    // The PDA lost exactly the unbonded amount; the wallet gained it (net of the
    // small tx fee, which is far below one SOL).
    assert_eq!(
        pda_before_withdraw - pda_after_withdraw,
        MIN_VALIDATOR_STAKE,
        "PDA debited by the unbonded amount"
    );
    assert!(
        wallet_after_withdraw > wallet_before_withdraw,
        "wallet credited by the released stake"
    );

    // 7. A second withdraw has nothing left to release.
    let err = send(
        &mut ctx,
        &validator,
        Instruction {
            program_id,
            data: instruction::WithdrawUnbondedStake {}.data(),
            accounts: accounts::WithdrawUnbondedStake {
                validator_account: validator_pda,
                validator: validator.pubkey(),
            }
            .to_account_metas(None),
        },
    )
    .await
    .expect_err("double withdraw must fail");
    assert_eq!(
        custom_code(err),
        u32::from(BridgeError::NothingUnbonding),
        "second withdraw must fail with NothingUnbonding"
    );
}
