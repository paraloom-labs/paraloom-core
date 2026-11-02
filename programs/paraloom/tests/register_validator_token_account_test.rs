//! On-chain regression pins for the `RegisterValidator` token-account surface
//! (#1215).
//!
//! `validator_token_account` used to be a typed
//! `InterfaceAccount<'info, TokenAccount>`. Anchor deserializes typed fields in
//! `try_accounts`, *before* any constraint of the context runs, so an account
//! that does not exist yet aborted with a bare `AccountNotInitialized` (3012)
//! that named no account and told the operator nothing — even though the CLI
//! builders, which only derive the address, leave a fresh validator's associated
//! token account nonexistent by construction.
//!
//! The field is now validated in the context, cheapest check first: ownership,
//! then the mint, then the authority, then the balance. These tests drive one
//! case per check and assert the distinct *named* error each one produces.

use anchor_lang::prelude::*;
use paraloom_program::{BridgeError, MIN_VALIDATOR_STAKE, RECOMMENDED_MIN_TOKEN_STAKE};
use solana_program_test::{processor, tokio, BanksClientError, ProgramTest, ProgramTestContext};
use solana_sdk::{
    account::Account,
    instruction::{Instruction, InstructionError},
    program_pack::Pack,
    signature::{Keypair, Signer},
    system_program,
    transaction::{Transaction, TransactionError},
};

mod common;
use common::{add_program_data, entry, init_validator_registry_ix, register_validator_ix};

/// The staked amount used throughout; a validator that can pay it is assumed.
const TOKEN_STAKE: u64 = RECOMMENDED_MIN_TOKEN_STAKE;

/// Submit `ix` signed by `signer` (the fee payer too) on a fresh blockhash so a
/// repeated instruction is not deduped, and hand back the raw result.
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

/// The Anchor custom error code carried by a failed transaction.
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

/// Bake an initialized SPL mint and return it.
fn bake_mint(ctx: &mut ProgramTestContext, authority: Pubkey) -> Pubkey {
    let mint = Pubkey::new_unique();
    let mut data = vec![0u8; spl_token::state::Mint::LEN];
    spl_token::state::Mint {
        mint_authority: Some(authority).into(),
        // Non-zero so a later slash burn can never underflow supply.
        supply: 1_000_000_000_000_000,
        decimals: 0,
        is_initialized: true,
        freeze_authority: None.into(),
    }
    .pack_into_slice(&mut data);
    ctx.set_account(
        &mint,
        &Account {
            lamports: 1_000_000_000,
            data,
            owner: spl_token::id(),
            executable: false,
            rent_epoch: 0,
        }
        .into(),
    );
    mint
}

/// Bake an initialized SPL token account for `owner` of `mint` holding `amount`.
fn bake_token_account(
    ctx: &mut ProgramTestContext,
    mint: Pubkey,
    owner: Pubkey,
    amount: u64,
) -> Pubkey {
    let token_account = Pubkey::new_unique();
    let mut data = vec![0u8; spl_token::state::Account::LEN];
    spl_token::state::Account {
        mint,
        owner,
        amount,
        delegate: None.into(),
        state: spl_token::state::AccountState::Initialized,
        is_native: None.into(),
        delegated_amount: 0,
        close_authority: None.into(),
    }
    .pack_into_slice(&mut data);
    ctx.set_account(
        &token_account,
        &Account {
            lamports: 1_000_000_000,
            data,
            owner: spl_token::id(),
            executable: false,
            rent_epoch: 0,
        }
        .into(),
    );
    token_account
}

/// Start a bank with the registry already initialized as the upgrade authority
/// and its `stake_mint` pinned. Returns the pinned mint and a funded validator
/// that has no token account of its own, which is the fresh-node state the issue
/// describes.
async fn setup() -> (ProgramTestContext, Pubkey, Keypair) {
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

    let mut ctx = pt.start_with_context().await;
    let stake_mint = bake_mint(&mut ctx, upgrade_authority.pubkey());

    let init = init_validator_registry_ix(
        program_id,
        upgrade_authority.pubkey(),
        program_data_pda,
        stake_mint,
    );
    let blockhash = ctx.get_new_latest_blockhash().await.expect("new blockhash");
    let mut tx = Transaction::new_with_payer(&[init], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], blockhash);
    ctx.banks_client
        .process_transaction(tx)
        .await
        .expect("initialize registry");

    (ctx, stake_mint, validator)
}

fn register_ix(
    validator: &Keypair,
    stake_mint: Pubkey,
    token_account: Pubkey,
    token_stake: u64,
) -> Instruction {
    register_validator_ix(
        paraloom_program::ID,
        validator.pubkey(),
        stake_mint,
        token_account,
        MIN_VALIDATOR_STAKE,
        token_stake,
    )
}

/// The pre-#1215 failure mode A, from the issue: the validator never created its
/// associated token account for the stake mint, so there is nothing on chain at
/// the derived address.
#[tokio::test]
async fn register_without_token_account_reports_named_error() {
    let (mut ctx, stake_mint, validator) = setup().await;

    // An address nothing was ever baked at — exactly what the CLI's offline
    // `derive_associated_token_address` hands over for a fresh validator.
    let missing = Pubkey::new_unique();

    let err = send(
        &mut ctx,
        &validator,
        register_ix(&validator, stake_mint, missing, TOKEN_STAKE),
    )
    .await
    .expect_err("registering against a nonexistent token account must fail");

    // The whole point of the fix: a named error, not a bare 3012.
    assert_eq!(
        custom_code(err),
        u32::from(BridgeError::ValidatorTokenAccountNotInitialized),
        "a missing token account must surface as the named error"
    );
}

/// An initialized account for the wrong mint keeps its own distinct error, so a
/// wrong-asset mistake is never mistaken for a missing account.
#[tokio::test]
async fn register_with_wrong_mint_token_account_reports_mint_mismatch() {
    let (mut ctx, stake_mint, validator) = setup().await;
    let other_mint = bake_mint(&mut ctx, Pubkey::new_unique());
    let wrong_mint_token =
        bake_token_account(&mut ctx, other_mint, validator.pubkey(), TOKEN_STAKE);

    let err = send(
        &mut ctx,
        &validator,
        register_ix(&validator, stake_mint, wrong_mint_token, TOKEN_STAKE),
    )
    .await
    .expect_err("a token account for another mint must be rejected");

    assert_eq!(
        custom_code(err),
        u32::from(BridgeError::ValidatorTokenAccountMintMismatch),
        "a wrong-mint token account must stay distinguishable from a missing one"
    );
}

/// Failure mode B: the account exists and is the right mint, but is owned by
/// somebody else, so its authority is not the registering validator.
#[tokio::test]
async fn register_with_foreign_authority_reports_authority_mismatch() {
    let (mut ctx, stake_mint, validator) = setup().await;
    let foreign_token = bake_token_account(&mut ctx, stake_mint, Pubkey::new_unique(), TOKEN_STAKE);

    let err = send(
        &mut ctx,
        &validator,
        register_ix(&validator, stake_mint, foreign_token, TOKEN_STAKE),
    )
    .await
    .expect_err("a token account owned by another wallet must be rejected");

    assert_eq!(
        custom_code(err),
        u32::from(BridgeError::ValidatorTokenAccountAuthorityMismatch),
        "a foreign token authority must surface as its own named error"
    );
}

/// The silent-gas-burn half of failure mode B: the right account, but thinner
/// than the stake asked for. Previously the transaction was broadcast and only
/// SPL's `InsufficientFunds` (`0x1`) came back from an already-reverted
/// transfer.
#[tokio::test]
async fn register_with_underfunded_token_account_reports_shortfall() {
    let (mut ctx, stake_mint, validator) = setup().await;
    let thin_token = bake_token_account(&mut ctx, stake_mint, validator.pubkey(), TOKEN_STAKE / 2);

    let err = send(
        &mut ctx,
        &validator,
        register_ix(&validator, stake_mint, thin_token, TOKEN_STAKE),
    )
    .await
    .expect_err("an under-funded token account must be rejected");

    assert_eq!(
        custom_code(err),
        u32::from(BridgeError::ValidatorTokenAccountBalanceTooLow),
        "a short token balance must surface before the transfer CPI"
    );
}

/// The happy path still works with the token account supplied as a plain
/// `UncheckedAccount`, and the stake lands in the vault as before.
#[tokio::test]
async fn register_with_initialized_token_account_succeeds() {
    let (mut ctx, stake_mint, validator) = setup().await;
    let funded = bake_token_account(&mut ctx, stake_mint, validator.pubkey(), TOKEN_STAKE * 2);

    send(
        &mut ctx,
        &validator,
        register_ix(&validator, stake_mint, funded, TOKEN_STAKE),
    )
    .await
    .expect("a correctly initialized token account must register");

    let (validator_pda, _) = Pubkey::find_program_address(
        &[b"validator", validator.pubkey().as_ref()],
        &paraloom_program::ID,
    );
    let raw = ctx
        .banks_client
        .get_account(validator_pda)
        .await
        .expect("rpc")
        .expect("validator account exists");
    let account = paraloom_program::ValidatorAccount::try_deserialize(&mut raw.data.as_slice())
        .expect("deserialize validator");
    assert_eq!(
        account.token_stake_amount, TOKEN_STAKE,
        "token stake recorded"
    );

    let token_raw = ctx
        .banks_client
        .get_account(funded)
        .await
        .expect("rpc")
        .expect("token account exists");
    let token = spl_token::state::Account::unpack(&token_raw.data).expect("unpack token account");
    assert_eq!(
        token.amount, TOKEN_STAKE,
        "exactly the stake was debited from the validator"
    );
}
