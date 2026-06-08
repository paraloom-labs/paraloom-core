//! On-chain unit test for #237: asset-aware SPL deposit + withdraw.
//!
//! Drives the full SPL custody loop through `solana-program-test`:
//! initialize -> init validator registry -> register validator -> create an
//! SPL mint + token accounts -> `deposit_spl` into the per-asset vault ->
//! `withdraw_spl` out of it. Pins the value movement (tokens land in the
//! per-asset vault on deposit; the recipient receives `amount - fee` on
//! withdraw), the 25 bps fee parity with the native path (fee stays in the
//! vault and is credited to the settling validator's `pending_rewards`), the
//! L2-visible counters, and the nullifier PDA the replay layer relies on.
//!
//! Init + withdraw run as the program upgrade authority (#204); the SPL
//! deposit is permissionless and signed by the depositor.

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use anchor_spl::token::spl_token;
use paraloom_program::{accounts, instruction, BridgeState, NullifierAccount, ValidatorAccount};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{
    instruction::Instruction,
    program_pack::Pack,
    signature::{Keypair, Signer},
    system_instruction,
    transaction::Transaction,
};

mod common;
use common::{add_program_data, entry};

const NULLIFIER: [u8; 32] = [42u8; 32];
const DEPOSIT_AMOUNT: u64 = 5_000_000; // 5 token units
const WITHDRAW_AMOUNT: u64 = 1_000_000;
// 25 bps of WITHDRAW_AMOUNT.
const EXPECTED_FEE: u64 = WITHDRAW_AMOUNT * 25 / 10_000;
const MIN_VALIDATOR_STAKE: u64 = 1_000_000_000;

async fn send(
    banks_client: &mut solana_program_test::BanksClient,
    recent_blockhash: anchor_lang::solana_program::hash::Hash,
    payer: &Keypair,
    signers: &[&Keypair],
    ixs: &[Instruction],
) {
    let mut tx = Transaction::new_with_payer(ixs, Some(&payer.pubkey()));
    tx.sign(signers, recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();
}

#[tokio::test]
async fn deposit_spl_then_withdraw_spl_credits_validator_fee() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    let (state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (nullifier_pda, _) = Pubkey::find_program_address(&[b"nullifier", &NULLIFIER], &program_id);
    let (validator_pda, _) = Pubkey::find_program_address(
        &[b"validator", upgrade_authority.pubkey().as_ref()],
        &program_id,
    );
    let (vault_authority_pda, _) =
        Pubkey::find_program_address(&[b"asset_vault_authority"], &program_id);

    // 1. initialize the bridge (upgrade-authority gated, #204).
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        &[&upgrade_authority],
        &[Instruction {
            program_id,
            data: instruction::Initialize {
                program_version: 0x0004_0000,
                initial_merkle_root: [0u8; 32],
            }
            .data(),
            accounts: accounts::Initialize {
                bridge_state: state_pda,
                authority: upgrade_authority.pubkey(),
                program_data: program_data_pda,
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        }],
    )
    .await;

    // 2. initialize the validator registry.
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        &[&upgrade_authority],
        &[Instruction {
            program_id,
            data: instruction::InitializeValidatorRegistry {}.data(),
            accounts: accounts::InitializeValidatorRegistry {
                validator_registry: registry_pda,
                authority: upgrade_authority.pubkey(),
                program_data: program_data_pda,
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        }],
    )
    .await;

    // 3. register the settling authority as a validator.
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        &[&upgrade_authority],
        &[Instruction {
            program_id,
            data: instruction::RegisterValidator {
                stake_amount: MIN_VALIDATOR_STAKE,
            }
            .data(),
            accounts: accounts::RegisterValidator {
                validator_account: validator_pda,
                validator_registry: registry_pda,
                validator: upgrade_authority.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        }],
    )
    .await;

    // 4. create an SPL mint owned by `payer`; the mint pubkey is the asset id.
    let mint = Keypair::new();
    let rent = banks_client.get_rent().await.unwrap();
    let mint_rent = rent.minimum_balance(spl_token::state::Mint::LEN);
    send(
        &mut banks_client,
        recent_blockhash,
        &payer,
        &[&payer, &mint],
        &[
            system_instruction::create_account(
                &payer.pubkey(),
                &mint.pubkey(),
                mint_rent,
                spl_token::state::Mint::LEN as u64,
                &spl_token::id(),
            ),
            spl_token::instruction::initialize_mint(
                &spl_token::id(),
                &mint.pubkey(),
                &payer.pubkey(),
                None,
                6,
            )
            .unwrap(),
        ],
    )
    .await;

    // The per-asset vault PDA is keyed by the mint.
    let (vault_pda, _) =
        Pubkey::find_program_address(&[b"asset_vault", mint.pubkey().as_ref()], &program_id);

    // 5. create the depositor's token account (owned by `payer`) and mint it
    //    the deposit balance.
    let depositor_token = Keypair::new();
    let token_rent = rent.minimum_balance(spl_token::state::Account::LEN);
    send(
        &mut banks_client,
        recent_blockhash,
        &payer,
        &[&payer, &depositor_token],
        &[
            system_instruction::create_account(
                &payer.pubkey(),
                &depositor_token.pubkey(),
                token_rent,
                spl_token::state::Account::LEN as u64,
                &spl_token::id(),
            ),
            spl_token::instruction::initialize_account(
                &spl_token::id(),
                &depositor_token.pubkey(),
                &mint.pubkey(),
                &payer.pubkey(),
            )
            .unwrap(),
            spl_token::instruction::mint_to(
                &spl_token::id(),
                &mint.pubkey(),
                &depositor_token.pubkey(),
                &payer.pubkey(),
                &[],
                DEPOSIT_AMOUNT,
            )
            .unwrap(),
        ],
    )
    .await;

    // 6. deposit_spl — permissionless; the depositor (payer) signs the token
    //    transfer into the per-asset vault, which `init_if_needed` creates.
    send(
        &mut banks_client,
        recent_blockhash,
        &payer,
        &[&payer],
        &[Instruction {
            program_id,
            data: instruction::DepositSpl {
                amount: DEPOSIT_AMOUNT,
                recipient: [1u8; 32],
                randomness: [2u8; 32],
            }
            .data(),
            accounts: accounts::DepositSpl {
                bridge_state: state_pda,
                mint: mint.pubkey(),
                asset_vault_authority: vault_authority_pda,
                asset_vault: vault_pda,
                depositor_token: depositor_token.pubkey(),
                depositor: payer.pubkey(),
                token_program: spl_token::id(),
                system_program: solana_sdk::system_program::ID,
                rent: solana_sdk::sysvar::rent::ID,
            }
            .to_account_metas(None),
        }],
    )
    .await;

    // The vault now holds the full deposit.
    let vault_raw = banks_client
        .get_account(vault_pda)
        .await
        .unwrap()
        .expect("vault token account must exist after deposit_spl");
    let vault = spl_token::state::Account::unpack(&vault_raw.data).unwrap();
    assert_eq!(vault.amount, DEPOSIT_AMOUNT);
    assert_eq!(vault.mint, mint.pubkey());

    let state_raw = banks_client.get_account(state_pda).await.unwrap().unwrap();
    let state = BridgeState::try_deserialize(&mut state_raw.data.as_slice()).unwrap();
    assert_eq!(state.total_deposited, DEPOSIT_AMOUNT);
    assert_eq!(state.deposit_count, 1);

    // 7. create a recipient token account for the withdraw destination.
    let recipient_owner = Keypair::new();
    let recipient_token = Keypair::new();
    send(
        &mut banks_client,
        recent_blockhash,
        &payer,
        &[&payer, &recipient_token],
        &[
            system_instruction::create_account(
                &payer.pubkey(),
                &recipient_token.pubkey(),
                token_rent,
                spl_token::state::Account::LEN as u64,
                &spl_token::id(),
            ),
            spl_token::instruction::initialize_account(
                &spl_token::id(),
                &recipient_token.pubkey(),
                &mint.pubkey(),
                &recipient_owner.pubkey(),
            )
            .unwrap(),
        ],
    )
    .await;

    // 8. withdraw_spl — signed by the bridge authority (also the validator).
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        &[&upgrade_authority],
        &[Instruction {
            program_id,
            data: instruction::WithdrawSpl {
                nullifier: NULLIFIER,
                amount: WITHDRAW_AMOUNT,
                expiration_slot: u64::MAX,
                proof: vec![1, 2, 3, 4],
            }
            .data(),
            accounts: accounts::WithdrawSpl {
                bridge_state: state_pda,
                mint: mint.pubkey(),
                asset_vault_authority: vault_authority_pda,
                asset_vault: vault_pda,
                nullifier_account: nullifier_pda,
                recipient_token: recipient_token.pubkey(),
                validator_account: validator_pda,
                authority: upgrade_authority.pubkey(),
                token_program: spl_token::id(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        }],
    )
    .await;

    // The recipient receives the amount net of the 25 bps fee.
    let recipient_raw = banks_client
        .get_account(recipient_token.pubkey())
        .await
        .unwrap()
        .unwrap();
    let recipient_acc = spl_token::state::Account::unpack(&recipient_raw.data).unwrap();
    assert_eq!(recipient_acc.amount, WITHDRAW_AMOUNT - EXPECTED_FEE);

    // The fee stays in the vault: vault = deposit - payout.
    let vault_raw = banks_client.get_account(vault_pda).await.unwrap().unwrap();
    let vault = spl_token::state::Account::unpack(&vault_raw.data).unwrap();
    assert_eq!(
        vault.amount,
        DEPOSIT_AMOUNT - (WITHDRAW_AMOUNT - EXPECTED_FEE)
    );

    // The fee is credited to the settling validator's pending_rewards and the
    // settlement is recorded — parity with the native withdraw path.
    let val_raw = banks_client
        .get_account(validator_pda)
        .await
        .unwrap()
        .unwrap();
    let val = ValidatorAccount::try_deserialize(&mut val_raw.data.as_slice()).unwrap();
    assert_eq!(val.pending_rewards, EXPECTED_FEE);
    assert_eq!(val.successful_verifications, 1);

    // Counters advance and the nullifier PDA exists (replay defense).
    let state_raw = banks_client.get_account(state_pda).await.unwrap().unwrap();
    let state = BridgeState::try_deserialize(&mut state_raw.data.as_slice()).unwrap();
    assert_eq!(state.total_withdrawn, WITHDRAW_AMOUNT);
    assert_eq!(state.withdrawal_count, 1);

    let nul_raw = banks_client
        .get_account(nullifier_pda)
        .await
        .unwrap()
        .expect("nullifier PDA must exist after withdraw_spl");
    let nul = NullifierAccount::try_deserialize(&mut nul_raw.data.as_slice()).unwrap();
    assert_eq!(nul.nullifier, NULLIFIER);
    assert_eq!(nul.withdrawal_id, 1);
}
