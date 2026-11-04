//! #1138 regression: user withdrawals must not drain validator rewards.
//!
//! `bridge_vault` co-mingles user funds and validator settlement fees. Before
//! the fix, `transact`'s solvency check reserved only `payout + rent_floor`,
//! so a withdrawal could spend lamports already owed to a validator as
//! `pending_rewards`. That validator's `claim_rewards` would then fail for
//! want of funds, and because `withdraw_unbonded_stake` refuses to close a
//! PDA with unclaimed rewards, its unbonded stake exit deadlocked forever.
//!
//! Scenario (the issue's drain, at fixture scale):
//! - Validator A is seeded exited-and-unbonded with `pending_rewards = 300`
//!   and the vault-wide aggregate (raw `BridgeState` bytes at the appended
//!   field's offset) also seeded to 300 — exactly the state `transact`'s fee
//!   credit produces on the fixed program. A itself settles nothing here.
//! - Validator B (the bridge authority, `pending_rewards = 0`) settles the
//!   fixture withdrawal (gross 500, fee 1, payout 499) against a vault funded
//!   to exactly `rent_floor + payout + 300 - 1`: enough for the payout and
//!   rent, but 1 lamport short of also covering A's accrued fees.
//! - Post-fix the withdrawal must fail with `InsufficientFunds`; pre-fix it
//!   succeeds and drains A's fees (this test fails at that assertion).
//! - A then claims its 300 successfully and its `withdraw_unbonded_stake`
//!   exit succeeds (PDA closed) — the deadlock is gone.
//!
//! The aggregate is read/seeded as raw bytes at offset 117
//! (8 disc + 4 version + 32 authority + 8*4 totals/counts + 1 paused
//! + 32 merkle_root + 8 deposit_cap) so this file compiles against both the
//! pre-fix `BridgeState` (no such field; the program ignores the trailing
//! seeded bytes) and the post-fix one (field appended last).

use anchor_lang::prelude::*;
use anchor_lang::{AccountSerialize, InstructionData, ToAccountMetas};
use paraloom_program::transact_fixture_data as fx;
use paraloom_program::{accounts, instruction, BridgeError, BridgeState, ValidatorAccount};
use solana_program_test::{processor, tokio, BanksClientError, ProgramTest};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction, InstructionError},
    signature::{Keypair, Signer},
    transaction::{Transaction, TransactionError},
};

mod common;
use common::{add_program_data, add_stake_mint, add_token_account, entry, withdraw_unbonded_ix};

const MIN_VALIDATOR_STAKE: u64 = 1_000_000_000;
const RECIPIENT_PREFUND: u64 = 1_000_000_000;
/// `Rent::minimum_balance(0)` under the default test rent sysvar:
/// (0 + 128) bytes * 3480 lamports/byte-year * 2.0 exemption threshold.
const RENT_FLOOR: u64 = 890_880;
/// A's accrued, unclaimed settlement fees sitting in the shared vault.
const PENDING_A: u64 = 300;
const GROSS: u64 = 500; // |FIXTURE_EXT_AMOUNT|
const FEE: u64 = GROSS * 25 / 10_000; // 1
const PAYOUT: u64 = GROSS - FEE; // 499
/// Vault balance at the drain attempt: payout + rent + A's fees - 1.
const VAULT_TARGET: u64 = RENT_FLOOR + PAYOUT + PENDING_A - 1;
/// `deposit_note` adds FIXTURE_DEPOSIT_AMOUNT on top of the pre-fund.
const VAULT_PREFUND: u64 = VAULT_TARGET - fx::FIXTURE_DEPOSIT_AMOUNT;
/// Byte offset of the appended `total_pending_rewards` field (see header).
const TOTAL_PENDING_OFFSET: usize = 117;

fn fixture_proof() -> Vec<u8> {
    let mut p = Vec::with_capacity(256);
    p.extend_from_slice(&fx::FIXTURE_PROOF_A);
    p.extend_from_slice(&fx::FIXTURE_PROOF_B);
    p.extend_from_slice(&fx::FIXTURE_PROOF_C);
    p
}

fn raw_total_pending(state_data: &[u8]) -> Option<u64> {
    let bytes: [u8; 8] = state_data
        .get(TOTAL_PENDING_OFFSET..TOTAL_PENDING_OFFSET + 8)?
        .try_into()
        .ok()?;
    Some(u64::from_le_bytes(bytes))
}

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

async fn send_ok(
    banks_client: &mut solana_program_test::BanksClient,
    recent_blockhash: anchor_lang::solana_program::hash::Hash,
    signer: &Keypair,
    ix: Instruction,
) {
    let mut tx = Transaction::new_with_payer(&[ix], Some(&signer.pubkey()));
    tx.sign(&[signer], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();
}

async fn send_result(
    banks_client: &mut solana_program_test::BanksClient,
    recent_blockhash: anchor_lang::solana_program::hash::Hash,
    signer: &Keypair,
    ix: Instruction,
) -> std::result::Result<(), BanksClientError> {
    let mut tx = Transaction::new_with_payer(&[ix], Some(&signer.pubkey()));
    tx.sign(&[signer], recent_blockhash);
    banks_client.process_transaction(tx).await
}

/// Serialized `BridgeState` in the post-fix layout, built byte-by-byte so it
/// is identical under both program versions: the pre-fix fields in order,
/// then the appended aggregate the fix adds.
fn seeded_bridge_state(authority: Pubkey, total_pending_rewards: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(TOTAL_PENDING_OFFSET + 8);
    data.extend_from_slice(BridgeState::DISCRIMINATOR);
    data.extend_from_slice(&0x0004_0000u32.to_le_bytes()); // program_version
    data.extend_from_slice(authority.as_ref());
    data.extend_from_slice(&0u64.to_le_bytes()); // total_deposited
    data.extend_from_slice(&0u64.to_le_bytes()); // total_withdrawn
    data.extend_from_slice(&0u64.to_le_bytes()); // deposit_count
    data.extend_from_slice(&0u64.to_le_bytes()); // withdrawal_count
    data.push(0); // paused = false
    data.extend_from_slice(&[0u8; 32]); // merkle_root (legacy, unused)
    data.extend_from_slice(&u64::MAX.to_le_bytes()); // deposit_cap: open
    data.extend_from_slice(&total_pending_rewards.to_le_bytes());
    data
}

#[tokio::test]
async fn withdrawal_cannot_drain_other_validators_pending_rewards() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);

    let recipient = Pubkey::new_from_array(fx::FIXTURE_RECIPIENT);
    pt.add_account(
        recipient,
        Account {
            lamports: RECIPIENT_PREFUND,
            data: vec![],
            owner: solana_sdk::system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );

    let stake_mint = add_stake_mint(&mut pt, Pubkey::new_unique());
    let authority_token = add_token_account(
        &mut pt,
        stake_mint,
        upgrade_authority.pubkey(),
        common::TEST_TOKEN_FUND,
    );

    // Independent quorum co-signer C (settler B is excluded from its own tally).
    let cosigner = Keypair::new();
    pt.add_account(
        cosigner.pubkey(),
        Account {
            lamports: 10_000_000_000,
            data: vec![],
            owner: solana_sdk::system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );
    let cosigner_token = add_token_account(
        &mut pt,
        stake_mint,
        cosigner.pubkey(),
        common::TEST_TOKEN_FUND,
    );

    // Victim validator A: exited, unbonding elapsed, stake still in its PDA,
    // and PENDING_A of unclaimed fees in the shared vault.
    let victim = Keypair::new();
    pt.add_account(
        victim.pubkey(),
        Account {
            lamports: 10_000_000_000,
            data: vec![],
            owner: solana_sdk::system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );
    let victim_token = add_token_account(
        &mut pt,
        stake_mint,
        victim.pubkey(),
        common::TEST_TOKEN_FUND,
    );
    let (victim_pda, _) =
        Pubkey::find_program_address(&[b"validator", victim.pubkey().as_ref()], &program_id);
    let seeded_victim = ValidatorAccount {
        validator: victim.pubkey(),
        stake_amount: 0,
        reputation_score: 1000,
        total_tasks_verified: 0,
        successful_verifications: 0,
        registered_at: 0,
        last_active: 0,
        is_active: false,
        pending_rewards: PENDING_A,
        total_earnings: 0,
        times_slashed: 0,
        unbonding_amount: MIN_VALIDATOR_STAKE,
        unbonding_slot: 0,
        token_stake_amount: 0,
        token_unbonding_amount: 0,
    };
    let mut victim_data = Vec::new();
    seeded_victim
        .try_serialize(&mut victim_data)
        .expect("serialize victim validator");
    pt.add_account(
        victim_pda,
        Account {
            lamports: 2_000_000_000, // rent + the 1 SOL unbonded stake
            data: victim_data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );

    // Bridge state seeded directly (bypassing `initialize`) so the aggregate
    // starts at PENDING_A, matching A's seeded `pending_rewards`.
    let (state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    pt.add_account(
        state_pda,
        Account {
            lamports: 10_000_000,
            data: seeded_bridge_state(upgrade_authority.pubkey(), PENDING_A),
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );

    // Pre-seed the vault itself at VAULT_PREFUND: that amount is (by design)
    // a hair below the rent floor, so a system transfer creating the account
    // would be rejected with InsufficientFundsForRent; genesis seeding is
    // how the crafted level is reached. `deposit_note` tops it to target.
    let (vault_pda, _) = Pubkey::find_program_address(&[b"bridge_vault"], &program_id);
    pt.add_account(
        vault_pda,
        Account {
            lamports: VAULT_PREFUND,
            data: vec![],
            owner: solana_sdk::system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );

    let (mut banks_client, payer, recent_blockhash) = pt.start().await;
    let (tree_pda, _) = Pubkey::find_program_address(&[b"merkle_tree"], &program_id);
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (settler_pda, _) = Pubkey::find_program_address(
        &[b"validator", upgrade_authority.pubkey().as_ref()],
        &program_id,
    );
    let (cosigner_pda, _) =
        Pubkey::find_program_address(&[b"validator", cosigner.pubkey().as_ref()], &program_id);
    let (nf0_pda, _) =
        Pubkey::find_program_address(&[b"nullifier", &fx::FIXTURE_NULLIFIER_0], &program_id);
    let (nf1_pda, _) =
        Pubkey::find_program_address(&[b"nullifier", &fx::FIXTURE_NULLIFIER_1], &program_id);
    let (stake_vault_pda, _) =
        Pubkey::find_program_address(&[b"stake_token_vault"], &program_id);
    let (stake_vault_authority_pda, _) =
        Pubkey::find_program_address(&[b"stake_vault_authority"], &program_id);

    // Init the merkle tree and the validator registry (upgrade-authority gated).
    send_ok(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::InitializeMerkleTree {}.data(),
            accounts: accounts::InitializeMerkleTree {
                merkle_tree: tree_pda,
                authority: upgrade_authority.pubkey(),
                program_data: program_data_pda,
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;
    send_ok(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::InitializeValidatorRegistry {}.data(),
            accounts: accounts::InitializeValidatorRegistry {
                stake_mint,
                stake_token_vault: stake_vault_pda,
                stake_vault_authority: stake_vault_authority_pda,
                token_program: spl_token::id(),
                rent: solana_sdk::sysvar::rent::ID,
                validator_registry: registry_pda,
                authority: upgrade_authority.pubkey(),
                program_data: program_data_pda,
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;

    // Register settler B (the bridge authority; pending_rewards starts at 0).
    send_ok(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::RegisterValidator {
                token_stake_amount: paraloom_program::RECOMMENDED_MIN_TOKEN_STAKE,
                stake_amount: MIN_VALIDATOR_STAKE,
            }
            .data(),
            accounts: accounts::RegisterValidator {
                stake_mint,
                validator_account: settler_pda,
                validator_token_account: authority_token,
                stake_token_vault: stake_vault_pda,
                token_program: spl_token::id(),
                validator_registry: registry_pda,
                validator: upgrade_authority.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;
    // Register co-signer C so B's settlement can reach quorum.
    send_ok(
        &mut banks_client,
        recent_blockhash,
        &cosigner,
        Instruction {
            program_id,
            data: instruction::RegisterValidator {
                token_stake_amount: paraloom_program::RECOMMENDED_MIN_TOKEN_STAKE,
                stake_amount: MIN_VALIDATOR_STAKE,
            }
            .data(),
            accounts: accounts::RegisterValidator {
                stake_mint,
                validator_account: cosigner_pda,
                validator_token_account: cosigner_token,
                stake_token_vault: stake_vault_pda,
                token_program: spl_token::id(),
                validator_registry: registry_pda,
                validator: cosigner.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;

    // Deposit the fixture note so the tree reaches FIXTURE_ROOT; the deposit
    // tops the pre-seeded vault up to the crafted VAULT_TARGET level.
    send_ok(
        &mut banks_client,
        recent_blockhash,
        &payer,
        Instruction {
            program_id,
            data: instruction::DepositNote {
                amount: fx::FIXTURE_DEPOSIT_AMOUNT,
                pubkey: fx::FIXTURE_DEPOSIT_PUBKEY,
                blinding: fx::FIXTURE_DEPOSIT_BLINDING,
            }
            .data(),
            accounts: accounts::DepositNote {
                bridge_state: state_pda,
                bridge_vault: vault_pda,
                merkle_tree: tree_pda,
                depositor: payer.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;

    let vault_before = banks_client
        .get_account(vault_pda)
        .await
        .unwrap()
        .unwrap()
        .lamports;
    assert_eq!(vault_before, VAULT_TARGET, "crafted vault level");
    let state_raw = banks_client.get_account(state_pda).await.unwrap().unwrap();
    assert_eq!(
        raw_total_pending(&state_raw.data),
        Some(PENDING_A),
        "seeded aggregate must be readable at the appended offset"
    );

    // THE DRAIN ATTEMPT: B (pending = 0) settles a user withdrawal whose
    // payout fits payout+rent but would consume A's accrued fees.
    let transact_ix = Instruction {
        program_id,
        data: instruction::Transact {
            nullifiers: [fx::FIXTURE_NULLIFIER_0, fx::FIXTURE_NULLIFIER_1],
            output_commitments: [fx::FIXTURE_COMMITMENT_0, fx::FIXTURE_COMMITMENT_1],
            root: fx::FIXTURE_ROOT,
            ext_amount: fx::FIXTURE_EXT_AMOUNT,
            proof: fixture_proof(),
        }
        .data(),
        accounts: {
            let mut metas = accounts::Transact {
                bridge_state: state_pda,
                merkle_tree: tree_pda,
                bridge_vault: vault_pda,
                nullifier_account_0: nf0_pda,
                nullifier_account_1: nf1_pda,
                recipient,
                validator_account: settler_pda,
                validator_registry: registry_pda,
                authority: upgrade_authority.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None);
            metas.push(AccountMeta::new_readonly(cosigner.pubkey(), true));
            metas.push(AccountMeta::new_readonly(cosigner_pda, false));
            metas
        },
    };
    let transact_tx = Transaction::new_signed_with_payer(
        &[transact_ix],
        Some(&upgrade_authority.pubkey()),
        &[&upgrade_authority, &cosigner],
        recent_blockhash,
    );
    let drain_err = banks_client
        .process_transaction(transact_tx)
        .await
        .expect_err("withdrawal that would drain A's pending rewards must fail");
    assert_eq!(
        custom_code(drain_err),
        u32::from(BridgeError::InsufficientFunds),
        "drain attempt must fail with InsufficientFunds"
    );

    // Nothing moved: recipient unpaid, vault intact, A's reward intact.
    let recipient_acc = banks_client.get_account(recipient).await.unwrap().unwrap();
    assert_eq!(recipient_acc.lamports, RECIPIENT_PREFUND);
    let vault_after = banks_client
        .get_account(vault_pda)
        .await
        .unwrap()
        .unwrap()
        .lamports;
    assert_eq!(vault_after, VAULT_TARGET);

    // A claims successfully — the claim the drain would have made impossible.
    send_ok(
        &mut banks_client,
        recent_blockhash,
        &victim,
        Instruction {
            program_id,
            data: instruction::ClaimRewards {}.data(),
            accounts: accounts::ClaimRewards {
                bridge_state: state_pda,
                validator_account: victim_pda,
                bridge_vault: vault_pda,
                validator: victim.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;

    let victim_raw = banks_client.get_account(victim_pda).await.unwrap().unwrap();
    let victim_acc =
        ValidatorAccount::try_deserialize(&mut victim_raw.data.as_slice()).unwrap();
    assert_eq!(victim_acc.pending_rewards, 0);
    assert_eq!(victim_acc.total_earnings, PENDING_A);
    let state_raw = banks_client.get_account(state_pda).await.unwrap().unwrap();
    assert_eq!(
        raw_total_pending(&state_raw.data),
        Some(0),
        "claim must debit the vault-wide aggregate back to zero"
    );
    let vault_after_claim = banks_client
        .get_account(vault_pda)
        .await
        .unwrap()
        .unwrap()
        .lamports;
    assert_eq!(vault_after_claim, VAULT_TARGET - PENDING_A);

    // A's exit now succeeds: unbonded stake returned and the PDA closed —
    // the exact exit the bug permanently deadlocked.
    send_result(
        &mut banks_client,
        recent_blockhash,
        &victim,
        withdraw_unbonded_ix(program_id, victim.pubkey(), stake_mint, victim_token),
    )
    .await
    .expect("withdraw_unbonded_stake must succeed after claiming");
    assert!(
        banks_client
            .get_account(victim_pda)
            .await
            .unwrap()
            .is_none(),
        "validator PDA must be closed by the successful exit"
    );
}
