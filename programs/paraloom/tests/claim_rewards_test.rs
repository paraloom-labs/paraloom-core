//! claim_rewards over the real reward flow: a `transact` withdrawal credits the
//! settling validator its 25 bps fee into `pending_rewards`, then `claim_rewards`
//! transfers that out of `bridge_vault`, zeros pending, and accumulates
//! `total_earnings`. The fee is credited by `transact` itself (the only path
//! that mints pending rewards) — the former `distribute_fee` admin shortcut was
//! removed as an unbacked drain surface, and the legacy off-chain-root
//! `withdraw` path was removed in favour of the program-owned-tree `transact`.

use anchor_lang::prelude::*;
use anchor_lang::{AccountSerialize, InstructionData, ToAccountMetas};
use paraloom_program::transact_fixture_data as fx;
use paraloom_program::{accounts, instruction, BridgeError, BridgeState, ValidatorAccount};
use solana_program_test::{processor, tokio, BanksClientError, ProgramTest};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction, InstructionError},
    rent::Rent,
    signature::{Keypair, Signer},
    transaction::{Transaction, TransactionError},
};

mod common;
use common::{add_program_data, add_stake_mint, add_token_account, entry};

const MIN_VALIDATOR_STAKE: u64 = 1_000_000_000;
/// Pre-fund the fixed recipient above rent so the tiny withdrawal credits an
/// existing account (see transact_test).
const RECIPIENT_PREFUND: u64 = 1_000_000_000;
/// The transact fixture withdraws `|ext_amount|` (500 units); the fee is
/// `500 * 25 / 10000 = 1` lamport, credited to the settling validator.
const EXPECTED_FEE: u64 = fx::FIXTURE_EXT_AMOUNT.unsigned_abs() * 25 / 10_000;

fn fixture_proof() -> Vec<u8> {
    let mut p = Vec::with_capacity(256);
    p.extend_from_slice(&fx::FIXTURE_PROOF_A);
    p.extend_from_slice(&fx::FIXTURE_PROOF_B);
    p.extend_from_slice(&fx::FIXTURE_PROOF_C);
    p
}

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

#[tokio::test]
async fn claim_rewards_drains_pending_and_accumulates_earnings() {
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

    // An independent validator that co-signs the quorum. The settling authority
    // is excluded from its own tally, so this second validator is what actually
    // satisfies the quorum; the fee still accrues to the authority's validator.
    // Created before `start` so its token-stake account can be baked in genesis.
    let cosigner = Keypair::new();
    let stake_mint = add_stake_mint(&mut pt, Pubkey::new_unique());
    let authority_token = add_token_account(
        &mut pt,
        stake_mint,
        upgrade_authority.pubkey(),
        common::TEST_TOKEN_FUND,
    );
    let cosigner_token = add_token_account(
        &mut pt,
        stake_mint,
        cosigner.pubkey(),
        common::TEST_TOKEN_FUND,
    );
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    let (state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(&[b"bridge_vault"], &program_id);
    let (tree_pda, _) = Pubkey::find_program_address(&[b"merkle_tree"], &program_id);
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (validator_pda, _) = Pubkey::find_program_address(
        &[b"validator", upgrade_authority.pubkey().as_ref()],
        &program_id,
    );
    let (cosigner_pda, _) =
        Pubkey::find_program_address(&[b"validator", cosigner.pubkey().as_ref()], &program_id);
    let (nf0_pda, _) =
        Pubkey::find_program_address(&[b"nullifier", &fx::FIXTURE_NULLIFIER_0], &program_id);
    let (nf1_pda, _) =
        Pubkey::find_program_address(&[b"nullifier", &fx::FIXTURE_NULLIFIER_1], &program_id);

    // initialize → init tree → init registry → register the settling authority.
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
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
        },
    )
    .await;
    send(
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
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::InitializeValidatorRegistry {}.data(),
            accounts: accounts::InitializeValidatorRegistry {
                stake_mint,
                stake_token_vault: Pubkey::find_program_address(
                    &[b"stake_token_vault"],
                    &program_id,
                )
                .0,
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
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;
    // Open the deposit cap (u64::MAX) so the fixture `deposit_note` below is not
    // rejected by the TVL cap, which `initialize` leaves at 0. The vault is
    // pre-funded with 2 SOL before that deposit; this test exercises rewards,
    // not the cap. Cold-authority signed.
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::SetDepositCap { new_cap: u64::MAX }.data(),
            accounts: accounts::SetDepositCap {
                bridge_state: state_pda,
                validator_registry: registry_pda,
                authority: upgrade_authority.pubkey(),
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
            data: instruction::RegisterValidator {
                token_stake_amount: paraloom_program::RECOMMENDED_MIN_TOKEN_STAKE,
                stake_amount: MIN_VALIDATOR_STAKE,
            }
            .data(),
            accounts: accounts::RegisterValidator {
                stake_mint,
                validator_account: validator_pda,
                validator_token_account: authority_token,
                stake_token_vault: Pubkey::find_program_address(
                    &[b"stake_token_vault"],
                    &program_id,
                )
                .0,
                token_program: spl_token::id(),
                validator_registry: registry_pda,
                validator: upgrade_authority.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;

    // Register an INDEPENDENT validator to co-sign the quorum. Fund it from the
    // payer (stake + fees), then self-register it (RegisterValidator is
    // permissionless). total_active_stake becomes 2 SOL; with the authority's
    // 1 SOL excluded, eligible stake is 1 SOL and the cosigner's 1 SOL clears it.
    send(
        &mut banks_client,
        recent_blockhash,
        &payer,
        solana_sdk::system_instruction::transfer(
            &payer.pubkey(),
            &cosigner.pubkey(),
            MIN_VALIDATOR_STAKE + 100_000_000,
        ),
    )
    .await;
    send(
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
                stake_token_vault: Pubkey::find_program_address(
                    &[b"stake_token_vault"],
                    &program_id,
                )
                .0,
                token_program: spl_token::id(),
                validator_registry: registry_pda,
                validator: cosigner.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;

    // Fund the vault (2 SOL) so it stays rent-exempt through the payout + claim.
    send(
        &mut banks_client,
        recent_blockhash,
        &payer,
        solana_sdk::system_instruction::transfer(&payer.pubkey(), &vault_pda, 2_000_000_000),
    )
    .await;

    // deposit_note the fixture's input note so the on-chain tree reaches
    // FIXTURE_ROOT (the root the transact proof proves membership against).
    send(
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

    // transact — credits EXPECTED_FEE to the settling validator's pending_rewards.
    // The authority is excluded from its own quorum, so the independent cosigner
    // supplies the satisfying (wallet, PDA) pair; the tx is signed by both.
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
                validator_account: validator_pda,
                validator_registry: registry_pda,
                authority: upgrade_authority.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None);
            // Quorum co-signer (#260): an INDEPENDENT registered validator,
            // co-signing as a (wallet, PDA) pair. The authority's own pair is
            // not needed — it is skipped in the tally.
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
    banks_client.process_transaction(transact_tx).await.unwrap();

    // The fee is now pending; nothing claimed yet.
    let before = banks_client
        .get_account(validator_pda)
        .await
        .unwrap()
        .unwrap();
    let before = ValidatorAccount::try_deserialize(&mut before.data.as_slice()).unwrap();
    assert_eq!(before.pending_rewards, EXPECTED_FEE);
    assert_eq!(before.total_earnings, 0);

    // claim_rewards — pays pending out of the vault, zeros it, accumulates earnings.
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::ClaimRewards {}.data(),
            accounts: accounts::ClaimRewards {
                bridge_state: state_pda,
                validator_account: validator_pda,
                bridge_vault: vault_pda,
                validator: upgrade_authority.pubkey(),
                system_program: solana_sdk::system_program::ID,
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
    assert_eq!(acc.pending_rewards, 0);
    assert_eq!(acc.total_earnings, EXPECTED_FEE);
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

struct TestHarness {
    banks_client: solana_program_test::BanksClient,
    recent_blockhash: anchor_lang::solana_program::hash::Hash,
    validator: Keypair,
    state_pda: Pubkey,
    vault_pda: Pubkey,
    validator_pda: Pubkey,
    program_id: Pubkey,
}

async fn setup_claim_rewards_test(vault_lamports: u64, pending_rewards: u64) -> TestHarness {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (_program_data_pda, _upgrade_authority) = add_program_data(&mut pt, program_id);

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

    let (state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(&[b"bridge_vault"], &program_id);
    let (validator_pda, _) =
        Pubkey::find_program_address(&[b"validator", validator.pubkey().as_ref()], &program_id);

    let bridge_state = BridgeState {
        program_version: 0x0004_0000,
        authority: Pubkey::new_unique(),
        total_deposited: 0,
        total_withdrawn: 0,
        deposit_count: 0,
        withdrawal_count: 0,
        paused: false,
        merkle_root: [0u8; 32],
        deposit_cap: u64::MAX,
    };
    let mut state_data = Vec::new();
    bridge_state
        .try_serialize(&mut state_data)
        .expect("serialize bridge_state");
    pt.add_account(
        state_pda,
        Account {
            lamports: Rent::default().minimum_balance(state_data.len()),
            data: state_data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );

    let validator_account = ValidatorAccount {
        validator: validator.pubkey(),
        stake_amount: 1_000_000_000,
        reputation_score: 1000,
        total_tasks_verified: 0,
        successful_verifications: 0,
        registered_at: 0,
        last_active: 0,
        is_active: true,
        pending_rewards,
        total_earnings: 0,
        times_slashed: 0,
        unbonding_amount: 0,
        unbonding_slot: 0,
        token_stake_amount: 0,
        token_unbonding_amount: 0,
    };
    let mut val_data = Vec::new();
    validator_account
        .try_serialize(&mut val_data)
        .expect("serialize validator_account");
    pt.add_account(
        validator_pda,
        Account {
            lamports: Rent::default().minimum_balance(val_data.len()),
            data: val_data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );

    if vault_lamports > 0 {
        pt.add_account(
            vault_pda,
            Account {
                lamports: vault_lamports,
                data: vec![],
                owner: solana_sdk::system_program::ID,
                executable: false,
                rent_epoch: 0,
            },
        );
    }

    let (banks_client, _payer, recent_blockhash) = pt.start().await;

    TestHarness {
        banks_client,
        recent_blockhash,
        validator,
        state_pda,
        vault_pda,
        validator_pda,
        program_id,
    }
}

async fn try_claim_rewards(
    harness: &mut TestHarness,
) -> std::result::Result<(), BanksClientError> {
    let ix = Instruction {
        program_id: harness.program_id,
        data: instruction::ClaimRewards {}.data(),
        accounts: accounts::ClaimRewards {
            bridge_state: harness.state_pda,
            validator_account: harness.validator_pda,
            bridge_vault: harness.vault_pda,
            validator: harness.validator.pubkey(),
            system_program: solana_sdk::system_program::ID,
        }
        .to_account_metas(None),
    };
    let mut tx = Transaction::new_with_payer(&[ix], Some(&harness.validator.pubkey()));
    tx.sign(&[&harness.validator], harness.recent_blockhash);
    harness.banks_client.process_transaction(tx).await
}

#[tokio::test]
async fn claim_rewards_succeeds_at_exact_rent_floor_boundary() {
    let rent_floor = Rent::default().minimum_balance(0);
    let reward = 250_000;
    let mut h = setup_claim_rewards_test(rent_floor + reward, reward).await;

    try_claim_rewards(&mut h)
        .await
        .expect("claim preserving exact rent floor must succeed");

    let vault_acc = h
        .banks_client
        .get_account(h.vault_pda)
        .await
        .unwrap()
        .expect("vault account must exist");
    assert_eq!(
        vault_acc.lamports, rent_floor,
        "vault must retain exactly the rent-exempt floor after full reward payout"
    );

    let val_acc_raw = h
        .banks_client
        .get_account(h.validator_pda)
        .await
        .unwrap()
        .expect("validator account must exist");
    let val_acc = ValidatorAccount::try_deserialize(&mut val_acc_raw.data.as_slice()).unwrap();
    assert_eq!(val_acc.pending_rewards, 0, "pending rewards must be cleared");
    assert_eq!(val_acc.total_earnings, reward, "total earnings must accumulate");
}

#[tokio::test]
async fn claim_rewards_rejects_when_vault_balance_violates_rent_floor() {
    let rent_floor = Rent::default().minimum_balance(0);
    let reward = 250_000;
    // Vault balance is 1 lamport short of maintaining the rent floor after reward payout
    let mut h = setup_claim_rewards_test(rent_floor + reward - 1, reward).await;

    let err = try_claim_rewards(&mut h)
        .await
        .expect_err("claim drawing vault below rent floor must fail");
    assert_eq!(
        custom_code(err),
        u32::from(BridgeError::InsufficientFunds),
        "must fail cleanly with InsufficientFunds"
    );

    let val_acc_raw = h
        .banks_client
        .get_account(h.validator_pda)
        .await
        .unwrap()
        .expect("validator account must exist");
    let val_acc = ValidatorAccount::try_deserialize(&mut val_acc_raw.data.as_slice()).unwrap();
    assert_eq!(
        val_acc.pending_rewards, reward,
        "pending rewards must remain untouched on failure"
    );
    assert_eq!(
        val_acc.total_earnings, 0,
        "total earnings must not change on failure"
    );
}

#[tokio::test]
async fn claim_rewards_rejects_when_vault_balance_is_at_rent_floor() {
    let rent_floor = Rent::default().minimum_balance(0);
    let reward = 100_000;
    // Vault only has rent floor; transferable lamports are 0
    let mut h = setup_claim_rewards_test(rent_floor, reward).await;

    let err = try_claim_rewards(&mut h)
        .await
        .expect_err("claim when transferable is zero must fail");
    assert_eq!(
        custom_code(err),
        u32::from(BridgeError::InsufficientFunds),
        "must fail cleanly with InsufficientFunds"
    );
}

#[tokio::test]
async fn claim_rewards_rejects_when_vault_balance_below_rent_floor() {
    let rent_floor = Rent::default().minimum_balance(0);
    let reward = 100_000;
    // Vault is already below rent floor
    let mut h = setup_claim_rewards_test(rent_floor - 1, reward).await;

    let err = try_claim_rewards(&mut h)
        .await
        .expect_err("claim when vault is below rent floor must fail");
    assert_eq!(
        custom_code(err),
        u32::from(BridgeError::InsufficientFunds),
        "must fail cleanly with InsufficientFunds"
    );
}

#[tokio::test]
async fn claim_rewards_succeeds_with_ample_funds_above_rent_floor() {
    let rent_floor = Rent::default().minimum_balance(0);
    let reward = 500_000;
    let surplus = 10_000_000;
    let mut h = setup_claim_rewards_test(rent_floor + reward + surplus, reward).await;

    try_claim_rewards(&mut h)
        .await
        .expect("claim with surplus above rent floor must succeed");

    let vault_acc = h
        .banks_client
        .get_account(h.vault_pda)
        .await
        .unwrap()
        .expect("vault account must exist");
    assert_eq!(
        vault_acc.lamports,
        rent_floor + surplus,
        "vault must retain rent floor plus remaining surplus"
    );

    let val_acc_raw = h
        .banks_client
        .get_account(h.validator_pda)
        .await
        .unwrap()
        .expect("validator account must exist");
    let val_acc = ValidatorAccount::try_deserialize(&mut val_acc_raw.data.as_slice()).unwrap();
    assert_eq!(val_acc.pending_rewards, 0);
    assert_eq!(val_acc.total_earnings, reward);
}
