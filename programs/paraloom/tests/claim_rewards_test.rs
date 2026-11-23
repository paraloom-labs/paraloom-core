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
use solana_program_test::{processor, tokio, BanksClientError, ProgramTest, ProgramTestBanksClientExt};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction, InstructionError},
    rent::Rent,
    signature::{Keypair, Signer},
    transaction::{Transaction, TransactionError},
};

mod common;
use common::{add_program_data, add_stake_mint, add_token_account, entry};

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

#[tokio::test]
async fn claim_rewards_insufficient_funds_when_vault_at_or_below_rent_floor() {
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
            lamports: 10_000_000,
            data: state_data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );

    let seeded_validator = ValidatorAccount {
        validator: validator.pubkey(),
        stake_amount: 1_000_000_000,
        reputation_score: 1000,
        total_tasks_verified: 0,
        successful_verifications: 0,
        registered_at: 0,
        last_active: 0,
        is_active: true,
        pending_rewards: 500_000,
        total_earnings: 0,
        times_slashed: 0,
        unbonding_amount: 0,
        unbonding_slot: 0,
        token_stake_amount: 0,
        token_unbonding_amount: 0,
    };
    let mut val_data = Vec::new();
    seeded_validator
        .try_serialize(&mut val_data)
        .expect("serialize validator");
    pt.add_account(
        validator_pda,
        Account {
            lamports: 2_000_000_000,
            data: val_data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );

    // Vault funded to EXACTLY rent floor (Rent::minimum_balance(0)) so available balance is 0.
    let rent_floor = Rent::default().minimum_balance(0);
    pt.add_account(
        vault_pda,
        Account {
            lamports: rent_floor,
            data: vec![],
            owner: solana_sdk::system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );

    let (mut banks_client, _payer, recent_blockhash) = pt.start().await;

    let ix = Instruction {
        program_id,
        data: instruction::ClaimRewards {}.data(),
        accounts: accounts::ClaimRewards {
            bridge_state: state_pda,
            validator_account: validator_pda,
            bridge_vault: vault_pda,
            validator: validator.pubkey(),
            system_program: solana_sdk::system_program::ID,
        }
        .to_account_metas(None),
    };

    let mut tx = Transaction::new_with_payer(&[ix], Some(&validator.pubkey()));
    tx.sign(&[&validator], recent_blockhash);
    let err = banks_client
        .process_transaction(tx)
        .await
        .expect_err("claim_rewards must fail when vault is at rent floor");
    assert_eq!(
        custom_code(err),
        u32::from(BridgeError::InsufficientFunds),
        "must fail cleanly with InsufficientFunds rather than dropping below rent floor"
    );

    // Verify pending_rewards was not altered
    let raw = banks_client.get_account(validator_pda).await.unwrap().unwrap();
    let acc = ValidatorAccount::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(acc.pending_rewards, 500_000);
    assert_eq!(acc.total_earnings, 0);
}

#[tokio::test]
async fn claim_rewards_partial_claim_preserves_rent_floor_and_unblocks_exit() {
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
            lamports: 10_000_000,
            data: state_data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );

    // Pre-seed an exited validator: inactive, unbonding window elapsed, 1 SOL unbonding,
    // and 1_000_000 lamports in pending rewards.
    let seeded_validator = ValidatorAccount {
        validator: validator.pubkey(),
        stake_amount: 0,
        reputation_score: 1000,
        total_tasks_verified: 0,
        successful_verifications: 0,
        registered_at: 0,
        last_active: 0,
        is_active: false,
        pending_rewards: 1_000_000,
        total_earnings: 0,
        times_slashed: 0,
        unbonding_amount: 1_000_000_000,
        unbonding_slot: 0,
        token_stake_amount: 0,
        token_unbonding_amount: 0,
    };
    let mut val_data = Vec::new();
    seeded_validator
        .try_serialize(&mut val_data)
        .expect("serialize validator");
    pt.add_account(
        validator_pda,
        Account {
            lamports: 2_000_000_000,
            data: val_data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        },
    );

    let stake_mint = add_stake_mint(&mut pt, Pubkey::new_unique());
    let validator_token = add_token_account(&mut pt, stake_mint, validator.pubkey(), 1_000_000);
    common::bake_stake_vault(&mut pt, stake_mint, program_id, 1_000_000_000);

    // Vault has rent_floor + 400_000 lamports (only 400_000 available to claim)
    let rent_floor = Rent::default().minimum_balance(0);
    let partial_avail = 400_000u64;
    pt.add_account(
        vault_pda,
        Account {
            lamports: rent_floor + partial_avail,
            data: vec![],
            owner: solana_sdk::system_program::ID,
            executable: false,
            rent_epoch: 0,
        },
    );

    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    // Withdraw unbonded stake initially rejects because pending_rewards > 0
    let withdraw_ix = Instruction {
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
    let mut tx_withdraw =
        Transaction::new_with_payer(&[withdraw_ix.clone()], Some(&validator.pubkey()));
    tx_withdraw.sign(&[&validator], recent_blockhash);
    let err = banks_client
        .process_transaction(tx_withdraw)
        .await
        .expect_err("must reject exit");
    assert_eq!(
        custom_code(err),
        u32::from(BridgeError::PendingRewardsUnclaimed)
    );

    // First claim: claims 400_000 lamports (partial claim)
    let claim_ix = Instruction {
        program_id,
        data: instruction::ClaimRewards {}.data(),
        accounts: accounts::ClaimRewards {
            bridge_state: state_pda,
            validator_account: validator_pda,
            bridge_vault: vault_pda,
            validator: validator.pubkey(),
            system_program: solana_sdk::system_program::ID,
        }
        .to_account_metas(None),
    };
    send(&mut banks_client, recent_blockhash, &validator, claim_ix.clone()).await;

    // Verify vault balance is now exactly rent floor
    let vault_acc = banks_client.get_account(vault_pda).await.unwrap().unwrap();
    assert_eq!(vault_acc.lamports, rent_floor);

    // Verify validator account has reduced pending_rewards and accumulated earnings
    let val_acc = banks_client.get_account(validator_pda).await.unwrap().unwrap();
    let val = ValidatorAccount::try_deserialize(&mut val_acc.data.as_slice()).unwrap();
    assert_eq!(val.pending_rewards, 600_000);
    assert_eq!(val.total_earnings, 400_000);

    // Immediate second claim fails because available == 0 (vault at rent floor)
    let blockhash2 = banks_client
        .get_new_latest_blockhash(&recent_blockhash)
        .await
        .expect("new blockhash");
    let mut tx_claim2 =
        Transaction::new_with_payer(&[claim_ix.clone()], Some(&validator.pubkey()));
    tx_claim2.sign(&[&validator], blockhash2);
    let err2 = banks_client
        .process_transaction(tx_claim2)
        .await
        .expect_err("must fail at rent floor");
    assert_eq!(custom_code(err2), u32::from(BridgeError::InsufficientFunds));

    // Refill the vault with 600_000 lamports so remaining rewards can be claimed
    let blockhash3 = banks_client
        .get_new_latest_blockhash(&blockhash2)
        .await
        .expect("new blockhash");
    send(
        &mut banks_client,
        blockhash3,
        &payer,
        solana_sdk::system_instruction::transfer(&payer.pubkey(), &vault_pda, 600_000),
    )
    .await;

    // Final claim drains remaining 600_000
    let blockhash4 = banks_client
        .get_new_latest_blockhash(&blockhash3)
        .await
        .expect("new blockhash");
    send(&mut banks_client, blockhash4, &validator, claim_ix).await;

    let val_acc_final = banks_client.get_account(validator_pda).await.unwrap().unwrap();
    let val_final = ValidatorAccount::try_deserialize(&mut val_acc_final.data.as_slice()).unwrap();
    assert_eq!(val_final.pending_rewards, 0);
    assert_eq!(val_final.total_earnings, 1_000_000);

    // Now that pending_rewards == 0, withdraw_unbonded_stake succeeds!
    let blockhash5 = banks_client
        .get_new_latest_blockhash(&blockhash4)
        .await
        .expect("new blockhash");
    send(&mut banks_client, blockhash5, &validator, withdraw_ix).await;

    // The validator PDA is now closed!
    let closed_pda = banks_client.get_account(validator_pda).await.unwrap();
    assert!(closed_pda.is_none(), "Validator PDA must be closed on exit");
}
