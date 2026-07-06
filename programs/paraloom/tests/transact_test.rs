//! End-to-end on-chain test for the v3 unified `transact` instruction (#350).
//!
//! Flow: initialize → init merkle tree → init validator registry → register
//! validator → fund the vault → `deposit_note` (recreates the fixture's spent
//! input note at leaf 0, so the on-chain tree reaches `FIXTURE_ROOT`) →
//! `transact` (spends that note, withdraws `|ext_amount|` net of the fee to the
//! fixed recipient, records both nullifiers, appends both output commitments).
//!
//! The `deposit_note` → `FIXTURE_ROOT` assertion is the load-bearing check that
//! the on-chain incremental tree (`solana_poseidon`) computes bit-identical
//! roots to the host circuit (`light_poseidon`) the proof was built against —
//! if the two Poseidon implementations disagreed, no v3 proof would verify.
//!
//! Settlement is quorum-gated exactly like `withdraw` (#260): the authority is
//! the sole registered validator (threshold 1), co-signing as a (wallet, PDA)
//! pair in `remaining_accounts`.

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::merkle_tree::{IncrementalMerkleTree, TREE_DEPTH, ZERO_HASHES};
use paraloom_program::transact_fixture_data as fx;
use paraloom_program::{accounts, instruction, BridgeState, NullifierAccount, ValidatorAccount};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction},
    signature::{Keypair, Signer},
    transaction::Transaction,
};

/// Lamports the recipient is pre-funded with. The fixture withdraws only 500
/// lamports (units, not SOL), which is below the rent-exempt minimum, so a
/// brand-new recipient account could not be created by the payout alone; the
/// on-chain logic is identical for a mainnet-scale amount.
const RECIPIENT_PREFUND: u64 = 1_000_000_000;

mod common;
use common::{add_program_data, entry};

const MIN_VALIDATOR_STAKE: u64 = 1_000_000_000;

/// The 256-byte alt_bn128 wire proof from the fixture.
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
async fn transact_spends_deposited_note_and_withdraws_net_of_fee() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);

    // Pre-fund the fixed recipient above the rent-exempt minimum so the tiny
    // 500-lamport payout credits an existing account rather than trying to
    // create one below rent.
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

    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    let (state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(&[b"bridge_vault"], &program_id);
    let (tree_pda, _) = Pubkey::find_program_address(&[b"merkle_tree"], &program_id);
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (validator_pda, _) = Pubkey::find_program_address(
        &[b"validator", upgrade_authority.pubkey().as_ref()],
        &program_id,
    );
    let (nf0_pda, _) =
        Pubkey::find_program_address(&[b"nullifier", &fx::FIXTURE_NULLIFIER_0], &program_id);
    let (nf1_pda, _) =
        Pubkey::find_program_address(&[b"nullifier", &fx::FIXTURE_NULLIFIER_1], &program_id);

    // 1. initialize the bridge state. `initial_merkle_root` is the v2 legacy
    //    root and is irrelevant to `transact`, which uses the tree account.
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::Initialize {
                program_version: 1,
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

    // 2. initialize the on-chain incremental tree (empty).
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

    // 3. initialize the validator registry (upgrade-authority gated).
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

    // 4. register the settling authority as a validator (stakes 1 SOL).
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
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
        },
    )
    .await;

    // 5. fund the vault with 2 SOL so it stays comfortably above rent after the
    //    withdrawal (this permissionless `Deposit` only adds lamports; it does
    //    not touch the v3 tree).
    send(
        &mut banks_client,
        recent_blockhash,
        &payer,
        Instruction {
            program_id,
            data: instruction::Deposit {
                amount: 2_000_000_000,
                recipient: [1u8; 32],
                randomness: [2u8; 32],
            }
            .data(),
            accounts: accounts::Deposit {
                bridge_state: state_pda,
                bridge_vault: vault_pda,
                depositor: payer.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;

    // 6. deposit_note the fixture's input note — this appends commitment c0 at
    //    leaf 0, so the on-chain tree root becomes exactly `FIXTURE_ROOT`.
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

    // The load-bearing cross-check: the on-chain tree computed the same root the
    // proof was built against. If Poseidon disagreed, this would fail here
    // rather than as an opaque "invalid proof" inside `transact`.
    let tree_raw = banks_client.get_account(tree_pda).await.unwrap().unwrap();
    let tree = IncrementalMerkleTree::try_deserialize(&mut tree_raw.data.as_slice()).unwrap();
    assert_eq!(tree.next_index, 1, "one note deposited");
    assert_eq!(
        tree.root,
        fx::FIXTURE_ROOT,
        "on-chain tree root must equal the host circuit root the proof proves"
    );
    assert_ne!(tree.root, ZERO_HASHES[TREE_DEPTH]);

    // 7. transact — spend the note, withdraw 500 (net of the 25 bps fee) to the
    //    recipient, record both nullifiers, append both output commitments.
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
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
                // Quorum co-signers (#260): the sole registered validator.
                metas.push(AccountMeta::new_readonly(upgrade_authority.pubkey(), true));
                metas.push(AccountMeta::new_readonly(validator_pda, false));
                metas
            },
        },
    )
    .await;

    // The withdrawn amount is |ext_amount| = 500; fee = 500 * 25 / 10000 = 1.
    let gross = fx::FIXTURE_EXT_AMOUNT.unsigned_abs();
    let fee = gross * 25 / 10_000;
    let payout = gross - fee;

    // Recipient balance increased by the payout net of the fee.
    let recipient_acc = banks_client
        .get_account(recipient)
        .await
        .unwrap()
        .expect("recipient funded by transact");
    assert_eq!(
        recipient_acc.lamports,
        RECIPIENT_PREFUND + payout,
        "recipient gains |ext| - fee"
    );

    // The fee landed in the settling validator's pending_rewards.
    let val_raw = banks_client
        .get_account(validator_pda)
        .await
        .unwrap()
        .unwrap();
    let val = ValidatorAccount::try_deserialize(&mut val_raw.data.as_slice()).unwrap();
    assert_eq!(val.pending_rewards, fee);
    assert_eq!(val.successful_verifications, 1);

    // Both input nullifiers were recorded (double-spend defense).
    for (pda, expected) in [
        (nf0_pda, fx::FIXTURE_NULLIFIER_0),
        (nf1_pda, fx::FIXTURE_NULLIFIER_1),
    ] {
        let raw = banks_client
            .get_account(pda)
            .await
            .unwrap()
            .expect("nullifier PDA must exist after transact");
        let nul = NullifierAccount::try_deserialize(&mut raw.data.as_slice()).unwrap();
        assert_eq!(nul.nullifier, expected);
        assert_eq!(nul.withdrawal_id, 1);
    }

    // Both output commitments were appended: leaf 0 (deposit) + 2 outputs = 3.
    let tree_raw = banks_client.get_account(tree_pda).await.unwrap().unwrap();
    let tree = IncrementalMerkleTree::try_deserialize(&mut tree_raw.data.as_slice()).unwrap();
    assert_eq!(tree.next_index, 3, "two output commitments appended");
    // The pre-append root the proof cited is still in the ring buffer.
    assert!(tree.is_known_root(fx::FIXTURE_ROOT));

    let state_raw = banks_client.get_account(state_pda).await.unwrap().unwrap();
    let state = BridgeState::try_deserialize(&mut state_raw.data.as_slice()).unwrap();
    assert_eq!(state.withdrawal_count, 1);
}
