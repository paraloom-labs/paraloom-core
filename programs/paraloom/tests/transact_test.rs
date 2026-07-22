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
//! Settlement is quorum-gated exactly like `withdraw` (#260). Because the
//! settling authority is excluded from its own quorum tally, an INDEPENDENT
//! registered validator (`cosigner`) must co-sign the `transact` as a
//! (wallet, PDA) pair in `remaining_accounts`; the transaction is signed by
//! both the authority and that cosigner.

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
use common::{add_program_data, add_stake_mint, entry};

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

    let stake_mint = add_stake_mint(&mut pt, Pubkey::new_unique());
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    let (state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(&[b"bridge_vault"], &program_id);
    let (tree_pda, _) = Pubkey::find_program_address(&[b"merkle_tree"], &program_id);
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (validator_pda, _) = Pubkey::find_program_address(
        &[b"validator", upgrade_authority.pubkey().as_ref()],
        &program_id,
    );
    // An independent validator that co-signs the quorum. The settling authority
    // is excluded from its own tally, so a second, unrelated validator is what
    // actually satisfies the quorum.
    let cosigner = Keypair::new();
    let (cosigner_pda, _) =
        Pubkey::find_program_address(&[b"validator", cosigner.pubkey().as_ref()], &program_id);
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

    // 3b. open the deposit cap so step 6's `deposit_note` is not rejected by the
    //     TVL cap (`initialize` leaves it at 0). The vault is pre-funded with
    //     2 SOL in step 5 before that deposit, so use an unbounded cap here —
    //     this test exercises settlement, not the cap. Cold-authority signed.
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

    // 4b. register an INDEPENDENT validator that will co-sign the quorum. Fund it
    //     from the payer (stake + fees), then self-register it (RegisterValidator
    //     is permissionless — the validator signs for itself). This raises
    //     total_active_stake to 2 SOL; with the authority's 1 SOL excluded, the
    //     eligible stake is 1 SOL and the cosigner's 1 SOL clears the threshold.
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
                stake_amount: MIN_VALIDATOR_STAKE,
            }
            .data(),
            accounts: accounts::RegisterValidator {
                validator_account: cosigner_pda,
                validator_registry: registry_pda,
                validator: cosigner.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;

    // 5. fund the vault with 2 SOL so it stays comfortably above rent after the
    //    withdrawal. The vault is a program-owned `SystemAccount`, so a plain
    //    system transfer tops it up; the v3 tree is untouched (funding is not a
    //    note-creating deposit).
    send(
        &mut banks_client,
        recent_blockhash,
        &payer,
        solana_sdk::system_instruction::transfer(&payer.pubkey(), &vault_pda, 2_000_000_000),
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
    //    The authority is excluded from its own quorum, so the independent
    //    `cosigner` supplies the (wallet, PDA) pair that satisfies it; the tx is
    //    signed by both the authority (fee payer) and the cosigner.
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
    // The paired total is now maintained alongside successes (was dead).
    assert_eq!(val.total_tasks_verified, 1);

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
    // Withdrawal volume is now tracked (gross = |ext_amount|, was stuck at 0).
    assert_eq!(state.total_withdrawn, gross);
}
