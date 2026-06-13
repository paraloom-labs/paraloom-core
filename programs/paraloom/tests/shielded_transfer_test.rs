//! On-chain unit tests for `shielded_transfer` (#193, part of #192).
//!
//! Pins the new nullify-without-withdraw path: two input nullifier PDAs are
//! created, the Merkle root advances, and no lamports move. Covers the happy
//! path, replay rejection (reusing spent nullifiers), and a duplicate input
//! nullifier within one transfer. Double-spend is rejected by the same
//! `init`'d nullifier PDA the `withdraw` path relies on — and because both
//! paths share the `b"nullifier"` namespace, a note spent here can never be
//! re-spent via `withdraw` either.
//!
//! Init + transfer both run as the program upgrade authority (#204), since
//! `shielded_transfer` is gated by `has_one = authority` against bridge_state.

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::transfer_fixture_data as fx;
use paraloom_program::{accounts, instruction, BridgeState, NullifierAccount};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{
    instruction::Instruction,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

mod common;
use common::{add_program_data, entry};

// Nullifiers, output commitments, root and proof come from the on-chain
// transfer verifier fixture so the happy-path proof verifies against the
// program's root.
const N0: [u8; 32] = fx::FIXTURE_NULLIFIER_0;
const N1: [u8; 32] = fx::FIXTURE_NULLIFIER_1;
const NEW_ROOT: [u8; 32] = [7u8; 32];

/// The 256-byte alt_bn128 wire transfer proof from the fixture.
fn fixture_proof() -> Vec<u8> {
    let mut p = Vec::with_capacity(256);
    p.extend_from_slice(&fx::FIXTURE_PROOF_A);
    p.extend_from_slice(&fx::FIXTURE_PROOF_B);
    p.extend_from_slice(&fx::FIXTURE_PROOF_C);
    p
}

/// The two output commitments bound into the fixture proof.
fn out_commitments() -> [[u8; 32]; 2] {
    [fx::FIXTURE_COMMITMENT_0, fx::FIXTURE_COMMITMENT_1]
}

fn initialize_ix(
    program_id: Pubkey,
    state_pda: Pubkey,
    upgrade_authority: Pubkey,
    program_data: Pubkey,
) -> Instruction {
    Instruction {
        program_id,
        data: instruction::Initialize {
            program_version: 0x0004_0000,
            initial_merkle_root: fx::FIXTURE_ROOT,
        }
        .data(),
        accounts: accounts::Initialize {
            bridge_state: state_pda,
            authority: upgrade_authority,
            program_data,
            system_program: solana_sdk::system_program::ID,
        }
        .to_account_metas(None),
    }
}

async fn send(
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
async fn shielded_transfer_records_nullifiers_and_advances_root() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let (mut banks_client, _payer, recent_blockhash) = pt.start().await;

    let (state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (n0_pda, _) = Pubkey::find_program_address(&[b"nullifier", &N0], &program_id);
    let (n1_pda, _) = Pubkey::find_program_address(&[b"nullifier", &N1], &program_id);

    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        initialize_ix(
            program_id,
            state_pda,
            upgrade_authority.pubkey(),
            program_data_pda,
        ),
    )
    .await
    .unwrap();
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::ShieldedTransfer {
                nullifiers: [N0, N1],
                output_commitments: out_commitments(),
                new_merkle_root: NEW_ROOT,
                proof: fixture_proof(),
            }
            .data(),
            accounts: accounts::ShieldedTransfer {
                bridge_state: state_pda,
                nullifier_account_0: n0_pda,
                nullifier_account_1: n1_pda,
                authority: upgrade_authority.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await
    .unwrap();

    // Root advanced to the leader-computed value; no counters touched.
    let state_raw = banks_client.get_account(state_pda).await.unwrap().unwrap();
    let state = BridgeState::try_deserialize(&mut state_raw.data.as_slice()).unwrap();
    assert_eq!(state.merkle_root, NEW_ROOT);
    assert_eq!(
        state.withdrawal_count, 0,
        "transfers must not move the withdrawal counter"
    );
    assert_eq!(state.total_withdrawn, 0, "transfers release no funds");

    // Both input nullifier PDAs now exist and record the spent notes.
    for (pda, nullifier) in [(n0_pda, N0), (n1_pda, N1)] {
        let raw = banks_client.get_account(pda).await.unwrap().unwrap();
        let acct = NullifierAccount::try_deserialize(&mut raw.data.as_slice()).unwrap();
        assert_eq!(acct.nullifier, nullifier);
        assert_eq!(
            acct.withdrawal_id, 0,
            "transfer-spent nullifiers carry no withdrawal id"
        );
    }
}

#[tokio::test]
async fn shielded_transfer_replay_is_rejected() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let (mut banks_client, _payer, recent_blockhash) = pt.start().await;

    let (state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (n0_pda, _) = Pubkey::find_program_address(&[b"nullifier", &N0], &program_id);
    let (n1_pda, _) = Pubkey::find_program_address(&[b"nullifier", &N1], &program_id);

    // The replay reuses the same input nullifiers (the only fields that seed
    // the nullifier PDAs) but advances `new_merkle_root`, so the second
    // transaction is not a byte-identical copy of the first — otherwise
    // BanksClient would dedupe it on a matching signature and return the
    // cached success without re-executing.
    let transfer_ix = |root: [u8; 32]| Instruction {
        program_id,
        data: instruction::ShieldedTransfer {
            nullifiers: [N0, N1],
            output_commitments: out_commitments(),
            new_merkle_root: root,
            proof: fixture_proof(),
        }
        .data(),
        accounts: accounts::ShieldedTransfer {
            bridge_state: state_pda,
            nullifier_account_0: n0_pda,
            nullifier_account_1: n1_pda,
            authority: upgrade_authority.pubkey(),
            system_program: solana_sdk::system_program::ID,
        }
        .to_account_metas(None),
    };

    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        initialize_ix(
            program_id,
            state_pda,
            upgrade_authority.pubkey(),
            program_data_pda,
        ),
    )
    .await
    .unwrap();
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        transfer_ix(NEW_ROOT),
    )
    .await
    .unwrap();

    // Reusing the spent nullifiers must fail on the already-initialized PDA —
    // the same double-spend defence `withdraw` relies on.
    let result = send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        transfer_ix([9u8; 32]),
    )
    .await;
    assert!(result.is_err(), "replay of spent nullifiers must fail");
}

#[tokio::test]
async fn shielded_transfer_with_duplicate_nullifier_is_rejected() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let (mut banks_client, _payer, recent_blockhash) = pt.start().await;

    let (state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (n0_pda, _) = Pubkey::find_program_address(&[b"nullifier", &N0], &program_id);

    // Both inputs carry the same nullifier, so both account slots resolve to
    // the same PDA. Anchor rejects the second `init` on an account the first
    // already created (the body's `DuplicateNullifier` guard is defence in
    // depth behind that). Either way the transaction must fail.
    let dup_ix = Instruction {
        program_id,
        data: instruction::ShieldedTransfer {
            nullifiers: [N0, N0],
            output_commitments: out_commitments(),
            new_merkle_root: NEW_ROOT,
            proof: fixture_proof(),
        }
        .data(),
        accounts: accounts::ShieldedTransfer {
            bridge_state: state_pda,
            nullifier_account_0: n0_pda,
            nullifier_account_1: n0_pda,
            authority: upgrade_authority.pubkey(),
            system_program: solana_sdk::system_program::ID,
        }
        .to_account_metas(None),
    };

    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        initialize_ix(
            program_id,
            state_pda,
            upgrade_authority.pubkey(),
            program_data_pda,
        ),
    )
    .await
    .unwrap();
    let result = send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        dup_ix,
    )
    .await;
    assert!(result.is_err(), "duplicate input nullifier must fail");
}
