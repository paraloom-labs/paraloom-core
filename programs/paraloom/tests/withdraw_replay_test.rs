//! Twelfth on-chain unit test for #71. Replay-rejection counterpart
//! to withdraw_test (#143). The audit's primary concern was
//! double-spend; the on-chain defence is the init'd nullifier PDA,
//! and Anchor's init rejects an already-initialised account.
//!
//! Init + withdraw both run as the program upgrade authority (#204);
//! deposit is permissionless and stays on the auto-payer.

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::withdraw_fixture_data as fx;
use paraloom_program::{accounts, instruction};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{
    instruction::Instruction,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

mod common;
use common::{add_program_data, entry};

// Root, nullifier, amount and proof come from the on-chain verifier fixture so
// the first withdraw's proof verifies against the program's root.
const NULLIFIER: [u8; 32] = fx::FIXTURE_NULLIFIER;

/// The 256-byte alt_bn128 wire proof from the fixture.
fn fixture_proof() -> Vec<u8> {
    let mut p = Vec::with_capacity(256);
    p.extend_from_slice(&fx::FIXTURE_PROOF_A);
    p.extend_from_slice(&fx::FIXTURE_PROOF_B);
    p.extend_from_slice(&fx::FIXTURE_PROOF_C);
    p
}

#[tokio::test]
async fn withdraw_with_same_nullifier_is_rejected() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    let (state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(&[b"bridge_vault"], &program_id);
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (nullifier_pda, _) = Pubkey::find_program_address(&[b"nullifier", &NULLIFIER], &program_id);
    // The settling authority is also the registered validator that earns the
    // fee — `withdraw` requires its account to exist and be active.
    let (validator_pda, _) = Pubkey::find_program_address(
        &[b"validator", upgrade_authority.pubkey().as_ref()],
        &program_id,
    );

    let recipient = Keypair::new();

    // Both attempts use the SAME valid fixture proof and the SAME nullifier
    // (the whole point of the test). To keep the two transaction signatures
    // distinct — otherwise BanksClient returns the cached result of the first
    // instead of re-executing the second — they vary `expiration_slot`, which
    // is not a proof public input, so the proof still verifies. The replay is
    // then rejected by the init'd nullifier PDA, the on-chain primary defence.
    let withdraw_ix = |expiration_slot: u64| Instruction {
        program_id,
        data: instruction::Withdraw {
            nullifier: NULLIFIER,
            amount: fx::FIXTURE_AMOUNT,
            expiration_slot,
            proof: fixture_proof(),
        }
        .data(),
        accounts: accounts::Withdraw {
            bridge_state: state_pda,
            bridge_vault: vault_pda,
            nullifier_account: nullifier_pda,
            recipient: recipient.pubkey(),
            validator_account: validator_pda,
            authority: upgrade_authority.pubkey(),
            system_program: solana_sdk::system_program::ID,
        }
        .to_account_metas(None),
    };

    // Setup: init (upgrade-authority signer) + deposit (auto-payer) +
    // first withdraw (upgrade-authority signer). Each tx uses the right signer
    // for the instruction it carries.
    let init_ix = Instruction {
        program_id,
        data: instruction::Initialize {
            program_version: 0x0004_0000,
            initial_merkle_root: fx::FIXTURE_ROOT,
        }
        .data(),
        accounts: accounts::Initialize {
            bridge_state: state_pda,
            authority: upgrade_authority.pubkey(),
            program_data: program_data_pda,
            system_program: solana_sdk::system_program::ID,
        }
        .to_account_metas(None),
    };
    let deposit_ix = Instruction {
        program_id,
        data: instruction::Deposit {
            amount: 3_000_000_000,
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
    };

    // Registry init (upgrade-authority gated) + register the settling
    // authority as a validator so the first withdraw can credit its fee.
    let registry_ix = Instruction {
        program_id,
        data: instruction::InitializeValidatorRegistry {}.data(),
        accounts: accounts::InitializeValidatorRegistry {
            validator_registry: registry_pda,
            authority: upgrade_authority.pubkey(),
            program_data: program_data_pda,
            system_program: solana_sdk::system_program::ID,
        }
        .to_account_metas(None),
    };
    let register_ix = Instruction {
        program_id,
        data: instruction::RegisterValidator {
            stake_amount: 1_000_000_000,
        }
        .data(),
        accounts: accounts::RegisterValidator {
            validator_account: validator_pda,
            validator_registry: registry_pda,
            validator: upgrade_authority.pubkey(),
            system_program: solana_sdk::system_program::ID,
        }
        .to_account_metas(None),
    };

    let mut tx = Transaction::new_with_payer(&[init_ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();

    let mut tx = Transaction::new_with_payer(&[registry_ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();

    let mut tx = Transaction::new_with_payer(&[register_ix], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();

    let mut tx = Transaction::new_with_payer(&[deposit_ix], Some(&payer.pubkey()));
    tx.sign(&[&payer], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();

    let mut tx =
        Transaction::new_with_payer(&[withdraw_ix(u64::MAX)], Some(&upgrade_authority.pubkey()));
    tx.sign(&[&upgrade_authority], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();

    // Replay: same NULLIFIER (the whole point) and the same valid proof, with a
    // different expiration_slot so the tx signature does not collide with the
    // first. Anchor's `init` on the nullifier_account PDA must reject the
    // already-existing account, the on-chain primary defence the audit pinned.
    let mut tx = Transaction::new_with_payer(
        &[withdraw_ix(u64::MAX - 1)],
        Some(&upgrade_authority.pubkey()),
    );
    tx.sign(&[&upgrade_authority], recent_blockhash);
    let result = banks_client.process_transaction(tx).await;
    assert!(result.is_err(), "replay of the same nullifier must fail");
}
