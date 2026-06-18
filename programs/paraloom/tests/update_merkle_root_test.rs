//! Fourth on-chain unit test for #71. Pins the contract that
//! `update_merkle_root` actually replaces `BridgeState.merkle_root`.
//! The L2 reads this field to anchor every withdrawal proof; a
//! handler regression that silently kept the old root would let
//! verifiers accept stale Merkle paths against a tree the on-chain
//! state has already moved past.
//!
//! Publishing a root anchors every subsequent withdrawal proof, so it
//! is gated by the same BFT validator quorum (#260) as settlement: a
//! single key can no longer install a forged root and drain the vault.
//! This test proves both the rejection (no quorum) and the positive
//! control (a full quorum replaces the field).

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::{accounts, instruction, BridgeState};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    signature::{Keypair, Signer},
    transaction::Transaction,
};

mod common;
use common::{add_program_data, entry};

const MIN_VALIDATOR_STAKE: u64 = 1_000_000_000;

#[tokio::test]
async fn update_merkle_root_requires_quorum_then_replaces_state_field() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let (mut banks_client, _payer, recent_blockhash) = pt.start().await;

    let (state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (validator_pda, _) = Pubkey::find_program_address(
        &[b"validator", upgrade_authority.pubkey().as_ref()],
        &program_id,
    );

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

    // initialize + registry + register the authority as the single validator.
    // With one active validator the quorum threshold is `floor(2*1/3)+1 = 1`.
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
    .await
    .unwrap();

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
    .await
    .unwrap();

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
    .await
    .unwrap();

    let new_root = [42u8; 32];

    // The update instruction, parameterised by the quorum co-signers appended
    // as remaining accounts.
    let update_ix = |quorum: &[(&Keypair, Pubkey)]| {
        let mut metas = accounts::UpdateMerkleRoot {
            bridge_state: state_pda,
            validator_registry: registry_pda,
            authority: upgrade_authority.pubkey(),
        }
        .to_account_metas(None);
        for (wallet, pda) in quorum {
            metas.push(AccountMeta::new_readonly(wallet.pubkey(), true));
            metas.push(AccountMeta::new_readonly(*pda, false));
        }
        Instruction {
            program_id,
            data: instruction::UpdateMerkleRoot {
                new_merkle_root: new_root,
            }
            .data(),
            accounts: metas,
        }
    };

    // Case A — no co-signers. The authority signs, but with zero co-signers the
    // quorum is not met and the root must NOT change.
    let result = send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        update_ix(&[]),
    )
    .await;
    assert!(
        result.is_err(),
        "an authority with no validator quorum must not publish a root"
    );

    // Case B — the registered validator co-signs, meeting the 1-of-1 quorum.
    let mut tx = Transaction::new_with_payer(
        &[update_ix(&[(&upgrade_authority, validator_pda)])],
        Some(&upgrade_authority.pubkey()),
    );
    tx.sign(&[&upgrade_authority], recent_blockhash);
    banks_client
        .process_transaction(tx)
        .await
        .expect("a full quorum must publish the new root");

    let raw = banks_client
        .get_account(state_pda)
        .await
        .unwrap()
        .unwrap();
    let state = BridgeState::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert_eq!(state.merkle_root, new_root);
}
