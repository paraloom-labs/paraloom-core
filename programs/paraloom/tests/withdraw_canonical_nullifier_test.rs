//! Adversarial on-chain test for the non-canonical nullifier replay (audit).
//!
//! `withdraw`'s proof public input is `Fr::from_le_bytes_mod_order(nullifier)`,
//! which maps both a canonical `n` and the non-canonical `n + p` (`p` = the
//! BN254 scalar modulus) to the SAME field element — so the same proof verifies
//! for both. The replay defence, the nullifier PDA, keys on the RAW bytes, so
//! `n` and `n + p` derive DIFFERENT PDAs. Without a canonical check a spent note
//! could be settled a second time under `n + p`. This test settles `n`, then
//! replays under `n + p` with the same proof and asserts it is now rejected.

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::withdraw_fixture_data as fx;
use paraloom_program::{accounts, instruction};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    signature::{Keypair, Signer},
    transaction::Transaction,
};

mod common;
use common::{add_program_data, entry};

const NULLIFIER: [u8; 32] = fx::FIXTURE_NULLIFIER;
const WITHDRAW_AMOUNT: u64 = fx::FIXTURE_AMOUNT;
const MIN_VALIDATOR_STAKE: u64 = 1_000_000_000;

/// The BN254 scalar field modulus `p` in little-endian bytes.
const BN254_FR_MODULUS_LE: [u8; 32] = [
    0x01, 0x00, 0x00, 0xf0, 0x93, 0xf5, 0xe1, 0x43, 0x91, 0x70, 0xb9, 0x79, 0x48, 0xe8, 0x33, 0x28,
    0x5d, 0x58, 0x81, 0x81, 0xb6, 0x45, 0x50, 0xb8, 0x29, 0xa0, 0x31, 0xe1, 0x72, 0x4e, 0x64, 0x30,
];

/// `n + p` as a 256-bit little-endian value. For a canonical `n < p < 2^254`
/// this fits in 32 bytes (no final carry), and reduces mod `p` back to `n`.
fn add_modulus(n: [u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let s = n[i] as u16 + BN254_FR_MODULUS_LE[i] as u16 + carry;
        out[i] = (s & 0xff) as u8;
        carry = s >> 8;
    }
    assert_eq!(carry, 0, "n + p must fit in 256 bits for a canonical n");
    out
}

/// The 256-byte alt_bn128 wire proof from the fixture.
fn fixture_proof() -> Vec<u8> {
    let mut p = Vec::with_capacity(256);
    p.extend_from_slice(&fx::FIXTURE_PROOF_A);
    p.extend_from_slice(&fx::FIXTURE_PROOF_B);
    p.extend_from_slice(&fx::FIXTURE_PROOF_C);
    p
}

#[tokio::test]
async fn withdraw_rejects_a_non_canonical_nullifier_replay() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    let (state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(&[b"bridge_vault"], &program_id);
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);
    let (validator_pda, _) = Pubkey::find_program_address(
        &[b"validator", upgrade_authority.pubkey().as_ref()],
        &program_id,
    );

    let recipient = Keypair::new();

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

    // init + registry + register + deposit.
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
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
    .await
    .unwrap();

    let withdraw_ix = |nullifier: [u8; 32]| {
        let (npda, _) = Pubkey::find_program_address(&[b"nullifier", &nullifier], &program_id);
        let mut metas = accounts::Withdraw {
            bridge_state: state_pda,
            bridge_vault: vault_pda,
            nullifier_account: npda,
            recipient: recipient.pubkey(),
            validator_account: validator_pda,
            validator_registry: registry_pda,
            authority: upgrade_authority.pubkey(),
            system_program: solana_sdk::system_program::ID,
        }
        .to_account_metas(None);
        metas.push(AccountMeta::new_readonly(upgrade_authority.pubkey(), true));
        metas.push(AccountMeta::new_readonly(validator_pda, false));
        Instruction {
            program_id,
            data: instruction::Withdraw {
                nullifier,
                amount: WITHDRAW_AMOUNT,
                expiration_slot: u64::MAX,
                proof: fixture_proof(),
            }
            .data(),
            accounts: metas,
        }
    };

    // The canonical nullifier settles normally.
    send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        withdraw_ix(NULLIFIER),
    )
    .await
    .expect("the canonical nullifier must settle");

    // The same note replayed under `n + p`: the proof still verifies (same
    // reduced field element) and the PDA is a fresh one, so only the canonical
    // check stands between this and a double-spend. It must be rejected.
    let non_canonical = add_modulus(NULLIFIER);
    assert_ne!(non_canonical, NULLIFIER, "n + p must differ from n in raw bytes");
    let result = send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        withdraw_ix(non_canonical),
    )
    .await;
    assert!(
        result.is_err(),
        "a non-canonical nullifier encoding must be rejected, not settled a second time"
    );
}
