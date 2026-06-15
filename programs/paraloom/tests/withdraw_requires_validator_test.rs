//! On-chain unit test for #71: settlement is validator-gated.
//!
//! `withdraw` credits its fee to the settling validator's account, bound
//! by seeds to the `authority` signer. If that signer never registered as
//! a validator, the `validator_account` PDA does not exist and the
//! withdraw must fail — settlement is reserved for staked validators.
//!
//! Counterpart to withdraw_test (happy path): this pins the *negative*
//! side of the same gate.

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::{accounts, instruction};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{
    instruction::Instruction,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

mod common;
use common::{add_program_data, entry};

const NULLIFIER: [u8; 32] = [7u8; 32];

#[tokio::test]
async fn withdraw_fails_when_authority_is_not_a_registered_validator() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    let (state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(&[b"bridge_vault"], &program_id);
    let (nullifier_pda, _) = Pubkey::find_program_address(&[b"nullifier", &NULLIFIER], &program_id);
    // Derived but deliberately never created — no register_validator call.
    let (validator_pda, _) = Pubkey::find_program_address(
        &[b"validator", upgrade_authority.pubkey().as_ref()],
        &program_id,
    );
    let (registry_pda, _) = Pubkey::find_program_address(&[b"validator_registry"], &program_id);

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

    // initialize + deposit, but NO validator registration.
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

    // withdraw against a validator account that was never created → fail.
    let result = send(
        &mut banks_client,
        recent_blockhash,
        &upgrade_authority,
        Instruction {
            program_id,
            data: instruction::Withdraw {
                nullifier: NULLIFIER,
                amount: 1_000_000_000,
                expiration_slot: u64::MAX,
                proof: vec![1, 2, 3, 4],
            }
            .data(),
            accounts: accounts::Withdraw {
                bridge_state: state_pda,
                bridge_vault: vault_pda,
                nullifier_account: nullifier_pda,
                recipient: recipient.pubkey(),
                validator_account: validator_pda,
                validator_registry: registry_pda,
                authority: upgrade_authority.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;

    assert!(
        result.is_err(),
        "withdraw must fail when the settling authority is not a registered validator"
    );
}
