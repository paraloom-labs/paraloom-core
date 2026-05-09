//! Twelfth on-chain unit test for #71. Replay-rejection counterpart
//! to withdraw_test (#143). The audit's primary concern was
//! double-spend; the on-chain defence is the init'd nullifier PDA,
//! and Anchor's init rejects an already-initialised account.

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::{accounts, instruction};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{instruction::Instruction, signature::Signer, transaction::Transaction};

mod common;
use common::entry;

const NULLIFIER: [u8; 32] = [42u8; 32];

#[tokio::test]
async fn withdraw_with_same_nullifier_is_rejected() {
    let program_id = paraloom_program::ID;
    let pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    let (state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(&[b"bridge_vault"], &program_id);
    let (nullifier_pda, _) = Pubkey::find_program_address(&[b"nullifier", &NULLIFIER], &program_id);

    let withdraw_ix = || Instruction {
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
            recipient: payer.pubkey(),
            authority: payer.pubkey(),
            system_program: solana_sdk::system_program::ID,
        }
        .to_account_metas(None),
    };

    let setup = [
        Instruction {
            program_id,
            data: instruction::Initialize {
                program_version: 0x0004_0000,
                initial_merkle_root: [0u8; 32],
            }
            .data(),
            accounts: accounts::Initialize {
                bridge_state: state_pda,
                authority: payer.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
        Instruction {
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
        },
        withdraw_ix(),
    ];
    for ix in setup {
        let mut tx = Transaction::new_with_payer(&[ix], Some(&payer.pubkey()));
        tx.sign(&[&payer], recent_blockhash);
        banks_client.process_transaction(tx).await.unwrap();
    }

    // Replay with a fresh blockhash so the runtime does not dedupe
    // the second tx as a copy of the first. Same nullifier, same
    // shape — Anchor's init on the nullifier_account PDA must
    // reject the already-existing account, the on-chain primary
    // defence the audit asked us to pin.
    let new_blockhash = banks_client.get_latest_blockhash().await.unwrap();
    let mut tx = Transaction::new_with_payer(&[withdraw_ix()], Some(&payer.pubkey()));
    tx.sign(&[&payer], new_blockhash);
    let result = banks_client.process_transaction(tx).await;
    assert!(result.is_err(), "replay of the same nullifier must fail");
}
