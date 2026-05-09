//! Seventh on-chain unit test for #71. Mirror of pause_test:
//! initialize → pause → unpause → deposit must now succeed and the
//! state must reflect the deposit. Pins the gate is bidirectional —
//! a regression in unpause that left `paused = true` would silently
//! freeze the bridge after any incident, an availability bug just
//! as bad as the safety bug pause_test guards against.

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::{accounts, instruction, BridgeState};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{instruction::Instruction, signature::Signer, transaction::Transaction};

mod common;
use common::entry;

#[tokio::test]
async fn unpause_clears_flag_and_unblocks_deposit() {
    let program_id = paraloom_program::ID;
    let pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    let (state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(&[b"bridge_vault"], &program_id);

    let pause_meta = accounts::Pause {
        bridge_state: state_pda,
        authority: payer.pubkey(),
    }
    .to_account_metas(None);

    let ixs = [
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
            data: instruction::Pause {}.data(),
            accounts: pause_meta.clone(),
        },
        Instruction {
            program_id,
            data: instruction::Unpause {}.data(),
            accounts: pause_meta,
        },
        Instruction {
            program_id,
            data: instruction::Deposit {
                amount: 1_000_000,
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
    ];
    for ix in ixs {
        let mut tx = Transaction::new_with_payer(&[ix], Some(&payer.pubkey()));
        tx.sign(&[&payer], recent_blockhash);
        banks_client.process_transaction(tx).await.unwrap();
    }

    let raw = banks_client.get_account(state_pda).await.unwrap().unwrap();
    let state = BridgeState::try_deserialize(&mut raw.data.as_slice()).unwrap();
    assert!(!state.paused);
    assert_eq!(state.total_deposited, 1_000_000);
    assert_eq!(state.deposit_count, 1);
}
