//! On-chain unit test for `set_bridge_authority` (bridge authority rotation).
//!
//! `initialize` (#204) pins the bridge authority to the program upgrade
//! authority at genesis. This rotates it to a separate operating key so the
//! upgrade authority can stay offline while a node-resident validator key
//! settles. Pins: (1) the current authority can rotate it; (2) a non-authority
//! signer is rejected by `has_one = authority`.

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::{accounts, instruction, BridgeState};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{
    instruction::Instruction,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

mod common;
use common::{add_program_data, entry};

#[tokio::test]
async fn set_bridge_authority_rotates_and_rejects_non_authority() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    let (state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);

    // initialize — signed by the upgrade authority (#204); bridge_state.authority
    // becomes the upgrade authority.
    let mut tx = Transaction::new_with_payer(
        &[Instruction {
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
        }],
        Some(&upgrade_authority.pubkey()),
    );
    tx.sign(&[&upgrade_authority], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();

    // Negative: a non-authority signer cannot rotate (has_one = authority).
    let new_authority = Keypair::new();
    let set_ix = |signer: &Pubkey| Instruction {
        program_id,
        data: instruction::SetBridgeAuthority {
            new_authority: new_authority.pubkey(),
        }
        .data(),
        accounts: accounts::SetBridgeAuthority {
            bridge_state: state_pda,
            authority: *signer,
        }
        .to_account_metas(None),
    };

    let mut tx = Transaction::new_with_payer(&[set_ix(&payer.pubkey())], Some(&payer.pubkey()));
    tx.sign(&[&payer], recent_blockhash);
    let res = banks_client.process_transaction(tx).await;
    assert!(
        res.is_err(),
        "a non-authority signer must not rotate the bridge authority"
    );

    // Happy path: the current authority rotates to the new key.
    let mut tx = Transaction::new_with_payer(
        &[set_ix(&upgrade_authority.pubkey())],
        Some(&upgrade_authority.pubkey()),
    );
    tx.sign(&[&upgrade_authority], recent_blockhash);
    banks_client.process_transaction(tx).await.unwrap();

    let state_raw = banks_client.get_account(state_pda).await.unwrap().unwrap();
    let state = BridgeState::try_deserialize(&mut state_raw.data.as_slice()).unwrap();
    assert_eq!(
        state.authority,
        new_authority.pubkey(),
        "bridge authority must be the rotated key"
    );
}
