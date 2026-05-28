//! Eleventh on-chain unit test for #71. Happy-path withdraw:
//! initialize → deposit → withdraw. Pins the recipient transfer,
//! the L2-visible counters, and the nullifier PDA the replay layer
//! relies on. Replay-rejection is a separate PR.
//!
//! Init + withdraw both run as the program upgrade authority (#204);
//! the deposit ix is permissionless and signed by the auto-payer.

use anchor_lang::prelude::*;
use anchor_lang::{InstructionData, ToAccountMetas};
use paraloom_program::{accounts, instruction, BridgeState, NullifierAccount};
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{
    instruction::Instruction,
    signature::{Keypair, Signer},
    transaction::Transaction,
};

mod common;
use common::{add_program_data, entry};

const NULLIFIER: [u8; 32] = [42u8; 32];

#[tokio::test]
async fn withdraw_credits_recipient_and_advances_counters() {
    let program_id = paraloom_program::ID;
    let mut pt = ProgramTest::new("paraloom_program", program_id, processor!(entry));
    let (program_data_pda, upgrade_authority) = add_program_data(&mut pt, program_id);
    let (mut banks_client, payer, recent_blockhash) = pt.start().await;

    let (state_pda, _) = Pubkey::find_program_address(&[b"bridge_state"], &program_id);
    let (vault_pda, _) = Pubkey::find_program_address(&[b"bridge_vault"], &program_id);
    let (nullifier_pda, _) = Pubkey::find_program_address(&[b"nullifier", &NULLIFIER], &program_id);

    let recipient = Keypair::new();

    // Helper to land a single ix signed by `signer` (also tx payer).
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

    // 1. initialize — must be signed by the upgrade authority (#204).
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
    .await;

    // 2. deposit — permissionless; 2 SOL so the vault stays above the
    //    rent-exempt minimum (~890_880 lamports) after the 1 SOL withdraw.
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

    // 3. withdraw — must be signed by the bridge authority
    //    (`has_one = authority` on bridge_state), which now equals the
    //    upgrade authority from init.
    send(
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
                authority: upgrade_authority.pubkey(),
                system_program: solana_sdk::system_program::ID,
            }
            .to_account_metas(None),
        },
    )
    .await;

    let state_raw = banks_client.get_account(state_pda).await.unwrap().unwrap();
    let state = BridgeState::try_deserialize(&mut state_raw.data.as_slice()).unwrap();
    assert_eq!(state.total_withdrawn, 1_000_000_000);
    assert_eq!(state.withdrawal_count, 1);

    let nul_raw = banks_client
        .get_account(nullifier_pda)
        .await
        .unwrap()
        .expect("nullifier PDA must exist after withdraw");
    let nul = NullifierAccount::try_deserialize(&mut nul_raw.data.as_slice()).unwrap();
    assert_eq!(nul.nullifier, NULLIFIER);
    assert_eq!(nul.withdrawal_id, 1);
}
