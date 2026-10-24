//! Pause / unpause the bridge.
//!
//! Freezes (or re-opens) deposits and settlement. Signed by the **cold registry
//! authority** (the upgrade/registry key, the same one `reconcile-validators`
//! uses) — NOT the hot settlement key. Freeze/rotate power is deliberately kept
//! off the settlement host so a compromise of the node-resident settler cannot
//! freeze the bridge or rotate itself in. The redeploy runbook pauses before the
//! in-place upgrade and unpauses only after a co-signed smoke settlement succeeds.
//!
//! Usage:  pause-bridge pause | unpause
//!
//! Env:
//!   SOLANA_RPC_URL, SOLANA_PROGRAM_ID
//!   BRIDGE_AUTHORITY_KEYPAIR_PATH   the cold registry/upgrade authority keypair

use paraloom::bridge::solana::*;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    account::Account, commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Signer,
    transaction::Transaction,
};
use std::str::FromStr;

/// Anchor discriminator for `BridgeState`: `sha256("account:BridgeState")[..8]`.
const BRIDGE_STATE_DISCRIMINATOR: [u8; 8] = [6, 190, 226, 198, 76, 100, 157, 198];

/// Byte offset of `BridgeState.paused`: disc(8) + program_version(u32=4) +
/// authority(32) + total_deposited(8) + total_withdrawn(8) + deposit_count(8) +
/// withdrawal_count(8) = 76.
const PAUSED_OFFSET: usize = 76;

fn decode_paused_from_account(
    acc: &Account,
    program_id: &Pubkey,
) -> Result<bool, Box<dyn std::error::Error>> {
    if acc.owner != *program_id {
        return Err(format!(
            "BridgeState account owner mismatch: expected {}, got {}",
            program_id, acc.owner
        )
        .into());
    }
    if acc.data.len() <= PAUSED_OFFSET {
        return Err(format!(
            "BridgeState account too short: {} bytes (need > {})",
            acc.data.len(),
            PAUSED_OFFSET
        )
        .into());
    }
    if acc.data[..8] != BRIDGE_STATE_DISCRIMINATOR {
        return Err("BridgeState account discriminator mismatch".into());
    }
    Ok(acc.data[PAUSED_OFFSET] != 0)
}

fn read_paused(
    client: &RpcClient,
    program_id: &Pubkey,
) -> Result<bool, Box<dyn std::error::Error>> {
    let (bridge_state, _) =
        solana_sdk::pubkey::Pubkey::find_program_address(&[b"bridge_state"], program_id);
    let acc = client.get_account(&bridge_state)?;
    decode_paused_from_account(&acc, program_id)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let action = std::env::args().nth(1).unwrap_or_default();
    let pause = match action.as_str() {
        "pause" => true,
        "unpause" => false,
        _ => return Err("usage: pause-bridge pause | unpause".into()),
    };

    let rpc_url =
        std::env::var("SOLANA_RPC_URL").unwrap_or_else(|_| "http://localhost:8899".to_string());
    let program_id = Pubkey::from_str(&std::env::var("SOLANA_PROGRAM_ID")?)?;
    let authority = load_keypair_from_file(&std::env::var("BRIDGE_AUTHORITY_KEYPAIR_PATH")?)?;

    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    println!("Program:   {program_id}");
    println!(
        "Authority: {} (cold registry authority)",
        authority.pubkey()
    );
    println!("Action:    {action}");
    println!("paused before: {}", read_paused(&client, &program_id)?);

    let ix = if pause {
        create_pause_instruction(&program_id, &authority.pubkey())
    } else {
        create_unpause_instruction(&program_id, &authority.pubkey())
    };
    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&authority.pubkey()),
        &[&authority],
        blockhash,
    );
    let sig = client.send_and_confirm_transaction(&tx)?;
    println!("sig {sig}");
    println!("paused after:  {}", read_paused(&client, &program_id)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_bridge_state_account(program_id: Pubkey, paused: bool) -> Account {
        let mut data = vec![0u8; 117];
        data[..8].copy_from_slice(&BRIDGE_STATE_DISCRIMINATOR);
        data[PAUSED_OFFSET] = u8::from(paused);
        Account {
            lamports: 2_000_000,
            data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        }
    }

    #[test]
    fn decode_paused_reads_valid_bridge_state() {
        let program_id = Pubkey::new_unique();
        let unpaused = valid_bridge_state_account(program_id, false);
        assert!(!decode_paused_from_account(&unpaused, &program_id).unwrap());

        let paused = valid_bridge_state_account(program_id, true);
        assert!(decode_paused_from_account(&paused, &program_id).unwrap());
    }

    #[test]
    fn decode_paused_rejects_wrong_owner_discriminator_or_short_data() {
        let program_id = Pubkey::new_unique();
        let mut wrong_owner = valid_bridge_state_account(program_id, true);
        wrong_owner.owner = Pubkey::default();
        assert!(decode_paused_from_account(&wrong_owner, &program_id).is_err());

        let mut wrong_disc = valid_bridge_state_account(program_id, true);
        wrong_disc.data[0] ^= 0xFF;
        assert!(decode_paused_from_account(&wrong_disc, &program_id).is_err());

        let mut short = valid_bridge_state_account(program_id, true);
        short.data.truncate(PAUSED_OFFSET);
        assert!(decode_paused_from_account(&short, &program_id).is_err());
    }
}
