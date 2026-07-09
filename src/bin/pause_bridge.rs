//! Pause / unpause the bridge.
//!
//! Freezes (or re-opens) deposits and settlement. Signed by the **bridge
//! settlement authority** (the `Hky4Zx2…` settler key) — this is a DIFFERENT
//! key from the upgrade/registry authority that `reconcile-validators` uses.
//! The redeploy runbook pauses before the in-place upgrade and unpauses only
//! after a co-signed smoke settlement succeeds.
//!
//! Usage:  pause-bridge pause | unpause
//!
//! Env:
//!   SOLANA_RPC_URL, SOLANA_PROGRAM_ID
//!   BRIDGE_SETTLER_KEYPAIR_PATH   the bridge settlement authority keypair

use paraloom::bridge::solana::*;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Signer,
    transaction::Transaction,
};
use std::str::FromStr;

/// Byte offset of `BridgeState.paused`: disc(8) + program_version(u32=4) +
/// authority(32) + total_deposited(8) + total_withdrawn(8) + deposit_count(8) +
/// withdrawal_count(8) = 76.
const PAUSED_OFFSET: usize = 76;

fn read_paused(
    client: &RpcClient,
    program_id: &Pubkey,
) -> Result<bool, Box<dyn std::error::Error>> {
    let (bridge_state, _) =
        solana_sdk::pubkey::Pubkey::find_program_address(&[b"bridge_state"], program_id);
    let acc = client.get_account(&bridge_state)?;
    Ok(acc.data.get(PAUSED_OFFSET).copied().unwrap_or(0) != 0)
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
    let authority = load_keypair_from_file(&std::env::var("BRIDGE_SETTLER_KEYPAIR_PATH")?)?;

    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    println!("Program:   {program_id}");
    println!("Authority: {} (bridge settler)", authority.pubkey());
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
