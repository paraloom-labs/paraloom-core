//! Rotate the bridge settlement authority (`bridge_state.authority`).
//!
//! `transact` binds settlement to `bridge_state.authority` via `has_one`, so the
//! node that submits the co-signed settlement must hold this key. When the
//! validator set is swapped (e.g. a dual-stake cutover), point this at the new
//! settling validator's wallet or every settlement aborts `ConstraintHasOne`.
//!
//! Cold-authority-gated: signed by `validator_registry.authority` (the cold
//! registry authority that manages the hot settlement key), not the current
//! bridge authority — so a compromised hot key cannot rotate control away.
//!
//! Env:
//!   SOLANA_RPC_URL                 (default: devnet)
//!   SOLANA_PROGRAM_ID              the deployed bridge program id
//!   BRIDGE_AUTHORITY_KEYPAIR_PATH  the cold registry authority (signer)
//!   NEW_BRIDGE_AUTHORITY           the new settlement authority pubkey

use paraloom::bridge::solana::*;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Signer,
    transaction::Transaction,
};
use std::str::FromStr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());
    let program_id = Pubkey::from_str(&std::env::var("SOLANA_PROGRAM_ID")?)?;
    let authority = load_keypair_from_file(&std::env::var("BRIDGE_AUTHORITY_KEYPAIR_PATH")?)?;
    let new_authority = Pubkey::from_str(&std::env::var("NEW_BRIDGE_AUTHORITY")?)?;

    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    println!("=== rotate bridge authority ===");
    println!("Program:       {program_id}");
    println!("Cold signer:   {}", authority.pubkey());
    println!("New authority: {new_authority}");

    let ix =
        create_set_bridge_authority_instruction(&program_id, &authority.pubkey(), &new_authority)?;
    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&authority.pubkey()),
        &[&authority],
        blockhash,
    );

    println!("\nSending set_bridge_authority...");
    let sig = client.send_and_confirm_transaction(&tx)?;
    println!("Rotated. Signature: {sig}");

    Ok(())
}
