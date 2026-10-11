//! Raise or lower the per-asset SPL deposit cap for a mint (#779).
//!
//! Upgrade-authority-gated. Controls the maximum live token balance
//! that the asset vault can hold.
//!
//! Env:
//!   SOLANA_RPC_URL                 (default: devnet)
//!   SOLANA_PROGRAM_ID              the deployed bridge program id
//!   BRIDGE_AUTHORITY_KEYPAIR_PATH  the program's upgrade authority (signer)
//!   MINT                           the SPL token mint to adjust
//!   DEPOSIT_CAP                    the new deposit cap (integer token units)

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
    let mint = Pubkey::from_str(&std::env::var("MINT")?)?;
    let new_cap: u64 = std::env::var("DEPOSIT_CAP")?.parse()?;

    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());
    let (config, _) = derive_asset_config(&program_id, &mint);

    println!("=== set asset deposit cap ===");
    println!("Program:     {program_id}");
    println!("Authority:   {}", authority.pubkey());
    println!("Mint:        {mint}");
    println!("Config PDA:  {config}");
    println!("New Cap:     {new_cap}");

    let ix = create_set_asset_deposit_cap_instruction(
        &program_id,
        &authority.pubkey(),
        &mint,
        new_cap,
    );
    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&authority.pubkey()),
        &[&authority],
        blockhash,
    );

    println!("\nSending set_asset_deposit_cap...");
    let sig = client.send_and_confirm_transaction(&tx)?;
    println!("Deposit cap updated. Signature: {sig}");

    Ok(())
}
