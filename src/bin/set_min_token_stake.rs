//! Update the required dual-stake minimum token stake (#829).
//!
//! Registry-authority-signed.
//!
//! Env:
//!   SOLANA_RPC_URL                 (default: devnet)
//!   SOLANA_PROGRAM_ID              the deployed bridge program id
//!   AUTHORITY_KEYPAIR_PATH         the registry authority keypair (signer)
//!   MIN_TOKEN_STAKE                the new minimum token stake

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
    let authority = load_keypair_from_file(&std::env::var("AUTHORITY_KEYPAIR_PATH")?)?;
    let new_min: u64 = std::env::var("MIN_TOKEN_STAKE")?.parse()?;

    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());
    let (registry, _) = derive_validator_registry(&program_id);

    println!("=== set min token stake ===");
    println!("Program:      {program_id}");
    println!("Authority:    {}", authority.pubkey());
    println!("Registry PDA: {registry}");
    println!("New Min:      {new_min}");

    let ix = create_set_min_token_stake_instruction(
        &program_id,
        &authority.pubkey(),
        new_min,
    );
    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&authority.pubkey()),
        &[&authority],
        blockhash,
    );

    println!("\nSending set_min_token_stake...");
    let sig = client.send_and_confirm_transaction(&tx)?;
    println!("Min token stake updated. Signature: {sig}");

    Ok(())
}
