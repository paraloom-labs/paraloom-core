//! Initialize the per-asset shielded-token vault and config for an SPL mint.
//!
//! Run once by the program's upgrade authority to onboard a new SPL token
//! into the shielded pool (#779). The cap starts at 0 (fail-closed);
//! call `set-asset-deposit-cap` to open deposits.
//!
//! Env:
//!   SOLANA_RPC_URL                 (default: devnet)
//!   SOLANA_PROGRAM_ID              the deployed bridge program id
//!   BRIDGE_AUTHORITY_KEYPAIR_PATH  the program's upgrade authority (signer)
//!   MINT                           the SPL token mint to initialize

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

    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    let token_program = client.get_account(&mint)?.owner;

    let (vault, _) = derive_asset_vault(&program_id, &mint);
    let (config, _) = derive_asset_config(&program_id, &mint);

    println!("=== init asset vault ===");
    println!("Program:       {program_id}");
    println!("Authority:     {}", authority.pubkey());
    println!("Mint:          {mint}");
    println!("Token program: {token_program}");
    println!("Vault PDA:     {vault}");
    println!("Config PDA:    {config}");

    if client.get_account(&vault).is_ok() {
        println!("\nVault already exists — nothing to do.");
        return Ok(());
    }

    let ix = create_init_asset_vault_instruction(
        &program_id,
        &authority.pubkey(),
        &mint,
        &token_program,
    )?;
    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&authority.pubkey()),
        &[&authority],
        blockhash,
    );

    println!("\nSending init_asset_vault...");
    let sig = client.send_and_confirm_transaction(&tx)?;
    println!("Asset vault created. Signature: {sig}");

    Ok(())
}
