//! Initialize bridge on Solana localnet/devnet

use paraloom::bridge::solana::*;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig, signature::Signer, transaction::Transaction,
};
use std::str::FromStr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("=== Initializing Paraloom Bridge ===\n");

    // Load config from environment
    let rpc_url =
        std::env::var("SOLANA_RPC_URL").unwrap_or_else(|_| "http://localhost:8899".to_string());
    let program_id_str = std::env::var("SOLANA_PROGRAM_ID")?;
    let keypair_path = std::env::var("BRIDGE_AUTHORITY_KEYPAIR_PATH")?;

    println!("RPC URL: {}", rpc_url);
    println!("Program ID: {}", program_id_str);
    println!("Authority Keypair: {}\n", keypair_path);

    // Parse program ID
    let program_id = solana_sdk::pubkey::Pubkey::from_str(&program_id_str)?;

    // Load authority keypair
    println!("Loading authority keypair...");
    let authority = load_keypair_from_file(&keypair_path)?;
    println!("Authority Address: {}\n", authority.pubkey());

    // Create RPC client
    println!("Connecting to Solana...");
    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    // Check authority balance
    let balance = client.get_balance(&authority.pubkey())?;
    println!("Authority Balance: {} SOL\n", balance as f64 / 1e9);

    if balance < 1_000_000 {
        return Err("Insufficient balance. Need at least 0.001 SOL".into());
    }

    // Create initialize instruction with initial merkle root
    println!("Creating initialize instruction...");
    // Initial merkle root is the empty tree root (all zeros for now)
    // In production, this should come from a trusted setup
    let initial_merkle_root = [0u8; 32];
    let ix = create_initialize_instruction(&program_id, &authority.pubkey(), initial_merkle_root)?;
    println!(
        "Instruction created with initial merkle root: {:?}\n",
        &initial_merkle_root[..8]
    );

    // Get recent blockhash
    println!("Getting recent blockhash...");
    let blockhash = client.get_latest_blockhash()?;
    println!("Blockhash: {}\n", blockhash);

    // Create and sign transaction
    println!("Creating transaction...");
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&authority.pubkey()),
        &[&authority],
        blockhash,
    );

    // Send transaction
    println!("Sending transaction...");
    let signature = client.send_and_confirm_transaction(&tx)?;

    println!("\n=== Bridge Initialized Successfully! ===");
    println!("Signature: {}", signature);
    println!("\nBridge State PDA:");
    let (bridge_state, bump) = derive_bridge_state(&program_id);
    println!("  Address: {}", bridge_state);
    println!("  Bump: {}", bump);

    Ok(())
}
