//! Test deposit flow on localnet

use paraloom::bridge::solana::*;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig, native_token::LAMPORTS_PER_SOL, signature::Signer,
    transaction::Transaction,
};
use std::str::FromStr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("=== Testing Paraloom Deposit Flow ===\n");

    // Load config from environment
    let rpc_url =
        std::env::var("SOLANA_RPC_URL").unwrap_or_else(|_| "http://localhost:8899".to_string());
    let program_id_str = std::env::var("SOLANA_PROGRAM_ID")?;
    let keypair_path = std::env::var("BRIDGE_AUTHORITY_KEYPAIR_PATH")?;

    println!("RPC URL: {}", rpc_url);
    println!("Program ID: {}", program_id_str);
    println!("Depositor Keypair: {}\n", keypair_path);

    // Parse program ID
    let program_id = solana_sdk::pubkey::Pubkey::from_str(&program_id_str)?;

    // Load depositor keypair (using authority for testing)
    println!("Loading depositor keypair...");
    let depositor = load_keypair_from_file(&keypair_path)?;
    println!("Depositor Address: {}\n", depositor.pubkey());

    // Create RPC client
    println!("Connecting to Solana...");
    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    // Check depositor balance
    let balance = client.get_balance(&depositor.pubkey())?;
    println!("Depositor Balance: {} SOL\n", balance as f64 / 1e9);

    if balance < LAMPORTS_PER_SOL {
        return Err("Insufficient balance. Need at least 1 SOL".into());
    }

    // Derive bridge vault PDA
    let (bridge_vault, vault_bump) = derive_bridge_vault(&program_id);
    println!("Bridge Vault PDA: {}", bridge_vault);
    println!("Vault Bump: {}\n", vault_bump);

    // Deposit parameters
    let deposit_amount = LAMPORTS_PER_SOL / 10; // 0.1 SOL
    let recipient = [1u8; 32]; // Mock recipient in privacy pool
    let randomness = [2u8; 32]; // Mock randomness for commitment

    println!("Deposit Amount: {} SOL", deposit_amount as f64 / 1e9);
    println!(
        "Recipient (privacy address): {:?}",
        hex::encode(&recipient[..8])
    );
    println!("Randomness: {:?}\n", hex::encode(&randomness[..8]));

    // Create deposit instruction
    println!("Creating deposit instruction...");
    let ix = create_deposit_instruction(
        &program_id,
        &depositor.pubkey(),
        &bridge_vault,
        deposit_amount,
        recipient,
        randomness,
    )?;
    println!("Instruction created\n");

    // Get recent blockhash
    println!("Getting recent blockhash...");
    let blockhash = client.get_latest_blockhash()?;

    // Create and sign transaction
    println!("Creating and signing transaction...");
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&depositor.pubkey()),
        &[&depositor],
        blockhash,
    );

    // Send transaction
    println!("Sending transaction...");
    let signature = client.send_and_confirm_transaction(&tx)?;

    println!("\n=== Deposit Successful! ===");
    println!("Signature: {}", signature);
    println!("\nView transaction:");
    println!("  solana confirm -v {}", signature);

    // Verify vault balance
    println!("\nChecking bridge vault balance...");
    let vault_balance = client.get_balance(&bridge_vault)?;
    println!("Bridge Vault Balance: {} SOL", vault_balance as f64 / 1e9);

    Ok(())
}
