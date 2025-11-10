//! Test withdrawal flow on localnet

use paraloom::bridge::solana::*;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig, native_token::LAMPORTS_PER_SOL, pubkey::Pubkey,
    signature::Signer, transaction::Transaction,
};
use std::str::FromStr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("=== Testing Paraloom Withdrawal Flow ===\n");

    // Load config from environment
    let rpc_url =
        std::env::var("SOLANA_RPC_URL").unwrap_or_else(|_| "http://localhost:8899".to_string());
    let program_id_str = std::env::var("SOLANA_PROGRAM_ID")?;
    let keypair_path = std::env::var("BRIDGE_AUTHORITY_KEYPAIR_PATH")?;

    println!("RPC URL: {}", rpc_url);
    println!("Program ID: {}", program_id_str);
    println!("Authority Keypair: {}\n", keypair_path);

    // Parse program ID
    let program_id = Pubkey::from_str(&program_id_str)?;

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

    // Derive bridge vault PDA
    let (bridge_vault, vault_bump) = derive_bridge_vault(&program_id);
    println!("Bridge Vault PDA: {}", bridge_vault);
    println!("Vault Bump: {}\n", vault_bump);

    // Check vault balance before withdrawal
    let vault_balance_before = client.get_balance(&bridge_vault)?;
    println!(
        "Bridge Vault Balance (before): {} SOL\n",
        vault_balance_before as f64 / 1e9
    );

    if vault_balance_before < LAMPORTS_PER_SOL / 20 {
        return Err("Insufficient vault balance. Need at least 0.05 SOL in vault".into());
    }

    // Create a test recipient (different from authority)
    let recipient_keypair = solana_sdk::signature::Keypair::new();
    let recipient = recipient_keypair.pubkey().to_bytes();
    println!("Recipient Address: {}", recipient_keypair.pubkey());

    // Withdrawal parameters
    let withdrawal_amount = LAMPORTS_PER_SOL / 20; // 0.05 SOL
    let nullifier = [3u8; 32]; // Mock nullifier (should be unique per withdrawal)
    let proof = vec![4u8; 128]; // Mock zkSNARK proof (will be skipped in MVP)

    println!("Withdrawal Amount: {} SOL", withdrawal_amount as f64 / 1e9);
    println!("Nullifier: {:?}", hex::encode(&nullifier[..8]));
    println!("Proof length: {} bytes\n", proof.len());

    // Create withdraw instruction
    println!("Creating withdraw instruction...");
    let ix = create_withdraw_instruction(
        &program_id,
        &authority.pubkey(),
        &bridge_vault,
        recipient,
        nullifier,
        withdrawal_amount,
        proof,
    )?;
    println!("Instruction created\n");

    // Get recent blockhash
    println!("Getting recent blockhash...");
    let blockhash = client.get_latest_blockhash()?;

    // Create and sign transaction
    println!("Creating and signing transaction...");
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&authority.pubkey()),
        &[&authority],
        blockhash,
    );

    // Send transaction
    println!("Sending transaction...");
    let signature = client.send_and_confirm_transaction(&tx)?;

    println!("\n=== Withdrawal Successful! ===");
    println!("Signature: {}", signature);
    println!("\nView transaction:");
    println!("  solana confirm -v {}", signature);

    // Verify balances after withdrawal
    println!("\nVerifying balances...");
    let vault_balance_after = client.get_balance(&bridge_vault)?;
    let recipient_balance = client.get_balance(&recipient_keypair.pubkey())?;

    println!(
        "Bridge Vault Balance (after): {} SOL",
        vault_balance_after as f64 / 1e9
    );
    println!("Recipient Balance: {} SOL", recipient_balance as f64 / 1e9);
    println!(
        "\nWithdrawn: {} SOL",
        (vault_balance_before - vault_balance_after) as f64 / 1e9
    );

    Ok(())
}
