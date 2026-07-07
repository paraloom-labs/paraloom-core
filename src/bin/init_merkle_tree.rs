//! One-time creation of the v3 on-chain incremental Merkle tree (#350),
//! signed by the program upgrade authority (#204). Mirrors
//! `init-validator-registry`.
//!
//! ```sh
//! SOLANA_RPC_URL=https://api.devnet.solana.com \
//! SOLANA_PROGRAM_ID=8gPsRSm1CAw38mfzc1bcLMUXyFN7LnS8k6CV5hPUTWrP \
//! BRIDGE_AUTHORITY_KEYPAIR_PATH=~/.config/solana/paraloom-devnet.json \
//! cargo run --bin init-merkle-tree
//! ```

use paraloom::bridge::solana::*;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Signer,
    transaction::Transaction,
};
use std::str::FromStr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("=== Initializing the v3 Merkle Tree ===\n");

    let rpc_url =
        std::env::var("SOLANA_RPC_URL").unwrap_or_else(|_| "http://localhost:8899".to_string());
    let program_id_str = std::env::var("SOLANA_PROGRAM_ID")?;
    let authority_keypair_path = std::env::var("BRIDGE_AUTHORITY_KEYPAIR_PATH")?;

    println!("RPC URL: {}", rpc_url);
    println!("Program ID: {}", program_id_str);

    let program_id = Pubkey::from_str(&program_id_str)?;
    let authority = load_keypair_from_file(&authority_keypair_path)?;
    println!("Authority Address: {}\n", authority.pubkey());

    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());
    let balance = client.get_balance(&authority.pubkey())?;
    println!("Authority Balance: {} SOL\n", balance as f64 / 1e9);

    let (tree_pda, _bump) = Pubkey::find_program_address(&[b"merkle_tree"], &program_id);
    println!("Merkle Tree PDA: {}\n", tree_pda);

    if client.get_account(&tree_pda).is_ok() {
        println!("Merkle tree already initialized!");
        return Ok(());
    }

    // The library builder includes the #204 ProgramData upgrade-authority
    // account the on-chain `InitializeMerkleTree` requires.
    let ix = create_initialize_merkle_tree_instruction(&program_id, &authority.pubkey());

    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&authority.pubkey()),
        &[&authority],
        blockhash,
    );

    println!("Sending transaction...");
    let signature = client.send_and_confirm_transaction(&tx)?;

    println!("\n=== Merkle Tree Initialized Successfully! ===");
    println!("Signature: {}", signature);
    println!("Tree PDA: {}", tree_pda);
    println!("\nView transaction:");
    println!("  solana confirm -v {}", signature);

    Ok(())
}
