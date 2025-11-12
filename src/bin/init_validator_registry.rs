use paraloom::bridge::solana::*;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::Signer,
    transaction::Transaction,
};
use std::str::FromStr;

const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("=== Initializing Validator Registry on Devnet ===\n");

    let rpc_url =
        std::env::var("SOLANA_RPC_URL").unwrap_or_else(|_| "http://localhost:8899".to_string());
    let program_id_str = std::env::var("SOLANA_PROGRAM_ID")?;
    let authority_keypair_path = std::env::var("BRIDGE_AUTHORITY_KEYPAIR_PATH")?;

    println!("RPC URL: {}", rpc_url);
    println!("Program ID: {}", program_id_str);
    println!("Authority Keypair: {}\n", authority_keypair_path);

    let program_id = Pubkey::from_str(&program_id_str)?;

    println!("Loading authority keypair...");
    let authority = load_keypair_from_file(&authority_keypair_path)?;
    println!("Authority Address: {}\n", authority.pubkey());

    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    let balance = client.get_balance(&authority.pubkey())?;
    println!("Authority Balance: {} SOL\n", balance as f64 / 1e9);

    let (validator_registry_pda, _bump) =
        Pubkey::find_program_address(&[b"validator_registry"], &program_id);

    println!("Validator Registry PDA: {}\n", validator_registry_pda);

    let account_info = client.get_account(&validator_registry_pda);
    if account_info.is_ok() {
        println!("Validator registry already initialized!");
        return Ok(());
    }

    let discriminator: [u8; 8] = [168, 49, 128, 236, 25, 7, 168, 85];

    let instruction_data = discriminator.to_vec();
    let system_program_id = Pubkey::from_str(SYSTEM_PROGRAM_ID).unwrap();

    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(validator_registry_pda, false),
            AccountMeta::new(authority.pubkey(), true),
            AccountMeta::new_readonly(system_program_id, false),
        ],
        data: instruction_data,
    };

    println!("Getting recent blockhash...");
    let blockhash = client.get_latest_blockhash()?;

    println!("Creating and signing transaction...");
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&authority.pubkey()),
        &[&authority],
        blockhash,
    );

    println!("Sending transaction...");
    let signature = client.send_and_confirm_transaction(&tx)?;

    println!("\n=== Validator Registry Initialized Successfully! ===");
    println!("Signature: {}", signature);
    println!("Registry PDA: {}", validator_registry_pda);
    println!("\nView transaction:");
    println!("  solana confirm -v {}", signature);

    Ok(())
}
