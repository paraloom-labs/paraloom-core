use paraloom::bridge::solana::*;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    native_token::LAMPORTS_PER_SOL,
    pubkey::Pubkey,
    signature::Signer,
    transaction::Transaction,
};
use std::str::FromStr;

const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("=== Registering Validator on Devnet ===\n");

    let rpc_url =
        std::env::var("SOLANA_RPC_URL").unwrap_or_else(|_| "http://localhost:8899".to_string());
    let program_id_str = std::env::var("SOLANA_PROGRAM_ID")?;
    let validator_keypair_path = std::env::var("VALIDATOR_KEYPAIR_PATH")?;

    println!("RPC URL: {}", rpc_url);
    println!("Program ID: {}", program_id_str);
    println!("Validator Keypair: {}\n", validator_keypair_path);

    let program_id = Pubkey::from_str(&program_id_str)?;

    println!("Loading validator keypair...");
    let validator = load_keypair_from_file(&validator_keypair_path)?;
    println!("Validator Address: {}\n", validator.pubkey());

    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    let balance = client.get_balance(&validator.pubkey())?;
    println!("Validator Balance: {} SOL\n", balance as f64 / 1e9);

    if balance < 2 * LAMPORTS_PER_SOL {
        return Err("Insufficient balance. Need at least 2 SOL".into());
    }

    let (validator_account_pda, _bump) =
        Pubkey::find_program_address(&[b"validator", validator.pubkey().as_ref()], &program_id);

    let (validator_registry_pda, _registry_bump) =
        Pubkey::find_program_address(&[b"validator_registry"], &program_id);

    println!("Validator Account PDA: {}", validator_account_pda);
    println!("Validator Registry PDA: {}\n", validator_registry_pda);

    let stake_amount = LAMPORTS_PER_SOL;
    println!("Stake Amount: {} SOL\n", stake_amount as f64 / 1e9);

    let discriminator: [u8; 8] = [118, 98, 251, 58, 81, 30, 13, 240];

    let mut instruction_data = discriminator.to_vec();
    instruction_data.extend_from_slice(&stake_amount.to_le_bytes());

    let system_program_id = Pubkey::from_str(SYSTEM_PROGRAM_ID).unwrap();

    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(validator_account_pda, false),
            AccountMeta::new(validator_registry_pda, false),
            AccountMeta::new(validator.pubkey(), true),
            AccountMeta::new_readonly(system_program_id, false),
        ],
        data: instruction_data,
    };

    println!("Getting recent blockhash...");
    let blockhash = client.get_latest_blockhash()?;

    println!("Creating and signing transaction...");
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&validator.pubkey()),
        &[&validator],
        blockhash,
    );

    println!("Sending transaction...");
    let signature = client.send_and_confirm_transaction(&tx)?;

    println!("\n=== Validator Registered Successfully! ===");
    println!("Signature: {}", signature);
    println!("Validator: {}", validator.pubkey());
    println!("Stake: {} SOL", stake_amount as f64 / 1e9);
    println!("\nView transaction:");
    println!("  solana confirm -v {}", signature);

    Ok(())
}
