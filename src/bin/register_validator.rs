//! Register a validator on the Paraloom Solana bridge with dual stake.
//!
//! Replaces the obsolete pre-dual-stake 4-account / 8-byte instruction format
//! with the full 8-account dual-stake instruction (`create_register_validator_instruction`).
//!
//! Env:
//!   SOLANA_RPC_URL                 (default: http://localhost:8899)
//!   SOLANA_PROGRAM_ID              the deployed bridge program id
//!   VALIDATOR_KEYPAIR_PATH         path to the validator keypair json
//!   STAKE_AMOUNT                   (optional: SOL stake in lamports, default: registry minimum_stake)
//!   STAKE_MINT                     (optional: override stake mint pubkey, default: read from registry)
//!   TOKEN_STAKE_AMOUNT             (optional: token stake amount, default: registry min_token_stake)
//!   VALIDATOR_TOKEN_ACCOUNT        (optional: override validator ATA, default: derived ATA)

use paraloom::bridge::solana::*;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    native_token::LAMPORTS_PER_SOL,
    pubkey::Pubkey,
    signature::Signer,
    transaction::Transaction,
};
use std::str::FromStr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("=== Registering Validator on Paraloom ===\n");

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

    let (validator_account_pda, _) = derive_validator_account(&program_id, &validator.pubkey());
    let (validator_registry_pda, _) = derive_validator_registry(&program_id);

    println!("Validator Account PDA: {}", validator_account_pda);
    println!("Validator Registry PDA: {}", validator_registry_pda);

    // Read registry state to extract minimum_stake, stake_mint, and min_token_stake.
    let registry_data = client.get_account_data(&validator_registry_pda)?;
    if registry_data.len() < 112 {
        return Err("Validator registry data too short (< 112 bytes); predates dual-stake layout".into());
    }

    // Registry layout after the 8-byte discriminator:
    // authority [8..40]
    // total_validators [40..48]
    // active_validators [48..56]
    // minimum_stake [56..64]
    // total_active_stake [64..72]
    // stake_mint [72..104]
    // min_token_stake [104..112]
    let reg_min_stake = u64::from_le_bytes(
        registry_data[56..64]
            .try_into()
            .map_err(|_| "invalid minimum_stake slice")?,
    );
    let reg_stake_mint = Pubkey::new_from_array(
        registry_data[72..104]
            .try_into()
            .map_err(|_| "invalid stake_mint slice")?,
    );
    let reg_min_token_stake = u64::from_le_bytes(
        registry_data[104..112]
            .try_into()
            .map_err(|_| "invalid min_token_stake slice")?,
    );

    let stake_mint = match std::env::var("STAKE_MINT") {
        Ok(val) => Pubkey::from_str(&val)?,
        Err(_) => reg_stake_mint,
    };

    let stake_amount = match std::env::var("STAKE_AMOUNT") {
        Ok(val) => val.parse::<u64>()?,
        Err(_) => reg_min_stake.max(LAMPORTS_PER_SOL),
    };

    let token_stake_amount = match std::env::var("TOKEN_STAKE_AMOUNT") {
        Ok(val) => val.parse::<u64>()?,
        Err(_) => reg_min_token_stake,
    };

    println!("Stake Mint: {}", stake_mint);
    println!("SOL Stake Amount: {} SOL ({} lamports)", stake_amount as f64 / 1e9, stake_amount);
    println!("Token Stake Amount: {}\n", token_stake_amount);

    if balance < stake_amount.saturating_add(LAMPORTS_PER_SOL / 100) {
        return Err(format!(
            "Insufficient SOL balance. Have {} SOL, need at least {} SOL (stake + fee)",
            balance as f64 / 1e9,
            (stake_amount.saturating_add(LAMPORTS_PER_SOL / 100)) as f64 / 1e9
        )
        .into());
    }

    let token_program = client.get_account(&stake_mint)?.owner;
    let validator_token_account = match std::env::var("VALIDATOR_TOKEN_ACCOUNT") {
        Ok(val) => Pubkey::from_str(&val)?,
        Err(_) => derive_associated_token_address(&validator.pubkey(), &stake_mint, &token_program),
    };

    println!("Token Program: {}", token_program);
    println!("Validator Token Account: {}\n", validator_token_account);

    let ix = create_register_validator_instruction(
        &program_id,
        &validator.pubkey(),
        &stake_mint,
        &validator_token_account,
        &token_program,
        stake_amount,
        token_stake_amount,
    )?;

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
    println!("SOL Stake: {} SOL", stake_amount as f64 / 1e9);
    println!("Token Stake: {}", token_stake_amount);
    println!("\nView transaction:");
    println!("  solana confirm -v {}", signature);

    Ok(())
}
