//! Initialize the ValidatorRegistry PDA and shared dual-stake `stake_token_vault`
//! on the Paraloom Solana bridge.
//!
//! Env:
//!   SOLANA_RPC_URL                 (default: http://localhost:8899)
//!   SOLANA_PROGRAM_ID              the deployed bridge program id
//!   BRIDGE_AUTHORITY_KEYPAIR_PATH  the program's upgrade authority (signer)
//!   STAKE_MINT                     the dual-stake token mint to pin into the registry

use paraloom::bridge::solana::*;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Signer,
    transaction::Transaction,
};
use std::str::FromStr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("=== Initializing Validator Registry on Devnet ===\n");

    let rpc_url =
        std::env::var("SOLANA_RPC_URL").unwrap_or_else(|_| "http://localhost:8899".to_string());
    let program_id_str = std::env::var("SOLANA_PROGRAM_ID")?;
    let authority_keypair_path = std::env::var("BRIDGE_AUTHORITY_KEYPAIR_PATH")?;
    let stake_mint_str = std::env::var("STAKE_MINT")?;

    println!("RPC URL: {}", rpc_url);
    println!("Program ID: {}", program_id_str);
    println!("Authority Keypair: {}", authority_keypair_path);
    println!("Stake Mint: {}\n", stake_mint_str);

    let program_id = Pubkey::from_str(&program_id_str)?;
    let stake_mint = Pubkey::from_str(&stake_mint_str)?;

    println!("Loading authority keypair...");
    let authority = load_keypair_from_file(&authority_keypair_path)?;
    println!("Authority Address: {}\n", authority.pubkey());

    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    let balance = client.get_balance(&authority.pubkey())?;
    println!("Authority Balance: {} SOL\n", balance as f64 / 1e9);

    let (validator_registry_pda, _bump) = derive_validator_registry(&program_id);
    let (stake_token_vault_pda, _) = derive_stake_token_vault(&program_id);

    println!("Validator Registry PDA: {}", validator_registry_pda);
    println!("Stake Token Vault PDA: {}\n", stake_token_vault_pda);

    let account_info = client.get_account(&validator_registry_pda);
    if account_info.is_ok() {
        println!("Validator registry already initialized!");
        return Ok(());
    }

    // The vault's token program must be the one that owns `stake_mint` (classic
    // SPL Token or Token-2022); read it on-chain so `token::token_program`
    // matches what `register_validator` will pass.
    let token_program = client.get_account(&stake_mint)?.owner;
    println!("Token Program: {}\n", token_program);

    // Use the library builder: it includes the dual-stake vault accounts and
    // the #204 ProgramData upgrade-authority account the on-chain
    // `InitializeValidatorRegistry` context requires.
    let ix = create_initialize_validator_registry_instruction(
        &program_id,
        &authority.pubkey(),
        &stake_mint,
        &token_program,
    )?;

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
    println!("Stake Token Vault PDA: {}", stake_token_vault_pda);
    println!("\nView transaction:");
    println!("  solana confirm -v {}", signature);

    Ok(())
}
