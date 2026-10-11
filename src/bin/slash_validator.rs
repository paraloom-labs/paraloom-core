//! Slash a misbehaving or equivocating validator on-chain.
//!
//! Cold-authority-gated: signed by `validator_registry.authority`.
//! Reduces validator active or unbonding stake by `slash_percentage`,
//! increments `times_slashed`, routes slashed lamports to `slashed_funds_vault`,
//! and burns proportional dual-stake tokens from `stake_token_vault`.
//!
//! Env:
//!   SOLANA_RPC_URL                 (default: devnet)
//!   SOLANA_PROGRAM_ID              the deployed bridge program id
//!   BRIDGE_AUTHORITY_KEYPAIR_PATH  the cold registry authority (signer)
//!   VALIDATOR_PUBKEY               the validator wallet pubkey to slash
//!   SLASH_PERCENTAGE               1..=100 (e.g. 50 or 100)
//!   STAKE_MINT                     (optional: read from validator_registry if omitted)

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
    let validator = Pubkey::from_str(&std::env::var("VALIDATOR_PUBKEY")?)?;
    let slash_percentage: u8 = std::env::var("SLASH_PERCENTAGE")?.parse()?;

    if slash_percentage == 0 || slash_percentage > 100 {
        return Err(format!("SLASH_PERCENTAGE must be 1..=100, got {slash_percentage}").into());
    }

    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    let (registry_pda, _) = derive_validator_registry(&program_id);
    let (validator_pda, _) = derive_validator_account(&program_id, &validator);
    let (slashed_funds_vault, _) = derive_slashed_funds_vault(&program_id);

    // Resolve stake_mint from env or read directly from registry account data (offset 72..104)
    let stake_mint = if let Ok(mint_str) = std::env::var("STAKE_MINT") {
        Pubkey::from_str(&mint_str)?
    } else {
        let registry_account = client.get_account(&registry_pda)?;
        if registry_account.data.len() < 104 {
            return Err("Registry account data is too short to contain stake_mint".into());
        }
        let mint_bytes: [u8; 32] = registry_account.data[72..104].try_into()?;
        Pubkey::new_from_array(mint_bytes)
    };

    let token_program = client.get_account(&stake_mint)?.owner;

    println!("=== slash validator ===");
    println!("Program:             {program_id}");
    println!("Authority signer:    {}", authority.pubkey());
    println!("Target validator:    {validator}");
    println!("Validator PDA:       {validator_pda}");
    println!("Slashed vault PDA:   {slashed_funds_vault}");
    println!("Stake mint:          {stake_mint}");
    println!("Token program:       {token_program}");
    println!("Slash percentage:    {slash_percentage}%");

    let ix = create_slash_validator_instruction(
        &program_id,
        &authority.pubkey(),
        &validator,
        &stake_mint,
        &token_program,
        slash_percentage,
    )?;

    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&authority.pubkey()),
        &[&authority],
        blockhash,
    );

    println!("\nSending slash_validator transaction...");
    let sig = client.send_and_confirm_transaction(&tx)?;
    println!("Slashed successfully. Signature: {sig}");

    Ok(())
}
