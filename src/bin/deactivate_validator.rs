//! Deactivate an inactive or flapping validator on-chain.
//!
//! Cold-authority-gated: signed by `validator_registry.authority`.
//! Flips validator PDA to inactive and drops its stake from registry counters,
//! preventing orphaned validator accounts from participating in settlement quorums.
//!
//! Env:
//!   SOLANA_RPC_URL                 (default: devnet)
//!   SOLANA_PROGRAM_ID              the deployed bridge program id
//!   BRIDGE_AUTHORITY_KEYPAIR_PATH  the cold registry authority (signer)
//!   VALIDATOR_PUBKEY               the validator wallet pubkey to deactivate

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

    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    let (validator_pda, _) = derive_validator_account(&program_id, &validator);
    let (registry_pda, _) = derive_validator_registry(&program_id);

    println!("=== deactivate validator ===");
    println!("Program:          {program_id}");
    println!("Authority signer: {}", authority.pubkey());
    println!("Target validator: {validator}");
    println!("Validator PDA:    {validator_pda}");
    println!("Registry PDA:     {registry_pda}");

    let ix = create_deactivate_validator_instruction(
        &program_id,
        &authority.pubkey(),
        &validator,
    )?;

    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&authority.pubkey()),
        &[&authority],
        blockhash,
    );

    println!("\nSending deactivate_validator transaction...");
    let sig = client.send_and_confirm_transaction(&tx)?;
    println!("Deactivated successfully. Signature: {sig}");

    Ok(())
}
