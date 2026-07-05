//! Ceremony-redeploy registry migration tool.
//!
//! Calls the on-chain `reset_validator_registry` (upgrade-authority gated):
//! grows the registry PDA to the current stake-weighted layout (#329) and
//! rebuilds its counters from EXACTLY the co-signer validator wallets given in
//! `RESET_CO_SIGNERS` — the real settle set for the redeployed program. Stale
//! registrations are dropped by not being listed, so the on-chain quorum
//! denominator reflects only validators that actually co-sign. Run once, right
//! after the in-place program upgrade.
//!
//! Env:
//!   SOLANA_RPC_URL              devnet RPC
//!   SOLANA_PROGRAM_ID           8gPsR…TWrP
//!   BRIDGE_AUTHORITY_KEYPAIR_PATH  the program upgrade-authority keypair
//!   RESET_CO_SIGNERS            comma-separated validator wallet pubkeys
//!                               (each must already be registered + active)

use paraloom::bridge::solana::*;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Signer,
    transaction::Transaction,
};
use std::str::FromStr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("=== Reset Validator Registry (ceremony redeploy) ===\n");

    let rpc_url =
        std::env::var("SOLANA_RPC_URL").unwrap_or_else(|_| "http://localhost:8899".to_string());
    let program_id = Pubkey::from_str(&std::env::var("SOLANA_PROGRAM_ID")?)?;
    let authority_keypair_path = std::env::var("BRIDGE_AUTHORITY_KEYPAIR_PATH")?;
    let co_signers_raw = std::env::var("RESET_CO_SIGNERS")?;

    let co_signers: Vec<Pubkey> = co_signers_raw
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(Pubkey::from_str)
        .collect::<std::result::Result<_, _>>()?;
    if co_signers.is_empty() {
        return Err("RESET_CO_SIGNERS is empty — refusing to reset to zero validators".into());
    }

    let authority = load_keypair_from_file(&authority_keypair_path)?;
    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    let (registry_pda, _) = derive_validator_registry(&program_id);
    println!("Program:      {}", program_id);
    println!("Authority:    {}", authority.pubkey());
    println!("Registry PDA: {}", registry_pda);
    println!("Co-signers ({}):", co_signers.len());
    for (i, w) in co_signers.iter().enumerate() {
        let (pda, _) = derive_validator_account(&program_id, w);
        // Warn early if a listed co-signer is not actually registered on-chain.
        let exists = client.get_account(&pda).is_ok();
        println!(
            "  {}. {}  (validator PDA {}{})",
            i + 1,
            w,
            pda,
            if exists { "" } else { "  ⚠ NOT REGISTERED" }
        );
    }
    println!();

    let ix =
        create_reset_validator_registry_instruction(&program_id, &authority.pubkey(), &co_signers)?;
    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&authority.pubkey()),
        &[&authority],
        blockhash,
    );

    println!("Sending reset transaction...");
    let signature = client.send_and_confirm_transaction(&tx)?;

    println!("\n=== Registry reset ===");
    println!("Signature: {}", signature);
    println!("Verify:    solana confirm -v {}", signature);
    println!(
        "Expect active_validators = {} and total_active_stake = {} lamports.",
        co_signers.len(),
        co_signers.len() as u64 * 1_000_000_000
    );

    Ok(())
}
