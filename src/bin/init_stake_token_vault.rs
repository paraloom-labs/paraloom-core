//! Create the shared dual-stake `stake_token_vault` for a registry that predates
//! the dual-stake fields.
//!
//! `initialize_validator_registry` creates the vault inline, but a registry
//! initialized by the pre-dual-stake program has no vault and its PDA already
//! exists, so that instruction can never run again. This bin calls the
//! `init_stake_token_vault` migration instruction (upgrade-authority-gated) to
//! create the vault once, keyed to the same mint `reset_validator_registry`
//! pins into the registry. Run it once on the ceremony-key redeploy, before any
//! dual-stake `register_validator`.
//!
//! Env:
//!   SOLANA_RPC_URL                 (default: devnet)
//!   SOLANA_PROGRAM_ID              the deployed bridge program id
//!   BRIDGE_AUTHORITY_KEYPAIR_PATH  the program's upgrade authority (signer)
//!   STAKE_MINT                     the dual-stake token mint to key the vault to

use paraloom::bridge::solana::*;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Signer,
    transaction::Transaction,
};
use std::str::FromStr;

// ValidatorRegistry layout (see programs/paraloom/src/lib.rs):
//   [0..8]   discriminator
//   [8..40]  authority (Pubkey)
//   [40..48] total_validators (u64)
//   [48..56] active_validators (u64)
//   [56..64] minimum_stake (u64)
//   [64..72] total_active_stake (u64)
//   [72..104] stake_mint (Pubkey)  <- the pinned dual-stake mint
const REGISTRY_STAKE_MINT_OFFSET: usize = 72;
const REGISTRY_STAKE_MINT_LEN: usize = 32;

/// Defensive pre-flight: refuse to initialize the singleton vault when the
/// registry already pins a different `stake_mint`. A mismatch would permanently
/// brick `register_validator` (the vault's immutable mint would not agree with
/// `registry.stake_mint`).
fn require_registry_matches_mint(registry_data: &[u8], stake_mint: Pubkey) -> Result<(), Box<dyn std::error::Error>> {
    if registry_data.len() < REGISTRY_STAKE_MINT_OFFSET + REGISTRY_STAKE_MINT_LEN {
        return Err(format!(
            "validator_registry account too short ({} bytes), cannot read stake_mint",
            registry_data.len()
        )
        .into());
    }
    let on_chain_mint = Pubkey::try_from(&registry_data
        [REGISTRY_STAKE_MINT_OFFSET..REGISTRY_STAKE_MINT_OFFSET + REGISTRY_STAKE_MINT_LEN])?;
    if on_chain_mint != Pubkey::default() && on_chain_mint != stake_mint {
        return Err(format!(
            "STAKE_MINT {stake_mint} does not match validator_registry pinned stake_mint {on_chain_mint}; \
             refusing to initialize the singleton vault"
        )
        .into());
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let rpc_url = std::env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "https://api.devnet.solana.com".to_string());
    let program_id = Pubkey::from_str(&std::env::var("SOLANA_PROGRAM_ID")?)?;
    let authority = load_keypair_from_file(&std::env::var("BRIDGE_AUTHORITY_KEYPAIR_PATH")?)?;
    let stake_mint = Pubkey::from_str(&std::env::var("STAKE_MINT")?)?;

    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    // The vault's token program must be the one that owns the mint (classic SPL
    // Token or Token-2022); read it rather than assume, so the vault's
    // `token::token_program` matches what `register_validator` will pass.
    let token_program = client.get_account(&stake_mint)?.owner;

    let (vault, _) = derive_stake_token_vault(&program_id);

    println!("=== init stake token vault ===");
    println!("Program:       {program_id}");
    println!("Authority:     {}", authority.pubkey());
    println!("Stake mint:    {stake_mint}");
    println!("Token program: {token_program}");
    println!("Vault PDA:     {vault}");

    if client.get_account(&vault).is_ok() {
        println!("\nVault already exists — nothing to do.");
        return Ok(());
    }

    // Pre-flight: bind the stake mint to the registry's pinned stake_mint so a
    // mismatched STAKE_MINT cannot permanently brick the singleton vault.
    let registry_pda = Pubkey::find_program_address(&[b"validator_registry"], &program_id).0;
    let registry_acct = client.get_account(&registry_pda)?;
    let registry_data = registry_acct.data;
    require_registry_matches_mint(&registry_data, stake_mint)?;

    let ix = create_init_stake_token_vault_instruction(
        &program_id,
        &authority.pubkey(),
        &stake_mint,
        &token_program,
    )?;
    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&authority.pubkey()),
        &[&authority],
        blockhash,
    );

    println!("\nSending init_stake_token_vault...");
    let sig = client.send_and_confirm_transaction(&tx)?;
    println!("Vault created. Signature: {sig}");

    Ok(())
}
