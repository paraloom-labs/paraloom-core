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
//!   RESET_EXPECTED_ACTIVE_VALIDATORS  optional: the active-validator count the
//!                               on-chain guard checks the rebuild against.
//!                               Source it independently of RESET_CO_SIGNERS
//!                               (defaults to the co-signer count with a warning)

use paraloom::bridge::solana::*;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Signer,
    transaction::Transaction,
};
use std::collections::HashSet;
use std::str::FromStr;

const VALIDATOR_DISC: [u8; 8] = [32, 144, 229, 203, 9, 154, 158, 255];
const VALIDATOR_REGISTRY_DISC: [u8; 8] = [125, 198, 232, 196, 68, 122, 84, 11];
const VALIDATOR_LEN: usize = 145;
const REGISTRY_LEN: usize = 112;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("=== Reset Validator Registry (ceremony redeploy) ===\n");

    let rpc_url =
        std::env::var("SOLANA_RPC_URL").unwrap_or_else(|_| "http://localhost:8899".to_string());
    let program_id = Pubkey::from_str(&std::env::var("SOLANA_PROGRAM_ID")?)?;
    let authority_keypair_path = std::env::var("BRIDGE_AUTHORITY_KEYPAIR_PATH")?;
    let co_signers_raw = std::env::var("RESET_CO_SIGNERS")?;
    // The dual-stake mint re-pinned into the registry on reset (predates the grown
    // layout, so supplied explicitly). Wrong value bricks dual-stake registration.
    let stake_mint = Pubkey::from_str(&std::env::var("RESET_STAKE_MINT").map_err(|_| {
        "RESET_STAKE_MINT is required (the dual-stake token mint to pin into the registry)"
    })?)?;
    if stake_mint == Pubkey::default() {
        return Err("RESET_STAKE_MINT must not be the default all-zero pubkey".into());
    }

    let co_signers: Vec<Pubkey> = co_signers_raw
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(Pubkey::from_str)
        .collect::<std::result::Result<_, _>>()?;
    if co_signers.is_empty() {
        return Err("RESET_CO_SIGNERS is empty — refusing to reset to zero validators".into());
    }
    let mut seen_wallets = HashSet::with_capacity(co_signers.len());
    for w in &co_signers {
        if !seen_wallets.insert(*w) {
            return Err(format!("duplicate validator wallet in RESET_CO_SIGNERS: {w}").into());
        }
    }

    // The count the on-chain guard checks the rebuilt registry against. Set
    // RESET_EXPECTED_ACTIVE_VALIDATORS from an INDEPENDENT source (your own
    // roster / monitoring), not by counting RESET_CO_SIGNERS — the guard only
    // catches a dropped co-signer if the expected count did not drop with it.
    // Defaulting to the co-signer count keeps the tool working but makes the
    // check tautological, so warn loudly.
    let expected_active_validators: u64 = match std::env::var("RESET_EXPECTED_ACTIVE_VALIDATORS") {
        Ok(s) => s.trim().parse()?,
        Err(_) => {
            println!(
                "⚠ RESET_EXPECTED_ACTIVE_VALIDATORS not set — defaulting to the {} \
                 co-signers listed. The omission guard is only meaningful when this \
                 count comes from an independent source.\n",
                co_signers.len()
            );
            co_signers.len() as u64
        }
    };
    if expected_active_validators != co_signers.len() as u64 {
        return Err(format!(
            "RESET_EXPECTED_ACTIVE_VALIDATORS ({expected_active_validators}) != listed co-signers ({})",
            co_signers.len()
        )
        .into());
    }

    let authority = load_keypair_from_file(&authority_keypair_path)?;
    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    // Confirm stake_mint exists on-chain before pinning it into the registry.
    client
        .get_account(&stake_mint)
        .map_err(|e| format!("failed to fetch RESET_STAKE_MINT account {stake_mint}: {e}"))?;

    let (registry_pda, _) = derive_validator_registry(&program_id);
    println!("Program:      {}", program_id);
    println!("Authority:    {}", authority.pubkey());
    println!("Registry PDA: {}", registry_pda);
    println!("Co-signers ({}):", co_signers.len());
    for (i, w) in co_signers.iter().enumerate() {
        let (pda, _) = derive_validator_account(&program_id, w);
        let acc = client.get_account(&pda).map_err(|e| {
            format!("co-signer {w} (PDA {pda}) is not registered on-chain: {e}")
        })?;
        if acc.owner != program_id {
            return Err(format!(
                "co-signer {w} PDA {pda} is owned by {}, expected program {program_id}",
                acc.owner
            )
            .into());
        }
        if acc.data.len() < VALIDATOR_LEN || acc.data[0..8] != VALIDATOR_DISC {
            return Err(format!(
                "co-signer {w} PDA {pda} is not a migrated ValidatorAccount (len {}, expected >= {VALIDATOR_LEN})",
                acc.data.len()
            )
            .into());
        }
        if acc.data[88] == 0 {
            return Err(format!(
                "co-signer {w} PDA {pda} is inactive (is_active == false); reset_validator_registry would abort"
            )
            .into());
        }
        println!("  {}. {}  (validator PDA {})", i + 1, w, pda);
    }
    println!();

    let ix = create_reset_validator_registry_instruction(
        &program_id,
        &authority.pubkey(),
        &co_signers,
        &stake_mint,
        expected_active_validators,
    )?;
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

    // Auto-verify the on-chain registry rather than only printing what to expect
    // (#742). Registry layout after the 8-byte discriminator: authority[8..40],
    // total_validators[40..48], active_validators[48..56], minimum_stake[56..64],
    // total_active_stake[64..72], stake_mint[72..104], min_token_stake[104..112].
    let data = client.get_account_data(&registry_pda)?;
    if data.len() < REGISTRY_LEN || data[0..8] != VALIDATOR_REGISTRY_DISC {
        return Err(format!(
            "registry account is unexpectedly short or invalid ({} bytes, need >= {REGISTRY_LEN})",
            data.len()
        )
        .into());
    }
    let active_validators = u64::from_le_bytes(data[48..56].try_into().unwrap());
    let total_active_stake = u64::from_le_bytes(data[64..72].try_into().unwrap());
    let pinned_mint = Pubkey::new_from_array(data[72..104].try_into().unwrap());
    println!(
        "On-chain: active_validators = {active_validators}, total_active_stake = {total_active_stake} lamports, stake_mint = {pinned_mint}."
    );
    if active_validators != expected_active_validators || pinned_mint != stake_mint {
        return Err(format!(
            "post-reset mismatch: on-chain active_validators = {active_validators} (expected {expected_active_validators}), stake_mint = {pinned_mint} (expected {stake_mint})."
        )
        .into());
    }
    println!("✓ active_validators and stake_mint match expected values.");

    Ok(())
}
