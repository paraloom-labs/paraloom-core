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
use std::str::FromStr;

/// `sha256("account:ValidatorAccount")[..8]`.
const VALIDATOR_ACCOUNT_DISC: [u8; 8] = [32, 144, 229, 203, 9, 154, 158, 255];
const VALIDATOR_ACCOUNT_LEN: usize = 145;

/// `sha256("account:ValidatorRegistry")[..8]`.
const VALIDATOR_REGISTRY_DISC: [u8; 8] = [168, 113, 195, 186, 62, 121, 163, 230];
const VALIDATOR_REGISTRY_LEN: usize = 112;

fn parse_unique_co_signers(raw: &str) -> std::result::Result<Vec<Pubkey>, String> {
    let mut co_signers = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let pubkey = Pubkey::from_str(entry)
            .map_err(|e| format!("invalid co-signer pubkey '{entry}': {e}"))?;
        if !seen.insert(pubkey) {
            return Err(format!(
                "duplicate co-signer wallet {pubkey} in RESET_CO_SIGNERS — on-chain reset_validator_registry rejects duplicate remaining_accounts"
            ));
        }
        co_signers.push(pubkey);
    }
    if co_signers.is_empty() {
        return Err("RESET_CO_SIGNERS is empty — refusing to reset to zero validators".to_string());
    }
    Ok(co_signers)
}

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

    let co_signers = parse_unique_co_signers(&co_signers_raw)?;

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

    let authority = load_keypair_from_file(&authority_keypair_path)?;
    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    let (registry_pda, _) = derive_validator_registry(&program_id);
    println!("Program:      {}", program_id);
    println!("Authority:    {}", authority.pubkey());
    println!("Registry PDA: {}", registry_pda);
    println!("Co-signers ({}):", co_signers.len());
    let mut bad_co_signers = Vec::new();
    for (i, w) in co_signers.iter().enumerate() {
        let (pda, _) = derive_validator_account(&program_id, w);
        // Verify each listed co-signer PDA exists, is owned by the program, is
        // migrated to the 145-byte layout, and is active before sending.
        let status = match client.get_account(&pda) {
            Err(_) => {
                bad_co_signers.push(format!("{w} (PDA {pda} not found)"));
                "  ⚠ NOT REGISTERED"
            }
            Ok(acc) if acc.owner != program_id => {
                bad_co_signers.push(format!("{w} (PDA {pda} wrong owner {})", acc.owner));
                "  ⚠ WRONG OWNER"
            }
            Ok(acc)
                if acc.data.len() < VALIDATOR_ACCOUNT_LEN
                    || acc.data[0..8] != VALIDATOR_ACCOUNT_DISC =>
            {
                bad_co_signers.push(format!(
                    "{w} (PDA {pda} unmigrated or invalid: len={}, need >= {VALIDATOR_ACCOUNT_LEN})",
                    acc.data.len()
                ));
                "  ⚠ UNMIGRATED"
            }
            Ok(acc) if acc.data[88] != 1 => {
                bad_co_signers.push(format!("{w} (PDA {pda} is not active)"));
                "  ⚠ INACTIVE"
            }
            Ok(_) => "",
        };
        println!("  {}. {}  (validator PDA {}{})", i + 1, w, pda, status);
    }
    println!();
    if !bad_co_signers.is_empty() {
        return Err(format!(
            "refusing to reset registry with {} invalid co-signer PDA(s):\n  - {}",
            bad_co_signers.len(),
            bad_co_signers.join("\n  - ")
        )
        .into());
    }

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
    if data.len() < VALIDATOR_REGISTRY_LEN || data[0..8] != VALIDATOR_REGISTRY_DISC {
        return Err(format!(
            "registry account is unexpectedly short or invalid ({} bytes, need >= {VALIDATOR_REGISTRY_LEN})",
            data.len()
        )
        .into());
    }
    let active_validators = u64::from_le_bytes(data[48..56].try_into().unwrap());
    let total_active_stake = u64::from_le_bytes(data[64..72].try_into().unwrap());
    println!(
        "On-chain: active_validators = {active_validators}, total_active_stake = {total_active_stake} lamports."
    );
    if active_validators != expected_active_validators {
        return Err(format!(
            "post-reset mismatch: on-chain active_validators = {active_validators} but expected \
             {expected_active_validators}. The quorum denominator may be wrong — investigate before \
             relying on settlement."
        )
        .into());
    }
    println!("✓ active_validators matches the expected count.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_unique_co_signers_rejects_empty_and_duplicates() {
        let w1 = Pubkey::new_unique();
        let w2 = Pubkey::new_unique();

        assert!(parse_unique_co_signers(" , ").is_err());
        assert!(parse_unique_co_signers(&format!("{w1}, {w1}")).is_err());

        let parsed = parse_unique_co_signers(&format!(" {w1} , {w2} ")).expect("valid unique list");
        assert_eq!(parsed, vec![w1, w2]);
    }
}
