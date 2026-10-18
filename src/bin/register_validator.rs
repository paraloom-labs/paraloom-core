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
//!   TOKEN_STAKE_AMOUNT             (optional: token stake amount, default: registry min_token_stake)
//!   VALIDATOR_TOKEN_ACCOUNT        (optional: override validator ATA, default: derived ATA)

use paraloom::bridge::solana::*;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig, native_token::LAMPORTS_PER_SOL, pubkey::Pubkey,
    signature::Signer, transaction::Transaction,
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
    let (reg_min_stake, stake_mint, reg_min_token_stake) =
        parse_validator_registry_config(&registry_data)?;

    let min_sol_stake = reg_min_stake.max(LAMPORTS_PER_SOL);
    let stake_amount = match std::env::var("STAKE_AMOUNT") {
        Ok(val) => {
            let parsed = val.parse::<u64>()?;
            if parsed < min_sol_stake {
                return Err(format!(
                    "STAKE_AMOUNT ({parsed} lamports) is below registry minimum stake ({min_sol_stake} lamports)"
                )
                .into());
            }
            parsed
        }
        Err(_) => min_sol_stake,
    };

    let token_stake_amount = match std::env::var("TOKEN_STAKE_AMOUNT") {
        Ok(val) => {
            let parsed = val.parse::<u64>()?;
            if parsed < reg_min_token_stake {
                return Err(format!(
                    "TOKEN_STAKE_AMOUNT ({parsed}) is below registry min_token_stake ({reg_min_token_stake})"
                )
                .into());
            }
            parsed
        }
        Err(_) => reg_min_token_stake,
    };

    println!("Stake Mint: {}", stake_mint);
    println!(
        "SOL Stake Amount: {} SOL ({} lamports)",
        stake_amount as f64 / 1e9,
        stake_amount
    );
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

/// `sha256("account:ValidatorRegistry")[..8]` — the Anchor discriminator every
/// on-chain `ValidatorRegistry` carries in its first 8 bytes.
const VALIDATOR_REGISTRY_DISCRIMINATOR: [u8; 8] = [135, 198, 225, 159, 60, 129, 98, 43];

/// Parse `(minimum_stake, stake_mint, min_token_stake)` from raw
/// `ValidatorRegistry` account data after verifying its 8-byte Anchor
/// discriminator and 112-byte dual-stake layout length.
fn parse_validator_registry_config(
    registry_data: &[u8],
) -> Result<(u64, Pubkey, u64), Box<dyn std::error::Error>> {
    if registry_data.len() < 112 {
        return Err(
            "Validator registry data too short (< 112 bytes); predates dual-stake layout".into(),
        );
    }
    if registry_data[0..8] != VALIDATOR_REGISTRY_DISCRIMINATOR {
        return Err("Account discriminator mismatch: not a ValidatorRegistry account".into());
    }
    let reg_min_stake = u64::from_le_bytes(
        registry_data[56..64]
            .try_into()
            .map_err(|_| "invalid minimum_stake slice")?,
    );
    let stake_mint = Pubkey::new_from_array(
        registry_data[72..104]
            .try_into()
            .map_err(|_| "invalid stake_mint slice")?,
    );
    let reg_min_token_stake = u64::from_le_bytes(
        registry_data[104..112]
            .try_into()
            .map_err(|_| "invalid min_token_stake slice")?,
    );
    Ok((reg_min_stake, stake_mint, reg_min_token_stake))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_registry_config_validates_discriminator_and_extracts_fields() {
        let mut data = vec![0u8; 112];
        data[0..8].copy_from_slice(&VALIDATOR_REGISTRY_DISCRIMINATOR);
        let expected_min_stake = 2_500_000_000u64;
        let expected_mint = Pubkey::new_unique();
        let expected_min_token = 1_000_000_000_000u64;
        data[56..64].copy_from_slice(&expected_min_stake.to_le_bytes());
        data[72..104].copy_from_slice(expected_mint.as_ref());
        data[104..112].copy_from_slice(&expected_min_token.to_le_bytes());

        let (min_stake, mint, min_token) =
            parse_validator_registry_config(&data).expect("valid registry");
        assert_eq!(min_stake, expected_min_stake);
        assert_eq!(mint, expected_mint);
        assert_eq!(min_token, expected_min_token);

        let mut bad_disc = data.clone();
        bad_disc[0] ^= 0xFF;
        assert!(
            parse_validator_registry_config(&bad_disc).is_err(),
            "wrong discriminator must be rejected"
        );
        assert!(
            parse_validator_registry_config(&data[..111]).is_err(),
            "short registry data must be rejected"
        );
    }
}
