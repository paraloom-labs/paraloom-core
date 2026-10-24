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
    account::Account, commitment_config::CommitmentConfig, native_token::LAMPORTS_PER_SOL,
    pubkey::Pubkey, signature::Signer, transaction::Transaction,
};
use std::str::FromStr;

/// Anchor discriminator for `ValidatorRegistry`: `sha256("account:ValidatorRegistry")[..8]`.
const VALIDATOR_REGISTRY_DISCRIMINATOR: [u8; 8] = [168, 113, 195, 186, 62, 121, 163, 230];

fn parse_validator_registry(
    acc: &Account,
    program_id: &Pubkey,
) -> Result<(u64, Pubkey, u64), Box<dyn std::error::Error>> {
    if acc.owner != *program_id {
        return Err(format!(
            "Validator registry owner mismatch: expected {}, got {}",
            program_id, acc.owner
        )
        .into());
    }
    let registry_data = &acc.data;
    if registry_data.len() < 112 {
        return Err(
            "Validator registry data too short (< 112 bytes); predates dual-stake layout".into(),
        );
    }
    if registry_data[..8] != VALIDATOR_REGISTRY_DISCRIMINATOR {
        return Err("Validator registry discriminator mismatch".into());
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

fn validate_stake_amounts(
    stake_amount: u64,
    token_stake_amount: u64,
    reg_min_stake: u64,
    reg_min_token_stake: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let required_sol = reg_min_stake.max(LAMPORTS_PER_SOL);
    if stake_amount < required_sol {
        return Err(format!(
            "STAKE_AMOUNT ({stake_amount} lamports) is below minimum required stake ({required_sol} lamports)"
        )
        .into());
    }
    if token_stake_amount < reg_min_token_stake {
        return Err(format!(
            "TOKEN_STAKE_AMOUNT ({token_stake_amount}) is below registry min_token_stake ({reg_min_token_stake})"
        )
        .into());
    }
    Ok(())
}

fn validate_token_program_owner(owner: &Pubkey) -> Result<Pubkey, Box<dyn std::error::Error>> {
    if *owner != SPL_TOKEN_PROGRAM_ID && *owner != SPL_TOKEN_2022_PROGRAM_ID {
        return Err(format!(
            "stake_mint account owner {} is neither SPL Token nor Token-2022",
            owner
        )
        .into());
    }
    Ok(*owner)
}

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
    let registry_acc = client.get_account(&validator_registry_pda)?;
    let (reg_min_stake, stake_mint, reg_min_token_stake) =
        parse_validator_registry(&registry_acc, &program_id)?;

    let stake_amount = match std::env::var("STAKE_AMOUNT") {
        Ok(val) => val.parse::<u64>()?,
        Err(_) => reg_min_stake.max(LAMPORTS_PER_SOL),
    };

    let token_stake_amount = match std::env::var("TOKEN_STAKE_AMOUNT") {
        Ok(val) => val.parse::<u64>()?,
        Err(_) => reg_min_token_stake,
    };

    validate_stake_amounts(
        stake_amount,
        token_stake_amount,
        reg_min_stake,
        reg_min_token_stake,
    )?;

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

    let mint_acc = client.get_account(&stake_mint)?;
    let token_program = validate_token_program_owner(&mint_acc.owner)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_registry_account(
        program_id: Pubkey,
        min_stake: u64,
        stake_mint: Pubkey,
        min_token_stake: u64,
    ) -> Account {
        let mut data = vec![0u8; 112];
        data[..8].copy_from_slice(&VALIDATOR_REGISTRY_DISCRIMINATOR);
        data[56..64].copy_from_slice(&min_stake.to_le_bytes());
        data[72..104].copy_from_slice(stake_mint.as_ref());
        data[104..112].copy_from_slice(&min_token_stake.to_le_bytes());
        Account {
            lamports: 2_000_000,
            data,
            owner: program_id,
            executable: false,
            rent_epoch: 0,
        }
    }

    #[test]
    fn parse_validator_registry_validates_owner_and_discriminator() {
        let program_id = Pubkey::new_unique();
        let mint = Pubkey::new_unique();
        let acc = valid_registry_account(program_id, 2_000_000_000, mint, 500_000);
        let (min_stake, parsed_mint, min_token) =
            parse_validator_registry(&acc, &program_id).unwrap();
        assert_eq!(min_stake, 2_000_000_000);
        assert_eq!(parsed_mint, mint);
        assert_eq!(min_token, 500_000);

        let mut wrong_owner = acc.clone();
        wrong_owner.owner = Pubkey::default();
        assert!(parse_validator_registry(&wrong_owner, &program_id).is_err());

        let mut wrong_disc = acc;
        wrong_disc.data[0] ^= 0xFF;
        assert!(parse_validator_registry(&wrong_disc, &program_id).is_err());
    }

    #[test]
    fn validate_stake_amounts_rejects_under_minimum_stakes() {
        assert!(validate_stake_amounts(2_000_000_000, 1_000, 2_000_000_000, 1_000).is_ok());
        assert!(validate_stake_amounts(999_999_999, 1_000, 500_000_000, 1_000).is_err());
        assert!(validate_stake_amounts(1_500_000_000, 1_000, 2_000_000_000, 1_000).is_err());
        assert!(validate_stake_amounts(2_000_000_000, 999, 2_000_000_000, 1_000).is_err());
    }

    #[test]
    fn validate_token_program_owner_accepts_only_token_programs() {
        assert!(validate_token_program_owner(&SPL_TOKEN_PROGRAM_ID).is_ok());
        assert!(validate_token_program_owner(&SPL_TOKEN_2022_PROGRAM_ID).is_ok());
        assert!(validate_token_program_owner(&Pubkey::default()).is_err());
    }
}
