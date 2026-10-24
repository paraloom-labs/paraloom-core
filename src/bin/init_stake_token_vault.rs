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
    account::Account, commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Signer,
    transaction::Transaction,
};
use std::str::FromStr;

fn validate_stake_mint_account(acc: &Account) -> Result<Pubkey, Box<dyn std::error::Error>> {
    if acc.owner != SPL_TOKEN_PROGRAM_ID && acc.owner != SPL_TOKEN_2022_PROGRAM_ID {
        return Err(format!(
            "stake_mint account owner {} is neither SPL Token nor Token-2022",
            acc.owner
        )
        .into());
    }
    if acc.data.is_empty() {
        return Err("stake_mint account has empty data (uninitialized mint)".into());
    }
    Ok(acc.owner)
}

fn is_stake_vault_initialized(acc: &Account, token_program: &Pubkey) -> bool {
    acc.owner == *token_program && !acc.data.is_empty()
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
    // Token or Token-2022); read and verify it rather than assume, so the vault's
    // `token::token_program` matches what `register_validator` will pass.
    let mint_acc = client.get_account(&stake_mint)?;
    let token_program = validate_stake_mint_account(&mint_acc)?;

    let (vault, _) = derive_stake_token_vault(&program_id);

    println!("=== init stake token vault ===");
    println!("Program:       {program_id}");
    println!("Authority:     {}", authority.pubkey());
    println!("Stake mint:    {stake_mint}");
    println!("Token program: {token_program}");
    println!("Vault PDA:     {vault}");

    if let Ok(acc) = client.get_account(&vault) {
        if is_stake_vault_initialized(&acc, &token_program) {
            println!("\nVault already exists — nothing to do.");
            return Ok(());
        }
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stake_mint_must_be_owned_by_spl_token_or_token_2022() {
        let bad_owner = Account {
            lamports: 1_000_000,
            data: vec![1; 82],
            owner: Pubkey::default(),
            executable: false,
            rent_epoch: 0,
        };
        assert!(validate_stake_mint_account(&bad_owner).is_err());

        let empty_mint = Account {
            lamports: 1_000_000,
            data: vec![],
            owner: SPL_TOKEN_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        };
        assert!(validate_stake_mint_account(&empty_mint).is_err());

        let valid_mint = Account {
            lamports: 1_000_000,
            data: vec![1; 82],
            owner: SPL_TOKEN_2022_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        };
        assert_eq!(
            validate_stake_mint_account(&valid_mint).unwrap(),
            SPL_TOKEN_2022_PROGRAM_ID
        );
    }

    #[test]
    fn prefunded_vault_pda_is_not_treated_as_initialized() {
        let squatted = Account {
            lamports: 1,
            data: vec![],
            owner: Pubkey::default(),
            executable: false,
            rent_epoch: 0,
        };
        assert!(!is_stake_vault_initialized(&squatted, &SPL_TOKEN_PROGRAM_ID));

        let initialized = Account {
            lamports: 2_039_280,
            data: vec![1; 165],
            owner: SPL_TOKEN_PROGRAM_ID,
            executable: false,
            rent_epoch: 0,
        };
        assert!(is_stake_vault_initialized(&initialized, &SPL_TOKEN_PROGRAM_ID));
    }
}
