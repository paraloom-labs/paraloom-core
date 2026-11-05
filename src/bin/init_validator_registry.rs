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
    // The dual-stake mint pinned into the registry at creation (same
    // `STAKE_MINT` env convention as `init_stake_token_vault`). The on-chain
    // `InitializeValidatorRegistry` context creates the stake vault for
    // this mint, so there is no default: a missing/invalid value is a
    // hard error, not a silent fallback.
    let stake_mint_str = std::env::var("STAKE_MINT").map_err(|_| {
        "STAKE_MINT is required (the dual-stake token mint to pin into the registry)"
    })?;
    let stake_mint = Pubkey::from_str(&stake_mint_str)
        .map_err(|e| format!("STAKE_MINT is not a valid pubkey ({stake_mint_str}): {e}"))?;

    println!("RPC URL: {}", rpc_url);
    println!("Program ID: {}", program_id_str);
    println!("Authority Keypair: {}", authority_keypair_path);
    println!("Stake Mint: {}\n", stake_mint);

    let program_id = Pubkey::from_str(&program_id_str)?;

    println!("Loading authority keypair...");
    let authority = load_keypair_from_file(&authority_keypair_path)?;
    println!("Authority Address: {}\n", authority.pubkey());

    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    let balance = client.get_balance(&authority.pubkey())?;
    println!("Authority Balance: {} SOL\n", balance as f64 / 1e9);

    let (validator_registry_pda, _bump) =
        Pubkey::find_program_address(&[b"validator_registry"], &program_id);

    println!("Validator Registry PDA: {}\n", validator_registry_pda);

    let account_info = client.get_account(&validator_registry_pda);
    if account_info.is_ok() {
        println!("Validator registry already initialized!");
        return Ok(());
    }

    // The vault's token program must be the one that owns the mint (classic
    // SPL Token or Token-2022); read it rather than assume, so the
    // `token_program` account matches the mint — same resolution as
    // `init_stake_token_vault`.
    let token_program = client.get_account(&stake_mint)?.owner;
    println!("Token Program (mint owner): {}\n", token_program);

    // Use the library builder: it includes the #204 ProgramData
    // upgrade-authority account and all five dual-stake accounts the
    // on-chain `InitializeValidatorRegistry` context requires (9 total).
    // The previous 4-account form failed with AccountNotEnoughKeys (3005).
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
    println!("\nView transaction:");
    println!("  solana confirm -v {}", signature);

    Ok(())
}
