use ark_std::rand;
use paraloom::bridge::solana::*;
use paraloom::privacy::transaction::DepositTx;
use paraloom::privacy::types::ShieldedAddress;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig, native_token::LAMPORTS_PER_SOL, signature::Signer,
    transaction::Transaction,
};
use std::str::FromStr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("=== Privacy Deposit Flow ===\n");

    let rpc_url =
        std::env::var("SOLANA_RPC_URL").unwrap_or_else(|_| "http://localhost:8899".to_string());
    let program_id_str = std::env::var("SOLANA_PROGRAM_ID")?;
    let keypair_path = std::env::var("BRIDGE_AUTHORITY_KEYPAIR_PATH")?;

    println!("RPC URL: {}", rpc_url);
    println!("Program ID: {}", program_id_str);
    println!("Depositor Keypair: {}\n", keypair_path);

    let program_id = solana_sdk::pubkey::Pubkey::from_str(&program_id_str)?;

    println!("Loading depositor keypair...");
    let depositor = load_keypair_from_file(&keypair_path)?;
    println!("Depositor Address: {}\n", depositor.pubkey());

    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    let balance = client.get_balance(&depositor.pubkey())?;
    println!("Depositor Balance: {} SOL\n", balance as f64 / 1e9);

    if balance < LAMPORTS_PER_SOL {
        return Err("Insufficient balance. Need at least 1 SOL".into());
    }

    let (bridge_vault, vault_bump) = derive_bridge_vault(&program_id);
    println!("Bridge Vault PDA: {}", bridge_vault);
    println!("Vault Bump: {}\n", vault_bump);

    let deposit_amount = LAMPORTS_PER_SOL / 10;
    let fee = 1000;

    println!("=== Creating Privacy Deposit ===");
    println!("Amount: {} SOL", deposit_amount as f64 / 1e9);
    println!("Fee: {} lamports\n", fee);

    let mut rng = rand::thread_rng();
    let mut recipient_bytes = [0u8; 32];
    let mut randomness = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut recipient_bytes);
    rand::RngCore::fill_bytes(&mut rng, &mut randomness);

    let recipient = ShieldedAddress::from_bytes(recipient_bytes);

    let privacy_tx = DepositTx::new(
        depositor.pubkey().to_bytes().to_vec(),
        deposit_amount,
        recipient.clone(),
        randomness,
        fee,
    );

    println!("Privacy Transaction Created:");
    println!("  TX ID: {}", privacy_tx.tx_id);
    println!("  Recipient (shielded address): {}", recipient.to_hex());
    println!("  Commitment: {}", privacy_tx.output_commitment.to_hex());
    println!("  Note Amount: {} lamports", privacy_tx.output_note.amount);
    println!("  Randomness: {}\n", hex::encode(randomness));

    if !privacy_tx.verify() {
        return Err("Privacy transaction verification failed".into());
    }
    println!("Privacy transaction verified\n");

    println!("Creating on-chain deposit instruction...");
    let ix = create_deposit_instruction(
        &program_id,
        &depositor.pubkey(),
        &bridge_vault,
        deposit_amount,
        recipient_bytes,
        randomness,
    )?;

    println!("Getting recent blockhash...");
    let blockhash = client.get_latest_blockhash()?;

    println!("Creating and signing transaction...");
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&depositor.pubkey()),
        &[&depositor],
        blockhash,
    );

    println!("Sending transaction...");
    let signature = client.send_and_confirm_transaction(&tx)?;

    println!("\n=== Privacy Deposit Successful! ===");
    println!("Signature: {}", signature);
    println!("\nPrivacy Details:");
    println!("  Shielded Address: {}", recipient.to_hex());
    println!("  Commitment: {}", privacy_tx.output_commitment.to_hex());
    println!(
        "  Amount: {} SOL (hidden)",
        (deposit_amount - fee) as f64 / 1e9
    );
    println!("\nThe deposit is now private. The recipient address and amount");
    println!("are hidden on-chain, only the commitment is public.");
    println!("\nView transaction:");
    println!("  solana confirm -v {}", signature);

    let vault_balance = client.get_balance(&bridge_vault)?;
    println!("\nBridge Vault Balance: {} SOL", vault_balance as f64 / 1e9);

    println!("\n=== Save These Values for Withdrawal ===");
    println!("Recipient: {}", recipient.to_hex());
    println!("Randomness: {}", hex::encode(randomness));
    println!("Commitment: {}", privacy_tx.output_commitment.to_hex());
    println!("Amount: {} lamports", privacy_tx.output_note.amount);

    Ok(())
}
