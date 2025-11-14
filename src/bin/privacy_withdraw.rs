use paraloom::bridge::solana::*;
use paraloom::privacy::transaction::WithdrawTx;
use paraloom::privacy::types::{Note, Nullifier, ShieldedAddress};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Signer,
    transaction::Transaction,
};
use std::str::FromStr;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("=== Privacy Withdrawal Flow ===\n");

    let rpc_url =
        std::env::var("SOLANA_RPC_URL").unwrap_or_else(|_| "http://localhost:8899".to_string());
    let program_id_str = std::env::var("SOLANA_PROGRAM_ID")?;
    let authority_keypair_path = std::env::var("BRIDGE_AUTHORITY_KEYPAIR_PATH")?;

    let recipient_hex = std::env::var("WITHDRAWAL_RECIPIENT")
        .unwrap_or_else(|_| "8zayzfSnGHw6KgxYSLMDB2keGpMQ7yxGGdqHjckN6XvH".to_string());
    let shielded_address_hex = std::env::var("SHIELDED_ADDRESS")?;
    let randomness_hex = std::env::var("RANDOMNESS")?;
    let amount_str = std::env::var("AMOUNT")?;

    println!("RPC URL: {}", rpc_url);
    println!("Program ID: {}", program_id_str);
    println!("Authority Keypair: {}\n", authority_keypair_path);

    let program_id = Pubkey::from_str(&program_id_str)?;

    println!("Loading authority keypair...");
    let authority = load_keypair_from_file(&authority_keypair_path)?;
    println!("Authority Address: {}\n", authority.pubkey());

    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    let (bridge_vault, vault_bump) = derive_bridge_vault(&program_id);
    println!("Bridge Vault PDA: {}", bridge_vault);
    println!("Vault Bump: {}\n", vault_bump);

    let vault_balance = client.get_balance(&bridge_vault)?;
    println!("Vault Balance: {} SOL\n", vault_balance as f64 / 1e9);

    println!("=== Reconstructing Privacy Note ===");

    let shielded_address_bytes = hex::decode(&shielded_address_hex)?;
    let mut shielded_address = [0u8; 32];
    shielded_address.copy_from_slice(&shielded_address_bytes);

    let randomness_bytes = hex::decode(&randomness_hex)?;
    let mut randomness = [0u8; 32];
    randomness.copy_from_slice(&randomness_bytes);

    let amount: u64 = amount_str.parse()?;
    let fee = 500;

    let recipient_address = ShieldedAddress::from_bytes(shielded_address);
    let note = Note::new(recipient_address.clone(), amount, randomness);
    let commitment = note.commitment();

    println!("Shielded Address: {}", recipient_address.to_hex());
    println!("Note Amount: {} lamports", amount);
    println!("Commitment: {}\n", commitment.to_hex());

    println!("=== Generating Nullifier ===");

    let mut spending_key = [0u8; 32];
    spending_key.copy_from_slice(&randomness);

    let nullifier = Nullifier::derive(&commitment, &spending_key);
    println!("Nullifier: {}\n", nullifier.to_hex());

    println!("=== Creating Privacy Withdrawal ===");

    let recipient_pubkey = Pubkey::from_str(&recipient_hex)?;
    let (bridge_state, _) = derive_bridge_state(&program_id);

    let bridge_state_account = client.get_account(&bridge_state)?;
    let mut merkle_root = [0u8; 32];
    if bridge_state_account.data.len() >= 40 {
        merkle_root.copy_from_slice(&bridge_state_account.data[8..40]);
    }

    println!("Current Merkle Root: {}", hex::encode(merkle_root));
    println!("Withdrawal Recipient: {}", recipient_pubkey);
    println!("Withdrawal Amount: {} SOL\n", amount as f64 / 1e9);

    let privacy_tx = WithdrawTx::new(
        nullifier.clone(),
        amount,
        recipient_pubkey.to_bytes().to_vec(),
        merkle_root,
        fee,
    );

    println!("Privacy Withdrawal Created:");
    println!("  TX ID: {}", privacy_tx.tx_id);
    println!("  Nullifier: {}", nullifier.to_hex());
    println!("  Amount: {} lamports", amount);
    println!("  Recipient: {}", recipient_pubkey);

    if !privacy_tx.verify() {
        return Err("Privacy transaction verification failed".into());
    }
    println!("Privacy transaction verified\n");

    // Load zkSNARK proof
    println!("Loading zkSNARK proof...");
    let proof_path = std::env::var("WITHDRAWAL_PROOF_PATH")
        .unwrap_or_else(|_| "withdrawal_proof.bin".to_string());

    let proof = std::fs::read(&proof_path).map_err(|e| {
        format!(
            "Failed to read proof from {}: {}.\n\
             Please generate proof first using:\n\
             cargo run --bin generate_withdrawal_proof",
            proof_path, e
        )
    })?;

    println!("Proof loaded: {} bytes\n", proof.len());

    println!("Creating on-chain withdrawal instruction...");
    let ix = create_withdraw_instruction(
        &program_id,
        &authority.pubkey(),
        &bridge_vault,
        recipient_pubkey.to_bytes(),
        *nullifier.as_bytes(),
        amount,
        proof,
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

    println!("\n=== Privacy Withdrawal Successful! ===");
    println!("Signature: {}", signature);
    println!("\nPrivacy Details:");
    println!("  Nullifier: {}", nullifier.to_hex());
    println!("  Commitment: {}", commitment.to_hex());
    println!("  Amount: {} SOL (revealed)", amount as f64 / 1e9);
    println!("\nThe nullifier prevents double-spending this note.");
    println!("The link between deposit and withdrawal is broken.");
    println!("\nView transaction:");
    println!("  solana confirm -v {}", signature);

    let vault_balance_after = client.get_balance(&bridge_vault)?;
    println!(
        "\nVault Balance After: {} SOL",
        vault_balance_after as f64 / 1e9
    );

    Ok(())
}
