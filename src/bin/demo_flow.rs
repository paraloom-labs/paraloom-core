//! End-to-end Alice → Bob privacy flow smoke test (#161).
//!
//! Single-binary orchestrator for the full deposit → proof → withdraw flow
//! against a deployed program on a fresh localnet. Mirrors the in-process
//! shape of `tests/validator_privacy_e2e.rs::test_deposit_transfer_withdraw_flow`
//! but submits real on-chain transactions through `create_deposit_instruction`
//! and `create_withdraw_instruction`.
//!
//! Scope: single-deposit local case (`merkle_path = []`,
//! `merkle_root = commitment`). Multi-deposit Merkle state requires a running
//! paraloom-node Merkle indexer — out of scope here, tracked separately.

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_std::rand as ark_rand;
use paraloom::bridge::solana::*;
use paraloom::privacy::circuits::{Groth16ProofSystem, WithdrawCircuit};
use paraloom::privacy::onchain_verifier::proof_to_onchain_bytes;
use paraloom::privacy::transaction::{DepositTx, WithdrawTx};
use paraloom::privacy::types::{Nullifier, ShieldedAddress};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    native_token::LAMPORTS_PER_SOL,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use std::{fs, path::Path, str::FromStr, time::Instant};

const PROVING_KEY_PATH: &str = "keys/withdraw_proving_v3.key";
const VERIFYING_KEY_PATH: &str = "keys/withdraw_verifying_v3.key";

fn header(s: &str) {
    println!("\n=== {} ===", s);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("=== Paraloom Privacy Demo Flow ===");
    println!("End-to-end Alice → Bob deposit + withdraw on localnet.");
    println!("Mirrors tests/validator_privacy_e2e.rs flow with real on-chain txs.");

    let rpc_url =
        std::env::var("SOLANA_RPC_URL").unwrap_or_else(|_| "http://localhost:8899".to_string());
    let program_id_str =
        std::env::var("SOLANA_PROGRAM_ID").map_err(|_| "SOLANA_PROGRAM_ID env var required")?;
    let authority_keypair_path = std::env::var("BRIDGE_AUTHORITY_KEYPAIR_PATH")
        .map_err(|_| "BRIDGE_AUTHORITY_KEYPAIR_PATH env var required")?;
    let deposit_amount: u64 = match std::env::var("DEPOSIT_AMOUNT_LAMPORTS") {
        Ok(s) => s.parse()?,
        Err(_) => LAMPORTS_PER_SOL,
    };
    let deposit_fee: u64 = 1_000;

    let program_id = solana_sdk::pubkey::Pubkey::from_str(&program_id_str)?;
    let authority = load_keypair_from_file(&authority_keypair_path)?;
    let client = RpcClient::new_with_commitment(rpc_url.clone(), CommitmentConfig::confirmed());

    header("Pre-flight checks");
    println!("RPC URL:           {}", rpc_url);
    println!("Program ID:        {}", program_id);
    println!("Authority:         {}", authority.pubkey());

    if !Path::new(PROVING_KEY_PATH).exists() {
        return Err(format!(
            "Proving key missing at {PROVING_KEY_PATH}. Run:\n  \
             cargo run --release --bin setup-withdrawal-ceremony"
        )
        .into());
    }

    let (bridge_state, _) = derive_bridge_state(&program_id);
    let bridge_state_account = client
        .get_account(&bridge_state)
        .map_err(|_| "Bridge state PDA not found. Run bridge-init first.".to_string())?;
    println!(
        "Bridge state PDA:  {} ({} bytes)",
        bridge_state,
        bridge_state_account.data.len()
    );

    let (bridge_vault, _) = derive_bridge_vault(&program_id);
    let vault_balance_initial = client.get_balance(&bridge_vault)?;
    println!(
        "Bridge vault PDA:  {} ({} SOL)",
        bridge_vault,
        vault_balance_initial as f64 / 1e9
    );

    header("Generating Alice (depositor) and Bob (recipient)");
    let alice = Keypair::new();
    let bob = Keypair::new();
    println!("Alice (deposit):   {}", alice.pubkey());
    println!("Bob (withdrawal):  {}", bob.pubkey());

    let airdrop_amount = deposit_amount + LAMPORTS_PER_SOL; // deposit + tx fees
    println!("\nAirdropping Alice {} SOL...", airdrop_amount as f64 / 1e9);
    let _airdrop_sig = client.request_airdrop(&alice.pubkey(), airdrop_amount)?;
    // `confirm_transaction` returns once the signature is known but the
    // balance may not yet reflect the credit on localnet — poll until it
    // does (or give up after ~10s).
    let mut alice_balance = 0u64;
    for _ in 0..20 {
        alice_balance = client.get_balance(&alice.pubkey())?;
        if alice_balance >= airdrop_amount {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    if alice_balance < airdrop_amount {
        return Err(format!(
            "Airdrop did not credit Alice within 10s (balance: {} lamports, expected >= {})",
            alice_balance, airdrop_amount
        )
        .into());
    }
    let bob_balance_before = client.get_balance(&bob.pubkey())?;
    println!("Alice balance:     {} SOL", alice_balance as f64 / 1e9);
    println!(
        "Bob balance:       {} SOL (before withdraw)",
        bob_balance_before as f64 / 1e9
    );

    header("Step 1: Alice → shielded deposit");

    let mut rng_std = ark_rand::thread_rng();
    let mut recipient_bytes = [0u8; 32];
    let mut randomness = [0u8; 32];
    ark_rand::RngCore::fill_bytes(&mut rng_std, &mut recipient_bytes);
    ark_rand::RngCore::fill_bytes(&mut rng_std, &mut randomness);

    let recipient = ShieldedAddress::from_bytes(recipient_bytes);
    let net_deposit = deposit_amount - deposit_fee;

    let deposit_tx_priv = DepositTx::new(
        alice.pubkey().to_bytes().to_vec(),
        deposit_amount,
        recipient.clone(),
        randomness,
        deposit_fee,
    );
    if !deposit_tx_priv.verify() {
        return Err("Off-chain deposit structure verification failed".into());
    }
    let commitment = deposit_tx_priv.output_commitment.clone();

    println!(
        "Deposit amount:    {} SOL ({} lamports)",
        deposit_amount as f64 / 1e9,
        deposit_amount
    );
    println!("Fee:               {} lamports", deposit_fee);
    println!("Net to vault:      {} lamports", net_deposit);
    println!("Shielded address:  {}", recipient.to_hex());
    println!("Randomness:        {}", hex::encode(randomness));
    println!("Commitment:        {}", commitment.to_hex());

    let ix_deposit = create_deposit_instruction(
        &program_id,
        &alice.pubkey(),
        &bridge_vault,
        deposit_amount,
        recipient_bytes,
        randomness,
    )?;
    let blockhash = client.get_latest_blockhash()?;
    let deposit_tx_signed = Transaction::new_signed_with_payer(
        &[ix_deposit],
        Some(&alice.pubkey()),
        &[&alice],
        blockhash,
    );
    let deposit_sig = client.send_and_confirm_transaction(&deposit_tx_signed)?;
    println!("Deposit tx:        {}", deposit_sig);

    let vault_after_deposit = client.get_balance(&bridge_vault)?;
    println!(
        "Vault balance:     {} SOL (after deposit, was {})",
        vault_after_deposit as f64 / 1e9,
        vault_balance_initial as f64 / 1e9
    );

    header("Step 2: Derive nullifier (off-chain)");
    let nullifier = Nullifier::derive(&commitment, &randomness);
    println!("Nullifier:         {}", nullifier.to_hex());
    println!("                   = poseidon_nullifier(commitment, randomness)");

    header("Step 3: Compute local Merkle root");
    // On-chain `deposit` (programs/paraloom/src/lib.rs:54) does NOT update
    // `BridgeState.merkle_root`; that's an L2-indexer responsibility, reached
    // via the separate `update_merkle_root` instruction. And on-chain `withdraw`
    // checks the proof only with `!proof.is_empty()` — actual Groth16
    // verification runs in the L2 validator consensus path. So we choose the
    // local single-deposit root unilaterally: `root = commitment, path = []`.
    let mut merkle_root_bytes = [0u8; 32];
    merkle_root_bytes.copy_from_slice(commitment.as_bytes());
    let merkle_path: Vec<([u8; 32], bool)> = Vec::new();
    println!("Merkle root:       {}", hex::encode(merkle_root_bytes));
    println!("Merkle path:       [] (single-deposit local case)");

    header("Step 4: Generate Groth16 withdrawal proof");
    let proving_key_bytes = fs::read(PROVING_KEY_PATH)?;
    let proving_key = ProvingKey::<Bn254>::deserialize_compressed(&proving_key_bytes[..])?;

    let mut nullifier_bytes_arr = [0u8; 32];
    nullifier_bytes_arr.copy_from_slice(nullifier.as_bytes());

    let circuit = WithdrawCircuit::with_witness(
        merkle_root_bytes,
        nullifier_bytes_arr,
        net_deposit,     // withdraw_amount
        net_deposit,     // input_value (whole note)
        randomness,      // input_randomness (matches commitment)
        recipient_bytes, // input_recipient (shielded address)
        randomness,      // secret == randomness (matches Nullifier::derive)
        merkle_path,
    );

    let proof_start = Instant::now();
    let mut rng = ark_rand::thread_rng();
    let proof = Groth16ProofSystem::prove::<WithdrawCircuit, _>(&proving_key, circuit, &mut rng)?;
    let proof_elapsed = proof_start.elapsed();

    // 256-byte alt_bn128 wire form for on-chain submission (the off-chain
    // local verify below still uses the arkworks `proof` object directly).
    let proof_bytes = proof_to_onchain_bytes(&proof).to_vec();
    println!(
        "Proof generated:   {} bytes in {:.2}s",
        proof_bytes.len(),
        proof_elapsed.as_secs_f64()
    );

    if Path::new(VERIFYING_KEY_PATH).exists() {
        let vk_bytes = fs::read(VERIFYING_KEY_PATH)?;
        let vk = VerifyingKey::<Bn254>::deserialize_compressed(&vk_bytes[..])?;
        let public_inputs = vec![
            Fr::from_le_bytes_mod_order(&merkle_root_bytes),
            Fr::from_le_bytes_mod_order(&nullifier_bytes_arr),
            Fr::from(net_deposit),
        ];
        let valid = Groth16ProofSystem::verify(&vk, &public_inputs, &proof)?;
        if !valid {
            return Err("Local proof verification failed (prover/verifier disagree)".into());
        }
        println!("Local verify:      OK");
    }

    header("Step 5: Submit on-chain withdrawal to Bob");

    let withdraw_tx_priv = WithdrawTx::new(
        nullifier.clone(),
        net_deposit,
        bob.pubkey().to_bytes().to_vec(),
        merkle_root_bytes,
        0,
    );
    if !withdraw_tx_priv.verify() {
        return Err("Off-chain withdraw structure verification failed".into());
    }

    let ix_withdraw = create_withdraw_instruction(
        &program_id,
        &authority.pubkey(),
        &bridge_vault,
        bob.pubkey().to_bytes(),
        *nullifier.as_bytes(),
        net_deposit,
        u64::MAX, // never-expires sentinel; production callers use current_slot + window
        proof_bytes.clone(),
        &[authority.pubkey()], // quorum co-signers (#260)
    )?;
    let blockhash = client.get_latest_blockhash()?;
    let withdraw_tx_signed = Transaction::new_signed_with_payer(
        &[ix_withdraw],
        Some(&authority.pubkey()),
        &[&authority],
        blockhash,
    );
    let withdraw_sig = client.send_and_confirm_transaction(&withdraw_tx_signed)?;
    println!("Withdraw tx:       {}", withdraw_sig);

    let bob_balance_after = client.get_balance(&bob.pubkey())?;
    let vault_balance_after = client.get_balance(&bridge_vault)?;

    header("Final state");
    println!(
        "Bob balance:       {} SOL (was {})",
        bob_balance_after as f64 / 1e9,
        bob_balance_before as f64 / 1e9
    );
    println!(
        "Vault balance:     {} SOL (was {})",
        vault_balance_after as f64 / 1e9,
        vault_after_deposit as f64 / 1e9
    );
    println!();
    println!("Deposit signer:    {}", alice.pubkey());
    println!("Withdraw recipient:{}", bob.pubkey());
    println!("(no shared signer between the two on-chain transactions)");
    println!();
    println!("Inspect the on-chain trace:");
    println!("  solana confirm -v {} --url {}", deposit_sig, rpc_url);
    println!("  solana confirm -v {} --url {}", withdraw_sig, rpc_url);

    if bob_balance_after <= bob_balance_before {
        return Err("Bob balance did not increase after withdrawal".into());
    }
    Ok(())
}
