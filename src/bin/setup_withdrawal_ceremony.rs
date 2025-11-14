use ark_serialize::CanonicalSerialize;
use ark_std::rand::thread_rng;
use paraloom::privacy::circuits::{Groth16ProofSystem, WithdrawCircuit};
use std::fs;
use std::path::Path;

const PROVING_KEY_PATH: &str = "keys/withdraw_proving.key";
const VERIFYING_KEY_PATH: &str = "keys/withdraw_verifying.key";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("=== Withdrawal Circuit Setup Ceremony ===\n");
    println!("This will generate proving and verifying keys for the withdrawal circuit.");
    println!("This is a TRUSTED SETUP. In production, this should be done");
    println!("         through a multi-party computation ceremony.\n");

    if Path::new(PROVING_KEY_PATH).exists() || Path::new(VERIFYING_KEY_PATH).exists() {
        println!("WARNING: Keys already exist!");
        println!("  Proving key: {}", PROVING_KEY_PATH);
        println!("  Verifying key: {}", VERIFYING_KEY_PATH);
        println!("\nDo you want to overwrite? (y/N)");

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Setup cancelled.");
            return Ok(());
        }
    }

    fs::create_dir_all("keys")?;

    println!("Creating dummy circuit for setup...");
    let dummy_circuit = WithdrawCircuit::new();

    println!("Running trusted setup...");
    println!("This may take a few minutes...\n");

    let mut rng = thread_rng();
    let (proving_key, verifying_key) =
        Groth16ProofSystem::setup::<WithdrawCircuit, _>(dummy_circuit, &mut rng)?;

    println!("Serializing keys...");
    let mut proving_key_bytes = Vec::new();
    proving_key.serialize_compressed(&mut proving_key_bytes)?;

    let mut verifying_key_bytes = Vec::new();
    verifying_key.serialize_compressed(&mut verifying_key_bytes)?;

    println!("Writing keys to disk...");
    fs::write(PROVING_KEY_PATH, &proving_key_bytes)?;
    fs::write(VERIFYING_KEY_PATH, &verifying_key_bytes)?;

    println!("\n=== Setup Complete! ===");
    println!(
        "Proving key: {} ({} bytes)",
        PROVING_KEY_PATH,
        proving_key_bytes.len()
    );
    println!(
        "Verifying key: {} ({} bytes)",
        VERIFYING_KEY_PATH,
        verifying_key_bytes.len()
    );

    println!("\nKEY SECURITY:");
    println!("  - Keep the proving key SECRET");
    println!("  - The verifying key can be public");
    println!("  - For production, use a multi-party computation ceremony");
    println!("  - Never commit keys to version control");
    println!("\nNext steps:");
    println!("  1. Generate proofs: cargo run --bin generate_withdrawal_proof");
    println!("  2. Add keys/ to .gitignore");

    Ok(())
}
