use ark_serialize::CanonicalSerialize;
use ark_std::rand::thread_rng;
use paraloom::privacy::circuits::{Groth16ProofSystem, WithdrawCircuit};
use paraloom::privacy::merkle::DEFAULT_TREE_DEPTH;
use std::fs;
use std::path::Path;

// Versioned (`_v4`) after the commitment tree became fixed-depth (#184). A
// withdrawal proof now always carries a depth-`DEFAULT_TREE_DEPTH` Merkle
// path, so the circuit's constraint system has a fixed shape with that many
// `poseidon_merkle_pair` gadgets. The `_v3` keys were generated from
// `WithdrawCircuit::new()` (an empty path) and only fit a single-leaf
// withdrawal — incompatible with the fixed-depth circuit. Bumping the
// filename ensures the loader can't silently pick up a stale, single-leaf key.
const PROVING_KEY_PATH: &str = "keys/withdraw_proving_v4.key";
const VERIFYING_KEY_PATH: &str = "keys/withdraw_verifying_v4.key";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("=== Withdrawal Circuit Setup Ceremony (v4) ===\n");
    println!("This will generate proving and verifying keys for the");
    println!(
        "fixed-depth withdrawal circuit (depth {}).\n",
        DEFAULT_TREE_DEPTH
    );
    println!("Earlier keys (keys/withdraw_*.key, including the _v3 set)");
    println!("are INCOMPATIBLE with the fixed-depth circuit. They can be");
    println!("deleted safely once this ceremony completes.\n");
    println!("This is a TRUSTED SETUP. In production, this should be done");
    println!("through a multi-party computation ceremony.\n");

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
    // The setup only reads the circuit's constraint *shape*, not the witness
    // values — but the shape now depends on the Merkle path length, so the
    // dummy must carry a full depth-`DEFAULT_TREE_DEPTH` path (the fixed depth
    // every real withdrawal proof uses). An empty path would regenerate the
    // old single-leaf keys.
    let dummy_path: Vec<([u8; 32], bool)> = vec![([0u8; 32], false); DEFAULT_TREE_DEPTH];
    let dummy_circuit = WithdrawCircuit::with_witness(
        [0u8; 32], // merkle_root
        [0u8; 32], // nullifier
        0,         // withdraw_amount
        0,         // input_value
        [0u8; 32], // input_randomness
        [0u8; 32], // input_recipient
        [0u8; 32], // secret
        dummy_path,
    );

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
