use ark_serialize::CanonicalSerialize;
use ark_std::rand::thread_rng;
use paraloom::privacy::circuits::{Groth16ProofSystem, TransferCircuit, MAX_INPUTS, MAX_OUTPUTS};
use paraloom::privacy::merkle::DEFAULT_TREE_DEPTH;
use std::fs;
use std::path::Path;

// Transfer circuit keys (#194). The constraint shape is fixed by the
// 2-in/2-out arity (MAX_INPUTS/MAX_OUTPUTS) and the fixed Merkle path depth,
// so the dummy circuit must carry that exact shape — two inputs each with a
// full depth-`DEFAULT_TREE_DEPTH` path and two outputs. A different arity or
// path length would generate keys that no real transfer proof verifies under.
const PROVING_KEY_PATH: &str = "keys/transfer_proving.key";
const VERIFYING_KEY_PATH: &str = "keys/transfer_verifying.key";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("=== Transfer Circuit Setup Ceremony ===\n");
    println!(
        "Generating proving and verifying keys for the fixed-depth, {}-in/{}-out",
        MAX_INPUTS, MAX_OUTPUTS
    );
    println!("transfer circuit (Merkle depth {}).\n", DEFAULT_TREE_DEPTH);
    println!("This is a TRUSTED SETUP. In production, this should be done");
    println!("through a multi-party computation ceremony (#64).\n");

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
    // The setup reads only the circuit's constraint *shape*, not witness
    // values — but the shape depends on the input/output arity and the Merkle
    // path length, so the dummy must match every real transfer proof:
    // MAX_INPUTS inputs (each with a full-depth path) and MAX_OUTPUTS outputs.
    let dummy_path: Vec<([u8; 32], bool)> = vec![([0u8; 32], false); DEFAULT_TREE_DEPTH];
    let dummy_circuit = TransferCircuit::with_witness(
        [0u8; 32],                            // merkle_root
        vec![[0u8; 32]; MAX_INPUTS],          // nullifiers
        vec![[0u8; 32]; MAX_OUTPUTS],         // output_commitments
        vec![0u64; MAX_INPUTS],               // input_values
        vec![[0u8; 32]; MAX_INPUTS],          // input_randomness
        vec![[0u8; 32]; MAX_INPUTS],          // input_recipients
        vec![[0u8; 32]; MAX_INPUTS],          // input_secrets
        vec![dummy_path.clone(); MAX_INPUTS], // input_paths
        vec![0u64; MAX_OUTPUTS],              // output_values
        vec![[0u8; 32]; MAX_OUTPUTS],         // output_randomness
        vec![[0u8; 32]; MAX_OUTPUTS],         // recipient_addresses
    );

    println!("Running trusted setup...");
    println!("This may take a few minutes...\n");

    let mut rng = thread_rng();
    let (proving_key, verifying_key) =
        Groth16ProofSystem::setup::<TransferCircuit, _>(dummy_circuit, &mut rng)?;

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
    println!("  - For production, use a multi-party computation ceremony (#64)");
    println!("  - Never commit keys to version control");

    Ok(())
}
