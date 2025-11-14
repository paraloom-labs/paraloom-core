use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::ToConstraintField;
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::thread_rng;
use paraloom::privacy::circuits::{Groth16ProofSystem, WithdrawCircuit};
use std::fs;
use std::path::Path;

const PROVING_KEY_PATH: &str = "keys/withdraw_proving.key";
const VERIFYING_KEY_PATH: &str = "keys/withdraw_verifying.key";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("=== Withdrawal Proof Generator ===\n");

    let nullifier_hex =
        std::env::var("NULLIFIER").expect("NULLIFIER environment variable required (hex string)");
    let amount_str = std::env::var("AMOUNT").expect("AMOUNT environment variable required");
    let merkle_root_hex = std::env::var("MERKLE_ROOT")
        .expect("MERKLE_ROOT environment variable required (hex string)");
    let input_value_str =
        std::env::var("INPUT_VALUE").expect("INPUT_VALUE environment variable required");
    let input_randomness_hex = std::env::var("INPUT_RANDOMNESS")
        .expect("INPUT_RANDOMNESS environment variable required (hex string)");
    let secret_hex =
        std::env::var("SECRET").expect("SECRET environment variable required (hex string)");
    let merkle_path_json =
        std::env::var("MERKLE_PATH").expect("MERKLE_PATH environment variable required (JSON)");

    println!("Parsing inputs...");
    let nullifier = hex::decode(&nullifier_hex)?;
    let mut nullifier_bytes = [0u8; 32];
    nullifier_bytes.copy_from_slice(&nullifier);

    let merkle_root = hex::decode(&merkle_root_hex)?;
    let mut merkle_root_bytes = [0u8; 32];
    merkle_root_bytes.copy_from_slice(&merkle_root);

    let input_randomness = hex::decode(&input_randomness_hex)?;
    let mut input_randomness_bytes = [0u8; 32];
    input_randomness_bytes.copy_from_slice(&input_randomness);

    let secret = hex::decode(&secret_hex)?;
    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(&secret);

    let amount: u64 = amount_str.parse()?;
    let input_value: u64 = input_value_str.parse()?;

    let merkle_path: Vec<([u8; 32], bool)> = serde_json::from_str(&merkle_path_json)?;

    println!("\nInputs:");
    println!("  Nullifier: {}", nullifier_hex);
    println!("  Amount: {} lamports", amount);
    println!("  Input Value: {} lamports", input_value);
    println!("  Merkle Root: {}", merkle_root_hex);
    println!("  Merkle Path Length: {}", merkle_path.len());
    println!();

    if input_value < amount {
        return Err("Input value must be >= withdrawal amount".into());
    }

    if !Path::new(PROVING_KEY_PATH).exists() {
        println!("ERROR: Proving key not found at {}", PROVING_KEY_PATH);
        println!("Please run the setup ceremony first:");
        println!("  cargo run --bin setup_withdrawal_ceremony");
        return Err("Proving key not found".into());
    }

    println!("Loading proving key from {}...", PROVING_KEY_PATH);
    let proving_key_bytes = fs::read(PROVING_KEY_PATH)?;
    let proving_key = ProvingKey::<Bls12_381>::deserialize_compressed(&proving_key_bytes[..])?;

    println!("Creating withdrawal circuit with witness...");
    let circuit = WithdrawCircuit::with_witness(
        merkle_root_bytes,
        nullifier_bytes,
        amount,
        input_value,
        input_randomness_bytes,
        secret_bytes,
        merkle_path,
    );

    println!("Generating zkSNARK proof...");
    println!("This may take a few seconds...\n");

    let mut rng = thread_rng();
    let proof = Groth16ProofSystem::prove::<WithdrawCircuit, _>(&proving_key, circuit, &mut rng)?;

    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes)?;

    println!("=== Proof Generation Successful! ===");
    println!("Proof size: {} bytes", proof_bytes.len());
    println!("\nProof (hex):");
    println!("{}", hex::encode(&proof_bytes));
    println!();

    let output_file = "withdrawal_proof.bin";
    fs::write(output_file, &proof_bytes)?;
    println!("Proof saved to: {}", output_file);

    if Path::new(VERIFYING_KEY_PATH).exists() {
        println!("\nVerifying proof locally...");
        let verifying_key_bytes = fs::read(VERIFYING_KEY_PATH)?;
        let verifying_key =
            VerifyingKey::<Bls12_381>::deserialize_compressed(&verifying_key_bytes[..])?;

        // Prepare public inputs (5 field elements total)
        // UInt8::new_input_vec packs 32 bytes into 2 field elements
        let mut public_inputs = Vec::new();

        // Merkle root: 32 bytes → 2 Fr elements
        let root_fes: Vec<Fr> = merkle_root_bytes.to_field_elements().unwrap();
        public_inputs.extend(root_fes);

        // Nullifier: 32 bytes → 2 Fr elements
        let null_fes: Vec<Fr> = nullifier_bytes.to_field_elements().unwrap();
        public_inputs.extend(null_fes);

        // Amount: 1 Fr element
        public_inputs.push(Fr::from(amount));

        println!(
            "Public inputs prepared: {} field elements",
            public_inputs.len()
        );

        let is_valid = Groth16ProofSystem::verify(&verifying_key, &public_inputs, &proof)?;

        if is_valid {
            println!("✓ Local verification: SUCCESS");
        } else {
            println!("✗ Local verification: FAILED");
            return Err("Proof verification failed".into());
        }
    }

    println!("\nUse this proof in your withdrawal transaction:");
    println!("  WITHDRAWAL_PROOF={}", hex::encode(&proof_bytes));

    Ok(())
}
