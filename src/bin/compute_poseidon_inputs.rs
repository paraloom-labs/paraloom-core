use paraloom::privacy::poseidon::poseidon_hash;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Computing Withdrawal Inputs with Poseidon Hash ===\n");

    // Test parameters
    let input_value = 100_000_000u64;
    let withdraw_amount = 100_000_000u64;
    let input_randomness =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000003")?;
    let secret = hex::decode("0000000000000000000000000000000000000000000000000000000000000001")?;

    println!("Inputs:");
    println!("  Value: {} lamports", input_value);
    println!("  Randomness: {}", hex::encode(&input_randomness));
    println!("  Secret: {}", hex::encode(&secret));
    println!();

    // Step 1: Compute commitment = poseidon_hash(value || randomness)
    let mut commitment_preimage = Vec::new();
    commitment_preimage.extend_from_slice(&input_value.to_le_bytes());
    commitment_preimage.extend_from_slice(&input_randomness);

    let commitment = poseidon_hash(&commitment_preimage);

    println!("Step 1: Commitment");
    println!("  Preimage: value || randomness");
    println!("  Hash: {}", hex::encode(commitment));
    println!();

    // Step 2: Compute nullifier = poseidon_hash(commitment || secret)
    let mut nullifier_preimage = Vec::new();
    nullifier_preimage.extend_from_slice(&commitment);
    nullifier_preimage.extend_from_slice(&secret);

    let nullifier = poseidon_hash(&nullifier_preimage);

    println!("Step 2: Nullifier");
    println!("  Preimage: commitment || secret");
    println!("  Hash: {}", hex::encode(nullifier));
    println!();

    // For empty Merkle path, merkle_root = commitment
    let merkle_root = commitment;
    let merkle_path = Vec::<([u8; 32], bool)>::new();

    println!("Step 3: Merkle Tree (empty path test)");
    println!("  Root: {}", hex::encode(merkle_root));
    println!("  Path: []");
    println!();

    // Output environment variables
    println!("=== Environment Variables for Proof Generation ===\n");
    println!("export NULLIFIER={}", hex::encode(nullifier));
    println!("export AMOUNT={}", withdraw_amount);
    println!("export MERKLE_ROOT={}", hex::encode(merkle_root));
    println!("export INPUT_VALUE={}", input_value);
    println!("export INPUT_RANDOMNESS={}", hex::encode(&input_randomness));
    println!("export SECRET={}", hex::encode(&secret));
    println!(
        "export MERKLE_PATH='{}'",
        serde_json::to_string(&merkle_path)?
    );
    println!();

    println!("=== Run Proof Generation ===\n");
    println!("cargo run --bin generate_withdrawal_proof");
    println!();

    // Verification
    println!("=== Verification ===");
    println!("Commitment == Merkle Root: {}", commitment == merkle_root);
    println!("Nullifier != Commitment: {}", nullifier != commitment);
    println!();

    if nullifier == commitment {
        println!("WARNING: Nullifier equals commitment! This shouldn't happen with Poseidon.");
        println!("This indicates the hash function is not working correctly.");
        return Err("Invalid nullifier derivation".into());
    }

    println!("All checks passed! Ready to generate proof.");

    Ok(())
}
