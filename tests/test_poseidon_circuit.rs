//! Test Poseidon hash in circuit context
//!
//! This test isolates the Poseidon hash computation to identify
//! where the constraint satisfaction is failing.

use ark_bls12_381::Fr;
use ark_r1cs_std::{prelude::*, uint8::UInt8};
use ark_relations::r1cs::ConstraintSystem;
use paraloom::privacy::circuits::compute_hash_gadget;
use paraloom::privacy::poseidon::poseidon_hash;

#[test]
fn test_poseidon_gadget_matches_native() {
    // Test data: value || randomness (8 + 32 = 40 bytes)
    let input_value = 100_000_000u64;
    let input_randomness =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000003").unwrap();

    let mut commitment_preimage = Vec::new();
    commitment_preimage.extend_from_slice(&input_value.to_le_bytes());
    commitment_preimage.extend_from_slice(&input_randomness);

    // Compute native hash
    let native_hash = poseidon_hash(&commitment_preimage);
    println!("Native hash: {}", hex::encode(native_hash));

    // Now compute in circuit
    let cs = ConstraintSystem::<Fr>::new_ref();

    // Create witness variables for the input
    // IMPORTANT: Convert u64 to bytes directly, not through FpVar
    let input_value_bytes = UInt8::new_witness_vec(cs.clone(), &input_value.to_le_bytes()).unwrap();
    let input_randomness_var = UInt8::new_witness_vec(cs.clone(), &input_randomness[..]).unwrap();

    // Combine into bytes
    let mut input_bytes = input_value_bytes;
    input_bytes.extend_from_slice(&input_randomness_var);

    // Debug: Check what bytes we're hashing
    let input_bytes_values: Vec<u8> = input_bytes.iter().map(|b| b.value().unwrap()).collect();
    println!(
        "\nCircuit input bytes ({} bytes): {}",
        input_bytes_values.len(),
        hex::encode(&input_bytes_values)
    );

    // Compute hash in circuit
    let circuit_hash_bytes = compute_hash_gadget(cs.clone(), &input_bytes).unwrap();

    println!("Circuit has {} constraints", cs.num_constraints());

    // Check if circuit is satisfied
    if !cs.is_satisfied().unwrap() {
        println!("ERROR: Circuit is NOT satisfied!");
        panic!("Circuit constraint satisfaction failed");
    }

    println!("Circuit is satisfied");

    // Extract circuit hash value
    let circuit_hash: Vec<u8> = circuit_hash_bytes
        .iter()
        .map(|b| b.value().unwrap())
        .collect();

    println!("Circuit hash: {}", hex::encode(&circuit_hash));

    // They should match
    assert_eq!(
        native_hash,
        circuit_hash.as_slice(),
        "Native and circuit hashes don't match"
    );

    println!("Native and circuit hashes match!");
}

#[test]
fn test_nullifier_derivation() {
    // Test: nullifier = hash(commitment || secret)
    let commitment =
        hex::decode("246d7fd6b0158d1a0f748c801648845f4bdd286cc9fb5c36d3bd8675b65b661e").unwrap();
    let secret =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap();

    let mut nullifier_preimage = Vec::new();
    nullifier_preimage.extend_from_slice(&commitment);
    nullifier_preimage.extend_from_slice(&secret);

    // Compute native hash
    let native_nullifier = poseidon_hash(&nullifier_preimage);
    println!("Native nullifier: {}", hex::encode(native_nullifier));

    // Compute in circuit
    let cs = ConstraintSystem::<Fr>::new_ref();

    let commitment_var = UInt8::new_witness_vec(cs.clone(), &commitment[..]).unwrap();
    let secret_var = UInt8::new_witness_vec(cs.clone(), &secret[..]).unwrap();

    let mut nullifier_bytes = Vec::new();
    nullifier_bytes.extend_from_slice(&commitment_var);
    nullifier_bytes.extend_from_slice(&secret_var);

    let circuit_nullifier_bytes = compute_hash_gadget(cs.clone(), &nullifier_bytes).unwrap();

    println!("Circuit has {} constraints", cs.num_constraints());

    // Check if circuit is satisfied
    if !cs.is_satisfied().unwrap() {
        println!("ERROR: Circuit is NOT satisfied!");
        panic!("Circuit constraint satisfaction failed");
    }

    println!("Circuit is satisfied");

    // Extract circuit nullifier value
    let circuit_nullifier: Vec<u8> = circuit_nullifier_bytes
        .iter()
        .map(|b| b.value().unwrap())
        .collect();

    println!("Circuit nullifier: {}", hex::encode(&circuit_nullifier));

    // They should match
    assert_eq!(
        native_nullifier,
        circuit_nullifier.as_slice(),
        "Native and circuit nullifiers don't match"
    );

    println!("Native and circuit nullifiers match!");
}
