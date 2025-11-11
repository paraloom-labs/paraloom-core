//! End-to-end privacy integration tests
//!
//! Tests the complete privacy flow focusing on implemented functionality:
//! 1. Deposit with commitment generation
//! 2. Merkle tree updates
//! 3. Proof codec (serialization/deserialization)
//! 4. Nullifier tracking

use paraloom::privacy::*;
use std::sync::Arc;

#[tokio::test]
async fn test_deposit_and_commitment_generation() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("=== Testing Deposit and Commitment Generation ===");

    // Initialize privacy pool
    let pool = Arc::new(ShieldedPool::new());
    let initial_root = pool.root().await;
    log::info!("Initial Merkle root: {:?}", &initial_root[..8]);

    // Create deposit transaction with Pedersen commitment
    let address = ShieldedAddress([42u8; 32]);
    let randomness = pedersen::generate_randomness();
    let deposit_amount = 1000u64;
    let fee = 10u64;

    let deposit_tx = DepositTx::new(
        vec![0x01; 32], // tx_hash
        deposit_amount,
        address,
        randomness,
        fee,
    );

    log::info!("Created deposit transaction");
    log::info!("  Amount: {} lamports", deposit_amount);
    log::info!("  Fee: {} lamports", fee);
    log::info!(
        "  Commitment: {:?}",
        &deposit_tx.output_commitment.as_bytes()[..8]
    );

    // Verify deposit transaction
    assert!(deposit_tx.verify(), "Deposit should be valid");

    // Add to pool
    let note = deposit_tx.output_note.clone();
    let net_amount = deposit_amount - fee;
    let commitment = pool.deposit(note, net_amount).await.unwrap();

    log::info!("PASS: Deposit added to pool");
    assert_eq!(commitment, deposit_tx.output_commitment);

    // Verify Merkle root changed
    let root_after_deposit = pool.root().await;
    assert_ne!(
        initial_root, root_after_deposit,
        "Merkle root should change after deposit"
    );
    log::info!("PASS: Merkle root updated: {:?}", &root_after_deposit[..8]);

    // Verify pool state
    assert_eq!(pool.commitment_count().await, 1);
    assert_eq!(pool.total_supply().await, net_amount);

    log::info!("PASS: All deposit checks passed");
}

#[tokio::test]
async fn test_nullifier_generation_and_tracking() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("=== Testing Nullifier Generation and Tracking ===");

    let pool = Arc::new(ShieldedPool::new());

    // Create and process deposit
    let address = ShieldedAddress([42u8; 32]);
    let randomness = pedersen::generate_randomness();
    let deposit = DepositTx::new(vec![0x01; 32], 1000, address, randomness, 10);

    let note = deposit.output_note.clone();
    pool.deposit(note.clone(), 990).await.unwrap();

    log::info!("Setup complete: deposit processed");

    // Generate nullifier from the note
    let spending_key = randomness; // In production, this would be derived from private key
    let nullifier = Nullifier::derive(&note.commitment(), &spending_key);

    log::info!("Generated nullifier: {:?}", &nullifier.0[..8]);

    // Verify nullifier is not spent initially
    assert!(
        !pool.is_spent(&nullifier).await,
        "Nullifier should not be spent initially"
    );
    log::info!("PASS: Nullifier initially unspent");

    // Process withdrawal (marking nullifier as spent)
    let withdraw_amount = 500u64;
    let recipient = [0x99u8; 32];
    pool.withdraw(nullifier.clone(), withdraw_amount, &recipient)
        .await
        .unwrap();

    log::info!("PASS: Withdrawal processed");

    // Verify nullifier is now spent
    assert!(
        pool.is_spent(&nullifier).await,
        "Nullifier should be marked as spent"
    );
    log::info!("PASS: Nullifier marked as spent");

    // Attempt double-spend
    let result = pool
        .withdraw(nullifier.clone(), withdraw_amount, &recipient)
        .await;

    assert!(result.is_err(), "Double-spend should fail");
    log::info!("PASS: Double-spend prevented");
}

#[tokio::test]
#[ignore] // Proof generation is slow (60+ seconds), run manually with: cargo test --test privacy_integration_test test_proof_serialization_codec -- --ignored
async fn test_proof_serialization_codec() {
    use ark_bls12_381::Bls12_381;
    use ark_groth16::Proof;
    use ark_std::rand::rngs::StdRng;
    use ark_std::rand::SeedableRng;

    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("=== Testing Proof Serialization Codec ===");

    // Generate a test circuit and proof
    let mut rng = StdRng::seed_from_u64(0u64);
    let circuit = DepositCircuit::new();

    let (pk, _vk) = Groth16ProofSystem::setup(circuit, &mut rng).unwrap();
    log::info!("PASS: Circuit setup complete");

    // Create a proof
    let prove_circuit = DepositCircuit::new();
    let proof = Groth16ProofSystem::prove(&pk, prove_circuit, &mut rng).unwrap();
    log::info!("PASS: Proof generated");

    // Serialize the proof
    let serialized = serialize_proof(&proof).unwrap();
    log::info!("Serialized proof size: {} bytes", serialized.len());

    // Deserialize the proof
    let deserialized: Proof<Bls12_381> = deserialize_proof(&serialized).unwrap();
    log::info!("PASS: Proof deserialized");

    // Serialize again and verify roundtrip
    let reserialized = serialize_proof(&deserialized).unwrap();
    assert_eq!(serialized, reserialized, "Proof should roundtrip correctly");
    log::info!("PASS: Proof codec roundtrip successful");
}

#[tokio::test]
async fn test_multiple_deposits_merkle_tree() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("=== Testing Multiple Deposits and Merkle Tree ===");

    let pool = Arc::new(ShieldedPool::new());
    let mut roots = vec![pool.root().await];

    // Create multiple deposits
    for i in 0..10 {
        let address = ShieldedAddress([i as u8; 32]);
        let randomness = pedersen::generate_randomness();
        let amount = 1000 + (i as u64 * 100);

        let deposit = DepositTx::new(vec![i as u8; 32], amount, address, randomness, 10);

        let note = deposit.output_note.clone();
        pool.deposit(note, amount - 10).await.unwrap();

        let new_root = pool.root().await;
        roots.push(new_root);

        // Verify root changed
        assert_ne!(
            roots[i],
            roots[i + 1],
            "Root should change after each deposit"
        );
    }

    log::info!("PASS: Processed 10 deposits");
    log::info!("  Initial root: {:?}", &roots[0][..8]);
    log::info!("  Final root:   {:?}", &roots[10][..8]);
    log::info!("  Commitment count: {}", pool.commitment_count().await);
    log::info!("  Total supply: {}", pool.total_supply().await);
}

#[tokio::test]
async fn test_nullifier_uniqueness() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("=== Testing Nullifier Uniqueness ===");

    let pool = Arc::new(ShieldedPool::new());
    let mut nullifiers = Vec::new();

    // Create notes with same value but different randomness
    for i in 0..10 {
        let address = ShieldedAddress([42u8; 32]); // Same address
        let randomness = pedersen::generate_randomness(); // Different randomness

        let deposit = DepositTx::new(
            vec![i as u8; 32],
            1000, // Same amount
            address,
            randomness,
            10,
        );

        let note = deposit.output_note.clone();
        pool.deposit(note.clone(), 990).await.unwrap();

        // Generate nullifier
        let nullifier = Nullifier::derive(&note.commitment(), &randomness);
        nullifiers.push(nullifier);
    }

    // Verify all nullifiers are unique
    for i in 0..nullifiers.len() {
        for j in (i + 1)..nullifiers.len() {
            assert_ne!(
                nullifiers[i].0, nullifiers[j].0,
                "Nullifiers should be unique"
            );
        }
    }

    log::info!("PASS: All {} nullifiers are unique", nullifiers.len());
}

#[tokio::test]
async fn test_field_element_codec() {
    use ark_bls12_381::Fr;
    use ark_std::UniformRand;

    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    log::info!("=== Testing Field Element Codec ===");

    let mut rng = ark_std::test_rng();

    // Test multiple field elements
    for i in 0..10 {
        let field = Fr::rand(&mut rng);

        // Convert to bytes
        let bytes = field_to_bytes(&field);

        // Convert back to field
        let recovered = bytes_to_field(&bytes).unwrap();

        assert_eq!(field, recovered, "Field element {} should roundtrip", i);
    }

    log::info!("PASS: Field element codec tested with 10 random elements");
}
