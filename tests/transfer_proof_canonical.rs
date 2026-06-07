//! #194: a real 2-in/2-out transfer proof verifies through the node's
//! canonical transfer verifier.
//!
//! The transfer twin of `withdrawal_proof_canonical`. Deposits several notes
//! into a real `ShieldedPool`, pulls the depth-32 Merkle paths for two of them,
//! builds and proves a `TransferCircuit` (2 inputs consolidated into 2 outputs,
//! value-preserving) against the pool's own root, and confirms
//! `ProofVerifier::verify_transfer_parts` accepts it — a genuine Groth16 proof
//! against a real anonymity set. It also confirms that passing the public
//! inputs in the wrong order (commitments where nullifiers go) is rejected, so
//! the public-input layout is pinned.
//!
//! Requires the transfer trusted-setup key in `keys/` (gitignored), so this is
//! `#[ignore]`'d and run locally / in the `--ignored` CI job.

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::ProvingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::thread_rng;
use paraloom::privacy::circuits::{Groth16ProofSystem, TransferCircuit};
use paraloom::privacy::pool::ShieldedPool;
use paraloom::privacy::poseidon::{poseidon_commit, poseidon_nullifier};
use paraloom::privacy::types::{Commitment, Note, ShieldedAddress};
use paraloom::privacy::{ProofVerifier, VerificationResult};
use std::path::Path;

const PROVING_KEY_PATH: &str = "keys/transfer_proving.key";

fn fr_to_le_bytes_32(fr: Fr) -> [u8; 32] {
    let mut v = fr.into_bigint().to_bytes_le();
    v.resize(32, 0);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v[..32]);
    out
}

/// The canonical nullifier for a deposited note, via the same helpers the
/// circuit uses. Returns `(commitment, nullifier, merkle_path)` pulled from the
/// pool's real tree.
async fn spend_parts(
    pool: &ShieldedPool,
    value: u64,
    randomness: [u8; 32],
    recipient: [u8; 32],
    secret: [u8; 32],
) -> ([u8; 32], [u8; 32], Vec<([u8; 32], bool)>) {
    let commitment_fr = poseidon_commit(
        Fr::from(value),
        Fr::from_le_bytes_mod_order(&randomness),
        Fr::from_le_bytes_mod_order(&recipient),
        Fr::from(0u64),
    );
    let nullifier_fr = poseidon_nullifier(commitment_fr, Fr::from_le_bytes_mod_order(&secret));
    let commitment = Commitment::from_bytes(fr_to_le_bytes_32(commitment_fr));
    let merkle = pool
        .path(&commitment)
        .await
        .expect("pool must hold the spent note's commitment");
    let path = merkle
        .path
        .iter()
        .copied()
        .zip(merkle.indices.iter().copied())
        .collect();
    (
        fr_to_le_bytes_32(commitment_fr),
        fr_to_le_bytes_32(nullifier_fr),
        path,
    )
}

#[tokio::test]
#[ignore = "needs the transfer trusted-setup key in keys/; run locally / --ignored CI"]
async fn real_two_in_two_out_transfer_verifies_through_canonical_verifier() {
    let _ = env_logger::builder().is_test(true).try_init();
    assert!(
        Path::new(PROVING_KEY_PATH).exists(),
        "transfer proving key {PROVING_KEY_PATH} missing — run setup-transfer-ceremony"
    );

    // Deposit several notes so the two spent notes sit in a real anonymity set.
    const N: usize = 8;
    let pool = ShieldedPool::new();
    let mut notes: Vec<(u64, [u8; 32], [u8; 32])> = Vec::new();
    for i in 0..N {
        let value = 100_000u64 + i as u64;
        let randomness = [i as u8 + 1; 32];
        let recipient = [i as u8 + 100; 32];
        pool.deposit(
            Note::new_native(ShieldedAddress(recipient), value, randomness),
            value,
        )
        .await
        .expect("deposit");
        notes.push((value, randomness, recipient));
    }

    // Spend notes 2 and 5; the Merkle paths are pulled after all deposits so
    // both prove membership against the same final root.
    let (v0, r0, rec0) = notes[2];
    let (v1, r1, rec1) = notes[5];
    let secret0 = [0xC0u8; 32];
    let secret1 = [0xC1u8; 32];
    let (_c0, null0, path0) = spend_parts(&pool, v0, r0, rec0, secret0).await;
    let (_c1, null1, path1) = spend_parts(&pool, v1, r1, rec1, secret1).await;
    let root = pool.root().await;

    // Two outputs, value-preserving: consolidate the full input value into the
    // first output, the second is an empty (zero-value) note.
    let out_total = v0 + v1;
    let out_rand0 = [0xD0u8; 32];
    let out_rec0 = [0xE0u8; 32];
    let out_rand1 = [0xD1u8; 32];
    let out_rec1 = [0xE1u8; 32];
    let commit_out0 = fr_to_le_bytes_32(poseidon_commit(
        Fr::from(out_total),
        Fr::from_le_bytes_mod_order(&out_rand0),
        Fr::from_le_bytes_mod_order(&out_rec0),
        Fr::from(0u64),
    ));
    let commit_out1 = fr_to_le_bytes_32(poseidon_commit(
        Fr::from(0u64),
        Fr::from_le_bytes_mod_order(&out_rand1),
        Fr::from_le_bytes_mod_order(&out_rec1),
        Fr::from(0u64),
    ));

    let circuit = TransferCircuit::with_witness(
        root,
        vec![null0, null1],
        vec![commit_out0, commit_out1],
        vec![v0, v1],
        vec![r0, r1],
        vec![rec0, rec1],
        vec![secret0, secret1],
        vec![path0, path1],
        vec![out_total, 0],
        vec![out_rand0, out_rand1],
        vec![out_rec0, out_rec1],
    );

    let pk_bytes = std::fs::read(PROVING_KEY_PATH).expect("read transfer proving key");
    let pk = ProvingKey::<Bls12_381>::deserialize_compressed(&pk_bytes[..])
        .expect("deserialize transfer proving key");
    let mut rng = thread_rng();
    let proof = Groth16ProofSystem::prove::<TransferCircuit, _>(&pk, circuit, &mut rng)
        .expect("prove transfer");
    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .expect("serialize proof");

    let nullifiers = [null0, null1];
    let commitments = [commit_out0, commit_out1];

    // Canonical verifier (transfer ceremony vk + [root, nullifiers.., commitments..])
    // must accept a proof generated against the pool's own root.
    match ProofVerifier::verify_transfer_parts(&root, &nullifiers, &commitments, &proof_bytes) {
        VerificationResult::Valid => {}
        VerificationResult::Invalid { reason } => {
            panic!("real 2-in/2-out transfer proof must verify, got Invalid: {reason}")
        }
    }

    // Swapping nullifiers and commitments (wrong public-input order) must be
    // rejected — pins the layout the prover and on-chain instruction rely on.
    assert!(
        matches!(
            ProofVerifier::verify_transfer_parts(&root, &commitments, &nullifiers, &proof_bytes),
            VerificationResult::Invalid { .. }
        ),
        "transfer proof must NOT verify with nullifiers/commitments swapped"
    );
}
