//! #184: a real multi-leaf withdrawal proof verifies through the node's
//! canonical verifier.
//!
//! Deposits several notes into a real `ShieldedPool`, pulls the depth-32
//! Merkle path for one of them, builds and proves a `WithdrawCircuit` against
//! the pool's own root, and confirms `ProofVerifier::verify_withdrawal_parts`
//! accepts it — a genuine Groth16 proof (not the injected accept-verifier the
//! network tests use), against a real anonymity set rather than a single
//! leaf. The whole chain lines up by construction: `Note::commitment`,
//! `MerkleTree`'s `hash_pair` and the circuit gadget all use the same
//! `poseidon_commit` / `poseidon_nullifier` / `poseidon_merkle_pair`.
//!
//! Requires the fixed-depth (#184) `_v4` trusted-setup keys in `keys/`, which
//! are gitignored, so this is `#[ignore]`'d and run locally.

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::ProvingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::thread_rng;
use paraloom::privacy::circuits::{Groth16ProofSystem, WithdrawCircuit};
use paraloom::privacy::pool::ShieldedPool;
use paraloom::privacy::poseidon::{poseidon_commit, poseidon_nullifier};
use paraloom::privacy::types::{Commitment, Note, ShieldedAddress};
use paraloom::privacy::{ProofVerifier, VerificationResult};
use std::path::Path;

const PROVING_KEY_PATH: &str = "keys/withdraw_proving_v4.key";

/// Little-endian 32-byte encoding of a field element — mirrors the private
/// `fr_to_bytes_32` the host uses, so the nullifier we pass lines up with what
/// `verify_withdrawal_parts` lifts back via `from_le_bytes_mod_order`.
fn fr_to_le_bytes_32(fr: Fr) -> [u8; 32] {
    let mut v = fr.into_bigint().to_bytes_le();
    v.resize(32, 0);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v[..32]);
    out
}

#[tokio::test]
#[ignore = "needs the fixed-depth (_v4) trusted-setup keys in keys/; run locally"]
async fn real_multi_leaf_proof_verifies_through_canonical_verifier() {
    let _ = env_logger::builder().is_test(true).try_init();
    assert!(
        Path::new(PROVING_KEY_PATH).exists(),
        "ceremony proving key {PROVING_KEY_PATH} missing — run setup-withdrawal-ceremony"
    );

    // Deposit several notes so the spent note sits in a real anonymity set and
    // the Merkle path is a genuine non-empty one, not the single-leaf case.
    const N: usize = 10;
    const SPEND: usize = 4;
    let pool = ShieldedPool::new();

    let mut spent: Option<(u64, [u8; 32], [u8; 32])> = None;
    for i in 0..N {
        let value = 100_000u64 + i as u64;
        let randomness = [i as u8 + 1; 32];
        let recipient = [i as u8 + 100; 32];
        let note = Note::new_native(ShieldedAddress(recipient), value, randomness);
        pool.deposit(note, value).await.expect("deposit");
        if i == SPEND {
            spent = Some((value, randomness, recipient));
        }
    }
    let (value, randomness, recipient) = spent.expect("spent note captured");

    // Canonical commitment + nullifier via the same helpers the circuit uses.
    let commitment_fr = poseidon_commit(
        Fr::from(value),
        Fr::from_le_bytes_mod_order(&randomness),
        Fr::from_le_bytes_mod_order(&recipient),
        Fr::from(0u64),
    );
    let secret = [7u8; 32];
    let nullifier_fr = poseidon_nullifier(commitment_fr, Fr::from_le_bytes_mod_order(&secret));
    let nullifier = fr_to_le_bytes_32(nullifier_fr);

    // The pool stored this exact commitment (built via Note::commitment).
    let commitment = Commitment::from_bytes(fr_to_le_bytes_32(commitment_fr));
    let merkle = pool
        .path(&commitment)
        .await
        .expect("pool must hold the spent note's commitment");
    let root = pool.root().await;
    let merkle_path: Vec<([u8; 32], bool)> = merkle
        .path
        .iter()
        .copied()
        .zip(merkle.indices.iter().copied())
        .collect();

    let withdraw_amount = value;

    let circuit = WithdrawCircuit::with_witness(
        root,
        nullifier,
        withdraw_amount,
        value,
        randomness,
        recipient,
        secret,
        merkle_path,
    );

    let pk_bytes = std::fs::read(PROVING_KEY_PATH).expect("read proving key");
    let pk = ProvingKey::<Bls12_381>::deserialize_compressed(&pk_bytes[..])
        .expect("deserialize proving key");
    let mut rng = thread_rng();
    let proof = Groth16ProofSystem::prove::<WithdrawCircuit, _>(&pk, circuit, &mut rng)
        .expect("prove withdrawal");
    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .expect("serialize proof");

    // The node's canonical verifier (ceremony vk + from_le_bytes_mod_order
    // public inputs) must accept a proof generated against the pool's own root.
    match ProofVerifier::verify_withdrawal_parts(&root, &nullifier, withdraw_amount, &proof_bytes) {
        VerificationResult::Valid => {}
        VerificationResult::Invalid { reason } => {
            panic!("real multi-leaf proof must verify, got Invalid: {reason}")
        }
    }
}
