//! Demo client for `scripts/demo.sh`. Assembles a withdrawal for the fixed
//! `test-deposit` note (0.1 SOL, recipient `[1; 32]`, randomness `[2; 32]`) and
//! prints either the note commitment or a ready-to-submit ingress body.
//!
//!   demo-withdraw commitment
//!       Print the note commitment (hex) so the caller can fetch its Merkle
//!       path from the node's path server.
//!
//!   MERKLE_ROOT=<hex> PATH_HEX=<json> INDICES=<json> demo-withdraw prove
//!       Build a Groth16 proof against that path and print the ingress JSON.
//!       A fresh random secret is used each run unless SECRET_HEX is set, so
//!       the derived nullifier is unspent and the same on-chain deposit can be
//!       demonstrated repeatedly.

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::ProvingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::thread_rng;
use paraloom::privacy::circuits::{Groth16ProofSystem, WithdrawCircuit};
use paraloom::privacy::poseidon::{poseidon_commit, poseidon_nullifier};

fn fr_to_le_bytes_32(fr: Fr) -> [u8; 32] {
    let mut v = fr.into_bigint().to_bytes_le();
    v.resize(32, 0);
    let mut o = [0u8; 32];
    o.copy_from_slice(&v[..32]);
    o
}

fn hex32(s: &str) -> [u8; 32] {
    let b = hex::decode(s.trim()).expect("hex");
    let mut o = [0u8; 32];
    o.copy_from_slice(&b);
    o
}

fn main() {
    // The fixed test-deposit note: amount 0.1 SOL, fee 0, recipient [1;32],
    // randomness [2;32]. The spender picks the secret.
    let value: u64 = 100_000_000;
    let randomness = [2u8; 32];
    let recipient = [1u8; 32];
    // Each run picks a fresh secret so the derived nullifier is unspent;
    // the note commitment does not depend on the secret, so the same
    // on-chain deposit can be demonstrated repeatedly without a replay.
    let secret: [u8; 32] = match std::env::var("SECRET_HEX") {
        Ok(s) => hex32(&s),
        Err(_) => {
            let mut s = [0u8; 32];
            ark_std::rand::RngCore::fill_bytes(&mut thread_rng(), &mut s);
            s
        }
    };

    let commitment_fr = poseidon_commit(
        Fr::from(value),
        Fr::from_le_bytes_mod_order(&randomness),
        Fr::from_le_bytes_mod_order(&recipient),
    );

    let mode = std::env::args().nth(1).unwrap_or_default();
    if mode == "commitment" {
        println!("{}", hex::encode(fr_to_le_bytes_32(commitment_fr)));
        return;
    }

    // prove mode: take the real (root, path) the path server returned.
    let root = hex32(&std::env::var("MERKLE_ROOT").expect("MERKLE_ROOT"));
    let path_hex: Vec<String> =
        serde_json::from_str(&std::env::var("PATH_HEX").expect("PATH_HEX")).expect("PATH_HEX json");
    let indices: Vec<bool> =
        serde_json::from_str(&std::env::var("INDICES").expect("INDICES")).expect("INDICES json");
    let merkle_path: Vec<([u8; 32], bool)> =
        path_hex.iter().map(|h| hex32(h)).zip(indices).collect();

    let nullifier_fr = poseidon_nullifier(commitment_fr, Fr::from_le_bytes_mod_order(&secret));
    let nullifier = fr_to_le_bytes_32(nullifier_fr);

    let circuit = WithdrawCircuit::with_witness(
        root,
        nullifier,
        value,
        value,
        randomness,
        recipient,
        secret,
        merkle_path,
    );
    let pk_bytes = std::fs::read("keys/withdraw_proving_v4.key").expect("v4 proving key");
    let pk = ProvingKey::<Bls12_381>::deserialize_compressed(&pk_bytes[..]).expect("pk");
    let proof = Groth16ProofSystem::prove::<WithdrawCircuit, _>(&pk, circuit, &mut thread_rng())
        .expect("prove");
    let mut pb = Vec::new();
    proof.serialize_compressed(&mut pb).expect("serialize");

    println!(
        "{{\"nullifier\":\"{}\",\"recipient\":\"{}\",\"proof\":\"{}\",\"amount\":{},\"fee\":0}}",
        hex::encode(nullifier),
        hex::encode(recipient),
        hex::encode(pb),
        value
    );
}
