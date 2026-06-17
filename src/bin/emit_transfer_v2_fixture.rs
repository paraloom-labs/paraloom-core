//! Dev tool: single-party setup of the spend-key 2-in/2-out transfer circuit
//! (circuit v2, #293) and emit of its on-chain verifying key + proof fixture.
//!
//! Writes `keys/transfer_v2_{proving,verifying}.key` (the proving key is what
//! the wallet's prover bundles) and prints the VK constants (7 IC points for the
//! 6 public inputs `[merkle_root, nullifier0, nullifier1, commitment0,
//! commitment1, asset_id]`) plus a fixture, both to paste into the program at
//! cutover. The fixture is two input notes at leaves 0 and 1 of a full-depth
//! tree spending to two output notes, native asset, value-conserving.
//!
//! `cargo run --release --bin emit_transfer_v2_fixture`
//! A real multi-party MPC ceremony remains the mainnet gate (#64).

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::CanonicalSerialize;
use paraloom::privacy::circuits::{Groth16ProofSystem, TransferCircuitV2};
use paraloom::privacy::merkle::DEFAULT_TREE_DEPTH;
use paraloom::privacy::onchain_verifier::{fr_to_be, proof_to_wire, verify, WireVerifyingKey};
use paraloom::privacy::poseidon::{
    poseidon_commit_spend, poseidon_merkle_pair, poseidon_nullifier_spend, poseidon_pubkey,
    poseidon_signature,
};
use std::fs;

const NATIVE_SOL: [u8; 32] = [0u8; 32];

fn fr_to_le(f: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let le = f.into_bigint().to_bytes_le();
    out[..le.len().min(32)].copy_from_slice(&le[..le.len().min(32)]);
    out
}

fn rust_bytes(name: &str, b: &[u8]) {
    print!("pub const {name}: [u8; {}] = [", b.len());
    for (i, x) in b.iter().enumerate() {
        if i % 16 == 0 {
            print!("\n    ");
        }
        print!("{x},");
    }
    println!("\n];");
}

/// Spend-key input note: returns (commitment_fr, leaf_index, nullifier_fr).
fn input_note(
    privkey: [u8; 32],
    blinding: [u8; 32],
    amount: u64,
    leaf_index: u64,
) -> (Fr, [u8; 32]) {
    let sk = Fr::from_le_bytes_mod_order(&privkey);
    let commitment = poseidon_commit_spend(
        Fr::from(amount),
        poseidon_pubkey(sk),
        Fr::from_le_bytes_mod_order(&blinding),
        Fr::from(0u64),
    );
    let sig = poseidon_signature(sk, commitment, Fr::from(leaf_index));
    let nullifier = poseidon_nullifier_spend(commitment, Fr::from(leaf_index), sig);
    (commitment, fr_to_le(&nullifier))
}

fn main() {
    let mut rng = ark_std::rand::thread_rng();

    // Setup against the fixed 2-in/2-out, full-depth shape.
    let full_path = vec![([0u8; 32], true); DEFAULT_TREE_DEPTH];
    let setup = TransferCircuitV2::with_witness(
        [0u8; 32],
        vec![[0u8; 32]; 2],
        vec![[0u8; 32]; 2],
        vec![0u64; 2],
        vec![[0u8; 32]; 2],
        vec![[0u8; 32]; 2],
        vec![full_path.clone(), full_path.clone()],
        vec![0u64; 2],
        vec![[0u8; 32]; 2],
        vec![[0u8; 32]; 2],
        NATIVE_SOL,
    );
    let (pk, vk) =
        Groth16ProofSystem::setup::<TransferCircuitV2, _>(setup, &mut rng).expect("setup");

    fs::create_dir_all("keys").unwrap();
    let mut pk_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_bytes).unwrap();
    fs::write("keys/transfer_v2_proving.key", &pk_bytes).unwrap();
    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes).unwrap();
    fs::write("keys/transfer_v2_verifying.key", &vk_bytes).unwrap();

    // Two input notes at leaves 0 and 1 of an otherwise-empty full-depth tree.
    let (c0, nf0) = input_note([9u8; 32], [3u8; 32], 600, 0);
    let (c1, nf1) = input_note([10u8; 32], [4u8; 32], 400, 1);

    // Root: pair the two leaves, then fold up with zero siblings.
    let mut root_fr = poseidon_merkle_pair(c0, c1);
    for _ in 1..DEFAULT_TREE_DEPTH {
        root_fr = poseidon_merkle_pair(root_fr, Fr::from(0u64));
    }
    // leaf 0 is the left child at depth 0 (sibling = c1), left everywhere above.
    let mut path0 = vec![(fr_to_le(&c1), true)];
    path0.extend(vec![([0u8; 32], true); DEFAULT_TREE_DEPTH - 1]);
    // leaf 1 is the right child at depth 0 (sibling = c0), left everywhere above.
    let mut path1 = vec![(fr_to_le(&c0), false)];
    path1.extend(vec![([0u8; 32], true); DEFAULT_TREE_DEPTH - 1]);

    // Two output notes binding recipient spend pubkeys; value-conserving (1000).
    let out_pk0 = poseidon_pubkey(Fr::from_le_bytes_mod_order(&[20u8; 32]));
    let out_pk1 = poseidon_pubkey(Fr::from_le_bytes_mod_order(&[21u8; 32]));
    let oc0 = poseidon_commit_spend(
        Fr::from(700u64),
        out_pk0,
        Fr::from_le_bytes_mod_order(&[5u8; 32]),
        Fr::from(0u64),
    );
    let oc1 = poseidon_commit_spend(
        Fr::from(300u64),
        out_pk1,
        Fr::from_le_bytes_mod_order(&[6u8; 32]),
        Fr::from(0u64),
    );

    let root = fr_to_le(&root_fr);
    let oc0_b = fr_to_le(&oc0);
    let oc1_b = fr_to_le(&oc1);

    let circuit = TransferCircuitV2::with_witness(
        root,
        vec![nf0, nf1],
        vec![oc0_b, oc1_b],
        vec![600, 400],
        vec![[3u8; 32], [4u8; 32]],
        vec![[9u8; 32], [10u8; 32]],
        vec![path0, path1],
        vec![700, 300],
        vec![[5u8; 32], [6u8; 32]],
        vec![fr_to_le(&out_pk0), fr_to_le(&out_pk1)],
        NATIVE_SOL,
    );
    let proof = Groth16ProofSystem::prove(&pk, circuit, &mut rng).expect("prove");

    let wp = proof_to_wire(&proof);
    let wvk = WireVerifyingKey::from_arkworks(&vk);
    let pis = [
        fr_to_be(&root_fr),
        fr_to_be(&Fr::from_le_bytes_mod_order(&nf0)),
        fr_to_be(&Fr::from_le_bytes_mod_order(&nf1)),
        fr_to_be(&oc0),
        fr_to_be(&oc1),
        fr_to_be(&Fr::from_le_bytes_mod_order(&NATIVE_SOL)),
    ];
    assert_eq!(wvk.ic.len(), 7, "transfer v2 VK must have 7 IC points");
    assert!(
        verify(&wp, &pis, &wvk.as_verifying_key()),
        "emitted transfer v2 fixture must verify through alt_bn128"
    );

    println!("\n// ===== transfer v2 verifying key (dev ceremony, spend-key) =====");
    rust_bytes("VK_ALPHA_G1", &wvk.alpha);
    rust_bytes("VK_BETA_G2", &wvk.beta);
    rust_bytes("VK_GAMMA_G2", &wvk.gamma);
    rust_bytes("VK_DELTA_G2", &wvk.delta);
    for (i, ic) in wvk.ic.iter().enumerate() {
        rust_bytes(&format!("VK_IC_{i}"), ic);
    }
    println!("\n// ===== transfer v2 proof fixture =====");
    rust_bytes("FIXTURE_ROOT", &root);
    rust_bytes("FIXTURE_NULLIFIER_0", &nf0);
    rust_bytes("FIXTURE_NULLIFIER_1", &nf1);
    rust_bytes("FIXTURE_COMMITMENT_0", &oc0_b);
    rust_bytes("FIXTURE_COMMITMENT_1", &oc1_b);
    rust_bytes("FIXTURE_ASSET_ID", &NATIVE_SOL);
    rust_bytes("FIXTURE_PROOF_A", &wp.a);
    rust_bytes("FIXTURE_PROOF_B", &wp.b);
    rust_bytes("FIXTURE_PROOF_C", &wp.c);
}
