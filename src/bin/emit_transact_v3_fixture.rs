//! Dev tool: single-party setup of the v3 unified transact circuit and emit of
//! its on-chain verifying key + a proof fixture (circuit v3, #350).
//!
//! Prints the constants to paste into `programs/paraloom/src/transact_vk_data.rs`
//! (9 IC points for the 8 public inputs `[root, public_amount, ext_data_hash,
//! asset_id, nullifier0, nullifier1, out_commitment0, out_commitment1]`) and
//! `transact_fixture_data.rs`. A real multi-party ceremony on this circuit
//! remains the mainnet gate (#64); these are dev keys for devnet.
//!
//! `cargo run --release --bin emit_transact_v3_fixture`

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use paraloom::privacy::circuits::{Groth16ProofSystem, TransactCircuitV3, TX_LEVELS};
use paraloom::privacy::onchain_verifier::{fr_to_be, proof_to_wire, verify, WireVerifyingKey};
use paraloom::privacy::poseidon_circom::{
    v3_commit, v3_merkle_pair, v3_nullifier, v3_pubkey, v3_signature,
};

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

/// Empty-subtree hashes under the v3 Merkle hash.
fn zeros() -> Vec<Fr> {
    let mut z = vec![Fr::from(0u64)];
    for k in 0..TX_LEVELS {
        z.push(v3_merkle_pair(z[k], z[k]));
    }
    z
}

/// Root + path for `leaf` at index 0 of an otherwise-empty tree (all-left
/// fold; every sibling is a zero-subtree hash).
fn member_root_and_path(leaf: Fr) -> (Fr, Vec<[u8; 32]>) {
    let z = zeros();
    let mut current = leaf;
    for zi in z.iter().take(TX_LEVELS) {
        current = v3_merkle_pair(current, *zi);
    }
    let path = z[..TX_LEVELS].iter().map(fr_to_le).collect();
    (current, path)
}

fn main() {
    // A spend: one real 1000-unit input at leaf 0 + one zero dummy, two outputs
    // (400 + 100), so 500 is withdrawn via public_amount = 500 − 1000 = −500.
    const IN_AMOUNT: u64 = 1000;
    const OUT0: u64 = 400;
    const OUT1: u64 = 100;
    let asset = Fr::from(0u64); // NATIVE_SOL
    let ext_data_hash = [7u8; 32];

    // Real input note.
    let sk0 = Fr::from(51u64);
    let bl0 = Fr::from(5u64);
    let pk0 = v3_pubkey(sk0);
    let c0 = v3_commit(Fr::from(IN_AMOUNT), pk0, bl0, asset);
    let sig0 = v3_signature(sk0, c0, Fr::from(0u64));
    let nf0 = v3_nullifier(c0, Fr::from(0u64), sig0);
    let (root_fr, path0) = member_root_and_path(c0);

    // Dummy input (amount 0; membership skipped).
    let sk1 = Fr::from(52u64);
    let bl1 = Fr::from(6u64);
    let pk1 = v3_pubkey(sk1);
    let c1 = v3_commit(Fr::from(0u64), pk1, bl1, asset);
    let sig1 = v3_signature(sk1, c1, Fr::from(0u64));
    let nf1 = v3_nullifier(c1, Fr::from(0u64), sig1);
    let dummy_path: Vec<[u8; 32]> = zeros()[..TX_LEVELS].iter().map(fr_to_le).collect();

    // Outputs.
    let opk0 = v3_pubkey(Fr::from(61u64));
    let opk1 = v3_pubkey(Fr::from(62u64));
    let obl0 = Fr::from(1u64);
    let obl1 = Fr::from(2u64);
    let oc0 = v3_commit(Fr::from(OUT0), opk0, obl0, asset);
    let oc1 = v3_commit(Fr::from(OUT1), opk1, obl1, asset);

    let public_amount = Fr::from(OUT0 + OUT1) - Fr::from(IN_AMOUNT);

    let circuit = TransactCircuitV3 {
        root: Some(fr_to_le(&root_fr)),
        public_amount: Some(fr_to_le(&public_amount)),
        ext_data_hash: Some(ext_data_hash),
        asset_id: Some(fr_to_le(&asset)),
        input_nullifiers: vec![Some(fr_to_le(&nf0)), Some(fr_to_le(&nf1))],
        output_commitments: vec![Some(fr_to_le(&oc0)), Some(fr_to_le(&oc1))],
        in_amounts: vec![Some(IN_AMOUNT), Some(0)],
        in_privkeys: vec![Some(fr_to_le(&sk0)), Some(fr_to_le(&sk1))],
        in_blindings: vec![Some(fr_to_le(&bl0)), Some(fr_to_le(&bl1))],
        in_leaf_indices: vec![Some(0), Some(0)],
        in_paths: vec![Some(path0), Some(dummy_path)],
        out_amounts: vec![Some(OUT0), Some(OUT1)],
        out_pubkeys: vec![Some(fr_to_le(&opk0)), Some(fr_to_le(&opk1))],
        out_blindings: vec![Some(fr_to_le(&obl0)), Some(fr_to_le(&obl1))],
    };

    let mut rng = ark_std::rand::thread_rng();
    let (pk, vk) =
        Groth16ProofSystem::setup(TransactCircuitV3::blank(), &mut rng).expect("setup dev keys");
    let proof = Groth16ProofSystem::prove(&pk, circuit, &mut rng).expect("prove");

    let wvk = WireVerifyingKey::from_arkworks(&vk);
    let wp = proof_to_wire(&proof);

    // Public inputs in the circuit's new_input order.
    let pis = [
        fr_to_be(&root_fr),
        fr_to_be(&public_amount),
        fr_to_be(&Fr::from_le_bytes_mod_order(&ext_data_hash)),
        fr_to_be(&asset),
        fr_to_be(&nf0),
        fr_to_be(&nf1),
        fr_to_be(&oc0),
        fr_to_be(&oc1),
    ];
    assert_eq!(wvk.ic.len(), 9, "transact v3 VK must have 9 IC points");
    assert!(
        verify(&wp, &pis, &wvk.as_verifying_key()),
        "emitted transact v3 fixture must verify through alt_bn128"
    );

    println!("// ===== transact v3 verifying key (dev, single-party) =====");
    rust_bytes("VK_ALPHA_G1", &wvk.alpha);
    rust_bytes("VK_BETA_G2", &wvk.beta);
    rust_bytes("VK_GAMMA_G2", &wvk.gamma);
    rust_bytes("VK_DELTA_G2", &wvk.delta);
    for (i, ic) in wvk.ic.iter().enumerate() {
        rust_bytes(&format!("VK_IC_{i}"), ic);
    }

    println!("\n// ===== transact v3 proof fixture =====");
    rust_bytes("FIXTURE_ROOT", &fr_to_le(&root_fr));
    rust_bytes("FIXTURE_PUBLIC_AMOUNT", &fr_to_le(&public_amount));
    rust_bytes("FIXTURE_EXT_DATA_HASH", &ext_data_hash);
    rust_bytes("FIXTURE_ASSET_ID", &fr_to_le(&asset));
    rust_bytes("FIXTURE_NULLIFIER_0", &fr_to_le(&nf0));
    rust_bytes("FIXTURE_NULLIFIER_1", &fr_to_le(&nf1));
    rust_bytes("FIXTURE_COMMITMENT_0", &fr_to_le(&oc0));
    rust_bytes("FIXTURE_COMMITMENT_1", &fr_to_le(&oc1));
    rust_bytes("FIXTURE_PROOF_A", &wp.a);
    rust_bytes("FIXTURE_PROOF_B", &wp.b);
    rust_bytes("FIXTURE_PROOF_C", &wp.c);
}
