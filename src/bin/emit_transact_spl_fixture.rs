//! Dev tool: emit an SPL-asset proof fixture for the v3 transact circuit, used
//! by the on-chain `transact_spl` e2e test (#779).
//!
//! Identical circuit, proving key and verifying key as the native transact
//! fixture (`emit_transact_v3_fixture`) — only the `asset` public input changes
//! from the all-zero native asset to `Fr::from_le_bytes_mod_order(mint_bytes)`,
//! and the bound recipient is the payout **token account** address (what
//! `transact_spl` feeds to `transact_ext_data_hash`). Because the circuit is
//! asset-aware and the VK is unchanged, no new ceremony or VK constants are
//! needed; this only emits the `SPL_FIXTURE_*` proof + public-input constants
//! for `transact_spl_fixture_data.rs`.
//!
//! `cargo run --release --bin emit_transact_spl_fixture`

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use paraloom::privacy::circuits::{Groth16ProofSystem, TransactCircuitV3, TX_LEVELS};
use paraloom::privacy::onchain_verifier::{fr_to_be, proof_to_wire, verify, WireVerifyingKey};
use paraloom::privacy::poseidon_circom::{
    v3_commit, v3_merkle_pair, v3_nullifier, v3_pubkey, v3_signature,
};

/// The shielded SPL mint this fixture withdraws. Arbitrary fixed bytes; the
/// on-chain test bakes a mint account at exactly this address so the derived
/// asset field element matches.
const MINT: [u8; 32] = [0x11; 32];
/// The payout token account address, bound into the proof via `ext_data_hash`.
const RECIPIENT_TOKEN_ACCOUNT: [u8; 32] = [0x22; 32];

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

fn zeros() -> Vec<Fr> {
    let mut z = vec![Fr::from(0u64)];
    for k in 0..TX_LEVELS {
        z.push(v3_merkle_pair(z[k], z[k]));
    }
    z
}

fn member_root_and_path(leaf: Fr) -> (Fr, Vec<[u8; 32]>) {
    let z = zeros();
    let mut current = leaf;
    for zi in z.iter().take(TX_LEVELS) {
        current = v3_merkle_pair(current, *zi);
    }
    let path = z[..TX_LEVELS].iter().map(fr_to_le).collect();
    (current, path)
}

fn transact_ext_data_hash(recipient: &[u8; 32], ext_amount: i64) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(recipient);
    hasher.update(ext_amount.to_le_bytes());
    hasher.finalize().into()
}

fn main() {
    const IN_AMOUNT: u64 = 1000;
    const OUT0: u64 = 400;
    const OUT1: u64 = 100;
    const EXT_AMOUNT: i64 = -500;

    // The asset field element: Poseidon(2) over the mint's two 16-byte
    // little-endian halves, matching the on-chain `merkle_tree::mint_to_asset`.
    // A raw mint pubkey is usually non-canonical (>= p) and Poseidon rejects it,
    // so we hash two independently-canonical halves into a canonical, collision-
    // resistant asset id. `v3_merkle_pair` is the circuit's Poseidon(2), proven
    // bit-identical to the on-chain `poseidon2`.
    let mint_lo = Fr::from_le_bytes_mod_order(&MINT[..16]);
    let mint_hi = Fr::from_le_bytes_mod_order(&MINT[16..]);
    let asset = v3_merkle_pair(mint_lo, mint_hi);
    let ext_data_hash = transact_ext_data_hash(&RECIPIENT_TOKEN_ACCOUNT, EXT_AMOUNT);

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

    // Outputs (same asset).
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

    // The SAME ceremony keys the on-chain transact VK was emitted from. A proof
    // for a non-zero asset still verifies against that unchanged VK because the
    // circuit is asset-aware.
    let pk_path = std::env::var("TRANSACT_V3_PROVING_KEY")
        .unwrap_or_else(|_| "keys/transact_v3_proving.key".to_string());
    let vk_path = std::env::var("TRANSACT_V3_VERIFYING_KEY")
        .unwrap_or_else(|_| "keys/transact_v3_verifying.key".to_string());

    use ark_serialize::CanonicalDeserialize;
    let pk_bytes = std::fs::read(&pk_path).expect("read transact v3 proving key (ceremony)");
    let vk_bytes = std::fs::read(&vk_path).expect("read transact v3 verifying key (ceremony)");
    let pk = ark_groth16::ProvingKey::<ark_bn254::Bn254>::deserialize_compressed(&pk_bytes[..])
        .expect("deserialize proving key");
    let vk = ark_groth16::VerifyingKey::<ark_bn254::Bn254>::deserialize_compressed(&vk_bytes[..])
        .expect("deserialize verifying key");
    eprintln!("loaded ceremony keys from {pk_path}");

    let mut rng = ark_std::rand::thread_rng();
    let proof = Groth16ProofSystem::prove(&pk, circuit, &mut rng).expect("prove");

    let wvk = WireVerifyingKey::from_arkworks(&vk);
    let wp = proof_to_wire(&proof);

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
    assert!(
        verify(&wp, &pis, &wvk.as_verifying_key()),
        "emitted transact SPL fixture must verify through alt_bn128 against the ceremony VK"
    );

    println!("//! SPL-asset proof fixture for the v3 transact circuit (#779), emitted by");
    println!("//! `emit_transact_spl_fixture` from the ceremony keys. Same circuit + VK as");
    println!("//! the native `transact_fixture_data`; only `asset` and the bound recipient");
    println!("//! (a payout token account) differ. Withdraws 500 of `SPL_FIXTURE_MINT`.");
    println!("#![allow(dead_code)]\n");
    rust_bytes("SPL_FIXTURE_MINT", &MINT);
    rust_bytes(
        "SPL_FIXTURE_RECIPIENT_TOKEN_ACCOUNT",
        &RECIPIENT_TOKEN_ACCOUNT,
    );
    rust_bytes("SPL_FIXTURE_ROOT", &fr_to_le(&root_fr));
    rust_bytes("SPL_FIXTURE_ASSET_ID", &fr_to_le(&asset));
    rust_bytes("SPL_FIXTURE_NULLIFIER_0", &fr_to_le(&nf0));
    rust_bytes("SPL_FIXTURE_NULLIFIER_1", &fr_to_le(&nf1));
    rust_bytes("SPL_FIXTURE_COMMITMENT_0", &fr_to_le(&oc0));
    rust_bytes("SPL_FIXTURE_COMMITMENT_1", &fr_to_le(&oc1));
    rust_bytes("SPL_FIXTURE_PROOF_A", &wp.a);
    rust_bytes("SPL_FIXTURE_PROOF_B", &wp.b);
    rust_bytes("SPL_FIXTURE_PROOF_C", &wp.c);
    println!("pub const SPL_FIXTURE_DEPOSIT_AMOUNT: u64 = {IN_AMOUNT};");
    rust_bytes("SPL_FIXTURE_DEPOSIT_PUBKEY", &fr_to_le(&pk0));
    rust_bytes("SPL_FIXTURE_DEPOSIT_BLINDING", &fr_to_le(&bl0));
    println!("pub const SPL_FIXTURE_EXT_AMOUNT: i64 = {EXT_AMOUNT};");
}
