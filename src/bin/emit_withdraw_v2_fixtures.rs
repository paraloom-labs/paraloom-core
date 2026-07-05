//! Dev tool: emit the on-chain withdraw proof fixtures for the spend-key
//! circuit v2 (#293), bound to the FIXED test vectors the program's
//! integration tests use.
//!
//! The v2 withdraw proof commits to `ext_data_hash` (the destination, finding
//! D) and `asset_id` (the released asset, finding A). A static fixture
//! therefore has to be bound to the exact recipient and asset the tests drive,
//! so the tests must recreate those same accounts. This binary derives them
//! deterministically (the native recipient is a fixed pubkey; the SPL mint and
//! recipient token account come from fixed seeds via `keypair_from_seed`) and
//! prints two fixture modules:
//!
//!   - native  (asset_id = NATIVE_SOL all-zero), for `withdraw` tests
//!   - SPL     (asset_id = the fixed mint pubkey), for `withdraw_spl` tests
//!
//! Run after `setup_withdrawal_ceremony_v2` (needs `keys/withdraw_v2_*.key`):
//! `cargo run --bin emit_withdraw_v2_fixtures > /tmp/fixtures.txt`
//! then paste the two modules into the program crate. The seeds below MUST stay
//! in sync with the integration tests.

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;
use paraloom::privacy::circuits::{Groth16ProofSystem, WithdrawCircuitV2};
use paraloom::privacy::merkle::DEFAULT_TREE_DEPTH;
use paraloom::privacy::onchain_verifier::{fr_to_be, proof_to_wire, WireVerifyingKey};
use paraloom::privacy::poseidon::{
    poseidon_commit_spend, poseidon_merkle_pair, poseidon_nullifier_spend, poseidon_pubkey,
    poseidon_signature,
};
use sha2::{Digest, Sha256};
use solana_sdk::signer::{keypair::keypair_from_seed, Signer};

/// MUST match the integration tests.
const NATIVE_RECIPIENT: [u8; 32] = [
    0x9a, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
];
const SPL_MINT_SEED: [u8; 32] = [11u8; 32];
const SPL_RECIPIENT_TOKEN_SEED: [u8; 32] = [22u8; 32];
const WITHDRAW_AMOUNT: u64 = 1_000_000_000;

/// `ext_data_hash = sha256(recipient_pubkey || amount.to_le_bytes())`, exactly
/// the derivation `withdraw_ext_data_hash` performs on-chain.
fn ext_data_hash(recipient: &[u8; 32], amount: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(recipient);
    h.update(amount.to_le_bytes());
    h.finalize().into()
}

fn rust_bytes(prefix: &str, name: &str, b: &[u8]) {
    print!("pub const {prefix}{name}: [u8; {}] = [", b.len());
    for (i, x) in b.iter().enumerate() {
        if i % 16 == 0 {
            print!("\n    ");
        }
        print!("{x},");
    }
    println!("\n];");
}

/// Build, verify and print one fixture: a spend-key note for `asset_id`
/// withdrawn to `recipient`, at leaf 0 of a full-depth all-left tree.
fn emit_fixture(
    pk: &ProvingKey<Bn254>,
    vk_wire: &WireVerifyingKey,
    prefix: &str,
    asset_id: [u8; 32],
    recipient: [u8; 32],
) {
    let privkey = [9u8; 32];
    let blinding = [3u8; 32];
    let sk = Fr::from_le_bytes_mod_order(&privkey);
    let commitment_fr = poseidon_commit_spend(
        Fr::from(WITHDRAW_AMOUNT),
        poseidon_pubkey(sk),
        Fr::from_le_bytes_mod_order(&blinding),
        Fr::from_le_bytes_mod_order(&asset_id),
    );
    let mut root_fr = commitment_fr;
    for _ in 0..DEFAULT_TREE_DEPTH {
        root_fr = poseidon_merkle_pair(root_fr, Fr::from(0u64));
    }
    let path = vec![([0u8; 32], true); DEFAULT_TREE_DEPTH];
    let leaf_index = 0u64;
    let signature = poseidon_signature(sk, commitment_fr, Fr::from(leaf_index));
    let nullifier_fr = poseidon_nullifier_spend(commitment_fr, Fr::from(leaf_index), signature);

    let edh = ext_data_hash(&recipient, WITHDRAW_AMOUNT);
    let root = fr_to_le(&root_fr);
    let nullifier = fr_to_le(&nullifier_fr);

    let circuit = WithdrawCircuitV2 {
        merkle_root: Some(root),
        nullifier: Some(nullifier),
        withdraw_amount: Some(WITHDRAW_AMOUNT),
        ext_data_hash: Some(edh),
        input_value: Some(WITHDRAW_AMOUNT),
        blinding: Some(blinding),
        privkey: Some(privkey),
        asset_id: Some(asset_id),
        input_path: Some(path),
    };
    let mut rng = ark_std::rand::thread_rng();
    let proof = Groth16ProofSystem::prove(pk, circuit, &mut rng).expect("prove");

    let wp = proof_to_wire(&proof);
    let pis = [
        fr_to_be(&root_fr),
        fr_to_be(&nullifier_fr),
        fr_to_be(&Fr::from(WITHDRAW_AMOUNT)),
        fr_to_be(&Fr::from_le_bytes_mod_order(&edh)),
        fr_to_be(&Fr::from_le_bytes_mod_order(&asset_id)),
    ];
    assert!(
        paraloom::privacy::onchain_verifier::verify(&wp, &pis, &vk_wire.as_verifying_key()),
        "emitted fixture must verify through alt_bn128"
    );

    rust_bytes(prefix, "ROOT", &root);
    rust_bytes(prefix, "NULLIFIER", &nullifier);
    println!("pub const {prefix}AMOUNT: u64 = {WITHDRAW_AMOUNT};");
    rust_bytes(prefix, "EXT_DATA_HASH", &edh);
    rust_bytes(prefix, "ASSET_ID", &asset_id);
    rust_bytes(prefix, "RECIPIENT", &recipient);
    rust_bytes(prefix, "PROOF_A", &wp.a);
    rust_bytes(prefix, "PROOF_B", &wp.b);
    rust_bytes(prefix, "PROOF_C", &wp.c);
}

fn fr_to_le(f: &Fr) -> [u8; 32] {
    use ark_ff::BigInteger;
    let mut out = [0u8; 32];
    let le = f.into_bigint().to_bytes_le();
    out[..le.len().min(32)].copy_from_slice(&le[..le.len().min(32)]);
    out
}

fn main() {
    // Key paths default to the repo v2 keys but can be overridden via env so the
    // same prove+verify round-trip can validate ceremony-produced keys (point
    // these at a finalized ceremony output to confirm it produces on-chain-
    // verifiable proofs before trusting the chain).
    let pk_path = std::env::var("WITHDRAW_V2_PROVING_KEY")
        .unwrap_or_else(|_| "keys/withdraw_v2_proving.key".to_string());
    let vk_path = std::env::var("WITHDRAW_V2_VERIFYING_KEY")
        .unwrap_or_else(|_| "keys/withdraw_v2_verifying.key".to_string());
    let pk_bytes = std::fs::read(&pk_path).expect("v2 proving key");
    let vk_bytes = std::fs::read(&vk_path).expect("v2 verifying key");
    let pk = ProvingKey::<Bn254>::deserialize_compressed(&pk_bytes[..]).unwrap();
    let vk = ark_groth16::VerifyingKey::<Bn254>::deserialize_compressed(&vk_bytes[..]).unwrap();
    let vk_wire = WireVerifyingKey::from_arkworks(&vk);

    let mint = keypair_from_seed(&SPL_MINT_SEED).unwrap();
    let recipient_token = keypair_from_seed(&SPL_RECIPIENT_TOKEN_SEED).unwrap();

    println!("// ===== native withdraw v2 fixture (asset_id = NATIVE_SOL) =====");
    println!("// recipient = fixed pubkey NATIVE_RECIPIENT in the tests");
    emit_fixture(&pk, &vk_wire, "FIXTURE_", [0u8; 32], NATIVE_RECIPIENT);

    println!("\n// ===== SPL withdraw v2 fixture =====");
    println!("// mint = keypair_from_seed([11;32]), recipient_token = keypair_from_seed([22;32])");
    println!("// SPL_FIXTURE_MINT = {}", mint.pubkey());
    println!(
        "// SPL_FIXTURE_RECIPIENT_TOKEN = {}",
        recipient_token.pubkey()
    );
    emit_fixture(
        &pk,
        &vk_wire,
        "SPL_FIXTURE_",
        mint.pubkey().to_bytes(),
        recipient_token.pubkey().to_bytes(),
    );
}
