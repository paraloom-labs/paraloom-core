//! On-chain Groth16 verification bridge (BN254 / `alt_bn128`).
//!
//! The Solana program verifies withdrawal/transfer proofs on-chain using the
//! `alt_bn128` syscalls (the same path Light Protocol's `groth16-solana` and
//! Privacy Cash use). Those syscalls expect a specific wire encoding that
//! differs from arkworks' native serialization:
//!
//! - coordinates are **big-endian** (arkworks is little-endian),
//! - G2 `Fp2` coordinates are ordered `c1` then `c0` (arkworks emits `c0`
//!   then `c1`),
//! - `proof_a` is the **negated** G1 point (the pairing check folds the
//!   negation into A rather than into the result).
//!
//! This module converts an arkworks `Proof`/`VerifyingKey` over BN254 into
//! that wire form and verifies it through a vendored copy of the
//! `groth16-solana` verifier, so the exact bytes the program will see are
//! exercised off-chain first. The program (#165) reuses the identical
//! encoding.

use ark_bn254::{Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use num_bigint::BigUint;
use solana_bn254::prelude::{alt_bn128_addition, alt_bn128_multiplication, alt_bn128_pairing};
use std::ops::Neg;

// ──────────────────────────────────────────────────────────────────────────
// arkworks → alt_bn128 wire encoding
// ──────────────────────────────────────────────────────────────────────────

/// Reverse a 32-byte coordinate in place (little-endian ↔ big-endian).
fn rev32(src: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in src.iter().take(32).rev().enumerate() {
        out[i] = *b;
    }
    out
}

/// G1 point → 64-byte big-endian `[x || y]`.
fn g1_to_wire(p: &G1Affine) -> [u8; 64] {
    // arkworks uncompressed G1 = `x_le(32) || y_le(32)`.
    let mut le = Vec::with_capacity(64);
    p.serialize_uncompressed(&mut le)
        .expect("G1 serialize_uncompressed is infallible for a valid point");
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&rev32(&le[..32])); // x big-endian
    out[32..].copy_from_slice(&rev32(&le[32..64])); // y big-endian
    out
}

/// G2 point → 128-byte big-endian `[x.c1 || x.c0 || y.c1 || y.c0]`.
fn g2_to_wire(p: &G2Affine) -> [u8; 128] {
    // arkworks uncompressed G2 = `x.c0_le || x.c1_le || y.c0_le || y.c1_le`.
    // alt_bn128 wants `x.c1_be || x.c0_be || y.c1_be || y.c0_be`.
    let mut le = Vec::with_capacity(128);
    p.serialize_uncompressed(&mut le)
        .expect("G2 serialize_uncompressed is infallible for a valid point");
    let mut out = [0u8; 128];
    out[..32].copy_from_slice(&rev32(&le[32..64])); // x.c1
    out[32..64].copy_from_slice(&rev32(&le[..32])); // x.c0
    out[64..96].copy_from_slice(&rev32(&le[96..128])); // y.c1
    out[96..].copy_from_slice(&rev32(&le[64..96])); // y.c0
    out
}

/// A field element → 32-byte big-endian, as the verifier expects each public
/// input.
pub fn fr_to_be(f: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let be = f.into_bigint().to_bytes_be(); // BN254 Fr is 32 bytes
    out[32 - be.len()..].copy_from_slice(&be);
    out
}

/// The three proof points in wire form. `proof_a` is already negated, so the
/// verifier can use it directly (matches the `groth16-solana` convention).
pub struct WireProof {
    pub a: [u8; 64],
    pub b: [u8; 128],
    pub c: [u8; 64],
}

/// Convert an arkworks Groth16 proof to the `alt_bn128` wire form, negating A.
pub fn proof_to_wire(proof: &Proof<ark_bn254::Bn254>) -> WireProof {
    WireProof {
        a: g1_to_wire(&proof.a.neg()),
        b: g2_to_wire(&proof.b),
        c: g1_to_wire(&proof.c),
    }
}

impl WireProof {
    /// The 256-byte on-chain submission blob: `a(64) || b(128) || c(64)`. This
    /// is exactly what the program's `withdraw_verifier` slices and verifies.
    pub fn to_bytes(&self) -> [u8; 256] {
        let mut out = [0u8; 256];
        out[..64].copy_from_slice(&self.a);
        out[64..192].copy_from_slice(&self.b);
        out[192..].copy_from_slice(&self.c);
        out
    }
}

/// Serialize an arkworks Groth16 proof into the 256-byte on-chain wire blob.
/// Callers building the `withdraw` / `shielded_transfer` instruction pass this
/// instead of the arkworks-compressed encoding.
pub fn proof_to_onchain_bytes(proof: &Proof<ark_bn254::Bn254>) -> [u8; 256] {
    proof_to_wire(proof).to_bytes()
}

/// Deserialize an arkworks-compressed BN254 proof and re-encode it as the
/// 256-byte on-chain wire blob. Used at the submission boundary, where the
/// node/relayer holds the prover's compressed proof and must hand the program
/// the wire form it verifies.
pub fn compressed_proof_to_onchain_bytes(
    compressed: &[u8],
) -> Result<[u8; 256], ark_serialize::SerializationError> {
    use ark_serialize::CanonicalDeserialize;
    let proof = Proof::<ark_bn254::Bn254>::deserialize_compressed(compressed)?;
    Ok(proof_to_onchain_bytes(&proof))
}

/// A verifying key in the byte layout the vendored verifier consumes. Owns the
/// IC vector so the borrowed [`Groth16Verifyingkey`] can point into it.
pub struct WireVerifyingKey {
    pub alpha: [u8; 64],
    pub beta: [u8; 128],
    pub gamma: [u8; 128],
    pub delta: [u8; 128],
    pub ic: Vec<[u8; 64]>,
}

impl WireVerifyingKey {
    pub fn from_arkworks(vk: &VerifyingKey<ark_bn254::Bn254>) -> Self {
        WireVerifyingKey {
            alpha: g1_to_wire(&vk.alpha_g1),
            beta: g2_to_wire(&vk.beta_g2),
            gamma: g2_to_wire(&vk.gamma_g2),
            delta: g2_to_wire(&vk.delta_g2),
            ic: vk.gamma_abc_g1.iter().map(g1_to_wire).collect(),
        }
    }

    /// Borrowed view matching the vendored verifier's `'static`-style struct.
    pub fn as_verifying_key(&self) -> Groth16Verifyingkey<'_> {
        Groth16Verifyingkey {
            nr_pubinputs: self.ic.len().saturating_sub(1),
            vk_alpha_g1: self.alpha,
            vk_beta_g2: self.beta,
            vk_gamme_g2: self.gamma,
            vk_delta_g2: self.delta,
            vk_ic: &self.ic,
        }
    }
}

/// Verify a wire-form proof against `public_inputs` (each 32-byte big-endian).
pub fn verify<const N: usize>(
    proof: &WireProof,
    public_inputs: &[[u8; 32]; N],
    vk: &Groth16Verifyingkey,
) -> bool {
    match Groth16Verifier::new(&proof.a, &proof.b, &proof.c, public_inputs, vk) {
        Ok(mut v) => v.verify().unwrap_or(false),
        Err(_) => false,
    }
}

// ──────────────────────────────────────────────────────────────────────────
// Vendored `groth16-solana` verifier.
// Source: https://github.com/Lightprotocol/groth16-solana (MIT), trimmed.
// The on-chain program (#165) vendors the same code.
// ──────────────────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub enum Groth16Error {
    InvalidG1Length,
    InvalidG2Length,
    InvalidPublicInputsLength,
    PublicInputGreaterThanFieldSize,
    PreparingInputsG1MulFailed,
    PreparingInputsG1AdditionFailed,
    ProofVerificationFailed,
}

#[derive(PartialEq, Eq, Debug)]
pub struct Groth16Verifyingkey<'a> {
    pub nr_pubinputs: usize,
    pub vk_alpha_g1: [u8; 64],
    pub vk_beta_g2: [u8; 128],
    pub vk_gamme_g2: [u8; 128],
    pub vk_delta_g2: [u8; 128],
    pub vk_ic: &'a [[u8; 64]],
}

pub struct Groth16Verifier<'a, const NR_INPUTS: usize> {
    proof_a: &'a [u8; 64],
    proof_b: &'a [u8; 128],
    proof_c: &'a [u8; 64],
    public_inputs: &'a [[u8; 32]; NR_INPUTS],
    prepared_public_inputs: [u8; 64],
    verifyingkey: &'a Groth16Verifyingkey<'a>,
}

impl<const NR_INPUTS: usize> Groth16Verifier<'_, NR_INPUTS> {
    pub fn new<'a>(
        proof_a: &'a [u8; 64],
        proof_b: &'a [u8; 128],
        proof_c: &'a [u8; 64],
        public_inputs: &'a [[u8; 32]; NR_INPUTS],
        verifyingkey: &'a Groth16Verifyingkey<'a>,
    ) -> Result<Groth16Verifier<'a, NR_INPUTS>, Groth16Error> {
        if public_inputs.len() + 1 != verifyingkey.vk_ic.len() {
            return Err(Groth16Error::InvalidPublicInputsLength);
        }
        Ok(Groth16Verifier {
            proof_a,
            proof_b,
            proof_c,
            public_inputs,
            prepared_public_inputs: [0u8; 64],
            verifyingkey,
        })
    }

    fn prepare_inputs(&mut self) -> Result<(), Groth16Error> {
        let mut prepared = self.verifyingkey.vk_ic[0];
        for (i, input) in self.public_inputs.iter().enumerate() {
            if !is_less_than_bn254_field_size_be(input) {
                return Err(Groth16Error::PublicInputGreaterThanFieldSize);
            }
            let mul_res = alt_bn128_multiplication(
                &[&self.verifyingkey.vk_ic[i + 1][..], &input[..]].concat(),
            )
            .map_err(|_| Groth16Error::PreparingInputsG1MulFailed)?;
            prepared = alt_bn128_addition(&[&mul_res[..], &prepared[..]].concat())
                .map_err(|_| Groth16Error::PreparingInputsG1AdditionFailed)?[..]
                .try_into()
                .map_err(|_| Groth16Error::PreparingInputsG1AdditionFailed)?;
        }
        self.prepared_public_inputs = prepared;
        Ok(())
    }

    pub fn verify(&mut self) -> Result<bool, Groth16Error> {
        self.prepare_inputs()?;
        let pairing_input = [
            self.proof_a.as_slice(),
            self.proof_b.as_slice(),
            self.prepared_public_inputs.as_slice(),
            self.verifyingkey.vk_gamme_g2.as_slice(),
            self.proof_c.as_slice(),
            self.verifyingkey.vk_delta_g2.as_slice(),
            self.verifyingkey.vk_alpha_g1.as_slice(),
            self.verifyingkey.vk_beta_g2.as_slice(),
        ]
        .concat();
        let res = alt_bn128_pairing(pairing_input.as_slice())
            .map_err(|_| Groth16Error::ProofVerificationFailed)?;
        if !pairing_result_is_identity(&res) {
            return Err(Groth16Error::ProofVerificationFailed);
        }
        Ok(true)
    }
}

fn pairing_result_is_identity(res: &[u8]) -> bool {
    res.len() == 32 && res[..31].iter().all(|&b| b == 0) && res[31] == 1
}

fn is_less_than_bn254_field_size_be(bytes: &[u8; 32]) -> bool {
    BigUint::from_bytes_be(bytes) < Fr::MODULUS.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::circuits::Groth16ProofSystem;
    use ark_std::rand::thread_rng;

    fn fr_to_le_bytes_32(f: Fr) -> [u8; 32] {
        let mut out = [0u8; 32];
        let le = f.into_bigint().to_bytes_le();
        out[..le.len().min(32)].copy_from_slice(&le[..le.len().min(32)]);
        out
    }

    #[test]
    fn pairing_result_identity_requires_exact_big_endian_one() {
        let mut valid = [0u8; 32];
        valid[31] = 1;
        assert!(pairing_result_is_identity(&valid));

        let mut nonzero_high_byte = valid;
        nonzero_high_byte[0] = 1;
        assert!(!pairing_result_is_identity(&nonzero_high_byte));
        assert!(!pairing_result_is_identity(&[0u8; 32]));
        assert!(!pairing_result_is_identity(&valid[..31]));
    }

    /// The v2 (spend-key) withdraw circuit verified through the same vendored
    /// `alt_bn128` path the Solana program runs. This pins the v2 on-chain
    /// public-input layout — `[merkle_root, nullifier, withdraw_amount,
    /// ext_data_hash, asset_id]`, 5 inputs → 6 IC points — and proves both the
    /// asset binding (finding A) and the destination binding (finding D) hold
    /// through the wire verifier, not just the native arkworks one. Self-contained
    /// inline setup, so it needs no `keys/`.
    #[test]
    fn withdraw_v2_verifies_through_alt_bn128_with_asset_and_ext_data_bound() {
        use crate::privacy::circuits::WithdrawCircuitV2;
        use crate::privacy::poseidon::{
            poseidon_commit_spend, poseidon_merkle_pair, poseidon_nullifier_spend, poseidon_pubkey,
            poseidon_signature,
        };

        // A note owned by `privkey`, native asset, at tree position 2
        // (path = left@depth0, right@depth1), withdrawing 500 of 1000.
        let privkey = [6u8; 32];
        let blinding = [3u8; 32];
        let asset = [0u8; 32];
        let input_value = 1_000u64;
        let withdraw_amount = 500u64;
        let ext_data_hash = [0x42u8; 32];

        let sk = Fr::from_le_bytes_mod_order(&privkey);
        let commitment_fr = poseidon_commit_spend(
            Fr::from(input_value),
            poseidon_pubkey(sk),
            Fr::from_le_bytes_mod_order(&blinding),
            Fr::from_le_bytes_mod_order(&asset),
        );
        let sibling_0 = [4u8; 32];
        let sibling_1 = [5u8; 32];
        let level_1 = poseidon_merkle_pair(commitment_fr, Fr::from_le_bytes_mod_order(&sibling_0));
        let merkle_root_fr = poseidon_merkle_pair(Fr::from_le_bytes_mod_order(&sibling_1), level_1);
        let path = vec![(sibling_0, true), (sibling_1, false)];
        let leaf_index = 2u64;

        let signature = poseidon_signature(sk, commitment_fr, Fr::from(leaf_index));
        let nullifier_fr = poseidon_nullifier_spend(commitment_fr, Fr::from(leaf_index), signature);

        let merkle_root = fr_to_le_bytes_32(merkle_root_fr);
        let nullifier = fr_to_le_bytes_32(nullifier_fr);

        let mk = |p: Vec<([u8; 32], bool)>| WithdrawCircuitV2 {
            merkle_root: Some(merkle_root),
            nullifier: Some(nullifier),
            withdraw_amount: Some(withdraw_amount),
            ext_data_hash: Some(ext_data_hash),
            input_value: Some(input_value),
            blinding: Some(blinding),
            privkey: Some(privkey),
            asset_id: Some(asset),
            input_path: Some(p),
        };

        let mut rng = thread_rng();
        let (pk, vk) = Groth16ProofSystem::setup(mk(path.clone()), &mut rng).expect("setup");
        let proof = Groth16ProofSystem::prove(&pk, mk(path.clone()), &mut rng).expect("prove");

        // On-chain public-input order matches the circuit's new_input order.
        let public_inputs: [[u8; 32]; 5] = [
            fr_to_be(&merkle_root_fr),
            fr_to_be(&nullifier_fr),
            fr_to_be(&Fr::from(withdraw_amount)),
            fr_to_be(&Fr::from_le_bytes_mod_order(&ext_data_hash)),
            fr_to_be(&Fr::from_le_bytes_mod_order(&asset)),
        ];

        let wire_proof = proof_to_wire(&proof);
        let wire_vk = WireVerifyingKey::from_arkworks(&vk);
        let vk_view = wire_vk.as_verifying_key();

        assert_eq!(wire_vk.ic.len(), 6, "withdraw v2 VK must have 6 IC points");
        assert!(
            verify(&wire_proof, &public_inputs, &vk_view),
            "valid v2 withdrawal proof must verify through the alt_bn128 path"
        );

        // A different asset_id (finding A) must not verify.
        let mut bad_asset = public_inputs;
        bad_asset[4] = fr_to_be(&Fr::from_le_bytes_mod_order(&[0xCCu8; 32]));
        assert!(
            !verify(&wire_proof, &bad_asset, &vk_view),
            "a proof claimed for a different asset_id must not verify"
        );

        // A redirected destination (finding D) must not verify.
        let mut bad_dest = public_inputs;
        bad_dest[3] = fr_to_be(&Fr::from_le_bytes_mod_order(&[0x43u8; 32]));
        assert!(
            !verify(&wire_proof, &bad_dest, &vk_view),
            "a proof bound to one ext_data_hash must not verify against another"
        );
    }

    /// Dev tool — regenerates the on-chain program's withdraw verifying-key
    /// constant and proof fixture for the **spend-key v2** circuit (#293). Loads
    /// the v2 ceremony keys produced by `setup_withdrawal_ceremony_v2`, builds a
    /// proof in the 5-input layout `[merkle_root, nullifier, withdraw_amount,
    /// ext_data_hash, asset_id]` (6 IC points), and prints the constants to paste
    /// into `programs/paraloom/src/withdraw_vk_data.rs` at cutover. Run with:
    /// `cargo test --lib privacy::onchain_verifier::tests::emit_program_fixture_v2 \
    ///   -- --ignored --nocapture`
    #[test]
    #[ignore = "dev fixture generator; needs keys/withdraw_v2_*.key locally"]
    fn emit_program_fixture_v2() {
        use crate::privacy::circuits::WithdrawCircuitV2;
        use crate::privacy::merkle::DEFAULT_TREE_DEPTH;
        use crate::privacy::poseidon::{
            poseidon_commit_spend, poseidon_merkle_pair, poseidon_nullifier_spend, poseidon_pubkey,
            poseidon_signature,
        };
        use ark_bn254::Bn254;
        use ark_groth16::{ProvingKey, VerifyingKey};
        use ark_serialize::CanonicalDeserialize;

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

        // Key paths default to the repo dev keys but can be overridden via env,
        // so this same generator can regenerate withdraw_vk_data.rs from a
        // finalized CEREMONY verifying key at cutover (point the env vars at the
        // ceremony output and check the emitted constants compile + verify).
        let pk_path = std::env::var("WITHDRAW_V2_PROVING_KEY")
            .unwrap_or_else(|_| "keys/withdraw_v2_proving.key".to_string());
        let vk_path = std::env::var("WITHDRAW_V2_VERIFYING_KEY")
            .unwrap_or_else(|_| "keys/withdraw_v2_verifying.key".to_string());
        let pk_bytes = std::fs::read(&pk_path).expect("v2 proving key");
        let vk_bytes = std::fs::read(&vk_path).expect("v2 verifying key");
        let pk = ProvingKey::<Bn254>::deserialize_compressed(&pk_bytes[..]).unwrap();
        let vk = VerifyingKey::<Bn254>::deserialize_compressed(&vk_bytes[..]).unwrap();

        // A spend-key note (1 SOL, native asset) at leaf 0 of a full-depth tree:
        // all-left path with zero siblings, so leaf_index = 0 and the root folds
        // the commitment up DEFAULT_TREE_DEPTH levels. The pool stores v1
        // commitments, so the v2 leaf is built directly here.
        let privkey = [9u8; 32];
        let blinding = [3u8; 32];
        let asset = [0u8; 32];
        let value = 1_000_000_000u64;
        let ext_data_hash = [0x11u8; 32];

        let sk = Fr::from_le_bytes_mod_order(&privkey);
        let commitment_fr = poseidon_commit_spend(
            Fr::from(value),
            poseidon_pubkey(sk),
            Fr::from_le_bytes_mod_order(&blinding),
            Fr::from_le_bytes_mod_order(&asset),
        );
        let zero_sibling = Fr::from(0u64);
        let mut root_fr = commitment_fr;
        for _ in 0..DEFAULT_TREE_DEPTH {
            root_fr = poseidon_merkle_pair(root_fr, zero_sibling);
        }
        let path = vec![([0u8; 32], true); DEFAULT_TREE_DEPTH];
        let leaf_index = 0u64;

        let signature = poseidon_signature(sk, commitment_fr, Fr::from(leaf_index));
        let nullifier_fr = poseidon_nullifier_spend(commitment_fr, Fr::from(leaf_index), signature);
        let root = fr_to_le_bytes_32(root_fr);
        let nullifier = fr_to_le_bytes_32(nullifier_fr);

        let circuit = WithdrawCircuitV2 {
            merkle_root: Some(root),
            nullifier: Some(nullifier),
            withdraw_amount: Some(value),
            ext_data_hash: Some(ext_data_hash),
            input_value: Some(value),
            blinding: Some(blinding),
            privkey: Some(privkey),
            asset_id: Some(asset),
            input_path: Some(path),
        };

        let mut rng = thread_rng();
        let proof = Groth16ProofSystem::prove(&pk, circuit, &mut rng).unwrap();

        let wp = proof_to_wire(&proof);
        let wvk = WireVerifyingKey::from_arkworks(&vk);
        let pis = [
            fr_to_be(&root_fr),
            fr_to_be(&nullifier_fr),
            fr_to_be(&Fr::from(value)),
            fr_to_be(&Fr::from_le_bytes_mod_order(&ext_data_hash)),
            fr_to_be(&Fr::from_le_bytes_mod_order(&asset)),
        ];
        assert_eq!(wvk.ic.len(), 6, "v2 withdraw VK must have 6 IC points");
        assert!(
            verify(&wp, &pis, &wvk.as_verifying_key()),
            "emitted v2 fixture must verify"
        );

        println!("\n// ===== withdraw v2 verifying key (dev ceremony, spend-key) =====");
        rust_bytes("VK_ALPHA_G1", &wvk.alpha);
        rust_bytes("VK_BETA_G2", &wvk.beta);
        rust_bytes("VK_GAMMA_G2", &wvk.gamma);
        rust_bytes("VK_DELTA_G2", &wvk.delta);
        for (i, ic) in wvk.ic.iter().enumerate() {
            rust_bytes(&format!("VK_IC_{i}"), ic);
        }
        println!("\n// ===== withdraw v2 proof fixture =====");
        rust_bytes("FIXTURE_ROOT", &root);
        rust_bytes("FIXTURE_NULLIFIER", &nullifier);
        println!("pub const FIXTURE_AMOUNT: u64 = {value};");
        rust_bytes("FIXTURE_EXT_DATA_HASH", &ext_data_hash);
        rust_bytes("FIXTURE_ASSET_ID", &asset);
        rust_bytes("FIXTURE_PROOF_A", &wp.a);
        rust_bytes("FIXTURE_PROOF_B", &wp.b);
        rust_bytes("FIXTURE_PROOF_C", &wp.c);
    }
}
