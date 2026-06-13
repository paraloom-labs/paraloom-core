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
        if res[31] != 1 {
            return Err(Groth16Error::ProofVerificationFailed);
        }
        Ok(true)
    }
}

fn is_less_than_bn254_field_size_be(bytes: &[u8; 32]) -> bool {
    BigUint::from_bytes_be(bytes) < Fr::MODULUS.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::circuits::{Groth16ProofSystem, WithdrawCircuit};
    use crate::privacy::pool::ShieldedPool;
    use crate::privacy::poseidon::{poseidon_commit, poseidon_nullifier};
    use crate::privacy::types::{Commitment, Note, ShieldedAddress};
    use ark_std::rand::thread_rng;

    fn fr_to_le_bytes_32(f: Fr) -> [u8; 32] {
        let mut out = [0u8; 32];
        let le = f.into_bigint().to_bytes_le();
        out[..le.len().min(32)].copy_from_slice(&le[..le.len().min(32)]);
        out
    }

    /// Build a valid multi-leaf withdrawal proof, convert it to the on-chain
    /// wire form, and verify it through the vendored `alt_bn128` verifier — the
    /// exact path the Solana program will run. A self-contained, in-memory
    /// trusted setup keeps the test independent of `keys/`.
    #[tokio::test]
    async fn withdrawal_proof_verifies_through_alt_bn128() {
        let _ = env_logger::builder().is_test(true).try_init();

        const N: usize = 8;
        const SPEND: usize = 3;
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
        let (value, randomness, recipient) = spent.unwrap();

        let commitment_fr = poseidon_commit(
            Fr::from(value),
            Fr::from_le_bytes_mod_order(&randomness),
            Fr::from_le_bytes_mod_order(&recipient),
            Fr::from(0u64),
        );
        let secret = [7u8; 32];
        let nullifier_fr = poseidon_nullifier(commitment_fr, Fr::from_le_bytes_mod_order(&secret));
        let nullifier = fr_to_le_bytes_32(nullifier_fr);

        let commitment = Commitment::from_bytes(fr_to_le_bytes_32(commitment_fr));
        let merkle = pool.path(&commitment).await.expect("path");
        let root = pool.root().await;
        let merkle_path: Vec<([u8; 32], bool)> = merkle
            .path
            .iter()
            .copied()
            .zip(merkle.indices.iter().copied())
            .collect();

        let circuit = WithdrawCircuit::with_witness(
            root,
            nullifier,
            value, // withdraw_amount
            value, // input_value
            randomness,
            recipient,
            secret,
            merkle_path,
        );

        let mut rng = thread_rng();
        let setup_circuit = WithdrawCircuit::with_witness(
            root,
            nullifier,
            value,
            value,
            randomness,
            recipient,
            secret,
            vec![([0u8; 32], false); crate::privacy::merkle::DEFAULT_TREE_DEPTH],
        );
        let (pk, vk) = Groth16ProofSystem::setup::<WithdrawCircuit, _>(setup_circuit, &mut rng)
            .expect("setup");
        let proof =
            Groth16ProofSystem::prove::<WithdrawCircuit, _>(&pk, circuit, &mut rng).expect("prove");

        // Public inputs, in circuit order: [merkle_root, nullifier, withdraw_amount].
        let public_inputs: [[u8; 32]; 3] = [
            fr_to_be(&Fr::from_le_bytes_mod_order(&root)),
            fr_to_be(&Fr::from_le_bytes_mod_order(&nullifier)),
            fr_to_be(&Fr::from(value)),
        ];

        let wire_proof = proof_to_wire(&proof);
        let wire_vk = WireVerifyingKey::from_arkworks(&vk);
        let vk_view = wire_vk.as_verifying_key();

        assert_eq!(wire_vk.ic.len(), 4, "withdraw VK must have 4 IC points");
        assert!(
            verify(&wire_proof, &public_inputs, &vk_view),
            "valid withdrawal proof must verify through the alt_bn128 path"
        );

        // Tampering any public input must make verification fail.
        let mut bad = public_inputs;
        bad[2] = fr_to_be(&Fr::from(value + 1));
        assert!(
            !verify(&wire_proof, &bad, &vk_view),
            "tampered public input must not verify"
        );
    }
}
