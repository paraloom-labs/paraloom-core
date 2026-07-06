//! On-chain proof verification for the v3 unified transact circuit (#350).
//!
//! Verifies a wire-form Groth16 proof against the eight public inputs, in the
//! circuit's `new_input` order:
//! `[root, public_amount, ext_data_hash, asset_id, nullifier0, nullifier1,
//!   out_commitment0, out_commitment1]`.
//!
//! `root` is the tree root the spent notes are proven members of (the caller
//! checks it is a known root); `public_amount` is the signed net moved
//! (`> 0` deposit, `< 0` withdraw); `ext_data_hash` binds the recipient/fee;
//! `asset_id` binds the asset; the nullifiers are recorded to prevent replay
//! and the output commitments are appended to the tree.
//!
//! The proof blob is the 256-byte `alt_bn128` wire form
//! (`proof_a[64] || proof_b[128] || proof_c[64]`), `proof_a` pre-negated.

#![allow(dead_code)]

use crate::groth16::{Groth16Verifier, Groth16Verifyingkey};
use crate::transact_vk_data as vk;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

/// Transact circuit public-input count.
const NUM_PUBLIC_INPUTS: usize = 8;

/// Length of the `alt_bn128` wire proof: `a(64) + b(128) + c(64)`.
pub const WIRE_PROOF_LEN: usize = 256;

const VK_IC: [[u8; 64]; NUM_PUBLIC_INPUTS + 1] = [
    vk::VK_IC_0,
    vk::VK_IC_1,
    vk::VK_IC_2,
    vk::VK_IC_3,
    vk::VK_IC_4,
    vk::VK_IC_5,
    vk::VK_IC_6,
    vk::VK_IC_7,
    vk::VK_IC_8,
];

fn verifying_key() -> Groth16Verifyingkey<'static> {
    Groth16Verifyingkey {
        nr_pubinputs: NUM_PUBLIC_INPUTS,
        vk_alpha_g1: vk::VK_ALPHA_G1,
        vk_beta_g2: vk::VK_BETA_G2,
        vk_gamme_g2: vk::VK_GAMMA_G2,
        vk_delta_g2: vk::VK_DELTA_G2,
        vk_ic: &VK_IC,
    }
}

/// Field element → 32-byte big-endian, matching the prover's public-input
/// encoding.
fn fr_to_be(f: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let be = f.into_bigint().to_bytes_be();
    out[32 - be.len()..].copy_from_slice(&be);
    out
}

/// Verify a transact proof against its eight public inputs. Each 32-byte input
/// is a little-endian field element (the same encoding the prover used).
#[allow(clippy::too_many_arguments)]
pub fn verify_transact(
    root: &[u8; 32],
    public_amount: &[u8; 32],
    ext_data_hash: &[u8; 32],
    asset_id: &[u8; 32],
    nullifier0: &[u8; 32],
    nullifier1: &[u8; 32],
    out_commitment0: &[u8; 32],
    out_commitment1: &[u8; 32],
    proof: &[u8],
) -> bool {
    if proof.len() != WIRE_PROOF_LEN {
        return false;
    }
    let proof_a: [u8; 64] = match proof[0..64].try_into() {
        Ok(v) => v,
        Err(_) => return false,
    };
    let proof_b: [u8; 128] = match proof[64..192].try_into() {
        Ok(v) => v,
        Err(_) => return false,
    };
    let proof_c: [u8; 64] = match proof[192..256].try_into() {
        Ok(v) => v,
        Err(_) => return false,
    };

    let le = |b: &[u8; 32]| fr_to_be(&Fr::from_le_bytes_mod_order(b));
    let public_inputs: [[u8; 32]; NUM_PUBLIC_INPUTS] = [
        le(root),
        le(public_amount),
        le(ext_data_hash),
        le(asset_id),
        le(nullifier0),
        le(nullifier1),
        le(out_commitment0),
        le(out_commitment1),
    ];

    let vk = verifying_key();
    match Groth16Verifier::new(&proof_a, &proof_b, &proof_c, &public_inputs, &vk) {
        Ok(mut v) => v.verify().unwrap_or(false),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transact_fixture_data as fx;

    fn fixture_proof() -> Vec<u8> {
        let mut p = Vec::with_capacity(WIRE_PROOF_LEN);
        p.extend_from_slice(&fx::FIXTURE_PROOF_A);
        p.extend_from_slice(&fx::FIXTURE_PROOF_B);
        p.extend_from_slice(&fx::FIXTURE_PROOF_C);
        p
    }

    fn verify_fixture(proof: &[u8]) -> bool {
        verify_transact(
            &fx::FIXTURE_ROOT,
            &fx::FIXTURE_PUBLIC_AMOUNT,
            &fx::FIXTURE_EXT_DATA_HASH,
            &fx::FIXTURE_ASSET_ID,
            &fx::FIXTURE_NULLIFIER_0,
            &fx::FIXTURE_NULLIFIER_1,
            &fx::FIXTURE_COMMITMENT_0,
            &fx::FIXTURE_COMMITMENT_1,
            proof,
        )
    }

    #[test]
    fn valid_fixture_verifies() {
        assert!(verify_fixture(&fixture_proof()));
    }

    #[test]
    fn wrong_root_rejected() {
        let mut root = fx::FIXTURE_ROOT;
        root[0] ^= 1;
        assert!(!verify_transact(
            &root,
            &fx::FIXTURE_PUBLIC_AMOUNT,
            &fx::FIXTURE_EXT_DATA_HASH,
            &fx::FIXTURE_ASSET_ID,
            &fx::FIXTURE_NULLIFIER_0,
            &fx::FIXTURE_NULLIFIER_1,
            &fx::FIXTURE_COMMITMENT_0,
            &fx::FIXTURE_COMMITMENT_1,
            &fixture_proof(),
        ));
    }

    #[test]
    fn wrong_public_amount_rejected() {
        let mut pa = fx::FIXTURE_PUBLIC_AMOUNT;
        pa[0] ^= 1;
        assert!(!verify_transact(
            &fx::FIXTURE_ROOT,
            &pa,
            &fx::FIXTURE_EXT_DATA_HASH,
            &fx::FIXTURE_ASSET_ID,
            &fx::FIXTURE_NULLIFIER_0,
            &fx::FIXTURE_NULLIFIER_1,
            &fx::FIXTURE_COMMITMENT_0,
            &fx::FIXTURE_COMMITMENT_1,
            &fixture_proof(),
        ));
    }

    #[test]
    fn wrong_ext_data_hash_rejected() {
        let mut edh = fx::FIXTURE_EXT_DATA_HASH;
        edh[0] ^= 1;
        assert!(!verify_transact(
            &fx::FIXTURE_ROOT,
            &fx::FIXTURE_PUBLIC_AMOUNT,
            &edh,
            &fx::FIXTURE_ASSET_ID,
            &fx::FIXTURE_NULLIFIER_0,
            &fx::FIXTURE_NULLIFIER_1,
            &fx::FIXTURE_COMMITMENT_0,
            &fx::FIXTURE_COMMITMENT_1,
            &fixture_proof(),
        ));
    }

    #[test]
    fn wrong_output_commitment_rejected() {
        let mut oc = fx::FIXTURE_COMMITMENT_0;
        oc[0] ^= 1;
        assert!(!verify_transact(
            &fx::FIXTURE_ROOT,
            &fx::FIXTURE_PUBLIC_AMOUNT,
            &fx::FIXTURE_EXT_DATA_HASH,
            &fx::FIXTURE_ASSET_ID,
            &fx::FIXTURE_NULLIFIER_0,
            &fx::FIXTURE_NULLIFIER_1,
            &oc,
            &fx::FIXTURE_COMMITMENT_1,
            &fixture_proof(),
        ));
    }

    #[test]
    fn tampered_proof_rejected() {
        let mut p = fixture_proof();
        p[0] ^= 1;
        assert!(!verify_fixture(&p));
    }

    #[test]
    fn wrong_length_rejected() {
        assert!(!verify_fixture(&[0u8; 255]));
    }
}
