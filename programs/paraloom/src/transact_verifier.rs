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

    #[test]
    fn vk_constants_byte_match_the_published_ceremony_key() {
        use ark_bn254::{Fq, Fq2, G1Affine, G2Affine};
        use num_bigint::BigUint;
        use std::str::FromStr;

        let raw_json = include_str!("../../../ceremony/transact/verification_key.json");

        // Extract quoted decimal strings following a JSON key without pulling in serde_json.
        let extract_decimals_after = |key: &str, count: usize| -> Vec<String> {
            let pos = raw_json.find(key).expect("key in verification_key.json");
            let mut rest = &raw_json[pos + key.len()..];
            let mut out = Vec::new();
            while out.len() < count {
                let start = rest.find('"').expect("opening quote") + 1;
                rest = &rest[start..];
                let end = rest.find('"').expect("closing quote");
                let token = &rest[..end];
                if token.chars().all(|c| c.is_ascii_digit()) {
                    out.push(token.to_string());
                }
                rest = &rest[end + 1..];
            }
            out
        };

        let dec_be32 = |s: &str| -> [u8; 32] {
            let n = BigUint::from_str(s).expect("decimal field element");
            assert!(n < Fq::MODULUS.into(), "coordinate must be < Fq::MODULUS");
            let be = n.to_bytes_be();
            let mut out = [0u8; 32];
            out[32 - be.len()..].copy_from_slice(&be);
            out
        };

        let g1_from_decimals = |coords: &[String]| -> [u8; 64] {
            // [x, y, "1"]
            let x = dec_be32(&coords[0]);
            let y = dec_be32(&coords[1]);
            let mut out = [0u8; 64];
            out[..32].copy_from_slice(&x);
            out[32..].copy_from_slice(&y);
            out
        };

        let g2_from_decimals = |coords: &[String]| -> [u8; 128] {
            // [[x_c0, x_c1], [y_c0, y_c1], ["1", "0"]] -> wire [x_c1, x_c0, y_c1, y_c0]
            let x_c0 = dec_be32(&coords[0]);
            let x_c1 = dec_be32(&coords[1]);
            let y_c0 = dec_be32(&coords[2]);
            let y_c1 = dec_be32(&coords[3]);
            let mut out = [0u8; 128];
            out[..32].copy_from_slice(&x_c1);
            out[32..64].copy_from_slice(&x_c0);
            out[64..96].copy_from_slice(&y_c1);
            out[96..].copy_from_slice(&y_c0);
            out
        };

        let alpha_dec = extract_decimals_after("\"vk_alpha_1\"", 3);
        let beta_dec = extract_decimals_after("\"vk_beta_2\"", 6);
        let gamma_dec = extract_decimals_after("\"vk_gamma_2\"", 6);
        let delta_dec = extract_decimals_after("\"vk_delta_2\"", 6);
        let ic_dec = extract_decimals_after("\"IC\"", VK_IC.len() * 3);

        assert_eq!(vk::VK_ALPHA_G1, g1_from_decimals(&alpha_dec));
        assert_eq!(vk::VK_BETA_G2, g2_from_decimals(&beta_dec));
        assert_eq!(vk::VK_GAMMA_G2, g2_from_decimals(&gamma_dec));
        assert_eq!(vk::VK_DELTA_G2, g2_from_decimals(&delta_dec));

        for (i, onchain_ic) in VK_IC.iter().enumerate() {
            let chunk = &ic_dec[i * 3..(i + 1) * 3];
            assert_eq!(
                *onchain_ic,
                g1_from_decimals(chunk),
                "VK_IC_{i} must byte-match ceremony/transact/verification_key.json"
            );
        }

        // Every G1/G2 coordinate in the VK and proof fixtures must be strictly < q
        // (top bits 6..7 clear) and lie on the curve without relying on ark-serialize
        // masking SWFlags.
        let assert_canonical_g1 = |bytes: &[u8; 64], label: &str| {
            let x_uint = BigUint::from_bytes_be(&bytes[..32]);
            let y_uint = BigUint::from_bytes_be(&bytes[32..]);
            assert!(x_uint < Fq::MODULUS.into(), "{label}.x >= q");
            assert!(y_uint < Fq::MODULUS.into(), "{label}.y >= q");
            let x = Fq::from_be_bytes_mod_order(&bytes[..32]);
            let y = Fq::from_be_bytes_mod_order(&bytes[32..]);
            let pt = G1Affine::new_unchecked(x, y);
            assert!(pt.is_on_curve(), "{label} is not on G1 curve");
        };

        let assert_canonical_g2 = |bytes: &[u8; 128], label: &str| {
            for (coord_idx, chunk) in bytes.chunks_exact(32).enumerate() {
                let u = BigUint::from_bytes_be(chunk);
                assert!(u < Fq::MODULUS.into(), "{label} coord {coord_idx} >= q");
            }
            let x = Fq2::new(
                Fq::from_be_bytes_mod_order(&bytes[32..64]),
                Fq::from_be_bytes_mod_order(&bytes[..32]),
            );
            let y = Fq2::new(
                Fq::from_be_bytes_mod_order(&bytes[96..128]),
                Fq::from_be_bytes_mod_order(&bytes[64..96]),
            );
            let pt = G2Affine::new_unchecked(x, y);
            assert!(pt.is_on_curve(), "{label} is not on G2 curve");
        };

        assert_canonical_g1(&vk::VK_ALPHA_G1, "VK_ALPHA_G1");
        assert_canonical_g2(&vk::VK_BETA_G2, "VK_BETA_G2");
        assert_canonical_g2(&vk::VK_GAMMA_G2, "VK_GAMMA_G2");
        assert_canonical_g2(&vk::VK_DELTA_G2, "VK_DELTA_G2");
        for (i, ic) in VK_IC.iter().enumerate() {
            assert_canonical_g1(ic, &format!("VK_IC_{i}"));
        }
        assert_canonical_g1(&fx::FIXTURE_PROOF_A, "FIXTURE_PROOF_A");
        assert_canonical_g2(&fx::FIXTURE_PROOF_B, "FIXTURE_PROOF_B");
        assert_canonical_g1(&fx::FIXTURE_PROOF_C, "FIXTURE_PROOF_C");
    }
}
