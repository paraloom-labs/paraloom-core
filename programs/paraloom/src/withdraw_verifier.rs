//! On-chain withdrawal proof verification (#165, spend-key circuit v2 #293).
//!
//! Verifies a wire-form Groth16 proof against the program's published Merkle
//! root and the withdrawal's nullifier, amount, external-data hash and asset.
//! The spend-key withdraw circuit exposes five public inputs, in order:
//! `[merkle_root, nullifier, withdraw_amount, ext_data_hash, asset_id]`.
//!
//! `ext_data_hash` binds the destination (finding D) and `asset_id` binds the
//! released asset (finding A): the caller passes the asset id of the vault it
//! is about to release and a hash of the actual recipient, so a proof cannot be
//! replayed against a different asset or redirected to a different recipient.
//!
//! The proof blob is the 256-byte `alt_bn128` wire form
//! (`proof_a[64] || proof_b[128] || proof_c[64]`), with `proof_a` already
//! negated by the prover.

use crate::groth16::{Groth16Verifier, Groth16Verifyingkey};
use crate::withdraw_vk_data as vk;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

/// Withdraw circuit public-input count:
/// `[merkle_root, nullifier, amount, ext_data_hash, asset_id]`.
const NUM_PUBLIC_INPUTS: usize = 5;

/// Length of the `alt_bn128` wire proof: `a(64) + b(128) + c(64)`.
pub const WIRE_PROOF_LEN: usize = 256;

const VK_IC: [[u8; 64]; NUM_PUBLIC_INPUTS + 1] = [
    vk::VK_IC_0,
    vk::VK_IC_1,
    vk::VK_IC_2,
    vk::VK_IC_3,
    vk::VK_IC_4,
    vk::VK_IC_5,
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

/// A field element → 32-byte big-endian, matching how the prover encodes each
/// public input.
fn fr_to_be(f: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let be = f.into_bigint().to_bytes_be();
    out[32 - be.len()..].copy_from_slice(&be);
    out
}

/// Verify a withdrawal proof. Returns `true` only if `proof` is a valid Groth16
/// proof for `[merkle_root, nullifier, amount, ext_data_hash, asset_id]` under
/// the embedded verifying key.
///
/// The caller supplies `asset_id` from the vault it is releasing (the mint's
/// 32 bytes, or all-zero for native SOL) and `ext_data_hash` from the actual
/// recipient it is paying — binding the proof to that asset and destination.
pub fn verify_withdrawal(
    merkle_root: &[u8; 32],
    nullifier: &[u8; 32],
    amount: u64,
    ext_data_hash: &[u8; 32],
    asset_id: &[u8; 32],
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

    let public_inputs: [[u8; 32]; NUM_PUBLIC_INPUTS] = [
        fr_to_be(&Fr::from_le_bytes_mod_order(merkle_root)),
        fr_to_be(&Fr::from_le_bytes_mod_order(nullifier)),
        fr_to_be(&Fr::from(amount)),
        fr_to_be(&Fr::from_le_bytes_mod_order(ext_data_hash)),
        fr_to_be(&Fr::from_le_bytes_mod_order(asset_id)),
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
    use crate::withdraw_fixture_data as fx;

    fn fixture_proof() -> Vec<u8> {
        let mut p = Vec::with_capacity(WIRE_PROOF_LEN);
        p.extend_from_slice(&fx::FIXTURE_PROOF_A);
        p.extend_from_slice(&fx::FIXTURE_PROOF_B);
        p.extend_from_slice(&fx::FIXTURE_PROOF_C);
        p
    }

    #[test]
    fn valid_fixture_verifies() {
        assert!(verify_withdrawal(
            &fx::FIXTURE_ROOT,
            &fx::FIXTURE_NULLIFIER,
            fx::FIXTURE_AMOUNT,
            &fx::FIXTURE_EXT_DATA_HASH,
            &fx::FIXTURE_ASSET_ID,
            &fixture_proof(),
        ));
    }

    #[test]
    fn wrong_amount_rejected() {
        assert!(!verify_withdrawal(
            &fx::FIXTURE_ROOT,
            &fx::FIXTURE_NULLIFIER,
            fx::FIXTURE_AMOUNT + 1,
            &fx::FIXTURE_EXT_DATA_HASH,
            &fx::FIXTURE_ASSET_ID,
            &fixture_proof(),
        ));
    }

    #[test]
    fn wrong_root_rejected() {
        let mut root = fx::FIXTURE_ROOT;
        root[0] ^= 1;
        assert!(!verify_withdrawal(
            &root,
            &fx::FIXTURE_NULLIFIER,
            fx::FIXTURE_AMOUNT,
            &fx::FIXTURE_EXT_DATA_HASH,
            &fx::FIXTURE_ASSET_ID,
            &fixture_proof(),
        ));
    }

    #[test]
    fn wrong_ext_data_hash_rejected() {
        // Finding D: a different destination (ext_data_hash) must not verify, so
        // a settling validator cannot redirect the payout to another recipient.
        let mut edh = fx::FIXTURE_EXT_DATA_HASH;
        edh[0] ^= 1;
        assert!(!verify_withdrawal(
            &fx::FIXTURE_ROOT,
            &fx::FIXTURE_NULLIFIER,
            fx::FIXTURE_AMOUNT,
            &edh,
            &fx::FIXTURE_ASSET_ID,
            &fixture_proof(),
        ));
    }

    #[test]
    fn wrong_asset_id_rejected() {
        // Finding A: a proof for one asset must not verify against a different
        // asset_id, so a note cannot drain another mint's vault.
        let mut asset = fx::FIXTURE_ASSET_ID;
        asset[0] ^= 1;
        assert!(!verify_withdrawal(
            &fx::FIXTURE_ROOT,
            &fx::FIXTURE_NULLIFIER,
            fx::FIXTURE_AMOUNT,
            &fx::FIXTURE_EXT_DATA_HASH,
            &asset,
            &fixture_proof(),
        ));
    }

    #[test]
    fn tampered_proof_rejected() {
        let mut p = fixture_proof();
        p[0] ^= 1;
        assert!(!verify_withdrawal(
            &fx::FIXTURE_ROOT,
            &fx::FIXTURE_NULLIFIER,
            fx::FIXTURE_AMOUNT,
            &fx::FIXTURE_EXT_DATA_HASH,
            &fx::FIXTURE_ASSET_ID,
            &p,
        ));
    }

    #[test]
    fn wrong_length_rejected() {
        assert!(!verify_withdrawal(
            &fx::FIXTURE_ROOT,
            &fx::FIXTURE_NULLIFIER,
            fx::FIXTURE_AMOUNT,
            &fx::FIXTURE_EXT_DATA_HASH,
            &fx::FIXTURE_ASSET_ID,
            &[0u8; 255],
        ));
    }
}
