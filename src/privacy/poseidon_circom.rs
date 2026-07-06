//! Circom-compatible fixed-width Poseidon (BN254 x5).
//!
//! This is the hash construction circuit v3 (#350) moves to, replacing the
//! variable-length arkworks sponge + domain-tag scheme in [`super::poseidon`].
//! The reason is compatibility with an **on-chain Merkle tree**: to bind the
//! post-insert root without a bespoke in-circuit insert gadget, the program
//! appends output commitments and recomputes the root itself, hashing with the
//! Solana `sol_poseidon` syscall. That syscall implements circomlib's
//! fixed-width Poseidon; for the program-computed root to ever match a proof's
//! membership root, the circuit's hash must be **bit-identical** to the
//! syscall's. This module provides that hash on both surfaces we control:
//!
//! - [`circom_poseidon`] — the host hash, delegating to `light-poseidon`
//!   (the arkworks-0.4 implementation whose output equals the syscall's).
//! - [`circom_poseidon_gadget`] — an in-circuit R1CS replica of the exact same
//!   permutation, using the same round constants and MDS matrix, so the gadget
//!   output equals the host output by construction.
//!
//! Domain separation is by **width** (circomlib convention): a Merkle inner
//! node is `Poseidon(2)`, a nullifier `Poseidon(3)`, a commitment `Poseidon(4)`
//! — distinct widths are distinct permutations and cannot collide, so no
//! absorbed domain tag is needed. The capacity element (`state[0]`) is the
//! fixed `0` circomlib uses (`new_circom`), which the syscall also assumes.
//!
//! The three-way parity — gadget == host == syscall — is what makes the
//! on-chain-tree architecture safe to adopt. Gadget==host is enforced by the
//! tests here; host==syscall is anchored by the canonical circomlib
//! known-answer value (the syscall implements circomlib by definition) and is
//! additionally checked on-chain by a `solana-program-test` in the program
//! crate.

use ark_bn254::Fr;
use ark_r1cs_std::{fields::fp::FpVar, fields::FieldVar};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use light_poseidon::{parameters::bn254_x5::get_poseidon_parameters, Poseidon, PoseidonHasher};

/// Host-side circom Poseidon over `inputs` (width = `inputs.len() + 1`).
///
/// Panics if `inputs` is empty or wider than the syscall supports (widths
/// 2..=13, i.e. 1..=12 inputs); callers use fixed small widths.
pub fn circom_poseidon(inputs: &[Fr]) -> Fr {
    let mut hasher =
        Poseidon::<Fr>::new_circom(inputs.len()).expect("circom Poseidon supports 1..=12 inputs");
    hasher
        .hash(inputs)
        .expect("input count matches the hasher width")
}

/// `x^5` (the BN254 x5 S-box) in-circuit, as three multiplications.
fn pow5(x: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let x2 = x * x;
    let x4 = &x2 * &x2;
    Ok(&x4 * x)
}

/// In-circuit replica of [`circom_poseidon`]: the exact circomlib fixed-width
/// permutation (capacity `0`, `apply_ark` → S-box → `apply_mds` per round,
/// full–partial–full round split, result = `state[0]`), using the same
/// constants the host and the syscall use. Output equals `circom_poseidon` by
/// construction.
pub fn circom_poseidon_gadget(
    _cs: ConstraintSystemRef<Fr>,
    inputs: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    let width = inputs.len() + 1;
    let params =
        get_poseidon_parameters::<Fr>(width as u8).expect("circom Poseidon supports 1..=12 inputs");

    // state = [capacity=0, in0, in1, ...]
    let mut state: Vec<FpVar<Fr>> = Vec::with_capacity(width);
    state.push(FpVar::constant(Fr::from(0u64)));
    state.extend(inputs.iter().cloned());

    let half = params.full_rounds / 2;
    let total = params.full_rounds + params.partial_rounds;
    for round in 0..total {
        // apply_ark: state[i] += ark[round * width + i]
        for (i, s) in state.iter_mut().enumerate() {
            *s = &*s + FpVar::constant(params.ark[round * width + i]);
        }
        // S-box: full rounds hit every element, partial rounds only state[0].
        let is_full = round < half || round >= half + params.partial_rounds;
        if is_full {
            for s in state.iter_mut() {
                *s = pow5(s)?;
            }
        } else {
            state[0] = pow5(&state[0])?;
        }
        // apply_mds: new[i] = Σ_j state[j] * mds[i][j] (constant coefficients).
        let mut next: Vec<FpVar<Fr>> = Vec::with_capacity(width);
        for i in 0..width {
            let mut acc = FpVar::constant(Fr::from(0u64));
            for (j, s) in state.iter().enumerate() {
                acc += s * FpVar::constant(params.mds[i][j]);
            }
            next.push(acc);
        }
        state = next;
    }
    Ok(state[0].clone())
}

// ────────────────────────────────────────────────────────────────────────────
// v3 note hashes (circom fixed-width; domain separation by WIDTH).
//
// The UTXO construction of the audited Tornado-Nova / privacy-cash transaction
// circuit, reimplemented on our circom Poseidon so the host and the in-circuit
// gadget agree and the on-chain tree (syscall) sees the same commitments:
//
//   pubkey      = Poseidon(1)([privkey])
//   commitment  = Poseidon(4)([amount, pubkey, blinding, asset_id])
//   signature   = Poseidon(3)([privkey, commitment, leaf_index])
//   nullifier   = Poseidon(3)([commitment, leaf_index, signature])
//   merkle node = Poseidon(2)([left, right])
//
// `leaf_index` is the note's tree position, folded into the signature and
// nullifier so a note at a given position yields exactly one nullifier that
// only its key-holder can produce. `asset_id` is bound into every commitment
// so a note of one asset cannot be spent as another.
// ────────────────────────────────────────────────────────────────────────────

/// Host: spend public key `Poseidon(1)([privkey])`.
pub fn v3_pubkey(privkey: Fr) -> Fr {
    circom_poseidon(&[privkey])
}

/// Host: note commitment `Poseidon(4)([amount, pubkey, blinding, asset_id])`.
pub fn v3_commit(amount: Fr, pubkey: Fr, blinding: Fr, asset_id: Fr) -> Fr {
    circom_poseidon(&[amount, pubkey, blinding, asset_id])
}

/// Host: spend signature `Poseidon(3)([privkey, commitment, leaf_index])`.
pub fn v3_signature(privkey: Fr, commitment: Fr, leaf_index: Fr) -> Fr {
    circom_poseidon(&[privkey, commitment, leaf_index])
}

/// Host: nullifier `Poseidon(3)([commitment, leaf_index, signature])`.
pub fn v3_nullifier(commitment: Fr, leaf_index: Fr, signature: Fr) -> Fr {
    circom_poseidon(&[commitment, leaf_index, signature])
}

/// Host: Merkle inner node `Poseidon(2)([left, right])`.
pub fn v3_merkle_pair(left: Fr, right: Fr) -> Fr {
    circom_poseidon(&[left, right])
}

/// In-circuit: `Poseidon(1)([privkey])`.
pub fn v3_pubkey_gadget(
    cs: ConstraintSystemRef<Fr>,
    privkey: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    circom_poseidon_gadget(cs, std::slice::from_ref(privkey))
}

/// In-circuit: `Poseidon(4)([amount, pubkey, blinding, asset_id])`.
pub fn v3_commit_gadget(
    cs: ConstraintSystemRef<Fr>,
    amount: &FpVar<Fr>,
    pubkey: &FpVar<Fr>,
    blinding: &FpVar<Fr>,
    asset_id: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    circom_poseidon_gadget(
        cs,
        &[
            amount.clone(),
            pubkey.clone(),
            blinding.clone(),
            asset_id.clone(),
        ],
    )
}

/// In-circuit: `Poseidon(3)([privkey, commitment, leaf_index])`.
pub fn v3_signature_gadget(
    cs: ConstraintSystemRef<Fr>,
    privkey: &FpVar<Fr>,
    commitment: &FpVar<Fr>,
    leaf_index: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    circom_poseidon_gadget(
        cs,
        &[privkey.clone(), commitment.clone(), leaf_index.clone()],
    )
}

/// In-circuit: `Poseidon(3)([commitment, leaf_index, signature])`.
pub fn v3_nullifier_gadget(
    cs: ConstraintSystemRef<Fr>,
    commitment: &FpVar<Fr>,
    leaf_index: &FpVar<Fr>,
    signature: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    circom_poseidon_gadget(
        cs,
        &[commitment.clone(), leaf_index.clone(), signature.clone()],
    )
}

/// In-circuit: `Poseidon(2)([left, right])`.
pub fn v3_merkle_pair_gadget(
    cs: ConstraintSystemRef<Fr>,
    left: &FpVar<Fr>,
    right: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    circom_poseidon_gadget(cs, &[left.clone(), right.clone()])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::{alloc::AllocVar, R1CSVar};
    use ark_relations::r1cs::ConstraintSystem;
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use std::str::FromStr;

    fn gadget_value(inputs: &[Fr]) -> Fr {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let vars: Vec<FpVar<Fr>> = inputs
            .iter()
            .map(|x| FpVar::new_witness(cs.clone(), || Ok(*x)).unwrap())
            .collect();
        let out = circom_poseidon_gadget(cs.clone(), &vars).unwrap();
        assert!(
            cs.is_satisfied().unwrap(),
            "gadget constraints unsatisfiable"
        );
        out.value().unwrap()
    }

    /// The gadget reproduces the host hash for every width the circuits use
    /// (2 = Merkle node, 3 = nullifier, 4/5 = commitment), on random inputs.
    #[test]
    fn gadget_matches_host_all_widths() {
        let mut rng = StdRng::seed_from_u64(0x9051D02);
        for n in 1..=5usize {
            for _ in 0..8 {
                let inputs: Vec<Fr> = (0..n).map(|_| Fr::from(rng.gen::<u64>())).collect();
                assert_eq!(
                    circom_poseidon(&inputs),
                    gadget_value(&inputs),
                    "gadget != host at width {}",
                    n + 1
                );
            }
        }
    }

    /// The v3 note-hash helpers (pubkey/commit/signature/nullifier/merkle) each
    /// match their in-circuit gadget for random inputs — the whole UTXO note
    /// construction is host/gadget consistent.
    #[test]
    fn v3_note_hashes_host_matches_gadget() {
        let mut rng = StdRng::seed_from_u64(0x00DE);
        for _ in 0..8 {
            let sk = Fr::from(rng.gen::<u64>());
            let amt = Fr::from(rng.gen::<u64>());
            let bl = Fr::from(rng.gen::<u64>());
            let asset = Fr::from(rng.gen::<u64>());
            let idx = Fr::from(rng.gen::<u32>() as u64);

            let cs = ConstraintSystem::<Fr>::new_ref();
            let w = |x: Fr| FpVar::new_witness(cs.clone(), || Ok(x)).unwrap();
            let (skv, amtv, blv, assetv, idxv) = (w(sk), w(amt), w(bl), w(asset), w(idx));

            let pk = v3_pubkey(sk);
            let pkv = v3_pubkey_gadget(cs.clone(), &skv).unwrap();
            assert_eq!(pk, pkv.value().unwrap(), "pubkey");

            let c = v3_commit(amt, pk, bl, asset);
            let cv = v3_commit_gadget(cs.clone(), &amtv, &pkv, &blv, &assetv).unwrap();
            assert_eq!(c, cv.value().unwrap(), "commit");

            let s = v3_signature(sk, c, idx);
            let sv = v3_signature_gadget(cs.clone(), &skv, &cv, &idxv).unwrap();
            assert_eq!(s, sv.value().unwrap(), "signature");

            let n = v3_nullifier(c, idx, s);
            let nv = v3_nullifier_gadget(cs.clone(), &cv, &idxv, &sv).unwrap();
            assert_eq!(n, nv.value().unwrap(), "nullifier");

            let m = v3_merkle_pair(c, n);
            let mv = v3_merkle_pair_gadget(cs.clone(), &cv, &nv).unwrap();
            assert_eq!(m, mv.value().unwrap(), "merkle");

            assert!(cs.is_satisfied().unwrap());
        }
    }

    /// Anchor to the canonical circomlib known-answer value for `Poseidon(2)`
    /// of `[1, 2]`. The Solana `sol_poseidon` syscall implements circomlib, so
    /// matching this value ties host + gadget to the on-chain hash as well.
    #[test]
    fn matches_circomlib_canonical_kat() {
        let expected = Fr::from_str(
            "7853200120776062878684798364095072458815029376092732009249414926327459813530",
        )
        .unwrap();
        assert_eq!(circom_poseidon(&[Fr::from(1u64), Fr::from(2u64)]), expected);
        assert_eq!(gadget_value(&[Fr::from(1u64), Fr::from(2u64)]), expected);
    }
}
