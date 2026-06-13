//! BGM17 phase-2 contribution and verification.
//!
//! Implements the contribution operation from Bowe, Gabizon, Miers
//! (eprint 2017/1050) directly against arkworks
//! `ProvingKey<Bn254>` types. This is the cryptographic core of
//! paraloom's MPC ceremony: every contributor calls
//! [`apply_contribution`] with their toxic-waste scalar `δ_i`;
//! every verifier calls [`verify_contribution`] against the
//! resulting before/after pair and the accompanying DLEQ proof.
//!
//! ## What a contribution does
//!
//! Given a `ProvingKey` produced by the previous contributor (or
//! the initial single-source SRS for the first contribution) and a
//! fresh random scalar `δ_i ∈ F_r`:
//!
//! - `pk.delta_g1 ← pk.delta_g1 · δ_i`
//! - `pk.vk.delta_g2 ← pk.vk.delta_g2 · δ_i`
//! - `pk.h_query[j] ← pk.h_query[j] · δ_i⁻¹` for every `j`
//! - `pk.l_query[j] ← pk.l_query[j] · δ_i⁻¹` for every `j`
//!
//! Knowledge of every `δ_i` is required to derive the trapdoor; if
//! at least one contributor destroys their `δ_i`, the SRS is sound.
//!
//! ## DLEQ proof
//!
//! A contribution is accompanied by a discrete-log-equality proof
//! showing that the same `δ_i` was applied to both the G1 and G2
//! delta values. Without this, a malicious contributor could apply
//! `δ_i` in G1 and `δ_i'` in G2, breaking the pairing equation
//! that Groth16 verification depends on. The proof is a
//! Schnorr-style triple `(R_g1, R_g2, s)`:
//!
//! - Prover samples `k`, sets `R_g1 = δ_before_g1 · k` and
//!   `R_g2 = δ_before_g2 · k`.
//! - Fiat-Shamir challenge `c = H(δ_before_g1, δ_after_g1,
//!   δ_before_g2, δ_after_g2, R_g1, R_g2)`.
//! - Response `s = k + c · δ_i`.
//!
//! Verifier checks both:
//! - `δ_before_g1 · s == R_g1 + δ_after_g1 · c`
//! - `δ_before_g2 · s == R_g2 + δ_after_g2 · c`
//!
//! Both equations hold iff the same `δ_i` was applied to both
//! delta values.

use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, PrimeField, UniformRand, Zero};
use ark_groth16::ProvingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::RngCore;
use sha2::{Digest, Sha512};

/// Schnorr-style discrete-log-equality proof witnessing that the
/// same scalar was applied to both the G1 and G2 delta values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DleqProof {
    pub r_g1: G1Affine,
    pub r_g2: G2Affine,
    pub s: Fr,
}

impl DleqProof {
    /// Serialise the proof in a compact wire format. The bytes
    /// are what the transcript module stores in
    /// `Contribution::dleq_proof`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.r_g1
            .serialize_compressed(&mut out)
            .expect("G1Affine always serialises to its compressed form");
        self.r_g2
            .serialize_compressed(&mut out)
            .expect("G2Affine always serialises to its compressed form");
        self.s
            .serialize_compressed(&mut out)
            .expect("Fr always serialises to a fixed-size little-endian word");
        out
    }

    /// Inverse of [`to_bytes`]. Errors on truncation, trailing
    /// data, or a point that fails compressed-form validation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BgmError> {
        let mut cursor = bytes;
        let r_g1 = G1Affine::deserialize_compressed(&mut cursor)
            .map_err(|_| BgmError::MalformedDleqProof)?;
        let r_g2 = G2Affine::deserialize_compressed(&mut cursor)
            .map_err(|_| BgmError::MalformedDleqProof)?;
        let s =
            Fr::deserialize_compressed(&mut cursor).map_err(|_| BgmError::MalformedDleqProof)?;
        if !cursor.is_empty() {
            return Err(BgmError::MalformedDleqProof);
        }
        Ok(Self { r_g1, r_g2, s })
    }
}

/// Apply a fresh contribution to `pk` using the supplied scalar
/// `delta_i`.
///
/// Mutates `pk` in place: every Groth16 element that depends on
/// `δ` is updated. Returns the DLEQ proof witnessing that the
/// same `δ_i` was applied to both deltas.
///
/// `delta_i` is the contribution's toxic waste. The caller MUST
/// destroy it after this function returns. The function does not
/// retain a reference to it; once `apply_contribution` returns,
/// only the public elements (the updated SRS and the DLEQ proof)
/// remain.
///
/// `delta_i` must not be zero. The function returns
/// [`BgmError::ZeroContribution`] without mutating `pk` if it is.
pub fn apply_contribution<R: RngCore>(
    pk: &mut ProvingKey<Bn254>,
    delta_i: Fr,
    rng: &mut R,
) -> Result<DleqProof, BgmError> {
    if delta_i.is_zero() {
        return Err(BgmError::ZeroContribution);
    }
    let delta_inv = delta_i.inverse().ok_or(BgmError::ZeroContribution)?;

    let delta_before_g1 = pk.delta_g1;
    let delta_before_g2 = pk.vk.delta_g2;

    pk.delta_g1 = (pk.delta_g1 * delta_i).into_affine();
    pk.vk.delta_g2 = (pk.vk.delta_g2 * delta_i).into_affine();
    apply_scalar_to_g1_vec(&mut pk.h_query, delta_inv);
    apply_scalar_to_g1_vec(&mut pk.l_query, delta_inv);

    let delta_after_g1 = pk.delta_g1;
    let delta_after_g2 = pk.vk.delta_g2;

    let k = Fr::rand(rng);
    let r_g1 = (delta_before_g1 * k).into_affine();
    let r_g2 = (delta_before_g2 * k).into_affine();
    let c = fiat_shamir_challenge(
        &delta_before_g1,
        &delta_after_g1,
        &delta_before_g2,
        &delta_after_g2,
        &r_g1,
        &r_g2,
    );
    let s = k + c * delta_i;

    Ok(DleqProof { r_g1, r_g2, s })
}

/// Verify that `pk_after` is the result of a single legitimate
/// BGM17 contribution applied to `pk_before`, witnessed by
/// `proof`.
///
/// Cryptographically this checks the two Schnorr-DLEQ equations
/// and that the post-state delta values are non-zero. What it
/// does **not** check (left to the caller / transcript verifier):
/// the h_query / l_query updates against `δ_i⁻¹`, and that the
/// non-delta portions of `pk_after` equal `pk_before`. Those
/// structural checks live in subsequent PRs.
pub fn verify_contribution(
    pk_before: &ProvingKey<Bn254>,
    pk_after: &ProvingKey<Bn254>,
    proof: &DleqProof,
) -> Result<(), BgmError> {
    verify_contribution_deltas(
        &pk_before.delta_g1,
        &pk_after.delta_g1,
        &pk_before.vk.delta_g2,
        &pk_after.vk.delta_g2,
        proof,
    )
}

/// Lower-level DLEQ check that operates on raw delta points
/// rather than full proving keys. The transcript verifier
/// consumes this directly: a `Phase2Transcript` stores only
/// the delta bytes per contribution, not the full SRS, so the
/// PK-shaped wrapper above is the wrong API there.
pub fn verify_contribution_deltas(
    delta_before_g1: &G1Affine,
    delta_after_g1: &G1Affine,
    delta_before_g2: &G2Affine,
    delta_after_g2: &G2Affine,
    proof: &DleqProof,
) -> Result<(), BgmError> {
    if delta_after_g1.is_zero() || delta_after_g2.is_zero() {
        return Err(BgmError::ZeroContribution);
    }

    let c = fiat_shamir_challenge(
        delta_before_g1,
        delta_after_g1,
        delta_before_g2,
        delta_after_g2,
        &proof.r_g1,
        &proof.r_g2,
    );

    let lhs_g1 = (*delta_before_g1 * proof.s).into_affine();
    let rhs_g1 = (proof.r_g1 + *delta_after_g1 * c).into_affine();
    if lhs_g1 != rhs_g1 {
        return Err(BgmError::DleqMismatchG1);
    }

    let lhs_g2 = (*delta_before_g2 * proof.s).into_affine();
    let rhs_g2 = (proof.r_g2 + *delta_after_g2 * c).into_affine();
    if lhs_g2 != rhs_g2 {
        return Err(BgmError::DleqMismatchG2);
    }

    Ok(())
}

fn apply_scalar_to_g1_vec(points: &mut [G1Affine], scalar: Fr) {
    for point in points.iter_mut() {
        *point = (*point * scalar).into_affine();
    }
}

/// Fiat-Shamir challenge: deterministically derive a scalar from
/// the contribution's public inputs. Domain-separated by a fixed
/// prefix so the challenge cannot be reused as a hash for any
/// other ceremony or protocol artefact.
fn fiat_shamir_challenge(
    delta_before_g1: &G1Affine,
    delta_after_g1: &G1Affine,
    delta_before_g2: &G2Affine,
    delta_after_g2: &G2Affine,
    r_g1: &G1Affine,
    r_g2: &G2Affine,
) -> Fr {
    let mut hasher = Sha512::new();
    hasher.update(b"paraloom-bgm17-dleq-challenge-v1");
    write_canonical(&mut hasher, delta_before_g1);
    write_canonical(&mut hasher, delta_after_g1);
    write_canonical(&mut hasher, delta_before_g2);
    write_canonical(&mut hasher, delta_after_g2);
    write_canonical(&mut hasher, r_g1);
    write_canonical(&mut hasher, r_g2);
    let digest = hasher.finalize();
    Fr::from_le_bytes_mod_order(&digest[..])
}

fn write_canonical<T: CanonicalSerialize>(hasher: &mut Sha512, value: &T) {
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .expect("arkworks types serialise to their compressed form");
    hasher.update(&bytes);
}

/// Errors surfaced by the BGM17 contribution and verifier paths.
#[derive(Debug, thiserror::Error)]
pub enum BgmError {
    #[error("contribution scalar must not be zero")]
    ZeroContribution,
    #[error("DLEQ proof byte sequence is malformed or truncated")]
    MalformedDleqProof,
    #[error("DLEQ proof failed the G1 consistency check")]
    DleqMismatchG1,
    #[error("DLEQ proof failed the G2 consistency check")]
    DleqMismatchG2,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_groth16::Groth16;
    use ark_relations::{
        lc,
        r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
    };
    use ark_snark::SNARK;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn test_rng() -> StdRng {
        // Deterministic seed so the eight unit tests in this module
        // are reproducible across runs. Direct StdRng (rand 0.8)
        // rather than ark_std::test_rng so the rng's CryptoRng impl
        // is from the same rand_core version that ark_groth16 binds
        // against; ark_std exposes a newer rand_core that the
        // groth16 setup signature does not accept.
        StdRng::seed_from_u64(0xC0FFEE_BAADu64)
    }

    /// Trivial circuit so we can call `circuit_specific_setup` and
    /// produce a real `ProvingKey<Bn254>` for the
    /// contribution operation. We never prove or verify against
    /// it; the bgm17 module operates purely on the ProvingKey
    /// shape.
    #[derive(Clone)]
    struct TrivialCircuit;

    impl ConstraintSynthesizer<Fr> for TrivialCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let a = cs.new_witness_variable(|| Ok(Fr::from(3u32)))?;
            let b = cs.new_witness_variable(|| Ok(Fr::from(5u32)))?;
            let c = cs.new_input_variable(|| Ok(Fr::from(15u32)))?;
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
            Ok(())
        }
    }

    fn fresh_pk() -> ProvingKey<Bn254> {
        let mut rng = test_rng();
        let (pk, _vk) = Groth16::<Bn254>::circuit_specific_setup(TrivialCircuit, &mut rng).unwrap();
        pk
    }

    #[test]
    fn apply_then_verify_round_trip_succeeds() {
        let pk_before = fresh_pk();
        let mut pk_after = pk_before.clone();
        let mut rng = test_rng();
        let delta_i = Fr::rand(&mut rng);
        let proof =
            apply_contribution(&mut pk_after, delta_i, &mut rng).expect("contribution succeeds");
        verify_contribution(&pk_before, &pk_after, &proof).expect("DLEQ verifies");
    }

    #[test]
    fn zero_contribution_is_rejected_by_apply() {
        let mut pk = fresh_pk();
        let mut rng = test_rng();
        match apply_contribution(&mut pk, Fr::from(0u32), &mut rng) {
            Err(BgmError::ZeroContribution) => {}
            other => panic!("expected ZeroContribution, got {:?}", other),
        }
    }

    #[test]
    fn tampered_delta_after_g1_fails_verification() {
        let pk_before = fresh_pk();
        let mut pk_after = pk_before.clone();
        let mut rng = test_rng();
        let delta_i = Fr::rand(&mut rng);
        let proof =
            apply_contribution(&mut pk_after, delta_i, &mut rng).expect("contribution succeeds");

        // Re-multiply delta_g1 by an unrelated scalar; the DLEQ
        // verifier must surface the mismatch.
        let attacker_scalar = Fr::rand(&mut rng);
        pk_after.delta_g1 = (pk_after.delta_g1 * attacker_scalar).into_affine();

        match verify_contribution(&pk_before, &pk_after, &proof) {
            Err(BgmError::DleqMismatchG1) | Err(BgmError::DleqMismatchG2) => {}
            other => panic!("expected DleqMismatch, got {:?}", other),
        }
    }

    #[test]
    fn tampered_delta_after_g2_fails_verification() {
        let pk_before = fresh_pk();
        let mut pk_after = pk_before.clone();
        let mut rng = test_rng();
        let delta_i = Fr::rand(&mut rng);
        let proof =
            apply_contribution(&mut pk_after, delta_i, &mut rng).expect("contribution succeeds");

        let attacker_scalar = Fr::rand(&mut rng);
        pk_after.vk.delta_g2 = (pk_after.vk.delta_g2 * attacker_scalar).into_affine();

        match verify_contribution(&pk_before, &pk_after, &proof) {
            Err(BgmError::DleqMismatchG1) | Err(BgmError::DleqMismatchG2) => {}
            other => panic!("expected DleqMismatch, got {:?}", other),
        }
    }

    #[test]
    fn tampered_dleq_response_scalar_fails_verification() {
        let pk_before = fresh_pk();
        let mut pk_after = pk_before.clone();
        let mut rng = test_rng();
        let delta_i = Fr::rand(&mut rng);
        let mut proof =
            apply_contribution(&mut pk_after, delta_i, &mut rng).expect("contribution succeeds");

        proof.s += Fr::from(1u32);

        match verify_contribution(&pk_before, &pk_after, &proof) {
            Err(BgmError::DleqMismatchG1) | Err(BgmError::DleqMismatchG2) => {}
            other => panic!("expected DleqMismatch, got {:?}", other),
        }
    }

    #[test]
    fn dleq_proof_round_trips_through_bytes() {
        let pk_before = fresh_pk();
        let mut pk_after = pk_before.clone();
        let mut rng = test_rng();
        let delta_i = Fr::rand(&mut rng);
        let proof =
            apply_contribution(&mut pk_after, delta_i, &mut rng).expect("contribution succeeds");

        let bytes = proof.to_bytes();
        let decoded = DleqProof::from_bytes(&bytes).expect("round trip decodes");
        assert_eq!(decoded, proof);
    }

    #[test]
    fn dleq_from_bytes_rejects_truncated_input() {
        let pk_before = fresh_pk();
        let mut pk_after = pk_before.clone();
        let mut rng = test_rng();
        let delta_i = Fr::rand(&mut rng);
        let proof =
            apply_contribution(&mut pk_after, delta_i, &mut rng).expect("contribution succeeds");

        let bytes = proof.to_bytes();
        let truncated = &bytes[..bytes.len() - 4];
        match DleqProof::from_bytes(truncated) {
            Err(BgmError::MalformedDleqProof) => {}
            other => panic!("expected MalformedDleqProof, got {:?}", other),
        }
    }

    /// After contribution, h_query and l_query are scaled by
    /// `δ⁻¹`. Re-derive the expected post-state and compare
    /// element-by-element. This pins the math; a regression that
    /// updated by `δ` instead of `δ⁻¹` would silently break
    /// Groth16 soundness in production but show up here.
    #[test]
    fn h_and_l_query_are_scaled_by_delta_inverse() {
        let pk_before = fresh_pk();
        let mut pk_after = pk_before.clone();
        let mut rng = test_rng();
        let delta_i = Fr::rand(&mut rng);
        let _proof =
            apply_contribution(&mut pk_after, delta_i, &mut rng).expect("contribution succeeds");

        let delta_inv = delta_i.inverse().unwrap();
        for (i, (before, after)) in pk_before
            .h_query
            .iter()
            .zip(pk_after.h_query.iter())
            .enumerate()
        {
            let expected = (*before * delta_inv).into_affine();
            assert_eq!(*after, expected, "h_query[{}] mismatch", i);
        }
        for (i, (before, after)) in pk_before
            .l_query
            .iter()
            .zip(pk_after.l_query.iter())
            .enumerate()
        {
            let expected = (*before * delta_inv).into_affine();
            assert_eq!(*after, expected, "l_query[{}] mismatch", i);
        }
    }
}
