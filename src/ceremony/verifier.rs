//! End-to-end verifier for a phase-2 ceremony transcript.
//!
//! Walks a [`Phase2Transcript`] from the initial single-source SRS
//! through every contribution and confirms that:
//!
//! 1. The transcript's hash chain is intact (every `prior_hash`
//!    matches the previous contribution's serialised digest, or
//!    the initial SRS hash for the first contribution).
//! 2. Every contribution's DLEQ proof verifies against the delta
//!    transition it claims.
//!
//! The verifier deliberately does not check the contribution
//! signatures or the per-contributor attestations here; those are
//! social-trust artefacts validated separately by the contributor
//! CLI in a later PR. This module is the cryptographic safety
//! check that makes the SRS trustworthy.

use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{One, PrimeField};
use ark_groth16::ProvingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::{Digest, Sha512};

use super::bgm17::{verify_contribution_deltas, BgmError, DleqProof};
use super::transcript::{Phase2Transcript, TranscriptError};

/// Errors surfaced by [`verify_phase2_transcript`].
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("transcript chain is broken or malformed: {0}")]
    Chain(#[from] TranscriptError),

    #[error("contribution {position}: delta_after_g1 bytes are not a valid G1Affine")]
    MalformedDeltaG1 { position: usize },

    #[error("contribution {position}: delta_after_g2 bytes are not a valid G2Affine")]
    MalformedDeltaG2 { position: usize },

    #[error("contribution {position}: dleq_proof bytes are malformed: {source}")]
    MalformedDleq { position: usize, source: BgmError },

    #[error("contribution {position}: DLEQ verification failed: {source}")]
    DleqRejected { position: usize, source: BgmError },

    #[error(
        "final proving key does not match the transcript: its delta is not the \
         delta the chain culminates in"
    )]
    FinalPkDeltaMismatch,

    #[error(
        "final key element `{field}` was altered by the ceremony but a phase-2 \
         contribution must leave it untouched"
    )]
    KeyElementAltered { field: &'static str },

    #[error("final key vector `{field}` has a different length than the initial key")]
    QueryLengthMismatch { field: &'static str },

    #[error(
        "final key `{field}` is not a consistent δ⁻¹ scaling of the initial key: \
         the pairing consistency check failed"
    )]
    QueryInconsistent { field: &'static str },
}

/// Verify a finalised phase-2 transcript end to end.
///
/// `initial_pk` is the single-source ProvingKey produced by the
/// existing `setup_*_ceremony` binaries before any contribution
/// was applied. The verifier uses its delta values as the starting
/// point of the chain.
///
/// On success the transcript is sound: at least one honest
/// contributor destroying their `δ_i` is enough for the resulting
/// final SRS to keep the Groth16 trapdoor unrecoverable. On any
/// failure the SRS must be considered compromised and the ceremony
/// aborted.
pub fn verify_phase2_transcript(
    initial_pk: &ProvingKey<Bn254>,
    transcript: &Phase2Transcript,
) -> Result<(), VerifyError> {
    transcript.verify_chain()?;

    let mut delta_before_g1 = initial_pk.delta_g1;
    let mut delta_before_g2 = initial_pk.vk.delta_g2;

    for (position, contribution) in transcript.contributions.iter().enumerate() {
        let delta_after_g1 = G1Affine::deserialize_compressed(&contribution.delta_after_g1[..])
            .map_err(|_| VerifyError::MalformedDeltaG1 { position })?;
        let delta_after_g2 = G2Affine::deserialize_compressed(&contribution.delta_after_g2[..])
            .map_err(|_| VerifyError::MalformedDeltaG2 { position })?;
        let proof = DleqProof::from_bytes(&contribution.dleq_proof)
            .map_err(|source| VerifyError::MalformedDleq { position, source })?;

        verify_contribution_deltas(
            &delta_before_g1,
            &delta_after_g1,
            &delta_before_g2,
            &delta_after_g2,
            &proof,
        )
        .map_err(|source| VerifyError::DleqRejected { position, source })?;

        delta_before_g1 = delta_after_g1;
        delta_before_g2 = delta_after_g2;
    }

    Ok(())
}

/// Verify that `final_pk` is the proving key the transcript culminates in.
///
/// [`verify_phase2_transcript`] proves the *transcript* is internally sound —
/// the delta transitions are honest. But finalize separately reads the
/// `final_pk` it promotes to a production key, and nothing tied that key to the
/// verified transcript: an operator could pair an honest transcript with an
/// arbitrary, separately-generated (trapdoored) proving key. This binds them by
/// requiring `final_pk`'s delta to equal the delta the chain ends on — the last
/// contribution's `delta_after` (or the `initial_pk`'s delta for an empty
/// transcript). A key carrying any other delta is rejected.
///
/// (The deeper check that the key's `h_query`/`l_query` were consistently
/// divided by the cumulative delta is tracked separately; this closes the
/// substituted-key path.)
pub fn verify_final_pk(
    initial_pk: &ProvingKey<Bn254>,
    transcript: &Phase2Transcript,
    final_pk: &ProvingKey<Bn254>,
) -> Result<(), VerifyError> {
    let (expected_g1, expected_g2) = match transcript.contributions.last() {
        Some(last) => {
            let position = transcript.contributions.len() - 1;
            let g1 = G1Affine::deserialize_compressed(&last.delta_after_g1[..])
                .map_err(|_| VerifyError::MalformedDeltaG1 { position })?;
            let g2 = G2Affine::deserialize_compressed(&last.delta_after_g2[..])
                .map_err(|_| VerifyError::MalformedDeltaG2 { position })?;
            (g1, g2)
        }
        None => (initial_pk.delta_g1, initial_pk.vk.delta_g2),
    };

    if final_pk.delta_g1 != expected_g1 || final_pk.vk.delta_g2 != expected_g2 {
        return Err(VerifyError::FinalPkDeltaMismatch);
    }
    Ok(())
}

/// Verify the final key's δ-dependent vectors were consistently divided by the
/// cumulative δ, and that every δ-INdependent element is byte-identical to the
/// initial key.
///
/// [`verify_final_pk`] binds the final key's δ to the transcript, but a phase-2
/// contribution touches more than δ: alongside `δ ← δ·δ_i` it divides every
/// `h_query` and `l_query` element by `δ_i⁻¹`. An operator could present a key
/// whose δ matches the chain end (passing [`verify_final_pk`]) yet whose
/// `h_query`/`l_query` were left unscaled — or scaled by a δ they secretly
/// know — keeping the Groth16 trapdoor recoverable and proofs forgeable.
///
/// We cannot divide by the cumulative δ in the clear: it is the toxic waste no
/// honest party holds. So we check the relation *in the exponent* via a
/// pairing. For each element `j`:
///
/// ```text
///   e(final.h_query[j], final.δ_g2) == e(initial.h_query[j], initial.δ_g2)
/// ```
///
/// Both sides collapse to `e(g1, g2)^{H_j}`: `h_query[j]` carries `H_j / δ` and
/// `δ_g2` carries `δ`, so the product recovers the δ-invariant numerator `H_j`.
/// Equality therefore holds iff `h_query[j]` was divided by exactly the δ that
/// `δ_g2` multiplies up to. The thousands of per-element pairings are batched
/// into a single random linear combination — Fiat-Shamir powers `ρ^j` seeded
/// from both keys — collapsing each vector's check to two pairings with
/// negligible soundness error.
///
/// Every other proving-key field is independent of δ; a contribution must leave
/// it untouched, so we require exact equality. That stops a substituted phase-1
/// element (`a_query`, `gamma_abc_g1`, …) from riding in on an honest
/// transcript.
///
/// Call this *after* [`verify_final_pk`]: that one ties `final.δ_g2` to the
/// transcript, this one ties the rest of the key to `final.δ_g2`.
pub fn verify_final_pk_consistency(
    initial_pk: &ProvingKey<Bn254>,
    final_pk: &ProvingKey<Bn254>,
) -> Result<(), VerifyError> {
    // 1. Every δ-independent element must survive a contribution untouched.
    if final_pk.vk.alpha_g1 != initial_pk.vk.alpha_g1 {
        return Err(VerifyError::KeyElementAltered {
            field: "vk.alpha_g1",
        });
    }
    if final_pk.vk.beta_g2 != initial_pk.vk.beta_g2 {
        return Err(VerifyError::KeyElementAltered {
            field: "vk.beta_g2",
        });
    }
    if final_pk.vk.gamma_g2 != initial_pk.vk.gamma_g2 {
        return Err(VerifyError::KeyElementAltered {
            field: "vk.gamma_g2",
        });
    }
    if final_pk.vk.gamma_abc_g1 != initial_pk.vk.gamma_abc_g1 {
        return Err(VerifyError::KeyElementAltered {
            field: "vk.gamma_abc_g1",
        });
    }
    if final_pk.beta_g1 != initial_pk.beta_g1 {
        return Err(VerifyError::KeyElementAltered { field: "beta_g1" });
    }
    if final_pk.a_query != initial_pk.a_query {
        return Err(VerifyError::KeyElementAltered { field: "a_query" });
    }
    if final_pk.b_g1_query != initial_pk.b_g1_query {
        return Err(VerifyError::KeyElementAltered {
            field: "b_g1_query",
        });
    }
    if final_pk.b_g2_query != initial_pk.b_g2_query {
        return Err(VerifyError::KeyElementAltered {
            field: "b_g2_query",
        });
    }

    // 2. The δ-dependent vectors must keep their length (an extra or missing
    //    element would otherwise be silently dropped by the zip in step 3).
    if final_pk.h_query.len() != initial_pk.h_query.len() {
        return Err(VerifyError::QueryLengthMismatch { field: "h_query" });
    }
    if final_pk.l_query.len() != initial_pk.l_query.len() {
        return Err(VerifyError::QueryLengthMismatch { field: "l_query" });
    }

    // 3. Pairing consistency, batched per vector.
    check_query_consistency(
        "h_query",
        &initial_pk.h_query,
        &final_pk.h_query,
        &initial_pk.vk.delta_g2,
        &final_pk.vk.delta_g2,
    )?;
    check_query_consistency(
        "l_query",
        &initial_pk.l_query,
        &final_pk.l_query,
        &initial_pk.vk.delta_g2,
        &final_pk.vk.delta_g2,
    )?;

    Ok(())
}

/// Batched in-the-exponent check that `final[j]` is `initial[j]` scaled by the
/// same δ-ratio that carries `initial_delta_g2` to `final_delta_g2`, for every
/// `j`. See [`verify_final_pk_consistency`] for the algebra.
///
/// Takes a random linear combination `Σ ρ^j · P[j]` of each vector with
/// Fiat-Shamir powers of a challenge ρ seeded from both vectors and both
/// deltas, then compares the two pairings. A single inconsistent element makes
/// the combined relation a non-trivial degree-`<n` polynomial in ρ, which the
/// honest, key-derived ρ vanishes on only with negligible probability.
fn check_query_consistency(
    field: &'static str,
    initial: &[G1Affine],
    final_: &[G1Affine],
    initial_delta_g2: &G2Affine,
    final_delta_g2: &G2Affine,
) -> Result<(), VerifyError> {
    // Empty vectors carry no δ-dependent data and are trivially consistent.
    if initial.is_empty() {
        return Ok(());
    }

    let rho = fiat_shamir_rho(field, initial, final_, initial_delta_g2, final_delta_g2);
    let scalars = scalar_powers(rho, initial.len());

    // Σ ρ^j · P[j] over each vector. msm only errors on a length mismatch,
    // which step 2 already ruled out, so the lengths here are equal by
    // construction.
    let final_combined = G1Projective::msm(final_, &scalars)
        .expect("scalars and bases share a length")
        .into_affine();
    let initial_combined = G1Projective::msm(initial, &scalars)
        .expect("scalars and bases share a length")
        .into_affine();

    // e(Σρ^j·final[j], final.δ_g2) == e(Σρ^j·initial[j], initial.δ_g2)
    let lhs = Bn254::pairing(final_combined, *final_delta_g2);
    let rhs = Bn254::pairing(initial_combined, *initial_delta_g2);
    if lhs != rhs {
        return Err(VerifyError::QueryInconsistent { field });
    }
    Ok(())
}

/// `[1, base, base², …, base^{n-1}]`.
fn scalar_powers(base: Fr, n: usize) -> Vec<Fr> {
    let mut out = Vec::with_capacity(n);
    let mut acc = Fr::one();
    for _ in 0..n {
        out.push(acc);
        acc *= base;
    }
    out
}

/// Fiat-Shamir challenge for the query-consistency RLC. Binding it to both
/// vectors and both deltas means a malformed key cannot be crafted against a
/// known combination: ρ depends on the very bytes the attacker would have to
/// choose, leaving only a hash-grinding fixed point that is infeasible.
fn fiat_shamir_rho(
    domain: &str,
    initial: &[G1Affine],
    final_: &[G1Affine],
    initial_delta_g2: &G2Affine,
    final_delta_g2: &G2Affine,
) -> Fr {
    let mut hasher = Sha512::new();
    hasher.update(b"paraloom-ceremony-query-consistency-v1");
    hasher.update(domain.as_bytes());
    write_canonical(&mut hasher, initial_delta_g2);
    write_canonical(&mut hasher, final_delta_g2);
    for point in initial {
        write_canonical(&mut hasher, point);
    }
    for point in final_ {
        write_canonical(&mut hasher, point);
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::bgm17::apply_contribution;
    use crate::ceremony::transcript::{hash_contribution, CircuitId, Contribution, TranscriptHash};
    use crate::types::NodeId;
    use ark_bn254::Fr;
    use ark_ff::UniformRand;
    use ark_groth16::Groth16;
    use ark_relations::{
        lc,
        r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
    };
    use ark_serialize::CanonicalSerialize;
    use ark_snark::SNARK;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    /// Trivial circuit so circuit_specific_setup yields a real
    /// ProvingKey<Bn254> we can run contributions against.
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

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0xFEED_C0DE_u64)
    }

    /// Apply `n` real contributions to a fresh initial SRS and
    /// return the (initial_pk, transcript) pair the verifier
    /// consumes. The transcript's initial_srs_hash is fixed at
    /// [0u8; 64] for these tests; the chain check uses it as the
    /// first prior_hash and that is all that matters for our
    /// invariants.
    fn build_real_transcript(n: usize) -> (ProvingKey<Bn254>, Phase2Transcript, ProvingKey<Bn254>) {
        let mut rng = rng();
        let (initial_pk, _vk) =
            Groth16::<Bn254>::circuit_specific_setup(TrivialCircuit, &mut rng).unwrap();
        let initial_hash: TranscriptHash = [0u8; 64];
        let mut transcript = Phase2Transcript::new(CircuitId::Deposit, initial_hash);
        let mut current_pk = initial_pk.clone();

        for i in 0..n {
            let mut next_pk = current_pk.clone();
            let delta_i = Fr::rand(&mut rng);
            let proof = apply_contribution(&mut next_pk, delta_i, &mut rng).unwrap();

            let mut delta_after_g1_bytes = Vec::new();
            next_pk
                .delta_g1
                .serialize_compressed(&mut delta_after_g1_bytes)
                .unwrap();
            let mut delta_after_g2_bytes = Vec::new();
            next_pk
                .vk
                .delta_g2
                .serialize_compressed(&mut delta_after_g2_bytes)
                .unwrap();

            let prior_hash = match transcript.contributions.last() {
                Some(prev) => hash_contribution(prev),
                None => initial_hash,
            };
            let contribution = Contribution {
                prior_hash,
                contributor: NodeId(vec![i as u8]),
                delta_after_g1: delta_after_g1_bytes,
                delta_after_g2: delta_after_g2_bytes,
                dleq_proof: proof.to_bytes(),
                contributor_pubkey: vec![0xDDu8; 32],
                signature: vec![0xEEu8; 64],
                attestation: format!("test contributor {}", i),
            };
            transcript.append(contribution).unwrap();
            current_pk = next_pk;
        }

        (initial_pk, transcript, current_pk)
    }

    #[test]
    fn empty_transcript_verifies_against_any_initial_pk() {
        let mut rng = rng();
        let (initial_pk, _vk) =
            Groth16::<Bn254>::circuit_specific_setup(TrivialCircuit, &mut rng).unwrap();
        let transcript = Phase2Transcript::new(CircuitId::Deposit, [0u8; 64]);
        verify_phase2_transcript(&initial_pk, &transcript).expect("empty chain verifies");
    }

    #[test]
    fn chain_of_three_real_contributions_verifies() {
        let (initial_pk, transcript, _) = build_real_transcript(3);
        verify_phase2_transcript(&initial_pk, &transcript)
            .expect("3-contribution real chain verifies end-to-end");
    }

    #[test]
    fn tampered_attestation_breaks_chain_at_next_position() {
        let (initial_pk, mut transcript, _) = build_real_transcript(3);
        // Mutate the first contribution's attestation. Its hash
        // changes; the second contribution's prior_hash no longer
        // matches; the chain check surfaces the break at position 1.
        transcript.contributions[0].attestation = "tampered".to_string();
        match verify_phase2_transcript(&initial_pk, &transcript) {
            Err(VerifyError::Chain(TranscriptError::ChainBroken { position })) => {
                assert_eq!(position, 1);
            }
            other => panic!("expected Chain(ChainBroken at 1), got {:?}", other),
        }
    }

    #[test]
    fn wrong_initial_pk_fails_first_dleq_check() {
        let (_real_initial_pk, transcript, _) = build_real_transcript(2);
        // Hand the verifier an unrelated initial PK. The chain
        // check still passes (it does not depend on the PK), but
        // the very first DLEQ check fails because delta_before_g1
        // does not match the value the prover used.
        let mut other_rng = StdRng::seed_from_u64(0xDEAD_BEEF_u64);
        let (other_pk, _vk) =
            Groth16::<Bn254>::circuit_specific_setup(TrivialCircuit, &mut other_rng).unwrap();
        match verify_phase2_transcript(&other_pk, &transcript) {
            Err(VerifyError::DleqRejected { position: 0, .. }) => {}
            other => panic!("expected DleqRejected at 0, got {:?}", other),
        }
    }

    #[test]
    fn malformed_dleq_proof_bytes_rejected() {
        let (initial_pk, mut transcript, _) = build_real_transcript(1);
        // Replace the single contribution's DLEQ bytes with
        // garbage. The chain hash also changes, but with only one
        // contribution there is no next link to break, so the
        // chain check passes and we hit MalformedDleq.
        transcript.contributions[0].dleq_proof = vec![0xAAu8; 16];
        // The chain check verifies prior_hash for the *first*
        // contribution against transcript.initial_srs_hash; that
        // still matches because we did not mutate prior_hash. So
        // the chain check passes and the verifier reaches the
        // bytes parse, which fails.
        match verify_phase2_transcript(&initial_pk, &transcript) {
            Err(VerifyError::MalformedDleq { position: 0, .. }) => {}
            other => panic!("expected MalformedDleq at 0, got {:?}", other),
        }
    }

    #[test]
    fn final_pk_matching_the_transcript_passes() {
        let (initial_pk, transcript, final_pk) = build_real_transcript(3);
        verify_final_pk(&initial_pk, &transcript, &final_pk)
            .expect("the real final pk must match the transcript it was built from");
    }

    #[test]
    fn substituted_final_pk_is_rejected() {
        // An honest transcript paired with an unrelated, separately-generated
        // proving key — the trapdoored-key substitution finalize must refuse.
        let (initial_pk, transcript, _real_final_pk) = build_real_transcript(3);
        let mut other_rng = StdRng::seed_from_u64(0xBAD0_5EED_u64);
        let (evil_pk, _vk) =
            Groth16::<Bn254>::circuit_specific_setup(TrivialCircuit, &mut other_rng).unwrap();
        match verify_final_pk(&initial_pk, &transcript, &evil_pk) {
            Err(VerifyError::FinalPkDeltaMismatch) => {}
            other => panic!("expected FinalPkDeltaMismatch, got {:?}", other),
        }
    }

    #[test]
    fn consistent_final_pk_passes_query_consistency() {
        // The real final pk from a 3-contribution chain has its h_query and
        // l_query divided by exactly the cumulative δ — the in-exponent check
        // must accept it.
        let (initial_pk, _transcript, final_pk) = build_real_transcript(3);
        verify_final_pk_consistency(&initial_pk, &final_pk)
            .expect("an honestly contributed key is δ⁻¹-consistent");
    }

    #[test]
    fn unscaled_h_query_is_rejected() {
        // δ matches the chain end (verify_final_pk would pass), but h_query was
        // left at the initial key's value instead of being divided by δ. The
        // pairing check must catch the inconsistency.
        let (initial_pk, _transcript, mut final_pk) = build_real_transcript(3);
        final_pk.h_query = initial_pk.h_query.clone();
        match verify_final_pk_consistency(&initial_pk, &final_pk) {
            Err(VerifyError::QueryInconsistent { field: "h_query" }) => {}
            other => panic!("expected QueryInconsistent(h_query), got {:?}", other),
        }
    }

    #[test]
    fn tampered_single_l_query_element_is_rejected() {
        // A single l_query element re-scaled by an unrelated scalar breaks the
        // relation; the random linear combination surfaces it.
        let (initial_pk, _transcript, mut final_pk) = build_real_transcript(2);
        let mut rng = StdRng::seed_from_u64(0x1234_5678_u64);
        let bogus = Fr::rand(&mut rng);
        final_pk.l_query[0] = (final_pk.l_query[0] * bogus).into_affine();
        match verify_final_pk_consistency(&initial_pk, &final_pk) {
            Err(VerifyError::QueryInconsistent { field: "l_query" }) => {}
            other => panic!("expected QueryInconsistent(l_query), got {:?}", other),
        }
    }

    #[test]
    fn altered_a_query_is_rejected_as_key_element() {
        // a_query is δ-independent; a contribution must not touch it. Swapping
        // one element is caught by the byte-equality gate before any pairing.
        let (initial_pk, _transcript, mut final_pk) = build_real_transcript(1);
        let mut rng = StdRng::seed_from_u64(0x9999_u64);
        let bogus = Fr::rand(&mut rng);
        final_pk.a_query[0] = (final_pk.a_query[0] * bogus).into_affine();
        match verify_final_pk_consistency(&initial_pk, &final_pk) {
            Err(VerifyError::KeyElementAltered { field: "a_query" }) => {}
            other => panic!("expected KeyElementAltered(a_query), got {:?}", other),
        }
    }

    #[test]
    fn altered_gamma_abc_is_rejected_as_key_element() {
        let (initial_pk, _transcript, mut final_pk) = build_real_transcript(1);
        let mut rng = StdRng::seed_from_u64(0xAAAA_u64);
        let bogus = Fr::rand(&mut rng);
        final_pk.vk.gamma_abc_g1[0] = (final_pk.vk.gamma_abc_g1[0] * bogus).into_affine();
        match verify_final_pk_consistency(&initial_pk, &final_pk) {
            Err(VerifyError::KeyElementAltered {
                field: "vk.gamma_abc_g1",
            }) => {}
            other => panic!(
                "expected KeyElementAltered(vk.gamma_abc_g1), got {:?}",
                other
            ),
        }
    }

    #[test]
    fn h_query_length_mismatch_is_rejected() {
        let (initial_pk, _transcript, mut final_pk) = build_real_transcript(1);
        let extra = final_pk.h_query[0];
        final_pk.h_query.push(extra);
        match verify_final_pk_consistency(&initial_pk, &final_pk) {
            Err(VerifyError::QueryLengthMismatch { field: "h_query" }) => {}
            other => panic!("expected QueryLengthMismatch(h_query), got {:?}", other),
        }
    }

    #[test]
    fn empty_transcript_requires_the_initial_pk_unchanged() {
        let mut rng = rng();
        let (initial_pk, _vk) =
            Groth16::<Bn254>::circuit_specific_setup(TrivialCircuit, &mut rng).unwrap();
        let transcript = Phase2Transcript::new(CircuitId::Deposit, [0u8; 64]);

        // With no contributions the final pk must be the initial pk itself.
        verify_final_pk(&initial_pk, &transcript, &initial_pk)
            .expect("an empty ceremony's final pk is the initial pk");

        // A different key over an empty transcript is rejected.
        let mut other_rng = StdRng::seed_from_u64(0xABCD_u64);
        let (other_pk, _vk) =
            Groth16::<Bn254>::circuit_specific_setup(TrivialCircuit, &mut other_rng).unwrap();
        match verify_final_pk(&initial_pk, &transcript, &other_pk) {
            Err(VerifyError::FinalPkDeltaMismatch) => {}
            other => panic!("expected FinalPkDeltaMismatch, got {:?}", other),
        }
    }
}
