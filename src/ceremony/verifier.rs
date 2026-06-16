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

use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;

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
