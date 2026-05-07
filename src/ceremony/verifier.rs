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

use ark_bls12_381::{Bls12_381, G1Affine, G2Affine};
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
    initial_pk: &ProvingKey<Bls12_381>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ceremony::bgm17::apply_contribution;
    use crate::ceremony::transcript::{hash_contribution, CircuitId, Contribution, TranscriptHash};
    use crate::types::NodeId;
    use ark_bls12_381::Fr;
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
    /// ProvingKey<Bls12_381> we can run contributions against.
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
    fn build_real_transcript(n: usize) -> (ProvingKey<Bls12_381>, Phase2Transcript) {
        let mut rng = rng();
        let (initial_pk, _vk) =
            Groth16::<Bls12_381>::circuit_specific_setup(TrivialCircuit, &mut rng).unwrap();
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

        (initial_pk, transcript)
    }

    #[test]
    fn empty_transcript_verifies_against_any_initial_pk() {
        let mut rng = rng();
        let (initial_pk, _vk) =
            Groth16::<Bls12_381>::circuit_specific_setup(TrivialCircuit, &mut rng).unwrap();
        let transcript = Phase2Transcript::new(CircuitId::Deposit, [0u8; 64]);
        verify_phase2_transcript(&initial_pk, &transcript).expect("empty chain verifies");
    }

    #[test]
    fn chain_of_three_real_contributions_verifies() {
        let (initial_pk, transcript) = build_real_transcript(3);
        verify_phase2_transcript(&initial_pk, &transcript)
            .expect("3-contribution real chain verifies end-to-end");
    }
}
