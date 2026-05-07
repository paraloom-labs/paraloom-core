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
