//! Contributor-side flow for a phase-2 ceremony.
//!
//! Wraps the BGM17 contribution math and the transcript data
//! layer into a single high-level operation a contributor (or the
//! contributor CLI) can call to extend a transcript with one
//! contribution. Pure orchestration; the cryptographic core lives
//! in [`super::bgm17`] and the data shape in [`super::transcript`].

use std::fs;
use std::io;
use std::path::Path;

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::UniformRand;
use ark_groth16::ProvingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::{CryptoRng, RngCore};

use crate::types::NodeId;

use super::bgm17::{apply_contribution, BgmError};
use super::transcript::{
    CircuitId, Contribution, Phase2Transcript, TranscriptError, TranscriptHash,
};

/// Errors surfaced by the contributor flow.
#[derive(Debug, thiserror::Error)]
pub enum ContributeError {
    #[error("io error reading or writing ceremony files: {0}")]
    Io(#[from] io::Error),

    #[error("failed to deserialise a ceremony artefact: {0}")]
    Deserialize(String),

    #[error("failed to serialise a ceremony artefact: {0}")]
    Serialize(String),

    #[error("BGM17 contribution failed: {0}")]
    Bgm(#[from] BgmError),

    #[error("transcript chain rejected the new contribution: {0}")]
    Transcript(#[from] TranscriptError),
}

/// Apply one contribution and return the updated proving key plus
/// the extended transcript. Pure orchestration of the cryptographic
/// pieces in [`super::bgm17`] and the data shape in
/// [`super::transcript`].
///
/// The caller supplies `prior_pk` and the previous `prior_transcript`
/// (or `None` for the very first contribution, in which case
/// `initial_srs_hash` seeds the transcript). `delta_i` is sampled
/// inside this function from `rng` and is dropped at the end of the
/// call so it does not outlive the stack frame; the caller's `rng`
/// remains the only entropy reference.
///
/// `contributor_pubkey` and `signature` on the resulting
/// Contribution are left empty in this commit; a follow-up PR
/// wires up signed attestations once the signing-key plumbing
/// lands. Verifiers built from this module check the DLEQ and
/// chain integrity regardless; signatures only add the
/// social-trust layer on top.
pub fn contribute<R: RngCore + CryptoRng>(
    mut prior_pk: ProvingKey<Bls12_381>,
    prior_transcript: Option<Phase2Transcript>,
    circuit: CircuitId,
    initial_srs_hash: TranscriptHash,
    contributor: NodeId,
    attestation: String,
    rng: &mut R,
) -> Result<(ProvingKey<Bls12_381>, Phase2Transcript), ContributeError> {
    let delta_i = Fr::rand(rng);
    let proof = apply_contribution(&mut prior_pk, delta_i, rng)?;

    let mut delta_after_g1 = Vec::new();
    prior_pk
        .delta_g1
        .serialize_compressed(&mut delta_after_g1)
        .map_err(|e| ContributeError::Serialize(format!("delta_after_g1: {}", e)))?;
    let mut delta_after_g2 = Vec::new();
    prior_pk
        .vk
        .delta_g2
        .serialize_compressed(&mut delta_after_g2)
        .map_err(|e| ContributeError::Serialize(format!("delta_after_g2: {}", e)))?;

    let mut transcript = prior_transcript
        .unwrap_or_else(|| Phase2Transcript::new(circuit.clone(), initial_srs_hash));
    let prior_hash = match transcript.contributions.last() {
        Some(prev) => super::transcript::hash_contribution(prev),
        None => transcript.initial_srs_hash,
    };

    let contribution = Contribution {
        prior_hash,
        contributor,
        delta_after_g1,
        delta_after_g2,
        dleq_proof: proof.to_bytes(),
        contributor_pubkey: Vec::new(),
        signature: Vec::new(),
        attestation,
    };
    transcript.append(contribution)?;

    Ok((prior_pk, transcript))
}

/// Read a `ProvingKey<Bls12_381>` from a compressed-arkworks file.
pub fn read_pk(path: &Path) -> Result<ProvingKey<Bls12_381>, ContributeError> {
    let bytes = fs::read(path)?;
    ProvingKey::<Bls12_381>::deserialize_compressed(&bytes[..])
        .map_err(|e| ContributeError::Deserialize(format!("ProvingKey at {:?}: {}", path, e)))
}

/// Write a `ProvingKey<Bls12_381>` to a compressed-arkworks file.
pub fn write_pk(pk: &ProvingKey<Bls12_381>, path: &Path) -> Result<(), ContributeError> {
    let mut bytes = Vec::new();
    pk.serialize_compressed(&mut bytes)
        .map_err(|e| ContributeError::Serialize(format!("ProvingKey to {:?}: {}", path, e)))?;
    fs::write(path, &bytes)?;
    Ok(())
}

/// Read a `Phase2Transcript` from a bincode file.
pub fn read_transcript(path: &Path) -> Result<Phase2Transcript, ContributeError> {
    let bytes = fs::read(path)?;
    bincode::deserialize::<Phase2Transcript>(&bytes)
        .map_err(|e| ContributeError::Deserialize(format!("Phase2Transcript at {:?}: {}", path, e)))
}

/// Write a `Phase2Transcript` to a bincode file.
pub fn write_transcript(transcript: &Phase2Transcript, path: &Path) -> Result<(), ContributeError> {
    let bytes = bincode::serialize(transcript).map_err(|e| {
        ContributeError::Serialize(format!("Phase2Transcript to {:?}: {}", path, e))
    })?;
    fs::write(path, &bytes)?;
    Ok(())
}
