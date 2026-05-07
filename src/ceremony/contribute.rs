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

use ark_bls12_381::Bls12_381;
use ark_groth16::ProvingKey;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use super::transcript::Phase2Transcript;

/// Errors surfaced by the contributor flow.
#[derive(Debug, thiserror::Error)]
pub enum ContributeError {
    #[error("io error reading or writing ceremony files: {0}")]
    Io(#[from] io::Error),

    #[error("failed to deserialise a ceremony artefact: {0}")]
    Deserialize(String),

    #[error("failed to serialise a ceremony artefact: {0}")]
    Serialize(String),
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
