//! Phase-2 ceremony contributor CLI.
//!
//! Reads the previous proving key and (optionally) transcript,
//! samples this contributor's `δ_i` from OS entropy, applies the
//! BGM17 contribution, appends the resulting record to the
//! transcript, and writes the new proving key plus extended
//! transcript to the supplied output paths. Tracking issue #64.
//!
//! Omit --prior-transcript on the very first contribution; the
//! binary then seeds a fresh transcript from --circuit and
//! --initial-srs-hash.

use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, Result};
use clap::Parser;
use paraloom::ceremony::{
    contribute, read_pk, read_transcript, try_hash_from_hex, write_pk, write_transcript, CircuitId,
};
use paraloom::types::NodeId;
use rand::rngs::OsRng;

#[derive(Parser, Debug)]
#[command(
    name = "paraloom-ceremony-contribute",
    about = "Apply one phase-2 ceremony contribution and extend the transcript"
)]
struct Args {
    /// Path to the previous proving key file (compressed-arkworks).
    #[arg(long)]
    prior_pk: PathBuf,

    /// Path to the previous transcript file (bincode). Omit on the
    /// very first contribution.
    #[arg(long)]
    prior_transcript: Option<PathBuf>,

    /// Output path for the new proving key.
    #[arg(long)]
    output_pk: PathBuf,

    /// Output path for the extended transcript.
    #[arg(long)]
    output_transcript: PathBuf,

    /// Which circuit this transcript covers. Only used when
    /// --prior-transcript is omitted.
    #[arg(long, default_value = "deposit")]
    circuit: String,

    /// Hex-encoded SHA-512 of the initial SRS. Only used when
    /// --prior-transcript is omitted.
    #[arg(long, default_value_t = "00".repeat(64))]
    initial_srs_hash: String,

    /// Hex-encoded NodeId of this contributor. Round-trips through
    /// NodeId's Display/FromStr impls.
    #[arg(long)]
    contributor_hex: String,

    /// Free-form attestation describing what this contributor did
    /// (hardware, OS, witnesses). Public, audit-only.
    #[arg(long)]
    attestation: String,
}

fn main() -> Result<()> {
    env_logger::init();
    let args = Args::parse();

    let circuit =
        CircuitId::from_str(&args.circuit).map_err(|e| anyhow::anyhow!("--circuit: {}", e))?;
    let initial_srs_hash = try_hash_from_hex(&args.initial_srs_hash)
        .map_err(|e| anyhow::anyhow!("--initial-srs-hash: {}", e))?;
    let contributor =
        NodeId::from_str(&args.contributor_hex).context("--contributor-hex is not valid hex")?;

    let prior_pk = read_pk(&args.prior_pk)?;
    let prior_transcript = match &args.prior_transcript {
        Some(path) => Some(read_transcript(path)?),
        None => None,
    };

    let mut rng = OsRng;
    let (new_pk, new_transcript) = contribute(
        prior_pk,
        prior_transcript,
        circuit,
        initial_srs_hash,
        contributor,
        args.attestation,
        &mut rng,
    )?;

    write_pk(&new_pk, &args.output_pk)?;
    write_transcript(&new_transcript, &args.output_transcript)?;

    println!(
        "Contribution applied. Transcript length: {}",
        new_transcript.len()
    );
    Ok(())
}
