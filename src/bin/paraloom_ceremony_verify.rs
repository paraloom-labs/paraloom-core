//! Phase-2 ceremony verifier CLI.
//!
//! Reads the initial single-source proving key plus a finalised
//! `Phase2Transcript`, confirms the key is the one the transcript
//! was built against, and walks the chain end-to-end, confirming
//! that every contribution's hash links and DLEQ proof verify.
//! Tracking issue #64.
//!
//! Anyone can run this against a published transcript: it consumes
//! only public artefacts (the initial PK from the existing
//! `setup_*_ceremony` binaries plus the transcript bincode) and
//! returns a non-zero exit code on any failure with a position-
//! tagged diagnostic.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use paraloom::ceremony::{hash_contribution, read_pk, read_transcript, verify_phase2_transcript};
use sha2::{Digest, Sha512};

#[derive(Parser, Debug)]
#[command(
    name = "paraloom-ceremony-verify",
    about = "Verify a finalised phase-2 ceremony transcript end to end"
)]
struct Args {
    /// Path to the initial single-source proving key file
    /// (compressed-arkworks). The verifier uses its delta values
    /// as the chain's starting point.
    #[arg(long)]
    initial_pk: PathBuf,

    /// Path to the finalised transcript file (bincode).
    #[arg(long)]
    transcript: PathBuf,
}

fn main() -> ExitCode {
    env_logger::init();
    let args = Args::parse();

    let initial_pk = match read_pk(&args.initial_pk) {
        Ok(pk) => pk,
        Err(e) => {
            eprintln!("failed to read initial PK: {}", e);
            return ExitCode::from(2);
        }
    };

    let transcript = match read_transcript(&args.transcript) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("failed to read transcript: {}", e);
            return ExitCode::from(2);
        }
    };

    // Bind the key on disk to the one the transcript was built against,
    // the same digest `paraloom_ceremony_finalize` pins. Without this the
    // chain is only ever checked against whatever key the caller happened
    // to pass, and a substituted initial SRS surfaces as an opaque
    // "position 0" DLEQ failure — or, if the transcript records no pin at
    // all, is not caught here.
    let initial_pk_file_hash = match std::fs::read(&args.initial_pk) {
        Ok(bytes) => Sha512::digest(&bytes),
        Err(e) => {
            eprintln!("failed to re-read initial PK for hashing: {}", e);
            return ExitCode::from(2);
        }
    };
    if transcript.initial_srs_hash == [0u8; 64] {
        eprintln!(
            "transcript verification FAILED: the transcript records no \
             initial-SRS hash.\n  \
             The chain was started without --initial-srs-hash, so nothing \
             pins it to an initial key."
        );
        return ExitCode::FAILURE;
    }
    if initial_pk_file_hash[..] != transcript.initial_srs_hash[..] {
        eprintln!(
            "transcript verification FAILED: --initial-pk is not the key \
             this chain was built on.\n  \
             transcript pins: {}\n  \
             key on disk:     {}",
            hex::encode(transcript.initial_srs_hash),
            hex::encode(initial_pk_file_hash),
        );
        return ExitCode::FAILURE;
    }

    match verify_phase2_transcript(&initial_pk, &transcript) {
        Ok(()) => {
            println!(
                "Transcript verified. Circuit: {}, contributions: {}",
                transcript.circuit.label(),
                transcript.len()
            );
            // The chain-tip hash is what `paraloom_ceremony_finalize
            // --final-contribution-hash` pins: print it after every
            // verification so the coordinator can record the exact
            // chain they approved.
            if let Some(tip) = transcript.contributions.last() {
                println!(
                    "  final contribution hash: {}",
                    hex::encode(hash_contribution(tip))
                );
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("transcript verification FAILED: {}", e);
            ExitCode::FAILURE
        }
    }
}
