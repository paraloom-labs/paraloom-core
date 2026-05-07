//! Phase-2 ceremony verifier CLI.
//!
//! Reads the initial single-source proving key plus a finalised
//! `Phase2Transcript` and walks the chain end-to-end, confirming
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
use paraloom::ceremony::{read_pk, read_transcript, verify_phase2_transcript};

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

    match verify_phase2_transcript(&initial_pk, &transcript) {
        Ok(()) => {
            println!(
                "Transcript verified. Circuit: {}, contributions: {}",
                transcript.circuit.label(),
                transcript.len()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("transcript verification FAILED: {}", e);
            ExitCode::FAILURE
        }
    }
}
