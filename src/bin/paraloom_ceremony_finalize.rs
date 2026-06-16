//! Promote a ceremony output to production proving and verifying
//! keys.
//!
//! Reads the initial single-source proving key, the final
//! ceremony proving key, and the finalised transcript. Verifies
//! the transcript end-to-end via `verify_phase2_transcript`. On
//! success extracts the verifying key from the proving key and
//! writes both to the supplied output paths in the same
//! compressed-arkworks format the rest of the codebase already
//! consumes via `keys/<circuit>_*_v3.key`. On any verification
//! failure refuses to write anything and surfaces the underlying
//! diagnostic.
//!
//! Tracking issue #64. The existing `setup_*_ceremony` binaries
//! remain as the testnet single-source tool; this binary is the
//! mainnet promotion path.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use paraloom::ceremony::{
    read_pk, read_transcript, verify_final_pk, verify_final_pk_consistency,
    verify_phase2_transcript, write_compressed,
};

#[derive(Parser, Debug)]
#[command(
    name = "paraloom-ceremony-finalize",
    about = "Verify a ceremony output and write production proving + verifying keys"
)]
struct Args {
    /// Path to the initial single-source proving key (the input
    /// the first contributor consumed).
    #[arg(long)]
    initial_pk: PathBuf,

    /// Path to the final proving key produced by the last
    /// contribution in the chain.
    #[arg(long)]
    ceremony_pk: PathBuf,

    /// Path to the finalised transcript.
    #[arg(long)]
    transcript: PathBuf,

    /// Where to write the production proving key. Conventionally
    /// `keys/<circuit>_proving_v3.key`.
    #[arg(long)]
    output_pk: PathBuf,

    /// Where to write the production verifying key. Conventionally
    /// `keys/<circuit>_verifying_v3.key`.
    #[arg(long)]
    output_vk: PathBuf,
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
    let ceremony_pk = match read_pk(&args.ceremony_pk) {
        Ok(pk) => pk,
        Err(e) => {
            eprintln!("failed to read ceremony PK: {}", e);
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

    if let Err(e) = verify_phase2_transcript(&initial_pk, &transcript) {
        eprintln!("transcript verification FAILED, refusing to write: {}", e);
        return ExitCode::FAILURE;
    }

    // Bind the key we are about to promote to the verified transcript: refuse a
    // ceremony PK whose delta is not the one the chain culminates in, so an
    // honest transcript cannot be paired with a substituted (trapdoored) key.
    if let Err(e) = verify_final_pk(&initial_pk, &transcript, &ceremony_pk) {
        eprintln!(
            "ceremony PK does not match the transcript, refusing to write: {}",
            e
        );
        return ExitCode::FAILURE;
    }

    // verify_final_pk binds the key's delta to the transcript; this binds the
    // rest of the key to that delta — h_query/l_query must be the cumulative
    // delta^-1 scaling, and every delta-independent element must be unchanged.
    // Together they reject a trapdoored key carrying the right delta but
    // malformed queries.
    if let Err(e) = verify_final_pk_consistency(&initial_pk, &ceremony_pk) {
        eprintln!(
            "ceremony PK is not delta-consistent with the initial key, refusing to write: {}",
            e
        );
        return ExitCode::FAILURE;
    }

    if let Err(e) = write_compressed(&ceremony_pk, &args.output_pk) {
        eprintln!("failed to write proving key: {}", e);
        return ExitCode::from(2);
    }
    if let Err(e) = write_compressed(&ceremony_pk.vk, &args.output_vk) {
        eprintln!("failed to write verifying key: {}", e);
        return ExitCode::from(2);
    }

    println!(
        "Ceremony finalised. Circuit: {}, contributions: {}",
        transcript.circuit.label(),
        transcript.len()
    );
    println!("  proving key  -> {:?}", args.output_pk);
    println!("  verifying key -> {:?}", args.output_vk);
    ExitCode::SUCCESS
}
