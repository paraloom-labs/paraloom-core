use ark_serialize::CanonicalSerialize;
use ark_std::rand::thread_rng;
use paraloom::privacy::circuits::{
    Groth16ProofSystem, TransactCircuitV3, TX_LEVELS, TX_NINS, TX_NOUTS,
};
use sha2::{Digest, Sha512};
use std::fs;
use std::path::Path;

// Single-party setup for the unified transact circuit (circuit v3, #350).
//
// This produces the *initial* SRS of the phase-2 ceremony (#659), not a
// production key. Its trapdoor is known to whoever runs it; the multi-party
// chain is what removes that trust, and it is sound as long as one contributor
// destroys their share. The same binary therefore serves both roles the v2
// setups did: it seeds the dev key used on devnet, and it seeds the chain.
//
// The key it writes must then stay FIXED for the whole ceremony: every
// contribution's delta chain anchors on it, and `paraloom_ceremony_finalize`
// re-reads it to match `--initial-srs-hash`. Back it up before contribution #1.
const PROVING_KEY_PATH: &str = "keys/transact_v3_proving.key";
const VERIFYING_KEY_PATH: &str = "keys/transact_v3_verifying.key";

/// SHA-512 over the serialised proving key, the digest
/// `paraloom_ceremony_finalize --initial-srs-hash` pins.
fn srs_hash(bytes: &[u8]) -> String {
    hex::encode(Sha512::digest(bytes))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("=== Transact Circuit v3 Setup (unified UTXO transact) ===\n");
    println!(
        "Generates the proving and verifying keys for the unified\n\
         {}-in / {}-out transact circuit over a depth-{} tree.\n",
        TX_NINS, TX_NOUTS, TX_LEVELS
    );
    println!("This is a SINGLE-PARTY setup. The key it writes is the initial");
    println!("SRS of the phase-2 MPC ceremony (#659), not a production key —");
    println!("its toxic waste is known to whoever runs this. Only the ceremony");
    println!("chain makes it mainnet-grade.\n");

    if Path::new(PROVING_KEY_PATH).exists() || Path::new(VERIFYING_KEY_PATH).exists() {
        println!("WARNING: transact v3 keys already exist!");
        println!("  Proving key:   {}", PROVING_KEY_PATH);
        println!("  Verifying key: {}", VERIFYING_KEY_PATH);
        println!("\nOverwriting mid-ceremony invalidates every contribution made");
        println!("so far, and orphans the VK constants already emitted from the");
        println!("existing key. Overwrite? (y/N)");

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            println!("\nSetup cancelled; keys left untouched.");
            if let Ok(existing) = fs::read(PROVING_KEY_PATH) {
                println!(
                    "\nInitial-SRS hash of the existing key (pin this if you\n\
                     start the ceremony from it):\n  {}",
                    srs_hash(&existing)
                );
            }
            return Ok(());
        }
    }

    fs::create_dir_all("keys")?;

    println!("Building the setup circuit...");
    // Setup reads only the constraint shape. `blank()` carries no witness
    // values but does fix that shape: the Merkle path length comes from the
    // TX_LEVELS index bits rather than from the path witness, so a blank
    // instance bakes the same R1CS every real proof is checked against.
    let circuit = TransactCircuitV3::blank();

    println!("Running trusted setup...");
    println!("This may take a few minutes...\n");

    let mut rng = thread_rng();
    let (proving_key, verifying_key) = Groth16ProofSystem::setup(circuit, &mut rng)?;

    println!("Serializing keys...");
    let mut proving_key_bytes = Vec::new();
    proving_key.serialize_compressed(&mut proving_key_bytes)?;

    let mut verifying_key_bytes = Vec::new();
    verifying_key.serialize_compressed(&mut verifying_key_bytes)?;

    println!("Writing keys to disk...");
    fs::write(PROVING_KEY_PATH, &proving_key_bytes)?;
    fs::write(VERIFYING_KEY_PATH, &verifying_key_bytes)?;

    println!("\n=== Setup Complete! ===");
    println!(
        "Proving key:   {} ({} bytes)",
        PROVING_KEY_PATH,
        proving_key_bytes.len()
    );
    println!(
        "Verifying key: {} ({} bytes)",
        VERIFYING_KEY_PATH,
        verifying_key_bytes.len()
    );
    println!("\nInitial-SRS hash (SHA-512 of the proving key):");
    println!("  {}", srs_hash(&proving_key_bytes));

    println!("\nKEY SECURITY:");
    println!("  - Discard the setup toxic waste from this run");
    println!("  - The verifying key can be public");
    println!("  - Never commit keys to version control (keys/ is gitignored)");
    println!("\nNext steps to start the ceremony (#659):");
    println!("  1. Back the initial key up, so it survives the chain:");
    println!(
        "       cp {} {}.dev.bak",
        PROVING_KEY_PATH, PROVING_KEY_PATH
    );
    println!("  2. Freeze the circuit: commit .ceremony-in-progress to main");
    println!("  3. Hand the key to contributor #1 with the hash above:");
    println!("       paraloom_ceremony_contribute --circuit transact \\");
    println!("         --initial-srs-hash <hash above> ...");
    println!("  4. After finalize, regenerate the on-chain VK constants:");
    println!("       TRANSACT_V3_PROVING_KEY=... TRANSACT_V3_VERIFYING_KEY=... \\");
    println!("         cargo run --release --bin emit_transact_v3_fixture");

    Ok(())
}
