use ark_serialize::CanonicalSerialize;
use ark_std::rand::thread_rng;
use paraloom::privacy::circuits::{Groth16ProofSystem, WithdrawCircuitV2};
use paraloom::privacy::merkle::DEFAULT_TREE_DEPTH;
use std::fs;
use std::path::Path;

// Dev trusted setup for the spend-key withdraw circuit (circuit v2, #293).
//
// Separate `_v2` filenames so this never collides with the live v1 `_v4` keys:
// the cutover swaps the prover, on-chain verifier and VK over together, and
// until that flip both key sets must be able to sit on disk side by side.
//
// The v2 circuit's public-input layout is wider than v1's — [merkle_root,
// nullifier, withdraw_amount, ext_data_hash, asset_id], 5 inputs → 6 IC points
// in the emitted verifying key — and the on-chain verifier picks that layout up
// at cutover. This is a single-party ("dev-key now") setup; a real multi-party
// MPC ceremony remains the mainnet gate (#64).
const PROVING_KEY_PATH: &str = "keys/withdraw_v2_proving.key";
const VERIFYING_KEY_PATH: &str = "keys/withdraw_v2_verifying.key";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("=== Withdrawal Circuit v2 Setup Ceremony (spend-key) ===\n");
    println!("Generates proving and verifying keys for the fixed-depth");
    println!(
        "spend-key withdrawal circuit (depth {}).\n",
        DEFAULT_TREE_DEPTH
    );
    println!("This is a single-party dev TRUSTED SETUP. The proving key's");
    println!("toxic waste must be discarded; a real multi-party MPC ceremony");
    println!("remains the mainnet gate (#64).\n");

    if Path::new(PROVING_KEY_PATH).exists() || Path::new(VERIFYING_KEY_PATH).exists() {
        println!("WARNING: v2 keys already exist!");
        println!("  Proving key:   {}", PROVING_KEY_PATH);
        println!("  Verifying key: {}", VERIFYING_KEY_PATH);
        println!("\nDo you want to overwrite? (y/N)");

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Setup cancelled.");
            return Ok(());
        }
    }

    fs::create_dir_all("keys")?;

    println!("Creating dummy circuit for setup...");
    // Setup only reads the circuit's constraint *shape*, not the witness
    // values, but the shape depends on the Merkle path length — so the dummy
    // must carry a full depth-`DEFAULT_TREE_DEPTH` path, the fixed depth every
    // real withdrawal proof uses. An empty path would bake the wrong shape.
    let dummy_path: Vec<([u8; 32], bool)> = vec![([0u8; 32], false); DEFAULT_TREE_DEPTH];
    let dummy_circuit = WithdrawCircuitV2 {
        merkle_root: Some([0u8; 32]),
        nullifier: Some([0u8; 32]),
        withdraw_amount: Some(0),
        ext_data_hash: Some([0u8; 32]),
        input_value: Some(0),
        blinding: Some([0u8; 32]),
        privkey: Some([0u8; 32]),
        asset_id: Some([0u8; 32]),
        input_path: Some(dummy_path),
    };

    println!("Running trusted setup...");
    println!("This may take a few minutes...\n");

    let mut rng = thread_rng();
    let (proving_key, verifying_key) =
        Groth16ProofSystem::setup::<WithdrawCircuitV2, _>(dummy_circuit, &mut rng)?;

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

    println!("\nKEY SECURITY:");
    println!("  - Keep the proving key SECRET; discard the setup toxic waste");
    println!("  - The verifying key can be public");
    println!("  - Never commit keys to version control (keys/ is gitignored)");
    println!("\nNext steps:");
    println!("  1. Emit the on-chain VK constants for the program:");
    println!("       cargo test --lib \\");
    println!("         privacy::onchain_verifier::tests::emit_program_fixture_v2 \\");
    println!("         -- --ignored --nocapture");
    println!("  2. Paste the emitted VK into programs/paraloom/src/withdraw_vk_data.rs");
    println!("  3. Wire the program's withdraw verifier to the 5-input v2 layout");

    Ok(())
}
