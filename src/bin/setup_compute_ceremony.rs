//! Compute Circuit Trusted Setup Ceremony
//!
//! Generates proving and verifying keys for the private compute circuit.
//!
//! ⚠️ WARNING: This is a SINGLE-PARTY setup suitable for DEVNET/TESTING ONLY!
//!
//! For MAINNET, a multi-party computation ceremony with 50+ participants is required
//! to ensure that no single party can generate fake proofs.
//!
//! # Usage
//!
//! ```bash
//! cargo run --bin setup_compute_ceremony
//! ```
//!
//! This will generate:
//! - `keys/compute_proving.key` (1-2 MB)
//! - `keys/compute_verifying.key` (~1 KB)
//!
//! # Security Notes
//!
//! - Keys are stored locally and NOT committed to git (.gitignore)
//! - Each developer must run this ceremony on their machine
//! - The "toxic waste" (randomness) is automatically discarded
//! - For production, use a multi-party ceremony (e.g., Powers of Tau)

use ark_bls12_381::Bls12_381;
use ark_groth16::Groth16;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use paraloom::compute::ComputeCircuit;
use std::fs;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("\n╔════════════════════════════════════════════════════════════╗");
    println!("║  Compute Circuit Trusted Setup Ceremony                    ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    println!("⚠️  WARNING: Single-party setup (DEVNET/TESTING ONLY)");
    println!("⚠️  For MAINNET: Multi-party ceremony required (50+ participants)\n");

    // Ensure keys directory exists
    let keys_dir = Path::new("keys");
    if !keys_dir.exists() {
        println!("📁 Creating keys directory...");
        fs::create_dir_all(keys_dir)?;
    }

    let proving_key_path = keys_dir.join("compute_proving.key");
    let verifying_key_path = keys_dir.join("compute_verifying.key");

    // Check if keys already exist
    if proving_key_path.exists() && verifying_key_path.exists() {
        println!("⚠️  Keys already exist:");
        println!("   - {}", proving_key_path.display());
        println!("   - {}", verifying_key_path.display());
        println!("\nDo you want to regenerate them? (y/N): ");

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            println!("\n✓ Keeping existing keys. Setup cancelled.");
            return Ok(());
        }
        println!();
    }

    println!("🔧 Creating compute circuit...");
    let circuit = ComputeCircuit::new();

    println!("🎲 Generating randomness (this creates 'toxic waste')...");
    println!("   Note: Randomness will be automatically discarded after setup\n");

    let mut rng = ark_std::rand::thread_rng();

    println!("⏳ Running trusted setup...");
    println!("   This may take 2-5 minutes depending on circuit complexity...");

    let start = std::time::Instant::now();
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circuit, &mut rng)?;
    let setup_time = start.elapsed();

    println!("✓ Setup completed in {:.2}s\n", setup_time.as_secs_f64());

    // Serialize and save proving key
    println!("💾 Saving proving key...");
    let mut pk_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_bytes)?;
    fs::write(&proving_key_path, &pk_bytes)?;
    println!("   ✓ {}", proving_key_path.display());
    println!("   Size: {:.2} MB", pk_bytes.len() as f64 / 1_048_576.0);

    // Serialize and save verifying key
    println!("\n💾 Saving verifying key...");
    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes)?;
    fs::write(&verifying_key_path, &vk_bytes)?;
    println!("   ✓ {}", verifying_key_path.display());
    println!("   Size: {} bytes", vk_bytes.len());

    // Verify we can load the keys back
    println!("\n🔍 Verifying key integrity...");
    let pk_loaded = ark_groth16::ProvingKey::<Bls12_381>::deserialize_compressed(&pk_bytes[..])?;
    let vk_loaded = ark_groth16::VerifyingKey::<Bls12_381>::deserialize_compressed(&vk_bytes[..])?;

    // Basic sanity check
    if pk_loaded.vk.gamma_g2 != vk_loaded.gamma_g2 {
        return Err("Key integrity check failed!".into());
    }
    println!("   ✓ Keys are valid and loadable\n");

    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║  ✓ Ceremony Complete                                       ║");
    println!("╚════════════════════════════════════════════════════════════╝\n");

    println!("📝 Next steps:");
    println!("   1. Keys are saved in: keys/");
    println!("   2. Keys are in .gitignore (not committed)");
    println!("   3. Run tests: cargo test --lib compute::private_job");
    println!("   4. Run demo: cargo run --example private_compute_demo");
    println!("\n⚠️  Remember: These keys are for DEVNET/TESTING only!");
    println!("   For MAINNET: Run multi-party ceremony with 50+ participants\n");

    // Security reminder
    println!("🔒 Security Notes:");
    println!("   - Toxic waste (randomness) has been discarded");
    println!("   - Each developer must run their own ceremony");
    println!("   - Keys are NOT committed to version control");
    println!("   - For production: Use Powers of Tau or similar MPC ceremony\n");

    Ok(())
}
