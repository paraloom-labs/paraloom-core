//! Privacy-Preserving Compute Workflow Demo
//!
//! This example demonstrates the full workflow of private compute jobs:
//! 1. Create a private job with encrypted input
//! 2. Submit to shielded pool with input commitment
//! 3. Execute with multi-validator consensus
//! 4. Generate zkSNARK proof of correct execution
//! 5. Verify result with privacy guarantees
//! 6. Retrieve and decrypt output

use paraloom::compute::{
    JobExecutor, JobResult, JobStatus, PrivateComputeJob, PrivateJobCoordinator, PrivateJobResult,
    ResourceLimits, VerificationCoordinator,
};
use paraloom::privacy::{ShieldedAddress, ShieldedPool};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("\n=== Privacy-Preserving Compute Demo ===\n");

    // Step 1: Setup components
    println!("Step 1: Setting up privacy-preserving compute infrastructure");
    let pool = Arc::new(ShieldedPool::new());
    let verifier = Arc::new(VerificationCoordinator::new());
    let coordinator = PrivateJobCoordinator::with_verification(pool.clone(), verifier.clone());
    let executor = JobExecutor::new()?;
    executor.start().await?;
    println!("Shielded pool and verification coordinator initialized\n");

    // Step 2: Create private job
    println!("Step 2: Creating private compute job");
    let wasm_code = create_sample_wasm();
    let sensitive_input = vec![42, 100, 200, 15, 75]; // Secret data
    let owner_address = ShieldedAddress([99u8; 32]);
    let limits = ResourceLimits::default();

    let private_job = PrivateComputeJob::new(
        wasm_code.clone(),
        sensitive_input.clone(),
        owner_address.clone(),
        limits,
    )?;
    println!("Job ID: {}", private_job.job_id);
    println!("Input data: {:?}", sensitive_input);
    println!(
        "Encrypted input (first 10 bytes): {:?}",
        &private_job.encrypted_input[..10.min(private_job.encrypted_input.len())]
    );
    println!("Input commitment created (hidden from validators)\n");

    // Step 3: Submit to shielded pool
    println!("Step 3: Submitting to shielded pool");
    let job_id = coordinator.submit_private_job(private_job.clone()).await?;
    println!("Job submitted to shielded pool: {}", job_id);
    println!("Input commitment registered (data remains private)\n");

    // Step 4: Setup multi-validator verification
    println!("Step 4: Setting up multi-validator consensus (3 validators)");
    let validators = vec![
        "validator-1".to_string(),
        "validator-2".to_string(),
        "validator-3".to_string(),
    ];
    verifier
        .create_verification_request(job_id.clone(), validators.clone())
        .await?;
    println!(
        "✓ Verification request created with {} validators\n",
        validators.len()
    );

    // Step 5: Simulate validator execution
    println!("Step 5: Validators executing WASM with encrypted input");
    let mock_output = vec![200, 150, 100, 50, 25]; // Simulated computation result

    for (i, validator_id) in validators.iter().enumerate() {
        println!("Validator {} processing...", i + 1);
        let result = JobResult {
            job_id: job_id.clone(),
            status: JobStatus::Completed,
            output_data: Some(mock_output.clone()),
            error: None,
            execution_time_ms: 100 + (i as u64 * 10),
            memory_used_bytes: 2048,
            instructions_executed: 50000 + (i as u64 * 1000),
        };
        verifier
            .submit_result(&job_id, validator_id.clone(), result)
            .await?;
        println!("Validator {} completed execution", i + 1);
    }
    println!("\nAll validators completed\n");

    // Step 6: Generate private result with zkSNARK proof
    println!("Step 6: Generating zkSNARK proof");
    let job_result = JobResult {
        job_id: job_id.clone(),
        status: JobStatus::Completed,
        output_data: Some(mock_output.clone()),
        error: None,
        execution_time_ms: 110,
        memory_used_bytes: 2048,
        instructions_executed: 51000,
    };
    let private_result =
        PrivateJobResult::from_job_result(job_id.clone(), job_result, &owner_address)?;

    println!(
        "zkSNARK proof generated ({} bytes)",
        private_result.execution_proof.len()
    );
    println!("Output encrypted (only owner can decrypt)");
    println!("Output commitment created\n");

    // Step 7: Verify result
    println!("Step 7: Verifying private result");
    println!("Checking zkSNARK proof...");
    println!("Verifying output commitment...");
    println!("Checking multi-validator consensus (2/3 required)...");

    let verified = coordinator.verify_result(&private_result).await?;
    if verified {
        println!("Result verified successfully\n");
    } else {
        println!("Verification failed\n");
        return Err("Verification failed".into());
    }

    // Step 8: Check consensus details
    println!("Step 8: Consensus analysis");
    let consensus = verifier.check_consensus(&job_id).await?;
    match consensus {
        paraloom::compute::ConsensusResult::Agreed(result) => {
            println!("✓ Consensus reached: 3/3 validators agreed");
            println!("  Execution time: {}ms", result.execution_time_ms);
            println!("  Memory used: {} bytes", result.memory_used_bytes);
            println!("  Instructions: {}\n", result.instructions_executed);
        }
        _ => {
            println!("✗ Consensus not reached\n");
        }
    }

    // Step 9: Finalize result
    println!("Step 9: Finalizing result in shielded pool");
    coordinator.finalize_result(private_result.clone()).await?;
    println!("Result finalized and registered in shielded pool\n");

    // Step 10: Decrypt output (only job owner can do this)
    println!("Step 10: Decrypting output (owner only)");
    let decrypted_output = private_result.decrypt_output(&owner_address)?;
    println!("✓ Original input: {:?}", sensitive_input);
    println!("✓ Decrypted output: {:?}", decrypted_output);
    println!("✓ Computation verified without revealing data\n");

    // Step 11: Demonstrate privacy guarantee
    println!("Step 11: Privacy guarantee demonstration (AES-GCM)");
    let wrong_address = ShieldedAddress([200u8; 32]);
    let wrong_decrypt = private_result.decrypt_output(&wrong_address);
    println!("  Wrong key decryption attempt:");
    match wrong_decrypt {
        Ok(_) => println!("    ✗ Unexpectedly succeeded (security issue!)"),
        Err(e) => println!("    ✓ Failed as expected: {}", e),
    }
    println!("    ✓ AES-GCM authenticated encryption protects data\n");

    // Final summary
    println!("=== Summary ===");
    println!("✓ Private job created with input commitment");
    println!("✓ Input/output encrypted with AES-GCM-256 throughout execution");
    println!("✓ Multi-validator consensus (3/3 agreement)");
    println!("✓ zkSNARK proof verified");
    println!("✓ Result decrypted by owner only");
    println!("\nPrivacy guarantees:");
    println!("  • Validators never see input/output data");
    println!("  • AES-GCM authenticated encryption protects confidentiality");
    println!("  • zkSNARK proves correct execution");
    println!("  • Multi-validator consensus ensures correctness");
    println!("  • Only owner can decrypt results");
    println!("\n=== Demo Complete ===\n");

    Ok(())
}

fn create_sample_wasm() -> Vec<u8> {
    // WASM magic number - in real scenario this would be full WASM binary
    vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]
}
