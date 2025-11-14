//! Compute layer demonstration
//!
//! This demo shows the distributed compute capabilities:
//! - Multiple validators registering with capacity
//! - Job submission and distribution
//! - Load balancing across validators
//! - Result aggregation

use anyhow::Result;
use log::info;
use paraloom::compute::{
    ComputeJob, JobManager, JobStatus, ResourceLimits, ValidatorCapacity,
};
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!("=== Paraloom Distributed Compute Demo ===\n");

    // Create job manager
    let manager = JobManager::new();

    // Register 3 validators with different capacities
    info!("1. Registering validators...");
    manager.register_validator(ValidatorCapacity::new(
        "validator1".to_string(),
        8,    // 8 CPU cores
        16384, // 16GB RAM
        4,    // Max 4 concurrent jobs
    ))?;

    manager.register_validator(ValidatorCapacity::new(
        "validator2".to_string(),
        4,    // 4 CPU cores
        8192, // 8GB RAM
        2,    // Max 2 concurrent jobs
    ))?;

    manager.register_validator(ValidatorCapacity::new(
        "validator3".to_string(),
        16,   // 16 CPU cores
        32768, // 32GB RAM
        8,    // Max 8 concurrent jobs
    ))?;

    print_stats(&manager);

    // Submit 7 compute jobs
    info!("\n2. Submitting compute jobs...");
    let mut job_ids = Vec::new();

    for i in 0..7 {
        let job = ComputeJob::new(
            vec![0x00, 0x61, 0x73, 0x6d], // WASM bytecode
            vec![i],                       // Input data
            ResourceLimits::default(),
        );

        let job_id = manager.submit_job(job)?;
        info!("  Submitted job {}: {}", i + 1, job_id);
        job_ids.push(job_id);
    }

    print_stats(&manager);

    // Assign jobs to validators (load balancing)
    info!("\n3. Assigning jobs to validators (load balancing)...");
    let assignments = manager.assign_jobs()?;

    for assignment in &assignments {
        info!(
            "  Job {} → {}",
            &assignment.job_id[..8],
            assignment.validator_id
        );
    }

    print_stats(&manager);

    // Show load distribution
    info!("\n4. Load distribution:");
    let stats = manager.get_stats();
    info!(
        "  Total capacity: {} jobs across {} validators",
        stats.total_capacity, stats.active_validators
    );
    info!(
        "  Active jobs: {} | Pending: {}",
        stats.active_jobs, stats.pending_jobs
    );

    // Simulate job execution by submitting results
    info!("\n5. Simulating job execution...");
    sleep(Duration::from_millis(500)).await;

    for (idx, job_id) in job_ids.iter().enumerate() {
        let result = paraloom::compute::JobResult::success(
            job_id.clone(),
            vec![42u8; 10], // Output data
            100 + (idx as u64 * 10), // Execution time
            1024,           // Memory used
            50000,          // Instructions executed
        );

        manager.submit_result(result)?;
        info!("  ✓ Job {} completed", idx + 1);
    }

    print_stats(&manager);

    // Check final status
    info!("\n6. Final status:");
    for (idx, job_id) in job_ids.iter().enumerate() {
        if let Some(status) = manager.get_job_status(job_id) {
            info!("  Job {}: {:?}", idx + 1, status);
        }
    }

    // Get results
    info!("\n7. Retrieving results...");
    let mut completed = 0;
    for job_id in &job_ids {
        if let Some(result) = manager.get_result(job_id) {
            if result.status == JobStatus::Completed {
                completed += 1;
                info!(
                    "  Job result: {} bytes output, {}ms execution",
                    result.output_data.as_ref().map(|d| d.len()).unwrap_or(0),
                    result.execution_time_ms
                );
            }
        }
    }

    info!("\n=== Demo Complete ===");
    info!("Successfully executed {}/{} jobs across {} validators",
          completed, job_ids.len(), stats.active_validators);

    Ok(())
}

fn print_stats(manager: &JobManager) {
    let stats = manager.get_stats();
    info!("  Stats: {} validators | {} active jobs | {} pending | {} completed",
          stats.active_validators,
          stats.active_jobs,
          stats.pending_jobs,
          stats.completed_jobs
    );
}
