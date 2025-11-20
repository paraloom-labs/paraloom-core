//! Compute layer demonstration
//!
//! This demo shows REAL WASM execution with:
//! - JobExecutor with real WasmEngine
//! - Multiple WASM programs executing concurrently
//! - Resource limits (memory, instructions, timeout)
//! - Real execution metrics

use anyhow::Result;
use log::info;
use paraloom::compute::{ComputeJob, JobExecutor, JobStatus, ResourceLimits};
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!("=== Paraloom Real WASM Execution Demo ===\n");

    // Create executor with real WASM engine
    let executor = JobExecutor::new()?;
    info!("✓ JobExecutor created with WasmEngine\n");

    // Start the executor
    executor.start().await?;
    info!("✓ Executor started, processing jobs...\n");

    // Demo 1: Simple arithmetic
    info!("1. Simple WASM execution (returns 42)...");
    let wat1 = r#"
        (module
            (memory (export "memory") 1)
            (func (export "execute") (param i32 i32) (result i32)
                i32.const 42
            )
        )
    "#;
    let wasm1 = wat::parse_str(wat1)?;
    let job1 = ComputeJob::new(wasm1, vec![], ResourceLimits::default());
    let job_id1 = executor.submit_job(job1)?;
    info!("  Job submitted: {}", job_id1);

    // Demo 2: Sum input bytes
    info!("\n2. Memory operation (sum input bytes)...");
    let wat2 = r#"
        (module
            (memory (export "memory") 1)
            (func (export "execute") (param i32 i32) (result i32)
                (local $i i32)
                (local $sum i32)
                (local.set $sum (i32.const 0))
                (block $break
                    (loop $continue
                        (br_if $break (i32.ge_u (local.get $i) (local.get 1)))
                        (local.set $sum
                            (i32.add
                                (local.get $sum)
                                (i32.load8_u (i32.add (local.get 0) (local.get $i)))
                            )
                        )
                        (local.set $i (i32.add (local.get $i) (i32.const 1)))
                        (br $continue)
                    )
                )
                (local.get $sum)
            )
        )
    "#;
    let wasm2 = wat::parse_str(wat2)?;
    let job2 = ComputeJob::new(wasm2, vec![10, 20, 30, 40], ResourceLimits::default());
    let job_id2 = executor.submit_job(job2)?;
    info!("  Job submitted: {} (input: [10, 20, 30, 40])", job_id2);

    // Demo 3: Multiple concurrent jobs
    info!("\n3. Submitting 5 concurrent jobs...");
    let wat3 = r#"
        (module
            (memory (export "memory") 1)
            (func (export "execute") (param i32 i32) (result i32)
                (local.get 1)
            )
        )
    "#;
    let wasm3 = wat::parse_str(wat3)?;

    let mut concurrent_jobs = Vec::new();
    for i in 0..5 {
        let job = ComputeJob::new(
            wasm3.clone(),
            vec![i; i as usize],
            ResourceLimits::default(),
        );
        let job_id = executor.submit_job(job)?;
        concurrent_jobs.push(job_id.clone());
        info!("  Job {} submitted: {}", i + 1, job_id);
    }

    // Wait for all jobs to complete
    info!("\n4. Waiting for jobs to complete...");
    let all_jobs = vec![job_id1, job_id2]
        .into_iter()
        .chain(concurrent_jobs)
        .collect::<Vec<_>>();

    let mut completed = 0;
    for job_id in &all_jobs {
        if let Some(result) = wait_for_result(&executor, job_id).await {
            completed += 1;
            match result.status {
                JobStatus::Completed => {
                    info!(
                        "  ✓ Job {} completed: {}ms, {} bytes memory, {} instructions",
                        &job_id[..8],
                        result.execution_time_ms,
                        result.memory_used_bytes,
                        result.instructions_executed
                    );
                }
                JobStatus::Failed { ref error } => {
                    info!("  ✗ Job {} failed: {}", &job_id[..8], error);
                }
                _ => {}
            }
        }
    }

    // Show final stats
    info!("\n5. Final statistics:");
    let stats = executor.get_stats();
    info!("  Total jobs: {}", all_jobs.len());
    info!("  Completed: {}", completed);
    info!("  Pending: {}", stats.pending_jobs);
    info!("  Active: {}", stats.active_jobs);

    info!("\n=== Demo Complete ===");
    info!(
        "Successfully executed {} WASM programs with real WasmEngine!",
        completed
    );

    Ok(())
}

// Helper to wait for job completion
async fn wait_for_result(
    executor: &JobExecutor,
    job_id: &str,
) -> Option<paraloom::compute::JobResult> {
    let job_id_string = job_id.to_string();
    for _ in 0..100 {
        if let Some(result) = executor.get_job_result(&job_id_string) {
            return Some(result);
        }
        sleep(Duration::from_millis(50)).await;
    }
    None
}
