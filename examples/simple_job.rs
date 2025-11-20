use paraloom::compute::{ComputeJob, JobExecutor, ResourceLimits};

#[tokio::main]
async fn main() {
    env_logger::init();

    println!("Testing Simple Job Submission\n");

    let executor = JobExecutor::new().expect("Failed to create executor");
    executor.start().await.expect("Failed to start executor");

    let wasm_code = wat::parse_str(
        r#"
        (module
            (memory (export "memory") 1)
            (func (export "execute") (param i32 i32) (result i32)
                i32.const 42
            )
        )
    "#,
    )
    .expect("Failed to compile WAT");

    let job = ComputeJob::new(wasm_code, vec![], ResourceLimits::default());
    let job_id = job.id.clone();

    println!("Submitting job: {}", job_id);
    executor.submit_job(job).expect("Failed to submit job");

    println!("Waiting for execution...");
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    if let Some(result) = executor.get_job_result(&job_id) {
        println!("\nSUCCESS! Job completed!");
        println!("   Status: {:?}", result.status);
        println!("   Execution time: {}ms", result.execution_time_ms);
        println!("   Memory used: {} bytes", result.memory_used_bytes);
    } else {
        println!("\nFAILED! Job result not found!");
        std::process::exit(1);
    }

    let stats = executor.get_stats();
    println!("\nExecutor Stats:");
    println!("   Total completed: {}", stats.completed_jobs);
    println!("   Total failed: {}", stats.failed_jobs);
}
