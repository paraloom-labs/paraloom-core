//! Real WASM execution tests for compute layer
//!
//! Tests actual WASM bytecode execution with:
//! - Simple arithmetic operations
//! - Memory operations
//! - Resource limit enforcement
//! - Timeout handling

use paraloom::compute::{ComputeJob, JobExecutor, JobStatus, ResourceLimits};

#[tokio::test]
async fn test_simple_wasm_execution() {
    // Create a simple WASM module that adds two numbers
    let wat = r#"
        (module
            (memory (export "memory") 1)
            (func (export "execute") (param i32 i32) (result i32)
                ;; Simple function that returns 42
                i32.const 42
            )
        )
    "#;

    let wasm_bytes = wat::parse_str(wat).expect("Failed to parse WAT");

    // Create job with default limits
    let job = ComputeJob::new(wasm_bytes, vec![1, 2, 3, 4], ResourceLimits::default());
    let job_id = job.id.clone();

    // Create executor and submit job
    let executor = JobExecutor::new().expect("Failed to create executor");
    executor.submit_job(job).expect("Failed to submit job");

    // Start executor
    executor.start().await.expect("Failed to start executor");

    // Wait for completion (max 5 seconds)
    let mut attempts = 0;
    let result = loop {
        if let Some(r) = executor.get_job_result(&job_id) {
            break r;
        }

        attempts += 1;
        if attempts > 50 {
            panic!("Job did not complete within 5 seconds");
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    };

    // Verify result
    assert_eq!(result.status, JobStatus::Completed);
    assert!(result.output_data.is_some());
    assert!(result.execution_time_ms > 0);
}

#[tokio::test]
async fn test_wasm_memory_read_write() {
    // WASM module that reads input bytes from memory, sums them, writes the sum
    // back to linear memory at offset 0, and returns the output pointer (0).
    let wat = r#"
        (module
            (memory (export "memory") 1)
            (func (export "execute") (param i32 i32) (result i32)
                (local $i i32)
                (local $sum i32)

                ;; Read input bytes and sum them
                (local.set $i (i32.const 0))
                (local.set $sum (i32.const 0))

                (block $break
                    (loop $continue
                        ;; Check if we've read all bytes
                        (br_if $break (i32.ge_u (local.get $i) (local.get 1)))

                        ;; Read byte and add to sum
                        (local.set $sum
                            (i32.add
                                (local.get $sum)
                                (i32.load8_u (i32.add (local.get 0) (local.get $i)))
                            )
                        )

                        ;; Increment counter
                        (local.set $i (i32.add (local.get $i) (i32.const 1)))
                        (br $continue)
                    )
                )

                ;; Write sum to linear memory at offset 0 and return output pointer 0
                (i32.store (i32.const 0) (local.get $sum))
                (i32.const 0)
            )
        )
    "#;

    let wasm_bytes = wat::parse_str(wat).expect("Failed to parse WAT");

    // Input: [10, 20, 30, 40] -> sum should be 100
    let input_data = vec![10u8, 20, 30, 40];
    let job = ComputeJob::new(wasm_bytes, input_data, ResourceLimits::default());
    let job_id = job.id.clone();

    let executor = JobExecutor::new().unwrap();
    executor.submit_job(job).unwrap();
    executor.start().await.unwrap();

    // Wait for completion
    let result = wait_for_result(&executor, &job_id).await;

    // Verify execution succeeded and output memory contains the computed sum (100)
    assert_eq!(result.status, JobStatus::Completed);
    let output = result
        .output_data
        .as_ref()
        .expect("Completed job must return output_data");
    assert!(
        output.len() >= 4,
        "Output buffer must contain at least 4 bytes"
    );
    let sum = i32::from_le_bytes(output[..4].try_into().unwrap());
    assert_eq!(sum, 100, "Expected sum of [10, 20, 30, 40] to be 100");
    assert!(result.execution_time_ms > 0);
    assert!(result.memory_used_bytes > 0);
    assert!(result.instructions_executed > 0);
}

#[tokio::test]
async fn test_wasm_resource_limit_memory() {
    // WASM module that attempts to grow memory by 50 pages (~3.2MB) beyond the 1MB limit
    // and writes the `memory.grow` return code (-1 when denied by the limiter) to offset 0.
    let wat = r#"
        (module
            (memory (export "memory") 1 100)  ;; Request up to 100 pages (6.4MB)
            (func (export "execute") (param i32 i32) (result i32)
                ;; Try to grow memory beyond limit and record the return value at offset 0
                (i32.store (i32.const 0) (memory.grow (i32.const 50)))
                i32.const 0
            )
        )
    "#;

    let wasm_bytes = wat::parse_str(wat).unwrap();

    // Set very low memory limit (1MB = 16 WASM pages)
    let limits = ResourceLimits {
        max_memory_bytes: 1024 * 1024, // 1MB
        max_instructions: 1_000_000,
        timeout_secs: 5,
    };

    let job = ComputeJob::new(wasm_bytes, vec![], limits.clone());
    let job_id = job.id.clone();

    let executor = JobExecutor::new().unwrap();
    executor.submit_job(job).unwrap();
    executor.start().await.unwrap();

    // Wait for completion
    let result = wait_for_result(&executor, &job_id).await;

    // ResourceLimiter denies `memory.grow(50)` by returning -1 while keeping memory at 1 page (64KB)
    assert_eq!(result.status, JobStatus::Completed);
    assert!(
        result.memory_used_bytes <= limits.max_memory_bytes,
        "Memory used ({} bytes) exceeded limit ({} bytes)",
        result.memory_used_bytes,
        limits.max_memory_bytes
    );
    assert_eq!(
        result.memory_used_bytes, 65_536,
        "Memory should remain at 1 initial page (65536 bytes) after denied grow"
    );
    let output = result
        .output_data
        .as_ref()
        .expect("Completed job must return output_data");
    let grow_result = i32::from_le_bytes(output[..4].try_into().unwrap());
    assert_eq!(
        grow_result, -1,
        "memory.grow beyond limit must be denied with -1"
    );
}

#[tokio::test]
async fn test_wasm_instruction_limit() {
    // WASM module with infinite loop (will hit instruction limit)
    let wat = r#"
        (module
            (memory (export "memory") 1)
            (func (export "execute") (param i32 i32) (result i32)
                (local $counter i32)
                (local.set $counter (i32.const 0))

                ;; Infinite loop
                (block $break
                    (loop $continue
                        ;; Increment counter
                        (local.set $counter
                            (i32.add (local.get $counter) (i32.const 1))
                        )

                        ;; Break if counter reaches a large number
                        (br_if $break (i32.gt_u (local.get $counter) (i32.const 10000000)))
                        (br $continue)
                    )
                )

                (local.get $counter)
            )
        )
    "#;

    let wasm_bytes = wat::parse_str(wat).unwrap();

    // Set low instruction limit
    let limits = ResourceLimits {
        max_memory_bytes: 10 * 1024 * 1024, // 10MB
        max_instructions: 100_000,          // Only 100k instructions
        timeout_secs: 5,
    };

    let job = ComputeJob::new(wasm_bytes, vec![], limits);
    let job_id = job.id.clone();

    let executor = JobExecutor::new().unwrap();
    executor.submit_job(job).unwrap();
    executor.start().await.unwrap();

    // Wait for completion
    let result = wait_for_result(&executor, &job_id).await;

    // Should fail due to instruction limit
    assert!(
        matches!(result.status, JobStatus::Failed { .. }),
        "Expected Failed due to instruction limit, got {:?}",
        result.status
    );
}

#[tokio::test]
async fn test_wasm_timeout_enforcement() {
    // WASM module with truly infinite loop (will never complete without timeout)
    let wat = r#"
        (module
            (memory (export "memory") 1)
            (func (export "execute") (param i32 i32) (result i32)
                (local $i i64)
                (local.set $i (i64.const 0))

                ;; Infinite loop with very large counter
                (loop $continue
                    (local.set $i (i64.add (local.get $i) (i64.const 1)))
                    ;; Never breaks, loops forever
                    (br $continue)
                )

                ;; Unreachable
                i32.const 0
            )
        )
    "#;

    let wasm_bytes = wat::parse_str(wat).unwrap();

    // Set 1-second timeout with unbounded fuel so only the epoch timeout can terminate execution
    let limits = ResourceLimits {
        max_memory_bytes: 10 * 1024 * 1024,
        max_instructions: u64::MAX,
        timeout_secs: 1,
    };

    let job = ComputeJob::new(wasm_bytes, vec![], limits);
    let job_id = job.id.clone();

    let executor = JobExecutor::new().unwrap();
    executor.submit_job(job).unwrap();
    executor.start().await.unwrap();

    // Wait for completion (with longer timeout since we expect failure)
    let result = wait_for_result(&executor, &job_id).await;

    // Must fail specifically due to epoch timeout, not fuel exhaustion
    match &result.status {
        JobStatus::Failed { error } => {
            assert!(
                error.contains("timeout"),
                "Expected timeout failure message, got: {}",
                error
            );
        }
        other => panic!("Expected Failed with timeout error, got {:?}", other),
    }
}

#[tokio::test]
async fn test_wasm_multiple_concurrent_jobs() {
    // Simple WASM module
    let wat = r#"
        (module
            (memory (export "memory") 1)
            (func (export "execute") (param i32 i32) (result i32)
                ;; Return input length
                (local.get 1)
            )
        )
    "#;

    let wasm_bytes = wat::parse_str(wat).unwrap();

    let executor = JobExecutor::new().unwrap();
    executor.start().await.unwrap();

    // Submit 10 jobs concurrently
    let mut job_ids = Vec::new();
    for i in 0..10 {
        let job = ComputeJob::new(
            wasm_bytes.clone(),
            vec![i; i as usize],
            ResourceLimits::default(),
        );
        let job_id = job.id.clone();
        executor.submit_job(job).unwrap();
        job_ids.push(job_id);
    }

    // Wait for all jobs to complete
    for job_id in &job_ids {
        let result = wait_for_result(&executor, job_id).await;
        assert_eq!(result.status, JobStatus::Completed);
    }

    // Verify executor stats
    let stats = executor.get_stats();
    assert_eq!(stats.completed_jobs, 10);
}

// Helper function to wait for job result
async fn wait_for_result(executor: &JobExecutor, job_id: &str) -> paraloom::compute::JobResult {
    let mut attempts = 0;
    let job_id_string = job_id.to_string();
    loop {
        if let Some(result) = executor.get_job_result(&job_id_string) {
            return result;
        }

        attempts += 1;
        if attempts > 100 {
            panic!("Job {} did not complete within 10 seconds", job_id);
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
}
