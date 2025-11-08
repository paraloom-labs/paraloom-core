//! Benchmark: Coordinator result processing performance

use anyhow::Result;
use paraloom::config::Settings;
use paraloom::coordinator::Coordinator;
use paraloom::network::NetworkManager;
use paraloom::task::{ResultData, TaskResult};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    println!("\nBENCHMARK: Coordinator Result Processing\n");

    // Test scenarios
    let scenarios = vec![
        ("Baseline: 10 validators", 10),
        ("Small: 50 validators", 50),
        ("Medium: 100 validators", 100),
        ("Large: 500 validators", 500),
        ("Extreme: 1000 validators", 1000),
    ];

    for (name, num_validators) in scenarios {
        println!("Scenario: {}", name);
        run_benchmark(num_validators).await?;
        println!();
    }

    println!("Benchmark completed");
    Ok(())
}

async fn run_benchmark(num_validators: usize) -> Result<()> {
    let settings = Settings::development();
    let network = Arc::new(NetworkManager::new(&settings)?);
    let coordinator = Arc::new(Coordinator::new(network.clone()));

    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let task_id = format!("benchmark-task-{}", timestamp);

    let processed = Arc::new(Mutex::new(0usize));
    let process_delay_ms: u64 = 5;

    // Start timer
    let start = Instant::now();

    // Spawn concurrent validators
    let mut handles = vec![];

    for i in 0..num_validators {
        let coordinator_clone = coordinator.clone();
        let processed_clone = processed.clone();
        let task_id_clone = task_id.clone();

        let handle = tokio::spawn(async move {
            let result = TaskResult {
                task_id: format!("{}-chunk-{}", task_id_clone, i),
                execution_time_ms: 100,
                data: ResultData::Hashes {
                    hashes: vec![(i as u64, format!("hash_{}", i))],
                    count: 1,
                },
            };

            tokio::time::sleep(tokio::time::Duration::from_millis(process_delay_ms)).await;
            if coordinator_clone.handle_task_result(result).await.is_ok() {
                let mut count = processed_clone.lock().await;
                *count += 1;
            }
        });

        handles.push(handle);
    }

    // Wait for all validators
    for handle in handles {
        let _ = handle.await;
    }

    let elapsed = start.elapsed();
    let count = *processed.lock().await;

    // Calculate metrics
    let throughput = if elapsed.as_secs_f64() > 0.0 {
        (count as f64 / elapsed.as_secs_f64()) as usize
    } else {
        0
    };
    let avg_latency_ms = if count > 0 {
        elapsed.as_millis() as f64 / count as f64
    } else {
        0.0
    };

    // Theoretical bounds
    let sequential_time_ms = num_validators as u64 * process_delay_ms;
    let parallel_time_ms = process_delay_ms;

    let elapsed_ms = elapsed.as_millis();
    println!("  Processed: {}/{} results", count, num_validators);
    println!("  Total time: {}ms", elapsed_ms);
    println!("  Throughput: {} results/sec", throughput);
    println!("  Avg latency: {:.2}ms per result", avg_latency_ms);
    println!();
    println!("  Theoretical comparison:");
    println!("    Sequential: {}ms", sequential_time_ms);
    println!("    Parallel: {}ms", parallel_time_ms);
    println!("    Actual: {}ms", elapsed_ms);
    println!();

    let ratio = elapsed_ms as f64 / sequential_time_ms as f64;

    if ratio < 0.3 {
        println!(
            "  EXCELLENT: Highly concurrent ({:.1}x faster than sequential)",
            1.0 / ratio
        );
    } else if ratio < 0.6 {
        println!("  GOOD: Good concurrency ({:.1}x faster)", 1.0 / ratio);
    } else if ratio < 0.9 {
        println!(
            "  PARTIAL: Some concurrency but bottlenecks exist ({:.1}x faster)",
            1.0 / ratio
        );
    } else {
        println!("  BAD: Mostly sequential (only {:.1}x faster)", 1.0 / ratio);
    }

    Ok(())
}
