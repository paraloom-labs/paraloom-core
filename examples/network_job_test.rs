use paraloom::compute::{ComputeJob, ResourceLimits, ValidatorCapacity};
use paraloom::config::Settings;
use paraloom::node::Node;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    println!("\nTesting Network-Based Job Execution");
    println!("=====================================\n");

    println!("Starting ResourceProvider node...");
    let mut validator_settings = Settings::development();
    validator_settings.node.node_type = "ResourceProvider".to_string();
    validator_settings.network.listen_address = "/ip4/127.0.0.1/tcp/9001".to_string();
    validator_settings.network.bootstrap_nodes = vec![];

    let validator_node = Node::new(validator_settings)?;
    let validator_id = validator_node.node_info().id.to_string();
    println!("   Validator ID: {}", validator_id);

    let validator_handle = tokio::spawn(async move { validator_node.run().await });

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    println!("\nStarting Coordinator node...");
    let mut coord_settings = Settings::development();
    coord_settings.node.node_type = "Coordinator".to_string();
    coord_settings.network.listen_address = "/ip4/127.0.0.1/tcp/9002".to_string();
    coord_settings.network.bootstrap_nodes = vec!["/ip4/127.0.0.1/tcp/9001".to_string()];

    let coordinator_node = Node::new(coord_settings)?;

    let coord_clone = coordinator_node.clone();
    let coord_handle = tokio::spawn(async move { coord_clone.run().await });

    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    println!("\nRegistering validator with coordinator...");
    let capacity = ValidatorCapacity::new(validator_id.clone(), 8, 16384, 10);
    coordinator_node
        .register_compute_validator(capacity)
        .await?;
    println!("   Validator registered");

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    println!("\nSubmitting job to network...");
    let wasm_code = wat::parse_str(
        r#"
        (module
            (memory (export "memory") 1)
            (func (export "execute") (param i32 i32) (result i32)
                i32.const 42
            )
        )
    "#,
    )?;

    let job = ComputeJob::new(wasm_code, vec![], ResourceLimits::default());
    let job_id = job.id.clone();
    println!("   Job ID: {}", job_id);

    match coordinator_node.submit_compute_job_to_network(job).await {
        Ok(submitted_job_id) => {
            println!("   Job submitted successfully: {}", submitted_job_id);

            println!("\nWaiting for job execution (10 seconds)...");
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

            if let Some(manager) = coordinator_node.compute_manager() {
                if let Some(result) = manager.get_result(&job_id) {
                    println!("\nSUCCESS! Job completed on remote validator!");
                    println!("   Status: {:?}", result.status);
                    println!("   Execution time: {}ms", result.execution_time_ms);
                } else {
                    println!("\nResult not yet available (may still be executing)");
                }
            }
        }
        Err(e) => {
            println!("   Failed to submit job: {}", e);
        }
    }

    println!("\nShutting down nodes...");
    drop(coordinator_node);
    drop(validator_handle);
    drop(coord_handle);

    Ok(())
}
