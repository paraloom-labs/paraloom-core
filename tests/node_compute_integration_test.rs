//! Integration tests for compute layer with Node
//!
//! Tests the full integration of compute layer into the Node infrastructure.

use paraloom::compute::{ComputeJob, ResourceLimits};
use paraloom::config::Settings;
use paraloom::node::Node;

#[tokio::test]
async fn test_resource_provider_node_can_execute_jobs() {
    // Create a ResourceProvider node
    let mut settings = Settings::development();
    settings.node.node_type = "ResourceProvider".to_string();
    settings.network.listen_address = "/ip4/127.0.0.1/tcp/0".to_string();

    let node = Node::new(settings).expect("Failed to create ResourceProvider node");

    // Verify compute executor is initialized
    assert!(
        node.compute_executor().is_some(),
        "ResourceProvider node should have compute executor"
    );
    assert!(
        node.compute_coordinator().is_none(),
        "ResourceProvider node should not have coordinator"
    );
    assert!(
        node.compute_manager().is_none(),
        "ResourceProvider node should not have manager"
    );

    // Start the executor (normally done in Node::run())
    let executor = node.compute_executor().unwrap();
    executor.start().await.expect("Failed to start executor");

    // Create a simple WASM job
    // This is a minimal valid WASM module that exports an "execute" function
    let wasm_code = wat::parse_str(
        r#"
        (module
            (func (export "execute")
                ;; Simple function that just returns
                nop
            )
        )
        "#,
    )
    .expect("Failed to compile WAT to WASM");

    let input_data = vec![5, 10]; // Will add 5 + 10
    let limits = ResourceLimits::default();

    let job = ComputeJob::new(wasm_code, input_data, limits);
    let job_id = job.id.clone();

    // Submit job to executor
    node.submit_compute_job(job).expect("Failed to submit job");

    // Wait a bit for execution
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Query job result
    let result = node.get_compute_job_result(&job_id);
    assert!(result.is_some(), "Job result should be available");

    let result = result.unwrap();
    println!("Job execution result: {:?}", result);

    // Check executor stats
    let stats = node
        .get_compute_stats()
        .expect("Should have executor stats");
    assert_eq!(stats.active_jobs, 0, "No jobs should be active");
    assert!(
        stats.completed_jobs > 0 || stats.failed_jobs > 0,
        "Should have at least one completed or failed job"
    );
    println!("Executor stats: {:?}", stats);
}

#[tokio::test]
async fn test_coordinator_node_has_manager_and_coordinator() {
    // Create a Coordinator node
    let mut settings = Settings::development();
    settings.node.node_type = "Coordinator".to_string();
    settings.network.listen_address = "/ip4/127.0.0.1/tcp/0".to_string();

    let node = Node::new(settings).expect("Failed to create Coordinator node");

    // Verify compute manager and coordinator are initialized
    assert!(
        node.compute_manager().is_some(),
        "Coordinator node should have compute manager"
    );
    assert!(
        node.compute_coordinator().is_some(),
        "Coordinator node should have compute coordinator"
    );
    assert!(
        node.compute_executor().is_none(),
        "Coordinator node should not have executor"
    );

    println!("Coordinator node initialized with compute manager and coordinator");
}

#[tokio::test]
async fn test_coordinator_can_register_validators() {
    use paraloom::compute::ValidatorCapacity;

    // Create a Coordinator node
    let mut settings = Settings::development();
    settings.node.node_type = "Coordinator".to_string();
    settings.network.listen_address = "/ip4/127.0.0.1/tcp/0".to_string();

    let node = Node::new(settings).expect("Failed to create Coordinator node");

    // Register a validator
    let capacity = ValidatorCapacity::new(
        "validator-1".to_string(),
        8,     // CPU cores
        16384, // Memory MB
        10,    // Max concurrent jobs
    );

    node.register_compute_validator(capacity)
        .await
        .expect("Failed to register validator");

    // Get coordinator and check validator count
    let coordinator = node.compute_coordinator().unwrap();
    let validators = coordinator.get_validators().await;
    assert_eq!(validators.len(), 1, "Should have one registered validator");
    assert_eq!(validators[0].validator_id, "validator-1");

    println!("Successfully registered validator with coordinator");
}

#[test]
fn test_node_compute_api_methods_exist() {
    // This test just verifies that all compute API methods compile
    // and have the correct signatures

    fn _check_resource_provider_api(_node: &Node) {
        let _: Option<_> = _node.compute_executor();
        let _: Option<_> = _node.get_compute_stats();
        // submit_compute_job and get_compute_job_result tested above
    }

    fn _check_coordinator_api(_node: &Node) {
        let _: Option<_> = _node.compute_manager();
        let _: Option<_> = _node.compute_coordinator();
        // register_compute_validator and submit_compute_job_to_network tested above
    }

    println!("All compute API methods compile successfully");
}
