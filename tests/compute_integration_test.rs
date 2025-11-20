//! Integration tests for distributed compute layer
//!
//! Tests the complete workflow:
//! - Validator registration
//! - Job submission and distribution
//! - Load balancing
//! - Result aggregation
//! - Timeout handling and recovery
//! - Multi-validator consensus verification
//! - Error recovery and resilience

use paraloom::compute::{
    CapacityAnnouncement, ComputeJob, ConsensusResult, JobCoordinator, JobManager, JobResult,
    JobStatus, ResourceLimits, ValidatorCapacity, VerificationCoordinator, MAX_JOB_RETRIES,
};

#[test]
fn test_distributed_compute_workflow() {
    // Create job manager
    let manager = JobManager::new();

    // Register 3 validators
    manager
        .register_validator(ValidatorCapacity::new(
            "validator1".to_string(),
            8,
            16384,
            4,
        ))
        .unwrap();

    manager
        .register_validator(ValidatorCapacity::new("validator2".to_string(), 4, 8192, 2))
        .unwrap();

    manager
        .register_validator(ValidatorCapacity::new(
            "validator3".to_string(),
            16,
            32768,
            8,
        ))
        .unwrap();

    // Verify validator registration
    let stats = manager.get_stats();
    assert_eq!(stats.total_validators, 3);
    assert_eq!(stats.active_validators, 3);
    assert_eq!(stats.total_capacity, 14); // 4 + 2 + 8

    // Submit 5 jobs
    let mut job_ids = Vec::new();
    for i in 0..5 {
        let job = ComputeJob::new(
            vec![0x00, 0x61, 0x73, 0x6d],
            vec![i],
            ResourceLimits::default(),
        );
        let job_id = manager.submit_job(job).unwrap();
        job_ids.push(job_id);
    }

    // Verify pending jobs
    let stats = manager.get_stats();
    assert_eq!(stats.pending_jobs, 5);

    // Assign jobs
    let assignments = manager.assign_jobs().unwrap();
    assert_eq!(assignments.len(), 5);

    // Verify all jobs assigned
    let stats = manager.get_stats();
    assert_eq!(stats.pending_jobs, 0);
    assert_eq!(stats.active_jobs, 5);

    // Verify load balancing (jobs distributed across validators)
    let validator1_jobs = assignments
        .iter()
        .filter(|a| a.validator_id == "validator1")
        .count();
    let validator2_jobs = assignments
        .iter()
        .filter(|a| a.validator_id == "validator2")
        .count();
    let validator3_jobs = assignments
        .iter()
        .filter(|a| a.validator_id == "validator3")
        .count();

    assert!(validator1_jobs > 0 || validator2_jobs > 0 || validator3_jobs > 0);
    assert_eq!(validator1_jobs + validator2_jobs + validator3_jobs, 5);

    // Submit results
    for job_id in &job_ids {
        let result = JobResult::success(job_id.clone(), vec![42; 10], 100, 1024, 50000);
        manager.submit_result(result).unwrap();
    }

    // Verify all jobs completed
    let stats = manager.get_stats();
    assert_eq!(stats.active_jobs, 0);
    assert_eq!(stats.completed_jobs, 5);

    // Verify results can be retrieved
    for job_id in &job_ids {
        let result = manager.get_result(job_id);
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.status, JobStatus::Completed);
        assert_eq!(result.output_data.as_ref().unwrap().len(), 10);
    }
}

#[test]
fn test_load_balancing_priority() {
    let manager = JobManager::new();

    // Register validators with different capacities
    manager
        .register_validator(ValidatorCapacity::new("small".to_string(), 2, 4096, 1))
        .unwrap();

    manager
        .register_validator(ValidatorCapacity::new("large".to_string(), 16, 32768, 8))
        .unwrap();

    // Submit 2 jobs
    let job1 = ComputeJob::new(vec![1], vec![1], ResourceLimits::default());
    let job2 = ComputeJob::new(vec![2], vec![2], ResourceLimits::default());

    manager.submit_job(job1).unwrap();
    manager.submit_job(job2).unwrap();

    // Assign jobs
    let assignments = manager.assign_jobs().unwrap();
    assert_eq!(assignments.len(), 2);

    // Both should go to "large" initially (lowest load factor)
    // But after first assignment, second might go to small
    let large_jobs = assignments
        .iter()
        .filter(|a| a.validator_id == "large")
        .count();

    // At least one should go to large validator
    assert!(large_jobs >= 1);
}

#[test]
fn test_validator_capacity_limits() {
    let manager = JobManager::new();

    // Register validator with max 2 jobs
    manager
        .register_validator(ValidatorCapacity::new("limited".to_string(), 4, 8192, 2))
        .unwrap();

    // Submit 3 jobs
    for i in 0..3 {
        let job = ComputeJob::new(vec![i], vec![i], ResourceLimits::default());
        manager.submit_job(job).unwrap();
    }

    // Assign jobs
    let assignments = manager.assign_jobs().unwrap();

    // Should only assign 2 jobs (validator capacity limit)
    assert_eq!(assignments.len(), 2);

    // 1 job should remain pending
    let stats = manager.get_stats();
    assert_eq!(stats.pending_jobs, 1);
    assert_eq!(stats.active_jobs, 2);
}

#[test]
fn test_job_status_tracking() {
    let manager = JobManager::new();

    manager
        .register_validator(ValidatorCapacity::new("test".to_string(), 4, 8192, 2))
        .unwrap();

    // Create and submit job
    let job = ComputeJob::new(vec![1], vec![1], ResourceLimits::default());
    let job_id = job.id.clone();
    manager.submit_job(job).unwrap();

    // Check pending status
    assert_eq!(manager.get_job_status(&job_id), Some(JobStatus::Pending));

    // Assign job
    manager.assign_jobs().unwrap();

    // Check running status
    assert_eq!(manager.get_job_status(&job_id), Some(JobStatus::Running));

    // Submit result
    let result = JobResult::success(job_id.clone(), vec![42], 100, 1024, 50000);
    manager.submit_result(result).unwrap();

    // Check completed status
    assert_eq!(manager.get_job_status(&job_id), Some(JobStatus::Completed));
}

#[test]
fn test_multiple_validator_failover() {
    let manager = JobManager::new();

    // Register 2 validators
    manager
        .register_validator(ValidatorCapacity::new("v1".to_string(), 4, 8192, 2))
        .unwrap();

    manager
        .register_validator(ValidatorCapacity::new("v2".to_string(), 4, 8192, 2))
        .unwrap();

    // Submit 4 jobs (fill both validators)
    for i in 0..4 {
        let job = ComputeJob::new(vec![i], vec![i], ResourceLimits::default());
        manager.submit_job(job).unwrap();
    }

    let assignments = manager.assign_jobs().unwrap();
    assert_eq!(assignments.len(), 4);

    // Jobs should be distributed
    let v1_jobs = assignments
        .iter()
        .filter(|a| a.validator_id == "v1")
        .count();
    let v2_jobs = assignments
        .iter()
        .filter(|a| a.validator_id == "v2")
        .count();

    assert_eq!(v1_jobs + v2_jobs, 4);
    assert!(v1_jobs == 2 && v2_jobs == 2); // Should be balanced
}

#[tokio::test]
async fn test_end_to_end_distributed_execution_with_verification() {
    // Setup coordinator
    let coordinator = JobCoordinator::new();
    let verifier = VerificationCoordinator::new();

    // Register 3 validators
    for i in 1..=3 {
        let capacity = ValidatorCapacity::new(format!("validator-{}", i), 4, 8192, 2);
        coordinator
            .update_validator_capacity(CapacityAnnouncement::new(capacity, 0))
            .await;
    }

    // Create and assign job
    let job_id = "test-job-123".to_string();
    let assignment = coordinator.assign_job(job_id.clone()).await.unwrap();
    assert!(assignment.is_some());

    // Setup verification with all 3 validators
    let validators = vec![
        "validator-1".to_string(),
        "validator-2".to_string(),
        "validator-3".to_string(),
    ];
    let verification = verifier
        .create_verification_request(job_id.clone(), validators)
        .await;
    assert!(verification.is_ok());

    // Simulate validators executing and agreeing on result
    let expected_output = vec![42u8; 16];
    for i in 1..=3 {
        let result = JobResult::success(job_id.clone(), expected_output.clone(), 100, 1024, 50000);
        verifier
            .submit_result(&job_id, format!("validator-{}", i), result)
            .await
            .unwrap();
    }

    // Check consensus - all 3 agreed
    let consensus = verifier.check_consensus(&job_id).await.unwrap();
    match consensus {
        ConsensusResult::Agreed(result) => {
            assert_eq!(result.status, JobStatus::Completed);
            assert_eq!(result.output_data.unwrap(), expected_output);
        }
        _ => panic!("Expected consensus agreement"),
    }

    // Verify metrics
    let stats = verifier.get_stats().await;
    assert_eq!(stats.active_verifications, 1);
    assert_eq!(stats.total_results_collected, 3);
    assert_eq!(stats.consensus_agreements, 1);
    assert_eq!(stats.consensus_disagreements, 0);
}

#[tokio::test]
async fn test_timeout_detection_and_automatic_reassignment() {
    let coordinator = JobCoordinator::new();

    // Register 2 validators
    for i in 1..=2 {
        let capacity = ValidatorCapacity::new(format!("validator-{}", i), 4, 8192, 2);
        coordinator
            .update_validator_capacity(CapacityAnnouncement::new(capacity, 0))
            .await;
    }

    // Assign job with custom short timeout (1 second for testing)
    let job_id = "timeout-test-job".to_string();
    let assignment = coordinator.assign_job(job_id.clone()).await.unwrap();
    assert!(assignment.is_some());

    let _initial_validator = assignment.unwrap().validator_id.clone();

    // Manually set timeout to expired for testing
    {
        let mut pending = coordinator.pending_assignments.write().await;
        if let Some(assignment) = pending.get_mut(&job_id) {
            assignment.timeout_at = 0; // Force timeout
        }
    }

    // Handle timeouts - should reassign
    let reassigned_jobs = coordinator.handle_timeouts().await.unwrap();
    assert_eq!(reassigned_jobs.len(), 1);
    assert_eq!(reassigned_jobs[0], job_id);

    // Verify job was reassigned to different or same validator
    let stats = coordinator.get_stats().await;
    assert_eq!(stats.pending_assignments, 1);
    assert_eq!(stats.average_retry_count, 1.0); // One retry
}

#[tokio::test]
async fn test_validator_failure_complete_recovery() {
    let coordinator = JobCoordinator::new();

    // Register 3 validators
    for i in 1..=3 {
        let capacity = ValidatorCapacity::new(format!("validator-{}", i), 4, 8192, 4);
        coordinator
            .update_validator_capacity(CapacityAnnouncement::new(capacity, 0))
            .await;
    }

    // Assign 6 jobs (should distribute across validators)
    let mut job_ids = Vec::new();
    for i in 0..6 {
        let job_id = format!("job-{}", i);
        coordinator.assign_job(job_id.clone()).await.unwrap();
        job_ids.push(job_id);
    }

    let stats_before = coordinator.get_stats().await;
    assert_eq!(stats_before.total_validators, 3);
    assert_eq!(stats_before.pending_assignments, 6);

    // Simulate validator-1 failure
    let _reassigned_count = coordinator
        .handle_validator_failure(&"validator-1".to_string())
        .await
        .unwrap();

    // Verify:
    // 1. Validator removed
    let stats_after = coordinator.get_stats().await;
    assert_eq!(stats_after.total_validators, 2);

    // 2. Jobs reassigned to remaining validators
    assert_eq!(stats_after.pending_assignments, 6); // All jobs still pending

    // 3. No jobs left on failed validator
    let v1_jobs = coordinator
        .get_pending_jobs_for_validator(&"validator-1".to_string())
        .await;
    assert_eq!(v1_jobs.len(), 0);
}

#[tokio::test]
async fn test_consensus_with_byzantine_disagreement() {
    let verifier = VerificationCoordinator::new();
    let job_id = "byzantine-test".to_string();

    // Setup verification with 3 validators
    let validators = vec!["v1".to_string(), "v2".to_string(), "v3".to_string()];
    verifier
        .create_verification_request(job_id.clone(), validators)
        .await
        .unwrap();

    // Two validators agree, one disagrees (Byzantine behavior)
    let good_output = vec![42u8; 16];
    let bad_output = vec![99u8; 16];

    // v1 and v2 agree
    for validator_id in ["v1", "v2"] {
        let result = JobResult::success(job_id.clone(), good_output.clone(), 100, 1024, 50000);
        verifier
            .submit_result(&job_id, validator_id.to_string(), result)
            .await
            .unwrap();
    }

    // v3 disagrees (Byzantine)
    let bad_result = JobResult::success(job_id.clone(), bad_output.clone(), 100, 1024, 50000);
    verifier
        .submit_result(&job_id, "v3".to_string(), bad_result)
        .await
        .unwrap();

    // Check consensus - should still reach agreement (2/3)
    let consensus = verifier.check_consensus(&job_id).await.unwrap();
    match consensus {
        ConsensusResult::Agreed(result) => {
            // Should agree on the majority result
            assert_eq!(result.output_data.unwrap(), good_output);
        }
        _ => panic!("Expected consensus agreement with 2/3 majority"),
    }

    // Verify stats show disagreement was handled
    let stats = verifier.get_stats().await;
    assert_eq!(stats.consensus_agreements, 1);
}

#[tokio::test]
async fn test_max_retries_gives_up() {
    let coordinator = JobCoordinator::new();

    // Register 1 validator
    let capacity = ValidatorCapacity::new("validator-1".to_string(), 4, 8192, 2);
    coordinator
        .update_validator_capacity(CapacityAnnouncement::new(capacity, 0))
        .await;

    // Assign job
    let job_id = "retry-test".to_string();
    coordinator.assign_job(job_id.clone()).await.unwrap();

    // Simulate MAX_JOB_RETRIES timeouts + 1 more to verify it gives up
    // retry_count starts at 0, so we need MAX_JOB_RETRIES + 1 iterations
    // Iterations: 0 (rc 0→1), 1 (rc 1→2), 2 (rc 2→3), 3 (rc 3, give up)
    for retry in 0..=MAX_JOB_RETRIES {
        // Force timeout
        {
            let mut pending = coordinator.pending_assignments.write().await;
            if let Some(assignment) = pending.get_mut(&job_id) {
                assignment.timeout_at = 0;
            }
        }

        // Handle timeout
        let reassigned_jobs = coordinator.handle_timeouts().await.unwrap();

        if retry < MAX_JOB_RETRIES {
            assert_eq!(
                reassigned_jobs.len(),
                1,
                "Should reassign on attempt {} (retry_count {})",
                retry,
                retry
            );
        } else {
            assert_eq!(
                reassigned_jobs.len(),
                0,
                "Should give up after max retries (retry_count = {})",
                MAX_JOB_RETRIES
            );
        }
    }

    // Job should be removed from pending (gave up)
    let stats = coordinator.get_stats().await;
    assert_eq!(stats.pending_assignments, 0);
}

#[tokio::test]
async fn test_full_lifecycle_with_monitoring() {
    let coordinator = JobCoordinator::new();
    let verifier = VerificationCoordinator::new();

    // Register validators
    for i in 1..=3 {
        let capacity = ValidatorCapacity::new(format!("v{}", i), 8, 16384, 5);
        coordinator
            .update_validator_capacity(CapacityAnnouncement::new(capacity, 0))
            .await;
    }

    // Submit 5 jobs
    let mut job_ids = Vec::new();
    for i in 0..5 {
        let job_id = format!("job-{}", i);
        coordinator.assign_job(job_id.clone()).await.unwrap();
        job_ids.push(job_id);
    }

    // Check coordinator stats
    let coord_stats = coordinator.get_stats().await;
    assert_eq!(coord_stats.total_validators, 3);
    assert_eq!(coord_stats.available_validators, 3);
    assert_eq!(coord_stats.pending_assignments, 5);
    assert_eq!(coord_stats.average_retry_count, 0.0);

    // Setup verification for all jobs
    let validators = vec!["v1".to_string(), "v2".to_string(), "v3".to_string()];
    for job_id in &job_ids {
        verifier
            .create_verification_request(job_id.clone(), validators.clone())
            .await
            .unwrap();
    }

    // Simulate execution and consensus for all jobs
    for job_id in &job_ids {
        for validator_id in &validators {
            let result = JobResult::success(job_id.clone(), vec![42u8; 8], 100, 1024, 50000);
            verifier
                .submit_result(job_id, validator_id.clone(), result)
                .await
                .unwrap();
        }
    }

    // Verify all reached consensus
    let verify_stats = verifier.get_stats().await;
    assert_eq!(verify_stats.active_verifications, 5);
    assert_eq!(verify_stats.total_results_collected, 15); // 5 jobs * 3 validators
    assert_eq!(verify_stats.consensus_agreements, 5);
    assert_eq!(verify_stats.consensus_disagreements, 0);
    assert_eq!(verify_stats.average_validators_per_job, 3.0);
}
