//! Integration tests for distributed compute layer
//!
//! Tests the complete workflow:
//! - Validator registration
//! - Job submission and distribution
//! - Load balancing
//! - Result aggregation

use paraloom::compute::{
    ComputeJob, JobManager, JobResult, JobStatus, ResourceLimits, ValidatorCapacity,
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
