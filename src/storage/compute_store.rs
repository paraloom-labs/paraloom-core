//! Compute layer storage implementation
//!
//! Stores compute job state including:
//! - Pending jobs queue
//! - Active jobs (currently executing)
//! - Completed job results
//! - Job metadata

use crate::compute::{ComputeJob, JobId, JobResult};
use anyhow::{anyhow, Result};
use log::{debug, info};
use rocksdb::{ColumnFamilyDescriptor, Options, DB};
use std::path::Path;
use std::sync::Arc;

/// Column family names
const CF_PENDING_JOBS: &str = "pending_jobs";
const CF_ACTIVE_JOBS: &str = "active_jobs";
const CF_COMPLETED_RESULTS: &str = "completed_results";

/// Compute storage using RocksDB column families
pub struct ComputeStorage {
    db: Arc<DB>,
}

impl ComputeStorage {
    /// Open compute storage with column families
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        info!("Opening compute storage at {:?}", path.as_ref());

        // Create directory if it doesn't exist
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Configure RocksDB options
        let mut options = Options::default();
        options.create_if_missing(true);
        options.create_missing_column_families(true);
        options.set_keep_log_file_num(10);
        options.set_max_total_wal_size(100 * 1024 * 1024); // 100 MB for compute jobs

        // Define column families
        let cf_pending = ColumnFamilyDescriptor::new(CF_PENDING_JOBS, Options::default());
        let cf_active = ColumnFamilyDescriptor::new(CF_ACTIVE_JOBS, Options::default());
        let cf_completed = ColumnFamilyDescriptor::new(CF_COMPLETED_RESULTS, Options::default());

        // Open database with column families
        let db =
            DB::open_cf_descriptors(&options, path, vec![cf_pending, cf_active, cf_completed])?;

        Ok(ComputeStorage { db: Arc::new(db) })
    }

    // ========== Pending Jobs Operations ==========

    /// Add a job to the pending queue
    pub fn add_pending_job(&self, job: &ComputeJob) -> Result<()> {
        let cf = self
            .db
            .cf_handle(CF_PENDING_JOBS)
            .ok_or_else(|| anyhow!("Pending jobs CF not found"))?;

        let key = job.id.as_bytes();
        let value = bincode::serialize(job)?;
        self.db.put_cf(cf, key, value)?;

        debug!("Added pending job: {}", job.id);
        Ok(())
    }

    /// Get a pending job by ID
    pub fn get_pending_job(&self, job_id: &JobId) -> Result<Option<ComputeJob>> {
        let cf = self
            .db
            .cf_handle(CF_PENDING_JOBS)
            .ok_or_else(|| anyhow!("Pending jobs CF not found"))?;

        match self.db.get_cf(cf, job_id.as_bytes())? {
            Some(bytes) => {
                let job: ComputeJob = bincode::deserialize(&bytes)?;
                Ok(Some(job))
            }
            None => Ok(None),
        }
    }

    /// Get all pending jobs
    pub fn get_all_pending_jobs(&self) -> Result<Vec<ComputeJob>> {
        let cf = self
            .db
            .cf_handle(CF_PENDING_JOBS)
            .ok_or_else(|| anyhow!("Pending jobs CF not found"))?;

        let mut jobs = Vec::new();
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);

        for item in iter {
            let (_, value) = item?;
            let job: ComputeJob = bincode::deserialize(&value)?;
            jobs.push(job);
        }

        Ok(jobs)
    }

    /// Remove a job from pending queue
    pub fn remove_pending_job(&self, job_id: &JobId) -> Result<()> {
        let cf = self
            .db
            .cf_handle(CF_PENDING_JOBS)
            .ok_or_else(|| anyhow!("Pending jobs CF not found"))?;

        self.db.delete_cf(cf, job_id.as_bytes())?;
        debug!("Removed pending job: {}", job_id);
        Ok(())
    }

    /// Count pending jobs
    pub fn count_pending_jobs(&self) -> Result<usize> {
        let cf = self
            .db
            .cf_handle(CF_PENDING_JOBS)
            .ok_or_else(|| anyhow!("Pending jobs CF not found"))?;

        let count = self
            .db
            .iterator_cf(cf, rocksdb::IteratorMode::Start)
            .count();
        Ok(count)
    }

    // ========== Active Jobs Operations ==========

    /// Mark a job as active (currently executing)
    pub fn mark_job_active(&self, job: &ComputeJob) -> Result<()> {
        let cf = self
            .db
            .cf_handle(CF_ACTIVE_JOBS)
            .ok_or_else(|| anyhow!("Active jobs CF not found"))?;

        let key = job.id.as_bytes();
        let value = bincode::serialize(job)?;
        self.db.put_cf(cf, key, value)?;

        // Remove from pending
        self.remove_pending_job(&job.id)?;

        debug!("Marked job as active: {}", job.id);
        Ok(())
    }

    /// Get an active job by ID
    pub fn get_active_job(&self, job_id: &JobId) -> Result<Option<ComputeJob>> {
        let cf = self
            .db
            .cf_handle(CF_ACTIVE_JOBS)
            .ok_or_else(|| anyhow!("Active jobs CF not found"))?;

        match self.db.get_cf(cf, job_id.as_bytes())? {
            Some(bytes) => {
                let job: ComputeJob = bincode::deserialize(&bytes)?;
                Ok(Some(job))
            }
            None => Ok(None),
        }
    }

    /// Get all active jobs
    pub fn get_all_active_jobs(&self) -> Result<Vec<ComputeJob>> {
        let cf = self
            .db
            .cf_handle(CF_ACTIVE_JOBS)
            .ok_or_else(|| anyhow!("Active jobs CF not found"))?;

        let mut jobs = Vec::new();
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);

        for item in iter {
            let (_, value) = item?;
            let job: ComputeJob = bincode::deserialize(&value)?;
            jobs.push(job);
        }

        Ok(jobs)
    }

    /// Remove a job from active queue
    pub fn remove_active_job(&self, job_id: &JobId) -> Result<()> {
        let cf = self
            .db
            .cf_handle(CF_ACTIVE_JOBS)
            .ok_or_else(|| anyhow!("Active jobs CF not found"))?;

        self.db.delete_cf(cf, job_id.as_bytes())?;
        debug!("Removed active job: {}", job_id);
        Ok(())
    }

    /// Count active jobs
    pub fn count_active_jobs(&self) -> Result<usize> {
        let cf = self
            .db
            .cf_handle(CF_ACTIVE_JOBS)
            .ok_or_else(|| anyhow!("Active jobs CF not found"))?;

        let count = self
            .db
            .iterator_cf(cf, rocksdb::IteratorMode::Start)
            .count();
        Ok(count)
    }

    // ========== Completed Results Operations ==========

    /// Store a completed job result
    pub fn store_result(&self, result: &JobResult) -> Result<()> {
        let cf = self
            .db
            .cf_handle(CF_COMPLETED_RESULTS)
            .ok_or_else(|| anyhow!("Completed results CF not found"))?;

        let key = result.job_id.as_bytes();
        let value = bincode::serialize(result)?;
        self.db.put_cf(cf, key, value)?;

        // Remove from active jobs
        self.remove_active_job(&result.job_id)?;

        debug!("Stored result for job: {}", result.job_id);
        Ok(())
    }

    /// Get a job result by ID
    pub fn get_result(&self, job_id: &JobId) -> Result<Option<JobResult>> {
        let cf = self
            .db
            .cf_handle(CF_COMPLETED_RESULTS)
            .ok_or_else(|| anyhow!("Completed results CF not found"))?;

        match self.db.get_cf(cf, job_id.as_bytes())? {
            Some(bytes) => {
                let result: JobResult = bincode::deserialize(&bytes)?;
                Ok(Some(result))
            }
            None => Ok(None),
        }
    }

    /// Get all completed results
    pub fn get_all_results(&self) -> Result<Vec<JobResult>> {
        let cf = self
            .db
            .cf_handle(CF_COMPLETED_RESULTS)
            .ok_or_else(|| anyhow!("Completed results CF not found"))?;

        let mut results = Vec::new();
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);

        for item in iter {
            let (_, value) = item?;
            let result: JobResult = bincode::deserialize(&value)?;
            results.push(result);
        }

        Ok(results)
    }

    /// Delete a result (for cleanup)
    pub fn delete_result(&self, job_id: &JobId) -> Result<()> {
        let cf = self
            .db
            .cf_handle(CF_COMPLETED_RESULTS)
            .ok_or_else(|| anyhow!("Completed results CF not found"))?;

        self.db.delete_cf(cf, job_id.as_bytes())?;
        debug!("Deleted result for job: {}", job_id);
        Ok(())
    }

    /// Count completed results
    pub fn count_completed_results(&self) -> Result<usize> {
        let cf = self
            .db
            .cf_handle(CF_COMPLETED_RESULTS)
            .ok_or_else(|| anyhow!("Completed results CF not found"))?;

        let count = self
            .db
            .iterator_cf(cf, rocksdb::IteratorMode::Start)
            .count();
        Ok(count)
    }

    // ========== Utility Operations ==========

    /// Clear all pending jobs (for testing/cleanup)
    pub fn clear_pending_jobs(&self) -> Result<()> {
        let cf = self
            .db
            .cf_handle(CF_PENDING_JOBS)
            .ok_or_else(|| anyhow!("Pending jobs CF not found"))?;

        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        for item in iter {
            let (key, _) = item?;
            self.db.delete_cf(cf, key)?;
        }

        info!("Cleared all pending jobs");
        Ok(())
    }

    /// Get statistics
    pub fn get_stats(&self) -> Result<ComputeStorageStats> {
        Ok(ComputeStorageStats {
            pending_jobs: self.count_pending_jobs()?,
            active_jobs: self.count_active_jobs()?,
            completed_results: self.count_completed_results()?,
        })
    }
}

/// Storage statistics
#[derive(Debug, Clone)]
pub struct ComputeStorageStats {
    pub pending_jobs: usize,
    pub active_jobs: usize,
    pub completed_results: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute::ResourceLimits;
    use tempfile::tempdir;

    #[test]
    fn test_storage_creation() {
        let dir = tempdir().unwrap();
        let storage = ComputeStorage::open(dir.path().join("compute"));
        assert!(storage.is_ok());
    }

    #[test]
    fn test_pending_job_operations() {
        let dir = tempdir().unwrap();
        let storage = ComputeStorage::open(dir.path().join("compute")).unwrap();

        // Create a test job
        let job = ComputeJob::new(
            vec![0x00, 0x61, 0x73, 0x6d],
            vec![1, 2, 3],
            ResourceLimits::default(),
        );
        let job_id = job.id.clone();

        // Add job
        storage.add_pending_job(&job).unwrap();

        // Retrieve job
        let retrieved = storage.get_pending_job(&job_id).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, job_id);

        // Count
        assert_eq!(storage.count_pending_jobs().unwrap(), 1);

        // Remove job
        storage.remove_pending_job(&job_id).unwrap();
        assert_eq!(storage.count_pending_jobs().unwrap(), 0);
    }

    #[test]
    fn test_active_job_operations() {
        let dir = tempdir().unwrap();
        let storage = ComputeStorage::open(dir.path().join("compute")).unwrap();

        let job = ComputeJob::new(vec![1, 2], vec![3, 4], ResourceLimits::default());
        let job_id = job.id.clone();

        // Add as pending first
        storage.add_pending_job(&job).unwrap();
        assert_eq!(storage.count_pending_jobs().unwrap(), 1);

        // Mark as active
        storage.mark_job_active(&job).unwrap();
        assert_eq!(storage.count_pending_jobs().unwrap(), 0);
        assert_eq!(storage.count_active_jobs().unwrap(), 1);

        // Retrieve
        let retrieved = storage.get_active_job(&job_id).unwrap();
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_result_storage() {
        let dir = tempdir().unwrap();
        let storage = ComputeStorage::open(dir.path().join("compute")).unwrap();

        let job = ComputeJob::new(vec![5], vec![6], ResourceLimits::default());
        let job_id = job.id.clone();

        // Add as active
        storage.add_pending_job(&job).unwrap();
        storage.mark_job_active(&job).unwrap();

        // Store result
        let result = crate::compute::JobResult::success(job_id.clone(), vec![42], 100, 1024, 50000);

        storage.store_result(&result).unwrap();
        assert_eq!(storage.count_active_jobs().unwrap(), 0);
        assert_eq!(storage.count_completed_results().unwrap(), 1);

        // Retrieve result
        let retrieved = storage.get_result(&job_id).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().job_id, job_id);
    }
}
