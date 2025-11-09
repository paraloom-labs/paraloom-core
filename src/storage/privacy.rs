//! Privacy layer storage implementation
//!
//! Stores shielded pool state including:
//! - Merkle tree commitments
//! - Nullifier set
//! - Shielded pool metadata

use crate::privacy::types::{Commitment, Nullifier};
use anyhow::{anyhow, Result};
use log::info;
use rocksdb::{ColumnFamilyDescriptor, Options, DB};
use std::path::Path;
use std::sync::Arc;

/// Column family names
const CF_MERKLE_TREE: &str = "merkle_tree";
const CF_NULLIFIER_SET: &str = "nullifier_set";
const CF_POOL_STATE: &str = "pool_state";

/// Privacy storage using RocksDB column families
pub struct PrivacyStorage {
    db: Arc<DB>,
}

impl PrivacyStorage {
    /// Open privacy storage with column families
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        info!("Opening privacy storage at {:?}", path.as_ref());

        // Create directory if it doesn't exist
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Configure RocksDB options
        let mut options = Options::default();
        options.create_if_missing(true);
        options.create_missing_column_families(true);
        options.set_keep_log_file_num(10);
        options.set_max_total_wal_size(50 * 1024 * 1024); // 50 MB for privacy data

        // Define column families
        let cf_merkle = ColumnFamilyDescriptor::new(CF_MERKLE_TREE, Options::default());
        let cf_nullifier = ColumnFamilyDescriptor::new(CF_NULLIFIER_SET, Options::default());
        let cf_pool = ColumnFamilyDescriptor::new(CF_POOL_STATE, Options::default());

        // Open database with column families
        let db = DB::open_cf_descriptors(&options, path, vec![cf_merkle, cf_nullifier, cf_pool])?;

        Ok(PrivacyStorage { db: Arc::new(db) })
    }

    // ========== Merkle Tree Operations ==========

    /// Insert a commitment into the Merkle tree
    /// Key: index (u64 as bytes)
    /// Value: commitment (32 bytes)
    pub fn insert_commitment(&self, index: u64, commitment: &Commitment) -> Result<()> {
        let cf = self
            .db
            .cf_handle(CF_MERKLE_TREE)
            .ok_or_else(|| anyhow!("Merkle tree CF not found"))?;

        let key = index.to_le_bytes();
        self.db.put_cf(cf, key, commitment.as_bytes())?;
        Ok(())
    }

    /// Get a commitment by index
    pub fn get_commitment(&self, index: u64) -> Result<Option<Commitment>> {
        let cf = self
            .db
            .cf_handle(CF_MERKLE_TREE)
            .ok_or_else(|| anyhow!("Merkle tree CF not found"))?;

        let key = index.to_le_bytes();
        match self.db.get_cf(cf, key)? {
            Some(bytes) => {
                if bytes.len() != 32 {
                    return Err(anyhow!("Invalid commitment size: {}", bytes.len()));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Some(Commitment::from_bytes(arr)))
            }
            None => Ok(None),
        }
    }

    /// Batch insert commitments
    pub fn insert_commitments_batch(
        &self,
        start_index: u64,
        commitments: &[Commitment],
    ) -> Result<()> {
        let cf = self
            .db
            .cf_handle(CF_MERKLE_TREE)
            .ok_or_else(|| anyhow!("Merkle tree CF not found"))?;

        for (i, commitment) in commitments.iter().enumerate() {
            let index = start_index + i as u64;
            let key = index.to_le_bytes();
            self.db.put_cf(cf, key, commitment.as_bytes())?;
        }

        Ok(())
    }

    /// Get the total number of commitments
    pub fn commitment_count(&self) -> Result<u64> {
        let cf = self
            .db
            .cf_handle(CF_MERKLE_TREE)
            .ok_or_else(|| anyhow!("Merkle tree CF not found"))?;

        let mut count = 0u64;
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        for _ in iter {
            count += 1;
        }

        Ok(count)
    }

    /// Get all commitments (for rebuilding Merkle tree)
    pub fn get_all_commitments(&self) -> Result<Vec<Commitment>> {
        let cf = self
            .db
            .cf_handle(CF_MERKLE_TREE)
            .ok_or_else(|| anyhow!("Merkle tree CF not found"))?;

        let mut commitments = Vec::new();
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);

        for item in iter {
            let (_, value) = item?;
            if value.len() != 32 {
                return Err(anyhow!("Invalid commitment size in storage"));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&value);
            commitments.push(Commitment::from_bytes(arr));
        }

        Ok(commitments)
    }

    // ========== Nullifier Set Operations ==========

    /// Insert a nullifier (mark as spent)
    /// Key: nullifier (32 bytes)
    /// Value: empty (existence = spent)
    pub fn insert_nullifier(&self, nullifier: &Nullifier) -> Result<()> {
        let cf = self
            .db
            .cf_handle(CF_NULLIFIER_SET)
            .ok_or_else(|| anyhow!("Nullifier set CF not found"))?;

        self.db.put_cf(cf, nullifier.as_bytes(), [])?;
        Ok(())
    }

    /// Check if a nullifier exists (is spent)
    pub fn contains_nullifier(&self, nullifier: &Nullifier) -> Result<bool> {
        let cf = self
            .db
            .cf_handle(CF_NULLIFIER_SET)
            .ok_or_else(|| anyhow!("Nullifier set CF not found"))?;

        Ok(self.db.get_cf(cf, nullifier.as_bytes())?.is_some())
    }

    /// Batch insert nullifiers
    pub fn insert_nullifiers_batch(&self, nullifiers: &[Nullifier]) -> Result<()> {
        let cf = self
            .db
            .cf_handle(CF_NULLIFIER_SET)
            .ok_or_else(|| anyhow!("Nullifier set CF not found"))?;

        for nullifier in nullifiers {
            self.db.put_cf(cf, nullifier.as_bytes(), [])?;
        }

        Ok(())
    }

    /// Check if all nullifiers in batch are unspent (don't exist)
    pub fn check_nullifiers_batch(&self, nullifiers: &[Nullifier]) -> Result<bool> {
        let cf = self
            .db
            .cf_handle(CF_NULLIFIER_SET)
            .ok_or_else(|| anyhow!("Nullifier set CF not found"))?;

        for nullifier in nullifiers {
            if self.db.get_cf(cf, nullifier.as_bytes())?.is_some() {
                return Ok(false); // Found spent nullifier
            }
        }

        Ok(true) // All unspent
    }

    /// Get total number of spent nullifiers
    pub fn nullifier_count(&self) -> Result<u64> {
        let cf = self
            .db
            .cf_handle(CF_NULLIFIER_SET)
            .ok_or_else(|| anyhow!("Nullifier set CF not found"))?;

        let mut count = 0u64;
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        for _ in iter {
            count += 1;
        }

        Ok(count)
    }

    /// Get all nullifiers (for rebuilding set)
    pub fn get_all_nullifiers(&self) -> Result<Vec<Nullifier>> {
        let cf = self
            .db
            .cf_handle(CF_NULLIFIER_SET)
            .ok_or_else(|| anyhow!("Nullifier set CF not found"))?;

        let mut nullifiers = Vec::new();
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);

        for item in iter {
            let (key, _) = item?;
            if key.len() != 32 {
                return Err(anyhow!("Invalid nullifier size in storage"));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&key);
            nullifiers.push(Nullifier::from_bytes(arr));
        }

        Ok(nullifiers)
    }

    // ========== Pool State Operations ==========

    /// Store total shielded supply
    pub fn set_total_supply(&self, supply: u64) -> Result<()> {
        let cf = self
            .db
            .cf_handle(CF_POOL_STATE)
            .ok_or_else(|| anyhow!("Pool state CF not found"))?;

        self.db.put_cf(cf, b"total_supply", supply.to_le_bytes())?;
        Ok(())
    }

    /// Get total shielded supply
    pub fn get_total_supply(&self) -> Result<u64> {
        let cf = self
            .db
            .cf_handle(CF_POOL_STATE)
            .ok_or_else(|| anyhow!("Pool state CF not found"))?;

        match self.db.get_cf(cf, b"total_supply")? {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(anyhow!("Invalid total supply size"));
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);
                Ok(u64::from_le_bytes(arr))
            }
            None => Ok(0), // No supply yet
        }
    }

    /// Store Merkle root
    pub fn set_merkle_root(&self, root: &[u8; 32]) -> Result<()> {
        let cf = self
            .db
            .cf_handle(CF_POOL_STATE)
            .ok_or_else(|| anyhow!("Pool state CF not found"))?;

        self.db.put_cf(cf, b"merkle_root", root)?;
        Ok(())
    }

    /// Get Merkle root
    pub fn get_merkle_root(&self) -> Result<Option<[u8; 32]>> {
        let cf = self
            .db
            .cf_handle(CF_POOL_STATE)
            .ok_or_else(|| anyhow!("Pool state CF not found"))?;

        match self.db.get_cf(cf, b"merkle_root")? {
            Some(bytes) => {
                if bytes.len() != 32 {
                    return Err(anyhow!("Invalid merkle root size"));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }

    // ========== Utility Operations ==========

    /// Flush all data to disk
    pub fn flush(&self) -> Result<()> {
        self.db.flush()?;
        Ok(())
    }

    /// Get a clone of the DB handle for sharing
    pub fn db_handle(&self) -> Arc<DB> {
        Arc::clone(&self.db)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_privacy_storage_open() {
        let dir = tempdir().unwrap();
        let storage = PrivacyStorage::open(dir.path().join("privacy.db")).unwrap();
        assert_eq!(storage.commitment_count().unwrap(), 0);
    }

    #[test]
    fn test_commitment_insert_and_get() {
        let dir = tempdir().unwrap();
        let storage = PrivacyStorage::open(dir.path().join("privacy.db")).unwrap();

        let commitment = Commitment([42u8; 32]);
        storage.insert_commitment(0, &commitment).unwrap();

        let retrieved = storage.get_commitment(0).unwrap().unwrap();
        assert_eq!(commitment, retrieved);
    }

    #[test]
    fn test_commitment_batch_insert() {
        let dir = tempdir().unwrap();
        let storage = PrivacyStorage::open(dir.path().join("privacy.db")).unwrap();

        let commitments = vec![
            Commitment([1u8; 32]),
            Commitment([2u8; 32]),
            Commitment([3u8; 32]),
        ];

        storage.insert_commitments_batch(0, &commitments).unwrap();
        assert_eq!(storage.commitment_count().unwrap(), 3);

        let retrieved = storage.get_commitment(1).unwrap().unwrap();
        assert_eq!(commitments[1], retrieved);
    }

    #[test]
    fn test_nullifier_insert_and_check() {
        let dir = tempdir().unwrap();
        let storage = PrivacyStorage::open(dir.path().join("privacy.db")).unwrap();

        let nullifier = Nullifier([100u8; 32]);
        assert!(!storage.contains_nullifier(&nullifier).unwrap());

        storage.insert_nullifier(&nullifier).unwrap();
        assert!(storage.contains_nullifier(&nullifier).unwrap());
    }

    #[test]
    fn test_nullifier_batch_check() {
        let dir = tempdir().unwrap();
        let storage = PrivacyStorage::open(dir.path().join("privacy.db")).unwrap();

        let nullifiers = vec![Nullifier([1u8; 32]), Nullifier([2u8; 32])];

        // All unspent initially
        assert!(storage.check_nullifiers_batch(&nullifiers).unwrap());

        // Spend one
        storage.insert_nullifier(&nullifiers[0]).unwrap();

        // Batch check should fail
        assert!(!storage.check_nullifiers_batch(&nullifiers).unwrap());
    }

    #[test]
    fn test_total_supply() {
        let dir = tempdir().unwrap();
        let storage = PrivacyStorage::open(dir.path().join("privacy.db")).unwrap();

        assert_eq!(storage.get_total_supply().unwrap(), 0);

        storage.set_total_supply(1000).unwrap();
        assert_eq!(storage.get_total_supply().unwrap(), 1000);

        storage.set_total_supply(2000).unwrap();
        assert_eq!(storage.get_total_supply().unwrap(), 2000);
    }

    #[test]
    fn test_merkle_root() {
        let dir = tempdir().unwrap();
        let storage = PrivacyStorage::open(dir.path().join("privacy.db")).unwrap();

        assert!(storage.get_merkle_root().unwrap().is_none());

        let root = [42u8; 32];
        storage.set_merkle_root(&root).unwrap();
        assert_eq!(storage.get_merkle_root().unwrap().unwrap(), root);
    }

    #[test]
    fn test_get_all_commitments() {
        let dir = tempdir().unwrap();
        let storage = PrivacyStorage::open(dir.path().join("privacy.db")).unwrap();

        let commitments = vec![
            Commitment([1u8; 32]),
            Commitment([2u8; 32]),
            Commitment([3u8; 32]),
        ];

        storage.insert_commitments_batch(0, &commitments).unwrap();

        let all = storage.get_all_commitments().unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all, commitments);
    }

    #[test]
    fn test_get_all_nullifiers() {
        let dir = tempdir().unwrap();
        let storage = PrivacyStorage::open(dir.path().join("privacy.db")).unwrap();

        let nullifiers = vec![Nullifier([1u8; 32]), Nullifier([2u8; 32])];

        for nullifier in &nullifiers {
            storage.insert_nullifier(nullifier).unwrap();
        }

        let all = storage.get_all_nullifiers().unwrap();
        assert_eq!(all.len(), 2);
        assert!(all.contains(&nullifiers[0]));
        assert!(all.contains(&nullifiers[1]));
    }
}
