//! Blockchain storage implementation

use anyhow::Result;
use log::info;
use rocksdb::{Options, DB};
use std::path::Path;

/// Blockchain storage
pub struct BlockchainStorage {
    db: DB,
}

impl BlockchainStorage {
    /// Open a blockchain storage
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_ref = path.as_ref();
        if path_ref.as_os_str().is_empty() {
            anyhow::bail!("blockchain storage path must not be empty");
        }
        info!("Opening blockchain storage at {:?}", path_ref);

        // Create directory if it doesn't exist
        if let Some(parent) = path_ref.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        // Configure RocksDB
        let mut options = Options::default();
        options.create_if_missing(true);
        options.set_keep_log_file_num(10);
        options.set_max_total_wal_size(10 * 1024 * 1024); // 10 MB

        // Open the database
        let db = DB::open(&options, path)?;

        Ok(BlockchainStorage { db })
    }

    /// Store a key-value pair
    pub fn put(&self, key: &[u8], value: &[u8]) -> Result<()> {
        self.db.put(key, value)?;
        Ok(())
    }

    /// Retrieve a value by key
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.db.get(key)?)
    }

    /// Delete a key-value pair
    pub fn delete(&self, key: &[u8]) -> Result<()> {
        self.db.delete(key)?;
        Ok(())
    }

    /// Flush data to disk
    pub fn flush(&self) -> Result<()> {
        self.db.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_rejects_empty_path_and_creates_nested_dirs() {
        assert!(BlockchainStorage::open("").is_err());
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("sub").join("chain_db");
        let store = BlockchainStorage::open(&nested).expect("open nested blockchain storage");
        store.put(b"k", b"v").unwrap();
        assert_eq!(store.get(b"k").unwrap(), Some(b"v".to_vec()));
    }
}
