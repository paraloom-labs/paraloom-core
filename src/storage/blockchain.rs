//! Blockchain storage implementation

use anyhow::Result;
use log::info;
use rocksdb::{DB, Options};
use std::path::Path;

/// Blockchain storage
pub struct BlockchainStorage {
    db: DB,
}

impl BlockchainStorage {
    /// Open a blockchain storage
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        info!("Opening blockchain storage at {:?}", path.as_ref());
        
        // Create directory if it doesn't exist
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
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