//! Privacy layer storage implementation
//!
//! Stores shielded pool state including:
//! - Merkle tree commitments
//! - Nullifier set
//! - Shielded pool metadata
//!
//! ## Durability model (#68)
//!
//! Five writes are durability-critical: they record the on-disk
//! state the privacy layer relies on to prevent double-spends and
//! to anchor proofs after a crash. They go through
//! [`durable_write_options`], which sets `sync = true` so the
//! write only returns once the data has been fsync'd through to
//! disk:
//!
//! - `insert_commitment` / `insert_commitments_batch`
//! - `insert_nullifier` / `insert_nullifiers_batch`
//! - `set_total_supply`
//!
//! `set_merkle_root` is intentionally async — the root is a cache
//! that the tree can rebuild from the persisted leaves on startup,
//! so a missed write costs at most a one-time recomputation rather
//! than data loss. Documented as such in #59 and preserved here.

use crate::privacy::types::{AssetId, Commitment, Nullifier, NATIVE_SOL_ASSET};
use anyhow::{anyhow, Result};
use log::info;
use rocksdb::{ColumnFamilyDescriptor, Options, WriteOptions, DB};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// `WriteOptions` for the durability-critical paths described in the
/// module docs. `sync = true` instructs RocksDB to fsync the WAL
/// (and through it, the OS page cache) before the write is
/// acknowledged, so a crash in the next millisecond cannot lose the
/// already-confirmed mutation.
fn durable_write_options() -> WriteOptions {
    let mut opts = WriteOptions::default();
    opts.set_sync(true);
    opts
}

/// Column family names
const CF_MERKLE_TREE: &str = "merkle_tree";
const CF_NULLIFIER_SET: &str = "nullifier_set";
const CF_POOL_STATE: &str = "pool_state";

/// Key prefix for per-asset shielded supply entries in `CF_POOL_STATE`
/// (#236). A non-native asset's supply is stored under
/// `SUPPLY_PREFIX || asset_id` (39 bytes). Native SOL is the exception:
/// it stays under the legacy `total_supply` key so pools predating
/// multi-asset support load with no migration.
const SUPPLY_PREFIX: &[u8] = b"supply:";

/// Build the `CF_POOL_STATE` key for a non-native asset's supply.
fn asset_supply_key(asset_id: &AssetId) -> Vec<u8> {
    let mut key = Vec::with_capacity(SUPPLY_PREFIX.len() + asset_id.len());
    key.extend_from_slice(SUPPLY_PREFIX);
    key.extend_from_slice(asset_id);
    key
}

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

    /// Insert a commitment into the Merkle tree.
    ///
    /// Durability-critical: synchronous fsync via
    /// [`durable_write_options`]. A crash after this returns must
    /// not lose the leaf — the in-memory tree relies on RocksDB as
    /// the source of truth on restart.
    pub fn insert_commitment(&self, index: u64, commitment: &Commitment) -> Result<()> {
        let cf = self
            .db
            .cf_handle(CF_MERKLE_TREE)
            .ok_or_else(|| anyhow!("Merkle tree CF not found"))?;

        let key = index.to_le_bytes();
        self.db
            .put_cf_opt(cf, key, commitment.as_bytes(), &durable_write_options())?;
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

    /// Batch insert commitments.
    ///
    /// Uses a `WriteBatch` with sync semantics: every entry is
    /// staged into the batch, then a single atomic, fsync'd write
    /// commits all of them. Either every leaf in the batch lands
    /// on disk, or none does — the in-memory tree mirrors the
    /// successful-path invariant.
    pub fn insert_commitments_batch(
        &self,
        start_index: u64,
        commitments: &[Commitment],
    ) -> Result<()> {
        let cf = self
            .db
            .cf_handle(CF_MERKLE_TREE)
            .ok_or_else(|| anyhow!("Merkle tree CF not found"))?;

        let mut batch = rocksdb::WriteBatch::default();
        for (i, commitment) in commitments.iter().enumerate() {
            let index = start_index + i as u64;
            let key = index.to_le_bytes();
            batch.put_cf(cf, key, commitment.as_bytes());
        }
        self.db.write_opt(batch, &durable_write_options())?;

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

        // Return commitments in numeric leaf-index order. Leaves are stored
        // keyed by `index.to_le_bytes()`, but RocksDB iterates keys bytewise and
        // little-endian order diverges from numeric order past index 255 (the
        // second byte becomes non-zero) — iterating without re-sorting would
        // permute the tree on reconstruction and change its root and paths.
        // Decode each key and sort by it so the rebuilt tree matches the order
        // the leaves were appended in.
        let mut indexed: Vec<(u64, Commitment)> = Vec::new();
        let iter = self.db.iterator_cf(cf, rocksdb::IteratorMode::Start);

        for item in iter {
            let (key, value) = item?;
            if value.len() != 32 {
                return Err(anyhow!("Invalid commitment size in storage"));
            }
            let idx_bytes: [u8; 8] = key
                .as_ref()
                .try_into()
                .map_err(|_| anyhow!("Invalid merkle-tree key length in storage"))?;
            let index = u64::from_le_bytes(idx_bytes);
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&value);
            indexed.push((index, Commitment::from_bytes(arr)));
        }

        indexed.sort_by_key(|(index, _)| *index);
        Ok(indexed.into_iter().map(|(_, c)| c).collect())
    }

    // ========== Nullifier Set Operations ==========

    /// Insert a nullifier (mark as spent).
    ///
    /// Most safety-critical write in the system: a missed nullifier
    /// on restart re-opens a double-spend window for the
    /// already-spent note. Forced fsync via
    /// [`durable_write_options`] — the write does not return until
    /// the WAL has hit disk.
    pub fn insert_nullifier(&self, nullifier: &Nullifier) -> Result<()> {
        let cf = self
            .db
            .cf_handle(CF_NULLIFIER_SET)
            .ok_or_else(|| anyhow!("Nullifier set CF not found"))?;

        self.db
            .put_cf_opt(cf, nullifier.as_bytes(), [], &durable_write_options())?;
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

    /// Batch insert nullifiers.
    ///
    /// Same crash-consistency contract as
    /// [`Self::insert_commitments_batch`]: a single atomic, fsync'd
    /// `WriteBatch`. All-or-nothing relative to a crash, with one
    /// fsync amortised across the whole batch.
    pub fn insert_nullifiers_batch(&self, nullifiers: &[Nullifier]) -> Result<()> {
        let cf = self
            .db
            .cf_handle(CF_NULLIFIER_SET)
            .ok_or_else(|| anyhow!("Nullifier set CF not found"))?;

        let mut batch = rocksdb::WriteBatch::default();
        for nullifier in nullifiers {
            batch.put_cf(cf, nullifier.as_bytes(), []);
        }
        self.db.write_opt(batch, &durable_write_options())?;

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

    /// Store total shielded supply.
    ///
    /// Durability-critical: a stale total-supply on restart breaks
    /// the pool's accounting invariants. Forced fsync.
    pub fn set_total_supply(&self, supply: u64) -> Result<()> {
        let cf = self
            .db
            .cf_handle(CF_POOL_STATE)
            .ok_or_else(|| anyhow!("Pool state CF not found"))?;

        self.db.put_cf_opt(
            cf,
            b"total_supply",
            supply.to_le_bytes(),
            &durable_write_options(),
        )?;
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

    /// Store the shielded supply of `asset_id` (#236).
    ///
    /// Native SOL routes to [`set_total_supply`](Self::set_total_supply) so
    /// its on-disk key is unchanged; non-native assets are stored under
    /// `SUPPLY_PREFIX || asset_id`. Durability-critical like the native
    /// supply — a stale value on restart breaks pool accounting — so the
    /// non-native path also forces fsync.
    pub fn set_asset_supply(&self, asset_id: &AssetId, supply: u64) -> Result<()> {
        if asset_id == &NATIVE_SOL_ASSET {
            return self.set_total_supply(supply);
        }
        let cf = self
            .db
            .cf_handle(CF_POOL_STATE)
            .ok_or_else(|| anyhow!("Pool state CF not found"))?;
        self.db.put_cf_opt(
            cf,
            asset_supply_key(asset_id),
            supply.to_le_bytes(),
            &durable_write_options(),
        )?;
        Ok(())
    }

    /// Get the shielded supply of `asset_id` (#236). Returns 0 for an asset
    /// the pool has never held.
    pub fn get_asset_supply(&self, asset_id: &AssetId) -> Result<u64> {
        if asset_id == &NATIVE_SOL_ASSET {
            return self.get_total_supply();
        }
        let cf = self
            .db
            .cf_handle(CF_POOL_STATE)
            .ok_or_else(|| anyhow!("Pool state CF not found"))?;
        match self.db.get_cf(cf, asset_supply_key(asset_id))? {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(anyhow!("Invalid asset supply size"));
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);
                Ok(u64::from_le_bytes(arr))
            }
            None => Ok(0),
        }
    }

    /// Load every asset's shielded supply (#236) — native SOL from the
    /// legacy `total_supply` key plus all non-native assets under the
    /// `SUPPLY_PREFIX`. Used to rehydrate the pool's per-asset map on
    /// startup. Zero-valued entries are omitted.
    pub fn get_all_asset_supplies(&self) -> Result<HashMap<AssetId, u64>> {
        let cf = self
            .db
            .cf_handle(CF_POOL_STATE)
            .ok_or_else(|| anyhow!("Pool state CF not found"))?;

        let mut supplies = HashMap::new();

        // Native SOL lives under the legacy key, not the prefix.
        let native = self.get_total_supply()?;
        if native > 0 {
            supplies.insert(NATIVE_SOL_ASSET, native);
        }

        // Non-native assets: scan the `supply:` prefix. The iterator seeks
        // to the first key >= prefix and runs forward, so stop once a key
        // no longer carries the prefix.
        for item in self.db.prefix_iterator_cf(cf, SUPPLY_PREFIX) {
            let (key, value) = item?;
            if !key.starts_with(SUPPLY_PREFIX) {
                break;
            }
            let id_bytes = &key[SUPPLY_PREFIX.len()..];
            if id_bytes.len() != 32 || value.len() != 8 {
                continue;
            }
            let mut asset = [0u8; 32];
            asset.copy_from_slice(id_bytes);
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&value);
            let supply = u64::from_le_bytes(arr);
            if supply > 0 {
                supplies.insert(asset, supply);
            }
        }

        Ok(supplies)
    }

    /// Store Merkle root.
    ///
    /// Intentionally async (no fsync) — the root is a cache that
    /// the tree rebuilds from the persisted leaves on startup, so a
    /// missed write here costs at most a one-time recomputation
    /// rather than data loss. See the module docs and #59.
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
    fn test_per_asset_supply() {
        let dir = tempdir().unwrap();
        let storage = PrivacyStorage::open(dir.path().join("privacy.db")).unwrap();

        let usdc: AssetId = [7u8; 32];

        // Unknown assets read as zero.
        assert_eq!(storage.get_asset_supply(&usdc).unwrap(), 0);

        // Native SOL routes through the legacy total_supply key.
        storage.set_asset_supply(&NATIVE_SOL_ASSET, 1000).unwrap();
        assert_eq!(storage.get_total_supply().unwrap(), 1000);
        assert_eq!(storage.get_asset_supply(&NATIVE_SOL_ASSET).unwrap(), 1000);

        // A non-native asset is stored under its own prefixed key.
        storage.set_asset_supply(&usdc, 500).unwrap();
        assert_eq!(storage.get_asset_supply(&usdc).unwrap(), 500);

        // Loading all supplies returns both, keyed by asset.
        let all = storage.get_all_asset_supplies().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[&NATIVE_SOL_ASSET], 1000);
        assert_eq!(all[&usdc], 500);
    }

    #[test]
    fn test_all_asset_supplies_back_compat() {
        // A pool persisted before #236 has only the legacy total_supply
        // key; it must load as the native-SOL supply with no migration.
        let dir = tempdir().unwrap();
        let storage = PrivacyStorage::open(dir.path().join("privacy.db")).unwrap();
        storage.set_total_supply(4242).unwrap();

        let all = storage.get_all_asset_supplies().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[&NATIVE_SOL_ASSET], 4242);
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

    #[test]
    fn get_all_commitments_preserves_numeric_index_order_past_256() {
        // Regression: leaves are keyed by `index.to_le_bytes()`, but RocksDB
        // iterates keys bytewise, so little-endian key order diverges from
        // numeric order past index 255. get_all_commitments() must re-sort by the
        // decoded index, or the rebuilt tree permutes and its root/paths change
        // on restart. Tag each leaf with its index so we can assert the order.
        let dir = tempdir().unwrap();
        let storage = PrivacyStorage::open(dir.path().join("privacy.db")).unwrap();

        for i in 0u64..=256 {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&i.to_le_bytes());
            storage.insert_commitment(i, &Commitment(bytes)).unwrap();
        }

        let all = storage.get_all_commitments().unwrap();
        assert_eq!(all.len(), 257);
        for (pos, c) in all.iter().enumerate() {
            let idx = u64::from_le_bytes(c.as_bytes()[..8].try_into().unwrap());
            assert_eq!(
                idx, pos as u64,
                "leaf at position {pos} carries index {idx}; reconstruction must \
                 follow numeric index order, not RocksDB bytewise key order"
            );
        }
    }
}
