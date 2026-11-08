//! Consensus mechanism for distributed validator network
//!
//! Handles withdrawal verification consensus, leader selection,
//! reputation tracking, and validator coordination.

pub mod leader;
pub mod reputation;
pub mod slashing;
pub mod transact;
pub mod vote_tally;

pub use leader::{LeaderSelector, ValidatorInfo};
pub use reputation::{ReputationTracker, ValidatorMetrics};
pub use slashing::{SlashingEvidence, SlashingRecord, SlashingTracker};
pub use transact::{
    ApprovedTransact, TransactVerificationCoordinator, TransactVerificationRequest,
    TransactVerificationResult,
};
pub use vote_tally::{VerificationVote, VoteTally};

/// Write `bytes` to `path` atomically by writing to a sibling temporary file,
/// flushing/fsyncing it, and renaming it over `path`. This guarantees that a
/// crash, process kill, or power loss mid-write cannot leave a truncated or
/// corrupted file.
pub(crate) fn atomic_write(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let tmp = path.with_extension("tmp");
    {
        use std::io::Write;
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        let parent_to_open = if parent.as_os_str().is_empty() {
            std::path::Path::new(".")
        } else {
            parent
        };
        if let Ok(dir) = std::fs::File::open(parent_to_open) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}
