//! Authorization for confidential-compute job submission (F3).
//!
//! A compute worker runs WASM bytecode that a submitter hands it. Before that
//! is a public or paid market, two things must be gated: WHO may submit a job,
//! and HOW MUCH of the worker any single job may claim. This module is the pure
//! policy for both — the node's `ComputeJobRequest` handler consults it before
//! passing bytecode to the executor, so an unauthorized or over-sized request
//! never reaches WASM compilation.

use super::job::ResourceLimits;
use crate::types::NodeId;
use std::collections::HashSet;
use thiserror::Error;

/// Per-job memory ceiling. Set well above the 64 MB default job so ordinary
/// jobs pass, while a single request still cannot claim the whole worker.
pub const DEFAULT_MAX_MEMORY_BYTES: u64 = 512 * 1024 * 1024;
/// Per-job instruction (fuel) ceiling.
pub const DEFAULT_MAX_INSTRUCTIONS: u64 = 10_000_000_000;
/// Per-job wall-clock timeout ceiling.
pub const DEFAULT_MAX_TIMEOUT_SECS: u64 = 300;

/// Why a compute-job submission was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ComputeAuthError {
    /// The submitting peer is not on the configured allowlist.
    #[error("submitter {0} is not authorized to submit compute jobs")]
    UnauthorizedSubmitter(NodeId),
    /// The requested memory limit exceeds the per-job ceiling.
    #[error("requested memory {requested} B exceeds the {max} B ceiling")]
    MemoryTooHigh { requested: u64, max: u64 },
    /// The requested instruction budget exceeds the per-job ceiling.
    #[error("requested instruction budget {requested} exceeds the {max} ceiling")]
    InstructionsTooHigh { requested: u64, max: u64 },
    /// The requested timeout exceeds the per-job ceiling.
    #[error("requested timeout {requested}s exceeds the {max}s ceiling")]
    TimeoutTooHigh { requested: u64, max: u64 },
}

/// Who may submit compute jobs, and the per-job resource ceiling. Pure policy;
/// it holds no execution state and does no I/O.
#[derive(Clone, Debug)]
pub struct ComputeAuthPolicy {
    /// `None` = open: any peer may submit (dev/demo). `Some(set)` = only these
    /// node identities may submit. An empty set is fail-closed (nobody). The
    /// resource ceiling below applies in either mode.
    authorized_submitters: Option<HashSet<NodeId>>,
    /// Upper bound on a single job's requested resources.
    max_limits: ResourceLimits,
}

impl ComputeAuthPolicy {
    /// Open submission (any peer) with the default resource ceiling. The
    /// ceiling still bounds every job, so even in open mode a request cannot
    /// exhaust the worker.
    pub fn open() -> Self {
        Self {
            authorized_submitters: None,
            max_limits: default_max_limits(),
        }
    }

    /// Restrict submission to `submitters`, with an explicit resource ceiling.
    /// An empty set means NO peer may submit (fail-closed) — use [`open`] for
    /// unrestricted submission.
    ///
    /// [`open`]: Self::open
    pub fn restricted(submitters: HashSet<NodeId>, max_limits: ResourceLimits) -> Self {
        Self {
            authorized_submitters: Some(submitters),
            max_limits,
        }
    }

    /// Replace the resource ceiling (builder-style).
    pub fn with_max_limits(mut self, max_limits: ResourceLimits) -> Self {
        self.max_limits = max_limits;
        self
    }

    /// True when any peer may submit (no allowlist configured).
    pub fn is_open(&self) -> bool {
        self.authorized_submitters.is_none()
    }

    /// Authorize a submission. The submitter must be allowed (when an allowlist
    /// is configured) and every requested limit must be within the ceiling.
    /// Returns the specific reason on refusal so the caller can report it.
    pub fn authorize(
        &self,
        submitter: &NodeId,
        requested: &ResourceLimits,
    ) -> Result<(), ComputeAuthError> {
        if let Some(allowed) = &self.authorized_submitters {
            if !allowed.contains(submitter) {
                return Err(ComputeAuthError::UnauthorizedSubmitter(submitter.clone()));
            }
        }
        if requested.max_memory_bytes > self.max_limits.max_memory_bytes {
            return Err(ComputeAuthError::MemoryTooHigh {
                requested: requested.max_memory_bytes,
                max: self.max_limits.max_memory_bytes,
            });
        }
        if requested.max_instructions > self.max_limits.max_instructions {
            return Err(ComputeAuthError::InstructionsTooHigh {
                requested: requested.max_instructions,
                max: self.max_limits.max_instructions,
            });
        }
        if requested.timeout_secs > self.max_limits.timeout_secs {
            return Err(ComputeAuthError::TimeoutTooHigh {
                requested: requested.timeout_secs,
                max: self.max_limits.timeout_secs,
            });
        }
        Ok(())
    }
}

impl Default for ComputeAuthPolicy {
    fn default() -> Self {
        Self::open()
    }
}

fn default_max_limits() -> ResourceLimits {
    ResourceLimits {
        max_memory_bytes: DEFAULT_MAX_MEMORY_BYTES,
        max_instructions: DEFAULT_MAX_INSTRUCTIONS,
        timeout_secs: DEFAULT_MAX_TIMEOUT_SECS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(byte: u8) -> NodeId {
        NodeId(vec![byte; 8])
    }

    /// A request comfortably inside every ceiling.
    fn small_request() -> ResourceLimits {
        ResourceLimits {
            max_memory_bytes: 64 * 1024 * 1024,
            max_instructions: 1_000_000_000,
            timeout_secs: 30,
        }
    }

    #[test]
    fn open_policy_allows_any_submitter_within_the_ceiling() {
        let policy = ComputeAuthPolicy::open();
        assert!(policy.is_open());
        assert!(policy.authorize(&node(1), &small_request()).is_ok());
        assert!(policy.authorize(&node(2), &small_request()).is_ok());
    }

    #[test]
    fn open_policy_still_rejects_over_ceiling_requests() {
        let policy = ComputeAuthPolicy::open();

        let mut over_mem = small_request();
        over_mem.max_memory_bytes = DEFAULT_MAX_MEMORY_BYTES + 1;
        assert!(matches!(
            policy.authorize(&node(1), &over_mem),
            Err(ComputeAuthError::MemoryTooHigh { .. })
        ));

        let mut over_fuel = small_request();
        over_fuel.max_instructions = DEFAULT_MAX_INSTRUCTIONS + 1;
        assert!(matches!(
            policy.authorize(&node(1), &over_fuel),
            Err(ComputeAuthError::InstructionsTooHigh { .. })
        ));

        let mut over_time = small_request();
        over_time.timeout_secs = DEFAULT_MAX_TIMEOUT_SECS + 1;
        assert!(matches!(
            policy.authorize(&node(1), &over_time),
            Err(ComputeAuthError::TimeoutTooHigh { .. })
        ));
    }

    #[test]
    fn a_request_exactly_at_the_ceiling_is_allowed() {
        let policy = ComputeAuthPolicy::open();
        let at_ceiling = ResourceLimits {
            max_memory_bytes: DEFAULT_MAX_MEMORY_BYTES,
            max_instructions: DEFAULT_MAX_INSTRUCTIONS,
            timeout_secs: DEFAULT_MAX_TIMEOUT_SECS,
        };
        assert!(policy.authorize(&node(1), &at_ceiling).is_ok());
    }

    #[test]
    fn restricted_policy_rejects_an_unlisted_submitter() {
        let allowed: HashSet<NodeId> = [node(1), node(2)].into_iter().collect();
        let policy = ComputeAuthPolicy::restricted(allowed, default_max_limits());
        assert!(!policy.is_open());
        assert!(policy.authorize(&node(1), &small_request()).is_ok());
        assert!(matches!(
            policy.authorize(&node(9), &small_request()),
            Err(ComputeAuthError::UnauthorizedSubmitter(_))
        ));
    }

    #[test]
    fn an_empty_allowlist_is_fail_closed() {
        let policy = ComputeAuthPolicy::restricted(HashSet::new(), default_max_limits());
        assert!(matches!(
            policy.authorize(&node(1), &small_request()),
            Err(ComputeAuthError::UnauthorizedSubmitter(_))
        ));
    }

    #[test]
    fn the_submitter_check_precedes_the_limit_check() {
        // An unlisted submitter is rejected as unauthorized even when its
        // requested limits are also over the ceiling — identity gates first.
        let policy = ComputeAuthPolicy::restricted(HashSet::new(), default_max_limits());
        let mut over = small_request();
        over.max_memory_bytes = u64::MAX;
        assert!(matches!(
            policy.authorize(&node(1), &over),
            Err(ComputeAuthError::UnauthorizedSubmitter(_))
        ));
    }
}
