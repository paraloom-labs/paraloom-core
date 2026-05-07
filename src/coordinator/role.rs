//! Coordinator role state machine.
//!
//! A node hosting a coordinator can be in one of two roles:
//! `Primary` (active, owning canonical state) or `Standby` (mirroring
//! a remote primary's state and watching for liveness). Promotion
//! flips a `Standby` to a `Primary` when the primary stalls.
//!
//! State replication and stall detection consume this enum;
//! promotion election sets it. Keeping the role separate from the
//! task-distribution logic in `Coordinator` keeps the failover
//! state machine reviewable in isolation.

use crate::types::NodeId;
use std::time::{Duration, Instant};

/// The role a coordinator-capable node is currently playing.
#[derive(Debug, Clone)]
pub enum CoordinatorRole {
    /// Active primary; owns canonical state, accepts client task
    /// submissions, dispatches chunks to validators.
    Primary,

    /// Mirroring a remote primary's state and watching for liveness.
    /// Promotes itself if the primary appears stalled.
    Standby {
        /// Identity of the primary being mirrored. Used as the
        /// tiebreak basis when multiple standbys race to promote.
        primary: NodeId,
        /// Wall-clock instant of the most recently observed
        /// heartbeat from `primary`. Initialised to construction
        /// time so a single early miss does not promote.
        last_heartbeat_at: Instant,
        /// How long the standby tolerates silence from the primary
        /// before declaring it stalled. Tunable per deployment.
        stall_threshold: Duration,
    },
}

impl CoordinatorRole {
    /// Construct a fresh `Standby` role tracking `primary`. The
    /// last-heartbeat timestamp is anchored at `now`, so the standby
    /// will not promote for at least `stall_threshold` after start
    /// even if the primary has been silent the whole time.
    pub fn standby_of(primary: NodeId, stall_threshold: Duration, now: Instant) -> Self {
        CoordinatorRole::Standby {
            primary,
            last_heartbeat_at: now,
            stall_threshold,
        }
    }

    /// True if this role is `Primary`.
    pub fn is_primary(&self) -> bool {
        matches!(self, CoordinatorRole::Primary)
    }

    /// True if this role is `Standby` and the last observed heartbeat
    /// is older than the configured stall threshold relative to `now`.
    pub fn is_stalled(&self, now: Instant) -> bool {
        match self {
            CoordinatorRole::Primary => false,
            CoordinatorRole::Standby {
                last_heartbeat_at,
                stall_threshold,
                ..
            } => now.saturating_duration_since(*last_heartbeat_at) > *stall_threshold,
        }
    }

    /// Update the standby's last-heartbeat timestamp. No-op for
    /// primary, since a primary tracking its own heartbeats would be
    /// meaningless.
    pub fn record_heartbeat(&mut self, now: Instant) {
        if let CoordinatorRole::Standby {
            last_heartbeat_at, ..
        } = self
        {
            *last_heartbeat_at = now;
        }
    }

    /// Transition from `Standby` to `Primary`. Returns the previous
    /// primary identity for audit logging if the transition occurred,
    /// `None` if already `Primary` (idempotent on repeated calls).
    pub fn promote(&mut self) -> Option<NodeId> {
        if let CoordinatorRole::Standby { primary, .. } = self {
            let previous = primary.clone();
            *self = CoordinatorRole::Primary;
            Some(previous)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nodeid(byte: u8) -> NodeId {
        NodeId(vec![byte])
    }

    #[test]
    fn primary_is_never_stalled() {
        let role = CoordinatorRole::Primary;
        assert!(!role.is_stalled(Instant::now()));
        assert!(role.is_primary());
    }

    #[test]
    fn fresh_standby_is_not_stalled() {
        let now = Instant::now();
        let role = CoordinatorRole::standby_of(nodeid(1), Duration::from_secs(30), now);
        assert!(!role.is_stalled(now));
        assert!(!role.is_stalled(now + Duration::from_secs(29)));
    }

    #[test]
    fn standby_stalls_after_threshold() {
        let now = Instant::now();
        let role = CoordinatorRole::standby_of(nodeid(1), Duration::from_secs(30), now);
        assert!(role.is_stalled(now + Duration::from_secs(31)));
    }

    #[test]
    fn record_heartbeat_postpones_stall() {
        let t0 = Instant::now();
        let mut role = CoordinatorRole::standby_of(nodeid(1), Duration::from_secs(30), t0);
        // Heartbeat received 25 seconds in: window resets.
        role.record_heartbeat(t0 + Duration::from_secs(25));
        assert!(!role.is_stalled(t0 + Duration::from_secs(54)));
        assert!(role.is_stalled(t0 + Duration::from_secs(56)));
    }

    #[test]
    fn promote_flips_standby_to_primary_and_returns_previous() {
        let now = Instant::now();
        let mut role = CoordinatorRole::standby_of(nodeid(7), Duration::from_secs(30), now);
        let previous = role.promote();
        assert_eq!(previous, Some(nodeid(7)));
        assert!(role.is_primary());
    }

    #[test]
    fn promote_is_idempotent_on_primary() {
        let mut role = CoordinatorRole::Primary;
        assert_eq!(role.promote(), None);
        assert!(role.is_primary());
    }

    #[test]
    fn record_heartbeat_on_primary_is_no_op() {
        let mut role = CoordinatorRole::Primary;
        role.record_heartbeat(Instant::now());
        assert!(role.is_primary());
    }
}
