//! Peer registry with reconnection state machine.
//!
//! The pre-#65 module was a one-line stub. This module gives the
//! network layer a typed view of every known peer — connected,
//! disconnected, or in backoff — plus the algorithm that decides
//! when to retry a failed connection.
//!
//! Responsibilities split between this module and the libp2p
//! swarm event loop:
//!   - **Here**: peer state, retry scheduling, slow-vs-offline
//!     classification, summary metrics.
//!   - **Caller (swarm event loop)**: actually opening / closing
//!     connections, calling `mark_*` methods on the right events,
//!     polling `peers_due_for_reconnect` and dialing them.
//!
//! Keeping the algorithm pure means it has no libp2p dependency
//! and is fully unit-testable. The swarm integration (Kademlia
//! DHT, dial logic) lands in a follow-up; this PR provides the
//! state-machine foundation that integration will sit on top of.
//!
//! See #65 for the audit follow-up that introduced this module.

use crate::types::NodeId;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How long to wait before each reconnect attempt, indexed by the
/// number of consecutive failed attempts. Saturates at 5 minutes —
/// long enough to back off a peer that's actually offline, short
/// enough to recover quickly when the peer comes back.
pub const RECONNECT_BACKOFF: &[Duration] = &[
    Duration::from_secs(10),
    Duration::from_secs(30),
    Duration::from_secs(60),
    Duration::from_secs(120),
    Duration::from_secs(300),
];

/// Slow-response threshold. A response that takes longer than this
/// is classed as "slow"; the peer is still considered alive but the
/// metric is exported so the reputation/slashing layer can act
/// proportionally (per #62).
pub const DEFAULT_SLOW_RESPONSE_THRESHOLD: Duration = Duration::from_millis(2_000);

/// Per-peer connection state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerState {
    /// Currently connected. `last_seen` advances every time we hear
    /// from the peer.
    Connected { last_seen: Instant },
    /// Disconnected. The next reconnect attempt is scheduled at
    /// `retry_at`; `consecutive_failures` indexes into
    /// [`RECONNECT_BACKOFF`].
    Backoff {
        retry_at: Instant,
        consecutive_failures: usize,
    },
    /// Permanent — explicitly removed by the operator. The registry
    /// will not retry. Currently unused by the swarm event loop;
    /// reserved for the eventual `/admin/forget-peer` endpoint.
    Forgotten,
}

/// Snapshot of a single peer's state for the registry's external
/// reporting surface.
#[derive(Clone, Debug)]
pub struct PeerSummary {
    pub node_id: NodeId,
    pub state: PeerState,
    /// Number of slow responses observed since the peer was last
    /// connected. Reset to 0 on every fresh `mark_connected`.
    pub slow_responses: u64,
}

/// Aggregate counts for the metrics endpoint.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerCounts {
    pub connected: usize,
    pub backoff: usize,
    pub forgotten: usize,
}

/// Registry of every peer the swarm has heard about, with the
/// reconnection state machine layered on top.
pub struct PeerRegistry {
    peers: HashMap<NodeId, PeerEntry>,
    slow_response_threshold: Duration,
    /// Injectable clock so tests can deterministically advance
    /// time. Production uses `Instant::now()` via the default.
    clock: Box<dyn Fn() -> Instant + Send + Sync>,
}

#[derive(Clone, Debug)]
struct PeerEntry {
    state: PeerState,
    slow_responses: u64,
}

impl PeerRegistry {
    /// Construct a registry that uses the system clock and the
    /// default 2-second slow-response threshold.
    pub fn new() -> Self {
        Self::with_clock(Box::new(Instant::now))
    }

    /// Construct a registry with a caller-supplied clock. Used by
    /// tests to drive deterministic backoff behaviour.
    pub fn with_clock(clock: Box<dyn Fn() -> Instant + Send + Sync>) -> Self {
        Self {
            peers: HashMap::new(),
            slow_response_threshold: DEFAULT_SLOW_RESPONSE_THRESHOLD,
            clock,
        }
    }

    /// Override the slow-response threshold.
    pub fn with_slow_response_threshold(mut self, threshold: Duration) -> Self {
        self.slow_response_threshold = threshold;
        self
    }

    /// Mark a peer as actively connected. If the peer was in
    /// backoff, the failure counter resets so a future disconnect
    /// starts the backoff sequence from the beginning.
    pub fn mark_connected(&mut self, node_id: NodeId) {
        let now = (self.clock)();
        let entry = self.peers.entry(node_id).or_insert(PeerEntry {
            state: PeerState::Connected { last_seen: now },
            slow_responses: 0,
        });
        entry.state = PeerState::Connected { last_seen: now };
        entry.slow_responses = 0;
    }

    /// Update `last_seen` without changing connection state. Useful
    /// for ping/pong responses or any inbound traffic.
    pub fn mark_alive(&mut self, node_id: &NodeId) {
        let now = (self.clock)();
        if let Some(entry) = self.peers.get_mut(node_id) {
            if let PeerState::Connected { ref mut last_seen } = entry.state {
                *last_seen = now;
            }
        }
    }

    /// Record a successful response and classify it as slow if it
    /// exceeded the threshold. Slow responses count toward the
    /// per-peer summary; the connection state is not changed.
    pub fn record_response(&mut self, node_id: &NodeId, latency: Duration) {
        if let Some(entry) = self.peers.get_mut(node_id) {
            if let PeerState::Connected { ref mut last_seen } = entry.state {
                *last_seen = (self.clock)();
            }
            if latency > self.slow_response_threshold {
                entry.slow_responses = entry.slow_responses.saturating_add(1);
                log::debug!(
                    target: "paraloom::network::discovery",
                    "slow response from {:?}: {} ms (threshold {} ms)",
                    node_id,
                    latency.as_millis(),
                    self.slow_response_threshold.as_millis()
                );
            }
        }
    }

    /// Mark a peer as disconnected and schedule the next reconnect
    /// attempt according to [`RECONNECT_BACKOFF`].
    pub fn mark_disconnected(&mut self, node_id: NodeId) {
        let now = (self.clock)();
        let entry = self.peers.entry(node_id.clone()).or_insert(PeerEntry {
            state: PeerState::Backoff {
                retry_at: now,
                consecutive_failures: 0,
            },
            slow_responses: 0,
        });
        let next_failure_count = match &entry.state {
            PeerState::Backoff {
                consecutive_failures,
                ..
            } => consecutive_failures.saturating_add(1),
            _ => 1,
        };
        let backoff_idx = next_failure_count.min(RECONNECT_BACKOFF.len()) - 1;
        let retry_at = now + RECONNECT_BACKOFF[backoff_idx];
        entry.state = PeerState::Backoff {
            retry_at,
            consecutive_failures: next_failure_count,
        };
        log::info!(
            target: "paraloom::network::discovery",
            "peer {:?} disconnected; next retry in {:?} (failure #{})",
            node_id,
            RECONNECT_BACKOFF[backoff_idx],
            next_failure_count
        );
    }

    /// Mark a peer as permanently forgotten. The swarm event loop
    /// stops trying to dial it.
    pub fn forget(&mut self, node_id: NodeId) {
        let entry = self.peers.entry(node_id).or_insert(PeerEntry {
            state: PeerState::Forgotten,
            slow_responses: 0,
        });
        entry.state = PeerState::Forgotten;
    }

    /// IDs of every peer in `Backoff` whose `retry_at` has elapsed.
    /// The swarm event loop calls this on a tick and dials each
    /// returned peer.
    pub fn peers_due_for_reconnect(&self) -> Vec<NodeId> {
        let now = (self.clock)();
        self.peers
            .iter()
            .filter_map(|(id, entry)| match &entry.state {
                PeerState::Backoff { retry_at, .. } if *retry_at <= now => Some(id.clone()),
                _ => None,
            })
            .collect()
    }

    /// Snapshot summaries for every known peer. Order is not
    /// guaranteed; callers that need ordering should sort.
    pub fn summaries(&self) -> Vec<PeerSummary> {
        self.peers
            .iter()
            .map(|(id, entry)| PeerSummary {
                node_id: id.clone(),
                state: entry.state.clone(),
                slow_responses: entry.slow_responses,
            })
            .collect()
    }

    /// Aggregate counts for the metrics endpoint.
    pub fn counts(&self) -> PeerCounts {
        let mut c = PeerCounts::default();
        for entry in self.peers.values() {
            match entry.state {
                PeerState::Connected { .. } => c.connected += 1,
                PeerState::Backoff { .. } => c.backoff += 1,
                PeerState::Forgotten => c.forgotten += 1,
            }
        }
        c
    }

    /// Total number of peers known (regardless of state).
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether the registry has any peers at all.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

impl Default for PeerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Returns `(registry, clock_handle)`. Mutating `clock_handle`
    /// moves the fake clock the registry observes, so backoff
    /// branches can be tested without sleeping.
    fn registry_with_fake_clock() -> (PeerRegistry, Arc<Mutex<Instant>>) {
        let clock = Arc::new(Mutex::new(Instant::now()));
        let clock_clone = Arc::clone(&clock);
        let registry = PeerRegistry::with_clock(Box::new(move || *clock_clone.lock().unwrap()));
        (registry, clock)
    }

    fn advance(clock: &Arc<Mutex<Instant>>, by: Duration) {
        let mut t = clock.lock().unwrap();
        *t += by;
    }

    fn now(clock: &Arc<Mutex<Instant>>) -> Instant {
        *clock.lock().unwrap()
    }

    fn node(byte: u8) -> NodeId {
        NodeId(vec![byte])
    }

    /// A fresh registry has no peers and reports the right zero
    /// counts.
    #[test]
    fn fresh_registry_is_empty() {
        let registry = PeerRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.counts(), PeerCounts::default());
        assert!(registry.peers_due_for_reconnect().is_empty());
    }

    /// `mark_connected` followed by `mark_disconnected` produces
    /// the first backoff entry; advancing the fake clock past the
    /// scheduled retry surfaces the peer in
    /// `peers_due_for_reconnect`.
    #[test]
    fn disconnect_schedules_first_backoff() {
        let (mut registry, clock) = registry_with_fake_clock();
        let peer = node(1);

        registry.mark_connected(peer.clone());
        assert_eq!(registry.counts().connected, 1);

        registry.mark_disconnected(peer.clone());
        assert_eq!(registry.counts().backoff, 1);
        assert_eq!(registry.counts().connected, 0);

        // Right after disconnect, retry is 10s in the future.
        assert!(registry.peers_due_for_reconnect().is_empty());
        advance(&clock, Duration::from_secs(11));
        let due = registry.peers_due_for_reconnect();
        assert_eq!(due, vec![peer]);
    }

    /// Repeated disconnects without an intervening successful
    /// connect walk forward through `RECONNECT_BACKOFF` and
    /// saturate at the max (5 minutes).
    #[test]
    fn repeated_disconnects_walk_backoff_table_then_saturate() {
        let (mut registry, clock) = registry_with_fake_clock();
        let peer = node(2);

        for expected in RECONNECT_BACKOFF {
            registry.mark_disconnected(peer.clone());
            match &registry.summaries()[0].state {
                PeerState::Backoff { retry_at, .. } => {
                    let delay = *retry_at - now(&clock);
                    assert_eq!(delay, *expected, "backoff entry mismatch");
                }
                other => panic!("expected Backoff, got {:?}", other),
            }
        }

        // One more disconnect past the table — saturates at the max.
        registry.mark_disconnected(peer);
        match &registry.summaries()[0].state {
            PeerState::Backoff { retry_at, .. } => {
                let delay = *retry_at - now(&clock);
                let max = *RECONNECT_BACKOFF.last().unwrap();
                assert_eq!(delay, max, "saturated delay should be {:?}", max);
            }
            other => panic!("expected Backoff, got {:?}", other),
        }
    }

    /// A successful reconnect after a string of failures resets
    /// the failure counter so the next disconnect starts the
    /// backoff at the first entry again. Lets a peer that
    /// genuinely came back recover its low-latency retry without
    /// being punished for past failures.
    #[test]
    fn successful_reconnect_resets_backoff() {
        let (mut registry, clock) = registry_with_fake_clock();
        let peer = node(3);

        for _ in 0..3 {
            registry.mark_disconnected(peer.clone());
        }
        registry.mark_connected(peer.clone());
        registry.mark_disconnected(peer.clone());

        match &registry.summaries()[0].state {
            PeerState::Backoff {
                consecutive_failures,
                retry_at,
            } => {
                assert_eq!(*consecutive_failures, 1);
                let delay = *retry_at - now(&clock);
                assert_eq!(delay, RECONNECT_BACKOFF[0]);
            }
            other => panic!(
                "expected Backoff after reconnect+disconnect, got {:?}",
                other
            ),
        }
    }

    /// `record_response` with a latency above the threshold bumps
    /// the slow-response counter; below-threshold latencies do
    /// not. Peer state stays Connected throughout.
    #[test]
    fn record_response_classifies_slow_responses() {
        let (mut registry, _clock) = registry_with_fake_clock();
        let peer = node(4);
        registry.mark_connected(peer.clone());

        registry.record_response(&peer, Duration::from_millis(100));
        registry.record_response(&peer, Duration::from_millis(500));
        // Under the 2s default threshold; counter stays at 0.
        assert_eq!(registry.summaries()[0].slow_responses, 0);

        registry.record_response(&peer, Duration::from_millis(2_500));
        registry.record_response(&peer, Duration::from_secs(5));
        assert_eq!(registry.summaries()[0].slow_responses, 2);

        // The peer is still Connected throughout.
        assert!(matches!(
            registry.summaries()[0].state,
            PeerState::Connected { .. }
        ));
    }

    /// A successful reconnect zeroes the slow-response counter,
    /// preventing stale slow counts from carrying across a
    /// reconnect cycle.
    #[test]
    fn reconnect_clears_slow_response_counter() {
        let (mut registry, _clock) = registry_with_fake_clock();
        let peer = node(5);
        registry.mark_connected(peer.clone());
        registry.record_response(&peer, Duration::from_secs(5));
        registry.record_response(&peer, Duration::from_secs(5));
        assert_eq!(registry.summaries()[0].slow_responses, 2);

        registry.mark_disconnected(peer.clone());
        registry.mark_connected(peer.clone());
        assert_eq!(registry.summaries()[0].slow_responses, 0);
    }

    /// `forget` is sticky: a forgotten peer is never returned
    /// from `peers_due_for_reconnect` regardless of clock
    /// advances.
    #[test]
    fn forgotten_peers_never_due() {
        let (mut registry, clock) = registry_with_fake_clock();
        let peer = node(6);
        registry.mark_disconnected(peer.clone());
        registry.forget(peer);

        advance(&clock, Duration::from_secs(60 * 60));
        assert!(registry.peers_due_for_reconnect().is_empty());
        assert_eq!(registry.counts().forgotten, 1);
    }

    /// A custom slow-response threshold is honoured.
    #[test]
    fn slow_response_threshold_is_configurable() {
        let clock = Arc::new(Mutex::new(Instant::now()));
        let clock_clone = Arc::clone(&clock);
        let mut registry = PeerRegistry::with_clock(Box::new(move || *clock_clone.lock().unwrap()))
            .with_slow_response_threshold(Duration::from_millis(500));
        let peer = node(7);
        registry.mark_connected(peer.clone());

        // 600ms exceeds the 500ms override.
        registry.record_response(&peer, Duration::from_millis(600));
        assert_eq!(registry.summaries()[0].slow_responses, 1);
    }

    /// `peers_due_for_reconnect` returns multiple peers when
    /// multiple have elapsed retry deadlines, and skips peers
    /// still in waiting periods.
    #[test]
    fn peers_due_for_reconnect_returns_only_elapsed_peers() {
        let (mut registry, clock) = registry_with_fake_clock();
        let early = node(8);
        let late = node(9);

        registry.mark_disconnected(early.clone());
        // Push `late` further out by walking it through the table.
        for _ in 0..3 {
            registry.mark_disconnected(late.clone());
        }

        advance(&clock, Duration::from_secs(11));
        let due = registry.peers_due_for_reconnect();
        assert_eq!(due, vec![early.clone()]);

        // Eventually `late` (60s after its third disconnect) is
        // also due.
        advance(&clock, Duration::from_secs(60));
        let mut due = registry.peers_due_for_reconnect();
        due.sort_by_key(|n| n.0.clone());
        assert_eq!(due, vec![early, late]);
    }
}
