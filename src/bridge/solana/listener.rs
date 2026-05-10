//! Event listener for Solana deposits
//!
//! Periodically polls the Paraloom Solana program for new deposit
//! transactions, decodes them via [`crate::bridge::solana::decoder`],
//! and feeds the resulting events into the local privacy pool.

use crate::bridge::solana::decoder::{extract_deposit_events, LISTENER_TX_ENCODING};
use crate::bridge::solana::rpc::BridgeRpc;
use crate::bridge::{BridgeConfig, BridgeError, BridgeStats, DepositEvent, Result};
use crate::privacy::{DepositTx, ShieldedAddress, ShieldedPool};
use solana_client::rpc_client::GetConfirmedSignaturesForAddress2Config;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};

/// Maximum number of signatures to request per RPC call. Bounded to
/// keep memory and round-trip latency predictable; if the program
/// volume ever exceeds one batch per poll interval the cursor still
/// converges, just over multiple polls.
const SIGNATURE_BATCH_LIMIT: usize = 1_000;

/// Cap on the in-memory dedup set so a long-running listener cannot
/// grow it without bound. Once the cap is reached the oldest entries
/// are dropped — the cursor is still the primary defense against
/// reprocessing.
const SEEN_SIGNATURE_CAP: usize = 100_000;

/// Event listener for deposit events
pub struct EventListener {
    /// Bridge configuration
    config: BridgeConfig,

    /// RPC client (behind the trait so tests can substitute a mock).
    rpc: Arc<dyn BridgeRpc>,

    /// Privacy pool to process deposits into
    pool: Arc<ShieldedPool>,

    /// Bridge statistics
    stats: Arc<RwLock<BridgeStats>>,

    /// Running flag
    running: Arc<RwLock<bool>>,

    /// Last successfully processed Solana signature. The next poll uses
    /// this as the `until` boundary on `getSignaturesForAddress`, so we
    /// only ever fetch transactions newer than this point.
    last_signature: Arc<RwLock<Option<Signature>>>,

    /// In-memory set of signatures the listener has already emitted
    /// during this run. The cursor (`last_signature`) covers the
    /// across-restart case for everything strictly older than itself;
    /// this set covers the within-poll case where the same signature
    /// appears in two consecutive batches before the cursor advances.
    seen_signatures: Arc<RwLock<HashSet<Signature>>>,

    /// Last slot number observed on a processed deposit. Reported via
    /// [`BridgeStats::last_block`] for operator visibility.
    last_processed_slot: Arc<RwLock<u64>>,
}

/// State shared with the spawned poller task. Grouping it keeps the
/// `tokio::spawn` body from accumulating clones of every field.
struct PollerState {
    rpc: Arc<dyn BridgeRpc>,
    program_id: Pubkey,
    pool: Arc<ShieldedPool>,
    stats: Arc<RwLock<BridgeStats>>,
    last_signature: Arc<RwLock<Option<Signature>>>,
    seen_signatures: Arc<RwLock<HashSet<Signature>>>,
    last_processed_slot: Arc<RwLock<u64>>,
    /// Slot count above which the listener emits a warning each poll —
    /// pulled from [`BridgeConfig::event_lag_warn_threshold_slots`].
    lag_warn_threshold_slots: u64,
}

impl EventListener {
    /// Create a new event listener with the supplied RPC implementation.
    /// `SolanaBridge::new` wires the production `RealBridgeRpc`; tests
    /// substitute a `MockBridgeRpc`.
    pub fn new(
        config: BridgeConfig,
        rpc: Arc<dyn BridgeRpc>,
        pool: Arc<ShieldedPool>,
        stats: Arc<RwLock<BridgeStats>>,
    ) -> Self {
        Self {
            config,
            rpc,
            pool,
            stats,
            running: Arc::new(RwLock::new(false)),
            last_signature: Arc::new(RwLock::new(None)),
            seen_signatures: Arc::new(RwLock::new(HashSet::new())),
            last_processed_slot: Arc::new(RwLock::new(0)),
        }
    }

    /// Start listening for events
    pub async fn start(&mut self) -> Result<()> {
        // Defer program-ID resolution to start time so that
        // construction of the listener cannot fail just because the
        // bridge hasn't been configured yet.
        let program_id = Pubkey::from_str(&self.config.program_id).map_err(|e| {
            BridgeError::ConfigError(format!(
                "invalid bridge program_id '{}': {}",
                self.config.program_id, e
            ))
        })?;

        *self.running.write().await = true;

        let state = PollerState {
            rpc: Arc::clone(&self.rpc),
            program_id,
            pool: Arc::clone(&self.pool),
            stats: Arc::clone(&self.stats),
            last_signature: Arc::clone(&self.last_signature),
            seen_signatures: Arc::clone(&self.seen_signatures),
            last_processed_slot: Arc::clone(&self.last_processed_slot),
            lag_warn_threshold_slots: self.config.event_lag_warn_threshold_slots,
        };
        let running = Arc::clone(&self.running);
        let poll_interval = self.config.poll_interval_secs;

        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(poll_interval));

            while *running.read().await {
                ticker.tick().await;

                match Self::poll_events(&state).await {
                    Ok(count) => {
                        if count > 0 {
                            log::info!(
                                target: "paraloom::bridge::solana",
                                "processed {} deposit event(s)",
                                count
                            );
                        }
                    }
                    Err(e) => {
                        log::error!(
                            target: "paraloom::bridge::solana",
                            "error polling events: {}",
                            e
                        );
                    }
                }
            }
        });

        Ok(())
    }

    /// Stop listening
    pub async fn stop(&mut self) -> Result<()> {
        *self.running.write().await = false;
        Ok(())
    }

    /// Run a single poll cycle: fetch new signatures, decode any deposits,
    /// process them into the pool. Returns the number of events processed.
    async fn poll_events(state: &PollerState) -> Result<usize> {
        let cursor = *state.last_signature.read().await;
        let events = Self::fetch_events(state, cursor).await?;

        let mut processed = 0;
        let mut latest_signature: Option<Signature> = None;
        let mut latest_slot: u64 = 0;

        for event in events {
            let amount = event.amount;
            let slot = event.block;
            let sig_str = event.signature.clone();

            match Self::process_deposit(&state.pool, event).await {
                Ok(_) => {
                    processed += 1;
                    let mut stats_guard = state.stats.write().await;
                    stats_guard.total_deposits += 1;
                    stats_guard.volume_deposited += amount;

                    // Track the cursor (signatures are processed in
                    // ascending slot order — see fetch_events).
                    if let Ok(parsed) = sig_str.parse::<Signature>() {
                        latest_signature = Some(parsed);
                    }
                    if slot > latest_slot {
                        latest_slot = slot;
                    }
                }
                Err(e) => {
                    log::error!(
                        target: "paraloom::bridge::solana",
                        "failed to process deposit {}: {}",
                        sig_str,
                        e
                    );
                }
            }
        }

        if let Some(sig) = latest_signature {
            *state.last_signature.write().await = Some(sig);
        }
        if latest_slot > 0 {
            *state.last_processed_slot.write().await = latest_slot;
            let mut stats_guard = state.stats.write().await;
            stats_guard.last_block = latest_slot;
        }

        Self::update_lag_metric(state).await;

        Ok(processed)
    }

    /// Pull the current Solana slot, compute the listener's lag against
    /// the most recently processed slot, persist the lag in
    /// [`BridgeStats::event_lag_slots`], and warn loudly if the lag
    /// exceeds the configured threshold.
    ///
    /// During the cold-start phase (`last_processed_slot == 0`) the
    /// warning is suppressed: the listener has not seen any events yet
    /// and would otherwise report a "lag" equal to the chain's full
    /// recorded history.
    async fn update_lag_metric(state: &PollerState) {
        let current_slot = match state.rpc.get_slot().await {
            Ok(slot) => slot,
            Err(e) => {
                log::warn!(
                    target: "paraloom::bridge::solana",
                    "skipping lag metric — {}",
                    e
                );
                return;
            }
        };

        let last_processed = *state.last_processed_slot.read().await;
        let lag = current_slot.saturating_sub(last_processed);

        state.stats.write().await.event_lag_slots = lag;

        if last_processed > 0 && lag > state.lag_warn_threshold_slots {
            log::warn!(
                target: "paraloom::bridge::solana",
                "deposit listener is {} slots behind chain tip (current={}, last_processed={}, threshold={})",
                lag,
                current_slot,
                last_processed,
                state.lag_warn_threshold_slots
            );
        }
    }

    /// Fetch deposit events newer than `cursor` from the Solana RPC.
    ///
    /// Uses `getSignaturesForAddress` to walk the recent transaction
    /// history of the bridge program, pulls each transaction in full,
    /// and lets [`extract_deposit_events`] turn them into typed events.
    /// Signatures already seen during this listener's lifetime are
    /// filtered out before the RPC fetch to avoid redundant
    /// `getTransaction` calls.
    async fn fetch_events(
        state: &PollerState,
        cursor: Option<Signature>,
    ) -> Result<Vec<DepositEvent>> {
        // RPC calls go through the BridgeRpc trait — RealBridgeRpc
        // handles the spawn_blocking + ClientError mapping, mocks
        // return canned data directly.
        let signatures = state
            .rpc
            .get_signatures_for_address_with_config(
                &state.program_id,
                GetConfirmedSignaturesForAddress2Config {
                    before: None,
                    until: cursor,
                    limit: Some(SIGNATURE_BATCH_LIMIT),
                    commitment: Some(solana_sdk::commitment_config::CommitmentConfig::confirmed()),
                },
            )
            .await?;

        if signatures.is_empty() {
            return Ok(Vec::new());
        }

        // The RPC returns newest-first; we want to process in the order
        // the chain produced them so the cursor advances monotonically.
        let mut to_fetch = Vec::with_capacity(signatures.len());
        {
            let seen = state.seen_signatures.read().await;
            for s in signatures.into_iter().rev() {
                let sig = match s.signature.parse::<Signature>() {
                    Ok(sig) => sig,
                    Err(e) => {
                        log::warn!(
                            target: "paraloom::bridge::solana",
                            "skipping unparsable signature '{}': {}",
                            s.signature,
                            e
                        );
                        continue;
                    }
                };
                if s.err.is_some() {
                    continue;
                }
                if seen.contains(&sig) {
                    continue;
                }
                to_fetch.push(sig);
            }
        }

        let mut events = Vec::new();
        for sig in to_fetch {
            let confirmed = match state.rpc.get_transaction(&sig, LISTENER_TX_ENCODING).await {
                Ok(tx) => tx,
                Err(e) => {
                    log::warn!(
                        target: "paraloom::bridge::solana",
                        "failed to fetch tx {}: {}",
                        sig,
                        e
                    );
                    continue;
                }
            };

            let sig_str = sig.to_string();
            let mut decoded = extract_deposit_events(&sig_str, &confirmed, &state.program_id);
            events.append(&mut decoded);

            let mut seen = state.seen_signatures.write().await;
            if seen.len() >= SEEN_SIGNATURE_CAP {
                seen.clear();
            }
            seen.insert(sig);
        }

        Ok(events)
    }

    /// Process a single deposit event
    async fn process_deposit(pool: &Arc<ShieldedPool>, event: DepositEvent) -> Result<()> {
        log::info!(
            target: "paraloom::bridge::solana",
            "processing deposit: {} lamports from {:?}",
            event.amount,
            &event.from[..8]
        );

        // Create shielded address from recipient
        let recipient = ShieldedAddress(event.recipient);

        // Create deposit transaction
        let deposit_tx = DepositTx::new(
            event.from.to_vec(),
            event.amount,
            recipient,
            event.randomness,
            event.fee,
        );

        // Verify deposit transaction
        if !deposit_tx.verify() {
            return Err(BridgeError::InvalidTransaction(
                "Deposit verification failed".to_string(),
            ));
        }

        // Process deposit into pool
        let net_amount = event.amount.saturating_sub(event.fee);
        pool.deposit(deposit_tx.output_note, net_amount)
            .await
            .map_err(|e| BridgeError::DepositFailed(e.to_string()))?;

        log::info!(target: "paraloom::bridge::solana", "deposit processed successfully");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::pedersen;

    #[test]
    fn test_listener_creation() {
        use crate::bridge::solana::rpc::RealBridgeRpc;
        use solana_client::rpc_client::RpcClient;
        let config = BridgeConfig::default();
        let pool = Arc::new(ShieldedPool::new());
        let stats = Arc::new(RwLock::new(BridgeStats::default()));
        let rpc = Arc::new(RealBridgeRpc::new(Arc::new(RpcClient::new(
            config.solana_rpc_url.clone(),
        ))));

        let listener = EventListener::new(config, rpc, pool, stats);
        assert!(listener.last_signature.blocking_read().is_none());
        assert_eq!(*listener.last_processed_slot.blocking_read(), 0);
    }

    fn make_state(rpc: Arc<dyn BridgeRpc>) -> PollerState {
        PollerState {
            rpc,
            program_id: Pubkey::new_unique(),
            pool: Arc::new(ShieldedPool::new()),
            stats: Arc::new(RwLock::new(BridgeStats::default())),
            last_signature: Arc::new(RwLock::new(None)),
            seen_signatures: Arc::new(RwLock::new(HashSet::new())),
            last_processed_slot: Arc::new(RwLock::new(0)),
            lag_warn_threshold_slots: 100,
        }
    }

    /// Drives `fetch_events` through `MockBridgeRpc` — the mock
    /// returns an empty signature list, so `get_transaction` is never
    /// called and the function reports no events. Validates the
    /// trait+mock plumbing on the listener side end to end.
    #[tokio::test]
    async fn fetch_events_with_no_signatures_returns_empty() {
        use crate::bridge::solana::test_support::MockBridgeRpc;
        let mock = Arc::new(MockBridgeRpc::new());
        *mock.next_get_signatures.lock().unwrap() = Some(Ok(vec![]));
        let events = EventListener::fetch_events(&make_state(mock), None)
            .await
            .unwrap();
        assert!(events.is_empty());
    }

    /// `update_lag_metric` writes `current_slot - last_processed_slot`
    /// to `stats.event_lag_slots`. The metric powers the operator-
    /// visible "deposit listener is N slots behind chain tip" line;
    /// a regression that wrote zero would silently mask a stalled
    /// listener.
    #[tokio::test]
    async fn update_lag_metric_writes_slot_delta_to_stats() {
        use crate::bridge::solana::test_support::MockBridgeRpc;
        let mock = Arc::new(MockBridgeRpc::new());
        *mock.next_get_slot.lock().unwrap() = Some(Ok(1_000));
        let state = make_state(mock);
        *state.last_processed_slot.write().await = 100;
        EventListener::update_lag_metric(&state).await;
        assert_eq!(state.stats.read().await.event_lag_slots, 900);
    }

    /// A signature whose `err` field is `Some` (the on-chain
    /// transaction reverted) must be skipped before `get_transaction`
    /// is reached — in this test `get_transaction` is intentionally
    /// not configured, so a regression that lost the filter would
    /// surface as the "mock get_transaction not configured" error,
    /// not as the empty-Vec we assert here.
    #[tokio::test]
    async fn fetch_events_skips_signatures_with_chain_err() {
        use crate::bridge::solana::test_support::MockBridgeRpc;
        use solana_client::rpc_response::RpcConfirmedTransactionStatusWithSignature;
        use solana_sdk::transaction::TransactionError;
        let mock = Arc::new(MockBridgeRpc::new());
        *mock.next_get_signatures.lock().unwrap() =
            Some(Ok(vec![RpcConfirmedTransactionStatusWithSignature {
                signature: Signature::new_unique().to_string(),
                slot: 1,
                err: Some(TransactionError::AlreadyProcessed),
                memo: None,
                block_time: None,
                confirmation_status: None,
            }]));
        let events = EventListener::fetch_events(&make_state(mock), None)
            .await
            .unwrap();
        assert!(events.is_empty());
    }

    #[tokio::test]
    async fn test_process_deposit() {
        let pool = Arc::new(ShieldedPool::new());
        let randomness = pedersen::generate_randomness();

        let event = DepositEvent {
            signature: "test_sig".to_string(),
            from: [1u8; 32],
            amount: 1000,
            recipient: [2u8; 32],
            randomness,
            fee: 10,
            block: 100,
            timestamp: 0,
        };

        let result = EventListener::process_deposit(&pool, event).await;
        assert!(result.is_ok());

        // Verify deposit was added to pool
        assert_eq!(pool.total_supply().await, 990); // 1000 - 10 fee
        assert_eq!(pool.commitment_count().await, 1);
    }
}
