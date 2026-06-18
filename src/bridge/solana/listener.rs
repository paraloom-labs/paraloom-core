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
/// keep memory and round-trip latency predictable; when the program
/// volume between two polls exceeds one batch, `fetch_events` paginates
/// (walking older pages with `before`) so no deposit in the gap is lost.
const SIGNATURE_BATCH_LIMIT: usize = 1_000;

/// Safety cap on how many `SIGNATURE_BATCH_LIMIT` pages a single poll walks
/// back toward the cursor. At 50 pages that is 50k program transactions in one
/// poll interval — far beyond any real load — so it never fires in practice; it
/// exists only to bound a pathological backlog or a misbehaving RPC. If it ever
/// fires the listener logs it loudly rather than silently dropping the tail.
const MAX_SIGNATURE_PAGES: usize = 50;

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
    /// Signatures requested per `getSignaturesForAddress` page. Production uses
    /// [`SIGNATURE_BATCH_LIMIT`]; tests set it small to exercise pagination
    /// without synthesising a thousand transactions.
    batch_limit: usize,
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
            batch_limit: SIGNATURE_BATCH_LIMIT,
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
            // `last_block` tracks the most recent DEPOSIT slot for stats; the
            // scan frontier (`last_processed_slot`) is advanced by
            // `update_lag_metric` to the chain tip, not to the deposit slot.
            state.stats.write().await.last_block = latest_slot;
        }

        Self::update_lag_metric(state).await;

        Ok(processed)
    }

    /// Record the listener's lag and advance the scan frontier.
    ///
    /// `last_processed_slot` is the chain tip as of the last SUCCESSFUL poll —
    /// the frontier the listener has scanned through. This runs only after a
    /// successful fetch (a failed fetch returns early from `poll_events` and the
    /// caller logs it), so the reported lag is the slots elapsed since the
    /// previous successful poll (≈ the poll interval, normally tiny), NOT the
    /// time since the last deposit. We then advance the frontier to the tip.
    ///
    /// This is what keeps a merely quiet chain (no deposits for hours) from
    /// tripping the warning, while a genuine fetch outage — which freezes the
    /// frontier because this is not called — surfaces as a large lag (and a
    /// warning) on the first poll after recovery, plus the caller's per-tick
    /// "error polling events" logs during the outage.
    ///
    /// During cold start (`last_processed_slot == 0`) the warning is
    /// suppressed but the metric is still written.
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

        // Advance the frontier to the tip: this poll confirmed the chain is
        // scanned through `current_slot`, so the next poll measures lag from
        // here, not from the last deposit.
        *state.last_processed_slot.write().await = current_slot;
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
        //
        // `getSignaturesForAddress` returns newest-first, capped at
        // `SIGNATURE_BATCH_LIMIT`. When more than one batch of program
        // transactions accumulated since `cursor` (a burst, or a resume after
        // downtime), a single call would return only the newest batch and drop
        // every deposit older than it. Walk older pages with `before` until a
        // short page reaches `cursor` (or history runs out), so the gap is never
        // dropped. On a cold start (`cursor == None`) there is no resume point,
        // so take only the newest page and begin scanning from now rather than
        // replaying the program's entire history.
        let mut signatures = Vec::new();
        let mut before: Option<Signature> = None;
        let mut pages = 0usize;
        loop {
            let batch = state
                .rpc
                .get_signatures_for_address_with_config(
                    &state.program_id,
                    GetConfirmedSignaturesForAddress2Config {
                        before,
                        until: cursor,
                        limit: Some(state.batch_limit),
                        commitment: Some(
                            solana_sdk::commitment_config::CommitmentConfig::confirmed(),
                        ),
                    },
                )
                .await?;
            let batch_len = batch.len();
            if batch_len == 0 {
                break;
            }
            // The batch is newest-first, so its last entry is the oldest — the
            // boundary for the next, older page.
            let oldest = batch
                .last()
                .and_then(|s| s.signature.parse::<Signature>().ok());
            signatures.extend(batch);
            pages += 1;

            // A short page means this batch reached `cursor` (or the end of
            // history): there is nothing older left to walk.
            if batch_len < state.batch_limit {
                break;
            }
            // Cold start: take only the newest page, do not walk all history.
            if cursor.is_none() {
                break;
            }
            if pages >= MAX_SIGNATURE_PAGES {
                log::warn!(
                    target: "paraloom::bridge::solana",
                    "deposit listener hit the {}-page scan cap (~{} transactions) before reaching the cursor; deposits older than this window are skipped this poll",
                    MAX_SIGNATURE_PAGES,
                    MAX_SIGNATURE_PAGES * state.batch_limit
                );
                break;
            }
            match oldest {
                Some(sig) => before = Some(sig),
                None => break,
            }
        }

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

        // Create deposit transaction, indexed under the deposit's asset (#237):
        // an SPL deposit carries its mint, a native deposit NATIVE_SOL.
        let deposit_tx = DepositTx::new_asset(
            event.from.to_vec(),
            event.amount,
            recipient,
            event.randomness,
            event.fee,
            event.asset_id,
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
            batch_limit: SIGNATURE_BATCH_LIMIT,
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

    /// During cold start (`last_processed_slot == 0`) the lag is
    /// still written to stats — the warn-on-threshold path is what
    /// suppresses the noisy "we are 200_000 slots behind" message,
    /// not the metric itself. Operators who scrape the metric should
    /// see a real value from boot, even if it temporarily looks like
    /// the listener has the entire chain to catch up on.
    #[tokio::test]
    async fn update_lag_metric_writes_lag_during_cold_start() {
        use crate::bridge::solana::test_support::MockBridgeRpc;
        let mock = Arc::new(MockBridgeRpc::new());
        *mock.next_get_slot.lock().unwrap() = Some(Ok(1_000));
        let state = make_state(mock);
        // last_processed_slot defaults to 0 — cold start.
        EventListener::update_lag_metric(&state).await;
        assert_eq!(state.stats.read().await.event_lag_slots, 1_000);
    }

    /// When `get_slot` errors out the listener must skip the metric
    /// update entirely — no half-written stats, no panic. Without
    /// that guard a flaky RPC could clobber `event_lag_slots` with
    /// stale or zero values and operators would lose visibility on
    /// the actual lag.
    #[tokio::test]
    async fn update_lag_metric_silent_on_rpc_error() {
        use crate::bridge::solana::test_support::MockBridgeRpc;
        let mock = Arc::new(MockBridgeRpc::new());
        // Leave next_get_slot unconfigured — the mock returns Err.
        let state = make_state(mock);
        *state.last_processed_slot.write().await = 100;
        // Pre-seed a previous lag value to detect any clobber.
        state.stats.write().await.event_lag_slots = 42;
        EventListener::update_lag_metric(&state).await;
        assert_eq!(
            state.stats.read().await.event_lag_slots,
            42,
            "rpc error must not overwrite a previous lag reading"
        );
    }

    /// After recording the lag, `update_lag_metric` advances the scan frontier
    /// to the current tip, so a later poll measures lag from there (≈ the poll
    /// interval) rather than from the last deposit. This is what stops a quiet,
    /// deposit-free chain from accumulating a false "N slots behind chain tip".
    #[tokio::test]
    async fn update_lag_metric_advances_frontier_to_tip() {
        use crate::bridge::solana::test_support::MockBridgeRpc;
        let mock = Arc::new(MockBridgeRpc::new());
        *mock.next_get_slot.lock().unwrap() = Some(Ok(1_000));
        let state = make_state(mock);
        *state.last_processed_slot.write().await = 100;

        EventListener::update_lag_metric(&state).await;

        assert_eq!(state.stats.read().await.event_lag_slots, 900);
        assert_eq!(
            *state.last_processed_slot.read().await,
            1_000,
            "frontier must advance to the tip after a successful poll"
        );
    }

    /// `poll_events` must update `state.last_signature` to the most
    /// recent successfully-processed deposit's signature so the next
    /// poll narrows `getSignaturesForAddress` to "newer than this".
    /// Drives the full path: get_signatures → get_transaction →
    /// extract_deposit_events → process_deposit → cursor update.
    /// The synth_deposit_tx helper builds the in-memory tx the
    /// decoder expects so we never need to boot a validator.
    #[tokio::test]
    async fn poll_events_advances_cursor_after_successful_deposit() {
        use crate::bridge::solana::test_support::{synth_deposit_tx, MockBridgeRpc};
        use solana_client::rpc_response::RpcConfirmedTransactionStatusWithSignature;
        let sig = Signature::new_unique();
        let program_id = Pubkey::new_unique();
        let depositor = Pubkey::new_unique();
        let mock = Arc::new(MockBridgeRpc::new());
        *mock.next_get_signatures.lock().unwrap() =
            Some(Ok(vec![RpcConfirmedTransactionStatusWithSignature {
                signature: sig.to_string(),
                slot: 7,
                err: None,
                memo: None,
                block_time: None,
                confirmation_status: None,
            }]));
        *mock.next_get_transaction.lock().unwrap() = Some(Ok(synth_deposit_tx(
            sig,
            7,
            &program_id,
            &depositor,
            1_000,
            [9u8; 32],
            [11u8; 32],
        )));
        let mut state = make_state(mock);
        state.program_id = program_id;
        let processed = EventListener::poll_events(&state).await.unwrap();
        assert_eq!(processed, 1, "exactly one deposit must process");
        assert_eq!(*state.last_signature.read().await, Some(sig));
        assert_eq!(state.pool.commitment_count().await, 1);
    }

    /// A backlog larger than one signature batch must be walked across pages,
    /// not truncated to the newest batch. With `batch_limit = 2` the first page
    /// returns full (== limit), so the listener must fetch a second page with
    /// `before` to reach the cursor; the deposit on that older page would be
    /// silently dropped without pagination.
    #[tokio::test]
    async fn poll_paginates_a_backlog_larger_than_one_batch() {
        use crate::bridge::solana::test_support::{synth_deposit_tx, MockBridgeRpc};
        use solana_client::rpc_response::RpcConfirmedTransactionStatusWithSignature;

        let program_id = Pubkey::new_unique();
        let depositor = Pubkey::new_unique();
        let mock = Arc::new(MockBridgeRpc::new());

        // Three deposits, newest-first across two pages: page1 = [s0, s1] (full),
        // page2 = [s2] (short, reaches the cursor).
        let sigs: Vec<Signature> = (0..3).map(|_| Signature::new_unique()).collect();
        let status = |sig: &Signature, slot: u64| RpcConfirmedTransactionStatusWithSignature {
            signature: sig.to_string(),
            slot,
            err: None,
            memo: None,
            block_time: None,
            confirmation_status: None,
        };
        mock.get_signatures_pages.lock().unwrap().extend([
            Ok(vec![status(&sigs[0], 30), status(&sigs[1], 20)]),
            Ok(vec![status(&sigs[2], 10)]),
        ]);
        for (i, sig) in sigs.iter().enumerate() {
            // Distinct randomness per deposit so the commitments differ.
            mock.get_transactions.lock().unwrap().insert(
                *sig,
                synth_deposit_tx(
                    *sig,
                    30 - i as u64 * 10,
                    &program_id,
                    &depositor,
                    1_000,
                    [9u8; 32],
                    [11u8 + i as u8; 32],
                ),
            );
        }
        *mock.next_get_slot.lock().unwrap() = Some(Ok(30));

        let mut state = make_state(mock);
        state.program_id = program_id;
        state.batch_limit = 2;
        // A resume cursor (not a cold start) so pagination engages.
        *state.last_signature.write().await = Some(Signature::new_unique());

        let processed = EventListener::poll_events(&state).await.unwrap();
        assert_eq!(
            processed, 3,
            "every deposit across both pages must process, not just the newest batch"
        );
        assert_eq!(state.pool.commitment_count().await, 3);
        // The cursor advances to the newest processed signature.
        assert_eq!(*state.last_signature.read().await, Some(sigs[0]));
    }

    /// A signature already in `state.seen_signatures` must be filtered
    /// before `get_transaction` is reached. The mock leaves
    /// get_transaction unconfigured for the seen sig — if the dedup
    /// guard regressed, the listener would call `get_transaction` and
    /// pick up the "mock not configured" Err. The empty-Vec assertion
    /// catches that path too.
    #[tokio::test]
    async fn fetch_events_skips_signatures_already_in_seen_set() {
        use crate::bridge::solana::test_support::MockBridgeRpc;
        use solana_client::rpc_response::RpcConfirmedTransactionStatusWithSignature;
        let already_seen = Signature::new_unique();
        let mock = Arc::new(MockBridgeRpc::new());
        *mock.next_get_signatures.lock().unwrap() =
            Some(Ok(vec![RpcConfirmedTransactionStatusWithSignature {
                signature: already_seen.to_string(),
                slot: 1,
                err: None,
                memo: None,
                block_time: None,
                confirmation_status: None,
            }]));
        let state = make_state(mock);
        state.seen_signatures.write().await.insert(already_seen);
        let events = EventListener::fetch_events(&state, None).await.unwrap();
        assert!(events.is_empty());
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
            asset_id: crate::privacy::types::NATIVE_SOL_ASSET,
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
