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
use std::path::{Path, PathBuf};
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
    /// Where to persist the scan cursor after each advance. `None` keeps the
    /// cursor in memory only (the default and what tests use).
    cursor_path: Option<PathBuf>,
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

        // Resume from the persisted cursor if one exists, so a restart does not
        // re-scan from the chain tip and lose deposits that landed while the node
        // was down. A missing or unparsable cursor falls back to an in-memory
        // cold start.
        if let Some(path) = &self.config.cursor_path {
            if let Some(sig) = Self::load_cursor(path).await {
                *self.last_signature.write().await = Some(sig);
                log::info!(
                    target: "paraloom::bridge::solana",
                    "resumed deposit listener cursor {} from {}",
                    sig,
                    path.display()
                );
            }
        }

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
            cursor_path: self.config.cursor_path.clone(),
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

    /// True when an RPC error reports the `until`/`before` boundary signature as
    /// unknown (JSON-RPC error -32020). This happens when the persisted cursor
    /// ages out of a provider's signature history: the boundary can never be
    /// satisfied again, so retrying it forever would stall the listener. The
    /// caller drops the cursor and cold-starts instead.
    fn is_stale_until_cursor(e: &BridgeError) -> bool {
        matches!(e, BridgeError::SolanaRpc(msg) if msg.contains("-32020"))
    }

    /// Drop the scan cursor — in memory and on disk — so the next fetch resumes
    /// from the latest signatures (a cold start). Used when the cursor ages out
    /// of the RPC's history and can no longer serve as an `until` boundary.
    async fn clear_cursor(state: &PollerState) {
        *state.last_signature.write().await = None;
        if let Some(path) = &state.cursor_path {
            match tokio::fs::remove_file(path).await {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => log::warn!(
                    target: "paraloom::bridge::solana",
                    "failed to remove stale deposit cursor at {}: {}",
                    path.display(),
                    e
                ),
            }
        }
    }

    /// Read the persisted scan cursor. A missing file (first run) or an
    /// unparsable one yields `None` so the listener cold-starts rather than
    /// failing — a corrupt cursor is recoverable, a refusal to start is not.
    async fn load_cursor(path: &Path) -> Option<Signature> {
        let raw = tokio::fs::read_to_string(path).await.ok()?;
        match raw.trim().parse::<Signature>() {
            Ok(sig) => Some(sig),
            Err(e) => {
                log::warn!(
                    target: "paraloom::bridge::solana",
                    "ignoring unparsable persisted cursor at {}: {}",
                    path.display(),
                    e
                );
                None
            }
        }
    }

    /// Persist the scan cursor durably. Writes to a sibling temp file and
    /// renames it over the target so a crash mid-write cannot leave a truncated
    /// cursor (the rename is atomic on a single filesystem).
    async fn persist_cursor(path: &Path, sig: &Signature) {
        let tmp = path.with_extension("tmp");
        if let Err(e) = tokio::fs::write(&tmp, sig.to_string()).await {
            log::warn!(
                target: "paraloom::bridge::solana",
                "failed to write deposit cursor to {}: {}",
                tmp.display(),
                e
            );
            return;
        }
        if let Err(e) = tokio::fs::rename(&tmp, path).await {
            log::warn!(
                target: "paraloom::bridge::solana",
                "failed to commit deposit cursor to {}: {}",
                path.display(),
                e
            );
        }
    }

    /// Decide how far the scan cursor may advance, given each processed
    /// deposit's `(signature, succeeded)` in the ascending order they were
    /// handled. The cursor may move up only through the unbroken run of
    /// successes from the old cursor: the moment one fails it must stop before
    /// that signature, or the next poll's `until` boundary would skip the failed
    /// deposit forever (a later success would otherwise carry the cursor past an
    /// earlier failure). Returns the new cursor (the last contiguous success, if
    /// any) and every failed signature, which the caller un-sees so the next
    /// poll re-fetches and retries them.
    fn contiguous_cursor(outcomes: &[(Signature, bool)]) -> (Option<Signature>, Vec<Signature>) {
        let mut cursor = None;
        let mut frozen = false;
        let mut failed = Vec::new();
        for (sig, ok) in outcomes {
            if *ok {
                if !frozen {
                    cursor = Some(*sig);
                }
            } else {
                frozen = true;
                failed.push(*sig);
            }
        }
        (cursor, failed)
    }

    /// Run a single poll cycle: fetch new signatures, decode any deposits,
    /// process them into the pool. Returns the number of events processed.
    async fn poll_events(state: &PollerState) -> Result<usize> {
        let cursor = *state.last_signature.read().await;
        let events = Self::fetch_events(state, cursor).await?;

        let mut processed = 0;
        let mut latest_slot: u64 = 0;
        // Per-signature outcome, in the ascending order deposits are processed,
        // so the cursor can advance only through the unbroken run of successes.
        let mut outcomes: Vec<(Signature, bool)> = Vec::new();

        for event in events {
            let amount = event.amount;
            let slot = event.block;
            let sig_str = event.signature.clone();
            let parsed = sig_str.parse::<Signature>().ok();

            match Self::process_deposit(&state.pool, event).await {
                Ok(_) => {
                    processed += 1;
                    let mut stats_guard = state.stats.write().await;
                    stats_guard.total_deposits += 1;
                    stats_guard.volume_deposited += amount;
                    drop(stats_guard);

                    if slot > latest_slot {
                        latest_slot = slot;
                    }
                    if let Some(sig) = parsed {
                        outcomes.push((sig, true));
                    }
                }
                Err(e) => {
                    log::error!(
                        target: "paraloom::bridge::solana",
                        "failed to process deposit {}: {}",
                        sig_str,
                        e
                    );
                    if let Some(sig) = parsed {
                        outcomes.push((sig, false));
                    }
                }
            }
        }

        let (cursor_advance, failed) = Self::contiguous_cursor(&outcomes);

        // Un-see the failed signatures so the next poll re-fetches and retries
        // them. The cursor stays below the first failure, so the re-fetch's
        // `until` boundary actually returns them; re-processing is idempotent at
        // the pool, so the successes after a failure are no-ops on retry.
        if !failed.is_empty() {
            let mut seen = state.seen_signatures.write().await;
            for sig in &failed {
                seen.remove(sig);
            }
        }

        if let Some(sig) = cursor_advance {
            *state.last_signature.write().await = Some(sig);
            // Persist the advanced cursor so a restart resumes here. Best-effort:
            // a write failure is logged but does not fail the poll — the
            // in-memory cursor still drives this run.
            if let Some(path) = &state.cursor_path {
                Self::persist_cursor(path, &sig).await;
            }
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
        // The cursor is the `until` boundary. If it ages out of the RPC's
        // queryable history (some providers retain devnet signatures only
        // briefly), the RPC rejects it as a boundary with a "Transaction not
        // found" (-32020) error, and every poll fails forever — the listener
        // stalls and stops indexing deposits. Detect that, drop the stale
        // cursor, and resume from the latest page (a cold start) so the listener
        // self-heals. `effective_cursor` may be reset to `None` mid-loop.
        let mut effective_cursor = cursor;
        loop {
            let batch = match state
                .rpc
                .get_signatures_for_address_with_config(
                    &state.program_id,
                    GetConfirmedSignaturesForAddress2Config {
                        before,
                        until: effective_cursor,
                        limit: Some(state.batch_limit),
                        // Enumerate (and therefore credit) deposits only once
                        // finalized. A `confirmed` slot is not rooted: a deposit
                        // credited at confirmed, then orphaned by a fork-choice
                        // switch, would leave the shielded pool believing more
                        // value exists than the vault custodies. Finality costs a
                        // few seconds of deposit latency for reorg safety.
                        commitment: Some(
                            solana_sdk::commitment_config::CommitmentConfig::finalized(),
                        ),
                    },
                )
                .await
            {
                Ok(batch) => batch,
                Err(e) if effective_cursor.is_some() && Self::is_stale_until_cursor(&e) => {
                    log::warn!(
                        target: "paraloom::bridge::solana",
                        "deposit listener cursor {} is no longer resolvable by the RPC ({}); resetting it and resuming from the latest signatures",
                        effective_cursor.expect("guarded by effective_cursor.is_some()"),
                        e
                    );
                    Self::clear_cursor(state).await;
                    effective_cursor = None;
                    before = None;
                    pages = 0;
                    signatures.clear();
                    continue;
                }
                Err(e) => return Err(e),
            };
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
            if effective_cursor.is_none() {
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
        let mut newly_seen = Vec::with_capacity(to_fetch.len());
        for sig in to_fetch {
            let confirmed = match state.rpc.get_transaction(&sig, LISTENER_TX_ENCODING).await {
                Ok(tx) => tx,
                Err(e) => {
                    // Do NOT skip. A `getTransaction` failure happens before we
                    // can decode whether this finalized program signature was a
                    // deposit, so it produces no outcome — and the
                    // contiguous-cursor barrier only freezes on decoded
                    // outcomes. If we skipped it and a newer deposit in the same
                    // batch succeeded, the cursor would advance past this
                    // un-fetched signature: the next poll's `until` boundary
                    // would exclude it and a restart would resume past it,
                    // durably losing a real deposit (#429). Propagate the error
                    // so the cursor stays put; the next poll re-fetches this
                    // signature (it was never marked seen), and re-processing is
                    // idempotent at the pool.
                    log::warn!(
                        target: "paraloom::bridge::solana",
                        "failed to fetch tx {}: {} — aborting this poll so the cursor cannot advance past it",
                        sig,
                        e
                    );
                    return Err(e);
                }
            };

            let sig_str = sig.to_string();
            let mut decoded = extract_deposit_events(&sig_str, &confirmed, &state.program_id);
            events.append(&mut decoded);
            newly_seen.push(sig);
        }

        // Mark signatures seen only after the WHOLE batch was fetched
        // successfully. Inserting per-signature inside the loop would let a
        // later `getTransaction` failure — which aborts the poll with `Err` and
        // discards `events` — leave an already-fetched-but-discarded signature
        // marked seen; the next poll would then filter it out and advance the
        // cursor past it, durably losing that deposit (#515).
        {
            let mut seen = state.seen_signatures.write().await;
            for sig in newly_seen {
                if seen.len() >= SEEN_SIGNATURE_CAP {
                    seen.clear();
                }
                seen.insert(sig);
            }
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
        pool.deposit_asset(deposit_tx.output_note, net_amount, event.asset_id)
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
            cursor_path: None,
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

    /// When the persisted cursor ages out of the RPC's history, the boundary
    /// `getSignaturesForAddress(until = cursor)` call fails with -32020
    /// "Transaction not found" *forever* — the listener would stall and stop
    /// indexing deposits. `fetch_events` must detect that, drop the stale cursor,
    /// and cold-start from the latest page so deposits keep flowing. Models the
    /// real Helius-devnet failure that stalled the anchor for ~3 days.
    #[tokio::test]
    async fn fetch_events_self_heals_when_cursor_ages_out() {
        use crate::bridge::solana::test_support::{synth_deposit_tx, MockBridgeRpc};
        use solana_client::rpc_response::RpcConfirmedTransactionStatusWithSignature;

        let stale = Signature::new_unique();
        let fresh = Signature::new_unique();
        let program_id = Pubkey::new_unique();
        let depositor = Pubkey::new_unique();
        let mock = Arc::new(MockBridgeRpc::new());

        // First page (the `until = stale` boundary call) is rejected: the RPC no
        // longer knows the cursor signature. Second page (the cold-start retry,
        // `until = None`) returns a real deposit.
        {
            let mut pages = mock.get_signatures_pages.lock().unwrap();
            pages.push_back(Err(BridgeError::SolanaRpc(format!(
                "getSignaturesForAddress: RPC response error -32020: Transaction {stale} not found"
            ))));
            pages.push_back(Ok(vec![RpcConfirmedTransactionStatusWithSignature {
                signature: fresh.to_string(),
                slot: 9,
                err: None,
                memo: None,
                block_time: None,
                confirmation_status: None,
            }]));
        }
        *mock.next_get_transaction.lock().unwrap() = Some(Ok(synth_deposit_tx(
            fresh,
            9,
            &program_id,
            &depositor,
            2_000,
            [7u8; 32],
            [13u8; 32],
        )));

        let mut state = make_state(mock);
        state.program_id = program_id;
        *state.last_signature.write().await = Some(stale);

        let events = EventListener::fetch_events(&state, Some(stale))
            .await
            .expect("a stale cursor must self-heal, not propagate the error");

        assert_eq!(
            events.len(),
            1,
            "the cold-start retry must recover the deposit"
        );
        assert_eq!(
            *state.last_signature.read().await,
            None,
            "the stale cursor must be cleared so a restart does not reload it"
        );
    }

    /// A non-cursor RPC failure (one that is not the -32020 stale-boundary case)
    /// must still propagate: self-healing is scoped to the aged-out cursor, not a
    /// blanket "swallow every RPC error".
    #[tokio::test]
    async fn fetch_events_propagates_non_cursor_rpc_errors() {
        use crate::bridge::solana::test_support::MockBridgeRpc;
        let mock = Arc::new(MockBridgeRpc::new());
        *mock.next_get_signatures.lock().unwrap() = Some(Err(BridgeError::SolanaRpc(
            "getSignaturesForAddress: connection reset".to_string(),
        )));
        let state = make_state(mock);
        let result = EventListener::fetch_events(&state, Some(Signature::new_unique())).await;
        assert!(
            result.is_err(),
            "a non-cursor RPC error must not be swallowed"
        );
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

    /// #429 regression: a `getTransaction` failure on one signature must not let
    /// the cursor advance past it when a newer deposit in the same batch
    /// succeeds. Before the fix, `fetch_events` logged and continued on the
    /// failed fetch, so the un-fetched signature produced no outcome and the
    /// contiguous cursor advanced to the newer deposit — durably skipping the
    /// older finalized deposit (the next poll's `until` boundary and the
    /// persisted cursor both excluded it forever). The fix propagates the fetch
    /// error so the cursor stays put and the next poll re-fetches and indexes
    /// the older deposit.
    #[tokio::test]
    async fn poll_does_not_skip_a_deposit_whose_body_failed_to_fetch() {
        use crate::bridge::solana::test_support::{synth_deposit_tx, MockBridgeRpc};
        use solana_client::rpc_response::RpcConfirmedTransactionStatusWithSignature;

        let program_id = Pubkey::new_unique();
        let depositor = Pubkey::new_unique();
        let older = Signature::new_unique();
        let newer = Signature::new_unique();
        let status = |sig: &Signature, slot: u64| RpcConfirmedTransactionStatusWithSignature {
            signature: sig.to_string(),
            slot,
            err: None,
            memo: None,
            block_time: None,
            confirmation_status: None,
        };

        let mock = Arc::new(MockBridgeRpc::new());
        let mut state = make_state(mock.clone());
        state.program_id = program_id;

        // Poll 1: the RPC lists [newer, older] (newest-first). The listener
        // fetches in chain order (older first); `getTransaction(older)` fails.
        // `newer`'s body is available but is never reached — the poll aborts.
        *mock.next_get_signatures.lock().unwrap() =
            Some(Ok(vec![status(&newer, 8), status(&older, 7)]));
        *mock.next_get_transaction.lock().unwrap() = Some(Err(BridgeError::SolanaRpc(
            "transient getTransaction failure".to_string(),
        )));
        mock.get_transactions.lock().unwrap().insert(
            newer,
            synth_deposit_tx(
                newer,
                8,
                &program_id,
                &depositor,
                2_000,
                [9u8; 32],
                [11u8; 32],
            ),
        );

        let poll1 = EventListener::poll_events(&state).await;
        assert!(
            poll1.is_err(),
            "a getTransaction failure must abort the poll, not skip the signature"
        );
        assert_eq!(
            *state.last_signature.read().await,
            None,
            "cursor must not advance past the un-fetched signature"
        );
        assert_eq!(state.pool.commitment_count().await, 0);

        // Poll 2: the older body is now available and the cursor never advanced,
        // so the same batch is re-fetched and BOTH deposits are indexed.
        mock.get_transactions.lock().unwrap().insert(
            older,
            synth_deposit_tx(
                older,
                7,
                &program_id,
                &depositor,
                1_000,
                [7u8; 32],
                [13u8; 32],
            ),
        );
        *mock.next_get_signatures.lock().unwrap() =
            Some(Ok(vec![status(&newer, 8), status(&older, 7)]));

        let processed = EventListener::poll_events(&state).await.unwrap();
        assert_eq!(
            processed, 2,
            "both deposits index once the older body is available"
        );
        assert_eq!(state.pool.commitment_count().await, 2);
        assert_eq!(*state.last_signature.read().await, Some(newer));
    }

    /// #515 — the inverse ordering of the test above: an EARLIER signature in
    /// the batch is fetched successfully, then a LATER one fails. The successful
    /// fetch must NOT be marked seen until the whole batch succeeds, otherwise
    /// the aborted poll discards its event while leaving it in the seen set, and
    /// the retry filters it out — durably losing the older deposit.
    #[tokio::test]
    async fn poll_does_not_strand_an_earlier_deposit_when_a_later_sig_fails() {
        use crate::bridge::solana::test_support::{synth_deposit_tx, MockBridgeRpc};
        use solana_client::rpc_response::RpcConfirmedTransactionStatusWithSignature;

        let program_id = Pubkey::new_unique();
        let depositor = Pubkey::new_unique();
        let older = Signature::new_unique();
        let newer = Signature::new_unique();
        let status = |sig: &Signature, slot: u64| RpcConfirmedTransactionStatusWithSignature {
            signature: sig.to_string(),
            slot,
            err: None,
            memo: None,
            block_time: None,
            confirmation_status: None,
        };

        let mock = Arc::new(MockBridgeRpc::new());
        let mut state = make_state(mock.clone());
        state.program_id = program_id;

        // Poll 1: RPC lists [newer, older]; fetched oldest-first. `older`
        // succeeds (present in the map); `newer` then falls to the error, so the
        // poll aborts. `older` must NOT be left marked seen.
        *mock.next_get_signatures.lock().unwrap() =
            Some(Ok(vec![status(&newer, 8), status(&older, 7)]));
        *mock.next_get_transaction.lock().unwrap() = Some(Err(BridgeError::SolanaRpc(
            "transient getTransaction failure".to_string(),
        )));
        mock.get_transactions.lock().unwrap().insert(
            older,
            synth_deposit_tx(
                older,
                7,
                &program_id,
                &depositor,
                1_000,
                [7u8; 32],
                [13u8; 32],
            ),
        );

        let poll1 = EventListener::poll_events(&state).await;
        assert!(
            poll1.is_err(),
            "a later getTransaction failure must abort the poll"
        );
        assert_eq!(
            *state.last_signature.read().await,
            None,
            "cursor must not advance"
        );
        assert_eq!(state.pool.commitment_count().await, 0);
        assert!(
            !state.seen_signatures.read().await.contains(&older),
            "an earlier fetched-then-discarded signature must not be marked seen"
        );

        // Poll 2: newer's body is now available; because `older` was never
        // stranded in the seen set, BOTH deposits are re-fetched and indexed.
        mock.get_transactions.lock().unwrap().insert(
            newer,
            synth_deposit_tx(
                newer,
                8,
                &program_id,
                &depositor,
                2_000,
                [9u8; 32],
                [11u8; 32],
            ),
        );
        *mock.next_get_signatures.lock().unwrap() =
            Some(Ok(vec![status(&newer, 8), status(&older, 7)]));

        let processed = EventListener::poll_events(&state).await.unwrap();
        assert_eq!(processed, 2, "the earlier deposit is not lost");
        assert_eq!(state.pool.commitment_count().await, 2);
        assert_eq!(*state.last_signature.read().await, Some(newer));
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

    #[tokio::test]
    async fn cursor_persists_and_reloads_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bridge_cursor");
        let sig = Signature::new_unique();
        EventListener::persist_cursor(&path, &sig).await;
        // A fresh listener (the restart) reads the same signature back.
        assert_eq!(EventListener::load_cursor(&path).await, Some(sig));
    }

    #[tokio::test]
    async fn load_cursor_cold_starts_on_a_missing_or_corrupt_file() {
        let dir = tempfile::tempdir().unwrap();
        // Missing file (first run) → cold start, not an error.
        let missing = dir.path().join("absent");
        assert_eq!(EventListener::load_cursor(&missing).await, None);
        // Corrupt contents → cold start rather than a refusal to start.
        let corrupt = dir.path().join("corrupt");
        tokio::fs::write(&corrupt, "not-a-signature").await.unwrap();
        assert_eq!(EventListener::load_cursor(&corrupt).await, None);
    }

    #[tokio::test]
    async fn poll_persists_the_advanced_cursor_to_disk() {
        use crate::bridge::solana::test_support::{synth_deposit_tx, MockBridgeRpc};
        use solana_client::rpc_response::RpcConfirmedTransactionStatusWithSignature;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bridge_cursor");
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
        *mock.next_get_slot.lock().unwrap() = Some(Ok(7));

        let mut state = make_state(mock);
        state.program_id = program_id;
        state.cursor_path = Some(path.clone());

        let processed = EventListener::poll_events(&state).await.unwrap();
        assert_eq!(processed, 1);
        // The cursor advanced and was committed to disk, so a restart resumes here.
        assert_eq!(EventListener::load_cursor(&path).await, Some(sig));
    }

    #[test]
    fn contiguous_cursor_stops_before_the_first_failure() {
        let a = Signature::new_unique();
        let b = Signature::new_unique();
        let c = Signature::new_unique();

        // All succeed → the cursor advances to the last, nothing to retry.
        let (cursor, failed) = EventListener::contiguous_cursor(&[(a, true), (b, true), (c, true)]);
        assert_eq!(cursor, Some(c));
        assert!(failed.is_empty());

        // A failure in the middle freezes the cursor at the last success before
        // it; the later success must NOT carry the cursor past the failure, and
        // the failure is reported for retry.
        let (cursor, failed) =
            EventListener::contiguous_cursor(&[(a, true), (b, false), (c, true)]);
        assert_eq!(cursor, Some(a));
        assert_eq!(failed, vec![b]);

        // A failure first leaves the cursor unmoved.
        let (cursor, failed) = EventListener::contiguous_cursor(&[(a, false), (b, true)]);
        assert_eq!(cursor, None);
        assert_eq!(failed, vec![a]);

        // Nothing processed → no movement.
        let (cursor, failed) = EventListener::contiguous_cursor(&[]);
        assert_eq!(cursor, None);
        assert!(failed.is_empty());
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

    #[tokio::test]
    async fn test_process_deposit_credits_the_deposits_own_asset() {
        // An SPL deposit must credit its mint's supply, not native SOL's. The
        // note is built asset-aware (`new_asset`), so the supply ledger has to
        // be keyed by the same asset or `supply_of` / the gossiped total drift.
        let pool = Arc::new(ShieldedPool::new());
        let randomness = pedersen::generate_randomness();
        let mint: crate::privacy::types::AssetId = [7u8; 32];

        let event = DepositEvent {
            signature: "spl_sig".to_string(),
            from: [1u8; 32],
            amount: 1000,
            recipient: [2u8; 32],
            randomness,
            asset_id: mint,
            fee: 10,
            block: 100,
            timestamp: 0,
        };

        EventListener::process_deposit(&pool, event).await.unwrap();

        // Credited to the mint, not to native SOL.
        assert_eq!(pool.supply_of(mint).await, 990);
        assert_eq!(
            pool.supply_of(crate::privacy::types::NATIVE_SOL_ASSET)
                .await,
            0
        );
        assert_eq!(pool.commitment_count().await, 1);
    }
}
