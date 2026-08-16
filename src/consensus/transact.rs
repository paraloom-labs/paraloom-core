//! Unified-transact verification consensus (#350).
//!
//! Circuit-v3 settlement consensus. A client submits a
//! unified transact (two input nullifiers, two output commitments, the
//! membership root, a signed external flow, and a `TransactCircuitV3` proof);
//! validators verify the proof and vote, and once a BFT quorum of eligible
//! voters agrees the coordinator emits an [`ApprovedTransact`] that a
//! submitter task settles on-chain via the unified `transact` instruction.
//!
//! The vote/quorum machinery is shared with withdrawals through
//! [`VoteTally`]; this module only adds the transact-specific request,
//! approval, and the thin coordinator shell. The reputation/slashing/leader
//! trackers are reused as-is, so a validator's standing is consistent across
//! all verification paths.

use crate::consensus::leader::{LeaderSelector, ValidatorInfo};
use crate::consensus::reputation::ReputationTracker;
use crate::consensus::slashing::SlashingTracker;
use crate::consensus::vote_tally::{VerificationVote, VoteTally};
use crate::types::NodeId;

/// Default minimum registered validators that must approve before a transact
/// settles (7-of-10 BFT). The actual threshold is configurable per
/// coordinator; this is the fallback when no override is supplied. (Relocated
/// here from the retired off-chain-root withdrawal consensus module.)
pub const DEFAULT_MIN_VALIDATORS_FOR_CONSENSUS: usize = 7;

/// Default validator-set size for the 7-of-10 BFT consensus, used as the
/// completion-percentage divisor when no override is supplied.
pub const DEFAULT_TOTAL_VALIDATORS: usize = 10;

/// Default reputation floor for consensus participation. A validator below this
/// may still submit a vote, but the result is computed as if it had not.
pub const DEFAULT_MIN_REPUTATION_FOR_CONSENSUS: u64 = 200;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// A unified-transact verification request broadcast to validators (#350).
///
/// Fixed 2-in/2-out, matching the on-chain `transact` instruction and
/// `TransactCircuitV3`. One request covers both a pure shielded transfer
/// (`ext_amount == 0`) and a withdrawal (`ext_amount < 0`); the signed
/// external flow and the recipient are proof public inputs, so validators
/// verify exactly what settles.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactVerificationRequest {
    /// Unique request ID
    pub request_id: String,

    /// Withdrawal destination (`ext_amount < 0`); all-zero for a pure
    /// shielded transfer (`ext_amount == 0`). For an SPL settlement (`mint`
    /// set) this is the recipient **token account**, not a system address.
    pub recipient: [u8; 32],

    /// The SPL mint being spent (#779), or `None` for a native-SOL settlement.
    /// When set, the settlement takes the `transact_spl` path: the proof's
    /// asset id is `mint_to_asset(mint)` and the payout leaves the mint's asset
    /// vault. Defaulted so older native requests (no field) decode as `None`.
    #[serde(default)]
    pub mint: Option<[u8; 32]>,

    /// Input note nullifiers (one may be a random dummy for a 1-real-input spend)
    pub nullifiers: [[u8; 32]; 2],

    /// New output note commitments
    pub output_commitments: [[u8; 32]; 2],

    /// The on-chain tree root the proof proves membership against; must be
    /// in the program's root history at settlement (`is_known_root`).
    pub root: [u8; 32],

    /// Signed external flow: `< 0` withdraws `|ext_amount|`, `== 0` moves
    /// nothing externally. `> 0` is invalid (deposits go through
    /// `deposit_note`).
    pub ext_amount: i64,

    /// Settlement proof in the L2 wire encoding `suite_tag(1) || body` — see
    /// [`crate::privacy::ProofSuite`]. Today the only tag is
    /// `Groth16Bn254TransactV3`, whose body is an arkworks-compressed Groth16
    /// proof for `TransactCircuitV3`.
    ///
    /// The tag lives inside `proof` rather than in a sibling field so that
    /// [`Self::canonical_id`], which already hashes these bytes, binds the
    /// suite to the request id for free: the same proof body presented under
    /// two suites yields two distinct request ids and can never collide in one
    /// verification round.
    pub proof: Vec<u8>,

    /// Encrypted output notes (#196), one per output commitment, hex-encoded
    /// `EncryptedNote`. Opaque to validators — carried so recipients can scan
    /// and trial-decrypt; never verified or settled on-chain.
    pub ciphertexts: [String; 2],

    /// Timestamp when the request was created
    pub timestamp: u64,
}

impl TransactVerificationRequest {
    /// Canonical, content-bound request id: a domain-separated SHA-256 over the
    /// proof/settlement-defining fields (#383). Keying consensus state by this,
    /// rather than by a caller-chosen string, means a peer cannot pick an id to
    /// overwrite or poison a cache entry; an exact replay is idempotent (same
    /// id); and any mutated field yields a different id — so two distinct
    /// transacts can never collide on one verification round (which previously
    /// let an honest validator's Valid-then-Invalid votes read as equivocation).
    /// Excludes `ciphertexts`, `timestamp`, and `request_id`, which are not
    /// settlement-bound.
    pub fn canonical_id(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"paraloom:transact-request:v1");
        h.update(self.root);
        h.update(self.recipient);
        h.update(self.ext_amount.to_le_bytes());
        h.update(self.nullifiers[0]);
        h.update(self.nullifiers[1]);
        h.update(self.output_commitments[0]);
        h.update(self.output_commitments[1]);
        h.update((self.proof.len() as u64).to_le_bytes());
        h.update(&self.proof);
        // Bind the asset so an SPL settlement can never collide with a native
        // one on the same proof/nullifiers, and the mint is settlement-bound.
        // Only hashed when present, so native request ids are unchanged (#779).
        if let Some(mint) = self.mint {
            h.update(b"spl");
            h.update(mint);
        }
        format!("transact-{}", hex::encode(h.finalize()))
    }
}

/// Verification result from a validator for a transact request.
///
/// Rides inside `Message::TransactVerificationResult`, which is bincode-encoded
/// (positional, NOT self-describing): adding the two trailing fields is a
/// BREAKING wire change for that one variant, so both validators must run the
/// identical binary and be restarted together (a mixed pair drops each other's
/// votes on decode error and cannot settle).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactVerificationResult {
    /// Request ID
    pub request_id: String,

    /// Voter's authenticated libp2p identity. DEMOTED from the counting/
    /// eligibility identity to routing + liveness only: the ingress checks
    /// `validator == source`, the signed preimage binds it (so a relayed copy
    /// cannot re-attribute the vote), and the tally retains it for co-sign
    /// routing. Counting is by `wallet_pubkey`.
    pub validator: NodeId,

    /// Verification vote
    pub vote: VerificationVote,

    /// Timestamp when verified. NOT signed (excluded from the preimage): dedup
    /// is wallet-keyed in the tally, so the timestamp is advisory only.
    pub timestamp: u64,

    /// The voter's on-chain co-sign wallet (base58) — the counting/attribution
    /// identity and the ed25519 verifying key for `signature`.
    pub wallet_pubkey: String,

    /// ed25519 signature by the co-sign key over
    /// [`transact_vote_signing_bytes`]. A vote with an empty or invalid
    /// signature is dropped at ingress (structural backstop in `submit_result`).
    pub signature: Vec<u8>,
}

/// Build the exact canonical preimage a transact vote signature covers. PURE and
/// crypto-agnostic (no solana dependency) so this module still compiles under
/// `--no-default-features`; the node layer signs/verifies these bytes with the
/// co-sign ed25519 key.
///
/// Every variable-length field is u64-little-endian length-prefixed so no field
/// boundary can be slid. The layout binds, in order:
/// domain tag, program id, cluster tag, request id (== canonical settlement id),
/// the VOTER NodeId (defeats relay/rewrap re-attribution), a single validity
/// bit (matches the equivocation model; `Invalid.reason` free text stays
/// unsigned), and the wallet pubkey (defeats ed25519 key-substitution).
pub fn transact_vote_signing_bytes(
    program_id: &str,
    cluster_tag: &str,
    request_id: &str,
    validator: &NodeId,
    vote: &VerificationVote,
    wallet_pubkey: &str,
) -> Vec<u8> {
    // 25-byte fixed domain tag, disjoint from the settlement co-sign input (a
    // raw Solana Message beginning with a small u8), so a vote signature can
    // never double as a settlement signature.
    const DOMAIN: &[u8] = b"paraloom:transact-vote:v1";
    let mut buf = Vec::with_capacity(
        DOMAIN.len()
            + 8 * 4
            + program_id.len()
            + cluster_tag.len()
            + request_id.len()
            + validator.0.len()
            + wallet_pubkey.len()
            + 1,
    );
    buf.extend_from_slice(DOMAIN);
    let put = |bytes: &[u8], buf: &mut Vec<u8>| {
        buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        buf.extend_from_slice(bytes);
    };
    put(program_id.as_bytes(), &mut buf);
    put(cluster_tag.as_bytes(), &mut buf);
    put(request_id.as_bytes(), &mut buf);
    put(&validator.0, &mut buf);
    buf.push(if vote.is_valid() { 1u8 } else { 0u8 });
    put(wallet_pubkey.as_bytes(), &mut buf);
    buf
}

/// A transact the validator quorum has approved (#350). Emitted on the
/// approval channel the moment a `Valid` quorum is first reached, carrying
/// the full request — everything needed to build the on-chain `transact`
/// instruction.
#[derive(Clone, Debug)]
pub struct ApprovedTransact {
    pub request: TransactVerificationRequest,
}

/// Consensus state for one transact verification: the request plus the
/// shared [`VoteTally`].
#[derive(Clone, Debug)]
pub struct TransactConsensus {
    pub request: TransactVerificationRequest,
    pub tally: VoteTally,
}

impl TransactConsensus {
    /// Create new consensus state with explicit BFT thresholds.
    pub fn new_with_thresholds(
        request: TransactVerificationRequest,
        min_validators_for_consensus: usize,
        total_validators: usize,
    ) -> Self {
        let tally = VoteTally::new(
            request.request_id.clone(),
            min_validators_for_consensus,
            total_validators,
        );
        Self { request, tally }
    }
}

/// Coordinates transact verification across validators. The quorum logic is
/// delegated to the embedded [`VoteTally`] of each [`TransactConsensus`].
pub struct TransactVerificationCoordinator {
    /// Active consensus states (request_id -> consensus)
    pending: Arc<RwLock<HashMap<String, TransactConsensus>>>,

    /// Registered validators
    validators: Arc<RwLock<Vec<NodeId>>>,

    /// Leader selector (shared selection model with withdrawals)
    leader_selector: Arc<RwLock<LeaderSelector>>,

    /// Reputation tracker for eligibility gating
    reputation_tracker: Arc<ReputationTracker>,

    /// Slashing-evidence log (equivocation detection)
    slashing_tracker: Arc<SlashingTracker>,

    /// Per-validator timeout streaks
    timeout_streaks: Arc<RwLock<HashMap<NodeId, u64>>>,

    /// Minimum eligible-vote count for the BFT quorum
    min_validators_for_consensus: usize,

    /// Total validator-set size (percentage divisor)
    total_validators: usize,

    /// Approval-event sender; `Some` only when built with
    /// [`new_with_approvals`](Self::new_with_approvals).
    approval_tx: Option<mpsc::UnboundedSender<ApprovedTransact>>,

    /// Request IDs already emitted, so a transact is settled at most once.
    emitted: Arc<RwLock<HashSet<String>>>,

    /// This node's own validator id — the settlement authority it would submit
    /// under. Used to mirror the on-chain stake-weighted quorum off-chain: the
    /// authority is excluded from both the eligible stake and the counted
    /// co-signer stake (#611). `None` (unit tests without a registered
    /// validator set) disables the stake gate, leaving the head-count check.
    local_node_id: Option<NodeId>,

    /// On-chain swap-validator co-sign wallets (the ValidatorRegistry set),
    /// refreshed every reconcile tick from `list_validator_stakes`. Registration
    /// into the swap consensus is gated to these wallets so compute
    /// ResourceProviders and wallet-less connectivity entries never enter the
    /// quorum. Empty = uninitialized (pre-first-snapshot / tests): the gate
    /// fails open, and the stake gate still withholds on 0 total stake.
    onchain_wallets: Arc<RwLock<HashSet<String>>>,

    /// On-chain co-sign stake, keyed by wallet (base58). The numerator source
    /// for the stake gate: votes are counted by wallet and each Valid voter's
    /// weight is read here. Refreshed atomically with `onchain_wallets` (its
    /// key set) each reconcile tick. Empty = uninitialized.
    onchain_stakes: Arc<RwLock<HashMap<String, u64>>>,

    /// The on-chain `ValidatorRegistry.total_active_stake` — the DENOMINATOR for
    /// the stake threshold, read from the registry account (NOT reconstructed by
    /// summing `onchain_stakes`), so a lagging `getProgramAccounts` sum can never
    /// lower the threshold below what the on-chain quorum enforces. 0 =
    /// uninitialized (withholds, like 0 eligible stake).
    onchain_registry_total: Arc<RwLock<u64>>,

    /// This node's own co-sign wallet (base58), excluded from both sides of the
    /// stake quorum exactly as the on-chain authority is. `None` disables the
    /// stake gate (unit/unconfigured case). Set via [`Self::with_local_wallet`].
    local_wallet: Option<String>,

    /// Wallets banned for equivocation (persisted). A banned wallet's standing
    /// vote is excluded from counting, undodgeable by NodeId rotation.
    equivocators: Arc<RwLock<HashSet<String>>>,

    /// Where the equivocator ban set is persisted (sibling of reputation.json).
    /// `None` = in-memory only (unit/unconfigured case).
    equivocators_path: Option<std::path::PathBuf>,
}

impl TransactVerificationCoordinator {
    /// Create a new coordinator with the default 7-of-10 thresholds.
    pub fn new() -> Self {
        Self {
            pending: Arc::new(RwLock::new(HashMap::new())),
            validators: Arc::new(RwLock::new(Vec::new())),
            leader_selector: Arc::new(RwLock::new(LeaderSelector::new())),
            reputation_tracker: Arc::new(ReputationTracker::new()),
            slashing_tracker: Arc::new(SlashingTracker::new()),
            timeout_streaks: Arc::new(RwLock::new(HashMap::new())),
            min_validators_for_consensus: DEFAULT_MIN_VALIDATORS_FOR_CONSENSUS,
            total_validators: DEFAULT_TOTAL_VALIDATORS,
            approval_tx: None,
            emitted: Arc::new(RwLock::new(HashSet::new())),
            local_node_id: None,
            onchain_wallets: Arc::new(RwLock::new(HashSet::new())),
            onchain_stakes: Arc::new(RwLock::new(HashMap::new())),
            onchain_registry_total: Arc::new(RwLock::new(0)),
            local_wallet: None,
            equivocators: Arc::new(RwLock::new(HashSet::new())),
            equivocators_path: None,
        }
    }

    /// Set this node's own validator id, so the off-chain quorum can exclude the
    /// settlement authority exactly as the on-chain quorum does (#611).
    pub fn with_local_node_id(mut self, node_id: NodeId) -> Self {
        self.local_node_id = Some(node_id);
        self
    }

    /// Set this node's own co-sign wallet (base58), so the wallet-keyed stake
    /// quorum can exclude the settlement authority from both sides exactly as
    /// the on-chain quorum does. Mirrors [`Self::with_local_node_id`] but on the
    /// stable stake identity used for counting.
    pub fn with_local_wallet(mut self, wallet: String) -> Self {
        self.local_wallet = Some(wallet);
        self
    }

    /// Back the reputation tracker with a file so accumulated scores survive a
    /// node restart (#691), instead of resetting every validator to the base and
    /// re-admitting a previously-penalised one at full weight.
    pub fn with_reputation_persistence(mut self, path: std::path::PathBuf) -> Self {
        // Persist the equivocator ban set alongside reputation.json so a banned
        // wallet stays banned across a restart (a NodeId-rotation re-entry must
        // not silently restore its counting weight).
        let eq_path = path.with_file_name("equivocators.json");
        if let Ok(bytes) = std::fs::read(&eq_path) {
            if let Ok(set) = serde_json::from_slice::<HashSet<String>>(&bytes) {
                self.equivocators = Arc::new(RwLock::new(set));
            }
        }
        self.equivocators_path = Some(eq_path);
        self.reputation_tracker = Arc::new(ReputationTracker::with_persistence(path));
        self
    }

    /// Best-effort persist of the equivocator ban set. Called while holding the
    /// write lock so the on-disk set never lags the in-memory one.
    async fn persist_equivocators(&self, set: &HashSet<String>) {
        if let Some(path) = &self.equivocators_path {
            match serde_json::to_vec(set) {
                Ok(bytes) => {
                    if let Err(e) = std::fs::write(path, bytes) {
                        log::warn!("could not persist equivocators to {:?}: {}", path, e);
                    }
                }
                Err(e) => log::warn!("could not serialize equivocators: {}", e),
            }
        }
    }

    /// Remove `request_id` from the emitted set so a re-proved identical
    /// canonical id can be approved again — called on final settlement failure
    /// and on timeout sweep, so a content-bound id is never permanently
    /// un-approvable (a wedged-until-restart hazard otherwise).
    pub async fn clear_emitted(&self, request_id: &str) {
        self.emitted.write().await.remove(request_id);
    }

    /// Whether the `Valid`-voting co-signers hold enough stake for the on-chain
    /// stake-weighted quorum to accept the settlement this node would submit
    /// (#611). The off-chain consensus is otherwise a head count, which under a
    /// heterogeneous stake distribution can declare a quorum whose members hold
    /// less than the on-chain two-thirds threshold — the leader then assembles a
    /// transaction the program rejects with `QuorumNotMet`, a durable
    /// settlement-liveness failure. Mirroring the threshold here means any
    /// quorum we assemble already clears the on-chain gate.
    ///
    /// Mirrors `quorum::verify_validator_quorum`: the settlement authority
    /// (this node) is excluded from both the eligible stake (the denominator)
    /// and the counted co-signer stake, and the threshold is
    /// `floor(2 * eligible_stake / 3) + 1`.
    ///
    /// With no configured local id the gate is a no-op and the head-count check
    /// stands alone: that is the unit-test and unconfigured case, where there is
    /// no settlement authority to exclude and nothing is submitted anyway.
    ///
    /// A configured node that sees zero active stake withholds instead (#698).
    /// Reaching that state means the on-chain reconciler has not yet landed a
    /// snapshot — connectivity registration seeds 0 stake, and a failing
    /// `list_validator_stakes` leaves it that way for as long as the RPC stays
    /// down. Approving there would have been the gate's own failure mode: it
    /// exists so this node never assembles a settlement the program will reject
    /// with `QuorumNotMet`, and with no stake data there is no basis to believe
    /// it would clear. A quorum whose co-signers hold no stake cannot clear the
    /// on-chain threshold regardless, so withholding costs nothing a real
    /// snapshot would have bought.
    async fn stake_quorum_met(&self, tally: &VoteTally) -> bool {
        // Wallet-keyed, NO NodeId lookup and NO active-set filter (the flap-prone
        // path). Eligibility + stake come from the on-chain snapshot keyed by
        // wallet, so a reconnected co-signer whose wallet is staked always
        // counts.
        let local = match &self.local_wallet {
            Some(w) => w,
            None => {
                log::warn!(
                    target: "paraloom::consensus::transact",
                    "local_wallet unset; stake gate disabled (unit/unconfigured)"
                );
                return true;
            }
        };

        let onchain_stakes = self.onchain_stakes.read().await;
        // DENOMINATOR = on-chain ValidatorRegistry.total_active_stake, NOT a
        // getProgramAccounts sum, so a lagging PDA scan can never lower the
        // threshold below what the on-chain quorum enforces (mirrors
        // programs/paraloom/src/quorum.rs).
        let registry_total = *self.onchain_registry_total.read().await;
        let authority_stake = onchain_stakes.get(local).copied().unwrap_or(0);
        let eligible_stake = registry_total.saturating_sub(authority_stake);

        if eligible_stake == 0 {
            log::warn!(
                target: "paraloom::consensus::transact",
                "withholding approval: zero eligible on-chain stake \
                 (registry_total={registry_total}, authority_stake={authority_stake}; \
                 reconciler snapshot not landed yet)"
            );
            return false;
        }
        let threshold = eligible_stake.saturating_mul(2) / 3 + 1;

        let equivocators = self.equivocators.read().await;
        let votes = tally.votes.read().await;
        let mut counted_stake: u64 = 0;
        for (wallet, rec) in votes.iter() {
            if wallet == local
                || !rec.vote.is_valid()
                || equivocators.contains(wallet)
                || !onchain_stakes.contains_key(wallet)
            {
                continue;
            }
            counted_stake =
                counted_stake.saturating_add(onchain_stakes.get(wallet).copied().unwrap_or(0));
        }

        // counted must never exceed eligible: an orphaned/duplicate is_active PDA
        // inflating the getProgramAccounts numerator above the registry
        // denominator would otherwise clear a set the chain rejects
        // (mirrors quorum.rs QuorumNotMet on counted>eligible). Withhold, fail safe.
        if counted_stake > eligible_stake {
            log::warn!(
                target: "paraloom::consensus::transact",
                "withholding approval: counted stake {counted_stake} > eligible {eligible_stake} \
                 (getProgramAccounts/registry divergence); reconcile validators"
            );
            return false;
        }

        let met = counted_stake >= threshold;
        if !met {
            let per_wallet: Vec<(String, u64)> = onchain_stakes
                .iter()
                .map(|(w, s)| (w.clone(), *s))
                .collect();
            log::warn!(
                target: "paraloom::consensus::transact",
                "withholding approval: counted co-signer stake {} < threshold {} \
                 (eligible {}, authority {}); on-chain stakes = {:?}",
                counted_stake,
                threshold,
                eligible_stake,
                authority_stake,
                per_wallet
            );
        }
        met
    }

    /// The eligibility basis for counting: the staked on-chain co-sign wallets
    /// minus any banned for equivocation. Replaces the flap-prone
    /// `active_snapshot()` NodeId set at every tally call site.
    async fn eligible_wallets(&self) -> HashSet<String> {
        let onchain = self.onchain_wallets.read().await;
        let equivocators = self.equivocators.read().await;
        onchain.difference(&equivocators).cloned().collect()
    }

    /// Create a coordinator that emits approved transacts on a channel.
    /// Returned as a pair so the receiver (not `Clone`) is owned by exactly
    /// one submitter consumer.
    pub fn new_with_approvals() -> (Self, mpsc::UnboundedReceiver<ApprovedTransact>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut coordinator = Self::new();
        coordinator.approval_tx = Some(tx);
        (coordinator, rx)
    }

    /// Override the BFT thresholds. Falls back to defaults on an invalid
    /// pair (`min == 0`, `total == 0`, or `min > total`).
    pub fn set_consensus_thresholds(
        &mut self,
        min_validators_for_consensus: usize,
        total_validators: usize,
    ) {
        if min_validators_for_consensus == 0
            || total_validators == 0
            || min_validators_for_consensus > total_validators
        {
            log::warn!(
                target: "paraloom::consensus",
                "ignoring invalid transact consensus thresholds (min={} total={}); falling back to {}/{}",
                min_validators_for_consensus,
                total_validators,
                DEFAULT_MIN_VALIDATORS_FOR_CONSENSUS,
                DEFAULT_TOTAL_VALIDATORS
            );
            self.min_validators_for_consensus = DEFAULT_MIN_VALIDATORS_FOR_CONSENSUS;
            self.total_validators = DEFAULT_TOTAL_VALIDATORS;
            return;
        }
        self.min_validators_for_consensus = min_validators_for_consensus;
        self.total_validators = total_validators;
    }

    /// Reference to the slashing-evidence log (tests/pipelines read it).
    pub fn slashing_tracker(&self) -> &Arc<SlashingTracker> {
        &self.slashing_tracker
    }

    /// Register a validator into the transact consensus, mirroring the
    /// withdrawal coordinator (reputation tracker + leader selector).
    pub async fn register_validator(&self, validator: NodeId) {
        self.register_validator_with_wallet(validator, None).await;
    }

    /// Register a validator, recording the Solana wallet pubkey it co-signs
    /// settlement with (#260) — the leader maps a voting `NodeId` to the
    /// on-chain `(wallet, pda)` pair the settlement quorum requires.
    pub async fn register_validator_with_wallet(
        &self,
        validator: NodeId,
        wallet_pubkey: Option<String>,
    ) {
        // Gate: only on-chain swap validators (the ValidatorRegistry set) may
        // enter the settlement quorum. Compute ResourceProviders share the same
        // p2p network but must never carry co-sign weight, and a wallet-less
        // connectivity entry (`None`) must never re-seed a real validator at 0
        // stake. Fail open while the allowlist is empty (pre-first-snapshot /
        // tests) — the stake gate still withholds on 0 total stake, so a
        // transiently-admitted peer is inert.
        {
            let allow = self.onchain_wallets.read().await;
            if !allow.is_empty() {
                let admitted = wallet_pubkey
                    .as_ref()
                    .map(|w| allow.contains(w))
                    .unwrap_or(false);
                if !admitted {
                    log::debug!(
                        "transact registration rejected (not an on-chain swap validator): \
                         {:?} wallet={:?}",
                        validator,
                        wallet_pubkey
                    );
                    return;
                }
            }
        }

        let mut validators = self.validators.write().await;
        if !validators.contains(&validator) {
            log::info!(
                "Validator registered for transact consensus: {:?} (wallet: {:?})",
                validator,
                wallet_pubkey
            );
            validators.push(validator.clone());
        }

        self.reputation_tracker
            .register_validator(validator.clone())
            .await;

        // Preserve an existing leader-selector entry's stake/reputation; only a
        // new validator is added with defaults, and an existing one only adopts a
        // freshly advertised co-sign wallet (#260). Mirrors the withdrawal
        // coordinator so a wallet-less reconciler pass / periodic Discovery never
        // clobbers a known wallet or resets accumulated state.
        let mut leader_selector = self.leader_selector.write().await;
        match leader_selector.get_validator(&validator).cloned() {
            Some(existing) => {
                if wallet_pubkey.is_some() && wallet_pubkey != existing.wallet_pubkey {
                    leader_selector.update_validator(existing.with_wallet(wallet_pubkey));
                }
                // A reconnect re-activates a preserved (deactivated) entry;
                // its stake/wallet/reputation are kept intact (see
                // `unregister_validator` -> `deactivate_validator`).
                leader_selector.activate_validator(&validator);
            }
            None => {
                // Register with ZERO stake (fail-closed): a freshly-seen peer
                // carries no quorum weight until the on-chain stake reconciler
                // (`sync_onchain_stakes`) reads its real, at-risk stake from its
                // `ValidatorAccount`. The old placeholder gave every connected
                // peer a fixed stake, collapsing the stake-weighted quorum into
                // head-count and making it Sybil-forgeable.
                leader_selector.register_validator(
                    ValidatorInfo::new(validator, 0, 1000).with_wallet(wallet_pubkey),
                );
            }
        }
    }

    /// Remove a validator from the *active* transact-consensus set — e.g. when
    /// it disconnects. Drops it from the live voter set and leader selection so
    /// a stale peer stops counting toward (and being selected for) settlement,
    /// but deliberately PRESERVES its `ReputationTracker` metrics.
    ///
    /// Connectivity and security history are separate lifecycle state. Deleting
    /// the reputation entry on disconnect let a validator penalized below the
    /// consensus-eligibility floor reset itself to `BASE_REPUTATION` simply by
    /// reconnecting — for any offline duration — erasing its Byzantine history
    /// and regaining eligibility. Preserving the entry keeps a penalized
    /// validator penalized across reconnects: reputation only decays with
    /// inactivity, it never rises back over the floor. A preserved entry for a
    /// disconnected peer is inert (tallies only iterate over validators who
    /// actually voted this round).
    pub async fn unregister_validator(&self, validator: &NodeId) {
        let mut validators = self.validators.write().await;
        validators.retain(|v| v != validator);

        // Deactivate (do NOT delete) the leader-selector entry: preserve its
        // on-chain stake + co-sign wallet + reputation across a connectivity
        // flap. Deleting them re-seeded a reconnecting validator at stake 0 /
        // wallet None, which the wallet-keyed on-chain reconciler could never
        // repair, silently withholding every settlement. A genuinely
        // deregistered (off-chain) validator is dropped by the on-chain prune,
        // not by a transient disconnect.
        let mut leader_selector = self.leader_selector.write().await;
        leader_selector.deactivate_validator(validator);

        log::info!(
            "Validator deactivated in transact consensus (stake + wallet + reputation preserved): {:?}",
            validator
        );
    }

    /// Reconcile the consensus set's stakes with on-chain reality: set each
    /// validator's stake to the value read from its `ValidatorAccount` (keyed by
    /// co-sign wallet), or 0 if it has no active on-chain registration.
    ///
    /// This is what makes the stake-weighted quorum real. Connectivity
    /// registration (`register_validator_with_wallet`) now seeds 0 stake; this
    /// pass, driven periodically by the node from
    /// `ProgramInterface::list_validator_stakes`, fills in the true at-risk
    /// stake so an unregistered/unstaked peer can never reach a supermajority.
    pub async fn sync_onchain_stakes(
        &self,
        stakes: std::collections::HashMap<String, u64>,
        registry_total_active_stake: u64,
    ) {
        // Refresh the registration allowlist + the wallet-keyed stake numerator
        // to exactly the on-chain swap-validator wallets. These map keys ARE the
        // ValidatorRegistry set; compute ResourceProviders have no
        // ValidatorAccount so are absent, which keeps them out of the quorum.
        // An empty snapshot (RPC returned nothing) is NOT trusted to clear the
        // allowlist/stakes — that would fail-open the gate; keep the previous
        // set (and the previous registry total, updated only alongside a
        // non-empty snapshot so numerator and denominator move together).
        if !stakes.is_empty() {
            *self.onchain_wallets.write().await = stakes.keys().cloned().collect();
            *self.onchain_registry_total.write().await = registry_total_active_stake;
            *self.onchain_stakes.write().await = stakes.clone();
        }

        let mut leader_selector = self.leader_selector.write().await;
        leader_selector.apply_onchain_stakes(&stakes);
        log::debug!(
            "Reconciled consensus stakes against on-chain state ({} staked wallets, registry_total={})",
            stakes.len(),
            registry_total_active_stake
        );
    }

    /// Look up the Solana wallet pubkey a registered validator co-signs
    /// settlement with (#260), or `None` if unknown / not advertised.
    pub async fn validator_wallet(&self, node_id: &NodeId) -> Option<String> {
        let leader_selector = self.leader_selector.read().await;
        leader_selector
            .get_validator(node_id)
            .and_then(|v| v.wallet_pubkey.clone())
    }

    /// The validators that voted `Valid` on a transact (#260) — the eligible
    /// co-signers for its settlement. Empty if the request is unknown here.
    pub async fn valid_voters(&self, request_id: &str) -> Vec<NodeId> {
        let pending = self.pending.read().await;
        match pending.get(request_id) {
            Some(consensus) => {
                let eligible = self.eligible_wallets().await;
                consensus.tally.valid_voters(&eligible).await
            }
            None => Vec::new(),
        }
    }

    /// Whether `node_id` maps to a wallet in the on-chain staked set — the
    /// flap-surviving driver-auth check (replaces `is_registered_validator`,
    /// which used the flap-prone `self.validators`). The leader_selector entry
    /// is preserved across a flap (deactivate-not-delete), so a reconnected
    /// co-signer still authenticates. Fail-open only while the on-chain set is
    /// empty (pre-first-snapshot), matching the registration gate.
    pub async fn source_is_onchain_validator(&self, node_id: &NodeId) -> bool {
        let onchain = self.onchain_wallets.read().await;
        if onchain.is_empty() {
            return true;
        }
        match self.validator_wallet(node_id).await {
            Some(wallet) => onchain.contains(&wallet),
            None => false,
        }
    }

    /// Number of registered validators
    pub async fn validator_count(&self) -> usize {
        self.validators.read().await.len()
    }

    /// Whether `node_id` is in the active validator set. Used to authenticate
    /// the source of a co-sign request (#648): only a registered validator may
    /// drive a co-sign round, so an unregistered mesh peer cannot copy a spend's
    /// public parameters and exhaust a validator's per-nullifier co-sign budget
    /// to block the legitimate leader.
    pub async fn is_registered_validator(&self, node_id: &NodeId) -> bool {
        self.validators.read().await.iter().any(|v| v == node_id)
    }

    /// Clear the timeout streak after a validator is observed alive.
    async fn reset_timeout_streak(&self, validator: &NodeId) {
        self.timeout_streaks
            .write()
            .await
            .insert(validator.clone(), 0);
    }

    /// Start verification for a transact request. Errors if there are not
    /// enough registered validators to reach the configured quorum.
    pub async fn start_verification(&self, request: TransactVerificationRequest) -> Result<String> {
        // The pending map (and every vote's counting id) is keyed by the
        // content-bound canonical id; refuse a request whose id is not its own
        // canonical id so a mis-keyed round can never collect uncountable votes.
        if request.request_id != request.canonical_id() {
            return Err(anyhow!(
                "request_id {} is not the canonical id of its settlement",
                request.request_id
            ));
        }

        let validators = self.validators.read().await;

        if validators.is_empty() {
            return Err(anyhow!("No validators available"));
        }
        if validators.len() < self.min_validators_for_consensus {
            return Err(anyhow!(
                "Not enough validators: {} < {}",
                validators.len(),
                self.min_validators_for_consensus
            ));
        }

        let request_id = request.request_id.clone();
        let consensus = TransactConsensus::new_with_thresholds(
            request,
            self.min_validators_for_consensus,
            self.total_validators,
        );

        // Insert-if-absent: a duplicate start for an already in-flight canonical
        // id (a client retry or a re-broadcast) must not discard the votes
        // already collected for this round. The id is content-bound
        // (`canonical_id`), so an existing entry is the same settlement — keep
        // collecting on it rather than resetting the tally.
        self.pending
            .write()
            .await
            .entry(request_id.clone())
            .or_insert(consensus);

        log::info!("Started transact verification: {}", request_id);
        Ok(request_id)
    }

    /// Submit a verification result from a validator. On the node that
    /// started the request, the vote that first completes a `Valid` quorum
    /// makes the coordinator emit an [`ApprovedTransact`] exactly once.
    pub async fn submit_result(&self, result: TransactVerificationResult) -> Result<()> {
        let pending = self.pending.read().await;

        let consensus = pending
            .get(&result.request_id)
            .ok_or_else(|| anyhow!("Request not found: {}", result.request_id))?;

        // REPLAY invariant on the counting path: the id we count under must be
        // the content-bound canonical id of the settlement in flight. (Signed
        // bytes also bind request_id, so this is belt-and-suspenders.)
        if result.request_id != consensus.request.canonical_id() {
            log::warn!(
                "dropping vote: request_id {} != canonical id of pending settlement",
                result.request_id
            );
            return Ok(());
        }

        // Structural backstop behind the ingress signature check: a vote with no
        // wallet or no signature can never be counted (the self-vote is signed
        // too, so this is safe for the initiator).
        if result.wallet_pubkey.is_empty() || result.signature.is_empty() {
            log::warn!(
                "dropping unsigned/wallet-less vote for {} from {:?}",
                result.request_id,
                result.validator
            );
            return Ok(());
        }

        // Eligibility: while the on-chain wallet set is known, only a staked
        // co-sign wallet may be counted (fail-open only while it is empty, as
        // the registration gate does).
        {
            let onchain = self.onchain_wallets.read().await;
            if !onchain.is_empty() && !onchain.contains(&result.wallet_pubkey) {
                log::warn!(
                    "dropping vote from non-staked wallet {} for {}",
                    result.wallet_pubkey,
                    result.request_id
                );
                return Ok(());
            }
        }

        log::debug!(
            "Transact vote submitted for {}: wallet={} node={:?}",
            result.request_id,
            result.wallet_pubkey,
            result.validator
        );

        let validator = result.validator.clone();
        self.reset_timeout_streak(&validator).await;

        if let Some(evidence) = consensus
            .tally
            .submit_vote(
                result.wallet_pubkey.clone(),
                validator.clone(),
                result.vote.clone(),
                result.signature.clone(),
            )
            .await?
        {
            // Equivocation: ban the WALLET (undodgeable by NodeId rotation) so
            // its standing vote's stake stops counting; persist the ban; keep the
            // NodeId reputation penalty for forensics.
            {
                let mut eq = self.equivocators.write().await;
                eq.insert(result.wallet_pubkey.clone());
                self.persist_equivocators(&eq).await;
            }
            if let Err(e) = self.reputation_tracker.record_failure(&validator).await {
                log::warn!("could not penalise equivocator {:?}: {}", validator, e);
            }
            self.slashing_tracker.record(validator, evidence).await;
        }

        // Emit the approval the first time this vote completes a `Valid` quorum.
        // Counting is by the on-chain staked wallet set (minus equivocators), NOT
        // the flap-prone active NodeId set.
        if let Some(tx) = &self.approval_tx {
            let eligible = self.eligible_wallets().await;
            let mut emitted = self.emitted.write().await;
            if !emitted.contains(&result.request_id)
                && consensus.tally.has_consensus(&eligible).await
                && self.stake_quorum_met(&consensus.tally).await
                && matches!(
                    consensus.tally.consensus_result(&eligible).await,
                    Ok(VerificationVote::Valid)
                )
            {
                let approved = ApprovedTransact {
                    request: consensus.request.clone(),
                };
                if tx.send(approved).is_ok() {
                    emitted.insert(result.request_id.clone());
                }
            }
        }

        Ok(())
    }

    /// Non-blocking quorum check.
    pub async fn check_consensus(&self, request_id: &str) -> Result<Option<VerificationVote>> {
        let pending = self.pending.read().await;
        let consensus = pending
            .get(request_id)
            .ok_or_else(|| anyhow!("Request not found: {}", request_id))?;

        if consensus.tally.is_timed_out() {
            return Err(anyhow!("Verification timed out"));
        }

        let eligible = self.eligible_wallets().await;
        if consensus.tally.has_consensus(&eligible).await {
            let result = consensus.tally.consensus_result(&eligible).await?;
            // A `Valid` result may be acted on only if the co-signers hold
            // enough stake for the on-chain quorum; otherwise keep waiting for
            // more stake to vote rather than assemble a transaction the program
            // would reject (#611). An `Invalid` result settles nothing and needs
            // no stake threshold.
            if matches!(result, VerificationVote::Valid)
                && !self.stake_quorum_met(&consensus.tally).await
            {
                return Ok(None);
            }
            Ok(Some(result))
        } else {
            Ok(None)
        }
    }

    /// `(completion_percentage, valid, invalid)` vote tally for a request.
    pub async fn get_status(&self, request_id: &str) -> Result<(f64, usize, usize)> {
        let pending = self.pending.read().await;
        let consensus = pending
            .get(request_id)
            .ok_or_else(|| anyhow!("Request not found: {}", request_id))?;
        let percentage = consensus.tally.completion_percentage().await;
        let (valid, invalid) = consensus.tally.vote_counts().await;
        Ok((percentage, valid, invalid))
    }

    /// Remove a completed verification's state.
    pub async fn cleanup(&self, request_id: &str) -> Result<()> {
        self.pending.write().await.remove(request_id);
        log::debug!("Cleaned up transact verification: {}", request_id);
        Ok(())
    }

    /// Remove timed-out pending verifications so the map cannot grow unbounded.
    /// The ingress write-surface inserts a request before any vote arrives, so
    /// requests that never reach quorum must be reclaimed by a periodic sweep.
    pub async fn cleanup_timeouts(&self) -> Result<usize> {
        let mut pending = self.pending.write().await;
        let timed_out: Vec<String> = pending
            .iter()
            .filter(|(_, consensus)| consensus.tally.is_timed_out())
            .map(|(id, _)| id.clone())
            .collect();
        let count = timed_out.len();
        for id in timed_out {
            pending.remove(&id);
            // A content-bound canonical id that timed out must be re-approvable
            // if the client re-proves it, so drop any stale emitted mark too.
            self.emitted.write().await.remove(&id);
            log::warn!("Cleaned up timed out transact verification: {}", id);
        }
        Ok(count)
    }
}

impl Default for TransactVerificationCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn sample_request() -> TransactVerificationRequest {
        TransactVerificationRequest {
            request_id: "attacker-chosen".to_string(),
            recipient: [1u8; 32],
            mint: None,
            nullifiers: [[2u8; 32], [3u8; 32]],
            output_commitments: [[4u8; 32], [5u8; 32]],
            root: [6u8; 32],
            ext_amount: -100,
            proof: vec![7, 8, 9],
            ciphertexts: ["a".to_string(), "b".to_string()],
            timestamp: 123,
        }
    }

    /// A canonical-id request ready to start verification.
    fn canonical_request() -> TransactVerificationRequest {
        let mut r = sample_request();
        r.request_id = r.canonical_id();
        r
    }

    /// Build a vote result. The coordinator only checks the signature is
    /// NON-EMPTY (the ed25519 verify lives at the node ingress, not here), so a
    /// dummy non-empty signature exercises the coordinator's counting logic.
    fn vote(request_id: &str, node: u8, wallet: &str, valid: bool) -> TransactVerificationResult {
        TransactVerificationResult {
            request_id: request_id.to_string(),
            validator: NodeId(vec![node]),
            vote: if valid {
                VerificationVote::Valid
            } else {
                VerificationVote::Invalid {
                    reason: "bad".to_string(),
                }
            },
            timestamp: 1,
            wallet_pubkey: wallet.to_string(),
            signature: vec![1],
        }
    }

    fn stakes(pairs: &[(&str, u64)]) -> HashMap<String, u64> {
        pairs.iter().map(|(w, s)| (w.to_string(), *s)).collect()
    }

    /// A 2-of-2 coordinator: authority W0 (val0) + co-signer W1 (val1), each
    /// staked 1 SOL, registry total 2 SOL. Both registered and stake-synced.
    async fn coord_2of2() -> (
        TransactVerificationCoordinator,
        mpsc::UnboundedReceiver<ApprovedTransact>,
    ) {
        let (c, rx) = TransactVerificationCoordinator::new_with_approvals();
        let mut c = c
            .with_local_node_id(NodeId(vec![0]))
            .with_local_wallet("W0".to_string());
        c.set_consensus_thresholds(2, 2);
        c.register_validator_with_wallet(NodeId(vec![0]), Some("W0".to_string()))
            .await;
        c.register_validator_with_wallet(NodeId(vec![1]), Some("W1".to_string()))
            .await;
        c.sync_onchain_stakes(
            stakes(&[("W0", 1_000_000_000), ("W1", 1_000_000_000)]),
            2_000_000_000,
        )
        .await;
        (c, rx)
    }

    #[tokio::test]
    async fn register_then_unregister_tracks_the_validator_set() {
        let coordinator = TransactVerificationCoordinator::new();
        coordinator.register_validator(NodeId(vec![1])).await;
        coordinator.register_validator(NodeId(vec![2])).await;
        assert_eq!(coordinator.validator_count().await, 2);
        coordinator.unregister_validator(&NodeId(vec![1])).await;
        assert_eq!(coordinator.validator_count().await, 1);
        coordinator.unregister_validator(&NodeId(vec![9])).await;
        assert_eq!(coordinator.validator_count().await, 1);
    }

    #[tokio::test]
    async fn reconciler_reregister_preserves_the_advertised_wallet() {
        let coordinator = TransactVerificationCoordinator::new();
        coordinator
            .register_validator_with_wallet(NodeId(vec![1]), Some("WaLLet1111".to_string()))
            .await;
        coordinator
            .register_validator_with_wallet(NodeId(vec![1]), None)
            .await;
        assert_eq!(
            coordinator.validator_wallet(&NodeId(vec![1])).await,
            Some("WaLLet1111".to_string()),
            "a wallet-less re-register must not clobber the advertised wallet"
        );
    }

    // ---- signing-bytes (pure) ----

    #[test]
    fn signing_bytes_are_deterministic_and_bind_every_field() {
        let base = transact_vote_signing_bytes(
            "PROG",
            "mainnet-beta",
            "req-1",
            &NodeId(vec![1, 2, 3]),
            &VerificationVote::Valid,
            "W1",
        );
        // Deterministic for identical inputs.
        assert_eq!(
            base,
            transact_vote_signing_bytes(
                "PROG",
                "mainnet-beta",
                "req-1",
                &NodeId(vec![1, 2, 3]),
                &VerificationVote::Valid,
                "W1"
            )
        );
        // Every field is bound: changing any one changes the bytes.
        let mutations = [
            transact_vote_signing_bytes(
                "PROG2",
                "mainnet-beta",
                "req-1",
                &NodeId(vec![1, 2, 3]),
                &VerificationVote::Valid,
                "W1",
            ),
            transact_vote_signing_bytes(
                "PROG",
                "devnet",
                "req-1",
                &NodeId(vec![1, 2, 3]),
                &VerificationVote::Valid,
                "W1",
            ),
            transact_vote_signing_bytes(
                "PROG",
                "mainnet-beta",
                "req-2",
                &NodeId(vec![1, 2, 3]),
                &VerificationVote::Valid,
                "W1",
            ),
            transact_vote_signing_bytes(
                "PROG",
                "mainnet-beta",
                "req-1",
                &NodeId(vec![9, 9, 9]),
                &VerificationVote::Valid,
                "W1",
            ),
            transact_vote_signing_bytes(
                "PROG",
                "mainnet-beta",
                "req-1",
                &NodeId(vec![1, 2, 3]),
                &VerificationVote::Invalid { reason: "x".into() },
                "W1",
            ),
            transact_vote_signing_bytes(
                "PROG",
                "mainnet-beta",
                "req-1",
                &NodeId(vec![1, 2, 3]),
                &VerificationVote::Valid,
                "W2",
            ),
        ];
        for m in mutations {
            assert_ne!(base, m, "each field must be bound into the preimage");
        }
        // The Invalid reason free-text is NOT signed (only the validity bit).
        assert_eq!(
            transact_vote_signing_bytes(
                "PROG",
                "mainnet-beta",
                "req-1",
                &NodeId(vec![1]),
                &VerificationVote::Invalid { reason: "a".into() },
                "W1"
            ),
            transact_vote_signing_bytes(
                "PROG",
                "mainnet-beta",
                "req-1",
                &NodeId(vec![1]),
                &VerificationVote::Invalid { reason: "b".into() },
                "W1"
            ),
        );
    }

    // ---- wallet-keyed counting / stake gate ----

    #[tokio::test]
    async fn two_of_two_wallet_quorum_settles() {
        let (coord, mut approvals) = coord_2of2().await;
        let req = canonical_request();
        let id = req.request_id.clone();
        coord.start_verification(req).await.unwrap();
        coord.submit_result(vote(&id, 0, "W0", true)).await.unwrap();
        assert!(approvals.try_recv().is_err(), "one vote is not a quorum");
        coord.submit_result(vote(&id, 1, "W1", true)).await.unwrap();
        assert!(
            approvals.try_recv().is_ok(),
            "authority + co-signer wallet quorum must settle"
        );
    }

    /// CORE FIX: a co-signer removed from the active NodeId set (flap) still has
    /// its signed vote counted, because counting is keyed by the on-chain wallet.
    /// Arm-the-guard: revert counting to intersect the active NodeId set and
    /// val1 (unregistered) is filtered, quorum never forms, this fails.
    #[tokio::test]
    async fn flapped_wallet_vote_still_counts_and_settles() {
        let (coord, mut approvals) = coord_2of2().await;
        let req = canonical_request();
        let id = req.request_id.clone();
        coord.start_verification(req).await.unwrap();

        // val1 flaps: dropped from the active NodeId set (but W1 stays on-chain).
        coord.unregister_validator(&NodeId(vec![1])).await;
        assert!(!coord.is_registered_validator(&NodeId(vec![1])).await);

        coord.submit_result(vote(&id, 0, "W0", true)).await.unwrap();
        coord.submit_result(vote(&id, 1, "W1", true)).await.unwrap();
        assert!(
            approvals.try_recv().is_ok(),
            "a flapped co-signer's signed vote must still count by wallet"
        );
    }

    /// The authority's own wallet is excluded from both sides of the stake
    /// quorum: its lone self-vote cannot self-approve.
    /// Arm-the-guard: stop excluding local and W0's stake self-clears.
    #[tokio::test]
    async fn authority_wallet_excluded_from_quorum() {
        let (c, rx) = TransactVerificationCoordinator::new_with_approvals();
        let mut c = c
            .with_local_node_id(NodeId(vec![0]))
            .with_local_wallet("W0".to_string());
        c.set_consensus_thresholds(1, 2);
        c.register_validator_with_wallet(NodeId(vec![0]), Some("W0".to_string()))
            .await;
        c.sync_onchain_stakes(
            stakes(&[("W0", 1_000_000_000), ("W1", 1_000_000_000)]),
            2_000_000_000,
        )
        .await;
        let mut approvals = rx;
        let req = canonical_request();
        let id = req.request_id.clone();
        c.start_verification(req).await.unwrap();
        c.submit_result(vote(&id, 0, "W0", true)).await.unwrap();
        assert!(
            approvals.try_recv().is_err(),
            "the authority's own vote must not settle its own quorum"
        );
    }

    /// The stake denominator is the registry total, not the getProgramAccounts
    /// sum: a co-signer holding less than 2/3 of the registry total is withheld
    /// even though it is 100% of the scanned stake map.
    /// Arm-the-guard: use sum(onchain_stakes) as the denominator and it approves.
    #[tokio::test]
    async fn off_chain_denominator_uses_registry_total() {
        let (c, rx) = TransactVerificationCoordinator::new_with_approvals();
        let mut c = c
            .with_local_node_id(NodeId(vec![0]))
            .with_local_wallet("W0".to_string());
        c.set_consensus_thresholds(1, 3);
        c.register_validator_with_wallet(NodeId(vec![1]), Some("W1".to_string()))
            .await;
        // Only W1 is in the scanned map, but the registry counts 3 SOL active.
        c.sync_onchain_stakes(stakes(&[("W1", 1_000_000_000)]), 3_000_000_000)
            .await;
        let mut approvals = rx;
        let req = canonical_request();
        let id = req.request_id.clone();
        c.start_verification(req).await.unwrap();
        c.submit_result(vote(&id, 1, "W1", true)).await.unwrap();
        assert!(
            approvals.try_recv().is_err(),
            "1 SOL < 2/3 of the 3-SOL registry total must withhold"
        );
    }

    /// counted_stake must never exceed eligible_stake (an orphaned/duplicate
    /// is_active PDA inflating the scan above the registry total): withhold.
    /// Arm-the-guard: drop the counted<=eligible guard and it approves.
    #[tokio::test]
    async fn counted_exceeds_eligible_withholds() {
        let (c, rx) = TransactVerificationCoordinator::new_with_approvals();
        let mut c = c
            .with_local_node_id(NodeId(vec![0]))
            .with_local_wallet("W0".to_string());
        c.set_consensus_thresholds(2, 3);
        c.register_validator_with_wallet(NodeId(vec![1]), Some("W1".to_string()))
            .await;
        c.register_validator_with_wallet(NodeId(vec![2]), Some("W2".to_string()))
            .await;
        // Scan sums to 2 SOL but the registry only records 1 SOL active.
        c.sync_onchain_stakes(
            stakes(&[("W1", 1_000_000_000), ("W2", 1_000_000_000)]),
            1_000_000_000,
        )
        .await;
        let mut approvals = rx;
        let req = canonical_request();
        let id = req.request_id.clone();
        c.start_verification(req).await.unwrap();
        c.submit_result(vote(&id, 1, "W1", true)).await.unwrap();
        c.submit_result(vote(&id, 2, "W2", true)).await.unwrap();
        assert!(
            approvals.try_recv().is_err(),
            "counted (2 SOL) > eligible (1 SOL) must fail safe"
        );
    }

    /// A wallet that equivocates (Valid then Invalid, from two NodeIds) is
    /// banned and its standing vote stops counting.
    /// Arm-the-guard: remove the equivocator ban/filter and the standing Valid
    /// vote keeps its weight.
    #[tokio::test]
    async fn equivocation_bans_wallet_and_stops_counting() {
        // Two co-signers are needed for the quorum; W1 equivocates and is banned,
        // so W2 alone can no longer complete it.
        let (c, rx) = TransactVerificationCoordinator::new_with_approvals();
        let mut c = c
            .with_local_node_id(NodeId(vec![0]))
            .with_local_wallet("W0".to_string());
        c.set_consensus_thresholds(2, 3);
        c.register_validator_with_wallet(NodeId(vec![1]), Some("W1".to_string()))
            .await;
        c.register_validator_with_wallet(NodeId(vec![2]), Some("W2".to_string()))
            .await;
        c.sync_onchain_stakes(
            stakes(&[("W1", 1_000_000_000), ("W2", 1_000_000_000)]),
            2_000_000_000,
        )
        .await;
        let mut approvals = rx;
        let req = canonical_request();
        let id = req.request_id.clone();
        c.start_verification(req).await.unwrap();
        // W1 votes Valid (node 1), then flips to Invalid (node 9) — equivocation.
        c.submit_result(vote(&id, 1, "W1", true)).await.unwrap();
        c.submit_result(vote(&id, 9, "W1", false)).await.unwrap();
        // W2 votes Valid, but with W1 banned the quorum cannot form.
        c.submit_result(vote(&id, 2, "W2", true)).await.unwrap();
        assert!(
            approvals.try_recv().is_err(),
            "an equivocating wallet's standing vote must stop counting"
        );
        assert!(
            c.slashing_tracker().total_count().await > 0,
            "equivocation must be recorded"
        );
    }

    /// A vote from a wallet absent from the on-chain staked set is dropped
    /// (re-expression of #408 + Sybil): only staked wallets count.
    /// Arm-the-guard: count regardless of onchain_wallets membership.
    #[tokio::test]
    async fn non_staked_wallet_vote_not_counted() {
        let (coord, mut approvals) = coord_2of2().await;
        let req = canonical_request();
        let id = req.request_id.clone();
        coord.start_verification(req).await.unwrap();
        coord.submit_result(vote(&id, 0, "W0", true)).await.unwrap();
        // W9 is not in the staked set — dropped, so no quorum forms.
        coord.submit_result(vote(&id, 9, "W9", true)).await.unwrap();
        assert!(
            approvals.try_recv().is_err(),
            "a non-staked wallet's vote must not count toward the quorum"
        );
    }

    /// After an approval is emitted but settlement fails, clear_emitted lets the
    /// same canonical id be approved again.
    /// Arm-the-guard: never clear `emitted` and the re-trigger is swallowed.
    #[tokio::test]
    async fn clear_emitted_allows_reapproval() {
        let (coord, mut approvals) = coord_2of2().await;
        let req = canonical_request();
        let id = req.request_id.clone();
        coord.start_verification(req).await.unwrap();
        coord.submit_result(vote(&id, 0, "W0", true)).await.unwrap();
        coord.submit_result(vote(&id, 1, "W1", true)).await.unwrap();
        assert!(approvals.try_recv().is_ok(), "first approval fires");

        // Simulate a settlement failure freeing the id, then a re-trigger.
        coord.clear_emitted(&id).await;
        coord.submit_result(vote(&id, 1, "W1", true)).await.unwrap();
        assert!(
            approvals.try_recv().is_ok(),
            "after clear_emitted the same canonical id can be re-approved"
        );
    }

    #[tokio::test]
    async fn start_verification_rejects_non_canonical_id() {
        let coordinator = TransactVerificationCoordinator::new();
        coordinator.register_validator(NodeId(vec![1])).await;
        coordinator.register_validator(NodeId(vec![2])).await;
        let req = sample_request(); // request_id = "attacker-chosen" != canonical
        assert!(
            coordinator.start_verification(req).await.is_err(),
            "a request whose id is not its canonical id must be rejected"
        );
    }

    #[tokio::test]
    async fn restarting_an_in_flight_verification_preserves_collected_votes() {
        let (coord, mut approvals) = coord_2of2().await;
        let req = canonical_request();
        let id = req.request_id.clone();
        coord.start_verification(req.clone()).await.unwrap();
        coord.submit_result(vote(&id, 0, "W0", true)).await.unwrap();
        assert!(
            approvals.try_recv().is_err(),
            "one of two votes is not a quorum"
        );
        // Duplicate start for the same in-flight id — must NOT reset the tally.
        coord.start_verification(req).await.unwrap();
        coord.submit_result(vote(&id, 1, "W1", true)).await.unwrap();
        assert!(
            approvals.try_recv().is_ok(),
            "the first vote must survive the duplicate start"
        );
    }

    // ---- canonical id (pure, unchanged) ----

    #[test]
    fn canonical_id_binds_only_settlement_fields() {
        let base = sample_request().canonical_id();
        let mut r = sample_request();
        r.request_id = "different".to_string();
        r.ciphertexts = ["x".to_string(), "y".to_string()];
        r.timestamp = 999;
        assert_eq!(
            r.canonical_id(),
            base,
            "id must bind only settlement fields"
        );
    }

    #[test]
    fn canonical_id_changes_when_a_settlement_field_changes() {
        let base = sample_request().canonical_id();
        for mutate in [
            (|r: &mut TransactVerificationRequest| r.ext_amount = -101) as fn(&mut _),
            |r| r.nullifiers[0] = [9u8; 32],
            |r| r.output_commitments[1] = [9u8; 32],
            |r| r.root = [9u8; 32],
            |r| r.recipient = [9u8; 32],
            |r| r.proof = vec![7, 8, 10],
        ] {
            let mut r = sample_request();
            mutate(&mut r);
            assert_ne!(r.canonical_id(), base);
        }
    }

    #[test]
    fn canonical_id_binds_the_proof_suite_tag() {
        use crate::privacy::{tag_proof, ProofSuite, GROTH16_BN254_COMPRESSED_LEN};
        let body = vec![3u8; GROTH16_BN254_COMPRESSED_LEN];
        let a = TransactVerificationRequest {
            proof: tag_proof(ProofSuite::Groth16Bn254TransactV3, &body),
            ..sample_request()
        };
        let mut b = a.clone();
        b.proof[0] = 2;
        assert_ne!(a.canonical_id(), b.canonical_id());
    }

    // ---- registration gating / flap preservation ----

    #[tokio::test]
    async fn registration_is_gated_to_onchain_swap_validators() {
        let coordinator = TransactVerificationCoordinator::new();
        coordinator
            .sync_onchain_stakes(
                stakes(&[("VAL1wallet", 1_000_000_000), ("VAL2wallet", 1_000_000_000)]),
                2_000_000_000,
            )
            .await;
        coordinator
            .register_validator_with_wallet(NodeId(vec![0xC0]), Some("COMPUTEwallet".to_string()))
            .await;
        assert!(
            !coordinator
                .is_registered_validator(&NodeId(vec![0xC0]))
                .await,
            "a non-on-chain (compute) wallet must never enter the swap consensus"
        );
        coordinator
            .register_validator_with_wallet(NodeId(vec![0xC1]), None)
            .await;
        assert!(
            !coordinator
                .is_registered_validator(&NodeId(vec![0xC1]))
                .await,
            "a wallet-less registration must never enter the swap consensus"
        );
        coordinator
            .register_validator_with_wallet(NodeId(vec![0x01]), Some("VAL2wallet".to_string()))
            .await;
        assert!(
            coordinator
                .is_registered_validator(&NodeId(vec![0x01]))
                .await,
            "an on-chain swap validator must be admitted"
        );
    }

    #[tokio::test]
    async fn flap_preserves_validator_stake_and_wallet() {
        let coordinator = TransactVerificationCoordinator::new();
        coordinator
            .register_validator_with_wallet(NodeId(vec![2]), Some("VAL2wallet".to_string()))
            .await;
        coordinator
            .sync_onchain_stakes(stakes(&[("VAL2wallet", 1_000_000_000)]), 1_000_000_000)
            .await;
        coordinator.unregister_validator(&NodeId(vec![2])).await;
        {
            let sel = coordinator.leader_selector.read().await;
            let info = sel
                .get_validator(&NodeId(vec![2]))
                .expect("entry must survive a connectivity flap (deactivated, not deleted)");
            assert_eq!(info.stake_amount, 1_000_000_000);
            assert_eq!(info.wallet_pubkey.as_deref(), Some("VAL2wallet"));
            assert!(!info.is_active);
        }
        coordinator
            .register_validator_with_wallet(NodeId(vec![2]), Some("VAL2wallet".to_string()))
            .await;
        {
            let sel = coordinator.leader_selector.read().await;
            let info = sel.get_validator(&NodeId(vec![2])).unwrap();
            assert!(info.is_active);
            assert_eq!(info.stake_amount, 1_000_000_000);
        }
    }
}
