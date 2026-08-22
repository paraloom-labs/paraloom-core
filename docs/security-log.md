# Security log

A public record of security-relevant findings and the fixes that closed them.
Everything here was found and fixed **pre-mainnet, on devnet — no real funds
were ever at risk**. Newest first. Each entry links the public issue so anyone
can verify it.

This is the log referenced by [`SECURITY.md`](../SECURITY.md). To report a new
issue, email security@paraloom.network.

## 2026-08

- **The bridge decoder could not read `deposit_note_spl`, so nodes would have
  gone blind to every SPL deposit** (external bug-bounty report, nyiru79). #795 —
  #779 added the SPL deposit and settlement instructions to the program, but the
  node's decoder was never given the deposit half: there was no
  `DEPOSIT_NOTE_SPL` discriminator, and `decode_compiled_deposit` matched only
  `deposit_note` plus the two legacy instructions removed in July. A confirmed
  SPL deposit would have fallen out of `extract_deposit_events` entirely, so
  `process_deposit` never ran and the pool never saw the commitment or the mint's
  supply. Exactly the shape of #689, where the same decoder went blind to native
  deposits for nineteen days.

  The report's more valuable half is the trap it flagged for the fix. The legacy
  `deposit_spl` arm keys the asset as the raw mint bytes, but `deposit_note_spl`
  commits the leaf under `mint_to_asset(mint)`, a `Poseidon(2)` over the mint's
  two halves. An arm that reused the raw bytes would decode, credit, and be
  wrong, putting a leaf in the pool that the chain never appended — trading a
  blind node for a confidently wrong one, which is the same trap #693 called out.
  Fixed by adding the discriminator and an arm that reads the `DepositNoteSpl`
  account layout (mint at 2, depositor at 6) and maps the mint through
  `mint_to_asset`. Two regression tests pin it: the decoder test asserts the
  asset is `mint_to_asset(mint)` and explicitly *not* the raw mint, and a
  listener test walks mint to asset to leaf and compares it against the program's
  own formula, spelled out rather than imported so either side moving is caught.

  Impact is off-chain index correctness only, with no fund, spend, or settlement
  path affected: settlement verifies against the on-chain tree and `is_known_root`,
  and wallets build Merkle paths from chain events. The reporter also confirmed
  the deployed program does not yet carry the #779 instructions and filed it for
  the record rather than as a scope claim, which is the right read — the gap
  becomes live on the first redeploy that ships #779, and is now closed ahead of
  it. Devnet, pre-mainnet.

- **The live circuit's proving/verifying keys are now from a multi-party trusted
  setup, not a single-party dev key** (ceremony finalization, #659 / #64). Until
  now the deployed transact v3 circuit verified against a Groth16 key generated on
  one machine, so whoever ran that setup held the toxic waste and could in
  principle forge a proof for any statement, including a withdrawal with no
  matching deposit. That was a documented pre-ceremony limitation, listed out of
  bounty scope in `docs/bug-bounty.md`.

  The multi-party ceremony is now finalized and cut into the program. It starts
  from the public Perpetual Powers of Tau (phase 1), takes four independent
  phase-2 contributions, and closes on a public Bitcoin-block beacon, so the keys
  are sound as long as any one contributor discarded their secret. The full
  transcript, the initial and final keys, and their `SHA256SUMS` are published
  under `ceremony/transact/` for independent verification, following what
  `ceremony/transfer/` and `ceremony/withdraw/` already ship. The redeployed
  program verifies every settlement against the ceremony key; the old
  single-party key no longer exists on chain. Verified end to end on devnet: a
  wallet-generated proof settled through the live validator quorum against the
  ceremony key. Devnet, pre-mainnet.

- **Dual-stake vault and BridgeState migrations for a pre-existing pool**
  (hardening, ceremony redeploy). The dual-stake token half locks into a shared
  `stake_token_vault`, and the TVL cap (#642) added `deposit_cap` to
  `BridgeState`, but both fields are created inline at first-time initialization,
  which a pool deployed before them can never re-run. After the ceremony redeploy,
  `BridgeState` was one field short of the layout the program expected, so every
  `transact` / `deposit_note` / `pause` / `set_deposit_cap` aborted
  `AccountDidNotDeserialize`, and no `stake_token_vault` existed for dual-stake
  registration. Added upgrade-authority-gated `init_stake_token_vault` and
  `migrate_bridge_state` instructions that grow the accounts in place (rent topped
  up, new bytes zero-filled so `deposit_cap` starts closed), mirroring
  `reset_validator_registry`. An availability gap on a devnet pool, not a
  fund-loss path; no real funds were at risk. Devnet, pre-mainnet.

## 2026-07

- **Wallet connection-approval was bypassable from the page** (external
  bug-bounty report, Godswork4). #711 — the wallet's content-script relay
  forwarded any message type to the background, and the background gated the
  connection-approval branches on type alone without checking the sender. A
  script on any injected `*.paraloom.io` origin could send
  `GET_PENDING_CONNECTION` to read the id of a connection awaiting approval,
  then `APPROVE_CONNECTION` to resolve it — approving its own connection and
  reading the visitor's shielded address and balance with no popup and no
  interaction. For a shielded pool that is deanonymisation, linking a page
  visitor to a shielded amount, rather than a mere info leak.

  Fixed in two layers in `paraloom-wallet` (PR #1): the background now refuses
  the six popup-only message types when they carry a `sender.tab` — a popup
  message comes from the extension's own context and has none, a content-script
  message always has one — and the relay forwards only the eight message types
  the page provider actually sends, so the approval types cannot reach the
  background from a page at all.

  Out of Stage 1 bounty scope, credited not paid, on the #656/#677 precedent:
  the relay and this whole message path landed on 2026-07-28 (`f84e96d`), while
  the Chrome Web Store build is 1.3.0 from 2026-06-22, which contains neither.
  Confirmed empirically — against the shipped 1.3.0 the self-approval script
  hangs with no relay to answer — so the finding is reproducible only off the
  deployed extension, which the scope puts out of bounds. Had it been reachable
  on the shipped build the severity would have risen rather than fallen; it was
  not reachable by any user. Ships fixed in the wallet rebuild that first
  exposes the surface, alongside the ceremony redeploy. Devnet, pre-mainnet.

- **The off-chain stake gate failed open with no stake snapshot** (external
  bug-bounty report, Godswork4). #698 — `stake_quorum_met` returned `true` when
  it saw zero total active stake, documented as covering unit tests and nodes
  with no configured local id. A configured production node reached it too:
  connectivity registration seeds 0 stake, so between startup and the first
  successful `list_validator_stakes`, and for as long as that RPC kept failing,
  the gate applied no stake weighting at all and approval fell back to head
  count and reputation alone.

  That inverts what the gate is for. It exists so a node never assembles a
  settlement the program rejects with `QuorumNotMet`, and with no stake data
  there is no basis to believe one would clear. It now withholds, and the
  reconciler's failure log moved from `debug` to `warn`, since a persistent
  failure means the node has quietly stopped approving (PR #700). One correction
  to the report: `tokio::time::interval` completes its first tick immediately,
  so the startup window is one RPC round trip rather than 60 seconds. The
  unbounded RPC-failure window is the real one.

  Worth recording what fixing it exposed. `transact_cosign_e2e` — whose subject
  is stake-weighted co-signing — began failing, because its nodes point
  `solana_rpc_url` at a dead port, so no snapshot ever landed and the gate had
  always been a no-op there. The test had never exercised the stake weighting it
  is named for. A single fail-open branch both opened the production window and
  disabled the test that should have caught it; the test now supplies the
  snapshot its reconciler cannot fetch.

  On-chain settlement was never affected: `quorum::verify_validator_quorum` is
  the safety gate and is independent. Out of Stage 1 bounty scope on the #627
  precedent — an off-chain quorum gate being too permissive is quorum-liveness
  rather than safety, and out-of-scope item 3 covers both dimensions of a
  quorum that is not yet economically Sybil-resistant — so credited here rather
  than paid. Devnet, pre-mainnet.

- **The v3 deposit path was never finished off chain** (external bug-bounty
  reports, Godswork4). Four issues with one root cause. `deposit_note` landed on
  2026-07-06 and the legacy `deposit` / `deposit_spl` instructions came out two
  days later, moving every deposit onto the new instruction — but only the
  on-chain half of that move shipped.
  - #689 — the bridge decoder still matched the removed discriminators, so from
    2026-07-08 it recognized no deposit at all. The program kept appending
    leaves; nodes stopped seeing them, and every deposit in that window is
    missing from the node's own ledger — per-asset supply, stored notes, and the
    pool state it gossips to peers. Fixed by adding the `DEPOSIT_NOTE` branch
    and, more to the point, by crediting the commitment the program actually
    computes: `Note::commitment()` is the v2 hash (five inputs, domain tag) while
    the on-chain leaf is four inputs with no tag, so recognizing the instruction
    alone would have traded a blind node for a confidently wrong one (PR #693).
  - #680 — the pool's deposit idempotency guard was restored only in a
    constructor with no production caller, so on a real node it never came back
    and a re-indexed leaf could be appended twice. Guard fixed (PR #685); it does
    not yet run, for the reason #690 gives.
  - #690 — the pool is always constructed in memory, so none of the above is
    persisted and every restart rebuilds from the bridge cursor. Open.
  #691 was reported in the same batch and is **not** part of this root cause,
  though the first version of this entry filed it here. `ReputationTracker` has
  no persistence, so accumulated validator reputation resets to
  `BASE_REPUTATION` on restart. That is the consensus layer, with no causal link
  to the deposit path; the shared trait is only that neither survives a restart,
  which is a symptom rather than a cause. Filing it under the deposit-path
  heading was a stretch, and it happened to be the direction that suited us.

  Its impact is also not what the issue claims. Leader weighting is unaffected,
  because `LeaderSelector` reads its own `ValidatorInfo.reputation`, fixed at
  registration and never synced from the tracker, so leader weight is stake-only
  either way. The real exposure is vote eligibility: a validator pushed below the
  consensus floor by `record_failure` is eligible again after any restart of the
  tallying node, which is a penalty-evasion path. Low today only because the
  quorum is not yet economically Sybil-resistant, so reputation is not
  load-bearing; it joins the mainnet gate list alongside that. Open.

  No user was affected and settlement never depended on any of it, which is
  worth stating precisely rather than as reassurance. A v3 spend proves
  membership in the *on-chain* root and the program enforces that with
  `is_known_root` before the quorum and Groth16 checks, so `verify_transact_proof`
  deliberately never consults the pool. Wallets build merkle paths from leaves
  read straight off the chain, not from a node. A blind node was therefore a node
  with a stale private ledger, not a stalled or divergent protocol: deposits kept
  landing, funds stayed spendable throughout, and nothing here allowed minting,
  theft, freezing or a double spend.

  Recovery is the part that is not free, and the first version of this entry got
  it wrong. The scan cursor is passed as `until`, so a node restarted on fixed
  code only asks for transactions newer than the cursor and never re-requests the
  twenty days it was blind for. Deleting the cursor does not fix that either:
  `listener.rs:543` breaks after the newest page when no cursor is set, so a cold
  start reads one page and stops. Re-scanning means seeding an older signature
  into the cursor file so the walk-back has something to page toward.

  The deeper version of the same point, which #690 tracks: the pool is in-memory
  while the cursor is durable, so a node has always started each run with an
  empty tree and a cursor claiming the history was already scanned. The twenty
  days are not a hole in an otherwise complete ledger — the ledger has never held
  anything older than the last restart. That it went unnoticed for nineteen days
  is a consequence of the same thing that made it harmless: nothing in production
  reads this tree.

  Paid $150 from the Stage 1 pool: $100 for the deposit-path cluster as a single
  root cause, $50 for #691 as a separate Low. Devnet, pre-mainnet.

- **Dual-stake token gate started open** (external bug-bounty report, kiyeps).
  #656 — `initialize_validator_registry` and `reset_validator_registry` both
  hardcoded `min_token_stake: 0`, while preserving the SOL floor. Registration
  is permissionless and `register_validator` checks
  `token_stake_amount >= min_token_stake`, so a floor of zero passes for
  everyone: the token half of the dual-stake was absent until the authority
  set it. The code defended the default as behaving "like the deposit cap",
  which inverts — a `deposit_cap` of zero refuses every deposit. Two adjacent
  settings that look alike and fail in opposite directions, with the safe one
  cited as precedent for the unsafe one. The runbook step the design leaned on
  did not exist. Both paths now start at `RECOMMENDED_MIN_TOKEN_STAKE`, so a
  forgotten step costs a rejected registration rather than a validator slot
  bought with no token stake (#667). Out of Stage 1 bounty scope — the dual-stake
  instructions are merged but not on the deployed program, and findings only
  reproducible off the pinned deployment are out of scope — so credited here
  rather than paid. Devnet, pre-mainnet.

- **Off-chain settlement and consensus hygiene** (external bug-bounty reports,
  Godswork4 and iceiceic3). Correctness findings in the off-chain settlement and
  consensus layer, fixed:
  - #626 (Godswork4) — the per-nullifier co-sign counter map (added with the
    #593/#606 remediation) was never cleared and grew for the life of the
    process. It is now bounded with an eviction ceiling, like its sibling
    verified-transact cache. Single-node resource growth (out of bounty scope),
    credited.
  - #624 (Godswork4) — the off-chain nullifier set was never updated when a
    transact settled, so it did not pre-filter replays before consensus. The
    submitting node now records a settled spend's input nullifiers. The on-chain
    nullifier PDAs remain the authoritative double-spend gate, so this is a
    redundant pre-filter kept in step, not a safety change.
  - #623 (Godswork4) — `ProgramInterface::verify_deposit` took an
    `expected_amount` it never read and logged it as "verified". The misleading
    parameter is removed and the helper documented as a transaction-success
    check only (deposit amounts are bound on-chain by `deposit_note`).
  - #627 (iceiceic3) — the discovery handler registered any `ResourceProvider`
    peer as a transact validator without checking its on-chain validator PDA.
    The on-chain quorum rejects unregistered co-signers, so this is a liveness
    (doomed-attempt) issue, not a safety one; the authoritative on-chain
    verification is folded into the validator-set reconciler (#333). Sybil /
    quorum-liveness (out of scope), credited.
  Devnet, pre-mainnet.

- **Compute and HA layers hardened against unauthenticated resource exhaustion
  and state poisoning** (external bug-bounty reports, billythebotman). Four
  findings in the alpha compute/task and coordinator-HA subsystems. These are
  out of Stage 1 bounty scope (which covers the shielded-pool / settlement
  stack), so they are credited here rather than paid, but each is real and was
  fixed:
  - #609 — a peer-supplied `HashCalculation` range (`start=0, end=u64::MAX`)
    overflowed the item count and looped ~2^64 times, OOM-killing the validator.
    The range is now bounded and overflow-checked before any work is done.
  - #607 — an HA standby applied any higher-sequence heartbeat without checking
    the authenticated sender, so any connected peer could inject an arbitrary
    coordinator snapshot and suppress failover. Heartbeats are now accepted only
    from the standby's configured primary; the request's own `primary` field is
    not trusted.
  - #608 — the task-result handler retained a `TaskResult` from any peer under
    any task id before validating it, growing memory without bound and allowing
    a peer to race the assignee with a forged result. Results are now bound to
    the assigned validator, required to be for an active task, and not
    replaceable.
  - #610 — authorized-but-excess compute jobs were enqueued with no aggregate
    bound. The pending queue is now capped, and the handler checks capacity
    before committing any per-job state, so a rejected job leaves no residue.
  Devnet, pre-mainnet.

- **Compute execution-proof verification now fails closed when the verifying key
  is absent** (external bug-bounty report, Godswork4). `verify_execution_proof`
  dropped to a length-only check and accepted any 32- or 192-byte buffer as a
  valid Groth16 proof whenever `keys/compute_verifying.key` was missing; with
  multi-validator consensus optional by default, that length check was the sole
  gate, so a forged `PrivateJobResult` with an arbitrary output could pass. It
  now returns an error when the key is absent, and the permissive placeholder
  path is compiled only under `cfg(test)`, so release/dev binaries reject the
  result outright. Alpha compute subsystem, out of Stage 1 bounty scope (credited
  here, not paid). Devnet, pre-mainnet (#652, PR #654).

- **Deposit listener aborts a poll instead of skipping a signature whose body
  failed to fetch** (external bug-bounty report, gussamkodin). The
  contiguous-cursor barrier that keeps the listener from advancing past an
  unprocessed deposit only froze on decoded per-signature outcomes. A
  `getTransaction` failure happens *before* decoding, so it produced no outcome:
  `fetch_events` logged and continued, and a newer deposit in the same batch
  could then advance the cursor past the un-fetched signature — the next poll's
  `until` boundary and the persisted cursor excluded it durably, so this instance
  never indexed that finalized deposit. `fetch_events` now propagates the fetch
  error (like its other RPC-error paths) so the cursor cannot advance past an
  un-fetched signature; the next poll re-fetches it and re-processing is
  idempotent at the pool. Off-chain listener-index correctness only — the deposit
  is on-chain, the on-chain merkle tree holds its commitment, and settlement
  verifies against the on-chain root, so the skip degraded local pool
  metrics/index (operator-recoverable), not funds, spends, or settlement. Devnet,
  pre-mainnet.

- **Vote eligibility and co-signers are intersected with the active validator
  set** (external bug-bounty report, billythebotman). The reputation-preservation
  fix (below) keeps a validator's durable standing across a disconnect, but the
  tally's eligibility (`count_eligible_votes` / `consensus_result` /
  `valid_voters`) filtered by reputation alone, without checking that the voter is
  still in the coordinator's active set. So a validator could vote, leave the
  active set, and keep its stale vote counting — completing a quorum whose co-sign
  set can no longer include the departed signer, stranding that settlement.
  Eligibility and the returned co-signer set are now intersected with a snapshot
  of the current active validator set, so only validators that are both active and
  above the reputation floor count. Off-chain consensus correctness only — the
  on-chain stake-weighted quorum and proof verification were never affected.
  Devnet, pre-mainnet.

- **Initiator records encrypted notes only after self-verify and once per
  settlement** (external bug-bounty report, leansearch0). The record-once gate
  that landed for the mesh path (below, #382) was not applied on the initiator
  path: `initiate_transact_verification` recorded the encrypted output notes
  before its own proof self-verify and without the first-seen canonical-id check,
  so an invalid proof could leave notes on the initiator and a replay with mutated
  (non-proof-bound) ciphertexts could add rows for the same commitment and
  eventually FIFO-evict the authentic ciphertext. The initiator now records only
  inside the verified (`Ok(true)`) branch and only the first time it sees a
  canonical settlement, matching the mesh path. Off-chain note-delivery integrity
  only — no on-chain, fund, or double-spend impact. Devnet, pre-mainnet.

- **Nullifier storage-failure log now truncates the nullifier** (log-hygiene
  suggested by rinonism). On an `insert_nullifier` persistence error the handler
  logged the full hex nullifier; it now logs only the first 8 bytes. This is
  defense-in-depth, not a privacy fix — a nullifier is already public (broadcast
  in the gossiped transact request, emitted in the on-chain `TransactEvent`, and
  used as the on-chain nullifier PDA seed), so the log never exposed anything not
  already on chain. Aligns the nullifier log with the deposit listener's
  address-truncation convention. Devnet, pre-mainnet.

- **Validator reputation is preserved across disconnect/reconnect** (external
  bug-bounty report, billythebotman). The 30-second connectivity reconciler
  removed a dropped peer from the transact-consensus coordinator, and that
  removal also deleted the validator's `ReputationTracker` entry; a reconnect
  recreated it at `BASE_REPUTATION`. A validator penalized below the
  consensus-eligibility floor could therefore erase its Byzantine history and
  regain eligibility by disconnecting for any duration and reconnecting.
  Connectivity and security history are now separate lifecycle state:
  `unregister_validator` drops the peer from the active voter set and leader
  selection but preserves its reputation metrics, so a penalized validator stays
  penalized across reconnects (reputation only decays with inactivity, it never
  rises back over the floor). Off-chain only — the stake-weighted on-chain quorum
  and the Groth16 proof check are independent, so no funds were ever at risk;
  this closes an off-chain consensus-integrity/liveness defect. Devnet,
  pre-mainnet.

- **Removed the legacy off-chain Merkle path-query server** (hardening
  suggested by WakiyamaP alongside the reorder report). The `/merkle/path` HTTP
  server served inclusion paths from the off-chain shielded pool, but that pool
  uses a pre-v3 commitment scheme and is not populated by v3 `deposit_note`
  deposits — v3 clients derive their Merkle path directly from the program-owned
  on-chain incremental tree, which is authoritative and gates settlement via
  `is_known_root`. The server was dead plumbing on the v3 path, and keeping it
  risked silently re-exposing the off-chain tree's reconstruction. Removing it
  makes that unreachable by construction; no v3 client used it. Devnet,
  pre-mainnet.

- **Off-chain shielded-pool tree reconstructs in numeric-index order**
  (external bug-bounty report, WakiyamaP). Commitment leaves are stored keyed by
  `index.to_le_bytes()`, and `get_all_commitments()` rebuilt the tree by
  iterating RocksDB in bytewise key order while discarding the key. For a `u64`
  little-endian key, bytewise order matches numeric order only up to index 255,
  so a pool with 257+ commitments reconstructed in a permuted order after a
  restart, changing the off-chain tree's reported root. Reconstruction now
  decodes each key and sorts by numeric index (migration-free). No fund impact:
  v3 settlement verifies proofs against the program-owned on-chain
  incremental-tree root (`request.root` + on-chain `is_known_root`), not the
  off-chain pool root, so no withdrawal was ever gated on the permuted off-chain
  tree; this closes an off-chain reconstruction defect and its reported root.
  Devnet, pre-mainnet.

- **Equivocation is detected on the vote decision, not its wording** (in-house
  pattern audit prompted by the external bug-bounty findings). `VoteTally` flagged
  equivocation by whole-vote equality, so a validator's own two `Invalid` votes
  differing only in their free-text `reason` read as equivocation and
  self-penalised its reputation. Equivocation is now the Valid/Invalid decision
  flipping, so re-worded Invalid votes are idempotent. Off-chain robustness only.
  Devnet, pre-mainnet.

- **Transact verification requests are keyed by a content-bound id**
  (external bug-bounty report). The off-chain `request_id` on a transact
  verification request was a caller-chosen string, not derived from the
  settlement, so a connected mesh peer could choose an id to overwrite a cached
  verification or collide two distinct transacts onto one round — halting a
  targeted settlement round and making an honest validator's Valid-then-Invalid
  votes read as equivocation (reputation griefing). The id is now the canonical
  domain-separated digest of the settlement-bound fields (root, recipient,
  signed external amount, nullifiers, output commitments, proof); it is set at
  ingress and re-validated on receipt, so an exact replay is idempotent and any
  mutation yields a different, isolated id. Off-chain liveness only — the
  on-chain stake-weighted quorum, proof verification, and nullifier PDAs were
  never affected. Devnet, pre-mainnet (reported in #383).

- **Encrypted output notes are recorded once per settlement** (external
  bug-bounty report). The recipient-scan buffer recorded a transact's encrypted
  output-note ciphertexts on every verified sighting, de-duplicated by
  `(commitment, ciphertext)`. Because the ciphertexts are not proof-bound, a
  replay of the same valid transact with mutated ciphertexts produced a new
  record for the same commitment, so a replayer could pollute the bounded scan
  store and eventually evict authentic ciphertexts. The buffer now records only
  the first sighting of a canonical settlement (keyed by the content-bound
  request id), so mutated replays are ignored. Off-chain note-delivery
  integrity only — no on-chain, fund, or double-spend impact. Binding the
  ciphertexts into the proof is a tracked pre-mainnet hardening. Devnet,
  pre-mainnet (reported in #382).

- **Bridge freeze and authority rotation moved to the cold authority**
  (in-house pre-bounty audit). `pause` / `unpause` / `set_bridge_authority`
  were authorized by `bridge_state.authority` — which by design is a
  node-resident settlement key kept on a public host, safe to expose only
  because settlement (`transact`) additionally requires an independent
  stake-weighted validator quorum. But the freeze and rotation instructions
  were not quorum-gated, so a single compromise of that deliberately-hot key
  could freeze all deposits and settlement, or rotate the authority away and
  leave recovery only to a full program upgrade. These three instructions are
  now gated on the cold registry authority (the upgrade key, kept off the
  settlement host), so the hot key retains only its quorum-gated settlement
  role. No funds were ever at risk — vault balances are unaffected and always
  recoverable; this is an availability and operational-continuity fix. Devnet,
  pre-mainnet (PR #380).

- **Validator stake is locked for an unbonding period, not instantly
  refundable** (in-house security audit). Validator registration is
  permissionless at the minimum stake, and `unregister_validator` returned the
  full stake immediately with no lockup — so the Sybil resistance the
  stake-weighted quorum relies on (controlling a supermajority of stake being
  expensive) cost almost nothing: a party could register validators, use them
  to co-sign a settlement, and reclaim the stake in the very next transaction,
  never leaving it at risk. Unregistering (and a slash that deactivates a
  validator) now stop it counting toward the quorum immediately but withhold
  the staked lamports for an unbonding window (~1 day), released only by a new
  `withdraw_unbonded_stake` instruction after the delay — so the stake stays
  locked and slashable through the window in which any misbehavior it co-signed
  can be proven. A deactivating slash routes the unslashed remainder into the
  same unbonding path so honest residual capital is not stranded. This closes
  the "free to weaponize" property; evidence-based automatic slashing of an
  equivocating co-signer is a tracked follow-up, with the admin slash remaining
  the interim backstop (now meaningful because the stake is still reachable).
  Devnet, pre-mainnet (PR #375).

- **The settlement quorum is an independent, consistent factor** (in-house
  security audit). The on-chain validator quorum counted any active validator
  PDA that co-signed, weighted by stake, against the registry's recorded total
  active stake. Two gaps: the settling authority's own validator counted toward
  its own quorum, so the quorum was not an independent second factor from the
  settlement key; and because an earlier registry reset rebuilt the stake
  counter while leaving the excluded validators active on-chain, the recorded
  total could drift below the set of PDAs still eligible to sign — letting a
  stale-low threshold be cleared by stake it did not account for. Both required
  the settlement authority key (there was no external attacker path, and it was
  the documented pre-mainnet single-operator trust model), but the quorum was
  not the independent backstop it was meant to be. `verify_validator_quorum`
  now excludes the settling authority from both the tally and the denominator
  and rejects a counted stake above the eligible active total; a new admin
  `deactivate_validator` instruction flips orphaned active PDAs inactive so the
  recorded total and the live active set stay consistent. The threshold stays
  appropriately low for a small honest validator set — it just can no longer be
  satisfied by the settlement key alone or by orphaned PDAs. Bonding/slashing to
  make Sybil stake non-refundable is a tracked follow-up. Devnet, pre-mainnet
  (PR #373).

- **Shielded withdrawals verified against an operator-published Merkle root**
  (in-house security audit). The legacy `update_merkle_root` instruction set
  the pool's Merkle root to whatever value the settlement authority passed —
  gated by the validator quorum but with no zk proof — and `withdraw` /
  `shielded_transfer` / `withdraw_spl` then verified their proofs against that
  operator-set root. Because the pre-mainnet quorum is authority-satisfiable,
  a party holding the settlement key could have published a root committing a
  note that did not correspond to any real deposit and settled it: value out
  with no matching value in. The legacy off-chain root was also never
  reconciled on-chain against deposit accounting. Fixed by removing the entire
  off-chain-root path; all shielded operations now settle through the v3
  `transact` instruction, which appends the output commitments and recomputes
  the Merkle root itself on a program-owned tree and only accepts proofs
  against roots it has published (`is_known_root`), so no root can enter
  without the program having built it — the trusted off-chain root push is
  gone. SPL settlement is temporarily native-only pending the v3 per-asset
  follow-up. Devnet, pre-mainnet (PR #371).

- **The settlement co-sign set is the same reputation-eligible set that formed
  the quorum** (in-house security audit). A withdrawal or transfer reached
  consensus among the validators whose reputation was at or above the
  threshold, but the leader then collected on-chain co-signatures from every
  validator that had voted `Valid` — including ones the quorum count had
  excluded for low reputation. The on-chain program still re-checks each
  co-signer against its staked, active validator account, so no unstaked party
  could contribute a settling signature and no funds were reachable; the
  mismatch let a validator the quorum had discounted still be asked to sign.
  `valid_voters` is now gated on the same reputation view `has_consensus` and
  `consensus_result` use, so the co-sign set matches the set that formed the
  quorum. Devnet, pre-mainnet.

- **Verification-round ids derive from the full nullifier** (in-house security
  audit). A round id was `ingress-<timestamp>-<first 8 bytes of nullifier>`, so
  two distinct withdrawals submitted in the same second whose nullifiers shared
  an 8-byte prefix would collide onto one id and clobber each other's
  verification round — a liveness hazard, not a fund path (the nullifier itself
  still gates on-chain replay). The id now carries the full 32-byte nullifier,
  which is unique per spend, so distinct spends can never share a round id.
  Devnet, pre-mainnet.

- **Ceremony finalization fails closed** (community responsible disclosure to
  security@paraloom.network, independently overlapping an in-house audit
  finding). `paraloom_ceremony_finalize` verified that a transcript's
  contribution chain was cryptographically honest, but imposed no floor on
  what it would promote: an empty transcript verified vacuously, and for an
  empty transcript the final-key binding accepted the initial single-party
  key itself as the "ceremony output" — so a finalize run against the wrong
  or never-contributed files could have promoted a key whose trapdoor one
  party still held. Finalize now refuses an empty transcript, enforces a
  minimum contribution count, requires an operator-pinned SHA-512 of the
  initial proving key to match both the transcript's recorded initial SRS
  hash and the file on disk, rejects a final key whose delta is unchanged
  from the initial key, and can pin the expected chain-tip contribution
  hash. Contributor signature enforcement remains a mainnet-ceremony gate
  (#64). Caught before any finalize was ever run — the live devnet
  transcript passes every new gate. Devnet, pre-mainnet.

## 2026-06

- **Bearer-token ingress auth compares in constant time** (in-house security
  audit). The optional ingress bearer token was compared with `==`, which
  short-circuits on the first differing byte and leaks a per-byte timing signal
  on the shared secret. The token only authorizes still-proof-gated,
  still-quorum-gated relaying — not a signing key — and defaults to no token on
  a loopback interface, so no funds were at risk; the comparison is now
  constant-time regardless. Devnet, pre-mainnet.

- **A co-signer pins the settlement program to its own configuration** (in-house
  security audit). The co-signing validator rebuilt and signed the settlement
  message from the requester-supplied payload without checking that the
  payload's program id matched its own configured program — so any peer that had
  seen a legitimate verification round could obtain a genuine signature by the
  validator's settlement wallet over a message invoking an attacker-chosen
  program. No paraloom funds were reachable (the on-chain program re-derives its
  PDAs and binds the proof, and quorum wallets are appended as read-only
  signers), but the signature was a cross-program oracle. The co-signer now
  declines any payload whose program id is not the one it configured. Devnet,
  pre-mainnet.

- **Timed-out verification requests are swept from the consensus pending maps**
  (in-house security audit). The withdrawal and transfer verification
  coordinators inserted each incoming request into an in-memory `pending` map,
  but the `cleanup_timeouts` routine that removes requests which never reach
  quorum was never called — so the maps grew for the process lifetime, and a
  flood at the (loopback, token-gated) ingress could exhaust memory and stop the
  node co-signing. A periodic sweeper now drives `cleanup_timeouts` on both
  coordinators (transfer gained the routine, mirroring withdrawal), reclaiming
  timed-out entries. Availability only — no funds were at risk, as settlement
  still requires a valid proof and an on-chain quorum. Devnet, pre-mainnet.

- **The deposit listener credits a deposit only once it is finalized** (in-house
  security audit). The listener enumerated and credited program deposits at the
  `confirmed` commitment, which is not rooted: a deposit credited at confirmed
  and then orphaned by a fork-choice switch would leave the shielded pool's
  supply believing more value exists than the on-chain vault custodies. The
  listener now enumerates at `finalized`, so a deposit is credited only once it
  can no longer be reorged — a few seconds of added deposit latency bought for
  reorg safety. No funds were at risk on devnet. Devnet, pre-mainnet.

- **SPL deposits credit their own asset's shielded supply** (in-house security
  audit). The deposit listener built each note asset-aware — binding the real
  mint into the commitment — but then indexed it through the native-SOL supply
  helper, so an SPL deposit credited the native-SOL supply ledger instead of the
  mint's: `supply_of(mint)` stayed zero while the gossiped `total_supply` was
  inflated by the token amount. Accounting and state-visibility only — on-chain
  custody is gated by the program's per-asset vaults, and no settlement path
  consulted the off-chain per-asset supply, so no funds were affected. The
  listener now credits the deposit's own asset, with a regression test asserting
  an SPL deposit credits the mint and leaves native SOL at zero. Devnet,
  pre-mainnet.

- **Approved transfers settle through the validator co-signing quorum**
  (in-house security audit). The transfer twin of the withdrawal fix: the node
  settled quorum-approved shielded transfers single-key, which cannot meet the
  program's #260 supermajority on a multi-validator network. The transfer
  submitter now gathers the approving validators' signatures into one multi-sig
  `shielded_transfer` transaction and submits that, so a transfer is authorised
  by the same quorum the program checks; the single-key fallback still applies
  when no co-signing key is configured. Devnet, pre-mainnet.

- **Approved withdrawals settle through the validator co-signing quorum**
  (in-house security audit). The on-chain program gates settlement on a #260
  validator supermajority, but the node still submitted approved withdrawals
  signed by a single key — so on a multi-validator network one key could never
  meet the quorum (settlement would simply fail), and the live path never
  exercised the BFT co-signing the quorum exists to enforce. The withdrawal
  submitter now gathers the approving validators' signatures into one multi-sig
  transaction and submits that, so settlement is authorised by the same quorum
  the program checks; a solo operator with no co-signing key still falls back to
  the single-key path. Controlled by a `use_cosign_settlement` config flag
  (default on). Devnet, pre-mainnet.

- **The deposit listener retries a deposit that failed to process** (in-house
  security audit). The listener advanced its scan cursor to the last
  successfully processed signature, so a deposit that hit a transient error
  while a later deposit in the same batch succeeded was stepped over by the next
  poll's boundary and never retried — its funds sat in the vault, indexed by no
  shielded note and therefore unwithdrawable. The cursor now advances only
  through the unbroken run of successes, stopping before the first failure, and
  the failed signatures are re-fetched and retried on the next poll. So the
  retry cannot double-index a deposit, a pool deposit is now idempotent: a
  commitment already in the pool is a no-op instead of a duplicate Merkle leaf
  and a double-credited supply. Devnet, pre-mainnet.

- **The deposit listener resumes from a durable cursor across restarts**
  (in-house security audit). The listener tracked its scan cursor — the last
  processed signature — only in memory, so a restart reset it and re-scanned
  from the chain tip; any deposit that landed while the node was down and was
  older than the newest batch was never indexed and silently lost. The cursor
  is now written to a file under the node's data directory after each advance
  (atomically, via a temp file plus rename) and reloaded on start, so a restart
  resumes exactly where it left off. A missing or corrupt cursor cold-starts
  rather than refusing to boot. Devnet, pre-mainnet.

- **The deposit listener paginates a backlog larger than one batch** (in-house
  security audit). The listener polls `getSignaturesForAddress`, which returns
  the newest transactions capped at a batch limit. When more program
  transactions than one batch accumulated since the last cursor — a burst of
  activity, or resuming after the node was down — a single call returned only
  the newest batch, and deposits older than it (but newer than the cursor) were
  never fetched and silently lost. The listener now walks older pages with the
  `before` boundary until a short page reaches the cursor, bounded by a generous
  page cap that logs loudly rather than dropping the tail silently; a cold start
  with no cursor still scans only from now. Devnet, pre-mainnet.

- **The private-swap relayer trades the realized post-fee amount** (in-house
  security audit). The relayer withdraws a shielded note to a fresh ephemeral
  address and then swaps from it, but the on-chain withdraw deducts the 25bps
  protocol fee, so the fresh address receives `amount - fee` — not the gross
  note value the swap leg asked the router to trade. On a real submitter the
  swap would exceed the fresh address's balance and fail *after* the note's
  nullifier was already burned on-chain, stranding the funds with no way to
  retry. The relayer now computes the realized post-fee amount (and, for a
  native input, subtracts the rent/fee overhead reserve from that) before
  routing the swap. Devnet, pre-mainnet.

- **Publishing a Merkle root requires a validator quorum** (in-house security
  audit). The bridge state's published Merkle root anchors every withdrawal
  proof, but the `update_merkle_root` instruction was gated only by a single
  authority key — so one key could install an arbitrary root (for a forged tree
  or an old state that un-spends a nullifier) and then withdraw against it,
  draining the vault. The instruction now requires the same BFT validator
  quorum (#260) as `withdraw` and `shielded_transfer`: the new root must be
  co-signed by a supermajority of registered validators, each of which
  recomputes the appended root before signing. A unit test proves the rejection
  without a quorum and the positive control once a quorum co-signs. Devnet,
  pre-mainnet.

- **SPL deposits are indexed into the shielded pool** (in-house security
  audit). The bridge listener decoded only the native deposit instruction, so an
  SPL deposit moved real tokens into a per-asset vault but no shielded note was
  created and no commitment was ever inserted into the pool — the deposit's
  Merkle path could not be found and an SPL withdrawal could never prove
  membership, stranding the tokens in the vault. The listener now also decodes
  the `deposit_spl` instruction, binding the mint as the deposit's asset id, and
  creates the note asset-aware so it is indexed under its asset and is
  withdrawable through `withdraw_spl`. Devnet, pre-mainnet.

- **Removed an admin instruction that could credit unbacked validator rewards**
  (in-house security audit). A standalone `distribute_fee` instruction let the
  bridge authority add an arbitrary amount to any validator's pending rewards,
  which `claim_rewards` then pays out of the bridge vault where native deposits
  are held — so a single key could credit and withdraw funds it never earned.
  The instruction was redundant: the withdrawal path already credits the
  settling validator its real fee, the only legitimate source of pending
  rewards, and no production code path ever called `distribute_fee`. The
  instruction and its accounts were removed; reward claiming is unchanged and is
  now exercised over the real flow (a withdrawal credits the fee, then it is
  claimed). Devnet, pre-mainnet.

- **Shielded transfers settle only a Merkle root consistent with their own
  commitments** (in-house security audit). A shielded transfer advances the
  pool's published Merkle root to a post-state value, but that value was carried
  through from the client request and never checked against the output
  commitments the transfer actually adds — the root is not one of the proof's
  public inputs. A settling party could therefore advance the published root to
  a tree of its own construction. Verifying validators now recompute the root
  the transfer's output commitments produce (a non-mutating preview of the tree)
  and refuse to approve a transfer whose proposed root differs, so an honest
  quorum will not settle a root inconsistent with the transfer. Devnet,
  pre-mainnet — the live program still settles under a single key; this lands
  ahead of the quorum-wired deployment, and a deeper in-circuit binding of the
  post-insertion root is tracked for mainnet hardening.

- **Withdraw proofs bound to their asset and destination on-chain**
  (in-house security audit). The on-chain withdraw verifier checked a proof
  against the published Merkle root, nullifier and amount — but not the asset
  being released or the recipient being paid. A settling validator could
  therefore present a real note's proof while releasing a different asset's
  vault, or pay the proven note out to a recipient of its choosing. The
  spend-key circuit v2 adds both as public inputs, and the program now derives
  them on-chain from the accounts the instruction acts on, so neither can be set
  by the submitter: the released vault's mint becomes the proof's asset id (a
  note committed under one mint cannot release another's vault), and a hash of
  the actual recipient and amount becomes its external-data hash (the payout
  cannot be redirected). This lands in the program ahead of the devnet redeploy
  and pool reset that put circuit v2 live. Part of #293; covered by verifier
  tests that reject a mismatched asset or destination and by integration tests
  across the native and SPL withdraw paths.

- **Ceremony key's query vectors checked against the cumulative delta**
  (in-house security audit). The deeper consistency check the entry below
  deferred is now in place. Binding the final key's delta to the transcript
  stopped a wholly substituted key, but not one that kept the correct delta
  while leaving its internal query vectors inconsistent with it — a malformed
  proving key that could leave the Groth16 trapdoor recoverable. Finalize now
  verifies, in the exponent via a pairing, that those vectors were divided by
  exactly the cumulative delta the contribution chain produced, and that every
  delta-independent element is unchanged. The MPC ceremony remains a hard
  pre-mainnet gate; fixed in the tooling before it runs, covered by tests that a
  consistent key passes and unscaled or tampered vectors are rejected.

- **Ceremony finalize binds the promoted key to the verified transcript**
  (in-house security audit). The trusted-setup finalize tool verified the
  contribution transcript end-to-end, but then wrote the proving key it was
  handed without checking that key against the transcript. An operator could
  therefore pair an honest, fully-verified transcript with an arbitrary,
  separately-generated proving key, and finalize would promote it to a
  production key — the path by which a trapdoored verifying key could reach the
  chain. Finalize now additionally requires the key's delta to equal the delta
  the verified contribution chain culminates in, so a substituted key carrying
  any other delta is refused before anything is written. (A deeper consistency
  check on the key's internal query vectors against the cumulative delta remains
  tracked separately.) The MPC ceremony is still unexecuted and remains a hard
  pre-mainnet gate; fixed in the tooling before it runs, covered by tests that a
  matching key passes and a substituted key is rejected.

- **Transfer scan buffer recorded only after the proof verifies, and bounded**
  (in-house security audit). A gossiped transfer-verification request had its
  encrypted output notes recorded into the node's in-memory scan buffer *before*
  the zk proof was verified, so any peer could broadcast an unverified (garbage)
  transfer and pollute the buffer that recipients poll. Recording now happens
  only after the proof verifies on the gossip path, and the buffer is bounded
  (oldest-evicted at a fixed cap) so a high volume of transfers cannot grow it
  without limit. Fixed pre-mainnet on devnet; covered by a test that a gossiped
  transfer with an unverifiable proof records no notes.

- **Bearer-token auth for the consensus-triggering ingress endpoints** (in-house
  security audit). The withdrawal and transfer HTTP ingress endpoints each accept
  a request and broadcast it into the consensus mesh — a write surface — but were
  unauthenticated. They default to disabled and are meant for a loopback /
  management interface, yet an operator who exposed one beyond loopback had no
  way to require a caller to authenticate. A shared bearer token
  (`bridge.ingress_token` / `BRIDGE_INGRESS_TOKEN`) can now be configured; when
  set, `POST /withdrawal/submit` and `POST /transfer/submit` require
  `Authorization: Bearer <token>` and refuse a missing or incorrect token with
  401 before doing any work. With no token configured the behaviour is unchanged
  (still default-disabled). The read-only transfer scan route is not gated, as it
  is not a consensus write surface. Fixed pre-mainnet on devnet; covered by tests
  that a configured token rejects an unauthenticated submit and accepts an
  authenticated one.

- **Blocking dependency-advisory gate in CI** (in-house security audit). The
  repository's only dependency scan was a Snyk job that runs with
  `continue-on-error`, so a newly published advisory in the dependency tree
  never failed a build. A `cargo-deny` advisories check now runs on every push
  and pull request (and weekly), and it fails the build on any RUSTSEC advisory
  not already accounted for. The advisories present in the tree today — all
  transitive through the Solana SDK, the libp2p networking/TLS/QUIC stack, or the
  crypto stack, and none removable without an upstream bump — are enumerated and
  annotated in `deny.toml` and tracked for resolution on future dependency bumps.
  Anything new fails CI, which is the point of the gate. Defense-in-depth
  hardening; the gate runs in CI pre-mainnet on devnet.

- **Slashing a validator below the minimum stake deactivates it** (in-house
  security audit). `slash_validator` reduced a validator's recorded stake and
  moved the slashed lamports to the vault, but left the validator `is_active` and
  still counted in the registry's `active_validators` — the number the BFT
  settlement quorum is sized against. So a validator slashed to (or below) zero
  stake kept counting toward the quorum and could still co-sign settlements, even
  though registration requires meeting a minimum stake. A slash that drops stake
  below the registry minimum now clears `is_active` and decrements
  `active_validators` (guarded so a validator slashed twice is not
  double-decremented), so a depleted validator stops settling and stops counting.
  Fixed pre-mainnet on devnet; covered by tests that a sub-minimum slash
  deactivates and decrements the active set, while a slash that stays above the
  minimum keeps the validator active.

- **Wallet key files written owner-only** (in-house security audit). The CLI's
  `wallet new-address` wrote the generated spending key to
  `.paraloom/keys/<label>.key` with a plain write, so the file landed at the
  process umask — commonly world- or group-readable (0644/0664) — even though it
  holds the private key. The bridge's `save_keypair_to_file` helper had the same
  gap. Key files and the keys directory are now created owner-only on Unix — 0600
  for the file, 0700 for the directory — so a spending key is never left readable
  by other local users. Fixed pre-mainnet on devnet; covered by a test asserting
  a saved key file is mode 0600.

- **Shielded transfer marked spent only after on-chain settlement** (in-house
  security audit). The transfer twin of the withdrawal spend-after-settle fix
  below: the transfer submitter applied the settlement to its local pool —
  marking the input nullifiers spent and appending the output commitments —
  **before** submitting the on-chain `shielded_transfer`, with no rollback on
  failure. A transient submit failure (an RPC error, an expired blockhash, a
  momentary quorum miss) left the input notes marked spent locally while they
  stayed unspent on-chain, so every retry was rejected locally as "already
  spent", freezing them. The submitter now submits on-chain first and applies to
  the local pool only on success; a read-only nullifier pre-check still
  fast-fails an obvious replay before paying RPC fees, and the on-chain nullifier
  PDAs remain the authoritative double-spend defence. Fixed pre-mainnet on
  devnet; covered by a test asserting a failed transfer submit leaves the inputs
  spendable.

- **Co-sign settlement assembly rejects an oversized validator set** (in-house
  security audit). A co-sign request arrives over the network carrying the
  quorum validator set used to rebuild the settlement transaction every
  co-signer signs. Each validator contributes two accounts to the transaction,
  and a Solana message indexes its accounts with a single byte — so a set large
  enough to push past the 255-account limit would panic the message compiler
  while building, crashing the node before any signature or settlement check
  ran. Because the set came straight off the wire, a peer could send an
  oversized quorum to crash a node reachable on the co-sign protocol. The
  builder now rejects any quorum above a fixed maximum (100 — far beyond any
  realistic BFT quorum, and well under the transaction-size limit that binds
  first) with a typed error instead of panicking. Fixed pre-mainnet on devnet;
  covered by a test that an oversized quorum returns an error and a quorum at the
  cap still builds.
- **SPL withdrawal fee no longer credited as native lamport rewards** (in-house
  security audit). The native `withdraw` credits its lamport fee to the settling
  validator's `pending_rewards`, which `claim_rewards` later pays out in lamports
  from the native bridge vault. The SPL twin `withdraw_spl` mirrored that line —
  but its fee is denominated in the withdrawn SPL *token*, and those fee tokens
  already stay behind in the per-asset token vault. Crediting the token fee 1:1
  into the lamport-denominated `pending_rewards` mixed asset units: a validator
  settling SPL withdrawals accrued lamport-claimable rewards in proportion to
  token raw amounts, letting it draw down the native SOL vault through
  `claim_rewards` independent of any SOL the fee was worth. `withdraw_spl` no
  longer touches `pending_rewards`; the SPL fee tokens accrue in the per-asset
  vault for a future per-asset payout, and the settlement is still recorded
  against the validator's activity. Fixed pre-mainnet on devnet; the SPL withdraw
  test now asserts the native lamport `pending_rewards` stays zero while the fee
  tokens remain in the vault.

- **Unauthenticated shielded-transaction gossip no longer mutates pool state**
  (in-house security audit). One gossip message variant carried a shielded
  transaction that the node applied straight to its local shielded pool —
  marking nullifiers spent and appending output commitments — with no zk-proof
  verification and no authentication of the sender. No honest code path ever
  publishes this message: deposits, transfers and withdrawals settle through the
  proof-gated verification-request path, so the variant was an unauthenticated,
  untrusted ingress. A peer on the gossip mesh could mark arbitrary nullifiers as
  spent (freezing honest users' notes) or append junk commitments (perturbing the
  node's local Merkle root, which proof verification is checked against). The
  off-chain pool is not the source of truth — on-chain settlement stays
  proof-gated — so funds were never directly at risk, but the path enabled
  griefing and could degrade a node's local verification view. The handler now
  drops the message without touching pool state; the wire variant is retained so
  deployed nodes' message framing stays stable. Fixed pre-mainnet on devnet;
  covered by a test that a gossiped withdraw does not mark its nullifier spent and
  a gossiped transfer changes neither the commitment count nor the Merkle root.

- **Native-SOL swap output reconciled against the realized balance** (in-house
  security audit). When a private swap's output was native SOL, the relayer
  re-shielded the **quote estimate** rather than the amount actually delivered.
  An over-quote (ordinary slippage) meant the re-deposit asked for more lamports
  than the ephemeral held — the deposit failed, and because the input note's
  nullifier was already spent, the funds were stranded at the relayer-generated
  ephemeral address. The relayer now reads the ephemeral's realized lamport
  balance and re-shields that minus a small reserve for the re-deposit fee
  (mirroring the SPL-output path), falling back to the quote only when the
  balance can't be read. Fixed pre-mainnet on devnet; covered by a test that an
  over-quote re-shields the realized balance, not the quote.

- **Relayer no longer double-charges the swap fee** (in-house security audit).
  The private-swap relayer applied its fee twice: the swap provider took its
  `platformFeeBps` inside the route — so the swap output already excluded it —
  and then the orchestrator deducted `fee_bps` again from that output before
  re-shielding, silently shrinking the user's note by an extra cut that reached
  no one. The fee is now realized once, in-route by the provider; the
  orchestrator re-shields the full swap output. Latent today (the demo sets both
  fees to zero), but it would have bitten the first real fee. Fixed pre-mainnet
  on devnet; covered by a test that the orchestrator takes no second cut.

- **Equivocation now costs the validator reputation** (in-house security audit).
  A validator that cast two disagreeing votes on the same request had its
  equivocation recorded as evidence but kept its full reputation — so provable
  misbehaviour carried no off-chain consequence and the equivocator was never
  gated out of consensus. The withdrawal and transfer coordinators now lower the
  equivocator's reputation on detection, so repeated equivocation drops it below
  the consensus-eligibility floor and its votes stop counting. (Slashing the
  recorded stake on-chain remains a separate stake-economic-security item for
  mainnet.) Fixed pre-mainnet on devnet; covered by a test that an equivocating
  validator's reputation drops.

- **Bounded reads on the compute request-response codecs** (in-house security
  audit). The compute job/query codecs read inbound payloads with an unbounded
  `read_to_end`, where every sibling protocol (result, heartbeat, co-sign) caps
  its reads to stop a peer pinning the heap with an unbounded stream. The codecs
  are not currently wired into the live swarm, so this was a latent landmine
  rather than a reachable DoS — the reads are now size-bounded to match the
  siblings, disarming it before the protocol is ever enabled. Fixed pre-mainnet
  on devnet; covered by accept/reject tests.

- **Settlement RPC call bounded by a timeout** (in-house security audit). The
  bridge's `send_and_confirm_transaction` wrapped the blocking RPC call with no
  caller-side timeout; the client's confirmation loop polls until the blockhash
  expires, so a stalling or lagging RPC could block the settlement path for many
  minutes before erroring. The call is now bounded by a 120-second timeout that
  returns a typed error promptly, keeping a single stuck settlement from wedging
  the submitter pipeline. Combined with the spend-after-settle ordering above, a
  timed-out settlement leaves the note spendable for a retry. Fixed pre-mainnet
  on devnet; covered by a test that a stalled call returns promptly.

- **Overflow checks enabled for release/SBF builds** (in-house security audit).
  The on-chain program is its own Cargo workspace root, which detached it from
  the Anchor template's release profile — so release/SBF builds compiled with
  overflow checks off, and an arithmetic overflow on a balance, counter, or
  validator reward would wrap silently instead of panicking. Release builds now
  set `overflow-checks = true`. The flagged arithmetic is lamport-bounded or
  monotonic (so no concrete overflow is reachable today), making this
  defense-in-depth hardening; fixed pre-mainnet on devnet.

- **Withdrawal note marked spent only after on-chain settlement** (in-house
  security audit). The submitter recorded a withdrawal's nullifier as spent in
  the local pool **before** submitting the settlement on-chain, with no rollback
  on failure. So a transient submit failure — an RPC error, an expired
  blockhash, a momentary quorum miss — left the note marked spent locally while
  the funds stayed in the vault: every retry was then rejected as "already
  spent", freezing the note. The submitter now settles on-chain first and
  records the spend only on success, so a failed submit leaves the note
  spendable for a retry (the on-chain nullifier PDA remains the double-spend
  defence). Fixed pre-mainnet on devnet; covered by a test asserting a failed
  submit does not mark the note spent.

- **Verification votes bound to their authenticated sender** (in-house security
  audit). A withdrawal/transfer verification result carries a self-declared
  `validator` field. The node previously routed it into the consensus tally
  without checking it against the authenticated gossip publisher, so a single
  peer could submit votes under other validators' identities — fabricating an
  off-chain quorum or framing an honest validator for equivocation. Gossipsub
  runs in signed mode, so the node now attributes each message to its
  authenticated publisher and drops any vote whose claimed validator does not
  match the sender. (On-chain settlement separately requires genuine validator
  co-signatures, so this hardens the off-chain consensus layer.) Fixed
  pre-mainnet on devnet; covered by a test that drops a forged vote and counts a
  genuine one.

- **Canonical nullifier encoding enforced on-chain** (in-house security audit).
  A nullifier is reduced modulo the BN254 scalar field to form the proof's
  public input, but the replay defence — the nullifier PDA — keys on the raw
  bytes. So a spent note's nullifier `n` and its non-canonical re-encoding
  `n + p` (`p` = the field modulus) reduced to the same field element, verified
  under the same proof, yet derived different PDAs — a double-spend path. The
  program now requires the raw nullifier to be the canonical encoding of its
  field element (in `withdraw`, `withdraw_spl` and `shielded_transfer`),
  restoring the one-to-one byte↔field correspondence the off-chain code already
  maintained. Fixed pre-mainnet on devnet; covered by a test that settles a
  nullifier and asserts its non-canonical re-encoding is rejected.

- **SPL withdrawals brought to parity with the native withdraw gates**
  (in-house security audit). The native `withdraw` verifies both a registered-
  validator quorum and the Groth16 proof on-chain before releasing funds; the
  SPL twin `withdraw_spl` previously verified neither — its proof argument was
  only length-checked and its accounts carried no validator registry, so SPL
  settlement rested on the single bridge-authority key. It now verifies both the
  quorum and the proof (bound to the published Merkle root, nullifier and
  amount) before releasing tokens, matching the native path. Surfaced by the
  project's internal security audit and fixed pre-mainnet on devnet; covered by
  a test that asserts a withdraw with no quorum and one with an invalid proof
  are both rejected.

- **On-chain validator quorum for settlement**
  ([#260](https://github.com/paraloom-labs/paraloom-core/issues/260)).
  Settlement (`withdraw` and `shielded_transfer`) previously relied on a single
  settlement authority key (`has_one = authority`). The program now requires a
  BFT supermajority of registered validators to co-sign the transaction,
  verified on-chain against the validator registry. Each validator that approved the
  operation independently rebuilds the settlement transaction from the
  parameters it verified and signs that; the round leader only assembles the
  collected signatures. A single compromised settlement key can no longer move
  funds, and a malicious leader cannot redirect a withdrawal — a co-signer signs
  only a transaction it reconstructed from the parameters it saw, so a
  substituted recipient or amount is refused. This binds the recipient that the
  proof itself does not yet constrain.

- **On-chain proof verification for withdrawals and shielded transfers**
  ([#165](https://github.com/paraloom-labs/paraloom-core/issues/165),
  [#194](https://github.com/paraloom-labs/paraloom-core/issues/194)).
  The program previously recorded the Groth16 proof and relied on the off-chain
  validator quorum to verify it. It now verifies the proof itself, on-chain, via
  Solana's `alt_bn128` (BN254) syscalls — bound to the published Merkle root and
  the operation's nullifiers and amount/commitments. A settling validator can no
  longer forge or redirect a withdrawal or transfer despite holding the
  settlement authority.

- **Canonical field-element encoding at the proof-verify boundary**
  ([#231](https://github.com/paraloom-labs/paraloom-core/issues/231)).
  Adversarial circuit review found that non-canonical encodings of nullifiers and
  commitments could be accepted; encoding is now enforced canonical, closing a
  double-spend vector before mainnet.

## Earlier

- **Initialize front-run gate**
  ([#204](https://github.com/paraloom-labs/paraloom-core/issues/204)).
  The `initialize` instructions are pinned to the program's upgrade authority, so
  the bridge state cannot be initialized by a front-runner.

- **Withdraw settlement binding + proof-length bound**
  ([#178](https://github.com/paraloom-labs/paraloom-core/issues/178)).
  `has_one = authority` on `withdraw` plus a bound on the proof blob size.

- **Range constraints on values**
  ([#60](https://github.com/paraloom-labs/paraloom-core/issues/60)).
  In-circuit range constraints prevent forging value by assigning a
  near-field-prime amount.

- **Withdrawal replay protection**
  ([#61](https://github.com/paraloom-labs/paraloom-core/issues/61)).
  Each spent note is recorded as a nullifier PDA; re-spending the same nullifier
  fails on the already-initialized account.

- **Consistent commitment / nullifier derivation across circuits**
  ([#56](https://github.com/paraloom-labs/paraloom-core/issues/56)).
  Deposit, transfer, and withdraw derive commitments and nullifiers identically,
  so a note created on one path is spendable (and only once) on the others.

- **Graceful verifying-key load**
  ([#57](https://github.com/paraloom-labs/paraloom-core/issues/57)).
  A missing or malformed verifying key returns an error instead of panicking the
  node.
