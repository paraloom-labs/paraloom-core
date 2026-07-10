# Security log

A public record of security-relevant findings and the fixes that closed them.
Everything here was found and fixed **pre-mainnet, on devnet — no real funds
were ever at risk**. Newest first. Each entry links the public issue so anyone
can verify it.

This is the log referenced by [`SECURITY.md`](../SECURITY.md). To report a new
issue, email security@paraloom.network.

## 2026-07

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
