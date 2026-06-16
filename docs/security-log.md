# Security log

A public record of security-relevant findings and the fixes that closed them.
Everything here was found and fixed **pre-mainnet, on devnet — no real funds
were ever at risk**. Newest first. Each entry links the public issue so anyone
can verify it.

This is the log referenced by [`SECURITY.md`](../SECURITY.md). To report a new
issue, email security@paraloom.network.

## 2026-06

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
