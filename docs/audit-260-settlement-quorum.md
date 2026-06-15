# Internal security audit — settlement validator quorum (#260)

**This is an internal security audit by the project.** It records what was
examined, the properties the change is intended to hold, and the tests that back
each one, so a reader can verify every claim against the code. Everything below
is **pre-mainnet, on devnet — no real funds are at risk**.

- **Scope:** the move from a single settlement authority key to an on-chain BFT
  validator quorum with node-side co-signing — issue
  [#260](https://github.com/paraloom-labs/paraloom-core/issues/260), PRs
  #262–#270.
- **Out of scope:** the proving system and trusted setup (tracked separately),
  the off-chain consensus/networking stack beyond the co-sign path, and the
  on-chain `alt_bn128` proof verification (#165/#194).
- **Method:** code review of the merged path plus the adversarial tests linked
  below. Reviewer: the project (in-house).

## Trust model: before → after

Before, settlement (`withdraw` / `shielded_transfer`) was gated only by
`has_one = authority` — a single Ed25519 key. Whoever held that key could settle
any operation; a compromise of the one hot settlement key could move funds from
the vault.

After #260, the on-chain program requires a BFT supermajority
(`floor(2N/3)+1` of the `N` registered validators) to co-sign the settlement
transaction, verified on-chain against the validator registry
(`programs/paraloom/src/quorum.rs`). Each validator that approved the operation
**independently rebuilds the settlement transaction from the parameters it
verified and signs that**; the round leader only assembles the collected
signatures. No single key can settle alone.

## Properties verified

| # | Property | How it is enforced | Evidence |
| --- | --- | --- | --- |
| 1 | An under-quorum settlement is rejected on-chain | `verify_validator_quorum` counts signers whose canonical `[b"validator", wallet]` PDA is program-owned, active, and self-consistent; requires `counted ≥ floor(2N/3)+1` | `programs/paraloom/tests/withdraw_quorum_test.rs` — with 2 active validators, a 1-co-signer withdraw is rejected and a 2-co-signer withdraw settles (positive control) |
| 2 | A malicious leader cannot substitute the recipient or amount | a co-signer signs only a message it rebuilt from parameters it matched against the request it verified | `cosign_settlement` unit tests (PR #267): a substituted recipient is declined; an unknown request and a missing keypair are declined |
| 3 | A forged or wrong-message signature cannot reach the quorum | `gather_signatures` keeps a signature only if it verifies over the exact settlement message and comes from an expected wallet, deduped | `cosign_assembly` unit tests (PR #268): a forged signature is rejected and the threshold goes unmet |
| 4 | All co-signers sign identical bytes | the settlement message is rebuilt deterministically from a structured payload (program id, payer, blockhash, ordered co-signer set, parameters) | `cosign_message` unit tests (PR #266): same payload → byte-identical message; a changed parameter changes the bytes |
| 5 | The distributed round assembles a valid multi-signature transaction over a real network | leader requests each co-signer over `/paraloom/cosign`, then assembles | `tests/cosign_settlement_e2e.rs` (PR #270): two validators verify → cache → co-sign → the leader assembles a transaction that verifies with both signatures |
| 6 | The recipient the proof does not yet bind is bound at the co-sign layer | co-signers match the recipient against the gossiped request every validator saw | property of #2 — closes the open recipient-binding gap (#234) for the settlement path |

## Threat scenarios considered

- **Compromised single settlement key.** No longer sufficient to settle: the
  on-chain quorum requires a supermajority of distinct validator signatures
  (property 1).
- **Malicious round leader** proposing a transaction that pays a different
  recipient or amount. Honest co-signers refuse, because they sign a message
  they rebuilt from the parameters they verified, not the leader's bytes
  (properties 2, 4).
- **Byzantine co-signer** returning a forged or unrelated signature. It does not
  verify over the settlement message and is discarded; it cannot count toward
  the quorum (property 3).
- **Co-signer withholding its signature** (liveness, not safety). The round
  fails to reach threshold and the settlement is not submitted, rather than
  settling under-quorum (property 1, leader side).

## Known limitations and follow-ups

- **Not yet deployed to the live anchor.** The quorum-wired program, the live
  submitter cutover, and pruning the on-chain registry to the validators that
  actually run co-sign nodes must ship together; until then the deployed devnet
  program is still the single-key one. The code path is complete and tested.
- **Liveness under partial participation.** A round that cannot gather the
  threshold simply fails; automatic retry with a different co-signer subset is a
  follow-up.
- **An external audit is planned before mainnet** as an additional layer on top
  of this internal audit, the open-source code, and the adversarial tests.
- **Trusted setup** (proving keys) and the on-chain proof verification are
  tracked separately and are not covered here.
