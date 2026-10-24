# Security

Paraloom runs in the open: the protocol is open source, every circuit and
on-chain path is covered by tests in CI, and we keep a public record of what we
find and fix in [`docs/security-log.md`](docs/security-log.md). Following the
**mainnet-beta (`v1.5.0`)** launch on 2026-08-04, all adversarial testing must
still be performed strictly against **local test harnesses or Solana devnet** —
never test against live mainnet-beta accounts or user funds.

## Reporting a vulnerability

Choose the reporting channel based on severity (see
[`docs/bug-bounty.md`](docs/bug-bounty.md) for protocol-specific severity
definitions):

- **Critical and High findings — report privately to `security@paraloom.network`.**
  Please do **not** open a public GitHub issue for an undisclosed Critical or High
  vulnerability, as findings in shared program or node logic can affect live
  deployments before a fix ships.
- **Medium and Low findings — open a public GitHub issue** at
  [github.com/paraloom-labs/paraloom-core/issues](https://github.com/paraloom-labs/paraloom-core/issues)
  (which timestamps your claim and tracks triage, fix, and credit in the open),
  or email **security@paraloom.network** if you prefer private disclosure or are
  unsure of the severity.

Include, where you can:

- the affected component (on-chain program, circuit, L2 node, bridge, wallet),
- a description of the issue and its impact,
- steps to reproduce or a self-contained proof-of-concept / regression test.

We aim to acknowledge reports within 72 hours and to keep you updated through
triage and fix.

## Bug bounty

We reward valid security findings. Rewards are severity-scaled and assessed case
by case, and every fixed report is credited in the security log (unless you
prefer to remain anonymous).

**Stage 1 is live** — a $3,000 USDC pool on the shielded-pool settlement stack.
See [`docs/bug-bounty.md`](docs/bug-bounty.md) for the reward tiers, pinned
scope, known issues, payout mechanics, and reporting rules.

**In scope**

- `programs/paraloom/` — the on-chain Solana program
- `src/privacy/` — the shielded-pool circuits, Poseidon, and proof verification
- `src/consensus/`, `src/node/` — L2 verification and settlement
- `src/bridge/` — the Solana bridge
- `paraloom-prover-wasm`, `paraloom-wallet` — client proof generation and wallet

**Out of scope**

- issues that require a compromised upgrade-authority key
- denial of service from unbounded resource use on a self-run node
- findings only reproducible against forks/branches that are not deployed
- anything already listed in [`docs/security-log.md`](docs/security-log.md)

## What runs in CI

Every pull request runs, on GitHub Actions:

- the full Rust test suite per module, plus the on-chain program tests
  (`solana-program-test`) and a `cargo build-sbf` of the program
- `cargo fmt --check` and `clippy`
- CodeQL static analysis and Snyk dependency scanning
- `cargo-fuzz` targets
- a Poseidon/circuit parameter-freeze check, so the audit-critical constants
  cannot change unnoticed

## Audit status

The circuits and settlement paths are reviewed adversarially in the open, with
every confirmed finding and fix documented in [`docs/security-log.md`](docs/security-log.md).
An **independent professional audit** and full **multisig/timelock governance**
remain tracked security gates; verify the current state of each component in
[`docs/security-log.md`](docs/security-log.md) and [`docs/bug-bounty.md`](docs/bug-bounty.md).
