# Security

Paraloom is **pre-mainnet** and runs on devnet — no real funds are at risk yet.
We do security in the open: the protocol is open source, every circuit and
on-chain path is covered by tests in CI, and we keep a public record of what we
find and fix in [`docs/security-log.md`](docs/security-log.md).

## Reporting a vulnerability

Email **security@paraloom.network**.

Please do **not** open a public issue for an undisclosed vulnerability. Include,
where you can:

- the affected component (on-chain program, circuit, L2 node, bridge, wallet),
- a description of the issue and its impact,
- steps to reproduce or a proof-of-concept.

We aim to acknowledge reports within 72 hours and to keep you updated through
triage and fix.

## Bug bounty

We reward valid security findings. At this pre-mainnet stage rewards are
severity-scaled and assessed case by case, and every fixed report is credited in
the security log (unless you prefer to remain anonymous).

**Stage 1 is live** — a $3,000 USDC pool on the shielded-pool settlement stack.
See [`docs/bug-bounty.md`](docs/bug-bounty.md) for the reward tiers, pinned
scope, known issues, and reporting rules.

**In scope**

- `programs/paraloom/` — the on-chain Solana program
- `src/privacy/` — the shielded-pool circuits, Poseidon, and proof verification
- `src/consensus/`, `src/node/` — L2 verification and settlement
- `src/bridge/` — the Solana bridge
- `paraloom-prover-wasm`, `paraloom-wallet` — client proof generation

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

The circuits are reviewed adversarially in the open. Critical findings have been
fixed **on devnet, before any real money** — see the security log. An
**independent professional audit** and the **production MPC trusted-setup
ceremony** are hard gates before mainnet. We do not claim Paraloom is audited or
safe for real funds today; it is pre-mainnet, and the point is that you can
verify the state for yourself.
