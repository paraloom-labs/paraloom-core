# Paraloom Bug Bounty (devnet, pre-mainnet)

Paraloom is a privacy-preserving Solana L2 (a shielded pool with Groth16/BN254
proofs and a stake-weighted validator co-sign quorum). It runs on **devnet — no
real funds are at risk** — and we are inviting adversarial testing *before*
mainnet, while bugs are cheap to fix. Find a real issue, report it, earn a
reward.

This program complements [`SECURITY.md`](../SECURITY.md) and the running
[`security-log.md`](security-log.md). Reports: **security@paraloom.network**.

---

## Rewards

This is **Stage 1** of Paraloom's bug bounty — a **$3,000 USD pool paid in
USDC**, while the protocol is on devnet and no real funds are at risk. Larger,
mainnet-stage bounties follow once the pre-mainnet gates listed under
[Out of scope](#out-of-scope--known-issues) are closed.

| Severity | What it means (see definitions) | Reward (USDC) |
|---|---|---|
| **Critical** | Steal or mint pool funds; forge a valid proof **without** the trusted-setup toxic waste; settle without a genuine independent quorum; double-spend a note | up to **$1,000** |
| **High** | Permanently freeze user funds or validator stake; break in-circuit value conservation; redirect a payout | up to **$400** |
| **Medium** | Auth bypass on a non-fund instruction; incorrect accounting without loss; a griefing/liveness halt of settlement | up to **$150** |
| **Low** | Privacy-weakening info leak; unvalidated input without an exploit path; limited-impact edge case | up to **$50** |

Rewards are paid on triage-confirmed findings, first valid report per unique
root cause, until the $3,000 pool is exhausted. Duplicates of an already-reported
or already-known issue (see Out of scope) are not eligible. Every rewarded report
is credited in the security log unless you prefer to stay anonymous.

---

## Scope

Stage 1 covers **only** the shielded-pool / private-settlement stack listed
below, on the current devnet deployment. **If it is not in this list, it is out
of scope** (see [Out of scope](#out-of-scope--known-issues)).

- **Program:** `8gPsRSm1CAw38mfzc1bcLMUXyFN7LnS8k6CV5hPUTWrP` (Solana devnet)
- **Source:** the `main` branch at commit `468ffaa` (or later at launch)

In scope:

- `programs/paraloom/` — the on-chain Solana program (transact settlement,
  deposits, validator lifecycle, admin/authority)
- `src/privacy/` — the shielded-pool circuits (TransactCircuitV3), Poseidon, and
  on-chain proof verification
- `src/consensus/`, `src/bridge/`, and the **settlement / co-sign path** of
  `src/node/` — the L2 verification, stake-weighted quorum, and Solana bridge
- `paraloom-prover-wasm`, `paraloom-wallet` — client proof generation and the
  wallet

We are most interested in anything that lets a party **without special access**
steal, mint, freeze, or forge — especially a **circuit under-constraint** that
makes the on-chain verifier accept a semantically false proof *assuming an
honest trusted setup*.

The whole stack is open source. **Reproduce findings against a local devnet** —
clone the repo and run your own validator set to exercise the end-to-end
settlement path. The maintainer's live validator mesh is pre-mainnet and may be
offline, so don't depend on it for reproduction.

---

## Out of scope / known issues

These are already known and documented; reports of them are **not eligible**.

1. **Trusted-setup toxic waste.** `transact` currently verifies against a
   pre-ceremony (single-party dev) Groth16 verifying key; the production MPC
   trusted-setup ceremony is a pre-mainnet gate. Assume an **honest setup** —
   a forgery that requires the setup secret is known and out of scope; a forgery
   that does **not** (a real circuit under-constraint) is in scope and Critical.
2. **Single upgrade/registry authority key.** One key is both the program
   upgrade authority and the registry admin (slash/deactivate/reset/etc.); no
   multisig/timelock yet. Attacks that assume this key is compromised or misused
   are out of scope (multisig+timelock is a pre-mainnet gate).
3. **Validator-stake Sybil economics.** The minimum validator stake is
   intentionally cheap and the quorum is not yet economically Sybil-resistant.
   Both the safety (cheap co-sign stake) and liveness (a cheaply-registered
   validator inflating the quorum denominator to freeze settlement, admin-
   recoverable) dimensions are known and out of scope.
4. **No independent external audit yet.** In-house review only.
5. **Discretionary admin slashing.** Slashing is admin-triggered; on-chain
   evidence-based equivocation slashing is a tracked pre-mainnet item.
6. **In-circuit new-root binding / ceremony-key auth** are tracked pre-mainnet
   items.

**The compute / DePIN subsystem is out of scope for Stage 1.** The compute task
layer (`src/compute/`, task submission / verification / resource-provider
handling, and the compute paths in the node) is **alpha** and its reward
economics are not yet wired on devnet. Stage 1 is the shielded-pool / settlement
stack only; a dedicated compute bounty will follow when that subsystem matures.

Also out of scope: anything already in [`security-log.md`](security-log.md);
denial of service from unbounded resource use on a single self-run node;
findings only reproducible on branches/forks not deployed at the pinned scope;
attacks on third-party infrastructure (RPC providers, host OS, reverse proxy);
social engineering; physical attacks; spam/load on devnet.

---

## Severity definitions (protocol-specific)

- **Critical** — mint or steal pool funds; forge a proof the on-chain verifier
  accepts that is semantically false *without* the trusted-setup secret; settle
  a `transact` without a genuine stake-weighted supermajority of independent
  validators; double-spend a note (nullifier bypass); drain a vault.
- **High** — permanently freeze user funds or validator stake; break in-circuit
  value conservation (create/destroy value); forge merkle membership; bypass
  recipient/amount binding to redirect a payout.
- **Medium** — bypass authorization on a non-fund instruction; incorrect
  on-chain accounting without direct loss; a griefing/liveness path that halts
  settlement (beyond the out-of-scope single-node resource DoS).
- **Low** — information leakage that weakens privacy; an unvalidated input with
  no exploit path; a limited-impact edge case.

---

## Reporting & disclosure

How to submit — and why the channel matters:

- **Medium and Low findings — open a public GitHub issue** at
  [github.com/paraloom-labs/paraloom-core/issues](https://github.com/paraloom-labs/paraloom-core/issues).
  The issue *is* your claim: it timestamps your report (the first valid report of
  a unique root cause wins the reward), it becomes the public record we link from
  [`security-log.md`](security-log.md) so anyone can verify the finding and its
  fix, and triage, reward, and credit all happen on it. Prefer email? That works
  too.
- **Critical and High findings — report privately to security@paraloom.network;
  do NOT open a public issue.** A devnet exploit usually applies to mainnet too,
  so a public write-up before a fix ships hands an attacker a weapon. A private
  report still timestamps your claim and earns full credit — we publish it in the
  security log once the fix lands.
- Either way, include the affected component, the impact, and a proof-of-concept
  or reproduction steps.

We aim to acknowledge within **72 hours** and to keep you updated through triage
and fix. We follow coordinated disclosure: for private reports we agree a
public-disclosure timeline with you after the fix ships.

---

## Rules of engagement

- Test on **devnet only**. There is no mainnet. Use faucet SOL; do not spam the
  network or degrade it for others.
- Attack the **protocol**, not other operators' machines — no attempts to
  compromise validator hosts, RPC providers, or infrastructure beyond protocol
  messages.
- No exfiltration of, or interference with, other users' data beyond what a
  proof-of-concept minimally requires.
- Good-faith research under this policy will not be treated as a hostile act.
