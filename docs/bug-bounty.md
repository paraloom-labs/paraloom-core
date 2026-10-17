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

1. **Trusted-setup toxic waste.** `transact` now verifies against the
   multi-party ceremony Groth16 key (four independent contributions plus a
   Bitcoin-block beacon on the public Perpetual Powers of Tau; transcript and
   keys published under `ceremony/transact/`). Assume an **honest setup**, which
   holds as long as any one contributor discarded their secret: a forgery that
   requires the setup secret is out of scope; a forgery that does **not** (a real
   circuit under-constraint) is in scope and Critical.
2. **Single upgrade/registry authority key.** One key is both the program
   upgrade authority and the registry admin (slash/deactivate/reset/etc.); no
   multisig/timelock yet. Attacks that assume this key is compromised or misused
   are out of scope (multisig+timelock is a pre-mainnet gate).
3. **Validator-stake Sybil economics.** The minimum validator stake is
   intentionally cheap and the quorum is not yet economically Sybil-resistant.
   Both the safety (cheap co-sign stake) and liveness (a cheaply-registered
   validator inflating the quorum denominator to freeze settlement, admin-
   recoverable) dimensions are known and out 