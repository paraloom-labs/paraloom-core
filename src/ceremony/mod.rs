//! MPC trusted setup ceremony for Groth16 proving keys.
//!
//! This module is the v0.5.0 foothold for the multi-party computation
//! ceremony that replaces the deterministic-seed trusted setup currently
//! used in testnet. Tracking issue:
//! <https://github.com/paraloom-labs/paraloom-core/issues/64>.
//!
//! The ceremony is structured in two phases:
//!
//! - **Phase 1, Powers of Tau.** Circuit-independent. We reuse the
//!   Filecoin BLS12-381 Powers of Tau transcript rather than running
//!   our own; that transcript needs a one-time offline format
//!   conversion into the accumulator layout this module consumes.
//! - **Phase 2, circuit-specific.** Run by us against the three
//!   privacy circuits (`DepositCircuit`, `TransferCircuit`,
//!   `WithdrawCircuit`). `ComputeCircuit` is out of scope for v0.5.0;
//!   see issue #64 for the rationale.
//!
//! ## Implementation plan (Path A)
//!
//! The ceremony code in this module is being adapted from
//! `penumbra-zone/aleo-setup`, which is the most modern Rust +
//! arkworks ceremony implementation currently in production. The
//! original is BLS12-377; this module ports it to BLS12-381 in a
//! sequence of focused commits:
//!
//! 1. Module skeleton and `lib.rs` wire-up (this commit).
//! 2. Vendored `phase1` and `phase2` accumulator code, holding to
//!    BLS12-377 first to confirm the vendoring builds cleanly.
//! 3. Generic-curve refactor pinning the public API at `Bls12_381`
//!    while keeping the BLS12-377 paths green for regression
//!    coverage.
//! 4. One-time offline tool that converts Filecoin's bellman-format
//!    `.ptau` into the accumulator layout used here.
//!
//! The contributor and verifier binaries
//! (`paraloom-ceremony-contribute`, `paraloom-ceremony-verify`) will
//! live under `src/bin/` and depend on this module's public API once
//! it stabilizes.
//!
//! Implementation specifics, contributor count, hardware floor,
//! toxic-waste handling, and the circuit-freeze policy are all
//! recorded as comments on issue #64 and are treated as load-bearing
//! context for any future change to this module.
