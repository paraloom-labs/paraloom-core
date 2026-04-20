<p align="center">
  <img src="./assets/paraloom.svg" alt="Paraloom Logo" width="200"/>
</p>

<h1 align="center">Paraloom Core</h1>

<p align="center">
  <strong>Privacy-Preserving Distributed Computing on Solana</strong>
</p>

<p align="center">
  <a href="https://github.com/paraloom-labs/paraloom-core/actions"><img src="https://img.shields.io/badge/build-passing-brightgreen" alt="Build"/></a>
  <img src="https://img.shields.io/badge/tests-116%20passing-brightgreen" alt="Tests"/>
  <img src="https://img.shields.io/badge/LOC-21K-blue" alt="Lines of Code"/>
  <img src="https://img.shields.io/badge/rust-stable-orange" alt="Rust"/>
  <img src="https://img.shields.io/badge/anchor-0.31-purple" alt="Anchor"/>
  <a href="https://github.com/paraloom-labs/paraloom-core/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="License"/></a>
</p>

<p align="center">
  <a href="https://docs.paraloom.io">Documentation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="https://github.com/paraloom-labs/paraloom-core/issues">Issues</a>
</p>

---

## What is Paraloom?

Paraloom combines **Zcash-level transaction privacy** with **distributed computing** on Solana. Using zkSNARK proofs (Groth16 on BLS12-381), it enables confidential transactions and privacy-preserving compute jobs where validators process encrypted data without seeing the actual inputs or outputs.

**Core Features:**
- **zkSNARK Privacy** — Poseidon hash + Groth16 proofs (192 bytes, ~10ms verification)
- **Private Compute** — WASM execution with encrypted input/output
- **Byzantine Consensus** — 7/10 validator threshold, <1s latency
- **Solana Bridge** — Bidirectional SOL deposits/withdrawals

## Status

| Component | Status | Notes |
|-----------|--------|-------|
| zkSNARK privacy layer | ✅ Working | Groth16 + BLS12-381, 192-byte proofs, devnet tested |
| Solana bridge (Anchor) | ✅ Working | Deployed on devnet, deposit/withdraw end-to-end |
| Byzantine consensus | ✅ Working | 7/10 threshold, validated on 10-node localnet |
| Merkle + nullifier set | ✅ Working | Double-spend prevention verified |
| Private compute (WASM) | 🚧 Alpha | Engine works; encrypted I/O integration in progress |
| Poseidon hash | ⚠️ MVP | Arkworks-based; production-hardening pending |
| Trusted setup | ⚠️ MVP | Deterministic seed; MPC ceremony scheduled |
| Mainnet launch | 🔜 Planned | Awaiting external security audit |

## Quick Start

```bash
# Clone and build
git clone https://github.com/paraloom-labs/paraloom-core.git
cd paraloom-core
cargo build --release

# Run tests
cargo test --all

# Try the compute demo
cargo run --bin compute-demo
```

## Project Structure

```
paraloom-core/
├── src/
│   ├── privacy/      # zkSNARK circuits, Poseidon hash, shielded pool
│   ├── compute/      # WASM engine, job distribution, private compute
│   ├── consensus/    # Byzantine consensus, reputation system
│   ├── bridge/       # Solana program interface
│   └── bin/          # CLI tools
├── programs/         # Anchor program (Solana)
├── tests/            # Integration tests
└── scripts/          # Localnet/devnet scripts
```

## Documentation

Full documentation available at **[docs.paraloom.io](https://docs.paraloom.io)**

- [Architecture Overview](https://docs.paraloom.io/architecture)
- [Privacy Layer](https://docs.paraloom.io/privacy-layer)
- [Compute Layer](https://docs.paraloom.io/compute-layer)
- [Validator Guide](https://docs.paraloom.io/validator-guide)

## CLI Usage

```bash
# Privacy operations
paraloom wallet deposit --amount 1.0
paraloom wallet withdraw --amount 0.5 --to <ADDRESS>

# Compute operations
paraloom compute submit --wasm ./program.wasm --input ./data.json
paraloom compute submit --wasm ./program.wasm --input ./data.json --private

# Validator operations
paraloom validator start --config validator.toml
paraloom validator status
```

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Before submitting PR
cargo test --all
cargo clippy --all-targets -- -D warnings
cargo fmt --all
```

## Development History

`main` uses **squash-merge** — each commit represents a completed feature PR.
Granular commit history (232+ commits across 6 parallel feature branches) is
preserved on:

- [`feature/privacy-layer`](../../tree/feature/privacy-layer) — zkSNARK circuits, Pedersen commitments, shielded pool
- [`feature/solana-bridge`](../../tree/feature/solana-bridge) — Anchor program, PDA design, deposit/withdraw
- [`feature/zksnark-verification`](../../tree/feature/zksnark-verification) — proof generation, verifier integration
- [`feature/compute-layer`](../../tree/feature/compute-layer) — WASM engine, job distribution
- [`feature/compute-privacy-integration`](../../tree/feature/compute-privacy-integration) — encrypted I/O glue
- [`feature/cli-tool`](../../tree/feature/cli-tool) — `paraloom` CLI

See [Insights → Contributors](../../graphs/contributors) for full contribution breakdown.

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <sub>Built with Arkworks, libp2p, and Anchor</sub>
</p>
