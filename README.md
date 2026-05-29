<p align="center">
  <img src="./assets/paraloom.svg" alt="Paraloom Logo" width="200"/>
</p>

<h1 align="center">Paraloom Core</h1>

<p align="center">
  <strong>Privacy Layer 2 on Solana — shielded pool, zkSNARKs, run on commodity hardware</strong>
</p>

<p align="center">
  <a href="https://github.com/paraloom-labs/paraloom-core/actions/workflows/ci.yaml"><img src="https://img.shields.io/github/actions/workflow/status/paraloom-labs/paraloom-core/ci.yaml?branch=main&label=CI" alt="CI"/></a>
  <a href="https://github.com/paraloom-labs/paraloom-core/actions/workflows/programs.yml"><img src="https://img.shields.io/github/actions/workflow/status/paraloom-labs/paraloom-core/programs.yml?branch=main&label=Programs%20CI" alt="Programs CI"/></a>
  <a href="https://github.com/paraloom-labs/paraloom-core/releases/latest"><img src="https://img.shields.io/github/v/release/paraloom-labs/paraloom-core?include_prereleases&label=release" alt="Release"/></a>
  <img src="https://img.shields.io/badge/rust-stable-orange" alt="Rust"/>
  <img src="https://img.shields.io/badge/anchor-0.31-purple" alt="Anchor"/>
  <a href="https://github.com/paraloom-labs/paraloom-core/blob/main/LICENSE"><img src="https://img.shields.io/github/license/paraloom-labs/paraloom-core?color=blue" alt="License"/></a>
</p>

<p align="center">
  <a href="https://docs.paraloom.io">Documentation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="https://github.com/paraloom-labs/paraloom-core/issues">Issues</a>
</p>

---

## What is Paraloom?

Paraloom is a **privacy-focused Layer 2 on Solana**: SOL bridges into a shielded pool, transfers move privately inside that pool, and withdrawals settle back to Solana — all anchored by Groth16 zkSNARKs over BLS12-381. The validator network is intentionally designed for commodity hardware (laptops, home PCs, single-board computers) running a verify-only role; proof generation stays with the user, verification is cheap enough for an off-the-shelf machine to participate in consensus.

**Core Features:**
- **zkSNARK Privacy** — Poseidon hash, in-circuit u64 range proofs, Groth16 (192-byte proofs, ~10 ms verification)
- **Solana Bridge** — bidirectional SOL deposits/withdrawals, on-chain replay protection via expiration slots
- **Byzantine Consensus** — configurable BFT threshold (default 7-of-10), reputation-gated voting, equivocation slashing evidence
- **Operations** — `/health`, `/ready`, `/metrics` endpoints, RocksDB-backed crash-consistent storage, Kademlia DHT peer discovery with libp2p ping liveness, active/passive coordinator failover
- **Private Compute (alpha)** — WASM execution with encrypted I/O, ownership-proof bound; smaller, simpler nodes can opt out

## Status

| Component | Status | Notes |
|-----------|--------|-------|
| zkSNARK privacy layer | ✅ Working | Groth16 + BLS12-381, 192-byte proofs, devnet tested |
| In-circuit range proofs | ✅ Working | u64 bit-decomposition in deposit / transfer / withdraw (v0.4.0) |
| Solana bridge (Anchor) | ✅ Working | Deployed on devnet; replay-bound by `expiration_slot` (v0.4.0) |
| Shielded transfers (private→private) | ✅ Working | 2-in/2-out `TransferCircuit`, client-side proof, BFT-settled, encrypted note delivery + recipient scan (v0.5.0) |
| Program version handshake | ✅ Working | L2 refuses to talk to wrong on-chain program version |
| Byzantine consensus | ✅ Working | Configurable BFT threshold; default 7/10; validated on 10-node localnet |
| Reputation gating + slashing | ✅ Working | Equivocation + persistent-unavailability evidence (v0.4.0) |
| Merkle + nullifier set | ✅ Working | Double-spend prevention verified; fsync'd on hot writes |
| Operational endpoints | ✅ Working | `/health`, `/ready`, `/metrics` (Prometheus) on a separate port |
| Peer discovery | ✅ Working | Kademlia DHT, bootstrap refresh, libp2p ping liveness, registry-fed slow/offline distinction (v0.5.0-rc2) |
| Release pipeline | ✅ Working | Multi-platform binaries, SHA-256 checksums, CycloneDX SBOM, Sigstore-signed |
| Poseidon hash | ✅ Working | Domain-separated; native↔circuit equivalence pinned by tests |
| Coordinator HA | ✅ Working | Active/passive failover with RTO scenario test under 30s (v0.5.0-rc2) |
| MPC trusted setup tooling | ✅ Working | BGM17 contribution + verifier, transcript chain, contributor / verifier / finalize CLIs (v0.5.0-rc2) |
| Private compute (WASM) | 🚧 Alpha | Engine + ownership proof in place; output-note plumbing pending; explicitly out of scope for the v0.5.0 ceremony |
| MPC ceremony execution | 🟡 In progress | Tooling shipped at rc2; the 20–30 contributor run is the calendar gate to v0.5.0 final |
| Mainnet launch | 🟡 Pre-release | v0.5.0-rc2 cut; awaiting ceremony completion + external security audit |

### Known limitations (devnet, pre-mainnet)

Honest scope for the current devnet milestone. These are tracked and gate mainnet, not the devnet release; none affect fund safety on devnet.

- **ZK proofs are verified by the L2 quorum; on-chain re-verification is deferred.** Every withdrawal and shielded-transfer proof **is** verified — each validator runs the real Groth16 verifier (`verify_withdrawal_parts` / `verify_transfer_parts`) and a transfer/withdrawal settles only after a BFT quorum votes it valid. What is deferred is a *redundant* on-chain re-check: the Solana program records the proof and is gated by the consensus authority, but does not itself re-run Groth16 on-chain (blocked on Solana SIMD-0388, ~Q3'26 — #165). The post-transfer Merkle root is set by the consensus leader and is likewise not re-verified on-chain.
- **Trusted setup is a dev ceremony.** The MPC tooling is shipped (BGM17 contribution/verifier/transcript, rc2), but the proving/verifying keys in use today come from a single-party dev setup; running the multi-party ceremony is the remaining gate to v0.5.0 final (#64).
- **Transfer note delivery is L2-served and in-memory.** Encrypted output notes are delivered via a node's `/transfer/scan` endpoint (in-memory, not persisted across restart; the ingress is disabled by default and intended for a loopback/management interface). Recipients scan and trial-decrypt client-side.
- **Per-transfer pool convergence is partial.** The settling node appends a transfer's output commitments to its shielded pool; recipients rely on that node / the on-chain tree to spend.

These are the work between a pre-mainnet milestone and a mainnet launch, which also awaits an external security audit.

## Economic Model

Paraloom is structured as permissionless validator-run infrastructure rather than a founder-fee product. Withdrawal fees collected by the on-chain program are credited to the validator that led verification — not to a single recipient account.

The on-chain instructions wired today (`programs/paraloom/src/lib.rs`):

- `register_validator` — anyone meeting `MIN_VALIDATOR_STAKE` (1 SOL) joins the validator set
- `distribute_fee` — credits `pending_rewards` on the leader's `ValidatorAccount`
- `claim_rewards` — validator withdraws accumulated earnings to their own wallet
- `slash_validator` — burns 1–100% of stake for protocol violations, recorded in `times_slashed`

Validators are verify-only; proof generation stays with the user. A Groth16 proof verifies in roughly ten milliseconds on a single CPU core, so participation does not require GPUs or co-located hardware. The role is meant to run from a laptop.

The validator-quorum daemon path that automatically calls `distribute_fee` after consensus is tracked in [#164](https://github.com/paraloom-labs/paraloom-core/issues/164). Until that ships, fee distribution requires a manual instruction; the on-chain mechanism itself is unchanged.

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

Full documentation: **[docs.paraloom.io](https://docs.paraloom.io)**

**Getting started**
- [Quickstart](https://docs.paraloom.io/docs/quickstart) — get a node running on devnet
- [Installation](https://docs.paraloom.io/docs/installation) — build from source and prerequisites

**Core concepts**
- [Architecture](https://docs.paraloom.io/docs/architecture) — system layers and module structure
- [Vision](https://docs.paraloom.io/docs/vision) — design goals and threat model
- [Use cases](https://docs.paraloom.io/docs/use-cases) — what shielded transfers and private compute unlock

**Layers**
- [Privacy layer](https://docs.paraloom.io/docs/privacy-layer) — Groth16 circuits, Poseidon, nullifiers, Merkle tree
- [Compute layer](https://docs.paraloom.io/docs/compute-layer) — WASM execution, BFT verification, encrypted I/O
- [Consensus](https://docs.paraloom.io/docs/consensus) — BFT threshold, reputation gating, equivocation slashing
- [Networking](https://docs.paraloom.io/docs/networking) — libp2p mesh, Kademlia DHT, ping liveness
- [Solana bridge](https://docs.paraloom.io/docs/solana-bridge) — on-chain Anchor program, bridge state, nullifier PDAs

**Operations**
- [Validator guide](https://docs.paraloom.io/docs/validator-guide) — run a validator on commodity hardware
- [Coordinator HA](https://docs.paraloom.io/docs/coordinator-ha) — active/passive failover
- [Monitoring](https://docs.paraloom.io/docs/monitoring) — `/health`, `/ready`, `/metrics` endpoints
- [Performance](https://docs.paraloom.io/docs/performance) — proof generation, verification, throughput
- [Troubleshooting](https://docs.paraloom.io/docs/troubleshooting) — common errors and recovery

**Reference**
- [API reference](https://docs.paraloom.io/docs/api-reference) — RPC and library surface
- [MPC ceremony](https://docs.paraloom.io/docs/ceremony) — BGM17 trusted setup workflow
- [Security](https://docs.paraloom.io/docs/security) — threat model, known limitations, audit status
- [Releases](https://docs.paraloom.io/docs/releases) — version notes and migration guides
- [Developer guide](https://docs.paraloom.io/docs/developer-guide) — contributing to paraloom-core
- [FAQ](https://docs.paraloom.io/docs/faq)

## CLI Usage

```bash
# Privacy operations
paraloom wallet deposit --amount 1.0
paraloom wallet withdraw --amount 0.5 --to <ADDRESS>

# Compute operations
paraloom compute submit --wasm ./program.wasm --input ./data.json
paraloom compute submit --wasm ./program.wasm --input ./data.json --private
```

## Run a validator on devnet

Permissionless. Anyone with a devnet wallet holding ≥ 2 SOL can stake into
the registry and join the consensus mesh.

```bash
# 1. system deps (Debian/Ubuntu; see release.yml for full list)
sudo apt-get install -y build-essential pkg-config libssl-dev \
  protobuf-compiler clang libclang-dev cmake \
  libc++-dev libc++abi-dev libstdc++-12-dev

# 2. build the node and the on-chain registration helper
git clone https://github.com/paraloom-labs/paraloom-core.git
cd paraloom-core
cargo build --release --bin paraloom-node --bin register-validator

# 3. fund a Solana keypair on devnet (faucet.solana.com gives 2 SOL/8h)
solana-keygen new --no-bip39-passphrase -o ~/.config/solana/paraloom-validator.json
solana airdrop 2 $(solana-keygen pubkey ~/.config/solana/paraloom-validator.json) \
  --url https://api.devnet.solana.com

# 4. stake 1 SOL and register on-chain
SOLANA_RPC_URL=https://api.devnet.solana.com \
SOLANA_PROGRAM_ID=8gPsRSm1CAw38mfzc1bcLMUXyFN7LnS8k6CV5hPUTWrP \
VALIDATOR_KEYPAIR_PATH=$HOME/.config/solana/paraloom-validator.json \
  ./target/release/register-validator

# 5. write a validator.toml from the template (wires bootstrap + bridge)
cp scripts/devnet/validator.toml.example ~/.paraloom/validator.toml
# edit the marked paths in the file, then:
./target/release/paraloom-node start --config ~/.paraloom/validator.toml
```

The template's `bootstrap_nodes` points at the paraloom-labs anchor:

```
/ip4/67.205.142.8/tcp/9300/p2p/12D3KooWFf8xfNz77E9Ve4HnpyZkAHKAcUdw4LmagpFCYQD6R7WK
```

Once dialled, the Kademlia DHT fans out to the rest of the validator set
automatically — the anchor is just the first hop. Its libp2p identity is
persisted (#206), so this multiaddr is stable; if you cache it, it keeps
resolving across anchor restarts.

The full guide (systemd unit, log monitoring, common pitfalls) lives at
[docs.paraloom.io/docs/validator-guide](https://docs.paraloom.io/docs/validator-guide).

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Before submitting PR
cargo test --all
cargo clippy --all-targets -- -D warnings
cargo fmt --all
```

## Development History

`main` currently uses **merge commits** so each PR's atomic commit narrative
is preserved end-to-end. Earlier development (v0.1) used **squash-merge**
across six long-lived feature branches that consolidated the initial
privacy / bridge / compute / CLI work; that history is still readable on
those branches:

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
