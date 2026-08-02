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

Paraloom is a **privacy-focused Layer 2 on Solana**: SOL bridges into a shielded pool, transfers move privately inside that pool, and withdrawals settle back to Solana — all anchored by Groth16 zkSNARKs over BN254 and verified by the Solana program itself. The validator network is intentionally designed for commodity hardware (laptops, home PCs, single-board computers) running a verify-only role; proof generation stays with the user, verification is cheap enough for an off-the-shelf machine to participate in consensus.

**Core Features:**
- **zkSNARK Privacy** — Poseidon hash, in-circuit u64 range proofs, Groth16 over BN254 (128-byte compressed proofs, verified on-chain via `alt_bn128`)
- **Solana Bridge** — bidirectional SOL deposits/withdrawals, on-chain replay protection via expiration slots
- **Byzantine Consensus** — stake-weighted BFT supermajority (>2/3 of active stake), reputation-gated voting, equivocation slashing evidence
- **Operations** — `/health`, `/ready`, `/metrics` endpoints, RocksDB-backed crash-consistent storage, Kademlia DHT peer discovery with libp2p ping liveness, active/passive coordinator failover
- **Private Compute (alpha)** — WASM execution with encrypted I/O, ownership-proof bound; smaller, simpler nodes can opt out

## Status

| Component | Status | Notes |
|-----------|--------|-------|
| zkSNARK privacy layer | ✅ Working | Groth16 over BN254, 128-byte compressed proofs, verified on-chain |
| In-circuit range proofs | ✅ Working | u64 bit-decomposition in deposit / transfer / withdraw (v0.4.0) |
| Solana bridge (Anchor) | ✅ Working | Deployed on devnet; replay-bound by `expiration_slot` (v0.4.0) |
| Unified transact (deposit / transfer / withdraw) | ✅ Working | One 2-in/2-out `TransactCircuitV3` proof for all three, separated by a signed external amount; change returns as a note; client-side proving, quorum-cosigned settlement (v0.6.0) |
| Program version handshake | ✅ Working | L2 refuses to talk to wrong on-chain program version |
| Byzantine consensus | ✅ Working | Stake-weighted supermajority, `floor(2·stake/3)+1`, enforced on-chain at settlement |
| Reputation gating + slashing | ✅ Working | Equivocation + persistent-unavailability evidence (v0.4.0) |
| Merkle + nullifier set | ✅ Working | Double-spend prevention verified; fsync'd on hot writes |
| Operational endpoints | ✅ Working | `/health`, `/ready`, `/metrics` (Prometheus) on a separate port |
| Peer discovery | ✅ Working | Kademlia DHT, bootstrap refresh, libp2p ping liveness, registry-fed slow/offline distinction |
| Release pipeline | ✅ Working | Multi-platform binaries, SHA-256 checksums, CycloneDX SBOM, Sigstore-signed |
| Poseidon hash | ✅ Working | Domain-separated; native↔circuit equivalence pinned by tests |
| Coordinator HA | ✅ Working | Active/passive failover with RTO scenario test under 30s |
| MPC trusted setup tooling | ✅ Working | BGM17 contribution + verifier, transcript chain, contributor / verifier / finalize CLIs |
| Private compute (WASM) | 🚧 Alpha | Engine + ownership proof in place; output-note plumbing pending; out of Stage 1 bounty scope |
| MPC ceremony execution | ✅ Done | Four independent contributions plus a Bitcoin-block beacon on the unified transact circuit, built on the public Perpetual Powers of Tau. The final key is cut into the deployed program; transcript and keys in `ceremony/transact/` (#659) |
| Mainnet launch | 🟡 Pre-release | Devnet on `8gPsR…TWrP`; the ceremony key cutover is deployed and a dual-stake validator quorum settles end to end. The matching wallet is in Chrome Web Store review. Remaining mainnet gates below |

### Known limitations (devnet, pre-mainnet)

Honest scope for the current devnet milestone. These are tracked and gate mainnet, not the devnet release; none affect fund safety on devnet.

- **The quorum is not yet Sybil-resistant.** Settlement needs a stake-weighted supermajority to co-sign, and the proof is verified on-chain, so no single signature moves funds. But validator registration is permissionless and one key is both the program upgrade authority and the registry admin, with no multisig or timelock — so that key remains the trust anchor, with the quorum as defence in depth. A Sybil-resistant quorum and multisig with timelock are mainnet gates.
- **Note delivery is L2-served and in-memory.** Encrypted output notes are served from a node's `/transact/scan` endpoint — held in memory, not persisted across a restart, and the ingress is off by default and meant for a loopback or management interface. Recipients poll it and trial-decrypt client-side, so the node learns nothing about which notes are whose.
- **Pool convergence is partial.** The settling node appends a spend's output commitments to its shielded pool; recipients depend on that node or the on-chain tree to spend them.

These are the work between a pre-mainnet milestone and a mainnet launch. The review model is a public bug bounty (see [`docs/bug-bounty.md`](docs/bug-bounty.md)), where any test-proven finding is paid.

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

# 2. build the unified CLI
git clone https://github.com/paraloom-labs/paraloom-core.git
cd paraloom-core
cargo build --release --bin paraloom

# 3. fund a Solana keypair on devnet (faucet.solana.com gives 2 SOL/8h)
solana-keygen new --no-bip39-passphrase -o ~/.config/solana/paraloom-validator.json
solana airdrop 2 $(solana-keygen pubkey ~/.config/solana/paraloom-validator.json) \
  --url https://api.devnet.solana.com

# 4. stake 1 SOL and register on-chain
#    (devnet RPC and the canonical program ID are the defaults — keypair is all you need)
./target/release/paraloom validator register \
  --keypair ~/.config/solana/paraloom-validator.json

# 5. write a validator.toml from the template (wires bootstrap + bridge), then start
cp scripts/devnet/validator.toml.example ~/.paraloom/validator.toml
# edit the marked paths in the file, then:
./target/release/paraloom validator start --config ~/.paraloom/validator.toml
```

Check your registration any time with `paraloom validator status --keypair
~/.config/solana/paraloom-validator.json`, or see the whole live set with
`paraloom validator list`.

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
