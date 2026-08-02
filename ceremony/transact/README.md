# Transact v3 trusted-setup ceremony — transcript

Multi-party BGM17 phase-2 ceremony over the BN254 unified transact circuit
(`TransactCircuitV3`, 2-in/2-out, 9 public inputs, 18,477 constraints). Four
contributors, strictly sequential, each contribution verified before the chain
moved on.

**Status: finalized and deployed.** The four contributions below are complete and
verify, and the chain was closed with a `zkey beacon` against Bitcoin block
960500 (hash
`00000000000000000000d121b0b62b54a09cda3246ad80b699c1ce9d43a467e4`). The final
key (`paraloom_final.zkey`, SHA-256
`5d89e9fb89f4927a2abf0108cc2e67345fb4896d5b5513d82be2044f0e2fe571`) is the
production key: its verifying key is cut into the deployed program, and a
wallet-generated proof has settled end to end through the live validator quorum
against it on devnet.

## Why this ceremony exists, when two already ran

The [withdraw](../withdraw/) and [transfer](../transfer/) ceremonies each ran a
correct phase 2 — and it was not enough. A phase-2 ceremony only re-randomizes
`δ`. The `α`, `β` and `τ` from phase 1 pass through it untouched, so if phase 1
came from a single machine, whoever ran that machine can still forge proofs no
matter how many honest contributors follow.

Both earlier chains started from a locally generated initial key. That is the
gap, and it is demonstrable rather than theoretical: `src/ceremony/phase1_trapdoor.rs`
keeps the setup trapdoor, applies three honest contributions, and still forges a
proof for a statement it holds no witness for — which verifies.

This ceremony starts instead from the
[Perpetual Powers of Tau](https://github.com/privacy-ethereum/perpetualpowersoftau)
(`powersOfTau28_hez_final_16.ptau`, 54 contributions plus a beacon), so phase 1
is not ours to have compromised.

## Files

| file | what it is |
|---|---|
| `paraloom_0000.zkey` | the initial key, derived from the public ptau — what contributor #1 consumed |
| `paraloom_final.zkey` | the finalized production proving key (after the beacon) |
| `verification_key.json` | the finalized verifying key the on-chain program embeds |
| `SHA256SUMS` | digests of the files above |

`verification_key.json` and `SHA256SUMS` are committed here. The two ~28 MB zkeys
(`paraloom_0000.zkey`, `paraloom_final.zkey`) are attached to the `v0.6.0` release
rather than committed, so the repository stays light; the digests in `SHA256SUMS`
pin them wherever they are fetched from.

The circuit's `transact_v3.r1cs` is not committed — it is an 18 MB build output.
Regenerate it deterministically and check the digest below:

```
cargo run --release --bin export_transact_v3_r1cs   # → artifacts/transact_v3.r1cs
```

## Contributors, in chain order

Contribution hashes as printed by `snarkjs zkey verify`:

| # | contributor |
|---|---|
| 1 | **LoomOG** |
| | `1ffe7aa6 920f11c5 a2cab8c4 7f40e585 d362013d 12d65fd1 6333d011 a36289da` |
| | `0ead01a4 99c8a59d 0f8e8b3e 6c7c80aa 62d51592 75f8c211 c776274d b1844469` |
| 2 | **NodeSafe** |
| | `18bfe58e d3ca3e44 e0672224 13da205d 5faabc63 7d1b5f66 87ada883 22248df3` |
| | `7921b26f 999d2d4c fdc2fb1b 20a822f6 cced17f6 323ae082 34ed3461 06cc7c46` |
| 3 | **WakiyamaP** |
| | `6464c18c cabbea74 f1fda9c2 e0f0bc34 9c5f5c33 1adea2d0 1af5ed30 13509830` |
| | `2cd6935e 59d013f1 87a93268 cfe46460 244ff7b5 aa0f87f6 5cbf2f8e 0a7cbfae` |
| 4 | **LuckyStar** |
| | `c4431118 f6a59598 0b6c089b c3b44e2f c5f500f2 0c4520b7 e70a3dc9 fcdd2325` |
| | `f20a2ff0 6eaa48cc c60ed9b8 df42ffa3 05ca2ec7 5c40c19c 5d3497fe 8ab5bc00` |

Contributions were exchanged directly with the coordinator rather than published
between rounds, so no contributor saw another's key. The keys are sound as long
as **at least one** of them honestly destroyed their `δ_i` — and, because of the
ptau above, as long as the phase-1 chain was not wholly compromised either.

## Pinned values

- circuit hash (identical in `transact_v3.r1cs` and the zkey chain):
  ```
  f1af8ac9 cc821edb 99edfdc7 efc94c76 06f41cc5 c4161398 c44b8222 bd6b4fce
  e4a84814 189c679b 04f1d9ec ee6f8b2a bec539d5 93a37bb3 5f592558 6e12bd58
  ```
- `powersOfTau28_hez_final_16.ptau` (SHA-256):
  `1c401abb57c9ce531370f3015c3e75c0892e0f32b8b1e94ace0f6682d9695922`
- `paraloom_0000.zkey` (SHA-256):
  `b44d657cf69dd512391887b393c5d52455f6b566708c3869729ed6b4032d7ebd`
- `paraloom_final.zkey` (SHA-256):
  `5d89e9fb89f4927a2abf0108cc2e67345fb4896d5b5513d82be2044f0e2fe571`
- `transact_v3.r1cs` (SHA-256):
  `c468ebf1d15a82aeb7c00ece6cf714dc742b1660b8b04634b096e548a8fbe6d7`

## Verify it yourself

Fetch the ptau from the Perpetual Powers of Tau repository, regenerate the r1cs
with the command above, then:

```
snarkjs zkey verify transact_v3.r1cs powersOfTau28_hez_final_16.ptau paraloom_final.zkey
```

Expect `ZKey Ok!` and five entries — the four contributors above, then the
beacon. The circuit hash it prints must match the pinned value; if it does not,
the key belongs to a different circuit than the one this repository builds.

## A note on the proving path

Proofs must be produced under `CircomReduction`, which is what the ceremony's
snarkjs tooling assumes. A key and its QAP reduction move together: arkworks'
default reduction against a ceremony key yields proofs that do not verify, with
nothing in the error pointing at why. `Groth16ProofSystem` in
`src/privacy/circuits.rs` is the single place this is chosen, and
`paraloom-prover-wasm` includes that same file by path so the browser cannot
drift from it.
