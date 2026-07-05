# Transfer circuit trusted-setup ceremony — transcript v1

Multi-party BGM17 phase-2 ceremony over the BN254 transfer circuit
(`TransferCircuitV2`, 2-in/2-out spend-key, 6 public inputs). Five
contributors, strictly sequential, each contribution verified by the
coordinator before the chain moved on. Run and finalized 2026-07-05
through the fail-closed policy gate added in #344.

Together with the [withdraw ceremony](../withdraw/), this puts the
entire shielded stack on MPC keys: the resulting keys are sound as
long as at least one contributor honestly destroyed their `δ_i`.
This transcript is the public proof — anyone can re-verify the whole
chain from the files in this directory.

## Files

| file | what it is |
|---|---|
| `transfer_v2_initial_proving.key` | the initial single-source proving key the first contributor consumed |
| `transfer_ceremony_transcript.bin` | the full 5-contribution transcript (hash chain + DLEQ proofs) |
| `transfer_ceremony_proving.key` | the finalized production proving key (the chain tip, promoted by finalize) |
| `transfer_ceremony_verifying.key` | the finalized production verifying key (what the on-chain program will embed) |
| `SHA256SUMS` | digests of the four files above |

## Contributors, in chain order

| # | operator | validator pubkey |
|---|---|---|
| 1 | LoomOG | `AToKrSPngVUmWE2AnE9abAsMC78nWtjFcLfoqLMSRDiF` |
| 2 | WakiyamaP | `FdVH4d4k27PNNQe46zXHk5WJGnomh6Phn3cJLiPinvQ3` |
| 3 | tuanlaoga | `4H6dU1iKXuojjN4VxjSo3URdJ9dPanfT7BxDWmCaW1yZ` |
| 4 | BoyGau \| L3SDAO | `5AHtCMBTNBpPT8BJi9bK9aKeWu9po27hSMP5yw1LYowr` |
| 5 | Havana \| LuckyStar | `EyHavZ9iA4dyrmf49S7wTUxvq7McoTfgSKc3T3AUmwP9` |

Each contribution's `contributor` field in the transcript is the
operator's validator pubkey in hex.

## Pinned values

- initial SRS (SHA-512 of `transfer_v2_initial_proving.key`):
  `b58b88d59f2b99d6c08f5e16f51ada10279ddecf509e060718cbecf893cd703606e0ad0f500287d2a3d385f3c81dc08bb4d3f740b6a217a0bfb6a4b385dbcc8c`
- chain-tip contribution hash (SHA-512, printed by the verifier):
  `7b4a0e2a88b123f1556027ccb26797d467fbc3b88909b0809b67c5a1597d668cc2941cad769dc67df97d3797b4600c3fb6a3d5578ebdd2856dc14444af3459dd`

## Verify it yourself

```
cargo build --release --bin paraloom_ceremony_verify
target/release/paraloom_ceremony_verify \
  --initial-pk ceremony/transfer/transfer_v2_initial_proving.key \
  --transcript ceremony/transfer/transfer_ceremony_transcript.bin
```

Expected output:

```
Transcript verified. Circuit: transfer, contributions: 5
  final contribution hash: 7b4a0e2a88b123f1556027ccb26797d467fbc3b88909b0809b67c5a1597d668cc2941cad769dc67df97d3797b4600c3fb6a3d5578ebdd2856dc14444af3459dd
```

This walks the hash chain and verifies every contribution's DLEQ
proof against the delta transition it claims.

## How the keys were finalized

```
target/release/paraloom_ceremony_finalize \
  --initial-pk keys/transfer_v2_proving.key \
  --ceremony-pk 05_havana_pk.key \
  --transcript 05_havana_transcript.bin \
  --output-pk keys/transfer_ceremony_proving.key \
  --output-vk keys/transfer_ceremony_verifying.key \
  --initial-srs-hash b58b88d5…dbcc8c \
  --min-contributions 5 \
  --final-contribution-hash 7b4a0e2a…3459dd
```

Finalize re-verifies the transcript end to end, binds the promoted
key's delta to the chain tip, checks the key's `h_query`/`l_query`
are the consistent `δ⁻¹` scaling via pairings, and refuses anything
that fails a policy gate (#344). The promoted proving key is
byte-identical to the last contributor's output — `SHA256SUMS`
shows `transfer_ceremony_proving.key` and contribution #5's key
share the digest `8fe14c40…`.

## Honest scope

- Contributor identity is bound socially (the coordinator handed
  files to one known operator at a time over Discord DM), not
  cryptographically: the contribute CLI does not yet populate the
  transcript's signature fields. Signature enforcement is a mainnet
  ceremony gate, tracked in #64.
- These keys replace the single-party dev keys on devnet at the
  upcoming redeploy. The mainnet ceremony (#64) will re-run this
  process with signatures enforced.
