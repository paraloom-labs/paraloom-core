# Withdraw circuit trusted-setup ceremony — transcript v1

Multi-party BGM17 phase-2 ceremony over the BN254 withdraw circuit
(`WithdrawCircuitV2`, 5 public inputs). Four contributors, strictly
sequential, each contribution verified by the coordinator before the
chain moved on. Run 2026-06-26 through 2026-07-03, finalized
2026-07-04 with the fail-closed policy gate added in #344.

The resulting keys are sound as long as at least one contributor
honestly destroyed their `δ_i`. This transcript is the public proof:
anyone can re-verify the whole chain from the files in this
directory.

## Files

| file | what it is |
|---|---|
| `withdraw_v2_initial_proving.key` | the initial single-source proving key the first contributor consumed |
| `withdraw_ceremony_transcript.bin` | the full 4-contribution transcript (hash chain + DLEQ proofs) |
| `withdraw_ceremony_proving.key` | the finalized production proving key (the chain tip, promoted by finalize) |
| `withdraw_ceremony_verifying.key` | the finalized production verifying key (what the on-chain program will embed) |
| `SHA256SUMS` | digests of the four files above |

## Contributors, in chain order

| # | operator | validator pubkey |
|---|---|---|
| 1 | LoomOG | `AToKrSPngVUmWE2AnE9abAsMC78nWtjFcLfoqLMSRDiF` |
| 2 | WakiyamaP | `FdVH4d4k27PNNQe46zXHk5WJGnomh6Phn3cJLiPinvQ3` |
| 3 | Havana \| LuckyStar | `EyHavZ9iA4dyrmf49S7wTUxvq7McoTfgSKc3T3AUmwP9` |
| 4 | JohnWiard [CC] | `ESy6D2Kf7RxqdUTQoM5iQEUpNCbg6r8ugfvZMBosNacH` |

Each contribution's `contributor` field in the transcript is the
operator's validator pubkey in hex.

## Pinned values

- initial SRS (SHA-512 of `withdraw_v2_initial_proving.key`):
  `dc95c7c06e8d7ca7e069402ea0d5eada2c563c842802ec4eb8fbbba7f84b0559ed2fc9511d4bf8178516f264d4bca12ebca96e14db4a120f7ada3ec638946c90`
- chain-tip contribution hash (SHA-512, printed by the verifier):
  `21ce39760acf61a76ca2b78bf23bea7ac992a7456dd02ce2276950114c7a371aff2cfc1086b6bcbf390d587df474349db71636118852d567131902afee278aad`

## Verify it yourself

```
cargo build --release --bin paraloom_ceremony_verify
target/release/paraloom_ceremony_verify \
  --initial-pk ceremony/withdraw/withdraw_v2_initial_proving.key \
  --transcript ceremony/withdraw/withdraw_ceremony_transcript.bin
```

Expected output:

```
Transcript verified. Circuit: withdraw, contributions: 4
  final contribution hash: 21ce39760acf61a76ca2b78bf23bea7ac992a7456dd02ce2276950114c7a371aff2cfc1086b6bcbf390d587df474349db71636118852d567131902afee278aad
```

This walks the hash chain and verifies every contribution's DLEQ
proof against the delta transition it claims.

## How the keys were finalized

```
target/release/paraloom_ceremony_finalize \
  --initial-pk keys/withdraw_v2_proving.key \
  --ceremony-pk 04_johnwiard_pk.key \
  --transcript 04_johnwiard_transcript.bin \
  --output-pk keys/withdraw_ceremony_proving.key \
  --output-vk keys/withdraw_ceremony_verifying.key \
  --initial-srs-hash dc95c7c0…946c90 \
  --min-contributions 4 \
  --final-contribution-hash 21ce3976…278aad
```

Finalize re-verifies the transcript end to end, binds the promoted
key's delta to the chain tip, checks the key's `h_query`/`l_query`
are the consistent `δ⁻¹` scaling via pairings, and refuses anything
that fails a policy gate (#344). The promoted proving key is
byte-identical to the last contributor's output — `SHA256SUMS`
shows `withdraw_ceremony_proving.key` and contribution #4's key
share the digest `5c1536d5…`.

## Honest scope

- Contributor identity is bound socially (the coordinator handed
  files to one known operator at a time over Discord DM), not
  cryptographically: the contribute CLI does not yet populate the
  transcript's signature fields. Signature enforcement is a mainnet
  ceremony gate, tracked in #64.
- These keys replace the single-party dev keys on devnet at the
  upcoming redeploy. The mainnet ceremony (#64) will re-run this
  process with signatures enforced.
