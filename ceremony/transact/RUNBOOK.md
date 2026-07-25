# Transact v3 ceremony — runbook

The phase-2 multi-party trusted setup for `TransactCircuitV3`, the circuit
every shielded settlement is verified against. Tracking issue: #659.

This round differs from the withdraw and transfer rounds in two ways that
matter to everyone involved:

- **It starts from a public transcript.** The chain builds on the Perpetual
  Powers of Tau output (54 contributions plus a beacon), not on a key generated
  on the coordinator's machine. That is what makes "one honest contributor is
  enough" a true statement rather than a hopeful one — the earlier rounds could
  not claim it, because the `α`, `β` and `τ` they inherited came from a single
  laptop. `src/ceremony/phase1_trapdoor.rs` demonstrates why.
- **Contributors run snarkjs, not our CLI.** Nothing to compile. The commands
  below are the whole of it.

Every command here was executed end to end in rehearsal before being written
down, including the beacon.

---

## What a contributor does

You need [Node.js](https://nodejs.org) and one file from the coordinator:
`paraloom_<NN>.zkey`, about 28 MB. You do **not** need the powers-of-tau file,
the circuit, or this repository.

```bash
npx snarkjs@0.7.5 zkey contribute paraloom_<NN>.zkey paraloom_<NN+1>.zkey \
  --name="<your name or handle>"
```

It asks for a source of randomness — type whatever you like, at length. Your
entropy is combined with the machine's, used once, and never written anywhere.
It takes under a minute.

Send `paraloom_<NN+1>.zkey` back to the coordinator. Then **delete your local
copies and the terminal history**, and do not tell anyone what you typed. That
act — not the contribution itself — is what secures the setup: the final key is
safe as long as at least one contributor genuinely discarded their share, and
nobody can tell which one did.

snarkjs prints a contribution hash when it finishes. Keep it. It will appear in
the published transcript, and it is how you confirm your contribution is the
one that was included.

## What the coordinator does

### Before contribution #1

1. **Freeze the circuit.** Commit `.ceremony-in-progress` to `main` with the
   tag and start time. `.github/workflows/circuit-freeze.yml` then rejects any
   PR touching `src/privacy/circuits.rs` or the Poseidon gadgets. A constraint
   change mid-chain invalidates every contribution made so far — there is no
   partial recovery, the whole chain restarts from a fresh key.
2. **Fetch and check the transcript.**
   ```bash
   curl -O https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_16.ptau
   b2sum powersOfTau28_hez_final_16.ptau
   # 6a6277a2f74e1073601b4f9fed6e1e55226917efb0f0db8a07d98ab01df1ccf4
   # 3eb0e8c3159432acd4960e2f29fe84a4198501fa54c8dad9e43297453efec125
   ```
   Power 16 rather than the minimum 15: the circuit's domain input is 18,486,
   so 2^15 only just fits and leaves no room for a later constraint.
3. **Export the circuit and build the initial key.**
   ```bash
   cargo run --release --bin export_transact_v3_r1cs
   snarkjs r1cs info artifacts/transact_v3.r1cs     # 18477 constraints, 8 public inputs
   snarkjs groth16 setup artifacts/transact_v3.r1cs \
     powersOfTau28_hez_final_16.ptau paraloom_0000.zkey
   ```
   Record the circuit hash it prints. Publish the `.r1cs` alongside the final
   package so anyone can regenerate it and compare.
4. **Announce the beacon in advance** — see below.

### After each contribution

```bash
snarkjs zkey verify artifacts/transact_v3.r1cs \
  powersOfTau28_hez_final_16.ptau paraloom_<NN>.zkey
```

Expect `ZKey Ok!` and the contribution listed. Record the hash and confirm it
against the one the contributor reported. Only then pass the file on. Never
hand the same file to two people in parallel: the chain is linear, and two
contributions from one parent produce a fork where only one can survive.

### Closing the chain

The last step is a public random value nobody could have known in advance, so
the final contributor cannot grind their own share for a result they like.

```bash
snarkjs zkey beacon paraloom_<NN>.zkey paraloom_final.zkey <beaconHash> 10 \
  -n="Final Beacon phase2"
```

The beacon value has to be announced *before* the chain starts and be
independently checkable afterwards — a Bitcoin block hash at a stated future
height is the usual choice. `snarkjs zkey verify` prints the generator and
iteration count, so anyone can re-derive the final step.

### Cutting the key in

```bash
snarkjs zkey export verificationkey paraloom_final.zkey verification_key.json
snarkjs zkey export json paraloom_final.zkey paraloom_final.json
cargo run --release --bin zkey_json_to_arkworks -- \
  paraloom_final.json keys/transact_v3_proving.key
```

Then regenerate the on-chain constants and re-run the program tests:

```bash
TRANSACT_V3_PROVING_KEY=keys/transact_v3_proving.key \
TRANSACT_V3_VERIFYING_KEY=keys/transact_v3_verifying.key \
  cargo run --release --bin emit_transact_v3_fixture
cargo test --manifest-path programs/paraloom/Cargo.toml
```

The key is a circom-convention key, so **proof generation must switch to
`CircomReduction`** in `src/privacy/circuits.rs` and in `paraloom-prover-wasm`.
A key and its reduction move together; the default reduction against this key
produces proofs that do not verify. Verification is unaffected, so the on-chain
verifier needs only the regenerated constants.

Finally: remove `.ceremony-in-progress`, publish the package, and note that
validators cache the verifying key at startup — they need a restart, and the
wallet needs rebuilding and republishing before users can produce valid proofs.

---

## Open decisions

**File transport.** Each handoff moves a ~28 MB zkey. The previous rounds used
Discord DMs, which will not work here: the free upload limit is 25 MB and the
file exceeds it. Needs a host both sides can reach — a GitHub release asset,
object storage, or IPFS. Whatever is chosen, publish a checksum with each file
so a contributor can tell they received what was sent.

**Beacon source and height.** Must be fixed and announced before contribution
#1.

**Running order.** Locked before the chain starts, not adjusted mid-flight.
