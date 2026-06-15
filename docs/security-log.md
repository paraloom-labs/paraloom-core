# Security log

A public record of security-relevant findings and the fixes that closed them.
Everything here was found and fixed **pre-mainnet, on devnet — no real funds
were ever at risk**. Newest first. Each entry links the public issue so anyone
can verify it.

This is the log referenced by [`SECURITY.md`](../SECURITY.md). To report a new
issue, email security@paraloom.network.

## 2026-06

- **On-chain validator quorum for settlement**
  ([#260](https://github.com/paraloom-labs/paraloom-core/issues/260)).
  Settlement (`withdraw` and `shielded_transfer`) previously relied on a single
  settlement authority key (`has_one = authority`). The program now requires a
  BFT supermajority of registered validators to co-sign the transaction,
  verified on-chain against the validator registry. Each validator that approved the
  operation independently rebuilds the settlement transaction from the
  parameters it verified and signs that; the round leader only assembles the
  collected signatures. A single compromised settlement key can no longer move
  funds, and a malicious leader cannot redirect a withdrawal — a co-signer signs
  only a transaction it reconstructed from the parameters it saw, so a
  substituted recipient or amount is refused. This binds the recipient that the
  proof itself does not yet constrain.

- **On-chain proof verification for withdrawals and shielded transfers**
  ([#165](https://github.com/paraloom-labs/paraloom-core/issues/165),
  [#194](https://github.com/paraloom-labs/paraloom-core/issues/194)).
  The program previously recorded the Groth16 proof and relied on the off-chain
  validator quorum to verify it. It now verifies the proof itself, on-chain, via
  Solana's `alt_bn128` (BN254) syscalls — bound to the published Merkle root and
  the operation's nullifiers and amount/commitments. A settling validator can no
  longer forge or redirect a withdrawal or transfer despite holding the
  settlement authority.

- **Canonical field-element encoding at the proof-verify boundary**
  ([#231](https://github.com/paraloom-labs/paraloom-core/issues/231)).
  Adversarial circuit review found that non-canonical encodings of nullifiers and
  commitments could be accepted; encoding is now enforced canonical, closing a
  double-spend vector before mainnet.

## Earlier

- **Initialize front-run gate**
  ([#204](https://github.com/paraloom-labs/paraloom-core/issues/204)).
  The `initialize` instructions are pinned to the program's upgrade authority, so
  the bridge state cannot be initialized by a front-runner.

- **Withdraw settlement binding + proof-length bound**
  ([#178](https://github.com/paraloom-labs/paraloom-core/issues/178)).
  `has_one = authority` on `withdraw` plus a bound on the proof blob size.

- **Range constraints on values**
  ([#60](https://github.com/paraloom-labs/paraloom-core/issues/60)).
  In-circuit range constraints prevent forging value by assigning a
  near-field-prime amount.

- **Withdrawal replay protection**
  ([#61](https://github.com/paraloom-labs/paraloom-core/issues/61)).
  Each spent note is recorded as a nullifier PDA; re-spending the same nullifier
  fails on the already-initialized account.

- **Consistent commitment / nullifier derivation across circuits**
  ([#56](https://github.com/paraloom-labs/paraloom-core/issues/56)).
  Deposit, transfer, and withdraw derive commitments and nullifiers identically,
  so a note created on one path is spendable (and only once) on the others.

- **Graceful verifying-key load**
  ([#57](https://github.com/paraloom-labs/paraloom-core/issues/57)).
  A missing or malformed verifying key returns an error instead of panicking the
  node.
