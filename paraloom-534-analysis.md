Fix: Remove blinding factor from on-chain deposit_note instruction

## Summary
`deposit_note` currently accepts `blinding: [u8; 32]` as an instruction argument and stores it in the transaction log. Since the blinding factor, combined with public on-chain data (amount, pubkey, asset), allows anyone to reconstruct the commitment, an observer can link deposits to subsequent shielded transfers — defeating the unlinkability guarantee.

## Root Cause
The rule is simple: **what the prover must keep secret must not appear on-chain**. While the `DepositNoteEvent` correctly omits blinding, the instruction itself carries blinding as a cleartext argument, placing it in the Solana tx log where any RPC reader can extract it.

## Fix

### On-chain (`lib.rs` `deposit_note`)
- Remove `blinding: [u8; 32]` from function parameters
- Accept a pre-computed `commitment: [u8; 32]` instead
- Verify `commitment == Poseidon(amount, pubkey, blinding, asset)` is no longer possible on-chain

### Client-side
- Compute `commitment = Poseidon(amount, pubkey, blinding, asset)` off-chain
- Submit only the pre-computed commitment to `deposit_note`

## Impact
- LOW severity (per issue classification)
- Breaks note unlinkability for all shielded deposits
- Chain analysis tools can build deposit → transfer graphs

## Root Cause Confirmation

After reading the source:

1. `programs/paraloom/src/lib.rs` fn `deposit_note()`:
   - Accepts `blinding: [u8; 32]` as parameter → appears in tx log
   - Computes `commitment = crate::merkle_tree::commitment(amount, &pubkey, &blinding, &NATIVE_SOL_ASSET)` on-chain
   - Emits `DepositNoteEvent` with `commitment` (correctly) but blinding is already exposed via tx log

2. `src/bridge/solana/instructions.rs` `DepositNoteInstructionData`:
   - `blinding: [u8; 32]` serialized as borsh field → fully visible in tx data

3. `src/privacy/types.rs`:
   - `spend_commitment(amount, pubkey, blinding, asset_id)` — the commitment formula is `Poseidon(amount, pubkey, blinding, asset_id)`
   - Anyone on-chain already has: amount (via event), pubkey (via depositor), asset (NATIVE_SOL_ASSET), blinding (via tx log)
   - → They can compute commitment → search `TransactEvent` for matching out_commitment → transfer

## Proposed Fix

The simplest fix: compute the commitment off-chain and submit only the commitment on-chain.

### Client (off-chain):
```
commitment = poseidon_commit_spend(amount, pubkey, blinding, asset_id)
// Submit commitment instead of raw blinding
deposit_note(amount, pubkey, commitment)
```

### On-chain
```
pub fn deposit_note(
    ctx: Context<DepositNote>,
    amount: u64,
    pubkey: [u8; 32],
    commitment: [u8; 32],     // was: blinding: [u8; 32]
) -> Result<()> {
    // commitment is already pre-computed — just append to tree
    let mut tree = ctx.accounts.merkle_tree.load_mut()?;
    tree.append(commitment)?;
    ...
}
```
