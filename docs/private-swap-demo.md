# Private-swap end-to-end demo (#240)

An end-to-end run of the full private-swap flow: deposit a shielded note,
withdraw it to a fresh unlinkable address, perform a **real Jupiter SOL→USDC
swap** there, and re-deposit the output into a new shielded balance.

## Honest framing: why a mainnet-fork

Jupiter's aggregator and the DEX liquidity it routes through are **mainnet-only**
— there is no devnet/testnet Jupiter API and no devnet SOL/USDC pool liquidity.
A real swap therefore cannot run against plain devnet.

The demo runs against a **localnet mainnet-fork**: a `solana-test-validator`
with the Jupiter v6 program, the AMM program(s), and the SOL/USDC pool accounts
**cloned from mainnet**, plus the Paraloom program deployed locally. The swap leg
then trades against that forked mainnet liquidity — real routing, **no real
money** moves.

The swap leg uses mainnet liquidity (forked here). Paraloom's own deposit and
withdraw legs are also live and publicly verifiable on **devnet** separately
(that is the wallet's deposit→withdraw flow). The fork only supplies the public
DEX liquidity the swap leg needs that devnet lacks.

If you run the demo against plain devnet (no fork), the swap step returns
`NoRoute` and the demo narrates that honestly instead of faking a success — the
Paraloom deposit leg still executes on-chain.

## How to run

```
# 1. Start the mainnet-fork validator and deploy + bootstrap Paraloom on it.
scripts/localnet/private_swap_fork.sh

# 2. Export the env it prints (RPC, program id, authority key), e.g.
export SOLANA_RPC_URL="http://127.0.0.1:8899"
export SOLANA_PROGRAM_ID="8gPsRSm1CAw38mfzc1bcLMUXyFN7LnS8k6CV5hPUTWrP"
export BRIDGE_AUTHORITY_KEYPAIR_PATH="$HOME/.config/solana/id.json"

# 3. Run the demo.
cargo run --bin private-swap-demo
```

Prerequisites: the Solana CLI (`solana-test-validator`, `solana`,
`cargo build-sbf`), `jq`, and the withdrawal trusted-setup keys at
`keys/withdraw_proving_v3.key` / `keys/withdraw_verifying_v3.key` (generate once
with `cargo run --release --bin setup-withdrawal-ceremony`).

### Demo env vars

| var | default | meaning |
| --- | --- | --- |
| `SOLANA_RPC_URL` | `http://localhost:8899` | RPC endpoint (the fork) |
| `SOLANA_PROGRAM_ID` | _required_ | deployed Paraloom program id |
| `BRIDGE_AUTHORITY_KEYPAIR_PATH` | _required_ | funded, registered-validator authority |
| `USDC_MINT` | mainnet USDC | output mint |
| `SWAP_AMOUNT_LAMPORTS` | `50_000_000` (0.05 SOL) | note size to swap |
| `SLIPPAGE_BPS` | `50` | Jupiter slippage tolerance |
| `JUPITER_BASE_URL` | `https://quote-api.jup.ag/v6` | Jupiter v6 base |

## What composes the flow

- `src/bin/private_swap_demo.rs` — the orchestrator. Mirrors `demo_flow.rs` for
  the deposit + Groth16 proof, then builds the real relayer and runs it.
- `paraloom::relayer::PrivateSwapRelayer::execute` — withdraw → swap → re-deposit.
- `paraloom::relayer::JupiterSwapProvider` (`ReqwestJupiterClient` for routing,
  `RpcSwapSubmitter` for execution) — the real Jupiter v6 swap leg.
- `paraloom::relayer::OnChainSubmitter` — the production `Submitter`: the bridge
  **authority** signs the withdraw legs; the **fresh ephemeral** key signs the
  re-deposit leg. No key is shared with the user's original deposit, so the
  on-chain trace never ties the user to the swap.

## Completing the clone list

Jupiter picks the cheapest route at quote time, and the exact pool / tick-array
/ oracle accounts that route touches are only known once you have a concrete
quote+swap transaction. `scripts/localnet/private_swap_fork.sh` clones a sensible
SOL/USDC baseline (Jupiter v6 + Orca Whirlpool + Raydium CLMM + both mints + the
main Orca SOL/USDC whirlpools). If a swap fails on a missing cloned account,
follow the discovery recipe at the top of that script: build a real mainnet
SOL→USDC quote+swap, read every static account key out of the returned
transaction, and add each to the script's `CLONE_ACCOUNTS` / `CLONE_PROGRAMS`
lists. Cloning every account the quote references makes the local swap execute
the same route as mainnet, byte for byte.
