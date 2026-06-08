#!/usr/bin/env bash
#
# Private-swap end-to-end demo: localnet MAINNET-FORK setup (#240).
#
# ---------------------------------------------------------------------------
# WHY A FORK
# ---------------------------------------------------------------------------
# Jupiter's aggregator and the DEX liquidity it routes through live on
# MAINNET only — there is no devnet/testnet Jupiter API and no devnet pool
# liquidity for SOL/USDC. So a REAL swap cannot run on plain devnet.
#
# This script stands up a local `solana-test-validator` that CLONES the
# Jupiter v6 program, the AMM program(s), and the SOL/USDC pool accounts from
# mainnet, then deploys the Paraloom program locally. The private-swap demo
# (`cargo run --bin private-swap-demo`) then runs the whole flow with a REAL
# Jupiter swap against that forked mainnet liquidity — no real money moves.
#
# HONEST FRAMING: the swap leg uses mainnet liquidity (forked here); Paraloom's
# own deposit/withdraw legs are also live and publicly verifiable on devnet
# separately (the wallet flow). Forking just provides the public DEX liquidity
# the swap leg needs that devnet lacks.
#
# ---------------------------------------------------------------------------
# HOW TO RUN
# ---------------------------------------------------------------------------
#   1. scripts/localnet/private_swap_fork.sh         # starts validator + deploys
#   2. export the SOLANA_RPC_URL / SOLANA_PROGRAM_ID / BRIDGE_AUTHORITY_KEYPAIR_PATH
#      lines it prints
#   3. cargo run --bin private-swap-demo
#
# Requires: solana-cli (solana-test-validator, solana), cargo build-sbf, jq.
#
# ---------------------------------------------------------------------------
# COMPLETING THE CLONE LIST (read this if the swap fails on a missing account)
# ---------------------------------------------------------------------------
# Jupiter picks the *cheapest* route at quote time, and the exact pool / tick /
# oracle accounts that route touches are only known once you have a concrete
# quote+swap transaction. The set below clones a sensible SOL/USDC route
# (Jupiter program + Orca Whirlpool + Raydium CLMM + the two mints + the main
# Orca SOL/USDC whirlpool). If a swap fails with "account not found" / a program
# error referencing an un-cloned key, discover the missing accounts like this:
#
#   # against MAINNET, build a real SOL->USDC swap and read its account keys
#   AMOUNT=50000000  # 0.05 SOL in lamports
#   Q=$(curl -s "https://quote-api.jup.ag/v6/quote?inputMint=So11111111111111111111111111111111111111112&outputMint=EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v&amount=$AMOUNT&slippageBps=50")
#   curl -s -X POST https://quote-api.jup.ag/v6/swap \
#     -H 'Content-Type: application/json' \
#     -d "{\"quoteResponse\":$Q,\"userPublicKey\":\"<any-pubkey>\",\"wrapAndUnwrapSol\":true}" \
#     | jq -r '.swapTransaction' | base64 -d > /tmp/swap.bin
#   # decode the message and list every static account key, then add each to
#   # the CLONE_ACCOUNTS / CLONE_PROGRAMS lists below and re-run this script.
#   # (`solana decode-transaction` or any tx decoder reads the keys.)
#
# Cloning every account the quote references makes the local swap execute
# byte-for-byte the same route as mainnet.
set -eu

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO"

# We rewrite programs/paraloom/src/lib.rs's declare_id! to the local deploy key
# below. Snapshot it and restore on ANY exit so the committed source is never
# left modified (the devnet id stays canonical in git).
LIB_RS="programs/paraloom/src/lib.rs"
LIB_RS_BACKUP="$(mktemp)"
cp "$LIB_RS" "$LIB_RS_BACKUP"
restore_lib_rs() { cp "$LIB_RS_BACKUP" "$LIB_RS"; rm -f "$LIB_RS_BACKUP" "${LIB_RS}.bak"; }
trap restore_lib_rs EXIT

MAINNET_RPC="${MAINNET_RPC:-https://api.mainnet-beta.solana.com}"
RPC_PORT="${RPC_PORT:-8899}"
LEDGER="${LEDGER:-/tmp/paraloom-swap-fork-ledger}"
PROGRAM_SO="${PROGRAM_SO:-programs/paraloom/target/deploy/paraloom_program.so}"
AUTHORITY_KEYPAIR="${AUTHORITY_KEYPAIR:-$HOME/.config/solana/id.json}"

# Well-known mainnet mints.
WSOL="So11111111111111111111111111111111111111112"
USDC="EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"

# Upgradeable programs the SOL/USDC route can touch. `--clone-upgradeable-program`
# clones the program + its ProgramData so the BPF executes locally.
CLONE_PROGRAMS=(
  "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"   # Jupiter v6 aggregator
  "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc"   # Orca Whirlpool CLMM
  "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK"  # Raydium CLMM
)

# Data accounts to clone (pool state, mints, vaults, tick arrays, oracle). The
# pool-side accounts below are the exact ones Jupiter's live SOL->USDC Whirlpool
# direct route touches, discovered by decoding the swap tx (see the header note).
# They are stable across runs — only the ephemeral user/ATA accounts vary, and
# those are created locally at swap time, not cloned.
CLONE_ACCOUNTS=(
  "$WSOL"
  "$USDC"
  # Orca SOL/USDC Whirlpool the current direct route prefers, plus its vaults,
  # tick arrays, and oracle (all referenced by the route's Swap instruction).
  "FpCMFDFGYotvufJ7HrFHsWEiiQCGbkLCtwHiDnh7o28Q"  # whirlpool (route pool)
  "5os4kc32895qa1smTDGsAVXRiisXRo4UJWauUePnas1u"
  "6c4XJyitgSGkL2NyMULRt2zmssmpQzHonozVoZiD6uNb"
  "6mQ8xEaHdTikyMvvMxUctYch6dUjnKgfoeib2msyMMi1"
  "AQ36QRk3HAe6PHqBCtKTQnYKpt2kAagq9YoeTqUPMGHx"
  "BnVEE8KQgD6p7KkjDSXH3apFwi7ExHhTGgqDTRrhkQCo"
  "FqCcSudbMfFYiZEXTchAk4wVr6yfWmAcx3uEf5xyx4yV"
  "G9xKTRhM57AL4my3ZRVNqM95mxtACgKdNRPX6EVhB7hv"
  "923j69hYbT5Set5kYfiQr1D8jPL6z15tbfTbVLSwUWJD"
  # Earlier baseline whirlpools, kept in case the route shifts back to them.
  "Czfq3xZZDmsdGdUyrNLtRhGc47cXcZtLG4crryfu44zE"  # Orca SOL/USDC whirlpool (0.04%)
  "HJPjoWUrhoZzkNfRpHuieeFk9WcZWjwy6PBjZ81ngndJ"  # Orca SOL/USDC whirlpool (0.30%)
)

command -v solana-test-validator >/dev/null || {
  echo "solana-test-validator not found; install the Solana CLI." >&2; exit 1; }
command -v cargo-build-sbf >/dev/null || command -v cargo >/dev/null || {
  echo "cargo build-sbf not found; install the Solana SBF toolchain." >&2; exit 1; }

command -v anchor >/dev/null || {
  echo "anchor CLI not found (needed to sync declare_id! to the deploy key)." >&2; exit 1; }

# The authority is BOTH the deploy/upgrade authority and the bridge authority,
# so the #204 init gate ("signer must be the program's upgrade authority") is
# satisfied. Generate it first so the program keypair's upgrade authority is it.
if [ ! -f "$AUTHORITY_KEYPAIR" ]; then
  echo "Generating an authority keypair at $AUTHORITY_KEYPAIR"
  solana-keygen new --no-bip39-passphrase --silent --outfile "$AUTHORITY_KEYPAIR"
fi
AUTHORITY_PUBKEY="$(solana address -k "$AUTHORITY_KEYPAIR")"

# Deploy the program at a LOCAL program keypair and sync `declare_id!` to it, so
# the deployed address == declare_id (a mismatch bricks every write — Anchor
# 4100 / DeclaredProgramIdMismatch) AND the deploy is upgradeable with a real
# ProgramData account the #204 gate reads. We do NOT reuse the committed devnet
# id here because we don't hold its key and an upgradeable deploy needs the key.
PROGRAM_KEYPAIR="${PROGRAM_KEYPAIR:-/tmp/paraloom-swap-fork-program.json}"
[ -f "$PROGRAM_KEYPAIR" ] || solana-keygen new --no-bip39-passphrase --silent --outfile "$PROGRAM_KEYPAIR"
PROGRAM_ID="$(solana address -k "$PROGRAM_KEYPAIR")"
echo "Local program id (declare_id! synced to this): $PROGRAM_ID"

echo "=== Syncing declare_id! and building the program (cargo build-sbf) ==="
# anchor keys sync rewrites declare_id!/Anchor.toml to the program keypair under
# target/deploy. Point it at our keypair, then build.
cp "$PROGRAM_KEYPAIR" programs/paraloom/target/deploy/paraloom_program-keypair.json 2>/dev/null || {
  mkdir -p programs/paraloom/target/deploy
  cp "$PROGRAM_KEYPAIR" programs/paraloom/target/deploy/paraloom_program-keypair.json
}
( cd programs/paraloom && anchor keys sync >/dev/null 2>&1 || true )
# Pin declare_id! directly in case anchor keys sync is a no-op for this layout.
sed -i.bak -E "s/declare_id!\(\"[^\"]+\"\)/declare_id!(\"$PROGRAM_ID\")/" programs/paraloom/src/lib.rs
( cd programs/paraloom && cargo build-sbf )

# Live-route discovery: Jupiter's best SOL->USDC Whirlpool route shifts with the
# market, so a static pool list goes stale. Ask Jupiter for the swap tx the demo
# will build (same amount, onlyDirectRoutes + dexes=Whirlpool + legacy) and clone
# the exact pool-side accounts it references — whirlpool, vaults, tick arrays,
# oracle. These are stable enough between this call and the demo run seconds
# later. On any failure (e.g. offline) we fall back to the static list above.
DISCOVER_AMOUNT="${DISCOVER_AMOUNT:-45000000}" # 0.05 SOL deposit - 0.005 overhead
echo "=== Discovering the current Whirlpool SOL->USDC route accounts ==="
DISCOVERED="$(python3 - "$WSOL" "$USDC" "$DISCOVER_AMOUNT" <<'PY' 2>/dev/null || true
import json,sys,urllib.request,base64
BASE="https://lite-api.jup.ag/swap/v1"
sol,usdc,amount=sys.argv[1],sys.argv[2],sys.argv[3]
known={sol,usdc,"11111111111111111111111111111111","11111111111111111111111111111112",
 "ComputeBudget111111111111111111111111111111","TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
 "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL","JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
 "whirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc","D8cy77BBepLMngZx6ZukaTff5hCt1HrWyKk3Hnd9oitf"}
def b58(b):
    a="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n=int.from_bytes(b,'big');s=""
    while n>0:n,r=divmod(n,58);s=a[r]+s
    return "1"*(len(b)-len(b.lstrip(b'\x00')))+s
def cu16(b,i):
    v=b[i]
    return (v,i+1) if v<0x80 else ((v&0x7f)|(b[i+1]<<7),i+2)
q=urllib.request.urlopen(f"{BASE}/quote?inputMint={sol}&outputMint={usdc}&amount={amount}&slippageBps=50&onlyDirectRoutes=true&dexes=Whirlpool&asLegacyTransaction=true").read()
body={"quoteResponse":json.loads(q),"userPublicKey":"11111111111111111111111111111112","wrapAndUnwrapSol":True,"asLegacyTransaction":True}
r=urllib.request.Request(f"{BASE}/swap",data=json.dumps(body).encode(),headers={"Content-Type":"application/json"})
raw=base64.b64decode(json.loads(urllib.request.urlopen(r).read())["swapTransaction"])
i=0;nsig,i=cu16(raw,i);i+=nsig*64;i+=3;nkeys,i=cu16(raw,i)
out=[]
for _ in range(nkeys):
    k=b58(raw[i:i+32]);i+=32
    if k not in known:out.append(k)
print(" ".join(out))
PY
)"
if [ -n "$DISCOVERED" ]; then
  echo "  discovered route accounts: $DISCOVERED"
  for a in $DISCOVERED; do CLONE_ACCOUNTS+=("$a"); done
else
  echo "  discovery unavailable; using the static pool list"
fi

# Assemble the validator's clone flags.
CLONE_FLAGS=()
for p in "${CLONE_PROGRAMS[@]}"; do CLONE_FLAGS+=(--clone-upgradeable-program "$p"); done
# De-dup the accounts (the static list and discovery can overlap).
for a in $(printf '%s\n' "${CLONE_ACCOUNTS[@]}" | awk '!seen[$0]++'); do CLONE_FLAGS+=(--clone "$a"); done

echo "=== Starting solana-test-validator (mainnet-fork) ==="
echo "Cloning ${#CLONE_PROGRAMS[@]} programs + ${#CLONE_ACCOUNTS[@]} accounts from $MAINNET_RPC"
rm -rf "$LEDGER"
# Start WITHOUT the program; we deploy it upgradeably below so #204 sees a real
# upgrade authority (a --bpf-program load is non-upgradeable and fails the gate).
solana-test-validator \
  --reset \
  --ledger "$LEDGER" \
  --rpc-port "$RPC_PORT" \
  --url "$MAINNET_RPC" \
  "${CLONE_FLAGS[@]}" \
  > /tmp/paraloom-swap-fork-validator.log 2>&1 &
VALIDATOR_PID=$!
echo "validator pid $VALIDATOR_PID (log: /tmp/paraloom-swap-fork-validator.log)"

RPC_URL="http://127.0.0.1:$RPC_PORT"
echo "Waiting for the validator RPC to come up..."
until solana --url "$RPC_URL" cluster-version >/dev/null 2>&1; do
  kill -0 "$VALIDATOR_PID" 2>/dev/null || { echo "validator died; see log" >&2; exit 1; }
  sleep 1
done
echo "validator up at $RPC_URL"

solana --url "$RPC_URL" airdrop 100 "$AUTHORITY_PUBKEY" >/dev/null
echo "Funded authority $AUTHORITY_PUBKEY with 100 SOL"

echo "=== Deploying the Paraloom program (upgradeable, authority = $AUTHORITY_PUBKEY) ==="
solana --url "$RPC_URL" -k "$AUTHORITY_KEYPAIR" program deploy \
  --program-id "$PROGRAM_KEYPAIR" \
  --upgrade-authority "$AUTHORITY_KEYPAIR" \
  "$PROGRAM_SO"

export SOLANA_RPC_URL="$RPC_URL"
export SOLANA_PROGRAM_ID="$PROGRAM_ID"
export BRIDGE_AUTHORITY_KEYPAIR_PATH="$AUTHORITY_KEYPAIR"
export VALIDATOR_KEYPAIR_PATH="$AUTHORITY_KEYPAIR"

echo "=== Bootstrapping the Paraloom bridge on the fork ==="
# registry (#204-gated to the program upgrade authority = our authority) ->
# register the authority as a validator (the withdraw legs credit its validator
# account) -> bridge-init (also #204-gated). All signed by the authority, which
# is the upgrade authority of the deploy above, so the gates pass.
cargo run --quiet --bin init-validator-registry
cargo run --quiet --bin register-validator
cargo run --quiet --bin bridge-init

cat <<EOF

=== READY ===
Export these, then run the demo:

  export SOLANA_RPC_URL="$RPC_URL"
  export SOLANA_PROGRAM_ID="$PROGRAM_ID"
  export BRIDGE_AUTHORITY_KEYPAIR_PATH="$AUTHORITY_KEYPAIR"

  cargo run --bin private-swap-demo

The validator is running as pid $VALIDATOR_PID. Stop it with:
  kill $VALIDATOR_PID

If the swap leg fails on a missing cloned account, extend CLONE_ACCOUNTS /
CLONE_PROGRAMS per the discovery note at the top of this script and re-run.
EOF
