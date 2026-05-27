#!/usr/bin/env bash
#
# Drive an end-to-end shielded withdrawal against the validator set started by
# start.sh, and print the on-chain deposit and settlement transactions (#164).
#
# Flow:
#   1  deposit 0.1 SOL into the shielded pool on devnet
#   2  validators read the deposit from the chain and index it
#   3  build a Groth16 membership proof for the note
#   4  submit the proof; validators verify it and vote
#   5  on a >=7 quorum, the node that gathered the votes settles on-chain
#
# Required environment:
#   SOLANA_RPC_URL   devnet RPC endpoint (same one start.sh used)
#
# Optional environment (defaults in parentheses):
#   PROGRAM_ID       bridge program id (8gPsRSm1CAw38mfzc1bcLMUXyFN7LnS8k6CV5hPUTWrP)
#   AUTHORITY_KEYPAIR funded keypair that signs the deposit (~/.config/solana/paraloom-devnet.json)
#   DEMO_DIR         working directory shared with start.sh (/tmp/paraloom-demo)
#   PATH_SERVER      Merkle path query endpoint (http://127.0.0.1:9391)
#   INGRESS          withdrawal ingress endpoint (http://127.0.0.1:9491)
set -eu

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${SOLANA_RPC_URL:?set SOLANA_RPC_URL to a devnet endpoint}"
PROGRAM_ID="${PROGRAM_ID:-8gPsRSm1CAw38mfzc1bcLMUXyFN7LnS8k6CV5hPUTWrP}"
AUTHORITY_KEYPAIR="${AUTHORITY_KEYPAIR:-$HOME/.config/solana/paraloom-devnet.json}"
DEMO_DIR="${DEMO_DIR:-/tmp/paraloom-demo}"
PATH_SERVER="${PATH_SERVER:-http://127.0.0.1:9391}"
INGRESS="${INGRESS:-http://127.0.0.1:9491}"
LOG="$DEMO_DIR/v1.log"

# Run from the repo root so cargo and the relative proving-key path
# (keys/withdraw_proving_v4.key, loaded by demo-withdraw) resolve.
cd "$REPO"
cargo build --release -q --bin test-deposit --bin demo-withdraw
deposit="$REPO/target/release/test-deposit"
helper="$REPO/target/release/demo-withdraw"

step() { printf '\n=== %s\n' "$1"; }
link() { echo "https://explorer.solana.com/tx/$1?cluster=devnet"; }
jget() { python3 -c "import sys,json;print(json.load(open('$1'))$2)"; }

step "Validator set on Solana devnet"
running=$(ps ax | grep -c "[p]araloom-node start")
registered=$(grep "Validator registered for consensus" "$LOG" \
  | grep -oE "NodeId\(\[[0-9, ]+\]\)" | sort -u | wc -l | tr -d ' ')
stake=$(grep -oE "stake: [0-9]+" "$LOG" | head -1 | awk '{print $2/1000000000}')
printf 'validators running   : %s\n' "$running"
printf 'registered for BFT   : %s\n' "$registered"
printf 'quorum threshold     : 7 valid votes (a withdrawal settles only at >= 7)\n'
printf 'stake per validator  : %s SOL\n' "$stake"
printf 'bridge program       : %s\n' "$PROGRAM_ID"

step "1/5  Deposit 0.1 SOL into the shielded pool"
dep=$(SOLANA_RPC_URL="$SOLANA_RPC_URL" SOLANA_PROGRAM_ID="$PROGRAM_ID" \
  BRIDGE_AUTHORITY_KEYPAIR_PATH="$AUTHORITY_KEYPAIR" "$deposit" 2>/dev/null \
  | awk '/Signature:/{print $2}')
echo "deposit transaction: $dep"
link "$dep"

step "2/5  Validators read the deposit from the chain and index it"
commitment=$("$helper" commitment)
echo "note commitment: $commitment"
for _ in $(seq 1 15); do
  path=$(curl -s "$PATH_SERVER/merkle/path/$commitment")
  echo "$path" | grep -q root && break
  sleep 5
done
echo "$path" > "$DEMO_DIR/path.json"
echo "merkle path retrieved (tree depth $(jget "$DEMO_DIR/path.json" "['path'].__len__()"))"

step "3/5  Build a Groth16 proof that the note is in the pool"
MERKLE_ROOT=$(jget "$DEMO_DIR/path.json" "['root']") \
PATH_HEX=$(python3 -c "import json;print(json.dumps(json.load(open('$DEMO_DIR/path.json'))['path']))") \
INDICES=$(python3 -c "import json;print(json.dumps(json.load(open('$DEMO_DIR/path.json'))['indices']))") \
  "$helper" prove > "$DEMO_DIR/withdraw.json"
export MERKLE_ROOT PATH_HEX INDICES
echo "nullifier: $(jget "$DEMO_DIR/withdraw.json" "['nullifier']")"
echo "proof size: $(( $(jget "$DEMO_DIR/withdraw.json" "['proof'].__len__()") / 2 )) bytes"

step "4/5  Submit the proof — validators verify it and vote"
request=$(curl -s -X POST "$INGRESS/withdrawal/submit" -H 'Content-Type: application/json' \
  -d @"$DEMO_DIR/withdraw.json" | python3 -c "import sys,json;print(json.load(sys.stdin)['request_id'])")
echo "request id: $request"

step "5/5  Wait for the BFT quorum and the on-chain settlement"
sig=""
for _ in $(seq 1 25); do
  sig=$(awk "/on-chain withdraw submitted for $request:/{print \$NF}" "$LOG" | tail -1)
  [ -n "$sig" ] && break
  sleep 2
done
echo "validator votes received: $(grep -c "Received withdrawal verification result: $request" "$LOG")"
if [ -z "$sig" ]; then
  echo "no settlement within the wait window" >&2
  exit 1
fi
echo "settlement transaction: $sig"
link "$sig"
