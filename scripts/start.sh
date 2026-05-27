#!/usr/bin/env bash
#
# Bring up a local Paraloom validator set against Solana devnet and wait until
# the bootstrap node has registered a quorum-sized set of validators.
#
# Together with demo.sh this reproduces an end-to-end shielded withdrawal:
# deposit -> validator quorum -> on-chain settlement (#164).
#
# Required environment:
#   SOLANA_RPC_URL   devnet RPC endpoint (an API-keyed endpoint is recommended;
#                    the public endpoint is rate limited)
#
# Optional environment (defaults in parentheses):
#   PROGRAM_ID       bridge program id (8gPsRSm1CAw38mfzc1bcLMUXyFN7LnS8k6CV5hPUTWrP)
#   AUTHORITY_KEYPAIR funded keypair that signs settlements
#                    (~/.config/solana/paraloom-devnet.json)
#   VALIDATORS       number of validators to launch (12)
#   DEMO_DIR         working directory for configs and logs (/tmp/paraloom-demo)
#   BASE_PORT        first libp2p port; node i listens on BASE_PORT+i (9300)
#
# Prerequisite: the withdrawal trusted-setup keys must exist (keys/withdraw_*_v4.key);
# generate them once with `cargo run --release --bin setup-withdrawal-ceremony`.
set -eu

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
: "${SOLANA_RPC_URL:?set SOLANA_RPC_URL to a devnet endpoint}"
PROGRAM_ID="${PROGRAM_ID:-8gPsRSm1CAw38mfzc1bcLMUXyFN7LnS8k6CV5hPUTWrP}"
AUTHORITY_KEYPAIR="${AUTHORITY_KEYPAIR:-$HOME/.config/solana/paraloom-devnet.json}"
VALIDATORS="${VALIDATORS:-12}"
DEMO_DIR="${DEMO_DIR:-/tmp/paraloom-demo}"
BASE_PORT="${BASE_PORT:-9300}"

# The quorum is fixed at 7 valid votes (DEFAULT_MIN_VALIDATORS_FOR_CONSENSUS);
# over-provisioning past it absorbs the validators that mesh slowly.
QUORUM=7
BIN="$REPO/target/release/paraloom-node"
LOG_FILTER="warn,paraloom::node=info,paraloom::consensus=info,paraloom::bridge::solana=info"

# Run from the repo root so cargo and the relative trusted-setup key paths
# (keys/withdraw_*_v4.key, loaded by each validator) resolve.
cd "$REPO"
cargo build --release -q --bin paraloom-node
mkdir -p "$DEMO_DIR"
pkill -9 -f "$DEMO_DIR/v" 2>/dev/null || true
sleep 2

# Node 1 is the bootstrap node and also hosts the read-only Merkle path server
# and the withdrawal ingress. The rest bootstrap off the first three nodes
# rather than node 1 alone: a single bootstrap anchor makes the mesh a star
# whose centre is a bottleneck, and validators that miss its registration
# handshake never join the quorum.
config_for() {
  local i="$1" port=$((BASE_PORT + i)) boot mp ing
  if [ "$i" = 1 ]; then
    boot="[]"; mp="127.0.0.1:9391"; ing="127.0.0.1:9491"
  else
    boot='["/ip4/127.0.0.1/tcp/9301","/ip4/127.0.0.1/tcp/9302","/ip4/127.0.0.1/tcp/9303"]'
    mp=""; ing=""
  fi
  cat > "$DEMO_DIR/v$i.toml" <<EOF
[network]
listen_address = "/ip4/127.0.0.1/tcp/$port"
bootstrap_nodes = $boot
enable_mdns = false
[node]
node_type = "ResourceProvider"
max_cpu_usage = 80
max_memory_usage = 70
max_storage_usage = 10240
[storage]
data_dir = "$DEMO_DIR/v$i-data"
[bridge]
solana_rpc_url = "$SOLANA_RPC_URL"
program_id = "$PROGRAM_ID"
poll_interval_secs = 8
enabled = true
authority_keypair_path = "$AUTHORITY_KEYPAIR"
event_lag_warn_threshold_slots = 1500
withdrawal_expiration_window_slots = 150
merkle_path_query_address = "$mp"
withdrawal_ingress_address = "$ing"
EOF
  rm -rf "$DEMO_DIR/v$i-data"
}

launch() {
  local i="$1"
  nohup env RUST_LOG="$LOG_FILTER" "$BIN" start --config "$DEMO_DIR/v$i.toml" \
    > "$DEMO_DIR/v$i.log" 2>&1 &
}

for i in $(seq 1 "$VALIDATORS"); do config_for "$i"; done

echo "starting bootstrap node"
launch 1
# A peer's bootstrap dial is one-shot, so wait until node 1 accepts connections
# before launching the rest; staggering the launches avoids an accept storm.
until nc -z 127.0.0.1 9301 2>/dev/null; do sleep 1; done
echo "starting $((VALIDATORS - 1)) peer validators"
for i in $(seq 2 "$VALIDATORS"); do launch "$i"; sleep 1; done

echo "waiting for the validator set to register"
registered=0
for _ in $(seq 1 12); do
  sleep 10
  registered=$(grep "Validator registered for consensus" "$DEMO_DIR/v1.log" 2>/dev/null \
    | grep -oE "NodeId\(\[[0-9, ]+\]\)" | sort -u | wc -l | tr -d ' ')
  echo "registered: $registered/$QUORUM"
  [ "$registered" -ge "$QUORUM" ] && break
done

if [ "$registered" -lt "$QUORUM" ]; then
  echo "only $registered validators registered; quorum needs $QUORUM" >&2
  exit 1
fi
echo "ready"
