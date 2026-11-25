#!/usr/bin/env bash
# ADR 0015 conformance harness: the Rust Elder Tree against every peer it has, with no Tor.
# A SOCKS5 shim (socks-shim.mjs) stands in for the Tor daemon and routes each "onion" to a
# loopback port, so the real Rust node announces to the real Rust Elder over the real announce
# path, two Rust Elders federate with each other in both directions, and the JavaScript
# reference verifies what the Rust Elder serves:
#
#   1. the Rust node heartbeats to the Rust Elder (accepted, with its signed caps) and sends
#      its private relay telemetry report (accepted, counted in the Elder's metrics);
#   2. a JavaScript-built announce (announce.mjs) is accepted by the Rust Elder;
#   3. the Rust Elder's /directory, /incidents and /telemetry/aggregate verify with the
#      JavaScript verifyDirectory, verifyIncidents and verifyRelayAggregate, fetched straight
#      and through the shim as a client would (fetchOverTor);
#   4. the peer Elder pulls the first Elder's canopy and lists the Rust node; the first Elder
#      pulls the peer's canopy and lists a node announced only there;
#   5. the Rust Elder's prober reaches the node through the shim and keeps it `up`.
#
# Prereqs: `npm install` at the repo root + a Rust toolchain.
# Run from anywhere: bash crates/shadenet-rln/interop/elder-run.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
source "$REPO/scripts/node-bin.sh"
NODE_CMD="$(shadenet_node_cmd "$REPO")"
WORK="$(mktemp -d)"

echo "== building the Elder (cargo build -p shadenet-elder) =="
cargo build --locked -p shadenet-elder --manifest-path "$REPO/Cargo.toml" >&2
ELDER_BIN="$REPO/target/debug/shadenet-elder"

SHIM_PORT="${SHADE_TREE_ELDER_TEST_SHIM_PORT:-18550}"
ELDER_PORT="${SHADE_TREE_ELDER_TEST_RUST_PORT:-18551}"
PEER_PORT="${SHADE_TREE_ELDER_TEST_PEER_PORT:-18552}"
METRICS_PORT="${SHADE_TREE_ELDER_TEST_METRICS_PORT:-18553}"
GW_PORT="${SHADE_TREE_ELDER_TEST_GATEWAY_PORT:-18554}"

PIDS=()
cleanup() {
  for pid in "${PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM HUP PIPE

echo "== minting the identities (shadenet-elder identity) =="
"$ELDER_BIN" identity "$WORK/elder-hs" --label elder >/dev/null
"$ELDER_BIN" identity "$WORK/peer-hs" --label peer >/dev/null
"$ELDER_BIN" identity "$WORK/node-hs" --label node >/dev/null
ELDER_ONION="$(cat "$WORK/elder-hs/hostname")"
PEER_ONION="$(cat "$WORK/peer-hs/hostname")"
NODE_ONION="$(cat "$WORK/node-hs/hostname")"
echo "   elder  $ELDER_ONION"
echo "   peer   $PEER_ONION"
echo "   node   $NODE_ONION"

echo "== the SOCKS shim stands in for Tor =="
node "$HERE/socks-shim.mjs" "$SHIM_PORT" \
  "{\"$ELDER_ONION\":$ELDER_PORT,\"$PEER_ONION\":$PEER_PORT,\"$NODE_ONION\":$GW_PORT}" \
  > "$WORK/shim.log" 2>&1 &
PIDS+=($!)
node "$HERE/wait-log.mjs" "$WORK/shim.log" "[shim] up" 15000

# $1 = port, $2 = hs dir, $3 = peer onion, $4 = log, then any extra settings
start_elder() {
  local port="$1" hs="$2" peer="$3" log="$4"
  shift 4
  env "$@" \
  SHADE_TREE_BOOTNODE_PORT="$port" \
  SHADE_TREE_BOOTNODE_SIGNER_KEY="$hs/signer.key" \
  SHADE_TREE_BOOTNODE_STORE="$hs/store.json" \
  SHADE_TREE_BOOTNODE_INCIDENTS_FILE="$hs/incidents.json" \
  SHADE_TREE_RELAY_ELDER_STATE="$hs/relay-state.json" \
  SHADE_TREE_BOOTNODE_ONION="$(cat "$hs/hostname")" \
  SHADE_TREE_BOOTNODE_PEERS="$peer" \
  SHADE_TREE_BOOTNODE_FED_INTERVAL=1 \
  SHADE_TREE_BOOTNODE_MIN_REANNOUNCE=0 \
  SHADE_TREE_TOR_HOST=127.0.0.1 \
  SHADE_TREE_TOR_PORT="$SHIM_PORT" \
  SHADE_TREE_LOG_FORMAT=text SHADE_TREE_LOG_LEVEL=debug \
    "$ELDER_BIN" run > "$log" 2>&1 &
  PIDS+=($!)
  node "$HERE/wait-log.mjs" "$log" "bootnode up on" 20000
}

signer_of() {  # $1 = port
  curl -fsS "http://127.0.0.1:$1/health" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s).signer))'
}

echo "== the Rust Elder (federating with the peer, probing) =="
start_elder "$ELDER_PORT" "$WORK/elder-hs" "$PEER_ONION" "$WORK/elder.log" \
  SHADE_TREE_BOOTNODE_PROBE=1 SHADE_TREE_BOOTNODE_PROBE_INTERVAL=1 SHADE_TREE_METRICS_PORT="$METRICS_PORT"
ELDER_SIGNER="$(signer_of "$ELDER_PORT")"

echo "== the peer Elder (federating with the first) =="
start_elder "$PEER_PORT" "$WORK/peer-hs" "$ELDER_ONION" "$WORK/peer.log" SHADE_TREE_METRICS_PORT=0
PEER_SIGNER="$(signer_of "$PEER_PORT")"

echo "== the Rust node heartbeats to the Rust Elder through the shim, with relay telemetry =="
SHADE_TREE_MEMBERS_FILE="$REPO/group/members.json" \
SHADE_TREE_GATEWAY_PORT="$GW_PORT" \
SHADE_TREE_GW_IDENTITY="$WORK/node-hs/identity.local.json" \
SHADE_TREE_BOOTNODE_ONIONS="$ELDER_ONION" \
SHADE_TREE_BOOTNODE_HEARTBEAT=1 \
SHADE_TREE_EGRESS_CHECK=0 \
SHADE_TREE_TOR_HOST=127.0.0.1 \
SHADE_TREE_TOR_PORT="$SHIM_PORT" \
SHADE_TREE_RELAY_TELEMETRY=1 \
SHADE_TREE_RELAY_TELEMETRY_STATE="$WORK/relay-counter.json" \
SHADE_TREE_RELAY_REPORT_STATE="$WORK/relay-report.json" \
SHADE_TREE_GATEWAY_REGION=eu \
SHADE_TREE_BANNER=never \
SHADE_TREE_LOG_FORMAT=text SHADE_TREE_LOG_LEVEL=debug \
  $NODE_CMD > "$WORK/node.log" 2>&1 &
PIDS+=($!)
node "$HERE/wait-log.mjs" "$WORK/node.log" "gateway up on" 30000
node "$HERE/wait-log.mjs" "$WORK/node.log" "heartbeat accepted" 30000
node "$HERE/wait-log.mjs" "$WORK/node.log" "private relay telemetry accepted" 30000
echo "   the Rust Elder accepted the node's announce and its relay report"

echo "== a JavaScript-built announce to the Rust Elder, and one to the peer =="
JS_TO_ELDER="$(node "$HERE/elder-announce.mjs" "$ELDER_PORT" "$WORK/js-node-a" js-node-a)"
echo "   $JS_TO_ELDER"
JS_NODE_A="$(node -e 'console.log(JSON.parse(process.argv[1]).onion)' "$JS_TO_ELDER")"
JS_TO_PEER="$(node "$HERE/elder-announce.mjs" "$PEER_PORT" "$WORK/js-node-b" js-node-b)"
echo "   $JS_TO_PEER"
JS_NODE_B="$(node -e 'console.log(JSON.parse(process.argv[1]).onion)' "$JS_TO_PEER")"

echo "== federation converges in both directions =="
lists() {  # $1 = port, $2 = onion
  curl -fsS "http://127.0.0.1:$1/directory" | grep -q "\"onion\":\"$2\""
}
for _ in $(seq 1 30); do
  if lists "$PEER_PORT" "$NODE_ONION" && lists "$ELDER_PORT" "$JS_NODE_B"; then break; fi
  sleep 1
done
lists "$PEER_PORT" "$NODE_ONION" || { echo "the peer Elder never listed the Rust node pulled from the first Elder"; cat "$WORK/peer.log"; exit 1; }
lists "$ELDER_PORT" "$JS_NODE_B" || { echo "the first Elder never listed the node pulled from the peer"; cat "$WORK/elder.log"; exit 1; }
echo "   the peer lists the Rust node; the first Elder lists the peer's node"

echo "== the JavaScript reference verifies what the Rust Elder serves =="
node "$HERE/elder-verify.mjs" "$ELDER_PORT" "$ELDER_SIGNER" --expect "$NODE_ONION" --expect "$JS_NODE_A" --expect "$JS_NODE_B"
node "$HERE/elder-verify.mjs" "$ELDER_PORT" "$ELDER_SIGNER" --via-socks "$SHIM_PORT" "$ELDER_ONION" --expect "$NODE_ONION"
echo "== and the peer verifies with its own signer =="
node "$HERE/elder-verify.mjs" "$PEER_PORT" "$PEER_SIGNER" --expect "$NODE_ONION" --expect "$JS_NODE_B"

echo "== the prober keeps the reachable node up, and the metrics count the relay report =="
curl -fsS "http://127.0.0.1:$ELDER_PORT/directory" | node -e '
let s=""; process.stdin.on("data",d=>s+=d).on("end",()=>{
  const dir=JSON.parse(s); const node=dir.gateways.find(g=>g.onion===process.argv[1]);
  if (!node || node.health!=="up") { console.error("node not up after probing: "+JSON.stringify(node)); process.exit(1); }
  console.log("   health up for the probed node");
});' "$NODE_ONION"
METRICS="$(curl -fsS "http://127.0.0.1:$METRICS_PORT/metrics")"
echo "$METRICS" | grep -q 'shade_tree_bootnode_relay_reports_total{result="accepted"} [1-9]' || { echo "no accepted relay report in the metrics"; echo "$METRICS" | grep bootnode; exit 1; }
echo "$METRICS" | grep -q 'shade_tree_bootnode_announces_total{result="accepted"} [1-9]' || { echo "no accepted announce in the metrics"; exit 1; }
echo "$METRICS" | grep -q 'shade_tree_build_info{commit="[0-9a-f]*",role="elder"' || { echo "no elder build info"; exit 1; }
echo "   metrics: announces and relay reports accepted"

echo
echo "== ADR 0015 CONFORMANCE OK: the Rust Elder accepted the Rust node and a JavaScript announce, federated both ways with a peer, and serves a canopy, an incident feed and a relay aggregate the JavaScript reference verifies =="
