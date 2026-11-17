#!/usr/bin/env bash
# ADR 0015 conformance harness: the Rust Elder Tree against every peer it has, with no Tor.
# A SOCKS5 shim (socks-shim.mjs) stands in for the Tor daemon and routes each "onion" to a
# loopback port, so the real Rust node announces to the real Rust Elder over the real announce
# path, the JavaScript Elder and the Rust Elder federate with each other in both directions,
# and the JavaScript reference verifies what the Rust Elder serves:
#
#   1. the Rust node heartbeats to the Rust Elder (accepted, with its signed caps) and sends
#      its private relay telemetry report (accepted, counted in the Elder's metrics);
#   2. a JavaScript-built announce (keygen.mjs + announce.mjs) is accepted by the Rust Elder;
#   3. the Rust Elder's /directory, /incidents and /telemetry/aggregate verify with the
#      JavaScript verifyDirectory, verifyIncidents and verifyRelayAggregate, fetched straight
#      and through the shim as a client would (fetchOverTor);
#   4. the JavaScript Elder pulls the Rust Elder's canopy and lists the Rust node; the Rust
#      Elder pulls the JavaScript Elder's canopy and lists a node announced only there;
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
RUST_ELDER_PORT="${SHADE_TREE_ELDER_TEST_RUST_PORT:-18551}"
JS_ELDER_PORT="${SHADE_TREE_ELDER_TEST_JS_PORT:-18552}"
METRICS_PORT="${SHADE_TREE_ELDER_TEST_METRICS_PORT:-18553}"
GW_PORT="${SHADE_TREE_ELDER_TEST_GATEWAY_PORT:-18554}"

PIDS=()
cleanup() {
  for pid in "${PIDS[@]:-}"; do [ -n "$pid" ] && kill "$pid" 2>/dev/null || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM HUP PIPE

echo "== minting the identities (shadenet-elder identity) =="
"$ELDER_BIN" identity "$WORK/rust-elder-hs" --label rust-elder >/dev/null
"$ELDER_BIN" identity "$WORK/js-elder-hs" --label js-elder >/dev/null
"$ELDER_BIN" identity "$WORK/node-hs" --label node >/dev/null
RUST_ELDER_ONION="$(cat "$WORK/rust-elder-hs/hostname")"
JS_ELDER_ONION="$(cat "$WORK/js-elder-hs/hostname")"
NODE_ONION="$(cat "$WORK/node-hs/hostname")"
echo "   rust elder $RUST_ELDER_ONION"
echo "   js elder   $JS_ELDER_ONION"
echo "   node       $NODE_ONION"

echo "== the SOCKS shim stands in for Tor =="
node "$HERE/socks-shim.mjs" "$SHIM_PORT" \
  "{\"$RUST_ELDER_ONION\":$RUST_ELDER_PORT,\"$JS_ELDER_ONION\":$JS_ELDER_PORT,\"$NODE_ONION\":$GW_PORT}" \
  > "$WORK/shim.log" 2>&1 &
PIDS+=($!)
node "$HERE/wait-log.mjs" "$WORK/shim.log" "[shim] up" 15000

echo "== the Rust Elder (federating with the JavaScript Elder, probing) =="
SHADE_TREE_BOOTNODE_PORT="$RUST_ELDER_PORT" \
SHADE_TREE_BOOTNODE_SIGNER_KEY="$WORK/rust-signer.key" \
SHADE_TREE_BOOTNODE_STORE="$WORK/rust-store.json" \
SHADE_TREE_BOOTNODE_INCIDENTS_FILE="$WORK/incidents.json" \
SHADE_TREE_RELAY_ELDER_STATE="$WORK/relay-state.json" \
SHADE_TREE_BOOTNODE_ONION="$RUST_ELDER_ONION" \
SHADE_TREE_BOOTNODE_PEERS="$JS_ELDER_ONION" \
SHADE_TREE_BOOTNODE_FED_INTERVAL=1 \
SHADE_TREE_BOOTNODE_PROBE=1 \
SHADE_TREE_BOOTNODE_PROBE_INTERVAL=1 \
SHADE_TREE_BOOTNODE_MIN_REANNOUNCE=0 \
SHADE_TREE_TOR_HOST=127.0.0.1 \
SHADE_TREE_TOR_PORT="$SHIM_PORT" \
SHADE_TREE_METRICS_PORT="$METRICS_PORT" \
SHADE_TREE_LOG_FORMAT=text SHADE_TREE_LOG_LEVEL=debug \
  "$ELDER_BIN" run > "$WORK/rust-elder.log" 2>&1 &
PIDS+=($!)
node "$HERE/wait-log.mjs" "$WORK/rust-elder.log" "bootnode up on" 20000
RUST_SIGNER="$(curl -fsS "http://127.0.0.1:$RUST_ELDER_PORT/health" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s).signer))')"

echo "== the JavaScript Elder (federating with the Rust Elder) =="
SHADE_TREE_BOOTNODE_PORT="$JS_ELDER_PORT" \
SHADE_TREE_BOOTNODE_SIGNER_KEY="$WORK/js-signer.key" \
SHADE_TREE_BOOTNODE_INCIDENTS_FILE="$WORK/js-incidents.json" \
SHADE_TREE_RELAY_ELDER_STATE="$WORK/js-relay-state.json" \
SHADE_TREE_BOOTNODE_ONION="$JS_ELDER_ONION" \
SHADE_TREE_BOOTNODE_PEERS="$RUST_ELDER_ONION" \
SHADE_TREE_BOOTNODE_FED_INTERVAL=1 \
SHADE_TREE_BOOTNODE_MIN_REANNOUNCE=0 \
SHADE_TREE_TOR_HOST=127.0.0.1 \
SHADE_TREE_TOR_PORT="$SHIM_PORT" \
SHADE_TREE_LOG_FORMAT=text \
  node "$REPO/packages/node/bootnode/server.mjs" > "$WORK/js-elder.log" 2>&1 &
PIDS+=($!)
node "$HERE/wait-log.mjs" "$WORK/js-elder.log" "bootnode up on" 20000
JS_SIGNER="$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).pub)' "$WORK/js-signer.key")"

echo "== the Rust node heartbeats to the Rust Elder through the shim, with relay telemetry =="
SHADE_TREE_MEMBERS_FILE="$REPO/group/members.json" \
SHADE_TREE_GATEWAY_PORT="$GW_PORT" \
SHADE_TREE_GW_IDENTITY="$WORK/node-hs/identity.local.json" \
SHADE_TREE_BOOTNODE_ONIONS="$RUST_ELDER_ONION" \
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

echo "== a JavaScript-built announce to the Rust Elder, and one to the JavaScript Elder =="
JS_TO_RUST="$(node "$HERE/elder-announce.mjs" "$RUST_ELDER_PORT" "$WORK/js-node-a" js-node-a)"
echo "   $JS_TO_RUST"
JS_NODE_A="$(node -e 'console.log(JSON.parse(process.argv[1]).onion)' "$JS_TO_RUST")"
JS_TO_JS="$(node "$HERE/elder-announce.mjs" "$JS_ELDER_PORT" "$WORK/js-node-b" js-node-b)"
echo "   $JS_TO_JS"
JS_NODE_B="$(node -e 'console.log(JSON.parse(process.argv[1]).onion)' "$JS_TO_JS")"

echo "== federation converges in both directions =="
lists() {  # $1 = port, $2 = onion
  curl -fsS "http://127.0.0.1:$1/directory" | grep -q "\"onion\":\"$2\""
}
for _ in $(seq 1 30); do
  if lists "$JS_ELDER_PORT" "$NODE_ONION" && lists "$RUST_ELDER_PORT" "$JS_NODE_B"; then break; fi
  sleep 1
done
lists "$JS_ELDER_PORT" "$NODE_ONION" || { echo "the JavaScript Elder never listed the Rust node pulled from the Rust Elder"; cat "$WORK/js-elder.log"; exit 1; }
lists "$RUST_ELDER_PORT" "$JS_NODE_B" || { echo "the Rust Elder never listed the node pulled from the JavaScript Elder"; cat "$WORK/rust-elder.log"; exit 1; }
echo "   the JavaScript Elder lists the Rust node; the Rust Elder lists the JavaScript Elder's node"

echo "== the JavaScript reference verifies what the Rust Elder serves =="
node "$HERE/elder-verify.mjs" "$RUST_ELDER_PORT" "$RUST_SIGNER" --expect "$NODE_ONION" --expect "$JS_NODE_A" --expect "$JS_NODE_B"
node "$HERE/elder-verify.mjs" "$RUST_ELDER_PORT" "$RUST_SIGNER" --via-socks "$SHIM_PORT" "$RUST_ELDER_ONION" --expect "$NODE_ONION"
echo "== and the JavaScript Elder still verifies with its own signer =="
node "$HERE/elder-verify.mjs" "$JS_ELDER_PORT" "$JS_SIGNER" --expect "$NODE_ONION" --expect "$JS_NODE_B"

echo "== the prober keeps the reachable node up, and the metrics count the relay report =="
curl -fsS "http://127.0.0.1:$RUST_ELDER_PORT/directory" | node -e '
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
echo "== ADR 0015 CONFORMANCE OK: the Rust Elder accepted the Rust node and a JavaScript announce, federated both ways with the JavaScript Elder, and serves a canopy, an incident feed and a relay aggregate the JavaScript reference verifies =="
