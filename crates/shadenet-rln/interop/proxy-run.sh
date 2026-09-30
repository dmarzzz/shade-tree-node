#!/usr/bin/env bash
# Always-green Rust Proxy contract test. It uses the plain-TCP transport only to
# remove Tor/hidden-service propagation from this blocking CI layer; the recurring
# Hermes E2E separately proves this same Proxy over embedded Arti.
#
#   CONNECT clients -> Rust Proxy/shared egress client -> JS gateway -> echo sink
#
# The real RLN prover, gateway verification, CONNECT acceptance, early client data,
# and bidirectional relay all remain in path.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d)"

GW_PORT="${SHADE_TREE_PROXY_TEST_GATEWAY_PORT:-18444}"
PROXY_PORT="${SHADE_TREE_PROXY_TEST_PROXY_PORT:-18118}"
SINK_PORT="${SHADE_TREE_PROXY_TEST_SINK_PORT:-19443}"
TARGET="127.0.0.1:${SINK_PORT}"
SECRET="${SHADE_TREE_PROXY_TEST_SECRET:-23456789012345678901}"
PROXY_TOKEN="${SHADE_TREE_PROXY_TEST_TOKEN:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
TEST_EPOCH="$(node -e 'process.stdout.write(String(Math.floor(Date.now() / 1000 / 120)))')"

GW_PID=""
PROXY_PID=""
SINK_PID=""
cleanup() {
  [ -n "$PROXY_PID" ] && pkill -TERM -P "$PROXY_PID" 2>/dev/null || true
  [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null || true
  [ -n "$GW_PID" ] && kill "$GW_PID" 2>/dev/null || true
  [ -n "$SINK_PID" ] && kill "$SINK_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM HUP PIPE

if [ -n "${SHADE_TREE_RUST_BIN:-}" ]; then
  SHADE_TREE="$SHADE_TREE_RUST_BIN"
  [ -x "$SHADE_TREE" ] || { echo "Rust shade-tree binary is not executable: $SHADE_TREE" >&2; exit 2; }
else
  cargo build --locked --manifest-path "$REPO/Cargo.toml" \
    -p shadenet-cli --features live
  SHADE_TREE="$REPO/target/debug/shade-tree"
fi

echo "== derive an ephemeral identity and invited member set =="
node "$HERE/egress-derive.mjs" "$WORK" "$SECRET"
IDENTITY="$WORK/identity.json"
MEMBERS="$WORK/members.json"

echo "== start the local echo target =="
node -e 'const net=require("net"); net.createServer(s=>s.once("data",d=>s.end("shade-tree-proxy-ok:"+d))).listen('"$SINK_PORT"',"127.0.0.1",()=>console.error("sink ready"));' \
  > "$WORK/sink.log" 2>&1 &
SINK_PID=$!
node "$HERE/wait-log.mjs" "$WORK/sink.log" "sink ready" 15000

echo "== start the real JavaScript gateway =="
SHADE_TREE_MEMBERS_FILE="$MEMBERS" \
SHADE_TREE_GATEWAY_PORT="$GW_PORT" \
SHADE_TREE_EGRESS_ALLOW="$TARGET" \
SHADE_TREE_ALLOW_PRIVATE_TARGETS=1 \
SHADE_TREE_BANNER=never \
  node "$REPO/packages/node/gateway/gateway.mjs" > "$WORK/gateway.log" 2>&1 &
GW_PID=$!
node "$HERE/wait-log.mjs" "$WORK/gateway.log" "gateway up on" 30000

echo "== start long-lived Rust CONNECT Proxy =="
SHADE_TREE_SLOT_STATE_DIR="$WORK/slots" \
SHADE_TREE_PROXY_TOKEN="$PROXY_TOKEN" \
  "$SHADE_TREE" proxy \
    --listen "127.0.0.1:${PROXY_PORT}" \
    --plain-tcp "127.0.0.1:${GW_PORT}" \
    --identity "$IDENTITY" \
    --members "$MEMBERS" \
    --epoch "$TEST_EPOCH" \
    > "$WORK/proxy.log" 2>&1 &
PROXY_PID=$!
node "$HERE/wait-log.mjs" "$WORK/proxy.log" "proxy listening on" 15000

echo "== send two CONNECT tunnels plus early application bytes =="
if ! node "$HERE/proxy-client.mjs" "$PROXY_PORT" "$TARGET" "interop-ping-one" "$PROXY_TOKEN" || \
   ! node "$HERE/proxy-client.mjs" "$PROXY_PORT" "$TARGET" "interop-ping-two" "$PROXY_TOKEN"; then
  cat "$WORK/proxy.log" >&2 || true
  cat "$WORK/gateway.log" >&2 || true
  cat "$WORK/sink.log" >&2 || true
  exit 1
fi
kill -0 "$PROXY_PID" 2>/dev/null || {
  cat "$WORK/proxy.log" >&2 || true
  echo "Rust Proxy exited before the second CONNECT completed" >&2
  exit 1
}

node -e '
  const fs = require("fs");
  const path = process.argv[1];
  const files = fs.readdirSync(path).filter((name) => name.endsWith(".json"));
  if (files.length !== 1) throw new Error(`expected one slot cursor, got ${files.length}`);
  const state = JSON.parse(fs.readFileSync(`${path}/${files[0]}`, "utf8"));
  if (state.nextSlot !== 2) throw new Error(`expected two consumed slots, got ${state.nextSlot}`);
' "$WORK/slots"

echo "== T-RUST-PROXY OK: two CONNECT proofs accepted and relayed through one Proxy =="
