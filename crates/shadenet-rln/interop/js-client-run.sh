#!/usr/bin/env bash
# ADR 0014 conformance harness: the JavaScript reference client -> the Rust node, over a plain
# loopback socket (no Tor), always green like egress-run.sh. The client mints a real Groth16
# proof, the node verifies it, connects to the local sink and relays the payload both ways.
# Together with egress-run.sh (Rust client -> Rust node) this keeps both clients talking to
# the Rust node until the JavaScript client is retired.
#
# Prereqs: `npm install` at the repo root + a Rust toolchain.
# Run from anywhere: bash crates/shadenet-rln/interop/js-client-run.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
source "$REPO/scripts/node-bin.sh"
GATEWAY_CMD="$(shadenet_node_cmd "$REPO")"
WORK="$(mktemp -d)"

GW_PORT="${SHADE_TREE_JS_CLIENT_TEST_GATEWAY_PORT:-18445}"
SINK_PORT="${SHADE_TREE_JS_CLIENT_TEST_SINK_PORT:-19445}"
TARGET="127.0.0.1:${SINK_PORT}"
SECRET="${SHADE_TREE_JS_CLIENT_TEST_SECRET:-34567890123456789012}"

GW_PID="" ; SINK_PID=""
cleanup() {
  [ -n "$GW_PID" ]   && kill "$GW_PID"   2>/dev/null || true
  [ -n "$SINK_PID" ] && kill "$SINK_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM HUP PIPE

echo "== deriving identity + member set (packages/node/lib/rln.mjs) =="
node "$HERE/egress-derive.mjs" "$WORK" "$SECRET"
MEMBERS="$WORK/members.json"

echo "== start the local echo target =="
node -e 'const net=require("net"); net.createServer(s=>s.once("data",d=>{console.error("[sink] payload="+d);s.end("shade-tree-payload-ok:"+d)})).listen('"$SINK_PORT"',"127.0.0.1",()=>console.error("[sink] up on 127.0.0.1:'"$SINK_PORT"'"));' > "$WORK/sink.log" 2>&1 &
SINK_PID=$!
node "$HERE/wait-log.mjs" "$WORK/sink.log" "[sink] up" 15000

echo "== start the Rust node =="
SHADE_TREE_MEMBERS_FILE="$MEMBERS" \
SHADE_TREE_GATEWAY_PORT="$GW_PORT" \
SHADE_TREE_EGRESS_ALLOW="$TARGET" \
SHADE_TREE_ALLOW_PRIVATE_TARGETS=1 \
SHADE_TREE_BANNER=never \
  $GATEWAY_CMD > "$WORK/gw.log" 2>&1 &
GW_PID=$!
node "$HERE/wait-log.mjs" "$WORK/gw.log" "gateway up on" 30000

echo "== JavaScript client: prove, tunnel, relay =="
set +e
SHADE_TREE_SECRET="$SECRET" SHADE_TREE_MEMBERS_FILE="$MEMBERS" SHADE_TREE_SLOT_STATE_DIR="$WORK/slots" \
  node "$HERE/js-client.mjs" "$GW_PORT" "$TARGET" "interop-ping" > "$WORK/client.out"
CLIENT_RC=$?
set -e
echo "--- client result ---"; cat "$WORK/client.out"
echo "--- node log ---"; cat "$WORK/gw.log"
echo "--- sink log ---"; cat "$WORK/sink.log"
if [ "$CLIENT_RC" -ne 0 ] || ! grep -q '"accept":true' "$WORK/client.out"; then
  echo "JS CLIENT -> RUST NODE FAILED (rc=$CLIENT_RC)"; exit 1
fi

echo
echo "== ADR 0014 CONFORMANCE OK: the Rust node ACCEPTED the JavaScript client's envelope and relayed its payload =="
