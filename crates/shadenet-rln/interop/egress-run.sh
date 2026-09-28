#!/usr/bin/env bash
# T-RUST-2d integration harness: the Rust `shade-tree egress` (feature build) mints a REAL RLN
# envelope (native depth-20 Poseidon tree + Groth16 proof over the repo's circom-rln
# artifacts) and sends it over a PLAIN TCP socket to a running JS reference. Two layers:
#
#   Layer 2 (framing + verify): a minimal socket server (verify-socket.mjs) reads the
#     envelope and runs the REAL lib/rln.mjs verifyEnvelope. Isolates wire framing +
#     target-binding ACCEPT from the gateway's proxy path.
#
#   Layer 3 (full gateway proxy): the REAL gateway/gateway.mjs, with the derived member set
#     as its PoC root source and a local :port egress sink, ACCEPTS the Rust envelope end to
#     end (version gate -> verifyEnvelope Groth16 -> target policy -> spent-set -> upstream
#     connect -> `{ ok: true }`). No Tor here: the client uses the `--plain-tcp` escape hatch
#     (the embedded-Tor onion dial is T-RUST-2e; its best-effort harness is egress-tor-run.sh).
#     This plain-TCP layer stays the AUTHORITATIVE always-green accept check.
#
# Prereqs: `npm install` at the repo root (rlnjs) + a Rust toolchain.
# Run from anywhere: bash crates/shadenet-rln/interop/egress-run.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
CIRCUITS="$REPO/circuits/rln"
WORK="$(mktemp -d)"

# Ports: gateway is HARDCODED to 127.0.0.1:8443 (gateway.mjs LISTEN_PORT). The layer-2
# verify server + the egress sink use fixed loopback ports.
GW_PORT=8443
VS_PORT=8571
SINK_PORT=9443
TARGET="127.0.0.1:${SINK_PORT}"
# The epoch is left to the Rust client's own clock (default: floor(now/120)); the JS side
# checks this-or-previous epoch, so a boundary straddle during proving is still accepted.

GW_PID="" ; VS_PID="" ; SINK_PID=""
MEMBERS_BAK=""
cleanup() {
  [ -n "$GW_PID" ]   && kill "$GW_PID"   2>/dev/null || true
  [ -n "$VS_PID" ]   && kill "$VS_PID"   2>/dev/null || true
  [ -n "$SINK_PID" ] && kill "$SINK_PID" 2>/dev/null || true
  # restore the repo's group/members.json (layer 3 overwrites it as the gateway root source)
  [ -n "$MEMBERS_BAK" ] && [ -f "$MEMBERS_BAK" ] && mv -f "$MEMBERS_BAK" "$REPO/group/members.json" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "== building feature client (cargo build -p shadenet-cli --features live) =="
cargo build -p shadenet-cli --features live --manifest-path "$REPO/Cargo.toml"
SHADE_TREE="$REPO/target/debug/shade-tree"

echo "== deriving identity + member set (lib/rln.mjs) =="
node "$HERE/egress-derive.mjs" "$WORK"
IDENTITY="$WORK/identity.json"
MEMBERS="$WORK/members.json"

echo
echo "== LAYER 2: framing + verifyEnvelope ACCEPT (verify-socket.mjs) =="
node "$HERE/verify-socket.mjs" "$VS_PORT" "$MEMBERS" > "$WORK/vs.log" 2>&1 &
VS_PID=$!
disown "$VS_PID" 2>/dev/null || true
node "$HERE/wait-log.mjs" "$WORK/vs.log" "listening on" 15000
set +e
"$SHADE_TREE" egress --plain-tcp "127.0.0.1:${VS_PORT}" \
  --identity "$IDENTITY" --members "$MEMBERS" --target "$TARGET" \
  --circuits "$CIRCUITS"
L2_SHADE_TREE_RC=$?
set -e
wait "$VS_PID" 2>/dev/null || true
VS_PID=""
echo "--- verify-socket log ---"; cat "$WORK/vs.log"
if [ "$L2_SHADE_TREE_RC" -ne 0 ] || ! grep -q "PASS: verifyEnvelope ACCEPTED" "$WORK/vs.log"; then
  echo "LAYER 2 FAILED (shade-tree rc=$L2_SHADE_TREE_RC)"; exit 1
fi
echo "LAYER 2 OK"

echo
echo "== LAYER 3: full gateway proxy ACCEPT (gateway/gateway.mjs) =="
# Point the gateway's PoC root source at our derived member set (backup + restore in trap).
MEMBERS_BAK="$WORK/members.json.repo-bak"
cp "$REPO/group/members.json" "$MEMBERS_BAK"
cp "$MEMBERS" "$REPO/group/members.json"

# A local echo sink proves that Rust keeps the accepted socket and relays actual
# application payload bytes after the acknowledgement (issue #76), not merely the ack.
node -e 'const net=require("net"); net.createServer(s=>s.once("data",d=>{console.error("[sink] payload="+d);s.end("shade-tree-payload-ok:"+d)})).listen('"$SINK_PORT"',"127.0.0.1",()=>console.error("[sink] up on 127.0.0.1:'"$SINK_PORT"'"));' > "$WORK/sink.log" 2>&1 &
SINK_PID=$!
disown "$SINK_PID" 2>/dev/null || true
node "$HERE/wait-log.mjs" "$WORK/sink.log" "[sink] up" 15000

# Start the real gateway. Allow ONLY our local sink target; default epoch length.
# Wait on the gateway's OWN "gateway up" log line (never a TCP connect-probe: the gateway
# reads a full newline-terminated envelope, and a half-open probe would EPIPE-crash it).
SHADE_TREE_EGRESS_ALLOW="$TARGET" SHADE_TREE_ALLOW_PRIVATE_TARGETS=1 SHADE_TREE_EPOCH_SECONDS=120 \
  node "$REPO/gateway/gateway.mjs" > "$WORK/gw.log" 2>&1 &
GW_PID=$!
disown "$GW_PID" 2>/dev/null || true
node "$HERE/wait-log.mjs" "$WORK/gw.log" "gateway up on" 20000

set +e
printf 'interop-ping' | "$SHADE_TREE" egress --plain-tcp "127.0.0.1:${GW_PORT}" \
  --identity "$IDENTITY" --members "$MEMBERS" --target "$TARGET" \
  --circuits "$CIRCUITS" --stdio > "$WORK/payload.out"
L3_SHADE_TREE_RC=$?
set -e
echo "--- gateway log ---"; cat "$WORK/gw.log"
echo "--- sink log ---"; cat "$WORK/sink.log"
# The gateway can only send the success ack after verification, policy, admission and the
# destination connect. Requiring the destination's exact echoed bytes proves the same real
# gateway path and the post-ack relay without depending on an operator log format.
echo "--- relayed payload ---"; cat "$WORK/payload.out"
echo
RELAYED_PAYLOAD="$(cat "$WORK/payload.out")"
if [ "$L3_SHADE_TREE_RC" -ne 0 ] || [ "$RELAYED_PAYLOAD" != 'shade-tree-payload-ok:interop-ping' ]; then
  echo "LAYER 3 FAILED (shade-tree rc=$L3_SHADE_TREE_RC)"; exit 1
fi
echo "LAYER 3 OK"

echo
echo "== T-RUST-2d EGRESS OK: JS gateway ACCEPTED the Rust shade-tree egress envelope end-to-end =="
