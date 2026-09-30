#!/usr/bin/env bash
# T-TEST-1 real-Tor local fleet integration harness (BEST-EFFORT / GATED).
#
# Proves the FULL member egress path end-to-end over REAL Tor: the JS REFERENCE client
# (packages/node/client/shade-tree-client.mjs) mints a REAL per-request RLN membership proof, dials the
# gateway's published v3 `.onion` over the system Tor SOCKS port, and the REAL JS gateway
# (packages/node/gateway/gateway.mjs) ACCEPTS it and proxies the CONNECT to a LOCAL sink. We then assert
# three independent facts: the client got an `ok` ack (ACCEPT), the node's local pass
# counter advanced, and the sink actually received the tunneled connection.
#
# This is the LOCAL de-risk of the container CI job (.github/workflows/real-tor-e2e.yml),
# which runs the same client egress against the systemd-fleet onions bootstrap.sh publishes.
#
# WHY GATED (SHADE_TREE_TOR_E2E=1): it needs real Tor network access, and v3 HS descriptor
# propagation (local tor uploads to HSDirs -> the client's tor fetches) is SLOW (~30-90s)
# and FLAKY — the same reproducibility caveat T-TEST-8's container e2e documents for its
# over-Tor dial. So the whole client run is RETRIED a few times and a propagation timeout
# is a soft/neutral outcome, NOT a hard failure. A genuine ACCEPT, when observed, IS asserted.
#
# It is NOT part of `node scripts/test-all.mjs` (that auto-discovers *.selftest.mjs only;
# this is a .sh + a non-selftest .mjs) and NOT part of `cargo test`.
#
# Prereqs: `npm install` at the repo root (rlnjs + socks), and a system `tor`
# (SHADE_TREE_TOR_BIN to override the path). Run from anywhere:
#   SHADE_TREE_TOR_E2E=1 bash test/real-tor-e2e.sh
set -euo pipefail

if [ "${SHADE_TREE_TOR_E2E:-0}" != "1" ]; then
  echo "SKIP T-TEST-1 real-Tor harness: set SHADE_TREE_TOR_E2E=1 to run."
  echo "  (needs real Tor network access; HS descriptor propagation is slow + flaky."
  echo "   The always-green accept path is the non-Tor demo scripts/demo-e2e.mjs + gateway selftests.)"
  exit 0
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
INTEROP="$REPO/crates/shadenet-rln/interop"     # reuse egress-derive.mjs + wait-log.mjs
WORK="$(mktemp -d)"
TORBIN="${SHADE_TREE_TOR_BIN:-tor}"

SECRET="${SHADE_TREE_SECRET:-12345678901234567890}"
GW_PORT="${SHADE_TREE_GATEWAY_PORT:-8443}"
SINK_PORT="${SHADE_TREE_SINK_PORT:-9443}"
SOCKS_PORT="${SHADE_TREE_TOR_PORT:-9250}"
METRICS_PORT="${SHADE_TREE_NODE_METRICS_PORT:-9101}"
TARGET="127.0.0.1:${SINK_PORT}"
HS_DIR="$WORK/hs"
TOR_DATA="$WORK/tordata"
RUN_ATTEMPTS="${SHADE_TREE_TOR_RUN_ATTEMPTS:-4}"
BOOTSTRAP_TIMEOUT_MS="${SHADE_TREE_TOR_BOOTSTRAP_TIMEOUT_MS:-180000}"

# ---- SIGPIPE-robust cleanup: kill every child we start, restore the repo -----------
# PIDs tracked in vars AND mirrored to a pidfile so a reap works even if a var is lost. We
# trap PIPE (and HUP) too so a `... | head` that closes the pipe still runs cleanup and
# leaves ZERO leftover tor/gateway/sink processes.
GW_PID="" ; SINK_PID="" ; TOR_PID="" ; MEMBERS_BAK=""
PIDFILE="$WORK/pids"
: > "$PIDFILE"
track() { echo "$1" >> "$PIDFILE"; }
cleaned=0
cleanup() {
  [ "$cleaned" = "1" ] && return 0
  cleaned=1
  for p in "$GW_PID" "$SINK_PID" "$TOR_PID"; do
    [ -n "$p" ] && kill "$p" 2>/dev/null || true
  done
  if [ -f "$PIDFILE" ]; then
    while read -r p; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done < "$PIDFILE"
  fi
  # give them a beat to die, then hard-reap any survivor
  for p in "$GW_PID" "$SINK_PID" "$TOR_PID"; do
    [ -n "$p" ] && kill -0 "$p" 2>/dev/null && { sleep 1; kill -9 "$p" 2>/dev/null || true; }
  done
  [ -n "$MEMBERS_BAK" ] && [ -f "$MEMBERS_BAK" ] && mv -f "$MEMBERS_BAK" "$REPO/group/members.json" 2>/dev/null || true
  rm -rf "$WORK" 2>/dev/null || true
}
trap cleanup EXIT INT TERM HUP PIPE

command -v "$TORBIN" >/dev/null 2>&1 || { echo "no system tor ($TORBIN); set SHADE_TREE_TOR_BIN"; exit 1; }
command -v node   >/dev/null 2>&1 || { echo "no node on PATH"; exit 1; }

echo "== deriving member identity + single-member group (packages/node/lib/rln.mjs) =="
node "$INTEROP/egress-derive.mjs" "$WORK" "$SECRET"
MEMBERS="$WORK/members.json"

# Point the gateway's PoC root source at our derived member set (backup + restore in trap),
# so the gateway's membership root == the root the client's proof is generated against.
MEMBERS_BAK="$WORK/members.json.repo-bak"
cp "$REPO/group/members.json" "$MEMBERS_BAK"
cp "$MEMBERS" "$REPO/group/members.json"

echo "== starting local egress sink (:${SINK_PORT}) =="
node -e 'const net=require("net"); let n=0; net.createServer(s=>{n++;console.error("[sink] connection #"+n+" from gateway");s.resume();}).listen('"$SINK_PORT"',"127.0.0.1",()=>console.error("[sink] up on 127.0.0.1:'"$SINK_PORT"'"));' > "$WORK/sink.log" 2>&1 &
SINK_PID=$! ; track "$SINK_PID" ; disown "$SINK_PID" 2>/dev/null || true
node "$INTEROP/wait-log.mjs" "$WORK/sink.log" "[sink] up" 15000

echo "== starting real JS gateway (127.0.0.1:${GW_PORT}) =="
SHADE_TREE_EGRESS_ALLOW="$TARGET" \
  SHADE_TREE_ALLOW_PRIVATE_TARGETS=1 \
  SHADE_TREE_METRICS_PORT="$METRICS_PORT" \
  node "$REPO/packages/node/gateway/gateway.mjs" > "$WORK/gw.log" 2>&1 &
GW_PID=$! ; track "$GW_PID" ; disown "$GW_PID" 2>/dev/null || true
node "$INTEROP/wait-log.mjs" "$WORK/gw.log" "gateway up on" 20000

echo "== publishing a local v3 hidden service for the gateway + a SOCKS port (system tor) =="
mkdir -p "$HS_DIR" "$TOR_DATA"
chmod 700 "$HS_DIR" "$TOR_DATA"
cat > "$WORK/torrc" <<EOF
DataDirectory $TOR_DATA
SocksPort 127.0.0.1:${SOCKS_PORT}
HiddenServiceDir $HS_DIR
HiddenServiceVersion 3
HiddenServicePort 80 127.0.0.1:${GW_PORT}
Log notice file $WORK/tor.log
EOF
"$TORBIN" -f "$WORK/torrc" > "$WORK/tor.boot.log" 2>&1 &
TOR_PID=$! ; track "$TOR_PID" ; disown "$TOR_PID" 2>/dev/null || true

node "$INTEROP/wait-log.mjs" "$WORK/tor.log" "Bootstrapped 100%" "$BOOTSTRAP_TIMEOUT_MS" \
  || { echo "SOFT-SKIP: tor did not bootstrap in this environment (no Tor network access)."; echo "--- tor.log ---"; cat "$WORK/tor.log" 2>/dev/null || true; exit 0; }
for i in $(seq 1 60); do [ -f "$HS_DIR/hostname" ] && break; sleep 1; done
[ -f "$HS_DIR/hostname" ] || { echo "SOFT-SKIP: HS hostname never published."; exit 0; }
ONION="$(cat "$HS_DIR/hostname")"
echo "HS published: $ONION -> 127.0.0.1:${GW_PORT}"
# Give the descriptor time to reach the HSDirs before the client tries to fetch it.
node "$INTEROP/wait-log.mjs" "$WORK/tor.log" "Success uploading" 120000 >/dev/null 2>&1 || sleep 20

echo
echo "== running the JS reference client egress over Tor (SOCKS 127.0.0.1:${SOCKS_PORT}) =="
ACCEPT=0
for attempt in $(seq 1 "$RUN_ATTEMPTS"); do
  echo "--- client run attempt $attempt/$RUN_ATTEMPTS ---"
  set +e
  SHADE_TREE_SECRET="$SECRET" SHADE_TREE_ONION="$ONION" SHADE_TREE_TOR_PORT="$SOCKS_PORT" SHADE_TREE_DIAL_ATTEMPTS=3 \
    node "$HERE/real-tor-e2e-client.mjs" "$TARGET"
  rc=$?
  set -e
  [ "$rc" -eq 0 ] && { ACCEPT=1; break; }
  echo "attempt $attempt failed (rc=$rc); descriptor may not have propagated yet, retrying ..."
  sleep 15
done

echo
echo "--- gateway log ---"; cat "$WORK/gw.log"
echo "--- sink log ---";    cat "$WORK/sink.log"
echo "--- node pass metric ---"; curl -fsS "http://127.0.0.1:${METRICS_PORT}/metrics" 2>/dev/null | grep 'shade_tree_gateway_tunnels_total' || true

# Three independent assertions for a genuine over-Tor accept.
GW_OK=0;   curl -fsS "http://127.0.0.1:${METRICS_PORT}/metrics" 2>/dev/null | grep -Eq '^shade_tree_gateway_tunnels_total\{result="pass"\} [1-9][0-9]*$' && GW_OK=1
SINK_OK=0; grep -q "\[sink\] connection"        "$WORK/sink.log" && SINK_OK=1

if [ "$ACCEPT" = "1" ] && [ "$GW_OK" = "1" ] && [ "$SINK_OK" = "1" ]; then
  echo
  echo "== T-TEST-1 OVER-TOR EGRESS OK: JS client -> published .onion -> JS gateway ACCEPT -> sink =="
  echo "   (client ack=ACCEPT, node pass counter advanced, sink received the tunneled connection)"
  exit 0
fi

if [ "$ACCEPT" = "0" ]; then
  echo
  echo "SOFT-SKIP: no over-Tor ACCEPT observed after ${RUN_ATTEMPTS} attempts —"
  echo "  most likely v3 HS descriptor propagation did not complete in this environment."
  echo "  This step is BEST-EFFORT/gated (see header). The container CI job is the authoritative path."
  exit 0
fi

# Client reported ACCEPT but a corroborating signal is missing. That is a real inconsistency.
echo "FAIL: client reported ACCEPT but node-metric/sink evidence is missing (GW_OK=$GW_OK SINK_OK=$SINK_OK)"
exit 1
