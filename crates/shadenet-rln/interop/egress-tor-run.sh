#!/usr/bin/env bash
# T-RUST-2e over-Tor egress harness (BEST-EFFORT / GATED).
#
# Proves the FULL Gate-2 path: the Rust `shade-tree egress` (feature build) mints a REAL RLN
# envelope and dials the gateway's v3 `.onion` over EMBEDDED TOR (arti — no system tor
# daemon in the client, no SOCKS), and the REAL JS gateway ACCEPTS it end to end over Tor.
#
# It stands up a LOCAL hidden service (using the system `tor` ONLY as the HS host — the
# CLIENT still dials via embedded arti) pointing at the gateway's loopback :8443, waits for
# the descriptor to publish, then runs `shade-tree egress --onion <hostname>:80`.
#
# WHY GATED (SHADE_TREE_TOR_E2E=1): this needs real Tor network access, and v3 HS descriptor
# propagation (local tor uploads to HSDirs -> arti fetches) is SLOW (~30-90s) and FLAKY —
# exactly the reproducibility problem T-TEST-8's container e2e already documents for its
# over-Tor dial. The AUTHORITATIVE always-green accept check is the plain-TCP Layer-3 in
# egress-run.sh; THIS harness is the real-Tor confirmation when the environment allows it.
#
# Prereqs: `npm install` at the repo root (rlnjs), a Rust toolchain, and a system `tor`
# (`SHADE_TREE_TOR_BIN` to override the path). Run from anywhere:
#   SHADE_TREE_TOR_E2E=1 bash crates/shadenet-rln/interop/egress-tor-run.sh
set -euo pipefail

if [ "${SHADE_TREE_TOR_E2E:-0}" != "1" ]; then
  echo "SKIP T-RUST-2e over-Tor harness: set SHADE_TREE_TOR_E2E=1 to run."
  echo "  (needs real Tor network access; HS descriptor propagation is slow + flaky."
  echo "   The always-green accept check is the plain-TCP egress-run.sh Layer 3.)"
  exit 0
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
CIRCUITS="$REPO/circuits/rln"
WORK="$(mktemp -d)"
TORBIN="${SHADE_TREE_TOR_BIN:-tor}"

GW_PORT="${SHADE_TREE_GATEWAY_PORT:-8443}"
SINK_PORT=9443
TARGET="127.0.0.1:${SINK_PORT}"
HS_DIR="$WORK/hs"
TOR_DATA="$WORK/tordata"
DIAL_ATTEMPTS="${SHADE_TREE_TOR_DIAL_ATTEMPTS:-3}"

GW_PID="" ; SINK_PID="" ; TOR_PID="" ; MEMBERS_BAK=""
cleanup() {
  [ -n "$GW_PID" ]   && kill "$GW_PID"   2>/dev/null || true
  [ -n "$SINK_PID" ] && kill "$SINK_PID" 2>/dev/null || true
  [ -n "$TOR_PID" ]  && kill "$TOR_PID"  2>/dev/null || true
  [ -n "$MEMBERS_BAK" ] && [ -f "$MEMBERS_BAK" ] && mv -f "$MEMBERS_BAK" "$REPO/group/members.json" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

command -v "$TORBIN" >/dev/null 2>&1 || { echo "no system tor ($TORBIN); set SHADE_TREE_TOR_BIN"; exit 1; }

echo "== building feature client (cargo build -p shadenet-cli --features live) =="
cargo build -p shadenet-cli --features live --manifest-path "$REPO/Cargo.toml"
SHADE_TREE="$REPO/target/debug/shade-tree"

echo "== deriving identity + member set (packages/node/lib/rln.mjs) =="
node "$HERE/egress-derive.mjs" "$WORK"
IDENTITY="$WORK/identity.json"
MEMBERS="$WORK/members.json"

# Point the gateway's PoC root source at our derived member set (backup + restore in trap).
MEMBERS_BAK="$WORK/members.json.repo-bak"
cp "$REPO/group/members.json" "$MEMBERS_BAK"
cp "$MEMBERS" "$REPO/group/members.json"

echo "== starting local egress sink (:${SINK_PORT}) =="
node -e 'const net=require("net"); net.createServer(s=>{console.error("[sink] accepted");s.resume()}).listen('"$SINK_PORT"',"127.0.0.1",()=>console.error("[sink] up on 127.0.0.1:'"$SINK_PORT"'"));' > "$WORK/sink.log" 2>&1 &
SINK_PID=$!
disown "$SINK_PID" 2>/dev/null || true
node "$HERE/wait-log.mjs" "$WORK/sink.log" "[sink] up" 15000

echo "== starting real gateway (:${GW_PORT}) =="
SHADE_TREE_EGRESS_ALLOW="$TARGET" SHADE_TREE_ALLOW_PRIVATE_TARGETS=1 SHADE_TREE_EPOCH_SECONDS=120 \
  node "$REPO/packages/node/gateway/gateway.mjs" > "$WORK/gw.log" 2>&1 &
GW_PID=$!
disown "$GW_PID" 2>/dev/null || true
node "$HERE/wait-log.mjs" "$WORK/gw.log" "gateway up on" 20000

echo "== publishing a local v3 hidden service for the gateway (system tor as HS host) =="
mkdir -p "$HS_DIR" "$TOR_DATA"
chmod 700 "$HS_DIR" "$TOR_DATA"
cat > "$WORK/torrc" <<EOF
DataDirectory $TOR_DATA
SocksPort 0
HiddenServiceDir $HS_DIR
HiddenServiceVersion 3
HiddenServicePort 80 127.0.0.1:${GW_PORT}
Log notice file $WORK/tor.log
EOF
"$TORBIN" -f "$WORK/torrc" > "$WORK/tor.boot.log" 2>&1 &
TOR_PID=$!
disown "$TOR_PID" 2>/dev/null || true

# Wait for the HS hostname file, then for tor to reach 100% + upload the descriptor.
node "$HERE/wait-log.mjs" "$WORK/tor.log" "Bootstrapped 100%" 180000 || { echo "tor did not bootstrap"; echo "--- tor.log ---"; cat "$WORK/tor.log" 2>/dev/null; exit 1; }
for i in $(seq 1 60); do [ -f "$HS_DIR/hostname" ] && break; sleep 1; done
[ -f "$HS_DIR/hostname" ] || { echo "no HS hostname published"; exit 1; }
ONION="$(cat "$HS_DIR/hostname")"
echo "HS published: $ONION -> 127.0.0.1:${GW_PORT}"
# Give the descriptor time to reach the HSDirs before arti tries to fetch it.
node "$HERE/wait-log.mjs" "$WORK/tor.log" "Success uploading" 120000 >/dev/null 2>&1 || sleep 20

echo
echo "== dialing the gateway .onion over EMBEDDED TOR (arti) =="
SHADE_TREE_RC=1
for attempt in $(seq 1 "$DIAL_ATTEMPTS"); do
  echo "--- arti dial attempt $attempt/$DIAL_ATTEMPTS ---"
  set +e
  SHADE_TREE_TOR_TIMEOUT_SECS="${SHADE_TREE_TOR_TIMEOUT_SECS:-300}" \
    "$SHADE_TREE" egress --onion "${ONION}:80" \
      --identity "$IDENTITY" --members "$MEMBERS" --target "$TARGET" \
      --circuits "$CIRCUITS"
  SHADE_TREE_RC=$?
  set -e
  [ "$SHADE_TREE_RC" -eq 0 ] && break
  echo "attempt $attempt failed (rc=$SHADE_TREE_RC); descriptor may not have propagated yet, retrying ..."
  sleep 15
done

node "$HERE/wait-log.mjs" "$WORK/sink.log" "[sink] accepted" 5000 >/dev/null 2>&1 || true
echo "--- gateway log ---"; cat "$WORK/gw.log"
echo "--- sink log ---"; cat "$WORK/sink.log"
if [ "$SHADE_TREE_RC" -ne 0 ]; then
  echo "OVER-TOR EGRESS FAILED (shade-tree rc=$SHADE_TREE_RC) — likely HS descriptor propagation flake."
  echo "This step is BEST-EFFORT/gated; the authoritative accept check is egress-run.sh (plain TCP)."
  exit 1
fi
if ! grep -Fq "[sink] accepted" "$WORK/sink.log"; then
  echo "OVER-TOR EGRESS FAILED: client received success without the destination accepting a connection."
  exit 1
fi

echo
echo "== T-RUST-2e OVER-TOR EGRESS OK: JS gateway ACCEPTED the Rust shade-tree envelope OVER TOR =="
