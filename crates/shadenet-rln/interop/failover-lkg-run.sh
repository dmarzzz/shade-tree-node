#!/usr/bin/env bash
# T-RUST-3 integration harness: prove the Rust client's RESILIENT operational loop
# (client/shade-tree-client.mjs parity) — GATEWAY FAILOVER and LAST-KNOWN-GOOD directory
# caching — against the REAL JS gateway, with NO Tor (plain-TCP, always-green like
# egress-run.sh). Two layers:
#
#   LAYER A (FAILOVER): `shade-tree egress` is given an ORDERED candidate list whose FIRST
#     entry is a DEAD address (nothing listening) and whose SECOND is the real
#     gateway. The client builds ONE RLN envelope, fails to dial the first, ROTATES,
#     and the SECOND gateway ACCEPTS the SAME envelope end-to-end (deterministic
#     retry). Mirrors the connect() failover loop in client/shade-tree-client.mjs.
#
#   LAYER B (LAST-KNOWN-GOOD): `shade-tree fetch-directory` verifies a fresh signed
#     directory and writes the LKG cache; a SUBSEQUENT fetch whose FRESH source is
#     unavailable falls back to the verified cache (never nothing, never unverified);
#     a validly-signed but OLDER (rollback) fresh directory is REFUSED and the cache
#     is kept. Then `shade-tree select` picks a gateway from the cache. Mirrors
#     selection.mjs ensureLoaded / loadFromBootnode LKG discipline.
#
# The over-Tor variants (--onion / --directory / --bootnode-onion over embedded Tor)
# are exercised by egress-tor-run.sh under SHADE_TREE_TOR_E2E; this plain-TCP harness is the
# authoritative always-green check, exactly like egress-run.sh.
#
# Prereqs: `npm install` at the repo root (rlnjs) + a Rust toolchain.
# Run from anywhere: bash crates/shadenet-rln/interop/failover-lkg-run.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
CIRCUITS="$REPO/circuits/rln"
TESTDATA="$REPO/crates/shadenet/src/testdata"
WORK="$(mktemp -d)"

# Ports: the real gateway is HARDCODED to 127.0.0.1:8443 (gateway.mjs LISTEN_PORT).
# The DEAD candidate is a port with nothing listening (connection refused fast).
GW_PORT=8443
DEAD_PORT=1
SINK_PORT=9444
TARGET="127.0.0.1:${SINK_PORT}"

# ---- SIGPIPE-robust cleanup (T-RUST-2f lesson: a piped run must still reap) --------
# The loop-23 harness leaked its gateway/sink children when stdout was piped, because
# SIGPIPE terminated the script BEFORE the EXIT trap fired. We trap PIPE/INT/TERM/HUP
# in addition to EXIT and reap unconditionally from a pidfile, so piping this harness
# to head/tail leaves ZERO leftover gateway/sink processes.
PIDFILE="$WORK/pids"
: > "$PIDFILE"
track() { echo "$1" >> "$PIDFILE"; }   # record a backgrounded child's PID
MEMBERS_BAK=""
_cleaned=0
cleanup() {
  [ "$_cleaned" = 1 ] && return 0
  _cleaned=1
  if [ -f "$PIDFILE" ]; then
    while read -r pid; do
      [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done < "$PIDFILE"
  fi
  # restore the repo's group/members.json (layer A overwrites it as the gateway root)
  [ -n "$MEMBERS_BAK" ] && [ -f "$MEMBERS_BAK" ] && mv -f "$MEMBERS_BAK" "$REPO/group/members.json" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM HUP PIPE

echo "== building feature client (cargo build -p shadenet-cli --features live) =="
cargo build -p shadenet-cli --features live --manifest-path "$REPO/Cargo.toml"
SHADE_TREE="$REPO/target/debug/shade-tree"

SIGNER="$(cat "$TESTDATA/lkg_signer.txt")"

echo
echo "== LAYER B: LAST-KNOWN-GOOD directory caching (fetch-directory + select) =="
CACHE="$WORK/dir.lkg"
# 1. Fresh verifies -> writes the LKG cache.
OUT="$($SHADE_TREE fetch-directory --file "$TESTDATA/lkg_dir_200.json" --signer "$SIGNER" --cache "$CACHE")"
echo "$OUT"
echo "$OUT" | grep -q "^source: fresh" || { echo "LAYER B FAILED: expected fresh"; exit 1; }
[ -f "$CACHE" ] || { echo "LAYER B FAILED: LKG cache not written"; exit 1; }
# 2. Fresh source unavailable -> falls back to the verified LKG cache.
OUT="$($SHADE_TREE fetch-directory --file "$WORK/does-not-exist.json" --signer "$SIGNER" --cache "$CACHE")"
echo "$OUT"
echo "$OUT" | grep -q "^source: cache" || { echo "LAYER B FAILED: expected cache fallback"; exit 1; }
echo "$OUT" | grep -q "^issued: 200" || { echo "LAYER B FAILED: cache issued wrong"; exit 1; }
# 3. A validly-signed OLDER directory (issued 100 < cached 200) is a rollback: refused.
OUT="$($SHADE_TREE fetch-directory --file "$TESTDATA/lkg_dir_100.json" --signer "$SIGNER" --cache "$CACHE")"
echo "$OUT"
echo "$OUT" | grep -q "rollback rejected" || { echo "LAYER B FAILED: rollback not refused"; exit 1; }
echo "$OUT" | grep -q "^issued: 200" || { echo "LAYER B FAILED: rollback clobbered the cache"; exit 1; }
# 4. select picks a gateway from the LKG cache (never an unverified list). Capture the
# output first rather than piping to `grep -q`: a `grep -q` that exits on the first match
# would close the pipe and make the (multi-line) `select` print race a broken-pipe panic.
OUT="$($SHADE_TREE select "$CACHE" --signer "$SIGNER" --seed 1)"
echo "$OUT" | grep -q "^ok" || { echo "LAYER B FAILED: select from cache"; exit 1; }
echo "LAYER B OK (fresh->cache, LKG fallback, rollback refused, select-from-cache)"

echo
echo "== LAYER A: GATEWAY FAILOVER (dead first candidate -> second ACCEPTS) =="
echo "== deriving identity + member set (lib/rln.mjs) =="
node "$HERE/egress-derive.mjs" "$WORK"
IDENTITY="$WORK/identity.json"
MEMBERS="$WORK/members.json"

# Point the gateway's PoC root source at our derived member set (backup + restore in trap).
MEMBERS_BAK="$WORK/members.json.repo-bak"
cp "$REPO/group/members.json" "$MEMBERS_BAK"
cp "$MEMBERS" "$REPO/group/members.json"

# A local egress sink = the :port the gateway proxies to (so `pass` fires without real net).
node -e 'const net=require("net"); net.createServer(s=>s.resume()).listen('"$SINK_PORT"',"127.0.0.1",()=>console.error("[sink] up on 127.0.0.1:'"$SINK_PORT"'"));' > "$WORK/sink.log" 2>&1 &
SINK_PID=$!; track "$SINK_PID"; disown "$SINK_PID" 2>/dev/null || true
node "$HERE/wait-log.mjs" "$WORK/sink.log" "[sink] up" 15000

# Start the real gateway. Allow ONLY our local sink target; default epoch length.
SHADE_TREE_EGRESS_ALLOW="$TARGET" SHADE_TREE_ALLOW_PRIVATE_TARGETS=1 SHADE_TREE_EPOCH_SECONDS=120 \
  node "$REPO/gateway/gateway.mjs" > "$WORK/gw.log" 2>&1 &
GW_PID=$!; track "$GW_PID"; disown "$GW_PID" 2>/dev/null || true
node "$HERE/wait-log.mjs" "$WORK/gw.log" "gateway up on" 20000

# FAILOVER: candidate list = DEAD address first, real gateway second. The client must
# build one envelope, fail to dial the dead one, ROTATE, and have the gateway accept.
set +e
"$SHADE_TREE" egress --plain-tcp "127.0.0.1:${DEAD_PORT},127.0.0.1:${GW_PORT}" \
  --identity "$IDENTITY" --members "$MEMBERS" --target "$TARGET" \
  --circuits "$CIRCUITS" > "$WORK/shade-tree.out" 2> "$WORK/shade-tree.err"
A_SHADE_TREE_RC=$?
set -e
echo "--- shade-tree stderr (failover trace) ---"; cat "$WORK/shade-tree.err"
echo "--- shade-tree stdout ---"; cat "$WORK/shade-tree.out"
echo "--- gateway log ---"; cat "$WORK/gw.log"

# Assert: (1) the client ROTATED past the dead first candidate, (2) it printed ok (rc 0),
# and (3) the accepting gateway is the live second candidate. The gateway sends `ok:true` only after
# proof verification, target policy and the destination connect; it does not log per-egress lines.
grep -q "candidate 127.0.0.1:${DEAD_PORT} failed" "$WORK/shade-tree.err" || { echo "LAYER A FAILED: no rotation off the dead candidate"; exit 1; }
grep -q "^ok" "$WORK/shade-tree.out" || { echo "LAYER A FAILED: client did not report ok"; exit 1; }
[ "$A_SHADE_TREE_RC" -eq 0 ] || { echo "LAYER A FAILED: shade-tree rc=$A_SHADE_TREE_RC"; exit 1; }
grep -q "^gateway: 127.0.0.1:${GW_PORT}$" "$WORK/shade-tree.out" || { echo "LAYER A FAILED: the live gateway did not accept the rotated envelope"; exit 1; }
echo "LAYER A OK (dead first candidate -> rotated -> second gateway ACCEPTED the same envelope)"

echo
echo "== T-RUST-3 FAILOVER + LKG OK: Rust client rotates on a dead gateway AND falls back to the verified last-known-good directory =="
