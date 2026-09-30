#!/usr/bin/env bash
# CLIENT / LAPTOP role: prove membership and tunnel out through the remote gateway.
#
# Runs the two client-side pieces:
#   1. a client-only Tor SOCKS (no onion) unless you point at an existing one,
#   2. packages/node/client/shim.mjs, the local HTTP proxy that mints a Semaphore proof and
#      dials the gateway's .onion over Tor.
#
# Requires:
#   SHADE_TREE_ONION   the gateway's onion address (from the droplet's run-gateway.sh)
#   SHADE_TREE_SECRET  this member's secret (from `node group/enroll.mjs`; or a .secret file)
#
# This box must hold the SAME group/members.json as the gateway (public set), or
# every proof is built against the wrong Merkle root and the gateway drops it.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -z "${SHADE_TREE_SECRET:-}" ] && [ -f .secret ]; then export SHADE_TREE_SECRET="$(cat .secret)"; fi
if [ -z "${SHADE_TREE_SECRET:-}" ]; then
  echo "no SHADE_TREE_SECRET. Run:  node group/enroll.mjs   then   export SHADE_TREE_SECRET=..." >&2
  exit 1
fi
# Default to the original PoC gateway onion (single-gateway path; the fleet path is
# `shade-tree-node client --bootnode ...`, see docs/QUICKSTART.md) so a friend can run with no
# args. Override SHADE_TREE_ONION to point at a different box. The onion is a discovery
# handle: knowing it buys nothing without a valid membership proof (fail-closed gate).
# Its clearnet IP is deliberately not repeated here; scripts/join.sh carries it as
# SHADE_TREE_EXPECT_IP, the receipt verify.sh compares the observed egress IP against.
export SHADE_TREE_ONION="${SHADE_TREE_ONION:-ezguggje6sbldhw4pl5nudwg2mrwkb5zzyu3a26qc4eka2ur24bv3eqd.onion}"
echo "gateway onion: ${SHADE_TREE_ONION}"

# SOCKS source: reuse an existing Tor if SHADE_TREE_TOR_PORT is already set (e.g. system
# tor 9050), otherwise start our own client-only Tor on 9260.
if [ -n "${SHADE_TREE_TOR_PORT:-}" ]; then
  echo "using existing Tor SOCKS at 127.0.0.1:${SHADE_TREE_TOR_PORT}"
else
  bash scripts/start-tor-client.sh
  export SHADE_TREE_TOR_PORT=9260
fi

if pgrep -f "packages/node/client/shim.mjs" >/dev/null; then
  echo "shim already running"
else
  node packages/node/client/shim.mjs > shim.log 2>&1 &
  echo "shim pid $!"
fi
sleep 1
echo ""
echo "client role up. test it:"
echo "  curl -x http://127.0.0.1:${SHADE_TREE_SHIM_PORT:-8888} 'https://api.ipify.org?format=json'"
echo "the returned IP should be the GATEWAY's, not yours. logs: shim.log, tor/tor-client.log"
