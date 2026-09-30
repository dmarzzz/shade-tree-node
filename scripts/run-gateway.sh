#!/usr/bin/env bash
# GATEWAY / DROPLET role: the clean-IP egress box.
#
# Runs the two server-side pieces and nothing else:
#   1. Tor, publishing the gateway as a v3 onion service (./tor/torrc),
#   2. packages/node/gateway/gateway.mjs, the Shade Tree tunnel gateway (loopback only).
#
# It deliberately does NOT start the client shim and does NOT need SHADE_TREE_SECRET:
# the droplet never holds a member secret. It only needs group/members.json (the
# public reputation set) so it can compute the trusted Merkle root to gate on.
#
# Hand the printed .onion address to clients; they put it in SHADE_TREE_ONION.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -s group/members.json ]; then
  echo "group/members.json is missing or empty. Ship the reputation set to this box first." >&2
  echo "(It is public — just commitments — so copying it here leaks nothing.)" >&2
  exit 1
fi

# Bring up Tor + the onion service. Prints the gateway onion when published.
bash scripts/start-tor.sh

if pgrep -f "packages/node/gateway/gateway.mjs" >/dev/null; then
  echo "gateway already running"
else
  # Comfortable per-member budget for a demo (redemptions / member / epoch; epoch
  # defaults to a day). Lower it (e.g. SHADE_TREE_RATE_LIMIT=3) to show the limiter drop.
  export SHADE_TREE_RATE_LIMIT="${SHADE_TREE_RATE_LIMIT:-100}"
  node packages/node/gateway/gateway.mjs > gateway.log 2>&1 &
  echo "gateway pid $! (rate budget ${SHADE_TREE_RATE_LIMIT}/member/epoch)"
fi
sleep 1

ONION="$(cat tor/hs/hostname 2>/dev/null || echo '<not-published-yet>')"
echo ""
echo "gateway role up."
echo "  onion:   ${ONION}"
echo "  give clients:   export SHADE_TREE_ONION=${ONION}"
echo "  logs:    gateway.log, tor/tor.log"
echo ""
echo "this box egresses from its own IP. lock it down: only :443 outbound is used,"
echo "and the gateway binds 127.0.0.1 so it is reachable ONLY via the onion."
