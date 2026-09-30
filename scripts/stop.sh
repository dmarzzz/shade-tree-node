#!/usr/bin/env bash
# Stop everything this PoC started. Leaves the searxng-tor-bench tor untouched
# (we only kill tor started with our own torrc).
set -uo pipefail
cd "$(dirname "$0")/.."
pkill -f "packages/node/client/shim.mjs" 2>/dev/null && echo "stopped shim" || true
pkill -f "packages/node/gateway/gateway.mjs" 2>/dev/null && echo "stopped gateway" || true
pkill -f "tor -f ./tor/torrc" 2>/dev/null && echo "stopped tor" || true
rm -f tor/tor.pid
echo "done"
