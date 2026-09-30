#!/usr/bin/env bash
# Bring the whole PoC up: tor (onion service) + gateway + client shim.
# Requires SHADE_TREE_SECRET in the environment or in a .secret file (from `npm run enroll`).
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -z "${SHADE_TREE_SECRET:-}" ] && [ -f .secret ]; then export SHADE_TREE_SECRET="$(cat .secret)"; fi
if [ -z "${SHADE_TREE_SECRET:-}" ]; then
  echo "no SHADE_TREE_SECRET. Run:  node group/enroll.mjs   then   export SHADE_TREE_SECRET=..." >&2
  exit 1
fi

bash scripts/start-tor.sh

if pgrep -f "packages/node/gateway/gateway.mjs" >/dev/null; then echo "gateway already running"; else
  node packages/node/gateway/gateway.mjs > gateway.log 2>&1 & echo "gateway pid $!"
fi
sleep 1
if pgrep -f "packages/node/client/shim.mjs" >/dev/null; then echo "shim already running"; else
  node packages/node/client/shim.mjs > shim.log 2>&1 & echo "shim pid $!"
fi
sleep 1
echo ""
echo "ready. test it:"
echo "  curl -x http://127.0.0.1:8888 'https://api.ipify.org?format=json'"
echo "logs: gateway.log, shim.log, tor/tor.log"
