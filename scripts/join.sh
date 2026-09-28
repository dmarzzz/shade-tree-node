#!/usr/bin/env bash
# FRIEND entrypoint: step under Shade Tree and prove the tunnel works, in one command.
#
# Hand a friend: this repo (with group/members.json) and their own SHADE_TREE_SECRET.
# The live gateway onion is already the default, so they just run:
#
#   scripts/join.sh                       # uses .secret + the default gateway
#   scripts/join.sh <their-secret>        # pass the secret inline
#   scripts/join.sh <gateway-onion> <their-secret>   # override the gateway too
#
# or set SHADE_TREE_ONION / SHADE_TREE_SECRET in the environment.
# It starts their client-side Tor + shim, then runs the verification receipt.
set -euo pipefail
cd "$(dirname "$0")/.."

# Arg handling: one arg = secret; two args = onion then secret. A .onion-looking
# first arg is treated as the gateway address either way.
if [ -n "${2:-}" ]; then
  export SHADE_TREE_ONION="$1"; export SHADE_TREE_SECRET="$2"
elif [ -n "${1:-}" ]; then
  case "$1" in
    *.onion) export SHADE_TREE_ONION="$1" ;;
    *) export SHADE_TREE_SECRET="$1" ;;
  esac
fi

# Optional verification target: the gateway's clearnet IP. This is a RECEIPT, not an
# endpoint: when set, verify.sh compares the egress IP api.ipify.org observed against it
# and prints PASS/FAIL. Unset skips the assertion. No default: the PoC droplet is retired.
export SHADE_TREE_EXPECT_IP="${SHADE_TREE_EXPECT_IP:-}"

echo "joining Shade Tree as a member..."
bash scripts/run-client.sh

echo ""
echo "giving the onion descriptor a moment to resolve, then verifying..."
sleep 2
bash scripts/verify.sh
