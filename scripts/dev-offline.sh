#!/usr/bin/env bash
# Offline local loop (OPS-19, #97): a real Shade Tree node and the real Rust Proxy on loopback,
# with NO Tor. The Proxy still mints a real RLN proof per tunnel and the node still verifies it,
# enforces the rate limit and dials the destination; only the Tor rendezvous between them is
# replaced by a loopback TCP dial (`--plain-tcp`, which exists only in debug builds).
#
# DEVELOPMENT ONLY. Without Tor the node sees your IP. Never point this at a public node.
#
#   npm run dev:offline                  # then, in another shell:
#   curl -x http://shade-tree:<token>@127.0.0.1:18118 https://example.com -sI
#
# Ctrl-C stops everything. Env: SHADENET_DEV_PROXY_PORT (18118), SHADENET_DEV_NODE_PORT (18443),
# SHADENET_DEV_KEEP_LOGS=1 keeps the temp directory with node.log and proxy.log after exit.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INTEROP="$REPO/crates/shadenet-rln/interop"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/shadenet-offline.XXXXXX")"
NODE_PORT="${SHADENET_DEV_NODE_PORT:-18443}"
PROXY_PORT="${SHADENET_DEV_PROXY_PORT:-18118}"
SECRET="$(node -e 'const {randomBytes}=require("crypto"); process.stdout.write(BigInt("0x"+randomBytes(16).toString("hex")).toString())')"
TOKEN="$(node -e 'process.stdout.write(require("crypto").randomBytes(32).toString("hex"))')"
EPOCH_SECONDS=60
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; rm -rf "$WORK"; }
trap cleanup EXIT INT TERM
[ "${SHADENET_DEV_KEEP_LOGS:-0}" = 1 ] && cleanup() { for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done; }

echo "== build the Rust Proxy (debug, with the plain-TCP dev transport)"
cargo build --locked --quiet --manifest-path "$REPO/Cargo.toml" -p shadenet-cli --features live
BIN="$REPO/target/debug/shadenet"

echo "== ephemeral member identity + invited set"
node "$INTEROP/egress-derive.mjs" "$WORK" "$SECRET" >/dev/null

echo "== node on 127.0.0.1:$NODE_PORT (members.json admission, :443 egress)"
SHADE_TREE_MEMBERS_FILE="$WORK/members.json" \
SHADE_TREE_GATEWAY_PORT="$NODE_PORT" \
SHADE_TREE_EPOCH_SECONDS="$EPOCH_SECONDS" \
SHADE_TREE_SPENT_STATE_FILE=off \
SHADE_TREE_BANNER=never \
  node "$REPO/gateway/gateway.mjs" > "$WORK/node.log" 2>&1 &
PIDS+=($!)
node "$INTEROP/wait-log.mjs" "$WORK/node.log" "gateway up on" 30000 || { cat "$WORK/node.log"; exit 1; }

echo "== Proxy on 127.0.0.1:$PROXY_PORT (plain TCP to the node, no Tor)"
SHADENET_SLOT_STATE_DIR="$WORK/slots" SHADENET_PROXY_TOKEN="$TOKEN" SHADENET_EPOCH_SECONDS="$EPOCH_SECONDS" \
  "$BIN" proxy --listen "127.0.0.1:$PROXY_PORT" --plain-tcp "127.0.0.1:$NODE_PORT" \
    --identity "$WORK/identity.json" --members "$WORK/members.json" > "$WORK/proxy.log" 2>&1 &
PIDS+=($!)
node "$INTEROP/wait-log.mjs" "$WORK/proxy.log" "proxy listening on" 30000 || { cat "$WORK/proxy.log"; exit 1; }

cat <<MSG

Offline loop ready. Each tunnel spends one RLN slot of the member's per-epoch budget (${EPOCH_SECONDS}s epochs).

  curl -x http://shade-tree:${TOKEN}@127.0.0.1:${PROXY_PORT} https://example.com -sI

Logs: $WORK/node.log and $WORK/proxy.log (tail -f them to watch proofs verify). Ctrl-C to stop.
MSG
wait
