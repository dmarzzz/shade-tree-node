#!/usr/bin/env bash
# End-to-end RLN interop check (T-RUST-2b RLN-INTEROP).
#
#   Rust builds an RLN Groth16 envelope proof against the repo's circom-rln
#   artifacts; the JS reference (packages/node/lib/rln.mjs verifyEnvelope) ACCEPTS it; and a
#   cross-impl over-spend reconstructs the identity secret from two Rust shares.
#
# Prereqs: `npm install` at the repo root (rlnjs) and a Rust toolchain.
# Run from anywhere: bash crates/shadenet-rln/interop/run.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE="$(cd "$HERE/.." && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
CIRCUITS="$REPO/circuits/rln"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "== building rust probe =="
cargo build -p shadenet-rln --bin shadenet-rln-probe --manifest-path "$REPO/Cargo.toml"
PROBE="$REPO/target/debug/shadenet-rln-probe"

echo "== fixture A (nonce #1) =="
node "$HERE/fixture-gen.mjs" 0123456789abcdef0123456789abcdef > "$WORK/fixtureA.json"
"$PROBE" "$WORK/fixtureA.json" "$WORK/envA.json" "$CIRCUITS"

echo "== fixture B (same slot/epoch, nonce #2 -> different x) =="
node "$HERE/fixture-gen.mjs" ffffffffffffffffffffffffffffffff > "$WORK/fixtureB.json"
"$PROBE" "$WORK/fixtureB.json" "$WORK/envB.json" "$CIRCUITS"

echo "== JS verifyEnvelope must ACCEPT the Rust envelope =="
node "$HERE/verify-envelope.mjs" "$WORK/envA.json"

echo "== cross-impl over-spend reconstruction =="
node "$HERE/overspend.mjs" "$WORK/envA.json" "$WORK/envB.json" "$WORK/fixtureA.json"

echo "== reputation tier (T-FEAT-8): tier-32 leaf, slot 20 (>= default K) — Rust proves, JS accepts =="
SHADE_TREE_INTEROP_LIMIT=32 SHADE_TREE_INTEROP_SLOT=20 node "$HERE/fixture-gen.mjs" 0123456789abcdef0123456789abcdef > "$WORK/fixtureT.json"
"$PROBE" "$WORK/fixtureT.json" "$WORK/envT.json" "$CIRCUITS"
node "$HERE/verify-envelope.mjs" "$WORK/envT.json"

echo "== RLN INTEROP OK =="
