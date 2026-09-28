#!/usr/bin/env bash
# Rust member lifecycle against the real contracts on Anvil:
#
#   shadenet enroll -> register-member (stake) -> member-status (active)
#   -> exit-member (local Groth16 exit proof) -> member-status (exiting)
#   -> time passes the unbonding delay -> withdraw-member (proof bound to the recipient)
#   -> the recipient received the bond
#
# Every transaction is signed by shadenet's own EIP-1559 signer (shadenet::eth), so this is the
# end-to-end check that the ethers-core replacement produces transactions a real chain accepts.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d)"
PORT="${SHADENET_LIFECYCLE_ANVIL_PORT:-18645}"
URL="http://127.0.0.1:${PORT}"
# Anvil's published development accounts (never funded anywhere real).
GAS_KEY="0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
RECIPIENT="0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"

ANVIL_PID=""
cleanup() {
  status=$?
  [ "$status" -ne 0 ] && { echo "--- deploy log (tail) ---" >&2; tail -n 30 "$WORK/deploy.log" >&2 2>/dev/null || true; }
  [ -n "$ANVIL_PID" ] && kill "$ANVIL_PID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM HUP PIPE

command -v anvil >/dev/null && command -v forge >/dev/null || { echo "SKIP: anvil/forge not on PATH"; exit 0; }

if [ -n "${SHADE_TREE_RUST_BIN:-}" ]; then
  SHADENET="$SHADE_TREE_RUST_BIN"
else
  cargo build --locked --manifest-path "$REPO/Cargo.toml" -p shadenet-cli --features live
  SHADENET="$REPO/target/debug/shadenet"
fi

rpc() { curl -fsS -H 'content-type: application/json' --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}" "$URL"; }
field() { node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const v=JSON.parse(s);process.stdout.write(String(process.argv[1].split(".").reduce((o,k)=>o[k],v)))})' "$1"; }

anvil --port "$PORT" --silent &
ANVIL_PID=$!
for _ in $(seq 1 50); do rpc eth_chainId '[]' >/dev/null 2>&1 && break; sleep 0.2; done

echo "== deploy StakedReputationSet with the real Groth16 exit-auth verifier =="
OUT="$REPO/cache/lifecycle-${PORT}.local.json"
(cd "$REPO" && SHADE_TREE_BOND_WEI=10000000000000000 SHADE_TREE_UNBONDING=300 SHADE_TREE_MIN_UNBONDING=270 \
  SHADE_TREE_DEPLOY_REAL_VERIFIER=1 SHADE_TREE_DEPLOY_OUT="$OUT" SHADE_TREE_RPC_URL="$URL" \
  forge script contracts/script/DeployRegistry.s.sol:DeployRegistry --rpc-url "$URL" --broadcast \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 -vv) > "$WORK/deploy.log" 2>&1
SET="$(field stakedReputationSet < "$OUT")"
rm -f "$OUT"
echo "set: $SET"

export SHADENET_SLOT_STATE_DIR="$WORK/slots"
COMMON=(--contract "$SET" --rpc-url "$URL")

echo "== enroll + register-member (the loopback RPC selects Anvil's key 0) =="
"$SHADENET" enroll --limit 8 --out "$WORK/identity.json" > "$WORK/leaf.txt"
"$SHADENET" register-member --identity "$WORK/identity.json" "${COMMON[@]}"
"$SHADENET" member-status --identity "$WORK/identity.json" --json "${COMMON[@]}" > "$WORK/s1.json"
[ "$(field status < "$WORK/s1.json")" = active ] || { cat "$WORK/s1.json"; echo "FAIL: not active after registration"; exit 1; }
BOND="$(field bondWei < "$WORK/s1.json")"
echo "active with bond $BOND wei"

echo "== exit-member (local Groth16 proof, gas from an unrelated wallet) =="
printf '%s\n' "$GAS_KEY" > "$WORK/gas.key"; chmod 600 "$WORK/gas.key"
"$SHADENET" exit-member --identity "$WORK/identity.json" --key-file "$WORK/gas.key" "${COMMON[@]}"
"$SHADENET" member-status --identity "$WORK/identity.json" --json "${COMMON[@]}" > "$WORK/s2.json"
[ "$(field status < "$WORK/s2.json")" = exiting ] || { cat "$WORK/s2.json"; echo "FAIL: not exiting after exit-member"; exit 1; }

echo "== too early: withdraw-member refuses =="
if "$SHADENET" withdraw-member --identity "$WORK/identity.json" --recipient "$RECIPIENT" --key-file "$WORK/gas.key" "${COMMON[@]}" 2>"$WORK/early.err"; then
  echo "FAIL: withdrawal accepted before the unbonding delay"; exit 1
fi
grep -q "still bonded" "$WORK/early.err" || { cat "$WORK/early.err"; echo "FAIL: unexpected early-withdraw error"; exit 1; }

echo "== after the unbonding delay: withdraw-member pays the recipient =="
rpc evm_increaseTime '[400]' >/dev/null; rpc evm_mine '[]' >/dev/null
BEFORE="$(rpc eth_getBalance "[\"$RECIPIENT\",\"latest\"]" | field result)"
"$SHADENET" withdraw-member --identity "$WORK/identity.json" --recipient "$RECIPIENT" --key-file "$WORK/gas.key" "${COMMON[@]}"
AFTER="$(rpc eth_getBalance "[\"$RECIPIENT\",\"latest\"]" | field result)"
node -e 'const [b,a,bond]=process.argv.slice(1).map(BigInt); if (a-b!==bond){console.error(`FAIL: recipient gained ${a-b}, expected the bond ${bond}`);process.exit(1)} console.log(`recipient gained exactly the bond: ${bond} wei`)' "$BEFORE" "$AFTER" "$BOND"
"$SHADENET" member-status --identity "$WORK/identity.json" --json "${COMMON[@]}" > "$WORK/s3.json"
[ "$(field status < "$WORK/s3.json")" = absent ] || { cat "$WORK/s3.json"; echo "FAIL: member still present after withdrawal"; exit 1; }

echo "== MEMBER LIFECYCLE OK: register, exit, withdraw signed by shadenet::eth on the real contracts =="
