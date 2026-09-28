#!/usr/bin/env bash
# Proxy concurrency and structured-error contract (ShadeNet M2/M3 exit checks).
#
#   8 CONNECT clients at once -> one Rust Proxy -> JS gateway -> a sink that holds each tunnel
#
# 1. Eight tunnels are open at the same time: the sink answers nobody until all eight have
#    arrived, so a proxy that pinned tunnels to prover workers (the old design held at most two)
#    would never complete. Proving speed does not matter to this check.
# 2. The member's tier is 8, so a ninth CONNECT in the same epoch must be refused locally with
#    `429`, `X-ShadeNet-Error: budget_exhausted`, a `Retry-After` header and a JSON body, before any
#    proof is built.
# 3. `GET /_shadenet/status` reports 8 used / 0 left for the epoch.
#
# Plain TCP keeps Tor out of this blocking layer; the proof, the gateway's verification and the
# relay are real.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
WORK="$(mktemp -d)"

GW_PORT="${SHADENET_CONCURRENCY_GATEWAY_PORT:-18544}"
PROXY_PORT="${SHADENET_CONCURRENCY_PROXY_PORT:-18218}"
SINK_PORT="${SHADENET_CONCURRENCY_SINK_PORT:-19543}"
TARGET="127.0.0.1:${SINK_PORT}"
SECRET="${SHADENET_CONCURRENCY_SECRET:-34567890123456789012}"
PROXY_TOKEN="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
TUNNELS=8
# One-hour epochs on both sides: eight proofs on a small CI runner can take minutes, and a
# 120-second epoch would roll past the node's accepted window before the last proof arrives.
EPOCH_SECONDS=3600
TEST_EPOCH="$(node -e 'process.stdout.write(String(Math.floor(Date.now() / 1000 / '"$EPOCH_SECONDS"')))')"

PIDS=()
cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "--- gateway log (tail) ---" >&2; tail -n 40 "$WORK/gateway.log" >&2 2>/dev/null || true
    echo "--- proxy log (tail) ---" >&2; tail -n 40 "$WORK/proxy.log" >&2 2>/dev/null || true
  fi
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM HUP PIPE

if [ -n "${SHADE_TREE_RUST_BIN:-}" ]; then
  SHADENET="$SHADE_TREE_RUST_BIN"
else
  cargo build --locked --manifest-path "$REPO/Cargo.toml" -p shadenet-cli --features live
  SHADENET="$REPO/target/debug/shadenet"
fi

node "$HERE/egress-derive.mjs" "$WORK" "$SECRET"

# A barrier: hold every tunnel until TUNNELS of them are open at once, then answer them all.
node -e '
  const net = require("net");
  const want = Number(process.argv[2]);
  const waiting = [];
  net.createServer((s) => s.once("data", (d) => {
    waiting.push([s, String(d)]);
    console.error(`sink: ${waiting.length}/${want} tunnels open`);
    if (waiting.length === want) for (const [sock, data] of waiting.splice(0)) sock.end("held-ok:" + data);
  })).listen(Number(process.argv[1]), "127.0.0.1", () => console.error("sink ready"));
' "$SINK_PORT" "$TUNNELS" > "$WORK/sink.log" 2>&1 &
PIDS+=($!)
node "$HERE/wait-log.mjs" "$WORK/sink.log" "sink ready" 15000

SHADE_TREE_MEMBERS_FILE="$WORK/members.json" \
SHADE_TREE_GATEWAY_PORT="$GW_PORT" \
SHADE_TREE_EGRESS_ALLOW="$TARGET" \
SHADE_TREE_ALLOW_PRIVATE_TARGETS=1 \
SHADE_TREE_BANNER=never \
SHADE_TREE_EPOCH_SECONDS="$EPOCH_SECONDS" \
  node "$REPO/gateway/gateway.mjs" > "$WORK/gateway.log" 2>&1 &
PIDS+=($!)
node "$HERE/wait-log.mjs" "$WORK/gateway.log" "gateway up on" 30000

SHADENET_SLOT_STATE_DIR="$WORK/slots" \
SHADENET_PROXY_TOKEN="$PROXY_TOKEN" \
SHADENET_PROVER_WORKERS=4 \
  "$SHADENET" proxy --no-cache \
    --listen "127.0.0.1:${PROXY_PORT}" \
    --plain-tcp "127.0.0.1:${GW_PORT}" \
    --identity "$WORK/identity.json" \
    --members "$WORK/members.json" \
    --epoch "$TEST_EPOCH" \
    > "$WORK/proxy.log" 2>&1 &
PROXY_PID=$!
PIDS+=("$PROXY_PID")
node "$HERE/wait-log.mjs" "$WORK/proxy.log" "proxy listening on" 15000

echo "== ${TUNNELS} concurrent CONNECTs held open together by the sink =="
node - "$PROXY_PORT" "$TARGET" "$PROXY_TOKEN" "$TUNNELS" <<'NODE'
const net = require("net");
const [port, target, token, count] = process.argv.slice(2);
const credential = Buffer.from(`shadenet:${token}`).toString("base64");
let open = 0, peak = 0;
function one(i) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    const s = net.connect(Number(port), "127.0.0.1", () => {
      s.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\nProxy-Authorization: Basic ${credential}\r\n\r\n`);
    });
    let accepted = false;
    s.setTimeout(600000, () => s.destroy(new Error("timeout")));
    s.on("data", (c) => {
      chunks.push(c);
      const text = Buffer.concat(chunks).toString();
      if (!accepted && text.startsWith("HTTP/1.1 200 ")) {
        accepted = true;
        open += 1; peak = Math.max(peak, open);
        s.write(`ping-${i}`);
      }
    });
    s.on("error", reject);
    s.on("close", () => {
      if (accepted) open -= 1;
      const text = Buffer.concat(chunks).toString();
      text.includes(`held-ok:ping-${i}`) ? resolve() : reject(new Error(`tunnel ${i}: ${text.slice(0, 600)}`));
    });
  });
}
const started = Date.now();
Promise.all(Array.from({ length: Number(count) }, (_, i) => one(i))).then(() => {
  const elapsed = Date.now() - started;
  console.log(`all ${count} tunnels relayed in ${elapsed} ms; peak open at once = ${peak}`);
  if (peak < Number(count)) { console.error(`FAIL: expected ${count} tunnels open at once, saw ${peak}`); process.exit(1); }
}).catch((e) => { console.error(`FAIL: ${e.message}`); process.exit(1); });
NODE

echo "== a ninth CONNECT in the same epoch gets a structured 429 =="
node - "$PROXY_PORT" "$TARGET" "$PROXY_TOKEN" <<'NODE'
const net = require("net");
const [port, target, token] = process.argv.slice(2);
const credential = Buffer.from(`shadenet:${token}`).toString("base64");
const chunks = [];
const s = net.connect(Number(port), "127.0.0.1", () =>
  s.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\nProxy-Authorization: Basic ${credential}\r\n\r\n`));
s.on("data", (c) => chunks.push(c));
s.on("close", () => {
  const text = Buffer.concat(chunks).toString();
  const [head, body] = text.split("\r\n\r\n");
  const ok = head.startsWith("HTTP/1.1 429 ")
    && /\r\nX-ShadeNet-Error: budget_exhausted\r\n/.test(head + "\r\n")
    && /\r\nRetry-After: \d+/.test(head)
    && JSON.parse(body).error.code === "budget_exhausted";
  if (!ok) { console.error(`FAIL: expected a structured 429, got: ${text.slice(0, 400)}`); process.exit(1); }
  console.log("PASS: 429 budget_exhausted with Retry-After and a JSON body");
});
NODE

echo "== status endpoint reports the spent budget =="
node - "$PROXY_PORT" "$PROXY_TOKEN" "$TUNNELS" <<'NODE'
const http = require("http");
const [port, token, count] = process.argv.slice(2);
http.get({ host: "127.0.0.1", port: Number(port), path: "/_shadenet/status", headers: { Authorization: `Bearer ${token}` } }, (res) => {
  let body = "";
  res.on("data", (c) => (body += c));
  res.on("end", () => {
    const status = JSON.parse(body);
    if (res.statusCode !== 200 || status.slotsUsed !== Number(count) || status.slotsLeft !== 0 || status.state !== "budget_exhausted") {
      console.error(`FAIL: unexpected status ${res.statusCode} ${body}`);
      process.exit(1);
    }
    console.log(`PASS: status reports ${status.slotsUsed} used, ${status.slotsLeft} left, resets in ${status.epochResetsInSeconds}s`);
  });
}).on("error", (e) => { console.error(`FAIL: ${e.message}`); process.exit(1); });
NODE

kill -0 "$PROXY_PID" 2>/dev/null || { cat "$WORK/proxy.log" >&2; echo "proxy exited" >&2; exit 1; }
echo "== PROXY CONCURRENCY OK: ${TUNNELS} concurrent tunnels, structured 429, status endpoint =="
