// Test of the in-memory fleet-history trend buffer behind /api/history.
//
// It stands up the same MOCK bootnode shape as status.selftest.mjs (real /health +
// signDirectory'd /directory over onions derived from real ed25519 keys), then drives the status
// server and pins the trend contract:
//   - /api/status embeds a short `history` summary,
//   - GET /api/history returns bounded { ts, bootnodeReachable, signerOk, fleetSize } samples,
//   - the ring is CAPPED: hitting /api/status far more than the cap never grows past it,
//   - NO full onion and NO operator address ever appears in /api/history (privacy).
//
//   node web/status-history.selftest.mjs
//
// Exit 0 = every check held; nonzero = a check failed.

import http from "node:http";
import { generateKeyPairSync } from "node:crypto";
import { signDirectory, pubkeyToOnion } from "../packages/node/lib/directory.mjs";
import { makeStatusServer } from "./status-server.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

function mintEd25519() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
  const priv = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32).toString("hex");
  return { pub, priv };
}

function mintGateway(extra = {}) {
  const { pub } = mintEd25519();
  const onion = pubkeyToOnion(pub);
  return { onion, entry: { onion, pubkey: pub, weight: 100, health: "up", ...extra } };
}

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server.address().port)));
}
function close(server) {
  return new Promise((resolve) => (server ? server.close(resolve) : resolve()));
}
const getJson = async (url) => (await fetch(url)).json();

async function main() {
  const signer = mintEd25519();

  const g1 = mintGateway();
  const OPERATOR = "0xDEADBEEFdeadBEEFdeadBEEFdeadBEEFdeadBEEF";
  const g2 = mintGateway({ operator: OPERATOR, staked: true });
  const fullOnions = [g1.onion, g2.onion];

  const dir = signDirectory(
    { version: 1, issued: 1789000000, gateways: [g1.entry, g2.entry], signer: signer.pub },
    signer.priv
  );

  const mock = http.createServer((req, res) => {
    const j = (obj) => { const b = JSON.stringify(obj); res.writeHead(200, { "content-type": "application/json", "content-length": Buffer.byteLength(b) }); res.end(b); };
    if (req.url === "/health") return j({ ok: true, count: 2, admission: "stake", signer: signer.pub });
    if (req.url === "/directory") return j(dir);
    res.writeHead(404); res.end("{}");
  });
  const mockPort = await listen(mock);
  const bootnodeUrl = `http://127.0.0.1:${mockPort}`;

  // Small cap so we can cheaply overflow it and prove the bound holds.
  const CAP = 5;
  const cfg = { bootnodeUrl, dirSigner: signer.pub, torHost: "127.0.0.1", torPort: 9250 };
  let statusServer;
  try {
    statusServer = makeStatusServer(cfg, { historyCap: CAP });
    const port = await listen(statusServer);
    const base = `http://127.0.0.1:${port}`;

    // Fresh server: history empty until the first /api/status is computed.
    console.log("empty history before any status hit:");
    const h0 = await getJson(`${base}/api/history`);
    ok(Array.isArray(h0.samples) && h0.samples.length === 0, "history starts empty");
    ok(h0.cap === CAP, `history reports its cap (${CAP})`);

    // A few /api/status hits => a sample appended each time.
    console.log("\nsamples accrue on each /api/status hit:");
    for (let i = 0; i < 3; i++) await getJson(`${base}/api/status`);
    const h1 = await getJson(`${base}/api/history`);
    ok(h1.samples.length === 3, `3 status hits -> 3 samples (got ${h1.samples.length})`);
    ok(h1.count === 3, "history count matches samples length");
    const s0 = h1.samples[0];
    ok(typeof s0.ts === "string" && !Number.isNaN(Date.parse(s0.ts)), "sample carries a parseable ts");
    ok(typeof s0.fleetSize === "number" && s0.fleetSize === 2, `sample carries fleetSize (2, got ${s0.fleetSize})`);
    ok(typeof s0.bootnodeReachable === "boolean" && s0.bootnodeReachable === true, "sample carries bootnodeReachable boolean (true)");
    ok(typeof s0.signerOk === "boolean" && s0.signerOk === true, "sample carries signerOk boolean (true)");

    // /api/status embeds the short history summary.
    console.log("\n/api/status embeds a short history summary:");
    const st = await getJson(`${base}/api/status`);
    ok(st.history && typeof st.history === "object" && !Array.isArray(st.history), "status.history is a summary object");
    ok(st.history.cap === CAP && typeof st.history.count === "number", "status.history reports cap + count");
    ok(st.history.count === 4, `summary count tracks the ring (4, got ${st.history.count})`);

    // Overflow the cap: many more hits than CAP must NOT grow the ring past CAP.
    console.log("\nring is bounded under overflow:");
    for (let i = 0; i < CAP * 4; i++) await getJson(`${base}/api/status`);
    const hOver = await getJson(`${base}/api/history`);
    ok(hOver.samples.length === CAP, `after ${CAP * 4}+ hits, ring is capped at ${CAP} (got ${hOver.samples.length})`);
    ok(hOver.count === CAP, "history count equals cap under overflow");

    // Privacy: no full onion, no operator address anywhere in /api/history.
    console.log("\nprivacy scrub of the history endpoint:");
    const rawHistory = await (await fetch(`${base}/api/history`)).text();
    ok(!fullOnions.some((o) => rawHistory.includes(o)), "no FULL onion address appears anywhere in /api/history");
    ok(!rawHistory.toLowerCase().includes(OPERATOR.toLowerCase()), "no operator address appears in /api/history");
    ok(!rawHistory.includes(".onion"), "no .onion suffix anywhere in /api/history");
    ok(!rawHistory.includes("onionShort") && !rawHistory.includes("gateways"), "history carries no per-gateway fields at all");
    const hp = JSON.parse(rawHistory);
    ok(hp.samples.every((s) => Object.keys(s).sort().join(",") === "bootnodeReachable,fleetSize,signerOk,ts"),
      "every sample has exactly {ts, bootnodeReachable, signerOk, fleetSize} -- counts + booleans only");
  } finally {
    await close(statusServer);
    await close(mock);
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: web status-history selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
