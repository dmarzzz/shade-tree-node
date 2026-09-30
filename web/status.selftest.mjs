// End-to-end test of the fleet status page against a MOCK bootnode (no Tor, no chain).
//
// It stands up a local http server that speaks the real bootnode /health + /directory shapes,
// signing the directory with packages/node/lib/directory.mjs signDirectory over gateways whose onions are
// derived from real ed25519 keys (so verifyDirectory's onion<->pubkey binding holds). Then it
// runs the actual status server against it and pins the contract:
//   - /api/status reports the right fleetSize,
//   - signerOk is TRUE for a directory signed by the pinned signer,
//   - signerOk is FALSE when the status server pins a DIFFERENT signer,
//   - the scrubbed output leaks NO full onion and NO operator address -- only truncated onions
//     and a staked boolean.
//
//   node web/status.selftest.mjs
//
// Exit 0 = every check held; nonzero = a check failed.

import http from "node:http";
import { generateKeyPairSync } from "node:crypto";
import { signDirectory, pubkeyToOnion } from "../packages/node/lib/directory.mjs";
import { makeStatusServer, buildStatus } from "./status-server.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

// --- ed25519 raw-hex keygen (same DER-tail trick the bootnode uses) ----------
function mintEd25519() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = publicKey.export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
  const priv = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32).toString("hex");
  return { pub, priv };
}

// Build a gateway entry whose onion is the v3 encoding of a real ed25519 key, so the directory
// passes verifyDirectory's onion<->pubkey binding. Returns the entry + the full onion (for the
// leak assertions -- the test must know the address the page is NOT allowed to reveal).
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

async function main() {
  const signer = mintEd25519();            // the pinned bootnode directory signer
  const wrongSigner = mintEd25519();        // a DIFFERENT signer the status server will pin

  // Two gateways: one bare (no operator), one with an operator address + staked flag, so we can
  // assert BOTH that fleetSize counts them and that the operator address is scrubbed out.
  const g1 = mintGateway();
  const OPERATOR = "0xDEADBEEFdeadBEEFdeadBEEFdeadBEEFdeadBEEF";
  const g2 = mintGateway({ operator: OPERATOR, staked: true });
  const fullOnions = [g1.onion, g2.onion];

  const dir = signDirectory(
    { version: 1, issued: 1789000000, gateways: [g1.entry, g2.entry], signer: signer.pub },
    signer.priv
  );

  // --- mock bootnode: real /health + /directory JSON shapes --------------------
  const mock = http.createServer((req, res) => {
    const j = (obj) => { const b = JSON.stringify(obj); res.writeHead(200, { "content-type": "application/json", "content-length": Buffer.byteLength(b) }); res.end(b); };
    if (req.url === "/health") return j({ ok: true, count: 2, admission: "stake", signer: signer.pub });
    if (req.url === "/directory") return j(dir);
    res.writeHead(404); res.end("{}");
  });
  const mockPort = await listen(mock);
  const bootnodeUrl = `http://127.0.0.1:${mockPort}`;

  let statusOk, statusServer;
  try {
    // === correctly pinned signer ===============================================
    console.log("status against correctly-pinned signer:");
    const cfgOk = { bootnodeUrl, dirSigner: signer.pub, torHost: "127.0.0.1", torPort: 9250 };

    // Drive buildStatus directly (unit) ...
    statusOk = await buildStatus(cfgOk);
    ok(statusOk.bootnodeReachable === true, "bootnodeReachable is true against a live mock");
    ok(statusOk.fleetSize === 2, `fleetSize is 2 (got ${statusOk.fleetSize})`);
    ok(statusOk.gateways.length === 2, "two gateways in the scrubbed list");
    ok(statusOk.signerOk === true, "signerOk true for a directory signed by the pinned signer");
    ok(statusOk.admission === "stake", "admission surfaced from /health");

    // ... and through the real HTTP server + /api/status route.
    statusServer = makeStatusServer(cfgOk);
    const port = await listen(statusServer);
    const apiRes = await fetch(`http://127.0.0.1:${port}/api/status`);
    const api = await apiRes.json();
    ok(api.fleetSize === 2 && api.signerOk === true, "GET /api/status returns fleetSize 2 + signerOk true");
    const pageRes = await fetch(`http://127.0.0.1:${port}/`);
    const pageBody = await pageRes.text();
    ok(pageRes.headers.get("content-type").includes("text/html") && pageBody.includes("FLEET STATUS"), "GET / serves the HTML page");

    // === privacy: no full onion, no operator address in the output =============
    console.log("\nprivacy scrub:");
    const apiJson = JSON.stringify(api);
    let leakedOnion = fullOnions.some((o) => apiJson.includes(o));
    ok(!leakedOnion, "no FULL onion address appears anywhere in /api/status");
    ok(!apiJson.includes(OPERATOR) && !apiJson.toLowerCase().includes(OPERATOR.toLowerCase()), "no operator address appears in /api/status");
    // Truncated onion IS present and IS only the 16-char prefix.
    const shortG1 = g1.onion.slice(0, 16);
    ok(apiJson.includes(shortG1), "truncated onion prefix (16 chars) IS present");
    ok(api.gateways.every((g) => g.onionShort.length === 16 && !g.onionShort.includes(".onion")), "every onionShort is exactly 16 chars, no .onion suffix");
    // The staked gateway shows staked:true; neither entry carries an operator field.
    const staked = api.gateways.find((g) => g.staked === true);
    ok(staked && staked.operator === undefined, "staked gateway shows staked:true and NO operator field");
    ok(api.gateways.every((g) => !("operator" in g)), "no gateway view carries an operator key");

    await close(statusServer); statusServer = null;

    // === wrong pinned signer -> signerOk false =================================
    console.log("\nstatus against a WRONG pinned signer:");
    const cfgWrong = { bootnodeUrl, dirSigner: wrongSigner.pub, torHost: "127.0.0.1", torPort: 9250 };
    const statusWrong = await buildStatus(cfgWrong);
    ok(statusWrong.bootnodeReachable === true, "bootnode still reachable with wrong signer pinned");
    ok(statusWrong.signerOk === false, "signerOk FALSE when a different signer is pinned");
    ok(statusWrong.fleetSize === 2, "fleet still listed (unverified) so the board is not blank");

    // === unreachable bootnode -> graceful degrade ==============================
    console.log("\nstatus against an unreachable bootnode:");
    const cfgDead = { bootnodeUrl: "http://127.0.0.1:1", dirSigner: signer.pub, torHost: "127.0.0.1", torPort: 9250 };
    const statusDead = await buildStatus(cfgDead);
    ok(statusDead.bootnodeReachable === false, "bootnodeReachable false when bootnode is down");
    ok(statusDead.signerOk === false && statusDead.fleetSize === 0, "down bootnode -> signerOk false, empty fleet, no throw");
  } finally {
    await close(statusServer);
    await close(mock);
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: web status selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
