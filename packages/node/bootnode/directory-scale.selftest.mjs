// Directory scale/bandwidth features (T-DEV-11): ETag + conditional GET + gzip on GET /directory.
// These are TRANSPORT-ONLY: they never change the directory content or its signature. This test
// spins the real in-process bootnode (real HTTP, real onion identities, real signed directory) and
// proves the transport features work AND that a client still verifies the exact same signed bytes.
//
//   node packages/node/bootnode/directory-scale.selftest.mjs
//
// Exit 0 = all invariants held; nonzero = a check failed (prints which).

import http from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { generateOnionIdentity } from "./keygen.mjs";
import { buildAnnounce } from "./announce.mjs";
import { makeRegistry, makeServer, loadOrMintSigner } from "./server.mjs";
import { MockStakeVerifier } from "../lib/gateway-registry.mjs";
import { verifyDirectory } from "../lib/directory.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

// Raw HTTP GET that does NOT auto-decode Content-Encoding (unlike fetch/undici, which transparently
// gunzips), so we can inspect the true wire bytes and gunzip them ourselves.
function rawGet(base, path, headers = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(base + path);
    const req = http.request({ hostname: u.hostname, port: u.port, path: u.pathname, method: "GET", headers }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on("error", reject);
    req.end();
  });
}

async function main() {
  const work = await mkdtemp(join(tmpdir(), "shade-tree-dir-scale-"));
  let server;
  try {
    const g1 = await generateOnionIdentity(join(work, "g1"), { label: "g1" });
    const g2 = await generateOnionIdentity(join(work, "g2"), { label: "g2" });
    const signer = await loadOrMintSigner(join(work, "signer.key"));
    // Pin the registry clock so `issued` (a per-second timestamp inside the signed directory) is
    // constant across GETs -- otherwise the directory bytes, and thus the ETag, would change every
    // second even with no announce, making the 304 check race a second boundary. With the clock
    // fixed the ETag is stable iff the CONTENT is unchanged, which is exactly what we assert.
    const clock = Math.floor(Date.now() / 1000);
    const registry = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 900, minReannounceSec: 0, now: () => clock });
    server = makeServer(registry, { signerPub: signer.pub });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    const base = `http://127.0.0.1:${server.address().port}`;

    // Announce g1 so the directory is non-empty.
    const a1 = await fetch(base + "/announce", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify(buildAnnounce({ onion: g1.onion, weight: 100, onionSeedHex: g1.seed, ts: clock })),
    }).then((r) => r.json());
    ok(a1.ok === true, "honest announce (g1) accepted");

    const health = await fetch(base + "/health");
    ok(health.headers.get("x-shade-tree-role") === "elder-tree", "health identifies the Elder Tree role");
    ok(health.headers.get("x-shade-tree-view") === null, "health does not claim to be a Canopy payload");

    // (a) GET /directory returns a (strong) ETag, and the plain path still verifies.
    console.log("\nETag + conditional GET:");
    const r1 = await fetch(base + "/directory");
    const etag1 = r1.headers.get("etag");
    const dir1 = await r1.json();
    ok(r1.status === 200, "GET /directory -> 200");
    ok(typeof etag1 === "string" && /^"[0-9a-f]{64}"$/.test(etag1), "response carries a strong sha256 ETag");
    ok(r1.headers.get("x-shade-tree-role") === "elder-tree" && r1.headers.get("x-shade-tree-view") === "canopy",
      "directory carries informational Elder Tree and Canopy headers");
    ok(verifyDirectory(dir1, signer.pub).ok, "plain GET body still verifies against the pinned signer");

    // (b) a second GET with If-None-Match: <that etag> -> 304 and empty body.
    const r2 = await fetch(base + "/directory", { headers: { "if-none-match": etag1 } });
    const body2 = await r2.text();
    ok(r2.status === 304, "conditional GET with matching ETag -> 304 Not Modified");
    ok(body2.length === 0, "304 response has an empty body");
    ok(r2.headers.get("etag") === etag1, "304 still echoes the ETag");
    ok(r2.headers.get("x-shade-tree-view") === "canopy", "304 keeps the Canopy presentation header");

    // (c) after a NEW announce the ETag changes; a conditional GET with the OLD etag -> 200 + new body.
    console.log("\nETag changes on directory change:");
    const a2 = await fetch(base + "/announce", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify(buildAnnounce({ onion: g2.onion, weight: 100, onionSeedHex: g2.seed, ts: clock })),
    }).then((r) => r.json());
    ok(a2.ok === true, "second announce (g2) accepted");
    const r3 = await fetch(base + "/directory", { headers: { "if-none-match": etag1 } });
    const etag3 = r3.headers.get("etag");
    const dir3 = await r3.json();
    ok(r3.status === 200, "stale-ETag conditional GET -> 200 (content changed)");
    ok(etag3 && etag3 !== etag1, "ETag changed after the new announce");
    ok(dir3.gateways.length === 2 && verifyDirectory(dir3, signer.pub).ok, "new body lists both gateways and verifies");

    // (d) Accept-Encoding: gzip -> Content-Encoding: gzip, and the gunzipped body is the SAME
    //     signed directory that verifyDirectory accepts.
    console.log("\ngzip transport:");
    // fetch()/undici transparently gunzips, so use a raw HTTP GET to see the actual wire bytes and
    // gunzip them ourselves -- proving the body was genuinely gzip-encoded, not just header-labeled.
    const r4 = await rawGet(base, "/directory", { "accept-encoding": "gzip" });
    ok(r4.headers["content-encoding"] === "gzip", "Accept-Encoding: gzip -> Content-Encoding: gzip");
    let dir4;
    try { dir4 = JSON.parse(gunzipSync(r4.body).toString("utf8")); } catch (e) { dir4 = null; console.log(`  (gunzip/parse failed: ${e.message})`); }
    ok(dir4 && verifyDirectory(dir4, signer.pub).ok, "gunzipped body is the signed directory verifyDirectory accepts");
    ok(dir4 && JSON.stringify(dir4) === JSON.stringify(dir3), "gzip body == plain body (transport-only, content unchanged)");

    // A client that does NOT ask for gzip still gets the uncompressed path.
    const r5 = await rawGet(base, "/directory", { "accept-encoding": "identity" });
    ok(!r5.headers["content-encoding"], "no gzip when the client does not ask for it");
    ok(verifyDirectory(JSON.parse(r5.body.toString("utf8")), signer.pub).ok, "uncompressed path still verifies");
  } finally {
    if (server) await new Promise((r) => server.close(r));
    await rm(work, { recursive: true, force: true });
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: directory-scale selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
