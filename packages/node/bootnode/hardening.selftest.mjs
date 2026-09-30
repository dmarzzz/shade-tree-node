// Self-test for bootnode endpoint hardening (T-HARD-4): the GLOBAL announce token bucket and
// the HTTP slow-client limits. Runs the REAL registry + REAL http server; the attacks are
// executed with real sockets / real HTTP clients. `verify` is injected ONLY as a spy around
// the real verifyAnnounce so we can assert a throttled announce never reached signature
// verification.
//
//   GLOBAL announce bucket (makeAnnounceBucket / makeRegistry.announce):
//   - a burst of FRESH crypto-valid onions: exactly `burst` reach verify, the rest are refused
//     `global-rate-limited` and the verify spy count does NOT move past the cap
//   - over HTTP the refusal is 429 + Retry-After (all other rejections keep 400)
//   - the bucket refills at `rate`/s (injected clock): after waiting, announces pass again
//   - ordering: the cheap per-onion rate-limit and registry-full rejects come BEFORE the bucket
//     and do not consume tokens (an attacker's cheap rejects never starve a legit heartbeat)
//   - store reload (fromStore) is exempt (local work, never peer input)
//   - LEGIT CADENCE: N gateways heartbeating at the default interval — random phases AND a
//     perfectly lockstepped fleet restart — never hit the bucket at the default sizing
//   - defaults derive from maxEntries + heartbeat: rate = 2*maxEntries/heartbeat, burst =
//     max(100, maxEntries/10); the 100 floor keeps tiny registries usable
//
//   HTTP limits (HTTP_LIMITS / makeServer):
//   - slow-loris HEADERS: connect, send a partial request line, never finish => cut off
//   - slow-loris BODY: full headers + content-length, dribble part of the body, stall => 408 + close
//   - oversized headers => 431 (never buffered unbounded)
//   - idle keep-alive connection is closed after keepAliveTimeout
//   - a fast honest request on the same server is untouched
//   - HTTP_LIMITS defaults are the documented values
//
// Run:  node packages/node/bootnode/hardening.selftest.mjs

import assert from "node:assert/strict";
import net from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateOnionIdentity } from "./keygen.mjs";
import { buildAnnounce, verifyAnnounce } from "./announce.mjs";
import { makeRegistry, makeServer, loadOrMintSigner, makeAnnounceBucket, defaultAnnounceBucketParams, HTTP_LIMITS } from "./server.mjs";
import { MockStakeVerifier } from "../lib/gateway-registry.mjs";

let failures = 0;
function ok(name) { console.log("  PASS  " + name); }
function bad(name, e) { failures++; console.log("  FAIL  " + name + "  ::  " + (e && e.message || e)); }
async function test(name, fn) { try { await fn(); ok(name); } catch (e) { bad(name, e); } }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(pred, ms, what) {
  const until = Date.now() + ms;
  while (Date.now() < until) { if (pred()) return; await sleep(5); }
  throw new Error("timed out waiting for " + what);
}

// A verify spy: counts calls, delegates to the real verifyAnnounce.
function makeVerifySpy() {
  const spy = { calls: 0 };
  spy.verify = (rec, opts) => { spy.calls++; return verifyAnnounce(rec, opts); };
  return spy;
}
// Fast onion minting for floods: real ed25519 identities (the attacker really holds each key).
async function mintMany(work, n, prefix) {
  const out = [];
  for (let i = 0; i < n; i++) out.push(await generateOnionIdentity(join(work, `${prefix}-${i}`), { label: `${prefix}-${i}` }));
  return out;
}

// Raw-socket HTTP client for the slow-loris cases: returns close tracking + everything received.
function rawDial(port) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, "127.0.0.1");
    const st = { sock, closed: false, closedAt: 0, received: "" };
    sock.on("data", (d) => { st.received += d.toString("utf8"); });
    sock.on("error", () => {});
    sock.on("close", () => { st.closed = true; st.closedAt = Date.now(); });
    sock.once("connect", () => resolve(st));
    sock.once("error", reject);
  });
}

console.log("bootnode endpoint hardening (T-HARD-4):");

const work = await mkdtemp(join(tmpdir(), "shade-tree-bn-hard-"));
try {
  const signer = await loadOrMintSigner(join(work, "signer.key"));

  // ---- pure bucket -----------------------------------------------------------
  await test("makeAnnounceBucket: burst then refill at rate (injected clock), fractional refill, Retry-After >= 1", () => {
    let t = 1000;
    const b = makeAnnounceBucket({ rate: 0.5, burst: 3, now: () => t });
    assert.equal(b.take(), true); assert.equal(b.take(), true); assert.equal(b.take(), true);
    assert.equal(b.take(), false, "4th in the same instant refused");
    assert.ok(b.retryAfterSec() >= 1);
    t += 1; assert.equal(b.take(), false, "0.5 token after 1s: still < 1");
    t += 1; assert.equal(b.take(), true, "1 token after 2s");
    t += 100; assert.equal(b.tokens(), 3, "refill caps at burst");
    const off = makeAnnounceBucket({ rate: 0, burst: 0, now: () => t });
    for (let i = 0; i < 20; i++) assert.equal(off.take(), true, "rate=0,burst=0 disables (opt-out)");
  });

  await test("defaults derive from maxEntries + heartbeat: rate=2*maxEntries/heartbeat, burst=max(100, maxEntries/10)", () => {
    const d = defaultAnnounceBucketParams(10000);
    assert.equal(d.heartbeatSec, 300);
    assert.ok(Math.abs(d.rate - 66.666) < 0.01, `rate ${d.rate} ~= 66.67/s at defaults`);
    assert.equal(d.burst, 1000);
    assert.equal(defaultAnnounceBucketParams(50).burst, 100, "floor of 100 for tiny registries");
    // legit sustained load at FULL capacity is exactly half the refill:
    assert.ok(10000 / 300 < d.rate, "maxEntries/heartbeat (33.3/s) < rate (66.7/s): the bucket never drains at capacity");
    // and HTTP_LIMITS defaults:
    assert.deepEqual(HTTP_LIMITS, { headersTimeout: 10000, requestTimeout: 30000, keepAliveTimeout: 5000, maxHeaderSize: 8192, connectionsCheckingInterval: 1000 });
  });

  // ---- fresh-onion burst vs the bucket (before verify) --------------------------
  await test("fresh-onion burst: exactly `burst` reach verify, the rest are refused global-rate-limited BEFORE verify (spy)", async () => {
    let clock = 1_000_000;
    const spy = makeVerifySpy();
    const BURST = 4;
    const reg = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 900, minReannounceSec: 0, maxEntries: 1000,
      announceRate: 1, announceBurst: BURST, verify: spy.verify, now: () => clock });
    const onions = await mintMany(work, 10, "burst");
    let accepted = 0, throttled = 0;
    for (const g of onions) {
      const r = await reg.announce(buildAnnounce({ onion: g.onion, weight: 100, onionSeedHex: g.seed, ts: clock }));
      if (r.ok) accepted++; else if (r.reason === "global-rate-limited") throttled++;
    }
    assert.equal(accepted, BURST, `exactly burst=${BURST} admitted`);
    assert.equal(throttled, 10 - BURST, "every overflow refused global-rate-limited");
    assert.equal(spy.calls, BURST, `verify was called exactly ${BURST} times — never past the cap`);
    assert.equal(reg.size(), BURST);
    // refill: after 3s at rate 1/s, 3 more pass; still no verify beyond what was admitted
    clock += 3;
    let late = 0;
    for (const g of onions.slice(BURST)) { const r = await reg.announce(buildAnnounce({ onion: g.onion, weight: 100, onionSeedHex: g.seed, ts: clock })); if (r.ok) late++; }
    assert.equal(late, 3, "3 tokens refilled after 3s at 1/s");
    assert.equal(spy.calls, BURST + 3, "verify count == admitted count (throttled ones never verified)");
  });

  await test("ordering: per-onion rate-limit and registry-full rejects come BEFORE the bucket and consume no token", async () => {
    let clock = 2_000_000;
    const spy = makeVerifySpy();
    const reg = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 900, minReannounceSec: 5, maxEntries: 1,
      announceRate: 0.001, announceBurst: 2, verify: spy.verify, now: () => clock });
    const [a, b] = await mintMany(work, 2, "order");
    assert.equal((await reg.announce(buildAnnounce({ onion: a.onion, weight: 100, onionSeedHex: a.seed, ts: clock }))).ok, true, "a admitted (1 token used)");
    // Cheap rejects, hammered: none should touch the bucket.
    for (let i = 0; i < 20; i++) {
      assert.equal((await reg.announce(buildAnnounce({ onion: a.onion, weight: 100, onionSeedHex: a.seed, ts: clock }))).reason, "rate-limited");
      assert.equal((await reg.announce(buildAnnounce({ onion: b.onion, weight: 100, onionSeedHex: b.seed, ts: clock }))).reason, "registry-full");
    }
    assert.equal(reg.announceBucket.tokens(), 1, "40 cheap rejects consumed zero tokens");
    assert.equal(spy.calls, 1, "and none of them reached verify");
  });

  await test("store reload (fromStore) is exempt from the bucket: a persisted fleet larger than burst fully restores", async () => {
    let clock = 3_000_000;
    const store = join(work, "store.json");
    const fleet = await mintMany(work, 6, "persist");
    const regA = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 900, minReannounceSec: 0, persistPath: store,
      announceRate: 100, announceBurst: 100, now: () => clock });
    for (const g of fleet) assert.equal((await regA.announce(buildAnnounce({ onion: g.onion, weight: 100, onionSeedHex: g.seed, ts: clock }))).ok, true);
    // Restart with a bucket smaller than the fleet: reload must still restore all 6.
    const spy = makeVerifySpy();
    const regB = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 900, minReannounceSec: 0, persistPath: store,
      announceRate: 0.001, announceBurst: 2, verify: spy.verify, now: () => clock + 10 });
    const { loaded, dropped } = await regB.loadPersisted();
    assert.equal(loaded, 6, "all 6 restored despite burst=2"); assert.equal(dropped, 0);
    assert.equal(spy.calls, 6, "reload still RE-VERIFIES every record (persistence is never a trust bypass)");
    assert.equal(regB.announceBucket.tokens(), 2, "reload consumed no tokens");
  });

  await test("LEGIT CADENCE: N gateways heartbeating every 300s (random phase) at default sizing never hit the bucket", async () => {
    // Deterministic simulation with the REAL bucket at the DEFAULT sizing for this fleet, and a
    // synthetic announce stream (no crypto needed to exercise the bucket arithmetic).
    const N = 200, HB = 300, CYCLES = 6;
    const { rate, burst } = defaultAnnounceBucketParams(N); // registry sized to the fleet: rate = 2N/300, burst = 100
    let t = 0;
    const b = makeAnnounceBucket({ rate, burst, now: () => t });
    const phase = Array.from({ length: N }, (_, i) => (i * 7919) % HB); // spread phases
    let refused = 0;
    for (let sec = 0; sec < HB * CYCLES; sec++) {
      t = sec;
      for (let g = 0; g < N; g++) if (sec % HB === phase[g] && !b.take()) refused++;
    }
    assert.equal(refused, 0, `no legit heartbeat refused over ${CYCLES} cycles of ${N} gateways (rate ${rate.toFixed(2)}/s, burst ${burst})`);
  });

  await test("LEGIT CADENCE: a lockstepped fleet restart of up to `burst` gateways passes in one instant; every beat after that too", async () => {
    const N = 1000, HB = 300; // the default burst at maxEntries=10000
    const { rate, burst } = defaultAnnounceBucketParams(10000);
    let t = 0;
    const b = makeAnnounceBucket({ rate, burst, now: () => t });
    let refused = 0;
    for (let cycle = 0; cycle < 4; cycle++) {
      t = cycle * HB;
      for (let g = 0; g < N; g++) if (!b.take()) refused++; // all N in the same second
    }
    assert.equal(refused, 0, `a ${N}-gateway lockstep fleet is never refused (burst ${burst}, refill ${rate.toFixed(1)}/s fully restores between beats)`);
    // and the attack bound at the same sizing: 10000 fresh onions in one instant => only `burst` verified
    t = 10_000; let passed = 0;
    for (let i = 0; i < 10000; i++) if (b.take()) passed++;
    assert.equal(passed, burst, `a 10000-onion burst gets exactly ${burst} verifies (was: up to maxEntries=10000)`);
  });

  // ---- over HTTP: 429 + Retry-After ------------------------------------------------
  await test("over HTTP: throttled announce is 429 + Retry-After; other rejections keep 400; accepted 200", async () => {
    let clock = 4_000_000;
    const reg = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 900, minReannounceSec: 0, announceRate: 1, announceBurst: 1, now: () => clock });
    const server = makeServer(reg, { signerPub: signer.pub });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    const base = `http://127.0.0.1:${server.address().port}`;
    try {
      const [a, b] = await mintMany(work, 2, "http");
      const post = (body) => fetch(base + "/announce", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      const r1 = await post(buildAnnounce({ onion: a.onion, weight: 100, onionSeedHex: a.seed, ts: clock }));
      assert.equal(r1.status, 200);
      const r2 = await post(buildAnnounce({ onion: b.onion, weight: 100, onionSeedHex: b.seed, ts: clock }));
      assert.equal(r2.status, 429, "second fresh onion in the same second is 429");
      assert.equal((await r2.json()).err, "global-rate-limited");
      assert.ok(Number(r2.headers.get("retry-after")) >= 1, "Retry-After header present");
      // A forged sig is still a plain 400 (unchanged) — once the bucket has a token.
      clock += 2;
      const forged = buildAnnounce({ onion: b.onion, weight: 100, onionSeedHex: a.seed, ts: clock });
      const r3 = await post(forged);
      assert.equal(r3.status, 400); assert.equal((await r3.json()).err, "bad-onion-sig");
    } finally {
      await new Promise((r) => server.close(r));
    }
  });

  // ---- HTTP slow-client limits ---------------------------------------------------------
  {
    const reg = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 900, minReannounceSec: 0 });
    const LIM = { headersTimeout: 400, requestTimeout: 800, keepAliveTimeout: 300, maxHeaderSize: 2048, connectionsCheckingInterval: 50 };
    const server = makeServer(reg, { signerPub: signer.pub, limits: LIM });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    const port = server.address().port;
    const base = `http://127.0.0.1:${port}`;

    await test("slow-loris HEADERS: partial request line + silence => connection cut at headersTimeout (408)", async () => {
      const t0 = Date.now();
      const c = await rawDial(port);
      c.sock.write("GET /health HTTP/1.1\r\nHost: bootnode\r\nX-Slow: "); // never terminates the headers
      await waitFor(() => c.closed, LIM.headersTimeout * 10, "slow-headers client to be cut");
      const dt = c.closedAt - t0;
      assert.ok(dt >= LIM.headersTimeout * 0.8, `not cut before the timeout (${dt}ms)`);
      assert.ok(dt < LIM.headersTimeout * 6, `cut promptly after it (${dt}ms), not at Node's 60s default`);
      assert.match(c.received, /^HTTP\/1\.1 408/, "server answered 408 Request Timeout before closing");
    });

    await test("slow-loris HEADERS (dribble): one header byte every 50ms => still cut, deadline is not re-armed by bytes", async () => {
      const t0 = Date.now();
      const c = await rawDial(port);
      c.sock.write("GET /health HTTP/1.1\r\nHost: b\r\nX-Slow: ");
      const drip = setInterval(() => { if (!c.closed) { try { c.sock.write("a"); } catch {} } }, 50);
      await waitFor(() => c.closed, LIM.headersTimeout * 10, "dribbling-headers client to be cut");
      clearInterval(drip);
      const dt = c.closedAt - t0;
      assert.ok(dt < LIM.headersTimeout * 6, `dribbling did not extend the deadline (${dt}ms)`);
    });

    await test("slow-loris BODY: full headers + content-length, part of the body then stall => 408 + close at requestTimeout", async () => {
      const t0 = Date.now();
      const c = await rawDial(port);
      c.sock.write("POST /announce HTTP/1.1\r\nHost: b\r\nContent-Type: application/json\r\nContent-Length: 500\r\n\r\n{\"onion\":\"");
      await waitFor(() => c.closed, LIM.requestTimeout * 10, "slow-body client to be cut");
      const dt = c.closedAt - t0;
      assert.ok(dt >= LIM.headersTimeout * 0.8, `not cut before any timeout (${dt}ms)`);
      assert.ok(dt < LIM.requestTimeout * 6, `cut around requestTimeout (${dt}ms), not Node's 300s default`);
      assert.match(c.received, /^HTTP\/1\.1 408/, "408 Request Timeout");
    });

    await test("oversized headers => 431, never buffered unbounded", async () => {
      const c = await rawDial(port);
      c.sock.write("GET /health HTTP/1.1\r\nHost: b\r\nX-Big: " + "a".repeat(LIM.maxHeaderSize * 2) + "\r\n\r\n");
      await waitFor(() => c.closed, 5000, "oversized-header client to be answered + closed");
      assert.match(c.received, /^HTTP\/1\.1 431/, "431 Request Header Fields Too Large");
    });

    await test("idle keep-alive connection is closed after keepAliveTimeout", async () => {
      const c = await rawDial(port);
      c.sock.write("GET /health HTTP/1.1\r\nHost: b\r\nConnection: keep-alive\r\n\r\n");
      await waitFor(() => /"ok":true/.test(c.received), 3000, "first response");
      const t0 = Date.now();
      await waitFor(() => c.closed, LIM.keepAliveTimeout * 10, "idle keep-alive to be closed");
      const dt = c.closedAt - t0;
      assert.ok(dt >= LIM.keepAliveTimeout * 0.5 && dt < LIM.keepAliveTimeout * 8, `closed after ~keepAliveTimeout (${dt}ms)`);
    });

    await test("a fast honest request on the same hardened server is untouched", async () => {
      const r = await fetch(base + "/health");
      assert.equal(r.status, 200);
      assert.equal((await r.json()).ok, true);
      assert.equal(server.limits.headersTimeout, LIM.headersTimeout, "limits applied to the server");
    });

    await new Promise((r) => server.close(r));
  }
} finally {
  await rm(work, { recursive: true, force: true });
}

console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: bootnode hardening selftest (${failures} failure${failures === 1 ? "" : "s"})`);
process.exit(failures === 0 ? 0 : 1);
