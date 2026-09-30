// Self-test for the REAL cross-host fleet-tally transport (T-FEAT-20b).
//
// T-FEAT-20 shipped the FleetTally UNIT + an in-process loopback transport
// (packages/node/gateway/fleet-tally.selftest.mjs, still green). This proves the REAL transport:
// makeHttpTallyTransport — a tiny inbound HTTP endpoint + outbound POST to configured peer
// gateways — implementing the SAME { publish(nullifier, epoch), subscribe(cb) } seam over
// actual localhost sockets (real HTTP, real ports, cross-INSTANCE). No mocked network.
//
//   ACCEPTANCE (the T-FEAT-20b accept criteria)
//   - two gateways on SEPARATE tally instances over a real localhost socket: an envelope
//     admitted at gateway A propagates over HTTP and is rejected as replayed-envelope at
//     gateway B (fleet-wide replay defense across the wire)
//   - a KILLED peer degrades to the per-gateway defense with NO outage: after B's endpoint is
//     torn down, A still admits (publish swallows the connection error) and A's own local
//     replay defense still holds
//
//   PRIVACY (the crux — asserted against the ACTUAL bytes on the socket)
//   - ONLY (nullifier, epoch) crosses the transport: a raw capture server (independent of our
//     own parser) inspects the exact POST body A puts on the wire and proves it carries
//     nullifier + epoch and NOTHING else — never share.y, share.x, target, nonce, or member
//
//   ROBUSTNESS / BOUNDING
//   - malformed / oversized inbound bodies are dropped, never crash the endpoint (fail-open)
//   - an inbound announcement with EXTRA fields is accepted but only (nullifier, epoch) are
//     read — the extra keys never reach the tally
//   - a wrong method / wrong path is rejected without delivering
//
//   DEFAULT UNCHANGED
//   - makeConfiguredFleetTally with no SHADE_TREE_FLEET_TALLY_PEERS returns null (byte-identical to
//     today); with peers it returns a live tally over the real transport
//
//   NO LEAK
//   - every server/socket opened here is closed; the process exits on its own (proven by a
//     piped run in the task's verification), and this file force-exits only on failure
//
// Run:  node packages/node/gateway/fleet-tally-transport.selftest.mjs

import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import { makeSpentSet } from "./gateway.mjs";
import {
  makeHttpTallyTransport,
  makeFleetTally,
  makeConfiguredFleetTally,
  _internals,
} from "./fleet-tally.mjs";

let failures = 0;
function ok(name) { console.log("  PASS  " + name); }
function bad(name, e) { failures++; console.log("  FAIL  " + name + "  ::  " + ((e && e.message) || e)); }
async function test(name, fn) { try { await fn(); ok(name); } catch (e) { bad(name, e); } }

const WINDOW = 1000;
const MOCKS = { reconstruct: () => "S", derive: () => "C", replayWindowMs: WINDOW };
const TOKEN = "fleet-tally-test-token-32-bytes-minimum";
const E1 = "101";
const E7 = "107";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Poll until `cond()` is true or we time out — lets one gateway's async HTTP push land in the
// other's tally without a fixed sleep (deterministic, fast, no flake).
async function until(cond, { tries = 200, gapMs = 5 } = {}) {
  for (let i = 0; i < tries; i++) { if (cond()) return true; await sleep(gapMs); }
  return cond();
}

// Track everything we open so a single finally can guarantee no leaks.
const cleanup = [];
function track(x) { cleanup.push(x); return x; }

console.log("gateway real cross-host fleet-tally transport (T-FEAT-20b):");

await test("outbound oversized responses reject promptly and release capacity", async () => {
  const peer = track(http.createServer((_req, res) => {
    res.writeHead(200, { "content-length": 2048 });
    res.end("x".repeat(2048));
  }));
  const port = await new Promise((resolve) => peer.listen(0, "127.0.0.1", () => resolve(peer.address().port)));
  await assert.rejects(
    _internals.httpPostJson("127.0.0.1", port, "/fleet-tally", { nullifier: "1", epoch: E1 }, {
      timeoutMs: 1000,
      maxBytes: 128,
      authToken: TOKEN,
    }),
    /response too large/,
  );
});

await test("inbound slow headers and excess connections are cut before body parsing", async () => {
  const transport = track(makeHttpTallyTransport({
    listen: { host: "127.0.0.1", port: 0 },
    peers: [],
    authToken: TOKEN,
    headersTimeoutMs: 120,
    requestTimeoutMs: 240,
    connectionCheckMs: 10,
    maxConnections: 1,
  }));
  const addr = await transport.ready;
  const openRaw = async () => {
    const socket = net.connect(addr.port, "127.0.0.1");
    await new Promise((resolve, reject) => { socket.once("connect", resolve); socket.once("error", reject); });
    socket.on("error", () => {});
    return socket;
  };
  const slow = await openRaw();
  slow.write("POST /fleet-tally HTTP/1.1\r\nHost: localhost\r\n");
  const excess = await openRaw();
  assert.equal(await until(() => excess.destroyed, { tries: 100, gapMs: 5 }), true, "the connection cap drops the excess socket");
  assert.equal(await until(() => slow.destroyed, { tries: 200, gapMs: 5 }), true, "the incomplete header socket reaches its deadline");
});

await test("outbound pushes stay bounded when a peer never responds", async () => {
  const releases = [];
  const transport = track(makeHttpTallyTransport({
    listen: { host: "127.0.0.1", port: 0 },
    peers: ["127.0.0.1:1"],
    authToken: TOKEN,
    post: () => new Promise((resolve) => releases.push(resolve)),
  }));
  await transport.ready;
  for (let i = 0; i < 100; i++) transport.publish(String(900 + i), E1);
  await sleep(0);
  assert.equal(releases.length, 4, "at most four unresolved pushes are created for one peer");
  assert.equal(transport.pendingPushes(), 4, "the pending count remains bounded");
  for (const release of releases) release();
  assert.equal(await until(() => transport.pendingPushes() === 0), true, "capacity returns after the peer settles");
});

// ---- ACCEPTANCE 1: two instances over a real socket; replay to B rejected -----
await test("two gateways over REAL localhost HTTP: admit at A => replayed-envelope at B once propagated", async () => {
  // B binds first (ephemeral port); A pushes to B; B pushes to A (full mesh of two).
  const transB = track(makeHttpTallyTransport({ listen: { host: "127.0.0.1", port: 0 }, peers: [], authToken: TOKEN }));
  const addrB = await transB.ready;
  const transA = track(makeHttpTallyTransport({ listen: { host: "127.0.0.1", port: 0 }, peers: [`127.0.0.1:${addrB.port}`], authToken: TOKEN }));
  const addrA = await transA.ready;
  assert.equal(transB.addPeer(`127.0.0.1:${addrA.port}`), true); // B also pushes to A (symmetric)

  const tallyA = track(makeFleetTally({ transport: transA }));
  const tallyB = track(makeFleetTally({ transport: transB }));
  const A = makeSpentSet({ ...MOCKS, slash: async () => {}, sharedTally: tallyA });
  const B = makeSpentSet({ ...MOCKS, slash: async () => {}, sharedTally: tallyB });

  // A admits a fresh nullifier, then the simulated destination connect publishes it to B.
  const rA = await A.admit("201", { x: "xA", y: "yA" }, { nonce: "n1", epoch: E1, target: "example.com:443" });
  assert.equal(rA.action, "first");
  assert.equal(rA.ok, true);
  A.commit("201", E1);

  // Wait for the real HTTP push to reach B's tally.
  const arrived = await until(() => tallyB.size() === 1);
  assert.ok(arrived, "B's tally learned the nullifier over the real transport");

  // The SAME captured envelope fanned to B is now a fleet-wide replay.
  const rB = await B.admit("201", { x: "xA", y: "yA" }, { nonce: "n1", epoch: E1 });
  assert.equal(rB.ok, false, "a captured envelope replayed to a peer gateway must be rejected");
  assert.equal(rB.action, "replayed-envelope");
  assert.equal(rB.scope, "fleet", "rejected by the shared fleet tally, not the local cache");

  // A fresh nullifier at B is unaffected.
  const rB2 = await B.admit("202", { x: "xZ", y: "yZ" }, { nonce: "n9", epoch: E1 });
  assert.equal(rB2.action, "first");
});

// ---- PRIVACY: inspect the ACTUAL bytes on the socket -------------------------
await test("privacy: ONLY (nullifier, epoch) crosses the wire — asserted against the raw POST body", async () => {
  // A raw capture server, independent of our own transport parser, records the exact request
  // line + body A puts on the socket. A pushes to it; we assert on what actually crossed.
  const captured = [];
  const capture = track(http.createServer((req, res) => {
    let buf = Buffer.alloc(0);
    req.on("data", (c) => { buf = Buffer.concat([buf, c]); });
    req.on("end", () => { captured.push({ method: req.method, url: req.url, authorization: req.headers.authorization, body: buf.toString("utf8") }); res.statusCode = 200; res.end("{}"); });
  }));
  const capPort = await new Promise((r) => capture.listen(0, "127.0.0.1", () => r(capture.address().port)));

  const transA = track(makeHttpTallyTransport({ listen: { host: "127.0.0.1", port: 0 }, peers: [`127.0.0.1:${capPort}`], authToken: TOKEN }));
  await transA.ready;
  const tallyA = track(makeFleetTally({ transport: transA }));
  const A = makeSpentSet({ ...MOCKS, slash: async () => {}, sharedTally: tallyA });

  const SHARE = { x: "SECRET_X", y: "SECRET_Y" };
  const TARGET = "victim.example:443";
  await A.admit("203", SHARE, { nonce: "SECRET_NONCE", epoch: E7, target: TARGET, member: "SECRET_MEMBER" });
  A.commit("203", E7);

  const arrived = await until(() => captured.length === 1);
  assert.ok(arrived, "exactly one real POST reached the peer");
  const req = captured[0];
  assert.equal(req.method, "POST");
  assert.equal(req.url, "/fleet-tally");
  assert.equal(req.authorization, `Bearer ${TOKEN}`, "the peer push is authenticated out of band");

  const wire = req.body;
  const parsed = JSON.parse(wire);
  assert.deepEqual(Object.keys(parsed).sort(), ["epoch", "nullifier"], "the body carries EXACTLY nullifier + epoch");
  assert.equal(parsed.nullifier, "203");
  assert.equal(parsed.epoch, E7);
  // Nothing sensitive anywhere in the literal bytes on the wire.
  assert.ok(!wire.includes("SECRET_Y"), "share.y must NEVER cross the wire (it reconstructs the identity secret)");
  assert.ok(!wire.includes("SECRET_X"), "share.x does not cross the wire");
  assert.ok(!wire.includes("SECRET_NONCE"), "the request nonce does not cross the wire");
  assert.ok(!wire.includes("SECRET_MEMBER"), "member identity does not cross the wire");
  assert.ok(!wire.includes(TARGET), "the egress target does not cross the wire");
});

// ---- FAIL-OPEN: a killed peer degrades to per-gateway defense, no outage ------
await test("fail-open: a KILLED peer never blocks admission; A's local replay defense still holds", async () => {
  const transB = track(makeHttpTallyTransport({ listen: { host: "127.0.0.1", port: 0 }, peers: [], authToken: TOKEN }));
  const addrB = await transB.ready;
  const clk = { t: 1_000_000 };
  const now = () => clk.t;
  const transA = track(makeHttpTallyTransport({ listen: { host: "127.0.0.1", port: 0 }, peers: [`127.0.0.1:${addrB.port}`], authToken: TOKEN }));
  await transA.ready;
  const tallyA = track(makeFleetTally({ transport: transA, now }));
  const A = makeSpentSet({ ...MOCKS, slash: async () => {}, sharedTally: tallyA, now });

  // Warm path works while B is alive.
  const r0 = await A.admit("204", { x: "x0", y: "y0" }, { nonce: "n0", epoch: E1 });
  assert.equal(r0.action, "first");
  A.commit("204", E1);

  // KILL the peer (simulate a crashed/partitioned gateway): its port now refuses connections.
  transB.close();
  await sleep(20);

  // A must STILL admit — the outbound push hits ECONNREFUSED, which is swallowed (fail-open).
  const r1 = await A.admit("205", { x: "xA", y: "yA" }, { nonce: "n1", epoch: E1 });
  assert.equal(r1.action, "first", "admission proceeds despite the peer being down");
  assert.equal(r1.ok, true);
  A.commit("205", E1);

  // And the per-gateway T-FEAT-12 defense is intact locally: an exact replay past the window
  // is still rejected even though the fleet transport is degraded.
  clk.t += WINDOW + 1;
  const r2 = await A.admit("205", { x: "xA", y: "yA" }, { nonce: "n1", epoch: E1 });
  assert.equal(r2.action, "replayed-envelope", "local replay defense holds when the peer is dead");

  // Give any in-flight push microtask time to reject+swallow before we tear down.
  await sleep(20);
});

// ---- ROBUSTNESS: malformed / oversized / wrong-method inbound never crash -----
await test("robustness: malformed, oversized, and wrong-method/path inbound are dropped, never crash, never deliver", async () => {
  const delivered = [];
  const trans = track(makeHttpTallyTransport({ listen: { host: "127.0.0.1", port: 0 }, peers: [], maxBytes: 256, authToken: TOKEN }));
  const addr = await trans.ready;
  trans.subscribe((n, e) => delivered.push([n, e]));

  const post = (path, method, body, { token = TOKEN } = {}) => new Promise((resolve) => {
    const payload = Buffer.from(body, "utf8");
    const headers = {
      ...(payload.length ? { "content-length": payload.length, "content-type": "application/json" } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    };
    // agent:false => a fresh socket per request, so the oversized-flood cutoff (server-side
    // req.destroy) can't leak a half-broken keep-alive socket into the next request.
    const req = http.request({ host: "127.0.0.1", port: addr.port, path, method, headers, agent: false }, (res) => {
      res.on("data", () => {});
      res.on("end", () => resolve(res.statusCode));
    });
    req.on("error", () => resolve(-1));
    if (payload.length) req.write(payload);
    req.end();
  });

  const sBad = await post("/fleet-tally", "POST", "{not json");
  assert.equal(sBad, 400, "malformed JSON => 400, no crash");

  const big = JSON.stringify({ nullifier: "x".repeat(500), epoch: "E1" });
  const sBig = await post("/fleet-tally", "POST", big);
  assert.equal(sBig, 413, "oversized body => 413, no crash");

  const sGet = await post("/fleet-tally", "GET", "");
  assert.equal(sGet, 404, "wrong method => 404");

  const sPath = await post("/wrong", "POST", JSON.stringify({ nullifier: "206", epoch: E1 }));
  assert.equal(sPath, 404, "wrong path => 404");

  const sNoAuth = await post("/fleet-tally", "POST", JSON.stringify({ nullifier: "206", epoch: E1 }), { token: null });
  assert.equal(sNoAuth, 401, "missing peer token => 401, no delivery");
  const sBadAuth = await post("/fleet-tally", "POST", JSON.stringify({ nullifier: "206", epoch: E1 }), { token: TOKEN + "-wrong" });
  assert.equal(sBadAuth, 401, "wrong peer token => 401, no delivery");
  await assert.rejects(
    _internals.httpPostJson("127.0.0.1", addr.port, "/fleet-tally", { nullifier: "206", epoch: E1 }, {
      timeoutMs: 1000,
      maxBytes: 256,
      authToken: TOKEN + "-wrong",
    }),
    /fleet-tally push HTTP 401/,
    "the outbound sender surfaces a token mismatch instead of treating 401 as success",
  );

  const sBadFields = await post("/fleet-tally", "POST", JSON.stringify({ nullifier: "01", epoch: E1 }));
  assert.equal(sBadFields, 400, "non-canonical field element => 400, no allocation");

  // A well-formed announcement WITH extra fields: accepted, but only (nullifier, epoch) read.
  const sOk = await post("/fleet-tally", "POST", JSON.stringify({ nullifier: "207", epoch: E1, share: { y: "LEAK" }, target: "t" }));
  assert.equal(sOk, 200);
  await until(() => delivered.length === 1);
  assert.deepEqual(delivered, [["207", E1]], "only nullifier+epoch reached the subscriber; extra keys ignored");

  // The endpoint is still alive after all that abuse.
  const sOk2 = await post("/fleet-tally", "POST", JSON.stringify({ nullifier: "208", epoch: E1 }));
  assert.equal(sOk2, 200, "endpoint survived malformed/oversized/wrong traffic");
});

// ---- DEFAULT UNCHANGED: no peers => null; peers => live real transport --------
await test("default OFF: makeConfiguredFleetTally with no peers returns null (byte-identical to today)", async () => {
  assert.equal(makeConfiguredFleetTally({ env: {} }), null, "no env => null");
  assert.equal(makeConfiguredFleetTally({ env: { SHADE_TREE_FLEET_TALLY: "1" } }), null, "legacy flag, no peers => still null (fail-open)");
  assert.equal(makeConfiguredFleetTally({ env: { SHADE_TREE_FLEET_TALLY_PEERS: "" } }), null, "empty peers => null");
  assert.equal(makeConfiguredFleetTally({ env: { SHADE_TREE_FLEET_TALLY_PEERS: "127.0.0.1:1" } }), null, "peers without an auth token => disabled fail-open");
  assert.throws(
    () => makeHttpTallyTransport({ listen: { host: "127.0.0.1", port: 0 }, peers: [] }),
    /authToken/,
    "the low-level HTTP transport cannot be constructed unauthenticated",
  );
  assert.throws(
    () => makeHttpTallyTransport({ listen: { host: "127.0.0.1", port: 0 }, peers: ["https://peer.example:443"], authToken: TOKEN }),
    /invalid peer/,
    "a URL scheme is rejected rather than silently downgraded while carrying the bearer token",
  );
  assert.equal(
    makeConfiguredFleetTally({ env: { SHADE_TREE_FLEET_TALLY_PEERS: "https://peer.example:443", SHADE_TREE_FLEET_TALLY_TOKEN: TOKEN } }),
    null,
    "unsafe scheme-prefixed peer configuration fails closed to local-only tallying",
  );
});

await test("configured: SHADE_TREE_FLEET_TALLY_PEERS yields a live tally over the real HTTP transport", async () => {
  const t = makeConfiguredFleetTally({ env: {
    SHADE_TREE_FLEET_TALLY_PEERS: "127.0.0.1:1",
    SHADE_TREE_FLEET_TALLY_LISTEN: "127.0.0.1:0",
    SHADE_TREE_FLEET_TALLY_TOKEN: TOKEN,
  } });
  assert.ok(t && typeof t.has === "function" && typeof t.record === "function", "peers configured => a live FleetTally");
  // record() publishes to an unreachable peer (:1) but must never throw (fail-open).
  t.record("209", E1);
  assert.equal(t.has("209", E1), true, "the local side records regardless of peer reachability");
  t.close(); // tears down the bound transport listener too (no leak)
  await sleep(20);
});

// ---- teardown: prove no leaks -------------------------------------------------
for (const x of cleanup) { try { x.close?.(); } catch { /* best-effort */ } }
await sleep(30); // let any in-flight push microtask settle/reject before we report

console.log("");
if (failures) {
  console.log(`SELFTEST FAILED: ${failures} failing case(s)`);
  process.exit(1);
}
console.log("SELFTEST PASSED: all cases green");
