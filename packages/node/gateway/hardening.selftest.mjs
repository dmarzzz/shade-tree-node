// Self-test for gateway endpoint hardening (T-HARD-4): slow-loris deadline on the envelope
// read, idle timeout on the established relay, and concurrent-connection caps (total + per
// nullifier). Runs the REAL connection handler (makeHandler) on a REAL loopback TCP server
// against REAL client sockets — the attacks below are executed on the wire, not modelled.
// The only injections are `verify` (a stub that admits any envelope carrying a nullifier, so
// no Groth16 proof is needed) and the hardening knobs (tiny timeouts so the suite runs fast).
//
//   - slow-loris SILENCE: connect, never send the newline => cut at the deadline with
//     `bad-envelope:envelope timeout`, drop reason `envelope-timeout` counted
//   - slow-loris DRIBBLE: one byte every few ms, no newline => cut at the SAME absolute
//     deadline (activity does not re-arm it), the connection never lives past it
//   - a well-formed envelope arriving just before the deadline still passes (no false cut)
//   - envelope size cap => `envelope-too-large`; close-before-newline => `bad-envelope`
//   - established relay: bytes flow both ways; then no bytes in either direction for the
//     idle timeout => both ends closed, `idle-timeout` counted in tunnel_closes; steady
//     traffic inside the window keeps it open (timer IS re-armed by activity here)
//   - combined relay payload is truncated at one shared byte boundary across BOTH directions;
//     same-slot retries share the spent allowance and `payload-limit` is observable
//   - a black-holed upstream connect (never completes) is bounded by the same idle timeout
//   - SHADE_TREE_MAX_CONNS: the (max+1)th concurrent socket is refused `too-many-connections`
//     BEFORE any envelope read; closing one admits the next (release on close)
//   - SHADE_TREE_MAX_CONNS_PER_NULLIFIER: the (max+1)th tunnel on ONE nullifier is refused
//     `nullifier-conn-limit`; other nullifiers unaffected; released on close; and the
//     spent-set still SEES the over-limit share (admit is called before the cap)
//   - clients that vanish before/while sending release their slot (no leak)
//   - clients that vanish during verification or upstream connect leave no nullifier slot,
//     active-tunnel count, or orphan upstream socket behind
//   - HARDENING defaults are the documented values; makeConnLimiter 0 == unlimited
//
// Run:  node packages/node/gateway/hardening.selftest.mjs

import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import net from "node:net";

// The egress policy is built from env at import time; allow loopback so the fake upstream
// (a local echo server) is an admitted target. Set BEFORE the dynamic import.
process.env.SHADE_TREE_EGRESS_ALLOW = "*:*";
process.env.SHADE_TREE_ALLOW_PRIVATE_TARGETS = "1";
const {
  DEFAULT_TUNNEL_MAX_PAYLOAD_BYTES,
  HARDENING,
  makeConnLimiter,
  makeEgressPolicy,
  makeHandler,
  makePayloadBudget,
  readEnvelope,
} = await import("./gateway.mjs");
const { registry: metrics } = await import("../lib/metrics.mjs");

let failures = 0;
function ok(name) { console.log("  PASS  " + name); }
function bad(name, e) { failures++; console.log("  FAIL  " + name + "  ::  " + (e && e.message || e)); }
async function test(name, fn) { try { await fn(); ok(name); } catch (e) { bad(name, e); } }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---- harness ----------------------------------------------------------------
// Read the value of a labelled series out of the process-wide registry's rendered text.
function metricValue(name, labels) {
  // packages/node/lib/metrics.mjs renders labels sorted by name.
  const lab = Object.entries(labels).sort(([a], [b]) => (a < b ? -1 : 1)).map(([k, v]) => `${k}="${v}"`).join(",");
  const line = lab ? `${name}{${lab}} ` : `${name} `;
  const hit = metrics.render().split("\n").find((l) => l.startsWith(line));
  return hit ? Number(hit.slice(line.length)) : 0;
}

// Local echo server standing in for the :443 target (bytes are relayed opaquely either way).
function startEcho() {
  return new Promise((resolve) => {
    const s = net.createServer((c) => { c.on("data", (d) => c.write(d)); c.on("error", () => {}); });
    s.listen(0, "127.0.0.1", () => resolve(s));
  });
}

// A verify stub: admits any envelope with a `nullifier`, reading nullifier/share from the
// envelope itself (the real verifyEnvelope reads them from the proof's public signals).
const stubVerify = async (env) => env.nullifier
  ? { ok: true, nullifier: String(env.nullifier), externalNullifier: "1", share: env.share || { x: "1", y: "2" } }
  : { ok: false, reason: "no-nullifier" };
// A spent-set that admits everything and records what it saw.
function makeAdmitAll() {
  const seen = [];
  return { seen, admit: async (nullifier, share) => { seen.push({ nullifier: String(nullifier), x: String(share.x) }); return { ok: true, action: "first" }; } };
}

function startGateway(handler) {
  return new Promise((resolve) => {
    const s = net.createServer(handler);
    s.listen(0, "127.0.0.1", () => resolve(s));
  });
}
function closeServer(s) { return new Promise((r) => s.close(() => r())); }

// A client socket with a line reader + close tracking.
function dial(port) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, "127.0.0.1");
    const st = { sock, lines: [], closed: false, closedAt: 0, buf: "", data: [] };
    sock.on("data", (d) => {
      st.data.push(d);
      st.buf += d.toString("utf8");
      let i;
      while ((i = st.buf.indexOf("\n")) !== -1) { st.lines.push(st.buf.slice(0, i)); st.buf = st.buf.slice(i + 1); }
    });
    sock.on("error", () => {});
    sock.on("close", () => { st.closed = true; st.closedAt = Date.now(); });
    sock.once("connect", () => resolve(st));
    sock.once("error", reject);
  });
}
async function waitFor(pred, ms, what) {
  const until = Date.now() + ms;
  while (Date.now() < until) { if (pred()) return; await sleep(5); }
  throw new Error("timed out waiting for " + what);
}
const envelopeFor = (nullifier, port, x = "1") => JSON.stringify({ v: 4, target: `127.0.0.1:${port}`, nullifier, share: { x, y: "2" }, nonce: "n" }) + "\n";
const lastJson = (st) => JSON.parse(st.lines[st.lines.length - 1]);

console.log("gateway endpoint hardening (T-HARD-4):");

// ---- defaults ---------------------------------------------------------------
await test("HARDENING defaults are the documented safe values", () => {
  assert.equal(HARDENING.envelopeTimeoutMs, 30000, "envelope deadline 30s (the pre-hardening hard-coded value)");
  assert.equal(HARDENING.idleTimeoutMs, 300000, "relay idle timeout 5 min");
  assert.equal(HARDENING.maxPayloadBytes, 41_943_040, "combined payload ceiling 40 MiB");
  assert.equal(DEFAULT_TUNNEL_MAX_PAYLOAD_BYTES, 41_943_040);
  assert.equal(HARDENING.maxConns, 1024);
  assert.equal(HARDENING.maxConnsPerNullifier, 8);
});

await test("makeConnLimiter: caps, release, per-nullifier isolation, 0 == unlimited", () => {
  const l = makeConnLimiter({ maxConns: 2, maxPerNullifier: 1 });
  assert.equal(l.acquire(), true); assert.equal(l.acquire(), true); assert.equal(l.acquire(), false, "3rd over maxConns=2");
  l.release(); assert.equal(l.acquire(), true, "release frees a slot");
  assert.equal(l.acquireNullifier("a"), true); assert.equal(l.acquireNullifier("a"), false, "2nd on same nullifier over cap 1");
  assert.equal(l.acquireNullifier("b"), true, "other nullifier unaffected");
  l.releaseNullifier("a"); assert.equal(l.acquireNullifier("a"), true, "released nullifier slot reusable");
  assert.equal(l.trackedNullifiers(), 2);
  l.releaseNullifier("a"); l.releaseNullifier("b"); assert.equal(l.trackedNullifiers(), 0, "map entries vanish at zero (bounded by open sockets)");
  l.release(); l.release(); l.release(); l.release(); assert.equal(l.total(), 0, "release never underflows");
  const u = makeConnLimiter({ maxConns: 0, maxPerNullifier: 0 });
  for (let i = 0; i < 50; i++) { assert.equal(u.acquire(), true); assert.equal(u.acquireNullifier("z"), true); }
});

await test("makePayloadBudget: directions/retries share a slot, epochs and slots are independent, 0 disables", () => {
  let now = 1000;
  const budget = makePayloadBudget({ maxBytes: 10, ttlMs: 100, now: () => now });
  assert.deepEqual(budget.take("slot-a", "epoch-1", 4), { allowed: 4, used: 4, remaining: 6, exhausted: false });
  assert.deepEqual(budget.take("slot-a", "epoch-1", 9), { allowed: 6, used: 10, remaining: 0, exhausted: true }, "opposite direction truncates at the combined boundary");
  assert.deepEqual(budget.take("slot-a", "epoch-1", 1), { allowed: 0, used: 10, remaining: 0, exhausted: true }, "same-slot retry receives no fresh allowance");
  assert.equal(budget.remaining("slot-b", "epoch-1"), 10, "another RLN slot is independent");
  assert.equal(budget.remaining("slot-a", "epoch-2"), 10, "the next epoch is independent");
  assert.equal(budget.size(), 3);
  now += 101;
  budget.sweep();
  assert.equal(budget.size(), 0, "expired epoch budgets are pruned");

  const held = makePayloadBudget({ maxBytes: 10, ttlMs: 100, now: () => now });
  assert.equal(held.acquire("long-slot", "epoch-1"), 10);
  now += 101;
  held.sweep();
  assert.equal(held.size(), 1, "an active long-lived tunnel cannot have its allowance reset by pruning");
  held.release("long-slot", "epoch-1");
  now += 101;
  held.sweep();
  assert.equal(held.size(), 0, "a closed slot is retained only for the configured TTL");

  const unlimited = makePayloadBudget({ maxBytes: 0 });
  assert.deepEqual(unlimited.take("slot", "epoch", 123), { allowed: 123, used: null, remaining: Infinity, exhausted: false });
  assert.equal(unlimited.size(), 0, "disabled accounting allocates no per-slot state");
});

// ---- cheap target gate ordering --------------------------------------------
await test("malformed and policy-disallowed targets are rejected before proof verification", async () => {
  let verifies = 0;
  let lookups = 0;
  let dials = 0;
  const admit = makeAdmitAll();
  const gw = await startGateway(makeHandler(admit, {
    verify: async () => { verifies++; return { ok: false, reason: "should-not-run" }; },
    targetPolicy: makeEgressPolicy({ allow: "allowed.example:443" }),
    lookup: async () => { lookups++; return [{ address: "127.0.0.1", family: 4 }]; },
    connect: () => { dials++; return new net.Socket(); },
    envelopeTimeoutMs: 5000,
    idleTimeoutMs: 0,
    limiter: makeConnLimiter({ maxConns: 0, maxPerNullifier: 0 }),
  }));

  const cases = [
    ["missing-port", "bad-target"],
    ["denied.example:443", "bad-target-policy"],
  ];
  for (const [target, reason] of cases) {
    const c = await dial(gw.address().port);
    c.sock.write(JSON.stringify({ v: 4, target }) + "\n");
    await waitFor(() => c.closed, 2000, `${reason} connection to close`);
    assert.equal(lastJson(c).err, reason);
  }

  assert.equal(verifies, 0, "Groth16 verification seam was never called");
  assert.equal(admit.seen.length, 0, "rejected targets never reached admission");
  assert.equal(lookups, 0, "rejected targets never triggered DNS");
  assert.equal(dials, 0, "rejected targets never dialed upstream");
  await closeServer(gw);
});

await test("fleet replay evidence is committed only after the destination connects", async () => {
  const commits = [];
  const spent = {
    admit: async () => ({ ok: true, action: "first" }),
    commit: (nullifier, epoch) => commits.push([String(nullifier), String(epoch)]),
  };
  const policy = makeEgressPolicy({ allow: "*:*" });

  const dnsFail = await startGateway(makeHandler(spent, {
    verify: stubVerify,
    targetPolicy: policy,
    lookup: async () => { throw new Error("resolver unavailable"); },
    envelopeTimeoutMs: 5000,
    idleTimeoutMs: 0,
    limiter: makeConnLimiter({ maxConns: 0, maxPerNullifier: 0 }),
  }));
  const failed = await dial(dnsFail.address().port);
  failed.sock.write(JSON.stringify({ v: 4, target: "unavailable.example:443", nullifier: "pre-connect", share: { x: "1", y: "2" }, nonce: "n" }) + "\n");
  await waitFor(() => failed.closed, 2000, "DNS refusal to close");
  assert.equal(lastJson(failed).err, "bad-target-dns");
  assert.deepEqual(commits, [], "a DNS failure does not poison cross-node failover");
  await closeServer(dnsFail);

  const echo = await startEcho();
  const connected = await startGateway(makeHandler(spent, {
    verify: stubVerify,
    targetPolicy: policy,
    lookup: async () => [{ address: "127.0.0.1", family: 4 }],
    envelopeTimeoutMs: 5000,
    idleTimeoutMs: 0,
    limiter: makeConnLimiter({ maxConns: 0, maxPerNullifier: 0 }),
  }));
  const passed = await dial(connected.address().port);
  passed.sock.write(envelopeFor("connected", echo.address().port));
  await waitFor(() => passed.lines.length >= 1, 2000, "successful destination connection");
  assert.deepEqual(lastJson(passed), { ok: true });
  assert.deepEqual(commits, [["connected", "1"]], "an established egress publishes exactly once");
  passed.sock.destroy();
  await closeServer(connected);
  await closeServer(echo);
});

await test("a second validated DNS address is tried when the first cannot connect", async () => {
  const echo = await startEcho();
  const spent = makeAdmitAll();
  const attempts = [];
  const gw = await startGateway(makeHandler(spent, {
    verify: stubVerify,
    targetPolicy: makeEgressPolicy({ allow: "*:*" }),
    lookup: async () => [
      { address: "127.0.0.2", family: 4 },
      { address: "127.0.0.1", family: 4 },
    ],
    connect: (port, address, cb) => {
      attempts.push(address);
      return net.connect(port, address, cb);
    },
    envelopeTimeoutMs: 5000,
    idleTimeoutMs: 1000,
    limiter: makeConnLimiter({ maxConns: 0, maxPerNullifier: 0 }),
  }));
  const client = await dial(gw.address().port);
  client.sock.write(JSON.stringify({ v: 4, target: `multi.example:${echo.address().port}`, nullifier: "multi-address", share: { x: "1", y: "2" }, nonce: "n" }) + "\n");
  await waitFor(() => client.lines.length >= 1, 2000, "fallback address success ack");
  assert.deepEqual(lastJson(client), { ok: true });
  assert.deepEqual(attempts, ["127.0.0.2", "127.0.0.1"], "the handler stays on the validated answer set and tries the next address");
  client.sock.destroy();
  await closeServer(gw);
  await closeServer(echo);
});

// ---- envelope line-size boundary -------------------------------------------
await test("readEnvelope accepts a line exactly at the 64 KiB cap", async () => {
  const socket = new EventEmitter();
  const max = 64 * 1024;
  const pending = readEnvelope(socket, { timeoutMs: 1000 });
  socket.emit("data", Buffer.alloc(max, 0x61));
  socket.emit("data", Buffer.from("\nrest"));
  const { line, rest } = await pending;
  assert.equal(Buffer.byteLength(line), max);
  assert.equal(rest.toString("utf8"), "rest");
});

await test("readEnvelope rejects MAX+1 bytes when the extra byte and newline arrive later", async () => {
  const socket = new EventEmitter();
  const max = 64 * 1024;
  const pending = readEnvelope(socket, { timeoutMs: 1000 });
  socket.emit("data", Buffer.alloc(max, 0x61));
  socket.emit("data", Buffer.from("x\n"));
  await assert.rejects(pending, (error) => error?.reason === "envelope-too-large");
});

// ---- slow-loris on the envelope read ----------------------------------------
{
  const ENV_MS = 300;
  const echo = await startEcho();
  const admit = makeAdmitAll();
  const gw = await startGateway(makeHandler(admit, { verify: stubVerify, envelopeTimeoutMs: ENV_MS, idleTimeoutMs: 0, limiter: makeConnLimiter({ maxConns: 0, maxPerNullifier: 0 }) }));
  const port = gw.address().port;

  await test("slow-loris SILENCE: connect + never send => cut at the deadline, reason envelope-timeout", async () => {
    const before = metricValue("shade_tree_gateway_tunnels_total", { result: "drop", reason: "envelope-timeout" });
    const t0 = Date.now();
    const c = await dial(port);
    await waitFor(() => c.closed, ENV_MS * 10, "silent client to be closed");
    const dt = c.closedAt - t0;
    assert.ok(dt >= ENV_MS * 0.8, `closed no earlier than the deadline (${dt}ms >= ~${ENV_MS}ms)`);
    assert.ok(dt < ENV_MS * 8, `closed promptly after the deadline (${dt}ms)`);
    assert.equal(lastJson(c).err, "bad-envelope:envelope timeout", "wire reply text unchanged from the pre-hardening path");
    assert.equal(metricValue("shade_tree_gateway_tunnels_total", { result: "drop", reason: "envelope-timeout" }), before + 1, "drop reason envelope-timeout counted once");
  });

  await test("slow-loris DRIBBLE: a byte every 20ms with no newline => cut at the SAME absolute deadline", async () => {
    const before = metricValue("shade_tree_gateway_tunnels_total", { result: "drop", reason: "envelope-timeout" });
    const t0 = Date.now();
    const c = await dial(port);
    let sent = 0;
    const drip = setInterval(() => { if (!c.closed) { try { c.sock.write("x"); sent++; } catch {} } }, 20);
    await waitFor(() => c.closed, ENV_MS * 10, "dribbling client to be closed");
    clearInterval(drip);
    const dt = c.closedAt - t0;
    assert.ok(sent >= 5, `the client really dribbled bytes (${sent})`);
    assert.ok(dt < ENV_MS * 3, `dribbling did NOT extend the deadline (${dt}ms; would be unbounded with an inactivity timer)`);
    assert.equal(lastJson(c).err, "bad-envelope:envelope timeout");
    assert.equal(metricValue("shade_tree_gateway_tunnels_total", { result: "drop", reason: "envelope-timeout" }), before + 1);
  });

  await test("a slow-but-honest client that completes the envelope inside the deadline is NOT cut", async () => {
    const c = await dial(port);
    const env = envelopeFor("late-1", echo.address().port);
    // Send in two halves with a pause well inside the deadline.
    c.sock.write(env.slice(0, 10));
    await sleep(ENV_MS / 3);
    c.sock.write(env.slice(10));
    await waitFor(() => c.lines.length >= 1, ENV_MS * 5, "success ack");
    assert.deepEqual(lastJson(c), { ok: true }, "admitted and tunneled");
    assert.equal(c.closed, false, "still open (no false positive)");
    c.sock.destroy();
  });

  await test("envelope size cap => envelope-too-large; close-before-newline => bad-envelope (both counted, socket released)", async () => {
    const tooBig = metricValue("shade_tree_gateway_tunnels_total", { result: "drop", reason: "envelope-too-large" });
    const badEnv = metricValue("shade_tree_gateway_tunnels_total", { result: "drop", reason: "bad-envelope" });
    const c1 = await dial(port);
    c1.sock.write(Buffer.alloc(70 * 1024, 0x61)); // 70 KiB of 'a', no newline
    await waitFor(() => c1.closed, ENV_MS * 5, "oversized client to be closed");
    assert.equal(lastJson(c1).err, "bad-envelope:envelope too large");
    assert.equal(metricValue("shade_tree_gateway_tunnels_total", { result: "drop", reason: "envelope-too-large" }), tooBig + 1);
    const c2 = await dial(port);
    c2.sock.write("{\"partial\":");
    c2.sock.end(); // half-close before the newline
    await waitFor(() => c2.closed, ENV_MS * 5, "half-closed client to be closed");
    assert.equal(metricValue("shade_tree_gateway_tunnels_total", { result: "drop", reason: "bad-envelope" }), badEnv + 1);
  });

  await closeServer(gw); await closeServer(echo);
}

// ---- disconnect races across async verification / upstream connect ----------
await test("a client that closes during verification never dials or leaks a per-nullifier slot", async () => {
  let finishVerify;
  let verifyStarted = false;
  const delayedVerify = () => {
    verifyStarted = true;
    return new Promise((resolve) => { finishVerify = resolve; });
  };
  let dials = 0;
  const limiter = makeConnLimiter({ maxConns: 0, maxPerNullifier: 1 });
  const gw = await startGateway(makeHandler(makeAdmitAll(), {
    verify: delayedVerify,
    connect: () => { dials++; return new net.Socket(); },
    envelopeTimeoutMs: 5000,
    idleTimeoutMs: 0,
    limiter,
  }));
  const c = await dial(gw.address().port);
  c.sock.write(envelopeFor("verify-race", 443));
  await waitFor(() => verifyStarted, 2000, "verification to start");
  c.sock.destroy();
  await waitFor(() => c.closed, 2000, "client close during verification");
  finishVerify({ ok: true, nullifier: "verify-race", externalNullifier: "1", share: { x: "1", y: "2" } });
  await waitFor(() => limiter.total() === 0 && limiter.trackedNullifiers() === 0, 2000, "all connection slots to release");
  assert.equal(dials, 0, "no upstream dial starts for an already-closed client");
  await closeServer(gw);
});

await test("a client that closes during DNS resolution never dials or leaks a per-nullifier slot", async () => {
  let finishLookup;
  let lookupStarted = false;
  let dials = 0;
  const order = [];
  const delayedLookup = () => {
    order.push("dns");
    lookupStarted = true;
    return new Promise((resolve) => { finishLookup = resolve; });
  };
  const verifyThenAdmit = {
    admit: async () => { order.push("admit"); return { ok: true, action: "first" }; },
  };
  const limiter = makeConnLimiter({ maxConns: 0, maxPerNullifier: 1 });
  const gw = await startGateway(makeHandler(verifyThenAdmit, {
    verify: async (env) => { order.push("verify"); return stubVerify(env); },
    lookup: delayedLookup,
    connect: () => { dials++; return new net.Socket(); },
    envelopeTimeoutMs: 5000,
    dnsTimeoutMs: 5000,
    idleTimeoutMs: 0,
    limiter,
  }));
  const c = await dial(gw.address().port);
  c.sock.write(JSON.stringify({ v: 4, target: "slow.example:443", nullifier: "dns-race", share: { x: "1", y: "2" }, nonce: "n" }) + "\n");
  await waitFor(() => lookupStarted, 2000, "DNS resolution to start");
  assert.deepEqual(order, ["verify", "admit", "dns"], "DNS stays after proof verification and admission");
  c.sock.destroy();
  await waitFor(() => c.closed, 2000, "client close during DNS resolution");
  finishLookup([{ address: "93.184.216.34", family: 4 }]);
  await waitFor(() => limiter.total() === 0 && limiter.trackedNullifiers() === 0, 2000, "all DNS-race slots to release");
  await sleep(10);
  assert.equal(dials, 0, "no upstream dial starts for a client that closed during DNS resolution");
  await closeServer(gw);
});

await test("a client that closes during upstream connect destroys it and a late callback cannot open a tunnel", async () => {
  let pendingCallback = null;
  let pendingUpstream = null;
  let opened = 0;
  let closed = 0;
  const limiter = makeConnLimiter({ maxConns: 0, maxPerNullifier: 1 });
  const delayedConnect = (_port, _host, callback) => {
    pendingCallback = callback;
    pendingUpstream = new net.Socket();
    return pendingUpstream;
  };
  const gw = await startGateway(makeHandler(makeAdmitAll(), {
    verify: stubVerify,
    connect: delayedConnect,
    envelopeTimeoutMs: 5000,
    idleTimeoutMs: 0,
    limiter,
    onTunnelOpen: () => { opened++; },
    onTunnelClose: () => { closed++; },
  }));
  const c = await dial(gw.address().port);
  c.sock.write(envelopeFor("connect-race", 443));
  await waitFor(() => pendingUpstream !== null, 2000, "upstream connect to be pending");
  c.sock.destroy();
  await waitFor(() => pendingUpstream.destroyed, 2000, "pending upstream to be destroyed");
  await waitFor(() => limiter.total() === 0 && limiter.trackedNullifiers() === 0, 2000, "all connection slots to release");
  pendingCallback();
  await sleep(10);
  assert.equal(opened, 0, "late upstream callback did not increment active tunnels");
  assert.equal(closed, 0, "no close decrement was needed for a tunnel that never opened");
  assert.equal(pendingUpstream.destroyed, true, "late callback kept the orphan upstream closed");
  await closeServer(gw);
});

// ---- idle timeout on the established relay ----------------------------------
{
  const IDLE_MS = 300;
  const echo = await startEcho();
  const admit = makeAdmitAll();
  const gw = await startGateway(makeHandler(admit, { verify: stubVerify, envelopeTimeoutMs: 5000, idleTimeoutMs: IDLE_MS, limiter: makeConnLimiter({ maxConns: 0, maxPerNullifier: 0 }) }));
  const port = gw.address().port;

  await test("established relay: bytes flow both ways, then idle in BOTH directions => closed, idle-timeout counted", async () => {
    const before = metricValue("shade_tree_gateway_tunnel_closes_total", { reason: "idle-timeout" });
    const c = await dial(port);
    c.sock.write(envelopeFor("idle-1", echo.address().port));
    await waitFor(() => c.lines.length >= 1, 3000, "success ack");
    assert.deepEqual(lastJson(c), { ok: true });
    c.sock.write("ping\n");
    await waitFor(() => c.lines.length >= 2, 3000, "echo through the tunnel");
    assert.equal(c.lines[1], "ping", "relay carries bytes client->target->client");
    const t0 = Date.now();
    await waitFor(() => c.closed, IDLE_MS * 10, "idle tunnel to be closed");
    const dt = c.closedAt - t0;
    assert.ok(dt >= IDLE_MS * 0.8, `not closed before the idle window (${dt}ms)`);
    assert.equal(metricValue("shade_tree_gateway_tunnel_closes_total", { reason: "idle-timeout" }), before + 1, "idle-timeout counted once");
  });

  await test("steady traffic inside the idle window keeps the tunnel open (activity re-arms the idle timer)", async () => {
    const c = await dial(port);
    c.sock.write(envelopeFor("busy-1", echo.address().port));
    await waitFor(() => c.lines.length >= 1, 3000, "success ack");
    const t0 = Date.now();
    let n = 0;
    while (Date.now() - t0 < IDLE_MS * 3) { c.sock.write("k\n"); n++; await sleep(IDLE_MS / 4); }
    assert.equal(c.closed, false, `still open after ${IDLE_MS * 3}ms of periodic traffic (${n} writes)`);
    await waitFor(() => c.lines.length >= 1 + n, 3000, "all echoes");
    c.sock.destroy();
  });

  await test("a black-holed upstream connect (never completes, never errors) is bounded by the idle timeout", async () => {
    // A connector whose socket never connects and never errors: the classic SYN black hole.
    const blackHole = () => { const s = new net.Socket(); return s; };
    const admit2 = makeAdmitAll();
    const gw2 = await startGateway(makeHandler(admit2, { verify: stubVerify, connect: blackHole, envelopeTimeoutMs: 5000, idleTimeoutMs: IDLE_MS, limiter: makeConnLimiter({ maxConns: 0, maxPerNullifier: 0 }) }));
    const before = metricValue("shade_tree_gateway_tunnels_total", { result: "drop", reason: "upstream-timeout" });
    const connectCountBefore = metricValue("shade_tree_gateway_upstream_connect_seconds_count", {});
    const connectSumBefore = metricValue("shade_tree_gateway_upstream_connect_seconds_sum", {});
    const c = await dial(gw2.address().port);
    c.sock.write(envelopeFor("bh-1", 1));
    await waitFor(() => c.closed, IDLE_MS * 10, "black-holed tunnel to be cut");
    assert.equal(lastJson(c).err, "upstream:ETIMEDOUT");
    assert.equal(metricValue("shade_tree_gateway_tunnels_total", { result: "drop", reason: "upstream-timeout" }), before + 1);
    assert.equal(metricValue("shade_tree_gateway_upstream_connect_seconds_count", {}), connectCountBefore + 1, "timed-out connect is observed exactly once");
    assert.ok(metricValue("shade_tree_gateway_upstream_connect_seconds_sum", {}) > connectSumBefore, "timed-out connect contributes its wait to the latency sum");
    await closeServer(gw2);
  });

  await test("multiple DNS answers share one absolute upstream-connect deadline", async () => {
    const attempts = [];
    const blackHole = (_port, address) => { attempts.push(address); return new net.Socket(); };
    const gw2 = await startGateway(makeHandler(makeAdmitAll(), {
      verify: stubVerify,
      connect: blackHole,
      targetPolicy: makeEgressPolicy({ allow: "*:*" }),
      lookup: async () => [
        { address: "127.0.0.1", family: 4 },
        { address: "127.0.0.2", family: 4 },
        { address: "127.0.0.3", family: 4 },
      ],
      envelopeTimeoutMs: 5000,
      idleTimeoutMs: IDLE_MS,
      limiter: makeConnLimiter({ maxConns: 0, maxPerNullifier: 0 }),
    }));
    const c = await dial(gw2.address().port);
    const started = Date.now();
    c.sock.write(JSON.stringify({ v: 4, target: "blackhole.example:443", nullifier: "bh-many", share: { x: "1", y: "2" }, nonce: "n" }) + "\n");
    await waitFor(() => c.closed, IDLE_MS * 5, "multi-answer black hole to reach the shared deadline");
    assert.equal(lastJson(c).err, "upstream:ETIMEDOUT");
    assert.ok(Date.now() - started < IDLE_MS * 2.5, "DNS answer count does not multiply the deadline");
    assert.deepEqual(attempts, ["127.0.0.1", "127.0.0.2", "127.0.0.3"], "fallbacks divide one deadline instead of receiving a full timeout each");
    await closeServer(gw2);
  });

  await closeServer(gw); await closeServer(echo);
}

// ---- combined payload ceiling ----------------------------------------------
await test("combined payload ceiling truncates exactly, closes both ends, and survives a same-slot retry", async () => {
  const limit = 10;
  const echo = await startEcho();
  const payloadBudget = makePayloadBudget({ maxBytes: limit });
  let dials = 0;
  const gw = await startGateway(makeHandler(makeAdmitAll(), {
    verify: stubVerify,
    connect: (port, host, cb) => { dials++; return net.connect(port, host, cb); },
    envelopeTimeoutMs: 5000,
    idleTimeoutMs: 0,
    payloadBudget,
    limiter: makeConnLimiter({ maxConns: 0, maxPerNullifier: 0 }),
  }));
  const port = gw.address().port;
  const beforeAgent = metricValue("shade_tree_gateway_agent_to_destination_payload_bytes_total", {});
  const beforeDestination = metricValue("shade_tree_gateway_destination_to_agent_payload_bytes_total", {});
  const beforeCloses = metricValue("shade_tree_gateway_tunnel_closes_total", { reason: "payload-limit" });

  const first = await dial(port);
  const payload = Buffer.from("abcdef");
  first.sock.write(Buffer.concat([Buffer.from(envelopeFor("payload-slot", echo.address().port)), payload]));
  await waitFor(() => first.closed, 3000, "payload-limited tunnel to close");
  assert.deepEqual(
    Buffer.concat(first.data),
    Buffer.concat([Buffer.from('{"ok":true}\n'), Buffer.from("abcd")]),
    "six request bytes plus four response bytes reach the exact ten-byte combined ceiling",
  );
  assert.equal(metricValue("shade_tree_gateway_agent_to_destination_payload_bytes_total", {}), beforeAgent + 6);
  assert.equal(metricValue("shade_tree_gateway_destination_to_agent_payload_bytes_total", {}), beforeDestination + 4);
  assert.equal(metricValue("shade_tree_gateway_tunnel_closes_total", { reason: "payload-limit" }), beforeCloses + 1, "payload-limit close counted once");
  assert.equal(payloadBudget.remaining("payload-slot", "1"), 0);
  assert.equal(dials, 1);

  const retry = await dial(port);
  retry.sock.write(envelopeFor("payload-slot", echo.address().port));
  await waitFor(() => retry.closed, 3000, "spent same-slot retry to close");
  assert.equal(lastJson(retry).err, "payload-limit", "retry receives no replacement allowance");
  assert.equal(dials, 1, "spent retry is refused before another upstream connection");

  const independent = await dial(port);
  independent.sock.write(envelopeFor("payload-slot-2", echo.address().port));
  await waitFor(() => independent.lines.length >= 1, 3000, "independent slot ack");
  assert.deepEqual(lastJson(independent), { ok: true }, "another RLN slot has its own budget");
  independent.sock.destroy();

  await closeServer(gw);
  await closeServer(echo);
});

// ---- concurrent-connection caps ---------------------------------------------
{
  const echo = await startEcho();
  const admit = makeAdmitAll();
  const limiter = makeConnLimiter({ maxConns: 3, maxPerNullifier: 2 });
  const gw = await startGateway(makeHandler(admit, { verify: stubVerify, envelopeTimeoutMs: 5000, idleTimeoutMs: 0, limiter }));
  const port = gw.address().port;

  await test("SHADE_TREE_MAX_CONNS: the 4th concurrent socket is refused too-many-connections BEFORE any envelope; closing one admits the next", async () => {
    const before = metricValue("shade_tree_gateway_tunnels_total", { result: "drop", reason: "too-many-connections" });
    const held = [await dial(port), await dial(port), await dial(port)]; // 3 idle sockets, no envelope sent
    await waitFor(() => limiter.total() === 3, 2000, "3 held connections accounted");
    const c4 = await dial(port);
    await waitFor(() => c4.closed, 3000, "4th connection to be refused");
    assert.equal(lastJson(c4).err, "too-many-connections");
    assert.equal(metricValue("shade_tree_gateway_tunnels_total", { result: "drop", reason: "too-many-connections" }), before + 1);
    assert.equal(admit.seen.length, 0, "the refused socket never reached admit (no envelope read at all)");
    held[0].sock.destroy();
    await waitFor(() => limiter.total() === 2, 2000, "release on close");
    const c5 = await dial(port);
    await sleep(100);
    assert.equal(c5.closed, false, "a slot freed by close is granted to the next connection");
    for (const h of held) h.sock.destroy();
    c5.sock.destroy();
    await waitFor(() => limiter.total() === 0, 2000, "all released");
  });

  await test("SHADE_TREE_MAX_CONNS_PER_NULLIFIER: 3rd tunnel on ONE nullifier refused nullifier-conn-limit; other nullifiers fine; spent-set still saw the share; released on close", async () => {
    const before = metricValue("shade_tree_gateway_tunnels_total", { result: "drop", reason: "nullifier-conn-limit" });
    const seen0 = admit.seen.length;
    const t1 = await dial(port); t1.sock.write(envelopeFor("N", echo.address().port));
    await waitFor(() => t1.lines.length >= 1, 3000, "t1 ack");
    const t2 = await dial(port); t2.sock.write(envelopeFor("N", echo.address().port));
    await waitFor(() => t2.lines.length >= 1, 3000, "t2 ack");
    assert.deepEqual(lastJson(t1), { ok: true }); assert.deepEqual(lastJson(t2), { ok: true });
    assert.equal(limiter.nullifierCount("N"), 2);
    // maxConns is 3 -- the 3rd socket is admitted at accept, then refused at the per-nullifier gate.
    const t3 = await dial(port); t3.sock.write(envelopeFor("N", echo.address().port, "2")); // a DISTINCT share.x too
    await waitFor(() => t3.closed, 3000, "t3 refused");
    assert.equal(lastJson(t3).err, "nullifier-conn-limit");
    assert.equal(metricValue("shade_tree_gateway_tunnels_total", { result: "drop", reason: "nullifier-conn-limit" }), before + 1);
    assert.equal(admit.seen.length - seen0, 3, "admit saw ALL three shares (the cap sits AFTER admit so a slashable 2nd distinct share is never hidden)");
    assert.equal(admit.seen[admit.seen.length - 1].x, "2", "...including the distinct-x share on the refused tunnel");
    // Another nullifier is unaffected (t3's slot was released at its close; give the server-side
    // close event a beat -- the client can observe the close before the server's handler runs).
    await sleep(50);
    await waitFor(() => limiter.total() === 2, 2000, "t3 slot released");
    const o1 = await dial(port); o1.sock.write(envelopeFor("OTHER", echo.address().port));
    await waitFor(() => o1.lines.length >= 1, 3000, "other nullifier ack");
    assert.deepEqual(lastJson(o1), { ok: true }, "a different nullifier is not limited by N's cap");
    o1.sock.destroy();
    // Close one N tunnel -> the per-nullifier slot frees -> a new N tunnel is admitted.
    t1.sock.destroy();
    await waitFor(() => limiter.nullifierCount("N") === 1, 2000, "N slot released on close");
    const t4 = await dial(port); t4.sock.write(envelopeFor("N", echo.address().port));
    await waitFor(() => t4.lines.length >= 1, 3000, "t4 ack");
    assert.deepEqual(lastJson(t4), { ok: true }, "slot freed by close is granted to a new tunnel on the same nullifier");
    t2.sock.destroy(); t4.sock.destroy();
    await waitFor(() => limiter.total() === 0 && limiter.trackedNullifiers() === 0, 2000, "everything released; no per-nullifier residue");
  });

  await test("clients that vanish mid-envelope or before sending never leak a slot", async () => {
    const a = await dial(port); a.sock.write("{\"half"); a.sock.destroy();
    const b = await dial(port); b.sock.destroy();
    const c = await dial(port); c.sock.write(envelopeFor("V", echo.address().port)); await waitFor(() => c.lines.length >= 1, 3000, "ack"); c.sock.destroy();
    await waitFor(() => limiter.total() === 0 && limiter.trackedNullifiers() === 0, 3000, "all slots released");
  });

  await closeServer(gw); await closeServer(echo);
}

console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: gateway hardening selftest (${failures} failure${failures === 1 ? "" : "s"})`);
process.exit(failures === 0 ? 0 : 1);
