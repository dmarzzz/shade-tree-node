// Session tickets on the node (ADR 0011): the book state machine as a unit, and the REAL
// connection handler on loopback sockets with an injected session verifier (the proof itself is
// covered by test/session-e2e.selftest.mjs with real Groth16 proofs). Invariants from the design:
// one proof -> at most one book; one ticket -> at most one upstream establishment; a duplicate
// spend can never obtain a second socket; a definite pre-connect failure refunds, an ambiguous one
// burns; streams share the book's concurrency, byte ceiling, lifetime and idle limits; v4 is
// byte-identical on the same handler; with the flag off every session envelope is refused.
//
//   node gateway/session.selftest.mjs

import assert from "node:assert/strict";
import net from "node:net";
import { randomBytes } from "node:crypto";

process.env.SHADE_TREE_EGRESS_ALLOW = "*:*";
process.env.SHADE_TREE_ALLOW_PRIVATE_TARGETS = "1";
const { makeHandler, makePayloadBudget, makeConnLimiter } = await import("./gateway.mjs");
const { makeSessionBooks, makeTokenBucket } = await import("./session.mjs");
const st = await import("../lib/session-tickets.mjs");

let failures = 0;
function ok(name) { console.log("  PASS  " + name); }
function bad(name, e) { failures++; console.log("  FAIL  " + name + "  ::  " + (e && e.stack || e)); }
async function test(name, fn) { try { await fn(); ok(name); } catch (e) { bad(name, e); } }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function waitFor(pred, ms, what) {
  const until = Date.now() + ms;
  while (Date.now() < until) { if (pred()) return; await sleep(5); }
  throw new Error("timed out waiting for " + what);
}

const ONION = "ucnkl5d2m5myal7zkx4nyljkcss4thjdx2l7qzasp74tqncvutypp3ad.onion";
const nonce = () => randomBytes(16).toString("hex");
function newBook() {
  const secrets = Array.from({ length: 6 }, () => randomBytes(32));
  return { ...st.buildTicketBook(secrets), nonce: nonce() };
}
const initEnvelope = (book, nullifier, { gateway = ONION, digest = book.ticketBookDigest } = {}) => JSON.stringify({
  v: 4,
  session: st.sessionInitFields({ classId: "research-v1", gateway, nonce: book.nonce, commitments: book.commitments, ticketBookDigest: digest }),
  nullifier, share: { x: "1", y: "2" },
}) + "\n";
const ticketEnvelope = (book, i, target, requestNonce = nonce(), secret = book.secrets[i]) => JSON.stringify({
  v: 4, ticket: st.ticketFields({ ticketBookDigest: book.ticketBookDigest, index: i, secret, requestNonce }), target,
}) + "\n";

// A session verifier stub: admits any init that carries a `nullifier`, reading the session
// fields the real verifySessionEnvelope would take from the bound signal.
const stubVerifySession = async (env, _roots, _now, { gatewayOnion }) => {
  const init = st.validateSessionInit(env.session);
  if (!init.ok) return { ok: false, reason: init.reason };
  if (env.session.gateway !== gatewayOnion) return { ok: false, reason: "session-wrong-gateway" };
  if (!env.nullifier) return { ok: false, reason: "no-nullifier" };
  return { ok: true, nullifier: String(env.nullifier), externalNullifier: "1", share: env.share || { x: "1", y: "2" }, session: { classId: init.classId, policy: init.policy, digest: env.session.ticketBookDigest, commitments: env.session.ticketCommitments } };
};
const stubVerify = async (env) => env.nullifier
  ? { ok: true, nullifier: String(env.nullifier), externalNullifier: "1", share: env.share || { x: "1", y: "2" } }
  : { ok: false, reason: "no-nullifier" };
function makeAdmitAll() {
  const seen = []; const committed = [];
  return { seen, committed, admit: async (n, share) => { seen.push({ nullifier: String(n), x: String(share.x) }); return { ok: true, action: "first" }; }, commit: (n, e) => committed.push(`${n}@${e}`) };
}
function startEcho() {
  return new Promise((resolve) => {
    const s = net.createServer((c) => { c.on("data", (d) => c.write(d)); c.on("error", () => {}); });
    s.listen(0, "127.0.0.1", () => resolve(s));
  });
}
function startGateway(handler) {
  return new Promise((resolve) => { const s = net.createServer(handler); s.listen(0, "127.0.0.1", () => resolve(s)); });
}
const closeServer = (s) => new Promise((r) => s.close(() => r()));
function dial(port) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, "127.0.0.1");
    const s = { sock, lines: [], closed: false, buf: "", raw: [] };
    sock.on("data", (d) => {
      s.raw.push(d);
      s.buf += d.toString("utf8");
      let i;
      while ((i = s.buf.indexOf("\n")) !== -1) { s.lines.push(s.buf.slice(0, i)); s.buf = s.buf.slice(i + 1); }
    });
    sock.on("error", () => {});
    sock.on("close", () => { s.closed = true; });
    sock.once("connect", () => resolve(s));
    sock.once("error", reject);
  });
}
async function exchange(port, wire) {
  const c = await dial(port);
  c.sock.write(wire);
  await waitFor(() => c.lines.length >= 1, 3000, "an ack line");
  return { c, ack: JSON.parse(c.lines[0]) };
}
const lookup = async () => [{ address: "127.0.0.1", family: 4 }];

// ---- unit: token bucket -------------------------------------------------------------------
console.log("token bucket:");
await test("a shared bucket admits the burst at once and then delays proportionally to the rate", () => {
  let t = 0;
  const b = makeTokenBucket({ bytesPerSecond: 1000, burstBytes: 500, now: () => t });
  assert.equal(b.take(500), 0);
  assert.equal(b.take(250), 250);        // 250 bytes in debt at 1000 B/s = 250 ms
  t += 250;
  assert.equal(b.take(0), 0);
  assert.equal(b.take(1000), 1000);
  t += 5000;
  assert.equal(b.take(500), 0);          // refilled, capped at the burst
});

// ---- unit: book state machine -------------------------------------------------------------
console.log("\nsession books (unit):");
{
  let now = 1_000_000;
  const timers = [];
  const books = makeSessionBooks({ now: () => now, setTimer: (fn, ms) => { const t = { fn, at: now + ms }; timers.push(t); return t; }, clearTimer: (t) => { const i = timers.indexOf(t); if (i >= 0) timers.splice(i, 1); } });
  const fire = () => { for (const t of [...timers]) if (t.at <= now) { timers.splice(timers.indexOf(t), 1); t.fn(); } };
  const b = newBook();
  await test("one proof slot opens at most one book; an exact replay is idempotent, a different digest for the same slot conflicts", () => {
    const first = books.open({ digest: b.ticketBookDigest, commitments: b.commitments, classId: "research-v1", nullifier: "n1", epoch: "e1" });
    assert.equal(first.ok, true); assert.equal(first.replay, false);
    const again = books.open({ digest: b.ticketBookDigest, commitments: b.commitments, classId: "research-v1", nullifier: "n1", epoch: "e1" });
    assert.equal(again.ok, true); assert.equal(again.replay, true);
    const other = newBook();
    assert.equal(books.open({ digest: other.ticketBookDigest, commitments: other.commitments, classId: "research-v1", nullifier: "n1", epoch: "e1" }).reason, "session-conflict");
    assert.equal(books.open({ digest: b.ticketBookDigest, commitments: b.commitments, classId: "research-v1", nullifier: "n2", epoch: "e1" }).reason, "session-conflict");
    assert.equal(books.open({ digest: other.ticketBookDigest, commitments: other.commitments, classId: "bulk-v9", nullifier: "n3", epoch: "e1" }).reason, "session-class");
    assert.equal(books.size(), 1);
  });
  await test("reserve is synchronous and exclusive: exact duplicate = inflight, other target = conflict, after spend = spent; a refund only by the reserving stream", () => {
    const rn = nonce();
    const r1 = books.reserve({ digest: b.ticketBookDigest, index: 0, secret: b.secrets[0], target: "a:443", requestNonce: rn, streamId: 1 });
    assert.equal(r1.ok, true);
    assert.equal(books.reserve({ digest: b.ticketBookDigest, index: 0, secret: b.secrets[0], target: "a:443", requestNonce: rn, streamId: 2 }).reason, "ticket-inflight");
    assert.equal(books.reserve({ digest: b.ticketBookDigest, index: 0, secret: b.secrets[0], target: "b:443", requestNonce: rn, streamId: 2 }).reason, "ticket-conflict");
    assert.equal(books.reserve({ digest: b.ticketBookDigest, index: 1, secret: b.secrets[0], target: "a:443", requestNonce: rn, streamId: 2 }).reason, "ticket-mismatch");
    assert.equal(books.reserve({ digest: b.ticketBookDigest, index: 6, secret: b.secrets[0], target: "a:443", requestNonce: rn, streamId: 2 }).reason, "ticket-index");
    assert.equal(books.reserve({ digest: "0".repeat(64), index: 0, secret: b.secrets[0], target: "a:443", requestNonce: rn, streamId: 2 }).reason, "session-unknown");
    assert.equal(books.release(r1.book, r1.ticket, 99), false, "another stream cannot refund");
    assert.equal(books.release(r1.book, r1.ticket, 1), true);
    assert.equal(r1.ticket.state, "unused");
    const r2 = books.reserve({ digest: b.ticketBookDigest, index: 0, secret: b.secrets[0], target: "c:443", requestNonce: nonce(), streamId: 3 });
    assert.equal(r2.ok, true);
    assert.equal(books.spend(r2.book, r2.ticket, 3, null), true);
    assert.equal(books.release(r2.book, r2.ticket, 3), false, "no transition from spent back to unused");
    assert.equal(books.reserve({ digest: b.ticketBookDigest, index: 0, secret: b.secrets[0], target: "c:443", requestNonce: nonce(), streamId: 4 }).reason, "ticket-spent");
    books.streamClosed(r2.book, r2.ticket, 3, null);
    assert.equal(r2.book.openStreams, 0);
  });
  await test("a stream that vanishes while its connect is pending burns the ticket (ambiguous outcome), never refunds it", () => {
    const r = books.reserve({ digest: b.ticketBookDigest, index: 1, secret: b.secrets[1], target: "a:443", requestNonce: nonce(), streamId: 5 });
    assert.equal(r.ok, true);
    books.streamClosed(r.book, r.ticket, 5, null);
    assert.equal(r.ticket.state, "spent");
    assert.equal(r.book.pendingConnects, 0);
  });
  await test("the concurrent-stream cap is shared by the book: four streams, the fifth refused with tickets to spare", () => {
    const cb = newBook();
    const o = books.open({ digest: cb.ticketBookDigest, commitments: cb.commitments, classId: "research-v1", nullifier: "n5", epoch: "e1" });
    assert.equal(o.ok, true);
    const held = [0, 1, 2, 3].map((i) => books.reserve({ digest: cb.ticketBookDigest, index: i, secret: cb.secrets[i], target: "a:443", requestNonce: nonce(), streamId: 20 + i }));
    assert.ok(held.every((r) => r.ok));
    assert.equal(o.book.openStreams, 4);
    assert.equal(books.reserve({ digest: cb.ticketBookDigest, index: 4, secret: cb.secrets[4], target: "a:443", requestNonce: nonce(), streamId: 30 }).reason, "session-streams");
    // An established stream still counts; a closed one frees its slot.
    books.spend(held[0].book, held[0].ticket, 20, null);
    assert.equal(books.reserve({ digest: cb.ticketBookDigest, index: 4, secret: cb.secrets[4], target: "a:443", requestNonce: nonce(), streamId: 30 }).reason, "session-streams");
    books.streamClosed(held[0].book, held[0].ticket, 20, null);
    assert.equal(books.reserve({ digest: cb.ticketBookDigest, index: 4, secret: cb.secrets[4], target: "a:443", requestNonce: nonce(), streamId: 30 }).ok, true);
    books.close(o.book, "test");
  });
  await test("the hard lifetime closes the book and destroys its sockets; then every spend is session-unknown", () => {
    const fake = { destroyed: false, destroy() { this.destroyed = true; } };
    const r = books.reserve({ digest: b.ticketBookDigest, index: 3, secret: b.secrets[3], target: "a:443", requestNonce: nonce(), streamId: 40 });
    books.spend(r.book, r.ticket, 40, fake);
    now += 90_000; fire();
    assert.equal(fake.destroyed, true);
    assert.equal(r.book.closeReason, "session-expired");
    assert.equal(books.get(b.ticketBookDigest), null);
    assert.equal(books.reserve({ digest: b.ticketBookDigest, index: 4, secret: b.secrets[4], target: "a:443", requestNonce: nonce(), streamId: 41 }).reason, "session-unknown");
    assert.equal(books.size(), 0);
  });
  await test("the idle clock is reset only by payload; without it the book closes session-idle before its lifetime", () => {
    const b2 = newBook();
    const o = books.open({ digest: b2.ticketBookDigest, commitments: b2.commitments, classId: "research-v1", nullifier: "n9", epoch: "e1" });
    now += 10_000; books.touch(o.book); fire();
    now += 10_000; books.touch(o.book); fire();
    assert.equal(o.book.closed, false, "payload every 10 s keeps a 15 s idle clock alive");
    now += 15_000; fire();
    assert.equal(o.book.closeReason, "session-idle");
  });
}

// ---- handler on loopback ------------------------------------------------------------------
console.log("\nhandler (loopback, injected verifier):");
const echo = await startEcho();
const echoPort = echo.address().port;
const echoTarget = `127.0.0.1:${echoPort}`;

await test("flag off (default handler): initialization and spends are refused session-unsupported; v4 unchanged", async () => {
  const spent = makeAdmitAll();
  const gw = await startGateway(makeHandler(spent, { verify: stubVerify, lookup }));
  try {
    const b = newBook();
    assert.equal((await exchange(gw.address().port, initEnvelope(b, "n1"))).ack.err, "session-unsupported");
    assert.equal((await exchange(gw.address().port, ticketEnvelope(b, 0, echoTarget))).ack.err, "session-unsupported");
    const { c, ack } = await exchange(gw.address().port, JSON.stringify({ v: 4, target: echoTarget, nullifier: "v4", share: { x: "1", y: "2" }, nonce: "n" }) + "\n");
    assert.deepEqual(ack, { ok: true });
    assert.equal(c.lines[0], '{"ok":true}');
    c.sock.destroy();
  } finally { await closeServer(gw); }
});

{
  const spent = makeAdmitAll();
  const sessions = makeSessionBooks();
  const gw = await startGateway(makeHandler(spent, { verify: stubVerify, verifySession: stubVerifySession, sessions, sessionOnion: ONION, lookup, idleTimeoutMs: 2000 }));
  const port = gw.address().port;
  const b = newBook();

  await test("initialization: the ack echoes the digest and the research-v1 policy, the init socket closes, the slot is published once", async () => {
    const { c, ack } = await exchange(port, initEnvelope(b, "n1"));
    assert.equal(ack.ok, true);
    assert.equal(ack.session.ticketBookDigest, b.ticketBookDigest);
    assert.deepEqual(ack.session.policy, st.policyEcho("research-v1"));
    await waitFor(() => c.closed, 2000, "init socket close");
    assert.deepEqual(spent.committed, ["n1@1"]);
    const replay = await exchange(port, initEnvelope(b, "n1"));
    assert.equal(replay.ack.ok, true, "exact replay of a live book is idempotent");
    assert.deepEqual(spent.committed, ["n1@1"], "a replay publishes nothing new");
    const other = newBook();
    assert.equal((await exchange(port, initEnvelope(other, "n1"))).ack.err, "session-conflict");
  });

  await test("initialization bound to another node's onion is refused before any proof work", async () => {
    const other = newBook();
    const wrong = "a".repeat(56) + ".onion";
    assert.equal((await exchange(port, initEnvelope(other, "n2", { gateway: wrong }))).ack.err, "session-wrong-gateway");
    assert.equal((await exchange(port, initEnvelope(other, "n2", { digest: "0".repeat(64) }))).ack.err, "session-digest");
  });

  await test("a ticket opens a relayed tunnel with {ok:true}; the same ticket is then spent for any nonce or target", async () => {
    const rn = nonce();
    const { c, ack } = await exchange(port, ticketEnvelope(b, 0, echoTarget, rn));
    assert.deepEqual(ack, { ok: true });
    c.sock.write("hello through a ticket");
    await waitFor(() => Buffer.concat(c.raw).toString("utf8").includes("hello through a ticket"), 3000, "echo");
    assert.equal((await exchange(port, ticketEnvelope(b, 0, echoTarget, rn))).ack.err, "ticket-spent");
    assert.equal((await exchange(port, ticketEnvelope(b, 0, echoTarget))).ack.err, "ticket-spent");
    c.sock.destroy();
  });

  await test("wrong secret, unknown book, out-of-range index and a malformed ticket are refused with bounded reasons", async () => {
    assert.equal((await exchange(port, ticketEnvelope(b, 1, echoTarget, nonce(), randomBytes(32)))).ack.err, "ticket-mismatch");
    const stranger = newBook();
    assert.equal((await exchange(port, ticketEnvelope(stranger, 0, echoTarget))).ack.err, "session-unknown");
    assert.equal((await exchange(port, JSON.stringify({ v: 4, ticket: { ...JSON.parse(ticketEnvelope(b, 1, echoTarget)).ticket, i: 6 }, target: echoTarget }) + "\n")).ack.err, "ticket-index");
    assert.equal((await exchange(port, JSON.stringify({ v: 4, ticket: "x", target: echoTarget }) + "\n")).ack.err, "ticket-malformed");
    assert.equal((await exchange(port, JSON.stringify({ v: 4, ticket: JSON.parse(ticketEnvelope(b, 1, echoTarget)).ticket, target: "not a target" }) + "\n")).ack.err.startsWith("bad-target"), true);
  });

  await test("a definite pre-connect failure refunds the ticket: the retry after a refused port succeeds", async () => {
    const dead = await startEcho(); const deadPort = dead.address().port; await closeServer(dead);
    const rn = nonce();
    const { ack } = await exchange(port, ticketEnvelope(b, 1, `127.0.0.1:${deadPort}`, rn));
    assert.equal(ack.err, "upstream:ECONNREFUSED");
    const again = await exchange(port, ticketEnvelope(b, 1, echoTarget, rn));
    assert.deepEqual(again.ack, { ok: true });
    again.c.sock.destroy();
  });

  await test("two simultaneous spends of one ticket obtain at most one upstream socket", async () => {
    let dials = 0;
    const slowSpent = makeAdmitAll();
    const slowSessions = makeSessionBooks();
    const slow = await startGateway(makeHandler(slowSpent, {
      verify: stubVerify, verifySession: stubVerifySession, sessions: slowSessions, sessionOnion: ONION,
      lookup: async () => { await sleep(60); return [{ address: "127.0.0.1", family: 4 }]; },
      connect: (p, a, cb) => { dials++; return net.connect(p, a, cb); },
    }));
    try {
      const sb = newBook();
      const sp = slow.address().port;
      await exchange(sp, initEnvelope(sb, "s1"));
      const rn = nonce();
      const [x, y] = await Promise.all([exchange(sp, ticketEnvelope(sb, 0, echoTarget, rn)), exchange(sp, ticketEnvelope(sb, 0, echoTarget, rn))]);
      const oks = [x.ack, y.ack].filter((a) => a.ok === true);
      const refused = [x.ack, y.ack].filter((a) => a.ok !== true);
      assert.equal(oks.length, 1);
      assert.equal(refused[0].err, "ticket-inflight");
      assert.equal(dials, 1, "exactly one upstream dial");
      x.c.sock.destroy(); y.c.sock.destroy();
    } finally { await closeServer(slow); }
  });

  await test("four concurrent streams share the book; the fifth is refused session-streams until one closes", async () => {
    const cb = newBook();
    await exchange(port, initEnvelope(cb, "c1"));
    const open = [];
    for (const i of [0, 1, 2, 3]) {
      const r = await exchange(port, ticketEnvelope(cb, i, echoTarget));
      assert.deepEqual(r.ack, { ok: true });
      open.push(r.c);
    }
    assert.equal((await exchange(port, ticketEnvelope(cb, 4, echoTarget))).ack.err, "session-streams");
    open[0].sock.destroy();
    await sleep(30);
    const fifth = await exchange(port, ticketEnvelope(cb, 4, echoTarget));
    assert.deepEqual(fifth.ack, { ok: true });
    for (const c of [...open.slice(1), fifth.c]) c.sock.destroy();
  });

  await test("v4 envelopes on the same handler are unchanged", async () => {
    const { c, ack } = await exchange(port, JSON.stringify({ v: 4, target: echoTarget, nullifier: "v4", share: { x: "1", y: "2" }, nonce: "n" }) + "\n");
    assert.deepEqual(ack, { ok: true });
    c.sock.destroy();
  });

  await closeServer(gw);
}

await test("the byte ceiling is the proof's slot budget, shared by every stream of the book, cut at the exact boundary", async () => {
  const spent = makeAdmitAll();
  const sessions = makeSessionBooks();
  const budget = makePayloadBudget({ maxBytes: 40 });
  const gw = await startGateway(makeHandler(spent, { verify: stubVerify, verifySession: stubVerifySession, sessions, sessionOnion: ONION, lookup, payloadBudget: budget, limiter: makeConnLimiter({ maxConns: 0, maxPerNullifier: 0 }) }));
  try {
    const port = gw.address().port;
    const bb = newBook();
    await exchange(port, initEnvelope(bb, "b1"));
    const a = await exchange(port, ticketEnvelope(bb, 0, echoTarget));
    const c = await exchange(port, ticketEnvelope(bb, 1, echoTarget));
    const payload = (x) => Buffer.concat(x.c.raw).toString("utf8").slice('{"ok":true}\n'.length);
    a.c.sock.write("x".repeat(15));                    // 15 up + 15 echoed back = 30 of 40
    await waitFor(() => payload(a).length >= 15, 3000, "echo A");
    c.c.sock.write("y".repeat(30));                    // only 10 remain: 10 up, nothing back
    await waitFor(() => a.c.closed && c.c.closed, 3000, "both streams closed at the ceiling");
    assert.equal(payload(a), "x".repeat(15));
    assert.equal(payload(c), "");
    assert.equal(budget.remaining("b1", "1"), 0);
  } finally { await closeServer(gw); }
});

await test("the session lifetime destroys live tunnels on the handler too", async () => {
  let now = Date.now();
  const timers = [];
  const sessions = makeSessionBooks({ now: () => now, setTimer: (fn, ms) => { const t = { fn, at: now + ms }; timers.push(t); return t; }, clearTimer: (t) => { const i = timers.indexOf(t); if (i >= 0) timers.splice(i, 1); } });
  const gw = await startGateway(makeHandler(makeAdmitAll(), { verify: stubVerify, verifySession: stubVerifySession, sessions, sessionOnion: ONION, lookup }));
  try {
    const port = gw.address().port;
    const lb = newBook();
    await exchange(port, initEnvelope(lb, "l1"));
    const t = await exchange(port, ticketEnvelope(lb, 0, echoTarget));
    assert.deepEqual(t.ack, { ok: true });
    now += 90_000;
    for (const x of [...timers]) if (x.at <= now) { timers.splice(timers.indexOf(x), 1); x.fn(); }
    await waitFor(() => t.c.closed, 3000, "tunnel closed at the lifetime");
    assert.equal((await exchange(port, ticketEnvelope(lb, 1, echoTarget))).ack.err, "session-unknown");
  } finally { await closeServer(gw); }
});

await closeServer(echo);
console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: session selftest (${failures} failure${failures === 1 ? "" : "s"})`);
process.exit(failures === 0 ? 0 : 1);
