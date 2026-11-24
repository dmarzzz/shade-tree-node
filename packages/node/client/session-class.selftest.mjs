// Offline proof of the client's session class pick (ADR 0013 decision 6): no Tor, no network, no
// real proofs. A fake SOCKS layer hands back fake sockets that answer the client's envelopes the
// way a node does (validateSessionInit and policyEcho from the shared library), so the class the
// client requests, the policy it accepts and the fallback it takes are all observable.
//
//   - pickSessionClass: research-v2 over research-v1 for signed caps; none for unknown classes;
//     a pinned node without caps gets the best class it has not refused.
//   - a pinned client opens a research-v2 book, and that book survives a 20 s gap that closes a
//     research-v1 book (the point of the change).
//   - a pinned node that answers `session-class` to v2 gets ONE v1 init on a NEW slot, and the
//     client remembers it: later books go straight to v1.
//   - a node that echoes another policy than the class asked for fails closed.
//   - interleaving: two inits in flight against a v1-only pinned node, both refusals held, then
//     released in either order: each falls back to v1 exactly once, the remembered refusal holds,
//     and when the v1 retry itself is refused the call fails without a third class.
//
//   node packages/node/client/session-class.selftest.mjs
//
// Exit 0 = all cases green; nonzero = a case failed (prints which).

import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ShadeTreeClient, pickSessionClass, SESSION_CLASS_PREFERENCE } from "./shade-tree-client.mjs";
import { validateSessionInit, policyEcho, SESSION_CLASSES } from "../lib/session-tickets.mjs";

let failures = 0;
function ok(name) { console.log("  PASS  " + name); }
function bad(name, e) { failures++; console.log("  FAIL  " + name + "  ::  " + ((e && e.stack) || e)); }
async function test(name, fn) { try { await fn(); ok(name); } catch (e) { bad(name, e); } }

const ONION = "a".repeat(56);
const work = mkdtempSync(join(tmpdir(), "shade-tree-session-class-"));
let clientSeq = 0;

function deferred() {
  let resolve;
  const promise = new Promise((r) => { resolve = r; });
  return { promise, resolve };
}

// A fake node behind a fake SOCKS layer. `serves` is the set of classes it accepts; `echoAs(classId)`
// lets a test make it echo another policy. `hold(classId)` returns a promise the init reply waits on.
function fakeNode({ serves = ["research-v1", "research-v2"], echoAs = (c) => c, hold = () => null } = {}) {
  const inits = [];   // every session init the node saw: { class, signal digest }
  const tickets = []; // every ticket spend
  const classes = Object.fromEntries(serves.map((id) => [id, SESSION_CLASSES[id]]));
  function socket() {
    const s = new EventEmitter();
    s.setNoDelay = () => {};
    s.destroy = () => { s.destroyed = true; };
    s.end = (cb) => { if (typeof cb === "function") cb(); };
    s.write = (data, enc, cb) => {
      const done = typeof enc === "function" ? enc : cb;
      if (typeof done === "function") done();
      const env = JSON.parse(String(data).trim());
      const answer = (obj) => { if (!s.destroyed) s.emit("data", Buffer.from(JSON.stringify(obj) + "\n")); };
      if (env.session) {
        inits.push({ class: env.session.class, nullifier: env.nullifier });
        const v = validateSessionInit(env.session, { classes });
        const reply = v.ok
          ? { ok: true, session: { ticketBookDigest: env.session.ticketBookDigest, policy: policyEcho(echoAs(v.classId)) } }
          : { ok: false, err: v.reason };
        const gate = hold(env.session.class);
        if (gate) gate.then(() => answer(reply)); else process.nextTick(() => answer(reply));
      } else if (env.ticket) {
        tickets.push(env.ticket.i);
        process.nextTick(() => answer({ ok: true }));
      }
      return true;
    };
    return s;
  }
  return { inits, tickets, socks: { createConnection: async () => ({ socket: socket() }) } };
}

function client(node, extra = {}) {
  clientSeq += 1;
  const proofs = [];
  const c = new ShadeTreeClient({
    secret: "test-secret", onion: ONION, socksClient: node.socks, sessionTickets: true, socksIsolation: false,
    loadGroupFn: async () => ({ group: { root: 1n }, root: "1", count: 1, source: "members.json" }),
    prove: async (secret, epoch, slot) => {
      proofs.push(slot);
      return { proof: { epoch: String(epoch) }, nullifier: `n${clientSeq}-${slot}`, externalNullifier: "e", share: { x: "1", y: "2" } };
    },
    slotStatePath: join(work, `slots-${clientSeq}.json`),
    ...extra,
  });
  c.proofs = proofs;
  return c;
}

try {
  await test("pickSessionClass: v2 over v1 from signed caps, v1 when only v1, none for unknown classes", () => {
    assert.deepEqual([...SESSION_CLASS_PREFERENCE], ["research-v2", "research-v1"]);
    assert.equal(pickSessionClass({ session: { classes: ["research-v1", "research-v2"] } }), "research-v2");
    assert.equal(pickSessionClass({ session: { classes: ["research-v1"] } }), "research-v1");
    assert.equal(pickSessionClass({ session: { classes: ["research-v9"] } }), null);
    assert.equal(pickSessionClass({ session: { classes: "research-v2" } }), null, "a non-array caps field is no class");
    // Signed caps win over the pin, and a refusal list does not override signed caps.
    assert.equal(pickSessionClass({ session: { classes: ["research-v1"] } }, { pinned: true }), "research-v1");
  });

  await test("pickSessionClass: a candidate without caps is a session candidate only when pinned, best unrefused class first", () => {
    assert.equal(pickSessionClass({ onion: ONION }), null);
    assert.equal(pickSessionClass({ onion: ONION }, { pinned: true }), "research-v2");
    assert.equal(pickSessionClass({ onion: ONION }, { pinned: true, refused: new Set(["research-v2"]) }), "research-v1");
    assert.equal(pickSessionClass({ onion: ONION }, { pinned: true, refused: new Set(["research-v2", "research-v1"]) }), null);
  });

  await test("pinned: the first book is research-v2 and it survives a 20 s idle gap that would close a research-v1 book", async () => {
    const node = fakeNode();
    const c = client(node);
    const events = [];
    const t1 = await c.connect("example.com:443", { onEvent: (e) => events.push(e) });
    assert.deepEqual(node.inits.map((i) => i.class), ["research-v2"]);
    assert.ok(events.some((e) => e.phase === "session" && e.status === "opened" && e.class === "research-v2"));
    assert.equal(t1.shadeTree.ticket, 0);
    const book = c._books.get(ONION);
    assert.equal(book.policy.idleTimeoutMs, 60_000);
    book.lastUse -= 20_000; // 20 s idle: past research-v1's 15 s, inside research-v2's 60 s
    const t2 = await c.connect("example.com:443");
    assert.equal(t2.shadeTree.ticket, 1, "the second tunnel spends a ticket from the same book");
    assert.equal(c.proofs.length, 1, "one proof for both tunnels");
    // Control: the same gap on a research-v1 book drops it and costs a proof.
    const nodeV1 = fakeNode({ serves: ["research-v1"] });
    const v1 = client(nodeV1, { onion: undefined });
    v1.onion = null;
    v1._candidates = async () => [{ onion: ONION, artifacts: null, session: { version: 1, classes: ["research-v1"] } }];
    v1._sel = async () => null;
    await v1.connect("example.com:443");
    v1._books.get(ONION).lastUse -= 20_000;
    await v1.connect("example.com:443");
    assert.equal(v1.proofs.length, 2, "a research-v1 book is closed after 15 s idle");
    assert.deepEqual(nodeV1.inits.map((i) => i.class), ["research-v1", "research-v1"]);
  });

  await test("directory candidate: the class follows the signed caps (v2 when advertised)", async () => {
    const node = fakeNode();
    const c = client(node);
    c.onion = null;
    c._candidates = async () => [{ onion: ONION, artifacts: null, session: { version: 1, classes: ["research-v1", "research-v2"] } }];
    c._sel = async () => null;
    await c.connect("example.com:443");
    assert.deepEqual(node.inits.map((i) => i.class), ["research-v2"]);
  });

  await test("pinned node without v2: session-class -> one v1 init on a new slot, remembered for later books", async () => {
    const node = fakeNode({ serves: ["research-v1"] });
    const c = client(node);
    const t1 = await c.connect("example.com:443");
    assert.deepEqual(node.inits.map((i) => i.class), ["research-v2", "research-v1"]);
    assert.equal(c.proofs.length, 2, "the v1 init carries its own proof (the class is in the signal)");
    assert.notEqual(c.proofs[0], c.proofs[1], "never the refused slot again");
    assert.notEqual(node.inits[0].nullifier, node.inits[1].nullifier);
    assert.equal(c._books.get(ONION).policy.idleTimeoutMs, 15_000);
    assert.equal(t1.shadeTree.ticket, 0);
    c._books.delete(ONION); // force the next tunnel to open a new book
    await c.connect("example.com:443");
    assert.deepEqual(node.inits.map((i) => i.class), ["research-v2", "research-v1", "research-v1"], "v2 is not asked again");
  });

  await test("a node that echoes another policy than the class asked for fails closed (no book)", async () => {
    const node = fakeNode({ echoAs: () => "research-v1" }); // accepts v2, echoes v1 limits
    const c = client(node);
    await assert.rejects(c.connect("example.com:443"), /session-policy-mismatch/);
    assert.equal(c._books.size, 0);
    assert.deepEqual(node.inits.map((i) => i.class), ["research-v2"], "a mismatch is not a class refusal: no fallback");
  });

  await test("a node that serves neither class: v2 then v1, then the call fails with session-class (no third class)", async () => {
    const node = fakeNode({ serves: [] });
    const c = client(node);
    await assert.rejects(c.connect("example.com:443"), /session-class/);
    assert.deepEqual(node.inits.map((i) => i.class), ["research-v2", "research-v1"]);
    assert.equal(c._books.size, 0);
  });

  for (const order of ["first-then-second", "second-then-first"]) {
    await test(`interleaving (${order}): two held v2 refusals against a v1-only pinned node each fall back once; the last refusal read is still v2`, async () => {
      const gates = [deferred(), deferred()];
      let v2Seen = 0;
      const node = fakeNode({ serves: ["research-v1"], hold: (cls) => (cls === "research-v2" ? gates[v2Seen++].promise : null) });
      const c = client(node);
      const a = c.connect("example.com:443");
      const b = c.connect("example.com:443");
      // Wait until both v2 inits are on the wire, with both refusals held.
      for (let i = 0; i < 200 && v2Seen < 2; i++) await new Promise((r) => setImmediate(r));
      assert.equal(v2Seen, 2, "both inits asked for v2 before any refusal landed");
      const [first, second] = order === "first-then-second" ? [0, 1] : [1, 0];
      gates[first].resolve();
      const firstDone = await (first === 0 ? a : b);
      assert.deepEqual([...c._sessionClassRefused.get(ONION)], ["research-v2"]);
      // The LAST read lands after the first fallback already opened a v1 book.
      gates[second].resolve();
      const secondDone = await (second === 0 ? a : b);
      assert.ok(firstDone.shadeTree && secondDone.shadeTree);
      assert.deepEqual(node.inits.map((i) => i.class).sort(), ["research-v1", "research-v1", "research-v2", "research-v2"]);
      assert.deepEqual([...c._sessionClassRefused.get(ONION)], ["research-v2"], "the refused set holds v2 only");
      assert.equal(c._books.get(ONION).policy.idleTimeoutMs, 15_000, "the live book is v1");
      assert.equal(new Set(c.proofs).size, c.proofs.length, "four proofs, four distinct slots");
    });
  }

  await test("interleaving, failed fallback: the held v2 refusal lands after the v1 retry of the other call was refused too", async () => {
    const gates = [deferred(), deferred()];
    let v2Seen = 0;
    const node = fakeNode({ serves: [], hold: (cls) => (cls === "research-v2" ? gates[v2Seen++].promise : null) });
    const c = client(node);
    const a = c.connect("example.com:443");
    const b = c.connect("example.com:443");
    for (let i = 0; i < 200 && v2Seen < 2; i++) await new Promise((r) => setImmediate(r));
    assert.equal(v2Seen, 2);
    gates[0].resolve();
    await assert.rejects(a, /session-class/);
    assert.deepEqual([...c._sessionClassRefused.get(ONION)].sort(), ["research-v1", "research-v2"]);
    gates[1].resolve();
    await assert.rejects(b, /session-class/);
    assert.deepEqual(node.inits.map((i) => i.class).sort(), ["research-v1", "research-v2", "research-v2"],
      "the late call reads both classes refused and does not try v1 again");
    assert.equal(c._books.size, 0);
  });
} finally {
  rmSync(work, { recursive: true, force: true });
}

console.log("");
if (failures) {
  console.log(`SELFTEST FAILED: ${failures} failing case(s)`);
  process.exit(1);
}
console.log("SELFTEST PASSED: all cases green");
