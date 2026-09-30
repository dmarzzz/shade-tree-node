// Session tickets end to end with REAL Groth16 proofs (ADR 0011): the real node handler (real
// verifySessionEnvelope, real spent set, real books) on a loopback socket, and the real JS client
// with the flag on, dialing through a fake SOCKS client. One proof opens a book; the next tunnels
// spend tickets without proving; the same client with the flag off proves per tunnel, byte for
// byte as before. Slow lane (real proofs): skipped under SHADE_TREE_FAST.
//
//   node test/session-e2e.selftest.mjs

import assert from "node:assert/strict";
import net from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

process.env.SHADE_TREE_EGRESS_ALLOW = "*:*";
process.env.SHADE_TREE_ALLOW_PRIVATE_TARGETS = "1";
const {
  toField, identityFor, groupFromIdentities, currentEpoch, EPOCH_SECONDS, K_SLOTS, cleanUp,
} = await import("../packages/node/lib/rln.mjs");
const { makeHandler, makeSpentSet, _setRecentRoots } = await import("../packages/node/gateway/gateway.mjs");
const { makeSessionBooks } = await import("../packages/node/gateway/session.mjs");
const { ShadeTreeClient } = await import("../packages/node/client/shade-tree-client.mjs");
const { generateOnionIdentity } = await import("../packages/node/bootnode/keygen.mjs");

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

console.log("session tickets end to end (real proofs):");

// One member in a real group, the gateway trusting that root.
const secret = toField("0x" + "c3".repeat(32));
const filler = identityFor(toField("0x" + "44".repeat(32)));
const id = identityFor(secret);
const group = groupFromIdentities([filler, id]);
_setRecentRoots([group.root.toString()]);
const loadGroupFn = async () => ({ group, root: group.root.toString(), count: 2, source: "members.json" });

// A real onion identity for the node so the book binds to a real v3 onion.
const work = mkdtempSync(join(tmpdir(), "shade-tree-session-e2e-"));
const nodeId = await generateOnionIdentity(join(work, "node"), { label: "node" });
const ONION = nodeId.onion.replace(/\.onion$/, "");

const echo = await new Promise((resolve) => {
  const s = net.createServer((c) => { c.on("data", (d) => c.write(d)); c.on("error", () => {}); });
  s.listen(0, "127.0.0.1", () => resolve(s));
});
const echoTarget = `127.0.0.1:${echo.address().port}`;

let proofsVerified = 0;
const spentSet = makeSpentSet({ reconstruct: () => "x", derive: () => "y", slash: async () => {} });
const sessions = makeSessionBooks();
const gw = await new Promise((resolve) => {
  const s = net.createServer(makeHandler(spentSet, {
    sessions, sessionOnion: nodeId.onion,
    lookup: async () => [{ address: "127.0.0.1", family: 4 }],
  }));
  s.listen(0, "127.0.0.1", () => resolve(s));
});
const gwPort = gw.address().port;

// The fake SOCKS client: every "onion dial" is a loopback connection to the node. It records the
// per-dial SOCKS credential so the test can show one circuit identity per book.
const dials = [];
const fakeSocks = {
  createConnection: async ({ proxy, destination }) => {
    dials.push({ onion: destination.host, userId: proxy.userId || null });
    const socket = net.connect(gwPort, "127.0.0.1");
    await new Promise((r, j) => { socket.once("connect", r); socket.once("error", j); });
    return { socket };
  },
};
const epoch = currentEpoch();
const client = (sessionTickets) => new ShadeTreeClient({
  secret, onion: ONION, socksClient: fakeSocks, loadGroupFn, sessionTickets, limit: K_SLOTS,
  // One member, one durable slot cursor: every client here is the same member in the same epoch.
  slotStatePath: join(work, "slots.json"),
  prove: async (s, ep, slot, signal, opts) => { proofsVerified += 1; const { proveForSlot } = await import("../packages/node/lib/rln.mjs"); return proveForSlot(s, ep, slot, signal, opts); },
});

async function roundTrip(tunnel, text) {
  const got = [];
  tunnel.on("data", (d) => got.push(d));
  tunnel.write(text);
  await waitFor(() => Buffer.concat(got).toString("utf8").includes(text), 5000, "echo");
  tunnel.destroy();
}

try {
  await test("flag on: the first tunnel proves once and opens a book; the next tunnels spend tickets without a proof, on one circuit identity", async () => {
    const c = client(true);
    const events = [];
    const t1 = await c.connect(echoTarget, { onEvent: (e) => events.push(e) });
    assert.equal(proofsVerified, 1, "one proof for the first tunnel");
    assert.ok(events.some((e) => e.phase === "session" && e.status === "opened" && e.tickets === 6), "a research-v1 book was opened");
    assert.equal(t1.shadeTree.ticket, 0);
    assert.equal(t1.shadeTree.session.length, 64);
    await roundTrip(t1, "first through ticket 0");
    const t2 = await c.connect(echoTarget);
    const t3 = await c.connect(echoTarget);
    assert.equal(proofsVerified, 1, "tickets 1 and 2 cost no proof");
    assert.deepEqual([t2.shadeTree.ticket, t3.shadeTree.ticket], [1, 2]);
    await roundTrip(t2, "second"); await roundTrip(t3, "third");
    assert.equal(c.sessionBooks()[0].ticketsLeft, 3);
    const auths = new Set(dials.map((d) => d.userId));
    assert.equal(auths.size, 1, "the init and every ticket of the book share one SOCKS isolation credential");
    assert.equal(sessions.size(), 1, "the node holds exactly one book for the proof");
    assert.equal(spentSet.size(), 1, "one nullifier spent for three tunnels");
  });

  await test("flag on: after six tickets the seventh tunnel proves again and opens a second book", async () => {
    const c = client(true);
    const before = proofsVerified;
    const tickets = [];
    for (let i = 0; i < 7; i++) {
      const t = await c.connect(echoTarget);
      tickets.push(t.shadeTree.ticket);
      await roundTrip(t, `tunnel ${i}`);
      await sleep(20); // let the node see the close before the next spend (4 streams per book)
    }
    assert.equal(proofsVerified - before, 2, "six tickets per proof: two proofs for seven tunnels");
    assert.deepEqual(tickets, [0, 1, 2, 3, 4, 5, 0]);
  });

  await test("flag off: every tunnel is its own v4 proof and never touches the session path", async () => {
    const c = client(false);
    const before = proofsVerified;
    const booksBefore = sessions.size();
    const events = [];
    const t1 = await c.connect(echoTarget, { onEvent: (e) => events.push(e) });
    const t2 = await c.connect(echoTarget);
    assert.equal(proofsVerified - before, 2);
    assert.equal(t1.shadeTree.session, undefined);
    assert.equal(t2.shadeTree.session, undefined);
    assert.ok(!events.some((e) => e.phase === "session" || e.phase === "ticket"));
    assert.equal(sessions.size(), booksBefore, "no book was opened");
    await roundTrip(t1, "plain v4"); t2.destroy();
  });

  await test("the node's spent set saw each proof exactly once, whether it bought a tunnel or a book", async () => {
    assert.equal(spentSet.size(), proofsVerified, "one spent-set entry per proof, whether it bought a tunnel or a book");
  });
} finally {
  await new Promise((r) => gw.close(() => r()));
  await new Promise((r) => echo.close(() => r()));
  rmSync(work, { recursive: true, force: true });
  await cleanUp?.();
}

console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: session e2e selftest (${failures} failure${failures === 1 ? "" : "s"}; epoch ${epoch}, ${EPOCH_SECONDS}s)`);
process.exit(failures === 0 ? 0 : 1);
