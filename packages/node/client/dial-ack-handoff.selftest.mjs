// The SOCKS dial hands its socket to the acknowledgement reader with no await in between.
// No Tor, no network beyond loopback, no Groth16 work.
//
// The real `socks` library pauses the socket when the proxy's connect reply arrives and, one
// event-loop turn later (setImmediate), re-emits any bytes that came with that reply and resumes
// the socket. A node can answer before it reads an envelope and close right after: the
// envelope-deadline reply (`bad-envelope:envelope timeout`, from the gateway's readEnvelope timer)
// and `too-many-connections` are both written and then the socket is closed. If anything held the
// socket past that turn before attaching a `data` listener, the resumed socket would drop the line
// and the attempt would fail as an acknowledgement transport error instead of with the node's
// reason: SHADE_TREE_GATEWAY_ACK_EOF after a short hold (the reader attaches after the refusal data
// was emitted, before the end event), SHADE_TREE_GATEWAY_ACK_CLOSED after a hold that outlasts the
// close.
//
// This suite drives the real ShadeTreeClient and the real `socks` library against a loopback
// fake SOCKS5 proxy that turns into a fake node after the connect reply. For connect():
//   - a refusal in the same TCP write as the connect reply, then a close (both refusals)
//   - the gateway's own readEnvelope deadline error written after the reply, then a close
//   - a refusal written a little after the reply, then a close
//   - an ok acknowledgement plus tunnel bytes in the same write as the connect reply
// For session init and session ticket spend: an envelope-deadline refusal in the same TCP write
// as the connect reply, then a close. Three controls hold the socket after the connect() dial
// (the shape of an injected post-SOCKS hold) and show the loss this suite guards against:
// a refusal held one event-loop turn surfaces as ACK_EOF, a refusal held until the close as
// ACK_CLOSED, and a held ok as ACK_TIMEOUT.
//
//   node packages/node/client/dial-ack-handoff.selftest.mjs

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { EventEmitter } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SESSION_CLASSES } from "../lib/session-tickets.mjs";
import { readEnvelope } from "../gateway/gateway.mjs";
import { ShadeTreeClient } from "./shade-tree-client.mjs";

let failures = 0;
async function test(name, fn) {
  try { await fn(); console.log("  PASS  " + name); }
  catch (error) { failures += 1; console.log("  FAIL  " + name + " :: " + (error?.stack || error)); }
}

const slotWork = mkdtempSync(join(tmpdir(), "shade-tree-dial-ack-"));
let slotFileId = 0;
const slotStatePath = () => join(slotWork, `slots-${slotFileId++}.json`);

const ENVELOPE_TIMEOUT = "bad-envelope:envelope timeout";
const TOO_MANY = "too-many-connections";
// A v3-shaped onion: session init binds the gateway into its signal and checks the grammar.
const ONION = "a".repeat(56);
const SOCKS_CONNECT_OK = Buffer.from([0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80]);

const fakeGroup = async () => ({ group: {}, source: "members.json" });
const fakeProve = async (_secret, epoch, slot, signal, opts = {}) => ({
  proof: {
    epoch: String(epoch),
    rlnIdentifier: "1",
    snarkProof: {
      publicSignals: { y: "1", root: "2", nullifier: `null-${epoch}-${slot}`, x: signal, externalNullifier: `ext-${epoch}` },
      proof: { pi_a: ["1", "2"], pi_b: [["3", "4"], ["5", "6"]], pi_c: ["7", "8"] },
    },
  },
  nullifier: `null-${epoch}-${slot}`,
  externalNullifier: `ext-${epoch}`,
  share: { x: signal, y: "1" },
  artifact: opts.artifact,
});

const line = (obj) => Buffer.from(JSON.stringify(obj) + "\n");

// Node behaviours after the SOCKS5 handshake. `reply` is the proxy's connect-success reply; each
// behaviour decides whether node bytes share its TCP write. `end` sends FIN after the data, which
// the client sees as the node closing.
const NODE = {
  coalescedRefusal: (err) => ({ sock, reply }) => sock.end(Buffer.concat([reply, line({ ok: false, err })])),
  laterRefusal: (err, delayMs) => ({ sock, reply }) => {
    sock.write(reply);
    setTimeout(() => sock.end(line({ ok: false, err })), delayMs);
  },
  // The gateway's own envelope reader, driven into its deadline on a stream that never delivers
  // the envelope (standing in for an envelope still in transit), then the handler's reply text
  // (`bad-envelope:` + reader error) and a close.
  readerDeadline: (timeoutMs) => ({ sock, reply }) => {
    sock.write(reply);
    readEnvelope(new EventEmitter(), { timeoutMs }).then(
      () => sock.destroy(),
      (error) => sock.end(line({ ok: false, err: "bad-envelope:" + error.message })),
    );
  },
  coalescedOk: (tail) => ({ sock, reply }) => sock.write(Buffer.concat([reply, line({ ok: true }), tail])),
};

// A loopback SOCKS5 proxy (no-auth or username/password, CONNECT to a domain name) that hands each
// connected socket to `behave`. Records every byte the client sent after the handshake.
async function fakeTorNode(behave) {
  const sockets = new Set();
  const afterHandshake = [];
  const server = net.createServer((sock) => {
    sockets.add(sock);
    sock.on("close", () => sockets.delete(sock));
    sock.on("error", () => {});
    let buf = Buffer.alloc(0);
    let stage = "greeting";
    const received = [];
    afterHandshake.push(received);
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      for (;;) {
        if (stage === "greeting") {
          if (buf.length < 2 || buf.length < 2 + buf[1]) return;
          const methods = [...buf.subarray(2, 2 + buf[1])];
          buf = buf.subarray(2 + buf[1]);
          const method = methods.includes(0x02) ? 0x02 : 0x00;
          sock.write(Buffer.from([0x05, method]));
          stage = method === 0x02 ? "auth" : "request";
        } else if (stage === "auth") {
          if (buf.length < 2) return;
          const userLen = buf[1];
          if (buf.length < 3 + userLen) return;
          const passLen = buf[2 + userLen];
          if (buf.length < 3 + userLen + passLen) return;
          buf = buf.subarray(3 + userLen + passLen);
          sock.write(Buffer.from([0x01, 0x00]));
          stage = "request";
        } else {
          if (buf.length < 5) return;
          if (buf[0] !== 0x05 || buf[1] !== 0x01 || buf[3] !== 0x03) { sock.destroy(); return; }
          const need = 5 + buf[4] + 2;
          if (buf.length < need) return;
          const host = buf.subarray(5, 5 + buf[4]).toString("latin1");
          const early = buf.subarray(need);
          sock.removeListener("data", onData);
          if (early.length) received.push(early);
          sock.on("data", (c) => received.push(c));
          behave({ sock, reply: SOCKS_CONNECT_OK, host });
          return;
        }
      }
    };
    sock.on("data", onData);
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    port: server.address().port,
    afterHandshake,
    async close() {
      for (const s of sockets) s.destroy();
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

function makeClient(port, { sessionTickets = false, ackTimeoutMs = 2000 } = {}) {
  const events = [];
  const client = new ShadeTreeClient({
    secret: "test-secret",
    limit: 4,
    torHost: "127.0.0.1",
    torPort: port,
    dialAttempts: 1,
    gatewayAckTimeoutMs: ackTimeoutMs,
    gatewayAckMaxBytes: 256,
    // Real per-tunnel SOCKS credentials, so the proxy runs the username/password exchange too.
    socksIsolation: true,
    sessionTickets,
    artifacts: ["test-artifact"],
    gatewayArtifacts: ["test-artifact"],
    loadGroupFn: fakeGroup,
    prove: fakeProve,
    slotStatePath: slotStatePath(),
  });
  // One candidate, so the result does not depend on which refusals a client routes around.
  client._candidates = async () => [{
    onion: ONION,
    artifacts: ["test-artifact"],
    session: sessionTickets ? { classes: ["research-v1"] } : null,
  }];
  client._sel = async () => ({ reportResult() {} });
  const connect = () => client.connect("example.com:443", { onEvent: (event) => events.push(event) });
  return { client, events, connect };
}

async function outcome(promise) {
  try { return { tunnel: await promise }; } catch (error) { return { error }; }
}

// A live book for ONION, so connect() spends a ticket before it proves.
function preloadBook(client) {
  const policy = SESSION_CLASSES["research-v1"];
  client._books.set(ONION, {
    version: 4, digest: "0".repeat(64), secrets: [randomBytes(32)], commitments: [], nonce: "0".repeat(32),
    socksAuth: null, policy, unused: [0], openedAt: Date.now(), lastUse: Date.now(),
    slot: 0, nullifier: "n", artifact: "test-artifact",
  });
}

// Test-only: hold the dialed socket before the client reads it (the shape of an injected
// post-SOCKS hold), until `until(socket)` resolves.
function holdAfterDial(client, until) {
  const dial = client._dial.bind(client);
  client._dial = async (...args) => {
    const socket = await dial(...args);
    await until(socket);
    return socket;
  };
}
const untilClosed = (socket) => new Promise((resolve) => {
  if (socket.destroyed) resolve();
  else socket.once("close", resolve);
});
const forMs = (ms) => () => new Promise((resolve) => setTimeout(resolve, ms));
const oneTurn = () => new Promise((resolve) => setImmediate(resolve));

console.log("connect(): node replies that arrive with or right after the SOCKS reply:");

for (const err of [ENVELOPE_TIMEOUT, TOO_MANY]) {
  await test(`${err} in the same TCP write as the connect reply, then a close, surfaces as that refusal`, async () => {
    const node = await fakeTorNode(NODE.coalescedRefusal(err));
    try {
      const h = makeClient(node.port);
      const { error } = await outcome(h.connect());
      assert.equal(error?.message, "gate refused: " + err, `got ${error?.code || ""} ${error?.message}`);
      assert.equal(error?.code, undefined, "not a ShadeTreeGatewayAckError");
      assert.ok(h.events.some((e) => e.phase === "gate" && e.status === "refused" && e.error === err), "refused event carries the node reason");
      assert.ok(!h.events.some((e) => e.code === "SHADE_TREE_GATEWAY_ACK_CLOSED"), "no ACK_CLOSED event");
    } finally { await node.close(); }
  });
}

await test("the gateway's own readEnvelope deadline reply, written after the connect reply, surfaces as the refusal", async () => {
  const node = await fakeTorNode(NODE.readerDeadline(40));
  try {
    const h = makeClient(node.port);
    const { error } = await outcome(h.connect());
    assert.equal(error?.message, "gate refused: " + ENVELOPE_TIMEOUT, `got ${error?.code || ""} ${error?.message}`);
    assert.equal(node.afterHandshake[0].length > 0, true, "the client wrote its envelope before the node gave up on it");
  } finally { await node.close(); }
});

await test("a refusal written 30 ms after the connect reply, then a close, surfaces as the refusal", async () => {
  const node = await fakeTorNode(NODE.laterRefusal(ENVELOPE_TIMEOUT, 30));
  try {
    const h = makeClient(node.port);
    const { error } = await outcome(h.connect());
    assert.equal(error?.message, "gate refused: " + ENVELOPE_TIMEOUT, `got ${error?.code || ""} ${error?.message}`);
  } finally { await node.close(); }
});

await test("an ok acknowledgement plus tunnel bytes in the connect-reply write opens the tunnel with those bytes", async () => {
  const tail = Buffer.from("tunnel-bytes");
  const node = await fakeTorNode(NODE.coalescedOk(tail));
  try {
    const h = makeClient(node.port);
    const { tunnel, error } = await outcome(h.connect());
    try {
      assert.equal(error, undefined, `got ${error?.code || ""} ${error?.message}`);
      assert.equal(tunnel.shadeTree.onion, ONION);
      const first = tunnel.read();
      assert.equal(String(first), "tunnel-bytes", "bytes after the ack newline are tunnel data");
    } finally {
      tunnel?.on("error", () => {});
      tunnel?.destroy();
    }
  } finally { await node.close(); }
});

console.log("\nsession init and ticket spend:");

await test("session init: an envelope-deadline refusal coalesced with the connect reply surfaces as the refusal", async () => {
  const node = await fakeTorNode(NODE.coalescedRefusal(ENVELOPE_TIMEOUT));
  try {
    const h = makeClient(node.port, { sessionTickets: true });
    const { error } = await outcome(h.connect());
    assert.equal(error?.message, "gate refused: " + ENVELOPE_TIMEOUT, `got ${error?.code || ""} ${error?.message}`);
    assert.ok(h.events.some((e) => e.phase === "session" && e.status === "refused" && e.error === ENVELOPE_TIMEOUT));
    assert.ok(!h.events.some((e) => e.phase === "session" && e.status === "error"), "no transport error on the session init");
  } finally { await node.close(); }
});

await test("ticket spend: a refusal coalesced with the connect reply is read as a refusal, then session init reads its own", async () => {
  const node = await fakeTorNode(NODE.coalescedRefusal(ENVELOPE_TIMEOUT));
  try {
    const h = makeClient(node.port, { sessionTickets: true });
    preloadBook(h.client);
    const { error } = await outcome(h.connect());
    assert.ok(h.events.some((e) => e.phase === "ticket" && e.status === "refused" && e.error === ENVELOPE_TIMEOUT),
      `ticket events ${JSON.stringify(h.events.filter((e) => e.phase === "ticket"))}`);
    assert.ok(!h.events.some((e) => e.phase === "ticket" && e.status === "error"), "no transport error on the ticket spend");
    assert.equal(error?.message, "gate refused: " + ENVELOPE_TIMEOUT, `got ${error?.code || ""} ${error?.message}`);
    assert.equal(node.afterHandshake.length, 2, "one ticket connection, one session-init connection");
  } finally { await node.close(); }
});

console.log("\ncontrols: a socket held after the dial loses what the node sent:");

await test("held one event-loop turn: the refusal is lost and the attempt fails as ACK_EOF", async () => {
  const node = await fakeTorNode(NODE.coalescedRefusal(ENVELOPE_TIMEOUT));
  try {
    const h = makeClient(node.port);
    holdAfterDial(h.client, oneTurn);
    const { error } = await outcome(h.connect());
    assert.equal(error?.code, "SHADE_TREE_GATEWAY_ACK_EOF", `got ${error?.code || ""} ${error?.message}`);
    assert.ok(!h.events.some((e) => e.phase === "gate" && e.status === "refused"), "the node reason never reached the caller");
  } finally { await node.close(); }
});

await test("held until the node closed: the refusal is lost and the attempt fails as ACK_CLOSED", async () => {
  const node = await fakeTorNode(NODE.coalescedRefusal(ENVELOPE_TIMEOUT));
  try {
    const h = makeClient(node.port);
    holdAfterDial(h.client, untilClosed);
    const { error } = await outcome(h.connect());
    assert.equal(error?.code, "SHADE_TREE_GATEWAY_ACK_CLOSED", `got ${error?.code || ""} ${error?.message}`);
    assert.equal(node.afterHandshake[0].length, 0, "nothing was written to a closed socket");
  } finally { await node.close(); }
});

await test("held 100 ms with an ok acknowledgement: the ok is lost and the attempt fails as ACK_TIMEOUT", async () => {
  const node = await fakeTorNode(NODE.coalescedOk(Buffer.alloc(0)));
  try {
    const h = makeClient(node.port, { ackTimeoutMs: 300 });
    holdAfterDial(h.client, forMs(100));
    const { error } = await outcome(h.connect());
    assert.equal(error?.code, "SHADE_TREE_GATEWAY_ACK_TIMEOUT", `got ${error?.code || ""} ${error?.message}`);
  } finally { await node.close(); }
});

rmSync(slotWork, { recursive: true, force: true });
console.log(failures ? `\nSELFTEST FAILED: ${failures} case(s)` : "\nSELFTEST PASSED: all cases green");
process.exit(failures ? 1 : 0);
