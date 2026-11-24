import assert from "node:assert/strict";
import net from "node:net";
import { mkdtemp, chmod, readFile, readdir, rm, stat } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { makeDestinationLog } from "./destination-log.mjs";
import { makeSessionBooks } from "./session.mjs";
import { buildTicketBook, ticketFields } from "../lib/session-tickets.mjs";

process.env.SHADE_TREE_EGRESS_ALLOW = "*:*";
process.env.SHADE_TREE_ALLOW_PRIVATE_TARGETS = "1";
const { makeConnLimiter, makeEgressPolicy, makeHandler } = await import("./gateway.mjs");
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(predicate) {
  for (let i = 0; i < 200; i++) { if (await predicate()) return; await sleep(5); }
  throw new Error("timed out");
}
const listen = (server) => new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const close = (server) => new Promise((resolve) => server.close(resolve));
const dir = await mkdtemp(join(tmpdir(), "destination-log-test-"));
const env = { SHADE_TREE_DESTINATION_LOG: "1", SHADE_TREE_DESTINATION_LOG_DIR: dir };
let clock = Date.now();
let errors = 0;
let sink;
try {
  assert.equal(await makeDestinationLog({ env: {} }), null);
  assert.equal(await makeDestinationLog({ env: { SHADE_TREE_DESTINATION_LOG: "0", SHADE_TREE_DESTINATION_LOG_DIR: "/does/not/exist" } }), null);
  assert.deepEqual(await readdir(dir), [], "disabled destination logging creates no files");
  await chmod(dir, 0o755);
  await assert.rejects(makeDestinationLog({ env }), /0700/);
  await chmod(dir, 0o700);
  sink = await makeDestinationLog({ env, now: () => clock, onError: () => errors++ });
  const echo = net.createServer((socket) => {
    // Idle/payload-limit cases deliberately reset the upstream; this test peer must
    // consume that expected socket error rather than crash the selftest process.
    socket.on("error", () => {});
    socket.on("data", (data) => socket.write(data));
  });
  await listen(echo);
  async function tunnel(destinationLog, { fail = false, idle = false, limit = false, session = false } = {}) {
    const attempts = [];
    const books = session ? makeSessionBooks() : null;
    const tickets = session ? buildTicketBook(Array.from({ length: 6 }, (_, i) => Buffer.alloc(32, i + 1))) : null;
    if (session) assert.equal(books.open({ digest: tickets.ticketBookDigest, commitments: tickets.commitments,
      classId: "research-v1", nullifier: "DO-NOT-LOG-SESSION", epoch: "1" }).ok, true);
    let gatewayClosed = false;
    const gateway = net.createServer(makeHandler({ admit: async () => ({ ok: true }), commit() {} }, {
      verify: async (e) => ({ ok: true, nullifier: e.nullifier, externalNullifier: "1", share: e.share }),
      targetPolicy: makeEgressPolicy({ allow: "*:*" }),
      lookup: async () => [{ address: "127.0.0.2", family: 4 }, { address: "127.0.0.1", family: 4 }],
      connect(port, address, cb) {
        attempts.push(address);
        if (fail || address === "127.0.0.2") {
          const socket = new net.Socket();
          queueMicrotask(() => socket.emit("error", Object.assign(new Error("controlled refusal"), { code: "ECONNREFUSED" })));
          return socket;
        }
        return net.connect(port, address, cb);
      },
      envelopeTimeoutMs: 2000, idleTimeoutMs: idle ? 50 : 0,
      maxPayloadBytes: limit ? 5 : 0,
      limiter: makeConnLimiter({ maxConns: 0, maxPerNullifier: 0 }),
      destinationLog,
      sessions: books, sessionOnion: session ? "a".repeat(56) + ".onion" : null,
      onTunnelClose() { gatewayClosed = true; },
    }));
    await listen(gateway);
    const client = net.connect(gateway.address().port, "127.0.0.1");
    client.on("error", () => {});
    let received = Buffer.alloc(0);
    client.on("data", (data) => { received = Buffer.concat([received, data]); });
    await new Promise((resolve) => client.once("connect", resolve));
    const early = Buffer.from("opaque-early");
    const later = Buffer.from("opaque-later");
    const envelope = { v: 4, target: `destination-log-test.invalid:${echo.address().port}` };
    if (session) envelope.ticket = ticketFields({ ticketBookDigest: tickets.ticketBookDigest,
      index: 0, secret: tickets.secrets[0], requestNonce: "ab".repeat(16) });
    else Object.assign(envelope, { nullifier: "DO-NOT-LOG-IDENTIFIER", nonce: "DO-NOT-LOG-NONCE", share: { x: "1", y: "2" } });
    client.write(Buffer.concat([Buffer.from(JSON.stringify(envelope) + "\n"), early]));
    if (fail) await until(() => received.includes(Buffer.from("upstream:")));
    else {
      await until(() => received.includes(Buffer.from('{"ok":true}\n'))).catch(() => { throw new Error(`missing ack: ${received.toString()}; attempts=${attempts}`); });
      if (!limit) {
        client.write(later);
        await until(() => received.equals(Buffer.concat([Buffer.from('{"ok":true}\n'), early, later])));
      }
      if (idle || limit) await until(() => gatewayClosed);
    }
    client.destroy();
    if (!fail) await until(() => gatewayClosed);
    await close(gateway);
    books?.closeAll();
    return { attempts, port: echo.address().port, bytes: early.length + later.length, received };
  }
  const result = await tunnel(sink);
  await sink.flush();
  const files = await readdir(dir);
  assert.equal(files.length, 1);
  const file = join(dir, files[0]);
  assert.equal((await stat(file)).mode & 0o777, 0o600);
  const lines = (await readFile(file, "utf8")).trim().split("\n");
  assert.equal(lines.length, 1);
  const record = JSON.parse(lines[0]);
  assert.deepEqual(Object.keys(record).sort(), ["event", "host", "ip", "port", "openedAt", "durationMs", "agentToDestinationBytes", "destinationToAgentBytes", "closeReason"].sort());
  assert.deepEqual(result.attempts, ["127.0.0.2", "127.0.0.1"]);
  assert.equal(record.ip, "127.0.0.1", "logs successful pinned candidate, not first DNS answer");
  assert.equal(record.host, "destination-log-test.invalid");
  assert.equal(record.port, result.port);
  assert.equal(record.agentToDestinationBytes, result.bytes);
  assert.equal(record.destinationToAgentBytes, result.bytes);
  assert.equal(record.closeReason, "peer-close");
  assert.ok(Number.isFinite(Date.parse(record.openedAt)));
  assert.ok(record.durationMs >= 0);
  assert.ok(!lines[0].includes("DO-NOT-LOG"));
  assert.ok(!lines[0].includes("opaque-"));
  await tunnel(null);
  await tunnel(sink, { fail: true });
  await sink.flush();
  assert.equal((await readFile(file, "utf8")).trim().split("\n").length, 1, "off and failed dials produce no destination log records");
  await tunnel(sink, { idle: true });
  await tunnel(sink, { limit: true });
  await sink.flush();
  const records = (await readFile(file, "utf8")).trim().split("\n").map(JSON.parse);
  assert.equal(records[1].closeReason, "idle-timeout");
  assert.equal(records[2].closeReason, "payload-limit");
  assert.equal(records[2].agentToDestinationBytes + records[2].destinationToAgentBytes, 5);
  await tunnel(sink, { session: true });
  await sink.flush();
  const all = (await readFile(file, "utf8")).trim().split("\n").map(JSON.parse);
  assert.equal(all.length, 4);
  assert.deepEqual(Object.keys(all[3]).sort(), Object.keys(record).sort(), "session tickets use the same closed schema");
  assert.equal(all[3].agentToDestinationBytes, result.bytes);
  assert.equal(all[3].destinationToAgentBytes, result.bytes);
  assert.equal(all[3].ip, "127.0.0.1");
  assert.ok(!(await readFile(file, "utf8")).includes("DO-NOT-LOG"));
  await tunnel({ write() { throw new Error("sink unavailable"); } });
  await close(echo);
  // Retention tests run independently below; integration records remain local fixtures.
  assert.equal(errors, 0);
  console.log("PASS: destination logging, exact opaque relay/bytes, pinned fallback IP, off/failure silence, close reasons, sink failure isolation and permissions");
} finally {
  await sink?.close();
  await rm(dir, { recursive: true, force: true });
}
