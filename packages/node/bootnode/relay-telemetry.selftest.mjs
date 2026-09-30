import assert from "node:assert/strict";
import { createPublicKey, generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ed25519PrivateKey, pubkeyToOnion } from "../lib/directory.mjs";
import {
  RELAY_COUNTER_SCHEMA,
  buildRelayReport,
  makeRelayAggregator,
  verifyRelayAggregate,
} from "../lib/relay-telemetry.mjs";
import { reportRelayOnce } from "./heartbeat.mjs";
import { makeServer } from "./server.mjs";

function rawPair() {
  const pair = generateKeyPairSync("ed25519");
  return {
    pub: pair.publicKey.export({ type: "spki", format: "der" }).subarray(-32).toString("hex"),
    priv: pair.privateKey.export({ type: "pkcs8", format: "der" }).subarray(-32).toString("hex"),
  };
}
function nodeIdentity() {
  const seed = randomBytes(32).toString("hex");
  const pub = createPublicKey(ed25519PrivateKey(seed)).export({ type: "spki", format: "der" }).subarray(-32).toString("hex");
  return { seed, onion: pubkeyToOnion(pub) };
}
function request(port, method, path, body = null) {
  return new Promise((resolve, reject) => {
    const payload = body === null ? null : Buffer.from(JSON.stringify(body));
    const req = http.request({ host: "127.0.0.1", port, method, path, headers: payload ? { "content-type": "application/json", "content-length": payload.length } : {} }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: chunks.length ? JSON.parse(Buffer.concat(chunks)) : null }));
    });
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

const now = Date.parse("2026-08-25T12:30:00.000Z");
const signer = rawPair();
const id = nodeIdentity();
const announced = new Set([id.onion]);
const aggregator = makeRelayAggregator({ signer, now: () => now, isAnnounced: (onion) => announced.has(onion) });
const registry = {
  size: () => announced.size,
  admission: "open",
  ttlSec: 900,
  // None of these discovery functions should be reached by telemetry paths.
  directoryWithEtag() { throw new Error("directory route reached"); },
  delta() { throw new Error("delta route reached"); },
  record() { return null; },
  announce() { throw new Error("announce route reached"); },
};
const server = makeServer(registry, { signerPub: signer.pub, relayAggregator: aggregator });
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const temp = mkdtempSync(join(tmpdir(), "shade-tree-relay-heartbeat-"));
try {
  const counter = {
    schema: RELAY_COUNTER_SCHEMA,
    bootId: "ab".repeat(16),
    startedAt: "2026-08-25T05:15:00.000Z",
    updatedAt: "2026-08-25T05:30:00.000Z",
    counters: { agentToDestinationBytes: "1000", destinationToAgentBytes: "2000" },
  };
  const { report } = buildRelayReport({ counter, onion: id.onion, onionSeedHex: id.seed, now: Date.parse(counter.updatedAt) });
  const accepted = await request(server.address().port, "POST", "/telemetry/relay", report);
  assert.deepEqual(accepted, { status: 200, headers: accepted.headers, body: { ok: true } });

  const heartbeatId = nodeIdentity();
  announced.add(heartbeatId.onion);
  const heartbeatCounter = { ...counter, bootId: "bc".repeat(16), counters: { agentToDestinationBytes: "3000", destinationToAgentBytes: "4000" } };
  const counterPath = join(temp, "counter.json");
  const reportStatePath = join(temp, "report.json");
  writeFileSync(counterPath, `${JSON.stringify(heartbeatCounter)}\n`, { mode: 0o600 });
  const paths = [];
  await reportRelayOnce({
    id: heartbeatId,
    bootnode: "test-elder.onion",
    torHost: "127.0.0.1",
    torPort: 9250,
    counterPath,
    reportStatePath,
    now: Date.parse(counter.updatedAt),
    post: async (_bootnode, path, body) => {
      paths.push(path);
      return (await request(server.address().port, "POST", path, body)).body;
    },
  });
  assert.deepEqual(paths, ["/telemetry/relay"], "heartbeat uses only the separate telemetry path");
  assert.equal(JSON.parse(readFileSync(reportStatePath, "utf8")).sequence, 1, "reporter baseline persists after Elder acceptance");

  const aggregateResponse = await request(server.address().port, "GET", "/telemetry/aggregate");
  assert.equal(aggregateResponse.status, 200);
  assert.equal(verifyRelayAggregate(aggregateResponse.body, signer.pub), true);
  assert.equal(aggregateResponse.body.windows.twentyFourHour.status, "suppressed");
  assert.equal("roundedBytes" in aggregateResponse.body.windows.twentyFourHour, false);
  assert.ok(aggregateResponse.headers.etag, "aggregate route is revalidation-friendly");

  const replayed = await request(server.address().port, "POST", "/telemetry/relay", report);
  assert.equal(replayed.status, 400);
  assert.equal(replayed.body.err, "sequence-replay");

  const rejectedIdentity = nodeIdentity();
  const unknown = buildRelayReport({ counter: { ...counter, bootId: "cd".repeat(16) }, onion: rejectedIdentity.onion, onionSeedHex: rejectedIdentity.seed, now: Date.parse(counter.updatedAt) });
  const notAnnounced = await request(server.address().port, "POST", "/telemetry/relay", unknown.report);
  assert.equal(notAnnounced.status, 400);
  assert.equal(notAnnounced.body.err, "not-announced");
} finally {
  await new Promise((resolve) => server.close(resolve));
  rmSync(temp, { recursive: true, force: true });
}

console.log("PASS: separate authenticated Elder relay report and aggregate routes");
