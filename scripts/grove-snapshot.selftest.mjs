import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  aggregateAnnouncedNodeHours,
  attestPublicGroveSnapshot,
  buildPublicGroveSnapshot,
  grovePublicKeyRawBase64,
  GROVE_HISTORY_CAP,
  scrubGroveHistory,
  verifyPublicGroveAttestation,
} from "../packages/node/lib/public-grove.mjs";
import { collectPublicGrove } from "./grove-snapshot.mjs";

const NOW = new Date("2026-08-23T12:00:00.000Z");
const onion = (char) => char.repeat(56) + ".onion";
const gateways = [
  {
    onion: onion("a"), pubkey: "11".repeat(32), operator: "0x" + "22".repeat(20), health: "up", caps: { region: "na" },
    metrics: { reporterId: "MUST_NOT_PUBLISH", requests: 9001, bytes: 123456, destinations: ["private.example"] },
  },
  { onion: onion("b"), pubkey: "33".repeat(32), operator: "0x" + "44".repeat(20), health: "down", caps: { region: "eu" } },
];
const directory = { version: 1, issued: Math.floor(NOW.getTime() / 1000), signer: "55".repeat(32), signature: "66".repeat(64), gateways };
const keypair = generateKeyPairSync("ed25519");
const privateKey = keypair.privateKey.export({ type: "pkcs8", format: "pem" });
const publicKey = keypair.publicKey.export({ type: "spki", format: "pem" });

const previousUnsigned = buildPublicGroveSnapshot({
  directory,
  observedAt: new Date("2026-08-23T11:45:00.000Z"),
  network: "sepolia",
});
const previous = attestPublicGroveSnapshot(previousUnsigned, privateKey);

const snapshot = buildPublicGroveSnapshot({ directory, previous, previousPublicKey: publicKey, observedAt: NOW, network: "sepolia" });
assert.equal(snapshot.schema, "shade-tree-public-grove-v1");
assert.deepEqual(snapshot.nodes, { announced: 2 });
assert.equal(snapshot.source.directoryVerified, true);
assert.equal(snapshot.source.definition, "announced-within-ttl");
assert.equal(snapshot.history.length, 2);
assert.equal(snapshot.growth.announcedNodeHours, 0); // 2 nodes * 15 minutes, floored to whole hours
assert.equal(aggregateAnnouncedNodeHours([
  { at: "2026-08-23T11:00:00.000Z", announced: 2 },
  { at: "2026-08-23T11:30:00.000Z", announced: 2 },
  { at: "2026-08-23T12:00:00.000Z", announced: 2 },
], { now: NOW }), 2);
assert.equal(aggregateAnnouncedNodeHours([
  { at: "2026-08-22T11:00:00.000Z", announced: 10 },
  { at: "2026-08-22T12:10:00.000Z", announced: 0 },
], { now: NOW }), 0, "a sample that expired before the 24h window contributes no node-hours");

const oneNodeDirectory = { ...directory, gateways: [gateways[0]] };
let fullWindow = null;
for (let interval = GROVE_HISTORY_CAP - 1; interval >= 0; interval -= 1) {
  const observedAt = new Date(NOW.getTime() - interval * 15 * 60_000);
  const unsigned = buildPublicGroveSnapshot({
    directory: oneNodeDirectory,
    previous: fullWindow,
    previousPublicKey: publicKey,
    observedAt,
    network: "sepolia",
  });
  fullWindow = attestPublicGroveSnapshot(unsigned, privateKey);
}
assert.equal(fullWindow.history.length, 97, "24h at 15m retains both boundary samples");
assert.equal(fullWindow.history[0].at, "2026-08-22T12:00:00.000Z");
assert.equal(fullWindow.history.at(-1).at, NOW.toISOString());
assert.equal(fullWindow.growth.announcedNodeHours, 24, "one announced node over a full window yields 24 node-hours");

const serialized = JSON.stringify(snapshot);
for (const secret of [gateways[0].onion, gateways[1].onion, gateways[0].pubkey, gateways[0].operator, "region", "caps", "markedDown", "MUST_NOT_PUBLISH", "requests", "bytes", "private.example"]) {
  assert.equal(serialized.includes(secret), false, `public snapshot omits ${secret.slice(0, 16)}`);
}
assert.deepEqual(Object.keys(snapshot).sort(), ["growth", "history", "network", "nodes", "observedAt", "privacy", "schema", "source"]);
assert.ok(snapshot.history.every((sample) => Object.keys(sample).sort().join(",") === "announced,at"));

const signed = attestPublicGroveSnapshot(snapshot, privateKey);
assert.equal(verifyPublicGroveAttestation(signed, publicKey), true);
assert.equal(grovePublicKeyRawBase64(publicKey).length, 44);
assert.equal(verifyPublicGroveAttestation({ ...signed, nodes: { announced: 99 } }, publicKey), false);

const wrongNetworkPrevious = attestPublicGroveSnapshot(buildPublicGroveSnapshot({
  directory,
  observedAt: new Date("2026-08-23T11:45:00.000Z"),
  network: "other",
}), privateKey);
assert.equal(buildPublicGroveSnapshot({
  directory,
  previous: wrongNetworkPrevious,
  previousPublicKey: publicKey,
  observedAt: NOW,
  network: "sepolia",
}).history.length, 1, "cross-network history is discarded");

const tamperedPrevious = structuredClone(previous);
tamperedPrevious.history[0].announced = 100_000;
assert.equal(buildPublicGroveSnapshot({
  directory,
  previous: tamperedPrevious,
  previousPublicKey: publicKey,
  observedAt: NOW,
  network: "sepolia",
}).history.length, 1, "unauthenticated history is discarded");

const oversized = { history: Array.from({ length: GROVE_HISTORY_CAP * 3 }, (_, index) => ({
  at: new Date(NOW.getTime() - index * 60_000).toISOString(),
  announced: index % 5,
  identity: onion("d"),
})) };
assert.equal(scrubGroveHistory(oversized, { now: NOW }).length, GROVE_HISTORY_CAP);
assert.equal(JSON.stringify(scrubGroveHistory(oversized, { now: NOW })).includes("identity"), false);
assert.ok(scrubGroveHistory(oversized, { now: NOW }).every((sample) => Object.keys(sample).sort().join(",") === "announced,at"));

const collected = await collectPublicGrove({
  previous: null,
  network: "test",
  observedAt: NOW,
  signingKey: privateKey,
  observe: async () => ({ result: { ok: true, signerOk: true, directoryFresh: true }, directory }),
});
assert.equal(collected.nodes.announced, 2);
assert.equal(verifyPublicGroveAttestation(collected, publicKey), true);

const relay = {
  definition: "payload-bytes-relayed",
  unit: "bytes",
  generatedAt: NOW.toISOString(),
  delayHours: 6,
  minimumCohort: 5,
  rounding: { method: "ceiling", bucketBytes: "1073741824" },
  windows: {
    sixHour: {
      status: "available",
      windowHours: 6,
      windowStart: "2026-08-23T00:00:00.000Z",
      windowEnd: "2026-08-23T06:00:00.000Z",
      reportingNodes: 5,
      roundedBytes: "1073741824",
    },
    twentyFourHour: {
      status: "available",
      windowHours: 24,
      windowStart: "2026-08-22T06:00:00.000Z",
      windowEnd: "2026-08-23T06:00:00.000Z",
      reportingNodes: 5,
      roundedBytes: "1073741824",
    },
  },
};
const v2 = buildPublicGroveSnapshot({ directory, observedAt: NOW, network: "sepolia", relay });
assert.equal(v2.schema, "shade-tree-public-grove-v2");
assert.deepEqual(Object.keys(v2).sort(), ["growth", "history", "network", "nodes", "observedAt", "privacy", "relay", "schema", "source"]);
const signedV2 = attestPublicGroveSnapshot(v2, privateKey);
assert.equal(verifyPublicGroveAttestation(signedV2, publicKey), true);
assert.equal(verifyPublicGroveAttestation({ ...signedV2, relay: { ...signedV2.relay, minimumCohort: 6 } }, publicKey), false, "v2 attestation covers relay privacy metadata");
assert.equal(JSON.stringify(signedV2).includes(gateways[0].onion), false, "v2 fixture remains aggregate-only");
await assert.rejects(
  collectPublicGrove({ signingKey: privateKey, observe: async () => ({ result: { ok: false, signerOk: false, directoryFresh: false }, directory: null }) }),
  /no verified bootnode directory/,
);
await assert.rejects(
  collectPublicGrove({ observe: async () => ({ result: { ok: true, signerOk: true, directoryFresh: true }, directory }) }),
  /signing key required/,
);

console.log("PASS: public grove snapshot selftest");
