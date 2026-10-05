import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { attestPublicGroveSnapshot, buildPublicGroveSnapshot } from "../packages/node/lib/public-grove.mjs";
import { GET } from "../docs/post/api/grove-v2.mjs";
import {
  GROVE_V2_SNAPSHOT_URL,
  groveV2SigningPayload,
  validGroveV2Snapshot,
  verifyGroveV2Snapshot,
} from "../docs/post/api/_grove-v2-contract.mjs";

const NOW = new Date("2026-08-25T12:00:00.000Z");
const pair = generateKeyPairSync("ed25519");
const privateKey = pair.privateKey.export({ type: "pkcs8", format: "pem" });
const publicKey = pair.publicKey.export({ type: "spki", format: "pem" });
const directory = { gateways: Array.from({ length: 5 }, (_, index) => ({ onion: `${index}` })) };
const relay = {
  definition: "payload-bytes-relayed",
  unit: "bytes",
  generatedAt: NOW.toISOString(),
  delayHours: 6,
  minimumCohort: 5,
  rounding: { method: "ceiling", bucketBytes: "1073741824" },
  windows: {
    sixHour: { status: "suppressed", windowHours: 6, windowStart: "2026-08-25T00:00:00.000Z", windowEnd: "2026-08-25T06:00:00.000Z", reportingNodes: 2, suppressionReason: "minimum-cohort" },
    twentyFourHour: { status: "available", windowHours: 24, windowStart: "2026-08-24T06:00:00.000Z", windowEnd: "2026-08-25T06:00:00.000Z", reportingNodes: 5, roundedBytes: "1073741824" },
  },
};
const onchain = {
  definition: "finalized-v4-onchain-activity",
  generatedAt: NOW.toISOString(),
  delayHours: 6,
  minimumCohort: 5,
  source: {
    chainId: 11155111,
    finalizedBlock: "12345678",
    finalizedBlockHash: `0x${"ab".repeat(32)}`,
    finalizedBlockTime: "2026-08-25T06:00:00.000Z",
    finalityConfirmations: 64,
  },
  membership: {
    definition: "active-commitments-at-finalized-block",
    duplicatePolicy: "separate-contract-classes-no-cross-set-dedup",
    staked: { status: "available", activeCommitments: 9 },
    paid: { status: "suppressed", suppressionReason: "minimum-cohort" },
  },
  settlements: {
    definition: "finalized-settlement-linked-to-finalized-insert",
    attributionRule: "signed-registrar-chain-verified-v1",
    status: "unavailable",
    unavailableReason: "attribution-unavailable",
  },
  enforcement: {
    definition: "finalized-contract-slash-events",
    staked: { status: "suppressed", suppressionReason: "minimum-cohort" },
    paid: { status: "available", finalizedSlashes: 5 },
  },
};
const unsigned = buildPublicGroveSnapshot({ directory, observedAt: NOW, network: "sepolia", relay, onchain });
const snapshot = attestPublicGroveSnapshot(unsigned, privateKey);

assert.equal(validGroveV2Snapshot(snapshot, { now: NOW.getTime() }), true);
assert.equal(verifyGroveV2Snapshot(snapshot, publicKey), true);
assert.deepEqual(groveV2SigningPayload(snapshot).relay, relay);
assert.deepEqual(groveV2SigningPayload(snapshot).onchain, onchain);
assert.equal("roundedBytes" in snapshot.relay.windows.sixHour, false, "suppressed window omits a value instead of publishing zero");
assert.equal(validGroveV2Snapshot({ ...snapshot, relay: { ...relay, nodeId: "forbidden" } }, { now: NOW.getTime() }), false, "exact keys reject per-node metadata");
assert.equal(validGroveV2Snapshot({ ...snapshot, observedAt: "2026-08-25T10:45:00.000Z", history: [{ at: "2026-08-25T10:45:00.000Z", announced: 5 }] }, { now: NOW.getTime() }), false, "stale v2 head fails closed");
const staleRelay = { ...snapshot, relay: { ...relay, generatedAt: "2026-08-25T10:45:00.000Z" } };
assert.equal(validGroveV2Snapshot(staleRelay, { now: NOW.getTime() }), false, "stale relay aggregate fails closed independently of the Grove head");
assert.equal(verifyGroveV2Snapshot({ ...snapshot, relay: { ...relay, minimumCohort: 6 } }, publicKey), false, "relay metadata is signed");
assert.equal(verifyGroveV2Snapshot({ ...snapshot, onchain: { ...onchain, delayHours: 7 } }, publicKey), false, "onchain metadata is signed");
assert.equal(validGroveV2Snapshot({ ...snapshot, onchain: { ...onchain, payer: "forbidden" } }, { now: NOW.getTime() }), false, "onchain exact keys reject identity metadata");
const relayOnly = attestPublicGroveSnapshot(buildPublicGroveSnapshot({ directory, observedAt: NOW, network: "sepolia", relay }), privateKey);
assert.equal(validGroveV2Snapshot(relayOnly, { now: NOW.getTime() }), true, "relay-only v2 remains compatible");
assert.equal(JSON.stringify(snapshot).includes("nodeId"), false);
assert.equal(JSON.stringify(snapshot).includes("destination"), false);

const originalFetch = globalThis.fetch;
const originalError = console.error;
try {
  let called = false;
  globalThis.fetch = async (url, options) => {
    called = true;
    assert.equal(url, GROVE_V2_SNAPSHOT_URL);
    assert.equal(options.cache, "no-store");
    assert.equal(options.redirect, "error");
    return new Response(JSON.stringify(snapshot), { status: 200, headers: { "content-type": "application/json" } });
  };
  console.error = () => {};
  const invalidProductionSignature = await GET(new Request("https://shadenet.xyz/api/v2/data/grove/sepolia/head"));
  assert.equal(called, true);
  assert.equal(invalidProductionSignature.status, 503, "wrong publication key never reaches browsers");
  assert.equal(invalidProductionSignature.headers.get("cache-control"), "no-store");
  assert.equal(await invalidProductionSignature.text(), '{"error":"network_snapshot_unavailable"}\n');

  called = false;
  const query = await GET(new Request("https://shadenet.xyz/api/v2/data/grove/sepolia/head?x=1"));
  assert.equal(query.status, 400);
  assert.equal(called, false, "unsupported queries fail before upstream I/O");
} finally {
  globalThis.fetch = originalFetch;
  console.error = originalError;
}

console.log("PASS: Grove v2 exact-key, freshness, signature, Vercel, and privacy contract");
