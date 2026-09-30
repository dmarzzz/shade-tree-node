import assert from "node:assert/strict";
import { createPublicKey, generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ed25519PrivateKey,
  ed25519Sign,
  pubkeyToOnion,
} from "./directory.mjs";
import {
  RELAY_COUNTER_SCHEMA,
  RELAY_REPORT_STATE_SCHEMA,
  buildRelayReport,
  makeRelayAggregator,
  makeRelayByteCounter,
  publicRelayFromAggregate,
  readRelayCounterState,
  readRelayReportState,
  relayReportSigningPayload,
  validPublicRelay,
  validRelayAggregate,
  validRelayCounterState,
  verifyRelayAggregate,
  verifyRelayReport,
  writeRelayReportState,
} from "./relay-telemetry.mjs";

function identity() {
  const seed = randomBytes(32).toString("hex");
  const der = createPublicKey(ed25519PrivateKey(seed)).export({ type: "spki", format: "der" });
  const pub = der.subarray(-32).toString("hex");
  return { seed, pub, onion: pubkeyToOnion(pub) };
}

function elderSigner() {
  const pair = generateKeyPairSync("ed25519");
  return {
    pub: pair.publicKey.export({ type: "spki", format: "der" }).subarray(-32).toString("hex"),
    priv: pair.privateKey.export({ type: "pkcs8", format: "der" }).subarray(-32).toString("hex"),
  };
}

function counter(id, startedAt, a, b) {
  return {
    schema: RELAY_COUNTER_SCHEMA,
    bootId: id,
    startedAt,
    updatedAt: startedAt,
    counters: { agentToDestinationBytes: String(a), destinationToAgentBytes: String(b) },
  };
}

function resign(report, id) {
  const next = structuredClone(report);
  next.signature = ed25519Sign(Buffer.from(JSON.stringify(relayReportSigningPayload(next))), id.seed);
  return next;
}

const temp = mkdtempSync(join(tmpdir(), "shade-tree-relay-test-"));
try {
  let clock = Date.parse("2026-08-25T12:30:00.000Z");
  const counterPath = join(temp, "counter.json");
  const reportStatePath = join(temp, "report.json");
  const local = makeRelayByteCounter({
    path: counterPath,
    now: () => clock,
    bootId: "01".repeat(16),
    flushIntervalMs: 0,
  });
  local.addAgentToDestination(Buffer.from("agent"));
  local.addDestinationToAgent(Buffer.from("destination"));
  const localState = local.flush();
  assert.equal(localState.counters.agentToDestinationBytes, "5");
  assert.equal(localState.counters.destinationToAgentBytes, "11");
  assert.deepEqual(readRelayCounterState(counterPath), localState, "counter state persists exact decimal u64 values");
  assert.equal(JSON.stringify(localState).includes("target"), false);
  assert.equal(JSON.stringify(localState).includes("nullifier"), false);

  const firstId = identity();
  clock += 5 * 60_000;
  const built = buildRelayReport({ counter: localState, onion: firstId.onion, onionSeedHex: firstId.seed, now: clock });
  assert.equal(verifyRelayReport(built.report), true);
  assert.deepEqual(built.report.reset, { occurred: true, reason: "process-start" });
  writeRelayReportState(reportStatePath, built.nextState);
  assert.deepEqual(readRelayReportState(reportStatePath), built.nextState);
  assert.equal(built.nextState.schema, RELAY_REPORT_STATE_SCHEMA);
  assert.equal(Object.keys(built.report).includes("destination"), false);
  assert.equal(Object.keys(built.report).includes("flow"), false);

  const sameBootCounter = { ...localState, counters: { agentToDestinationBytes: "9", destinationToAgentBytes: "15" } };
  const second = buildRelayReport({ counter: sameBootCounter, previous: built.nextState, onion: firstId.onion, onionSeedHex: firstId.seed, now: clock + 5 * 60_000 });
  assert.equal(second.report.sequence, 2);
  assert.deepEqual(second.report.reset, { occurred: false, reason: null });
  await assert.rejects(async () => buildRelayReport({
    counter: { ...sameBootCounter, counters: { agentToDestinationBytes: "1", destinationToAgentBytes: "15" } },
    previous: built.nextState,
    onion: firstId.onion,
    onionSeedHex: firstId.seed,
    now: clock + 5 * 60_000,
  }), /rollback/);

  const now = Date.parse("2026-08-25T12:30:00.000Z");
  const reportStart = "2026-08-25T05:15:00.000Z";
  const reportEnd = Date.parse("2026-08-25T05:30:00.000Z");
  const ids = Array.from({ length: 6 }, identity);
  const announced = new Set(ids.map((id) => id.onion));
  const signer = elderSigner();
  const elderStatePath = join(temp, "elder-state.json");
  const aggregator = makeRelayAggregator({ signer, now: () => now, isAnnounced: (onion) => announced.has(onion), statePath: elderStatePath });
  const reports = ids.map((id, index) => buildRelayReport({
    counter: counter((index + 2).toString(16).padStart(2, "0").repeat(16), reportStart, 1000 + index, 2000 + index),
    onion: id.onion,
    onionSeedHex: id.seed,
    now: reportEnd,
  }));

  assert.deepEqual(await aggregator.accept(reports[0].report), { ok: true });
  assert.deepEqual(await aggregator.accept(reports[0].report), { ok: false, reason: "sequence-replay" });
  const restarted = makeRelayAggregator({ signer, now: () => now, isAnnounced: (onion) => announced.has(onion), statePath: elderStatePath });
  assert.deepEqual(await restarted.accept(reports[0].report), { ok: false, reason: "sequence-replay" }, "private checkpoint rejects replay after Elder restart");
  assert.equal(restarted.snapshot().windows.twentyFourHour.suppressionReason, "unavailable", "raw contributions are not restored across restart");
  const tampered = structuredClone(reports[1].report);
  tampered.counters.agentToDestinationBytes = "9999";
  assert.deepEqual(await aggregator.accept(tampered), { ok: false, reason: "bad-signature" });
  assert.deepEqual(await aggregator.accept(reports[1].report), { ok: true });

  const suppressed = aggregator.snapshot();
  assert.equal(validRelayAggregate(suppressed), true);
  assert.equal(verifyRelayAggregate(suppressed, signer.pub), true);
  assert.equal(suppressed.windows.twentyFourHour.status, "suppressed");
  assert.equal(suppressed.windows.twentyFourHour.suppressionReason, "minimum-cohort");
  assert.equal("roundedBytes" in suppressed.windows.twentyFourHour, false, "suppressed is omission, never zero");

  for (const builtReport of reports.slice(2, 5)) assert.deepEqual(await aggregator.accept(builtReport.report), { ok: true });
  const available = aggregator.snapshot();
  assert.equal(available.windows.sixHour.status, "available");
  assert.equal(available.windows.twentyFourHour.status, "available");
  assert.equal(available.windows.twentyFourHour.reportingNodes, 5);
  assert.equal(available.windows.twentyFourHour.roundedBytes, String(1024 ** 3), "positive total rounds up to a fixed 1 GiB bucket");
  assert.equal(verifyRelayAggregate({ ...available, minimumCohort: 6 }, signer.pub), false, "aggregate signature covers privacy metadata");

  const serialized = JSON.stringify(available);
  for (const secret of [...ids.map((id) => id.onion), "nodeId", "destination", "member", "nullifier", "flow", "payment"]) {
    assert.equal(serialized.includes(secret), false, `aggregate omits ${secret.slice(0, 16)}`);
  }
  const publicRelay = publicRelayFromAggregate(available, signer.pub);
  assert.equal(validPublicRelay(publicRelay, { observedAt: "2026-08-25T12:30:00.000Z" }), true);
  assert.deepEqual(Object.keys(publicRelay).sort(), ["definition", "delayHours", "generatedAt", "minimumCohort", "rounding", "unit", "windows"].sort());

  const prev = reports[0].nextState;
  const overlap = resign({
    ...reports[0].report,
    sequence: 2,
    intervalStart: "2026-08-25T05:20:00.000Z",
    intervalEnd: "2026-08-25T05:40:00.000Z",
    counters: { agentToDestinationBytes: "1100", destinationToAgentBytes: "2100" },
    reset: { occurred: false, reason: null },
  }, ids[0]);
  assert.deepEqual(await aggregator.accept(overlap), { ok: false, reason: "interval-overlap" });

  const rollback = resign({
    ...reports[0].report,
    sequence: prev.sequence + 1,
    intervalStart: reports[0].report.intervalEnd,
    intervalEnd: "2026-08-25T05:45:00.000Z",
    counters: { agentToDestinationBytes: "1", destinationToAgentBytes: "1" },
    reset: { occurred: false, reason: null },
  }, ids[0]);
  assert.deepEqual(await aggregator.accept(rollback), { ok: false, reason: "counter-rollback" });

  const unexpectedReset = resign({
    ...reports[0].report,
    sequence: prev.sequence + 1,
    intervalStart: reports[0].report.intervalEnd,
    intervalEnd: "2026-08-25T05:45:00.000Z",
    counters: { agentToDestinationBytes: "1100", destinationToAgentBytes: "2100" },
    reset: { occurred: true, reason: "process-start" },
  }, ids[0]);
  assert.deepEqual(await aggregator.accept(unexpectedReset), { ok: false, reason: "unexpected-reset" });

  const missingReset = resign({ ...reports[5].report, reset: { occurred: false, reason: null } }, ids[5]);
  assert.deepEqual(await aggregator.accept(missingReset), { ok: false, reason: "missing-reset" });

  const future = resign({ ...reports[5].report, intervalStart: "2026-08-25T12:31:00.000Z", intervalEnd: "2026-08-25T12:40:00.000Z" }, ids[5]);
  assert.deepEqual(await aggregator.accept(future), { ok: false, reason: "future-interval" });

  const implausible = buildRelayReport({
    counter: counter("ff".repeat(16), reportStart, 2n * 1024n ** 4n, 0),
    onion: ids[5].onion,
    onionSeedHex: ids[5].seed,
    now: reportEnd,
  });
  assert.deepEqual(await aggregator.accept(implausible.report), { ok: false, reason: "implausible-delta" });

  const wrapped = structuredClone(reports[5].report);
  wrapped.counters.agentToDestinationBytes = (1n << 64n).toString();
  wrapped.signature = ed25519Sign(Buffer.from(JSON.stringify(relayReportSigningPayload(wrapped))), ids[5].seed);
  assert.equal(verifyRelayReport(wrapped), false, "u64 wraparound-sized counter fails exact validation");

  const unknown = identity();
  const unknownReport = buildRelayReport({ counter: counter("ef".repeat(16), reportStart, 1, 1), onion: unknown.onion, onionSeedHex: unknown.seed, now: reportEnd });
  assert.deepEqual(await aggregator.accept(unknownReport.report), { ok: false, reason: "not-announced" });

  const empty = makeRelayAggregator({ signer, now: () => now, isAnnounced: () => true }).snapshot();
  assert.equal(empty.windows.sixHour.status, "suppressed");
  assert.equal(empty.windows.sixHour.suppressionReason, "unavailable");
  assert.equal("roundedBytes" in empty.windows.sixHour, false);

  assert.equal(validRelayCounterState({ ...localState, counters: { ...localState.counters, destination: "forbidden" } }), false, "counter exact-key validation rejects metadata grafts");
  assert.equal(readFileSync(counterPath, "utf8").includes("destination\""), false, "node state contains no destination label");
  console.log("PASS: private relay telemetry accounting, validation, aggregation, suppression, and privacy");
} finally {
  rmSync(temp, { recursive: true, force: true });
}
