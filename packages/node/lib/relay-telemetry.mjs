// Privacy-preserving relay-byte telemetry.
//
// The gateway keeps two node-local, unsigned-64-bit payload counters. A separate heartbeat
// process reads that state and, only when the operator opts in, sends an onion-key-signed report
// to the Elder Tree. The public side receives only delayed, rounded cohort aggregates: raw node
// identities and raw byte deltas never leave the Elder's private aggregator.

import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { ed25519Sign, ed25519Verify, verifyOnionControl } from "./directory.mjs";

export const RELAY_COUNTER_SCHEMA = "shade-tree-relay-counter-v1";
export const RELAY_REPORT_STATE_SCHEMA = "shade-tree-relay-report-state-v1";
export const RELAY_REPORT_SCHEMA = "shade-tree-relay-report-v1";
export const RELAY_AGGREGATE_SCHEMA = "shade-tree-relay-aggregate-v1";
export const RELAY_ELDER_STATE_SCHEMA = "shade-tree-relay-elder-state-v1";
export const GROVE_RELAY_SCHEMA = "shade-tree-public-grove-v2";
export const RELAY_MINIMUM_COHORT = 5;
export const RELAY_DELAY_HOURS = 6;
export const RELAY_ROUNDING_BUCKET_BYTES = 1024n * 1024n * 1024n; // 1 GiB
export const RELAY_WINDOWS = Object.freeze([
  Object.freeze({ key: "sixHour", hours: 6 }),
  Object.freeze({ key: "twentyFourHour", hours: 24 }),
]);

const MAX_U64 = (1n << 64n) - 1n;
const DEFAULT_MAX_BYTES_PER_SECOND = 2n * 1024n * 1024n * 1024n; // 16 Gibit/s combined payload
const DEFAULT_MAX_INTERVAL_MS = 24 * 60 * 60_000;
const DEFAULT_FUTURE_SKEW_MS = 5 * 60_000;
const DEFAULT_RETENTION_MS = 36 * 60 * 60_000;
const HOUR_MS = 60 * 60_000;

function exactKeys(value, keys) {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && Object.keys(value).sort().join(",") === [...keys].sort().join(",");
}

function isoMillis(value) {
  if (typeof value !== "string") return NaN;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : NaN;
}

function u64(value) {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,19})$/.test(value)) return null;
  try {
    const parsed = BigInt(value);
    return parsed <= MAX_U64 ? parsed : null;
  } catch {
    return null;
  }
}

function atomicJson(path, value) {
  if (!path) return;
  mkdirSync(dirname(path), { recursive: true });
  const temp = `${path}.tmp`;
  writeFileSync(temp, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  renameSync(temp, path);
}

function readJson(path) {
  if (!path) return null;
  try { return JSON.parse(readFileSync(path, "utf8")); } catch { return null; }
}

function byteLength(value) {
  if (Buffer.isBuffer(value) || ArrayBuffer.isView(value)) return value.byteLength;
  if (typeof value === "string") return Buffer.byteLength(value);
  const size = Number(value);
  return Number.isSafeInteger(size) && size >= 0 ? size : 0;
}

// Node-local counter source. State is intentionally unlabeled: no destination, member,
// nullifier, flow, payment, error, or tunnel identifier can be attached. A new random bootId on
// every process start makes resets explicit. Counters remain BigInt in memory and decimal strings
// on disk so they never silently wrap through Number precision.
export function makeRelayByteCounter({
  enabled = true,
  path = null,
  now = () => Date.now(),
  bootId = randomBytes(16).toString("hex"),
  flushIntervalMs = 5_000,
  setTimer = setInterval,
  clearTimer = clearInterval,
} = {}) {
  const startedAt = new Date(now()).toISOString();
  let agentToDestination = 0n;
  let destinationToAgent = 0n;
  let dirty = true;
  let timer = null;

  function add(which, chunk) {
    if (!enabled) return 0;
    const amount = BigInt(byteLength(chunk));
    if (amount <= 0n) return 0;
    if (which === "agent") {
      if (agentToDestination + amount > MAX_U64) throw new Error("relay counter overflow");
      agentToDestination += amount;
    } else {
      if (destinationToAgent + amount > MAX_U64) throw new Error("relay counter overflow");
      destinationToAgent += amount;
    }
    dirty = true;
    return Number(amount);
  }

  function snapshot() {
    return {
      schema: RELAY_COUNTER_SCHEMA,
      bootId,
      startedAt,
      updatedAt: new Date(now()).toISOString(),
      counters: {
        agentToDestinationBytes: agentToDestination.toString(),
        destinationToAgentBytes: destinationToAgent.toString(),
      },
    };
  }

  function flush() {
    const value = snapshot();
    if (enabled && path && dirty) {
      atomicJson(path, value);
      dirty = false;
    }
    return value;
  }

  if (enabled && path && flushIntervalMs > 0) {
    flush();
    timer = setTimer(flush, flushIntervalMs);
    timer.unref?.();
  }

  return {
    enabled,
    path,
    addAgentToDestination: (chunk) => add("agent", chunk),
    addDestinationToAgent: (chunk) => add("destination", chunk),
    snapshot,
    flush,
    close() {
      if (timer) clearTimer(timer);
      timer = null;
      return flush();
    },
  };
}

export function validRelayCounterState(value) {
  const startedAt = isoMillis(value?.startedAt);
  const updatedAt = isoMillis(value?.updatedAt);
  return exactKeys(value, ["schema", "bootId", "startedAt", "updatedAt", "counters"])
    && value.schema === RELAY_COUNTER_SCHEMA
    && /^[0-9a-f]{32}$/.test(value.bootId)
    && Number.isFinite(startedAt)
    && Number.isFinite(updatedAt)
    && updatedAt >= startedAt
    && exactKeys(value.counters, ["agentToDestinationBytes", "destinationToAgentBytes"])
    && u64(value.counters.agentToDestinationBytes) !== null
    && u64(value.counters.destinationToAgentBytes) !== null;
}

export function readRelayCounterState(path) {
  const value = readJson(path);
  if (!validRelayCounterState(value)) throw new Error("relay counter state unavailable");
  return value;
}

function validReportState(value) {
  if (value === null) return true;
  return exactKeys(value, ["schema", "sequence", "bootId", "intervalEnd", "counters"])
    && value.schema === RELAY_REPORT_STATE_SCHEMA
    && Number.isSafeInteger(value.sequence)
    && value.sequence >= 0
    && /^[0-9a-f]{32}$/.test(value.bootId)
    && Number.isFinite(isoMillis(value.intervalEnd))
    && exactKeys(value.counters, ["agentToDestinationBytes", "destinationToAgentBytes"])
    && u64(value.counters.agentToDestinationBytes) !== null
    && u64(value.counters.destinationToAgentBytes) !== null;
}

export function readRelayReportState(path) {
  const value = readJson(path);
  return validReportState(value) ? value : null;
}

export function writeRelayReportState(path, state) {
  if (!validReportState(state) || state === null) throw new Error("invalid relay report state");
  atomicJson(path, state);
}

export function relayReportSigningPayload(report) {
  return {
    schema: report.schema,
    onion: report.onion,
    bootId: report.bootId,
    sequence: report.sequence,
    intervalStart: report.intervalStart,
    intervalEnd: report.intervalEnd,
    counters: {
      agentToDestinationBytes: report.counters.agentToDestinationBytes,
      destinationToAgentBytes: report.counters.destinationToAgentBytes,
    },
    reset: {
      occurred: report.reset.occurred,
      reason: report.reset.reason,
    },
  };
}

function relayReportSigningBytes(report) {
  return Buffer.from(JSON.stringify(relayReportSigningPayload(report)), "utf8");
}

export function buildRelayReport({ counter, previous = null, onion, onionSeedHex, now = Date.now() } = {}) {
  if (!validRelayCounterState(counter)) throw new Error("valid relay counter state required");
  if (previous !== null && !validReportState(previous)) throw new Error("invalid prior relay report state");
  const endMs = Number(now);
  if (!Number.isFinite(endMs)) throw new Error("invalid relay report time");
  const sameBoot = previous?.bootId === counter.bootId;
  const start = sameBoot ? previous.intervalEnd : counter.startedAt;
  const startMs = isoMillis(start);
  if (!Number.isFinite(startMs) || startMs >= endMs) throw new Error("relay report interval is empty");
  if (sameBoot) {
    const priorA = u64(previous.counters.agentToDestinationBytes);
    const priorB = u64(previous.counters.destinationToAgentBytes);
    if (u64(counter.counters.agentToDestinationBytes) < priorA
      || u64(counter.counters.destinationToAgentBytes) < priorB) {
      throw new Error("relay counter rollback");
    }
  }
  const report = {
    schema: RELAY_REPORT_SCHEMA,
    onion,
    bootId: counter.bootId,
    sequence: (previous?.sequence || 0) + 1,
    intervalStart: new Date(startMs).toISOString(),
    intervalEnd: new Date(endMs).toISOString(),
    counters: {
      agentToDestinationBytes: counter.counters.agentToDestinationBytes,
      destinationToAgentBytes: counter.counters.destinationToAgentBytes,
    },
    reset: {
      occurred: !sameBoot,
      reason: sameBoot ? null : "process-start",
    },
  };
  report.signature = ed25519Sign(relayReportSigningBytes(report), onionSeedHex);
  const nextState = {
    schema: RELAY_REPORT_STATE_SCHEMA,
    sequence: report.sequence,
    bootId: report.bootId,
    intervalEnd: report.intervalEnd,
    counters: { ...report.counters },
  };
  return { report, nextState };
}

export function validRelayReport(report) {
  const start = isoMillis(report?.intervalStart);
  const end = isoMillis(report?.intervalEnd);
  return exactKeys(report, ["schema", "onion", "bootId", "sequence", "intervalStart", "intervalEnd", "counters", "reset", "signature"])
    && report.schema === RELAY_REPORT_SCHEMA
    && typeof report.onion === "string"
    && /^[0-9a-f]{32}$/.test(report.bootId)
    && Number.isSafeInteger(report.sequence)
    && report.sequence >= 1
    && Number.isFinite(start)
    && Number.isFinite(end)
    && start < end
    && exactKeys(report.counters, ["agentToDestinationBytes", "destinationToAgentBytes"])
    && u64(report.counters.agentToDestinationBytes) !== null
    && u64(report.counters.destinationToAgentBytes) !== null
    && exactKeys(report.reset, ["occurred", "reason"])
    && typeof report.reset.occurred === "boolean"
    && (report.reset.occurred ? report.reset.reason === "process-start" : report.reset.reason === null)
    && /^[0-9a-f]{128}$/i.test(report.signature || "");
}

export function verifyRelayReport(report) {
  return validRelayReport(report)
    && verifyOnionControl(report.onion, relayReportSigningBytes(report), report.signature);
}

function roundedUp(value, bucket) {
  return value <= 0n ? 0n : ((value + bucket - 1n) / bucket) * bucket;
}

function suppressionReason(reporters, total, minimumCohort) {
  if (reporters === 0) return "unavailable";
  if (reporters < minimumCohort) return "minimum-cohort";
  if (total === 0n) return "unavailable";
  return null;
}

export function relayAggregateSigningPayload(aggregate) {
  return {
    schema: aggregate.schema,
    generatedAt: aggregate.generatedAt,
    definition: aggregate.definition,
    unit: aggregate.unit,
    delayHours: aggregate.delayHours,
    minimumCohort: aggregate.minimumCohort,
    rounding: {
      method: aggregate.rounding.method,
      bucketBytes: aggregate.rounding.bucketBytes,
    },
    windows: Object.fromEntries(RELAY_WINDOWS.map(({ key }) => [key, { ...aggregate.windows[key] }])),
    signer: aggregate.signer,
  };
}

function aggregateSigningBytes(aggregate) {
  return Buffer.from(JSON.stringify(relayAggregateSigningPayload(aggregate)), "utf8");
}

export function verifyRelayAggregate(aggregate, pinnedSigner) {
  if (!validRelayAggregate(aggregate) || aggregate.signer !== pinnedSigner) return false;
  return ed25519Verify(aggregateSigningBytes(aggregate), aggregate.signature, aggregate.signer);
}

export function validRelayAggregate(value) {
  const generatedAt = isoMillis(value?.generatedAt);
  const validWindow = (window, hours) => {
    const start = isoMillis(window?.windowStart);
    const end = isoMillis(window?.windowEnd);
    const base = exactKeys(window, window?.status === "available"
      ? ["status", "windowHours", "windowStart", "windowEnd", "reportingNodes", "roundedBytes"]
      : ["status", "windowHours", "windowStart", "windowEnd", "reportingNodes", "suppressionReason"])
      && window.windowHours === hours
      && Number.isFinite(start)
      && Number.isFinite(end)
      && end - start === hours * HOUR_MS
      && end <= generatedAt - value.delayHours * HOUR_MS
      && Number.isInteger(window.reportingNodes)
      && window.reportingNodes >= 0
      && window.reportingNodes <= 100_000;
    if (!base) return false;
    if (window.status === "available") {
      const rounded = u64(window.roundedBytes);
      return window.reportingNodes >= value.minimumCohort
        && rounded !== null
        && rounded > 0n
        && rounded % u64(value.rounding.bucketBytes) === 0n;
    }
    return window.status === "suppressed"
      && ["minimum-cohort", "unavailable"].includes(window.suppressionReason)
      && window.roundedBytes === undefined;
  };
  return exactKeys(value, ["schema", "generatedAt", "definition", "unit", "delayHours", "minimumCohort", "rounding", "windows", "signer", "signature"])
    && value.schema === RELAY_AGGREGATE_SCHEMA
    && Number.isFinite(generatedAt)
    && value.definition === "payload-bytes-relayed"
    && value.unit === "bytes"
    && value.delayHours >= RELAY_DELAY_HOURS
    && value.minimumCohort >= RELAY_MINIMUM_COHORT
    && exactKeys(value.rounding, ["method", "bucketBytes"])
    && value.rounding.method === "ceiling"
    && u64(value.rounding.bucketBytes) !== null
    && u64(value.rounding.bucketBytes) > 0n
    && exactKeys(value.windows, RELAY_WINDOWS.map(({ key }) => key))
    && RELAY_WINDOWS.every(({ key, hours }) => validWindow(value.windows[key], hours))
    && /^[0-9a-f]{64}$/i.test(value.signer || "")
    && /^[0-9a-f]{128}$/i.test(value.signature || "");
}

export function makeRelayAggregator({
  signer,
  now = () => Date.now(),
  isAnnounced = () => false,
  statePath = null,
  minimumCohort = RELAY_MINIMUM_COHORT,
  delayHours = RELAY_DELAY_HOURS,
  bucketBytes = RELAY_ROUNDING_BUCKET_BYTES,
  maxBytesPerSecond = DEFAULT_MAX_BYTES_PER_SECOND,
  maxIntervalMs = DEFAULT_MAX_INTERVAL_MS,
  futureSkewMs = DEFAULT_FUTURE_SKEW_MS,
  retentionMs = DEFAULT_RETENTION_MS,
} = {}) {
  if (!signer?.pub || !signer?.priv) throw new Error("Elder relay signer required");
  if (minimumCohort < RELAY_MINIMUM_COHORT) throw new Error("relay minimum cohort cannot be below five");
  if (delayHours < RELAY_DELAY_HOURS) throw new Error("relay publication delay cannot be below six hours");
  const nodes = new Map();
  let contributions = [];

  function checkpoint() {
    if (!statePath) return;
    atomicJson(statePath, {
      schema: RELAY_ELDER_STATE_SCHEMA,
      nodes: [...nodes.entries()].map(([onion, entry]) => ({
        onion,
        sequence: entry.sequence,
        bootId: entry.bootId,
        end: new Date(entry.end).toISOString(),
        counters: {
          agentToDestinationBytes: entry.agentToDestination.toString(),
          destinationToAgentBytes: entry.destinationToAgent.toString(),
        },
      })),
    });
  }

  function loadCheckpoint() {
    if (!statePath || !existsSync(statePath)) return;
    let stored;
    try { stored = JSON.parse(readFileSync(statePath, "utf8")); }
    catch { throw new Error("invalid Elder relay checkpoint"); }
    if (!exactKeys(stored, ["schema", "nodes"]) || stored.schema !== RELAY_ELDER_STATE_SCHEMA
      || !Array.isArray(stored.nodes) || stored.nodes.length > 100_000) throw new Error("invalid Elder relay checkpoint");
    for (const entry of stored.nodes) {
      const end = isoMillis(entry?.end);
      if (!exactKeys(entry, ["onion", "sequence", "bootId", "end", "counters"])
        || typeof entry.onion !== "string"
        || !Number.isSafeInteger(entry.sequence) || entry.sequence < 1
        || !/^[0-9a-f]{32}$/.test(entry.bootId)
        || !Number.isFinite(end)
        || !exactKeys(entry.counters, ["agentToDestinationBytes", "destinationToAgentBytes"])
        || u64(entry.counters.agentToDestinationBytes) === null
        || u64(entry.counters.destinationToAgentBytes) === null
        || nodes.has(entry.onion)) throw new Error("invalid Elder relay checkpoint");
      nodes.set(entry.onion, {
        sequence: entry.sequence,
        bootId: entry.bootId,
        end,
        agentToDestination: u64(entry.counters.agentToDestinationBytes),
        destinationToAgent: u64(entry.counters.destinationToAgentBytes),
      });
    }
  }

  loadCheckpoint();

  function prune(at = now()) {
    const oldest = at - retentionMs;
    contributions = contributions.filter((entry) => entry.end >= oldest);
    let changed = false;
    for (const [onion, entry] of nodes) if (entry.end < oldest) { nodes.delete(onion); changed = true; }
    if (changed) checkpoint();
  }

  function reject(reason) { return { ok: false, reason }; }

  async function accept(report) {
    const current = now();
    prune(current);
    if (!validRelayReport(report)) return reject("bad-report");
    if (!verifyRelayReport(report)) return reject("bad-signature");
    if (!await isAnnounced(report.onion)) return reject("not-announced");
    const start = isoMillis(report.intervalStart);
    const end = isoMillis(report.intervalEnd);
    const duration = end - start;
    if (end > current + futureSkewMs) return reject("future-interval");
    if (end < current - retentionMs) return reject("stale-interval");
    if (duration > maxIntervalMs) return reject("interval-too-long");

    const previous = nodes.get(report.onion);
    if (previous && report.sequence <= previous.sequence) return reject("sequence-replay");
    if (previous && start < previous.end) return reject("interval-overlap");

    const currentA = u64(report.counters.agentToDestinationBytes);
    const currentB = u64(report.counters.destinationToAgentBytes);
    let deltaA, deltaB;
    if (!previous) {
      if (!report.reset.occurred) return reject("missing-reset");
      deltaA = currentA;
      deltaB = currentB;
    } else if (previous.bootId === report.bootId) {
      if (report.reset.occurred) return reject("unexpected-reset");
      if (currentA < previous.agentToDestination || currentB < previous.destinationToAgent) return reject("counter-rollback");
      deltaA = currentA - previous.agentToDestination;
      deltaB = currentB - previous.destinationToAgent;
    } else {
      if (!report.reset.occurred) return reject("missing-reset");
      deltaA = currentA;
      deltaB = currentB;
    }

    const allowed = BigInt(Math.ceil(duration / 1000)) * BigInt(maxBytesPerSecond);
    if (deltaA + deltaB > allowed) return reject("implausible-delta");

    nodes.set(report.onion, {
      sequence: report.sequence,
      bootId: report.bootId,
      end,
      agentToDestination: currentA,
      destinationToAgent: currentB,
    });
    contributions.push({ onion: report.onion, start, end, agentToDestination: deltaA, destinationToAgent: deltaB });
    checkpoint();
    return { ok: true };
  }

  function aggregateWindow(windowEnd, hours) {
    const windowStart = windowEnd - hours * HOUR_MS;
    const eligible = contributions.filter((entry) => entry.start >= windowStart && entry.end <= windowEnd);
    const reporters = new Set(eligible.map((entry) => entry.onion)).size;
    const total = eligible.reduce((sum, entry) => sum + entry.agentToDestination + entry.destinationToAgent, 0n);
    const common = {
      windowHours: hours,
      windowStart: new Date(windowStart).toISOString(),
      windowEnd: new Date(windowEnd).toISOString(),
      reportingNodes: reporters,
    };
    const reason = suppressionReason(reporters, total, minimumCohort);
    return reason
      ? { status: "suppressed", ...common, suppressionReason: reason }
      : { status: "available", ...common, roundedBytes: roundedUp(total, BigInt(bucketBytes)).toString() };
  }

  function snapshot() {
    const current = now();
    prune(current);
    // Stable 15-minute publication timestamp: repeated reads inside one collection cadence are
    // byte-identical and share an ETag instead of producing a new signed body every millisecond.
    const generatedAtMs = Math.floor(current / (15 * 60_000)) * 15 * 60_000;
    const generatedAt = new Date(generatedAtMs).toISOString();
    const delayed = current - delayHours * HOUR_MS;
    const windowEnd = Math.floor(delayed / HOUR_MS) * HOUR_MS;
    const aggregate = {
      schema: RELAY_AGGREGATE_SCHEMA,
      generatedAt,
      definition: "payload-bytes-relayed",
      unit: "bytes",
      delayHours,
      minimumCohort,
      rounding: { method: "ceiling", bucketBytes: BigInt(bucketBytes).toString() },
      windows: Object.fromEntries(RELAY_WINDOWS.map(({ key, hours }) => [key, aggregateWindow(windowEnd, hours)])),
      signer: signer.pub,
    };
    aggregate.signature = ed25519Sign(aggregateSigningBytes(aggregate), signer.priv);
    return aggregate;
  }

  return {
    accept,
    snapshot,
    prune,
    rawContributionCount: () => contributions.length,
    rawNodeCount: () => nodes.size,
  };
}

// Allowlisted public projection for Grove v2. This drops the Elder signer and signature after the
// collector verifies them: Grove's own attestation signs the projection. The projection contains
// coverage counts and suppression reasons, never a node identity or raw contribution.
export function publicRelayFromAggregate(aggregate, pinnedSigner) {
  if (!verifyRelayAggregate(aggregate, pinnedSigner)) throw new Error("invalid signed relay aggregate");
  return {
    definition: aggregate.definition,
    unit: aggregate.unit,
    generatedAt: aggregate.generatedAt,
    delayHours: aggregate.delayHours,
    minimumCohort: aggregate.minimumCohort,
    rounding: { ...aggregate.rounding },
    windows: Object.fromEntries(RELAY_WINDOWS.map(({ key }) => [key, { ...aggregate.windows[key] }])),
  };
}

export function validPublicRelay(value, { observedAt = null } = {}) {
  const generatedAt = isoMillis(value?.generatedAt);
  const observedAtMs = observedAt === null ? null : isoMillis(observedAt);
  const synthetic = {
    schema: RELAY_AGGREGATE_SCHEMA,
    ...value,
    signer: "00".repeat(32),
    signature: "00".repeat(64),
  };
  return exactKeys(value, ["definition", "unit", "generatedAt", "delayHours", "minimumCohort", "rounding", "windows"])
    && validRelayAggregate(synthetic)
    && (observedAtMs === null
      || (Number.isFinite(observedAtMs)
        && generatedAt >= observedAtMs - HOUR_MS
        && generatedAt <= observedAtMs + DEFAULT_FUTURE_SKEW_MS));
}
