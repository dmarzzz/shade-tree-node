// Privacy-preserving public view of the Shade Tree fleet.
//
// Input is a directory that has ALREADY passed verifyDirectory() against a pinned signer.
// Output is an allowlisted aggregate: a count, timestamps, and a bounded count history. No
// gateway field is copied through, so onions, pubkeys, operators, capabilities, locations,
// traffic, and stable node identifiers cannot reach the public snapshot by construction.

import {
  createPrivateKey,
  createPublicKey,
  sign as signBytes,
  verify as verifyBytes,
} from "node:crypto";
import { GROVE_RELAY_SCHEMA, validPublicRelay } from "./relay-telemetry.mjs";
import { onchainSigningPayload, validPublicOnchainActivity } from "./grove-onchain.mjs";

export const GROVE_SCHEMA = "shade-tree-public-grove-v1";
export const GROVE_SCHEMA_V2 = GROVE_RELAY_SCHEMA;
// A 24-hour window at a 15-minute cadence has 96 intervals and therefore needs
// 97 boundary samples, including both the window start and the current sample.
export const GROVE_HISTORY_CAP = 97;
export const GROVE_ATTESTATION_KEY_ID = "grove-2026-08";

function asIso(value) {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new Error("invalid grove observation time");
  return date.toISOString();
}

function safeCount(value) {
  return Number.isInteger(value) && value >= 0 && value <= 100_000 ? value : null;
}

// Previous snapshots are untrusted public data. Read only the two aggregate sample fields we
// understand, reject future/ancient/malformed samples, dedupe by timestamp, and cap the result.
// This also ensures a sensitive field accidentally added to an older snapshot is never carried
// into the next one.
export function scrubGroveHistory(previous, {
  now = new Date(),
  cap = GROVE_HISTORY_CAP,
  maxAgeHours = 48,
} = {}) {
  const nowMs = new Date(now).getTime();
  const oldest = nowMs - maxAgeHours * 60 * 60 * 1000;
  const newest = nowMs + 5 * 60 * 1000;
  const byTime = new Map();
  for (const raw of Array.isArray(previous?.history) ? previous.history : []) {
    const atMs = Date.parse(raw?.at);
    const announced = safeCount(raw?.announced);
    if (!Number.isFinite(atMs) || atMs < oldest || atMs > newest || announced === null) continue;
    const at = new Date(atMs).toISOString();
    byTime.set(at, { at, announced });
  }
  return [...byTime.values()]
    .sort((a, b) => Date.parse(a.at) - Date.parse(b.at))
    .slice(-Math.max(1, cap));
}

// Approximate aggregate node-hours over the requested window. We carry the earlier sample's
// count forward only until the next observation, and cap any gap so a stalled collector cannot
// invent hours of availability. The public value is floored to a whole hour.
export function aggregateAnnouncedNodeHours(history, {
  now = new Date(),
  windowHours = 24,
  maxGapMinutes = 30,
} = {}) {
  if (!Array.isArray(history) || history.length < 2) return null;
  const end = new Date(now).getTime();
  const start = end - windowHours * 60 * 60 * 1000;
  const maxGapMs = maxGapMinutes * 60 * 1000;
  let nodeMs = 0;
  for (let index = 0; index < history.length - 1; index += 1) {
    const sample = history[index];
    const next = history[index + 1];
    const sampleAt = Date.parse(sample.at);
    const from = Math.max(start, sampleAt);
    // Expire the carried count relative to the observation itself, before
    // clipping the interval to the requested window. Otherwise an already
    // expired sample just outside the window can be credited inside it.
    const to = Math.min(end, Date.parse(next.at), sampleAt + maxGapMs);
    if (to > from) nodeMs += sample.announced * (to - from);
  }
  return Math.floor(nodeMs / (60 * 60 * 1000));
}

export function buildPublicGroveSnapshot({
  directory,
  previous = null,
  previousPublicKey = null,
  observedAt = new Date(),
  network = "unknown",
  cadenceMinutes = 15,
  relay = null,
  onchain = null,
} = {}) {
  if (!directory || !Array.isArray(directory.gateways)) throw new Error("verified directory required");
  if (!Number.isInteger(cadenceMinutes) || cadenceMinutes < 5 || cadenceMinutes > 60) throw new Error("invalid Grove cadence");
  // Public time is cadence-bucketed. Exact heartbeat/directory timing is unnecessary for this
  // view and would make longitudinal differencing needlessly precise.
  const observedMs = new Date(observedAt).getTime();
  const bucketMs = cadenceMinutes * 60 * 1000;
  const observed = asIso(new Date(Math.floor(observedMs / bucketMs) * bucketMs));
  const networkCandidate = String(network || "unknown").toLowerCase().slice(0, 32);
  const publicNetwork = /^[a-z0-9][a-z0-9_-]{0,31}$/.test(networkCandidate) ? networkCandidate : "unknown";
  const announced = directory.gateways.length;
  if (safeCount(announced) === null) throw new Error("directory too large for public Grove");
  // The prior branch is public mutable input. Carry it forward only when its attestation verifies
  // and it belongs to this exact schema/network/cadence; otherwise begin a clean history.
  const compatiblePrevious = previousPublicKey
    && (previous?.schema === GROVE_SCHEMA || previous?.schema === GROVE_SCHEMA_V2)
    && previous?.network === publicNetwork
    && previous?.source?.cadenceMinutes === cadenceMinutes
    && previous?.source?.bootnodeReachable === true
    && previous?.source?.directoryVerified === true
    && previous?.source?.definition === "announced-within-ttl"
    && verifyPublicGroveAttestation(previous, previousPublicKey)
    ? previous
    : null;
  const history = scrubGroveHistory(compatiblePrevious, { now: observed, cap: GROVE_HISTORY_CAP });
  history.push({ at: observed, announced });
  const boundedHistory = scrubGroveHistory({ history }, { now: observed, cap: GROVE_HISTORY_CAP });

  if (relay !== null && !validPublicRelay(relay, { observedAt: observed })) throw new Error("invalid public relay aggregate");
  if (onchain !== null && relay === null) throw new Error("Grove v2 onchain activity requires the v2 relay envelope");
  if (onchain !== null && !validPublicOnchainActivity(onchain, { observedAt: observed })) throw new Error("invalid public onchain aggregate");
  return {
    schema: relay === null ? GROVE_SCHEMA : GROVE_SCHEMA_V2,
    network: publicNetwork,
    observedAt: observed,
    source: {
      bootnodeReachable: true,
      directoryVerified: true,
      definition: "announced-within-ttl",
      cadenceMinutes,
    },
    nodes: { announced },
    growth: {
      windowHours: 24,
      announcedNodeHours: aggregateAnnouncedNodeHours(boundedHistory, { now: observed }),
      samples: boundedHistory.length,
    },
    privacy: {
      identities: false,
      locations: false,
      traffic: false,
      stablePositions: false,
      futureSharedStatsMinReportingNodes: 5,
    },
    history: boundedHistory,
    ...(relay === null ? {} : { relay }),
    ...(onchain === null ? {} : { onchain }),
  };
}

// Canonical, allowlisted signing payload. Attestation metadata is deliberately excluded, and no
// caller-provided object is spread into the payload. The browser reconstructs this same field
// order before verifying the Ed25519 signature.
export function groveSigningPayload(snapshot) {
  const payload = {
    schema: snapshot.schema,
    network: snapshot.network,
    observedAt: snapshot.observedAt,
    source: {
      bootnodeReachable: snapshot.source.bootnodeReachable,
      directoryVerified: snapshot.source.directoryVerified,
      definition: snapshot.source.definition,
      cadenceMinutes: snapshot.source.cadenceMinutes,
    },
    nodes: {
      announced: snapshot.nodes.announced,
    },
    growth: {
      windowHours: snapshot.growth.windowHours,
      announcedNodeHours: snapshot.growth.announcedNodeHours,
      samples: snapshot.growth.samples,
    },
    privacy: {
      identities: snapshot.privacy.identities,
      locations: snapshot.privacy.locations,
      traffic: snapshot.privacy.traffic,
      stablePositions: snapshot.privacy.stablePositions,
      futureSharedStatsMinReportingNodes: snapshot.privacy.futureSharedStatsMinReportingNodes,
    },
    history: snapshot.history.map((sample) => ({
      at: sample.at,
      announced: sample.announced,
    })),
  };
  // v1 returns exactly the historical payload above. v2 appends one isolated top-level section
  // so future Grove domains (membership/payments/slashing) can compose beside it independently.
  if (snapshot.schema === GROVE_SCHEMA_V2) {
    payload.relay = {
      definition: snapshot.relay.definition,
      unit: snapshot.relay.unit,
      generatedAt: snapshot.relay.generatedAt,
      delayHours: snapshot.relay.delayHours,
      minimumCohort: snapshot.relay.minimumCohort,
      rounding: {
        method: snapshot.relay.rounding.method,
        bucketBytes: snapshot.relay.rounding.bucketBytes,
      },
      windows: {
        sixHour: { ...snapshot.relay.windows.sixHour },
        twentyFourHour: { ...snapshot.relay.windows.twentyFourHour },
      },
    };
    if (snapshot.onchain !== undefined) payload.onchain = onchainSigningPayload(snapshot.onchain);
  }
  return payload;
}

function signingBytes(snapshot) {
  return Buffer.from(JSON.stringify(groveSigningPayload(snapshot)), "utf8");
}

export function attestPublicGroveSnapshot(snapshot, privateKeyPem, {
  keyId = GROVE_ATTESTATION_KEY_ID,
} = {}) {
  if (!privateKeyPem) throw new Error("public Grove signing key required");
  const privateKey = createPrivateKey(privateKeyPem);
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("public Grove signing key must be Ed25519");
  const signature = signBytes(null, signingBytes(snapshot), privateKey).toString("base64");
  return {
    ...snapshot,
    attestation: { algorithm: "Ed25519", keyId, signature },
  };
}

export function verifyPublicGroveAttestation(snapshot, publicKeyPem, {
  keyId = GROVE_ATTESTATION_KEY_ID,
} = {}) {
  const attestation = snapshot?.attestation;
  if (attestation?.algorithm !== "Ed25519" || attestation?.keyId !== keyId) return false;
  if (!/^[A-Za-z0-9+/]{86}==$/.test(attestation.signature || "")) return false;
  try {
    const publicKey = createPublicKey(publicKeyPem);
    return publicKey.asymmetricKeyType === "ed25519"
      && verifyBytes(null, signingBytes(snapshot), publicKey, Buffer.from(attestation.signature, "base64"));
  } catch {
    return false;
  }
}

export function grovePublicKeyRawBase64(publicKeyPem) {
  const publicKey = createPublicKey(publicKeyPem);
  if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("public Grove key must be Ed25519");
  const der = publicKey.export({ type: "spki", format: "der" });
  return der.subarray(-32).toString("base64");
}
