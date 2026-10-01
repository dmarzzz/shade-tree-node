// Gateway heartbeat: keep this gateway listed on the bootnode.
//
// A bootnode entry is soft-state with a TTL (packages/node/bootnode/server.mjs): the gateway must re-announce
// periodically or it drops from the fleet. That is deliberate — liveness is proven by continuing
// to announce, so a dead gateway ages out without anyone deregistering it. This loop builds a
// fresh signed announce (fresh ts + nonce) from the gateway's onion identity and POSTs it to the
// bootnode onion over Tor, every SHADE_TREE_BOOTNODE_HEARTBEAT seconds.
//
// Config:
//   SHADE_TREE_BOOTNODE_ONION     the bootnode to announce to (required; or via SHADE_TREE_NETWORK, see packages/node/lib/network-record.mjs)
//   SHADE_TREE_BOOTNODE_ONIONS    every Elder Tree of the canopy, comma-separated (ADR 0012; filled
//                           from the record's elders[] by SHADE_TREE_NETWORK). The heartbeat announces
//                           to each one every interval, so a node stays listed on every Elder and
//                           a client that fails over to the second Elder still finds a fresh canopy
//   SHADE_TREE_GW_IDENTITY        path to the onion identity.local.json { onion, seed }
//                           (packages/node/bootnode/keygen.mjs; default tor/hs/identity.local.json)
//   SHADE_TREE_GW_WEIGHT          selection weight advertised                    (default 100)
//   SHADE_TREE_BOOTNODE_HEARTBEAT re-announce interval in seconds                (default 300)
//   SHADE_TREE_TOR_HOST/PORT      local Tor SOCKS                                (default 127.0.0.1:9250)
//   capability advertisement (optional, T-FEAT-10b — OFF/byte-identical when both unset):
//   SHADE_TREE_EGRESS_ALLOW       the gateway's egress policy (also read by packages/node/gateway/gateway.mjs);
//                           when SET, its concrete allowed ports are advertised as signed caps
//   SHADE_TREE_GATEWAY_REGION     a coarse self-declared region bucket (REGION_BUCKETS; e.g. `eu`)
//   SHADE_TREE_ZK_ARTIFACTS       the gateway's accepted ZK artifact set (also read by packages/node/lib/rln.mjs
//                           verifyEnvelope; T-HARD-8); when SET, its artifact ids are advertised
//                           as signed caps so clients pick a mutual set in a dual-VK window
//   SHADE_TREE_ADMIT              the gateway's ADMISSION POLICY (T-FEAT-9, also read by gateway.mjs);
//                           when SET (or its deprecated alias SHADE_TREE_ROOTS), the admitted paths
//                           are advertised as signed `caps.admits` so a client routes only to
//                           gateways that admit ITS leaf source (invited/staked/paid)
//   SHADE_TREE_REGISTRAR_ADVERTISE=1 + SHADE_TREE_PAY_ASSET/SHADE_TREE_PAY_PRICES[/SHADE_TREE_PAY_PROTOCOLS/
//   SHADE_TREE_REGISTRAR_PORT/SHADE_TREE_PAY_CHAIN_ID/SHADE_TREE_REGISTRAR_ONION]
//                           this provider SELLS access (T-FEAT-9): the same advert the bootnode
//                           puts in /health (packages/node/bootnode/server.mjs payAdvertFromEnv) rides in the
//                           gateway's signed caps as `caps.pay` (a gateway-only box has no
//                           bootnode /health to advertise on). SHADE_TREE_REGISTRAR_ONION names the
//                           onion the registrar rides when it is NOT the gateway's own
//   stake (optional, admission=stake bootnodes):
//   SHADE_TREE_GW_OPERATOR_KEY    operator EOA private key; signs the durable onion<->operator auth, OR
//   SHADE_TREE_GW_OPERATOR +      a pre-computed operator address and
//   SHADE_TREE_GW_OPERATOR_SIG    its signature over operatorAuthMessage(onion, operator)
//                           (the pair takes precedence over the key; any misconfiguration —
//                           half a pair, malformed key, sig that does not recover the
//                           operator — fails at startup; see resolveOperator)
//
// Selftest: packages/node/bootnode/heartbeat.selftest.mjs (operator resolution, announce bytes vs
// testdata/vectors.json, failure paths, log hygiene) + packages/node/bootnode/heartbeat-caps.selftest.mjs.

import { readFile } from "node:fs/promises";
import { loadCredentials } from "../lib/credentials.mjs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { buildAnnounce, operatorAuthMessage, verifyOperatorSig } from "./announce.mjs";
import { postOverTor } from "./fetch.mjs";
import { checkEgress, EGRESS_CHECK_TARGET, PROTO_RANGE } from "../gateway/gateway.mjs";
import { REGION_BUCKETS, canonicalCaps } from "../lib/directory.mjs";
import { loadArtifactSet } from "../lib/zk-artifacts.mjs";
import { parseAdmit, admitsFromRoots } from "../lib/admission.mjs";
import { payAdvertFromEnv } from "./server.mjs";
import { isPrivHex, isEthAddress } from "../lib/config.mjs";
import { applyNetworkEnv } from "../lib/network-record.mjs";
import { createLogger } from "../lib/log.mjs";
import { makeRegistry, installRuntimeMetrics, isLoopbackMetricsHost, listenMetrics, safeMetricsPort } from "../lib/metrics.mjs";
import { printOperatorBanner } from "../lib/operator-ui.mjs";
import { drainFilePath, drainPollMs, makeDrainWatcher } from "../lib/drain.mjs";
import { installAlerts, heartbeatRules } from "../lib/alerts.mjs";
import {
  buildRelayReport,
  readRelayCounterState,
  readRelayReportState,
  writeRelayReportState,
} from "../lib/relay-telemetry.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const heartbeatLog = createLogger("heartbeat");
// Heartbeat imports the Node and Elder modules for shared protocol helpers. Keep its scrape
// registry private so those modules' metrics never appear as misleading zero-value series here.
const metrics = makeRegistry();

const M = {
  attempts: metrics.counter("shade_tree_heartbeat_attempts_total", "Heartbeat cycles by bounded outcome=accepted|rejected|egress-unhealthy|transport-error."),
  lastSuccess: metrics.gauge("shade_tree_heartbeat_last_success_timestamp_seconds", "Unix timestamp of the last accepted heartbeat."),
  egressUp: metrics.gauge("shade_tree_heartbeat_egress_check_up", "1 when the latest local egress check succeeded, 0 when it failed."),
  // ADR 0012 fan-out: how many Elder Trees this heartbeat announces to, and how many accepted the
  // latest cycle. accepted < total while the fleet is healthy means one Elder is unreachable.
  eldersTotal: metrics.gauge("shade_tree_heartbeat_elders_total", "Elder Trees this heartbeat announces to (ADR 0012)."),
  eldersAccepted: metrics.gauge("shade_tree_heartbeat_elders_accepted", "Elder Trees that accepted the latest heartbeat cycle."),
  // Operator drain flag (lib/drain.mjs): 1 while the node announces `draining: true`.
  draining: metrics.gauge("shade_tree_heartbeat_draining", "1 while the operator drain flag is set and announced in the signed caps."),
};
M.eldersTotal.set(0);
M.eldersAccepted.set(0);
M.lastSuccess.set(0);

function writeLog(logger, level, message, fields, legacyMessage = message) {
  if (typeof logger === "function") return logger(legacyMessage);
  return logger?.[level]?.(message, fields);
}

// Every piece of the CLI path below takes its env + I/O as injectable arguments (defaulting to
// process.env / real fs / real ethers / real Tor) so packages/node/bootnode/heartbeat.selftest.mjs can drive
// each source/precedence path and each failure path with fakes — no Tor, no network, no chain.
// With the defaults, behaviour is byte-identical to the pre-refactor CLI.

export async function loadIdentity(env = process.env, { readFile: readFileFn = readFile } = {}) {
  const path = env.SHADE_TREE_GW_IDENTITY || join(HERE, "../../..", "tor", "hs", "identity.local.json");
  const id = JSON.parse(await readFileFn(path, "utf8"));
  if (!id || typeof id !== "object" || !id.onion || !id.seed) throw new Error(`identity file ${path} missing onion/seed (run packages/node/bootnode/keygen.mjs)`);
  return id;
}

// Resolve the optional operator-stake authorization once (it is durable across heartbeats).
// Precedence: a pre-computed (SHADE_TREE_GW_OPERATOR + SHADE_TREE_GW_OPERATOR_SIG) pair wins over
// SHADE_TREE_GW_OPERATOR_KEY; neither -> onion-only. Every misconfiguration FAILS FAST here (at
// startup) instead of surfacing as `announce rejected: bad-operator-sig` on every beat:
//   - a half-configured pair (operator without sig, or sig without operator) is an error, not a
//     silent downgrade to onion-only;
//   - a pre-computed sig is verified locally against the operator address before it is ever
//     sent (verifyOperatorSig — the same check the bootnode runs);
//   - a malformed SHADE_TREE_GW_OPERATOR_KEY is rejected by shape BEFORE it reaches ethers, whose
//     INVALID_ARGUMENT error would otherwise echo the mistyped key bytes into the message that
//     main() prints (log hygiene: the key value must never reach a log sink, mistyped or not).
export async function resolveOperator(onion, env = process.env, { importEthers = () => import("ethers") } = {}) {
  const operator = env.SHADE_TREE_GW_OPERATOR, operatorSig = env.SHADE_TREE_GW_OPERATOR_SIG, key = env.SHADE_TREE_GW_OPERATOR_KEY;
  if (operator && operatorSig) {
    if (!isEthAddress(operator)) throw new Error("SHADE_TREE_GW_OPERATOR is not a 0x-prefixed 20-byte address");
    if (!/^0x[0-9a-fA-F]{130}$/.test(String(operatorSig).trim())) throw new Error("SHADE_TREE_GW_OPERATOR_SIG is not a 65-byte 0x-hex personal_sign signature");
    if (!(await verifyOperatorSig(onion, operator, operatorSig))) {
      throw new Error(`SHADE_TREE_GW_OPERATOR_SIG does not recover SHADE_TREE_GW_OPERATOR for onion ${onion} (re-sign operatorAuthMessage with the operator key)`);
    }
    return { operator, operatorSig };
  }
  if (key) {
    if (!isPrivHex(key)) throw new Error("SHADE_TREE_GW_OPERATOR_KEY is not a 32-byte hex private key (64 hex, 0x optional)");
    const { ethers } = await importEthers();
    let w;
    try { w = new ethers.Wallet(key.trim()); } catch { throw new Error("SHADE_TREE_GW_OPERATOR_KEY is not a valid secp256k1 private key"); }
    return { operator: w.address, operatorSig: await w.signMessage(operatorAuthMessage(onion, w.address)) };
  }
  if (operator || operatorSig) {
    throw new Error("SHADE_TREE_GW_OPERATOR and SHADE_TREE_GW_OPERATOR_SIG must be set together (or set SHADE_TREE_GW_OPERATOR_KEY instead)");
  }
  return { operator: null, operatorSig: null };
}

// ---- capability advertisement (T-FEAT-10b) ----------------------------------
// T-FEAT-10 added build/verify/select SUPPORT for signed caps; this WIRES the producer so a
// gateway advertises its REAL config instead of "any gateway". Caps are derived from what the
// gateway actually runs:
//   - ports : the coarse ALLOWED egress port set, taken from the gateway's egress policy
//             (SHADE_TREE_EGRESS_ALLOW / gateway.mjs makeEgressPolicy). `*:443` -> [443]; a wildcard
//             `*` port is NOT enumerable coarsely, so it is dropped (never advertise "any port").
//   - region: a coarse, self-declared continent bucket (SHADE_TREE_GATEWAY_REGION, validated against
//             REGION_BUCKETS). Omitted when unset/invalid. Deliberately too coarse to fingerprint.
//   - proto : the envelope version range the gateway actually speaks (gateway.mjs PROTO_RANGE,
//             the version-negotiation source of truth) — carried through, never hardcoded here.
//   - artifacts: (T-HARD-8) the ZK artifact ids the gateway ACTUALLY verifies under, taken from
//             the same SHADE_TREE_ZK_ARTIFACTS the gateway's verifyEnvelope loads (packages/node/lib/zk-artifacts.mjs
//             loadArtifactSet — fail-closed: a mis-pointed set aborts the heartbeat too, so a
//             gateway never advertises ids it cannot verify). Advertised ONLY when the operator
//             set SHADE_TREE_ZK_ARTIFACTS explicitly (the dual-VK window); an unconfigured gateway
//             stays cap-free (its single built-in artifact is what a field-less envelope means).
//
// OPT-IN + OMIT-WHEN-UNCONFIGURED: with NEITHER a configured egress policy NOR a region NOR an
// explicit artifact set, buildGatewayCaps returns null, buildAnnounce attaches nothing, and the
// announce is BYTE-IDENTICAL to a pre-T-FEAT-10 announce. proto rides along ONLY when caps are
// otherwise non-empty, so it can never on its own force a non-identical announce.

// Coarse allowed-port set from an SHADE_TREE_EGRESS_ALLOW spec (comma-separated `host:port` patterns,
// same grammar as gateway.mjs makeEgressPolicy). Keeps only CONCRETE numeric ports — a wildcard
// `*` port or garbage is dropped — then dedupes + sorts. Returns [] when nothing concrete remains.
export function advertisedPorts(allowSpec) {
  const out = new Set();
  for (const raw of String(allowSpec ?? "").split(",")) {
    const spec = raw.trim();
    if (!spec) continue;
    const i = spec.lastIndexOf(":"); // split on LAST colon, mirroring parseEgressPattern
    if (i <= 0 || i === spec.length - 1) continue;
    const portStr = spec.slice(i + 1);
    if (!/^\d{1,5}$/.test(portStr)) continue; // "*" or junk -> not a concrete port
    const port = Number(portStr);
    if (port >= 1 && port <= 65535) out.add(port);
  }
  return [...out].sort((a, b) => a - b);
}

// The admission paths this gateway advertises (T-FEAT-9): SHADE_TREE_ADMIT parsed (the same spelling
// the gateway resolves), else the deprecated SHADE_TREE_ROOTS alias mapped over the contracts THIS env
// names, else null (unset => not advertised; the gateway itself then runs the `invited` default and
// a client treats the absent field as "may admit any path" during the rollout, docs/adr/0008).
// A malformed value is a startup error here too (fail fast, never advertise a guess).
export function advertisedAdmits(env = process.env) {
  if (env.SHADE_TREE_ADMIT !== undefined && String(env.SHADE_TREE_ADMIT).trim() !== "") return parseAdmit(env.SHADE_TREE_ADMIT);
  if (env.SHADE_TREE_ROOTS !== undefined && String(env.SHADE_TREE_ROOTS).trim() !== "") {
    return admitsFromRoots(env.SHADE_TREE_ROOTS, { hasStaked: !!(env.SHADE_TREE_GROUP_CONTRACT && String(env.SHADE_TREE_GROUP_CONTRACT).trim()), hasPaid: !!(env.SHADE_TREE_PAID_ACCESS_CONTRACT && String(env.SHADE_TREE_PAID_ACCESS_CONTRACT).trim()) });
  }
  return null;
}

// The payment advert this gateway carries in its caps (T-FEAT-9): the bootnode's /health `pay`
// shape (payAdvertFromEnv) plus `onion` when SHADE_TREE_REGISTRAR_ONION names a registrar onion other
// than the gateway's own (`gatewayOnion`). null when SHADE_TREE_REGISTRAR_ADVERTISE is unset/garbage.
export function advertisedPay(env = process.env, { gatewayOnion = null } = {}) {
  const pay = payAdvertFromEnv(env);
  if (!pay) return null;
  const out = { protocols: pay.protocols, port: pay.port, asset: pay.asset, chain: pay.chain, tiers: pay.tiers };
  const ro = env.SHADE_TREE_REGISTRAR_ONION ? String(env.SHADE_TREE_REGISTRAR_ONION).trim().toLowerCase().replace(/\.onion$/, "") + ".onion" : null;
  if (ro && ro !== String(gatewayOnion || "").toLowerCase()) out.onion = ro;
  return out;
}

export function advertisedRate(env = process.env) {
  const configured = [
    env.SHADE_TREE_EPOCH_SECONDS,
    env.SHADE_TREE_ROOT_FRESHNESS_SECONDS,
    env.SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES,
  ];
  if (configured.some((value) => value === undefined || String(value).trim() === "")) return null;
  const rate = {
    scope: "grove-v4",
    window: "fixed",
    epochSeconds: Number(configured[0]),
    previousEpochsAccepted: 1,
    rootFreshnessSeconds: Number(configured[1]),
    payloadBytesPerSlot: Number(configured[2]),
  };
  return canonicalCaps({ rate }).rate || null;
}

// The session-ticket capability (ADR 0011): `{ version: 1, classes: ["research-v1"] }` iff the
// node was started with SHADE_TREE_SESSION_TICKETS=1 (the same switch gateway.mjs reads), else null.
export function advertisedSession(env = process.env) {
  if (String(env.SHADE_TREE_SESSION_TICKETS ?? "0") !== "1") return null;
  return canonicalCaps({ session: { version: 1, classes: ["research-v1"] } }).session || null;
}

// Build the raw caps object from env (injectable for tests; defaults to process.env). Returns
// null when the gateway is UNCONFIGURED (no explicit egress policy, no valid region, no artifact
// set, no admission policy, no pay advert) so the announce stays byte-identical to today.
// buildAnnounce canonicalizes + signs whatever we return.
export function buildGatewayCaps(env = process.env, { artifactIds = null, gatewayOnion = null, draining = false } = {}) {
  const caps = {};
  // ports: advertised ONLY when the operator explicitly set an egress policy (env present). An
  // UNSET policy is the implicit :443 floor every gateway already meets (DEFAULT_EGRESS_PORT), so
  // advertising it would attach caps to an otherwise-default gateway — keep the default cap-free.
  if (env.SHADE_TREE_EGRESS_ALLOW !== undefined) {
    const ports = advertisedPorts(env.SHADE_TREE_EGRESS_ALLOW);
    if (ports.length) caps.ports = ports;
  }
  // region: opt-in coarse bucket, validated against the shared allowlist.
  if (typeof env.SHADE_TREE_GATEWAY_REGION === "string" && REGION_BUCKETS.has(env.SHADE_TREE_GATEWAY_REGION)) {
    caps.region = env.SHADE_TREE_GATEWAY_REGION;
  }
  // artifacts (T-HARD-8): opt-in via an EXPLICIT SHADE_TREE_ZK_ARTIFACTS. Loaded through the same
  // fail-closed loader the gateway verifies with, so the ad can never name an id we don't hold.
  // `artifactIds` is an injection seam (tests) that bypasses the file loads.
  if (Array.isArray(artifactIds)) {
    if (artifactIds.length) caps.artifacts = [...artifactIds];
  } else if (env.SHADE_TREE_ZK_ARTIFACTS !== undefined && String(env.SHADE_TREE_ZK_ARTIFACTS).trim() !== "") {
    caps.artifacts = loadArtifactSet({ env }).ids;
  }
  // admits (T-FEAT-9): the provider's admission policy, when it set one; pay: when it sells.
  const admits = advertisedAdmits(env);
  if (admits) caps.admits = admits;
  const pay = advertisedPay(env, { gatewayOnion });
  if (pay) caps.pay = pay;
  const rate = advertisedRate(env);
  if (rate) caps.rate = rate;
  // session (ADR 0011): advertised only while the node runs with session tickets on. Clients that
  // want a session route only to nodes whose SIGNED caps carry it.
  const session = advertisedSession(env);
  if (session) caps.session = session;
  // draining (operator drain flag): announced only while the flag file exists, so a planned
  // stop is visible in the signed caps and clients route around the node before it goes.
  if (draining === true) caps.draining = true;
  // Nothing configured -> no caps -> byte-identical announce (proven in the selftest).
  if (caps.ports === undefined && caps.region === undefined && caps.artifacts === undefined && caps.admits === undefined && caps.pay === undefined && caps.rate === undefined && caps.session === undefined && caps.draining === undefined) return null;
  // At least one real cap: advertise the proto range too (complete, and safe — it only ever
  // rides alongside already-present caps, never triggers caps on its own).
  caps.proto = { min: PROTO_RANGE.min, max: PROTO_RANGE.max };
  return caps;
}

// One announce: build a fresh signed record (fresh ts + nonce) and POST it to the bootnode over
// Tor. `post` is injectable (defaults to the real Tor transport) so the selftest can capture the
// exact record + path/opts that would go on the wire without a Tor daemon.
export async function announceOnce({ id, bootnode, op, weight, torHost, torPort, caps = buildGatewayCaps(), post = postOverTor }) {
  const rec = buildAnnounce({ onion: id.onion, weight, onionSeedHex: id.seed, operator: op.operator, operatorSig: op.operatorSig, caps });
  return post(bootnode, "/announce", rec, { torHost, torPort });
}

// Private relay telemetry uses a distinct opt-in request path. It is deliberately not part of
// buildAnnounce/caps or /directory: clients and public directory observers never receive node byte
// totals. Reporter state advances only after the Elder accepts a report, so a transport failure is
// retried with the same monotonic baseline rather than silently dropping an interval.
export async function reportRelayOnce({
  id,
  bootnode,
  torHost,
  torPort,
  counterPath,
  reportStatePath,
  post = postOverTor,
  now = Date.now(),
} = {}) {
  const counter = readRelayCounterState(counterPath);
  const previous = readRelayReportState(reportStatePath);
  const { report, nextState } = buildRelayReport({
    counter,
    previous,
    onion: id.onion,
    onionSeedHex: id.seed,
    now,
  });
  const response = await post(bootnode, "/telemetry/relay", report, { torHost, torPort });
  if (!response || response.ok !== true) throw new Error("Elder rejected relay telemetry");
  writeRelayReportState(reportStatePath, nextState);
  return response;
}

// ---- egress-gated announce (T-FEAT-16) --------------------------------------
// Before EACH announce, probe this host's clearnet egress (a metadata-only TCP connect to a
// well-known :443 host — see checkEgress in packages/node/gateway/gateway.mjs). If egress is DOWN, SKIP the
// announce: a broken gateway then ages out of the bootnode /directory via its TTL instead of
// staying listed and DROPping every member routed to it. When egress recovers, the next beat
// finds it healthy and announcing resumes — no state to reset. The probe runs once per beat
// (throttling is unnecessary at heartbeat cadence, default 300s).
//
// Off-switch: SHADE_TREE_EGRESS_CHECK=0 disables the check and announces UNCONDITIONALLY (today's
// behavior), so a fresh/offline env (no working egress yet, or a test box) is never blocked.
//
// Factored out and fully injectable (announce + egress + enabled) so the selftest asserts the
// gating with a fake checkEgress and a fake announce — no Tor, no real network.
export function egressCheckEnabled(env = process.env) {
  return String(env.SHADE_TREE_EGRESS_CHECK ?? "1") !== "0";
}

export async function announceIfHealthy({ announce, egress, enabled = egressCheckEnabled(), log = heartbeatLog }) {
  if (!enabled) return announce(); // check disabled: announce unconditionally (current behavior)
  let r;
  try { r = await egress(); }
  catch (error) { M.egressUp.set(0); throw error; }
  M.egressUp.set(r.healthy ? 1 : 0);
  if (!r.healthy) {
    writeLog(log, "warn", "egress check failed; skipping heartbeat", { reason: "egress-unhealthy" }, `egress DOWN (${r.target} ${r.reason}); SKIP announce; gateway ages out of the bootnode via TTL`);
    return { skipped: true, egress: r };
  }
  return announce();
}

// The runtime knobs main() reads. Throws (fail fast) when the bootnode is unset.
// SHADE_TREE_NETWORK=<name>: default the bootnode onion (and registry/rpc) from network/<name>/*.json
// first; explicit env still wins (packages/node/lib/network-record.mjs applyNetworkEnv fills only unset vars).
export function heartbeatConfig(env = process.env) {
  applyNetworkEnv(env);
  const bootnode = env.SHADE_TREE_BOOTNODE_ONION;
  const listed = String(env.SHADE_TREE_BOOTNODE_ONIONS || "").split(",").map((s) => s.trim()).filter(Boolean);
  if (!bootnode && !listed.length) throw new Error("set SHADE_TREE_BOOTNODE_ONION (the bootnode to announce to), or SHADE_TREE_NETWORK=<name> with a live network/<name>/bootnode.json");
  // ADR 0012: announce to every Elder Tree. An explicit SHADE_TREE_BOOTNODE_ONION stays first (and is
  // added when the list omits it), so a single-Elder configuration behaves exactly as before.
  const bootnodes = [];
  for (const onion of [bootnode, ...listed]) if (onion && !bootnodes.includes(onion)) bootnodes.push(onion);
  return {
    bootnode: bootnodes[0],
    bootnodes,
    intervalSec: Number(env.SHADE_TREE_BOOTNODE_HEARTBEAT || 300),
    weight: Number(env.SHADE_TREE_GW_WEIGHT || 100),
    torHost: env.SHADE_TREE_TOR_HOST || "127.0.0.1",
    torPort: Number(env.SHADE_TREE_TOR_PORT || 9250),
  };
}

// One heartbeat tick: egress-gate, announce, log the outcome. NEVER throws — a failed or
// rejected announce is logged and retried on the next interval (the bootnode's TTL is the only
// state, so there is nothing to back off or reset). Returns the outcome for tests:
//   { skipped: true }               egress DOWN, announce skipped
//   { ok: true, ...bootnode reply }  accepted
//   { ok: false, err }               rejected by the bootnode (or a malformed reply)
//   { failed: true, err }            transport failure (unreachable bootnode, bad HTTP, bad JSON)
// The bootnode reply is treated as UNTRUSTED input: anything that is not a plain object is a
// rejection ("malformed response"), never a TypeError out of the tick.
export function makeBeat({ announce, egress, enabled = egressCheckEnabled(), log = heartbeatLog, now = () => Date.now() } = {}) {
  return async () => {
    try {
      const r = await announceIfHealthy({ announce, egress, enabled, log });
      if (r && r.skipped) { M.attempts.inc({ outcome: "egress-unhealthy" }); return r; }
      if (!r || typeof r !== "object" || Array.isArray(r)) {
        M.attempts.inc({ outcome: "rejected" });
        writeLog(log, "warn", "heartbeat rejected", { reason: "malformed-response" }, "announce rejected: malformed response from bootnode (will retry next interval)");
        return { ok: false, err: "malformed response" };
      }
      if (r.ok === true) {
        M.attempts.inc({ outcome: "accepted" });
        M.lastSuccess.set(now() / 1000);
        writeLog(log, "info", "heartbeat accepted", { staked: Boolean(r.staked), ttlSec: Number(r.ttl) || 0 }, `announced (staked=${r.staked ?? false}, ttl=${r.ttl}s)`);
      } else {
        M.attempts.inc({ outcome: "rejected" });
        writeLog(log, "warn", "heartbeat rejected", { reason: "elder-rejected" }, `announce rejected: ${r.err}`);
      }
      return r.ok === true ? r : { ok: false, err: r.err };
    } catch (e) {
      M.attempts.inc({ outcome: "transport-error" });
      writeLog(log, "warn", "heartbeat transport failed; will retry", { reason: "transport-error" }, `announce failed: ${e.message} (will retry next interval)`);
      return { failed: true, err: e.message };
    }
  };
}

// ADR 0012 fan-out: one egress check, then one announce per Elder Tree, in parallel, each
// classified and logged exactly as a single-Elder tick is (tagged with the Elder's prefix). The
// cycle is `ok` when at least one Elder accepted: the node is listed somewhere and the relay
// report may follow. Per-Elder outcomes ride in `results` and the two gauges, so one dead Elder
// is visible without failing the cycle. NEVER throws, like makeBeat.
export function makeFanoutBeat({ bootnodes, announce, egress, enabled = egressCheckEnabled(), log = heartbeatLog, now = () => Date.now() } = {}) {
  const tagged = (bootnode) => {
    const tag = `${bootnode.slice(0, 16)}..onion`;
    if (typeof log === "function") return (s) => log(`[${tag}] ${s}`);
    return new Proxy({}, { get: (_, level) => (message, fields) => log?.[level]?.(message, { ...fields, elder: tag }) });
  };
  const beats = bootnodes.map((bootnode) => makeBeat({ announce: () => announce(bootnode), egress: async () => ({ healthy: true }), enabled: false, log: tagged(bootnode), now }));
  M.eldersTotal.set(bootnodes.length);
  return async () => {
    if (enabled) {
      let r;
      try { r = await egress(); }
      catch (e) {
        M.egressUp.set(0);
        M.eldersAccepted.set(0);
        M.attempts.inc({ outcome: "transport-error" });
        writeLog(log, "warn", "heartbeat transport failed; will retry", { reason: "transport-error" }, `announce failed: ${e.message} (will retry next interval)`);
        return { failed: true, err: e.message };
      }
      M.egressUp.set(r.healthy ? 1 : 0);
      if (!r.healthy) {
        M.eldersAccepted.set(0);
        M.attempts.inc({ outcome: "egress-unhealthy" });
        writeLog(log, "warn", "egress check failed; skipping heartbeat", { reason: "egress-unhealthy" }, `egress DOWN (${r.target} ${r.reason}); SKIP announce; gateway ages out of the bootnode via TTL`);
        return { skipped: true, egress: r };
      }
    }
    const results = await Promise.all(beats.map((beat) => beat()));
    const accepted = results.filter((r) => r && r.ok === true);
    M.eldersAccepted.set(accepted.length);
    const perElder = results.map((r, i) => ({ bootnode: bootnodes[i], ...(r || {}) }));
    if (accepted.length === 0) {
      const first = results.find((r) => r && (r.err || r.failed)) || {};
      return { ok: false, err: first.err || "no Elder Tree accepted the announce", accepted: 0, total: bootnodes.length, results: perElder };
    }
    if (accepted.length < bootnodes.length) {
      writeLog(log, "warn", "heartbeat accepted by some Elder Trees only", { accepted: accepted.length, total: bootnodes.length }, `announced to ${accepted.length} of ${bootnodes.length} Elder Trees (the rest will be retried next interval)`);
    }
    return { ...accepted[0], accepted: accepted.length, total: bootnodes.length, results: perElder };
  };
}

// The long-running heartbeat. `deps` are all optional (defaults = the real CLI); tests inject
// fakes for env, identity/operator resolution, announce transport, egress probe, scheduler, log.
export async function runHeartbeat({
  env = process.env,
  log = heartbeatLog,
  schedule = setInterval,
  announce = announceOnce,
  reportRelay = reportRelayOnce,
  egress = checkEgress,
  identity = null,       // pre-resolved { onion, seed } (else loadIdentity(env))
  operator = null,       // pre-resolved { operator, operatorSig } (else resolveOperator(onion, env))
} = {}) {
  const { bootnode, bootnodes, intervalSec, weight, torHost, torPort } = heartbeatConfig(env);
  const id = identity ?? await loadIdentity(env);
  const op = operator ?? await resolveOperator(id.onion, env);
  writeLog(log, "info", "heartbeat configured", { intervalSec, authMode: op.operator ? "staked-operator" : "onion-only" }, `heartbeat: ${id.onion.slice(0, 16)}..onion -> ${bootnode.slice(0, 16)}..onion every ${intervalSec}s${op.operator ? ` (operator ${op.operator.slice(0, 10)}..)` : " (onion-only)"}`);
  if (bootnodes.length > 1) writeLog(log, "info", "heartbeat fan-out configured", { elders: bootnodes.length }, `heartbeat: announcing to ${bootnodes.length} Elder Trees (${bootnodes.map((b) => b.slice(0, 16) + "..onion").join(", ")})`);
  M.eldersTotal.set(bootnodes.length);
  const enabled = egressCheckEnabled(env);
  writeLog(log, "info", "egress self-check configured", { enabled, target: enabled ? EGRESS_CHECK_TARGET : "disabled" }, enabled
    ? `egress self-check: ON (metadata-only TCP connect to ${EGRESS_CHECK_TARGET} before each announce; SKIP announce if DOWN). Disable with SHADE_TREE_EGRESS_CHECK=0`
    : "egress self-check: OFF (SHADE_TREE_EGRESS_CHECK=0) — announcing unconditionally");
  // Caps are rebuilt per beat so the drain flag (lib/drain.mjs) can flip between beats; with the
  // flag off the object is exactly what a single build produced before (the selftest pins it).
  const drainPath = drainFilePath(env);
  const drain = makeDrainWatcher({ path: drainPath, pollMs: drainPollMs(env), onChange: (on) => {
    M.draining.set(on ? 1 : 0);
    writeLog(log, "info", on ? "drain flag set; announcing draining" : "drain flag cleared; announcing normal", { draining: on, path: drainPath }, on ? `draining: ON (${drainPath} exists) -- announcing now; clients deprioritise this node` : "draining: OFF -- announcing now");
    beatNow().catch(() => {});
  } });
  const capsFor = () => buildGatewayCaps(env, { gatewayOnion: id.onion, draining: drain.state() });
  const caps = capsFor();
  writeLog(log, "debug", "signed capabilities prepared", { advertised: Boolean(caps), admits: caps?.admits || [], paid: Boolean(caps?.pay) }, caps
    ? `capabilities advertised (signed): ${JSON.stringify(caps)}`
    : "capabilities: none (unconfigured — announce is byte-identical to a legacy gateway; set SHADE_TREE_EGRESS_ALLOW, SHADE_TREE_GATEWAY_REGION, SHADE_TREE_ZK_ARTIFACTS, SHADE_TREE_ADMIT and/or SHADE_TREE_REGISTRAR_ADVERTISE to advertise)");
  if (caps?.admits) writeLog(log, "debug", "admission policy advertised", { admits: caps.admits }, `admission policy advertised: admits=${caps.admits.join(",")} (SHADE_TREE_ADMIT; must match the gateway unit's)`);
  else writeLog(log, "warn", "admission policy is not advertised", { reason: "SHADE_TREE_ADMIT-unset" }, "admission policy: NOT advertised (SHADE_TREE_ADMIT unset here); clients assume this gateway may admit any leaf source; set SHADE_TREE_ADMIT to the gateway's policy");
  if (caps?.pay) writeLog(log, "debug", "payment offer advertised", { protocols: caps.pay.protocols, port: caps.pay.port }, `payment advert: protocols=${caps.pay.protocols.join(",")} port=${caps.pay.port}${caps.pay.onion ? " onion=" + caps.pay.onion.slice(0, 16) + ".." : " (this onion)"}`);

  const announceBeat = bootnodes.length > 1
    ? makeFanoutBeat({ bootnodes, announce: (elder) => announce({ id, bootnode: elder, op, weight, torHost, torPort, caps: capsFor() }), egress: () => egress(), enabled, log })
    : makeBeat({
      announce: () => announce({ id, bootnode, op, weight, torHost, torPort, caps: capsFor() }),
      egress: () => egress(),
      enabled,
      log,
    });
  const relayEnabled = env.SHADE_TREE_RELAY_TELEMETRY === "1";
  const counterPath = env.SHADE_TREE_RELAY_TELEMETRY_STATE || join(HERE, "../../..", "tor", "hs", "relay-telemetry.local.json");
  const reportStatePath = env.SHADE_TREE_RELAY_REPORT_STATE || join(HERE, "../../..", "tor", "hs", "relay-report.local.json");
  const beat = async () => {
    const result = await announceBeat();
    if (bootnodes.length === 1) M.eldersAccepted.set(result?.ok === true ? 1 : 0);
    // Bind reports to an already-authenticated live announcement: only report after this cycle's
    // /announce was accepted. Telemetry remains best-effort and cannot make the liveness heartbeat
    // fail; the Elder independently verifies the onion signature and live registry membership.
    if (relayEnabled && result?.ok === true) {
      try {
        await reportRelay({ id, bootnode, torHost, torPort, counterPath, reportStatePath });
        writeLog(log, "debug", "private relay telemetry accepted", { published: "aggregate-input" }, "private relay telemetry accepted");
      } catch (error) {
        writeLog(log, "warn", "private relay telemetry deferred", { reason: "telemetry-unavailable", errorType: error?.name || "Error" }, "private relay telemetry unavailable; will retry next interval");
      }
    }
    return result;
  };
  // An immediate beat on a drain transition; `beat` is hoisted by the closure above.
  async function beatNow() { return beat(); }
  drain.start();
  M.draining.set(drain.state() ? 1 : 0);
  const first = await beat();
  const timer = schedule(beat, intervalSec * 1000);
  return { beat, first, timer, id: { onion: id.onion }, op: { operator: op.operator }, caps, capsFor, drain, relayTelemetry: relayEnabled, bootnodes };
}

async function main() {
  loadCredentials();
  const pkg = JSON.parse(await readFile(join(HERE, "../../..", "package.json"), "utf8"));
  installRuntimeMetrics(metrics, { role: "heartbeat", version: pkg.version });
  let config;
  try {
    config = heartbeatConfig();
  } catch (e) {
    heartbeatLog.error("heartbeat configuration invalid", { err: e }); process.exit(1);
  }
  let ready = false;
  const metricsPort = safeMetricsPort(process.env.SHADE_TREE_HEARTBEAT_METRICS_PORT, isLoopbackMetricsHost(config.torHost) ? [["Tor SOCKS", config.torPort]] : []);
  let metricsServer = null;
  if (metricsPort > 0) {
    metricsServer = listenMetrics({ port: metricsPort, reg: metrics, host: "127.0.0.1", ready: () => ready });
    await new Promise((resolve, reject) => {
      metricsServer.once("listening", resolve);
      metricsServer.once("error", reject);
    });
  }
  const running = await runHeartbeat({ log: heartbeatLog });
  ready = true;
  // Webhook alerts without Prometheus (lib/alerts.mjs): off unless SHADE_TREE_ALERT_WEBHOOK is set.
  const alerts = installAlerts({ role: "heartbeat", reg: metrics, rules: heartbeatRules({ intervalSec: config.intervalSec }), log: heartbeatLog });
  if (alerts.start()) {
    heartbeatLog.info("alert webhook configured", { event: "alert.ready", format: alerts.config.format, intervalMs: alerts.config.intervalMs });
    alerts.lifecycle("HeartbeatStarted", `heartbeat up (${running.bootnodes.length} Elder Tree${running.bootnodes.length === 1 ? "" : "s"})`).catch(() => {});
    const bye = () => { alerts.stop(); alerts.lifecycle("HeartbeatStopping", "heartbeat stopping (SIGTERM)").finally(() => process.exit(0)); };
    process.once("SIGTERM", bye);
    process.once("SIGINT", bye);
  }
  printOperatorBanner({ role: "heartbeat", rows: [
    ["interval", `${heartbeatConfig().intervalSec}s`],
    ["egress", egressCheckEnabled() ? "checked" : "unchecked"],
    ["relay telemetry", process.env.SHADE_TREE_RELAY_TELEMETRY === "1" ? "private reports on" : "off"],
    ["metrics", metricsPort > 0 ? `127.0.0.1:${metricsPort}` : "off"],
    ["drain flag", drainFilePath()],
    ["alerts", alerts.enabled ? `webhook (${alerts.config.format})` : "off"],
  ] });
  heartbeatLog.info("heartbeat ready", { event: "service.ready", first: running.first?.ok === true ? "accepted" : running.first?.skipped ? "skipped" : "retrying", metricsPort });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => { heartbeatLog.error("heartbeat failed", { event: "service.failed", err: e }); process.exit(1); });
}
