// The gateway: a Shade Tree proxy, published as a Tor onion service.
//
// It listens on 127.0.0.1:SHADE_TREE_GATEWAY_PORT (8443 by default; Tor maps
// <addr>.onion:80 -> here). For each
// incoming connection it:
//   1. reads a single newline-terminated v4 JSON envelope
//      { v:4, target, nonce, artifact?, proof /*RLNFullProof*/, nullifier, externalNullifier, share },
//   2. rejects malformed or operator-disallowed targets with a pure policy check,
//   3. verifies it CHEAP-FIRST (docs/NEXT-VERSION.md, adversarial-review #4):
//        externalNullifier is current/previous epoch's               (cheap)
//        share.x == proof's committed public x                        (cheap)
//        proof's public root ∈ recent-roots                           (cheap)
//        `artifact` id ∈ the accepted ZK artifact set (T-HARD-8)      (cheap; absent => legacy id)
//        RLN Groth16 verifyProof under THAT artifact's vkey            (expensive SNARK)
//      all bundled behind lib verifyEnvelope(),
//   4. collects the RLN share per `nullifier`: the first share egresses; an identical
//      replay (same share.x) is deduped (no slash); a SECOND DISTINCT signal (same
//      nullifier, different x) reconstructs the identitySecret and slashes the member's
//      on-chain stake,
//   5. resolves the admitted target, rejects non-public addresses, and opens a raw :443 TCP
//      tunnel to a validated pinned numeric answer from THIS host's IP; it
//      pipes bytes both ways (TLS stays end-to-end client<->target),
//   6. on any failure writes a short error envelope and drops the connection.
//
// The reputation root is read from a RootProvider (the on-chain StakedReputationSet,
// via lib/root-provider.mjs) so TRUSTED_ROOT is a recent-roots SET refreshed on
// membership change, not only a static members.json. T-FEAT-7 (docs/PAYMENTS.md): the
// accepted set is the UNION of every ADMITTED root SOURCE — the static members.json
// (invited friends / PoC), each StakedReputationSet in SHADE_TREE_GROUP_CONTRACT (a comma list),
// and the PaidAccessSet in SHADE_TREE_PAID_ACCESS_CONTRACT. WHICH of those this gateway admits is
// the provider's choice, SHADE_TREE_ADMIT=invited[,staked][,paid] (T-FEAT-9, docs/adr/0008): the
// default is `invited` alone — the maximum-anonymity mode — even when contract addresses are
// configured; see initRoots() / resolveAdmission(). A configured-but-not-admitted contract is
// neither a root source nor a slash target.

import net from "node:net";
import { Transform } from "node:stream";
import { lookup as dnsLookup } from "node:dns/promises";
import { readFile } from "node:fs/promises";
import { watch } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { verifyEnvelope, loadGroupOnchain, loadGroup, currentEpoch, EPOCH_SECONDS, MEMBERS_PATH, getArtifactSet } from "../lib/semaphore.mjs";
import { reconstructSecret, resolveSlashLeaf, deriveCommitments, TIERS, K_SLOTS } from "../lib/rln.mjs";
import { makeRootProvider, configuredContracts } from "../lib/root-provider.mjs";
import { ADMIT_ORDER, DEFAULT_ADMIT, parseAdmit, admitsFromRoots, describeAdmits } from "../lib/admission.mjs";
import { buildReceipt } from "../lib/receipt.mjs";
import { makeConfiguredFleetTally } from "./fleet-tally.mjs";
import { registry as metrics, installRuntimeMetrics, listenMetrics, safeMetricsPort } from "../lib/metrics.mjs";
import { createLogger } from "../lib/log.mjs";
import { printOperatorBanner } from "../lib/operator-ui.mjs";
import { jsonRpcCall, makeBoundedJsonRpcProvider, waitForTransactionReceipt } from "../lib/rpc-safety.mjs";
import { makeRelayByteCounter } from "../lib/relay-telemetry.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const LISTEN_HOST = "127.0.0.1";
const LISTEN_PORT = Number(process.env.SHADE_TREE_GATEWAY_PORT || 8443);
const MAX_ENVELOPE = 64 * 1024;
export const MAX_EGRESS_ADDRESSES = 8;
export const DEFAULT_TUNNEL_MAX_PAYLOAD_BYTES = 40 * 1024 * 1024;
const log = createLogger("node");

// ---- metrics (T-MON-2) ------------------------------------------------------
// Registered against the process-wide registry at import time: this only fills in-memory
// state and binds NO port. The gateway speaks raw TCP, so /metrics is exposed by a SEPARATE
// loopback http server started only when SHADE_TREE_METRICS_PORT is set (see main()). Off by
// default => no listener. Payload counters increment once per admitted stream chunk; all labels
// remain closed enums and no traffic identity is retained.
const M = {
  tunnels: metrics.counter("shade_tree_gateway_tunnels_total", "Tunnels by result=pass|drop (+ reason on drop)."),
  slashes: metrics.counter("shade_tree_gateway_slashes_total", "Members slashed for an RLN over-spend (2nd distinct signal on a nullifier)."),
  verify: metrics.histogram("shade_tree_gateway_verify_seconds", "verifyEnvelope() latency in seconds (cheap-first checks + Groth16)."),
  upstreamConnect: metrics.histogram("shade_tree_gateway_upstream_connect_seconds", "Node-to-destination TCP connect latency in seconds. No destination labels are recorded."),
  // Established tunnels closed by the gateway itself (not by either peer), by reason. Kept
  // SEPARATE from tunnels_total: a tunnel that idles out already counted as result=pass, so
  // counting it again as a drop would double-count the tunnel (T-HARD-4).
  tunnelCloses: metrics.counter("shade_tree_gateway_tunnel_closes_total", "Established tunnels closed by the gateway, by reason (idle-timeout|payload-limit|upstream-error)."),
  // T-FEAT-7: trusted roots per source (source=static|staked|paid, contract=address|members.json)
  // and the paid set's live leaf count (its anonymity set; the floor is SHADE_TREE_PAID_MIN_LEAVES).
  rootsBySource: metrics.gauge("shade_tree_gateway_trusted_roots", "Trusted admission roots right now, by bounded source=invited|staked|paid."),
  // 1 while a root SOURCE could not be read on its last refresh (the gateway keeps serving with the
  // sources it has: last-known-good roots + members.json), 0 once it reads again. Alert on it.
  rootDegraded: metrics.gauge("shade_tree_gateway_root_source_degraded", "1 = this bounded root source failed its last refresh; 0 = healthy."),
  paidLeaves: metrics.gauge("shade_tree_gateway_paid_access_leaves", "Live leaves in the PaidAccessSet; no contract label is exposed."),
  agentToDestinationBytes: metrics.counter("shade_tree_gateway_agent_to_destination_payload_bytes_total", "Application payload bytes relayed from agents after tunnel establishment. No traffic labels are recorded."),
  destinationToAgentBytes: metrics.counter("shade_tree_gateway_destination_to_agent_payload_bytes_total", "Application payload bytes relayed from destinations after tunnel establishment. No traffic labels are recorded."),
};

const DROP_LABELS = new Set([
  "too-many-connections", "envelope-timeout", "envelope-too-large", "bad-envelope",
  "bad-version", "unsupported-version", "wrong-group-root", "root-not-recent",
  "invalid-proof", "bad-share", "bad-signal", "bad-external-nullifier", "bad-nullifier",
  "artifact-unknown", "artifact-retired", "bad-artifact", "bad-target", "bad-target-policy",
  "bad-target-address", "bad-target-dns",
  "replayed-envelope", "rate-slashed", "over-spend-slashed", "nullifier-conn-limit",
  "payload-limit",
  "upstream-timeout", "upstream-refused", "upstream-unreachable", "upstream-reset",
  "upstream-error", "internal-error",
]);

export function gatewayDropLabel(reason) {
  const raw = String(reason || "internal-error").toLowerCase();
  const base = raw.split(":", 1)[0];
  if (DROP_LABELS.has(base)) return base;
  if (base.includes("artifact")) return "bad-artifact";
  if (base.includes("version")) return "bad-version";
  if (base.includes("root")) return "root-not-recent";
  if (base.includes("proof")) return "invalid-proof";
  return "internal-error";
}

function upstreamDropLabel(code) {
  if (["ECONNREFUSED"].includes(code)) return "upstream-refused";
  if (["ENETUNREACH", "EHOSTUNREACH", "ENETDOWN"].includes(code)) return "upstream-unreachable";
  if (["ECONNRESET", "EPIPE"].includes(code)) return "upstream-reset";
  if (["ETIMEDOUT"].includes(code)) return "upstream-timeout";
  return "upstream-error";
}

// ---- endpoint hardening knobs (T-HARD-4) -----------------------------------
// Every lever an unauthenticated peer could pull BEFORE it has proven anything (or after it has
// spent one proof) is bounded here, env-configurable with safe defaults. `envInt` keeps the
// convention of the rest of this file (unset/garbage => default) but ALLOWS an explicit 0, which
// disables the corresponding timeout/limit (an operator opt-out, never the default).
//   SHADE_TREE_ENVELOPE_TIMEOUT_MS      absolute deadline for the newline-terminated envelope, measured
//                                 from connect (default 30000 — the value that was hard-coded
//                                 before; a slow-loris that never sends the newline, or dribbles
//                                 one byte per N seconds, is cut at the deadline: the timer is
//                                 NOT reset by activity). Drop reason `envelope-timeout`.
//   SHADE_TREE_TUNNEL_IDLE_TIMEOUT_MS   inactivity timeout on the ESTABLISHED relay: no bytes in EITHER
//                                 direction for this long => both sockets destroyed (default
//                                 300000 = 5 min; 0 = never). Counted `idle-timeout` in
//                                 shade_tree_gateway_tunnel_closes_total. Also bounds an upstream
//                                 connect that black-holes (never completes, never errors).
//   SHADE_TREE_MAX_CONNS                max concurrent client connections to the gateway, counted from
//                                 accept (default 1024; 0 = unlimited). Over => reply
//                                 `too-many-connections` and close, BEFORE reading any envelope.
//   SHADE_TREE_MAX_CONNS_PER_NULLIFIER  max concurrent tunnels a single nullifier may hold open
//                                 (default 8; 0 = unlimited). The RLN budget counts admitted
//                                 CONNECT tunnels, not application requests inside them, and not
//                                 open tunnels: an exact-envelope honest retry inside the replay
//                                 window is admitted idempotently, so without this cap one proof
//                                 could pin N idle tunnels open. Over => `nullifier-conn-limit`.
//   SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES combined application payload relayed in both directions for
//                                 one (externalNullifier, nullifier) RLN slot (default 41943040 =
//                                 40 MiB; 0 = unlimited). Same-node retries share the budget. The
//                                 final chunk is truncated at the exact boundary, then both sockets
//                                 close and `payload-limit` is counted in tunnel_closes_total.
//   SHADE_TREE_DNS_TIMEOUT_MS      maximum time resolving an admitted target (default 5000).
//                                 A stalled resolver cannot pin the handler indefinitely.
function envInt(name, dflt) {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return dflt;
  const n = Number(raw);
  return Number.isSafeInteger(n) && n >= 0 ? n : dflt;
}
export const HARDENING = Object.freeze({
  envelopeTimeoutMs: envInt("SHADE_TREE_ENVELOPE_TIMEOUT_MS", 30000),
  idleTimeoutMs: envInt("SHADE_TREE_TUNNEL_IDLE_TIMEOUT_MS", 300000),
  maxPayloadBytes: envInt("SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES", DEFAULT_TUNNEL_MAX_PAYLOAD_BYTES),
  maxConns: envInt("SHADE_TREE_MAX_CONNS", 1024),
  maxConnsPerNullifier: envInt("SHADE_TREE_MAX_CONNS_PER_NULLIFIER", 8),
  dnsTimeoutMs: envInt("SHADE_TREE_DNS_TIMEOUT_MS", 5000),
});

// Concurrent-connection accounting. Pure + injectable (the selftest drives it directly and via
// the real handler). `acquire()` is called once per accepted socket BEFORE the envelope read and
// `release()` exactly once on that socket's close; the per-nullifier pair brackets an admitted
// tunnel the same way. Both maps are bounded by the total connection cap (an entry exists only
// while a socket is open), so an attacker cannot grow them past maxConns. 0 == unlimited.
export function makeConnLimiter({ maxConns = HARDENING.maxConns, maxPerNullifier = HARDENING.maxConnsPerNullifier } = {}) {
  let total = 0;
  const perNullifier = new Map(); // nullifier -> open tunnel count
  return {
    maxConns, maxPerNullifier,
    acquire() { if (maxConns > 0 && total >= maxConns) return false; total++; return true; },
    release() { if (total > 0) total--; },
    acquireNullifier(n) {
      const k = String(n);
      const cur = perNullifier.get(k) || 0;
      if (maxPerNullifier > 0 && cur >= maxPerNullifier) return false;
      perNullifier.set(k, cur + 1);
      return true;
    },
    releaseNullifier(n) {
      const k = String(n);
      const cur = perNullifier.get(k) || 0;
      if (cur <= 1) perNullifier.delete(k); else perNullifier.set(k, cur - 1);
    },
    total: () => total,
    nullifierCount: (n) => perNullifier.get(String(n)) || 0,
    trackedNullifiers: () => perNullifier.size,
  };
}

// One proof slot is named by its epoch external nullifier plus its RLN nullifier. Keep a local
// combined byte budget under that key so an exact-envelope retry cannot reset its allowance merely
// by opening another socket. State lives for two epochs, matching makeSpentSet's verifier/replay
// retention after the last socket closes. Active entries are never pruned, so a long-lived tunnel
// cannot regain 40 MiB merely by crossing the retention boundary. Pruning happens only when a new
// key is allocated or sweep() is called, never per byte. `maxBytes=0` is the explicit operator
// opt-out and allocates no state.
export function makePayloadBudget({
  maxBytes = HARDENING.maxPayloadBytes,
  ttlMs = 2 * EPOCH_SECONDS * 1000,
  now = () => Date.now(),
} = {}) {
  maxBytes = Number(maxBytes);
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) {
    throw new Error("payload budget maxBytes must be a non-negative safe integer");
  }
  if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0) {
    throw new Error("payload budget ttlMs must be a positive safe integer");
  }

  const entries = new Map(); // "epoch\0nullifier" -> { used, active, at }
  const keyOf = (nullifier, epoch) => `${String(epoch)}\0${String(nullifier)}`;

  function sweep() {
    const cutoff = now() - ttlMs;
    for (const [key, entry] of entries) {
      if (entry.active === 0 && entry.at < cutoff) entries.delete(key);
    }
  }

  function entryFor(nullifier, epoch) {
    const key = keyOf(nullifier, epoch);
    let entry = entries.get(key);
    if (!entry) {
      sweep();
      entry = { used: 0, active: 0, at: now() };
      entries.set(key, entry);
    }
    return entry;
  }

  function remaining(nullifier, epoch) {
    if (maxBytes === 0) return Infinity;
    const entry = entryFor(nullifier, epoch);
    return Math.max(0, maxBytes - entry.used);
  }

  function acquire(nullifier, epoch) {
    if (maxBytes === 0) return Infinity;
    const entry = entryFor(nullifier, epoch);
    entry.active += 1;
    return Math.max(0, maxBytes - entry.used);
  }

  function release(nullifier, epoch) {
    if (maxBytes === 0) return;
    const entry = entries.get(keyOf(nullifier, epoch));
    if (!entry) return;
    entry.active = Math.max(0, entry.active - 1);
    if (entry.active === 0) entry.at = now();
  }

  function take(nullifier, epoch, requestedBytes) {
    const requested = Number(requestedBytes);
    if (!Number.isSafeInteger(requested) || requested < 0) {
      throw new Error("payload budget request must be a non-negative safe integer");
    }
    if (maxBytes === 0) {
      return { allowed: requested, used: null, remaining: Infinity, exhausted: false };
    }
    const entry = entryFor(nullifier, epoch);
    const allowed = Math.min(requested, Math.max(0, maxBytes - entry.used));
    entry.used += allowed;
    return {
      allowed,
      used: entry.used,
      remaining: maxBytes - entry.used,
      exhausted: entry.used >= maxBytes,
    };
  }

  return { maxBytes, acquire, release, remaining, take, sweep, size: () => entries.size };
}

function payloadTransform({ budget, nullifier, epoch, count, onLimit }) {
  return new Transform({
    transform(chunk, _encoding, callback) {
      let result;
      try {
        result = budget.take(nullifier, epoch, chunk.length);
        if (result.allowed > 0) count(chunk.subarray(0, result.allowed));
      } catch (error) {
        callback(error);
        return;
      }

      // callback(null, data) pushes to the downstream socket synchronously. Schedule the close
      // only after that push so the boundary bytes may be relayed, while a shared budget prevents
      // the opposite direction from forwarding anything beyond the same combined ceiling.
      callback(null, result.allowed > 0 ? chunk.subarray(0, result.allowed) : undefined);
      if (result.exhausted) onLimit(result.used);
    },
  });
}

// ---- recent-roots: the accepted admission roots, refreshed on change --------
// A proof against any root inside the freshness window verifies. On-chain: fed by
// the RootProvider. PoC fallback: the single members.json root, re-read on change.
let recentRoots = new Set();
// The local set's LEAVES (members.json mode only; null in on-chain root mode, which holds
// roots). Used ONLY after an over-spend, to name which tier's leaf a reconstructed
// identitySecret sits behind (T-FEAT-8 resolveSlashLeaf) — never during verification.
let localLeaves = null;
// Test seam (gateway/*.selftest.mjs, lib/zk-artifacts.selftest.mjs): install the accepted
// root set directly so a handler can be driven without initRoots()/members.json/a chain.
export function _setRecentRoots(roots) { recentRoots = new Set(Array.from(roots || []).map(String)); }
export function _getRecentRoots() { return new Set(recentRoots); }

// resolveSlashTier(identitySecret) -> { commitment, limit, resolved }: the leaf to slash and
// the tier it sits at. Reputation tiers (T-FEAT-8) make the leaf depend on the member's
// PRIVATE limit, so try every tier this gateway knows (SHADE_TREE_TIERS; always includes K) and pick
// the one present in the local set. Without leaves (on-chain root mode) the local resolution
// falls back to the default tier's leaf (resolved:false); the on-chain slasher then finishes
// the job against the tiered contract's `limitOf` (T-FEAT-8b, makeSlasher below).
export function resolveSlashTier(identitySecret, { tiers = TIERS, leaves = localLeaves } = {}) {
  const hasLeaf = leaves ? (c) => leaves.has(String(c)) : null;
  const r = resolveSlashLeaf(identitySecret, { tiers, hasLeaf });
  if (!r.resolved && tiers.length > 1) {
    log.warn("slash: tier of the over-spent leaf not resolvable locally; naming the default tier's leaf" + (leaves ? "" : " (on-chain slasher resolves via limitOf)"), { tiers, limit: r.limit, hasLeaves: !!leaves });
  }
  return r;
}

// deriveSlashLeaf(identitySecret) -> commitment (string): the leaf to slash (resolveSlashTier's
// commitment). Kept as the string-returning form for callers/tests that only want the leaf.
export function deriveSlashLeaf(identitySecret, opts = {}) {
  return resolveSlashTier(identitySecret, opts).commitment;
}

// ---- admission policy: which root SOURCES this gateway trusts (T-FEAT-7 / T-FEAT-9) --------
// SHADE_TREE_ADMIT=invited[,staked][,paid] names the ADMISSION PATHS (docs/adr/0008, anonymity order
// most -> least: invited > staked > paid). Each path is one root source:
//   invited  the members.json file (MEMBERS_PATH / SHADE_TREE_MEMBERS_FILE)
//   staked   every StakedReputationSet in SHADE_TREE_GROUP_CONTRACT   (requires it to be configured)
//   paid     the PaidAccessSet in SHADE_TREE_PAID_ACCESS_CONTRACT     (requires it to be configured)
// DEFAULT `invited` — even when SHADE_TREE_NETWORK / env supply contract addresses: a provider opts
// into the less-anonymous paths explicitly. A path whose contract is missing FAILS CLOSED at
// startup (never a silently smaller admission set). SHADE_TREE_ROOTS (T-FEAT-7: static,onchain) is a
// DEPRECATED alias -- static->invited, onchain->staked+paid (whichever are configured) -- accepted
// with a startup warning; SHADE_TREE_ADMIT wins when both are set. Exported + pure for the selftest.
//   -> { admits: [..canonical order..], static, onchain, contracts: [ADMITTED contracts only],
//        explicit, source: "SHADE_TREE_ADMIT" | "SHADE_TREE_ROOTS" | "default", warnings: [..] }
export function resolveAdmission({ admit = process.env.SHADE_TREE_ADMIT, roots = process.env.SHADE_TREE_ROOTS, contracts = configuredContracts(), warn = (m, f) => log.warn(m, f) } = {}) {
  const staked = contracts.filter((c) => c.kind === "staked");
  const paid = contracts.filter((c) => c.kind === "paid");
  const rawAdmit = String(admit ?? "").trim();
  const rawRoots = String(roots ?? "").trim();
  const warnings = [];
  let admits, source;
  if (rawAdmit) {
    admits = parseAdmit(rawAdmit);
    source = "SHADE_TREE_ADMIT";
    if (rawRoots) warnings.push("SHADE_TREE_ROOTS is ignored because SHADE_TREE_ADMIT is set (SHADE_TREE_ROOTS is a deprecated alias; drop it)");
  } else if (rawRoots) {
    admits = admitsFromRoots(rawRoots, { hasStaked: staked.length > 0, hasPaid: paid.length > 0 });
    source = "SHADE_TREE_ROOTS";
    warnings.push(`SHADE_TREE_ROOTS is DEPRECATED (static->invited, onchain->staked+paid): set SHADE_TREE_ADMIT=${admits.join(",")} instead`);
  } else {
    admits = [...DEFAULT_ADMIT];
    source = "default";
    if (contracts.length) warnings.push(`SHADE_TREE_ADMIT is unset: admitting ${admits.join(",")} ONLY (the maximum-anonymity default); the configured ${contracts.map((c) => `${c.kind}(${c.address})`).join(" + ")} is NOT trusted until you set SHADE_TREE_ADMIT=${ADMIT_ORDER.filter((p) => p === "invited" || contracts.some((c) => c.kind === p)).join(",")}`);
  }
  if (admits.includes("staked") && staked.length === 0) throw new Error(`${source} names staked but no StakedReputationSet is configured (set SHADE_TREE_GROUP_CONTRACT, or SHADE_TREE_NETWORK with a contracts.json that has one) -- refusing to start with a smaller admission set than requested`);
  if (admits.includes("paid") && paid.length === 0) throw new Error(`${source} names paid but no PaidAccessSet is configured (set SHADE_TREE_PAID_ACCESS_CONTRACT, or SHADE_TREE_NETWORK with a contracts.json that has one) -- refusing to start with a smaller admission set than requested`);
  for (const w of warnings) warn(w, { source });
  const admitted = contracts.filter((c) => admits.includes(c.kind));
  return { admits, static: admits.includes("invited"), onchain: admitted.length > 0, contracts: admitted, explicit: source !== "default", source, warnings };
}

// Back-compat shim for the deprecated SHADE_TREE_ROOTS spelling (T-FEAT-7): { static, onchain, explicit }.
// Unset spec = the T-FEAT-9 default (invited only). Kept exported for older callers/tests.
export function resolveRootSources({ spec = process.env.SHADE_TREE_ROOTS, contracts = configuredContracts() } = {}) {
  const raw = String(spec == null ? "" : spec).trim();
  if (raw === "") return { static: true, onchain: false, explicit: false };
  const admits = admitsFromRoots(raw, { hasStaked: contracts.some((c) => c.kind === "staked"), hasPaid: contracts.some((c) => c.kind === "paid") });
  return { static: admits.includes("invited"), onchain: admits.some((p) => p !== "invited"), explicit: true };
}

// The paid set's anonymity-set floor K (docs/PAYMENTS.md open item 3): below it the gateway WARNS
// at startup and on every refresh that crosses it, and NEVER refuses — the floor is a deployment
// parameter, not a proven bound; it is logged so an operator can see how thin the set is.
export const PAID_MIN_LEAVES = Number(process.env.SHADE_TREE_PAID_MIN_LEAVES || 8);

// PaidAccessSet.leafCount() over raw JSON-RPC (selector precomputed; no ethers on this path).
// Returns null when the contract has no such view (a StakedReputationSet) or the call fails.
async function readLeafCount(contract, rpcUrl) {
  try {
    const result = await jsonRpcCall(rpcUrl, "eth_call", [{ to: contract, data: "0x30e69fc3" }, "latest"]);
    if (typeof result !== "string" || result === "0x") return null;
    return Number(BigInt(result));
  } catch { return null; }
}

// Format the ABI-file startup lines: `admits: invited+staked+paid` (T-FEAT-9, the policy) and
// `roots: members.json + staked(0x…) + paid(0x…)` (T-FEAT-7, the sources behind it).
export function describeAdmission(admits) { return describeAdmits(admits); }
export function describeRootSources({ static: st, contracts = [] } = {}) {
  const parts = [];
  if (st) parts.push("members.json");
  for (const c of contracts) parts.push(`${c.kind}(${c.address})`);
  return "roots: " + (parts.join(" + ") || "(none)");
}

// initRoots({ ... }) -> { count, contracts, degraded }: load every configured root source into
// recentRoots and keep it refreshed. Injectable (contracts / want / loadStatic / makeProvider /
// watchFile) so gateway/root-sources.selftest.mjs can drive the STARTUP posture without a chain:
//
//   FAIL-SOFT vs FAIL-CLOSED at startup (fleet crash-loop 2026-08-17, docs/GO-LIVE-LOG-2026-08-17.md):
//   an on-chain source that cannot be read at startup (RPC down, log-range cap, bad contract) is
//   logged LOUDLY (`root source UNAVAILABLE at startup`), gauged shade_tree_gateway_root_source_degraded=1,
//   and retried by the provider's own poll (onChange fires the moment it reads roots) -- PROVIDED
//   some root is trusted already (the static members.json root, or another chain source). With NO
//   root at all the gateway still exits nonzero (an admission set of nothing is not a gateway;
//   systemd restarts it, which is the retry). A source that fails on a LATER refresh keeps its
//   last-known-good only for the configured freshness window. Once that window expires, its
//   roots are removed and admission fails closed until a fresh chain read succeeds.
export async function initRoots({
  contracts = null,
  want = null,
  rpcUrl = process.env.SHADE_TREE_RPC_URL || "http://127.0.0.1:8545",
  loadStatic = loadGroup,
  makeProvider = (addrs) => makeRootProvider(undefined, { contracts: addrs }), // node|light per SHADE_TREE_ROOT_PROVIDER
  watchFile = (path, cb) => watch(path, { persistent: false }, cb),
  pollIntervalMs = undefined,
  quiet = false,
} = {}) {
  // Admission policy (T-FEAT-9): with no injected `want`, resolve SHADE_TREE_ADMIT over the configured
  // contracts and NARROW `contracts` to the admitted ones (a configured-but-not-admitted set is
  // never read). Tests inject { contracts, want } directly and skip the env resolution.
  if (!want) {
    want = resolveAdmission({ contracts: contracts ?? configuredContracts() });
    contracts = want.contracts;
  } else if (!contracts) {
    contracts = configuredContracts();
  }
  const admits = want.admits || [...(want.static ? ["invited"] : []), ...ADMIT_ORDER.filter((p) => p !== "invited" && (want.onchain ? contracts : []).some((c) => c.kind === p))];
  let staticRoot = null;
  let staticCount = 0;
  let chainRoots = [];
  let perSource = [];
  const degraded = new Set(); // contracts (lowercased) whose last refresh failed
  const kindOf = (contract) => (contracts.find((c) => c.address.toLowerCase() === String(contract || "").toLowerCase()) || {}).kind || "staked";
  const recompute = () => {
    const union = new Set();
    if (want.static && staticRoot) union.add(String(staticRoot));
    for (const r of chainRoots) union.add(String(r));
    recentRoots = union;
    if (want.static) M.rootsBySource.set(staticRoot ? 1 : 0, { source: "invited" });
    for (const source of ["staked", "paid"]) {
      const rows = perSource.filter((p) => kindOf(p.contract) === source);
      if (rows.length) M.rootsBySource.set(new Set(rows.flatMap((p) => p.roots.map(String))).size, { source });
      const configured = contracts.filter((c) => c.kind === source);
      if (configured.length) M.rootDegraded.set(configured.some((c) => degraded.has(c.address.toLowerCase())) ? 1 : 0, { source });
    }
  };

  // Static members.json: root + leaves (leaves feed the local slash-tier resolution).
  if (want.static) {
    const load = async () => {
      const { root, count, leaves } = await loadStatic();
      staticRoot = root;
      staticCount = count;
      localLeaves = new Set((leaves || []).map(String));
      recompute();
      return count;
    };
    await load();
    try {
      watchFile(MEMBERS_PATH, () => load().catch(() => {}));
    } catch { /* watch is best-effort */ }
  }

  // On-chain: one provider per contract, unioned (lib/root-provider.mjs makeRootProvider).
  let provider = null;
  let stopRootPolling = () => {};
  let paidWarned = false;
  const paidContracts = contracts.filter((c) => c.kind === "paid");
  const checkPaidFloor = async (first) => {
    for (const c of paidContracts) {
      const src = perSource.find((p) => String(p.contract || "").toLowerCase() === c.address.toLowerCase());
      const n = (await readLeafCount(c.address, rpcUrl)) ?? (src && src.leafCount != null ? src.leafCount : null);
      if (n == null) { if (first) log.warn("paid-access anonymity set: leafCount() unreadable", { contract: c.address }); continue; }
      M.paidLeaves.set(n);
      const line = `paid-access anonymity set: ${n} leaves (floor K=${PAID_MIN_LEAVES})`;
      if (n < PAID_MIN_LEAVES) {
        if (first || !paidWarned) log.warn(line + " — BELOW the floor: paid members are thinly hidden among each other (still admitted; the floor is a warning, not a gate)", { contract: c.address, leaves: n, floor: PAID_MIN_LEAVES });
        paidWarned = true;
      } else {
        if (first || paidWarned) log.info(line, { contract: c.address, leaves: n, floor: PAID_MIN_LEAVES });
        paidWarned = false;
      }
    }
  };
  if (want.onchain) {
    provider = makeProvider(contracts.map((c) => c.address));
    const refresh = async () => {
      const r = await loadGroupOnchain(provider);
      chainRoots = r.recentRoots || [];
      perSource = r.perSource || [{
        contract: provider.contract || contracts[0].address,
        roots: chainRoots.slice(),
        leafCount: r.leafCount ?? null,
        stale: !!r.stale,
        ...(r.error ? { error: r.error } : {}),
      }];
      degraded.clear();
      const failures = new Map();
      for (const e of r.errors || []) failures.set(String(e.contract || "").toLowerCase(), e.error);
      for (const source of perSource) {
        if (source.stale || source.error) {
          failures.set(String(source.contract || "").toLowerCase(), source.error || "serving last-known-good roots");
        }
      }
      for (const [contract] of failures) degraded.add(contract);
      recompute();
      for (const [contract, error] of failures) log.warn("root source failed this refresh; keeping its last-known-good", { contract, err: error });
    };
    try {
      await refresh();
    } catch (e) {
      // EVERY chain source failed at startup. Fail soft only if some root is already trusted.
      if (want.static && staticRoot) {
        for (const c of contracts) degraded.add(c.address.toLowerCase());
        chainRoots = [];
        perSource = contracts.map((c) => ({ contract: c.address, roots: [], leafCount: null, error: e.message }));
        recompute();
        log.error("root source UNAVAILABLE at startup; serving with members.json only until it reads (retrying every poll; shade_tree_gateway_root_source_degraded=1)", { contracts: contracts.map((c) => `${c.kind}(${c.address})`), err: e.message, hint: /block range|exceed/i.test(e.message) ? "public RPC eth_getLogs cap: set SHADE_TREE_FROM_BLOCK / SHADE_TREE_FROM_BLOCKS to the deploy block(s), or lower SHADE_TREE_LOGS_CHUNK (docs/OPERATOR.md 'public RPC log-range caps')" : undefined });
      } else {
        throw new Error(`no admission root available: ${e.message} (and no static members.json root to fall back on) -- refusing to start with an empty admission set`);
      }
    }
    stopRootPolling = provider.onChange?.(
      async (_roots, pollError) => {
        if (pollError) {
          chainRoots = [];
          perSource = contracts.map((c) => ({ contract: c.address, roots: [], leafCount: null, error: pollError.message }));
          degraded.clear();
          for (const c of contracts) degraded.add(c.address.toLowerCase());
          recompute();
          log.error("root freshness window expired; rejecting on-chain admission until a fresh read succeeds", { err: pollError.message });
          return;
        }
        await refresh()
          .then(() => checkPaidFloor(false))
          .catch((e) => log.warn("root refresh failed within freshness window; keeping recent-roots", { err: e.message }));
      },
      pollIntervalMs,
    ) || (() => {});
  }
  recompute();
  if (quiet) return { count: want.static ? staticCount : null, contracts, admits, degraded: Array.from(degraded), provider, close: stopRootPolling };

  // Startup lines. `root source: on-chain RootProvider` / `members.json (PoC fallback)` are the
  // pre-T-FEAT-7 substrings scripts grep; the ABI-file `roots:` line names every source.
  const desc = provider && provider.describe ? provider.describe() : null;
  const stateRootSource = desc ? (desc.provider === "composite" ? Array.from(new Set(desc.children.map((c) => c.stateRootSource))).join(" | ") : desc.stateRootSource) : undefined;
  if (want.onchain) {
    // stateRoot source is logged verbatim so an operator can see whether the admission root is
    // anchored to the sync committee (SHADE_TREE_HELIOS_RPC_URL) or merely RPC-trusted (T-DEV-9b).
    log.info("root source: on-chain RootProvider", { provider: process.env.SHADE_TREE_ROOT_PROVIDER || "node", contracts: contracts.length, recentRoots: chainRoots.length, ...(stateRootSource ? { stateRootSource } : {}) });
  }
  if (want.static) log.info(want.onchain ? "root source: members.json (static, unioned with the chain)" : "root source: members.json (PoC fallback)", { members: staticCount });
  // T-FEAT-9: the admission POLICY line (what this provider chose), then the T-FEAT-7 sources line.
  log.info(describeAdmits(admits), { source: want.source || "injected", policy: "SHADE_TREE_ADMIT (default invited = max-anon; docs/adr/0008)" });
  log.info(describeRootSources({ static: want.static, contracts: want.onchain ? contracts : [] }), {
    trustedRoots: recentRoots.size,
    ...(want.static ? { static: staticRoot ? 1 : 0 } : {}),
    ...Object.fromEntries(perSource.map((p) => [`${(contracts.find((c) => c.address.toLowerCase() === String(p.contract || "").toLowerCase()) || {}).kind || "staked"}:${String(p.contract || "").slice(0, 10)}`, p.roots.length])),
  });
  if (want.onchain) await checkPaidFloor(true);
  return { count: want.static ? staticCount : null, contracts, admits, degraded: Array.from(degraded), provider, close: stopRootPolling };
}

// ---- share-collecting spent-set (RLN slashing at PoC fidelity) --------------
// Keyed by `nullifier` alone (there is no public slot in RLN v3 — the messageId is a
// private circuit witness). Stores the first share; a second DISTINCT evaluation point
// (distinct public `x`) under the same nullifier is a provable over-spend: reconstruct
// the identitySecret from the two shares, derive the rateCommitment leaf, and slash. An
// IDENTICAL replay (same share.x) is NEVER slashed (no new point) — but see below for
// exactly WHEN that identical replay egresses vs is rejected.
//
// ---- cross-gateway replay defense: per-epoch seen-envelope cache (T-FEAT-12) ----
// Target binding (T-DEV-3) stops a captured proof being REDIRECTED to a new target, but an
// EXACT-envelope replay (same nullifier + same share.x + same nonce/target) to the SAME
// gateway still passed the nullifier dedup as an "honest retry" and egressed idempotently,
// with no time bound. A malicious relay could therefore replay a member's captured envelope
// to peer gateways and amplify apparent traffic on one proof. We add a per-gateway defense:
//
//   The seen-envelope cache fingerprints each admitted envelope by (nullifier, share.x,
//   nonce) and records WHEN it was first seen HERE. On an identical share.x under a live
//   nullifier:
//     - age <= SHADE_TREE_REPLAY_WINDOW_MS  => an in-flight HONEST retry (e.g. a dropped
//       connection re-sent within a few seconds). Idempotent: action "replay", ok:true,
//       NO second egress, NO slash. This preserves the deterministic-retry allowance.
//     - age  > SHADE_TREE_REPLAY_WINDOW_MS  (or a fingerprint we never recorded, e.g. same
//       share.x under a different nonce) => an ABUSIVE late replay. Rejected ok:false,
//       action/reason "replayed-envelope"; the handler counts the drop metric + logs.
//
// Why a SHORT window is the right scoping, and why it does not break failover: the client
// reuses the SAME envelope across gateway FAILOVER, but failover hits DIFFERENT gateways,
// so a PER-gateway cache never sees that legitimate reuse twice. Only a genuine same-gateway
// resend (dropped connection) repeats here, and it does so within seconds — comfortably
// inside the window. Anything repeating on ONE gateway seconds/minutes later is a replay.
//
// CROSS-FLEET (T-FEAT-20): the per-gateway cache above defends ONE gateway only. A
// non-colluding fleet still has no SHARED spent-set, so a malicious relay can fan a captured
// envelope out to its PEERS (each sees it once). The optional `sharedTally` (gateway/fleet-
// tally.mjs) narrows that window: on a nullifier we have NOT seen locally, we first ask the shared
// tally whether a PEER already admitted it this epoch and, if so, reject it as an exact
// cross-node replay. We publish a first-seen nullifier only after its destination connection
// succeeds, so a DNS refusal or failed TCP dial can safely fail over to another node. Only
// (nullifier, epoch) crosses the tally — never share.y,
// target, or member identity (see the privacy note in fleet-tally.mjs). The tally is consulted
// ONLY on the first-locally-seen branch, so the local slash path (2nd distinct share.x) and the
// honest-retry window are UNCHANGED, and it is fail-OPEN: any tally error degrades to exactly
// the per-gateway defense. sharedTally=null (the default) => byte-identical to T-FEAT-12.
//
// reconstruct/derive/slash are injected so the selftest can drive this control flow with
// mocks (the real lib + on-chain slasher land at combine). `now` is injectable so the
// window is deterministically testable without a real wall clock.
export function makeSpentSet({
  reconstruct = reconstructSecret,
  derive = resolveSlashTier,
  slash,
  sharedTally = null,
  ttlMs = 2 * EPOCH_SECONDS * 1000,
  replayWindowMs = Number(process.env.SHADE_TREE_REPLAY_WINDOW_MS) || 5000,
  now = () => Date.now(),
} = {}) {
  const seen = new Map();    // nullifier -> { xs:Set, first:share, slashed:bool, at:number }
  const seenEnv = new Map(); // "nullifier|share.x|nonce" -> firstSeenAt (exact-envelope fingerprints)
  const keyOf = (nullifier) => String(nullifier);
  const envKeyOf = (nullifier, share, nonce) => `${nullifier}|${share.x}|${nonce ?? ""}`;

  async function admit(nullifier, share, opts = {}) {
    if (!share || share.x == null) return { ok: false, action: "bad-share", reason: "no-share" };
    const nonce = opts.nonce;
    const k = keyOf(nullifier);
    const ek = envKeyOf(nullifier, share, nonce);
    const e = seen.get(k);

    if (!e) {
      // First time THIS gateway sees this nullifier. Before admitting, ask the shared fleet
      // tally whether a PEER already admitted it this epoch — if so, this is an exact
      // cross-node replay (a captured envelope fanned to us), reject it. `has()` is fail-open:
      // an unreachable/throwing tally returns false and we fall through to the local admit, so
      // a tally outage degrades to the per-gateway defense, never denies a legitimate member.
      if (sharedTally && sharedTally.has(nullifier, opts.epoch)) {
        log.debug("replayed envelope rejected", { scope: "fleet" });
        return { ok: false, action: "replayed-envelope", reason: "replayed-envelope", scope: "fleet" };
      }
      const t = now();
      seen.set(k, { xs: new Set([String(share.x)]), first: share, slashed: false, at: t });
      seenEnv.set(ek, t);
      return { ok: true, action: "first" };
    }
    if (e.slashed) return { ok: false, action: "slashed", reason: "rate-slashed" };
    if (e.xs.has(String(share.x))) {
      // Identical evaluation point == an exact-envelope replay to THIS gateway. Distinguish
      // an in-flight honest retry (within the window) from an abusive late replay.
      const firstAt = seenEnv.get(ek);
      if (firstAt != null && (now() - firstAt) <= replayWindowMs) {
        return { ok: true, action: "replay" }; // idempotent honest retry (dropped-conn resend)
      }
      // Out-of-window, or a fingerprint we never recorded (same share.x, foreign nonce): drop.
      log.debug("replayed envelope rejected", {
        ageMs: firstAt != null ? now() - firstAt : null,
        windowMs: replayWindowMs,
      });
      return { ok: false, action: "replayed-envelope", reason: "replayed-envelope" };
    }

    // Distinct public x under the same nullifier: the L+1-th point. Over-spend.
    e.slashed = true; // slash exactly once for this nullifier
    M.slashes.inc(); // one over-spend detected (counted at the point we decide to slash)
    let commitment = null;
    try {
      const secret = reconstruct(e.first, share); // identitySecret
      // `derive` returns either the leaf (string) or { commitment, limit, resolved } (tiers).
      const d = derive(secret);
      const tier = d && typeof d === "object" ? d : { commitment: d, limit: undefined, resolved: undefined };
      commitment = tier.commitment;               // rateCommitment leaf
      if (slash) await slash(commitment, secret, tier);
    } catch (err) {
      // Provider errors may echo transaction calldata, which contains the reconstructed secret.
      // The outcome is actionable; the provider's raw message is not safe log material.
      log.error("slash failed", { reason: "slash-submit-failed", errorType: err?.name || "Error" });
    }
    return { ok: false, action: "slash", reason: "over-spend-slashed", commitment };
  }

  // Publish only after the destination TCP connection is established. Admission remains local
  // before then so a second distinct share can still slash on this node, while a pre-connect
  // DNS/upstream failure does not poison the same envelope's cross-node failover path.
  function commit(nullifier, epoch) {
    if (!sharedTally || !seen.has(keyOf(nullifier))) return;
    try {
      sharedTally.record(nullifier, epoch);
    } catch (e) {
      log.warn("fleet tally publish failed; keeping per-node replay defense", { err: e?.message || "publish-failed" });
    }
  }

  function sweep() {
    const cutoff = now() - ttlMs;
    for (const [k, e] of seen) if (e.at < cutoff) seen.delete(k);
    for (const [ek, at] of seenEnv) if (at < cutoff) seenEnv.delete(ek);
  }

  return { admit, commit, sweep, size: () => seen.size };
}

// ---- on-chain slash submitter (ethers, hot key) -----------------------------
// The gateway's slashing is NOT anonymous and does not need to be: SHADE_TREE_SLASH_KEY is
// an operational hot key, deliberately separate from any member secret. Address +
// rpc come from contracts/deployed.local.json (or env). ethers is imported lazily so
// the gateway still runs without it (falls back to a dry-run log).
async function readDeployed() {
  try {
    return JSON.parse(await readFile(join(HERE, "..", "contracts", "deployed.local.json"), "utf8"));
  } catch {
    return {};
  }
}

// `rootContracts` = the ADMITTED root contracts (initRoots().contracts; T-FEAT-9): only those are
// appended as routing targets. Defaults to every configured contract for callers without a policy.
async function makeSlasher({ rootContracts = configuredContracts() } = {}) {
  const key = process.env.SHADE_TREE_SLASH_KEY;
  const deployed = await readDeployed();
  // Slash TARGETS (T-FEAT-7 routing). SHADE_TREE_SLASH_CONTRACT (or a deployed.local.json) is the
  // PRIMARY — it may name a set that is NOT a root source (the fleet's superseded rln-v3 set,
  // still slashable), which is why it stays independent of the root config. Every configured
  // root contract (the SHADE_TREE_GROUP_CONTRACT list + SHADE_TREE_PAID_ACCESS_CONTRACT) THAT THIS GATEWAY
  // ADMITS (SHADE_TREE_ADMIT, T-FEAT-9) is appended, so an over-spender is slashed on WHICHEVER contract
  // holds its leaf (`limitOf(leaf) != 0`, per makeRoutingSlasher). A configured contract the
  // policy does not admit is not routed to. One address => the plain single-contract slasher.
  const primary = process.env.SHADE_TREE_SLASH_CONTRACT || deployed.stakedReputationSet
    || deployed.StakedReputationSet || deployed.address || null;
  const targets = [];
  const push = (address, kind) => { if (address && !targets.some((t) => t.address.toLowerCase() === address.toLowerCase())) targets.push({ address, kind }); };
  push(primary, "primary");
  for (const c of rootContracts) push(c.address, c.kind);
  const rpcUrl = process.env.SHADE_TREE_RPC_URL || deployed.rpcUrl || "http://127.0.0.1:8545";
  const receiver = process.env.SHADE_TREE_SLASH_RECEIVER || null;

  if (!key || targets.length === 0) {
    log.info("slash: DRY-RUN (set SHADE_TREE_SLASH_KEY + deployed.local.json/SHADE_TREE_SLASH_CONTRACT/SHADE_TREE_GROUP_CONTRACT/SHADE_TREE_PAID_ACCESS_CONTRACT to submit on chain)");
    return async (commitment, secret, tier) => {
      // Log the (public) commitment leaf only; never any bytes of the reconstructed secret.
      log.info("SLASH (dry-run)", { commitment: String(commitment).slice(0, 18) + "..", ...(tier && tier.limit != null ? { limit: tier.limit } : {}) });
    };
  }

  let ethers;
  try {
    ({ ethers } = await import("ethers"));
  } catch {
    log.info("slash: ethers not installed; DRY-RUN only (add `ethers` to package.json)");
    return async (commitment) => log.info("SLASH (dry-run, no ethers)", { commitment: String(commitment).slice(0, 18) + ".." });
  }

  const provider = await makeBoundedJsonRpcProvider(ethers, rpcUrl);
  const wallet = new ethers.Wallet(key, provider);
  const rcv = receiver || wallet.address;
  if (targets.length === 1) return makeOnchainSlasher({ ethers, wallet, address: targets[0].address, receiver: rcv });
  return makeRoutingSlasher({ ethers, wallet, contracts: targets, receiver: rcv });
}

// The on-chain slash submitter proper, over an ethers wallet. Exported (with `ethers` injected)
// so gateway/onchain-tiers.selftest.mjs can drive it against a throwaway anvil.
//
// Three contract shapes (docs/ONCHAIN.md "Tiers on chain", docs/PAYMENTS.md):
//   rln-v3  slash(commitment, secret, receiver)          — hasher pins K=8; only tier-8 leaves
//   rln-v4  slash(commitment, secret, limit, receiver)   — T-FEAT-8b tiered: the leaf is
//           recomputed at the CLAIMED limit and that tier's bond burns; `limitOf(commitment)`
//           names the tier a leaf was staked at; `allowedLimits()` is the admitted tier table.
//           Fresh slash-burn-v1 sets burn >=90% and pay receiver <=10%; older addresses
//           retain the full payout. The ABI alone does not establish the penalty policy.
//   paid    PaidAccessSet: the SAME tiered slash signature (no bond to burn — the price is
//           already the operator's; the leaf is zeroed so the over-spender's access ends).
// Detected ONCE at startup by probing `DEFAULT_LIMIT()` (v4/paid only). Against a tiered set the
// tier is resolved in this order: the local resolution (members.json leaves), else the contract's
// own record — `limitOf` over the candidate leaves of every known tier (SHADE_TREE_TIERS ∪
// allowedLimits()); a leaf the contract does not hold is not slashable on it anyway.
// The returned function also carries `.holds(secret, tier)` -> { leaf, limit } | null (does THIS
// contract hold a live leaf of the secret?), `.address` and `.tiered`, for makeRoutingSlasher.
export async function makeOnchainSlasher({ ethers, wallet, address, receiver }) {
  const ABI = [
    "function slash(uint256 commitment, uint256 secret, address receiver)",
    "function slash(uint256 commitment, uint256 secret, uint256 limit, address receiver)",
    "function limitOf(uint256 commitment) view returns (uint256)",
    "function allowedLimits() view returns (uint256[])",
    "function DEFAULT_LIMIT() view returns (uint256)",
    "function isActive(uint256 commitment) view returns (bool)",
    "event SlashPayout(uint256 indexed commitment, address indexed receiver, uint256 burned, uint256 reward)",
  ];
  const contract = new ethers.Contract(address, ABI, wallet);
  let tiered = false;
  let tiers = TIERS.slice();
  try {
    await contract.DEFAULT_LIMIT();
    tiered = true;
    const onChain = (await contract.allowedLimits()).map(Number);
    tiers = Array.from(new Set([...tiers, ...onChain])).sort((a, b) => a - b);
  } catch {
    tiered = false; // rln-v3 shape (or unreachable: probed again lazily below on first slash)
  }
  log.info("slash: on-chain", { via: address, receiver, abi: tiered ? "rln-v4 tiered" : "rln-v3 (default tier only)", tiers: tiered ? tiers : [K_SLOTS] });

  // Which live leaf of `secret` does THIS contract hold? Tiered: `limitOf` over the candidates
  // (the locally-resolved tier's leaf first). rln-v3: `isActive` of the default-tier leaf.
  async function holds(secret, tier) {
    const cands = deriveCommitments(secret, tiered ? tiers : [K_SLOTS]);
    if (tier && tier.resolved && tier.commitment != null) {
      cands.sort((a, b) => (String(a.commitment) === String(tier.commitment) ? -1 : String(b.commitment) === String(tier.commitment) ? 1 : 0));
    }
    for (const c of cands) {
      if (tiered) {
        const l = Number(await contract.limitOf(c.commitment));
        if (l !== 0) return { leaf: c.commitment, limit: l };
      } else if (await contract.isActive(c.commitment)) {
        return { leaf: c.commitment, limit: K_SLOTS };
      }
    }
    return null;
  }

  const slash = async (commitment, secret, tier) => {
    let limit = tier && tier.resolved ? Number(tier.limit) : null;
    let leaf = commitment;
    if (tiered && limit == null) {
      // The local set could not name the tier (on-chain root mode holds roots, not leaves):
      // ask the contract which candidate leaf of this secret it actually holds.
      const h = await holds(secret, tier);
      if (h) { limit = h.limit; leaf = h.leaf; }
      if (limit == null) {
        // Not staked at any known tier on this contract: submit the default-tier claim so the
        // revert (NotMember) is on record — same outcome as rln-v3 for an unknown leaf.
        limit = tier && tier.limit != null ? Number(tier.limit) : K_SLOTS;
        log.warn("slash: leaf not held by the contract at any known tier; submitting the default-tier claim", { tiers, limit });
      }
    }
    const tx = tiered
      ? await contract["slash(uint256,uint256,uint256,address)"](leaf, secret, limit, receiver)
      : await contract["slash(uint256,uint256,address)"](leaf, secret, receiver);
    // "SLASH tx <hash>" substring preserved for scripts/integration-sepolia.mjs's regex.
    log.info(`SLASH tx ${tx.hash} (waiting)`, { commitment: String(leaf).slice(0, 18) + "..", via: address, ...(tiered ? { limit } : {}) });
    const rcpt = await waitForTransactionReceipt(tx, { operation: "slash" });
    // Only report an actual split emitted by this set for this leaf. Legacy and paid
    // sets emit no SlashPayout; do not infer a burn from a compatible slash selector.
    let payout;
    for (const entry of rcpt.logs || []) {
      if (entry.address?.toLowerCase() !== address.toLowerCase()) continue;
      let parsed;
      try { parsed = contract.interface.parseLog(entry); } catch { continue; }
      if (parsed?.name === "SlashPayout" && String(parsed.args.commitment) === String(leaf)) {
        payout = { burnedWei: String(parsed.args.burned), rewardWei: String(parsed.args.reward) };
      }
    }
    // "SLASH mined block <n>" substring preserved for scripts/integration-sepolia.mjs's regex.
    log.info(`SLASH mined block ${rcpt.blockNumber}`, { commitment: String(leaf).slice(0, 18) + "..", via: address, ...(tiered ? { limit } : {}), ...payout });
    return { hash: tx.hash, block: rcpt.blockNumber, limit: tiered ? limit : K_SLOTS, commitment: leaf, contract: address, ...payout };
  };
  slash.holds = holds;
  slash.address = address;
  slash.tiered = () => tiered;
  return slash;
}

// makeRoutingSlasher({ ethers, wallet, contracts: [{ address, kind }], receiver }) — T-FEAT-7:
// one makeOnchainSlasher per contract; a reconstructed secret is slashed on the FIRST contract
// (in the given order: SHADE_TREE_SLASH_CONTRACT primary, then the SHADE_TREE_GROUP_CONTRACT list, then the
// paid set) whose `holds(secret)` says it carries a live leaf of it — a paid over-spender lands on
// the PaidAccessSet (leaf zeroed, root changes), a staked one on its StakedReputationSet. If NO
// contract holds it (a members.json-only member, or a set this gateway is not configured to
// slash), the primary receives the default-tier claim exactly as the single-contract slasher
// would (the revert is on record). Exported for the selftest.
export async function makeRoutingSlasher({ ethers, wallet, contracts, receiver }) {
  const slashers = [];
  for (const c of contracts) {
    slashers.push({ ...c, slash: await makeOnchainSlasher({ ethers, wallet, address: c.address, receiver }) });
  }
  log.info("slash: routing over " + slashers.map((s) => `${s.kind}(${s.address})`).join(" + "), { contracts: slashers.length });
  const route = async (commitment, secret, tier) => {
    for (const s of slashers) {
      let h = null;
      try { h = await s.slash.holds(secret, tier); } catch (e) { log.warn("slash: holds() probe failed; skipping contract", { via: s.address, err: e.message }); continue; }
      if (h) {
        log.info(`slash: routed to ${s.kind}(${s.address})`, { commitment: String(h.leaf).slice(0, 18) + "..", limit: h.limit });
        return s.slash(h.leaf, secret, { commitment: h.leaf, limit: h.limit, resolved: true });
      }
    }
    log.warn("slash: no configured contract holds a live leaf of the over-spender; submitting the default claim to the primary", { primary: slashers[0].address });
    return slashers[0].slash(commitment, secret, tier);
  };
  route.slashers = slashers;
  return route;
}

// ---- wire protocol ----------------------------------------------------------

// ---- protocol version negotiation (T-FEAT-11) -------------------------------
// Shade Tree starts at v4. The gateway declares the INCLUSIVE range of envelope versions it
// can parse, checks the
// incoming envelope's `v` against it BEFORE any field is read, and — on a mismatch — advertises
// its range back to the client so the client can re-select (or fail closed with a precise error).
//
// PROTO_MIN/PROTO_MAX are the SINGLE source of truth for the gateway's supported range. Bump
// PROTO_MAX when a new format ships; raise PROTO_MIN only after the old parser is removed.
// The research preview intentionally has no v3 compatibility alias: the rename and new signal
// domain are one breaking v4 boundary. Signed directory capabilities advertise this range.
export const PROTO_MIN = 4;
export const PROTO_MAX = 4;
export const PROTO_RANGE = { min: PROTO_MIN, max: PROTO_MAX };

// An envelope with NO `v` is classified as the old v3 wire, then rejected against the v4-only
// range. Keeping the classification makes the error precise without accepting a protocol whose
// proof domain was renamed.
export const LEGACY_ENVELOPE_VERSION = 3;

// Decide whether we can parse an envelope of version `v`, WITHOUT reading any other field. Pure +
// exported so the selftest drives every branch directly. Returns:
//   { ok:true,  version }                              — in range; hand off to verifyEnvelope
//   { ok:false, reason:"bad-version:<repr>", proto }   — not an integer (garbage / string / float)
//   { ok:false, reason:"unsupported-version:<v>", proto } — a well-formed integer out of range
// `proto` (our advertised range) rides on BOTH rejections so the client learns what we speak.
// `reason` carries the specific value for logs/replies; `label` is a bounded coarse key for metrics.
export function acceptEnvelopeVersion(v, range = PROTO_RANGE) {
  const { min, max } = range;
  const ver = v === undefined || v === null ? LEGACY_ENVELOPE_VERSION : v;
  if (typeof ver !== "number" || !Number.isInteger(ver)) {
    // Reject BEFORE any mis-parse. A string "3", a float, NaN, or an object never reaches
    // verifyEnvelope (which does not inspect `v` at all — this gate is the sole version authority).
    return { ok: false, reason: `bad-version:${versionRepr(v)}`, label: "bad-version", proto: range };
  }
  if (ver < min || ver > max) {
    return { ok: false, reason: `unsupported-version:${ver}`, label: "unsupported-version", proto: range };
  }
  return { ok: true, version: ver, proto: range };
}

// A short, safe repr of an out-of-range/garbage version for the reason string (never dumps a
// large or nested value into a log line or wire reply).
function versionRepr(v) {
  if (v === undefined) return "undefined";
  if (v === null) return "null";
  if (typeof v === "number") return String(v);
  if (typeof v === "string") return JSON.stringify(v.slice(0, 16));
  return typeof v;
}

// Errors carry a bounded `reason` (envelope-timeout | envelope-too-large | bad-envelope) so the
// drop metric can label them without ever putting a client-controlled string on a metric label.
function envelopeError(message, reason) {
  const e = new Error(message);
  e.reason = reason;
  return e;
}

// The envelope deadline is ABSOLUTE from connect (setTimeout armed once, never re-armed on data), so
// a slow-loris client that dribbles one byte at a time inside the timeout cannot hold the read open
// past `timeoutMs` — that is the whole point of a deadline instead of an inactivity timer here.
export function readEnvelope(socket, { timeoutMs = HARDENING.envelopeTimeoutMs } = {}) {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const nl = buf.indexOf(0x0a);
      // The cap applies to the line itself, not merely to newline-free buffers. A peer can send
      // exactly MAX_ENVELOPE bytes, then append more bytes and the newline in one later chunk;
      // checking only the `nl === -1` branch would let that oversized line through.
      if (nl > MAX_ENVELOPE || (nl === -1 && buf.length > MAX_ENVELOPE)) {
        cleanup(envelopeError("envelope too large", "envelope-too-large"));
        return;
      }
      if (nl === -1) return;
      const line = buf.subarray(0, nl).toString("utf8");
      const rest = buf.subarray(nl + 1); // any early bytes after the envelope
      cleanup(null, line, rest);
    };
    const onErr = (e) => cleanup(e);
    const onEnd = () => cleanup(envelopeError("closed before envelope", "bad-envelope"));
    // 0 disables the deadline (operator opt-out); the default is the pre-hardening 30s.
    const timer = timeoutMs > 0 ? setTimeout(() => cleanup(envelopeError("envelope timeout", "envelope-timeout")), timeoutMs) : null;
    function cleanup(err, line, rest) {
      if (timer) clearTimeout(timer);
      socket.removeListener("data", onData);
      socket.removeListener("error", onErr);
      socket.removeListener("end", onEnd);
      if (err) reject(err);
      else resolve({ line, rest });
    }
    socket.on("data", onData);
    socket.on("error", onErr);
    socket.on("end", onEnd);
  });
}

function reply(socket, obj) {
  try { socket.write(JSON.stringify(obj) + "\n"); } catch {}
}

// ---- configurable egress target policy (T-DEV-10) ---------------------------
// A pure, unit-testable policy layer over `host:port` egress targets. Semantics:
// default-DENY — a target must match an ALLOW pattern AND no DENY pattern. Deny is
// evaluated first, so deny wins. Patterns are `host:port` where:
//   host: `*` (any host) | `*.suffix` (subdomains of suffix, NOT the bare apex) | exact
//   port: `*` (any port) | an exact number in 1..65535
// Multiple patterns are comma-separated. Malformed patterns are dropped safely (a
// garbage entry never widens or breaks the policy).
//
// Default allow = `*:443` with empty deny === EXACTLY the old :443-only rule, so with
// no env set nothing changes: the gateway stays a metadata-only TLS tunnel and never
// sees plaintext.
//
// SECURITY: widening the allow list to non-TLS ports (e.g. `*:80`, `*:8080`) lets the
// gateway observe PLAINTEXT for those connections — it is then NO LONGER a metadata-only
// tunnel but a forward proxy that can read the bytes it carries, an operator opt-in with
// real privacy implications. Keep the default (443-only) unless you accept that trade.
export function makeEgressPolicy({ allow = "*:443", deny = "" } = {}) {
  const parseList = (spec) =>
    String(spec ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
      .map(parseEgressPattern)
      .filter(Boolean); // drop malformed patterns safely
  const allows = parseList(allow);
  const denies = parseList(deny);
  return function isAllowed(host, port) {
    if (typeof host !== "string" || host.length === 0) return false;
    const p = Number(port);
    if (!Number.isInteger(p) || p < 1 || p > 65535) return false;
    // Canonicalize the host before matching. A trailing dot is a FQDN that DNS resolves to the
    // exact same server (so `sub.evil.com.` must be treated as `sub.evil.com`, or an appended dot
    // would evade a host-specific deny), and empty labels (leading/double dot) are invalid hosts.
    // Without this, a gated member could bypass an operator's deny list by appending one dot.
    const h = host.toLowerCase().replace(/\.$/, "");
    if (h.length === 0 || h.startsWith(".") || h.includes("..")) return false; // invalid labels -> drop
    if (denies.some((pat) => matchEgressPattern(pat, h, p))) return false; // deny wins
    return allows.some((pat) => matchEgressPattern(pat, h, p)); // else default-DENY
  };
}

// Parse one `host:port` pattern into { host, port } (port kept as "*" or a number),
// or null when malformed so the caller can drop it. Split on the LAST colon so hosts
// (which never contain ':' in a valid target) are unambiguous.
function parseEgressPattern(spec) {
  const i = spec.lastIndexOf(":");
  if (i <= 0 || i === spec.length - 1) return null; // need non-empty host and port
  const host = spec.slice(0, i).toLowerCase();
  const portStr = spec.slice(i + 1);
  if (portStr === "*") return { host, port: "*" };
  if (!/^\d{1,5}$/.test(portStr)) return null;
  const port = Number(portStr);
  if (port < 1 || port > 65535) return null;
  return { host, port };
}

function matchEgressPattern(pat, host, port) {
  if (pat.port !== "*" && pat.port !== port) return false;
  if (pat.host === "*") return true;
  if (pat.host.startsWith("*.")) return host.endsWith(pat.host.slice(1)); // ".suffix"
  return pat.host === host;
}

// Built once from env at import (unset => default `*:443`, empty deny => today's rule).
const egressPolicy = makeEgressPolicy({
  allow: process.env.SHADE_TREE_EGRESS_ALLOW,
  deny: process.env.SHADE_TREE_EGRESS_DENY,
});

// Returns { ok:true, host, port } for an admitted target, else { ok:false, reason }.
// reason distinguishes a malformed target ("bad-target") from one the policy refuses
// ("bad-target-policy") so the drop metric and error reply are precise.
function validTarget(target, policy = egressPolicy) {
  if (typeof target !== "string") return { ok: false, reason: "bad-target" };
  const m = target.match(/^([a-zA-Z0-9.\-]+):(\d{1,5})$/);
  if (!m) return { ok: false, reason: "bad-target" };
  const port = Number(m[2]);
  if (port < 1 || port > 65535) return { ok: false, reason: "bad-target" };
  if (!policy(m[1], port)) return { ok: false, reason: "bad-target-policy" };
  return { ok: true, host: m[1], port };
}

// A hostname allow-list is not an SSRF boundary by itself: an allowed hostname can resolve to
// loopback, RFC1918, link-local, or another special-purpose address. Resolve once, reject any
// non-public answer, then try only those pinned NUMERIC answers so DNS cannot change between the
// check and connect (DNS rebinding / TOCTOU). Local integration tests can opt in explicitly with
// SHADE_TREE_ALLOW_PRIVATE_TARGETS=1; production defaults remain fail-closed.
const IPV4_NON_PUBLIC = [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
  ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24],
  ["192.0.2.0", 24], ["192.31.196.0", 24], ["192.52.193.0", 24],
  ["192.88.99.0", 24], ["192.168.0.0", 16], ["192.175.48.0", 24],
  ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24],
  ["224.0.0.0", 4], ["240.0.0.0", 4],
];

function ipv4Int(address) {
  const octets = String(address).split(".").map(Number);
  if (octets.length !== 4 || octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return (((octets[0] << 24) >>> 0) + (octets[1] << 16) + (octets[2] << 8) + octets[3]) >>> 0;
}

function inIpv4Cidr(value, base, prefix) {
  const shift = 32 - prefix;
  return (value >>> shift) === (ipv4Int(base) >>> shift);
}

function ipv6BigInt(address) {
  let source = String(address).toLowerCase();
  const zone = source.indexOf("%");
  if (zone !== -1) source = source.slice(0, zone);
  if (net.isIP(source) !== 6) return null;

  // Turn an IPv4 tail into two hextets before expanding `::`.
  const tail = source.match(/(\d+\.\d+\.\d+\.\d+)$/)?.[1];
  if (tail) {
    const v4 = ipv4Int(tail);
    if (v4 === null) return null;
    source = source.slice(0, -tail.length) + `${((v4 >>> 16) & 0xffff).toString(16)}:${(v4 & 0xffff).toString(16)}`;
  }
  const halves = source.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves[1] ? halves[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || (halves.length === 2 && missing < 1)) return null;
  const words = [...left, ...Array(missing).fill("0"), ...right];
  if (words.length !== 8 || words.some((word) => !/^[0-9a-f]{1,4}$/.test(word))) return null;
  return words.reduce((value, word) => (value << 16n) | BigInt(`0x${word}`), 0n);
}

function inIpv6Cidr(value, base, prefix) {
  const baseValue = ipv6BigInt(base);
  const shift = 128n - BigInt(prefix);
  return (value >> shift) === (baseValue >> shift);
}

export function isPublicEgressAddress(address) {
  const family = net.isIP(address);
  if (family === 4) {
    const value = ipv4Int(address);
    return value !== null && !IPV4_NON_PUBLIC.some(([base, prefix]) => inIpv4Cidr(value, base, prefix));
  }
  if (family === 6) {
    const value = ipv6BigInt(address);
    if (value === null || !inIpv6Cidr(value, "2000::", 3)) return false;
    // Special-purpose space inside global-unicast. Blocking the parent 2001::/23 is
    // intentionally conservative: it contains protocol assignments, benchmarking, ORCHID,
    // and other non-general destinations rather than ordinary public hosts.
    return ![
      ["2001::", 23], ["2001:db8::", 32], ["2002::", 16],
      ["2620:4f:8000::", 48], ["3fff::", 20],
    ].some(([base, prefix]) => inIpv6Cidr(value, base, prefix));
  }
  return false;
}

export function privateTargetsAllowed(env = process.env) {
  return env.SHADE_TREE_ALLOW_PRIVATE_TARGETS === "1";
}

export async function resolveEgressTarget(target, {
  lookup = dnsLookup,
  allowPrivateTargets = false,
  timeoutMs = HARDENING.dnsTimeoutMs,
} = {}) {
  const literalFamily = net.isIP(target.host);
  if (literalFamily) {
    if (!allowPrivateTargets && !isPublicEgressAddress(target.host)) {
      return { ok: false, reason: "bad-target-address" };
    }
    return { ...target, address: target.host, family: literalFamily, addresses: [{ address: target.host, family: literalFamily }] };
  }

  let answers;
  let timer = null;
  const timedOut = Symbol("dns-timeout");
  try {
    const pending = Promise.resolve(lookup(target.host, { all: true, verbatim: true }));
    if (timeoutMs > 0) {
      answers = await Promise.race([
        pending,
        new Promise((resolve) => {
          timer = setTimeout(() => resolve(timedOut), timeoutMs);
        }),
      ]);
    } else {
      answers = await pending;
    }
  } catch {
    return { ok: false, reason: "bad-target-dns" };
  } finally {
    if (timer) clearTimeout(timer);
  }
  if (answers === timedOut) return { ok: false, reason: "bad-target-dns" };
  if (!Array.isArray(answers) || answers.length === 0) return { ok: false, reason: "bad-target-dns" };
  const normalized = answers.filter((answer) => answer && net.isIP(answer.address));
  if (normalized.length !== answers.length || (!allowPrivateTargets && normalized.some((answer) => !isPublicEgressAddress(answer.address)))) {
    return { ok: false, reason: "bad-target-address" };
  }
  const seen = new Set();
  const addresses = normalized
    .map((answer) => ({ address: answer.address, family: answer.family || net.isIP(answer.address) }))
    .filter((answer) => {
      const key = `${answer.family}:${answer.address}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    // Validate the complete resolver response above, then cap the pinned dial set. Slicing
    // earlier could hide a private answer beyond the cap; leaving it uncapped lets one proof
    // trigger arbitrarily many outbound connection attempts.
    .slice(0, MAX_EGRESS_ADDRESSES);
  const chosen = addresses[0];
  return { ...target, address: chosen.address, family: chosen.family, addresses };
}

// ---- egress self-check (T-FEAT-16) ------------------------------------------
// A METADATA-ONLY liveness probe of THIS host's clearnet egress, used by the heartbeat
// (bootnode/heartbeat.mjs) to keep a broken gateway out of the fleet. Problem: a gateway
// whose clearnet egress is dead (bad routing, firewall, dead upstream) still ANNOUNCES to
// the bootnode and then DROPs every member routed to it. This probe lets it self-eject:
// the heartbeat runs it before each announce and SKIPS announcing when egress is DOWN, so a
// dead gateway ages out of the bootnode /directory via its TTL while a healthy one keeps
// announcing.
//
// It opens a PLAIN TCP connection to a well-known :443 host and closes it the instant it
// connects. It writes NO bytes, carries NO member traffic, and reads NO data — a pure
// connect()/close liveness check, exactly as metadata-only as the :443 tunnel it guards.
// It touches nothing else: request handling, metrics, the spent-set/replay cache, policy,
// and shutdown are all untouched (this is off the hot path and never runs per-tunnel).
//
// Default target 1.1.1.1:443 (Cloudflare — an always-up anycast host reachable from anywhere
// with working egress). Override with SHADE_TREE_EGRESS_CHECK_TARGET (host:port). Timeout is short
// (SHADE_TREE_EGRESS_CHECK_TIMEOUT_MS, default 5000ms) so a beat is never blocked for long. The
// connector is injected so the selftest drives it with a fake — no real network in the test.
export const EGRESS_CHECK_TARGET = process.env.SHADE_TREE_EGRESS_CHECK_TARGET || "1.1.1.1:443";

export function checkEgress({
  target = EGRESS_CHECK_TARGET,
  timeoutMs = Number(process.env.SHADE_TREE_EGRESS_CHECK_TIMEOUT_MS) || 5000,
  connect = net.connect,
} = {}) {
  return new Promise((resolve) => {
    const s = String(target);
    const i = s.lastIndexOf(":");
    const host = i > 0 ? s.slice(0, i) : s;
    const port = i > 0 ? Number(s.slice(i + 1)) : 443;
    const label = `${host}:${port}`;
    let done = false;
    let socket = null;
    const finish = (healthy, reason) => {
      if (done) return;
      done = true;
      try { clearTimeout(timer); } catch {}
      try { socket && socket.destroy(); } catch {} // close immediately — no bytes ever sent/read
      resolve({ healthy, target: label, reason });
    };
    const timer = setTimeout(() => finish(false, "timeout"), timeoutMs);
    try {
      socket = connect(port, host, () => finish(true, "connected"));
    } catch (e) {
      return finish(false, "connect-threw:" + (e && e.message || e));
    }
    socket?.on?.("error", (e) => finish(false, "connect-error:" + ((e && e.code) || (e && e.message) || e)));
  });
}

// ---- signed egress success receipts (T-FEAT-13) -----------------------------
// OPTIONAL and ADDITIVE. When enabled, a SUCCESSFUL egress reply carries an extra `receipt`
// field: a small object signed by THIS gateway's onion-control key attesting "I (this onion)
// opened a tunnel at epoch E" (lib/receipt.mjs). A client holding the gateway's directory
// pubkey verifies it and accumulates it as gateway liveness/quality evidence (feeds T-FEAT-4).
//
// PRIVACY: the receipt carries NO member identity, NO nullifier (not even a prefix), NO share,
// NO target, NO tunnel nonce, NO fine timestamp/counter — only { v, onion, coarse-epoch, ok }.
// So it can be verified by anyone yet links to neither the member nor the target. See the field
// table in lib/receipt.mjs and docs/RECEIPTS.md.
//
// DEFAULT OFF. With SHADE_TREE_RECEIPTS unset the success reply is EXACTLY `{ ok: true }` — byte-for-
// byte today's path. The receipt signer + identity load happen ONLY when enabled, so an env
// without an onion identity file is never affected. `makeReceipt` is injected into makeHandler
// so the selftest drives it without a real onion or process.
export function receiptsEnabled() {
  return String(process.env.SHADE_TREE_RECEIPTS ?? "0") === "1";
}

// The connect-success reply. With no receipt signer this returns the ORIGINAL `{ ok: true }`
// object unchanged (proved byte-identical in gateway/receipt.selftest.mjs); with one it adds a
// freshly signed `receipt`. Signing failure never breaks egress — the ack degrades to `{ ok:
// true }` (the tunnel still opens; receipts are best-effort evidence, never a gate).
export function successAck(makeReceipt) {
  if (!makeReceipt) return { ok: true };
  try {
    const receipt = makeReceipt();
    return receipt ? { ok: true, receipt } : { ok: true };
  } catch {
    return { ok: true };
  }
}

// Load the gateway's onion identity ({ onion, seed }) — the SAME file the heartbeat announces
// with (SHADE_TREE_GW_IDENTITY, default tor/hs/identity.local.json). Only called when receipts are on.
async function loadReceiptIdentity() {
  const path = process.env.SHADE_TREE_GW_IDENTITY || join(HERE, "..", "tor", "hs", "identity.local.json");
  const id = JSON.parse(await readFile(path, "utf8"));
  if (!id.onion || !id.seed) throw new Error(`identity file ${path} missing onion/seed (run bootnode/keygen.mjs)`);
  return id;
}

// Build the `makeReceipt` closure for main(): signs { onion, currentEpoch(), ok:true } with the
// onion seed on each call. Returns null when receipts are disabled OR the identity can't load
// (fail-open: a missing identity disables receipts, it never blocks egress).
async function makeReceiptSigner() {
  if (!receiptsEnabled()) return null;
  let id;
  try {
    id = await loadReceiptIdentity();
  } catch (e) {
    log.warn("receipts requested (SHADE_TREE_RECEIPTS=1) but identity unavailable; receipts DISABLED", { err: e.message });
    return null;
  }
  log.info("egress receipts enabled", { signer: "onion-control-key" });
  return () => buildReceipt({ onion: id.onion, epoch: currentEpoch(), onionSeedHex: id.seed });
}

// Also driven by lib/zk-artifacts.selftest.mjs with a fake socket (artifact-reject reply path).
// Exported so gateway/hardening.selftest.mjs can run the REAL connection handler on a real
// loopback socket. Verification, target-policy, DNS, and connect seams are injectable ONLY for
// tests (their defaults are the real production functions; main() passes none); the hardening
// knobs default to HARDENING (env) and the limiter to a fresh one.
export function makeHandler(spentSet, {
  makeReceipt = null,
  verify = verifyEnvelope,
  connect = net.connect,
  targetPolicy = egressPolicy,
  lookup = dnsLookup,
  allowPrivateTargets = privateTargetsAllowed(),
  dnsTimeoutMs = HARDENING.dnsTimeoutMs,
  envelopeTimeoutMs = HARDENING.envelopeTimeoutMs,
  idleTimeoutMs = HARDENING.idleTimeoutMs,
  maxPayloadBytes = HARDENING.maxPayloadBytes,
  payloadBudget = null,
  limiter = makeConnLimiter(),
  onTunnelOpen = () => {},
  onTunnelClose = () => {},
  relayCounter = null,
} = {}) {
  const tunnelPayloadBudget = payloadBudget || makePayloadBudget({ maxBytes: maxPayloadBytes });
  return async function handle(socket) {
    socket.setNoDelay(true);
    // A permanent error sink on the client socket (T-HARD-4). Found by the slow-loris selftest: a
    // client that sends a PARTIAL envelope and then half-closes (FIN) made readEnvelope reject
    // (its listeners removed), and the error reply then hit Node's writeAfterFIN, which emits an
    // asynchronous 'error' on a server socket — with no listener that is an uncaught exception
    // and the WHOLE gateway process died. One half-closed connection == a full outage. Every
    // later per-path listener below is additive; this one guarantees there is always at least
    // one, so a peer's socket error can never escalate past that one connection.
    socket.on("error", () => {});
    // Concurrent-connection cap (T-HARD-4): decided at accept, BEFORE any byte is read, so an
    // attacker holding sockets open (with or without an envelope) is bounded at maxConns. The
    // release is bound to `close`, which every exit path below reaches (destroy() or a natural end).
    if (!limiter.acquire()) {
      M.tunnels.inc({ result: "drop", reason: "too-many-connections" });
      reply(socket, { ok: false, err: "too-many-connections" });
      return socket.destroy();
    }
    socket.once("close", () => limiter.release());
    let env;
    try {
      const { line, rest } = await readEnvelope(socket, { timeoutMs: envelopeTimeoutMs });
      env = JSON.parse(line);
      env.__rest = rest;
    } catch (e) {
      // `reason` is our own bounded tag (never client bytes): envelope-timeout for the slow-loris
      // deadline, envelope-too-large for the size cap, bad-envelope for close-before-newline / JSON.
      M.tunnels.inc({ result: "drop", reason: e.reason || "bad-envelope" });
      reply(socket, { ok: false, err: "bad-envelope:" + e.message });
      return socket.destroy();
    }

    // Everything after the envelope parse is guarded: any throw must REPLY, never hang
    // the client (a silent throw here is exactly the bug that left clients waiting).
    try {
      // Step 0: protocol version gate (T-FEAT-11). Run FIRST, before any field is trusted, so an
      // out-of-range/garbage `v` is rejected with a precise reason (and our advertised range) rather
      // than being fed to a parser expecting a different shape. This never bypasses target binding:
      // an accepted version still flows through verifyEnvelope's checks below unchanged.
      const vv = acceptEnvelopeVersion(env.v);
      if (!vv.ok) {
        const reason = gatewayDropLabel(vv.label ?? vv.reason);
        log.debug("tunnel rejected", { reason });
        M.tunnels.inc({ result: "drop", reason });
        reply(socket, { ok: false, err: vv.reason, proto: vv.proto });
        return socket.destroy();
      }

      // Reject lexical garbage and operator-disallowed destinations before spending CPU on a
      // proof. This check is deliberately pure: DNS resolution remains after proof verification
      // and admission below, so unauthenticated peers cannot turn the node into a DNS oracle.
      const tgt = validTarget(env.target, targetPolicy);
      if (!tgt.ok) {
        M.tunnels.inc({ result: "drop", reason: tgt.reason });
        reply(socket, { ok: false, err: tgt.reason });
        return socket.destroy();
      }

      // Steps 1-3, cheap-first, inside the lib: fresh externalNullifier -> share.x binding
      // -> root ∈ recent-roots -> RLN Groth16 verify. Returns the authoritative
      // nullifier/externalNullifier/share (read from the proof's public signals) to act on.
      const t0 = performance.now();
      const v = await verify(env, recentRoots);
      M.verify.observe((performance.now() - t0) / 1000);
      if (!v.ok) {
        const reason = gatewayDropLabel(v.label ?? v.reason);
        log.debug("tunnel rejected", { reason });
        // Metrics use the bounded `label` when the lib supplies one (the T-HARD-8 artifact
        // rejections carry the offending id in `reason`; the label is the coarse key), else the
        // reason itself as before.
        M.tunnels.inc({ result: "drop", reason });
        // An artifact rejection advertises the accepted ids back (like `proto` on a version
        // reject) so the client can re-select a mutual artifact set or fail closed precisely.
        reply(socket, v.artifacts ? { ok: false, err: "gate:" + v.reason, artifacts: v.artifacts } : { ok: false, err: "gate:" + v.reason });
        return socket.destroy();
      }

      // Step 4: nullifier dedup + share collection; slashes on 2nd distinct signal.
      // Pass the envelope nonce so the seen-envelope cache (T-FEAT-12) can reject an
      // exact-envelope replay outside the honest-retry window as "replayed-envelope", and the
      // proof's externalNullifier as the per-epoch scope key for the shared fleet tally
      // (T-FEAT-20). externalNullifier is the fleet-agreed per-epoch value, so both gateways
      // key the same nullifier into the same epoch bucket.
      const res = await spentSet.admit(v.nullifier, v.share, { nonce: env.nonce, epoch: v.externalNullifier });
      if (!res.ok) {
        const reason = gatewayDropLabel(res.reason);
        log.debug("tunnel rejected", { reason });
        M.tunnels.inc({ result: "drop", reason });
        reply(socket, { ok: false, err: res.reason });
        return socket.destroy();
      }

      // Per-nullifier concurrent-tunnel cap (T-HARD-4). Checked AFTER admit on purpose: the
      // spent-set must still see every share (a 2nd DISTINCT share under a nullifier that is
      // pinning tunnels open must still reconstruct + slash), and an exact replay inside the
      // honest-retry window is still admitted — it just cannot pin more than maxPerNullifier
      // tunnels open at once. Released on close of THIS socket only.
      if (!limiter.acquireNullifier(v.nullifier)) {
        log.debug("tunnel rejected", { reason: "nullifier-conn-limit", open: limiter.nullifierCount(v.nullifier) });
        M.tunnels.inc({ result: "drop", reason: "nullifier-conn-limit" });
        reply(socket, { ok: false, err: "nullifier-conn-limit" });
        return socket.destroy();
      }
      let nullifierSlotHeld = true;
      const releaseNullifierSlot = () => {
        if (!nullifierSlotHeld) return;
        nullifierSlotHeld = false;
        limiter.releaseNullifier(v.nullifier);
      };
      // Verification and the spent-set lookup are asynchronous. A client may disappear while
      // either is pending, before this close listener exists. Do not retain its per-nullifier
      // slot or start an upstream connection after its socket has already closed.
      if (socket.destroyed) {
        releaseNullifierSlot();
        return;
      }
      socket.once("close", releaseNullifierSlot);

      // An exact-envelope retry on this node shares the original slot's payload allowance. If
      // that slot already consumed the ceiling, fail before DNS/TCP work and do not manufacture
      // another 40 MiB merely because the member opened a replacement socket.
      const payloadRemaining = tunnelPayloadBudget.acquire(v.nullifier, v.externalNullifier);
      let payloadBudgetHeld = true;
      socket.once("close", () => {
        if (!payloadBudgetHeld) return;
        payloadBudgetHeld = false;
        tunnelPayloadBudget.release(v.nullifier, v.externalNullifier);
      });
      if (payloadRemaining <= 0) {
        log.debug("tunnel rejected", { reason: "payload-limit" });
        M.tunnels.inc({ result: "drop", reason: "payload-limit" });
        reply(socket, { ok: false, err: "payload-limit" });
        return socket.destroy();
      }

      const resolvedTarget = await resolveEgressTarget(tgt, { lookup, allowPrivateTargets, timeoutMs: dnsTimeoutMs });
      if (!resolvedTarget.ok) {
        M.tunnels.inc({ result: "drop", reason: resolvedTarget.reason });
        reply(socket, { ok: false, err: resolvedTarget.reason });
        return socket.destroy();
      }
      if (socket.destroyed) return;

      // Step 5: egress :443 tunnel (unchanged; TLS stays end-to-end).
      let established = false;
      let tunnelOpened = false;
      let upstream = null;
      let gatewayCloseReason = null;
      let relayStreams = [];
      const closeTunnel = () => {
        if (tunnelOpened) {
          tunnelOpened = false;
          onTunnelClose();
        }
        for (const stream of relayStreams) stream.destroy();
        relayStreams = [];
        upstream?.destroy();
      };
      // Attach cleanup before dialing. If the client closes while DNS/TCP connect is pending,
      // the pending upstream is destroyed and a late connect callback cannot create an orphan.
      socket.once("close", closeTunnel);
      const upstreamStarted = performance.now();
      let upstreamConnectObserved = false;
      const observeUpstreamConnect = () => {
        if (upstreamConnectObserved) return;
        upstreamConnectObserved = true;
        M.upstreamConnect.observe((performance.now() - upstreamStarted) / 1000);
      };
      const candidates = resolvedTarget.addresses?.length
        ? resolvedTarget.addresses
        : [{ address: resolvedTarget.address, family: resolvedTarget.family }];
      let candidateIndex = 0;
      const connectDeadlineAt = idleTimeoutMs > 0 ? performance.now() + idleTimeoutMs : Infinity;
      const failConnectTimeout = (candidateSocket = null) => {
        if (candidateSocket && candidateSocket !== upstream) return;
        observeUpstreamConnect();
        M.tunnels.inc({ result: "drop", reason: "upstream-timeout" });
        reply(socket, { ok: false, err: "upstream:ETIMEDOUT" });
        candidateSocket?.destroy();
        socket.destroy();
      };
      const dialNext = () => {
        // Every validated answer shares one absolute connection deadline. Immediate failures
        // may fall through to another pinned address, but DNS fanout cannot multiply the
        // operator's timeout by the number of answers.
        if (performance.now() >= connectDeadlineAt) return failConnectTimeout();
        const candidate = candidates[candidateIndex++];
        let candidateSocket = null;
        candidateSocket = connect(tgt.port, candidate.address, () => {
          if (candidateSocket !== upstream || socket.destroyed) {
            candidateSocket.destroy();
            return;
          }
          established = true;
          if (idleTimeoutMs > 0) candidateSocket.setTimeout(idleTimeoutMs);
          tunnelOpened = true;
          observeUpstreamConnect();
          onTunnelOpen();
          // Cross-node replay evidence represents a real egress, not a failed DNS/TCP attempt.
          // Publishing here preserves failover with the same envelope before any destination
          // connection succeeds while making the established tunnel single-use across the fleet.
          spentSet.commit?.(v.nullifier, v.externalNullifier);
          log.debug("tunnel established", { port: tgt.port });
          M.tunnels.inc({ result: "pass" });
          // Success ack. Default (no signer) => exactly `{ ok: true }` (byte-identical to the
          // pre-receipt path); with a signer => `{ ok: true, receipt }` (T-FEAT-13).
          reply(socket, successAck(makeReceipt));

          // Enforce one opaque, combined payload budget across both relay directions. TLS remains
          // end to end: these transforms see only byte chunks, never HTTP methods, queries, hosts,
          // or streams. The budget key is the admitted RLN epoch+slot, so same-node retries share
          // what remains. The two direction counters receive only bytes actually admitted by the
          // budget; the proof envelope and success acknowledgement are outside the accounting.
          let payloadLimitScheduled = false;
          const closeAtPayloadLimit = (used) => {
            if (payloadLimitScheduled) return;
            payloadLimitScheduled = true;
            queueMicrotask(() => {
              if (!established || gatewayCloseReason) return;
              gatewayCloseReason = "payload-limit";
              M.tunnelCloses.inc({ reason: "payload-limit" });
              log.debug("tunnel closed", { reason: "payload-limit", payloadBytes: used });
              // net.Socket.destroySoon() flushes the already-admitted boundary bytes before
              // teardown. No later chunk can pass because the shared budget is exhausted.
              if (typeof candidateSocket.destroySoon === "function") candidateSocket.destroySoon();
              else candidateSocket.destroy();
              if (typeof socket.destroySoon === "function") socket.destroySoon();
              else socket.destroy();
            });
          };
          const countAgentToDestination = (chunk) => {
            relayCounter?.addAgentToDestination(chunk);
            M.agentToDestinationBytes.inc({}, chunk.length);
          };
          const countDestinationToAgent = (chunk) => {
            relayCounter?.addDestinationToAgent(chunk);
            M.destinationToAgentBytes.inc({}, chunk.length);
          };
          const agentRelay = payloadTransform({
            budget: tunnelPayloadBudget,
            nullifier: v.nullifier,
            epoch: v.externalNullifier,
            count: countAgentToDestination,
            onLimit: closeAtPayloadLimit,
          });
          const destinationRelay = payloadTransform({
            budget: tunnelPayloadBudget,
            nullifier: v.nullifier,
            epoch: v.externalNullifier,
            count: countDestinationToAgent,
            onLimit: closeAtPayloadLimit,
          });
          const closeOnRelayError = () => {
            candidateSocket.destroy();
            socket.destroy();
          };
          agentRelay.on("error", closeOnRelayError);
          destinationRelay.on("error", closeOnRelayError);
          relayStreams = [agentRelay, destinationRelay];

          // Wire destinations first. `__rest` was consumed alongside the proof envelope, so feed
          // it explicitly before attaching the remaining client stream and count it exactly once.
          agentRelay.pipe(candidateSocket);
          destinationRelay.pipe(socket);
          candidateSocket.pipe(destinationRelay);
          if (env.__rest && env.__rest.length) {
            agentRelay.write(env.__rest);
          }
          if (!payloadLimitScheduled) socket.pipe(agentRelay);
        });
        upstream = candidateSocket;
        candidateSocket.setNoDelay(true);
        candidateSocket.on("error", (e) => {
          if (candidateSocket !== upstream) return;
          const reason = upstreamDropLabel(e.code);
          if (!established && candidateIndex < candidates.length && !socket.destroyed) {
            upstream = null;
            candidateSocket.destroy();
            dialNext();
            return;
          }
          if (established) {
            if (!gatewayCloseReason) {
              gatewayCloseReason = "upstream-error";
              M.tunnelCloses.inc({ reason: "upstream-error" });
            }
          } else {
            observeUpstreamConnect();
            M.tunnels.inc({ result: "drop", reason });
            reply(socket, { ok: false, err: "upstream:" + e.code });
          }
          log.debug("upstream connection closed", { reason, established });
          socket.destroy();
        });
        // The upstream sees activity for bytes travelling in either direction, so one timer
        // bounds both a black-holed connect and an idle established relay.
        if (idleTimeoutMs > 0) {
          const remainingConnectMs = Math.max(1, Math.ceil(connectDeadlineAt - performance.now()));
          const laterCandidates = candidates.length - candidateIndex;
          // Give each remaining pinned answer a fair slice of the one total deadline. This
          // preserves fallback when an address black-holes without granting every address a
          // fresh full timeout.
          const candidateTimeoutMs = laterCandidates > 0
            ? Math.max(1, Math.floor(remainingConnectMs / (laterCandidates + 1)))
            : remainingConnectMs;
          candidateSocket.setTimeout(candidateTimeoutMs, () => {
            if (candidateSocket !== upstream) return;
            if (established) {
              gatewayCloseReason = "idle-timeout";
              M.tunnelCloses.inc({ reason: "idle-timeout" });
              log.debug("tunnel closed", { reason: "idle-timeout", idleMs: idleTimeoutMs });
            } else {
              if (candidateIndex < candidates.length && performance.now() < connectDeadlineAt && !socket.destroyed) {
                upstream = null;
                candidateSocket.destroy();
                dialNext();
                return;
              }
              return failConnectTimeout(candidateSocket);
            }
            candidateSocket.destroy();
            socket.destroy();
          });
        }
      };
      dialNext();
      socket.on("error", () => upstream?.destroy());
    } catch (e) {
      // Request-path exceptions may contain peer-controlled values. Keep the default event useful
      // without copying arbitrary traffic metadata into logs.
      log.error("tunnel handler failed", { reason: "internal-error", errorType: e?.name || "Error" });
      M.tunnels.inc({ result: "drop", reason: "internal-error" });
      reply(socket, { ok: false, err: "gateway-error" });
      return socket.destroy();
    }
  };
}

// ---- graceful shutdown / connection draining (T-DEV-8) ----------------------
// OFF the hot path: signal handlers + a small openSockets set only; request handling
// is untouched. On SIGTERM/SIGINT we stop accepting NEW connections (server.close),
// let in-flight tunnels drain, then exit 0. If they outlive the grace window we
// force-destroy the stragglers and exit nonzero. server.close(cb) fires cb once the
// listener is shut AND every existing connection has ended, so the openSockets set is
// needed only to force-close on timeout (never consulted per-tunnel).
//
// Factored out + fully injectable (server, timer, onExit) so the selftest can drive it
// with a fake server + fake sockets + a fake clock, no real process signals involved.
export function makeGracefulShutdown(server, {
  openSockets = new Set(),
  timeoutMs = 10000,
  onExit = (code) => process.exit(code),
  log = console.log,
  label = "gateway",
  onStart = () => {},
  setTimer = setTimeout,
  clearTimer = clearTimeout,
} = {}) {
  let started = false; // idempotent: a second signal during drain is ignored
  return function shutdown(signal) {
    if (started) return;
    started = true;
    log(`${label}: draining (${signal || "shutdown"}); ${openSockets.size} in-flight, no new connections, ${timeoutMs}ms grace`);
    // Stop background control-plane work as soon as draining begins. Runtime cleanup must not
    // be able to prevent the listener from closing, even if one optional subsystem misbehaves.
    try { onStart(); } catch (error) { log(`${label}: shutdown cleanup failed (${error?.name || "Error"}); continuing drain`); }
    let timer = null;
    const finish = (code) => { if (timer) clearTimer(timer); onExit(code); };
    // Arm the grace window FIRST so an immediate (synchronous) clean drain can clear it —
    // force-close whatever is still open and exit nonzero if it elapses.
    timer = setTimer(() => {
      log(`${label}: drain timeout (${timeoutMs}ms) with ${openSockets.size} still open; forcing exit`);
      for (const s of openSockets) { try { s.destroy(); } catch {} }
      finish(1);
    }, timeoutMs);
    timer.unref?.();
    // Stop the listener; cb fires once all existing connections have ended -> clean exit.
    server.close(() => { log(`${label}: drained cleanly, exiting`); finish(0); });
    return timer;
  };
}

// ---- ZK artifact set (T-HARD-8 dual-VK rollout window) ----------------------
// Load the accepted {artifactId -> vkey} set at startup so a mis-configured window
// (SHADE_TREE_ZK_ARTIFACTS pointing an id at the wrong file, a missing vkey, ...) is a loud startup
// error, never a silently-wrong accepted set. verifyEnvelope reads the same process-wide set.
function initArtifacts() {
  const set = getArtifactSet(); // throws with a precise message on a bad config
  log.info("zk artifacts", {
    accepted: set.ids,
    legacy: set.legacyId,
    legacyStatus: set.legacyAccepted ? "accepted (window open: field-less envelopes verify under it)" : "RETIRED (field-less / explicit-legacy envelopes => artifact-retired)",
    source: set.explicit ? "SHADE_TREE_ZK_ARTIFACTS" : "built-in circuits/rln/verification_key.json",
  });
  return set;
}

async function main() {
  const pkg = JSON.parse(await readFile(join(HERE, "..", "package.json"), "utf8"));
  installRuntimeMetrics(metrics, { role: "node", version: pkg.version });
  initArtifacts();
  const roots = await initRoots();
  const slash = await makeSlasher({ rootContracts: roots.contracts });
  // Optional cross-fleet spent-nullifier tally (T-FEAT-20). It stays null unless peers and
  // authentication are configured, so the default makeSpentSet({ sharedTally:null }) path is
  // byte-identical to T-FEAT-12. The bundled transport is best-effort and fail-open.
  const sharedTally = makeConfiguredFleetTally();
  const spentSet = makeSpentSet({ slash, sharedTally });
  const payloadBudget = makePayloadBudget();
  const sweepTimer = setInterval(() => {
    spentSet.sweep();
    payloadBudget.sweep();
  }, EPOCH_SECONDS * 1000);
  sweepTimer.unref();

  // Optional signed success receipts (T-FEAT-13); null unless SHADE_TREE_RECEIPTS=1.
  const makeReceipt = await makeReceiptSigner();

  const limiter = makeConnLimiter();
  const relayTelemetryEnabled = process.env.SHADE_TREE_RELAY_TELEMETRY === "1";
  const relayCounter = makeRelayByteCounter({
    enabled: relayTelemetryEnabled,
    path: relayTelemetryEnabled
      ? process.env.SHADE_TREE_RELAY_TELEMETRY_STATE || join(HERE, "..", "tor", "hs", "relay-telemetry.local.json")
      : null,
  });
  let activeTunnels = 0;
  const server = net.createServer(makeHandler(spentSet, {
    makeReceipt,
    limiter,
    payloadBudget,
    relayCounter,
    onTunnelOpen: () => { activeTunnels += 1; },
    onTunnelClose: () => { activeTunnels = Math.max(0, activeTunnels - 1); },
  }));

  // Track live tunnels for draining (add/delete only — no per-byte work).
  const openSockets = new Set();
  server.on("connection", (s) => { openSockets.add(s); s.on("close", () => openSockets.delete(s)); });

  // Active-tunnels gauge reads openSockets.size at scrape time (the same set draining uses).
  metrics.gauge("shade_tree_gateway_active_tunnels", "Established egress tunnels open right now.").setCollect(() => activeTunnels);
  metrics.gauge("shade_tree_gateway_connections", "Accepted client connections, including pre-verification sockets.").setCollect(() => openSockets.size);

  // Local operator metrics never share the onion listener and can only bind loopback.
  const metricsPort = safeMetricsPort(process.env.SHADE_TREE_METRICS_PORT, [["node backend", LISTEN_PORT]]);
  let metricsServer = null;
  if (metricsPort > 0) {
    metricsServer = listenMetrics({ port: metricsPort, reg: metrics, host: "127.0.0.1", ready: () => server.listening });
    await new Promise((resolve, reject) => {
      metricsServer.once("listening", resolve);
      metricsServer.once("error", reject);
    });
    log.info("operator metrics ready", { event: "metrics.ready", listen: `127.0.0.1:${metricsPort}` });
  }

  server.on("error", (error) => {
    log.error(error.code === "EADDRINUSE"
      ? `port ${LISTEN_PORT} is already in use; stop the other node or set SHADE_TREE_GATEWAY_PORT`
      : "node listener failed", { event: "service.failed", code: error.code || "UNKNOWN" });
    process.exit(1);
  });
  server.listen(LISTEN_PORT, LISTEN_HOST, () => {
    // "gateway up on <host>:<port>" substring preserved for scripts/integration-sepolia.mjs.
    printOperatorBanner({ role: "node", rows: [
      ["listen", `${LISTEN_HOST}:${LISTEN_PORT}`],
      ["admission", roots.admits?.join(",") || process.env.SHADE_TREE_ADMIT || "invited"],
      ["egress", process.env.SHADE_TREE_EGRESS_ALLOW || "*:443"],
      ["payload limit", payloadBudget.maxBytes > 0 ? `${payloadBudget.maxBytes} bytes combined / RLN slot` : "off"],
      ["relay telemetry", relayTelemetryEnabled ? "private reports on" : "off"],
      ["metrics", metricsPort > 0 ? `127.0.0.1:${metricsPort}` : "off"],
      ["logs", `${process.env.SHADE_TREE_LOG_LEVEL || "info"} / ${process.env.SHADE_TREE_LOG_FORMAT || "auto"}`],
    ] });
    log.info(`gateway up on ${LISTEN_HOST}:${LISTEN_PORT}`, { event: "service.ready", epoch: currentEpoch(), epochSeconds: EPOCH_SECONDS, metricsPort });
    const allowDesc = process.env.SHADE_TREE_EGRESS_ALLOW || "*:443";
    const denyDesc = process.env.SHADE_TREE_EGRESS_DENY || "";
    const dflt = allowDesc === "*:443" && !denyDesc;
    log.info("egress policy ready", { allow: allowDesc, deny: denyDesc || "(none)", metadataOnly: dflt });
    if (privateTargetsAllowed()) {
      log.warn("private and special-purpose egress targets are ENABLED; use only for isolated local development", { env: "SHADE_TREE_ALLOW_PRIVATE_TARGETS" });
    }
    log.debug("rate policy", { scheme: "rln-degree-1", defaultSlots: K_SLOTS, slashTiers: TIERS });
    const replayWindowMs = Number(process.env.SHADE_TREE_REPLAY_WINDOW_MS) || 5000;
    log.debug("replay defense ready", { replayWindowMs });
    if (sharedTally) log.info("fleet tally: ON; best-effort per-epoch replay suppression after peer propagation (nullifier+epoch only; fail-open)");
    log.debug("endpoint hardening", { envelopeTimeoutMs: HARDENING.envelopeTimeoutMs, idleTimeoutMs: HARDENING.idleTimeoutMs, maxPayloadBytes: payloadBudget.maxBytes, dnsTimeoutMs: HARDENING.dnsTimeoutMs, maxConns: limiter.maxConns, maxConnsPerNullifier: limiter.maxPerNullifier });
  });

  const timeoutMs = Number(process.env.SHADE_TREE_SHUTDOWN_TIMEOUT_MS || 10000);
  const shutdown = makeGracefulShutdown(server, {
    openSockets,
    timeoutMs,
    label: "node",
    log: (message) => log.info(message, { event: "service.shutdown" }),
    onStart: () => {
      const cleanup = [
        ["spent sweep", () => clearInterval(sweepTimer)],
        ["root polling", () => roots.close?.()],
        ["fleet tally", () => sharedTally?.close?.()],
        ["relay telemetry", () => relayCounter.close()],
        ["metrics", () => metricsServer?.close?.()],
      ];
      for (const [resource, close] of cleanup) {
        try { close(); } catch (error) { log.warn("shutdown resource cleanup failed", { resource, errorType: error?.name || "Error" }); }
      }
    },
  });
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

// Only run the server when invoked directly; importing (the selftest) pulls the
// exported makeSpentSet / makeGracefulShutdown control flow with mocks and installs
// NO signal handlers (only main() does, below).
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => { log.error("node failed", { event: "service.failed", err: e }); process.exit(1); });
}
