// ShadeTreeClient: the Shade Tree client as a LIBRARY (no proxy process).
//
// This is the local proxy's hardened core, callable directly when an integration needs a raw
// tunnel. Most agents should use `shade-tree run -- <command>` and the CONNECT proxy instead:
//
//   import { ShadeTreeClient } from "./packages/node/client/shade-tree-client.mjs";
//   const shadeTree = new ShadeTreeClient({ secret, directory: "…/directory.json", dirSigner, torPort: 9260 });
//   const res  = await shadeTree.fetch("https://api.ipify.org");     // -> { status, headers, body }
//   // or lower level, for your own TLS/protocol:
//   const sock = await shadeTree.connect("api.ipify.org:443");       // raw duplex, tunneled via a gateway
//
// The per-tunnel RLN proof is irreducible (it is what makes the nullifier / rate cap /
// slashing work), so this library mints a fresh proof per connect and preserves the proxy's
// invariants: one proof per CONNECT tunnel, deterministic across gateway failover (same signal
// means the same share), plus slot and gateway rotation.
//
// The client proxy (packages/node/client/shim.mjs) is a thin HTTP-CONNECT front-end over this same class.

import { readFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { randomBytes, createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Duplex } from "node:stream";
import tls from "node:tls";
import https from "node:https";
import { SocksClient } from "socks";
import { currentEpoch, K_SLOTS, normLimit, requestSignal, proveForSlot, loadGroup, cleanUp, clientArtifactIds, selectArtifact } from "../lib/semaphore.mjs";
import { SESSION_CLASSES, buildTicketBook, sessionSignal, sessionInitFields, ticketFields, policyMatches, normalizeOnion } from "../lib/session-tickets.mjs";
import * as semaphoreConfig from "../lib/semaphore.mjs";
// Namespace import (not named): selftests that mock packages/node/lib/rln.mjs need not provide these two; they
// are only touched by makeLeafSourceLoader when a contract is configured.
import * as rln from "../lib/rln.mjs";
import { openIdentity, readIdentityFile } from "../lib/identity-file.mjs";
import { verifyReceipt } from "../lib/receipt.mjs";
import { configuredContracts, loadGroupFromContract } from "../lib/root-provider.mjs";
import { admitPathOfSource, parseLeafSource, envFlag, ADMIT_ORDER } from "../lib/admission.mjs";
import { applyClientNetworkEnv } from "../lib/network-record.mjs";
import {
  ShadeTreeSlotStateError,
  allocatePersistentSlot,
  defaultSlotStatePath,
  migrateLeafCursor,
} from "./slot-state.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
// Namespace access keeps lightweight module-loader tests compatible with older semaphore mocks
// that do not export the clock constant, while production still uses the protocol's one source.
const clientEpochSeconds = () => Number(process.env.SHADE_TREE_EPOCH_SECONDS ?? semaphoreConfig.EPOCH_SECONDS ?? 120);

// ---- leaf-source discovery (T-FEAT-7, docs/PAYMENTS.md) ----------------------------
// A member's leaf lives in exactly one of the sets the gateway trusts (packages/node/gateway/gateway.mjs
// initRoots): the static members.json (friends), a StakedReputationSet (`shade-tree register-member`),
// or the PaidAccessSet (paid access, docs/PAYMENTS.md). The proof must be built against THAT tree, so the client
// looks for its own leaf: members.json first (no chain needed), then each configured contract in
// order (the SHADE_TREE_GROUP_CONTRACT list, then SHADE_TREE_PAID_ACCESS_CONTRACT), rebuilding the tree from
// the event log (packages/node/lib/root-provider.mjs loadGroupFromContract). Returns a loadGroupFn for
// makeSlotPool: async () => { group, root, source }. Every failure names every source tried.
//   - With NO contract configured this is byte-compatible with the pre-T-FEAT-7 client: the
//     static group is returned even when the leaf is not in it (proveForSlot then reports
//     "not in group", as before), and a missing members.json is that read error.
//   - `limit` MUST be the tier the leaf was enrolled / staked / paid at (a different limit is a
//     different leaf) — the discovery error says so.
//   - `only` (T-FEAT-9, SHADE_TREE_LEAF_SOURCE=invited|staked|paid; default "auto"): PIN which set to
//     look in — `invited` = members.json alone, `staked` = the SHADE_TREE_GROUP_CONTRACT sets alone,
//     `paid` = the PaidAccessSet alone. A member with a leaf in more than one set uses it to
//     choose which one to prove from (and therefore which gateways admit it).
export function makeLeafSourceLoader({
  secret, limit = K_SLOTS, env = process.env,
  loadStatic = loadGroup, loadContract = loadGroupFromContract,
  contracts = null, rpcUrl = env.SHADE_TREE_RPC_URL || "http://127.0.0.1:8545",
  only = parseLeafSource(env.SHADE_TREE_LEAF_SOURCE, { name: "SHADE_TREE_LEAF_SOURCE" }),
} = {}) {
  const all = contracts || configuredContracts(env);
  const sources = only === "auto" ? all : all.filter((c) => (c.kind || "staked") === only);
  const publicRootTag = env.SHADE_TREE_STAKE_PROFILE === "public-stake-v1" ? "finalized" : null;
  const wantStatic = only === "auto" || only === "invited";
  const holds = (g, leaf) => !!g && typeof g.indexOf === "function" && g.indexOf(BigInt(leaf)) !== -1;
  return async function discoverGroup() {
    if (only !== "auto" && only !== "invited" && sources.length === 0) {
      throw new Error(`ShadeTreeClient: SHADE_TREE_LEAF_SOURCE=${only} but no ${only} set is configured (set ${only === "paid" ? "SHADE_TREE_PAID_ACCESS_CONTRACT" : "SHADE_TREE_GROUP_CONTRACT"}, or SHADE_TREE_NETWORK with a contracts.json that has one)`);
    }
    // Legacy path first (no contract configured / invited pinned): the static group, exactly as
    // before, even when the leaf is not in it or the secret is not derivable here (fakes in tests).
    if (sources.length === 0) return { ...(await loadStatic()), source: "members.json" };
    const leaf = rln.rateCommitmentOf(rln.identityFor(secret), limit).toString();
    const tried = [];
    if (wantStatic) {
      try {
        const st = await loadStatic();
        if (holds(st.group, leaf)) return { ...st, source: "members.json" };
        tried.push(`members.json (${st.count ?? (st.group && st.group.members ? st.group.members.length : "?")} leaves)`);
      } catch (e) {
        tried.push(`members.json (unreadable: ${e.message})`);
      }
    }
    for (const c of sources) {
      const label = `${c.kind || "staked"}(${c.address})`;
      try {
        const r = await loadContract({ contract: c.address, rpcUrl, ...(publicRootTag ? { blockTag: publicRootTag } : {}) });
        if (holds(r.group, leaf)) return { ...r, source: label };
        tried.push(`${label} (${r.count} leaves)`);
      } catch (e) {
        tried.push(`${label} (unreadable: ${e.message})`);
      }
    }
    throw new Error(
      `ShadeTreeClient: your leaf ${leaf.slice(0, 12)}.. (limit ${limit}) is in none of: ${tried.join(", ")}${only !== "auto" ? ` (SHADE_TREE_LEAF_SOURCE=${only} pins the search to that set)` : ""} — ` +
      "check --limit / SHADE_TREE_LIMIT (it must equal the tier you enrolled, staked or paid at), " +
      "or buy access (docs/PAYMENTS.md), stake (`shade-tree register-member`), or ask the operator to add you to members.json",
    );
  };
}

// ---- slot pool: per-epoch group warm + one slot/tunnel rotation ----------------
// (moved from the client proxy; the deterministic-retry + rotation invariants live here.)
// `K` is THIS member's tier limit (T-FEAT-8): the userMessageLimit its leaf was enrolled with.
// The pool allocates slots 0..K-1 once per epoch and every proof is made with `limit: K`, so a tier-2 member
// (K=32) gets 32 distinct nullifiers per epoch from the same tree, and a member configured
// with a K its leaf does not carry cannot prove at all (proveForSlot: not in group). A K+1st
// request fails locally; it never wraps into slashable slot reuse.
export class ShadeTreeEpochBudgetError extends Error {
  constructor({ epoch, limit, used = limit, epochSeconds = clientEpochSeconds(), nowMs = Date.now() }) {
    const epochValue = BigInt(epoch);
    const seconds = Number(epochSeconds);
    const resetAtMs = Number(epochValue + 1n) * seconds * 1000;
    const finiteReset = Number.isSafeInteger(resetAtMs) && seconds > 0 ? resetAtMs : null;
    const retryAfterMs = finiteReset == null ? null : Math.max(0, resetAtMs - nowMs);
    super(`Shade Tree epoch budget exhausted: used ${used}/${limit} slots in epoch ${epochValue}; retry after the epoch resets${finiteReset == null ? "" : ` at ${new Date(finiteReset).toISOString()}`}`);
    this.name = "ShadeTreeEpochBudgetError";
    this.code = "SHADE_TREE_EPOCH_BUDGET_EXHAUSTED";
    this.epoch = epochValue.toString();
    this.limit = limit;
    this.used = used;
    this.remaining = 0;
    this.resetAtMs = finiteReset;
    this.resetAt = finiteReset == null ? null : new Date(finiteReset).toISOString();
    this.retryAfterMs = retryAfterMs;
  }
}

export function makeSlotPool({
  secret,
  prove = proveForSlot,
  epochOf = currentEpoch,
  K = K_SLOTS,
  loadGroupFn = loadGroup,
  // Deliberately scary and test-only. Protocol/slashing tests may need to mint a second,
  // distinct signal for one slot. Production callers must never enable this: honest clients
  // stop at K and wait for the next epoch instead of manufacturing slashable evidence.
  unsafeAllowSlotReuseForTests = false,
  // Default-on durable state. `slotStatePath` is an exact advanced override;
  // `slotStateDir` changes only the parent while retaining per-identity-commitment namespacing (#B).
  // There is intentionally no production "off" value. The unsafe reuse seam above is
  // the sole opt-out and exists only for isolated slashing tests.
  slotStatePath,
  slotStateDir,
  slotLockTimeoutMs,
  epochSeconds = clientEpochSeconds(),
  now = Date.now,
}) {
  K = Number(normLimit(K));
  let epoch = null;
  let cursor = 0; // durable nextSlot observed after this process's latest allocation
  let resolvedStatePath;
  let group = null;
  let groupPromise = null;
  let source = null; // the discovered leaf-source label ("members.json" | "staked(0x..)" | "paid(0x..)"), T-FEAT-9

  async function ensureGroup() {
    if (group) return group;
    if (!groupPromise) groupPromise = Promise.resolve(loadGroupFn()).then((g) => { source = g.source ?? source; return (group = g.group); });
    return groupPromise;
  }
  // The leaf source's ADMISSION PATH (invited|staked|paid) once discovered; null when the loader
  // did not label its result (a bare loadGroup / a test fake) -- treated as "unknown" by the client.
  async function leafSource() { await ensureGroup(); return admitPathOfSource(source); }

  function statePath() {
    if (resolvedStatePath) return resolvedStatePath;
    if (slotStatePath !== undefined) {
      if (typeof slotStatePath !== "string" || !slotStatePath.trim() || ["0", "off"].includes(slotStatePath.trim().toLowerCase())) {
        throw new ShadeTreeSlotStateError(
          "SHADE_TREE_SLOT_STATE_UNAVAILABLE",
          "persistent slot state cannot be disabled; use unsafeAllowSlotReuseForTests only in an isolated slashing test",
        );
      }
      resolvedStatePath = slotStatePath;
      return resolvedStatePath;
    }
    // Key by the identity commitment Poseidon1(identitySecret): the same value for every tier
    // and every staking set of this secret, so all its leaves share one per-epoch messageId
    // budget and can never collide on a nullifier. Public (what registerIdentity stakes), so no
    // secret material lands in the path. On first use, carry forward a pre-existing per-leaf
    // cursor so a mid-epoch upgrade keeps its place (JS and Rust agree on both filenames).
    const identity = rln.identityFor(secret);
    const commitment = rln.identityCommitmentOf(identity).toString();
    const newPath = defaultSlotStatePath({ key: commitment, dir: slotStateDir });
    const legacyPath = defaultSlotStatePath({ key: rln.rateCommitmentOf(identity, K).toString(), dir: slotStateDir });
    migrateLeafCursor(newPath, legacyPath, slotLockTimeoutMs != null ? { lockTimeoutMs: slotLockTimeoutMs } : {});
    resolvedStatePath = newPath;
    return resolvedStatePath;
  }

  function rollover(ep) {
    epoch = ep;
    cursor = 0;
    group = null;
    groupPromise = null;
    // Background warm: cache the group + prime the prover so tunnel-time proving is as
    // fast as it can be (the signal-bound proof itself cannot be precomputed).
    Promise.resolve()
      .then(async () => {
        const g = await ensureGroup();
        await prove(secret, ep, 0, requestSignal("precompute:warm", String(ep)), { group: g, limit: K });
      })
      .catch(() => { /* warm is best-effort */ });
  }

  function ensureEpoch() {
    const ep = epochOf();
    if (ep !== epoch) rollover(ep);
    return ep;
  }

  // One slot per tunnel, up to K. Slot reuse with a DISTINCT signal is slashable evidence,
  // so the normal path MUST NOT wrap. Exhaustion is local and typed: an agent can inspect the
  // reset timestamp and retry in the next epoch without ever sending an over-spend.
  function nextSlot() {
    const ep = ensureEpoch();
    if (unsafeAllowSlotReuseForTests) {
      const i = cursor % K;
      cursor += 1;
      return { epoch: ep, slot: i, commit: () => false, release: () => false };
    }
    const allocated = allocatePersistentSlot({ path: statePath(), epoch: ep, limit: K, lockTimeoutMs: slotLockTimeoutMs });
    cursor = allocated.nextSlot;
    if (allocated.exhausted) {
      throw new ShadeTreeEpochBudgetError({ epoch: ep, limit: K, used: allocated.used, epochSeconds, nowMs: now() });
    }
    return {
      epoch: ep,
      slot: allocated.slot,
      // Allocation is committed before it is returned. A crash or local proof error burns
      // capacity; releasing it could let a restarted process manufacture the same nullifier.
      commit: () => false,
      release: () => false,
    };
  }

  return {
    ensureEpoch,
    ensureGroup,
    leafSource,
    nextSlot,
    K,
    statePath: unsafeAllowSlotReuseForTests ? () => null : statePath,
    state: () => {
      const used = cursor;
      return { epoch, cursor: used, remaining: Math.max(0, K - used), source };
    },
  };
}

// ---- protocol version negotiation (T-FEAT-11) -------------------------------
// The range of wire-envelope versions THIS client can emit/parse. Single source of truth on the
// client side (the gateway keeps its own PROTO_MIN/PROTO_MAX). Shade Tree starts at v4; legacy
// unversioned/v3 frames are rejected rather than silently reinterpreted.
export const CLIENT_PROTO_MIN = 4;
export const CLIENT_PROTO_MAX = 4;
export const CLIENT_PROTO_RANGE = { min: CLIENT_PROTO_MIN, max: CLIENT_PROTO_MAX };

// Pick the HIGHEST version both sides support. `gatewayRange` is {min,max} the client has learned
// for this gateway — from a version-reject advertisement (ack.proto), or later from the signed
// directory (deliberate follow-up, T-FEAT-10). When it is unknown (null), we optimistically send
// our own max: a true mismatch then surfaces as an explicit `unsupported-version` reject carrying
// the gateway's real range, which the caller can feed back here to re-select or fail closed.
// Returns { ok:true, version } or { ok:false, reason } — never silently downgrades to a bad guess.
export function selectProtoVersion(gatewayRange, clientRange = CLIENT_PROTO_RANGE) {
  const cMin = clientRange.min, cMax = clientRange.max;
  if (!gatewayRange || gatewayRange.min == null || gatewayRange.max == null) {
    return { ok: true, version: cMax }; // no advertisement yet: emit our best supported version
  }
  const gMin = gatewayRange.min, gMax = gatewayRange.max;
  const hi = Math.min(cMax, gMax); // highest either side will go
  const lo = Math.max(cMin, gMin); // lowest both sides still accept
  if (hi < lo) {
    return { ok: false, reason: `no-mutual-version:client=${cMin}-${cMax},gateway=${gMin}-${gMax}` };
  }
  return { ok: true, version: hi }; // highest mutually supported
}

// ---- ZK artifact-version negotiation (T-HARD-8) -----------------------------
// The client proves with one of its prover artifact sets (packages/node/lib/zk-artifacts.mjs
// loadProverSets, SHADE_TREE_ZK_PROVER_ARTIFACTS, newest first; default = the shipped set) and STAMPS
// the set's content-derived id into the envelope's `artifact` field so a gateway running a
// dual-VK window verifies under the matching vkey. Which id: the newest of ours that the
// gateway advertises in its signed caps (`caps.artifacts`); with no ad, optimistically our
// newest — a real mismatch surfaces as a precise `artifact-unknown/retired` reject that
// carries the gateway's accepted list (`ack.artifacts`). Reject-learned capabilities are keyed
// by candidate onion: one stale or incompatible node must not redefine the whole Grove.

// Build the envelope for one logical tunnel. `signal` is deterministic per tunnel
// (H(target, nonce)); the caller reuses the SAME envelope across failover so a retry
// reproduces the SAME share (deterministic-retry invariant). `version` is the negotiated
// wire version (v4). `artifact` is the negotiated artifact
// id (default = the prover's newest set; `null` = prove with the default set but omit the field,
// i.e. the exact pre-T-HARD-8 wire).
export async function buildEnvelope({ secret, target, pool, prove = proveForSlot, version = CLIENT_PROTO_MAX, artifact }) {
  const nonce = randomBytes(16).toString("hex");
  const signal = requestSignal(target, nonce);
  const reservation = pool.nextSlot();
  const { epoch, slot } = reservation;
  try {
    const group = await pool.ensureGroup();
    // `limit` = the pool's tier K (T-FEAT-8); a pool without one (older fakes) proves at the default.
    const proved = await prove(secret, epoch, slot, signal, { group, artifact: artifact ?? undefined, limit: pool.K ?? K_SLOTS });
    const { proof, nullifier, externalNullifier, share } = proved;
    // The nonce rides in the envelope so the gateway can recompute the signal and BIND the proof to
    // this target (verifyEnvelope check 2b). It reveals nothing (it is random per tunnel) and it is
    // what stops a captured proof from being redirected to a different target. `v` is FIRST so the
    // gateway's version gate reads it without parsing the rest. `artifact` names the ZK artifact set
    // the proof was made with (T-HARD-8): the id the prover actually used (echoed back by
    // proveForSlot), or the requested one for a prover that does not echo; omitted when `null`.
    const artifactId = artifact === null ? null : (proved.artifact ?? artifact ?? null);
    const envelope = artifactId
      ? { v: version, target, nonce, artifact: artifactId, proof, nullifier, externalNullifier, share }
      : { v: version, target, nonce, proof, nullifier, externalNullifier, share };
    reservation.commit?.();
    return { envelope, signal, slot, artifact: artifactId };
  } catch (error) {
    // Persistent allocations are deliberately not returned. The state advance happened before
    // proving, so a process crash at any point cannot make a restart reuse this nullifier. Local
    // failures therefore consume capacity; safety wins over availability.
    reservation.release?.();
    throw error;
  }
}

export const DEFAULT_GATEWAY_ACK_TIMEOUT_MS = 30_000;
export const MAX_GATEWAY_ACK_BYTES = 64 * 1024;
export const DEFAULT_FETCH_TIMEOUT_MS = 120_000;
export const DEFAULT_FETCH_MAX_BODY_BYTES = 8 * 1024 * 1024;

export class ShadeTreeGatewayAckError extends Error {
  constructor(code, message, options = {}) {
    super(message, options);
    this.name = "ShadeTreeGatewayAckError";
    this.code = code;
    this.retryable = true;
  }
}

export class ShadeTreeFetchError extends Error {
  constructor(code, message, details = {}) {
    const { cause, ...fields } = details;
    super(message, cause === undefined ? undefined : { cause });
    this.name = "ShadeTreeFetchError";
    this.code = code;
    Object.assign(this, fields);
  }
}

function positiveDuration(value, fallback) {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 && parsed <= 2_147_483_647
    ? parsed
    : fallback;
}

function positiveByteLimit(value, fallback) {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function destroyFetchResource(resource) {
  try { resource?.destroy?.(); } catch { /* best-effort close on a broken fake/native stream */ }
}

function destroyRejectedSocket(socket) {
  // Never pass the rejection into destroy(): after listener cleanup, destroy(error) may emit an
  // unhandled `error`. The original error is already carried by the rejected promise.
  try { socket.destroy(); } catch { /* best-effort close on a broken fake/native socket */ }
}

// Read one newline-terminated acknowledgement. The acknowledgement frame is bounded independently
// from any target bytes following its newline. Every failure owns and destroys the candidate
// socket, including timeout, EOF/close, transport error, and an oversized unterminated frame.
// Returns { line, rest }.
export function readGatewayAck(socket, { timeoutMs = DEFAULT_GATEWAY_ACK_TIMEOUT_MS, maxBytes = MAX_GATEWAY_ACK_BYTES } = {}) {
  const timeout = Number.isFinite(Number(timeoutMs)) && Number(timeoutMs) > 0
    ? Number(timeoutMs)
    : DEFAULT_GATEWAY_ACK_TIMEOUT_MS;
  const cap = Number.isSafeInteger(Number(maxBytes)) && Number(maxBytes) > 0
    ? Number(maxBytes)
    : MAX_GATEWAY_ACK_BYTES;
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let settled = false;
    const fail = (error) => {
      if (settled) return;
      settled = true;
      cleanup();
      destroyRejectedSocket(socket);
      reject(error);
    };
    const timer = setTimeout(() => fail(new ShadeTreeGatewayAckError(
      "SHADE_TREE_GATEWAY_ACK_TIMEOUT",
      `gateway did not acknowledge within ${timeout}ms`,
    )), timeout);
    const onData = (chunk) => {
      if (settled) return;
      const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      const nl = data.indexOf(0x0a);
      const lineBytes = nl === -1 ? data.length : nl;
      if (size + lineBytes > cap) {
        fail(new ShadeTreeGatewayAckError(
          "SHADE_TREE_GATEWAY_ACK_TOO_LARGE",
          `gateway acknowledgement exceeded ${cap} bytes`,
        ));
        return;
      }
      if (nl === -1) {
        chunks.push(data);
        size += data.length;
        return;
      }
      settled = true;
      cleanup();
      const prefix = nl === 0 ? Buffer.alloc(0) : data.subarray(0, nl);
      const line = chunks.length === 0
        ? prefix.toString("utf8")
        : Buffer.concat([...chunks, prefix], size + prefix.length).toString("utf8");
      resolve({ line, rest: data.subarray(nl + 1) });
    };
    const onErr = (error) => fail(new ShadeTreeGatewayAckError(
      "SHADE_TREE_GATEWAY_ACK_TRANSPORT",
      `gateway acknowledgement transport failed: ${error?.message || error}`,
      { cause: error },
    ));
    const onEnd = () => fail(new ShadeTreeGatewayAckError(
      "SHADE_TREE_GATEWAY_ACK_EOF",
      "gateway ended the connection before acknowledging",
    ));
    const onClose = () => fail(new ShadeTreeGatewayAckError(
      "SHADE_TREE_GATEWAY_ACK_CLOSED",
      "gateway closed the connection before acknowledging",
    ));
    function cleanup() {
      clearTimeout(timer);
      socket.removeListener("data", onData);
      socket.removeListener("error", onErr);
      socket.removeListener("end", onEnd);
      socket.removeListener("close", onClose);
    }
    socket.on("data", onData);
    socket.once("error", onErr);
    socket.once("end", onEnd);
    socket.once("close", onClose);
    // A very fast peer can close between the SOCKS promise resolving and these listeners being
    // attached. Inspect state after attachment so that already-observed EOF/close fails now rather
    // than waiting for the timeout for an event that has already happened.
    if (socket.destroyed || socket.closed) onClose();
    else if (socket.readableEnded) onEnd();
  });
}

// Start the ack reader BEFORE writing, so a synchronous/fake response cannot be missed. A write
// callback error races the bounded ack; the ack timeout also bounds a socket whose write never
// completes. readGatewayAck owns destruction on every rejection.
async function exchangeGatewayAck(socket, wire, options) {
  const ack = readGatewayAck(socket, options);
  if (socket.destroyed || socket.closed || socket.readableEnded) return ack;
  const writeFailure = new Promise((_, reject) => {
    try {
      socket.write(wire, (error) => {
        if (error) reject(new ShadeTreeGatewayAckError(
          "SHADE_TREE_GATEWAY_WRITE_FAILED",
          `gateway write failed: ${error.message || error}`,
          { cause: error },
        ));
      });
    } catch (error) {
      reject(new ShadeTreeGatewayAckError(
        "SHADE_TREE_GATEWAY_WRITE_FAILED",
        `gateway write failed: ${error.message || error}`,
        { cause: error },
      ));
    }
  });
  try {
    return await Promise.race([ack, writeFailure]);
  } catch (error) {
    destroyRejectedSocket(socket);
    throw error;
  }
}

// Only node-local, plausibly transient refusals are safe to route around. Candidate capability
// mismatches are handled separately: they are safe to route around without becoming health
// evidence. Other cryptographic, policy, or replay refusals remain terminal.
export function retryableGatewayRefusal(ack) {
  const reason = typeof ack?.err === "string" ? ack.err : "";
  return reason === "too-many-connections"
    || reason === "nullifier-conn-limit"
    || reason === "gateway-error"
    || reason === "bad-target-dns"
    || reason.startsWith("upstream:");
}

const GATEWAY_ARTIFACT_ID_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const MAX_LEARNED_GATEWAY_ARTIFACTS = 8;

function protoRange(value) {
  if (!Number.isSafeInteger(value?.min) || !Number.isSafeInteger(value?.max)) return null;
  if (value.min < 0 || value.max < value.min) return null;
  return { min: value.min, max: value.max };
}

function artifactIds(value) {
  if (!Array.isArray(value)) return null;
  const ids = [...new Set(value.filter((id) => typeof id === "string" && GATEWAY_ARTIFACT_ID_RE.test(id)))];
  return ids.length > 0 && ids.length <= MAX_LEARNED_GATEWAY_ARTIFACTS ? ids : null;
}

function capabilityRefusal(ack) {
  const reason = typeof ack?.err === "string" ? ack.err : "";
  const proto = protoRange(ack?.proto);
  if (proto && /^(unsupported|bad)-version/.test(reason)) return { kind: "proto", proto };
  const artifacts = artifactIds(ack?.artifacts);
  if (artifacts && /^gate:(artifact-(unknown|retired)|bad-artifact)/.test(reason)) {
    return { kind: "artifacts", artifacts };
  }
  return null;
}

// If the ack chunk carried early tunnel bytes after the newline, prepend them to the
// readable side so nothing is lost (e.g. the target's first TLS record). Returns a Duplex
// that tls.connect({ socket }) and .pipe() both accept.
function tunnelStream(socket, rest) {
  if (!rest || !rest.length) return socket;
  const dup = new Duplex({
    read() {},
    write(chunk, enc, cb) { socket.write(chunk, enc, cb); },
    final(cb) { socket.end(cb); },
    destroy(err, cb) { socket.destroy(err); cb(err); },
  });
  dup.push(rest);
  socket.on("data", (c) => dup.push(c));
  socket.on("end", () => dup.push(null));
  socket.on("error", (e) => dup.destroy(e));
  return dup;
}

// ---- per-tunnel SOCKS circuit isolation (T-FEAT-17) ----------------------------
// Tor with `IsolateSOCKSAuth` (packages/node/bootnode/deploy/torrc.hardened, T-HARD-7) forks a SEPARATE
// circuit per distinct SOCKS username/password pair. The client sends NO auth today, so
// every tunnel through a given SocksPort may share one circuit — collapsing per-tunnel gateway
// and slot rotation back onto a shared Tor path. Give each tunnel a unique SOCKS credential.
//
// socksAuthForTunnel(seed) -> { userId, password }, two opaque 16-byte hex tags Tor only
// compares for equality:
//   - seed given (the tunnel nonce): the credential is derived deterministically from it,
//     so it is distinct across tunnels yet stable across failover for one tunnel.
//   - seed omitted: a fresh random credential (each call = a new circuit).
//
// RETRY / CIRCUIT DECISION: we seed from the tunnel nonce (connect() passes envelope.nonce)
// so a retry of the same tunnel — an onion cold-start retry inside _dial, or a
// failover to another gateway — REUSES THE SAME circuit identity, mirroring the
// deterministic-retry invariant (same signal => same share across failover). We deliberately
// prefer this over a fresh circuit per dial attempt: cross-tunnel unlinkability is the
// property that matters, and distinct tunnels get distinct credentials; pinning one tunnel
// to one circuit identity avoids fanning it across multiple guards/circuits (extra correlation
// vantage points) for no unlinkability gain. (A fresh-per-attempt credential is also safe — just call with no seed — but that is
// not the safer default.)
//
// CAVEAT — a Tor daemon WITHOUT IsolateSOCKSAuth, or any plain no-auth SOCKS5 proxy: the
// socks lib always advertises NoAuth and only ADDS username/password to its method list when
// a credential is present; if the server selects NoAuth it proceeds WITHOUT sending the
// credential (an ordinary SOCKS5 connect). So these credentials are harmless — Tor without
// the flag just ignores them, and a no-auth proxy never negotiates them. Tor WITH the flag
// selects username/password (to enable isolation) and forks a circuit per credential.
export function socksAuthForTunnel(seed) {
  if (seed == null) {
    return { userId: randomBytes(16).toString("hex"), password: randomBytes(16).toString("hex") };
  }
  const tag = (label) =>
    createHash("sha256").update("shade-tree-socks-isolation:" + label + ":").update(String(seed)).digest("hex").slice(0, 32);
  return { userId: tag("uid"), password: tag("pwd") };
}

// The member credential, in one of two forms (#251):
//   - the app secret: { secret } / SHADE_TREE_SECRET (from `shade-tree enroll`); the identity is derived from it;
//   - an identity file, the one `shadenet init` writes and the Rust client reads: { identity } (its text,
//     parsed object, or a FileIdentity), { identityFile } / SHADE_TREE_IDENTITY (a path). A passphrase-
//     protected file needs { passphrase }, SHADE_TREE_PASSPHRASE_FILE or SHADE_TREE_PASSPHRASE.
// An option wins over the environment. Two credentials at one level (a secret and an identity
// file both as options, or both environment variables with no option choosing) are refused: the
// client must not quietly prove as the other member. Returns the app secret (string) or a
// FileIdentity; everything downstream takes either.
export function memberCredential(opts = {}, env = process.env) {
  const passphrase = () => {
    if (opts.passphrase != null) return String(opts.passphrase);
    if (env.SHADE_TREE_PASSPHRASE_FILE) {
      let text;
      try { text = readFileSync(env.SHADE_TREE_PASSPHRASE_FILE, "utf8"); } catch (e) {
        throw new Error(`ShadeTreeClient: read passphrase file ${env.SHADE_TREE_PASSPHRASE_FILE}: ${e.code || e.message}`);
      }
      return text.replace(/[\r\n]+$/, "");
    }
    return env.SHADE_TREE_PASSPHRASE || undefined;
  };
  // The passphrase is read only when the file turns out to be sealed.
  const open = (read) => {
    try {
      return read(undefined);
    } catch (e) {
      if (!/passphrase-protected/.test(e.message)) throw new Error(`ShadeTreeClient: ${e.message}`);
      const phrase = passphrase();
      if (!phrase) throw new Error(`ShadeTreeClient: ${e.message}`);
      try { return read(phrase); } catch (inner) { throw new Error(`ShadeTreeClient: ${inner.message}`); }
    }
  };
  const optionIdentity = opts.identity != null || !!opts.identityFile;
  if (opts.secret && optionIdentity) {
    throw new Error("ShadeTreeClient: `secret` and `identity`/`identityFile` were both given; pass one");
  }
  if (opts.secret) return opts.secret;
  if (opts.identity != null) return open((phrase) => openIdentity(opts.identity, { passphrase: phrase }));
  if (opts.identityFile) return open((phrase) => readIdentityFile(opts.identityFile, { passphrase: phrase }));
  if (env.SHADE_TREE_SECRET && env.SHADE_TREE_IDENTITY) {
    throw new Error("ShadeTreeClient: SHADE_TREE_SECRET and SHADE_TREE_IDENTITY are both set; unset one, or pass --identity or --secret to choose");
  }
  if (env.SHADE_TREE_SECRET) return env.SHADE_TREE_SECRET;
  if (env.SHADE_TREE_IDENTITY) return open((phrase) => readIdentityFile(env.SHADE_TREE_IDENTITY, { passphrase: phrase }));
  throw new Error("ShadeTreeClient: `secret` (or SHADE_TREE_SECRET) is required, or an identity file (`identityFile` / SHADE_TREE_IDENTITY)");
}

export class ShadeTreeClient {
  constructor(opts = {}) {
    this.secret = memberCredential(opts);
    // An identity file fixes the tier: its leaf commits to its `limit`.
    const fileLimit = typeof this.secret === "object" ? this.secret.limit : null;
    if (fileLimit != null && opts.limit != null && Number(opts.limit) !== fileLimit) {
      throw new Error(`ShadeTreeClient: the identity file is tier ${fileLimit}; limit ${opts.limit} would be a different leaf`);
    }
    this.torHost = opts.torHost || process.env.SHADE_TREE_TOR_HOST || "127.0.0.1";
    this.torPort = Number(opts.torPort || process.env.SHADE_TREE_TOR_PORT || 9250);
    this.dialAttempts = Number(opts.dialAttempts || 4);
    // The gateway must acknowledge the envelope before a candidate is considered healthy.
    // These option-only seams keep the production bounds fixed while letting offline tests use
    // small timeouts/caps without sleeping or allocating 64 KiB frames.
    this.gatewayAckTimeoutMs = Number.isFinite(Number(opts.gatewayAckTimeoutMs)) && Number(opts.gatewayAckTimeoutMs) > 0
      ? Number(opts.gatewayAckTimeoutMs)
      : DEFAULT_GATEWAY_ACK_TIMEOUT_MS;
    this.gatewayAckMaxBytes = Number.isSafeInteger(Number(opts.gatewayAckMaxBytes)) && Number(opts.gatewayAckMaxBytes) > 0
      ? Number(opts.gatewayAckMaxBytes)
      : MAX_GATEWAY_ACK_BYTES;
    // fetch() is intentionally bounded even when a destination accepts a tunnel and then stalls
    // or streams forever. Calls may lower/raise either default without changing the result shape.
    this.fetchTimeoutMs = positiveDuration(opts.fetchTimeoutMs, DEFAULT_FETCH_TIMEOUT_MS);
    this.fetchMaxBodyBytes = positiveByteLimit(opts.fetchMaxBodyBytes, DEFAULT_FETCH_MAX_BODY_BYTES);
    // Injectable HTTPS request seam for deterministic transport-boundary selftests.
    this._httpsRequest = opts.httpsRequest || https.request;
    // Per-tunnel SOCKS circuit isolation (T-FEAT-17): default ON, harmless without
    // IsolateSOCKSAuth. Disable with { socksIsolation: false } or SHADE_TREE_SOCKS_ISOLATION=0.
    this.socksIsolation = opts.socksIsolation !== false && process.env.SHADE_TREE_SOCKS_ISOLATION !== "0";
    // Session tickets (ADR 0011): { sessionTickets } or SHADE_TREE_SESSION_TICKETS=1 (the deployment
    // record's `sessionTickets`, set at H2). OFF by default: one proof, one tunnel, per-tunnel
    // rotation. ON: one proof buys a research-v1 book of six tickets at ONE node and the next five
    // tunnels ride cheap ticket envelopes on the same Tor circuit, linkable to that node.
    this.sessionTickets = opts.sessionTickets != null ? Boolean(opts.sessionTickets) : envFlag(process.env.SHADE_TREE_SESSION_TICKETS);
    this._books = new Map();          // onion -> live ticket book
    this._sessionRefused = new Set(); // onions that answered session-unsupported
    // Injectable SOCKS client (tests pass a fake); defaults to the real `socks` lib.
    this._socks = opts.socksClient || SocksClient;
    // Gateway selection: a pinned onion, or a signed directory (fleet rotation). Direct SDK
    // imports do not pass through the CLI, so apply the bundled profile here only after caller
    // options have established whether discovery is explicit.
    if (opts.network) process.env.SHADE_TREE_NETWORK = String(opts.network);
    if (opts.directoryRefreshMs != null) process.env.SHADE_TREE_DIRECTORY_REFRESH_MS = String(opts.directoryRefreshMs);
    if (opts.rotationSpread != null) process.env.SHADE_TREE_ROTATION_SPREAD = String(opts.rotationSpread);
    if (opts.onion) process.env.SHADE_TREE_ONION = String(opts.onion);
    if (opts.bootnode) process.env.SHADE_TREE_BOOTNODE_ONION = String(opts.bootnode);
    if (opts.directory) process.env.SHADE_TREE_DIRECTORY = String(opts.directory);
    if (opts.dirSigner) process.env.SHADE_TREE_DIR_SIGNER = String(opts.dirSigner);
    applyClientNetworkEnv(process.env);
    this.onion = (process.env.SHADE_TREE_ONION || "").replace(/\.onion$/, "") || null;
    this._selection = null;
    // Known gateway protocol range (T-FEAT-11), if the caller learned one out-of-band. null =>
    // unknown; the client optimistically sends its max and reacts to any version-reject. A future
    // directory that carries the range (follow-up) would populate this per candidate.
    this.gatewayRange = opts.gatewayRange || null;
    // ZK artifact ids (T-HARD-8): `artifacts` = the ORDERED (newest first) ids this client can
    // prove with (default: the configured prover sets, SHADE_TREE_ZK_PROVER_ARTIFACTS or the shipped
    // set); `gatewayArtifacts` = a gateway's accepted list learned out-of-band or from a reject.
    this.artifacts = opts.artifacts || null; // null => clientArtifactIds() lazily (loads no circuit)
    this.gatewayArtifacts = opts.gatewayArtifacts || null;
    const configuredRate = {
      scope: "grove-v4",
      window: "fixed",
      epochSeconds: Number(process.env.SHADE_TREE_EPOCH_SECONDS),
      previousEpochsAccepted: 1,
      rootFreshnessSeconds: Number(process.env.SHADE_TREE_ROOT_FRESHNESS_SECONDS),
      payloadBytesPerSlot: Number(process.env.SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES),
    };
    this.ratePolicy = opts.ratePolicy || (
      Number.isSafeInteger(configuredRate.epochSeconds) && configuredRate.epochSeconds > 0 &&
      Number.isSafeInteger(configuredRate.rootFreshnessSeconds) && configuredRate.rootFreshnessSeconds > 0 &&
      Number.isSafeInteger(configuredRate.payloadBytesPerSlot) && configuredRate.payloadBytesPerSlot > 0
        ? configuredRate
        : null
    );
    // Capability rejects belong to the onion that sent them. The legacy singular fields above
    // remain useful for one pinned gateway, but a directory client never lets one candidate's
    // advertisement poison negotiation for every other candidate.
    this._gatewayCapsByOnion = new Map();
    // Injectable prover (tests pass a fake); defaults to the real lib proveForSlot.
    this._prove = opts.prove || proveForSlot;
    // This member's tier limit (T-FEAT-8): { limit } or SHADE_TREE_LIMIT; default K_SLOTS (SHADE_TREE_SLOTS, 8).
    // Must equal the limit the member's leaf was enrolled with (`shade-tree enroll --limit`).
    this.limit = Number(normLimit(fileLimit ?? opts.limit ?? process.env.SHADE_TREE_LIMIT ?? K_SLOTS));
    // Which tree holds this member's leaf (T-FEAT-7): members.json, a staked set, or the paid
    // set — discovered lazily on first use (makeLeafSourceLoader); { loadGroupFn } overrides.
    // T-FEAT-9: { leafSource } / SHADE_TREE_LEAF_SOURCE pins the set (auto = whichever holds the leaf);
    // { maxAnon } / SHADE_TREE_MAX_ANON=1 routes ONLY to invited-only gateways (and refuses to run with
    // a staked/paid leaf, which an invited-only gateway would reject with wrong-group-root).
    this.leafSourcePin = parseLeafSource(opts.leafSource ?? process.env.SHADE_TREE_LEAF_SOURCE, { name: "SHADE_TREE_LEAF_SOURCE" });
    this.maxAnon = opts.maxAnon != null ? Boolean(opts.maxAnon) : envFlag(process.env.SHADE_TREE_MAX_ANON);
    if (this.maxAnon && this.leafSourcePin !== "auto" && this.leafSourcePin !== "invited") {
      throw new Error(`ShadeTreeClient: --max-anon requires an invited (members.json) leaf, but SHADE_TREE_LEAF_SOURCE=${this.leafSourcePin} pins a ${this.leafSourcePin} leaf; an invited-only gateway would reject it (wrong-group-root). Drop --max-anon or use an invited leaf.`);
    }
    this.pool = makeSlotPool({
      secret: this.secret,
      K: this.limit,
      loadGroupFn: opts.loadGroupFn || makeLeafSourceLoader({ secret: this.secret, limit: this.limit, only: this.leafSourcePin }),
      slotStatePath: opts.slotStatePath,
      slotStateDir: opts.slotStateDir,
      slotLockTimeoutMs: opts.slotLockTimeoutMs,
      unsafeAllowSlotReuseForTests: opts.unsafeAllowSlotReuseForTests === true,
    });
    this.pool.ensureEpoch(); // warm the current epoch in the background
  }

  // The admission path of THIS member's leaf (T-FEAT-9): the pin when set, else the discovered
  // source (invited|staked|paid), else "invited" for a loader that does not label its result
  // (a bare members.json loadGroup / a test fake -- the legacy PoC path is the invited set).
  async leafSource() {
    if (this.leafSourcePin !== "auto") return this.leafSourcePin;
    const s = await this.pool.leafSource();
    return s || "invited";
  }

  // The admission constraint handed to selection (T-FEAT-9): which gateways admit our leaf, and
  // the max-anon rule. Under max-anon a staked/paid leaf is refused HERE, before any dial, with
  // the reason (an invited-only gateway would reject the proof with wrong-group-root anyway).
  async _admission() {
    const leafSource = await this.leafSource();
    if (this.maxAnon && leafSource !== "invited") {
      throw new Error(`--max-anon: your leaf is in the ${leafSource} set (${ADMIT_ORDER.indexOf(leafSource) > 0 ? "less anonymous than invited: " : ""}${leafSource === "staked" ? "the staking wallet is linkable to your commitment on chain" : "the buyer address -> operator transfer and tier bucket are public"}); an invited-only gateway would reject it (wrong-group-root). Max-anon requires an invited (members.json) leaf -- drop --max-anon to use gateways that admit ${leafSource}.`);
    }
    // The on-chain sets this leaf lives in (dogfood #234): selection drops nodes whose signed
    // `caps.sets` name other sets, so a client on the wrong record fails before it proves.
    const sets = leafSource === "invited" ? [] : configuredContracts().filter((c) => c.kind === leafSource || leafSource === "auto").map((c) => c.address.toLowerCase());
    return { leafSource, maxAnon: this.maxAnon, sets };
  }

  async _sel() {
    if (!this._selection) this._selection = await import("./selection.mjs");
    return this._selection;
  }

  // Ordered candidates to try this tunnel: pin, else the directory selection (weighted pick
  // first, then failovers), else a local tor/hs/hostname (dev). Each is { onion, artifacts? }
  // where `artifacts` is the gateway's SIGNED accepted-artifact ad from the directory (T-HARD-8),
  // when it advertises one.
  async _candidates(onEvent) {
    if (this.onion) {
      // A pinned onion is the caller's explicit choice: no admission filtering is possible (its
      // policy is unknown here); a mismatch surfaces as the gateway's wrong-group-root reject.
      if (this.maxAnon) await this._admission(); // still refuse a staked/paid leaf under max-anon
      return [{ onion: this.onion, artifacts: this.gatewayArtifacts }];
    }
    const sel = await this._sel();
    if (sel.directoryEnabled()) {
      // T-FEAT-9: route only to gateways whose signed policy admits OUR leaf source (fail closed
      // with a precise fleet summary when none does); --max-anon = invited-only gateways only.
      const adm = await this._admission();
      const requirement = this.ratePolicy ? { rate: this.ratePolicy } : null;
      const cands = await sel.selectCandidates(requirement, adm, { onEvent });
      if (cands.length) return cands.map((c) => ({ onion: c.onion.replace(/\.onion$/, ""), artifacts: c.artifacts || null, admits: c.admits || null, rate: c.rate || null, session: c.session || null }));
    }
    try {
      const host = (await readFile(join(HERE, "../../..", "tor", "hs", "hostname"), "utf8")).trim();
      return [{ onion: host.replace(/\.onion$/, ""), artifacts: null }];
    } catch {
      throw new Error("ShadeTreeClient: no gateway — restore the bundled network profile or set { onion }, { bootnode, dirSigner }, or { directory, dirSigner }");
    }
  }

  _knownGatewayCaps(cand, candidateCount) {
    const onion = String(cand.onion).replace(/\.onion$/, "");
    const learned = this._gatewayCapsByOnion.get(onion) || {};
    // A singular out-of-band capability has no onion key, so it is safe only when this call has
    // one candidate. Multi-node calls use signed candidate caps plus onion-keyed reject learning.
    const singular = candidateCount === 1;
    return {
      onion,
      proto: learned.proto || protoRange(cand.proto) || (singular ? protoRange(this.gatewayRange) : null),
      artifacts: learned.artifacts || artifactIds(cand.artifacts) || (singular ? artifactIds(this.gatewayArtifacts) : null),
    };
  }

  _planEnvelope(cands) {
    const mine = this.artifacts || clientArtifactIds();
    const evaluated = cands.map((cand) => {
      const caps = this._knownGatewayCaps(cand, cands.length);
      return {
        cand,
        caps,
        pv: selectProtoVersion(caps.proto),
        pa: selectArtifact(caps.artifacts, mine),
      };
    });
    const chosen = evaluated.find(({ pv, pa }) => pv.ok && pa.ok);
    if (!chosen) {
      const versionCompatible = evaluated.filter(({ pv }) => pv.ok);
      if (versionCompatible.length === 0) {
        return { ok: false, stage: "version", reason: evaluated[0]?.pv.reason || "no candidate" };
      }
      return { ok: false, stage: "artifact", reason: versionCompatible[0].pa.reason };
    }
    const version = chosen.pv.version;
    const artifact = chosen.pa.id;
    // Preserve directory order while removing only candidates already known not to accept the
    // exact wire profile. Unknown candidates remain eligible. Every actual attempt still receives
    // the byte-identical envelope built below.
    const attempts = evaluated
      .filter(({ caps }) => {
        const protoOk = !caps.proto || (version >= caps.proto.min && version <= caps.proto.max);
        const artifactOk = !caps.artifacts || caps.artifacts.includes(artifact);
        return protoOk && artifactOk;
      })
      .map(({ cand }) => cand);
    return { ok: true, pv: chosen.pv, pa: chosen.pa, cands: attempts };
  }

  // Dial one gateway onion over Tor SOCKS, retrying through onion cold-start.
  // `socksAuth` (T-FEAT-17) is the per-tunnel SOCKS credential; it is reused for every
  // attempt here (and by connect() across gateway failover) so a retry rides the SAME Tor
  // circuit identity. null => legacy no-auth dial. See socksAuthForTunnel above.
  async _dial(onion, attempts = this.dialAttempts, socksAuth = null) {
    let lastErr;
    for (let i = 0; i < attempts; i++) {
      try {
        const proxy = { host: this.torHost, port: this.torPort, type: 5 };
        if (socksAuth) { proxy.userId = socksAuth.userId; proxy.password = socksAuth.password; }
        const { socket } = await this._socks.createConnection({
          proxy,
          command: "connect",
          destination: { host: onion + ".onion", port: 80 },
          timeout: 120000,
        });
        return socket;
      } catch (e) {
        lastErr = e;
        if (i < attempts - 1) await new Promise((r) => setTimeout(r, 3000));
      }
    }
    throw lastErr;
  }

  _gateRefusalError(ack, onion) {
    const candidate = String(onion || "").replace(/\.onion$/, "");
    const learned = capabilityRefusal(ack);
    if (learned && candidate) {
      const previous = this._gatewayCapsByOnion.get(candidate) || {};
      this._gatewayCapsByOnion.set(candidate, { ...previous, ...learned });
      // Preserve the public, singular compatibility fields only for the configured pinned node.
      if (this.onion === candidate) {
        if (learned.proto) this.gatewayRange = learned.proto;
        if (learned.artifacts) this.gatewayArtifacts = learned.artifacts;
      }
    }
    // A version reject advertises the gateway's real range in ack.proto (T-FEAT-11). Surface the
    // precise mutual-range failure and remember it for this onion's next call.
    if (learned?.proto) {
      const re = selectProtoVersion(learned.proto);
      const error = new Error(`gate refused: ${ack.err} (gateway speaks ${learned.proto.min}-${learned.proto.max}; ${re.ok ? "retry as v" + re.version : re.reason})`);
      error.gatewayCapabilityMismatch = true;
      return error;
    }
    // An artifact reject advertises the accepted artifact ids. Remember and report the exact
    // mutual-set result rather than reducing it to a generic invalid-proof error.
    if (learned?.artifacts) {
      const re = selectArtifact(learned.artifacts, this.artifacts || clientArtifactIds());
      const error = new Error(`gate refused: ${ack.err} (gateway accepts artifacts ${learned.artifacts.join(",")}; ${re.ok ? "retry with " + re.id : re.reason})`);
      error.gatewayCapabilityMismatch = true;
      return error;
    }
    return new Error("gate refused: " + (typeof ack.err === "string" && ack.err ? ack.err : "unspecified refusal"));
  }

  // connect("host:port", { onEvent }) -> a raw duplex stream tunneled to the target via a
  // gateway. Builds ONE proof and reuses the SAME envelope across gateway failover
  // (deterministic retry). Throws if the gate refuses or no gateway is reachable. TLS stays
  // end-to-end: do your own tls.connect({ socket }) — the gateway sees only ciphertext.
  // onEvent(e) is an optional progress hook. A live discovery refresh adds the local canopy
  // phase before select; refresh-window and static-directory selections emit no canopy event.
  async connect(target, { onEvent, onion } = {}) {
    const emit = (e) => { try { onEvent?.(e); } catch { /* progress is best-effort */ } };
    // opts.onion pins a specific gateway for this tunnel (else directory/pin/local order).
    let cands;
    try {
      cands = onion ? [{ onion: String(onion).replace(/\.onion$/, ""), artifacts: this.gatewayArtifacts }] : await this._candidates(emit);
    } catch (e) {
      emit({ phase: "select", status: "error", error: e.message });
      throw e;
    }
    emit({ phase: "select", status: "done", leafSource: await this.leafSource().catch(() => null), maxAnon: this.maxAnon, candidates: cands.map((c) => ({ onion: c.onion, admits: c.admits || null })) });

    // Session tickets (ADR 0011): a live book at any candidate spends a ticket before any proof.
    if (this.sessionTickets) {
      const spent = await this._sessionSpend(target, cands, emit);
      if (spent) return spent;
    }

    // Pick one wire profile against the first compatible candidate. Capability knowledge is
    // candidate-local; a disjoint first node is skipped rather than failing the whole client.
    // Unknown nodes remain eligible, and all actual attempts receive the same envelope.
    const plan = this._planEnvelope(cands);
    if (!plan.ok) {
      emit({ phase: "prove", status: "error", error: plan.reason });
      throw new Error(plan.stage + " negotiation failed: " + plan.reason);
    }
    cands = plan.cands;
    const onions = cands.map((c) => c.onion);
    const { pv, pa } = plan;

    // With session tickets on, the proof opens a book at the first session-capable candidate
    // (its SIGNED caps carry `session` with research-v1; a pinned onion is assumed capable until
    // it says otherwise) and the first ticket opens this tunnel.
    if (this.sessionTickets) {
      const sessionCand = cands.find((c) => !this._sessionRefused.has(c.onion) && (c.session ? c.session.classes.includes("research-v1") : !!(this.onion || onion)));
      if (sessionCand) return this._sessionInit(target, sessionCand, { pv, pa }, emit);
    }

    emit({ phase: "prove", status: "start", artifact: pa.id });
    let envelope, slot;
    try {
      ({ envelope, slot } = await buildEnvelope({ secret: this.secret, target, pool: this.pool, prove: this._prove, version: pv.version, artifact: pa.id }));
    } catch (error) {
      emit({
        phase: "prove", status: "error", error: error.message, code: error.code,
        resetAt: error instanceof ShadeTreeEpochBudgetError ? error.resetAt : undefined,
        retryAfterMs: error instanceof ShadeTreeEpochBudgetError ? error.retryAfterMs : undefined,
      });
      throw error;
    }
    // Surface the real proof material for anyone who wants the cryptographic detail: the
    // Groth16 public signals (what the gateway verifies) + the proof points.
    const sp = envelope.proof.snarkProof;
    emit({
      phase: "prove", status: "done", slot, nullifier: envelope.nullifier,
      pub: sp.publicSignals,                         // { y, root, nullifier, x, externalNullifier }
      pi: { a: sp.proof.pi_a, b: sp.proof.pi_b, c: sp.proof.pi_c },
      epoch: String(envelope.proof.epoch), rlnIdentifier: String(envelope.proof.rlnIdentifier),
      artifact: envelope.artifact,
    });
    const wire = JSON.stringify(envelope) + "\n";
    const sel = this.onion ? null : await this._sel();

    // One SOCKS credential for the whole tunnel (derived from its nonce), reused
    // across every gateway failover below so a retry keeps the SAME Tor circuit identity
    // while different tunnels get different circuits (T-FEAT-17).
    const socksAuth = this.socksIsolation ? socksAuthForTunnel(envelope.nonce) : null;

    let sock = null, usedOnion = null, ack = null, rest = Buffer.alloc(0), lastErr = null;
    for (const cand of onions) {
      const t0 = Date.now();
      emit({ phase: "dial", status: "start", onion: cand });
      let candidateSocket = null;
      try {
        candidateSocket = await this._dial(cand, this.dialAttempts, socksAuth);
        candidateSocket.setNoDelay(true);
      } catch (e) {
        destroyRejectedSocket(candidateSocket);
        lastErr = e;
        sel?.reportResult?.(cand, { ok: false });
        emit({ phase: "dial", status: "failover", onion: cand, error: e.message });
        continue;
      }
      emit({ phase: "dial", status: "done", onion: cand, latencyMs: Date.now() - t0 });

      emit({ phase: "gate", status: "start", onion: cand });
      let candidateAck, candidateRest;
      try {
        const frame = await exchangeGatewayAck(candidateSocket, wire, {
          timeoutMs: this.gatewayAckTimeoutMs,
          maxBytes: this.gatewayAckMaxBytes,
        });
        candidateRest = frame.rest;
        try {
          candidateAck = JSON.parse(frame.line);
        } catch (cause) {
          throw new ShadeTreeGatewayAckError(
            "SHADE_TREE_GATEWAY_ACK_INVALID",
            "gateway returned an invalid JSON acknowledgement",
            { cause },
          );
        }
        if (!candidateAck || typeof candidateAck !== "object" || Array.isArray(candidateAck) || typeof candidateAck.ok !== "boolean") {
          throw new ShadeTreeGatewayAckError(
            "SHADE_TREE_GATEWAY_ACK_INVALID",
            "gateway returned a malformed acknowledgement",
          );
        }
      } catch (e) {
        destroyRejectedSocket(candidateSocket);
        lastErr = e;
        sel?.reportResult?.(cand, { ok: false });
        emit({ phase: "gate", status: "error", onion: cand, error: e.message, code: e.code });
        emit({ phase: "dial", status: "failover", onion: cand, error: e.message });
        continue;
      }

      if (candidateAck.ok !== true) {
        const refusal = this._gateRefusalError(candidateAck, cand);
        destroyRejectedSocket(candidateSocket);
        emit({ phase: "gate", status: "refused", onion: cand, error: candidateAck.err, proto: candidateAck.proto, artifacts: candidateAck.artifacts });
        if (refusal.gatewayCapabilityMismatch) {
          // A protocol/artifact mismatch is evidence about this onion's deployment, not the proof
          // or the rest of the Grove. Keep node health unchanged and try the identical wire at the
          // next candidate.
          lastErr = refusal;
          emit({ phase: "dial", status: "failover", onion: cand, error: refusal.message });
          continue;
        }
        if (retryableGatewayRefusal(candidateAck)) {
          lastErr = refusal;
          sel?.reportResult?.(cand, { ok: false });
          emit({ phase: "dial", status: "failover", onion: cand, error: refusal.message });
          continue;
        }
        // Client/proof/policy refusals are terminal and do not poison node health.
        throw refusal;
      }

      const latencyMs = Date.now() - t0;
      sock = candidateSocket;
      usedOnion = cand;
      ack = candidateAck;
      rest = candidateRest;
      // A SOCKS connection alone is not health evidence. Only a node that accepted the exact
      // envelope and returned a bounded `ok:true` acknowledgement is marked healthy.
      sel?.reportResult?.(cand, { ok: true, latencyMs });
      emit({ phase: "gate", status: "done", onion: cand });
      break;
    }
    if (!sock) {
      emit({ phase: "dial", status: "error", error: (lastErr && lastErr.message) || "no gateway" });
      throw lastErr || new Error("no gateway reachable");
    }

    // Optional signed egress success receipt (T-FEAT-13). Purely ADDITIVE: a receipt is present
    // only when the gateway runs with SHADE_TREE_RECEIPTS=1, and its absence never affects the tunnel
    // (today's gateways send `{ ok: true }` with no `receipt` — nothing here fires). When present,
    // verify it against the ONION WE DIALED (self-authenticating pubkey) and the CURRENT epoch, so
    // it counts only as fresh liveness/quality evidence for THIS gateway. A bad receipt is NOT
    // fatal (the egress already succeeded) — it is surfaced as evidence via onEvent + tunnel.shadeTree
    // for a quality-aware selection layer (T-FEAT-4) to weigh.
    const receipt = this._verifyReceipt(ack.receipt, usedOnion, emit);

    // Fold this verified-or-bogus receipt outcome into the LOCAL, per-gateway quality tally
    // (T-FEAT-22's accumulation engine; wired here by T-FEAT-23). Gate on receipt.present so a
    // legacy gateway running with receipts OFF sends none, is never reported, and is never
    // entered into (or penalized in) the tally — keeping this fully ADDITIVE. reportReceipt is
    // itself a no-op unless SHADE_TREE_RECEIPT_SCORING is armed, so this stays byte-identical to today
    // when the flag is off (no tally file is ever written). It is pulled from the SAME lazily
    // imported selection.mjs the client already uses (config captured at import; see _sel + the
    // constructor) rather than a static top-level import that would evaluate selection.mjs before
    // the constructor could set its directory/signer env.
    if (receipt.present) {
      const { reportReceipt } = await this._sel();
      reportReceipt(usedOnion, { valid: receipt.valid === true });
    }

    const tunnel = tunnelStream(sock, rest);
    tunnel.shadeTree = { onion: usedOnion, slot, nullifier: envelope.nullifier, receipt, artifact: envelope.artifact, leafSource: await this.leafSource().catch(() => null) };
    return tunnel;
  }

  // ---- session tickets (ADR 0011) ------------------------------------------------------------
  _liveBook(onion) {
    const book = this._books.get(onion);
    if (!book) return null;
    const now = Date.now();
    const p = book.policy;
    if (book.unused.length === 0 || now - book.openedAt >= p.lifetimeMs - 1000 || now - book.lastUse >= p.idleTimeoutMs - 1000) {
      this._books.delete(onion);
      return null;
    }
    return book;
  }

  // Spend one ticket from a live book at one of `cands`. Resolves null when no usable book
  // exists (the caller proves as usual); throws only for a failure a new proof cannot fix.
  async _sessionSpend(target, cands, emit) {
    for (const cand of cands) {
      const book = this._liveBook(cand.onion);
      if (!book) continue;
      const index = book.unused.shift();
      const requestNonce = randomBytes(16).toString("hex");
      const wire = JSON.stringify({ v: book.version, ticket: ticketFields({ ticketBookDigest: book.digest, index, secret: book.secrets[index], requestNonce }), target }) + "\n";
      const sel = this.onion ? null : await this._sel();
      emit({ phase: "ticket", status: "start", onion: cand.onion, ticket: index, left: book.unused.length });
      let sock;
      try {
        sock = await this._dial(cand.onion, this.dialAttempts, book.socksAuth);
        sock.setNoDelay(true);
      } catch (e) {
        destroyRejectedSocket(sock);
        book.unused.unshift(index); // never sent: the node still holds it unused
        sel?.reportResult?.(cand.onion, { ok: false });
        emit({ phase: "ticket", status: "error", onion: cand.onion, ticket: index, error: e.message });
        throw e;
      }
      let ack, rest;
      try {
        const frame = await exchangeGatewayAck(sock, wire, { timeoutMs: this.gatewayAckTimeoutMs, maxBytes: this.gatewayAckMaxBytes });
        rest = frame.rest;
        ack = JSON.parse(frame.line);
        if (!ack || typeof ack !== "object" || typeof ack.ok !== "boolean") throw new ShadeTreeGatewayAckError("SHADE_TREE_GATEWAY_ACK_INVALID", "gateway returned a malformed acknowledgement");
      } catch (e) {
        destroyRejectedSocket(sock);
        this._books.delete(cand.onion); // ambiguous: the ticket may be burned; a new book is cheaper than guessing
        sel?.reportResult?.(cand.onion, { ok: false });
        emit({ phase: "ticket", status: "error", onion: cand.onion, ticket: index, error: e.message, code: e.code });
        throw e;
      }
      if (ack.ok !== true) {
        destroyRejectedSocket(sock);
        const err = typeof ack.err === "string" ? ack.err : "";
        emit({ phase: "ticket", status: "refused", onion: cand.onion, ticket: index, error: err });
        if (["session-unknown", "session-expired", "session-idle", "session-conflict", "session-unsupported"].includes(err)) {
          this._books.delete(cand.onion); // the node dropped the book: a fresh proof opens another
          continue;
        }
        if ((err.startsWith("upstream:") && !err.includes("ETIMEDOUT")) || err.startsWith("bad-target") || err === "session-streams" || err === "session-pending") {
          book.unused.unshift(index); // the node refunded the ticket; the target is the problem
          throw new Error("gate refused: " + err);
        }
        continue; // ticket-spent / mismatch / conflict: that ticket is lost, try the next book or prove
      }
      book.lastUse = Date.now();
      sel?.reportResult?.(cand.onion, { ok: true });
      emit({ phase: "ticket", status: "done", onion: cand.onion, ticket: index, left: book.unused.length });
      const tunnel = tunnelStream(sock, rest);
      tunnel.shadeTree = { onion: cand.onion, session: book.digest, ticket: index, slot: book.slot, nullifier: book.nullifier, receipt: { present: false }, artifact: book.artifact, leafSource: await this.leafSource().catch(() => null) };
      return tunnel;
    }
    return null;
  }

  // Prove once to open a research-v1 book at `cand`, then spend its first ticket for `target`.
  async _sessionInit(target, cand, { pv, pa }, emit) {
    const classId = "research-v1";
    const policy = SESSION_CLASSES[classId];
    const secrets = Array.from({ length: policy.tickets }, () => randomBytes(32));
    const built = buildTicketBook(secrets);
    const nonce = randomBytes(16).toString("hex");
    const gateway = normalizeOnion(cand.onion);
    const signal = sessionSignal({ gateway, classId, nonce, ticketBookDigest: built.ticketBookDigest });
    emit({ phase: "prove", status: "start", artifact: pa.id, session: classId });
    const reservation = this.pool.nextSlot();
    const { epoch, slot } = reservation;
    let proved;
    try {
      const group = await this.pool.ensureGroup();
      proved = await this._prove(this.secret, epoch, slot, signal, { group, artifact: pa.id ?? undefined, limit: this.pool.K ?? K_SLOTS });
      reservation.commit?.();
    } catch (error) {
      reservation.release?.();
      emit({ phase: "prove", status: "error", error: error.message, code: error.code, resetAt: error instanceof ShadeTreeEpochBudgetError ? error.resetAt : undefined, retryAfterMs: error instanceof ShadeTreeEpochBudgetError ? error.retryAfterMs : undefined });
      throw error;
    }
    const artifactId = proved.artifact ?? pa.id ?? null;
    const envelope = {
      v: pv.version,
      session: sessionInitFields({ classId, gateway, nonce, commitments: built.commitments, ticketBookDigest: built.ticketBookDigest }),
      ...(artifactId ? { artifact: artifactId } : {}),
      proof: proved.proof, nullifier: proved.nullifier, externalNullifier: proved.externalNullifier, share: proved.share,
    };
    emit({ phase: "prove", status: "done", slot, nullifier: proved.nullifier, session: classId, artifact: artifactId });
    const wire = JSON.stringify(envelope) + "\n";
    // One SOCKS credential for the whole book: every ticket of this session rides the same Tor
    // circuit identity (the session is linkable to the node by design; no reason to spend circuits).
    const socksAuth = this.socksIsolation ? socksAuthForTunnel(nonce) : null;
    const sel = this.onion ? null : await this._sel();
    emit({ phase: "session", status: "start", onion: cand.onion, class: classId });
    let sock;
    try {
      sock = await this._dial(cand.onion, this.dialAttempts, socksAuth);
      sock.setNoDelay(true);
    } catch (e) {
      destroyRejectedSocket(sock);
      sel?.reportResult?.(cand.onion, { ok: false });
      emit({ phase: "session", status: "error", onion: cand.onion, error: e.message });
      throw e;
    }
    let ack;
    try {
      const frame = await exchangeGatewayAck(sock, wire, { timeoutMs: this.gatewayAckTimeoutMs, maxBytes: this.gatewayAckMaxBytes });
      ack = JSON.parse(frame.line);
      if (!ack || typeof ack !== "object" || typeof ack.ok !== "boolean") throw new ShadeTreeGatewayAckError("SHADE_TREE_GATEWAY_ACK_INVALID", "gateway returned a malformed acknowledgement");
    } catch (e) {
      destroyRejectedSocket(sock);
      sel?.reportResult?.(cand.onion, { ok: false });
      emit({ phase: "session", status: "error", onion: cand.onion, error: e.message, code: e.code });
      throw e;
    } finally {
      destroyRejectedSocket(sock); // the book, not this socket, is the session handle
    }
    if (ack.ok !== true) {
      if (ack.err === "session-unsupported") this._sessionRefused.add(cand.onion);
      emit({ phase: "session", status: "refused", onion: cand.onion, error: ack.err });
      throw this._gateRefusalError(ack, cand.onion);
    }
    const echo = ack.session || {};
    if (echo.ticketBookDigest !== built.ticketBookDigest || !policyMatches(echo.policy, classId)) {
      // Fail closed: another book or other limits than the compiled class is not a session we hold.
      emit({ phase: "session", status: "refused", onion: cand.onion, error: "session-policy-mismatch" });
      throw new Error("gate refused: session-policy-mismatch (the node echoed a different book or policy)");
    }
    sel?.reportResult?.(cand.onion, { ok: true });
    this._books.set(cand.onion, {
      version: pv.version, digest: built.ticketBookDigest, secrets: built.secrets, commitments: built.commitments, nonce, socksAuth, policy,
      unused: Array.from({ length: policy.tickets }, (_, i) => i), openedAt: Date.now(), lastUse: Date.now(),
      slot, nullifier: proved.nullifier, artifact: artifactId,
    });
    emit({ phase: "session", status: "opened", onion: cand.onion, class: classId, tickets: policy.tickets });
    const tunnel = await this._sessionSpend(target, [cand], emit);
    if (!tunnel) throw new Error("gate refused: session-lost (the node dropped the book before its first ticket)");
    return tunnel;
  }

  // Live books as [{ onion, ticketsLeft }], for status.
  sessionBooks() {
    return [...this._books.keys()].map((onion) => ({ onion, ticketsLeft: this._liveBook(onion)?.unused.length ?? 0 })).filter((b) => b.ticketsLeft > 0);
  }

  // Verify an optional gateway success receipt (T-FEAT-13). Returns a small evidence record
  //   { present, valid, reason?, epoch?, onion? }
  // and emits a "receipt" progress event. `present:false` is the normal legacy case (a gateway
  // with receipts off), NOT a failure. Verification binds the receipt to the dialed onion and the
  // current epoch; a bad receipt is reported (valid:false + reason) but never throws, because the
  // egress already succeeded and a receipt is best-effort quality evidence, not a gate.
  _verifyReceipt(receipt, usedOnion, emit = () => {}) {
    if (!receipt) { const ev = { present: false }; emit({ phase: "receipt", status: "absent", onion: usedOnion }); return ev; }
    let v;
    try {
      v = verifyReceipt(receipt, { onion: usedOnion, epoch: currentEpoch() });
    } catch (e) {
      v = { ok: false, reason: "verify-threw:" + e.message };
    }
    const ev = v.ok
      ? { present: true, valid: true, onion: v.onion, epoch: v.epoch }
      : { present: true, valid: false, reason: v.reason };
    emit({ phase: "receipt", status: v.ok ? "verified" : "invalid", onion: usedOnion, reason: v.ok ? undefined : v.reason, epoch: v.ok ? v.epoch : undefined });
    return ev;
  }

  // fetch(url, opts) -> { status, headers, body }. HTTPS over the tunnel (end-to-end TLS
  // to the target; the gateway only relays ciphertext). opts: { method, headers, body,
  // timeoutMs, maxBodyBytes }. The deadline covers the complete fetch, including connect, TLS,
  // headers, and body. A rejected call owns and destroys any request/response/tunnel it acquired.
  async fetch(url, opts = {}) {
    const emit = (e) => { try { opts.onEvent?.(e); } catch { /* best-effort */ } };
    const u = new URL(url);
    if (u.protocol !== "https:") throw new Error("ShadeTreeClient.fetch: https:// only (the gateway egresses :443)");
    const port = u.port || 443;
    const timeoutMs = positiveDuration(opts.timeoutMs, this.fetchTimeoutMs);
    const maxBodyBytes = positiveByteLimit(opts.maxBodyBytes, this.fetchMaxBodyBytes);

    return new Promise((resolve, reject) => {
      let socket = null;
      let req = null;
      let res = null;
      let settled = false;

      const closeOwnedResources = () => {
        destroyFetchResource(res);
        destroyFetchResource(req);
        destroyFetchResource(socket);
      };
      const fail = (error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        closeOwnedResources();
        emit({ phase: "egress", status: "error", error: error.message, code: error.code });
        reject(error);
      };
      const timer = setTimeout(() => fail(new ShadeTreeFetchError(
        "SHADE_TREE_FETCH_TIMEOUT",
        `ShadeTreeClient.fetch exceeded ${timeoutMs}ms; raise { fetchTimeoutMs } or per-call { timeoutMs } only for a known slow destination`,
        { timeoutMs, retryable: true },
      )), timeoutMs);

      Promise.resolve()
        .then(() => this.connect(`${u.hostname}:${port}`, { onEvent: opts.onEvent, onion: opts.onion }))
        .then((connected) => {
          socket = connected;
          // connect() cannot currently accept an AbortSignal. If it finishes after the public
          // deadline, consume its promise and immediately close the late tunnel.
          if (settled) { destroyFetchResource(socket); return; }
          emit({ phase: "egress", status: "start", target: u.hostname });

          const onResponse = (response) => {
            res = response;
            if (settled) { destroyFetchResource(res); return; }
            const chunks = [];
            let receivedBytes = 0;
            let ended = false;
            const transportFailure = (cause, description = "response failed") => fail(new ShadeTreeFetchError(
              "SHADE_TREE_FETCH_TRANSPORT",
              `ShadeTreeClient.fetch ${description}: ${cause?.message || cause || "connection closed"}`,
              { cause: cause instanceof Error ? cause : undefined, retryable: true },
            ));
            res.on("data", (chunk) => {
              if (settled) return;
              const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
              receivedBytes += data.length;
              if (receivedBytes > maxBodyBytes) {
                fail(new ShadeTreeFetchError(
                  "SHADE_TREE_FETCH_BODY_TOO_LARGE",
                  `ShadeTreeClient.fetch response exceeded ${maxBodyBytes} bytes; raise { fetchMaxBodyBytes } or per-call { maxBodyBytes } only for a trusted destination`,
                  { maxBodyBytes, receivedBytes, retryable: false },
                ));
                return;
              }
              chunks.push(data);
            });
            res.once("aborted", () => transportFailure(null, "response was aborted"));
            res.once("error", (error) => transportFailure(error));
            res.once("close", () => {
              if (!ended && !settled) transportFailure(null, "response closed before completion");
            });
            res.once("end", () => {
              if (settled) return;
              ended = true;
              settled = true;
              clearTimeout(timer);
              emit({ phase: "egress", status: "done", httpStatus: res.statusCode });
              resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks, receivedBytes).toString("utf8"), gateway: socket.shadeTree });
            });
          };

          try {
            req = this._httpsRequest(
              {
                hostname: u.hostname,
                port,
                path: (u.pathname || "/") + (u.search || ""),
                method: opts.method || "GET",
                headers: opts.headers || {},
                createConnection: () => tls.connect({ socket, servername: u.hostname }),
              },
              onResponse,
            );
            req.once("error", (cause) => fail(new ShadeTreeFetchError(
              "SHADE_TREE_FETCH_TRANSPORT",
              `ShadeTreeClient.fetch request failed: ${cause?.message || cause}`,
              { cause, retryable: true },
            )));
            if (opts.body) req.write(opts.body);
            req.end();
          } catch (cause) {
            fail(new ShadeTreeFetchError(
              "SHADE_TREE_FETCH_TRANSPORT",
              `ShadeTreeClient.fetch request failed: ${cause?.message || cause}`,
              { cause, retryable: true },
            ));
          }
        }, fail);
    });
  }
}

export { cleanUp };
export { ShadeTreeSlotStateError };
