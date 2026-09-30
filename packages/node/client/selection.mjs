// Client-proxy router: per-CONNECT-tunnel gateway selection over the signed Grove directory.
//
// The client proxy stays the router; curl stays dumb. When SHADE_TREE_DIRECTORY points at a
// signed directory JSON, the proxy asks here for a candidate ORDER per CONNECT:
// a smooth weighted-round-robin pick first, then a weighted-random failover tail.
// The membership proof is gateway-independent (same root + same epoch verifies at
// any gateway loading the same members.json), so failover within one tunnel reuses
// that tunnel's proof and just dials a different onion. Every new tunnel still mints
// a fresh slot-bound proof.
//
// An explicit single-onion path (SHADE_TREE_ONION) bypasses directory selection. With no explicit
// source, clients use the current-v4 Elder+signer pair from the bundled default network record.
//
// Integration is one line in the client proxy's CONNECT handler (see docs/FLEET.md):
//   const candidates = await selectCandidates();   // [{ onion }, ...] in try order
// then dial candidates in order, and on success/failure call:
//   reportResult(onion, { ok, latencyMs });

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { loadDirectory, selectionOrder, reportHealth, verifyDirectory, MAX_WEIGHT, canonicalCaps, DEFAULT_EGRESS_PORT, DEFAULT_PROTO_VERSION } from "../lib/directory.mjs";
import { fetchOverTor } from "../bootnode/fetch.mjs";
import { verifyAnnounce } from "../bootnode/announce.mjs";
import { makeStakeVerifier } from "../lib/gateway-registry.mjs";
import { applyClientNetworkEnv } from "../lib/network-record.mjs";
import { createLogger } from "../lib/log.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const clientLog = createLogger("proxy");

// Fill discovery inputs before the constants below snapshot the env. An explicit source wins;
// SHADE_TREE_NETWORK selects a named record; otherwise clients use the bundled current-v4 default.
// Done here, not only in packages/node/bin/shade-tree.mjs, so direct shim and SDK imports get the same safe pin.
applyClientNetworkEnv(process.env);

// Two directory SOURCES, same signed shape and same pinned-signer verification:
//   - SHADE_TREE_BOOTNODE_ONION : live discovery. Fetch /directory from the bootnode onion over Tor
//                           (packages/node/bootnode/server.mjs). The pinned signer (SHADE_TREE_DIR_SIGNER) is the
//                           bootnode's signer key. This is the dynamic fleet.
//   - SHADE_TREE_DIRECTORY      : static signed JSON file (group/sign-directory.mjs). The offline path.
// Bootnode wins if both are set. Either way, verifyDirectory + last-known-good caching apply.
const BOOTNODE_ONION = process.env.SHADE_TREE_BOOTNODE_ONION || null;
const DIRECTORY_PATH = process.env.SHADE_TREE_DIRECTORY || null;
const CACHE_PATH =
  process.env.SHADE_TREE_DIRECTORY_CACHE ||
  (BOOTNODE_ONION ? join(HERE, "../../..", "cache", "bootnode-directory.lkg") : DIRECTORY_PATH ? DIRECTORY_PATH + ".lkg" : null);
const TOR_HOST = process.env.SHADE_TREE_TOR_HOST || "127.0.0.1";
const TOR_PORT = Number(process.env.SHADE_TREE_TOR_PORT || 9250);

// ---- client-side gateway reputation persistence (T-FEAT-19) ---------------------
// reportHealth() (packages/node/lib/directory.mjs) mutates in-memory dir entries (_fails/health/_latencyMs),
// which is LOST on restart: a gateway that failed all last session is forgotten and gets a fresh
// weighted pick again this session. We keep a SMALL local, best-effort cache of per-gateway
// liveness so a flaky gateway stays deprioritized ACROSS sessions until it proves healthy again.
//
// Scope + privacy: this is a LOCAL file only. It is never sent to the bootnode or the fleet, and
// it stores only onions the client already learned from the SIGNED directory plus fail counts and
// a latency EWMA. No member data, no directory contents. The cache is keyed by onion:
//   onion -> { fails, lastFail, latencyMs, lastSeen }
//
// Fully OPTIONAL and non-breaking: if the path is empty or the dir isn't writable, load returns {}
// and save no-ops (fail soft) — selection behaves exactly as the in-memory-only path does today.
//
// SHADE_TREE_HEALTH_CACHE   : path to the JSON file (default cache/gateway-health.json, which is gitignored).
//                       Set to "" (or "off"/"0") to disable persistence entirely.
// SHADE_TREE_HEALTH_MAX     : max distinct gateways retained (oldest-lastSeen evicted first).
// SHADE_TREE_HEALTH_DECAY_MS: an entry not SEEN for this long is treated as recovered (not seeded, pruned).
function resolveHealthCachePath() {
  const raw = process.env.SHADE_TREE_HEALTH_CACHE;
  if (raw === undefined) return join(HERE, "../../..", "cache", "gateway-health.json");
  const v = raw.trim();
  if (v === "" || v === "0" || v.toLowerCase() === "off") return null; // explicit OFF
  return v;
}
const HEALTH_CACHE_PATH = resolveHealthCachePath();
const HEALTH_MAX_ENTRIES = Math.max(1, Number(process.env.SHADE_TREE_HEALTH_MAX || 512));
const HEALTH_DECAY_MS = Number(process.env.SHADE_TREE_HEALTH_DECAY_MS || 14 * 24 * 60 * 60 * 1000); // 14 days
const HEALTH_FAIL_THRESHOLD = 2; // mirror reportHealth(): >= 2 consecutive fails => "down"

// Read the persisted cache. Best-effort and TOTAL: any error (missing/unwritable/corrupt) yields an
// empty map, so a broken cache can never break selection. Tolerates both the versioned envelope we
// write ({version,entries}) and a bare onion->entry map.
export function loadHealthCache(path = HEALTH_CACHE_PATH) {
  if (!path) return {};
  try {
    const raw = JSON.parse(readFileSync(path, "utf8"));
    if (raw && typeof raw === "object") {
      if (raw.entries && typeof raw.entries === "object") return raw.entries;
      if (!raw.version) return raw; // bare map
    }
  } catch { /* fail soft */ }
  return {};
}

// Cap the cache in place: evict the oldest-lastSeen entries down to `max` so it can never grow
// unboundedly. Mutates and returns the same object. Generalized (T-FEAT-22) so the receipt tally
// reuses the exact same oldest-first eviction; the health cache keeps its HEALTH_MAX_ENTRIES default.
function boundHealthCache(cache, max = HEALTH_MAX_ENTRIES) {
  const keys = Object.keys(cache);
  if (keys.length <= max) return cache;
  keys.sort((a, b) => (cache[a]?.lastSeen || 0) - (cache[b]?.lastSeen || 0));
  for (const k of keys.slice(0, keys.length - max)) delete cache[k];
  return cache;
}

// Write-through, bounded, best-effort. Returns true iff the file was written. A failure (no path,
// read-only dir, ENOTDIR, ...) is swallowed: persistence is off, selection is unaffected.
export function saveHealthCache(cache = _healthCache, path = HEALTH_CACHE_PATH) {
  if (!path) return false;
  try {
    boundHealthCache(cache);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, JSON.stringify({ version: 1, entries: cache }, null, 2) + "\n");
    return true;
  } catch { return false; }
}

// Seed a freshly-loaded directory's in-memory liveness from the persisted cache, so a gateway that
// failed a lot last session STARTS deprioritized (health "down" and/or a latency handicap) until it
// proves healthy again this session. Decay, not blacklist: an entry not seen for HEALTH_DECAY_MS is
// ignored (and will be pruned on the next save), so a long-idle or recovered gateway comes back.
// Mutates dir.gateways in place (the same objects selectionOrder/reportHealth key on) and returns dir.
export function seedHealthFromCache(dir, cache = _healthCache, now = Date.now()) {
  if (!dir || !Array.isArray(dir.gateways) || !cache) return dir;
  for (const g of dir.gateways) {
    const e = cache[g.onion];
    if (!e) continue;
    if (typeof e.lastSeen === "number" && now - e.lastSeen >= HEALTH_DECAY_MS) {
      delete cache[g.onion]; // decayed: recovered, prune
      continue;
    }
    const fails = Number(e.fails) || 0;
    if (fails > 0) g._fails = fails;
    if (fails >= HEALTH_FAIL_THRESHOLD) g.health = "down";
    if (typeof e.latencyMs === "number") g._latencyMs = e.latencyMs;
  }
  return dir;
}

// Fold one dial result into the persisted cache and write through. Privacy guard: only persist an
// onion the client already knows from the SIGNED directory (never arbitrary caller input). A
// successful dial resets fails (recovery); failures increment toward the "down" threshold.
function updateHealthCache(dir, onion, { ok, latencyMs } = {}) {
  if (!HEALTH_CACHE_PATH) return; // persistence disabled
  if (!(dir.gateways || []).some((x) => x.onion === onion)) return; // unknown onion: don't persist
  const now = Date.now();
  const e = _healthCache[onion] || { fails: 0, lastFail: 0, latencyMs: null, lastSeen: 0 };
  if (ok === false) {
    e.fails = (e.fails || 0) + 1;
    e.lastFail = now;
  } else if (ok === true) {
    e.fails = 0; // a successful dial recovers the gateway
    if (typeof latencyMs === "number") {
      e.latencyMs = e.latencyMs == null ? latencyMs : Math.round(0.7 * e.latencyMs + 0.3 * latencyMs);
    }
  }
  e.lastSeen = now;
  _healthCache[onion] = e;
  saveHealthCache(_healthCache, HEALTH_CACHE_PATH);
}

// Loaded once at module init (best-effort). Env is read at import, same as the rest of this module.
let _healthCache = loadHealthCache(HEALTH_CACHE_PATH);

// ---- client-side receipt reputation → quality-aware selection (T-FEAT-22) --------
// The client verifies each gateway's signed egress-success receipt (packages/node/lib/receipt.mjs, T-FEAT-13) and
// today throws it away. This folds the outcome into a SMALL, LOCAL, per-gateway quality tally sitting
// NEXT TO the health cache (a sibling file in the same cache dir), so a gateway that keeps returning
// VALID receipts earns a MODEST selection bonus, and one that sends BAD receipts (present but bogus —
// the gate-then-drop signal a receipt can attest) is deprioritized.
//
// OFF BY DEFAULT / FULLY ADDITIVE. This whole feature is gated behind SHADE_TREE_RECEIPT_SCORING. With it
// disabled (the default): reportReceipt is a no-op, NO tally file is ever written, and selectCandidates
// takes the byte-identical weight-only path — selection is exactly today's behavior. Even with the flag
// ARMED, a fleet with no receipt evidence yet produces an identity adjustment (same gateway objects,
// same weights), so enabling it changes nothing until real receipts arrive.
//
// PRIVACY (the whole point). We store ONLY the gateway .onion (already learned from the SIGNED
// directory) plus three locally-computed numbers: a decaying quality EWMA in [0,1], a bounded sample
// count, and a lastSeen wall-clock for decay/eviction. We NEVER store receipt bytes, the receipt's
// epoch, or anything tied to a specific request — same never-sent, local-only discipline as the health
// cache. Two receipts from a gateway in one epoch are byte-identical by design, so there is nothing
// request-linkable to store even if we wanted to. The tally is never transmitted anywhere.
//
//   onion -> { score, samples, lastSeen }   // score: EWMA of (valid?1:0); samples: capped confidence
//
// SHADE_TREE_RECEIPT_SCORING   : "1"/"on"/"true" to arm. Unset/anything else => OFF (default).
// SHADE_TREE_RECEIPT_CACHE     : tally file path (default cache/gateway-receipts.json, gitignored). ""/"off"/"0" => no persistence.
// SHADE_TREE_RECEIPT_MAX       : max distinct gateways retained (oldest-lastSeen evicted first). Default 512.
// SHADE_TREE_RECEIPT_DECAY_MS  : a tally not updated for this long is treated as decayed → neutral (no bonus, no penalty). Default 14d.
// SHADE_TREE_RECEIPT_ALPHA     : EWMA weight on the newest outcome (0..1). Default 0.3 (mirrors the health latency EWMA).
// SHADE_TREE_RECEIPT_BONUS     : max fractional weight swing at full confidence + extreme score. Default 0.5 (±50%).
// SHADE_TREE_RECEIPT_CONFIDENCE_N: samples needed for full confidence (one good receipt is not decisive). Default 4.
const clamp01 = (x) => (Number.isFinite(x) ? Math.max(0, Math.min(1, x)) : 0);
function parseReceiptScoring(raw) {
  if (raw === undefined) return false;
  const v = String(raw).trim().toLowerCase();
  return v === "1" || v === "on" || v === "true" || v === "yes";
}
const RECEIPT_SCORING = parseReceiptScoring(process.env.SHADE_TREE_RECEIPT_SCORING);
export function receiptScoringEnabled() { return RECEIPT_SCORING; }

function resolveReceiptCachePath() {
  const raw = process.env.SHADE_TREE_RECEIPT_CACHE;
  if (raw === undefined) return join(HERE, "../../..", "cache", "gateway-receipts.json");
  const v = raw.trim();
  if (v === "" || v === "0" || v.toLowerCase() === "off") return null; // explicit OFF
  return v;
}
const RECEIPT_CACHE_PATH = resolveReceiptCachePath();
const RECEIPT_MAX_ENTRIES = Math.max(1, Number(process.env.SHADE_TREE_RECEIPT_MAX || 512));
const RECEIPT_DECAY_MS = Number(process.env.SHADE_TREE_RECEIPT_DECAY_MS || 14 * 24 * 60 * 60 * 1000);
const RECEIPT_ALPHA = clamp01(Number(process.env.SHADE_TREE_RECEIPT_ALPHA ?? 0.3));
const RECEIPT_BONUS = Math.max(0, Number(process.env.SHADE_TREE_RECEIPT_BONUS ?? 0.5));
const RECEIPT_CONFIDENCE_N = Math.max(1, Number(process.env.SHADE_TREE_RECEIPT_CONFIDENCE_N || 4));

// Read the persisted tally. Best-effort and total, exactly like loadHealthCache: any error yields {}
// so a broken tally can never break selection. Tolerates the versioned envelope and a bare map.
export function loadReceiptCache(path = RECEIPT_CACHE_PATH) {
  if (!path) return {};
  try {
    const raw = JSON.parse(readFileSync(path, "utf8"));
    if (raw && typeof raw === "object") {
      if (raw.entries && typeof raw.entries === "object") return raw.entries;
      if (!raw.version) return raw; // bare map
    }
  } catch { /* fail soft */ }
  return {};
}

// Write-through, bounded (reuses boundHealthCache's oldest-first eviction with the receipt cap),
// best-effort. Returns true iff written; any failure is swallowed so persistence-off never affects
// selection.
export function saveReceiptCache(cache = _receiptCache, path = RECEIPT_CACHE_PATH) {
  if (!path) return false;
  try {
    boundHealthCache(cache, RECEIPT_MAX_ENTRIES);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, JSON.stringify({ version: 1, entries: cache }, null, 2) + "\n");
    return true;
  } catch { return false; }
}

// Loaded once at module init — but ONLY when scoring is armed, so the default path never touches disk.
let _receiptCache = RECEIPT_SCORING ? loadReceiptCache(RECEIPT_CACHE_PATH) : {};
export function _setReceiptCache(next) { _receiptCache = next || {}; } // test seam

// The bounded, decaying weight MULTIPLIER a gateway's receipt record earns, in
//   [1 - RECEIPT_BONUS, 1 + RECEIPT_BONUS].
// score in [0,1] maps to a centered pull (2*score-1) in [-1,1]; confidence ramps from one sample to
// full at RECEIPT_CONFIDENCE_N so a single receipt is not decisive; a decayed (stale) or absent tally
// returns exactly 1 (neutral) so it neither helps nor hurts — a gateway is never punished forever.
function receiptFactor(onion, now = Date.now()) {
  const e = _receiptCache[onion];
  if (!e) return 1;
  if (now - (e.lastSeen || 0) >= RECEIPT_DECAY_MS) return 1; // decayed → neutral
  const confidence = Math.min(1, (e.samples || 0) / RECEIPT_CONFIDENCE_N);
  const centered = 2 * clamp01(e.score) - 1; // valid-heavy → +, bad-heavy → -
  return 1 + RECEIPT_BONUS * centered * confidence;
}

// Produce a selection view of `gateways` with receipt-adjusted weights. Returns the SAME array
// reference when nothing is adjusted (flag off, or no live tally) so the caller stays on the exact
// byte-identical weight-only path. Otherwise returns NEW shallow copies with a scaled `weight`, never
// mutating the signed weight or the live objects reportHealth/reportResult key on. selectionOrder only
// reads {onion, weight, health}, all of which the copies preserve.
function applyReceiptWeights(gateways, now = Date.now()) {
  if (!RECEIPT_SCORING) return gateways;
  let touched = false;
  const out = gateways.map((g) => {
    const f = receiptFactor(g.onion, now);
    if (f === 1) return g;
    touched = true;
    const w = Number(g.weight);
    const base = Number.isFinite(w) ? w : 1;
    return { ...g, weight: Math.max(0, base * f) };
  });
  return touched ? out : gateways;
}

// Fold one verified-or-not receipt outcome for a dialed gateway into the persisted tally (T-FEAT-22).
// SEAM mirroring reportResult(onion, {ok,latencyMs}). No-op unless scoring is armed (keeps the default
// byte-identical and writes nothing). Privacy guard: only persist an onion already in the SIGNED
// directory (never arbitrary caller input). `valid:true` = a receipt that verified against this onion +
// current epoch; `valid:false` = a bad/bogus receipt (the gate-then-drop evidence a receipt can carry).
// The RECEIPT-ABSENT legacy case (a gateway simply running with receipts off) is NOT a report — the
// caller does not call here for it — so opting a gateway out of receipts is never penalized (additive).
export function reportReceipt(onion, { valid } = {}) {
  if (!RECEIPT_SCORING) return;         // OFF by default: no-op, nothing persisted, selection unchanged
  if (!loaded) return;                  // no fleet loaded yet — nothing to attribute this to
  const full = onion.endsWith(".onion") ? onion : onion + ".onion";
  if (!(loaded.dir.gateways || []).some((x) => x.onion === full)) return; // unknown onion: don't persist
  const now = Date.now();
  const signal = valid === true ? 1 : 0;
  let e = _receiptCache[full];
  // A brand-new or fully-decayed record starts fresh from this observation (not punished forever).
  if (!e || now - (e.lastSeen || 0) >= RECEIPT_DECAY_MS) e = { score: signal, samples: 0, lastSeen: 0 };
  e.score = RECEIPT_ALPHA * signal + (1 - RECEIPT_ALPHA) * clamp01(e.score);
  e.samples = Math.min(RECEIPT_CONFIDENCE_N, (e.samples || 0) + 1); // capped: bounded + caps confidence
  e.lastSeen = now;
  _receiptCache[full] = e;
  saveReceiptCache(_receiptCache, RECEIPT_CACHE_PATH);
}

// ---- quality-aware rotation / load spread (T-FEAT-4) ----------------------------
// Slot-0 (the gateway the client proxy actually dials) uses smooth weighted round-robin by default.
// A fresh independent weighted-random draw still exists as an explicit opt-out. Over the long run
// weighted-random honors weight, but request-to-request it is memoryless: the
// single top-weight gateway keeps winning the draw and gets hammered back-to-back, and equal-weight
// peers see bursty, clumped load instead of an even spread — the opposite of what a rotation policy
// wants for load balancing (and traffic concentration is a deanonymization lever this system already
// clamps weight to fight).
//
// Unless SHADE_TREE_ROTATION_SPREAD is explicitly disabled, slot-0 is chosen by a SMOOTH weighted round-robin (SWRR, the
// nginx/`ngx_http_upstream` scheduler) over the SAME healthy, weight-clamped, receipt-adjusted pool
// selectionOrder already selects from. SWRR keeps a per-gateway "current deficit" that advances every
// CONNECT: each step adds the gateway's effective weight to its deficit, picks the max, then subtracts
// the pool total from the winner. Two properties fall out for free:
//   1. ANTI-STICKINESS / SPREAD: a gateway that just won drops far below its peers, so it is not
//      re-picked until the others have had their proportional turn — no back-to-back hammering, and
//      load is spread evenly across the healthy fleet (equal weights => strict round-robin, zero
//      immediate repeats), which is exactly the T-FEAT-4 goal.
//   2. LONG-RUN WEIGHT IS PRESERVED EXACTLY: over each full cycle a gateway is selected a number of
//      times exactly proportional to its effective weight (the -total decrement conserves the
//      deficit sum), so the marginal slot-0 distribution is still weight- (and receipt-) proportional
//      — spread changes the ORDER, never the long-run share.
// The deficits are seeded with a small rng jitter so two clients loading the same fleet don't emit an
// identical, cross-linkable sequence; the jitter only offsets the phase and washes out of the marginal.
//
// The failover TAIL (slots 1..n, only consulted on a dial timeout) stays weighted-random via the
// existing selectionOrder over the remaining fleet — spread only needs to govern the gateway actually
// used. ON BY DEFAULT: only an explicit false value takes the `selectionOrder(view)` weighted-random
// path. Reuses the health ("down") + receipt-adjusted weight signals already in this module; adds no
// persistence store (the SWRR deficits are in-memory session state, like health).
//
// SHADE_TREE_ROTATION_SPREAD : unset/"1"/"on"/"true"/"yes" => smooth spread (default);
//                              "0"/"off"/"false"/"no" => weighted-random first choice.
function parseRotationSpread(raw) {
  if (raw === undefined || String(raw).trim() === "") return true;
  const v = String(raw).trim().toLowerCase();
  return !["0", "off", "false", "no"].includes(v);
}
const ROTATION_SPREAD = parseRotationSpread(process.env.SHADE_TREE_ROTATION_SPREAD);
export function rotationSpreadEnabled() { return ROTATION_SPREAD; }

// Injectable rng for the spread path (jitter seed + failover-tail weighting), so distribution tests
// are deterministic and don't flake. Only the spread path reads it; the explicitly disabled
// weight-only path stays on selectionOrder's own Math.random, untouched. Test seam, additive.
let _rng = Math.random;
export function _setRng(fn) { _rng = typeof fn === "function" ? fn : Math.random; }

// Per-gateway SWRR "current deficit", keyed by onion, persisted across selectCandidates() calls so
// successive CONNECTs advance the schedule (that persistence is what spreads load instead of
// re-rolling the dice each time). In-memory session state — NOT a new persistence store. Test seam.
let _swrr = new Map();
export function _resetRotationState() { _swrr = new Map(); }
// Read-only test seam (T-FEAT-24): expose the SWRR deficit map's size so a regression test can prove
// the map stays bounded — pruned to the live fleet each spreadSelectionOrder() call — without making
// _swrr public. No behavior change; nothing writes through this.
export function _swrrSize() { return _swrr.size; }

// Effective selection weight: mirror packages/node/lib/directory.mjs clampWeight (undefined/NaN => 1, negative => 0,
// huge => MAX_WEIGHT) so the spread path bounds gateway-attested weight exactly as pickGateway does.
function effWeight(g) {
  const w = Number(g?.weight);
  return Number.isFinite(w) ? Math.max(0, Math.min(MAX_WEIGHT, w)) : 1;
}

// One smooth-weighted-round-robin step over `pool` (advances + mutates _swrr). Returns the winner.
function swrrPick(pool) {
  const total = pool.reduce((s, g) => s + effWeight(g), 0);
  if (total <= 0) return pool[Math.floor(_rng() * pool.length)]; // all-zero weights: uniform random
  let best = null, bestCur = -Infinity;
  for (const g of pool) {
    const w = effWeight(g);
    let cur = _swrr.get(g.onion);
    if (cur === undefined) cur = _rng() * w; // phase jitter in [0,w) so clients diverge
    cur += w;
    _swrr.set(g.onion, cur);
    if (cur > bestCur) { bestCur = cur; best = g; }
  }
  _swrr.set(best.onion, _swrr.get(best.onion) - total);
  return best;
}

// The SHADE_TREE_ROTATION_SPREAD ordering: SWRR chooses slot-0 over the healthy, positive-weight pool
// (same "healthy unless all down" / "positive unless all zero" fallbacks as pickGateway), then the
// existing weighted selectionOrder fills the failover tail over the remaining fleet. Falls back to
// plain selectionOrder when there is nothing to spread across (< 2 candidates).
function spreadSelectionOrder(view) {
  const all = (view.gateways || []).slice();
  const healthy = all.filter((g) => g.health !== "down");
  const pool = healthy.length ? healthy : all; // last resort: spread over "down" ones
  const positive = pool.filter((g) => effWeight(g) > 0);
  const spreadPool = positive.length ? positive : pool;
  if (spreadPool.length < 2) return selectionOrder(view, { rng: _rng });
  // Prune deficits for onions no longer in the fleet so the map can't grow unboundedly across
  // directory refreshes; a temporarily-"down" gateway keeps its deficit (it is still in `all`).
  const live = new Set(all.map((g) => g.onion));
  for (const k of _swrr.keys()) if (!live.has(k)) _swrr.delete(k);
  const first = swrrPick(spreadPool);
  const rest = { ...view, gateways: all.filter((g) => g.onion !== first.onion) };
  return [first, ...selectionOrder(rest, { rng: _rng })];
}

// The pinned directory signer(s). The current v4 default comes from the bundled deployment
// record; SHADE_TREE_DIR_SIGNER overrides it only when the caller also selects an explicit source.
// An unpinned directory is never accepted: directory mode remains off without a source+pin pair.
//
// SHADE_TREE_DIR_SIGNER accepts a COMMA-SEPARATED list of pubkeys — the signer-rotation
// OVERLAP SET. This is an allowlist (verifyDirectory accepts a directory signed by ANY
// listed signer, and requires the declared `dir.signer` to be one of them), NOT
// "trust any signer": an unpinned/wrong key is still rejected. A single value behaves
// exactly as before. Rotating the directory signer without a flag day:
//   1. Add the NEW signer pubkey to the client set (now {old,new}); ship it. Clients
//      still accept the old-signed directory, so nothing breaks during rollout.
//   2. Once the {old,new} clients have propagated, rotate the bootnode's signing key
//      to NEW (bootnode now signs with, and declares, the new key). Old clients that
//      already have {old,new} accept it; not-yet-updated {old} clients still work
//      until they update, because the overlap window covers both.
//   3. After everyone has the new set, drop OLD from the client set (now {new} only),
//      retiring the old key.
function parsePinnedSigners(raw) {
  if (!raw) return null;
  const list = raw.split(",").map((s) => s.trim()).filter(Boolean);
  return list.length ? list : null;
}
const PINNED_SIGNER = parsePinnedSigners(process.env.SHADE_TREE_DIR_SIGNER);

export function directoryEnabled() {
  return Boolean((BOOTNODE_ONION || DIRECTORY_PATH) && PINNED_SIGNER);
}

// ---- client zero-trust operator re-verification (T-DEV-5) -----------------------
// OFF by default (SHADE_TREE_VERIFY_STAKE=1 to arm) so existing behavior + tests are unchanged.
//
// The signed directory carries the bootnode's `operator`/`staked` LABEL, but that label is the
// one claim in the directory the client cannot check from the entry alone: the onion<->operator
// binding and the operator's live stake live in the raw announce and on chain, not in the
// signed directory. So a compromised bootnode (or a compromised directory signer) could paste a
// `staked:true` label onto a gateway whose operator never authorized it, or whose stake has
// lapsed. With the flag armed, the client refuses to take that label on faith: for every entry
// that claims stake it fetches the bootnode's STORED signed announce (GET /gateway/<onion>) and
// independently re-runs the same two proofs the bootnode ran at admission —
//   1. onion-control + operator-authorization signatures (announce.mjs verifyAnnounce), and
//   2. GatewayRegistry.isStaked(operator) live (gateway-registry.mjs makeStakeVerifier) —
// dropping any gateway that fails, regardless of the label. Onion-only entries (no operator)
// are not claiming stake, so there is nothing to re-verify and they pass through untouched.
const VERIFY_STAKE = process.env.SHADE_TREE_VERIFY_STAKE === "1";
export function verifyStakeEnabled() {
  return VERIFY_STAKE;
}

// Injectable dependencies. Defaults hit the live bootnode over Tor and the configured
// StakeVerifier; a test swaps in an in-memory fetch + a mock stake verifier via setVerifyDeps()
// so the re-verification can be driven with no Tor and no chain. Mirrors how selection.mjs reads
// config at import while still exposing the moving parts as hooks.
let _fetchAnnounce = null; // (onion) => Promise<announceRecord>  (GET /gateway/<onion>)
let _stakeVerifier = null; // { isStaked(operatorAddr) => Promise<bool> }
export function setVerifyDeps({ fetchAnnounce, stake } = {}) {
  if (fetchAnnounce !== undefined) _fetchAnnounce = fetchAnnounce;
  if (stake !== undefined) _stakeVerifier = stake;
}

// Default announce fetch: the bootnode's stored, signed announce for one onion, over Tor.
// Only meaningful in live-discovery mode (SHADE_TREE_BOOTNODE_ONION); a static-file directory has no
// bootnode to ask, so re-verification is a live-discovery feature.
function defaultFetchAnnounce(onion) {
  if (!BOOTNODE_ONION) throw new Error("stake re-verification needs SHADE_TREE_BOOTNODE_ONION (no bootnode to fetch the signed announce from)");
  const full = onion.endsWith(".onion") ? onion : onion + ".onion";
  return fetchOverTor(BOOTNODE_ONION, `/gateway/${encodeURIComponent(full)}`, { torHost: TOR_HOST, torPort: TOR_PORT });
}

function stakeVerifier() {
  if (!_stakeVerifier) _stakeVerifier = makeStakeVerifier();
  return _stakeVerifier;
}

// Independently re-verify one directory entry that claims stake. Returns { ok, reason }.
// An entry with no `operator` is not claiming stake, so there is nothing to re-verify (ok).
// Freshness is intentionally NOT re-enforced here (skew defaults to Infinity): the replay window
// is the bootnode's admission control, and the client already verified the signed directory's
// recency + probes liveness by dialing. What the client re-checks is the pairing (onion<->operator
// signatures) and the LIVE stake — the two things a lying bootnode/label could get wrong.
export async function reverifyGateway(entry, opts = {}) {
  if (!entry || !entry.operator) return { ok: true, reason: "not-staked-entry" };
  const fetchAnnounce = opts.fetchAnnounce || _fetchAnnounce || defaultFetchAnnounce;
  const stake = opts.stake || _stakeVerifier || stakeVerifier();
  const skew = opts.skew ?? Infinity;

  let rec;
  try {
    rec = await fetchAnnounce(entry.onion);
  } catch (e) {
    return { ok: false, reason: `announce-fetch-failed:${e.message}` };
  }
  // The fetched announce must be for the SAME onion the directory listed (a bootnode cannot
  // satisfy a re-verify by returning a valid announce for a DIFFERENT onion).
  const want = String(entry.onion).replace(/\.onion$/, "");
  const got = String(rec?.onion || "").replace(/\.onion$/, "");
  if (got !== want) return { ok: false, reason: "announce-onion-mismatch" };

  // verifyAnnounce runs onion-control sig + operator-authorization sig + isStaked in one place —
  // the SAME code the bootnode uses, so the client never reimplements the crypto. requireStake
  // makes a missing/failed stake a hard reject.
  const v = await verifyAnnounce(rec, { isStaked: stake.isStaked, requireStake: true, skew });
  return v.ok ? { ok: true } : { ok: false, reason: v.reason };
}

// Filter a gateway list down to those that survive re-verification. Entries without an operator
// label pass through; entries claiming stake are re-verified in parallel and dropped on failure.
async function filterReverified(gateways) {
  const kept = await Promise.all(
    gateways.map(async (g) => {
      if (!g.operator) return g;
      const v = await reverifyGateway(g);
      if (v.ok) return g;
      clientLog.debug("Canopy entry dropped after stake re-verification", { reason: String(v.reason || "failed").split(":", 1)[0] });
      return null;
    })
  );
  return kept.filter(Boolean);
}

// A canopy event is local process state, not telemetry. Keep the surface deliberately small:
// no bootnode address, gateway onion, target, raw response, request id, or shared query count.
// Callback failures cannot affect discovery.
function emitCanopy(onEvent, status, fields = {}) {
  try { onEvent?.({ phase: "canopy", status, ...fields }); } catch { /* progress is best-effort */ }
}

function canopyFields(dir) {
  return {
    issued: Number(dir?.issued) || 0,
    count: Array.isArray(dir?.gateways) ? dir.gateways.length : 0,
  };
}

// Injectable live fetch for the focused canopy-event selftest. Production keeps the Tor fetch.
let _fetchCanopy = fetchOverTor;
export function _setCanopyFetch(fetchFn) { _fetchCanopy = fetchFn || fetchOverTor; }

// Fetch + verify the bootnode's live directory over Tor, with the same last-known-good
// discipline loadDirectory() gives the file path: a dead or poisoned bootnode degrades to
// the previously-cached good fleet, never to nothing and never to an unverified list.
// Events fire only when this function performs a real refresh. A selection served from the
// in-memory refresh window emits nothing.
async function loadFromBootnode(onEvent) {
  emitCanopy(onEvent, "query");
  try {
    const fresh = await _fetchCanopy(BOOTNODE_ONION, "/directory", { torHost: TOR_HOST, torPort: TOR_PORT });
    const v = verifyDirectory(fresh, PINNED_SIGNER);
    if (!v.ok) throw new Error(v.reason);
    if (CACHE_PATH) {
      try { await mkdir(dirname(CACHE_PATH), { recursive: true }); await writeFile(CACHE_PATH, JSON.stringify(fresh, null, 2) + "\n"); } catch {}
    }
    return { dir: fresh, source: "bootnode" };
  } catch (freshErr) {
    if (CACHE_PATH) {
      try {
        const cached = JSON.parse(await readFile(CACHE_PATH, "utf8"));
        if (verifyDirectory(cached, PINNED_SIGNER).ok) {
          emitCanopy(onEvent, "cache", canopyFields(cached));
          return { dir: cached, source: "cache", freshError: freshErr.message };
        }
      } catch {}
    }
    const error = new Error(`no verifiable bootnode directory (fresh: ${freshErr.message}, no valid cache)`);
    emitCanopy(onEvent, "error", { reason: "unavailable-or-invalid" });
    error.canopyEventEmitted = true;
    throw error;
  }
}

// Loaded once and refreshed lazily; health is mutated in place across requests.
let loaded = null; // { dir, source }
let loadedAt = 0;
// High-water mark of every directory `issued` we've accepted this session. Used to refuse a
// directory whose timestamp moves BACKWARD (audit loop-15 F2). Exported reset for tests.
let lastAcceptedIssued = 0;
export function _resetIssuedFloor() { lastAcceptedIssued = 0; }
const REFRESH_MS = Number(process.env.SHADE_TREE_DIRECTORY_REFRESH_MS || 5 * 60 * 1000);
const POLL_JITTER = 0.2; // spread clients over 80%-120% of the interval; avoids an Elder thundering herd

// ---- optional absolute directory freshness bound (T-FEAT-21) --------------------
// The monotonic issued FLOOR above only stops rollback WITHIN a session: it refuses a directory
// older than the newest one already accepted. It does NOT bound staleness on a COLD start — a fresh
// client with no prior state accepts whatever `issued` the bootnode first serves, so a bootnode that
// is simply far behind (or is replaying a months-old but validly signed directory to a new client)
// is undetectable. This OPTIONAL bound closes that gap: it rejects a FRESH directory (source !==
// "cache") whose `issued` is older than now - SHADE_TREE_DIRECTORY_MAX_AGE_MS, failing closed to the
// last-good in-memory fleet / cache via the same catch path as the rollback guard.
//
// OFF by default: unset => no max-age check at all, so legitimate long-lived static-file directories
// and every existing behavior/test are byte-for-byte unaffected. Our own last-known-good CACHE is
// exempt (source === "cache") — a stale-but-verified cache is still better than going dark, exactly
// as the rollback guard treats it.
//
// UNIT: directory `issued` is in SECONDS (bootnode makeRegistry: now = () => Math.floor(Date.now()/
// 1000)), matching the rollback floor's comparison. The env bound is in MILLISECONDS, so we scale
// `issued` to ms (× 1000) before comparing — no unit mismatch with the floor, which stays unitless.
function parseMaxAgeMs(raw) {
  if (raw === undefined) return null; // unset => bound disabled
  const v = Number(raw);
  return Number.isFinite(v) && v > 0 ? v : null; // non-positive / non-numeric => disabled (fail open to off)
}
const DIRECTORY_MAX_AGE_MS = parseMaxAgeMs(process.env.SHADE_TREE_DIRECTORY_MAX_AGE_MS);
// Clock-skew grace added on top of the bound so a client whose clock lags the signer's doesn't
// spuriously reject a just-issued directory. Only consulted when the bound is armed.
const DIRECTORY_MAX_AGE_SKEW_MS = Math.max(0, Number(process.env.SHADE_TREE_DIRECTORY_MAX_AGE_SKEW_MS || 5 * 60 * 1000));

let refreshInFlight = null;
async function ensureLoaded(onEvent, { force = false } = {}) {
  const now = Date.now();
  if (!force && loaded && now - loadedAt < REFRESH_MS) return loaded;
  if (refreshInFlight) return refreshInFlight;
  refreshInFlight = (async () => {
    try {
      const next = BOOTNODE_ONION
        ? await loadFromBootnode(onEvent)
        : await loadDirectory({ path: DIRECTORY_PATH, pinnedSigner: PINNED_SIGNER, cachePath: CACHE_PATH });
    // Rollback / stale-directory replay guard (audit loop-15 F2): a directory's `issued` must
    // never move BACKWARD. The bootnode signs its own directory and an ed25519 signature is
    // valid forever, so a hostile or replaying bootnode could serve an OLD signed directory to
    // resurrect a gateway that was since dropped or slashed — and verifyDirectory, being
    // stateless, would accept it clean. We refuse any FRESH directory whose issued predates the
    // newest one we've already accepted (a same-issued refetch is idempotent and fine). Our own
    // last-known-good CACHE is trusted so it never trips the guard, but it still raises the floor
    // so a subsequent fresh fetch can't roll us back behind the cache. A thrown rejection is
    // caught below and we keep the good in-memory fleet — fail-closed.
    const nextIssued = Number(next.dir && next.dir.issued) || 0;
    if (next.source !== "cache" && nextIssued < lastAcceptedIssued) {
      throw new Error(`directory rollback rejected: issued ${nextIssued} < last accepted ${lastAcceptedIssued}`);
    }
    // Absolute freshness bound (T-FEAT-21): reject a FRESH directory whose issued is beyond the
    // configured max age + skew grace. `issued` is in SECONDS, the bound in MS, so scale × 1000.
    // OFF unless SHADE_TREE_DIRECTORY_MAX_AGE_MS is set; cache source is exempt. Thrown => caught below =>
    // keep the last-good in-memory fleet (fail-closed), same as the rollback guard.
    if (DIRECTORY_MAX_AGE_MS != null && next.source !== "cache") {
      const ageMs = now - nextIssued * 1000;
      if (ageMs > DIRECTORY_MAX_AGE_MS + DIRECTORY_MAX_AGE_SKEW_MS) {
        throw new Error(
          `directory too stale: issued ${nextIssued}s is ${Math.round(ageMs / 1000)}s old > max-age ` +
          `${Math.round((DIRECTORY_MAX_AGE_MS + DIRECTORY_MAX_AGE_SKEW_MS) / 1000)}s (bound + skew)`
        );
      }
    }
    if (nextIssued > lastAcceptedIssued) lastAcceptedIssued = nextIssued;
    // Carry forward live health across a refresh so a reload doesn't forget which
    // gateways just failed.
    if (loaded) {
      const prev = new Map(loaded.dir.gateways.map((g) => [g.onion, g]));
      for (const g of next.dir.gateways) {
        const p = prev.get(g.onion);
        if (p) { g.health = p.health; g._fails = p._fails; g._latencyMs = p._latencyMs; }
      }
    } else {
      // First load of the session: seed liveness from the persisted cross-session cache so a
      // gateway that failed a lot last session starts deprioritized until it proves healthy again.
      seedHealthFromCache(next.dir, _healthCache, now);
    }
    loaded = next;
    loadedAt = now;
    if (BOOTNODE_ONION && next.source === "bootnode") {
      emitCanopy(onEvent, "verified", canopyFields(next.dir));
    }
    if (next.source === "cache") {
      clientLog.warn("using last-known-good Canopy", { reason: "fresh-unavailable-or-invalid" });
    }
    } catch (e) {
      if (BOOTNODE_ONION && !e.canopyEventEmitted) {
        emitCanopy(onEvent, "error", { reason: "unavailable-or-invalid" });
      }
      if (loaded) {
        clientLog.warn("Canopy refresh failed; keeping in-memory fleet", { reason: "unavailable-or-invalid" });
      } else {
        throw e; // no fleet at all is fatal for directory mode
      }
    }
    return loaded;
  })();
  try {
    return await refreshInFlight;
  } finally {
    refreshInFlight = null;
  }
}

// A long-lived Proxy should learn new gateway onions even while no CONNECT is arriving. Start a
// single process-wide, unref'd polling loop after the first verified Canopy load. Every tick forces
// a signed refresh; verification/rollback failure retains the in-memory last-known-good fleet.
// SHADE_TREE_DIRECTORY_REFRESH_MS=0 keeps the existing test/dev "reload on every selection" meaning
// and disables the background timer rather than creating a hot loop.
let directoryPollTimer = null;
let pollSetTimeout = setTimeout;
let pollClearTimeout = clearTimeout;
let pollRng = Math.random;

function nextPollDelay() {
  return Math.max(1, Math.round(REFRESH_MS * (1 - POLL_JITTER + 2 * POLL_JITTER * pollRng())));
}

function scheduleDirectoryPoll() {
  if (directoryPollTimer || !BOOTNODE_ONION || REFRESH_MS <= 0) return;
  directoryPollTimer = pollSetTimeout(async () => {
    directoryPollTimer = null;
    try { await ensureLoaded(null, { force: true }); }
    catch { /* ensureLoaded already logs and preserves last-known-good state */ }
    scheduleDirectoryPoll();
  }, nextPollDelay());
  directoryPollTimer?.unref?.();
}

export function startDirectoryPolling() {
  scheduleDirectoryPoll();
}

export function stopDirectoryPolling() {
  if (directoryPollTimer) pollClearTimeout(directoryPollTimer);
  directoryPollTimer = null;
}

// Deterministic timer seam for the polling selftest. Production never calls this.
export function _setDirectoryPollScheduler({ setTimeoutFn = setTimeout, clearTimeoutFn = clearTimeout, rng = Math.random } = {}) {
  stopDirectoryPolling();
  pollSetTimeout = setTimeoutFn;
  pollClearTimeout = clearTimeoutFn;
  pollRng = rng;
}

// ---- capability-aware selection (T-FEAT-10) -------------------------------------
// A request may carry a capability REQUIREMENT — { port, proto, region }, all optional —
// so the client routes to a gateway that can actually serve it (a destination port the
// gateway's egress policy allows, a mutually-supported envelope version, or a coarse region).
// Capabilities are the gateway's SIGNED self-declaration (dir entry `caps` + `capsSig`,
// already verified by verifyDirectory before we ever get here).
//
// OPT-IN and byte-identical by default: `selectCandidates()` with no requirement takes the
// EXACT path it did before (requirementActive(null) === false -> the fleet is not filtered).
// A requirement that NO gateway meets FAILS CLOSED — selectCandidates throws a clear error
// naming the unmet requirement, rather than silently dialing an incapable gateway.

// Does one directory entry satisfy a capability requirement? Pure + TOTAL. A gateway that
// advertises NO caps is assumed to meet only the conservative default (DEFAULT_EGRESS_PORT /
// DEFAULT_PROTO_VERSION) — it cannot prove a non-default capability, so it is not selected for
// one. Region is NEVER implicit (a gateway must advertise a region to match a region require).
export function gatewayMeetsRequirement(entry, req) {
  if (!req || typeof req !== "object") return true;
  const caps = canonicalCaps(entry && entry.caps);
  if (req.port != null) {
    const port = Number(req.port);
    if (Array.isArray(caps.ports)) { if (!caps.ports.includes(port)) return false; }
    else if (port !== DEFAULT_EGRESS_PORT) return false;
  }
  if (req.proto != null) {
    const v = Number(req.proto);
    if (caps.proto) { if (!(v >= caps.proto.min && v <= caps.proto.max)) return false; }
    else if (v !== DEFAULT_PROTO_VERSION) return false;
  }
  if (req.region != null) {
    if (!caps.region || caps.region !== req.region) return false;
  }
  if (req.rate != null) {
    if (!caps.rate || JSON.stringify(caps.rate) !== JSON.stringify(canonicalCaps({ rate: req.rate }).rate)) return false;
  }
  return true;
}

// A requirement is "active" only if it actually constrains something; an absent/empty object
// leaves selection untouched (the byte-identical default path).
export function requirementActive(req) {
  return Boolean(req && typeof req === "object" && (req.port != null || req.proto != null || req.region != null || req.rate != null));
}

function describeRequirement(req) {
  const parts = [];
  if (req.port != null) parts.push(`port=${req.port}`);
  if (req.proto != null) parts.push(`proto=${req.proto}`);
  if (req.region != null) parts.push(`region=${req.region}`);
  if (req.rate != null) parts.push(`rate=${req.rate.epochSeconds}s/${req.rate.payloadBytesPerSlot}B`);
  return parts.join(",");
}

// Filter a gateway list to those meeting `req`. Returns the SAME array reference when the
// requirement is inactive, so callers stay on the byte-identical weight-only path. Exported
// for direct unit testing of the capability filter.
export function filterByCapability(gateways, req) {
  if (!requirementActive(req)) return gateways;
  return gateways.filter((g) => gatewayMeetsRequirement(g, req));
}

// ---- admission-aware selection (T-FEAT-9, docs/adr/0008) ----------------------------------
// Each gateway advertises WHICH admission paths it honours as signed `caps.admits` (a subset
// of invited/staked/paid in anonymity order). The client knows which set holds ITS leaf (the
// leaf SOURCE: members.json => invited, a StakedReputationSet => staked, the PaidAccessSet =>
// paid) and routes only to gateways that admit it -- a gateway that does not would reject the
// proof with `wrong-group-root` after a wasted dial.
//   - `admits` ABSENT (a legacy gateway, or a heartbeat without SHADE_TREE_ADMIT) is treated as
//     "may admit any path" during the rollout window (kept, and logged once) -- the worst case is
//     the same wrong-group-root reject + failover a pre-T-FEAT-9 client got. docs/CLIENTS.md.
//   - `maxAnon` (--max-anon / SHADE_TREE_MAX_ANON=1): keep ONLY gateways whose admits is EXACTLY
//     ["invited"] -- the maximum-anonymity fleet: no staked/paid leaves are hidden among the
//     invited set there, so nothing about a member's on-chain footprint leaks by association.
//     An absent `admits` cannot prove invited-only and is EXCLUDED under max-anon.
// Pure + TOTAL. Returns the SAME array reference when neither constraint is active.
export function admitsOf(entry) {
  const a = canonicalCaps(entry && entry.caps).admits;
  return Array.isArray(a) ? a : null;
}
export function admissionActive(adm) {
  return Boolean(adm && typeof adm === "object" && ((adm.leafSource && adm.leafSource !== "auto") || adm.maxAnon));
}
let _legacyAdmitsWarned = false;
export function _resetLegacyAdmitsWarning() { _legacyAdmitsWarned = false; }
export function filterByAdmission(gateways, adm, { log = (message) => clientLog.warn(message) } = {}) {
  if (!admissionActive(adm)) return gateways;
  const src = adm.leafSource && adm.leafSource !== "auto" ? adm.leafSource : null;
  let legacy = 0;
  const kept = gateways.filter((g) => {
    const admits = admitsOf(g);
    if (adm.maxAnon) return Array.isArray(admits) && admits.length === 1 && admits[0] === "invited";
    if (!admits) { legacy++; return true; } // rollout compat: unknown policy => assume it may admit us
    return admits.includes(src);
  });
  if (legacy && !_legacyAdmitsWarned) {
    _legacyAdmitsWarned = true;
    log(`selection: ${legacy} gateway(s) advertise no admission policy (legacy / SHADE_TREE_ADMIT unset on their heartbeat); assuming they may admit a ${src} leaf -- a wrong guess costs one wrong-group-root reject + failover`);
  }
  return kept;
}
// One-line fleet policy summary for the fail-closed errors: `gw1=[invited,staked] gw2=(none)`.
export function describeFleetAdmits(gateways) {
  return gateways.map((g) => `${String(g.onion || "").slice(0, 12)}..=${admitsOf(g) ? "[" + admitsOf(g).join(",") + "]" : "(no policy advertised)"}`).join(" ") || "(empty directory)";
}

// Returns an ordered list of candidate gateways to try this CONNECT: the weighted
// pick first, then failovers. Each is { onion }.
//
// `req` (optional, T-FEAT-10): a capability requirement { port?, proto?, region? }. OMITTED or
// empty => today's behavior exactly. Present => the fleet is pre-filtered to capable gateways
// and, if none qualify, this throws (fail closed) with a reason naming the requirement.
//
// `adm` (optional, T-FEAT-9): { leafSource: "invited"|"staked"|"paid", maxAnon: bool }. OMITTED
// or inactive => no admission filtering (byte-identical). Active => the fleet is pre-filtered to
// gateways that admit this leaf source (or, under maxAnon, to invited-only gateways) and, if none
// remain, this throws (fail closed) naming every gateway's advertised policy.
//
// `opts.onEvent` (optional) observes a live bootnode refresh locally. The canopy phase emits
// query, verified, cache, or error. It emits nothing for static files or an in-memory cache hit.
export async function selectCandidates(req = null, adm = null, opts = null) {
  const { dir } = await ensureLoaded(opts?.onEvent);
  startDirectoryPolling();
  let gateways = dir.gateways;
  if (VERIFY_STAKE) gateways = await filterReverified(gateways);
  // Admission-aware filter (T-FEAT-9). Runs FIRST so a policy mismatch is named precisely even
  // when a capability requirement is also active. Same-reference when inactive.
  if (admissionActive(adm)) {
    const before = gateways;
    gateways = filterByAdmission(gateways, adm);
    if (gateways.length === 0) {
      if (adm.maxAnon) throw new Error(`--max-anon: no invited-only gateway in the directory (a gateway qualifies only when its signed caps say admits=[invited]); fleet: ${describeFleetAdmits(before)}`);
      throw new Error(`no gateway admits a ${adm.leafSource} leaf (your leaf source); fleet: ${describeFleetAdmits(before)} -- pick a gateway that admits ${adm.leafSource}, or obtain a leaf in a set the fleet admits (docs/CLIENTS.md "Leaf source")`);
    }
  }
  // Receipt-quality weight adjustment (T-FEAT-22). OFF by default and identity when no gateway has a
  // live tally: applyReceiptWeights returns the SAME array reference, so we fall through to the exact
  // weight-only path below (byte-identical to pre-feature behavior). When it does adjust, it returns
  // NEW weight-scaled COPIES, leaving the signed weight and the live reportHealth/reportResult targets
  // untouched.
  gateways = applyReceiptWeights(gateways);
  // Capability-aware filter (T-FEAT-10). OPT-IN: only runs when `req` actually constrains
  // something, so the default path is byte-identical (filterByCapability returns the same
  // array reference for an inactive requirement). When active but no gateway qualifies, fail
  // CLOSED with a clear reason rather than dial an incapable gateway.
  if (requirementActive(req)) {
    gateways = filterByCapability(gateways, req);
    if (gateways.length === 0) {
      throw new Error(`no gateway meets capability requirement: ${describeRequirement(req)}`);
    }
  }
  // Run selection over the (possibly filtered/adjusted) fleet. Reuse the SAME entry objects so
  // reportHealth's in-place mutation (keyed by onion on dir.gateways) still lands on them.
  const view = gateways === dir.gateways ? dir : { ...dir, gateways };
  // Rotation/spread policy (T-FEAT-4). ON by default: slot-0 uses smooth weighted round-robin so
  // load spreads across the healthy fleet without changing long-run weighted share. An explicit
  // false SHADE_TREE_ROTATION_SPREAD restores the original fully weighted-random order.
  const order = ROTATION_SPREAD ? spreadSelectionOrder(view) : selectionOrder(view);
  // Each candidate carries the gateway's SIGNED accepted-ZK-artifact ad when it has one
  // (caps.artifacts, T-HARD-8) so the client can pick a mutual artifact set before proving.
  // ADDITIVE: the field is present only when advertised (legacy candidates are `{ onion }` as before).
  return order.map((g) => {
    const c = { onion: g.onion.replace(/\.onion$/, "") };
    const arts = canonicalCaps(g.caps).artifacts;
    if (arts) c.artifacts = arts;
    const admits = admitsOf(g); // T-FEAT-9: the gateway's signed admission policy, when advertised
    if (admits) c.admits = admits;
    const rate = canonicalCaps(g.caps).rate;
    if (rate) c.rate = rate;
    return c;
  });
}

// Health/latency feedback from the client proxy after a dial attempt.
export function reportResult(onion, { ok, latencyMs } = {}) {
  if (!loaded) return;
  const full = onion.endsWith(".onion") ? onion : onion + ".onion";
  reportHealth(loaded.dir, full, { ok, latencyMs });
  // Write-through to the local cross-session cache (best-effort; no-op if persistence is off).
  updateHealthCache(loaded.dir, full, { ok, latencyMs });
}

// INTEGRATION SEAM (T-FEAT-22). The client (packages/node/client/shade-tree-client.mjs) already verifies the optional
// egress receipt in `_verifyReceipt`, yielding an evidence record `{ present, valid, ... }`, and then
// discards it. To feed quality-aware selection, add exactly ONE line right after that call
// (shade-tree-client.mjs, immediately after `const receipt = this._verifyReceipt(ack.receipt, usedOnion, emit);`):
//
//     if (receipt.present) reportReceipt(usedOnion, { valid: receipt.valid === true });
//
// Gating on `receipt.present` keeps this fully additive: a legacy gateway running with receipts OFF
// sends no receipt (present:false) and is never entered into the tally or penalized. A gateway that
// opts into receipts and returns a VALID one earns the bonus; one that returns a bogus receipt
// (present but invalid) is deprioritized. shade-tree-client.mjs is intentionally NOT edited here — this is
// the seam it would call.
