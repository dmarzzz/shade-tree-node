// The bootnode: a live gateway-discovery service, published as its own v3 onion service.
//
// The static signed directory (group/sign-directory.mjs + packages/node/lib/directory.mjs) is complete but
// hand-maintained: to add or retire a gateway you re-sign and re-ship a file. The bootnode is
// the DYNAMIC version of that exact same signed shape. Gateways announce themselves (bootnode/
// announce.mjs); the bootnode verifies each announce, holds live ones for a TTL, and serves the
// union as a signed directory that packages/node/lib/directory.mjs verifyDirectory() already knows how to check.
//
// THE BOOTNODE IS A CONVENIENCE CACHE, NOT A TRUST ROOT. It cannot forge a gateway:
//   - every entry is self-authenticating (the v3 .onion IS its ed25519 key; verifyDirectory
//     re-derives the key from the address, so a swapped onion fails the client's own check),
//   - onion control is proven cryptographically on announce and re-provable by any client
//     from GET /gateway/<onion> (the stored, signed announce),
//   - the operator stake, if required, is checked on chain and re-checkable by any client.
// So a hostile bootnode can at worst OMIT gateways or list one whose stake later lapsed — both
// caught by the client re-checking on chain — never inject an onion it does not control.
//
// The onion is NEVER on chain (contracts/GatewayRegistry.sol stakes only an operator address).
// Discovery of the onion happens HERE, through the bootnode, exactly as intended.
//
// Config (all SHADE_TREE_*):
//   SHADE_TREE_BOOTNODE_PORT       loopback port Tor maps the onion to        (default 8877)
//   SHADE_TREE_BOOTNODE_SIGNER_KEY {pub,priv} JSON path for the pinned signer (default bootnode/bootnode-signer.key)
//   SHADE_TREE_BOOTNODE_ADMISSION  open | stake                               (default open)
//   SHADE_TREE_BOOTNODE_TTL        seconds a gateway stays live w/o re-announce (default 900)
//   SHADE_TREE_BOOTNODE_STORE      OPTIONAL JSON path for write-through persistence  (default off)
//                            When set, accepted announces are mirrored to disk and reloaded
//                            on boot so a restart does not blank the fleet until every gateway
//                            re-announces. Reload re-runs each stored record through the real
//                            announce path, so persistence can never admit anything a live
//                            announce would reject (see loadPersisted below).
//   SHADE_TREE_BOOTNODE_PROBE      1 => ACTIVELY probe live gateways (needs Tor); default off (0).
//                            When off, behavior is byte-for-byte today's: every live entry == up.
//                            When on, the bootnode periodically dials each live gateway's onion
//                            (a cheap SOCKS connect on port 80) and demotes one that fails the
//                            last N probes to health:"down" in /directory (still LISTED — TTL, not
//                            the probe, governs removal — just deprioritized by the client). A
//                            false-negative probe is therefore a soft failure, never an outage.
//   SHADE_TREE_BOOTNODE_PROBE_INTERVAL  seconds between probe cycles                 (default 120)
//   SHADE_TREE_BOOTNODE_PROBE_FAILS     consecutive failed probes before demote      (default 3)
//   SHADE_TREE_BOOTNODE_PEERS      OPTIONAL comma-list of PEER bootnode onions to federate with
//                            (default off/empty => today's standalone behavior, byte-identical).
//                            When set, a pull loop periodically fetches each peer's /directory over
//                            Tor, pulls each listed gateway's stored announce (GET /gateway/<onion>),
//                            and re-verifies it through the SAME real announce path (onion control +
//                            operator/stake) before MERGING it into this registry. The peer's own
//                            directory signature is NEVER trusted as authority over entries -- a
//                            forged/tampered gossiped gateway is rejected exactly as a direct
//                            announce. See packages/node/bootnode/federation.mjs + docs/BOOTNODE.md (Federation).
//   SHADE_TREE_BOOTNODE_FED_INTERVAL    seconds between federation pull cycles       (default 60)
//   SHADE_TREE_BOOTNODE_FED_MAX_PULL    max gateways pulled per peer per cycle (bounds a hostile peer)
//   SHADE_TREE_BOOTNODE_ONION      OPTIONAL this bootnode's own onion, filtered out of the peer set
//   SHADE_TREE_STAKE_MODE etc.     the StakeVerifier (packages/node/lib/gateway-registry.mjs)
//   SHADE_TREE_BOOTNODE_ANNOUNCE_RATE   GLOBAL announce token-bucket refill, announces/second that reach
//                            signature verification (default 2*maxEntries/heartbeat = 66.7/s; see
//                            makeAnnounceBucket for the sizing math). Over => 429 global-rate-limited.
//   SHADE_TREE_BOOTNODE_ANNOUNCE_BURST  the bucket's capacity (default max(100, maxEntries/10) = 1000).
//   SHADE_TREE_BOOTNODE_HEADERS_TIMEOUT_MS / _REQUEST_TIMEOUT_MS / _KEEPALIVE_TIMEOUT_MS /
//   _MAX_HEADER_BYTES / _CONN_CHECK_MS   HTTP slow-client limits (see HTTP_LIMITS below).
//   SHADE_TREE_REGISTRAR_ADVERTISE OPTIONAL: advertise the operator's 402 registrar (packages/node/payments/registrar.mjs,
//                            T-FEAT-7) in GET /health as `pay: {port, protocols, asset, chain, tiers}`
//                            so a client can discover "this fleet sells access, here". Either a JSON
//                            object literal, or "1" to compose it from SHADE_TREE_REGISTRAR_PORT (8878),
//                            SHADE_TREE_PAY_ASSET, SHADE_TREE_PAY_PRICES ("8=100000,32=400000"), SHADE_TREE_PAY_CHAIN_ID
//                            (11155111). Unset (default) => /health is byte-identical to before.

import http from "node:http";
import { chmod, readFile, writeFile, mkdir } from "node:fs/promises";
import { existsSync, readFileSync, writeFileSync, renameSync, mkdirSync } from "node:fs";
import { generateKeyPairSync, createHash, timingSafeEqual } from "node:crypto";
import { makeIncidents } from "./incidents.mjs";
import { gzipSync } from "node:zlib";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { signDirectory } from "../lib/directory.mjs";
import { parsePayProtocols } from "../lib/admission.mjs";
import { verifyAnnounce } from "./announce.mjs";
import { makeStakeVerifier } from "../lib/gateway-registry.mjs";
import { registry as metrics, installRuntimeMetrics, listenMetrics, safeMetricsPort } from "../lib/metrics.mjs";
import { createLogger } from "../lib/log.mjs";
import { printOperatorBanner } from "../lib/operator-ui.mjs";
import { makeFederation, parsePeers } from "./federation.mjs";
import { makeRelayAggregator } from "../lib/relay-telemetry.mjs";
import { buildCommit } from "../lib/build-info.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const log = createLogger("elder");

// ---- metrics (T-MON-2) ------------------------------------------------------
// Registered against the process-wide registry at import time; this only populates
// in-memory state — it binds no port and starts no server (see packages/node/lib/metrics.mjs).
const M = {
  announces: metrics.counter("shade_tree_bootnode_announces_total", "Announces received, labeled result=accepted|rejected (+ reason on reject)."),
  directoryFetches: metrics.counter("shade_tree_bootnode_directory_fetches_total", "Signed directory (Canopy) requests served by the Elder Tree."),
  deltaFetches: metrics.counter("shade_tree_bootnode_directory_delta_fetches_total", "GET /directory/delta requests served, labeled result=delta|full."),
  relayReports: metrics.counter("shade_tree_bootnode_relay_reports_total", "Private signed relay telemetry reports received, labeled only by bounded result/reason."),
  relayAggregates: metrics.counter("shade_tree_bootnode_relay_aggregates_total", "Delayed cohort aggregate relay snapshots served."),
};

const ANNOUNCE_REASON_LABELS = new Set([
  "rate-limited", "global-rate-limited", "registry-full", "no-announce", "bad-version",
  "no-onion", "bad-onion", "stale-ts", "replayed-nonce", "bad-onion-sig", "bad-caps-sig",
  "bad-operator-sig", "stake-check-failed", "not-staked",
]);

export function announceReasonLabel(reason) {
  const base = String(reason || "other").toLowerCase().split(":", 1)[0];
  return ANNOUNCE_REASON_LABELS.has(base) ? base : "other";
}

const RELAY_REASON_LABELS = new Set([
  "bad-report", "bad-signature", "not-announced", "future-interval", "stale-interval",
  "interval-too-long", "sequence-replay", "interval-overlap", "missing-reset",
  "unexpected-reset", "counter-rollback", "implausible-delta",
]);
function relayReasonLabel(reason) {
  const base = String(reason || "other").toLowerCase().split(":", 1)[0];
  return RELAY_REASON_LABELS.has(base) ? base : "other";
}

// Public presentation names. These headers are informational only. They are not signed and
// clients must continue to verify the directory body against the pinned signer.
const ELDER_ROLE_HEADERS = Object.freeze({
  "x-shade-tree-role": "elder-tree",
});
const CANOPY_HEADERS = Object.freeze({
  ...ELDER_ROLE_HEADERS,
  "x-shade-tree-view": "canopy",
});

// ---- signer key (mint + persist if absent) ----------------------------------
function rawSeedHex(privKey) {
  const der = privKey.export({ format: "der", type: "pkcs8" });
  return der.subarray(der.length - 32).toString("hex");
}
function rawPubHex(pubKey) {
  const der = pubKey.export({ format: "der", type: "spki" });
  return der.subarray(der.length - 32).toString("hex");
}
export async function loadOrMintSigner(path) {
  if (existsSync(path)) {
    await chmod(path, 0o600);
    return JSON.parse(await readFile(path, "utf8"));
  }
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const signer = { pub: rawPubHex(publicKey), priv: rawSeedHex(privateKey) };
  await mkdir(dirname(path), { recursive: true });
  try {
    await writeFile(path, JSON.stringify(signer, null, 2) + "\n", { flag: "wx", mode: 0o600 });
    return signer;
  } catch (error) {
    if (error?.code !== "EEXIST") throw error;
    await chmod(path, 0o600);
    return JSON.parse(await readFile(path, "utf8"));
  }
}

// ---- replay guard: bounded nonce memory, swept with the entries -------------
function makeNonceGuard(ttlMs) {
  const seen = new Map(); // key -> at
  return {
    has: (k) => seen.has(k),
    add: (k) => seen.set(k, Date.now()),
    sweep: () => { const cut = Date.now() - ttlMs; for (const [k, at] of seen) if (at < cut) seen.delete(k); },
  };
}

// ---- GLOBAL announce token bucket (T-HARD-4) ---------------------------------
// The per-onion throttle (minReannounceSec) and the size cap (maxEntries) do not slow an attacker
// who mints FRESH onions: each new onion is not "existing" (no throttle) and until the registry is
// full it is not refused, so up to maxEntries ed25519 verifies were reachable in one burst. This
// bucket sits directly in front of verifyAnnounce and bounds the RATE at which ANY announces reach
// signature verification, whoever sends them. A rejected announce costs one Map lookup + this
// arithmetic — never a verify.
//
// SIZING (defaults; every number derives from the registry constants + the fleet heartbeat):
//   legit sustained load  = N gateways × 1 announce / heartbeatSec, N ≤ maxEntries
//                         = maxEntries / heartbeatSec = 10000 / 300 = 33.3 announces/s at FULL capacity
//   rate  (refill/s)      = 2 × maxEntries / heartbeatSec = 66.7/s   (2× headroom over full capacity)
//   burst (capacity)      = max(100, maxEntries / 10) = 1000
// So a fleet at the registry cap, heartbeating at the default cadence, draws HALF the refill and
// the bucket never drains; a fleet of up to `burst` gateways re-announcing in perfect lockstep
// (e.g. a fleet-wide restart) passes in one instant; an attacker minting fresh onions gets at most
// `burst` verifies up front and then `rate`/s — 1000 then 66.7/s instead of 10000 in a burst.
// The floor of 100 on burst keeps small/dev registries (tiny maxEntries) usable. Only fleets
// LARGER than `burst` that restart in lockstep need SHADE_TREE_BOOTNODE_ANNOUNCE_BURST raised.
// A throttled legit heartbeat is not lost: it is refused 429 with Retry-After and re-sent at the
// next beat (TTL 900s = 3 beats), so a healthy gateway is never aged out by the bucket.
// Refill uses the registry's injected `now()` (seconds) so tests are deterministic; fractional
// tokens accumulate, so a sub-1/s rate still refills correctly. rate=0 && burst=0 disables (opt-out).
// Env number with an explicit-0 allowed (0 = opt-out where documented); unset/garbage => default.
function envInt(name, dflt) {
  const raw = process.env[name];
  if (raw === undefined || raw === "") return dflt;
  const n = Number(raw);
  return Number.isFinite(n) && n >= 0 ? n : dflt;
}
export function makeAnnounceBucket({ rate, burst, now = () => Math.floor(Date.now() / 1000) }) {
  let tokens = burst;
  let last = now();
  const disabled = !(rate > 0) && !(burst > 0);
  const refill = () => {
    const t = now();
    if (t > last) { tokens = Math.min(burst, tokens + (t - last) * rate); last = t; }
    return tokens;
  };
  return {
    rate, burst, disabled,
    take() {
      if (disabled) return true;
      if (refill() < 1) return false;
      tokens -= 1;
      return true;
    },
    tokens: refill,
    // Seconds until one token is available (for Retry-After); >= 1.
    retryAfterSec: () => (rate > 0 ? Math.max(1, Math.ceil((1 - tokens) / rate)) : 1),
  };
}
export function defaultAnnounceBucketParams(maxEntries) {
  const heartbeatSec = Number(process.env.SHADE_TREE_BOOTNODE_HEARTBEAT || 300);
  const rate = envInt("SHADE_TREE_BOOTNODE_ANNOUNCE_RATE", (2 * maxEntries) / heartbeatSec);
  const burst = envInt("SHADE_TREE_BOOTNODE_ANNOUNCE_BURST", Math.max(100, Math.floor(maxEntries / 10)));
  return { rate, burst, heartbeatSec };
}

// ---- active health probing (T-DEV-12) ---------------------------------------
// directory() defaults every announced-within-TTL gateway to health:"up" -- liveness there means
// "announced recently", not "onion still reachable". A gateway that announced then silently died
// (host gone, onion no longer published) keeps showing up:"up" until its TTL lapses; a client only
// learns it is dead by failing a dial. OPTIONAL active probing closes that gap: the bootnode itself
// dials each live onion and DEMOTES a silently-dead one to health:"down" sooner. It never REMOVES
// an entry (TTL still governs that) and never touches verify/admission/announce -- it only changes
// the health LABEL in directory(). A demoted gateway is still served, just deprioritized by the
// client's pickGateway (packages/node/lib/directory.mjs skips health:"down" when a healthy one exists), so a
// false-negative probe is a soft failure, not an outage.
//
// Two pieces, deliberately separate so the health logic is unit-testable WITHOUT Tor:
//   makeProbeHealth -- a PURE per-onion consecutive-fail tracker (demote after N fails, any
//                      success recovers). No I/O, injected clock, bounded (swept with the live set).
//   makeProber      -- the dialer loop, taking an INJECTED probe(onion)->Promise<bool> (default: a
//                      real SOCKS connect over Tor). A probe that throws counts as a fail
//                      (fail-closed to down), never crashing the cycle.

// Pure, testable health-tracking unit: per-onion consecutive-fail counter. `failThreshold`
// consecutive failed probes => isDown() true; ANY success resets (and drops the entry, so a
// perpetually-healthy fleet holds no state). Bounded via retain(), driven from the registry sweep.
export function makeProbeHealth({ failThreshold = Number(process.env.SHADE_TREE_BOOTNODE_PROBE_FAILS || 3),
    now = () => Date.now() } = {}) {
  const state = new Map(); // onion -> { fails, lastAt }  (present only while failing)
  return {
    failThreshold,
    // Record one probe outcome. ok=true recovers immediately (clear the counter); ok=false
    // increments the consecutive-fail counter for this onion.
    record(onion, ok) {
      if (ok) { state.delete(onion); return; }
      const e = state.get(onion) || { fails: 0, lastAt: 0 };
      e.fails += 1;
      e.lastAt = now();
      state.set(onion, e);
    },
    // Demoted iff it has failed the last failThreshold-or-more probes in a row.
    isDown: (onion) => (state.get(onion)?.fails || 0) >= failThreshold,
    // Bound the map: drop counters for onions no longer live. Called from registry.sweep(), so
    // probe state can never outlive the gateway it tracks.
    retain(keep) { for (const k of state.keys()) if (!keep.has(k)) state.delete(k); },
    fails: (onion) => state.get(onion)?.fails || 0,
    size: () => state.size,
  };
}

// The real onion dialer: a cheap SOCKS connect to <onion>:80 over the local Tor daemon. A
// successful connect == the onion is reachable. `socks` is dynamically imported so merely importing
// this module (every selftest does) pulls in no SOCKS dependency unless probing is actually used.
async function defaultProbe(onion) {
  const { SocksClient } = await import("socks");
  const host = String(onion).replace(/\.onion$/, "") + ".onion";
  const torHost = process.env.SHADE_TREE_TOR_HOST || "127.0.0.1";
  const torPort = Number(process.env.SHADE_TREE_TOR_PORT || 9250);
  const timeoutMs = Number(process.env.SHADE_TREE_BOOTNODE_PROBE_TIMEOUT_MS || 20000);
  return await new Promise((resolve) => {
    let done = false, socket;
    const finish = (v) => { if (done) return; done = true; try { socket?.destroy(); } catch {} resolve(v); };
    const timer = setTimeout(() => finish(false), timeoutMs); // never hang a cycle
    timer.unref?.();
    SocksClient.createConnection({ proxy: { host: torHost, port: torPort, type: 5 }, command: "connect", destination: { host, port: 80 } })
      .then(({ socket: s }) => { socket = s; clearTimeout(timer); finish(true); })
      .catch(() => { clearTimeout(timer); finish(false); });
  });
}

// The prober: on each cycle, dial every currently-live onion (via the injected probe) and record
// the outcome into the pure health tracker. OFF by default -- nothing dials until start() is called
// (main() only calls it under SHADE_TREE_BOOTNODE_PROBE=1). The test drives runCycle() directly with an
// injected probe + injected clock and never arms the timer.
export function makeProber({ probe = defaultProbe, health = makeProbeHealth(),
    listOnions = () => [],
    intervalMs = Number(process.env.SHADE_TREE_BOOTNODE_PROBE_INTERVAL || 120) * 1000,
    setTimer = setInterval, clearTimer = clearInterval } = {}) {
  let timer = null;
  // One probe pass over the whole live set. Each dial is independent and fail-closed: a probe that
  // returns non-true OR throws counts as a failure, so one bad onion can't abort the cycle.
  async function runCycle() {
    const onions = listOnions() || [];
    await Promise.all(onions.map(async (onion) => {
      let ok = false;
      try { ok = (await probe(onion)) === true; } catch { ok = false; }
      health.record(onion, ok);
    }));
    return onions.length;
  }
  return {
    health, runCycle, intervalMs, listOnions,
    start() { if (!timer) { timer = setTimer(() => { runCycle().catch(() => {}); }, intervalMs); timer.unref?.(); } return timer; },
    stop() { if (timer) { clearTimer(timer); timer = null; } },
  };
}

// ---- the registry (transport-independent; the selftest drives it directly) --
// DoS controls for the default `admission=open` mode, where anyone can mint onions and announce:
//   maxEntries      caps resident memory (a new onion is refused when full; existing ones still
//                   refresh, so a live fleet is never evicted by a flood).
//   minReannounceSec throttles per-onion re-announce so a single onion cannot spin the verify path.
//   MAX_WEIGHT      clamps the gateway-attested selection weight so one gateway cannot self-assign
//                   a huge weight and capture ~all client traffic (a concentration/deanon lever).
const MAX_WEIGHT = 1000;
export function makeRegistry({ signer, stake, admission = "open", ttlSec = 900, now = () => Math.floor(Date.now() / 1000),
    maxEntries = Number(process.env.SHADE_TREE_BOOTNODE_MAX_ENTRIES || 10000),
    minReannounceSec = Number(process.env.SHADE_TREE_BOOTNODE_MIN_REANNOUNCE || 5),
    // How many recent directory versions the delta protocol (T-FEAT-6) remembers. A client
    // whose last etag has aged past this window is told full:true and re-fetches. This is a
    // bounded, recent history — memory is O(deltaHistoryMax * live-set-size of onion strings).
    deltaHistoryMax = Number(process.env.SHADE_TREE_BOOTNODE_DELTA_HISTORY || 64),
    // OPTIONAL persistence: a JSON store the live set is mirrored to. Off (null) by default, so
    // unset behavior — and every existing test — is byte-for-byte unchanged.
    persistPath = process.env.SHADE_TREE_BOOTNODE_STORE || null,
    // OPTIONAL active prober (T-DEV-12). Off (null) by default => directory() marks every live
    // entry up, exactly as before. When supplied, directory() consults prober.health.isDown() to
    // demote a silently-dead gateway to health:"down" (still listed, just deprioritized).
    prober = null,
    // GLOBAL announce token bucket (T-HARD-4): rate/burst default from maxEntries + heartbeat
    // (see makeAnnounceBucket). `verify` is injectable ONLY so the selftest can spy that a
    // throttled announce never reaches signature verification; default = the real verifyAnnounce.
    announceRate = defaultAnnounceBucketParams(maxEntries).rate,
    announceBurst = defaultAnnounceBucketParams(maxEntries).burst,
    verify = verifyAnnounce }) {
  const live = new Map(); // onion -> { pubkey, weight, operator, staked, rec, expiresAt, lastAt }
  const nonces = makeNonceGuard(ttlSec * 1000);
  const bucket = makeAnnounceBucket({ rate: announceRate, burst: announceBurst, now });
  const requireStake = admission === "stake";
  // While replaying the store on boot we call announce() but must NOT write-through each replay
  // (it would churn the file mid-reload); a single persist() after reload prunes what dropped.
  let reloading = false;

  // Write-through the CURRENT live set. We store the raw signed announce records (rec) + their
  // expiresAt — NOT derived state (pubkey/weight/staked). That is deliberate: reload must
  // RE-VERIFY from the signed record, never trust a cached verdict, so nothing on disk can grant
  // trust the crypto/stake path would not. Written atomically (tmp + rename) so a crash mid-write
  // cannot leave a truncated store. Persistence is a convenience cache: a write failure logs and
  // is swallowed, never breaking an accepted announce.
  function persist() {
    if (!persistPath) return;
    try {
      const entries = [...live.values()].map((e) => ({ rec: e.rec, expiresAt: e.expiresAt }));
      mkdirSync(dirname(persistPath), { recursive: true });
      const tmp = persistPath + ".tmp";
      writeFileSync(tmp, JSON.stringify({ version: 1, entries }));
      renameSync(tmp, persistPath);
    } catch (e) {
      log.error("persist write failed (continuing)", { err: e.message });
    }
  }

  // Reload-on-boot. For EACH persisted record we re-run the real announce() path — verifyAnnounce
  // (onion control + operator/stake) plus every DoS cap. WHY re-verify instead of trusting the
  // file: persistence must not be a trust bypass. A record is restored only if its onion signature
  // (and, in stake mode, its live operator stake) still verifies, so
  //   - a tampered store entry (e.g. a flipped onionSig) fails signature verification and is dropped,
  //   - a poisoned file can add nothing a live gateway could not have announced itself,
  //   - an operator who has since unstaked drops (isStaked is re-read on chain, fail-closed).
  // FRESHNESS on reload is the stored TTL (expiresAt), NOT the live-announce anti-replay window.
  // Those are different clocks: the ts-skew (~120s) bounds how old a LIVE announce may be to defeat
  // replay; the TTL (~900s) bounds how long an ACCEPTED gateway stays listed without re-announcing.
  // A restart 300s after the last heartbeat is normal and must keep the fleet — so we gate each
  // entry on its own expiresAt here and tell announce() to skip the ts-skew for this replay of our
  // OWN atomically-written store. An entry already past expiresAt is dropped (a stale store cannot
  // resurrect a long-dead gateway). Returns { loaded, dropped } for boot logging/tests.
  async function loadPersisted() {
    if (!persistPath || !existsSync(persistPath)) return { loaded: 0, dropped: 0 };
    let stored;
    try {
      stored = JSON.parse(readFileSync(persistPath, "utf8"));
    } catch (e) {
      log.error("persist read failed, ignoring store", { err: e.message });
      return { loaded: 0, dropped: 0 };
    }
    const entries = Array.isArray(stored?.entries) ? stored.entries : [];
    let loaded = 0, dropped = 0;
    reloading = true;
    try {
      for (const ent of entries) {
        // TTL freshness gate (against the current clock), independent of the announce ts-skew.
        if (!ent || typeof ent.expiresAt !== "number" || ent.expiresAt <= now()) { dropped++; continue; }
        const r = await announce(ent.rec, { fromStore: { expiresAt: ent.expiresAt } });
        if (r.ok) loaded++; else dropped++;
      }
    } finally {
      reloading = false;
    }
    persist(); // rewrite the store once so dropped (stale/tampered) records don't linger on disk
    return { loaded, dropped };
  }

  async function announce(rec, { fromStore = null } = {}) {
    // Cheap pre-checks BEFORE the expensive signature verify, so a flood is rejected early.
    const onionKey = typeof rec?.onion === "string" ? rec.onion : null;
    const existing = onionKey ? live.get(onionKey) : null;
    if (existing && now() - existing.lastAt < minReannounceSec) return { ok: false, reason: "rate-limited" };
    if (!existing && live.size >= maxEntries) { sweep(); if (live.size >= maxEntries) return { ok: false, reason: "registry-full" }; }
    // GLOBAL rate cap (T-HARD-4), the LAST gate before the ed25519 verify: whatever the mix of
    // onions, at most `burst` + `rate`/s announces reach verifyAnnounce. Charged only here (after
    // the cheap rejects) so a legit heartbeat never pays for an attacker's rate-limited/full
    // rejects. Replaying our OWN store on boot (fromStore) is local work, not peer input: exempt.
    if (!fromStore && !bucket.take()) return { ok: false, reason: "global-rate-limited", retryAfterSec: bucket.retryAfterSec() };

    const v = await verify(rec, {
      now: now(),
      // Reloading our OWN persisted store: freshness is the stored TTL (checked in loadPersisted),
      // not the anti-replay ts window — so don't drop a gateway announced more than one skew-window
      // before the restart. Onion control + operator stake are still fully re-verified.
      ...(fromStore ? { skew: Number.MAX_SAFE_INTEGER } : {}),
      isStaked: stake?.isStaked,
      requireStake,
      seenNonce: nonces,
    });
    if (!v.ok) return { ok: false, reason: v.reason };
    const rawWeight = Number.isFinite(rec.weight) ? rec.weight : 100;
    live.set(v.onion, {
      pubkey: v.pubkey,
      weight: Math.max(0, Math.min(MAX_WEIGHT, rawWeight)), // clamp self-attested weight
      operator: v.operator,
      staked: v.staked,
      caps: v.caps, capsSig: typeof rec.capsSig === "string" ? rec.capsSig : null, // T-FEAT-10/9: verified, bounded (canonicalCaps)
      rec,
      // Preserve the original expiry across a restart (don't silently extend a gateway's TTL);
      // a live announce gets a fresh now()+ttlSec.
      expiresAt: fromStore ? fromStore.expiresAt : now() + ttlSec,
      lastAt: now(),
    });
    if (!reloading) persist(); // write-through on each accepted announce (skipped during reload)
    return { ok: true, onion: v.onion, staked: v.staked };
  }

  // ---- gossip merge (T-FEAT-1 federation) -----------------------------------
  // Admit ONE announce record pulled from a PEER bootnode, re-verified from scratch through
  // the SAME real path a direct announce takes -- the peer's signature over its directory is
  // NEVER trusted as authority over the entry. The rec is the verbatim signed announce a client
  // would fetch from GET /gateway/<onion>, so verifyAnnounce re-checks onion control (the v3
  // .onion IS its ed25519 key) and, in stake mode, the operator sig + a LIVE on-chain isStaked
  // against THIS bootnode's own chain view. A forged/tampered/unstaked gossiped entry is rejected
  // exactly as a direct announce would be. Differences from announce(), all safety-preserving:
  //   - freshness is the TTL against the announce's OWN ts (skew bypassed, like the store reload):
  //     a gossiped announce is legitimately relayed and may be older than the anti-replay window,
  //     but it can live no longer than ttlSec past the ts the origin gateway signed -- so a peer
  //     cannot keep a dead gateway alive by re-gossiping a fixed old rec (its ts never moves), and
  //     gossip never REFRESHES a TTL (loop/propagation bound).
  //   - dedup by onion: an entry we already hold at an equal-or-later expiry is a no-op (merged
  //     false) -- gossip never SHORTENS or churns a fresher local (e.g. directly-heartbeated) entry.
  //   - the same maxEntries cap: a NEW gossiped onion is refused when full (existing refresh is fine).
  //   - no nonce-guard coupling: dedup is by expiry above, so re-pulling the same rec is idempotent
  //     rather than a replayed-nonce rejection; the onion-control SIGNATURE is still fully verified,
  //     which is the actual security crux, not the anti-replay nonce.
  async function admitGossip(rec) {
    const onionKey = typeof rec?.onion === "string" ? rec.onion : null;
    if (!onionKey) return { ok: false, reason: "no-onion", merged: false };
    const ts = typeof rec.ts === "number" ? rec.ts : null;
    if (ts == null) return { ok: false, reason: "stale-ts", merged: false };
    const gossipExpiry = ts + ttlSec;
    // TTL/freshness gate: an origin announce whose TTL already lapsed cannot be resurrected.
    if (gossipExpiry <= now()) return { ok: false, reason: "stale-gossip", merged: false };
    const existing = live.get(onionKey);
    // Dedup: we already hold this onion at least as fresh -> nothing to do, don't re-verify/churn.
    if (existing && existing.expiresAt >= gossipExpiry) return { ok: true, reason: "fresh-existing", merged: false, onion: onionKey };
    // Capacity: honor the DoS cap. A NEW onion must fit; an existing one may always refresh.
    if (!existing && live.size >= maxEntries) { sweep(); if (live.size >= maxEntries) return { ok: false, reason: "registry-full", merged: false }; }
    const v = await verifyAnnounce(rec, {
      now: now(),
      skew: Number.MAX_SAFE_INTEGER, // freshness is the TTL gate above, not the anti-replay window
      isStaked: stake?.isStaked,
      requireStake,
      seenNonce: null, // idempotent re-pull; onion-control sig is still fully verified
    });
    if (!v.ok) return { ok: false, reason: v.reason, merged: false };
    const rawWeight = Number.isFinite(rec.weight) ? rec.weight : 100;
    live.set(v.onion, {
      pubkey: v.pubkey,
      weight: Math.max(0, Math.min(MAX_WEIGHT, rawWeight)), // clamp self-attested weight
      operator: v.operator,
      staked: v.staked,
      caps: v.caps, capsSig: typeof rec.capsSig === "string" ? rec.capsSig : null,
      rec,
      expiresAt: gossipExpiry, // origin-bounded, never extended by gossip
      lastAt: now(),
    });
    if (!reloading) persist();
    return { ok: true, reason: "merged", merged: true, onion: v.onion, staked: v.staked };
  }

  function sweep() {
    const t = now();
    let evicted = false;
    for (const [onion, e] of live) if (e.expiresAt <= t) { live.delete(onion); evicted = true; }
    nonces.sweep();
    // Bound the prober's per-onion fail state to the (post-eviction) live set, so a demoted
    // gateway that TTLs out drops its counter too -- probe state never outlives the gateway.
    if (prober) prober.health.retain(new Set(live.keys()));
    if (evicted && !reloading) persist(); // keep the store from retaining aged-out gateways
  }

  // Build the signed directory over currently-live entries — the exact shape
  // packages/node/lib/directory.mjs verifyDirectory() consumes, plus operator/staked labels.
  function directory() {
    sweep();
    const gateways = [...live.entries()].map(([onion, e]) => ({
      onion,
      pubkey: e.pubkey,
      weight: e.weight,
      // Liveness here == announced within TTL (=> up). With active probing on (T-DEV-12), a live
      // entry the prober has found unreachable for the last N cycles is DEMOTED to down (still
      // listed; clients deprioritize it). Off => every live entry is up, exactly as before.
      health: prober && prober.health.isDown(onion) ? "down" : "up",
      ...(e.operator ? { operator: e.operator, staked: e.staked } : {}),
      // T-FEAT-10 / T-FEAT-9: the gateway's SIGNED caps (ports/region/proto/artifacts/admits/pay)
      // pass through VERBATIM with their onion-control capsSig, so a client re-verifies them
      // against the gateway's own onion key (verifyDirectory) — the bootnode cannot forge or
      // widen them. An announce whose caps lack a standalone capsSig is listed cap-free (a
      // directory entry with caps but no capsSig would fail verification).
      ...(e.caps && e.capsSig ? { caps: e.caps, capsSig: e.capsSig } : {}),
    }));
    const dir = { version: 1, issued: now(), gateways, signer: signer.pub };
    return signDirectory(dir, signer.priv);
  }

  // ---- directory delta protocol (T-FEAT-6) ----------------------------------
  // For large or frequently-polled fleets, a client can fetch only what CHANGED since its
  // last view instead of the whole signed directory each poll. We keep a bounded history of
  // recent versions, keyed by the SAME strong ETag /directory emits (sha256 of the signed
  // bytes), each mapping to the set of onions that version listed. Given a client's last etag
  // we diff that remembered set against the current live set.
  //
  // TRUST (see docs/adr/0003-bootnode-is-a-cache-not-a-trust-root.md). A delta is a diff, not
  // a signed list, so the delta is NOT independently signature-verifiable on its own. We take
  // option (a) from the design: the delta ships the CURRENT directory's signer + signature +
  // exact gateway ORDER, and full bodies for every `added` entry. The client RECONSTRUCTS the
  // new directory from its cached base (unchanged entries) plus `added`, laid out in `order`,
  // then runs the ordinary verifyDirectory(reconstructed, pinnedSigner). This closes forgery
  // on both axes the bootnode might attack:
  //   - a forged `added` entry fails verifyDirectory's onion<->pubkey binding (the v3 .onion IS
  //     its ed25519 key; the client re-derives it), so an injected gateway under a key the
  //     bootnode does not control is rejected by the client's own check; and
  //   - any lie in `added`/`removed`/`order` changes the reconstructed canonical bytes, so the
  //     pinned signer's signature over them no longer verifies -- the bootnode cannot present a
  //     gateway list the pinned signer never signed.
  // Worst case is therefore identical to the full-directory path (ADR 0003): a hostile bootnode
  // can OMIT a gateway or answer full:true (a re-fetch), never INJECT one it does not control.
  const etagKey = (e) => String(e || "").trim().replace(/^"|"$/g, "").toLowerCase();
  // etagKey -> Map(onion -> serialized entry) for that served version. Keyed by BODY, not only
  // onion, so an entry whose signed content changed in place (weight, health, or its signed caps
  // -- e.g. a provider flipping SHADE_TREE_ADMIT, T-FEAT-9) is re-shipped in `added` (the client's
  // by-onion reconstruction overrides its cached copy) instead of leaving the client to
  // reconstruct with a stale body that would no longer verify.
  const versionHistory = new Map();
  const entryKey = (g) => JSON.stringify(g);

  function recordVersion(etag, gateways) {
    const key = etagKey(etag);
    if (versionHistory.has(key)) versionHistory.delete(key); // refresh recency (move to newest)
    versionHistory.set(key, new Map(gateways.map((g) => [g.onion, entryKey(g)])));
    while (versionHistory.size > deltaHistoryMax) versionHistory.delete(versionHistory.keys().next().value);
  }

  // The signed directory plus its serialized bytes and strong ETag, computed once. Also records
  // the version into the delta history so a client that just fetched /directory (or a delta) can
  // ask for a delta since the etag it just received. Byte-identical to the old inline path.
  function directoryWithEtag() {
    const dir = directory();
    const bytes = Buffer.from(JSON.stringify(dir), "utf8");
    const etag = `"${createHash("sha256").update(bytes).digest("hex")}"`;
    recordVersion(etag, dir.gateways);
    return { dir, bytes, etag };
  }

  // Everything a client needs to RECONSTRUCT + verify the current directory from its cached
  // base and the `added` bodies: signer, signature, and the exact gateway order.
  function reconstructMeta(dir) {
    return { version: dir.version, issued: dir.issued, signer: dir.signer, signature: dir.signature,
             order: dir.gateways.map((g) => g.onion) };
  }

  // Compute a delta against the client's last etag. Returns either
  //   { full: true, base } .............. when `since` is missing/unknown/aged out (fetch /directory), or
  //   { base, since, added, removed, unchanged, directory: reconstructMeta } .. a verifiable delta.
  function delta(sinceEtag) {
    const { dir, etag: base } = directoryWithEtag();
    const currentSet = new Set(dir.gateways.map((g) => g.onion));
    const sinceKey = etagKey(sinceEtag);
    if (!sinceKey) return { full: true, base };
    const oldSet = versionHistory.get(sinceKey);
    // `base` was just recorded, so `since === current` resolves here to an empty delta.
    if (!oldSet) return { full: true, base };
    const added = dir.gateways.filter((g) => oldSet.get(g.onion) !== entryKey(g)); // new OR changed in place
    const removed = [...oldSet.keys()].filter((o) => !currentSet.has(o));
    return { base, since: sinceEtag, added, removed, unchanged: currentSet.size - added.length,
             directory: reconstructMeta(dir) };
  }

  const record = (onion) => live.get(String(onion).endsWith(".onion") ? onion : onion + ".onion")?.rec || null;

  return { announce, admitGossip, directory, directoryWithEtag, delta, sweep, record, loadPersisted, size: () => live.size,
    has: (onion) => live.has(String(onion).endsWith(".onion") ? String(onion) : `${onion}.onion`),
    liveOnions: () => [...live.keys()], maxEntries: () => maxEntries, prober, admission, ttlSec, announceBucket: bucket };
}

// ---- registrar advert (T-FEAT-7) ---------------------------------------------
// The bootnode is discovery: it says WHERE the registrar is (same onion, another port) and what it
// sells; it never proxies a payment. Pure over env so the selftest can pin the shape. Returns null
// when unset/garbage (=> no `pay` key in /health at all).
export function payAdvertFromEnv(env = process.env) {
  const raw = env.SHADE_TREE_REGISTRAR_ADVERTISE;
  if (!raw || String(raw).trim() === "" || String(raw).trim() === "0") return null;
  if (String(raw).trim().startsWith("{")) {
    try { const j = JSON.parse(raw); return j && typeof j === "object" && !Array.isArray(j) ? j : null; } catch { return null; }
  }
  const asset = env.SHADE_TREE_PAY_ASSET;
  if (!/^0x[0-9a-fA-F]{40}$/.test(asset || "")) return null;
  const tiers = {};
  for (const part of String(env.SHADE_TREE_PAY_PRICES || "").split(",").map((x) => x.trim()).filter(Boolean)) {
    const m = /^([1-9][0-9]{0,4})=([1-9][0-9]*)$/.exec(part);
    if (!m) return null;
    tiers[m[1]] = m[2];
  }
  if (!Object.keys(tiers).length) return null;
  const chainId = Number(env.SHADE_TREE_PAY_CHAIN_ID || 11155111);
  // T-FEAT-9: only the rails the registrar actually serves (SHADE_TREE_PAY_PROTOCOLS; default both).
  let protocols;
  try { protocols = parsePayProtocols(env.SHADE_TREE_PAY_PROTOCOLS); } catch { return null; }
  return { port: envInt("SHADE_TREE_REGISTRAR_PORT", 8878), protocols, asset, chain: `eip155:${chainId}`, tiers };
}

// ---- HTTP transport ---------------------------------------------------------
function send(res, code, obj, extraHeaders = null) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { "content-type": "application/json", "content-length": Buffer.byteLength(body), ...(extraHeaders || {}) });
  res.end(body);
}

// ---- HTTP slow-client limits (T-HARD-4) --------------------------------------
// Node's http.Server defaults leave several slow-loris levers open: headersTimeout 60s,
// requestTimeout 300s (a body can dribble for 5 minutes), maxHeaderSize 16 KiB, and the
// timeouts are only enforced every connectionsCheckingInterval=30s. Every request the bootnode
// serves is small and fast (a signed JSON announce or a directory fetch), so these can be tight.
// Env-configurable, an explicit 0 disables the corresponding timeout (opt-out, never the default).
//   SHADE_TREE_BOOTNODE_HEADERS_TIMEOUT_MS   complete request headers must arrive within (default 10000)
//   SHADE_TREE_BOOTNODE_REQUEST_TIMEOUT_MS   the WHOLE request (headers+body) within (default 30000);
//                                      a slow-dribbled body is cut at 408 (must be >= headers)
//   SHADE_TREE_BOOTNODE_KEEPALIVE_TIMEOUT_MS idle keep-alive connection closed after (default 5000, Node's)
//   SHADE_TREE_BOOTNODE_MAX_HEADER_BYTES     max total header bytes, over => 431 (default 8192)
//   SHADE_TREE_BOOTNODE_CONN_CHECK_MS        how often the timeouts are enforced (default 1000)
export const HTTP_LIMITS = Object.freeze({
  headersTimeout: envInt("SHADE_TREE_BOOTNODE_HEADERS_TIMEOUT_MS", 10000),
  requestTimeout: envInt("SHADE_TREE_BOOTNODE_REQUEST_TIMEOUT_MS", 30000),
  keepAliveTimeout: envInt("SHADE_TREE_BOOTNODE_KEEPALIVE_TIMEOUT_MS", 5000),
  maxHeaderSize: envInt("SHADE_TREE_BOOTNODE_MAX_HEADER_BYTES", 8192),
  connectionsCheckingInterval: envInt("SHADE_TREE_BOOTNODE_CONN_CHECK_MS", 1000),
});
function readBody(req, max = 64 * 1024) {
  return new Promise((resolve, reject) => {
    let buf = "";
    req.on("data", (c) => { buf += c; if (buf.length > max) { reject(new Error("body too large")); req.destroy(); } });
    req.on("end", () => resolve(buf));
    req.on("error", reject);
  });
}

// `limits` overrides HTTP_LIMITS (the selftest sets tiny timeouts); main() passes none.
export function makeServer(registry, { signerPub, limits = {}, pay = null, relayAggregator = null, incidents = null, incidentsToken = null } = {}) {
  // Current live-gateway count as a gauge, evaluated at scrape time from this registry.
  metrics.gauge("shade_tree_bootnode_live_gateways", "Gateways currently live (announced within TTL).").setCollect(() => registry.size());

  const lim = { ...HTTP_LIMITS, ...limits };
  // Node refuses headersTimeout > requestTimeout (when both are on); clamp so a partial override
  // can never wedge startup.
  if (lim.requestTimeout > 0 && lim.headersTimeout > lim.requestTimeout) lim.headersTimeout = lim.requestTimeout;
  const server = http.createServer({
    headersTimeout: lim.headersTimeout,
    requestTimeout: lim.requestTimeout,
    keepAliveTimeout: lim.keepAliveTimeout,
    maxHeaderSize: lim.maxHeaderSize,
    connectionsCheckingInterval: lim.connectionsCheckingInterval,
  }, async (req, res) => {
    try {
      const url = new URL(req.url, "http://bootnode");
      if (req.method === "GET" && url.pathname === "/health") {
        // `pay` (T-FEAT-7): present only when the operator advertises a registrar (see payAdvertFromEnv).
        return send(res, 200, { ok: true, count: registry.size(), admission: registry.admission, signer: signerPub, commit: buildCommit(), ...(pay ? { pay } : {}) }, ELDER_ROLE_HEADERS);
      }
      // Separate private telemetry ingestion. Reports never ride in /announce or /directory.
      // The aggregator re-verifies onion control and requires this identity to be live in the
      // authenticated registry before retaining a bounded raw delta.
      if (req.method === "POST" && url.pathname === "/telemetry/relay") {
        if (!relayAggregator) return send(res, 404, { ok: false, err: "telemetry-disabled" });
        let report;
        try { report = JSON.parse(await readBody(req, 16 * 1024)); }
        catch { return send(res, 400, { ok: false, err: "bad-report" }); }
        const result = await relayAggregator.accept(report);
        M.relayReports.inc({ result: result.ok ? "accepted" : "rejected", ...(result.ok ? {} : { reason: relayReasonLabel(result.reason) }) });
        return send(res, result.ok ? 200 : 400, result.ok ? { ok: true } : { ok: false, err: result.reason });
      }
      // The observer receives only a signed, delayed, rounded cohort aggregate. The raw node map
      // is not exposed by any route. Suppressed windows omit roundedBytes completely.
      if (req.method === "GET" && url.pathname === "/telemetry/aggregate") {
        if (!relayAggregator) return send(res, 404, { ok: false, err: "telemetry-disabled" });
        M.relayAggregates.inc();
        const aggregate = relayAggregator.snapshot();
        const body = Buffer.from(JSON.stringify(aggregate), "utf8");
        const etag = `"${createHash("sha256").update(body).digest("hex")}"`;
        if (req.headers["if-none-match"]?.split(",").some((value) => value.trim() === etag)) {
          res.writeHead(304, { etag, "cache-control": "public, max-age=60", ...ELDER_ROLE_HEADERS });
          return res.end();
        }
        res.writeHead(200, {
          "content-type": "application/json",
          "content-length": body.length,
          "cache-control": "public, max-age=60",
          etag,
          ...ELDER_ROLE_HEADERS,
        });
        return res.end(body);
      }
      // Operator metrics intentionally do not live on this server. Tor maps this entire
      // listener into the Elder onion, so exposing /metrics here would publish exact fleet
      // activity. main() starts a separate loopback-only listener when configured.
      // GET /incidents -> the signed operator incident feed (packages/node/bootnode/incidents.mjs).
      // Served with the canopy headers because clients fetch it right after /directory and verify
      // it under the same pinned signer. Empty when nothing is declared; never 404.
      if (req.method === "GET" && url.pathname === "/incidents") {
        if (!incidents) return send(res, 200, { version: 1, issued: Math.floor(Date.now() / 1000), incidents: [] }, CANOPY_HEADERS);
        return send(res, 200, incidents.feed(), CANOPY_HEADERS);
      }
      // POST /incidents/alertmanager -> Alertmanager webhook receiver. Off (404) unless the
      // operator set SHADE_TREE_BOOTNODE_INCIDENTS_TOKEN; a wrong or missing bearer is 401.
      if (req.method === "POST" && url.pathname === "/incidents/alertmanager") {
        if (!incidents || !incidentsToken) return send(res, 404, { ok: false, err: "incidents-webhook-disabled" });
        const auth = String(req.headers.authorization || "");
        const presented = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
        if (!presented || presented.length !== incidentsToken.length || !timingSafeEqual(Buffer.from(presented), Buffer.from(incidentsToken))) {
          return send(res, 401, { ok: false, err: "bad-token" });
        }
        let payload;
        try { payload = JSON.parse(await readBody(req, 256 * 1024)); } catch { return send(res, 400, { ok: false, err: "bad-json" }); }
        const result = incidents.applyAlertmanager(payload);
        return send(res, 200, { ok: true, ...result });
      }
      // GET /directory/delta?since=<etag> -> only what CHANGED since the client's last view
      // (T-FEAT-6). Additive to /directory: the response carries the current signer + signature
      // + gateway order so the client reconstructs the new directory from its cached base + the
      // `added` bodies and verifies it with the ordinary verifyDirectory (the delta cannot smuggle
      // a forged gateway -- see registry.delta above and docs/adr/0003). An unknown/aged-out
      // `since` returns { full: true } telling the client to fetch the whole /directory.
      if (req.method === "GET" && url.pathname === "/directory/delta") {
        const d = registry.delta(url.searchParams.get("since"));
        M.deltaFetches.inc({ result: d.full ? "full" : "delta" });
        const body = Buffer.from(JSON.stringify(d), "utf8");
        const wantsGzip = /(^|[,\s])gzip($|[,;\s])/i.test(req.headers["accept-encoding"] || "");
        const out = wantsGzip ? gzipSync(body) : body;
        const headers = { "content-type": "application/json", "content-length": out.length, ...CANOPY_HEADERS };
        if (wantsGzip) headers["content-encoding"] = "gzip";
        res.writeHead(200, headers);
        return res.end(out);
      }
      if (req.method === "GET" && url.pathname === "/directory") {
        M.directoryFetches.inc();
        // Transport-only scale features (T-DEV-11): ETag + conditional GET + gzip. NEITHER
        // changes the directory CONTENT or its signature -- a client that ignores both still
        // receives the identical signed bytes and verifies the decompressed JSON exactly as
        // before. (The registry already caps entry count via maxEntries, so no pagination is
        // needed now; pagination is a later step if a single fleet ever exceeds that cap.)
        // directoryWithEtag() returns the identical signed bytes and the same strong sha256 ETag
        // as before, and additionally records this version into the delta history (T-FEAT-6).
        const { bytes: body, etag } = registry.directoryWithEtag();
        const inm = req.headers["if-none-match"];
        if (inm && inm.split(",").some((t) => t.trim() === etag)) {
          res.writeHead(304, { etag, ...CANOPY_HEADERS });
          return res.end(); // 304 Not Modified: no body
        }
        const wantsGzip = /(^|[,\s])gzip($|[,;\s])/i.test(req.headers["accept-encoding"] || "");
        const out = wantsGzip ? gzipSync(body) : body;
        const headers = { "content-type": "application/json", etag, "content-length": out.length, ...CANOPY_HEADERS };
        if (wantsGzip) headers["content-encoding"] = "gzip";
        res.writeHead(200, headers);
        return res.end(out);
      }
      // GET /gateway/<onion> -> the stored signed announce, for zero-trust re-verification.
      if (req.method === "GET" && url.pathname.startsWith("/gateway/")) {
        const onion = decodeURIComponent(url.pathname.slice("/gateway/".length));
        const rec = registry.record(onion);
        return rec ? send(res, 200, rec) : send(res, 404, { ok: false, err: "not-found" });
      }
      if (req.method === "POST" && url.pathname === "/announce") {
        let rec;
        try { rec = JSON.parse(await readBody(req)); } catch (e) { return send(res, 400, { ok: false, err: "bad-json:" + e.message }); }
        const r = await registry.announce(rec);
        if (r.ok) M.announces.inc({ result: "accepted" });
        else M.announces.inc({ result: "rejected", reason: announceReasonLabel(r.reason) });
        // The GLOBAL bucket (T-HARD-4) answers 429 + Retry-After (a heartbeat should simply retry
        // at its next beat); every other rejection keeps its 400 exactly as before.
        if (!r.ok && r.reason === "global-rate-limited") return send(res, 429, { ok: false, err: r.reason }, { "retry-after": String(r.retryAfterSec || 1) });
        return send(res, r.ok ? 200 : 400, r.ok ? { ok: true, onion: r.onion, staked: r.staked, ttl: registry.ttlSec } : { ok: false, err: r.reason });
      }
      return send(res, 404, { ok: false, err: "no-route" });
    } catch (e) {
      return send(res, 500, { ok: false, err: "bootnode-error:" + e.message });
    }
  });
  server.limits = lim; // introspection for the selftest / boot log
  return server;
}

// ---- graceful shutdown / connection draining (T-DEV-8) ----------------------
// Same pattern as the gateway (packages/node/gateway/gateway.mjs): OFF the hot path — signal handlers
// plus a small openSockets set only, request handling untouched. On SIGTERM/SIGINT we
// stop accepting NEW connections (server.close), let the (short) in-flight requests
// finish, then exit 0; a straggler past the grace window is force-closed and we exit
// nonzero. Bootnode requests are short, so draining is near-instant in practice.
//
// Injectable (server, timer, onExit) so the selftest drives it with a fake server +
// fake sockets + fake clock and no real process signals.
export function makeGracefulShutdown(server, {
  openSockets = new Set(),
  timeoutMs = 10000,
  onExit = (code) => process.exit(code),
  log = console.log,
  label = "bootnode",
  setTimer = setTimeout,
  clearTimer = clearTimeout,
} = {}) {
  let started = false; // idempotent: a second signal during drain is ignored
  return function shutdown(signal) {
    if (started) return;
    started = true;
    log(`${label}: draining (${signal || "shutdown"}); ${openSockets.size} in-flight, no new connections, ${timeoutMs}ms grace`);
    let timer = null;
    const finish = (code) => { if (timer) clearTimer(timer); onExit(code); };
    // Arm the grace window FIRST so an immediate (synchronous) clean drain can clear it.
    timer = setTimer(() => {
      log(`${label}: drain timeout (${timeoutMs}ms) with ${openSockets.size} still open; forcing exit`);
      for (const s of openSockets) { try { s.destroy(); } catch {} }
      finish(1);
    }, timeoutMs);
    timer.unref?.();
    server.close(() => { log(`${label}: drained cleanly, exiting`); finish(0); });
    return timer;
  };
}

// ---- main -------------------------------------------------------------------
async function main() {
  const pkg = JSON.parse(await readFile(join(HERE, "../../..", "package.json"), "utf8"));
  installRuntimeMetrics(metrics, { role: "elder", version: pkg.version });
  const port = Number(process.env.SHADE_TREE_BOOTNODE_PORT || 8877);
  const admission = process.env.SHADE_TREE_BOOTNODE_ADMISSION || "open";
  const ttlSec = Number(process.env.SHADE_TREE_BOOTNODE_TTL || 900);
  const signerPath = process.env.SHADE_TREE_BOOTNODE_SIGNER_KEY || join(HERE, "bootnode-signer.key");

  const signer = await loadOrMintSigner(signerPath);
  const stake = makeStakeVerifier();
  const persistPath = process.env.SHADE_TREE_BOOTNODE_STORE || null;
  // OPTIONAL active health probing (T-DEV-12). Off unless SHADE_TREE_BOOTNODE_PROBE=1 (needs Tor). The
  // prober lists onions from the registry, so it's built first with a getter that closes over the
  // registry declared just below, then handed in.
  let registry;
  const prober = process.env.SHADE_TREE_BOOTNODE_PROBE === "1"
    ? makeProber({ health: makeProbeHealth(), listOnions: () => registry.liveOnions() })
    : null;
  registry = makeRegistry({ signer, stake, admission, ttlSec, persistPath, prober });
  registry.ttlSec = ttlSec;
  // Reload-on-boot: re-announce any persisted fleet so a restart doesn't blank the directory
  // until every gateway re-announces. Each record is re-verified (stale/tampered ones drop).
  if (persistPath) {
    const { loaded, dropped } = await registry.loadPersisted();
    log.info("persistence: reloaded gateways", { loaded, dropped, store: persistPath });
  }
  setInterval(() => registry.sweep(), Math.min(ttlSec, 60) * 1000).unref();

  // Arm the active prober only when enabled. It self-unrefs, so it never keeps the process alive.
  if (prober) {
    prober.start();
    log.info("active health probing on", { intervalSec: prober.intervalMs / 1000, failThreshold: prober.health.failThreshold });
  }

  // OPTIONAL bootnode federation / gossip (T-FEAT-1). Off unless SHADE_TREE_BOOTNODE_PEERS is set, so
  // the default (empty) is byte-for-byte today's standalone bootnode. When on, we pull each peer's
  // directory + per-gateway announces over Tor and re-verify every entry through the real announce
  // path before merging (packages/node/bootnode/federation.mjs). The timer self-unrefs (never holds the process).
  const peers = parsePeers(process.env.SHADE_TREE_BOOTNODE_PEERS, { self: process.env.SHADE_TREE_BOOTNODE_ONION });
  if (peers.length) {
    const federation = makeFederation({ registry, peers, log });
    federation.start();
    log.info("bootnode federation on", { peers, intervalSec: federation.intervalMs / 1000 });
  }

  const pay = payAdvertFromEnv();
  const relayAggregator = makeRelayAggregator({
    signer,
    isAnnounced: (onion) => registry.has(onion),
    statePath: process.env.SHADE_TREE_RELAY_ELDER_STATE || join(HERE, "relay-telemetry-state.local.json"),
    minimumCohort: Number(process.env.SHADE_TREE_RELAY_MIN_COHORT || 5),
    delayHours: Number(process.env.SHADE_TREE_RELAY_DELAY_HOURS || 6),
  });
  // Operator incident feed (GET /incidents): hand-edited file and/or the Alertmanager webhook.
  const incidents = makeIncidents({
    signer,
    path: process.env.SHADE_TREE_BOOTNODE_INCIDENTS_FILE || join(HERE, "incidents.local.json"),
    log,
  });
  const incidentsToken = process.env.SHADE_TREE_BOOTNODE_INCIDENTS_TOKEN || null;
  const server = makeServer(registry, { signerPub: signer.pub, pay, relayAggregator, incidents, incidentsToken });
  log.info("incident feed on", { file: incidents.path, webhook: incidentsToken ? "POST /incidents/alertmanager (bearer)" : "off" });
  if (pay) log.info("advertising 402 registrar in /health", pay);

  // Track live connections for draining (add/delete only — no per-request work).
  const openSockets = new Set();
  server.on("connection", (s) => { openSockets.add(s); s.on("close", () => openSockets.delete(s)); });
  metrics.gauge("shade_tree_bootnode_connections", "Open Elder Tree transport connections.").setCollect(() => openSockets.size);

  // The Elder onion maps the discovery listener wholesale. Metrics therefore use a distinct
  // loopback-only port and are disabled unless the operator opts in (the reference deploy does).
  const metricsPort = safeMetricsPort(process.env.SHADE_TREE_METRICS_PORT, [["Elder Tree backend", port]]);
  let metricsServer = null;
  if (metricsPort > 0) {
    metricsServer = listenMetrics({ port: metricsPort, reg: metrics, host: "127.0.0.1", ready: () => server.listening });
    await new Promise((resolve, reject) => {
      metricsServer.once("listening", resolve);
      metricsServer.once("error", reject);
    });
    log.info("operator metrics ready", { event: "metrics.ready", listen: `127.0.0.1:${metricsPort}` });
  }

  server.listen(port, "127.0.0.1", () => {
    // "bootnode up on <host>:<port>" substring preserved for any startup-readiness grep.
    printOperatorBanner({ role: "elder", rows: [
      ["listen", `127.0.0.1:${port}`],
      ["admission", admission],
      ["canopy", `${registry.size()} trees`],
      ["metrics", metricsPort > 0 ? `127.0.0.1:${metricsPort}` : "off"],
      ["logs", `${process.env.SHADE_TREE_LOG_LEVEL || "info"} / ${process.env.SHADE_TREE_LOG_FORMAT || "auto"}`],
    ] });
    log.info(`bootnode up on 127.0.0.1:${port}`, { event: "service.ready", admission, stake: stake.mode, ttlSec, metricsPort });
    log.info("Canopy signer ready", { signer: signer.pub });
    log.debug("discovery endpoints ready", { endpoints: ["POST /announce", "POST /telemetry/relay", "GET /telemetry/aggregate", "GET /directory", "GET /directory/delta", "GET /gateway/<onion>", "GET /health", "GET /incidents", "POST /incidents/alertmanager"] });
    const b = registry.announceBucket;
    log.debug("endpoint hardening", { announceRatePerSec: Number(b.rate.toFixed(2)), announceBurst: b.burst, ...server.limits });
  });

  const timeoutMs = Number(process.env.SHADE_TREE_SHUTDOWN_TIMEOUT_MS || 10000);
  const shutdown = makeGracefulShutdown(server, { openSockets, timeoutMs, label: "elder", log: (message) => log.info(message, { event: "service.shutdown" }) });
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

// Only main() (direct run) installs signal handlers; importing the module (the
// selftest) pulls the exported makeRegistry / makeServer / makeGracefulShutdown with
// mocks and installs NONE.
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => { log.error("Elder Tree failed", { event: "service.failed", err: e }); process.exit(1); });
}
