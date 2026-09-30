// Load/soak selftest (T-TEST-7).
//
// A BOUNDED, DETERMINISTIC soak over the hot correctness paths, driven purely in-process
// with injected clocks / seeded RNG / mocked reconstruct+derive+slash -- no real network,
// Tor, chain, or sleeps. It exercises three engines under high iteration counts and asserts
// they stay CORRECT and BOUNDED under volume:
//
//   A. replay cache (packages/node/gateway/gateway.mjs makeSpentSet) -- thousands of distinct + duplicate
//      envelopes across many epochs: assert every genuine in-window replay is caught, dedup
//      is exact under volume, slashing fires exactly once per over-spend, and the resident
//      cache stays SIZE-BOUNDED (epoch pruning via sweep() reclaims aged entries -- no
//      unbounded growth as total volume climbs).
//
//   B. weighted selection (packages/node/lib/directory.mjs selectionOrder / pickGateway) -- a large fleet
//      drawn tens of thousands of times under a SEEDED rng: assert the empirical distribution
//      is roughly proportional to weight (within tolerance), the MAX_WEIGHT clamp holds (a
//      gateway self-assigning a huge weight cannot capture the fleet), a floored-to-zero
//      weight is never picked, and selectionOrder always returns a full de-duplicated
//      permutation of the fleet.
//
//   C. bootnode registry (packages/node/bootnode/server.mjs makeRegistry) under an announce storm -- mint
//      more onions than maxEntries and assert the DoS caps hold: the entry count never
//      exceeds maxEntries (a flood is refused, not resident), a self-attested huge weight is
//      clamped to MAX_WEIGHT, and a re-announce inside minReannounceSec is rate-limited.
//
// The DEFAULT run is bounded to stay fast (<~2s). Set SHADE_TREE_SOAK=1 for a heavier multiplier
// (the default suite never sets it); heavy is still deterministic, just longer.
//
// Run:  node test/soak.selftest.mjs
//       SHADE_TREE_SOAK=1 node test/soak.selftest.mjs   (heavy variant)

import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash, createPublicKey } from "node:crypto";

import { makeSpentSet } from "../packages/node/gateway/gateway.mjs";
import {
  MAX_WEIGHT,
  pickGateway,
  selectionOrder,
  ed25519PrivateKey,
  pubkeyToOnion,
} from "../packages/node/lib/directory.mjs";
import { buildAnnounce } from "../packages/node/bootnode/announce.mjs";
import { makeRegistry, loadOrMintSigner } from "../packages/node/bootnode/server.mjs";
import { MockStakeVerifier } from "../packages/node/lib/gateway-registry.mjs";

let failures = 0;
function ok(name) { console.log("  PASS  " + name); }
function bad(name, e) { failures++; console.log("  FAIL  " + name + "  ::  " + (e && e.message || e)); }
async function test(name, fn) { try { await fn(); ok(name); } catch (e) { bad(name, e); } }

// Heavy multiplier: default is a bounded, fast pass; SHADE_TREE_SOAK=1 scales the volume up.
const HEAVY = process.env.SHADE_TREE_SOAK === "1";
const X = HEAVY ? 10 : 1;

// A controllable clock (matches packages/node/gateway/replay-cache.selftest.mjs): now() reads `t`.
function makeClock(t = 1_000_000) {
  const c = { t };
  return { now: () => c.t, advance: (ms) => { c.t += ms; }, set: (v) => { c.t = v; } };
}

// Deterministic seeded PRNG (mulberry32) -- so every distribution assertion is stable and
// never depends on Math.random or wall-clock.
function mulberry32(seed) {
  let a = seed >>> 0;
  return function () {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const t0 = Date.now();
console.log(`load/soak (T-TEST-7)${HEAVY ? "  [HEAVY: SHADE_TREE_SOAK=1]" : ""}:`);

// ============================================================================
// A. replay cache: volume dedup + slash-once + size-bounded epoch pruning
// ============================================================================
await test("replay cache: exact-envelope dedup is correct over volume + resident size stays bounded across epochs", async () => {
  const EPOCHS = 40 * X;
  const PER_EPOCH = 1000;             // distinct nullifiers minted per epoch
  const WINDOW = 5000;               // honest-retry window (ms)
  const TTL = 20_000;                // entries older than this are swept
  const clk = makeClock();
  const slashes = [];
  const s = makeSpentSet({
    reconstruct: (a, b) => "S(" + a.y + "|" + b.y + ")",
    derive: (secret) => "C(" + secret + ")",
    slash: async (commitment, secret) => slashes.push({ commitment, secret }),
    replayWindowMs: WINDOW, ttlMs: TTL, now: clk.now,
  });

  let firsts = 0, replaysCaught = 0, peakSize = 0;
  for (let e = 0; e < EPOCHS; e++) {
    // Each epoch: mint PER_EPOCH fresh nullifiers, admit each once (first), then immediately
    // resend the exact same envelope inside the window (an honest dropped-conn retry).
    for (let i = 0; i < PER_EPOCH; i++) {
      const nf = `nf#${e}:${i}`;
      const share = { x: `x${i}`, y: `y${i}` };
      const r1 = await s.admit(nf, share, { nonce: "n1" });
      assert.equal(r1.action, "first", "a brand-new nullifier must be 'first'");
      firsts++;
      const r2 = await s.admit(nf, share, { nonce: "n1" }); // exact resend, still in window
      assert.equal(r2.action, "replay", "an in-window exact resend must be caught as 'replay'");
      assert.equal(r2.ok, true, "an honest retry stays idempotently ok");
      replaysCaught++;
    }
    peakSize = Math.max(peakSize, s.size());
    // Age the whole epoch out, then sweep. The NEXT epoch's fresh nullifiers keep resident
    // size bounded by ~one epoch's working set rather than growing with total volume.
    clk.advance(TTL + 1);
    s.sweep();
    assert.equal(s.size(), 0, "sweep() reclaims every aged-out nullifier (epoch pruning)");
  }

  // Correctness under volume: every genuine replay was caught, no slash from pure replays.
  assert.equal(firsts, EPOCHS * PER_EPOCH);
  assert.equal(replaysCaught, EPOCHS * PER_EPOCH, "every in-window replay across the soak was caught");
  assert.equal(slashes.length, 0, "pure replays never slash");
  // BOUNDED: resident size tracked one epoch's working set, never the cumulative total. This
  // is the anti-leak invariant -- peak stays ~PER_EPOCH even though total volume is EPOCHS x.
  assert.ok(peakSize <= PER_EPOCH + 5, `resident cache bounded (peak ${peakSize} <= ~${PER_EPOCH}, total processed ${firsts})`);
});

await test("replay cache: an over-spend under high nullifier count slashes EXACTLY once each, never double", async () => {
  const N = 2000 * X;
  const WINDOW = 5000;
  const clk = makeClock();
  const slashes = [];
  const s = makeSpentSet({
    reconstruct: (a, b) => `SECRET(${a.y}|${b.y})`,
    derive: (secret) => `COMMIT(${secret})`,
    slash: async (commitment, secret) => slashes.push({ commitment, secret }),
    replayWindowMs: WINDOW, ttlMs: 10 * 60_000, now: clk.now,
  });

  for (let i = 0; i < N; i++) {
    const nf = `over#${i}`;
    await s.admit(nf, { x: "xA", y: "yA" }, { nonce: "a" });              // first
    await s.admit(nf, { x: "xA", y: "yA" }, { nonce: "a" });              // replay (no slash)
    const r = await s.admit(nf, { x: "xB", y: "yB" }, { nonce: "b" });    // distinct x => slash
    assert.equal(r.action, "slash");
    const r2 = await s.admit(nf, { x: "xC", y: "yC" }, { nonce: "c" });   // further over-spend
    assert.equal(r2.ok, false, "post-slash the nullifier is refused");
  }
  assert.equal(slashes.length, N, "slash fired exactly once per over-spent nullifier (no double, no miss)");
  // Spot-check a reconstruction is well-formed (the RLN secret-recovery path is unchanged).
  assert.equal(slashes[0].commitment, "COMMIT(SECRET(yA|yB))");
});

await test("replay cache: a late exact replay (past the window) is rejected, distinctly from an in-window retry", async () => {
  const N = 3000 * X;
  const WINDOW = 5000;
  const clk = makeClock();
  const s = makeSpentSet({
    reconstruct: () => "S", derive: () => "C", slash: async () => {},
    replayWindowMs: WINDOW, ttlMs: 10 * 60_000, now: clk.now,
  });
  let rejected = 0;
  for (let i = 0; i < N; i++) {
    const nf = `late#${i}`;
    await s.admit(nf, { x: "x", y: "y" }, { nonce: "n" });
  }
  clk.advance(WINDOW + 1); // every fingerprint above is now out-of-window
  for (let i = 0; i < N; i++) {
    const nf = `late#${i}`;
    const r = await s.admit(nf, { x: "x", y: "y" }, { nonce: "n" });
    assert.equal(r.ok, false, "a late exact replay must not egress again");
    assert.equal(r.action, "replayed-envelope");
    rejected++;
  }
  assert.equal(rejected, N, "every out-of-window replay across the volume was rejected");
});

// ============================================================================
// B. weighted selection: proportional distribution + MAX_WEIGHT clamp
// ============================================================================
await test("selection: empirical distribution is ~proportional to weight over many draws (seeded)", async () => {
  // A large fleet with a mix of weights, all well under MAX_WEIGHT so the clamp is inert here.
  const FLEET = 120;
  const DRAWS = 30_000 * X;
  const gateways = [];
  for (let i = 0; i < FLEET; i++) {
    const w = [1, 5, 10, 25, 50][i % 5]; // deterministic weight mix
    gateways.push({ onion: `g${i}.onion`, pubkey: `pk${i}`, weight: w, health: "up" });
  }
  const dir = { gateways };
  const rng = mulberry32(0xC0FFEE);
  const totalW = gateways.reduce((s, g) => s + g.weight, 0);

  const counts = new Map();
  for (let d = 0; d < DRAWS; d++) {
    const g = pickGateway(dir, { rng });
    counts.set(g.onion, (counts.get(g.onion) || 0) + 1);
  }

  // Every gateway with positive weight is reachable, and observed share tracks weight share
  // within a comfortable tolerance (sampling error at 30k draws is tiny; seed makes it stable).
  for (const g of gateways) {
    const obs = counts.get(g.onion) || 0;
    const exp = DRAWS * (g.weight / totalW);
    assert.ok(obs > 0, `gateway ${g.onion} (weight ${g.weight}) is reachable`);
    const tol = Math.max(0.15 * exp, 30); // 15% relative, with an absolute floor for small buckets
    assert.ok(Math.abs(obs - exp) <= tol,
      `share ~proportional for weight ${g.weight}: obs ${obs} vs exp ${exp.toFixed(0)} (tol ${tol.toFixed(0)})`);
  }
});

await test("selection: MAX_WEIGHT clamp holds -- a huge self-attested weight cannot capture the fleet", async () => {
  const DRAWS = 30_000 * X;
  // 40 honest weight-10 gateways + one 'greedy' gateway attesting an absurd weight. If the
  // clamp holds, greedy behaves as weight=MAX_WEIGHT, NOT weight=1e9 (which would starve all).
  const gateways = [{ onion: "greedy.onion", pubkey: "pkG", weight: 1e9, health: "up" }];
  for (let i = 0; i < 40; i++) gateways.push({ onion: `h${i}.onion`, pubkey: `pk${i}`, weight: 10, health: "up" });
  const dir = { gateways };
  const rng = mulberry32(0x5EED);

  let greedy = 0;
  const honestCounts = new Map();
  for (let d = 0; d < DRAWS; d++) {
    const g = pickGateway(dir, { rng });
    if (g.onion === "greedy.onion") greedy++;
    else honestCounts.set(g.onion, (honestCounts.get(g.onion) || 0) + 1);
  }

  // Effective total after clamping = MAX_WEIGHT + 40*10.
  const effTotal = MAX_WEIGHT + 40 * 10;
  const expGreedy = DRAWS * (MAX_WEIGHT / effTotal);
  assert.ok(Math.abs(greedy - expGreedy) <= 0.15 * expGreedy,
    `greedy behaves as MAX_WEIGHT (obs ${greedy} vs exp ${expGreedy.toFixed(0)}), not 1e9`);
  // And crucially it did NOT capture ~all draws: honest gateways still get a real share.
  const totalHonest = [...honestCounts.values()].reduce((a, b) => a + b, 0);
  assert.ok(totalHonest > DRAWS * 0.25, `honest fleet retains real share (${totalHonest}/${DRAWS}) despite the greedy attest`);
  assert.ok(greedy < DRAWS * 0.85, "the clamp prevents the greedy gateway from capturing ~all traffic");
});

await test("selection: a floored-to-zero (negative) weight is never picked; selectionOrder is a full de-duped permutation", async () => {
  const FLEET = 60;
  const DRAWS = 5000 * X;
  const gateways = [{ onion: "dead.onion", pubkey: "pkD", weight: -100, health: "up" }]; // floors to 0
  for (let i = 0; i < FLEET; i++) gateways.push({ onion: `g${i}.onion`, pubkey: `pk${i}`, weight: 10, health: "up" });
  const dir = { gateways };
  const rng = mulberry32(0xABCD);

  for (let d = 0; d < DRAWS; d++) {
    const g = pickGateway(dir, { rng });
    assert.notEqual(g.onion, "dead.onion", "a zero-weight gateway is never selected while positive-weight peers exist");
  }

  // selectionOrder must always yield the ENTIRE fleet exactly once (a failover walk), across
  // many independent seeded draws -- no truncation, no duplication under volume.
  const ORDERS = 200 * X;
  for (let d = 0; d < ORDERS; d++) {
    const order = selectionOrder(dir, { rng });
    assert.equal(order.length, gateways.length, "selectionOrder returns the whole fleet");
    const uniq = new Set(order.map((g) => g.onion));
    assert.equal(uniq.size, gateways.length, "selectionOrder never duplicates a gateway");
  }
});

// ============================================================================
// C. bootnode registry: announce-storm DoS caps hold
// ============================================================================

// Mint a gateway onion identity IN-MEMORY (no disk) from a deterministic seed, matching
// packages/node/bootnode/keygen.mjs's derivation so onion == pubkeyToOnion(pub) and buildAnnounce can sign.
function mintOnion(i) {
  const seedHex = createHash("sha256").update("shade-tree-soak-onion:" + i).digest().toString("hex"); // 32 bytes
  const pubDer = createPublicKey(ed25519PrivateKey(seedHex)).export({ format: "der", type: "spki" });
  const pub = Buffer.from(pubDer.subarray(pubDer.length - 32)).toString("hex");
  return { seed: seedHex, pub, onion: pubkeyToOnion(pub) };
}

await test("registry: announce storm cannot exceed maxEntries; huge weight clamped; re-announce rate-limited", async () => {
  const work = await mkdtemp(join(tmpdir(), "shade-tree-soak-"));
  try {
    const signer = await loadOrMintSigner(join(work, "signer.key"));
    const clock = 1_700_000_000; // fixed verifier clock (seconds)
    const MAX_ENTRIES = 64;
    const MIN_REANNOUNCE = 5;
    const registry = makeRegistry({
      signer, stake: MockStakeVerifier({}), admission: "open",
      ttlSec: 900, maxEntries: MAX_ENTRIES, minReannounceSec: MIN_REANNOUNCE,
      now: () => clock,
    });

    const STORM = (MAX_ENTRIES + 200) * X; // mint far more distinct onions than the cap allows
    let accepted = 0, full = 0;
    for (let i = 0; i < STORM; i++) {
      const g = mintOnion(i);
      const rec = buildAnnounce({ onion: g.onion, weight: 100, onionSeedHex: g.seed, ts: clock, nonce: `soak-${i}` });
      const r = await registry.announce(rec);
      if (r.ok) accepted++;
      else if (r.reason === "registry-full") full++;
    }
    assert.equal(accepted, MAX_ENTRIES, "exactly maxEntries distinct onions are admitted");
    assert.equal(full, STORM - MAX_ENTRIES, "every onion beyond the cap is refused registry-full (flood not resident)");
    const dir = registry.directory();
    assert.equal(dir.gateways.length, MAX_ENTRIES, "resident entry count is bounded by maxEntries");

    // A re-announce of an ALREADY-resident onion inside minReannounceSec is rate-limited
    // (cannot be used to churn / amplify). Same clock => 0s since lastAt => below the floor.
    const g0 = mintOnion(0);
    const reRec = buildAnnounce({ onion: g0.onion, weight: 100, onionSeedHex: g0.seed, ts: clock, nonce: "soak-re" });
    const reR = await registry.announce(reRec);
    assert.equal(reR.ok, false);
    assert.equal(reR.reason, "rate-limited", "a re-announce inside minReannounceSec is rate-limited");

    // MAX_WEIGHT clamp on a fresh registry: a gateway self-attesting an absurd weight is clamped.
    const reg2 = makeRegistry({
      signer, stake: MockStakeVerifier({}), admission: "open",
      ttlSec: 900, maxEntries: MAX_ENTRIES, minReannounceSec: MIN_REANNOUNCE, now: () => clock,
    });
    const greedy = mintOnion(999999);
    const gRec = buildAnnounce({ onion: greedy.onion, weight: 1e9, onionSeedHex: greedy.seed, ts: clock, nonce: "soak-greedy" });
    const gR = await reg2.announce(gRec);
    assert.equal(gR.ok, true, "greedy announce itself is accepted");
    const gEntry = reg2.directory().gateways.find((x) => x.onion === greedy.onion);
    assert.equal(gEntry.weight, MAX_WEIGHT, `self-attested 1e9 weight clamped to MAX_WEIGHT (${MAX_WEIGHT})`);
  } finally {
    await rm(work, { recursive: true, force: true });
  }
});

console.log("");
console.log(`(soak wall-time: ${Date.now() - t0}ms${HEAVY ? "  [HEAVY]" : ""})`);
if (failures) {
  console.log(`SELFTEST FAILED: ${failures} failing case(s)`);
  process.exit(1);
}
console.log("SELFTEST PASSED: all cases green");
