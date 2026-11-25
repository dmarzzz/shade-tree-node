// Load/soak selftest (T-TEST-7).
//
// A BOUNDED, DETERMINISTIC soak over the client's hot selection path, driven purely in-process
// with a seeded RNG -- no real network, Tor, chain, or sleeps. (The node's replay cache and the
// Elder's registry caps, once soaked here, are tested in their Rust crates.)
//
//   weighted selection (packages/node/lib/directory.mjs selectionOrder / pickGateway) -- a large fleet
//      drawn tens of thousands of times under a SEEDED rng: assert the empirical distribution
//      is roughly proportional to weight (within tolerance), the MAX_WEIGHT clamp holds (a
//      gateway self-assigning a huge weight cannot capture the fleet), a floored-to-zero
//      weight is never picked, and selectionOrder always returns a full de-duplicated
//      permutation of the fleet.
//
// The DEFAULT run is bounded to stay fast (<~2s). Set SHADE_TREE_SOAK=1 for a heavier multiplier
// (the default suite never sets it); heavy is still deterministic, just longer.
//
// Run:  node test/soak.selftest.mjs
//       SHADE_TREE_SOAK=1 node test/soak.selftest.mjs   (heavy variant)

import assert from "node:assert/strict";
import {
  MAX_WEIGHT,
  pickGateway,
  selectionOrder,
} from "../packages/node/lib/directory.mjs";

let failures = 0;
function ok(name) { console.log("  PASS  " + name); }
function bad(name, e) { failures++; console.log("  FAIL  " + name + "  ::  " + (e && e.message || e)); }
async function test(name, fn) { try { await fn(); ok(name); } catch (e) { bad(name, e); } }

// Heavy multiplier: default is a bounded, fast pass; SHADE_TREE_SOAK=1 scales the volume up.
const HEAVY = process.env.SHADE_TREE_SOAK === "1";
const X = HEAVY ? 10 : 1;

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

console.log("");
console.log(`(soak wall-time: ${Date.now() - t0}ms${HEAVY ? "  [HEAVY]" : ""})`);
if (failures) {
  console.log(`SELFTEST FAILED: ${failures} failing case(s)`);
  process.exit(1);
}
console.log("SELFTEST PASSED: all cases green");
