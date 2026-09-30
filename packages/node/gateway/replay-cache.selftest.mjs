// Self-test for the per-gateway seen-envelope replay cache (T-FEAT-12).
//
// Drives makeSpentSet() directly (pure, no gateway process, no sockets) with an INJECTED
// clock so the honest-retry window is deterministic, and proves the exact semantics:
//
//   - first envelope for a nullifier             => egress (action "first"), no slash
//   - identical envelope WITHIN the window       => idempotent (action "replay"), NO new
//                                                   egress, NO slash  (dropped-conn retry)
//   - identical envelope AFTER the window         => rejected (action/reason
//                                                   "replayed-envelope"), no slash
//   - same share.x but a DIFFERENT nonce          => rejected "replayed-envelope"
//                                                   (fingerprint we never recorded)
//   - a 2nd DISTINCT share.x                       => reconstruct + slash EXACTLY once
//                                                   (RLN over-spend path UNCHANGED)
//   - different nullifiers are independent
//   - sweep() drops fingerprints past ttlMs (injected clock)
//
// Run:  node packages/node/gateway/replay-cache.selftest.mjs
//
// gateway.mjs imports cleanly standalone (no signal handlers, no port bound at import),
// so this pulls makeSpentSet straight out with no lib mocks (same as egress-policy.selftest).

import assert from "node:assert/strict";
import { makeSpentSet } from "./gateway.mjs";

let failures = 0;
function ok(name) { console.log("  PASS  " + name); }
function bad(name, e) { failures++; console.log("  FAIL  " + name + "  ::  " + (e && e.message || e)); }
async function test(name, fn) { try { await fn(); ok(name); } catch (e) { bad(name, e); } }

// A controllable clock: `now()` reads `clock`; tests advance it explicitly.
function makeClock(t = 1_000_000) {
  const c = { t };
  return { now: () => c.t, advance: (ms) => { c.t += ms; }, set: (v) => { c.t = v; } };
}

const WINDOW = 1000; // ms — the honest-retry window for these tests

console.log("gateway replay cache (T-FEAT-12):");

await test("first envelope egresses (action first), no slash", async () => {
  const clk = makeClock();
  const slashes = [];
  const s = makeSpentSet({ reconstruct: () => "S", derive: () => "C", slash: async (...a) => slashes.push(a), replayWindowMs: WINDOW, now: clk.now });
  const r = await s.admit("null#3", { x: "sigA", y: "yA" }, { nonce: "n1" });
  assert.equal(r.ok, true);
  assert.equal(r.action, "first");
  assert.equal(slashes.length, 0);
});

await test("identical envelope WITHIN the window is idempotent (replay), no new egress, no slash", async () => {
  const clk = makeClock();
  const slashes = [];
  const s = makeSpentSet({ reconstruct: () => "S", derive: () => "C", slash: async (...a) => slashes.push(a), replayWindowMs: WINDOW, now: clk.now });
  await s.admit("null#3", { x: "sigA", y: "yA" }, { nonce: "n1" });     // first
  clk.advance(WINDOW - 1);                                             // still inside the window
  const r = await s.admit("null#3", { x: "sigA", y: "yA" }, { nonce: "n1" }); // exact resend
  assert.equal(r.action, "replay");
  assert.equal(r.ok, true, "in-flight honest retry still succeeds idempotently");
  assert.equal(slashes.length, 0, "replay must not slash");
});

await test("identical envelope AFTER the window is rejected replayed-envelope", async () => {
  const clk = makeClock();
  const slashes = [];
  const s = makeSpentSet({ reconstruct: () => "S", derive: () => "C", slash: async (...a) => slashes.push(a), replayWindowMs: WINDOW, now: clk.now });
  await s.admit("null#3", { x: "sigA", y: "yA" }, { nonce: "n1" });     // first
  clk.advance(WINDOW + 1);                                             // past the window
  const r = await s.admit("null#3", { x: "sigA", y: "yA" }, { nonce: "n1" }); // late replay
  assert.equal(r.ok, false, "a late exact replay must NOT egress again");
  assert.equal(r.action, "replayed-envelope");
  assert.equal(r.reason, "replayed-envelope");
  assert.equal(slashes.length, 0, "a replay is orthogonal to slashing — never slashes");
});

await test("same share.x but a DIFFERENT nonce is rejected replayed-envelope (foreign fingerprint)", async () => {
  const clk = makeClock();
  const slashes = [];
  const s = makeSpentSet({ reconstruct: () => "S", derive: () => "C", slash: async (...a) => slashes.push(a), replayWindowMs: WINDOW, now: clk.now });
  await s.admit("null#3", { x: "sigA", y: "yA" }, { nonce: "n1" });        // first, fingerprint n1
  const r = await s.admit("null#3", { x: "sigA", y: "yA" }, { nonce: "n2" }); // same x, unseen nonce
  assert.equal(r.ok, false);
  assert.equal(r.action, "replayed-envelope");
  assert.equal(slashes.length, 0);
});

await test("a 2nd DISTINCT share.x still reconstructs + slashes EXACTLY once (RLN path unchanged)", async () => {
  const clk = makeClock();
  const slashes = [];
  const s = makeSpentSet({
    reconstruct: (a, b) => "SECRET(" + a.y + "|" + b.y + ")",
    derive: (secret) => "COMMIT(" + secret + ")",
    slash: async (commitment, secret) => slashes.push({ commitment, secret }),
    replayWindowMs: WINDOW, now: clk.now,
  });
  await s.admit("null#3", { x: "sigA", y: "yA" }, { nonce: "n1" });        // first
  await s.admit("null#3", { x: "sigA", y: "yA" }, { nonce: "n1" });        // replay (no slash)
  const r = await s.admit("null#3", { x: "sigB", y: "yB" }, { nonce: "n2" }); // distinct x => slash
  assert.equal(r.action, "slash");
  assert.equal(r.ok, false, "the over-spending request itself is refused");
  assert.equal(slashes.length, 1, "slash exactly once");
  assert.equal(slashes[0].commitment, "COMMIT(SECRET(yA|yB))");
  assert.equal(slashes[0].secret, "SECRET(yA|yB)");
  const r2 = await s.admit("null#3", { x: "sigC", y: "yC" }, { nonce: "n3" });
  assert.equal(r2.ok, false);
  assert.equal(slashes.length, 1, "no double slash");
});

await test("different nullifiers are independent", async () => {
  const clk = makeClock();
  const slashes = [];
  const s = makeSpentSet({ reconstruct: () => "S", derive: () => "C", slash: async (...a) => slashes.push(a), replayWindowMs: WINDOW, now: clk.now });
  await s.admit("null#3", { x: "sigA", y: "yA" }, { nonce: "n1" });
  clk.advance(WINDOW + 1000); // a replay of null#3 would now be rejected...
  const r = await s.admit("null#4", { x: "sigB", y: "yB" }, { nonce: "n9" }); // ...but a fresh nullifier is first
  assert.equal(r.action, "first");
  assert.equal(r.ok, true);
  assert.equal(slashes.length, 0);
});

await test("backward-compatible: admit(nullifier, share) with no nonce/clock still dedups an immediate retry", async () => {
  // Preserves the pre-T-FEAT-12 call shape used by packages/node/gateway/shim.selftest.mjs: no opts, no
  // injected clock (real Date.now), default window. An immediate resend is inside the window.
  const slashes = [];
  const s = makeSpentSet({ reconstruct: () => "S", derive: () => "C", slash: async (...a) => slashes.push(a) });
  const a = await s.admit("null#7", { x: "sigA", y: "yA" });
  const b = await s.admit("null#7", { x: "sigA", y: "yA" });
  assert.equal(a.action, "first");
  assert.equal(b.action, "replay");
  assert.equal(b.ok, true);
  assert.equal(slashes.length, 0);
});

await test("sweep() drops fingerprints past ttlMs (injected clock)", async () => {
  const clk = makeClock();
  const s = makeSpentSet({ reconstruct: () => "S", derive: () => "C", replayWindowMs: WINDOW, ttlMs: 10_000, now: clk.now });
  await s.admit("null#3", { x: "sigA", y: "yA" }, { nonce: "n1" });
  assert.equal(s.size(), 1);
  clk.advance(10_001); // past ttl
  s.sweep();
  assert.equal(s.size(), 0, "nullifier entry swept");
  // fingerprint also swept => the same envelope now looks brand new (a fresh first), which
  // is safe because by ttlMs (>= 2 epochs) its externalNullifier is already stale at verify.
  const r = await s.admit("null#3", { x: "sigA", y: "yA" }, { nonce: "n1" });
  assert.equal(r.action, "first");
});

console.log("");
if (failures) {
  console.log(`SELFTEST FAILED: ${failures} failing case(s)`);
  process.exit(1);
}
console.log("SELFTEST PASSED: all cases green");
