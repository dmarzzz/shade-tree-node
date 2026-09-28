// Mocked control-flow self-test for Track 3 (gateway + shim).
//
// The real crypto lib (lib/semaphore.mjs extended + lib/rln.mjs new) lands at combine
// time, so here we MOCK the lib API from docs/history/NEXT-VERSION.md and prove Track 3's
// control flow against it:
//
//   Gateway spent-set (makeSpentSet):
//     - first share for a nullifier => egress, no slash
//     - identical replay (same share.x) => deduped, NO slash
//     - second DISTINCT signal on the same nullifier => reconstruct + slash EXACTLY once
//     - a distinct signal on a DIFFERENT nullifier => no slash (independent counter)
//
//   Shim slot pool (makeSlotPool / buildEnvelope):
//     - one slot per tunnel, cursor rotates and wraps at K
//     - the envelope carries the PRECOMPUTED membership proof and a REQUEST-BOUND share
//     - the share is bound to requestSignal(target, nonce) (deterministic-retry seam)
//
// Run:  node gateway/shim.selftest.mjs
//
// It redirects the two lib specifiers to in-memory mocks with a module resolve hook,
// so it needs no real lib and edits nothing under lib/.

import { register } from "node:module";
import { writeFile, mkdir, rm } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { tmpdir } from "node:os";
import { join } from "node:path";
import assert from "node:assert/strict";

const work = join(tmpdir(), "shade-tree-selftest-" + process.pid);
await mkdir(work, { recursive: true });

// ---- mock lib modules -------------------------------------------------------

const MOCK_SEMAPHORE = `
export const EPOCH_SECONDS = 120;
export const K_SLOTS = 8;
export function normLimit(l = K_SLOTS) { return BigInt(l); } // T-FEAT-8 tier limit (mock: identity)
export const MEMBERS_PATH = "/dev/null/members.json";
export function currentEpoch() { return 7n; }
export function externalNullifierFor(epoch) { return "extnull(" + epoch + ")"; }
export function requestSignal(target, nonce) { return "sig(" + target + "|" + nonce + ")"; }
export async function proveForSlot(secret, epoch, i, signal, opts) {
  // Mirror the real lib: the RLN proof BINDS the signal (proof's public x === signal),
  // and the share is evaluated at the same signal. proof + share are one coherent bundle.
  // The slot (messageId) is a PRIVATE witness returned for local bookkeeping only.
  return {
    proof: { message: signal, merkleTreeRoot: "ROOT" },
    nullifier: "null#" + i,
    externalNullifier: externalNullifierFor(epoch),
    slot: i,
    share: { x: signal, y: "y(" + i + "," + signal + ")" },
  };
}
export async function verifyEnvelope(env, recentRoots) {
  // Mirror the real cheap binding: the share must be evaluated at the proof's signal.
  if (String(env.proof.message) !== String(env.share.x)) return { ok: false, reason: "signal-mismatch" };
  return { ok: true, reason: "ok", nullifier: env.nullifier, externalNullifier: env.externalNullifier, share: env.share };
}
export async function loadGroup() { return { group: null, root: "ROOT", count: 1 }; }
export async function loadGroupOnchain() { return { recentRoots: ["ROOT"] }; }
export function cleanUp() {}

// T-HARD-8 artifact negotiation surface (mocked: one artifact set, no lock/vkey reads).
export function clientArtifactIds() { return ["rln-mock0000000000"]; }
export function selectArtifact(gatewayIds, clientIds) { return { ok: true, id: clientIds[0] }; }
export function getArtifactSet() { return { accepted: new Map(), ids: ["rln-mock0000000000"], legacyId: "rln-mock0000000000", legacyAccepted: true, explicit: false }; }
`;

const MOCK_RLN = `
export function reconstructSecret(a, b) { return "SECRET(" + a.y + "|" + b.y + ")"; }
export function deriveCommitment(secret) { return "COMMIT(" + secret + ")"; }
export const K_SLOTS = 8;
export const TIERS = [8];
export function resolveSlashLeaf(secret) { return { commitment: deriveCommitment(secret), limit: 8, resolved: true }; } // T-FEAT-8 (mock)
export function deriveCommitments(secret, tiers = TIERS) { return tiers.map((limit) => ({ limit, commitment: deriveCommitment(secret) })); } // T-FEAT-8b (mock)
`;

const LOADER = `
let redirects = {};
export async function initialize(data) { redirects = data; }
export async function resolve(specifier, context, next) {
  if (specifier.endsWith("lib/semaphore.mjs")) return { url: redirects.semaphore, shortCircuit: true };
  if (specifier.endsWith("lib/rln.mjs")) return { url: redirects.rln, shortCircuit: true };
  return next(specifier, context);
}
`;

await writeFile(join(work, "semaphore.mjs"), MOCK_SEMAPHORE);
await writeFile(join(work, "rln.mjs"), MOCK_RLN);
await writeFile(join(work, "loader.mjs"), LOADER);

register(pathToFileURL(join(work, "loader.mjs")).href, {
  parentURL: import.meta.url,
  data: {
    semaphore: pathToFileURL(join(work, "semaphore.mjs")).href,
    rln: pathToFileURL(join(work, "rln.mjs")).href,
  },
});

// ---- import Track 3 modules against the mocked lib --------------------------

const { makeSpentSet } = await import("../gateway/gateway.mjs");
const { makeSlotPool, buildEnvelope, proxyFailureLabel } = await import("../client/shim.mjs");

let failures = 0;
function ok(name) { console.log("  PASS  " + name); }
function bad(name, e) { failures++; console.log("  FAIL  " + name + "  ::  " + (e && e.message || e)); }
async function test(name, fn) { try { await fn(); ok(name); } catch (e) { bad(name, e); } }

// ---- gateway: share-collecting spent-set + slashing -------------------------

console.log("gateway spent-set:");

await test("first share egresses, no slash", async () => {
  const slashes = [];
  const s = makeSpentSet({ reconstruct: (a, b) => "S", derive: () => "C", slash: async (...a) => slashes.push(a) });
  const r = await s.admit("null#3", { x: "sigA", y: "yA" });
  assert.equal(r.ok, true);
  assert.equal(r.action, "first");
  assert.equal(slashes.length, 0);
});

await test("identical replay is deduped, NO slash", async () => {
  const slashes = [];
  const s = makeSpentSet({ reconstruct: (a, b) => "S", derive: () => "C", slash: async (...a) => slashes.push(a) });
  await s.admit("null#3", { x: "sigA", y: "yA" });
  const r = await s.admit("null#3", { x: "sigA", y: "yA" }); // same evaluation point
  assert.equal(r.action, "replay");
  assert.equal(r.ok, true);
  assert.equal(slashes.length, 0, "replay must not slash");
});

await test("second DISTINCT signal on one nullifier reconstructs + slashes EXACTLY once", async () => {
  const slashes = [];
  const s = makeSpentSet({
    reconstruct: (a, b) => "SECRET(" + a.y + "|" + b.y + ")",
    derive: (secret) => "COMMIT(" + secret + ")",
    slash: async (commitment, secret) => slashes.push({ commitment, secret }),
  });
  await s.admit("null#3", { x: "sigA", y: "yA" });                 // first
  await s.admit("null#3", { x: "sigA", y: "yA" });                 // replay (no slash)
  const r = await s.admit("null#3", { x: "sigB", y: "yB" });       // distinct => slash
  assert.equal(r.action, "slash");
  assert.equal(r.ok, false, "the over-spending request itself is refused");
  assert.equal(slashes.length, 1, "slash exactly once");
  assert.equal(slashes[0].commitment, "COMMIT(SECRET(yA|yB))");
  assert.equal(slashes[0].secret, "SECRET(yA|yB)");
  // a further distinct signal must NOT slash again
  const r2 = await s.admit("null#3", { x: "sigC", y: "yC" });
  assert.equal(r2.ok, false);
  assert.equal(slashes.length, 1, "no double slash");
});

await test("distinct signal on a DIFFERENT nullifier does not slash (independent counter)", async () => {
  const slashes = [];
  const s = makeSpentSet({ reconstruct: () => "S", derive: () => "C", slash: async (...a) => slashes.push(a) });
  await s.admit("null#3", { x: "sigA", y: "yA" }); // nullifier for slot 3
  const r = await s.admit("null#4", { x: "sigB", y: "yB" }); // distinct nullifier, first for its key
  assert.equal(r.action, "first");
  assert.equal(slashes.length, 0);
});

// ---- shim: slot pool rotation + request-bound share -------------------------

console.log("shim slot pool:");

await test("proxy failure metrics use bounded labels", async () => {
  const localClosed = new Error("a peer-controlled message that must not become a label");
  localClosed.code = "SHADE_TREE_LOCAL_CLIENT_CLOSED";
  assert.equal(proxyFailureLabel(localClosed), "client-closed");
  assert.equal(proxyFailureLabel(new Error("SOCKS connection refused at abc.onion")), "tor-dial-failed");
  assert.equal(proxyFailureLabel(new Error("unclassified attacker text")), "internal");
});

const noGroup = async () => ({ group: null });
function mockProve(calls) {
  // Mirror the real lib: proof binds the signal (proof.message === signal); the share is
  // evaluated at the same signal, so proof + share are one coherent bundle.
  return async (secret, epoch, i, signal, opts) => {
    calls.push({ epoch, i, signal, group: opts && opts.group });
    return {
      proof: { message: signal, merkleTreeRoot: "ROOT" },
      nullifier: "null#" + i,
      externalNullifier: "extnull(" + epoch + ")",
      slot: i,
      share: { x: signal, y: "y(" + i + "," + signal + ")" },
    };
  };
}

await test("the explicit unsafe test seam can exercise deliberate slot reuse", async () => {
  const calls = [];
  const pool = makeSlotPool({ secret: "sek", prove: mockProve(calls), epochOf: () => 7n, K: 4, loadGroupFn: noGroup, unsafeAllowSlotReuseForTests: true });
  const got = [];
  for (let n = 0; n < 6; n++) got.push(pool.nextSlot().slot);
  assert.deepEqual(got, [0, 1, 2, 3, 0, 1], "the test-only seam wraps at K for overspend coverage");
});

await test("envelope is a coherent v4 bundle; share bound to requestSignal(target,nonce)", async () => {
  const calls = [];
  const prove = mockProve(calls);
  const pool = makeSlotPool({ secret: "sek", prove, epochOf: () => 7n, K: 4, loadGroupFn: noGroup, slotStatePath: join(work, "envelope-slots.json") });
  const { envelope, signal, slot } = await buildEnvelope({ secret: "sek", target: "example.com:443", pool, prove });

  assert.equal(envelope.v, 4);
  assert.equal(envelope.target, "example.com:443");
  assert.equal(typeof slot, "number");
  assert.ok(!("slot" in envelope), "slot is a private witness — never on the wire");
  assert.ok(!("scope" in envelope), "scope is gone in the v4 wire format");
  for (const k of ["proof", "nullifier", "externalNullifier", "share"]) assert.ok(k in envelope, "missing " + k);

  // request-bound: share is evaluated at H(target, nonce) ...
  assert.ok(signal.startsWith("sig(example.com:443|"), "signal is H(target, nonce)");
  assert.equal(envelope.share.x, signal, "share.x must equal the request signal");
  // ... and the proof commits to the SAME signal, so verifyEnvelope's binding holds:
  assert.equal(envelope.proof.message, envelope.share.x, "proof.message === share.x (coherent bundle)");
});

await test("each request gets a fresh nonce (distinct signals across requests)", async () => {
  const calls = [];
  const prove = mockProve(calls);
  const pool = makeSlotPool({ secret: "sek", prove, epochOf: () => 7n, K: 4, loadGroupFn: noGroup, slotStatePath: join(work, "nonce-slots.json") });
  const a = await buildEnvelope({ secret: "sek", target: "a.com:443", pool, prove });
  const b = await buildEnvelope({ secret: "sek", target: "a.com:443", pool, prove });
  assert.notEqual(a.signal, b.signal, "fresh per-request nonce => distinct signals");
  assert.notEqual(a.slot, b.slot, "slot also rotates between requests");
});

console.log("");
if (failures) {
  await rm(work, { recursive: true, force: true });
  console.log(`SELFTEST FAILED: ${failures} failing case(s)`);
  process.exit(1);
}
await rm(work, { recursive: true, force: true });
console.log("SELFTEST PASSED: all cases green");
