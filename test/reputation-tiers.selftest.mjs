// Reputation-weighted rate budget (T-FEAT-8) with REAL Groth16 proofs — the acceptance
// criterion verbatim: "two tiers with different K, each proven in ZK; the gateway enforces the
// proven tier; a member cannot claim a tier they lack." Slow suite (real proving; in
// scripts/test-all.mjs SLOW_SUITES, skipped by SHADE_TREE_FAST=1). The fast half is packages/node/lib/tiers.selftest.mjs.
//
// Design under test (docs/adr/0006-reputation-tiers.md): the tier IS the leaf's PRIVATE
// userMessageLimit. circom-rln's leaf is Poseidon2(Poseidon1(identitySecret), limit) and the
// circuit range-checks messageId < limit, so ONE tree holds every tier, the wire is unchanged,
// and the gateway "enforces the proven tier" the only way a private input can be enforced: the
// SNARK verifies against a trusted root (a leaf carrying a different limit is a different leaf,
// not in the tree) and the nullifier set dedups messageIds under it. No circuit change, no
// new setup.
//
//   A = tier 1 (limit K1 = 8, the default)     B = tier 2 (limit K2 = 32)     same tree
//
// Proves, with real proofs:
//   TWO TIERS: A proves slots 0 and 7 (< K1); B proves slots 8 and 31 (< K2, >= K1) — all
//              accepted by verifyEnvelope; B's slot-8 proof is a budget A cannot have
//   ENFORCED:  A at slot 8 (>= K1, < K2): no proof exists — the client pre-check refuses and,
//              bypassing it, the CIRCUIT's RangeCheck asserts (a tier-1 member exceeding K1 but
//              under K2 has nothing to send => DROP at the source); A's 9th distinct request in
//              an epoch must reuse a messageId => same nullifier, distinct x => over-spend-slashed,
//              and the slash names A's TIER-8 leaf (resolveSlashLeaf over SHADE_TREE_TIERS=[8,32])
//   FORGED:    A cannot claim tier 2: proveForSlot(limit 32) against the real tree fails ("not
//              in group"); a proof over A's OWN tree containing Poseidon2(Poseidon1(sA), 32) is a
//              real, valid SNARK — rejected wrong-group-root (precise; before any SNARK work);
//              same for a forged tree at A's true limit (root binding, control)
//   UNLINKABLE: the tier never appears on the wire or in the verify result: same envelope keys,
//              same public-signal set, no limit field; verifyEnvelope returns no tier
//   CLIENT:    ShadeTreeClient/makeSlotPool at limit 32 => buildEnvelope proves at 32 (slot 20) and
//              the gateway accepts it; B's over-spend resolves to the tier-32 leaf
//
//   node test/reputation-tiers.selftest.mjs

import assert from "node:assert/strict";
import { RLNProver } from "rlnjs";
import {
  toField, identityFor, identitySecretOf, rateCommitmentOf, deriveCommitment, groupFromIdentities, newGroup,
  requestSignal, proveForSlot, verifyEnvelope, currentEpoch, EPOCH_SECONDS, K_SLOTS, RLN_IDENTIFIER,
  getProverSets, calculateSignalHash, cleanUp,
} from "../packages/node/lib/rln.mjs";
import { makeSpentSet, deriveSlashLeaf } from "../packages/node/gateway/gateway.mjs";
import { buildEnvelope, makeSlotPool } from "../packages/node/client/shade-tree-client.mjs";

let failures = 0;
function ok(name) { console.log("  PASS  " + name); }
function bad(name, e) { failures++; console.log("  FAIL  " + name + "  ::  " + (e && e.stack || e)); }
async function test(name, fn) { try { await fn(); ok(name); } catch (e) { bad(name, e); } }

console.log("reputation tiers with real proofs (T-FEAT-8):");

const K1 = K_SLOTS; // 8 (default tier)
const K2 = 32;      // tier 2
assert.equal(K1, 8, "this suite assumes the default K (SHADE_TREE_SLOTS unset)");
const TIERS = [K1, K2];

// ---- one tree, two tiers ---------------------------------------------------------------------
const epoch = currentEpoch();
const nowMs = Number(epoch) * EPOCH_SECONDS * 1000 + 1000; // pinned inside `epoch` (no rollover flake)
const secretA = toField("0x" + "a1".repeat(32));
const secretB = toField("0x" + "b2".repeat(32));
const filler = identityFor(toField("0x" + "33".repeat(32)));
const idA = identityFor(secretA), idB = identityFor(secretB);
const leafA = rateCommitmentOf(idA, K1).toString();
const leafB = rateCommitmentOf(idB, K2).toString();
const group = groupFromIdentities([filler, idA, { identity: idB, limit: K2 }]);
const roots = new Set([group.root.toString()]);
const leaves = new Set([rateCommitmentOf(filler).toString(), leafA, leafB]);

const TARGET = "example.com:443";
async function envelope(secret, slot, nonce, { limit, group: g = group } = {}) {
  const p = await proveForSlot(secret, epoch, slot, requestSignal(TARGET, nonce), { group: g, limit });
  return { v: 4, target: TARGET, nonce, artifact: p.artifact, proof: p.proof, nullifier: p.nullifier, externalNullifier: p.externalNullifier, share: p.share };
}

// ---- TWO TIERS, each proven in ZK -----------------------------------------------------------------
const a0 = await envelope(secretA, 0, "a-0", { limit: K1 });
const a7 = await envelope(secretA, 7, "a-7", { limit: K1 });
const b8 = await envelope(secretB, 8, "b-8", { limit: K2 });
const b31 = await envelope(secretB, 31, "b-31", { limit: K2 });
await test(`TWO TIERS: tier-1 (K=${K1}) proofs at slots 0 and 7 verify against the shared root`, async () => {
  for (const e of [a0, a7]) { const r = await verifyEnvelope(e, roots, nowMs); assert.equal(r.ok, true, r.reason); }
  assert.notEqual(a0.nullifier, a7.nullifier);
});
await test(`TWO TIERS: tier-2 (K=${K2}) proofs at slots 8 and 31 (>= K1) verify against the SAME root — a budget tier 1 cannot reach`, async () => {
  for (const e of [b8, b31]) { const r = await verifyEnvelope(e, roots, nowMs); assert.equal(r.ok, true, r.reason); }
  assert.notEqual(b8.nullifier, b31.nullifier);
  assert.equal(String(b8.proof.snarkProof.publicSignals.root), group.root.toString());
});
await test("TWO TIERS: default-limit call sites are unchanged — proveForSlot without `limit` proves at K_SLOTS (A verifies)", async () => {
  const e = await envelope(secretA, 3, "a-3");
  const r = await verifyEnvelope(e, roots, nowMs);
  assert.equal(r.ok, true, r.reason);
});

// ---- ENFORCED: tier 1 exceeding K1 but under K2 -----------------------------------------------------
await test(`ENFORCED: tier-1 member at slot ${K1} (>= K1, < K2): proveForSlot refuses (precise) and the CIRCUIT rejects it when the pre-check is bypassed`, async () => {
  await assert.rejects(() => proveForSlot(secretA, epoch, K1, requestSignal(TARGET, "a-8"), { group, limit: K1 }), /slot 8 >= limit 8/);
  // Bypass the client pre-check: drive rlnjs's prover directly with A's true leaf + limit and messageId = K1.
  const set = getProverSets()[0];
  const prover = new RLNProver(set.wasm, set.zkey);
  const mp = group.generateMerkleProof(group.indexOf(BigInt(leafA)));
  await assert.rejects(() => prover.generateProof({
    identitySecret: identitySecretOf(idA), userMessageLimit: BigInt(K1), messageId: BigInt(K1), merkleProof: mp,
    x: calculateSignalHash(requestSignal(TARGET, "a-8")), epoch, rlnIdentifier: RLN_IDENTIFIER,
  }), /Assert Failed|RangeCheck/, "circom-rln RangeCheck: messageId < userMessageLimit is asserted in-circuit");
});
await test("ENFORCED: a tier-1 member's 9th distinct request in an epoch reuses a messageId => over-spend-slashed, and the slash names its TIER-8 leaf", async () => {
  const slashes = [];
  const spent = makeSpentSet({ derive: (s) => deriveSlashLeaf(s, { tiers: TIERS, leaves }), slash: async (c, s) => slashes.push({ c, s }) });
  const first = await verifyEnvelope(a7, roots, nowMs);
  assert.deepEqual(await spent.admit(first.nullifier, first.share, { nonce: a7.nonce, epoch: first.externalNullifier }), { ok: true, action: "first" });
  const again = await envelope(secretA, 7, "a-7-again", { limit: K1 }); // slot 7 again, distinct signal
  const v2 = await verifyEnvelope(again, roots, nowMs);
  assert.equal(v2.ok, true, v2.reason);
  assert.equal(v2.nullifier, first.nullifier, "same (member, epoch, messageId) => same nullifier");
  const res = await spent.admit(v2.nullifier, v2.share, { nonce: again.nonce, epoch: v2.externalNullifier });
  assert.equal(res.ok, false);
  assert.equal(res.reason, "over-spend-slashed");
  assert.equal(res.commitment, leafA, "the slashed leaf is A's tier-8 leaf");
  assert.equal(slashes.length, 1);
  assert.equal(slashes[0].s, identitySecretOf(idA).toString(), "reconstructed identitySecret == A's");
  assert.equal(deriveCommitment(slashes[0].s, K1), leafA);
});
await test("ENFORCED: the same over-spend by the tier-2 member resolves to its TIER-32 leaf (SHADE_TREE_TIERS knows both)", async () => {
  const slashes = [];
  const spent = makeSpentSet({ derive: (s) => deriveSlashLeaf(s, { tiers: TIERS, leaves }), slash: async (c) => slashes.push(c) });
  const v1 = await verifyEnvelope(b31, roots, nowMs);
  await spent.admit(v1.nullifier, v1.share, { nonce: b31.nonce, epoch: v1.externalNullifier });
  const again = await envelope(secretB, 31, "b-31-again", { limit: K2 });
  const v2 = await verifyEnvelope(again, roots, nowMs);
  const res = await spent.admit(v2.nullifier, v2.share, { nonce: again.nonce, epoch: v2.externalNullifier });
  assert.deepEqual([res.reason, res.commitment], ["over-spend-slashed", leafB]);
  assert.deepEqual(slashes, [leafB]);
  // Without leaves (on-chain root mode) the resolver falls back to the default tier's leaf — the
  // documented on-chain gap (docs/ONCHAIN.md "Tiers on chain"), never a crash.
  assert.equal(deriveSlashLeaf(identitySecretOf(idB).toString(), { tiers: TIERS, leaves: null }), deriveCommitment(identitySecretOf(idB), K1));
});

// ---- FORGED: a member cannot claim a tier it lacks -------------------------------------------------
await test("FORGED: tier-1 member proving with limit 32 against the real tree => no leaf to prove against (not in group)", async () => {
  await assert.rejects(() => proveForSlot(secretA, epoch, 20, requestSignal(TARGET, "forge"), { group, limit: K2 }), /rateCommitment \(limit 32\) not in group/);
});
await test("FORGED: a REAL proof over A's own tree with a tier-32 leaf for A => wrong-group-root (precise; the root is the trust anchor)", async () => {
  const forgedGroup = newGroup([rateCommitmentOf(filler), rateCommitmentOf(idA, K2), BigInt(leafB)]);
  assert.notEqual(forgedGroup.root.toString(), group.root.toString());
  const forged = await envelope(secretA, 20, "forge-32", { limit: K2, group: forgedGroup });
  // It IS a valid SNARK against the forged root (the forger can always make one)...
  const selfCheck = await verifyEnvelope(forged, new Set([forgedGroup.root.toString()]), nowMs);
  assert.equal(selfCheck.ok, true, "sanity: the forged proof verifies against its OWN root");
  // ...and the gateway rejects it by root, before any SNARK verification.
  const r = await verifyEnvelope(forged, roots, nowMs);
  assert.deepEqual([r.ok, r.reason], [false, "wrong-group-root"]);
});
await test("FORGED (control): a forged tree at A's TRUE limit is rejected the same way — the tier is bound through the root, not a side channel", async () => {
  const forgedGroup = newGroup([rateCommitmentOf(idA, K1)]);
  const forged = await envelope(secretA, 1, "forge-8", { limit: K1, group: forgedGroup });
  const r = await verifyEnvelope(forged, roots, nowMs);
  assert.deepEqual([r.ok, r.reason], [false, "wrong-group-root"]);
});
await test("FORGED: swapping the tier-2 member's public signals into a tier-1 envelope buys nothing (invalid-proof / signal-mismatch)", async () => {
  const spliced = { ...a7, proof: { ...a7.proof, snarkProof: { ...a7.proof.snarkProof, publicSignals: b31.proof.snarkProof.publicSignals } } };
  const r = await verifyEnvelope(spliced, roots, nowMs);
  assert.equal(r.ok, false);
  assert.ok(["invalid-proof", "signal-mismatch", "target-not-bound"].includes(r.reason), r.reason);
});

// ---- UNLINKABLE: the tier never shows on the wire or in the verdict ---------------------------------
await test("UNLINKABLE: envelopes from both tiers have identical key sets and public-signal names; no limit/tier field anywhere; verifyEnvelope returns no tier", async () => {
  assert.deepEqual(Object.keys(a7), Object.keys(b31));
  assert.deepEqual(Object.keys(a7.proof.snarkProof.publicSignals), Object.keys(b31.proof.snarkProof.publicSignals));
  assert.deepEqual(Object.keys(a7.proof.snarkProof.publicSignals).sort(), ["externalNullifier", "nullifier", "root", "x", "y"]);
  for (const e of [a7, b31]) assert.doesNotMatch(JSON.stringify(e), /"(limit|tier|userMessageLimit|messageId|slot)"/);
  const r = await verifyEnvelope(b31, roots, nowMs);
  assert.deepEqual(Object.keys(r).sort(), ["artifact", "externalNullifier", "nullifier", "ok", "reason", "share"]);
  assert.equal(String(a7.proof.snarkProof.publicSignals.root), String(b31.proof.snarkProof.publicSignals.root), "same root for both tiers (one tree)");
});

// ---- CLIENT: the pool/buildEnvelope path proves at the member's tier ------------------------------
await test("CLIENT: makeSlotPool at limit 32 => buildEnvelope proves slot 20 at K2 and the gateway accepts it", async () => {
  const pool = makeSlotPool({ secret: secretB, K: K2, loadGroupFn: async () => ({ group }), epochOf: () => epoch, prove: async () => {} });
  await pool.ensureGroup();
  for (let i = 0; i < 20; i++) pool.nextSlot(); // advance to slot 20 (>= K1)
  const { envelope: env, slot } = await buildEnvelope({ secret: secretB, target: TARGET, pool });
  assert.equal(slot, 20);
  const r = await verifyEnvelope(env, roots, nowMs);
  assert.equal(r.ok, true, r.reason);
});
await test("CLIENT: a tier-1 member mis-configured at limit 32 fails at prove time (not in group), never producing a rejectable envelope", async () => {
  const pool = makeSlotPool({ secret: secretA, K: K2, loadGroupFn: async () => ({ group }), epochOf: () => epoch, prove: async () => {} });
  await pool.ensureGroup();
  await assert.rejects(() => buildEnvelope({ secret: secretA, target: TARGET, pool }), /not in group/);
});

cleanUp();
console.log(failures ? `\nSELFTEST FAILED: ${failures} case(s)` : "\nSELFTEST PASSED: all cases green");
process.exit(failures ? 1 : 0);
