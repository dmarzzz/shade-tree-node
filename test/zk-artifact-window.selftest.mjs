// The dual-VK rollout WINDOW, end to end with REAL Groth16 proofs (T-HARD-8). Slow suite
// (real proving; in scripts/test-all.mjs SLOW_SUITES, skipped by SHADE_TREE_FAST=1). The fast half
// (ids, config, reasons, caps, client pick) is packages/node/lib/zk-artifacts.selftest.mjs.
//
// Two genuinely DIFFERENT artifact sets are needed to prove the acceptance criterion
// ("old-artifact and new-artifact proofs both accepted inside the window; outside it the old
// is rejected with a precise reason"). The repo ships ONE set (circuits/rln). This test mints
// a second one at run time exactly the way a ceremony would: a fresh phase-2 CONTRIBUTION on
// top of the shipped rln_final.zkey (snarkjs zKey.contribute, ~2s) + its exported vkey, into a
// temp dir. Same circuit/wasm, different proving+verification keys => a proof made with one
// set does NOT verify under the other. (snarkjs is rlnjs's own dependency — no new dep.)
//
//   OLD = the shipped set (built-in id)         NEW = the contributed set (temp dir)
//
// Proves, with real proofs from both sets:
//   window OPEN  (accepted {OLD,NEW}, legacy=OLD): OLD without field (un-upgraded client) ok,
//                OLD explicit ok, NEW explicit ok — each verified under ITS vkey
//   window CLOSED (accepted {NEW}, legacy=OLD):   OLD without field => artifact-retired:<OLD>
//                (precise, no misleading invalid-proof), OLD explicit => artifact-retired:<OLD>,
//                NEW ok
//   unknown id   => artifact-unknown:<id> (no SNARK run — a vkey we don't hold can't verify)
//   ADVERSARIAL: id spoofing — an OLD proof CLAIMING NEW (and vice versa) => invalid-proof
//                (verified under the claimed key; a mismatched claim buys nothing); a claimed
//                id the gateway doesn't hold => artifact-unknown
//   CLIENT: SHADE_TREE_ZK_PROVER_ARTIFACTS=<NEW>=..,<OLD>=.. => the prover proves with the requested
//           set and echoes its id; buildEnvelope stamps it; against a gateway ad of {OLD} the
//           client downgrades to OLD and that proof verifies; the heartbeat ad from the SAME env
//           the gateway loads names exactly the accepted ids
//   the same-set default (nothing configured) is byte-equivalent: proveForSlot/verifyEnvelope
//           round-trip with no artifact config at all
//
//   node test/zk-artifact-window.selftest.mjs

import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, copyFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as snarkjs from "snarkjs";
import {
  toField, identityFor, groupFromIdentities, requestSignal, proveForSlot, verifyEnvelope, currentEpoch, EPOCH_SECONDS,
  loadArtifactSet, loadProverSets, _setProverSets, _setArtifactSet, cleanUp,
} from "../packages/node/lib/rln.mjs";
import { artifactIdOfFile, builtinArtifactId, lockArtifactIds, RLN_DIR, BUILTIN_VKEY_PATH } from "../packages/node/lib/zk-artifacts.mjs";
import { buildGatewayCaps } from "../packages/node/bootnode/heartbeat.mjs";
import { canonicalCaps } from "../packages/node/lib/directory.mjs";
import { buildEnvelope, makeSlotPool } from "../packages/node/client/shade-tree-client.mjs";

let failures = 0;
function ok(name) { console.log("  PASS  " + name); }
function bad(name, e) { failures++; console.log("  FAIL  " + name + "  ::  " + (e && e.stack || e)); }
async function test(name, fn) { try { await fn(); ok(name); } catch (e) { bad(name, e); } }

console.log("dual-VK rollout window with real proofs (T-HARD-8):");

// ---- mint the NEW artifact set: one phase-2 contribution on the shipped zkey ---------------
const work = mkdtempSync(join(tmpdir(), "shade-tree-zk-window-"));
const NEW_DIR = join(work, "new");
const { mkdirSync } = await import("node:fs");
mkdirSync(NEW_DIR);
const t0 = Date.now();
await snarkjs.zKey.contribute(join(RLN_DIR, "rln_final.zkey"), join(NEW_DIR, "rln_final.zkey"), "t-hard-8 selftest", "fixed-entropy-for-the-selftest-not-a-ceremony");
writeFileSync(join(NEW_DIR, "verification_key.json"), JSON.stringify(await snarkjs.zKey.exportVerificationKey(join(NEW_DIR, "rln_final.zkey")), null, 1));
copyFileSync(join(RLN_DIR, "rln.wasm"), join(NEW_DIR, "rln.wasm"));
console.log(`  (minted a second artifact set via snarkjs zKey.contribute in ${Date.now() - t0}ms)`);

const OLD = builtinArtifactId();
const NEW = artifactIdOfFile(join(NEW_DIR, "verification_key.json"));
const UNKNOWN = "rln-ffffffffffffffff";
assert.notEqual(OLD, NEW);

// The gateway's two window configurations, from the SAME env shape an operator would set.
// Since the PSE adoption the lock records a retired previous set (the dev keys), so a field-less
// envelope maps to THAT id unless the window names its own old id: an operator opening a window
// on top of a rotated lock sets SHADE_TREE_ZK_ARTIFACT_LEGACY to the set being phased out.
const ENV_OPEN = { SHADE_TREE_ZK_ARTIFACTS: `${NEW}=${join(NEW_DIR, "verification_key.json")},${OLD}=${BUILTIN_VKEY_PATH}`, SHADE_TREE_ZK_ARTIFACT_LEGACY: OLD };
const ENV_CLOSED = { SHADE_TREE_ZK_ARTIFACTS: `${NEW}=${join(NEW_DIR, "verification_key.json")}`, SHADE_TREE_ZK_ARTIFACT_LEGACY: OLD };
const OPEN = loadArtifactSet({ env: ENV_OPEN });
const CLOSED = loadArtifactSet({ env: ENV_CLOSED });
assert.deepEqual([OPEN.legacyId, OPEN.legacyAccepted, CLOSED.legacyId, CLOSED.legacyAccepted], [OLD, true, OLD, false]);

// The client's two prover sets (newest first), installed process-wide for proveForSlot.
_setProverSets(loadProverSets({ env: { SHADE_TREE_ZK_PROVER_ARTIFACTS: `${NEW}=${NEW_DIR},${OLD}=${RLN_DIR}` } }));

// ---- a member + group ------------------------------------------------------------------------
const epoch = currentEpoch();
const nowMs = Number(epoch) * EPOCH_SECONDS * 1000 + 1000; // pinned inside `epoch` (no rollover flake)
const secret = toField("0x" + "b96d0584614e2d620d19601d278b93278bf0a2479d2bf0ab2d5ec3ae36960f53");
const group = groupFromIdentities([identityFor(toField("0x" + "11".repeat(32))), identityFor(toField("0x" + "22".repeat(32))), identityFor(secret)]);
const roots = new Set([group.root.toString()]);

// One real proof per set (same target/nonce/slot so only the artifact differs).
const TARGET = "example.com:443";
async function envelopeWith(artifactToProveWith, { nonce, slot = 1, claim = artifactToProveWith, omitField = false } = {}) {
  const p = await proveForSlot(secret, epoch, slot, requestSignal(TARGET, nonce), { group, artifact: artifactToProveWith });
  assert.equal(p.artifact, artifactToProveWith, "proveForSlot echoes the set it proved with");
  const env = { v: 4, target: TARGET, nonce, proof: p.proof, nullifier: p.nullifier, externalNullifier: p.externalNullifier, share: p.share };
  if (!omitField) env.artifact = claim;
  return env;
}
const oldNoField = await envelopeWith(OLD, { nonce: "old-legacy", omitField: true }); // an un-upgraded client
const oldExplicit = await envelopeWith(OLD, { nonce: "old-explicit" });
const newExplicit = await envelopeWith(NEW, { nonce: "new-explicit" });

// ---- inside the window -----------------------------------------------------------------------
await test("WINDOW OPEN: old-artifact proof WITHOUT the field (un-upgraded client) is accepted under the legacy (old) vkey", async () => {
  const r = await verifyEnvelope(oldNoField, roots, nowMs, { artifacts: OPEN });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.artifact, OLD);
});
await test("WINDOW OPEN: old-artifact proof with an explicit old id is accepted", async () => {
  const r = await verifyEnvelope(oldExplicit, roots, nowMs, { artifacts: OPEN });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.artifact, OLD);
});
await test("WINDOW OPEN: new-artifact proof with the new id is accepted (verified under the NEW vkey)", async () => {
  const r = await verifyEnvelope(newExplicit, roots, nowMs, { artifacts: OPEN });
  assert.equal(r.ok, true, r.reason);
  assert.equal(r.artifact, NEW);
  assert.equal(r.nullifier, newExplicit.nullifier);
});

// ---- outside the window ----------------------------------------------------------------------
await test("WINDOW CLOSED: old proof WITHOUT the field => artifact-retired:<old> (precise; NOT invalid-proof), reply carries accepted ids", async () => {
  const r = await verifyEnvelope(oldNoField, roots, nowMs, { artifacts: CLOSED });
  assert.equal(r.ok, false);
  assert.equal(r.reason, `artifact-retired:${OLD}`);
  assert.equal(r.label, "artifact-retired");
  assert.deepEqual(r.artifacts, [NEW]);
});
await test("WINDOW CLOSED: old proof with an explicit old id => artifact-retired:<old>", async () => {
  const r = await verifyEnvelope(oldExplicit, roots, nowMs, { artifacts: CLOSED });
  assert.equal(r.reason, `artifact-retired:${OLD}`);
});
await test("WINDOW CLOSED: new proof still accepted", async () => {
  const r = await verifyEnvelope(newExplicit, roots, nowMs, { artifacts: CLOSED });
  assert.equal(r.ok, true, r.reason);
});

// ---- unknown / adversarial -------------------------------------------------------------------
await test("unknown artifact id => artifact-unknown:<id> in either window (no vkey to verify under)", async () => {
  const env = { ...newExplicit, artifact: UNKNOWN };
  for (const set of [OPEN, CLOSED]) {
    const r = await verifyEnvelope(env, roots, nowMs, { artifacts: set });
    assert.equal(r.reason, `artifact-unknown:${UNKNOWN}`);
    assert.equal(r.label, "artifact-unknown");
  }
});
await test("ADVERSARIAL id spoofing: an OLD proof claiming NEW (and NEW claiming OLD) => invalid-proof (verified under the CLAIMED key)", async () => {
  const oldClaimsNew = { ...oldExplicit, artifact: NEW };
  const r1 = await verifyEnvelope(oldClaimsNew, roots, nowMs, { artifacts: OPEN });
  assert.deepEqual([r1.ok, r1.reason], [false, "invalid-proof"]);
  const newClaimsOld = { ...newExplicit, artifact: OLD };
  const r2 = await verifyEnvelope(newClaimsOld, roots, nowMs, { artifacts: OPEN });
  assert.deepEqual([r2.ok, r2.reason], [false, "invalid-proof"]);
  // and outside the window an OLD proof cannot sneak in by claiming NEW either
  const r3 = await verifyEnvelope(oldClaimsNew, roots, nowMs, { artifacts: CLOSED });
  assert.deepEqual([r3.ok, r3.reason], [false, "invalid-proof"]);
  // a NEW proof with the field STRIPPED (downgrade to legacy) is judged under the legacy key
  const newStripped = { ...newExplicit }; delete newStripped.artifact;
  assert.equal((await verifyEnvelope(newStripped, roots, nowMs, { artifacts: OPEN })).reason, "invalid-proof");
  assert.equal((await verifyEnvelope(newStripped, roots, nowMs, { artifacts: CLOSED })).reason, `artifact-retired:${OLD}`);
});
await test("ADVERSARIAL: a claimed id the gateway does not hold is rejected by NAME before any SNARK (id spoofing to an unheld vkey)", async () => {
  const single = loadArtifactSet({ env: { SHADE_TREE_ZK_ARTIFACTS: `${OLD}=${BUILTIN_VKEY_PATH}` } });
  const r = await verifyEnvelope({ ...newExplicit }, roots, nowMs, { artifacts: single });
  assert.equal(r.reason, `artifact-unknown:${NEW}`);
});

// ---- client side ----------------------------------------------------------------------------------
await test("CLIENT: buildEnvelope proves with the negotiated set and stamps its id; a gateway ad of {old} => the client downgrades and that proof verifies", async () => {
  const pool = makeSlotPool({ secret, loadGroupFn: async () => ({ group }), epochOf: () => epoch, prove: async () => { throw new Error("warm should not throw here"); } });
  await pool.ensureGroup();
  const { envelope: eNew } = await buildEnvelope({ secret, target: TARGET, pool, artifact: NEW });
  assert.equal(eNew.artifact, NEW);
  assert.deepEqual(Object.keys(eNew).slice(0, 4), ["v", "target", "nonce", "artifact"]);
  assert.equal((await verifyEnvelope(eNew, roots, nowMs, { artifacts: OPEN })).ok, true);
  assert.equal((await verifyEnvelope(eNew, roots, nowMs, { artifacts: CLOSED })).ok, true);
  const { envelope: eOld } = await buildEnvelope({ secret, target: TARGET, pool, artifact: OLD }); // what _pickArtifact yields for an ad of {OLD}
  assert.equal(eOld.artifact, OLD);
  assert.equal((await verifyEnvelope(eOld, roots, nowMs, { artifacts: OPEN })).ok, true);
  assert.equal((await verifyEnvelope(eOld, roots, nowMs, { artifacts: CLOSED })).reason, `artifact-retired:${OLD}`);
});
await test("HEARTBEAT: the signed ad built from the gateway's own env names exactly its accepted ids", () => {
  assert.deepEqual(canonicalCaps(buildGatewayCaps(ENV_OPEN)).artifacts, [NEW, OLD].sort());
  assert.deepEqual(canonicalCaps(buildGatewayCaps(ENV_CLOSED)).artifacts, [NEW]);
});

// ---- default (nothing configured) is byte-equivalent -----------------------------------------------
await test("DEFAULT: with no artifact config on either side, prove -> verify round-trips under the built-in id; a field-less envelope is the lock's retired previous set", async () => {
  _setProverSets(null); // back to env-default prover sets (built-in only)
  _setArtifactSet(null);
  const p = await proveForSlot(secret, epoch, 2, requestSignal(TARGET, "dflt"), { group });
  assert.equal(p.artifact, OLD);
  const env = { v: 4, target: TARGET, nonce: "dflt", proof: p.proof, nullifier: p.nullifier, externalNullifier: p.externalNullifier, share: p.share };
  // Since the PSE adoption the lock records previousArtifactId (the dev set), so with no window
  // configured a field-less envelope names THAT set and is retired: precise reason, no SNARK run.
  const previous = lockArtifactIds().previous;
  assert.match(previous, /^rln-[0-9a-f]{16}$/);
  const r = await verifyEnvelope(env, roots, nowMs);
  assert.equal(r.ok, false);
  assert.equal(r.reason, `artifact-retired:${previous}`);
  const r2 = await verifyEnvelope({ ...env, artifact: OLD }, roots, nowMs);
  assert.equal(r2.ok, true, r2.reason);
  assert.equal(r2.artifact, OLD);
});

cleanUp();
console.log(failures ? `\nSELFTEST FAILED: ${failures} case(s)` : "\nSELFTEST PASSED: all cases green");
process.exit(failures ? 1 : 0);
