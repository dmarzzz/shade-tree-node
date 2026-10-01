// Selftest for ZK artifact-version negotiation (T-HARD-8) — the FAST half (no Groth16
// proving; the real dual-VK window with two live artifact sets is test/zk-artifact-window.
// selftest.mjs). Drives packages/node/lib/zk-artifacts.mjs + the surfaces that consume it:
//
//   - artifact ids are content-derived (sha256 prefix of the vkey bytes) and the built-in id
//     equals the lock's circuits.rln.artifactId (lock <-> runtime agree with no registry)
//   - loadArtifactSet: default == the built-in set (byte-equivalent to the single-VK code);
//     SHADE_TREE_ZK_ARTIFACTS `<id>=<path>` parsing; FAIL-CLOSED on a mislabeled id / missing file /
//     non-vkey / duplicate / empty; SHADE_TREE_ZK_ARTIFACT_LEGACY; legacyAccepted flips with the window
//   - resolveArtifact: absent -> legacy; accepted / retired / unknown / garbage with the PRECISE
//     reason string + bounded label + the accepted-id list for the wire reply
//   - the REAL verifyEnvelope rejects a bad/unknown/retired artifact BEFORE any SNARK (a
//     cheaply-consistent envelope reaches step 3b and stops there with the artifact reason;
//     no proof material is needed to prove the ordering) — and an unset field maps to legacy
//   - the gateway handler replies `{ ok:false, err:"gate:<reason>", artifacts:[...] }` and
//     counts the drop under the BOUNDED label (never the id-bearing reason)
//   - caps: canonicalCaps carries `artifacts` (sorted, deduped, grammar-checked, bounded, LAST);
//     absent => byte-identical to before; hasCaps true on artifacts alone; the signed ad
//     round-trips (signCaps/verifyCapsSig) and a grafted id breaks it
//   - heartbeat buildGatewayCaps advertises the accepted ids ONLY when SHADE_TREE_ZK_ARTIFACTS is set
//   - selection: selectCandidates carries each gateway's advertised artifacts; the client picks
//     the newest mutual id (selectArtifact), fails closed on disjoint sets, is optimistic with
//     no ad; buildEnvelope stamps `artifact` after `nonce` (and omits it for artifact:null)
//   - the client's precise handling of an artifact-reject ack (records ack.artifacts)
//
//   node packages/node/lib/zk-artifacts.selftest.mjs

import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { existsSync, mkdtempSync, mkdirSync, writeFileSync, readFileSync, copyFileSync } from "node:fs";
import { Duplex } from "node:stream";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  artifactIdOf, artifactIdOfFile, builtinArtifactId, isArtifactId, parseArtifactSpec, loadArtifactSet,
  resolveArtifact, selectArtifact, loadProverSets, lockArtifactIds, BUILTIN_VKEY_PATH, RLN_DIR, LOCK_PATH,
} from "./zk-artifacts.mjs";
import { canonicalCaps, hasCaps, signCaps, verifyCapsSig, canonicalCapsBytes, MAX_CAPS_ARTIFACTS, pubkeyToOnion, ed25519PrivateKey } from "./directory.mjs";
import { buildGatewayCaps } from "../bootnode/heartbeat.mjs";
import {
  verifyEnvelope, currentEpoch, externalNullifierFor, calculateSignalHash, requestSignal, _setArtifactSet, getArtifactSet, cleanUp,
} from "./rln.mjs";
import { makeHandler, _setRecentRoots } from "../gateway/gateway.mjs";
import { registry as metrics } from "./metrics.mjs";
import { buildEnvelope, ShadeTreeClient } from "../client/shade-tree-client.mjs";
import { createPublicKey } from "node:crypto";

let failures = 0;
function ok(name) { console.log("  PASS  " + name); }
function bad(name, e) { failures++; console.log("  FAIL  " + name + "  ::  " + (e && e.message || e)); }
async function test(name, fn) { try { await fn(); ok(name); } catch (e) { bad(name, e); } }

const work = mkdtempSync(join(tmpdir(), "shade-tree-zk-artifacts-"));
const BUILTIN = builtinArtifactId();
const lock = JSON.parse(readFileSync(LOCK_PATH, "utf8"));

// A second, DIFFERENT vkey file: the built-in vkey with one whitespace byte appended. Same
// key material, different BYTES => a different content-derived id. (For a proof-level second
// set see test/zk-artifact-window.selftest.mjs; here only ids/config paths are exercised.)
const ALT_VKEY_PATH = join(work, "alt_verification_key.json");
writeFileSync(ALT_VKEY_PATH, readFileSync(BUILTIN_VKEY_PATH, "utf8") + "\n");
const ALT = artifactIdOfFile(ALT_VKEY_PATH);
const UNKNOWN = "rln-ffffffffffffffff";
const PREVIOUS = "rln-0b25f824a04da3a8"; // the dev set retired by the PSE adoption (lock circuits.rln.previousArtifactId)
const PREVIOUS_VKEY_PATH = join(dirname(LOCK_PATH), "..", "circuits/rln/previous/verification_key.json");

console.log("ZK artifact-version negotiation (T-HARD-8), fast half:");

// ---- ids ---------------------------------------------------------------------------------
await test("artifact id = <circuit>-<sha256(vkey bytes)[0:16]>; built-in id == lock circuits.rln.artifactId", () => {
  assert.equal(artifactIdOf("rln", "hello"), "rln-2cf24dba5fb0a30e");
  assert.match(BUILTIN, /^rln-[0-9a-f]{16}$/);
  assert.equal(BUILTIN, lock.circuits.rln.artifactId);
  assert.equal(BUILTIN, "rln-" + lock.artifacts["circuits/rln/verification_key.json"].sha256.slice(0, 16));
  assert.equal(lockArtifactIds().current, BUILTIN);
  assert.equal(lockArtifactIds().previous, PREVIOUS, "the PSE adoption (2026-09-30) rotated the set; the dev id is the recorded previous id");
  assert.equal(existsSync(PREVIOUS_VKEY_PATH), false, "circuits/rln/previous/ is gone: the dual-VK window closed with the production launch record (M8); the dev id survives only as the lock's previousArtifactId");
  assert.notEqual(ALT, BUILTIN, "one extra byte => a different id (content-derived)");
  assert.equal(isArtifactId(BUILTIN), true);
  for (const junk of ["", "Rln-x", "rln x", "a".repeat(65), 42, null, undefined, {}]) assert.equal(isArtifactId(junk), false, JSON.stringify(junk));
});

// ---- accepted set config -----------------------------------------------------------------
await test("default (SHADE_TREE_ZK_ARTIFACTS unset) == the built-in set under its own id; legacy = the rotated-out dev id, NOT accepted", () => {
  const set = loadArtifactSet({ env: {} });
  assert.deepEqual(set.ids, [BUILTIN]);
  assert.equal(set.legacyId, PREVIOUS, "a field-less envelope means the previous set once a ceremony has rotated the keys");
  assert.equal(set.legacyAccepted, false, "the default (no window) gateway retires the dev set");
  assert.equal(set.explicit, false);
  assert.ok(Array.isArray(set.accepted.get(BUILTIN).vkey.IC), "vkey parsed");
  const live = getArtifactSet(); // the process-wide default the gateway/verifyEnvelope use
  assert.deepEqual(live.ids, [BUILTIN]);
});

await test("parseArtifactSpec: `id=path` pairs, bare paths, whitespace; bad id / empty path throw", () => {
  assert.deepEqual(parseArtifactSpec(` ${BUILTIN}=a/b.json , c.json ,`), [{ id: BUILTIN, path: "a/b.json" }, { id: null, path: "c.json" }]);
  assert.deepEqual(parseArtifactSpec(""), []);
  assert.throws(() => parseArtifactSpec("Not An Id=x.json"), /bad artifact id/);
  assert.throws(() => parseArtifactSpec(`${BUILTIN}=`), /missing vkey path/);
});

await test("dual-VK window closed (M8): the retired dev vkey file is gone, so no explicit set can accept the lock's previous id; legacy = the lock's previous id, not accepted", () => {
  assert.equal(existsSync(PREVIOUS_VKEY_PATH), false, "circuits/rln/previous/ was removed with the production launch record");
  assert.throws(() => loadArtifactSet({ env: { SHADE_TREE_ZK_ARTIFACTS: `${BUILTIN}=${BUILTIN_VKEY_PATH},${PREVIOUS}=${PREVIOUS_VKEY_PATH}` } }), /vkey not found/, "a record that still named the dev vkey fails closed at load");
  const synthetic = loadArtifactSet({ env: { SHADE_TREE_ZK_ARTIFACTS: `${ALT}=${ALT_VKEY_PATH},${BUILTIN}=${BUILTIN_VKEY_PATH}` } });
  assert.deepEqual(synthetic.ids, [ALT, BUILTIN].sort());
  assert.equal(synthetic.legacyId, PREVIOUS, "the legacy id comes from the lock, not from the window's membership");
  assert.equal(synthetic.legacyAccepted, false);
  // bare path => id derived
  const set2 = loadArtifactSet({ env: { SHADE_TREE_ZK_ARTIFACTS: ALT_VKEY_PATH } });
  assert.deepEqual(set2.ids, [ALT]);
});

await test("window closed: only the new id accepted; SHADE_TREE_ZK_ARTIFACT_LEGACY names the retired id", () => {
  const set = loadArtifactSet({ env: { SHADE_TREE_ZK_ARTIFACTS: `${ALT}=${ALT_VKEY_PATH}`, SHADE_TREE_ZK_ARTIFACT_LEGACY: BUILTIN } });
  assert.deepEqual(set.ids, [ALT]);
  assert.equal(set.legacyId, BUILTIN);
  assert.equal(set.legacyAccepted, false, "outside the window the legacy id is RETIRED");
  assert.throws(() => loadArtifactSet({ env: { SHADE_TREE_ZK_ARTIFACT_LEGACY: "Bad Id" } }), /SHADE_TREE_ZK_ARTIFACT_LEGACY: bad artifact id/);
});

await test("FAIL CLOSED at load: mislabeled id, missing file, non-vkey JSON, duplicate id, empty spec", () => {
  assert.throws(() => loadArtifactSet({ env: { SHADE_TREE_ZK_ARTIFACTS: `${UNKNOWN}=${BUILTIN_VKEY_PATH}` } }), /artifact id mismatch .* declared rln-ffffffffffffffff but the file's content id is rln-/);
  assert.throws(() => loadArtifactSet({ env: { SHADE_TREE_ZK_ARTIFACTS: `${BUILTIN}=${join(work, "nope.json")}` } }), /vkey not found/);
  const notVk = join(work, "not-a-vkey.json");
  writeFileSync(notVk, JSON.stringify({ hello: 1 }));
  assert.throws(() => loadArtifactSet({ env: { SHADE_TREE_ZK_ARTIFACTS: notVk } }), /does not look like a snarkjs verification key/);
  writeFileSync(notVk, "{not json");
  assert.throws(() => loadArtifactSet({ env: { SHADE_TREE_ZK_ARTIFACTS: notVk } }), /not a JSON verification key/);
  assert.throws(() => loadArtifactSet({ env: { SHADE_TREE_ZK_ARTIFACTS: `${BUILTIN_VKEY_PATH},${BUILTIN_VKEY_PATH}` } }), /duplicate artifact id/);
  assert.throws(() => loadArtifactSet({ env: { SHADE_TREE_ZK_ARTIFACTS: " , " } }), /names no artifact/);
});

// ---- resolveArtifact ---------------------------------------------------------------------
// Synthetic window "new = ALT, old = BUILTIN": name the old id explicitly, because since the PSE
// adoption the lock's previous id (the real retired dev set) is what a field-less envelope means.
const OPEN = loadArtifactSet({ env: { SHADE_TREE_ZK_ARTIFACTS: `${ALT}=${ALT_VKEY_PATH},${BUILTIN}=${BUILTIN_VKEY_PATH}`, SHADE_TREE_ZK_ARTIFACT_LEGACY: BUILTIN } });   // window open, legacy=BUILTIN
const CLOSED = loadArtifactSet({ env: { SHADE_TREE_ZK_ARTIFACTS: `${ALT}=${ALT_VKEY_PATH}`, SHADE_TREE_ZK_ARTIFACT_LEGACY: BUILTIN } }); // window closed

await test("resolveArtifact inside the window: absent -> legacy(old) ok; explicit old ok; explicit new ok", () => {
  assert.equal(resolveArtifact(undefined, OPEN).id, BUILTIN);
  assert.equal(resolveArtifact(null, OPEN).id, BUILTIN);
  assert.equal(resolveArtifact(BUILTIN, OPEN).id, BUILTIN);
  assert.equal(resolveArtifact(ALT, OPEN).id, ALT);
  assert.ok(Array.isArray(resolveArtifact(ALT, OPEN).vkey.IC));
});

await test("resolveArtifact outside the window: absent/explicit old -> artifact-retired:<old> (precise); new ok", () => {
  for (const f of [undefined, BUILTIN]) {
    const r = resolveArtifact(f, CLOSED);
    assert.equal(r.ok, false);
    assert.equal(r.reason, `artifact-retired:${BUILTIN}`);
    assert.equal(r.label, "artifact-retired");
    assert.deepEqual(r.artifacts, [ALT], "the reject carries the accepted ids");
  }
  assert.equal(resolveArtifact(ALT, CLOSED).id, ALT);
});

await test("resolveArtifact: unknown id -> artifact-unknown:<id>; garbage -> bad-artifact:<repr> (bounded repr)", () => {
  const u = resolveArtifact(UNKNOWN, OPEN);
  assert.deepEqual([u.ok, u.reason, u.label], [false, `artifact-unknown:${UNKNOWN}`, "artifact-unknown"]);
  const g = resolveArtifact("Not An Id", OPEN);
  assert.deepEqual([g.ok, g.reason, g.label], [false, 'bad-artifact:"Not An Id"', "bad-artifact"]);
  assert.equal(resolveArtifact("x".repeat(500), OPEN).reason, `bad-artifact:"${"x".repeat(16)}"`, "repr is bounded");
  assert.equal(resolveArtifact(42, OPEN).reason, "bad-artifact:42");
  assert.equal(resolveArtifact({ a: 1 }, OPEN).reason, "bad-artifact:object");
  assert.equal(resolveArtifact([BUILTIN], OPEN).label, "bad-artifact", "an array is not an id");
});

// ---- verifyEnvelope step 3b (real function, no proof needed to reach it) -------------------
// An envelope that passes checks 1-3 (fresh externalNullifier, share.x == ps.x, target bound,
// root accepted) but names a bad artifact must stop at 3b with the artifact reason — proving
// the artifact gate runs BEFORE the SNARK (step 4 would need real proof bytes to even run).
const epoch = currentEpoch();
const nowMs = Number(epoch) * 120 * 1000 + 1000; // inside `epoch` regardless of SHADE_TREE_EPOCH_SECONDS default (120)
function consistentEnvelope(artifactField) {
  const target = "example.com:443", nonce = "abc123";
  const x = String(calculateSignalHash(requestSignal(target, nonce)));
  const ps = { x, y: "7", root: "999", nullifier: "5", externalNullifier: externalNullifierFor(epoch).toString() };
  const env = { v: 4, target, nonce, proof: { snarkProof: { proof: {}, publicSignals: ps }, epoch: String(epoch), rlnIdentifier: "1" }, nullifier: "5", externalNullifier: ps.externalNullifier, share: { x, y: "7" } };
  if (artifactField !== undefined) env.artifact = artifactField;
  return env;
}
await test("verifyEnvelope stops at 3b: unknown / retired / garbage artifact => precise reason + label + accepted list, before any SNARK", async () => {
  const roots = new Set(["999"]);
  const u = await verifyEnvelope(consistentEnvelope(UNKNOWN), roots, nowMs, { artifacts: OPEN });
  assert.deepEqual([u.ok, u.reason, u.label, u.artifacts], [false, `artifact-unknown:${UNKNOWN}`, "artifact-unknown", OPEN.ids]);
  const r = await verifyEnvelope(consistentEnvelope(BUILTIN), roots, nowMs, { artifacts: CLOSED });
  assert.deepEqual([r.ok, r.reason, r.label], [false, `artifact-retired:${BUILTIN}`, "artifact-retired"]);
  const legacy = await verifyEnvelope(consistentEnvelope(undefined), roots, nowMs, { artifacts: CLOSED });
  assert.equal(legacy.reason, `artifact-retired:${BUILTIN}`, "field-less (old client) envelope outside the window: precise retired reason");
  const g = await verifyEnvelope(consistentEnvelope("Not An Id"), roots, nowMs, { artifacts: OPEN });
  assert.equal(g.label, "bad-artifact");
  // ordering: cheaper checks still come first (a bad root wins over a bad artifact)
  const rootFirst = await verifyEnvelope(consistentEnvelope(UNKNOWN), new Set(["1"]), nowMs, { artifacts: OPEN });
  assert.equal(rootFirst.reason, "wrong-group-root");
  const bindFirst = await verifyEnvelope({ ...consistentEnvelope(UNKNOWN), nonce: "other" }, roots, nowMs, { artifacts: OPEN });
  assert.equal(bindFirst.reason, "target-not-bound");
});

await test("verifyEnvelope with an ACCEPTED artifact proceeds to the SNARK (which then judges the proof bytes)", async () => {
  // The envelope above has no real proof, so under an accepted id it must get PAST 3b and be
  // judged by step 4 (invalid-proof / verify-threw) — never an artifact reason.
  const r = await verifyEnvelope(consistentEnvelope(ALT), new Set(["999"]), nowMs, { artifacts: OPEN });
  assert.equal(r.ok, false);
  assert.ok(!/artifact/.test(r.reason), "reason is a step-4 reason, got " + r.reason);
  const legacyOpen = await verifyEnvelope(consistentEnvelope(undefined), new Set(["999"]), nowMs, { artifacts: OPEN });
  assert.ok(!/artifact/.test(legacyOpen.reason), "field-less inside the window reaches step 4, got " + legacyOpen.reason);
});

// ---- gateway handler reply + metrics label ------------------------------------------------
class FakeSocket extends EventEmitter {
  constructor() { super(); this.written = []; this.destroyed = false; }
  setNoDelay() {}
  write(s) { this.written.push(String(s)); }
  destroy() { this.destroyed = true; this.emit("close"); }
  pipe() {}
}
function metricValue(name, labels) {
  const m = metrics.render().split("\n").find((l) => l.startsWith(name + "{") && Object.entries(labels).every(([k, v]) => l.includes(`${k}="${v}"`)));
  return m ? Number(m.split(" ").pop()) : 0;
}
await test("gateway handler: artifact reject replies {ok:false, err:'gate:<reason>', artifacts:[accepted]} and counts the BOUNDED label", async () => {
  _setArtifactSet(CLOSED);       // process-wide set the handler's verifyEnvelope reads (window closed)
  _setRecentRoots(["999"]);      // so the consistent envelope gets PAST the root check to 3b
  try {
    const spent = { admit: async () => ({ ok: true, action: "first" }) };
    const handle = makeHandler(spent);
    const drive = async (envelope) => {
      const sock = new FakeSocket();
      const p = handle(sock);
      sock.emit("data", Buffer.from(JSON.stringify(envelope) + "\n"));
      await p;
      return { ack: JSON.parse(sock.written[0]), sock };
    };
    const before = metricValue("shade_tree_gateway_tunnels_total", { result: "drop", reason: "artifact-retired" });
    // field-less (old client) envelope outside the window
    const legacy = await drive(consistentEnvelope(undefined));
    assert.deepEqual(legacy.ack, { ok: false, err: `gate:artifact-retired:${BUILTIN}`, artifacts: [ALT] });
    assert.equal(legacy.sock.destroyed, true);
    // explicit unknown id
    const unk = await drive(consistentEnvelope(UNKNOWN));
    assert.deepEqual(unk.ack, { ok: false, err: `gate:artifact-unknown:${UNKNOWN}`, artifacts: [ALT] });
    // garbage
    const bad = await drive(consistentEnvelope("Not An Id"));
    assert.equal(bad.ack.err, 'gate:bad-artifact:"Not An Id"');
    assert.deepEqual(bad.ack.artifacts, [ALT]);
    // metrics: bounded label, never the id-bearing reason
    assert.equal(metricValue("shade_tree_gateway_tunnels_total", { result: "drop", reason: "artifact-retired" }), before + 1);
    assert.equal(metricValue("shade_tree_gateway_tunnels_total", { result: "drop", reason: "artifact-unknown" }) >= 1, true);
    assert.equal(metricValue("shade_tree_gateway_tunnels_total", { result: "drop", reason: "bad-artifact" }) >= 1, true);
    assert.ok(!metrics.render().includes(`reason="artifact-retired:${BUILTIN}"`), "no id-bearing label leaked into metrics");
    // a non-artifact reject carries NO artifacts field (reply shape unchanged for every other reason)
    const root = await drive({ ...consistentEnvelope(ALT), proof: { ...consistentEnvelope(ALT).proof, snarkProof: { proof: {}, publicSignals: { ...consistentEnvelope(ALT).proof.snarkProof.publicSignals, root: "1" } } } });
    assert.deepEqual(root.ack, { ok: false, err: "gate:wrong-group-root" });
  } finally {
    _setArtifactSet(null);
    _setRecentRoots([]);
  }
});

// ---- caps ---------------------------------------------------------------------------------
await test("canonicalCaps.artifacts: sorted, deduped, grammar-checked, count-bounded, appended LAST; absent => byte-identical", () => {
  const base = { ports: [443], proto: { min: 3, max: 3 } };
  assert.equal(JSON.stringify(canonicalCaps(base)), '{"ports":[443],"proto":{"min":3,"max":3}}');
  const withA = canonicalCaps({ ...base, artifacts: [ALT, BUILTIN, ALT, "Not An Id", 7] });
  assert.deepEqual(Object.keys(withA), ["ports", "proto", "artifacts"]);
  assert.deepEqual(withA.artifacts, [ALT, BUILTIN].sort());
  assert.equal(canonicalCaps({ artifacts: ["Not An Id"] }).artifacts, undefined);
  assert.equal(canonicalCaps({ artifacts: "rln-x" }).artifacts, undefined);
  const tooMany = Array.from({ length: MAX_CAPS_ARTIFACTS + 1 }, (_, i) => `rln-${String(i).padStart(16, "0")}`);
  assert.equal(canonicalCaps({ artifacts: tooMany }).artifacts, undefined, "over the bound => dropped entirely");
  assert.equal(hasCaps({ artifacts: [BUILTIN] }), true, "artifacts alone make caps non-empty");
  assert.equal(hasCaps({ artifacts: ["Not An Id"] }), false);
});

await test("signed artifact ad round-trips; grafting an id breaks capsSig (unforgeable by bootnode/relay)", () => {
  const seed = "11".repeat(32);
  const der = createPublicKey(ed25519PrivateKey(seed)).export({ format: "der", type: "spki" });
  const onion = pubkeyToOnion(Buffer.from(der.subarray(der.length - 32)).toString("hex"));
  const caps = { ports: [443], artifacts: [BUILTIN] };
  const sig = signCaps(onion, caps, seed);
  assert.equal(verifyCapsSig(onion, caps, sig), true);
  assert.equal(verifyCapsSig(onion, { ...caps, artifacts: [BUILTIN, ALT] }, sig), false, "grafted id => bad sig");
  assert.equal(verifyCapsSig(onion, { ports: [443] }, sig), false, "stripped ad => bad sig");
  assert.ok(canonicalCapsBytes(onion, caps).toString("utf8").endsWith(`"artifacts":["${BUILTIN}"]}}`));
});

await test("heartbeat buildGatewayCaps: advertises accepted ids only when SHADE_TREE_ZK_ARTIFACTS is set (default stays cap-free)", () => {
  assert.equal(buildGatewayCaps({}), null, "unconfigured => no caps (byte-identical announce)");
  const c = buildGatewayCaps({ SHADE_TREE_ZK_ARTIFACTS: `${ALT}=${ALT_VKEY_PATH},${BUILTIN}=${BUILTIN_VKEY_PATH}` });
  assert.deepEqual(c.artifacts, [ALT, BUILTIN].sort());
  assert.deepEqual(c.proto, { min: 4, max: 4 }, "proto rides along with a real cap");
  assert.equal(c.ports, undefined);
  assert.throws(() => buildGatewayCaps({ SHADE_TREE_ZK_ARTIFACTS: `${UNKNOWN}=${BUILTIN_VKEY_PATH}` }), /artifact id mismatch/, "a mis-pointed set aborts the heartbeat too (never advertise what we can't verify)");
  assert.deepEqual(buildGatewayCaps({}, { artifactIds: [BUILTIN] }).artifacts, [BUILTIN], "injection seam");
});

// ---- client pick + envelope ---------------------------------------------------------------
await test("selectArtifact: newest mutual; optimistic with no ad; disjoint fails closed with a precise reason", () => {
  const mine = [ALT, BUILTIN]; // newest first
  assert.equal(selectArtifact([BUILTIN, ALT], mine).id, ALT);
  assert.equal(selectArtifact([BUILTIN], mine).id, BUILTIN, "gateway still on the old set => the client downgrades to it");
  assert.equal(selectArtifact(null, mine).id, ALT);
  assert.equal(selectArtifact([], mine).id, ALT);
  const d = selectArtifact([UNKNOWN], mine);
  assert.equal(d.ok, false);
  assert.equal(d.reason, `no-mutual-artifact:client=${ALT}|${BUILTIN},gateway=${UNKNOWN}`);
  assert.equal(selectArtifact([BUILTIN], []).reason, "no-client-artifact");
  assert.equal(selectArtifact([BUILTIN], ["Not An Id"]).reason, "no-client-artifact");
});

await test("loadProverSets: default == the shipped set under the built-in id; SHADE_TREE_ZK_PROVER_ARTIFACTS is ordered newest-first + fail-closed", () => {
  const dflt = loadProverSets({ env: {} });
  assert.equal(dflt.length, 1);
  assert.equal(dflt[0].id, BUILTIN);
  assert.equal(dflt[0].wasm, join(RLN_DIR, "rln.wasm"));
  // a second "set" dir: same wasm/zkey, alt vkey bytes (id differs) — config-level only
  const altDir = join(work, "altset");
  mkdirSync(altDir, { recursive: true });
  copyFileSync(ALT_VKEY_PATH, join(altDir, "verification_key.json"));
  writeFileSync(join(altDir, "rln.wasm"), "");
  writeFileSync(join(altDir, "rln_final.zkey"), "");
  const sets = loadProverSets({ env: { SHADE_TREE_ZK_PROVER_ARTIFACTS: `${ALT}=${altDir},${BUILTIN}=${RLN_DIR}` } });
  assert.deepEqual(sets.map((s) => s.id), [ALT, BUILTIN], "order preserved (newest first)");
  assert.throws(() => loadProverSets({ env: { SHADE_TREE_ZK_PROVER_ARTIFACTS: `${UNKNOWN}=${altDir}` } }), /artifact id mismatch/);
  assert.throws(() => loadProverSets({ env: { SHADE_TREE_ZK_PROVER_ARTIFACTS: join(work, "missing") } }), /missing/);
});

const fakePool = { nextSlot: () => ({ epoch: 1n, slot: 0 }), ensureGroup: async () => ({}) };
const fakeProve = async (secret, epoch, i, signal, opts) => ({
  proof: { epoch: String(epoch), rlnIdentifier: "1", snarkProof: { publicSignals: { x: "1", y: "2", externalNullifier: "3", root: "4", nullifier: "5" }, proof: { pi_a: ["a"], pi_b: [["b"]], pi_c: ["c"] } } },
  nullifier: "5", externalNullifier: "3", share: { x: "1", y: "2" }, artifact: opts.artifact ?? BUILTIN,
});
await test("buildEnvelope stamps `artifact` right after `nonce` (the prover's echoed id); artifact:null omits it (pre-T-HARD-8 wire)", async () => {
  const { envelope, artifact } = await buildEnvelope({ secret: "s", target: "h:443", pool: fakePool, prove: fakeProve, artifact: ALT });
  assert.deepEqual(Object.keys(envelope), ["v", "target", "nonce", "artifact", "proof", "nullifier", "externalNullifier", "share"]);
  assert.equal(envelope.artifact, ALT);
  assert.equal(artifact, ALT);
  const dflt = await buildEnvelope({ secret: "s", target: "h:443", pool: fakePool, prove: fakeProve });
  assert.equal(dflt.envelope.artifact, BUILTIN, "default = the prover's own (built-in) id");
  const none = await buildEnvelope({ secret: "s", target: "h:443", pool: fakePool, prove: fakeProve, artifact: null });
  assert.equal("artifact" in none.envelope, false);
  assert.deepEqual(Object.keys(none.envelope), ["v", "target", "nonce", "proof", "nullifier", "externalNullifier", "share"]);
});

await test("ShadeTreeClient._planEnvelope: keeps artifact knowledge onion-local and chooses one profile for failover", () => {
  const c = new ShadeTreeClient({ secret: "0x01", onion: "a".repeat(56), artifacts: [ALT, BUILTIN] });
  const unknownFirst = c._planEnvelope([{ onion: "x", artifacts: null }, { onion: "y", artifacts: [BUILTIN] }]);
  assert.equal(unknownFirst.pa.id, ALT, "an unknown first candidate is tried with our newest set");
  assert.deepEqual(unknownFirst.cands.map(({ onion }) => onion), ["x"], "a later known-incompatible node is not sent that envelope");
  const knownFallback = c._planEnvelope([{ onion: "x", artifacts: [UNKNOWN] }, { onion: "y", artifacts: [BUILTIN] }]);
  assert.equal(knownFallback.pa.id, BUILTIN, "a known-incompatible first node does not poison the next candidate");
  assert.deepEqual(knownFallback.cands.map(({ onion }) => onion), ["y"]);
  assert.equal(c._planEnvelope([{ onion: "x", artifacts: null }]).pa.id, ALT);
  const d = c._planEnvelope([{ onion: "x", artifacts: [UNKNOWN] }]);
  assert.equal(d.ok, false);
  assert.match(d.reason, /^no-mutual-artifact:/);
  // A singular out-of-band gateway list remains compatible with the pinned-node API.
  c.gatewayArtifacts = [BUILTIN];
  assert.equal(c._planEnvelope([{ onion: "x", artifacts: null }]).pa.id, BUILTIN);
  // default artifacts = the configured prover ids (built-in)
  const c2 = new ShadeTreeClient({ secret: "0x01", onion: "a".repeat(56) });
  assert.equal(c2._planEnvelope([{ onion: "x", artifacts: null }]).pa.id, BUILTIN);
  assert.equal(c2._planEnvelope([{ onion: "x", artifacts: [UNKNOWN] }]).ok, false, "gateway on a set we don't have => fail closed before proving");
});

// A fake SOCKS "gateway": records the wire the client sends and replies with a canned ack.
function fakeGateway(ackObj) {
  const state = { wire: "" };
  const createConnection = async () => {
    const sock = new Duplex({ read() {}, write(chunk, enc, cb) { state.wire += chunk.toString(); setImmediate(() => sock.push(JSON.stringify(ackObj) + "\n")); cb(); } });
    sock.setNoDelay = () => {};
    return { socket: sock };
  };
  return { socksClient: { createConnection }, state };
}
await test("ShadeTreeClient.connect: sends the negotiated `artifact`; an artifact-reject ack is surfaced precisely and its accepted list remembered", async () => {
  // accept
  const g1 = fakeGateway({ ok: true });
  const c1 = new ShadeTreeClient({ secret: "0x01", onion: "a".repeat(56), artifacts: [ALT, BUILTIN], socksClient: g1.socksClient, dialAttempts: 1, prove: fakeProve, socksIsolation: false });
  c1.pool = fakePool;
  const tunnel = await c1.connect("h:443");
  assert.equal(tunnel.shadeTree.artifact, ALT, "no ad => our newest");
  const sent = JSON.parse(g1.state.wire.split("\n")[0]);
  assert.equal(sent.artifact, ALT);
  assert.deepEqual(Object.keys(sent).slice(0, 4), ["v", "target", "nonce", "artifact"]);
  // pinned gateway with a known ad => the client downgrades to the mutual id
  const g2 = fakeGateway({ ok: true });
  const c2 = new ShadeTreeClient({ secret: "0x01", onion: "a".repeat(56), artifacts: [ALT, BUILTIN], gatewayArtifacts: [BUILTIN], socksClient: g2.socksClient, dialAttempts: 1, prove: fakeProve, socksIsolation: false });
  c2.pool = fakePool;
  assert.equal((await c2.connect("h:443")).shadeTree.artifact, BUILTIN);
  // reject: gateway holds only BUILTIN, we sent ALT (no ad was known)
  const g3 = fakeGateway({ ok: false, err: `gate:artifact-unknown:${ALT}`, artifacts: [BUILTIN] });
  const c3 = new ShadeTreeClient({ secret: "0x01", onion: "a".repeat(56), artifacts: [ALT, BUILTIN], socksClient: g3.socksClient, dialAttempts: 1, prove: fakeProve, socksIsolation: false });
  c3.pool = fakePool;
  await assert.rejects(() => c3.connect("h:443"), new RegExp(`gate refused: gate:artifact-unknown:${ALT} \\(gateway accepts artifacts ${BUILTIN}; retry with ${BUILTIN}\\)`));
  assert.deepEqual(c3.gatewayArtifacts, [BUILTIN], "learned for the next attempt");
  assert.equal((await c3.connect("h:443").catch((e) => e)).message.includes("gate refused"), true); // still rejected by this canned gateway, but now sent BUILTIN:
  assert.equal(JSON.parse(g3.state.wire.split("\n").filter(Boolean).pop()).artifact, BUILTIN, "second attempt used the learned mutual id");
  // reject with NO mutual set => the reason says so
  const g4 = fakeGateway({ ok: false, err: `gate:artifact-retired:${BUILTIN}`, artifacts: [UNKNOWN] });
  const c4 = new ShadeTreeClient({ secret: "0x01", onion: "a".repeat(56), artifacts: [BUILTIN], socksClient: g4.socksClient, dialAttempts: 1, prove: fakeProve, socksIsolation: false });
  c4.pool = fakePool;
  await assert.rejects(() => c4.connect("h:443"), /no-mutual-artifact:client=rln-[0-9a-f]{16},gateway=rln-ffffffffffffffff/);
  // and once a disjoint ad is known, the NEXT connect fails closed BEFORE proving/dialing
  await assert.rejects(() => c4.connect("h:443"), /^Error: artifact negotiation failed: no-mutual-artifact:/);
});

cleanUp();
console.log(failures ? `\nSELFTEST FAILED: ${failures} case(s)` : "\nSELFTEST PASSED: all cases green");
process.exit(failures ? 1 : 0);
