// ZK artifact-version negotiation (T-HARD-8): ids, the gateway's accepted-artifact set, and
// the client's pick — so the post-ceremony artifact swap (docs/CEREMONY.md §6) is a DUAL-VK
// ROLLOUT WINDOW instead of a flag day.
//
// The problem: a proving key (client) and a verification key (gateway) must come from the same
// zkey. Before this module `lib/rln.mjs` held exactly ONE vkey and the envelope said nothing
// about which artifact set produced its proof, so swapping the set meant every un-upgraded
// client was rejected `invalid-proof` the instant a gateway upgraded (or vice versa).
//
// The mechanism (three small pieces, all deterministic, JS<->Rust byte-compatible):
//
//   1. ARTIFACT ID = `<circuit>-<sha256(verification_key.json bytes)[0:16]>` (artifactIdOf).
//      Content-derived from the SAME bytes testdata/zk-artifacts.lock.json pins, so the lock,
//      the gateway, the JS client and the Rust client (which hashes its embedded bytes at
//      startup) all agree on the name of an artifact set with no registry and no way to lie
//      about it: an operator who points an id at the wrong vkey fails closed at startup.
//   2. GATEWAY ACCEPTED SET  {artifactId -> vkey}  (loadArtifactSet):
//        SHADE_TREE_ZK_ARTIFACTS=<id>=<vkey path>[,<id>=<vkey path>...]   (unset => the built-in
//        circuits/rln/verification_key.json under its own derived id — byte-equivalent to today)
//        SHADE_TREE_ZK_ARTIFACT_LEGACY=<id>   which id an envelope WITHOUT an `artifact` field means
//        (unset => the lock's `circuits.rln.previousArtifactId` if any, else the built-in id).
//      The window: accept {new, old}, legacy=old. Close it: accept {new}; the old id becomes
//      RETIRED and both old-style (no field) and explicit-old envelopes are rejected with the
//      precise reason `artifact-retired:<id>` (never a confusing `invalid-proof`).
//   3. CLIENT PICK (selectArtifact): the gateway advertises its accepted ids in its signed
//      capability ad (`caps.artifacts`, lib/directory.mjs canonicalCaps); the client intersects
//      that with its OWN prover sets (SHADE_TREE_ZK_PROVER_ARTIFACTS, newest first) and sends the
//      newest mutual id in the envelope's `artifact` field. No ad => it optimistically sends
//      its newest; the gateway's precise reject then carries the accepted list.
//
// This file is deliberately LIGHT (fs + crypto only, no rlnjs/snarkjs) so bootnode/heartbeat.mjs
// and the client can compute ids/sets without loading circuits; lib/rln.mjs imports from here.

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, isAbsolute, join, resolve } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
export const RLN_DIR = join(ROOT, "circuits", "rln");
export const BUILTIN_VKEY_PATH = join(RLN_DIR, "verification_key.json");
export const BUILTIN_WASM_PATH = join(RLN_DIR, "rln.wasm");
export const BUILTIN_ZKEY_PATH = join(RLN_DIR, "rln_final.zkey");
export const LOCK_PATH = join(ROOT, "testdata", "zk-artifacts.lock.json");

// ---- artifact ids ------------------------------------------------------------

// Grammar for an artifact id on the wire / in caps: lowercase, short, no whitespace. TOTAL
// checks elsewhere (canonicalCaps, verifyEnvelope) drop/reject anything outside this.
export const ARTIFACT_ID_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
export const ARTIFACT_ID_HASH_CHARS = 16;

export function isArtifactId(s) {
  return typeof s === "string" && ARTIFACT_ID_RE.test(s);
}

// artifactIdOf(circuit, vkeyBytes) -> `<circuit>-<sha256(bytes) hex[0:16]>`. `bytes` are the
// verification_key.json FILE bytes exactly as hashed by testdata/zk-artifacts.lock.json, so
// `"rln-" + lock.artifacts["circuits/rln/verification_key.json"].sha256.slice(0,16)` is the id.
// (Rust: shadenet_proto::artifact_id_of; pinned in testdata/vectors.json `artifacts`.)
export function artifactIdOf(circuit, vkeyBytes) {
  const buf = Buffer.isBuffer(vkeyBytes) ? vkeyBytes : Buffer.from(String(vkeyBytes), "utf8");
  return `${circuit}-${createHash("sha256").update(buf).digest("hex").slice(0, ARTIFACT_ID_HASH_CHARS)}`;
}

export function artifactIdOfFile(path, circuit = "rln") {
  return artifactIdOf(circuit, readFileSync(path));
}

// The built-in RLN artifact id (circuits/rln/verification_key.json as shipped). Computed lazily
// and cached: it is what a default gateway accepts and what a default client sends.
let _builtinId = null;
export function builtinArtifactId() {
  return (_builtinId ||= artifactIdOfFile(BUILTIN_VKEY_PATH));
}

// Best-effort read of the lock's artifact ids ({ current, previous } or null). The lock is a
// test/provenance file first; at runtime it only supplies the DEFAULT legacy id (the previous
// set's id after a ceremony regenerates the lock), so a missing/unreadable lock is not fatal.
export function lockArtifactIds(path = LOCK_PATH) {
  try {
    const lock = JSON.parse(readFileSync(path, "utf8"));
    const c = lock?.circuits?.rln || {};
    return {
      current: isArtifactId(c.artifactId) ? c.artifactId : null,
      previous: isArtifactId(c.previousArtifactId) ? c.previousArtifactId : null,
    };
  } catch {
    return null;
  }
}

// ---- gateway accepted set ------------------------------------------------------

// Parse `<id>=<path>[,<id>=<path>...]` (a bare `<path>` is allowed: its id is derived). Pure
// (no fs); returns [{ id|null, path }]. Throws on a syntactically broken entry.
export function parseArtifactSpec(spec) {
  const out = [];
  for (const raw of String(spec ?? "").split(",")) {
    const item = raw.trim();
    if (!item) continue;
    const eq = item.indexOf("=");
    if (eq === -1) { out.push({ id: null, path: item }); continue; }
    const id = item.slice(0, eq).trim();
    const path = item.slice(eq + 1).trim();
    if (!isArtifactId(id)) throw new Error(`SHADE_TREE_ZK_ARTIFACTS: bad artifact id ${JSON.stringify(id.slice(0, 32))} in ${JSON.stringify(item.slice(0, 80))}`);
    if (!path) throw new Error(`SHADE_TREE_ZK_ARTIFACTS: missing vkey path for ${id}`);
    out.push({ id, path });
  }
  return out;
}

// loadArtifactSet({ env, root }) -> {
//   accepted: Map<id, { vkey /*parsed JSON*/, path, sha256 }>,   the ids this gateway verifies with
//   ids: [id...]                                                 sorted (what the caps ad carries)
//   legacyId: id                                                 what an envelope with NO field means
//   legacyAccepted: bool                                         legacyId ∈ accepted (inside the window)
//   explicit: bool                                               SHADE_TREE_ZK_ARTIFACTS was set (advertise)
// }
// FAIL-CLOSED at load: a declared id that does not equal the vkey's derived id, an unreadable/
// unparsable vkey, an empty set, or a duplicate id all throw with a clear message (a mis-pointed
// window is a startup error, never a silently-wrong accepted set).
export function loadArtifactSet({ env = process.env, root = ROOT, circuit = "rln", builtinPath = BUILTIN_VKEY_PATH } = {}) {
  const spec = env.SHADE_TREE_ZK_ARTIFACTS;
  const explicit = spec !== undefined && String(spec).trim() !== "";
  const entries = explicit ? parseArtifactSpec(spec) : [{ id: null, path: builtinPath }];
  if (entries.length === 0) throw new Error("SHADE_TREE_ZK_ARTIFACTS is set but names no artifact");
  const accepted = new Map();
  for (const { id: declared, path: p } of entries) {
    const abs = isAbsolute(p) ? p : resolve(root, p);
    if (!existsSync(abs)) throw new Error(`SHADE_TREE_ZK_ARTIFACTS: vkey not found: ${abs}${declared ? ` (for ${declared})` : ""}`);
    const bytes = readFileSync(abs);
    let vkey;
    try { vkey = JSON.parse(bytes.toString("utf8")); } catch (e) { throw new Error(`SHADE_TREE_ZK_ARTIFACTS: ${abs} is not a JSON verification key: ${e.message}`); }
    if (!vkey || typeof vkey !== "object" || !Array.isArray(vkey.IC)) throw new Error(`SHADE_TREE_ZK_ARTIFACTS: ${abs} does not look like a snarkjs verification key (no IC)`);
    const derived = artifactIdOf(circuit, bytes);
    if (declared && declared !== derived) {
      throw new Error(`SHADE_TREE_ZK_ARTIFACTS: artifact id mismatch for ${abs}: declared ${declared} but the file's content id is ${derived} (refusing to verify under a mislabeled key)`);
    }
    if (accepted.has(derived)) throw new Error(`SHADE_TREE_ZK_ARTIFACTS: duplicate artifact id ${derived}`);
    accepted.set(derived, { vkey, path: abs, sha256: createHash("sha256").update(bytes).digest("hex") });
  }
  const ids = [...accepted.keys()].sort();
  const builtinId = existsSync(builtinPath) ? artifactIdOfFile(builtinPath, circuit) : ids[0];
  const legacyEnv = env.SHADE_TREE_ZK_ARTIFACT_LEGACY;
  let legacyId;
  if (legacyEnv !== undefined && String(legacyEnv).trim() !== "") {
    legacyId = String(legacyEnv).trim();
    if (!isArtifactId(legacyId)) throw new Error(`SHADE_TREE_ZK_ARTIFACT_LEGACY: bad artifact id ${JSON.stringify(legacyId.slice(0, 32))}`);
  } else {
    // Default: the previous set's id once a ceremony has rotated the lock (so old clients get
    // a precise `artifact-retired` even with zero env), else the built-in id (== today).
    legacyId = lockArtifactIds()?.previous || builtinId;
  }
  return { accepted, ids, legacyId, legacyAccepted: accepted.has(legacyId), explicit, builtinId };
}

// Resolve the artifact an envelope claims against a loaded set. PURE + TOTAL — the cheap check
// verifyEnvelope runs before the Groth16 verify. Returns
//   { ok:true,  id, vkey }                                              — verify under this vkey
//   { ok:false, reason:"bad-artifact:<repr>",   label:"bad-artifact"     } — field present but not an id
//   { ok:false, reason:"artifact-retired:<id>", label:"artifact-retired" } — the legacy id, no longer accepted
//   { ok:false, reason:"artifact-unknown:<id>", label:"artifact-unknown" } — an id this gateway holds no vkey for
// (`reason` is the precise wire/log string; `label` is the bounded metrics key.) Absent field
// (undefined/null) => the set's legacyId, then the same rules — so an old client keeps working
// exactly while the legacy id is accepted, and is rejected precisely once it is not.
export function resolveArtifact(field, set) {
  let id;
  if (field === undefined || field === null) {
    id = set.legacyId;
  } else if (!isArtifactId(field)) {
    return { ok: false, reason: `bad-artifact:${artifactRepr(field)}`, label: "bad-artifact", artifacts: set.ids };
  } else {
    id = field;
  }
  const hit = set.accepted.get(id);
  if (hit) return { ok: true, id, vkey: hit.vkey };
  if (id === set.legacyId) return { ok: false, reason: `artifact-retired:${id}`, label: "artifact-retired", artifacts: set.ids };
  return { ok: false, reason: `artifact-unknown:${id}`, label: "artifact-unknown", artifacts: set.ids };
}

// Short, safe repr of a garbage artifact field for the reason string (bounded; never dumps a
// large/nested value into a log line or wire reply).
function artifactRepr(v) {
  if (typeof v === "string") return JSON.stringify(v.slice(0, 16));
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return typeof v;
}

// ---- client pick ------------------------------------------------------------------

// selectArtifact(gatewayIds, clientIds) — the client's pick. `clientIds` is the ORDERED list of
// artifact sets this client can prove with, NEWEST FIRST; `gatewayIds` is the gateway's
// advertised accepted set (caps.artifacts) or null when unknown (no ad yet).
//   { ok:true, id }                                        the newest client id the gateway accepts
//   { ok:true, id }  (gatewayIds null)                     optimistic: the client's newest
//   { ok:false, reason:"no-mutual-artifact:client=a|b,gateway=c|d" }   disjoint — fail closed
// (Rust: shadenet_proto::select_artifact; reason literal pinned in testdata/vectors.json.)
export function selectArtifact(gatewayIds, clientIds) {
  const mine = (clientIds || []).filter(isArtifactId);
  if (mine.length === 0) return { ok: false, reason: "no-client-artifact" };
  if (!Array.isArray(gatewayIds) || gatewayIds.length === 0) return { ok: true, id: mine[0] };
  const theirs = new Set(gatewayIds.filter(isArtifactId));
  for (const id of mine) if (theirs.has(id)) return { ok: true, id };
  return { ok: false, reason: `no-mutual-artifact:client=${mine.join("|")},gateway=${[...theirs].sort().join("|")}` };
}

// ---- client prover sets ------------------------------------------------------------

// The client's own prover artifact sets, NEWEST FIRST:
//   SHADE_TREE_ZK_PROVER_ARTIFACTS=<id>=<dir>[,<id>=<dir>...]   dir holds rln.wasm + rln_final.zkey +
//                                                          verification_key.json; id must equal the
//                                                          vkey's derived id (fail closed otherwise)
// unset => [{ id: builtin, wasm, zkey }] — the shipped circuits/rln set (byte-equivalent to today).
export function loadProverSets({ env = process.env, root = ROOT, circuit = "rln" } = {}) {
  const spec = env.SHADE_TREE_ZK_PROVER_ARTIFACTS;
  if (spec === undefined || String(spec).trim() === "") {
    return [{ id: builtinArtifactId(), wasm: BUILTIN_WASM_PATH, zkey: BUILTIN_ZKEY_PATH, vkey: BUILTIN_VKEY_PATH }];
  }
  const out = [];
  const seen = new Set();
  for (const { id: declared, path: p } of parseArtifactSpec(spec)) {
    const dir = isAbsolute(p) ? p : resolve(root, p);
    const vkeyPath = join(dir, "verification_key.json");
    const wasm = join(dir, "rln.wasm");
    const zkey = join(dir, "rln_final.zkey");
    for (const f of [vkeyPath, wasm, zkey]) if (!existsSync(f)) throw new Error(`SHADE_TREE_ZK_PROVER_ARTIFACTS: missing ${f}`);
    const derived = artifactIdOfFile(vkeyPath, circuit);
    if (declared && declared !== derived) throw new Error(`SHADE_TREE_ZK_PROVER_ARTIFACTS: artifact id mismatch for ${dir}: declared ${declared}, content id ${derived}`);
    if (seen.has(derived)) throw new Error(`SHADE_TREE_ZK_PROVER_ARTIFACTS: duplicate artifact id ${derived}`);
    seen.add(derived);
    out.push({ id: derived, wasm, zkey, vkey: vkeyPath });
  }
  if (out.length === 0) throw new Error("SHADE_TREE_ZK_PROVER_ARTIFACTS is set but names no artifact");
  return out;
}
