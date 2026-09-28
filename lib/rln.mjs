// RLN circuit core — Rate-Limiting-Nullifier via rlnjs@3.3.0 against the
// locally-built circom-rln v1.0.0 Groth16 artifacts in circuits/rln/ (see
// circuits/rln/ARTIFACTS.md). This replaces the v2 PoC that layered a hand-rolled
// Shamir share over a Semaphore membership proof: the share <-> membership binding is
// now proven INSIDE one Groth16 circuit, not asserted by a cheap signal==share.x check.
//
// What a member proves per CONNECT tunnel (one RLN proof):
//   - it owns the identitySecret behind some rateCommitment leaf in the depth-20 tree,
//   - at messageId = slot i  (range-checked 0 <= i < K inside the circuit),
//   - for epoch (externalNullifier = Poseidon(epoch, rlnIdentifier)),
//   - evaluating the degree-1 line  y = identitySecret + a1*x  at  x = H(message),
//     where a1 is circuit-derived from (identitySecret, externalNullifier, messageId).
//
// Rate cap: K distinct messageIds per epoch => K distinct nullifiers. Reuse a messageId
// in the same epoch with a DIFFERENT message => two (x,y) points on the same line =>
// anyone can Shamir-reconstruct the identitySecret and slash the leaf.
//
// KEY SEMANTIC CHANGES from v2 (see lib/MIGRATION-NOTES.md):
//   - The slot is PRIVATE (messageId is a witness). There is no public "slot" any more.
//     The gateway keys its spent-set on `nullifier`; a repeated nullifier with a
//     DIFFERENT public `x` is a breach (over-spend), same as before but keyed differently.
//   - Per-epoch binding is `externalNullifier` (per-epoch, NOT per-slot). Per-slot
//     uniqueness comes from the private messageId inside the circuit.
//   - `identitySecret` (= Poseidon2(nullifier, trapdoor) of the Semaphore v3 identity) is
//     what a slash reveals — NOT the app's seed secret. deriveCommitment() takes that
//     identitySecret and returns the rateCommitment leaf.
//   - The signal/message is a STRING (rlnjs hashes it with keccak); requestSignal() now
//     returns that string, and the circuit's public `x` = calculateSignalHash(message).

import { readFile } from "node:fs/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { createRequire } from "node:module";
import { loadArtifactSet, loadProverSets, resolveArtifact, selectArtifact, artifactIdOf, builtinArtifactId } from "./zk-artifacts.mjs";

import {
  RLN,
  RLNProver,
  RLNVerifier,
  calculateExternalNullifier,
  calculateSignalHash,
  calculateRateCommitment,
} from "rlnjs";
// rlnjs uses Semaphore v3 identity/group (the versions the RLN circuit was built against).
// Resolve those dependencies FROM rlnjs so a checkout with top-level Semaphore v4 and an npm
// Git install that dedupes Semaphore v3 both load the same compatible implementation. A hard
// `rlnjs/node_modules/...` path breaks as soon as npm hoists the dependency.
const requireHere = createRequire(import.meta.url);
const requireFromRln = createRequire(requireHere.resolve("rlnjs"));
const importRlnDependency = (name) => import(pathToFileURL(requireFromRln.resolve(name)).href);
const [{ Identity }, { Group: RLNGroup }] = await Promise.all([
  importRlnDependency("@semaphore-protocol/identity"),
  importRlnDependency("@semaphore-protocol/group"),
]);
import { poseidon2 } from "poseidon-lite";
import { rateCommitment as coreRateCommitment } from "./identity-core.mjs";

// ---- paths + artifacts ------------------------------------------------------

const HERE = dirname(fileURLToPath(import.meta.url));
// The static (PoC / friends) member list. SHADE_TREE_MEMBERS_FILE overrides the path (T-FEAT-7: a
// gateway that trusts the static root ALONGSIDE on-chain sets can point it at any file; tests
// use a scratch file). Default: the committed group/members.json.
export const MEMBERS_PATH = process.env.SHADE_TREE_MEMBERS_FILE || join(HERE, "..", "group", "members.json");

// ---- artifact sets (T-HARD-8 artifact-version negotiation) -------------------
// The prover (client) and verifier (gateway) no longer hold ONE hard-wired artifact set. Each
// side holds a small named set keyed by content-derived artifact id (lib/zk-artifacts.mjs):
//   gateway: SHADE_TREE_ZK_ARTIFACTS  {id -> vkey}   (+ SHADE_TREE_ZK_ARTIFACT_LEGACY for field-less envelopes)
//   client:  SHADE_TREE_ZK_PROVER_ARTIFACTS  [{id, wasm, zkey}] newest first
// Both default to the shipped circuits/rln set under its own id, so with nothing configured
// the wire + behavior are byte-equivalent to the single-artifact code this replaces. Loaded
// LAZILY (first prove/verify) so importing this module never fails on a mis-set env; the
// gateway calls getArtifactSet() at startup to surface a bad window config as a startup error.
let _artifactSet = null;   // gateway/verifier side: loadArtifactSet()
let _proverSets = null;    // client/prover side: loadProverSets()
export function getArtifactSet() {
  return (_artifactSet ||= loadArtifactSet());
}
export function getProverSets() {
  return (_proverSets ||= loadProverSets());
}
// Test seams: install an explicit set (or null to re-read env on next use).
export function _setArtifactSet(set) { _artifactSet = set || null; _verifiers = new Map(); }
export function _setProverSets(sets) { _proverSets = sets || null; _provers = new Map(); }
// The ORDERED ids (newest first) this client can prove with — what selectArtifact intersects
// with a gateway's caps.artifacts ad.
export function clientArtifactIds() {
  return getProverSets().map((s) => s.id);
}

// ---- protocol constants -----------------------------------------------------

// BN254 (alt_bn128) scalar field prime — the field Poseidon + the RLN circuit operate in.
export const FIELD =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// K = userMessageLimit = K_SLOTS = 8: the DEFAULT tier's per-epoch message limit. bigint
// on-chain / in the circuit; Number here.
//
// Reputation tiers (T-FEAT-8, docs/adr/0006-reputation-tiers.md): the limit is NOT global. It is
// a PER-LEAF value — circom-rln's leaf is Poseidon2(Poseidon1(identitySecret), userMessageLimit)
// and the circuit takes userMessageLimit as a PRIVATE input, range-checking messageId < limit.
// So a member's tier IS its leaf's limit: it proves membership of a leaf carrying THAT limit and
// a messageId under it, and can never claim a bigger one (a different limit is a different
// Poseidon output — a leaf that is not in the trusted tree). No circuit change, no new setup,
// no wire change: the gateway learns nothing about which tier a proof came from. K_SLOTS is
// what a member/enrolment uses when no explicit `limit` is given (byte-compatible default).
export const K_SLOTS = Number(process.env.SHADE_TREE_SLOTS || 8);
const K_BIG = BigInt(K_SLOTS);

// The circuit is RLN(20, 16): messageId and userMessageLimit are compared with LessThan(16), so
// a limit MUST fit in 16 bits or the range check is unsound (an out-of-range limit is not
// rejected by the circuit — it is an admission-time rule: never admit a leaf with limit > this).
export const MAX_LIMIT = 65535;

// normLimit(limit) -> bigint. A tier limit is an integer in 1..MAX_LIMIT (Number, bigint, or
// decimal string). Anything else throws a precise error — never silently coerced.
export function normLimit(limit = K_SLOTS) {
  let n;
  if (typeof limit === "bigint") n = limit;
  else if (typeof limit === "number" && Number.isSafeInteger(limit)) n = BigInt(limit);
  else if (typeof limit === "string" && /^[0-9]+$/.test(limit)) n = BigInt(limit);
  else throw new Error("limit: not an integer (" + typeof limit + ")");
  if (n < 1n || n > BigInt(MAX_LIMIT)) throw new Error(`limit: out of range 1..${MAX_LIMIT} (got ${n})`);
  return n;
}

// The tier set a GATEWAY knows: the distinct limits it will try when naming a slashed leaf
// (`resolveSlashLeaf`). Proof verification does not depend on it (the limit is private to the
// proof); it only widens the slash path to non-default tiers. SHADE_TREE_TIERS="8,32" (ascending,
// distinct, each 1..MAX_LIMIT); the default tier K_SLOTS is always included. Default: [K_SLOTS].
export function parseTiers(spec = process.env.SHADE_TREE_TIERS, k = K_SLOTS) {
  const out = new Set([Number(normLimit(k))]);
  const raw = spec == null ? "" : String(spec).trim();
  if (raw !== "") {
    for (const part of raw.split(",")) {
      const t = part.trim();
      if (t === "") continue;
      if (!/^[0-9]+$/.test(t)) throw new Error(`SHADE_TREE_TIERS: bad tier "${t.slice(0, 16)}" (integers only)`);
      out.add(Number(normLimit(t)));
    }
  }
  return Array.from(out).sort((a, b) => a - b);
}
export const TIERS = parseTiers();

// The RLN app identifier. MUST match the on-chain contract, the circuit's rlnIdentifier,
// and rlnjs's registry group-id (smoke.mjs uses 1n). It seeds externalNullifier and the
// tree's construction, so both JS sides and the chain must agree byte-for-byte.
export const RLN_IDENTIFIER = BigInt(process.env.SHADE_TREE_RLN_IDENTIFIER || 1n);

const TREE_DEPTH = 20; // circom-rln RLN(20,16)

// Demo default 120s (production 3600s). Must match on both sides — client and gateway
// both import this file, so the default already agrees everywhere.
export function epochSeconds(env = process.env) {
  return Number(env.SHADE_TREE_EPOCH_SECONDS || 120);
}
export const EPOCH_SECONDS = epochSeconds();

export function currentEpoch(nowMs = Date.now()) {
  return BigInt(Math.floor(nowMs / 1000 / epochSeconds()));
}

// ---- field helpers ----------------------------------------------------------

export function toField(v) {
  let n;
  if (typeof v === "bigint") n = v;
  else if (typeof v === "number") n = BigInt(v);
  else if (typeof v === "string") n = v.startsWith("0x") ? BigInt(v) : BigInt(v);
  else throw new Error("toField: unsupported " + typeof v);
  return ((n % FIELD) + FIELD) % FIELD;
}

const modSub = (a, b) => (((a - b) % FIELD) + FIELD) % FIELD;
const modMul = (a, b) => (a * b) % FIELD;

// modular inverse via extended Euclid (a nonzero, mod prime FIELD)
function modInv(a) {
  let [old_r, r] = [((a % FIELD) + FIELD) % FIELD, FIELD];
  let [old_s, s] = [1n, 0n];
  if (old_r === 0n) throw new Error("modInv(0)");
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return ((old_s % FIELD) + FIELD) % FIELD;
}

// ---- external nullifier + request signal ------------------------------------

// externalNullifier(epoch) = Poseidon(epoch, rlnIdentifier): the per-EPOCH binding
// (NOT per-slot). rlnjs computes it the same way; this is what verifyEnvelope checks cheap.
export function externalNullifierFor(epoch) {
  return calculateExternalNullifier(toField(epoch), RLN_IDENTIFIER);
}

// The request-bound RLN message. rlnjs hashes a STRING message into the circuit's public
// `x` via calculateSignalHash (keccak256(utf8) >> 8). The shim MUST reuse the same
// (target, nonce) on every retry so a retry reproduces the SAME x (and therefore the same
// share + nullifier) — otherwise a rogue gateway could force retries to manufacture an
// over-spend. Returns a deterministic string; x is derived from it inside the circuit.
export function requestSignal(target, nonce) {
  return `shade-tree:v4\n${String(target)}\n${String(nonce)}`;
}

// The signal is a newline-delimited encoding, so (target, nonce) -> signal is injective ONLY when
// the fields are newline-free and bounded. A verifier MUST enforce this before hashing (the gateway
// runs verifyEnvelope ahead of its validTarget filter), so no crafted delimiter can make two
// distinct (target, nonce) pairs collide to the same signal and slip the target binding.
export function signalFieldSafe(s, maxLen) {
  return typeof s === "string" && s.length > 0 && s.length <= maxLen && !/[\n\r]/.test(s);
}

// ---- identity / commitment --------------------------------------------------

// A deterministic rlnjs (Semaphore v3) identity, seeded from the app's field-element
// secret so the same secret always yields the same identity / identitySecret / leaf.
export function identityFor(secret) {
  return new Identity(toField(secret).toString());
}

// identitySecret = Poseidon2(nullifier, trapdoor) — the Semaphore v3 identity secret and
// the value a slash reveals. This is NOT the app's seed `secret`.
export function identitySecretOf(identity) {
  return poseidon2([identity.getNullifier(), identity.getTrapdoor()]);
}

// deriveCommitment(identitySecret, limit = K_SLOTS) -> rateCommitment leaf (string).
//   rateCommitment = Poseidon2( Poseidon1(identitySecret), limit )
// This is the on-chain leaf. The gateway reconstructs identitySecret from two shares and
// deriveCommitment(that, tier) names the leaf to slash (see resolveSlashLeaf for a gateway
// that admits several tiers). Equals rlnjs calculateRateCommitment(identityCommitment, limit)
// and rlnjs's own getRateCommitment() for the same identity + limit. `limit` is the member's
// tier (T-FEAT-8); the default keeps every existing leaf byte-identical.
export function deriveCommitment(identitySecret, limit = K_SLOTS) {
  return rateCommitmentBig(toField(identitySecret), normLimit(limit)).toString();
}
// The formula lives in lib/identity-core.mjs, shared with the SDK's browser build.
function rateCommitmentBig(identitySecret, limitBig = K_BIG) {
  return coreRateCommitment(identitySecret, limitBig);
}

// Convenience: the rateCommitment leaf (bigint) for a whole identity at a tier limit.
export function rateCommitmentOf(identity, limit = K_SLOTS) {
  return rateCommitmentBig(identitySecretOf(identity), normLimit(limit));
}

// deriveCommitments(identitySecret, tiers = TIERS) -> [{ limit, commitment }] — the candidate
// leaves ONE identitySecret could sit behind, one per tier the gateway knows.
export function deriveCommitments(identitySecret, tiers = TIERS) {
  return tiers.map((limit) => ({ limit, commitment: deriveCommitment(identitySecret, limit) }));
}

// resolveSlashLeaf(identitySecret, { tiers, hasLeaf }) -> { commitment, limit, resolved }.
// After an over-spend the gateway holds the reconstructed identitySecret but NOT the tier (it is
// private to the proof). The leaf to slash is the candidate that is actually IN the set:
// `hasLeaf(commitment)` (e.g. membership in the local members.json leaves). With no `hasLeaf`
// (on-chain root mode holds roots, not leaves) or no candidate present, fall back to the DEFAULT
// tier's leaf with resolved:false — the pre-tier behavior, and the only leaf today's on-chain
// hasher (RateCommitmentHasher, K pinned to 8) can slash anyway (docs/ONCHAIN.md follow-up).
export function resolveSlashLeaf(identitySecret, { tiers = TIERS, hasLeaf = null } = {}) {
  const cands = deriveCommitments(identitySecret, tiers);
  if (typeof hasLeaf === "function") {
    for (const c of cands) if (hasLeaf(c.commitment)) return { ...c, resolved: true };
  }
  const dflt = cands.find((c) => c.limit === K_SLOTS) || cands[0];
  return { ...dflt, resolved: false };
}

// ---- group / tree -----------------------------------------------------------

// Build the depth-20 RLN Merkle tree of rateCommitment leaves using rlnjs's OWN Semaphore
// v3 Group (the exact tree its registry proves against), so the JS root == the circuit root.
export function newGroup(rateCommitments = []) {
  const g = new RLNGroup(RLN_IDENTIFIER, TREE_DEPTH);
  for (const leaf of rateCommitments) g.addMember(BigInt(leaf));
  return g;
}

// Build a group from a list of identities (test helper). Each entry is an Identity (default
// tier) or `{ identity, limit }` for a tiered member — ONE tree holds every tier.
export function groupFromIdentities(identities) {
  return newGroup(identities.map((e) => (e && e.identity ? rateCommitmentOf(e.identity, e.limit) : rateCommitmentOf(e))));
}

// Load the published reputation set (rateCommitment leaves). Returns { group, root, count, leaves }.
// `leaves` (decimal strings) feeds resolveSlashLeaf's hasLeaf. members.json is a list of leaf
// strings — a leaf already commits to its tier, so the file shape carries no per-member limit.
export async function loadGroup() {
  const raw = JSON.parse(await readFile(MEMBERS_PATH, "utf8"));
  const leaves = raw.members.map((m) => BigInt(m));
  const group = newGroup(leaves);
  return { group, root: group.root.toString(), count: leaves.length, leaves: leaves.map(String) };
}

// loadGroupOnchain(rootProvider) -> { recentRoots }: reconstruct the rateCommitment tree
// from the contract's Member* events (via lib/root-provider.mjs, node mode) and return the
// freshness-window root set the gateway accepts proofs against. NOTE: the leaves are now
// rateCommitments and the tree is the RLN v3 depth-20 Poseidon tree (root-provider was
// updated to build it with newGroup()), so the reconstructed root matches proof roots.
// A CompositeRootProvider (several contracts, T-FEAT-7) also yields `perSource` / `errors`,
// passed through untouched so the gateway can log and gauge each source.
export async function loadGroupOnchain(rootProvider) {
  const provider =
    rootProvider || (await import("./root-provider.mjs")).makeRootProvider("node");
  const r = await provider.currentRoots();
  return {
    recentRoots: (r.roots || []).map(String),
    perSource: r.perSource,
    errors: r.errors,
    leafCount: r.leafCount,
    stale: !!r.stale,
    error: r.error,
  };
}

// ---- prove one slot ---------------------------------------------------------

// One RLNProver per prover artifact set (keyed by id) and one RLNVerifier per accepted vkey.
let _provers = new Map();
function getProver(artifactId) {
  const sets = getProverSets();
  const set = artifactId == null ? sets[0] : sets.find((s) => s.id === artifactId);
  if (!set) throw new Error(`proveForSlot: no prover artifact set for id ${String(artifactId).slice(0, 32)} (have ${sets.map((s) => s.id).join(",")})`);
  let p = _provers.get(set.id);
  if (!p) { p = new RLNProver(set.wasm, set.zkey); _provers.set(set.id, p); }
  return { prover: p, id: set.id };
}
let _verifiers = new Map();
function getVerifier(id, vkey) {
  let v = _verifiers.get(id);
  if (!v) { v = new RLNVerifier(vkey); _verifiers.set(id, v); }
  return v;
}

// snarkjs' wasm witness calculator (shared by the one RLNProver) and groth16 fullProve
// are NOT reentrant in-process: two overlapping prove/verify calls share internal input
// buffers and clobber each other, surfacing as "Not enough values for input signal
// pathElements". This bites the shim (its background per-epoch warm proof races the first
// real tunnel) and any gateway serving concurrent tunnel proofs. Serialize ALL snarkjs work
// behind one promise-chain mutex. Proving is ~0.4s; overlapping callers simply queue.
let _snarkLock = Promise.resolve();
function withSnarkLock(fn) {
  const run = _snarkLock.then(fn, fn);
  _snarkLock = run.then(() => {}, () => {}); // keep the chain alive regardless of outcome
  return run;
}

// Make an RLNFullProof JSON-safe for the wire (epoch + rlnIdentifier are bigints).
function wireProof(full) {
  return {
    snarkProof: full.snarkProof, // proof fields + publicSignals are already strings
    epoch: String(full.epoch),
    rlnIdentifier: String(full.rlnIdentifier),
  };
}

// proveForSlot(secret, epoch, i, signal, { group, artifact, limit }) ->
//   { proof /*RLNFullProof (wire-safe)*/, nullifier, externalNullifier, slot: i, share:{x,y}, artifact }
// A REAL RLN Groth16 proof with messageId = i, the given epoch, and message = signal.
// `artifact` (optional) names which of this client's prover sets to prove with (T-HARD-8;
// default = the newest = getProverSets()[0]); the id used is echoed back so the caller can
// stamp it into the envelope's `artifact` field.
// `limit` (optional, default K_SLOTS) is THIS member's tier: the userMessageLimit its leaf was
// enrolled with (T-FEAT-8). The leaf looked up in `group` is Poseidon2(Poseidon1(secret), limit),
// so proving with a limit other than the enrolled one fails HERE with "not in group" (there is
// no leaf to prove against) — a member cannot claim a tier it lacks. `i` must be < limit; the
// circuit range-checks it (RangeCheck assert), we pre-check for a precise error.
// The Groth16 proof BYTES are randomized per call, but the PUBLIC SIGNALS (share x/y,
// nullifier, externalNullifier, root) are deterministic given (identitySecret,
// externalNullifier, messageId, x) — a retry with the same args reproduces an identical
// share + nullifier.
export async function proveForSlot(secret, epoch, i, signal, { group, artifact, limit } = {}) {
  const identity = identityFor(secret);
  const identitySecret = identitySecretOf(identity);
  const g = group || (await loadGroup()).group;
  const limitBig = normLimit(limit ?? K_SLOTS);
  const slotBig = toField(i);
  if (slotBig >= limitBig) throw new Error(`proveForSlot: slot ${slotBig} >= limit ${limitBig} (out of this member's tier)`);

  const leaf = rateCommitmentBig(identitySecret, limitBig);
  const index = g.indexOf(leaf);
  if (index === -1) throw new Error(`proveForSlot: identity's rateCommitment (limit ${limitBig}) not in group`);
  const merkleProof = g.generateMerkleProof(index);

  const message = String(signal);
  const x = calculateSignalHash(message); // circuit public x
  if (x <= 0n) throw new Error("proveForSlot: signal hashes to x<=0 (would leak secret)");

  const { prover, id: artifactId } = getProver(artifact);
  const full = await withSnarkLock(() =>
    prover.generateProof({
      identitySecret,
      userMessageLimit: limitBig,
      messageId: slotBig,
      merkleProof,
      x,
      epoch: toField(epoch),
      rlnIdentifier: RLN_IDENTIFIER,
    })
  );

  const ps = full.snarkProof.publicSignals;
  return {
    proof: wireProof(full),
    nullifier: String(ps.nullifier),
    externalNullifier: String(ps.externalNullifier),
    slot: i,
    share: { x: String(ps.x), y: String(ps.y) },
    artifact: artifactId,
  };
}

// ---- verify an envelope (gateway side) --------------------------------------

// Cheap checks BEFORE the SNARK verify (adversarial-review order):
//   1. externalNullifier == externalNullifierFor(current or previous epoch)  (one-epoch skew)
//   2. share.x == proof's public x  (the share is evaluated at the message this proof committed)
//   3. proof's public root ∈ recentRoots
//   3b. envelope `artifact` id resolves to a vkey this gateway accepts (T-HARD-8; cheap set
//       lookup: absent field => legacy id; retired/unknown/garbage => precise reason)
//   4. RLN Groth16 verify under THAT vkey  (expensive — last)
// Returns { ok, reason, nullifier, externalNullifier, share:{x,y}, artifact }. The nullifier +
// share are taken from the proof's PUBLIC SIGNALS (authoritative), never the envelope's copies,
// so a lying envelope cannot desync the gateway's spent-set. There is NO public slot.
// `opts.artifacts` is the accepted set (lib/zk-artifacts.mjs loadArtifactSet shape); default =
// the process-wide set from SHADE_TREE_ZK_ARTIFACTS (getArtifactSet). Rejections from 3b also carry
// `label` (bounded metrics key) and `artifacts` (the accepted ids, for the wire reply).
export async function verifyEnvelope(env, recentRoots, nowMs = Date.now(), { artifacts } = {}) {
  if (!env || typeof env !== "object") return { ok: false, reason: "no-envelope" };
  const { proof } = env;
  if (!proof || !proof.snarkProof || !proof.snarkProof.publicSignals) {
    return { ok: false, reason: "no-proof" };
  }
  const ps = proof.snarkProof.publicSignals;
  const share = env.share || { x: ps.x, y: ps.y };

  // 1. externalNullifier must be this-or-last epoch's (cheap).
  const now = currentEpoch(nowMs);
  const ok1 = [now, now - 1n].some(
    (e) => externalNullifierFor(e).toString() === String(ps.externalNullifier)
  );
  if (!ok1) return { ok: false, reason: "stale-external-nullifier" };

  // 2. the share must be evaluated at the proof's committed x (cheap binding).
  if (String(share.x) !== String(ps.x)) return { ok: false, reason: "signal-mismatch" };

  // 2b. bind the proof to THIS tunnel's target. The committed x is calculateSignalHash of
  // requestSignal(target, nonce); recomputing it from the envelope's target+nonce and checking it
  // equals ps.x means a captured proof cannot be redirected to a different target (or nonce) — a
  // malicious gateway replaying a member's proof to a peer with a swapped target is rejected. The
  // client sends the nonce for exactly this (client/shade-tree-client.mjs buildEnvelope); without it the
  // target is unverifiable, so we fail closed.
  if (env.nonce == null || env.target == null) return { ok: false, reason: "unbound-target" };
  // Fail closed on a target/nonce that could make the newline-delimited signal ambiguous (a
  // crafted delimiter) or exhaust the hasher (a giant nonce), BEFORE hashing.
  if (!signalFieldSafe(env.target, 256) || !signalFieldSafe(env.nonce, 128)) {
    return { ok: false, reason: "bad-signal-field" };
  }
  // INVARIANT (do not reorder apart): ps.x is attacker-supplied here and only becomes AUTHORITATIVE
  // once the Groth16 proof verifies (check 4 below). 2b binds target->ps.x cheaply; check 4 proves
  // ps.x really belongs to a valid membership proof. Both are required — never trust 2b without 4.
  if (String(calculateSignalHash(requestSignal(env.target, env.nonce))) !== String(ps.x)) {
    return { ok: false, reason: "target-not-bound" };
  }

  // 3. root must be one we currently accept (cheap). Accept an Array or a Set — Array.from
  //    normalizes both (the gateway keeps recentRoots as a Set).
  const roots = Array.from(recentRoots || []).map(String);
  if (!roots.includes(String(ps.root))) return { ok: false, reason: "wrong-group-root" };

  // 3b. which artifact set (vkey) does this proof claim? Cheap map lookup, BEFORE the SNARK.
  //     An id we hold no key for can never verify, so it is rejected by name here rather than
  //     as a misleading `invalid-proof`. A claimed id we DO hold but that the proof was not
  //     made for still fails check 4 under that key (id spoofing buys nothing).
  const art = resolveArtifact(env.artifact, artifacts || getArtifactSet());
  if (!art.ok) return { ok: false, reason: art.reason, label: art.label, artifacts: art.artifacts };

  // 4. the RLN Groth16 proof must verify under the resolved artifact's vkey (expensive — last).
  let valid = false;
  try {
    valid = await withSnarkLock(() =>
      getVerifier(art.id, art.vkey).verifyProof(RLN_IDENTIFIER, {
        snarkProof: proof.snarkProof,
        epoch: proof.epoch,
        rlnIdentifier: proof.rlnIdentifier ?? RLN_IDENTIFIER.toString(),
      })
    );
  } catch (e) {
    return { ok: false, reason: "verify-threw:" + e.message };
  }
  if (!valid) return { ok: false, reason: "invalid-proof" };

  return {
    ok: true,
    reason: "ok",
    nullifier: String(ps.nullifier),
    externalNullifier: String(ps.externalNullifier),
    share: { x: String(ps.x), y: String(ps.y) },
    artifact: art.id,
  };
}

// ---- reconstruct the identitySecret from two shares -------------------------

// Two points (xA,yA),(xB,yB) on the degree-1 line y = identitySecret + a1*x. Interpolate
// back to f(0) = identitySecret (the a0 revealed on over-spend). Distinct x required (a
// retry reuses x => same point => nothing to reconstruct). This is exactly rlnjs's
// shamirRecovery; kept as an explicit Lagrange interpolation.
export function reconstructSecret(shareA, shareB) {
  const xA = toField(shareA.x), yA = toField(shareA.y);
  const xB = toField(shareB.x), yB = toField(shareB.y);
  if (xA === xB) throw new Error("reconstructSecret: identical evaluation points");
  const a1 = modMul(modSub(yB, yA), modInv(modSub(xB, xA)));
  const a0 = modSub(yA, modMul(a1, xA));
  return a0.toString();
}

// ---- teardown ---------------------------------------------------------------

// Terminate snarkjs worker threads so the process can exit. Safe to call once at the end.
export function cleanUp() {
  try { RLN.cleanUp(); } catch { /* curve never initialized (no proof made) — fine */ }
}

export {
  // T-HARD-8 artifact negotiation (lib/zk-artifacts.mjs)
  loadArtifactSet,
  loadProverSets,
  resolveArtifact,
  selectArtifact,
  artifactIdOf,
  builtinArtifactId,
  RLN,
  Identity,
  RLNGroup,
  calculateRateCommitment,
  calculateSignalHash,
  calculateExternalNullifier,
};
