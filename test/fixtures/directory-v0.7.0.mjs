// The fleet directory: load, verify, and select from a signed list of gateways.
//
// The PoC pins one gateway (SHADE_TREE_ONION or tor/hs/hostname). A fleet needs a
// discovery layer, because onion descriptors are stored under a *blinded* key on
// the HSDir hashring precisely so gateways cannot be enumerated. So the directory
// is something we build at the app layer: a small signed JSON of
//   { onion, pubkey, weight, health }
// shipped with the bundle and refreshable over its own onion. The signer key is
// PINNED in the client, so a swapped file is rejected, not trusted.
//
// Two integrity checks, layered:
//   1. The whole list is ed25519-signed by the pinned directory signer.
//   2. Each entry's `pubkey` MUST equal the ed25519 identity key encoded in its
//      own v3 `.onion` address (onionToPubkey below). A v3 address *is* that key,
//      so a poisoned directory cannot graft a hostile onion under a pubkey it does
//      not control: the live onion-control challenge (verifyOnionControl) is then
//      a signature by that same key. Address and key cannot disagree.
//
// The static-signed-JSON path here is complete. The on-chain-sourced mode (source
// the fleet from the same group root as the reputation set) is a TODO that reuses
// the same entry shape; see docs/FLEET.md and docs/ONCHAIN.md.

// Primitives come from `#crypto` (package.json "imports"): node:crypto in Node, @noble in the
// browser (packages/node/lib/crypto-node.mjs, packages/node/lib/crypto-browser.mjs). Everything below is shared, so the SDK's
// browser build verifies a canopy with this exact code. File I/O is loaded lazily in
// loadDirectory, the one Node-only function here.
import {
  utf8, fromHex, toHex, concatBytes, bytesEqual, sha3_256,
  ed25519PublicKey, ed25519PrivateKey, ed25519Sign, ed25519Verify, ed25519PubFromSeed,
} from "#crypto";

export { ed25519PublicKey, ed25519PrivateKey, ed25519Sign, ed25519Verify, ed25519PubFromSeed };

// --- v3 onion <-> ed25519 key --------------------------------------------------
// v3 address = base32(PUBKEY[32] || CHECKSUM[2] || VERSION[1]), lowercase, no pad.
// CHECKSUM = SHA3-256(".onion checksum" || PUBKEY || 0x03)[:2]. The address is the
// key, so we can recover the key from the address and verify the checksum.

const B32 = "abcdefghijklmnopqrstuvwxyz234567";

function base32Decode(s) {
  let bits = 0, value = 0;
  const out = [];
  for (const ch of s.toLowerCase()) {
    const idx = B32.indexOf(ch);
    if (idx === -1) throw new Error("bad base32 char in onion");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >> bits) & 0xff);
    }
  }
  return Uint8Array.from(out);
}

function base32Encode(buf) {
  let bits = 0, value = 0, out = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += B32[(value >> bits) & 31];
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

// Recover the 32-byte ed25519 identity key from a v3 .onion address (checked).
export function onionToPubkey(onion) {
  const addr = onion.replace(/\.onion$/, "").toLowerCase();
  if (addr.length !== 56) throw new Error("not a v3 onion (expected 56 chars)");
  const decoded = base32Decode(addr);
  if (decoded.length !== 35) throw new Error("v3 onion decodes to 35 bytes");
  const pubkey = decoded.subarray(0, 32);
  const checksum = decoded.subarray(32, 34);
  const version = decoded[34];
  if (version !== 0x03) throw new Error("not onion version 3");
  const want = sha3_256(concatBytes([utf8(".onion checksum"), pubkey, Uint8Array.of(0x03)])).subarray(0, 2);
  if (!bytesEqual(checksum, want)) throw new Error("onion checksum mismatch");
  return toHex(pubkey);
}

// Encode a 32-byte ed25519 key as its v3 .onion address (used by the signer tool).
export function pubkeyToOnion(pubHex) {
  const pubkey = fromHex(pubHex);
  if (pubkey.length !== 32) throw new Error("pubkey must be 32 bytes");
  const checksum = sha3_256(concatBytes([utf8(".onion checksum"), pubkey, Uint8Array.of(0x03)])).subarray(0, 2);
  return base32Encode(concatBytes([pubkey, checksum, Uint8Array.of(0x03)])) + ".onion";
}

// --- gateway capability advertisement (T-FEAT-10) -----------------------------
// A gateway self-declares COARSE, BUCKETED capabilities so a client can route to a
// capable gateway (a target port the gateway allows, a mutually-supported protocol
// version, an optional region hint) instead of "any gateway". Three design rules:
//
//   1. ADDITIVE / OMIT-WHEN-ABSENT. Caps are an OPTIONAL field. `canonicalCaps` returns
//      {} when nothing valid is present, and every canonical-bytes builder (announce +
//      directory) OMITS the caps field entirely when caps are absent/empty — so an
//      announce/directory WITHOUT caps serializes byte-IDENTICALLY to before (the golden
//      canonicalAnnounceBytes/canonicalDirectoryBytes vectors are unchanged).
//   2. SIGNED UNDER THE ONION KEY. A directory signer cannot rewrite a present cap
//      advertisement, though it can omit the optional field. Caps ride inside the main
//      onion-signed announce bytes AND carry a standalone, durable, onion-bound `capsSig`
//      (like operatorAuthMessage: no ts, reusable across heartbeats) so a directory entry
//      can be re-verified against the entry's own onion key. Altering any present cap field
//      breaks a signature and is rejected.
//   3. BUCKETED, NOT FINGERPRINTABLE. `ports` is a small deduped sorted set; `region` is a
//      coarse self-declared continent/AS bucket (NO precise geo); `proto` is the T-FEAT-11
//      envelope {min,max} range; `artifacts` (T-HARD-8) is the deduped sorted set of ZK
//      artifact ids the gateway verifies proofs under (packages/node/lib/zk-artifacts.mjs), so a client can
//      pick a mutual artifact set during a dual-VK rollout window. Fleet-wide values, not
//      per-gateway fingerprints. `canonicalCaps` is TOTAL: any garbage/unknown field is
//      dropped, never thrown on, so a malformed caps is ignored safely rather than fatal.
export const CAPS_DOMAIN = "Shade Tree gateway capabilities v1\n";
// Read-only compatibility tag for observing the pre-v4 research fleet. Shade Tree v4
// deliberately reset the capability domain, and clients/nodes MUST use CAPS_DOMAIN above.
// The legacy tag is exposed only through the explicit verification helper below so an
// external census can authenticate old, already-deployed announcements without making
// them usable by the v4 protocol.
export const PRE_V4_CAPS_DOMAIN = "RGOE gateway capabilities v1\n";
// Coarse, self-declared region/AS buckets. Continent-scale only — deliberately too coarse
// to fingerprint an individual gateway/member. Anything outside this set is dropped.
export const REGION_BUCKETS = new Set(["na", "sa", "eu", "af", "as", "oc", "aq", "unknown"]);
// A gateway that advertises NO caps is assumed to allow only the T-DEV-10 default egress
// port and to speak only the current T-FEAT-11 envelope version — the conservative floor a
// legacy/heterogeneous gateway implicitly meets (used by capability-aware selection).
export const DEFAULT_EGRESS_PORT = 443;
export const DEFAULT_PROTO_VERSION = 4;
// Artifact-id grammar for `caps.artifacts` (== packages/node/lib/zk-artifacts.mjs ARTIFACT_ID_RE; duplicated
// here so this module stays free of that import graph). Bounded count so an ad can't balloon.
const ARTIFACT_ID_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;
export const MAX_CAPS_ARTIFACTS = 8;

// T-FEAT-9 (docs/adr/0008): per-gateway ADMISSION POLICY + PAYMENT advert, both additive.
//   admits : the admission paths the gateway honours — a subset of ADMIT_PATHS in the fixed
//            anonymity order (invited > staked > paid), deduped; anything else is dropped.
//            Absent = a legacy gateway (the client assumes it may admit any path, docs/CLIENTS.md).
//   pay    : present iff the provider SELLS access — { protocols (subset of PAY_PROTOCOLS, fixed
//            order), onion? (a v3 onion when the registrar rides ANOTHER onion than the gateway's,
//            e.g. the bootnode's; absent = the gateway's own onion), port, asset (0x-hex-40,
//            lowercased), chain (`eip155:<id>`), tiers ({ "<limit>": "<atomic price>" }, at most
//            MAX_CAPS_PAY_TIERS, canonical integer keys so JSON key order is numeric) }. A `pay`
//            missing protocols/port/asset/chain/tiers is dropped whole (never a half advert).
// Both are appended AFTER artifacts so every pre-existing caps object canonicalizes to
// byte-identical JSON (the golden vectors are unchanged).
export const ADMIT_PATHS = Object.freeze(["invited", "staked", "paid"]);
export const PAY_PROTOCOLS = Object.freeze(["x402", "mpp"]);
export const MAX_CAPS_PAY_TIERS = 8;
const ONION_RE = /^[a-z2-7]{56}\.onion$/;
const CHAIN_RE = /^eip155:[1-9][0-9]{0,15}$/;
const ASSET_RE = /^0x[0-9a-fA-F]{40}$/;
const TIER_KEY_RE = /^[1-9][0-9]{0,4}$/;      // a limit 1..65535 (checked numerically too)
const TIER_PRICE_RE = /^[1-9][0-9]{0,39}$/;   // atomic units, decimal string (uint128-ish bound)

// Runtime rate policy advertised under the onion signature. This prevents a reviewed 60-second
// client from spending a slot on a node accidentally left at the historical 120-second clock.
// The fixed v4 scope is Grove-wide; cross-gateway tallying remains best-effort and is not claimed
// by this capability.
export function canonicalRate(rate) {
  if (!rate || typeof rate !== "object" || Array.isArray(rate)) return null;
  if (rate.scope !== "grove-v4" || rate.window !== "fixed") return null;
  const fields = ["epochSeconds", "rootFreshnessSeconds", "payloadBytesPerSlot"];
  if (fields.some((field) => !Number.isSafeInteger(rate[field]) || rate[field] <= 0)) return null;
  if (rate.previousEpochsAccepted !== 1) return null;
  return {
    scope: "grove-v4",
    window: "fixed",
    epochSeconds: rate.epochSeconds,
    previousEpochsAccepted: 1,
    rootFreshnessSeconds: rate.rootFreshnessSeconds,
    payloadBytesPerSlot: rate.payloadBytesPerSlot,
  };
}

// The `admits` field alone: [] when nothing valid (caller omits it).
// Session-ticket capability (session-v1, ADR 0011): `{ version, classes }`. Onion-signed like every
// other cap, so a directory signer cannot add session support a node did not advertise. version is
// an integer 1..65535; classes are grammar-checked ids, deduped, sorted, non-empty and bounded.
// Appended after `rate` so every caps byte string from before session tickets is unchanged.
export const SESSION_CLASS_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;
export const MAX_SESSION_CLASSES = 8;
export function canonicalSession(session) {
  if (!session || typeof session !== "object" || Array.isArray(session)) return null;
  if (!Number.isInteger(session.version) || session.version < 1 || session.version > 65535) return null;
  if (!Array.isArray(session.classes)) return null;
  const classes = [...new Set(session.classes.filter((c) => typeof c === "string" && SESSION_CLASS_RE.test(c)))].sort();
  if (classes.length === 0 || classes.length > MAX_SESSION_CLASSES) return null;
  return { version: session.version, classes };
}

export function canonicalAdmits(list) {
  if (!Array.isArray(list)) return [];
  const set = new Set(list.filter((a) => typeof a === "string").map((a) => a.toLowerCase()));
  return ADMIT_PATHS.filter((p) => set.has(p));
}

// The `pay` field alone: null when it does not form a complete, bounded advert.
export function canonicalPay(pay) {
  if (!pay || typeof pay !== "object" || Array.isArray(pay)) return null;
  const protos = Array.isArray(pay.protocols) ? new Set(pay.protocols.filter((p) => typeof p === "string").map((p) => p.toLowerCase())) : new Set();
  const protocols = PAY_PROTOCOLS.filter((p) => protos.has(p));
  if (!protocols.length) return null;
  const out = { protocols };
  if (typeof pay.onion === "string") {
    const o = pay.onion.toLowerCase();
    if (ONION_RE.test(o)) out.onion = o;
  }
  if (!Number.isInteger(pay.port) || pay.port < 1 || pay.port > 65535) return null;
  out.port = pay.port;
  if (typeof pay.asset !== "string" || !ASSET_RE.test(pay.asset)) return null;
  out.asset = pay.asset.toLowerCase();
  if (typeof pay.chain !== "string" || !CHAIN_RE.test(pay.chain)) return null;
  out.chain = pay.chain;
  if (!pay.tiers || typeof pay.tiers !== "object" || Array.isArray(pay.tiers)) return null;
  const tiers = {};
  const keys = Object.keys(pay.tiers).filter((k) => TIER_KEY_RE.test(k) && Number(k) <= 65535).sort((a, b) => Number(a) - Number(b));
  for (const k of keys) {
    const v = pay.tiers[k];
    const price = typeof v === "string" ? v : Number.isInteger(v) && v > 0 ? String(v) : null;
    if (price && TIER_PRICE_RE.test(price)) tiers[k] = price;
  }
  const n = Object.keys(tiers).length;
  if (n === 0 || n > MAX_CAPS_PAY_TIERS) return null;
  out.tiers = tiers;
  return out;
}

// Normalize a caps object into canonical, bucketed form with FIXED field order
// (ports, region, proto, artifacts, admits, pay, rate). TOTAL: never throws; unknown/invalid fields
// are dropped; returns {} when nothing valid remains (which every canonical builder treats as absent).
export function canonicalCaps(caps) {
  const out = {};
  if (!caps || typeof caps !== "object") return out;
  if (Array.isArray(caps.ports)) {
    const ports = [...new Set(caps.ports.filter((p) => Number.isInteger(p) && p >= 1 && p <= 65535))].sort((a, b) => a - b);
    if (ports.length) out.ports = ports;
  }
  if (typeof caps.region === "string" && REGION_BUCKETS.has(caps.region)) out.region = caps.region;
  const pr = caps.proto;
  if (pr && typeof pr === "object" && Number.isInteger(pr.min) && Number.isInteger(pr.max) && pr.min >= 1 && pr.max >= pr.min) {
    out.proto = { min: pr.min, max: pr.max };
  }
  // T-HARD-8: accepted ZK artifact ids — deduped, sorted, id-grammar-checked, count-bounded.
  // Appended LAST so every pre-existing caps object canonicalizes to byte-identical JSON.
  if (Array.isArray(caps.artifacts)) {
    const ids = [...new Set(caps.artifacts.filter((a) => typeof a === "string" && ARTIFACT_ID_RE.test(a)))].sort();
    if (ids.length && ids.length <= MAX_CAPS_ARTIFACTS) out.artifacts = ids;
  }
  // T-FEAT-9: admission policy + payment advert, appended LAST (in that order), same rule.
  const admits = canonicalAdmits(caps.admits);
  if (admits.length) out.admits = admits;
  const pay = canonicalPay(caps.pay);
  if (pay) out.pay = pay;
  const rate = canonicalRate(caps.rate);
  if (rate) out.rate = rate;
  const session = canonicalSession(caps.session);
  if (session) out.session = session;
  return out;
}

// True iff caps carry at least one valid bucketed field. Used to OMIT the caps field from
// canonical bytes when empty, keeping absent/empty-caps records byte-identical to before.
export function hasCaps(caps) {
  const c = canonicalCaps(caps);
  return c.ports !== undefined || c.region !== undefined || c.proto !== undefined || c.artifacts !== undefined || c.admits !== undefined || c.pay !== undefined || c.rate !== undefined || c.session !== undefined;
}

// Domain-separated, onion-bound canonical bytes the ONION key signs to attest its caps.
// DURABLE (no ts, like operatorAuthMessage): a self-declaration reusable across heartbeats
// and re-verifiable from a directory entry. Onion-binding is defense-in-depth (the sig is
// already verified against onionToPubkey(onion), so a caps sig can't be pasted onto a
// different gateway). Runs caps through canonicalCaps so key order/junk can't shift bytes.
export function canonicalCapsBytes(onion, caps) {
  return utf8(CAPS_DOMAIN + JSON.stringify({ onion: String(onion), caps: canonicalCaps(caps) }));
}

export function canonicalPreV4CapsBytes(onion, caps) {
  return utf8(PRE_V4_CAPS_DOMAIN + JSON.stringify({ onion: String(onion), caps: canonicalCaps(caps) }));
}

export function signCaps(onion, caps, onionSeedHex) {
  return ed25519Sign(canonicalCapsBytes(onion, caps), onionSeedHex);
}

// Verify a caps attestation against the ed25519 key encoded in the onion address. TOTAL:
// a non-string/absent sig -> false, never throws. This is the check that makes caps
// unforgeable by a bootnode/directory signer that lacks the gateway's onion key.
export function verifyCapsSig(onion, caps, capsSig) {
  if (typeof capsSig !== "string" || !capsSig) return false;
  return verifyOnionControl(onion, canonicalCapsBytes(onion, caps), capsSig);
}

// Observation-only compatibility check. This does not participate in announcements,
// capability selection, client discovery, or gateway admission.
export function verifyPreV4CapsSig(onion, caps, capsSig) {
  if (typeof capsSig !== "string" || !capsSig) return false;
  return verifyOnionControl(onion, canonicalPreV4CapsBytes(onion, caps), capsSig);
}

// --- directory signing / verification -----------------------------------------
// The signature covers a canonical serialization with fixed field order, so it is
// independent of file whitespace or key ordering. Sign and verify build the same
// bytes from the same fields; nothing else in the file is covered.

export function canonicalDirectoryBytes(dir) {
  const payload = {
    version: dir.version,
    issued: dir.issued,
    gateways: (dir.gateways || []).map((g) => {
      const e = {
        onion: g.onion,
        pubkey: g.pubkey,
        weight: g.weight,
        health: g.health,
      };
      // T-FEAT-10: caps + their onion-control signature ride in the signed bytes ONLY when
      // present, appended AFTER the four legacy fields. An entry WITHOUT caps serializes
      // byte-identically to before, so the golden canonicalDirectoryBytes vector is unchanged.
      if (hasCaps(g.caps)) {
        e.caps = canonicalCaps(g.caps);
        if (typeof g.capsSig === "string") e.capsSig = g.capsSig;
      }
      return e;
    }),
  };
  return utf8(JSON.stringify(payload));
}

export function signDirectory(dir, signerPrivHex) {
  const sig = ed25519Sign(canonicalDirectoryBytes(dir), signerPrivHex);
  return { ...dir, signature: sig };
}

// ed25519PubFromSeed (re-exported above) recovers the raw pubkey hex from a raw seed hex;
// signDirectoryThreshold uses it to record which key produced each signature.

// --- threshold (M-of-N) directory signing -------------------------------------
// T-FEAT-9: sign the directory with N independent signer keys so no single key
// compromise can forge the fleet view. This is an ADDITIVE extension: the threshold
// lives in three OPTIONAL top-level fields (`signers`, `signatures`, `threshold`)
// that are, like the single-sig `signer`/`signature`, EXCLUDED from
// canonicalDirectoryBytes. Every signer signs the SAME canonical bytes, so:
//   - the signed bytes are byte-identical to the single-sig directory over the same
//     {version,issued,gateways}, and
//   - a directory with none of these fields takes the unchanged single-sig path.
// The classic single-`signer` directory is the 1-of-1 case and is untouched here.
//
// `signerPrivHexes` is an array of raw ed25519 seed hex; `threshold` defaults to N
// (all signers required). Composes with T-FEAT-1: each federated bootnode is one signer.
export function signDirectoryThreshold(dir, signerPrivHexes, threshold) {
  if (!Array.isArray(signerPrivHexes) || signerPrivHexes.length === 0) {
    throw new Error("signDirectoryThreshold needs a non-empty array of signer seeds");
  }
  const bytes = canonicalDirectoryBytes(dir);
  const signers = [];
  const signatures = [];
  for (const priv of signerPrivHexes) {
    signers.push(ed25519PubFromSeed(priv));
    signatures.push(ed25519Sign(bytes, priv));
  }
  const th = threshold == null ? signers.length : threshold;
  // Strip any legacy single-sig fields so the threshold representation is unambiguous.
  const { signer: _drop1, signature: _drop2, ...rest } = dir;
  return { ...rest, signers, signatures, threshold: th };
}

// Normalize the pinned-signer argument into an ALLOWLIST of lowercase hex pubkeys.
// Accepts a single hex string (the original single-pin model) OR an array/Set/iterable
// of them (the rotation overlap set). Empty/falsy strings and non-string members are
// dropped so verifyDirectory stays total on arbitrary input. A lone string yields a
// one-element list, so the single-signer path is byte-for-byte the old behavior.
function normalizePinnedSigners(pinned) {
  // Lowercase + strip an optional `0x` prefix so an operator who pastes `SHADE_TREE_DIR_SIGNER=0xabc..`
  // is not silently broken (the raw-hex pubkey is bare; a 0x-prefixed pin would never match and
  // reject every directory -- fail-closed, but a hard-to-diagnose footgun; audit loop-14 F1).
  const norm = (p) => p.toLowerCase().replace(/^0x/, "");
  if (pinned == null) return [];
  if (typeof pinned === "string") return pinned ? [norm(pinned)] : [];
  const out = [];
  for (const p of pinned) if (typeof p === "string" && p) out.push(norm(p));
  return out;
}

// Verify the pinned-signer signature AND each entry's onion<->pubkey binding.
// Returns { ok, reason } (and, on success, { signer } = which pinned key matched).
// Does NOT prove liveness or control (that is the live challenge, verifyOnionControl);
// it proves the list is authentic and internally consistent, which is what stops a
// swapped or poisoned file.
//
// `pinnedSigner` is an ALLOWLIST: a single hex string OR an array/Set of them. The
// directory verifies iff (a) it is validly signed by ANY signer in the set, AND (b)
// the declared `dir.signer` (when present) is itself in the set. The set is the
// signer-rotation overlap window (old + new key) — it is NOT "trust any signer": an
// unpinned or wrong signer is still rejected. A single string behaves exactly as before.
// A directory is in THRESHOLD (M-of-N) mode iff it carries any of the optional
// threshold fields. When none are present, verifyDirectory falls through to the
// unchanged single-`signer` path — so an existing directory is byte-for-byte the
// old behavior (and cannot be silently reinterpreted).
function isThresholdDirectory(dir) {
  return dir.threshold !== undefined || dir.signers !== undefined || dir.signatures !== undefined;
}

// Shared gateway onion<->pubkey binding check (spec 4: each entry's pubkey MUST equal
// the ed25519 key encoded in its own v3 .onion). Returns null on success, a { reason }
// on the first bad entry. Total on arbitrary input (never throws).
function checkGatewayBindings(dir, { acceptPreV4Caps = false } = {}) {
  for (const g of dir.gateways || []) {
    let derived;
    try {
      derived = onionToPubkey(g.onion);
    } catch (e) {
      return { reason: `bad-onion:${g.onion?.slice(0, 12)}..:${e.message}` };
    }
    if (derived.toLowerCase() !== String(g.pubkey).toLowerCase()) {
      return { reason: `pubkey-onion-mismatch:${g.onion.slice(0, 12)}..` };
    }
    // T-FEAT-10: an entry that advertises caps MUST carry a valid onion-control signature
    // over exactly those caps. This is what makes the capabilities unforgeable by the
    // bootnode / directory signer (they lack the gateway's onion key): altering a cap, or
    // grafting caps onto an entry, breaks capsSig -> the whole directory is rejected.
    // Absent caps => nothing to check (additive; legacy entries are unaffected).
    if (hasCaps(g.caps)) {
      const current = verifyCapsSig(g.onion, g.caps, g.capsSig);
      const observedPreV4 = acceptPreV4Caps && verifyPreV4CapsSig(g.onion, g.caps, g.capsSig);
      if (!current && !observedPreV4) {
        return { reason: `bad-caps-sig:${g.onion.slice(0, 12)}..` };
      }
    }
  }
  return null;
}

// Verify an M-of-N threshold directory (T-FEAT-9). Accepts iff at least `threshold`
// DISTINCT signers from the client's PINNED set produced a valid signature over the
// SAME canonical bytes verifyDirectory checks — composing with the T-HARD-5 pinned
// allowlist (unpinned signers are ignored, exactly as they are rejected in single-sig).
// Returns { ok, reason } and, on success, { signers: [matched...], threshold }.
//
// Adversarial safety (TOTAL — never throws, no unpinned/duplicate trust):
//   - non-integer / < 1 threshold          -> bad-threshold
//   - signers/signatures not equal-length arrays -> bad-signatures
//   - threshold greater than N provided     -> threshold-exceeds-signers (unsatisfiable)
//   - a signer appearing twice is counted ONCE (one key cannot self-satisfy M-of-N)
//   - an unpinned signer is ignored (never counts toward the threshold)
//   - a malformed (non-string) signer/sig entry is skipped, not fatal
//   - fewer than `threshold` distinct valid pinned sigs -> threshold-not-met:<got>/<want>
export function verifyDirectoryThreshold(dir, pinnedSigner, { acceptPreV4Caps = false } = {}) {
  if (!dir || typeof dir !== "object") return { ok: false, reason: "no-directory" };
  const pinned = normalizePinnedSigners(pinnedSigner);
  const threshold = dir.threshold;
  if (!Number.isInteger(threshold) || threshold < 1) return { ok: false, reason: "bad-threshold" };
  const signers = dir.signers;
  const signatures = dir.signatures;
  if (!Array.isArray(signers) || !Array.isArray(signatures) || signers.length !== signatures.length) {
    return { ok: false, reason: "bad-signatures" };
  }
  if (threshold > signers.length) return { ok: false, reason: "threshold-exceeds-signers" };

  const bytes = canonicalDirectoryBytes(dir);
  const counted = new Set(); // DISTINCT pinned signers whose signature verified
  for (let i = 0; i < signers.length; i++) {
    const s = signers[i];
    const sig = signatures[i];
    if (typeof s !== "string" || typeof sig !== "string") continue; // malformed entry -> skip
    const norm = s.toLowerCase().replace(/^0x/, "");
    if (!pinned.includes(norm)) continue; // unpinned -> ignored
    if (counted.has(norm)) continue;      // duplicate signer -> counted once
    if (ed25519Verify(bytes, sig, norm)) counted.add(norm);
  }
  if (counted.size < threshold) {
    return { ok: false, reason: `threshold-not-met:${counted.size}/${threshold}` };
  }
  const bindErr = checkGatewayBindings(dir, { acceptPreV4Caps });
  if (bindErr) return { ok: false, reason: bindErr.reason };
  return { ok: true, signers: [...counted], threshold };
}

export function verifyDirectory(dir, pinnedSigner, { acceptPreV4Caps = false } = {}) {
  if (!dir || typeof dir !== "object") return { ok: false, reason: "no-directory" };
  // Threshold directories (any of signers/signatures/threshold present) verify under
  // the M-of-N rule; everything else takes the unchanged single-signer path below.
  if (isThresholdDirectory(dir)) return verifyDirectoryThreshold(dir, pinnedSigner, { acceptPreV4Caps });
  if (!dir.signature) return { ok: false, reason: "unsigned" };
  const pinned = normalizePinnedSigners(pinnedSigner);
  // A hostile/malformed directory can carry a non-string `signer`; guard before .toLowerCase()
  // so verifyDirectory stays TOTAL (returns {ok:false}, never throws) on arbitrary input.
  if (dir.signer !== undefined && dir.signer !== null) {
    if (typeof dir.signer !== "string") return { ok: false, reason: "bad-signer-field" };
    if (pinned.length && !pinned.includes(dir.signer.toLowerCase())) {
      return { ok: false, reason: "signer-not-pinned" };
    }
  }
  // The signature must verify under SOME pinned signer (allowlist membership). Try each;
  // the first match is the signer of record. No pinned signers => nothing verifies.
  const bytes = canonicalDirectoryBytes(dir);
  let matched = null;
  for (const p of pinned) {
    if (ed25519Verify(bytes, dir.signature, p)) { matched = p; break; }
  }
  if (!matched) return { ok: false, reason: "bad-signature" };
  // Per-entry onion<->pubkey binding AND (T-FEAT-10) caps-signature check, shared with the
  // threshold path so both verify capabilities identically.
  const bindErr = checkGatewayBindings(dir, { acceptPreV4Caps });
  if (bindErr) return { ok: false, reason: bindErr.reason };
  return { ok: true, signer: matched };
}

// Live onion-control proof: the gateway signs a fresh challenge with its onion
// identity key. Verified against the key encoded in its own address, so a
// directory entry cannot claim an onion it does not hold the key for. Wire the
// challenge/response into the gateway envelope handshake; here is the check.
export function verifyOnionControl(onion, challengeBuf, sigHex) {
  let pub;
  try {
    pub = onionToPubkey(onion);
  } catch {
    return false;
  }
  return ed25519Verify(challengeBuf, sigHex, pub);
}

// --- load with last-known-good fallback ---------------------------------------
// A dead or poisoned directory must degrade to the PREVIOUS good fleet, never to
// nothing and never to a hostile gateway. So: verify the fetched file; on success
// cache it; on failure fall back to the cached last-known-good (itself re-verified
// against the same pinned signer). Returns { dir, source } or throws if neither
// the fresh nor the cached copy verifies.
export async function loadDirectory({ path, pinnedSigner, cachePath } = {}) {
  const [{ readFile, writeFile, mkdir }, { dirname }] = await Promise.all([import("node:fs/promises"), import("node:path")]);
  let fresh = null, freshErr = null;
  if (path) {
    try {
      fresh = JSON.parse(await readFile(path, "utf8"));
      const v = verifyDirectory(fresh, pinnedSigner);
      if (!v.ok) throw new Error(v.reason);
    } catch (e) {
      fresh = null;
      freshErr = e;
    }
  }
  if (fresh) {
    if (cachePath) {
      try {
        await mkdir(dirname(cachePath), { recursive: true });
        await writeFile(cachePath, JSON.stringify(fresh, null, 2) + "\n");
      } catch { /* cache write is best-effort */ }
    }
    return { dir: fresh, source: "fresh" };
  }
  // Fresh failed or absent: try last-known-good.
  if (cachePath) {
    try {
      const cached = JSON.parse(await readFile(cachePath, "utf8"));
      const v = verifyDirectory(cached, pinnedSigner);
      if (v.ok) return { dir: cached, source: "cache", freshError: freshErr?.message };
    } catch { /* fall through */ }
  }
  throw new Error("no verifiable directory (fresh: " + (freshErr?.message || "none") + ", no valid cache)");
}

// --- selection ----------------------------------------------------------------
// Weighted-random pick over healthy gateways, excluding any the caller already
// tried this connection. `exclude` is a Set of onion addresses. Health is a
// runtime signal (see reportHealth); a gateway marked "down" is skipped unless it
// is the only option left, so the fleet degrades rather than dead-ending.

// Selection weight is gateway-attested, so the CLIENT must bound it too, not just the bootnode:
// the bootnode clamps `weight` at announce (packages/node/bootnode/server.mjs MAX_WEIGHT), but a STATIC signed
// directory or a compromised directory signer bypasses that path. Clamping here means no directory
// source can concentrate a member's traffic on one gateway (a deanonymization lever). Undefined/NaN
// weight defaults to 1; negative floors at 0; anything huge caps at MAX_WEIGHT.
export const MAX_WEIGHT = 1000;
function clampWeight(g) {
  const w = Number(g?.weight);
  return Number.isFinite(w) ? Math.max(0, Math.min(MAX_WEIGHT, w)) : 1;
}

export function pickGateway(dir, { exclude = new Set(), rng = Math.random } = {}) {
  const all = (dir.gateways || []).filter((g) => !exclude.has(g.onion));
  if (all.length === 0) return null;
  const healthy = all.filter((g) => g.health !== "down");
  const pool = healthy.length ? healthy : all; // last resort: try a "down" one
  const total = pool.reduce((s, g) => s + clampWeight(g), 0);
  if (total <= 0) return pool[Math.floor(rng() * pool.length)];
  let r = rng() * total;
  for (const g of pool) {
    r -= clampWeight(g);
    if (r < 0) return g;
  }
  return pool[pool.length - 1];
}

// Failover order: the weighted pick first, then the rest of the fleet as fallbacks
// in weighted order, so the shim can walk the list on dial timeout.
export function selectionOrder(dir, { rng = Math.random } = {}) {
  const order = [];
  const exclude = new Set();
  let g;
  while ((g = pickGateway(dir, { exclude, rng }))) {
    order.push(g);
    exclude.add(g.onion);
  }
  return order;
}

// Health-update hook. Mutates the in-memory dir entry so subsequent picks react to
// live latency/failures. Health is intentionally NOT persisted to the signed file
// (the file is the signer's view; this is the client's local view of liveness).
export function reportHealth(dir, onion, { ok, latencyMs } = {}) {
  const g = (dir.gateways || []).find((x) => x.onion === onion);
  if (!g) return;
  if (ok === false) {
    g._fails = (g._fails || 0) + 1;
    if (g._fails >= 2) g.health = "down";
  } else if (ok === true) {
    g._fails = 0;
    g.health = "up";
    if (typeof latencyMs === "number") {
      // simple EWMA so a persistently slow gateway loses weight over time
      g._latencyMs = g._latencyMs == null ? latencyMs : Math.round(0.7 * g._latencyMs + 0.3 * latencyMs);
    }
  }
}
