// Task 52 — forward compatibility: a client verifies a directory whose capabilities carry fields it
// does not know, instead of rejecting the whole thing as `bad-signature`. This is the brick that hit
// every v0.7.0 client the first time the fleet signed `caps.sets` (task 51), and would hit v0.7.1 on
// the next new field. The fix: the SIGNED bytes preserve unknown capability fields verbatim
// (deterministically ordered), so verification is "over the bytes as signed"; INTERPRETATION still
// ignores unknown fields. This suite proves:
//   - NO-OP / additive: with no unknown field, canonicalCapsForBytes === canonicalCaps and the signed
//     directory bytes are byte-identical to the pre-fix path (golden vectors unchanged);
//   - FORWARD-COMPAT: a gateway whose caps carry a future unknown field (alongside a known one) signs a
//     valid capsSig and the directory verifies; selection/interpretation still ignore the field;
//   - PREVIOUS-RELEASE verifier: a verifier that canonicalizes caps the OLD way (dropping unknowns —
//     exactly what the shipped v0.7.0/v0.7.1 clients do) computes DIFFERENT bytes and REJECTS the same
//     directory. This reproduces the brick and shows the fix is load-bearing;
//   - UNFORGEABILITY tightened: injecting an unknown field into a signed entry's caps breaks the
//     onion-bound capsSig, so the directory is rejected (an intermediary cannot smuggle a field in);
//   - BOUNDS: too many / oversized / too-deep unknown fields drop to today's behavior, never throw.
//
//   node packages/node/lib/directory-compat.selftest.mjs

import {
  canonicalCaps, canonicalCapsForBytes, canonicalUnknownCaps, canonicalCapsBytes,
  canonicalDirectoryBytes, hasCaps, setsOf, signCaps, signDirectory, verifyDirectory,
  ed25519PubFromSeed, ed25519Verify, pubkeyToOnion,
  MAX_CAPS_UNKNOWN_KEYS, MAX_CAPS_UNKNOWN_BYTES,
} from "./directory.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };
const J = (x) => JSON.stringify(x);
const utf8 = (s) => new TextEncoder().encode(s);

// Keys: a gateway (its onion signs its caps) and a directory signer.
const gseed = "33".repeat(32);
const gpub = ed25519PubFromSeed(gseed);
const gonion = pubkeyToOnion(gpub);
const sseed = "44".repeat(32);
const spub = ed25519PubFromSeed(sseed);
const SET = "0x" + "a".repeat(40);

// The OLD verifier: builds the signed directory bytes the pre-fix way (caps through canonicalCaps,
// which DROPS unknown fields). This is what a shipped v0.7.0/v0.7.1 client does.
function oldCanonicalDirectoryBytes(dir) {
  const payload = {
    version: dir.version,
    issued: dir.issued,
    gateways: (dir.gateways || []).map((g) => {
      const e = { onion: g.onion, pubkey: g.pubkey, weight: g.weight, health: g.health };
      if (hasCaps(g.caps)) {
        e.caps = canonicalCaps(g.caps); // old: unknown fields dropped
        if (typeof g.capsSig === "string") e.capsSig = g.capsSig;
      }
      return e;
    }),
  };
  return utf8(JSON.stringify(payload));
}
const oldVerifies = (dir, signer) => ed25519Verify(oldCanonicalDirectoryBytes(dir), dir.signature, signer);

function signedDir(caps) {
  const capsSig = signCaps(gonion, caps, gseed);
  const dir = {
    version: 1, issued: 1000, signer: spub,
    gateways: [{ onion: gonion, pubkey: gpub, weight: 100, health: "up", caps, capsSig }],
  };
  return signDirectory(dir, sseed);
}

console.log("=== no-op / additive (no unknown field) ===");
{
  const known = { sets: [SET], region: "na", ports: [443] };
  ok(canonicalUnknownCaps(known) === null, "a caps with only known fields has no unknowns");
  ok(J(canonicalCapsForBytes(known)) === J(canonicalCaps(known)), "canonicalCapsForBytes === canonicalCaps when nothing is unknown");
  const signed = signedDir(known);
  ok(verifyDirectory(signed, spub).ok === true, "a known-only directory verifies");
  ok(oldVerifies(signed, spub) === true, "AND the previous-release verifier accepts it too (byte-identical) — additive");
}

console.log("=== forward-compat: an unknown future capability field ===");
{
  // `canopyWindow` is a field this build has never heard of; it rides alongside the known `sets`.
  const caps = { sets: [SET], canopyWindow: { min: 4, max: 4 }, futureFlag: true };
  ok(hasCaps(caps) === true, "an entry with an unknown field has caps (they must be signed)");
  const u = canonicalUnknownCaps(caps);
  ok(u !== null && J(Object.keys(u)) === J(["canopyWindow", "futureFlag"]), "unknowns are captured, key-sorted");
  ok(canonicalCaps(caps).canopyWindow === undefined, "INTERPRETATION still ignores the unknown field");
  ok(J(setsOf({ caps })) === J([SET]), "selection reads only the known `sets` field");

  const signed = signedDir(caps);
  const bytes = new TextDecoder().decode(canonicalDirectoryBytes(signed));
  ok(bytes.includes("canopyWindow") && bytes.includes("futureFlag"), "the unknown fields ride in the SIGNED bytes");
  ok(verifyDirectory(signed, spub).ok === true, "THIS build verifies the directory despite the unknown fields (no brick)");

  // The reproduction of tasks 51/52: the shipped client, which drops the unknown field, rebuilds
  // different bytes and rejects the exact same signed directory.
  ok(oldVerifies(signed, spub) === false, "a previous-release verifier (drops unknowns) REJECTS it — the brick the fix removes");
}

console.log("=== capsSig stays unforgeable: an injected unknown field is caught ===");
{
  const caps = { sets: [SET] };
  const signed = signedDir(caps);
  ok(verifyDirectory(signed, spub).ok === true, "baseline verifies");
  // A directory signer (no onion key) grafts an unknown field onto the entry's caps, re-signs the
  // DIRECTORY, but cannot re-sign the onion-bound capsSig.
  const tampered = JSON.parse(JSON.stringify(signed));
  tampered.gateways[0].caps.smuggled = { x: 1 };
  const resigned = signDirectory({ ...tampered, signature: undefined }, sseed);
  resigned.signer = spub;
  const res = verifyDirectory(resigned, spub);
  ok(res.ok === false && /bad-caps-sig/.test(res.reason || ""), "grafting a field breaks the onion-bound capsSig -> rejected");
}

console.log("=== bounds: unknown passthrough cannot balloon or recurse ===");
{
  const tooMany = {};
  for (let i = 0; i < MAX_CAPS_UNKNOWN_KEYS + 1; i++) tooMany["z" + i] = i;
  ok(canonicalUnknownCaps(tooMany) === null, `> ${MAX_CAPS_UNKNOWN_KEYS} unknown keys -> dropped`);

  const huge = { blob: "x".repeat(MAX_CAPS_UNKNOWN_BYTES + 10) };
  ok(canonicalUnknownCaps(huge) === null, `> ${MAX_CAPS_UNKNOWN_BYTES}B of unknowns -> dropped`);

  let deep = 0; let node = {};
  let cur = node; for (let i = 0; i < 12; i++) { cur.n = {}; cur = cur.n; deep++; }
  ok(canonicalUnknownCaps({ deep: node }) === null, "a too-deeply-nested unknown value -> dropped");

  const notFinite = { bad: Number.POSITIVE_INFINITY };
  ok(canonicalUnknownCaps(notFinite) === null, "a non-finite number -> dropped (never emitted)");

  // A dropped-unknowns caps still behaves exactly like today.
  ok(J(canonicalCapsForBytes(tooMany)) === J(canonicalCaps(tooMany)), "a bounds-tripping caps falls back to the known-only bytes");
}

console.log("=== key-order independence of preserved unknowns ===");
{
  const a = { sets: [SET], beta: { q: 1, a: 2 }, alpha: 9 };
  const b = { alpha: 9, sets: [SET], beta: { a: 2, q: 1 } }; // same data, different key order
  ok(J(canonicalCapsForBytes(a)) === J(canonicalCapsForBytes(b)), "unknown fields canonicalize independent of sender key order");
}

if (failures) { console.log(`\nFAIL: ${failures} directory-compat check(s) failed`); process.exit(1); }
console.log("\nPASS: directory forward-compat selftest");
