// Forward-compatibility guard for the signed Elder directory (task 52) — GENUINE cross-version.
//
// The brick we hit in production (tasks 51/52): a new SIGNED capability field (`caps.sets`, #243)
// made every already-released v0.7.0 client reject the directory with `bad-signature`. Root cause,
// in packages/node/lib/directory.mjs: the directory signature covers `canonicalDirectoryBytes`,
// which ran each entry's caps through `canonicalCaps` — a FIXED allow-list that DROPS fields it
// does not know. A client a version behind the Elder cannot reproduce the signed bytes of a
// directory that carries a field added after that client shipped, so the signature never matches.
//
// The fix (shipped here): verify "over the bytes AS SIGNED", preserving unknown capability fields
// (`canonicalCapsForBytes`/`canonicalUnknownCaps`), so a tolerant client no longer rejects a
// directory solely for carrying a signed field it does not recognize; interpretation still ignores
// the field. There is no way to retroactively teach an ALREADY-released client a future field, so
// the durable rollout is two-step (task 55): ship tolerant clients, THEN emit a new field.
//
// This suite is a REAL cross-version test, not a simulation: it imports the ACTUAL shipped v0.7.0
// verifier (test/fixtures/directory-v0.7.0.mjs, a byte-exact copy of packages/node/lib/directory.mjs
// at git tag v0.7.0) and runs it against the current directory format. It proves:
//   1. The v0.7.0 verifier REJECTS a current directory carrying `caps.sets` with `bad-signature` —
//      the exact incident operators saw on orbital-one (task 51). This is the load-bearing,
//      genuine previous-release-verifier assertion.
//   2. The CURRENT verifier ACCEPTS that same directory (the live canopy format).
//   3. The CURRENT (now-tolerant) verifier ACCEPTS a directory whose caps carry a field UNKNOWN to
//      THIS build, appended last — so the NEXT new field, once tolerant clients are adopted, no
//      longer bricks them. (The v0.7.0 verifier still rejects it, as it predates the fix.)
//   4. It PINS the set of signed cap fields as a review tripwire, so adding a field is a conscious
//      step through the task-55 rollout, not an accident on the wire.
//
// No network, no fleet, no secrets: pure canonicalization + ed25519 over fixtures.

import {
  canonicalCaps,
  canonicalDirectoryBytes,
  signDirectory,
  verifyDirectory,
  signCaps,
  pubkeyToOnion,
  ed25519PubFromSeed,
} from "../packages/node/lib/directory.mjs";

// The ACTUAL shipped v0.7.0 verifier (byte-exact copy of lib/directory.mjs @ tag v0.7.0). It
// predates both `caps.sets` and the forward-compat fix, so it is the real previous-release client
// that the live fleet bricked.
import { verifyDirectory as verifyDirectoryV070 } from "./fixtures/directory-v0.7.0.mjs";

let failures = 0;
function check(name, cond) {
  const ok = !!cond;
  if (!ok) failures++;
  console.log(`  ${ok ? "ok  " : "FAIL"} ${name}`);
}

// The exact set of capability fields that ride inside the directory signature today, in the
// order canonicalCaps appends them. Every name here is a field a prior release already knew, so
// it can reproduce the signed bytes. A NEW signed field means every installed client that predates
// it must first be TOLERANT (this fix) and adopted before the fleet emits the field (task 55).
// DO NOT add to this list to make a test pass — review the rollout first.
const SIGNED_CAP_FIELDS = Object.freeze([
  "ports",
  "region",
  "proto",
  "artifacts",
  "admits",
  "pay",
  "rate",
  "session",
  "draining",
  "sets",
]);

// A caps object exercising every signed field with a valid value, plus a junk field that
// canonicalCaps must drop from INTERPRETATION (the emitted key set is the signed cap-field list).
const maximalCaps = {
  ports: [443, 9050],
  region: "na",
  proto: { min: 4, max: 4 },
  artifacts: ["rln-v4"],
  admits: ["staked"],
  pay: {
    protocols: ["x402"],
    port: 443,
    asset: "0x" + "ab".repeat(20),
    chain: "eip155:11155111",
    tiers: { 8: "1000" },
  },
  rate: {
    scope: "grove-v4",
    window: "fixed",
    epochSeconds: 60,
    previousEpochsAccepted: 1,
    rootFreshnessSeconds: 300,
    payloadBytesPerSlot: 41943040,
  },
  session: { version: 1, classes: ["research-v1"] },
  draining: true,
  sets: ["0x" + "11".repeat(20)],
  // A field no release knows. canonicalCaps must still drop it from INTERPRETATION.
  zzFutureUnknownField: { anything: 1 },
};

console.log("=== signed cap-field allow-list (review tripwire) ===");
{
  const emitted = Object.keys(canonicalCaps(maximalCaps)).sort();
  const expected = [...SIGNED_CAP_FIELDS].sort();
  check(
    "canonicalCaps emits exactly the pinned signed cap-field allow-list (a new signed field trips this; see task 55)",
    emitted.length === expected.length && emitted.every((k, i) => k === expected[i]),
  );
  check(
    "INTERPRETATION ignores an unknown cap field (canonicalCaps drops it)",
    canonicalCaps(maximalCaps).zzFutureUnknownField === undefined,
  );
}

// Keys: a gateway (its onion signs its caps) and the pinned Elder signer.
const onionSeed = "cc".repeat(32);
const onionPub = ed25519PubFromSeed(onionSeed);
const onion = pubkeyToOnion(onionPub);
const elderSeed = "ab".repeat(32);
const elderPub = ed25519PubFromSeed(elderSeed);

// A directory exactly as the live fleet serves it: a gateway advertising caps.sets, onion-bound
// capsSig, signed by the pinned Elder signer.
function signedDirWith(caps) {
  const capsSig = signCaps(onion, caps, onionSeed);
  const gateway = { onion, pubkey: onionPub, weight: 100, health: "up", caps, capsSig };
  const unsigned = { version: 1, issued: 1000, gateways: [gateway], signer: elderPub };
  return signDirectory(unsigned, elderSeed);
}

console.log("=== genuine cross-version: v0.7.0 verifier vs the current fleet format ===");
{
  const setsDir = signedDirWith({ sets: ["0x" + "11".repeat(20)] });

  check(
    "the CURRENT client verifies the current fleet format (a directory carrying caps.sets)",
    verifyDirectory(setsDir, elderPub).ok === true,
  );

  // The exact production incident: the shipped v0.7.0 client drops caps.sets (unknown to it),
  // omits the caps from the bytes it reconstructs, and rejects the Elder signature.
  const v070 = verifyDirectoryV070(setsDir, elderPub);
  check(
    "the ACTUAL v0.7.0 verifier REJECTS a caps.sets directory with bad-signature (the task-51 brick, reproduced cross-version)",
    v070.ok === false && v070.reason === "bad-signature",
  );
}

console.log("=== forward-compat for the NEXT field: a field unknown to THIS build ===");
{
  // `canopyWindow` is a field THIS build has never heard of; it rides alongside the known `sets`,
  // appended last by the unknown-field passthrough. A future fleet emitting it (after tolerant
  // clients are adopted) produces these same bytes.
  const futureDir = signedDirWith({
    sets: ["0x" + "11".repeat(20)],
    canopyWindow: { min: 4, max: 4 },
    futureFlag: true,
  });
  const bytes = new TextDecoder().decode(canonicalDirectoryBytes(futureDir));
  check(
    "the unknown fields ride in the SIGNED bytes (preserved, key-sorted after known fields)",
    bytes.includes('"sets":["0x1111111111111111111111111111111111111111"],"canopyWindow":{"max":4,"min":4},"futureFlag":true'),
  );
  check(
    "the CURRENT (tolerant) client verifies a directory carrying a field it does not know — no brick",
    verifyDirectory(futureDir, elderPub).ok === true,
  );
  check(
    "INTERPRETATION still ignores the unknown field (canonicalCaps reads only known `sets`)",
    JSON.stringify(canonicalCaps(futureDir.gateways[0].caps).sets) ===
      JSON.stringify(["0x" + "11".repeat(20)]) &&
      canonicalCaps(futureDir.gateways[0].caps).canopyWindow === undefined,
  );
  // The v0.7.0 verifier predates the fix, so it still rejects (expected: it must be replaced, not
  // taught, which is exactly why the rollout is two-step).
  check(
    "the v0.7.0 verifier still REJECTS the unknown-field directory (it predates the fix; task 55)",
    verifyDirectoryV070(futureDir, elderPub).ok === false,
  );
}

if (failures) {
  console.log(`\nFAIL: directory forward-compat selftest (${failures} failed)`);
  process.exit(1);
}
console.log("\nPASS: directory forward-compat selftest (genuine cross-version against v0.7.0)");
