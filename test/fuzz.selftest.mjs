// T-TEST-2: fuzz / property tests over every surface that takes UNTRUSTED input. The bar is
// not "parses the good case" (other selftests do that) but "cannot be made to crash, hang, or
// return garbage by hostile bytes", plus a few algebraic properties that must hold for ALL input.
//
//   node test/fuzz.selftest.mjs                 (default seed + iteration count)
//   SHADE_TREE_FUZZ_SEED=123 SHADE_TREE_FUZZ_N=20000 node test/fuzz.selftest.mjs
//
// Seeded (mulberry32) so any failure is reproducible: the seed is printed and can be replayed.

import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { onionToPubkey, pubkeyToOnion, canonicalDirectoryBytes, verifyDirectory } from "../packages/node/lib/directory.mjs";
import { parseHttp } from "../packages/node/bootnode/fetch.mjs";
import { verifyAnnounce } from "../packages/node/bootnode/announce.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const CORPUS_PATH = join(HERE, "..", "testdata", "corpus", "regressions.json");

const SEED = Number(process.env.SHADE_TREE_FUZZ_SEED || 0x9e3779b9);
const N = Number(process.env.SHADE_TREE_FUZZ_N || 5000);

let failures = 0;
const fail = (msg) => { console.log(`  FAIL ${msg}`); failures++; };
const ok = (msg) => console.log(`  ok   ${msg}`);

// mulberry32: tiny deterministic PRNG so a failing case is reproducible from the seed.
function mulberry32(a) {
  return function () {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rnd = mulberry32(SEED);
const randInt = (n) => Math.floor(rnd() * n);
function randStr(maxLen) {
  const len = randInt(maxLen);
  let s = "";
  const alphabets = ["abcdefghijklmnopqrstuvwxyz234567", "0123456789abcdef", "\x00\n\r .:/onABZ!", "abcdefghijklmnopqrstuvwxyz"];
  const al = alphabets[randInt(alphabets.length)];
  for (let i = 0; i < len; i++) s += al[randInt(al.length)];
  return s;
}
function randBytes(maxLen) { return randomBytes(randInt(maxLen)); }
// A grab-bag random JS value, for object-shaped surfaces.
function randVal(depth = 0) {
  const k = randInt(depth > 2 ? 6 : 9);
  switch (k) {
    case 0: return randStr(40);
    case 1: return randInt(1e9) - 5e8;
    case 2: return rnd() < 0.5;
    case 3: return null;
    case 4: return undefined;
    case 5: return randBytes(20).toString("hex");
    case 6: return Array.from({ length: randInt(4) }, () => randVal(depth + 1));
    default: { const o = {}; for (let i = randInt(4); i > 0; i--) o[randStr(8)] = randVal(depth + 1); return o; }
  }
}

// Run a body many times; on the first throw, print the seed + iteration for replay.
function fuzz(label, body) {
  try {
    for (let i = 0; i < N; i++) body(i);
    ok(`${label} (${N} iters, no crash/hang/garbage)`);
  } catch (e) {
    fail(`${label}: iteration threw uncaught -> ${e.message} (seed=${SEED}; set SHADE_TREE_FUZZ_SEED=${SEED} to replay)`);
  }
}

// ---------------------------------------------------------------------------
// T-TEST-15: fuzz REGRESSION CORPUS.
//
// A PERSISTENT, curated set of known-tricky / adversarial inputs (testdata/corpus/
// regressions.json), one per real past finding, replayed on EVERY run. This phase
// runs FIRST and FAST (before the random fuzzing below), so any crashing/edge input
// a fuzzer or an audit ever found is caught immediately and DETERMINISTICALLY -- it
// never has to be re-discovered by the seeded random walk. The random phases still
// run after, to keep finding NEW cases.
//
// --- ADD-PROCEDURE: when the random fuzzer (or an audit) finds a NEW bad input ------
// The random phases print the SEED on failure, so you can reproduce the offending
// value. Turn it into a permanent regression by appending ONE entry to the `entries`
// array in testdata/corpus/regressions.json, using a STABLE serialization:
//
//   surface: which function it hits -- one of
//            onionToPubkey | parseHttp | verifyDirectory | verifyAnnounce | canonicalDirectoryBytes
//   the input, serialized per surface:
//     onionToPubkey            -> "input": "<the onion string>"
//     parseHttp                -> "inputHttp": { "encoding": "utf8"|"hex"|"base64", "data": "<bytes>" }
//     verifyDirectory          -> "input": <the directory object>, "pinnedSigner": <hex string | array>
//     verifyAnnounce           -> "input": <the announce object>, "opts": { ... }   (opts optional)
//     canonicalDirectoryBytes  -> "inputA": <dir>, "inputB": <dir>   (must serialize identically)
//   expect.outcome, one of:
//     "throw"       -- the call MUST throw (that IS rejection; used for onionToPubkey/parseHttp)
//     "decode"      -- onionToPubkey returns a 64-hex key ("hex": "<expected>" to pin it)
//     "parse"       -- parseHttp returns a value ("equals": <value> to deep-compare)
//     "reject"      -- returns {ok:false} WITHOUT throwing ("reason" exact, or "reasonPrefix")
//     "equal-bytes" -- canonicalDirectoryBytes(inputA) equals canonicalDirectoryBytes(inputB)
//   plus a human "id" and a "finding" note citing the loop/audit it came from.
//
// The point: a total-ness bug (an input that THREW where it should have returned
// ok:false, e.g. the loop-11 non-string `signer`) becomes a fast permanent regression
// tagged with expect.outcome:"reject". No auto-persistence -- just this replay + the
// documented append above. There is a serializeBytes() helper below to hexify a Buffer.
// ---------------------------------------------------------------------------

// Turn a Buffer into the {encoding:"hex", data} shape used by parseHttp corpus entries.
export function serializeBytes(buf) {
  return { encoding: "hex", data: Buffer.from(buf).toString("hex") };
}

function corpusBytes(inputHttp) {
  const enc = inputHttp.encoding === "base64" ? "base64" : inputHttp.encoding === "hex" ? "hex" : "utf8";
  return Buffer.from(inputHttp.data, enc);
}

// Assert a total surface (verifyDirectory/verifyAnnounce) rejected as documented: it
// returned {ok:false} WITHOUT throwing, and matched the pinned reason if one is given.
function checkReject(label, r, expect) {
  if (typeof r !== "object" || r === null || typeof r.ok !== "boolean") return fail(`corpus ${label}: non-{ok} result ${JSON.stringify(r)}`);
  if (r.ok !== false) return fail(`corpus ${label}: expected ok:false, got ${JSON.stringify(r)}`);
  if (expect.reason !== undefined && r.reason !== expect.reason) return fail(`corpus ${label}: reason ${JSON.stringify(r.reason)} !== ${JSON.stringify(expect.reason)}`);
  if (expect.reasonPrefix !== undefined && !String(r.reason).startsWith(expect.reasonPrefix)) return fail(`corpus ${label}: reason ${JSON.stringify(r.reason)} does not start with ${JSON.stringify(expect.reasonPrefix)}`);
  ok(`corpus ${label} (reject${expect.reason ? " " + expect.reason : expect.reasonPrefix ? " " + expect.reasonPrefix + "*" : ""})`);
}

// Replay one corpus entry against its surface, asserting the documented outcome.
// A THROW where the entry does not expect one is itself a FAILURE (that is exactly the
// total-ness regression class this corpus guards -- e.g. the loop-11 non-string signer).
async function replayEntry(e) {
  const label = e.id;
  const out = e.expect.outcome;
  switch (e.surface) {
    case "onionToPubkey": {
      let res, threw = null;
      try { res = onionToPubkey(e.input); } catch (err) { threw = err; }
      if (out === "throw") return threw ? ok(`corpus ${label} (throw: ${threw.message})`) : fail(`corpus ${label}: expected throw, returned ${JSON.stringify(res)}`);
      if (out === "decode") {
        if (threw) return fail(`corpus ${label}: expected decode, threw ${threw.message}`);
        if (!/^[0-9a-f]{64}$/.test(res)) return fail(`corpus ${label}: not a 64-hex key: ${JSON.stringify(res)}`);
        if (e.expect.hex !== undefined && res !== e.expect.hex) return fail(`corpus ${label}: decoded ${res} !== ${e.expect.hex}`);
        return ok(`corpus ${label} (decode)`);
      }
      return fail(`corpus ${label}: unsupported outcome ${out} for onionToPubkey`);
    }
    case "parseHttp": {
      const buf = corpusBytes(e.inputHttp);
      let res, threw = null;
      try { res = parseHttp(buf); } catch (err) { threw = err; }
      if (out === "throw") return threw ? ok(`corpus ${label} (throw: ${threw.message})`) : fail(`corpus ${label}: expected throw, returned ${JSON.stringify(res)}`);
      if (out === "parse") {
        if (threw) return fail(`corpus ${label}: expected parse, threw ${threw.message}`);
        if (e.expect.equals !== undefined && JSON.stringify(res) !== JSON.stringify(e.expect.equals)) return fail(`corpus ${label}: parsed ${JSON.stringify(res)} !== ${JSON.stringify(e.expect.equals)}`);
        return ok(`corpus ${label} (parse)`);
      }
      return fail(`corpus ${label}: unsupported outcome ${out} for parseHttp`);
    }
    case "verifyDirectory": {
      let r, threw = null;
      try { r = verifyDirectory(e.input, e.pinnedSigner); } catch (err) { threw = err; }
      if (threw) return fail(`corpus ${label}: verifyDirectory threw (total-ness regression!) -> ${threw.message}`);
      if (out === "reject") return checkReject(label, r, e.expect);
      return fail(`corpus ${label}: unsupported outcome ${out} for verifyDirectory`);
    }
    case "verifyAnnounce": {
      let r, threw = null;
      try { r = await verifyAnnounce(e.input, e.opts || {}); } catch (err) { threw = err; }
      if (threw) return fail(`corpus ${label}: verifyAnnounce threw (total-ness regression!) -> ${threw.message}`);
      if (out === "reject") return checkReject(label, r, e.expect);
      return fail(`corpus ${label}: unsupported outcome ${out} for verifyAnnounce`);
    }
    case "canonicalDirectoryBytes": {
      let threw = null, eq = false;
      try { eq = canonicalDirectoryBytes(e.inputA).equals(canonicalDirectoryBytes(e.inputB)); } catch (err) { threw = err; }
      if (threw) return fail(`corpus ${label}: canonicalDirectoryBytes threw -> ${threw.message}`);
      if (out === "equal-bytes") return eq ? ok(`corpus ${label} (equal-bytes)`) : fail(`corpus ${label}: canonical bytes diverged`);
      return fail(`corpus ${label}: unsupported outcome ${out} for canonicalDirectoryBytes`);
    }
    default:
      return fail(`corpus ${label}: unknown surface ${e.surface}`);
  }
}

async function replayCorpus() {
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(CORPUS_PATH, "utf8"));
  } catch (e) {
    return fail(`corpus load failed (${CORPUS_PATH}): ${e.message}`);
  }
  const entries = manifest.entries || [];
  if (entries.length === 0) return fail("corpus is empty -- expected curated regression entries");
  console.log(`corpus: replaying ${entries.length} curated regression${entries.length === 1 ? "" : "s"} (deterministic, runs first)`);
  for (const e of entries) await replayEntry(e);
  console.log("");
}

async function main() {
  console.log(`fuzz seed=${SEED} iters=${N}\n`);

  // 0. CORPUS phase (T-TEST-15): replay the curated known-tricky inputs FIRST and FAST,
  //    so a regression is caught immediately and deterministically before the random walk.
  await replayCorpus();

  // 1. onionToPubkey: hostile strings must throw (rejected) or return a 64-hex key. Never hang,
  //    never return anything else. A throw is FINE (that is rejection); an escape is not.
  fuzz("onionToPubkey rejects or cleanly decodes arbitrary strings", () => {
    const s = rnd() < 0.5 ? randStr(70) : randStr(70) + ".onion";
    let out;
    try { out = onionToPubkey(s); } catch { return; } // rejection is the expected path
    if (typeof out !== "string" || !/^[0-9a-f]{64}$/.test(out)) throw new Error(`bad accept for ${JSON.stringify(s)} -> ${out}`);
  });

  // 2. Round-trip property: for ALL valid 32-byte pubkeys, onionToPubkey(pubkeyToOnion(pub)) === pub,
  //    and the onion an accepted address yields must re-encode to that same address.
  fuzz("pubkey<->onion round-trip holds for all valid keys", () => {
    const pub = randomBytes(32).toString("hex");
    const onion = pubkeyToOnion(pub);
    if (onionToPubkey(onion) !== pub) throw new Error(`round-trip broke for ${pub}`);
    if (pubkeyToOnion(onionToPubkey(onion)) !== onion) throw new Error(`address not idempotent for ${onion}`);
  });

  // 3. parseHttp: hostile byte buffers must throw or return a parsed value; never hang/escape.
  fuzz("parseHttp rejects or parses arbitrary bytes", () => {
    const buf = rnd() < 0.5 ? randBytes(200) : Buffer.from(`HTTP/1.1 ${200 + randInt(400)} X\r\n${randStr(30)}\r\n\r\n${randStr(50)}`);
    try { parseHttp(buf); } catch { /* rejection is fine */ }
  });

  // 4. verifyDirectory: any object must yield {ok:boolean}. Garbage must be ok:false, never a throw,
  //    and never ok:true (only a genuinely valid signed+bound directory can be true, which random
  //    input effectively never is).
  fuzz("verifyDirectory total on arbitrary objects (garbage => ok:false, never throws)", () => {
    const dir = rnd() < 0.5 ? randVal() : { version: randInt(3), issued: randInt(1e9), gateways: Array.from({ length: randInt(3) }, () => ({ onion: randStr(62), pubkey: randBytes(32).toString("hex"), weight: randInt(200), health: "up" })), signer: rnd() < 0.2 ? randVal() : randBytes(32).toString("hex"), signature: rnd() < 0.2 ? randVal() : randBytes(64).toString("hex") };
    const r = verifyDirectory(dir, randBytes(32).toString("hex"));
    if (typeof r !== "object" || typeof r.ok !== "boolean") throw new Error(`non-{ok} result: ${JSON.stringify(r)}`);
    if (r.ok) throw new Error(`random directory verified as OK (should be impossible): ${JSON.stringify(dir).slice(0, 120)}`);
  });

  // 5. canonicalDirectoryBytes permutation invariance: the SIGNED bytes must not depend on key order
  //    or unsigned extra fields. This is what makes a signature independent of JSON formatting.
  fuzz("canonicalDirectoryBytes is permutation/extra-field invariant", () => {
    const gws = Array.from({ length: randInt(4) }, () => ({ onion: randStr(20), pubkey: randStr(20), weight: randInt(200), health: rnd() < 0.5 ? "up" : "down" }));
    const a = { version: 1, issued: 42, gateways: gws.map((g) => ({ onion: g.onion, pubkey: g.pubkey, weight: g.weight, health: g.health })) };
    // same logical value, shuffled key order + junk unsigned fields
    const b = { gateways: gws.map((g) => ({ health: g.health, note: randStr(6), weight: g.weight, pubkey: g.pubkey, onion: g.onion })), issued: 42, version: 1, extra: randVal() };
    if (!canonicalDirectoryBytes(a).equals(canonicalDirectoryBytes(b))) throw new Error("canonical bytes diverged under permutation");
  });

  // 6. verifyAnnounce (async, total): arbitrary objects must resolve to {ok:boolean}, garbage => false,
  //    never an uncaught rejection. (No isStaked injected, so stake is not consulted.)
  {
    let bad = 0;
    for (let i = 0; i < Math.min(N, 1500); i++) {
      const rec = rnd() < 0.5 ? randVal() : { v: 1, onion: randStr(62), weight: randInt(200), ts: Math.floor(Date.now() / 1000) + randInt(500) - 250, nonce: randBytes(16).toString("hex"), onionSig: randBytes(64).toString("hex") };
      let r;
      try { r = await verifyAnnounce(rec, {}); } catch (e) { bad++; if (bad <= 1) fail(`verifyAnnounce threw on ${JSON.stringify(rec).slice(0, 100)}: ${e.message} (seed=${SEED})`); continue; }
      if (typeof r !== "object" || typeof r.ok !== "boolean") { bad++; if (bad <= 1) fail(`verifyAnnounce non-{ok}: ${JSON.stringify(r)}`); continue; }
      if (r.ok) { bad++; if (bad <= 1) fail(`random announce verified OK (impossible): ${JSON.stringify(rec).slice(0, 100)}`); }
    }
    if (bad === 0) ok(`verifyAnnounce total on arbitrary objects (garbage => ok:false, never throws)`);
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: fuzz selftest (${failures} failure${failures === 1 ? "" : "s"}, seed=${SEED})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
