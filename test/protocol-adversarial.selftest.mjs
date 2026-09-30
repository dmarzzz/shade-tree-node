// T-TEST-21: ADVERSARIAL / TOTALITY suite for the two freshest wire surfaces —
//   (a) signed egress RECEIPTS   (packages/node/lib/receipt.mjs: buildReceipt / verifyReceipt / canonicalReceiptBytes)
//   (b) protocol VERSION NEGOTIATION (gateway.mjs acceptEnvelopeVersion + client selectProtoVersion)
//
// The authors' own selftests (packages/node/gateway/receipt.selftest.mjs, packages/node/gateway/version-negotiation.selftest.mjs)
// prove the happy path plus a few negatives. THIS file is the ATTACKER'S file: it drives ONLY the
// real, imported functions (never a reimplementation) through the failure modes a genuine defect
// would slip past — tamper, wrong-key, wrong-gateway, cross-protocol signature confusion, stale/
// future epochs, missing/extra fields, non-string/'' garbage, and the version-gate's totality +
// the guarantee that no (accepted or absent) version can strip the target binding.
//
// Every check below is one a REAL regression would fail. It byte-pins NOTHING (golden vectors are a
// separate task) — it asserts behavior: rejected-vs-accepted, the reason string, and never-throws.
//
//   node test/protocol-adversarial.selftest.mjs      (exit 0 = every adversarial case handled)
//
// No Tor, no sockets, no chain, no real Groth16 proof — pure logic + ed25519 over injected inputs.

import { createPublicKey, randomBytes } from "node:crypto";

import {
  RECEIPT_VERSION, RECEIPT_DOMAIN, canonicalReceiptBytes, buildReceipt, verifyReceipt,
} from "../packages/node/lib/receipt.mjs";
import {
  acceptEnvelopeVersion, PROTO_MIN, PROTO_MAX,
} from "../packages/node/gateway/gateway.mjs";
import {
  selectProtoVersion, CLIENT_PROTO_MIN, CLIENT_PROTO_MAX, CLIENT_PROTO_RANGE,
} from "../packages/node/client/shade-tree-client.mjs";
import {
  verifyEnvelope, currentEpoch, externalNullifierFor, calculateSignalHash, requestSignal,
} from "../packages/node/lib/rln.mjs";
import { buildAnnounce, canonicalAnnounceBytes, verifyAnnounce } from "../packages/node/bootnode/announce.mjs";
import { ed25519PrivateKey, ed25519Verify, pubkeyToOnion, onionToPubkey } from "../packages/node/lib/directory.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };
const section = (msg) => console.log(`\n${msg}`);

// Call `fn`; return { threw, value }. Used for the totality checks: a defect that lets a malformed
// input throw (instead of returning {ok:false}) is exactly what these must catch.
function guard(fn) {
  try { return { threw: false, value: fn() }; }
  catch (e) { return { threw: true, value: e }; }
}

// A deterministic onion identity: a random 32-byte ed25519 seed, the raw pubkey, and the v3 .onion
// that key commits to (same derivation as packages/node/bootnode/keygen.mjs / the authors' receipt selftest).
function makeOnionIdentity() {
  const seed = randomBytes(32).toString("hex");
  const der = createPublicKey(ed25519PrivateKey(seed)).export({ format: "der", type: "spki" });
  const pubHex = Buffer.from(der.subarray(der.length - 32)).toString("hex");
  return { seed, onion: pubkeyToOnion(pubHex), pubHex };
}

const gw = makeOnionIdentity();     // the gateway the client dialed
const other = makeOnionIdentity();  // a DIFFERENT gateway
const EPOCH = 424242n;

// ============================================================================
// (a) RECEIPTS — adversarial + totality
// ============================================================================
section("receipts: tamper / wrong-key / wrong-gateway");

{
  const base = buildReceipt({ onion: gw.onion, epoch: EPOCH, onionSeedHex: gw.seed });
  ok(verifyReceipt(base, { onion: gw.onion, epoch: EPOCH }).ok === true, "control: an honest receipt verifies");

  // TAMPER: flip each signed field independently; every flip must break the signature (or trip an
  // earlier structural check). A defect that recomputed the sig over the wrong fields would pass one.
  ok(verifyReceipt({ ...base, onion: other.onion }).reason !== undefined &&
     verifyReceipt({ ...base, onion: other.onion }).ok === false, "tampered onion (swapped to another gateway) fails");
  ok(verifyReceipt({ ...base, epoch: "999999" }, { epoch: 999999n }).reason === "bad-sig", "tampered epoch fails bad-sig (sig covers epoch)");
  ok(verifyReceipt({ ...base, ok: false }).reason === "not-success", "flipped ok:false is rejected not-success");
  ok(verifyReceipt({ ...base, v: RECEIPT_VERSION + 1 }).reason === `bad-version:${RECEIPT_VERSION + 1}`, "bumped version fails bad-version");
  ok(verifyReceipt({ ...base, sig: "00".repeat(64) }).reason === "bad-sig", "zeroed signature fails bad-sig");
  // Single-bit flip in the signature hex — the finest tamper.
  const bit = Buffer.from(base.sig, "hex"); bit[0] ^= 0x01;
  ok(verifyReceipt({ ...base, sig: bit.toString("hex") }, { onion: gw.onion, epoch: EPOCH }).reason === "bad-sig", "single-bit-flipped signature fails bad-sig");

  // WRONG KEY: claim gw.onion but sign with other's seed. The onion commits to gw's pubkey, so the
  // signature cannot verify — a forgery under a key the address does not name.
  const forged = buildReceipt({ onion: gw.onion, epoch: EPOCH, onionSeedHex: other.seed });
  ok(verifyReceipt(forged, { onion: gw.onion, epoch: EPOCH }).reason === "bad-sig", "signature from the WRONG onion key fails bad-sig");

  // WRONG GATEWAY: an honest receipt from `other`, but the client dialed `gw` and binds onion=gw.
  const otherRec = buildReceipt({ onion: other.onion, epoch: EPOCH, onionSeedHex: other.seed });
  ok(verifyReceipt(otherRec, { onion: gw.onion, epoch: EPOCH }).reason === "onion-mismatch", "valid receipt checked against a DIFFERENT gateway is onion-mismatch");
  // ...and even without the onion bind, it does NOT masquerade as gw's: its self-recovered key is other's.
  ok(verifyReceipt(otherRec).onion === other.onion, "a receipt is self-authenticating to its OWN onion, not the dialed one");
}

section("receipts: cross-protocol signature confusion (domain separation, both directions)");
{
  // The SAME onion key signs both an announce and a receipt. The receipt-only domain prefix must
  // make the two signatures non-interchangeable in BOTH directions.
  const ann = buildAnnounce({ onion: gw.onion, weight: 100, onionSeedHex: gw.seed, ts: Math.floor(Date.now() / 1000), nonce: "adv-nonce" });
  const rec = buildReceipt({ onion: gw.onion, epoch: EPOCH, onionSeedHex: gw.seed });

  ok(rec.sig !== ann.onionSig, "receipt sig and announce sig differ for the same key + onion");
  ok(canonicalReceiptBytes({ v: RECEIPT_VERSION, onion: gw.onion, epoch: EPOCH, ok: true })
       .subarray(0, RECEIPT_DOMAIN.length).toString("utf8") === RECEIPT_DOMAIN, "receipt canonical bytes carry the receipt-only domain prefix");

  // ANNOUNCE sig grafted onto a receipt shell -> must NOT verify as a receipt.
  ok(verifyReceipt({ v: RECEIPT_VERSION, onion: gw.onion, epoch: String(EPOCH), ok: true, sig: ann.onionSig }).reason === "bad-sig",
     "an ANNOUNCE onionSig does NOT verify as a receipt");
  // RECEIPT sig grafted onto an announce shell -> must NOT verify as an announce (drive REAL verifyAnnounce).
  const grafted = { ...ann, onionSig: rec.sig };
  const va = await verifyAnnounce(grafted, { now: grafted.ts });
  ok(va.ok === false && va.reason === "bad-onion-sig", "a RECEIPT sig does NOT verify as an announce (bad-onion-sig)");
  // Belt-and-suspenders at the raw ed25519 layer: each sig fails over the other's canonical bytes.
  const pub = onionToPubkey(gw.onion);
  ok(ed25519Verify(canonicalAnnounceBytes(ann), rec.sig, pub) === false, "receipt sig is invalid over announce canonical bytes");
  ok(ed25519Verify(canonicalReceiptBytes({ v: RECEIPT_VERSION, onion: gw.onion, epoch: EPOCH, ok: true }), ann.onionSig, pub) === false, "announce sig is invalid over receipt canonical bytes");
}

section("receipts: stale / future epoch freshness window");
{
  const rec = buildReceipt({ onion: gw.onion, epoch: EPOCH, onionSeedHex: gw.seed });
  ok(verifyReceipt(rec).ok === true, "no epoch bound => signature-only verify (freshness skipped)");
  ok(verifyReceipt(rec, { epoch: EPOCH }).ok === true, "same epoch is fresh");
  ok(verifyReceipt(rec, { epoch: EPOCH + 1n }).ok === true, "adjacent epoch (receipt behind) within default skew=1");
  ok(verifyReceipt(rec, { epoch: EPOCH - 1n }).ok === true, "adjacent epoch (receipt ahead) within default skew=1");
  // STALE: receipt 2 buckets behind current -> not fresh evidence.
  ok(verifyReceipt(rec, { epoch: EPOCH + 2n }).reason === `stale-epoch:${EPOCH}`, "receipt 2 buckets stale is rejected");
  // FUTURE: receipt 2 buckets AHEAD of current -> also rejected (window is symmetric |diff|).
  ok(verifyReceipt(rec, { epoch: EPOCH - 2n }).reason === `stale-epoch:${EPOCH}`, "receipt 2 buckets in the FUTURE is rejected");
  // A widened skew accepts a farther bucket; a zero skew accepts only the exact bucket.
  ok(verifyReceipt(rec, { epoch: EPOCH + 5n, epochSkew: 5 }).ok === true, "epochSkew=5 admits a 5-bucket gap");
  ok(verifyReceipt(rec, { epoch: EPOCH + 1n, epochSkew: 0 }).reason === `stale-epoch:${EPOCH}`, "epochSkew=0 admits only the exact bucket");
  // Freshness must be checked against the SIGNED epoch, not a caller-supplied one: a receipt whose
  // epoch field is edited to look fresh breaks the signature rather than sneaking through.
  ok(verifyReceipt({ ...rec, epoch: String(EPOCH + 2n) }, { epoch: EPOCH + 2n }).reason === "bad-sig", "editing the epoch to fake freshness breaks the sig, not the check");
}

section("receipts: missing / extra fields");
{
  const good = buildReceipt({ onion: gw.onion, epoch: EPOCH, onionSeedHex: gw.seed });
  ok(verifyReceipt({ onion: good.onion, epoch: good.epoch, ok: true, sig: good.sig }).reason === "bad-version:undefined", "missing v => bad-version:undefined");
  ok(verifyReceipt({ v: RECEIPT_VERSION, epoch: good.epoch, ok: true, sig: good.sig }).reason === "no-onion", "missing onion => no-onion");
  ok(verifyReceipt({ v: RECEIPT_VERSION, onion: good.onion, ok: true, sig: good.sig }).reason === "bad-epoch", "missing epoch => bad-epoch");
  ok(verifyReceipt({ v: RECEIPT_VERSION, onion: good.onion, epoch: good.epoch, sig: good.sig }).reason === "not-success", "missing ok => not-success");
  ok(verifyReceipt({ v: RECEIPT_VERSION, onion: good.onion, epoch: good.epoch, ok: true }).reason === "bad-sig", "missing sig => bad-sig");
  // EXTRA field: not covered by the signature and IGNORED by canonical bytes, so it neither breaks
  // verification nor leaks into the result (no data flows from an unauthenticated extra key).
  const extra = verifyReceipt({ ...good, evil: "smuggled-payload", nullifier: "deadbeef" }, { onion: gw.onion, epoch: EPOCH });
  ok(extra.ok === true, "an extra unsigned field is ignored (canonical bytes cover only {v,onion,epoch,ok})");
  ok(!("evil" in extra) && !("nullifier" in extra), "the extra field does NOT surface in the verify result");
}

section("receipts: non-canonical epoch encodings are rejected (no float/hex/leading-zero ambiguity)");
{
  const mk = (epoch) => {
    // Sign a receipt whose epoch is a non-canonical string, so the sig is valid but the FORMAT check
    // must still reject it (a canonical-string guard, not merely a signature check).
    const rec = { v: RECEIPT_VERSION, onion: gw.onion, epoch, ok: true };
    return { ...rec, sig: undefined }; // sig irrelevant: the epoch-format gate runs before sig verify
  };
  for (const badEpoch of ["007", "-1", "1e3", "0x10", "1.0", " 12", "12 ", "", "abc"]) {
    const r = verifyReceipt(mk(badEpoch));
    ok(r.ok === false && r.reason === "bad-epoch", `non-canonical epoch ${JSON.stringify(badEpoch)} => bad-epoch`);
  }
  ok(verifyReceipt(mk(12)).reason === "bad-epoch", "numeric (non-string) epoch => bad-epoch");
  // epoch "0" IS canonical: it reaches signature verification (fails there since our stub has no sig).
  ok(verifyReceipt(mk("0")).reason === "bad-sig", 'canonical epoch "0" passes the format gate (fails later at sig)');
}

section("receipts: TOTALITY — arbitrary garbage never throws, always {ok:false,reason}");
{
  const garbage = [
    null, undefined, 0, 1, -1, NaN, Infinity, "", "x", "not-an-object", true, false,
    [], [1, 2, 3], {}, { v: RECEIPT_VERSION }, { v: RECEIPT_VERSION, onion: 123 },
    { v: RECEIPT_VERSION, onion: "", epoch: "1", ok: true, sig: "zz" },
    { v: RECEIPT_VERSION, onion: "not-a-valid-onion.onion", epoch: "1", ok: true, sig: "00" },
    { v: RECEIPT_VERSION, onion: gw.onion, epoch: "1", ok: true, sig: {} },
    Object.create(null), () => {}, Symbol.iterator,
  ];
  for (const g of garbage) {
    const r = guard(() => verifyReceipt(g));
    ok(r.threw === false, `verifyReceipt(${describe(g)}) never throws`);
    ok(r.threw === false && r.value && r.value.ok === false && typeof r.value.reason === "string",
       `verifyReceipt(${describe(g)}) returns a clear {ok:false,reason:string}`);
  }
  // Options bag garbage must also be tolerated (an odd onion/epoch option cannot crash verification).
  ok(guard(() => verifyReceipt(buildReceipt({ onion: gw.onion, epoch: EPOCH, onionSeedHex: gw.seed }), { onion: 12345, epoch: {} })).threw === false,
     "garbage options ({onion:number,epoch:object}) never throw");
}

// ============================================================================
// (b) VERSION NEGOTIATION — adversarial + totality + downgrade-safety
// ============================================================================
section("version gate: out-of-range integers => unsupported-version (advertise range)");
{
  for (const v of [-5, -1, 0, 1, 2, 4, 5, 42, 1000, Number.MAX_SAFE_INTEGER]) {
    if (v >= PROTO_MIN && v <= PROTO_MAX) continue;
    const r = acceptEnvelopeVersion(v);
    ok(r.ok === false && r.reason === `unsupported-version:${v}`, `integer ${v} => unsupported-version:${v}`);
    ok(r.label === "unsupported-version", `integer ${v} carries the bounded metric label`);
    ok(r.proto && r.proto.min === PROTO_MIN && r.proto.max === PROTO_MAX, `integer ${v} reject advertises the gateway range`);
  }
}

section("version gate: non-integers => bad-version:<value-safe repr>, distinct from unsupported");
{
  // Well-formed-but-unsupported (integer) and garbage (non-integer) MUST use distinct reasons so a
  // bad encoding is never mistaken for a merely-old version.
  const cases = [
    ["3", 'bad-version:"3"'],
    [3.5, "bad-version:3.5"],
    [-0.1, "bad-version:-0.1"],
    [NaN, "bad-version:NaN"],
    [Infinity, "bad-version:Infinity"],
    [-Infinity, "bad-version:-Infinity"],
    [true, "bad-version:boolean"],
    [false, "bad-version:boolean"],
    [{}, "bad-version:object"],
    [{ v: 3 }, "bad-version:object"],
    [[3], "bad-version:object"],
    ["", 'bad-version:""'],
    ["3; DROP TABLE", 'bad-version:"3; DROP TABLE"'],       // repr is JSON-quoted -> no injection into logs/replies
    ["a-really-long-version-string-way-past-sixteen", 'bad-version:"a-really-long-ve"'], // repr truncates to 16 chars
  ];
  for (const [v, reason] of cases) {
    const r = acceptEnvelopeVersion(v);
    ok(r.ok === false && r.reason === reason, `${describe(v)} => ${reason}`);
    ok(r.label === "bad-version", `${describe(v)} carries the bad-version metric label`);
    ok(r.proto && r.proto.min === PROTO_MIN, `${describe(v)} reject advertises the range`);
  }
  // The two reasons are genuinely distinct for the same numeric-looking legacy version.
  ok(acceptEnvelopeVersion(3).reason !== acceptEnvelopeVersion("3").reason, "unsupported-version:3 and bad-version:\"3\" are distinct");
}

section("version gate: absent version is classified as legacy v3 and rejected");
{
  for (const absent of [undefined, null]) {
    const r = acceptEnvelopeVersion(absent);
    ok(r.ok === false && r.reason === "unsupported-version:3", `absent (${describe(absent)}) is classified as legacy v3 and rejected`);
  }
  // Classification is range-relative: an explicit legacy-only range still recognizes the old wire,
  // while the production v4 range rejects it cleanly rather than mis-parsing it.
  ok(acceptEnvelopeVersion(undefined, { min: 3, max: 3 }).ok === true, "a legacy-only diagnostic range recognizes an absent envelope as v3");
  // TOTALITY: the gate never throws on garbage input.
  for (const g of [Symbol("v"), () => {}, 12345678901234567890n]) {
    ok(guard(() => acceptEnvelopeVersion(g)).threw === false, `acceptEnvelopeVersion(${describe(g)}) never throws`);
  }
}

section("client selection: highest mutual / unknown => client max / disjoint => fail closed");
{
  ok(CLIENT_PROTO_MIN === 4 && CLIENT_PROTO_MAX === 4, "client range is {4} today");
  ok(CLIENT_PROTO_RANGE.min === CLIENT_PROTO_MIN && CLIENT_PROTO_RANGE.max === CLIENT_PROTO_MAX, "CLIENT_PROTO_RANGE mirrors the constants");

  // UNKNOWN gateway range -> optimistically emit our own max.
  for (const unknown of [null, undefined, {}, { min: 3 }, { max: 9 }, { min: null, max: null }, "garbage", 0, false]) {
    const r = selectProtoVersion(unknown);
    ok(r.ok === true && r.version === CLIENT_PROTO_MAX, `unknown gateway range ${describe(unknown)} => client max ${CLIENT_PROTO_MAX}`);
  }

  // HIGHEST mutual for overlapping ranges.
  const overlap = [
    [{ min: 3, max: 5 }, { min: 4, max: 6 }, 5],
    [{ min: 3, max: 7 }, { min: 5, max: 5 }, 5],
    [{ min: 1, max: 9 }, { min: 3, max: 6 }, 6],
    [{ min: 2, max: 2 }, { min: 2, max: 9 }, 2],
  ];
  for (const [client, gateway, want] of overlap) {
    const r = selectProtoVersion(gateway, client);
    ok(r.ok === true && r.version === want, `select highest mutual: client ${JSON.stringify(client)} x gateway ${JSON.stringify(gateway)} => v${want}`);
  }

  // DISJOINT ranges -> fail CLOSED (never silently downgrade to a version nobody accepts).
  const disjoint = [
    [{ min: 3, max: 3 }, { min: 4, max: 5 }],
    [{ min: 5, max: 6 }, { min: 3, max: 4 }],
    [{ min: 1, max: 2 }, { min: 8, max: 9 }],
  ];
  for (const [client, gateway] of disjoint) {
    const r = selectProtoVersion(gateway, client);
    ok(r.ok === false, `disjoint client ${JSON.stringify(client)} x gateway ${JSON.stringify(gateway)} fails closed`);
    ok(/^no-mutual-version:client=\d+-\d+,gateway=\d+-\d+$/.test(r.reason || ""), "disjoint reason is a precise no-mutual-version");
    ok(r.version === undefined, "a failed selection carries NO version (cannot be mistaken for a choice)");
  }
  // CLOSED-LEDGER round-trip: for every overlapping (client,gateway) grid cell the selected version
  // must be one the gateway then accepts — selection and gate agree, no version is picked-then-rejected.
  let grid = 0;
  for (let gMin = 1; gMin <= 6; gMin++) {
    for (let gMax = gMin; gMax <= 8; gMax++) {
      const client = { min: 1, max: 8 }, gateway = { min: gMin, max: gMax };
      const sel = selectProtoVersion(gateway, client);
      if (!sel.ok) continue;
      const acc = acceptEnvelopeVersion(sel.version, gateway);
      if (acc.ok && acc.version === sel.version) grid++;
      else { ok(false, `gateway ${JSON.stringify(gateway)} rejected its own selected v${sel.version}`); }
    }
  }
  ok(grid > 0, `every selected version across ${grid} overlapping grid cells is one the gateway accepts`);
}

section("downgrade cannot strip target binding (drive REAL verifyEnvelope)");
{
  // Build a proof-shape that passes the CHEAP pre-binding checks (fresh externalNullifier, share.x ==
  // ps.x) but OMITS the request nonce. The version gate accepts the version, yet verifyEnvelope — which
  // never inspects `v` — must still fail closed `unbound-target`. So no accepted/absent version can
  // downgrade its way past the target binding.
  const ep = currentEpoch();
  const extNull = externalNullifierFor(ep).toString();
  const x = calculateSignalHash(requestSignal("example.com:443", "the-nonce")).toString();
  const envMissingNonce = (v) => ({
    v, target: "example.com:443", // nonce intentionally omitted
    proof: { snarkProof: { publicSignals: { x, y: "0", externalNullifier: extNull, root: "0", nullifier: "0" } } },
    share: { x, y: "0" },
  });
  const envMissingTarget = (v) => ({
    v, nonce: "the-nonce", // target intentionally omitted
    proof: { snarkProof: { publicSignals: { x, y: "0", externalNullifier: extNull, root: "0", nullifier: "0" } } },
    share: { x, y: "0" },
  });

  for (const v of [4, PROTO_MAX]) {
    const gate = acceptEnvelopeVersion(v);
    ok(gate.ok === true, `gate accepts v=${describe(v)}`);
    const r1 = await verifyEnvelope(envMissingNonce(v), new Set());
    ok(r1.ok === false && r1.reason === "unbound-target", `missing nonce => unbound-target regardless of v=${describe(v)}`);
    const r2 = await verifyEnvelope(envMissingTarget(v), new Set());
    ok(r2.ok === false && r2.reason === "unbound-target", `missing target => unbound-target regardless of v=${describe(v)}`);
  }
  for (const v of [undefined, null, 3]) {
    const gate = acceptEnvelopeVersion(v);
    ok(gate.ok === false && gate.reason === "unsupported-version:3", `legacy v=${describe(v)} fails before proof verification`);
  }
  // The gate result exposes ONLY version-decision fields — no target/binding handle rides on it.
  ok(JSON.stringify(Object.keys(acceptEnvelopeVersion(4)).sort()) === JSON.stringify(["ok", "proto", "version"]),
     "the version gate result carries no target/binding fields (decides version only)");
  // verifyEnvelope truly ignores `v`: even an out-of-range/garbage version reaches the same binding
  // logic (it stops on the missing proof, never on the version) — which is WHY the gate must run first.
  ok((await verifyEnvelope({ v: 999 }, new Set())).reason === "no-proof", "verifyEnvelope ignores an out-of-range v (stops on no-proof)");
  ok((await verifyEnvelope({ v: "garbage" }, new Set())).reason === "no-proof", "verifyEnvelope ignores a garbage v (stops on no-proof)");
}

// A short, safe description of any value for the message strings above.
function describe(v) {
  if (v === null) return "null";
  if (v === undefined) return "undefined";
  if (typeof v === "bigint") return `${v}n`;
  if (typeof v === "symbol") return v.toString();
  if (typeof v === "function") return "function";
  if (typeof v === "string") return JSON.stringify(v.length > 20 ? v.slice(0, 20) + "…" : v);
  if (typeof v === "object") return Array.isArray(v) ? `[${v.length}]` : `{${Object.keys(v).join(",")}}`;
  return String(v);
}

console.log("");
if (failures) {
  console.log(`SELFTEST FAILED: ${failures} failing adversarial case(s)`);
} else {
  console.log("SELFTEST PASSED: all adversarial cases correctly handled");
}
process.exit(failures ? 1 : 0);
