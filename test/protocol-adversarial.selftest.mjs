// T-TEST-21: ADVERSARIAL / TOTALITY suite for the signed egress RECEIPTS wire surface
// (packages/node/lib/receipt.mjs: buildReceipt / verifyReceipt / canonicalReceiptBytes). The
// node's version gate, once covered here too, is tested in crates/shadenet-proto.
//
// The authors' own selftests prove the happy path plus a few negatives. THIS file is the ATTACKER'S file: it drives ONLY the
// real, imported functions (never a reimplementation) through the failure modes a genuine defect
// would slip past — tamper, wrong-key, wrong-gateway, cross-protocol signature confusion, stale/
// future epochs, missing/extra fields, non-string/'' garbage.
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
