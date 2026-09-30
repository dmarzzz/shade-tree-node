// Self-test for signed egress success receipts (T-FEAT-13).
//
// Drives the pure packages/node/lib/receipt.mjs (buildReceipt / verifyReceipt) plus the gateway's
// receipt wiring (successAck / receiptsEnabled from packages/node/gateway/gateway.mjs) with NO onion
// process, NO sockets, NO Tor. Proves:
//
//   - a fresh receipt round-trips and verifies under the onion's OWN key (self-authenticating)
//   - it is bound to the dialed onion (onion-mismatch), the coarse epoch (stale-epoch), the
//     version, the ok flag, and is tamper-evident (any byte flip => bad-sig)
//   - DOMAIN SEPARATION: a receipt sig never validates as an announce sig, and an announce's
//     onionSig never validates as a receipt (cross-protocol confusion is impossible)
//   - PRIVACY: the receipt's ONLY keys are {v,onion,epoch,ok,sig}; it carries no nullifier,
//     member commitment, share, target, request nonce, or fine timestamp/counter
//   - ADDITIVE / DEFAULT-OFF: receiptsEnabled() is false by default, and successAck(null) is
//     byte-identical to the pre-receipt `{ ok: true }` reply; successAck(signer) adds a
//     verifiable receipt
//
// Run:  node packages/node/gateway/receipt.selftest.mjs

import assert from "node:assert/strict";
import { createPublicKey, randomBytes } from "node:crypto";
import { ed25519PrivateKey, pubkeyToOnion } from "../lib/directory.mjs";
import { buildAnnounce, canonicalAnnounceBytes } from "../bootnode/announce.mjs";
import {
  RECEIPT_VERSION, RECEIPT_DOMAIN, canonicalReceiptBytes, buildReceipt, verifyReceipt,
} from "../lib/receipt.mjs";
import { successAck, receiptsEnabled } from "./gateway.mjs";

let failures = 0;
function ok(name) { console.log("  PASS  " + name); }
function bad(name, e) { failures++; console.log("  FAIL  " + name + "  ::  " + (e && e.message || e)); }
async function test(name, fn) { try { await fn(); ok(name); } catch (e) { bad(name, e); } }

// A deterministic onion identity: a random 32-byte ed25519 seed, its raw pubkey, and the
// v3 .onion address that key commits to (same derivation as packages/node/bootnode/keygen.mjs).
function makeOnionIdentity() {
  const seed = randomBytes(32).toString("hex");
  const der = createPublicKey(ed25519PrivateKey(seed)).export({ format: "der", type: "spki" });
  const pubHex = Buffer.from(der.subarray(der.length - 32)).toString("hex");
  return { seed, onion: pubkeyToOnion(pubHex), pubHex };
}

const gw = makeOnionIdentity();
const other = makeOnionIdentity();
const EPOCH = 12345n;

console.log("egress success receipts (T-FEAT-13):");

await test("a fresh receipt round-trips and verifies under the onion's own key", () => {
  const r = buildReceipt({ onion: gw.onion, epoch: EPOCH, onionSeedHex: gw.seed });
  const v = verifyReceipt(r, { onion: gw.onion, epoch: EPOCH });
  assert.equal(v.ok, true, v.reason);
  assert.equal(v.onion, gw.onion);
  assert.equal(v.epoch, String(EPOCH));
  assert.equal(r.v, RECEIPT_VERSION);
  assert.equal(r.ok, true);
});

await test("verifies with no epoch bound (signature-only), and with the adjacent bucket", () => {
  const r = buildReceipt({ onion: gw.onion, epoch: EPOCH, onionSeedHex: gw.seed });
  assert.equal(verifyReceipt(r).ok, true, "no epoch arg => signature-only verify");
  assert.equal(verifyReceipt(r, { epoch: EPOCH + 1n }).ok, true, "adjacent epoch within default skew=1");
});

await test("bound to the dialed onion: a receipt for another gateway is onion-mismatch", () => {
  const r = buildReceipt({ onion: other.onion, epoch: EPOCH, onionSeedHex: other.seed });
  const v = verifyReceipt(r, { onion: gw.onion, epoch: EPOCH }); // client dialed gw, got other's receipt
  assert.equal(v.ok, false);
  assert.equal(v.reason, "onion-mismatch");
});

await test("a receipt signed by the WRONG key is bad-sig (onion commits to a different pubkey)", () => {
  // Claim gw.onion but sign with other's seed: the sig cannot verify under gw's onion key.
  const forged = buildReceipt({ onion: gw.onion, epoch: EPOCH, onionSeedHex: other.seed });
  const v = verifyReceipt(forged, { onion: gw.onion, epoch: EPOCH });
  assert.equal(v.ok, false);
  assert.equal(v.reason, "bad-sig");
});

await test("stale epoch is rejected as fresh evidence (freshness window)", () => {
  const r = buildReceipt({ onion: gw.onion, epoch: EPOCH, onionSeedHex: gw.seed });
  const v = verifyReceipt(r, { onion: gw.onion, epoch: EPOCH + 5n });
  assert.equal(v.ok, false);
  assert.match(v.reason, /^stale-epoch:/);
});

await test("tamper-evident: flipping epoch, ok, or version breaks verification", () => {
  const base = buildReceipt({ onion: gw.onion, epoch: EPOCH, onionSeedHex: gw.seed });
  assert.equal(verifyReceipt({ ...base, epoch: "99999" }, { epoch: 99999n }).reason, "bad-sig");
  assert.equal(verifyReceipt({ ...base, ok: false }).reason, "not-success");
  assert.equal(verifyReceipt({ ...base, v: 2 }).reason, "bad-version:2");
  assert.equal(verifyReceipt({ ...base, sig: "00".repeat(64) }).reason, "bad-sig");
});

await test("totality: malformed input never throws, always {ok:false,reason}", () => {
  for (const bad of [null, undefined, 42, "x", {}, { v: 1 }, { v: 1, onion: gw.onion, ok: true, epoch: "1e3" }]) {
    const v = verifyReceipt(bad);
    assert.equal(v.ok, false);
    assert.ok(typeof v.reason === "string");
  }
});

await test("DOMAIN SEPARATION: receipt bytes carry the receipt-only prefix and differ from announce bytes", () => {
  const rb = canonicalReceiptBytes({ v: RECEIPT_VERSION, onion: gw.onion, epoch: EPOCH, ok: true });
  assert.ok(rb.subarray(0, RECEIPT_DOMAIN.length).toString("utf8") === RECEIPT_DOMAIN, "prefixed with the receipt domain");
  const ab = canonicalAnnounceBytes({ v: 1, onion: gw.onion, weight: 100, ts: 1, nonce: "n" });
  assert.notEqual(rb.toString("hex"), ab.toString("hex"));
});

await test("DOMAIN SEPARATION: an announce's onionSig is NOT a valid receipt sig, and vice versa", () => {
  // Same onion key signs both. The domain prefix must make the signatures non-interchangeable.
  const ann = buildAnnounce({ onion: gw.onion, weight: 100, onionSeedHex: gw.seed, ts: 1, nonce: "n" });
  const rec = buildReceipt({ onion: gw.onion, epoch: EPOCH, onionSeedHex: gw.seed });
  // Graft the announce signature onto a receipt shell -> must fail (bytes include receipt domain).
  assert.equal(verifyReceipt({ v: RECEIPT_VERSION, onion: gw.onion, epoch: String(EPOCH), ok: true, sig: ann.onionSig }).reason, "bad-sig");
  // And the receipt sig differs from the announce sig for the same key.
  assert.notEqual(rec.sig, ann.onionSig);
});

await test("PRIVACY: the receipt exposes ONLY {v,onion,epoch,ok,sig} — no member/target/request data", () => {
  const r = buildReceipt({ onion: gw.onion, epoch: EPOCH, onionSeedHex: gw.seed });
  assert.deepEqual(Object.keys(r).sort(), ["epoch", "ok", "onion", "sig", "v"]);
  // Belt-and-suspenders: no forbidden field name appears anywhere in the serialized receipt.
  // The onion (random base32) and sig (random hex) are opaque values that can contain any short
  // substring by chance (a 56-char onion contains "ts" ~5% of the time -> flaky), so they are
  // masked out; every OTHER byte of the receipt is scanned.
  const blob = JSON.stringify({ ...r, onion: "<onion>", sig: "<sig>" }).toLowerCase();
  for (const forbidden of ["nullifier", "target", "share", "commitment", "member", "nonce", "secret", "ts", "identity", "x\":"]) {
    assert.ok(!blob.includes(forbidden), `receipt must not contain "${forbidden}"`);
  }
  // epoch is a COARSE bucket (a plain decimal string), not a fine wall-clock timestamp.
  assert.equal(r.epoch, String(EPOCH));
});

await test("ADDITIVE / DEFAULT-OFF: receiptsEnabled() is false and successAck(null) === { ok: true }", () => {
  assert.equal(receiptsEnabled(), false, "receipts default OFF (SHADE_TREE_RECEIPTS unset)");
  const ack = successAck(null);
  assert.deepEqual(ack, { ok: true }, "no signer => byte-identical to the pre-receipt reply");
  assert.deepEqual(Object.keys(ack), ["ok"], "no extra keys leak into the default ack");
});

await test("ADDITIVE: successAck(signer) adds a verifiable receipt; a throwing signer degrades to { ok: true }", () => {
  const signer = () => buildReceipt({ onion: gw.onion, epoch: EPOCH, onionSeedHex: gw.seed });
  const ack = successAck(signer);
  assert.equal(ack.ok, true);
  assert.equal(verifyReceipt(ack.receipt, { onion: gw.onion, epoch: EPOCH }).ok, true);
  // A signer that throws must NOT break egress — the ack falls back to the bare success reply.
  const bad = successAck(() => { throw new Error("kaboom"); });
  assert.deepEqual(bad, { ok: true });
});

console.log("");
if (failures) {
  console.log(`SELFTEST FAILED: ${failures} failing case(s)`);
  process.exit(1);
}
console.log("SELFTEST PASSED: all cases green");
