// Selftest for the M-of-N THRESHOLD-signed directory (T-FEAT-9).
//
// The single-signer directory trusts one bootnode key: compromise it and every client's
// fleet VIEW can be steered (entries omitted/reordered — they still can't be sent a forged
// onion, onion-control is re-checked). The fix is to sign the directory with a k-of-n set
// of INDEPENDENT signers (composes with T-FEAT-1 federation: each bootnode is one signer),
// so no single key compromise produces an accepted directory.
//
// The extension is ADDITIVE: `signers`/`signatures`/`threshold` are OPTIONAL top-level
// fields, EXCLUDED from canonicalDirectoryBytes exactly like the single-sig
// `signer`/`signature`. So every signer signs the SAME canonical bytes, a directory
// carrying none of these fields takes the unchanged single-sig path, and the classic
// single-`signer` directory (the 1-of-1 case) verifies byte-for-byte as before.
//
// This proves: distinct-signer M-of-N counting (a duplicate signer counts once, an unpinned
// signer is ignored), the ordered adversarial reject reasons, that the whole surface is TOTAL
// (never throws on garbage), and that the single-sig path is untouched.
//
//   node packages/node/lib/directory-threshold.selftest.mjs
//
// Exit 0 = all invariants held. No network, no chain.

import { generateKeyPairSync } from "node:crypto";
import {
  pubkeyToOnion,
  signDirectory,
  signDirectoryThreshold,
  verifyDirectory,
  verifyDirectoryThreshold,
  canonicalDirectoryBytes,
} from "./directory.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

// raw ed25519 seed/pub hex from a fresh keypair (same helpers the other selftests use).
function newKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const priv = privateKey.export({ format: "der", type: "pkcs8" });
  const pub = publicKey.export({ format: "der", type: "spki" });
  return { priv: priv.subarray(priv.length - 32).toString("hex"), pub: pub.subarray(pub.length - 32).toString("hex") };
}
// A gateway entry whose pubkey is exactly the key encoded in its own v3 onion, so the
// onion<->pubkey binding holds and only the SIGNATURE dimension is under test.
function gw(weight = 100, health = "up") { const k = newKey(); return { onion: pubkeyToOnion(k.pub), pubkey: k.pub, weight, health }; }
function baseDir() { return { version: 1, issued: 123, gateways: [gw(100), gw(50)] }; }

// Assert a call is TOTAL: returns { ok:false }, never throws.
function total(fn, msg) {
  try { const r = fn(); ok(r && r.ok === false, `${msg} (returned ok:false, no throw)`); }
  catch (e) { ok(false, `${msg} — THREW ${e.message}`); }
}

function main() {
  const a = newKey(), b = newKey(), c = newKey();
  const outsider = newKey(); // never pinned, never signs a valid share the client trusts
  const pinnedAll = [a.pub, b.pub, c.pub];

  console.log("2-of-3 threshold, all three pinned:");
  {
    const signed = signDirectoryThreshold(baseDir(), [a.priv, b.priv, c.priv], 2);
    ok(signed.signers.length === 3 && signed.signatures.length === 3 && signed.threshold === 2, "signDirectoryThreshold emits 3 signers/signatures + threshold 2");
    ok(signed.signer === undefined && signed.signature === undefined, "no legacy single-sig signer/signature fields on a threshold directory");
    const r = verifyDirectory(signed, pinnedAll);
    ok(r.ok === true, "verifyDirectory accepts (>= 2 distinct pinned valid sigs)");
    ok(r.threshold === 2 && Array.isArray(r.signers) && r.signers.length >= 2, "reports the matched distinct signers + threshold");
    ok(verifyDirectoryThreshold(signed, pinnedAll).ok === true, "verifyDirectoryThreshold accepts directly too");
  }

  console.log("\nthreshold satisfied by EXACTLY the pinned set (3-of-3):");
  {
    const signed = signDirectoryThreshold(baseDir(), [a.priv, b.priv, c.priv], 3);
    ok(verifyDirectory(signed, pinnedAll).ok === true, "3-of-3 accepts when all three are pinned and sign");
    // Drop one from the pinned set -> only 2 distinct valid -> below 3.
    ok(verifyDirectory(signed, [a.pub, b.pub]).reason === "threshold-not-met:2/3", "3-of-3 with only 2 pinned -> threshold-not-met:2/3");
  }

  console.log("\nfewer than threshold distinct valid pinned sigs is rejected:");
  {
    const signed = signDirectoryThreshold(baseDir(), [a.priv, b.priv, c.priv], 2);
    const r = verifyDirectory(signed, [a.pub]); // only ONE pinned signer
    ok(r.ok === false && r.reason === "threshold-not-met:1/2", "only one pinned signer -> threshold-not-met:1/2");
    const r0 = verifyDirectory(signed, []); // nothing pinned
    ok(r0.ok === false && r0.reason === "threshold-not-met:0/2", "no pinned signers -> threshold-not-met:0/2");
  }

  console.log("\nunpinned signers are IGNORED (never count toward the threshold):");
  {
    // a + b + outsider all sign; client pins only {a,b,c}. outsider's valid sig must not count,
    // but a+b already meet threshold 2 -> accept.
    const signed = signDirectoryThreshold(baseDir(), [a.priv, b.priv, outsider.priv], 2);
    ok(verifyDirectory(signed, pinnedAll).ok === true, "two pinned + one unpinned meets 2-of-N (unpinned ignored, not fatal)");
    // Only the outsider signs; threshold 1 -> the single valid sig is unpinned -> rejected.
    const rogue = signDirectoryThreshold(baseDir(), [outsider.priv], 1);
    ok(verifyDirectory(rogue, pinnedAll).reason === "threshold-not-met:0/1", "an unpinned-only directory reaches 0 distinct pinned -> rejected");
  }

  console.log("\na single rogue signer cannot self-satisfy M-of-N (duplicate counted ONCE):");
  {
    // Same key signs twice: 2 signatures, but 1 DISTINCT signer. threshold 2 must NOT be met.
    const signed = signDirectoryThreshold(baseDir(), [a.priv, a.priv], 2);
    ok(signed.signatures[0] === signed.signatures[1], "the same key over the same bytes yields identical (deterministic) sigs");
    const r = verifyDirectory(signed, pinnedAll);
    ok(r.ok === false && r.reason === "threshold-not-met:1/2", "one key signing twice counts once -> threshold-not-met:1/2");
    // Distinct-key duplicate entries (a listed twice with the same sig) also collapse to one.
    const dup = { ...baseDir() };
    const s = signDirectoryThreshold(dup, [a.priv], 1);
    const collapsed = { ...s, signers: [a.pub, a.pub], signatures: [s.signatures[0], s.signatures[0]], threshold: 2 };
    ok(verifyDirectory(collapsed, pinnedAll).reason === "threshold-not-met:1/2", "a hand-crafted duplicate-signer array still counts once");
  }

  console.log("\nmalformed threshold structure is rejected TOTALLY (no throw):");
  {
    const good = signDirectoryThreshold(baseDir(), [a.priv, b.priv], 2);
    total(() => verifyDirectory({ ...good, threshold: 0 }, pinnedAll), "threshold 0");
    ok(verifyDirectory({ ...good, threshold: 0 }, pinnedAll).reason === "bad-threshold", "threshold 0 -> bad-threshold");
    ok(verifyDirectory({ ...good, threshold: 1.5 }, pinnedAll).reason === "bad-threshold", "non-integer threshold -> bad-threshold");
    ok(verifyDirectory({ ...good, threshold: "2" }, pinnedAll).reason === "bad-threshold", "string threshold -> bad-threshold");
    ok(verifyDirectory({ ...good, threshold: NaN }, pinnedAll).reason === "bad-threshold", "NaN threshold -> bad-threshold");
    ok(verifyDirectory({ ...good, signatures: "nope" }, pinnedAll).reason === "bad-signatures", "non-array signatures -> bad-signatures");
    ok(verifyDirectory({ ...good, signers: undefined }, pinnedAll).reason === "bad-signatures", "missing signers array -> bad-signatures");
    ok(verifyDirectory({ ...good, signatures: [good.signatures[0]] }, pinnedAll).reason === "bad-signatures", "length mismatch signers!=signatures -> bad-signatures");
    ok(verifyDirectory({ ...good, threshold: 3 }, pinnedAll).reason === "threshold-exceeds-signers", "threshold > N provided -> threshold-exceeds-signers");
    // A malformed ENTRY (null/number) is skipped, not fatal — the remaining valid pinned sigs still count.
    const withGarbage = { ...good, signers: [a.pub, b.pub, null, 42], signatures: [good.signatures[0], good.signatures[1], "zz", 7] };
    let garbageOk = false;
    try { garbageOk = verifyDirectory(withGarbage, pinnedAll).ok === true; } catch (e) { ok(false, `garbage entries THREW ${e.message}`); }
    ok(garbageOk, "two valid pinned sigs + garbage entries still meets 2-of-N (garbage skipped, no throw)");
  }

  console.log("\ntampered content or tampered binding is rejected:");
  {
    const signed = signDirectoryThreshold(baseDir(), [a.priv, b.priv, c.priv], 2);
    const flipped = { ...signed, issued: signed.issued + 1 }; // canonical bytes change -> sigs invalid
    ok(verifyDirectory(flipped, pinnedAll).reason === "threshold-not-met:0/2", "flipping `issued` invalidates every sig -> 0 distinct valid");
    // Enough sigs, but a gateway whose pubkey != its onion key.
    const badBind = signDirectoryThreshold({ version: 1, issued: 123, gateways: [{ ...gw(), pubkey: "00".repeat(32) }] }, [a.priv, b.priv], 2);
    const rb = verifyDirectory(badBind, pinnedAll);
    ok(rb.ok === false && rb.reason.startsWith("pubkey-onion-mismatch:"), "a valid-threshold directory with a mismatched gateway binding -> pubkey-onion-mismatch");
    const badOnion = signDirectoryThreshold({ version: 1, issued: 123, gateways: [{ onion: "not-an-onion", pubkey: "00".repeat(32) }] }, [a.priv, b.priv], 2);
    ok(verifyDirectory(badOnion, pinnedAll).reason.startsWith("bad-onion:"), "a malformed onion under threshold -> bad-onion");
  }

  console.log("\nallowlist niceties carry over (Set, 0x-prefix):");
  {
    const signed = signDirectoryThreshold(baseDir(), [a.priv, b.priv], 2);
    ok(verifyDirectory(signed, new Set(pinnedAll)).ok === true, "a Set works as the pinned allowlist");
    ok(verifyDirectory(signed, ["0x" + a.pub, "0x" + b.pub]).ok === true, "0x-prefixed pins match the bare-hex signers");
    // signers array may itself carry a 0x prefix from an operator export.
    const prefixed = { ...signed, signers: signed.signers.map((s) => "0x" + s) };
    ok(verifyDirectory(prefixed, pinnedAll).ok === true, "0x-prefixed signers in the directory still match a bare pinned set");
  }

  console.log("\n1-of-1 threshold + single-sig backward compatibility (path untouched):");
  {
    // Shared base so classic and 1-of-1 threshold cover the exact same gateways/canonical bytes.
    const shared = baseDir();
    // 1-of-1 threshold representation.
    const one = signDirectoryThreshold(shared, [a.priv], 1);
    ok(verifyDirectory(one, [a.pub]).ok === true, "1-of-1 threshold accepts its lone pinned signer");
    ok(verifyDirectory(one, [b.pub]).reason === "threshold-not-met:0/1", "1-of-1 rejects a directory whose signer is not pinned");

    // Classic single-sig directory: NO threshold fields -> takes the unchanged single-sig path.
    const classic = signDirectory({ ...shared, signer: a.pub }, a.priv);
    ok(classic.threshold === undefined && classic.signers === undefined, "signDirectory produces NO threshold fields");
    ok(verifyDirectory(classic, a.pub).ok === true, "classic single-sig directory still verifies (single-string pin)");
    ok(verifyDirectory(classic, [a.pub, b.pub]).ok === true, "classic single-sig verifies against an allowlist too");
    ok(verifyDirectory(classic, b.pub).reason === "signer-not-pinned", "classic single-sig still rejects a wrong pin via the single-sig reason");
    // The two representations sign identical canonical bytes.
    ok(canonicalDirectoryBytes(classic).equals(canonicalDirectoryBytes(one)), "classic and 1-of-1 threshold cover byte-identical canonical bytes");
  }

  console.log("\nverify surface is TOTAL on arbitrary garbage:");
  {
    for (const bad of [null, undefined, 42, "x", [], {}, { threshold: 2 }, { signers: [], signatures: [], threshold: 1 }, { threshold: 1, signers: [1], signatures: [1] }]) {
      total(() => verifyDirectoryThreshold(bad, pinnedAll), `verifyDirectoryThreshold(${JSON.stringify(bad)})`);
      total(() => verifyDirectory({ threshold: 2, signers: bad, signatures: bad }, pinnedAll), "verifyDirectory with garbage threshold arrays");
    }
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: directory-threshold selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
