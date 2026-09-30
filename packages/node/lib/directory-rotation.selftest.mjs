// Selftest for verifyDirectory's SIGNER-ROTATION overlap set (T-HARD-5).
//
// The single-pin model is a flag day: rotating the directory signer breaks every client
// that has not updated in lockstep. The fix is an overlap window — a client pins a SET of
// accepted signers {old, new} so the bootnode can rotate its signing key with no downtime,
// then drop the old one once everyone has propagated. This proves the set is a real
// ALLOWLIST (any member signs a valid directory, an unpinned signer never does) and that
// the single-string path is byte-for-byte the old behavior.
//
//   node packages/node/lib/directory-rotation.selftest.mjs
//
// Exit 0 = all invariants held. No network, no chain.

import { generateKeyPairSync } from "node:crypto";
import { pubkeyToOnion, signDirectory, verifyDirectory } from "./directory.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

// raw ed25519 seed/pub hex from a fresh keypair (same helpers the other selftests use).
function newKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const priv = privateKey.export({ format: "der", type: "pkcs8" });
  const pub = publicKey.export({ format: "der", type: "spki" });
  return { priv: priv.subarray(priv.length - 32).toString("hex"), pub: pub.subarray(pub.length - 32).toString("hex") };
}
// A gateway entry whose pubkey is exactly the key encoded in its own v3 onion, so
// verifyDirectory's onion<->pubkey binding holds and only the SIGNER dimension is under test.
function gw(weight = 100, health = "up") { const k = newKey(); return { onion: pubkeyToOnion(k.pub), pubkey: k.pub, weight, health }; }

// Build a directory declaring `signer` and signed by `signerKey.priv`.
function makeSigned(signerKey) {
  const gws = [gw(100), gw(50)];
  const base = { version: 1, issued: 123, gateways: gws.map(({ onion, pubkey, weight, health }) => ({ onion, pubkey, weight, health })), signer: signerKey.pub };
  return signDirectory(base, signerKey.priv);
}

function main() {
  const oldK = newKey();
  const newK = newKey();
  const thirdK = newKey(); // an unpinned signer — must NEVER be accepted
  const overlap = [oldK.pub, newK.pub]; // client pins the overlap set {old, new}

  console.log("overlap set accepts either pinned signer:");
  {
    const signedOld = makeSigned(oldK);
    const rOld = verifyDirectory(signedOld, overlap);
    ok(rOld.ok, "directory signed by OLD verifies against {old,new}");
    ok(rOld.signer === oldK.pub.toLowerCase(), "verifyDirectory reports OLD as the matched signer");

    const signedNew = makeSigned(newK);
    const rNew = verifyDirectory(signedNew, overlap);
    ok(rNew.ok, "directory signed by NEW verifies against {old,new}");
    ok(rNew.signer === newK.pub.toLowerCase(), "verifyDirectory reports NEW as the matched signer");
  }

  console.log("\nthe set is an allowlist, not trust-any-signer:");
  {
    // OLD-signed directory against {new} ONLY: declared signer is not pinned (or, absent that
    // guard, the signature does not verify under new). Either way it MUST be rejected.
    const signedOld = makeSigned(oldK);
    const r = verifyDirectory(signedOld, [newK.pub]);
    ok(r.ok === false, "OLD-signed directory is REJECTED against {new} only");
    ok(r.reason === "signer-not-pinned" || r.reason === "bad-signature", `rejection reason is signer-not-pinned or bad-signature (got ${r.reason})`);

    // A THIRD, unpinned signer against the overlap set: never accepted.
    const signedThird = makeSigned(thirdK);
    const r3 = verifyDirectory(signedThird, overlap);
    ok(r3.ok === false, "directory signed by an UNPINNED third signer is rejected against {old,new}");
    ok(r3.reason === "signer-not-pinned" || r3.reason === "bad-signature", `third-signer rejection is signer-not-pinned or bad-signature (got ${r3.reason})`);

    // Declared `signer` in the set but signed by an unpinned key: the signature must still fail.
    const spoof = { ...signedThird, signer: oldK.pub }; // claims OLD, actually signed by third
    const rs = verifyDirectory(spoof, overlap);
    ok(rs.ok === false && rs.reason === "bad-signature", "declaring a pinned signer while signed by an unpinned key fails on bad-signature");

    // A Set (not just an array) works as the allowlist too.
    ok(verifyDirectory(makeSigned(newK), new Set(overlap)).ok, "a Set overlap works as the allowlist");
  }

  console.log("\nsingle-string backward compatibility (unchanged single-pin path):");
  {
    const signedOld = makeSigned(oldK);
    ok(verifyDirectory(signedOld, oldK.pub).ok, "single-string pin of OLD verifies an OLD-signed directory");
    ok(verifyDirectory(signedOld, newK.pub).ok === false, "single-string pin of NEW rejects an OLD-signed directory");
    const rStr = verifyDirectory(signedOld, oldK.pub);
    ok(rStr.signer === oldK.pub.toLowerCase(), "single-string path still reports the matched signer");

    // audit loop-14 F1: a 0x-prefixed pin must still match the bare-hex directory signer.
    ok(verifyDirectory(signedOld, "0x" + oldK.pub).ok, "0x-prefixed pin matches (no silent-reject footgun)");
    ok(verifyDirectory(signedOld, ["0x" + oldK.pub, newK.pub]).ok, "0x-prefixed pin works in an allowlist too");
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: directory-rotation selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
