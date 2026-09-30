// Offline proof of the static signed-directory tool (group/sign-directory.mjs).
//
//   node group/sign-directory.selftest.mjs
//
// The CLI mints keys and writes into the repo (a persistent group/directory-signer.key
// plus group/directory.example.json), so invoking it would dirty the tree. Instead we
// exercise the SAME packages/node/lib/directory.mjs functions the CLI uses -- signDirectory,
// verifyDirectory, pubkeyToOnion, onionToPubkey, and the ed25519 helpers -- against a
// directory built exactly the way the tool builds one: fresh ed25519 gateway keys, raw
// pub = last 32 bytes of the spki DER, onion = pubkeyToOnion(pub). No files are written.
//
// Exit 0 = all invariants held; nonzero = a check failed (prints which).

import { generateKeyPairSync } from "node:crypto";
import {
  signDirectory,
  verifyDirectory,
  pubkeyToOnion,
  onionToPubkey,
  ed25519PublicKey,
} from "../packages/node/lib/directory.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

// Raw 32-byte ed25519 key material as hex, mirroring sign-directory.mjs's rawPubHex /
// rawSeedHex: the raw key is the trailing 32 bytes of the DER encoding.
function newEd25519() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pubDer = publicKey.export({ format: "der", type: "spki" });
  const privDer = privateKey.export({ format: "der", type: "pkcs8" });
  return { pub: pubDer.subarray(pubDer.length - 32).toString("hex"), priv: privDer.subarray(privDer.length - 32).toString("hex") };
}

// One gateway with a real, internally-consistent v3 onion (onionToPubkey(onion) === pubkey).
function mintGateway(weight, health, note) {
  const k = newEd25519();
  return { onion: pubkeyToOnion(k.pub), pubkey: k.pub, weight, health, note };
}

function main() {
  const signer = newEd25519();

  // Build a directory the way the CLI does (N=3 gateways), then sign it.
  const dir = {
    version: 1,
    issued: Math.floor(Date.now() / 1000),
    gateways: [
      mintGateway(100, "up", "primary, AS-A"),
      mintGateway(100, "up", "AS-B"),
      mintGateway(50, "up", "AS-C"),
    ],
    signer: signer.pub,
  };

  // --- 0. keygen round-trip: minted onions decode back to their own pubkeys -------
  console.log("keygen:");
  for (const g of dir.gateways) {
    ok(onionToPubkey(g.onion) === g.pubkey, `minted onion round-trips to its pubkey (${g.onion.slice(0, 8)}..)`);
    ok(g.onion.endsWith(".onion") && g.onion.length === 62, `onion is a 56-char v3 address (${g.onion.slice(0, 8)}..)`);
  }

  // --- 1. sign then verify under the pinned signer --------------------------------
  console.log("\nsign + verify:");
  const signed = signDirectory(dir, signer.priv);
  ok(typeof signed.signature === "string" && signed.signature.length > 0, "signDirectory attaches a signature");
  const good = verifyDirectory(signed, signer.pub);
  ok(good.ok === true, "verifyDirectory accepts the signed directory under the pinned signer");

  // --- 2. a DIFFERENT pinned signer must reject -----------------------------------
  console.log("\nwrong signer:");
  const wrong = newEd25519();
  // sanity: distinct keypair, and a valid pubkey object (mirrors the CLI's `other` check)
  ok(wrong.pub !== signer.pub, "wrong signer key is distinct");
  void ed25519PublicKey(wrong.pub); // throws if not a well-formed 32-byte key
  const rejWrong = verifyDirectory(signed, wrong.pub);
  // dir.signer is pinned to the real signer, so verify short-circuits on signer-not-pinned;
  // either that or a plain bad-signature is a correct rejection -- the point is ok === false.
  ok(rejWrong.ok === false, `verifyDirectory rejects under a wrong pinned signer (reason: ${rejWrong.reason})`);
  // and with dir.signer stripped (so the pin check can't short-circuit), the signature
  // itself must still fail against the wrong key.
  const noPin = { ...signed }; delete noPin.signer;
  const rejWrongSig = verifyDirectory(noPin, wrong.pub);
  ok(rejWrongSig.ok === false && rejWrongSig.reason === "bad-signature", "signature fails cryptographically against the wrong key (bad-signature)");

  // --- 3. tampering a signed field breaks verification ----------------------------
  console.log("\ntamper detection:");
  // 3a. flip a gateway weight (a signature-covered field) -> bad-signature
  const tWeight = JSON.parse(JSON.stringify(signed));
  tWeight.gateways[0].weight = tWeight.gateways[0].weight + 1;
  const rejWeight = verifyDirectory(tWeight, signer.pub);
  ok(rejWeight.ok === false && rejWeight.reason === "bad-signature", `flipping a gateway weight is caught (reason: ${rejWeight.reason})`);

  // 3b. swap in a foreign onion (different key) under an existing pubkey. Because the
  //     onion no longer encodes that pubkey, this trips the onion<->pubkey binding
  //     check first; even past that it would be a bad-signature. Either is a rejection.
  const foreign = mintGateway(100, "up", "attacker");
  const tOnion = JSON.parse(JSON.stringify(signed));
  tOnion.gateways[1].onion = foreign.onion; // pubkey left as the original -> mismatch
  const rejOnion = verifyDirectory(tOnion, signer.pub);
  ok(
    rejOnion.ok === false && (rejOnion.reason.startsWith("pubkey-onion-mismatch") || rejOnion.reason === "bad-signature"),
    `swapping an onion is caught (reason: ${rejOnion.reason})`
  );

  // 3c. a coherent-but-forged entry (matching onion+pubkey the signer never signed)
  //     passes the binding check but fails the signature -> bad-signature.
  const tGraft = JSON.parse(JSON.stringify(signed));
  tGraft.gateways.push({ onion: foreign.onion, pubkey: foreign.pubkey, weight: 100, health: "up" });
  const rejGraft = verifyDirectory(tGraft, signer.pub);
  ok(rejGraft.ok === false && rejGraft.reason === "bad-signature", `grafting an internally-consistent gateway is caught (reason: ${rejGraft.reason})`);

  // --- 4. CLI exercised? ----------------------------------------------------------
  console.log("\nCLI:");
  console.log("  skip  CLI not invoked: group/sign-directory.mjs mints a persistent");
  console.log("        group/directory-signer.key and writes group/directory.example.json");
  console.log("        into the repo; running it would dirty the tree. Library-level");
  console.log("        assertions above cover the same signDirectory/verifyDirectory path.");

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: sign-directory selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
