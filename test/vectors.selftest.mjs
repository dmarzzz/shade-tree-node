// T-TEST-11: golden cross-implementation test vectors. Re-derive every deterministic value in
// testdata/vectors.json from its fixed seeds and assert a byte-exact match. This is two things:
//   1. a REGRESSION GUARD for the JS canonical formats (change the serialization or signing and
//      this fails, so a silent wire-format change cannot slip through), and
//   2. the ANTI-DRIFT CONTRACT for the coming Rust client (T-RUST-1): the Rust implementation MUST
//      reproduce these exact bytes/signatures, so the two clients cannot diverge on the wire.
//
// ed25519 (RFC 8032) is deterministic, so directory + announce signatures are pinned exactly.
// RLN Groth16 proofs are NOT deterministic (random blinding), so they are verified for equivalence
// elsewhere (packages/node/lib/rln.selftest.mjs), not byte-pinned here.
//
//   node test/vectors.selftest.mjs

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createPublicKey } from "node:crypto";
import { ed25519Sign, ed25519PrivateKey, pubkeyToOnion, onionToPubkey, canonicalDirectoryBytes, signDirectory, signDirectoryThreshold, verifyDirectory, CAPS_DOMAIN, canonicalCaps, canonicalCapsBytes, signCaps, verifyCapsSig, ADMIT_PATHS, PAY_PROTOCOLS, MAX_CAPS_PAY_TIERS } from "../packages/node/lib/directory.mjs";
import { canonicalAnnounceBytes, operatorAuthMessage, verifyOperatorSig } from "../packages/node/bootnode/announce.mjs";
import { calculateSignalHash, requestSignal } from "../packages/node/lib/rln.mjs";
import { canonicalReceiptBytes, buildReceipt, RECEIPT_DOMAIN } from "../packages/node/lib/receipt.mjs";
import { acceptEnvelopeVersion } from "../packages/node/gateway/gateway.mjs";
import { selectProtoVersion } from "../packages/node/client/shade-tree-client.mjs";
import { artifactIdOf, selectArtifact, resolveArtifact, ARTIFACT_ID_RE, isArtifactId } from "../packages/node/lib/zk-artifacts.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const V = JSON.parse(readFileSync(join(HERE, "..", "testdata", "vectors.json"), "utf8"));

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };
const pubFromSeed = (s) => { const d = createPublicKey(ed25519PrivateKey(s)).export({ format: "der", type: "spki" }); return Buffer.from(d.subarray(d.length - 32)).toString("hex"); };

async function main() {
  console.log("key derivation:");
  ok(pubFromSeed(V.signerSeed) === V.signerPub, "signer pubkey re-derives from its seed");
  ok(pubFromSeed(V.onionSeed) === V.onionPub, "onion pubkey re-derives from its seed");
  ok(pubkeyToOnion(V.onionPub) === V.onion, "onion address re-derives from the pubkey");
  ok(onionToPubkey(V.onion) === V.onionPub, "onion decodes back to the pubkey");

  console.log("\ndirectory (deterministic canonical bytes + ed25519 signature):");
  const dir = { version: 1, issued: 1000000, gateways: [{ onion: V.onion, pubkey: V.onionPub, weight: 100, health: "up" }] };
  ok(canonicalDirectoryBytes(dir).toString("hex") === V.canonicalDirectoryBytesHex, "canonical directory bytes match the pinned vector");
  const signed = signDirectory({ ...dir, signer: V.signerPub }, V.signerSeed);
  ok(signed.signature === V.directorySignature, "directory signature matches the pinned vector (ed25519 determinism)");
  ok(verifyDirectory(signed, V.signerPub).ok, "the pinned signed directory verifies against the pinned signer");

  console.log("\nthreshold directory (T-FEAT-9 M-of-N; same canonical bytes, additive fields):");
  const td = V.thresholdDirectory;
  const tdBase = { version: td.version, issued: td.issued, gateways: [{ onion: td.onion, pubkey: td.onionPub, weight: 100, health: "up" }] };
  // The whole point: threshold signing covers the SAME canonical bytes as the single-sig vector.
  ok(canonicalDirectoryBytes(tdBase).toString("hex") === V.canonicalDirectoryBytesHex, "threshold directory canonical bytes are byte-identical to the single-sig vector");
  const tdSigned = signDirectoryThreshold(tdBase, td.signerSeeds, td.threshold);
  ok(JSON.stringify(tdSigned.signers) === JSON.stringify(td.signers), "threshold signer pubkeys re-derive from the fixed seeds");
  ok(JSON.stringify(tdSigned.signatures) === JSON.stringify(td.signatures), "threshold signatures match the pinned vector (ed25519 determinism)");
  const tdV = verifyDirectory(tdSigned, td.signers);
  ok(tdV.ok && tdV.signers.length >= td.threshold, "the pinned threshold directory verifies against the full pinned signer set");
  ok(verifyDirectory(tdSigned, [td.signers[0]]).reason === `threshold-not-met:1/${td.threshold}`, "one pinned signer is below threshold -> threshold-not-met");

  console.log("\nannounce (deterministic canonical bytes + onion signature):");
  ok(canonicalAnnounceBytes(V.announce).toString("hex") === V.canonicalAnnounceBytesHex, "canonical announce bytes match the pinned vector");
  ok(ed25519Sign(canonicalAnnounceBytes(V.announce), V.onionSeed) === V.announceOnionSig, "announce onion signature matches the pinned vector");

  console.log("\noperator authorization:");
  ok(operatorAuthMessage(V.onion, V.operator) === V.operatorAuthMessage, "operator-auth message matches the pinned vector");
  // and the pinned message, signed by ANY operator key, must verify against that operator (round-trip)
  const { ethers } = await import("ethers");
  const w = new ethers.Wallet("0x" + "34".repeat(32));
  const sig = await w.signMessage(operatorAuthMessage(V.onion, w.address));
  ok(await verifyOperatorSig(V.onion, w.address, sig), "operator-auth message signs + verifies round-trip");

  console.log("\nsignal hash (deterministic keccak256(utf8(message)) >> 8):");
  // The circuit public x, byte-pinned so the Rust port can conformance-check it (T-RUST-1b).
  const sh = V.signalHash;
  ok(
    calculateSignalHash(requestSignal(sh.target, sh.nonce)).toString() === sh.signalHashDecimal,
    "calculateSignalHash(requestSignal(target,nonce)) matches the pinned decimal"
  );

  console.log("\nstaked-announce operator (pinned key + EIP-191 personal_sign):");
  // Round-trip against the PINNED sig (not a freshly-generated one): the byte-pinned
  // operatorSig must recover the pinned operator address.
  const oa = V.operatorAnnounce;
  ok(
    (await import("ethers")).ethers.verifyMessage(operatorAuthMessage(V.onion, oa.operator), oa.operatorSig).toLowerCase()
      === oa.operator.toLowerCase(),
    "pinned operatorSig recovers the pinned operator (raw ethers recover)"
  );
  ok(
    await verifyOperatorSig(V.onion, oa.operator, oa.operatorSig),
    "verifyOperatorSig(onion, operator, operatorSig) === true against the pinned sig"
  );

  console.log("\negress success receipt (deterministic domain-tagged canonical bytes + onion ed25519 sig):");
  // Signed by the SAME onion key as the announce above; RFC 8032 determinism => byte-pinned (T-RUST-1).
  const rc = V.receipt;
  ok(RECEIPT_DOMAIN === rc.receiptDomain, "RECEIPT_DOMAIN matches the pinned vector");
  const rcInput = { v: rc.v, onion: rc.onion, epoch: rc.epoch, ok: rc.ok };
  ok(
    canonicalReceiptBytes(rcInput).toString("hex") === rc.canonicalReceiptBytesHex,
    "canonical receipt bytes match the pinned vector"
  );
  const builtReceipt = buildReceipt({ onion: rc.onion, epoch: rc.epoch, onionSeedHex: V.onionSeed, ok: rc.ok });
  ok(builtReceipt.sig === rc.receiptOnionSig, "receipt onion signature matches the pinned vector (ed25519 determinism)");

  console.log("\ngateway capabilities (T-FEAT-10; additive — golden announce/directory bytes above are UNCHANGED):");
  const cap = V.capabilities;
  ok(CAPS_DOMAIN === cap.capsDomain, "CAPS_DOMAIN matches the pinned vector");
  ok(JSON.stringify(canonicalCaps(cap.caps)) === JSON.stringify(cap.caps), "canonicalCaps is idempotent on the pinned (already-canonical) caps");
  ok(canonicalCapsBytes(V.onion, cap.caps).toString("hex") === cap.canonicalCapsBytesHex, "canonical caps bytes match the pinned vector");
  ok(signCaps(V.onion, cap.caps, V.onionSeed) === cap.capsSig, "caps onion signature matches the pinned vector (ed25519 determinism)");
  // An announce that CARRIES caps re-derives byte-exactly, and — the load-bearing property —
  // it DIFFERS from the no-caps golden announce (proving caps really are in the signed bytes
  // when present, while the no-caps vector above stayed byte-identical).
  const annCaps = { ...V.announce, caps: cap.caps };
  ok(canonicalAnnounceBytes(annCaps).toString("hex") === cap.announceWithCaps.canonicalBytesHex, "announce-with-caps canonical bytes match the pinned vector");
  ok(ed25519Sign(canonicalAnnounceBytes(annCaps), V.onionSeed) === cap.announceWithCaps.onionSig, "announce-with-caps onion signature matches the pinned vector");
  ok(cap.announceWithCaps.canonicalBytesHex !== V.canonicalAnnounceBytesHex, "announce-with-caps bytes DIFFER from the no-caps golden vector (caps really are signed when present)");
  // A directory entry carrying caps + capsSig re-derives byte-exactly and verifies.
  const dirCaps = { version: 1, issued: 1000000, gateways: [{ onion: V.onion, pubkey: V.onionPub, weight: 100, health: "up", caps: cap.caps, capsSig: cap.capsSig }] };
  ok(canonicalDirectoryBytes(dirCaps).toString("hex") === cap.directoryWithCaps.canonicalBytesHex, "directory-with-caps canonical bytes match the pinned vector");
  const dirCapsSigned = signDirectory({ ...dirCaps, signer: V.signerPub }, V.signerSeed);
  ok(dirCapsSigned.signature === cap.directoryWithCaps.signature, "directory-with-caps signature matches the pinned vector");
  ok(verifyDirectory(dirCapsSigned, V.signerPub).ok, "the pinned directory-with-caps verifies (caps signature checked)");

  console.log("\ngateway draining flag (operator drain; additive, LAST caps key):");
  const drn = V.capabilitiesDraining;
  ok(JSON.stringify(canonicalCaps(drn.caps)) === JSON.stringify(drn.caps), "canonicalCaps keeps draining:true as the last key and is idempotent");
  ok(JSON.stringify(canonicalCaps({ ...drn.caps, draining: false })) === JSON.stringify(cap.caps), "draining:false canonicalizes to the base caps vector (byte-unchanged when absent)");
  ok(canonicalCapsBytes(V.onion, drn.caps).toString("hex") === drn.canonicalCapsBytesHex, "canonical caps bytes with draining match the pinned vector");
  ok(signCaps(V.onion, drn.caps, V.onionSeed) === drn.capsSig, "caps signature with draining matches the pinned vector");
  ok(drn.canonicalCapsBytesHex !== cap.canonicalCapsBytesHex, "draining really is in the signed bytes (differs from the base vector)");

  console.log("\nversion-negotiation reason labels (stable public literals; runtime suffixes not pinned):");
  const pr = V.protoReasons;
  const badRej = acceptEnvelopeVersion("3");        // garbage/non-integer => bad-version
  ok(badRej.label === pr.badVersion, "acceptEnvelopeVersion label matches the pinned bad-version literal");
  const unsRej = acceptEnvelopeVersion(3);          // legacy/out-of-range integer => unsupported-version
  ok(unsRej.label === pr.unsupportedVersion, "acceptEnvelopeVersion label matches the pinned unsupported-version literal");
  const nmRej = selectProtoVersion({ min: 5, max: 6 }, { min: 1, max: 2 }); // disjoint ranges => no-mutual-version
  ok(nmRej.reason.startsWith(pr.noMutualVersion + ":"), "selectProtoVersion reason prefix matches the pinned no-mutual-version literal");

  console.log("\nZK artifact-version negotiation (T-HARD-8; additive — the `capabilities` vectors above are UNCHANGED):");
  const ar = V.artifacts;
  ok(artifactIdOf(ar.sample.circuit, ar.sample.inputUtf8) === ar.sample.artifactId, "artifactIdOf(circuit, bytes) matches the pinned sample id (sha256 prefix)");
  ok(ARTIFACT_ID_RE.source === ar.idGrammar, "ARTIFACT_ID_RE matches the pinned id grammar");
  ok(isArtifactId(ar.sample.artifactId) && !isArtifactId("Not An Id") && !isArtifactId(""), "id grammar accepts the sample and rejects junk");
  const sel = ar.selection;
  ok(selectArtifact(sel.gatewayAd, sel.clientNewestFirst).id === sel.picked, "selectArtifact picks the pinned mutual id (newest client id the gateway lists)");
  ok(selectArtifact(null, sel.clientNewestFirst).id === sel.noAdPicked, "selectArtifact with no gateway ad picks the client's newest");
  ok(selectArtifact(["rln-ffffffffffffffff", "rln-aaaaaaaaaaaaaaaa"], sel.clientNewestFirst).reason === sel.disjointReason, "selectArtifact disjoint reason matches the pinned string byte-for-byte");
  ok(sel.disjointReason.startsWith(ar.reasons.noMutualArtifact + ":"), "disjoint reason prefix == pinned no-mutual-artifact literal");
  ok(selectArtifact(null, []).reason === ar.reasons.noClientArtifact, "no client artifact reason == pinned literal");
  const fakeSet = { accepted: new Map([["rln-0b25f824a04da3a8", { vkey: {} }]]), ids: ["rln-0b25f824a04da3a8"], legacyId: "rln-2cf24dba5fb0a30e" };
  ok(resolveArtifact("Not An Id", fakeSet).label === ar.reasons.badArtifact, "resolveArtifact garbage label == pinned bad-artifact literal");
  ok(resolveArtifact(undefined, fakeSet).label === ar.reasons.artifactRetired && resolveArtifact(undefined, fakeSet).reason === `${ar.reasons.artifactRetired}:rln-2cf24dba5fb0a30e`, "resolveArtifact retired legacy label/reason == pinned literal + id");
  ok(resolveArtifact("rln-ffffffffffffffff", fakeSet).label === ar.reasons.artifactUnknown, "resolveArtifact unknown label == pinned artifact-unknown literal");
  const cwa = ar.capsWithArtifacts;
  ok(JSON.stringify(canonicalCaps(cwa.caps)) === JSON.stringify(cwa.canonical), "canonicalCaps sorts artifacts and appends them after proto (pinned canonical form)");
  ok(canonicalCapsBytes(V.onion, cwa.caps).toString("hex") === cwa.canonicalCapsBytesHex, "canonical caps-with-artifacts bytes match the pinned vector");
  ok(signCaps(V.onion, cwa.caps, V.onionSeed) === cwa.capsSig, "caps-with-artifacts onion signature matches the pinned vector (ed25519 determinism)");
  ok(canonicalCapsBytes(V.onion, cap.caps).toString("hex") === cap.canonicalCapsBytesHex, "caps WITHOUT artifacts still serialize byte-identically to the pre-T-HARD-8 vector");

  console.log("\nadmission policy + payment advert caps (T-FEAT-9; additive — every earlier caps vector is UNCHANGED):");
  const ad = V.admission;
  ok(JSON.stringify(ADMIT_PATHS) === JSON.stringify(ad.admitPaths) && JSON.stringify(PAY_PROTOCOLS) === JSON.stringify(ad.payProtocols) && MAX_CAPS_PAY_TIERS === ad.maxPayTiers, "ADMIT_PATHS / PAY_PROTOCOLS / MAX_CAPS_PAY_TIERS match the pinned constants");
  const cwad = ad.capsWithAdmission;
  ok(JSON.stringify(canonicalCaps(cwad.caps)) === JSON.stringify(cwad.canonical), "canonicalCaps dedups+orders admits (anonymity order), normalizes pay (protocol order, lowercased onion/asset, numeric tier keys), appended after artifacts (pinned canonical form)");
  ok(canonicalCapsBytes(V.onion, cwad.caps).toString("hex") === cwad.canonicalCapsBytesHex, "canonical caps-with-admission bytes match the pinned vector");
  ok(signCaps(V.onion, cwad.caps, V.onionSeed) === cwad.capsSig, "caps-with-admission onion signature matches the pinned vector (ed25519 determinism)");
  ok(verifyCapsSig(V.onion, cwad.caps, cwad.capsSig) === true, "…and verifies against the onion");
  ok(ad.junk.admits.every((j) => canonicalCaps({ admits: j }).admits === undefined), "junk admits lists canonicalize to NO admits");
  ok(ad.junk.pay.every((j) => canonicalCaps({ pay: j }).pay === undefined), "junk / oversized / half pay adverts canonicalize to NO pay");
  ok(canonicalCapsBytes(V.onion, cwa.caps).toString("hex") === cwa.canonicalCapsBytesHex && canonicalCapsBytes(V.onion, cap.caps).toString("hex") === cap.canonicalCapsBytesHex, "caps WITHOUT admits/pay still serialize byte-identically to the pre-T-FEAT-9 vectors");

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: vectors selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
