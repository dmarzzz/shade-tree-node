// T-FEAT-10: gateway capability advertisement + capability-aware selection.
//
// Capabilities let a gateway self-declare COARSE, BUCKETED egress ports / a region hint / a
// protocol-version range in its SIGNED announce, so a client routes to a CAPABLE gateway
// instead of "any gateway". This selftest proves the four load-bearing properties:
//
//   1. ADDITIVE + GOLDEN-VECTOR-SAFE. An announce/directory WITHOUT caps is byte-identical to
//      before (caps are OMITTED from canonical bytes when absent); with caps present the bytes
//      differ (caps really are signed).
//   2. SIGNED, NOT FORGEABLE. Caps ride under the onion-control signature (announce) and carry
//      a standalone onion `capsSig` (directory), so a bootnode / directory signer that lacks
//      the onion key cannot forge or alter them — a tampered cap is REJECTED.
//   3. TOTAL on garbage. canonicalCaps drops unknown/invalid fields, never throws; verify
//      stays total on hostile input.
//   4. OPT-IN, FAIL-CLOSED selection. No requirement => selection is byte-identical to today;
//      a port/proto/region requirement filters to capable gateways; an unmet requirement
//      fails closed with a clear reason.
//
//   node packages/node/lib/capability.selftest.mjs
//
// Exit 0 = all invariants held. No network, no chain, no Tor.

import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  canonicalCaps, hasCaps, canonicalCapsBytes, signCaps, verifyCapsSig,
  canonicalDirectoryBytes, signDirectory, verifyDirectory, pubkeyToOnion,
  DEFAULT_EGRESS_PORT, DEFAULT_PROTO_VERSION,
} from "./directory.mjs";
import { buildAnnounce, verifyAnnounce, canonicalAnnounceBytes } from "../bootnode/announce.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

// A fresh onion identity: raw ed25519 seed/pub hex + the v3 onion whose key IS that pub.
function newOnion() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const priv = privateKey.export({ format: "der", type: "pkcs8" });
  const pub = publicKey.export({ format: "der", type: "spki" });
  const seed = priv.subarray(priv.length - 32).toString("hex");
  const pubHex = pub.subarray(pub.length - 32).toString("hex");
  return { seed, pub: pubHex, onion: pubkeyToOnion(pubHex) };
}
function newSigner() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const priv = privateKey.export({ format: "der", type: "pkcs8" });
  const pub = publicKey.export({ format: "der", type: "spki" });
  return { priv: priv.subarray(priv.length - 32).toString("hex"), pub: pub.subarray(pub.length - 32).toString("hex") };
}
// A directory entry with validly-signed caps for a fresh onion.
function capEntry(o, caps, weight = 100) {
  return { onion: o.onion, pubkey: o.pub, weight, health: "up", caps: canonicalCaps(caps), capsSig: signCaps(o.onion, caps, o.seed) };
}

async function main() {
  const g = newOnion();
  const caps = { ports: [80, 443], region: "eu", proto: { min: 3, max: 4 } };
  const rate = { scope: "grove-v4", window: "fixed", epochSeconds: 60, previousEpochsAccepted: 1, rootFreshnessSeconds: 60, payloadBytesPerSlot: 41943040 };

  console.log("canonicalCaps normalization + totality:");
  {
    ok(JSON.stringify(canonicalCaps({ ports: [443, 80, 443], region: "eu", proto: { min: 3, max: 4 } })) ===
       JSON.stringify({ ports: [80, 443], region: "eu", proto: { min: 3, max: 4 } }),
       "ports deduped+sorted; fixed field order {ports,region,proto}");
    ok(JSON.stringify(canonicalCaps({ ports: [443], junk: 1, region: "atlantis", proto: { min: 2 } })) ===
       JSON.stringify({ ports: [443] }),
       "unknown field dropped, out-of-bucket region dropped, incomplete proto dropped");
    ok(JSON.stringify(canonicalCaps({ ports: [0, 70000, 1.5, "x", 22] })) === JSON.stringify({ ports: [22] }),
       "invalid port values (0, >65535, float, string) filtered out");
    for (const bad of [null, undefined, 42, "str", [], { ports: "no" }, { proto: 5 }, { region: 9 }, { ports: [NaN] }]) {
      let threw = false; try { canonicalCaps(bad); } catch { threw = true; }
      ok(!threw, `canonicalCaps(${JSON.stringify(bad)}) is total (no throw)`);
    }
    ok(hasCaps({}) === false && hasCaps({ junk: 1 }) === false, "hasCaps is false for empty / all-invalid caps");
    ok(hasCaps({ ports: [443] }) === true, "hasCaps is true when a valid field is present");
    ok(JSON.stringify(canonicalCaps({ rate }).rate) === JSON.stringify(rate), "fixed v4 rate policy canonicalizes in signed field order");
    ok(canonicalCaps({ rate: { ...rate, epochSeconds: 0 } }).rate === undefined, "malformed rate policy is dropped whole");
  }

  console.log("\nannounce: absent caps are byte-identical; present caps are signed:");
  {
    const noCaps = buildAnnounce({ onion: g.onion, weight: 100, onionSeedHex: g.seed, ts: 111, nonce: "n1" });
    const noCapsRef = { v: 1, onion: g.onion, weight: 100, ts: 111, nonce: "n1" };
    ok(noCaps.caps === undefined && noCaps.capsSig === undefined, "no-caps announce carries no caps/capsSig fields");
    ok(canonicalAnnounceBytes(noCaps).equals(canonicalAnnounceBytes(noCapsRef)),
       "no-caps announce canonical bytes are byte-identical to the legacy {v,onion,weight,ts,nonce} shape");

    const withCaps = buildAnnounce({ onion: g.onion, weight: 100, onionSeedHex: g.seed, ts: 111, nonce: "n1", caps });
    ok(hasCaps(withCaps.caps) && typeof withCaps.capsSig === "string", "with-caps announce carries caps + capsSig");
    ok(!canonicalAnnounceBytes(withCaps).equals(canonicalAnnounceBytes(noCaps)),
       "caps change the signed announce bytes (caps really are under the onion signature)");

    const v = await verifyAnnounce(withCaps, { now: 111 });
    ok(v.ok && JSON.stringify(v.caps) === JSON.stringify(canonicalCaps(caps)), "verifyAnnounce carries the canonical caps through on success");
    const v0 = await verifyAnnounce(noCaps, { now: 111 });
    ok(v0.ok && v0.caps === null, "verifyAnnounce reports caps:null for a no-caps announce");
  }

  console.log("\nannounce: a tampered / forged capability is REJECTED (bootnode can't forge):");
  {
    const a = buildAnnounce({ onion: g.onion, weight: 100, onionSeedHex: g.seed, ts: 222, nonce: "n2", caps });
    const tampered = JSON.parse(JSON.stringify(a));
    tampered.caps.ports = [8080]; // a "bootnode" widening the allowed ports it never signed
    const r = await verifyAnnounce(tampered, { now: 222 });
    ok(r.ok === false && r.reason === "bad-onion-sig", "widening a signed port set is rejected (bad-onion-sig)");

    const bare = buildAnnounce({ onion: g.onion, weight: 100, onionSeedHex: g.seed, ts: 223, nonce: "n3" });
    const grafted = { ...bare, caps: canonicalCaps(caps), capsSig: signCaps(g.onion, caps, g.seed) };
    const rg = await verifyAnnounce(grafted, { now: 223 });
    ok(rg.ok === false && rg.reason === "bad-onion-sig", "grafting a validly-capsSig'd caps onto a no-caps announce still fails the main onion sig");

    const a2 = buildAnnounce({ onion: g.onion, weight: 100, onionSeedHex: g.seed, ts: 224, nonce: "n4", caps });
    a2.capsSig = a2.capsSig.replace(/.$/, (c) => (c === "0" ? "1" : "0"));
    const r2 = await verifyAnnounce(a2, { now: 224 });
    ok(r2.ok === false && r2.reason === "bad-caps-sig", "a corrupted standalone capsSig is rejected (bad-caps-sig)");
  }

  console.log("\ncaps signature is onion-bound + total:");
  {
    ok(verifyCapsSig(g.onion, caps, signCaps(g.onion, caps, g.seed)) === true, "a valid capsSig verifies against its onion");
    const other = newOnion();
    ok(verifyCapsSig(other.onion, caps, signCaps(g.onion, caps, g.seed)) === false, "a capsSig cannot be replayed onto a different onion");
    for (const bad of [null, undefined, 5, "", "zz"]) ok(verifyCapsSig(g.onion, caps, bad) === false, `verifyCapsSig total on ${JSON.stringify(bad)}`);
    ok(canonicalCapsBytes(g.onion, caps).length > 0, "canonicalCapsBytes is domain-separated + non-empty");
  }

  console.log("\ndirectory: caps carried through verifyDirectory; a signer that alters caps is caught:");
  {
    const signer = newSigner();
    const entry = capEntry(g, caps);
    const dir = { version: 1, issued: 1000, gateways: [entry], signer: signer.pub };
    const signed = signDirectory(dir, signer.priv);
    ok(verifyDirectory(signed, signer.pub).ok, "a directory carrying validly-signed caps verifies");

    // No-caps directory: byte-identical to a directory whose entry has an empty caps field.
    const bareEntry = { onion: g.onion, pubkey: g.pub, weight: 100, health: "up" };
    const bareDir = { version: 1, issued: 1000, gateways: [bareEntry] };
    const capsDroppedDir = { version: 1, issued: 1000, gateways: [{ ...bareEntry, caps: {}, capsSig: undefined }] };
    ok(canonicalDirectoryBytes(bareDir).equals(canonicalDirectoryBytes(capsDroppedDir)),
       "an entry with empty caps serializes byte-identically to a no-caps entry (golden-safe)");

    // A malicious directory signer alters a cap and RE-SIGNS: the outer directory signature is
    // valid, but capsSig no longer matches -> rejected. Crux: caps are unforgeable by whoever
    // holds only the directory-signing key.
    const evil = JSON.parse(JSON.stringify(signed));
    evil.gateways[0].caps.ports = [80, 443, 8080];
    const reSigned = signDirectory({ version: evil.version, issued: evil.issued, gateways: evil.gateways, signer: signer.pub }, signer.priv);
    const rv = verifyDirectory(reSigned, signer.pub);
    ok(rv.ok === false && rv.reason.startsWith("bad-caps-sig"), "a directory signer that alters a gateway's caps is rejected (bad-caps-sig), even after re-signing the directory");

    const noSig = signDirectory({ version: 1, issued: 1000, gateways: [{ onion: g.onion, pubkey: g.pub, weight: 100, health: "up", caps: canonicalCaps(caps) }], signer: signer.pub }, signer.priv);
    ok(verifyDirectory(noSig, signer.pub).reason?.startsWith("bad-caps-sig"), "caps without a capsSig are rejected");
  }

  // ---- capability-aware selection, driven through the REAL selectCandidates(req) ----------
  // Env must be set BEFORE importing packages/node/client/selection.mjs (it reads SHADE_TREE_DIRECTORY /
  // SHADE_TREE_DIR_SIGNER at import), so we build a signed directory file first, then dynamic-import.
  const work = await mkdtemp(join(tmpdir(), "shade-tree-caps-"));
  try {
    const signer = newSigner();
    const full = newOnion();    // ports 80+443, region eu, proto 3-4
    const https = newOnion();   // ports 443 only, region na, legacy proto 3
    const legacy = newOnion();  // NO caps (inherits the conservative v4 default)
    const dir = {
      version: 1,
      issued: Math.floor(Date.now() / 1000),
      gateways: [
        capEntry(full, { ports: [80, 443], region: "eu", proto: { min: 3, max: 4 }, rate }),
        capEntry(https, { ports: [443], region: "na", proto: { min: 3, max: 3 } }),
        { onion: legacy.onion, pubkey: legacy.pub, weight: 100, health: "up" },
      ],
      signer: signer.pub,
    };
    const signed = signDirectory(dir, signer.priv);
    const dirPath = join(work, "directory.json");
    await writeFile(dirPath, JSON.stringify(signed));
    process.env.SHADE_TREE_DIRECTORY = dirPath;
    process.env.SHADE_TREE_DIR_SIGNER = signer.pub;
    process.env.SHADE_TREE_DIRECTORY_REFRESH_MS = "0";
    const sel = await import("../client/selection.mjs");

    console.log("\ncapability-aware selection: pure filter semantics:");
    const fleet = signed.gateways;
    ok(sel.requirementActive(null) === false && sel.requirementActive({}) === false, "empty/absent requirement is inactive");
    ok(sel.requirementActive({ port: 80 }) === true, "a port requirement is active");
    ok(sel.filterByCapability(fleet, null) === fleet, "inactive requirement returns the SAME array reference (byte-identical path)");
    ok(sel.filterByCapability(fleet, {}) === fleet, "empty-object requirement also returns the same array reference");
    ok(DEFAULT_EGRESS_PORT === 443 && DEFAULT_PROTO_VERSION === 4, "defaults are the documented 443 / Shade Tree v4 floor");
    ok(sel.gatewayMeetsRequirement(fleet[2], { port: 443 }) === true && sel.gatewayMeetsRequirement(fleet[2], { port: 80 }) === false,
       "a no-caps gateway meets only the default port (443), not a non-default one (80)");
    ok(sel.gatewayMeetsRequirement(fleet[2], { proto: 4 }) === true && sel.gatewayMeetsRequirement(fleet[2], { proto: 3 }) === false,
       "a no-caps gateway is assumed proto {4} only");
    ok(sel.gatewayMeetsRequirement(fleet[2], { region: "na" }) === false, "region is never implicit — a no-caps gateway matches no region");
    ok(sel.gatewayMeetsRequirement(fleet[0], { rate }) === true && sel.gatewayMeetsRequirement(fleet[1], { rate }) === false, "rate policy must match exactly; an absent signed policy is not assumed");
    for (const bad of [null, undefined, {}, { caps: 5 }, { caps: { ports: "no" } }]) {
      let threw = false; try { sel.gatewayMeetsRequirement(bad, { port: 443 }); } catch { threw = true; }
      ok(!threw, `gatewayMeetsRequirement total on entry ${JSON.stringify(bad)}`);
    }

    console.log("\ncapability-aware selection: end-to-end through selectCandidates(req):");
    const onionsOf = (arr) => new Set(arr.map((x) => x.onion));
    const shortFull = full.onion.replace(/\.onion$/, "");
    const shortHttps = https.onion.replace(/\.onion$/, "");
    const shortLegacy = legacy.onion.replace(/\.onion$/, "");

    const dflt = await sel.selectCandidates();
    ok(dflt.length === 3, "selectCandidates() with NO requirement returns the whole fleet (byte-identical default path)");
    ok((await sel.selectCandidates({})).length === 3, "selectCandidates({}) (inactive requirement) also returns the whole fleet");

    const p80 = await sel.selectCandidates({ port: 80 });
    ok(p80.length === 1 && onionsOf(p80).has(shortFull), "selectCandidates({port:80}) selects ONLY the gateway advertising port 80");

    const p443 = await sel.selectCandidates({ port: 443 });
    ok(p443.length === 3 && onionsOf(p443).has(shortLegacy), "selectCandidates({port:443}) includes the no-caps gateway (implicit default-port match)");

    const pr4 = await sel.selectCandidates({ proto: 4 });
    ok(pr4.length === 2 && onionsOf(pr4).has(shortFull) && onionsOf(pr4).has(shortLegacy), "selectCandidates({proto:4}) includes explicit-v4 and capless default-v4 gateways");

    const reu = await sel.selectCandidates({ region: "eu" });
    ok(reu.length === 1 && onionsOf(reu).has(shortFull), "selectCandidates({region:'eu'}) selects ONLY the eu gateway");
    const rna = await sel.selectCandidates({ region: "na" });
    ok(rna.length === 1 && onionsOf(rna).has(shortHttps), "selectCandidates({region:'na'}) selects ONLY the na gateway");

    const conj = await sel.selectCandidates({ port: 443, proto: 4 });
    ok(conj.length === 2 && onionsOf(conj).has(shortFull) && onionsOf(conj).has(shortLegacy), "a combined requirement is a conjunction (port AND proto), including the capless 443/v4 default");

    const rated = await sel.selectCandidates({ rate });
    ok(rated.length === 1 && onionsOf(rated).has(shortFull) && JSON.stringify(rated[0].rate) === JSON.stringify(rate), "signed rate requirement selects only the exact-policy gateway and carries the policy forward");

    let threw = null;
    try { await sel.selectCandidates({ port: 8080 }); } catch (e) { threw = e; }
    ok(threw && /no gateway meets capability requirement: port=8080/.test(threw.message),
       "an unmet requirement FAILS CLOSED with a clear reason (no gateway meets capability requirement: port=8080)");
  } finally {
    await rm(work, { recursive: true, force: true });
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: capability selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
