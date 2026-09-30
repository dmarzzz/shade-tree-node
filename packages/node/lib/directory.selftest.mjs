// Selftest for packages/node/lib/directory.mjs — the module the fleet's whole trust model rests on.
// Covers: ed25519 sign/verify, the v3 onion <-> ed25519-key binding (a poisoned directory
// cannot graft a hostile onion), canonical signing, verifyDirectory's every rejection path,
// live onion-control proofs, last-known-good fallback, and weighted selection + health.
//
//   node packages/node/lib/directory.selftest.mjs
//
// Exit 0 = all invariants held. No network, no chain.

import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ed25519Sign, ed25519Verify, onionToPubkey, pubkeyToOnion,
  canonicalDirectoryBytes, signDirectory, verifyDirectory, verifyOnionControl,
  loadDirectory, pickGateway, selectionOrder, reportHealth,
} from "./directory.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

// raw ed25519 seed/pub hex from a fresh keypair (same helpers group/sign-directory.mjs uses).
function newKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const priv = privateKey.export({ format: "der", type: "pkcs8" });
  const pub = publicKey.export({ format: "der", type: "spki" });
  return { priv: priv.subarray(priv.length - 32).toString("hex"), pub: pub.subarray(pub.length - 32).toString("hex") };
}
const gw = (weight, health = "up") => { const k = newKey(); return { onion: pubkeyToOnion(k.pub), pubkey: k.pub, weight, health, _k: k }; };

async function main() {
  console.log("ed25519 sign/verify:");
  {
    const k = newKey();
    const msg = Buffer.from("challenge-abc");
    const sig = ed25519Sign(msg, k.priv);
    ok(ed25519Verify(msg, sig, k.pub), "valid signature verifies");
    ok(!ed25519Verify(Buffer.from("challenge-abd"), sig, k.pub), "tampered message rejected");
    ok(!ed25519Verify(msg, sig.replace(/.$/, (c) => (c === "0" ? "1" : "0")), k.pub), "tampered signature rejected");
    ok(!ed25519Verify(msg, sig, newKey().pub), "wrong key rejected");
  }

  console.log("\nv3 onion <-> ed25519 key binding:");
  {
    const k = newKey();
    const onion = pubkeyToOnion(k.pub);
    ok(onion.length === 62 && onion.endsWith(".onion"), "onion is a 56-char v3 address");
    ok(onionToPubkey(onion) === k.pub, "onionToPubkey(pubkeyToOnion(k)) === k (round-trip)");
    let threw = false; try { onionToPubkey("tooshort.onion"); } catch { threw = true; }
    ok(threw, "non-56-char onion rejected");
    // flip one base32 char -> checksum must fail
    const bad = onion.replace(/^./, (c) => (c === "a" ? "b" : "a"));
    let threw2 = false; try { onionToPubkey(bad); } catch { threw2 = true; }
    ok(threw2, "corrupted onion fails the checksum");
  }

  console.log("\ncanonical signing is stable + scoped:");
  {
    const g = gw(100);
    const a = { version: 1, issued: 5, gateways: [{ onion: g.onion, pubkey: g.pubkey, weight: 100, health: "up" }] };
    const b = { issued: 5, gateways: [{ health: "up", weight: 100, pubkey: g.pubkey, onion: g.onion, note: "unsigned field" }], version: 1, extra: "ignored" };
    ok(canonicalDirectoryBytes(a).equals(canonicalDirectoryBytes(b)), "canonical bytes independent of key order + unsigned fields");
  }

  console.log("\nverifyDirectory: accept the good, reject every forgery:");
  {
    const signer = newKey();
    const gws = [gw(100), gw(100), gw(50)];
    const base = { version: 1, issued: 123, gateways: gws.map(({ onion, pubkey, weight, health }) => ({ onion, pubkey, weight, health })), signer: signer.pub };
    const signed = signDirectory(base, signer.priv);

    ok(verifyDirectory(signed, signer.pub).ok, "validly-signed directory verifies");
    ok(verifyDirectory(signed, newKey().pub).ok === false, "wrong pinned signer rejected");
    ok(verifyDirectory({ ...signed, signature: undefined }, signer.pub).reason === "unsigned", "unsigned rejected");

    // tamper a signed field (weight is covered) -> signature breaks
    const tampered = JSON.parse(JSON.stringify(signed)); tampered.gateways[0].weight = 999;
    ok(verifyDirectory(tampered, signer.pub).reason === "bad-signature", "tampered weight breaks the signature");

    // GRAFT: attacker swaps in their own onion but keeps a victim pubkey -> onion<->pubkey mismatch.
    // (Even if they could re-sign, the address no longer encodes the claimed key.)
    const graft = JSON.parse(JSON.stringify(base)); graft.gateways[0].onion = gw(100).onion; // different key's onion
    const graftSigned = signDirectory(graft, signer.priv);
    ok(verifyDirectory(graftSigned, signer.pub).reason?.startsWith("pubkey-onion-mismatch"), "grafted onion (address != claimed key) rejected");

    // signer-not-pinned: the file names a different signer than the client pins
    ok(verifyDirectory({ ...signed, signer: newKey().pub }, signer.pub).reason === "signer-not-pinned", "mismatched declared signer rejected");

    // a non-string signer must return {ok:false}, NEVER throw (verifyDirectory is total on hostile input)
    let threwOnBadSigner = false, badSignerRes = null;
    try { badSignerRes = verifyDirectory({ ...signed, signer: 12345 }, signer.pub); } catch { threwOnBadSigner = true; }
    ok(!threwOnBadSigner && badSignerRes?.ok === false && badSignerRes.reason === "bad-signer-field", "non-string signer field rejected without throwing");
  }

  console.log("\nlive onion-control proof:");
  {
    const g = gw(100);
    const challenge = Buffer.from("nonce-" + Date.now());
    const sig = ed25519Sign(challenge, g._k.priv);
    ok(verifyOnionControl(g.onion, challenge, sig), "onion holder proves control");
    ok(!verifyOnionControl(g.onion, challenge, ed25519Sign(challenge, newKey().priv)), "non-holder cannot prove control");
    ok(!verifyOnionControl(g.onion, Buffer.from("other"), sig), "signature over a different challenge rejected");
  }

  console.log("\nload with last-known-good fallback:");
  {
    const work = await mkdtemp(join(tmpdir(), "shade-tree-dir-"));
    try {
      const signer = newKey();
      const gws = [gw(100), gw(50)];
      const signed = signDirectory({ version: 1, issued: 1, gateways: gws.map(({ onion, pubkey, weight, health }) => ({ onion, pubkey, weight, health })), signer: signer.pub }, signer.priv);
      const path = join(work, "directory.json");
      const cachePath = join(work, "directory.json.lkg");
      await writeFile(path, JSON.stringify(signed));

      const fresh = await loadDirectory({ path, pinnedSigner: signer.pub, cachePath });
      ok(fresh.source === "fresh" && fresh.dir.gateways.length === 2, "fresh good directory loads + caches lkg");

      await writeFile(path, "{ corrupt json"); // fresh now unreadable
      const cached = await loadDirectory({ path, pinnedSigner: signer.pub, cachePath });
      ok(cached.source === "cache", "corrupt fresh falls back to last-known-good");

      await rm(cachePath, { force: true });
      let threw = false; try { await loadDirectory({ path, pinnedSigner: signer.pub, cachePath }); } catch { threw = true; }
      ok(threw, "no valid fresh + no cache is a hard error, never a silent empty fleet");
    } finally { await rm(work, { recursive: true, force: true }); }
  }

  console.log("\nweighted selection + health:");
  {
    const dir = { gateways: [gw(100), gw(100), gw(50)] };
    const order = selectionOrder(dir);
    ok(order.length === 3 && new Set(order.map((g) => g.onion)).size === 3, "selectionOrder covers the whole fleet with no duplicates");

    // weight PROPORTIONALITY: a uniform-pick regression must fail here. With weights 1:99, the
    // heavy gateway should win the first pick ~99% of the time; a uniform pick would be ~50%.
    {
      const heavy = gw(99), light = gw(1);
      const d = { gateways: [light, heavy] };
      let heavyFirst = 0;
      const N = 4000;
      for (let i = 0; i < N; i++) if (pickGateway(d).onion === heavy.onion) heavyFirst++;
      const frac = heavyFirst / N;
      ok(frac > 0.9 && frac < 0.995, `pickGateway is weight-proportional (heavy won ${(frac * 100).toFixed(1)}%, expected ~99%, uniform would be ~50%)`);
    }

    // client-side weight clamp: a static/poisoned directory bypasses the bootnode's announce-time
    // clamp, so the client caps `weight` at MAX_WEIGHT=1000 itself. The precise property: a gateway
    // attesting 1e12 is treated IDENTICALLY to one attesting MAX_WEIGHT, so no directory source can
    // push a gateway's share past the MAX_WEIGHT bound (~77% here, not the ~100% a 1e12 claim wants).
    {
      const others = [gw(100), gw(100), gw(100)];
      const sampleShare = (greedyW) => {
        const greedy = gw(greedyW);
        const d = { gateways: [greedy, ...others.map((o) => ({ ...o }))] };
        let first = 0; const N = 4000;
        for (let i = 0; i < N; i++) if (pickGateway(d).onion === greedy.onion) first++;
        return first / N;
      };
      const huge = sampleShare(1e12), capped = sampleShare(1000);
      ok(Math.abs(huge - capped) < 0.06, `weight 1e12 is clamped to MAX_WEIGHT (share ${(huge * 100).toFixed(1)}% ≈ capped ${(capped * 100).toFixed(1)}%)`);
      ok(huge < 0.85, `even clamped, a greedy gateway cannot capture ~all traffic (share ${(huge * 100).toFixed(1)}%)`);
    }

    // exclude honored
    const ex = new Set([dir.gateways[0].onion]);
    let excluded = true;
    for (let i = 0; i < 50; i++) if (pickGateway(dir, { exclude: ex }).onion === dir.gateways[0].onion) excluded = false;
    ok(excluded, "excluded gateway is never picked");

    // a "down" gateway is skipped while a healthy one exists
    const d2 = { gateways: [gw(100), gw(100, "down")] };
    let pickedDown = false;
    for (let i = 0; i < 50; i++) if (pickGateway(d2).health === "down") pickedDown = true;
    ok(!pickedDown, "a down gateway is skipped when a healthy one exists");

    // health degradation: 2 fails -> down; an ok resets
    const d3 = { gateways: [gw(100)] };
    reportHealth(d3, d3.gateways[0].onion, { ok: false });
    reportHealth(d3, d3.gateways[0].onion, { ok: false });
    ok(d3.gateways[0].health === "down", "two failures mark a gateway down");
    reportHealth(d3, d3.gateways[0].onion, { ok: true, latencyMs: 100 });
    ok(d3.gateways[0].health === "up" && d3.gateways[0]._latencyMs === 100, "a success resets health + records latency");
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: directory selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
