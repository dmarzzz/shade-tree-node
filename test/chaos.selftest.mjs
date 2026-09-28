// CHAOS / FAILURE-INJECTION selftest (T-TEST-14, docs/history/SHIP-PLAN.md).
//
// The adversarial suite proves the trust surface defeats a *malicious* directory. This file
// proves the client survives a *broken* one: it drives the REAL client selection + directory-load
// + gateway-reverify code paths while injecting faults, and asserts the system DEGRADES GRACEFULLY
// — it fails closed, routes around a dead gateway, never crashes, and never serves an unverified
// gateway. Every fault is injected through a seam the production code already exposes (a stubbed
// connector, a corrupt on-disk directory, an injected announce-fetch / stake verifier). No real
// network, no Tor, no chain, no wall-clock sleeps: the whole file runs in well under a second and
// cannot flake (deterministic rng where order matters; property assertions where it does not).
//
//   node test/chaos.selftest.mjs
//
// Exit 0 = every injected fault degraded gracefully.
//
// Faults covered:
//   1. DEAD GATEWAY        — a gateway that always fails to connect; the client fails over to the
//                            next candidate and, after repeated failures, demotes it to the tail.
//   2. PARTIAL FLEET DOWN  — some (then all) gateways "down"; selection still returns a complete,
//                            usable ordering (healthy first, never empty, last-resort otherwise).
//   3. FRESH FETCH THROWS  — a corrupt/garbage directory on refresh; the client falls back to the
//                            last-known-good CACHE and keeps serving the prior fleet (no dark-out).
//   4. CORRUPT SIGNATURE   — a fresh directory with a tampered signature is rejected; the client
//                            keeps the cached good fleet and never surfaces the corrupt entries.
//   5. BROKEN ONION-BINDING— a validly-signed fresh directory that grafts an onion under a pubkey
//                            it does not encode is rejected; the grafted onion NEVER appears in the
//                            client's candidate list (never serves an unverified gateway).
//   6. RE-VERIFY FAULTS    — client zero-trust gateway re-verification (reverifyGateway) under an
//                            injected announce-fetch that throws / substitutes a different onion,
//                            a broken onion<->operator binding, and a lapsed stake: each fails closed.
//
// Skipped for lack of a seam (noted below, no source edit per task constraints):
//   - Injecting a THROW into the live bootnode `/directory` fetch at the selection.mjs layer:
//     fetchOverTor is a hard import in selection.mjs (SHADE_TREE_BOOTNODE_ONION mode), not an injectable
//     dependency. The equivalent last-known-good fallback discipline IS exercised here through the
//     file-source path (loadDirectory + CACHE_PATH), which is the same fail-closed code.

import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  signDirectory, verifyDirectory, selectionOrder, reportHealth, pubkeyToOnion,
} from "../lib/directory.mjs";
import { buildAnnounce, operatorAuthMessage } from "../bootnode/announce.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };
const note = (msg) => console.log(`  note ${msg}`);

// Fresh raw ed25519 keypair as {priv,pub} 32-byte hex (matches the bootnode keygen shape). The
// seed IS the onion identity key, so pubkeyToOnion(pub) is the address the holder of `priv` controls.
function newKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const priv = privateKey.export({ format: "der", type: "pkcs8" });
  const pub = publicKey.export({ format: "der", type: "spki" });
  return { priv: priv.subarray(priv.length - 32).toString("hex"), pub: pub.subarray(pub.length - 32).toString("hex") };
}

// A gateway whose onion<->pubkey binding is HONEST (the pubkey is the key encoded in the address).
function honestGateway(weight = 100, health = "up") {
  const k = newKey();
  return { key: k, onion: pubkeyToOnion(k.pub), pubkey: k.pub, weight, health };
}

function signedDirectory(issued, gateways, signer) {
  return signDirectory({
    version: 1,
    issued,
    signer: signer.pub,
    gateways: gateways.map((g) => ({ onion: g.onion, pubkey: g.pubkey, weight: g.weight, health: g.health })),
  }, signer.priv);
}

// A deterministic pick: pickGateway(rng=()=>0) always returns the first candidate in the pool, so
// selectionOrder becomes exactly [healthy in list order..., down in list order...]. This lets the
// failover walk be asserted with no reliance on weighted-random luck.
const rng0 = () => 0;

// A fake, injected connector: dials never touch the network. `dead` onions always fail; everything
// else "connects" with a fixed latency drawn from an injected monotonic clock (no wall clock).
function makeConnector(deadSet, clock) {
  return (onion) => (deadSet.has(onion) ? { ok: false } : { ok: true, latencyMs: clock.tick() });
}

// Mimic the shim's connect handler over a raw directory object: get the failover order, dial each
// in turn through the injected connector, feed every result back into reportHealth, stop at the
// first success. Returns { order, winner } — winner is null iff EVERY candidate failed (fail-closed,
// never a throw, never a dropped caller connection).
function driveConnect(dir, connector, rng = Math.random) {
  const order = selectionOrder(dir, { rng }).map((g) => g.onion);
  let winner = null;
  for (const onion of order) {
    const res = connector(onion);
    reportHealth(dir, onion, res);
    if (res.ok) { winner = onion; break; }
  }
  return { order, winner };
}

async function main() {
  const clock = { t: 1_000, tick() { this.t += 5; return this.t; } };

  // =====================================================================================
  // FAULT 1 — DEAD GATEWAY: always fails to connect; client must fail over and then demote it.
  // Deterministic order (rng0) so the fail-over walk is exact, not probabilistic.
  // =====================================================================================
  console.log("FAULT 1 — a directory gateway that always fails to connect (fail over + demote):");
  {
    const B = honestGateway(); // the dead one, placed FIRST so it is dialed first
    const A = honestGateway();
    const C = honestGateway();
    const dir = signedDirectory(1000, [B, A, C], newKey()); // sign is irrelevant here; we drive selection
    dir.gateways.forEach((g) => { g.health = "up"; });
    const dead = new Set([B.onion]);
    const connector = makeConnector(dead, clock);

    const r1 = driveConnect(dir, connector, rng0);
    ok(r1.order[0] === B.onion, "dead gateway is first in the try order (worst case for fail-over)");
    ok(r1.winner === A.onion, "first CONNECT fails on the dead gateway and fails over to the next candidate (no dead-end)");

    const r2 = driveConnect(dir, connector, rng0); // second failure crosses the demotion threshold
    ok(r2.winner === A.onion, "second CONNECT still routes around the dead gateway");
    const bEntry = dir.gateways.find((g) => g.onion === B.onion);
    ok(bEntry.health === "down", "the repeatedly-failing gateway is demoted to health=down (>=2 fails)");

    const r3 = driveConnect(dir, connector, rng0);
    ok(r3.order[r3.order.length - 1] === B.onion, "once demoted, the dead gateway sinks to the TAIL of the failover order");
    ok(r3.winner === A.onion, "traffic keeps flowing through a healthy gateway; the client never dead-ends on the dead one");
  }

  // =====================================================================================
  // FAULT 2 — PARTIAL FLEET DOWN: selection must still yield a usable, COMPLETE ordering.
  // =====================================================================================
  console.log("\nFAULT 2 — a partial fleet with some (then all) gateways down (still routable):");
  {
    const gws = [honestGateway(), honestGateway(), honestGateway(), honestGateway()];
    const dir = signedDirectory(1000, gws, newKey());
    dir.gateways.forEach((g) => { g.health = "up"; });
    // Knock TWO gateways down through the real demotion path (two failed reports each).
    for (const idx of [1, 3]) {
      reportHealth(dir, dir.gateways[idx].onion, { ok: false });
      reportHealth(dir, dir.gateways[idx].onion, { ok: false });
    }
    const order = selectionOrder(dir, { rng: rng0 });
    ok(order.length === 4, "selection returns the COMPLETE fleet as a failover list even with half of it down");
    ok(order.slice(0, 2).every((g) => g.health !== "down"), "the two healthy gateways are ordered ahead of the down ones");
    ok(order.slice(2).every((g) => g.health === "down"), "down gateways are kept as last-resort failovers, not dropped");

    // Now knock the REMAINING two down: an all-down fleet must still return a usable ordering,
    // never an empty list (degrade, do not dead-end).
    for (const idx of [0, 2]) {
      reportHealth(dir, dir.gateways[idx].onion, { ok: false });
      reportHealth(dir, dir.gateways[idx].onion, { ok: false });
    }
    const allDown = selectionOrder(dir, { rng: rng0 });
    ok(allDown.length === 4, "an all-down fleet still yields a complete last-resort ordering (never empty)");
    // And a connector that can reach exactly one of them still resolves — degradation, not outage.
    const reachable = new Set(gws.map((g) => g.onion)); reachable.delete(gws[0].onion);
    const oneUp = new Set([gws[0].onion]); // gws[0] is dead; the rest are reachable
    const res = driveConnect(dir, makeConnector(oneUp, clock), rng0);
    ok(res.winner && reachable.has(res.winner), "even with the whole fleet marked down, a reachable gateway is still selected and dialed");
  }

  // =====================================================================================
  // FAULTS 3-5 — CLIENT DIRECTORY LOAD under injected corruption, through the REAL selection.mjs.
  // File-source mode, refresh-every-call, isolated caches. Config is read at import, so env is set
  // BEFORE the dynamic import. Each phase overwrites the on-disk directory with a different fault
  // and asserts the client degrades to the last-known-good CACHE and never surfaces the bad entries.
  // =====================================================================================
  console.log("\nFAULTS 3-5 — client directory load under injected corruption (fall back, fail closed):");
  const work = mkdtempSync(join(tmpdir(), "shade-tree-chaos-"));
  try {
    const signer = newKey();
    const dirPath = join(work, "directory.json");
    const cachePath = join(work, "directory.lkg");
    const healthPath = join(work, "gateway-health.json");

    process.env.SHADE_TREE_DIRECTORY = dirPath;
    process.env.SHADE_TREE_DIRECTORY_CACHE = cachePath;
    process.env.SHADE_TREE_DIR_SIGNER = signer.pub;
    process.env.SHADE_TREE_DIRECTORY_REFRESH_MS = "0"; // every selectCandidates() re-reads the file
    process.env.SHADE_TREE_HEALTH_CACHE = healthPath;  // isolated: never touch the real health cache
    delete process.env.SHADE_TREE_BOOTNODE_ONION;      // file source, not the un-injectable bootnode fetch
    delete process.env.SHADE_TREE_VERIFY_STAKE;

    const sel = await import("../client/selection.mjs");
    sel._resetIssuedFloor();

    // --- baseline: a good directory establishes the fleet AND writes the last-known-good cache ---
    const fleet1 = [honestGateway(), honestGateway(), honestGateway()];
    writeFileSync(dirPath, JSON.stringify(signedDirectory(1000, fleet1, signer)) + "\n");
    const baseSet = new Set(fleet1.map((g) => g.onion.replace(/\.onion$/, "")));
    const base = await sel.selectCandidates();
    ok(base.length === 3, "baseline: good directory loads the full fleet and seeds the LKG cache");
    ok(base.every((c) => baseSet.has(c.onion)), "baseline: candidates are exactly the signed fleet");

    // --- FAULT 3: the fresh directory is GARBAGE (parse throws) => fall back to LKG cache ---
    writeFileSync(dirPath, "{ this is not valid json ]\n");
    const afterGarbage = await sel.selectCandidates();
    ok(afterGarbage.length === 3, "FAULT 3: a corrupt/garbage fresh directory does NOT go dark");
    ok(afterGarbage.every((c) => baseSet.has(c.onion)), "FAULT 3: client falls back to the last-known-good cache (same verified fleet)");

    // --- FAULT 4: a fresh directory with a TAMPERED signature is rejected => keep the cache ---
    const fleetBad = [honestGateway(), honestGateway()]; // different onions, so we can prove they never surface
    const badSig = signedDirectory(2000, fleetBad, signer);
    badSig.signature = badSig.signature.replace(/.$/, (c) => (c === "0" ? "1" : "0")); // corrupt one byte
    ok(verifyDirectory(badSig, signer.pub).reason === "bad-signature", "FAULT 4 (sanity): the tampered directory fails verifyDirectory with bad-signature");
    writeFileSync(dirPath, JSON.stringify(badSig) + "\n");
    const afterBadSig = await sel.selectCandidates();
    const badSet = new Set(fleetBad.map((g) => g.onion.replace(/\.onion$/, "")));
    ok(afterBadSig.every((c) => baseSet.has(c.onion)), "FAULT 4: signature-corrupt directory rejected; still serving the cached good fleet");
    ok(afterBadSig.every((c) => !badSet.has(c.onion)), "FAULT 4: none of the corrupt directory's gateways are ever surfaced to selection");

    // --- FAULT 5: a VALIDLY-SIGNED fresh directory that grafts an onion under a pubkey it does not
    //     encode (broken onion<->pubkey binding) is rejected => the grafted onion never appears ---
    const attacker = honestGateway();
    const victim = honestGateway();
    const graft = signDirectory({
      version: 1, issued: 2000, signer: signer.pub,
      gateways: [{ onion: attacker.onion, pubkey: victim.pubkey, weight: 100, health: "up" }], // GRAFT
    }, signer.priv);
    ok(verifyDirectory(graft, signer.pub).reason?.startsWith("pubkey-onion-mismatch"), "FAULT 5 (sanity): the graft fails verifyDirectory on the onion<->pubkey binding");
    writeFileSync(dirPath, JSON.stringify(graft) + "\n");
    const afterGraft = await sel.selectCandidates();
    const attackerOnion = attacker.onion.replace(/\.onion$/, "");
    ok(!afterGraft.some((c) => c.onion === attackerOnion), "FAULT 5: the grafted attacker onion NEVER enters the client's candidate list (never serves an unverified gateway)");
    ok(afterGraft.every((c) => baseSet.has(c.onion)), "FAULT 5: client stayed on the last-known-good verified fleet throughout the poisoning attempt");

    // --- recovery + end-to-end fail-over through the real selectCandidates/reportResult loop ---
    // A fresh, valid directory (issued advances past the floor) is accepted again, and a dead
    // gateway among it is routed around on every CONNECT — regardless of the (random) pick order.
    const fleet2 = [honestGateway(), honestGateway(), honestGateway()];
    writeFileSync(dirPath, JSON.stringify(signedDirectory(3000, fleet2, signer)) + "\n");
    const recovered = await sel.selectCandidates();
    ok(recovered.length === 3, "recovery: a fresh valid directory (issued advanced) is accepted after the fault storm");

    const deadOnion = fleet2[0].onion.replace(/\.onion$/, "");
    let crashed = false, nulls = 0, deadWins = 0;
    for (let i = 0; i < 10; i++) {
      try {
        const cands = await sel.selectCandidates();
        let winner = null;
        for (const c of cands) {
          const res = c.onion === deadOnion ? { ok: false } : { ok: true, latencyMs: clock.tick() };
          sel.reportResult(c.onion, res);
          if (res.ok) { winner = c.onion; break; }
        }
        if (winner === null) nulls++;
        if (winner === deadOnion) deadWins++;
      } catch { crashed = true; }
    }
    ok(!crashed, "end-to-end: 10 CONNECTs against a dead gateway never throw (the client never crashes)");
    ok(nulls === 0, "end-to-end: every CONNECT resolved to a live gateway (never a dead-ended null while a healthy gateway exists)");
    ok(deadWins === 0, "end-to-end: the dead gateway is never returned as the winning route (always failed over)");
  } finally {
    rmSync(work, { recursive: true, force: true });
  }

  // =====================================================================================
  // FAULT 6 — GATEWAY RE-VERIFICATION under injected announce-fetch / stake faults.
  // reverifyGateway(entry, {fetchAnnounce, stake}) is the client's zero-trust re-check of a
  // stake-claiming entry (T-DEV-5). We inject its two dependencies directly (no Tor, no chain) and
  // assert every failure mode fails CLOSED (the gateway is dropped), while the honest path passes.
  // =====================================================================================
  console.log("\nFAULT 6 — zero-trust gateway re-verification under injected fetch/stake faults:");
  {
    const sel = await import("../client/selection.mjs");
    const { ethers } = await import("ethers");

    const gk = newKey();
    const onion = pubkeyToOnion(gk.pub);
    const opWallet = ethers.Wallet.createRandom();
    const operator = opWallet.address;
    const ts = 5_000; // fixed; reverifyGateway uses skew=Infinity so the value is irrelevant (no clock)
    const opSig = await opWallet.signMessage(operatorAuthMessage(onion, operator));
    const goodAnnounce = buildAnnounce({ onion, weight: 100, onionSeedHex: gk.priv, operator, operatorSig: opSig, ts });
    const entry = { onion, operator };
    const staked = { isStaked: async () => true };

    // control: a valid stored announce + a live stake re-verifies clean.
    const good = await sel.reverifyGateway(entry, { fetchAnnounce: async () => goodAnnounce, stake: staked });
    ok(good.ok === true, "control: an honest stake-claiming gateway survives re-verification");

    // fetch throws (bootnode/announce unreachable) => drop, do not admit on faith.
    const fetchThrows = await sel.reverifyGateway(entry, { fetchAnnounce: async () => { throw new Error("dial timeout"); }, stake: staked });
    ok(fetchThrows.ok === false && fetchThrows.reason?.startsWith("announce-fetch-failed"), "injected announce-fetch throw => gateway dropped (announce-fetch-failed), fail closed");

    // the fetch returns a valid announce for a DIFFERENT onion (substitution) => rejected.
    const other = newKey();
    const otherOnion = pubkeyToOnion(other.pub);
    const otherOpSig = await opWallet.signMessage(operatorAuthMessage(otherOnion, operator));
    const otherAnnounce = buildAnnounce({ onion: otherOnion, weight: 100, onionSeedHex: other.priv, operator, operatorSig: otherOpSig, ts });
    const substituted = await sel.reverifyGateway(entry, { fetchAnnounce: async () => otherAnnounce, stake: staked });
    ok(substituted.ok === false && substituted.reason === "announce-onion-mismatch", "a substituted announce for a different onion is rejected (announce-onion-mismatch)");

    // broken onion<->operator binding: the operator sig authorizes a DIFFERENT onion (stolen) => rejected.
    const stolenSig = await opWallet.signMessage(operatorAuthMessage(otherOnion, operator)); // signs other onion
    const brokenBinding = buildAnnounce({ onion, weight: 100, onionSeedHex: gk.priv, operator, operatorSig: stolenSig, ts });
    const brokenRes = await sel.reverifyGateway(entry, { fetchAnnounce: async () => brokenBinding, stake: staked });
    ok(brokenRes.ok === false && brokenRes.reason === "bad-operator-sig", "a broken onion<->operator binding (stolen sig) is rejected (bad-operator-sig)");

    // stake lapsed on chain (isStaked flips false) => dropped even though signatures are valid.
    const lapsed = await sel.reverifyGateway(entry, { fetchAnnounce: async () => goodAnnounce, stake: { isStaked: async () => false } });
    ok(lapsed.ok === false && lapsed.reason === "not-staked", "a lapsed/unstaked operator is dropped on re-verification (not-staked)");
  }

  note("skipped (no seam, no source edit): injecting a THROW into the live bootnode /directory fetch at the selection.mjs layer — fetchOverTor is a hard import there. The same fail-closed LKG fallback is exercised via the file-source path (FAULTS 3-5).");
  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: chaos / failure-injection selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
