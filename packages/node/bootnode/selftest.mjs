// Offline end-to-end proof of the bootnode discovery loop. No Tor, no chain: it mints real
// onion identities, runs the real HTTP bootnode, announces over real HTTP, and verifies the
// served directory with the SAME packages/node/lib/directory.mjs checks a client uses. Every adversarial
// case (forged onion sig, stale replay, duplicate nonce, unstaked operator) must be REJECTED.
//
//   node packages/node/bootnode/selftest.mjs
//
// Exit 0 = all invariants held; nonzero = a check failed (prints which).

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateOnionIdentity } from "./keygen.mjs";
import { buildAnnounce, operatorAuthMessage, canonicalAnnounceBytes } from "./announce.mjs";
import { makeRegistry, makeServer, loadOrMintSigner, payAdvertFromEnv } from "./server.mjs";
import { MockStakeVerifier } from "../lib/gateway-registry.mjs";
import { verifyDirectory, onionToPubkey } from "../lib/directory.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

async function post(base, path, body) {
  const res = await fetch(base + path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  return { status: res.status, json: await res.json() };
}
async function get(base, path) {
  const res = await fetch(base + path);
  return { status: res.status, json: await res.json() };
}

async function main() {
  const work = await mkdtemp(join(tmpdir(), "shade-tree-bootnode-"));
  try {
    // --- mint three real onion identities ------------------------------------
    const g1 = await generateOnionIdentity(join(work, "g1"), { label: "g1" });
    const g2 = await generateOnionIdentity(join(work, "g2"), { label: "g2" });
    const g3 = await generateOnionIdentity(join(work, "g3"), { label: "g3" });
    console.log("keygen:");
    ok(onionToPubkey(g1.onion) === g1.pub, "minted onion's checksum + key round-trip (g1)");
    ok(g1.onion.endsWith(".onion") && g1.onion.length === 62, "onion is a 56-char v3 address");

    // === admission = open ====================================================
    console.log("\nadmission=open:");
    const signer = await loadOrMintSigner(join(work, "signer.key"));
    // minReannounceSec: 0 here isolates the nonce-guard / verification tests from the per-onion
    // re-announce throttle (which is exercised separately below in "registry hardening").
    const registry = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 900, minReannounceSec: 0 });
    const server = makeServer(registry, { signerPub: signer.pub });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    const base = `http://127.0.0.1:${server.address().port}`;

    // 1. honest onion-only announce -> accepted
    const a1 = buildAnnounce({ onion: g1.onion, weight: 100, onionSeedHex: g1.seed });
    ok((await post(base, "/announce", a1)).json.ok === true, "honest announce (g1) accepted");

    // 2. forged onion signature -> rejected
    const a2 = buildAnnounce({ onion: g2.onion, weight: 100, onionSeedHex: g2.seed });
    a2.onionSig = a2.onionSig.replace(/.$/, (c) => (c === "0" ? "1" : "0")); // flip last nibble
    const r2 = await post(base, "/announce", a2);
    ok(r2.json.ok === false && r2.json.err === "bad-onion-sig", "forged onion-sig (g2) rejected");

    // 3. announce g2 signed with the WRONG key (g3's seed) -> rejected (key != address)
    const a2wrong = buildAnnounce({ onion: g2.onion, weight: 100, onionSeedHex: g3.seed });
    ok((await post(base, "/announce", a2wrong)).json.err === "bad-onion-sig", "onion signed by wrong key rejected");

    // 4. stale timestamp -> rejected
    const aStale = buildAnnounce({ onion: g3.onion, weight: 100, onionSeedHex: g3.seed, ts: Math.floor(Date.now() / 1000) - 9999 });
    ok((await post(base, "/announce", aStale)).json.err?.startsWith("stale-ts"), "stale-ts (g3) rejected");

    // 5. replayed nonce -> first ok, second rejected
    const aR = buildAnnounce({ onion: g3.onion, weight: 100, onionSeedHex: g3.seed });
    ok((await post(base, "/announce", aR)).json.ok === true, "fresh announce (g3) accepted");
    ok((await post(base, "/announce", aR)).json.err === "replayed-nonce", "replayed nonce rejected");

    // 6. the served directory verifies with the pinned signer, and lists exactly the accepted onions
    const dir = (await get(base, "/directory")).json;
    ok(verifyDirectory(dir, signer.pub).ok, "served /directory verifies against pinned signer");
    ok(verifyDirectory(dir, "00".repeat(32)).ok === false, "/directory rejected under a wrong pinned signer");
    const onions = new Set(dir.gateways.map((g) => g.onion));
    ok(onions.has(g1.onion) && onions.has(g3.onion) && !onions.has(g2.onion) && onions.size === 2, "directory lists only the accepted gateways (g1,g3)");

    // 7. zero-trust re-verification via GET /gateway/<onion>: the stored announce is
    //    re-checkable from scratch (onion control) without trusting the bootnode.
    const stored = (await get(base, `/gateway/${g1.onion}`)).json;
    const { verifyOnionControl } = await import("../lib/directory.mjs");
    ok(verifyOnionControl(stored.onion, canonicalAnnounceBytes(stored), stored.onionSig), "stored announce re-verifies (onion control) client-side");

    await new Promise((r) => server.close(r));

    // === admission = stake ===================================================
    console.log("\nadmission=stake (mock allowlist):");
    const { ethers } = await import("ethers");
    const opWallet = ethers.Wallet.createRandom();
    const operator = opWallet.address;
    const operatorSig = await opWallet.signMessage(operatorAuthMessage(g1.onion, operator));

    const stake = MockStakeVerifier({ allowlist: operator }); // only this operator is "staked"
    const reg2 = makeRegistry({ signer, stake, admission: "stake", ttlSec: 900 });
    const server2 = makeServer(reg2, { signerPub: signer.pub });
    await new Promise((r) => server2.listen(0, "127.0.0.1", r));
    const base2 = `http://127.0.0.1:${server2.address().port}`;

    // staked operator authorizes g1 -> accepted + labeled staked
    const sOk = buildAnnounce({ onion: g1.onion, weight: 100, onionSeedHex: g1.seed, operator, operatorSig });
    const rOk = await post(base2, "/announce", sOk);
    ok(rOk.json.ok === true && rOk.json.staked === true, "staked+authorized announce accepted and labeled staked");

    // onion-only announce (no operator) under stake mode -> rejected
    const sNo = buildAnnounce({ onion: g3.onion, weight: 100, onionSeedHex: g3.seed });
    ok((await post(base2, "/announce", sNo)).json.err === "not-staked", "onion-only announce rejected in stake mode");

    // authorized but UNSTAKED operator (not in allowlist) -> rejected
    const wStranger = ethers.Wallet.createRandom();
    const strangerSig = await wStranger.signMessage(operatorAuthMessage(g2.onion, wStranger.address));
    const sUnstaked = buildAnnounce({ onion: g2.onion, weight: 100, onionSeedHex: g2.seed, operator: wStranger.address, operatorSig: strangerSig });
    ok((await post(base2, "/announce", sUnstaked)).json.err === "not-staked", "authorized-but-unstaked operator rejected");

    // operator signature over a DIFFERENT onion (stolen sig) -> rejected
    const sStolen = buildAnnounce({ onion: g3.onion, weight: 100, onionSeedHex: g3.seed, operator, operatorSig }); // sig was for g1
    ok((await post(base2, "/announce", sStolen)).json.err === "bad-operator-sig", "operator sig bound to a different onion rejected");

    await new Promise((r) => server2.close(r));

    // === TTL expiry (now injected) ===========================================
    console.log("\nTTL expiry:");
    let clock = 1_000_000;
    const reg3 = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 100, now: () => clock });
    const aT = buildAnnounce({ onion: g1.onion, weight: 100, onionSeedHex: g1.seed, ts: clock });
    await reg3.announce(aT);
    ok(reg3.directory().gateways.length === 1, "gateway present within TTL");
    clock += 101;
    ok(reg3.directory().gateways.length === 0, "gateway expires after TTL without a re-announce");

    // === registry hardening (DoS controls) ===================================
    console.log("\nregistry hardening:");
    // weight clamp: a gateway self-attesting an enormous weight is clamped to MAX_WEIGHT (1000),
    // so it cannot capture ~all client traffic; a negative weight floors at 0.
    let hc = 2_000_000;
    const regW = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", now: () => hc });
    await regW.announce(buildAnnounce({ onion: g1.onion, weight: 1e12, onionSeedHex: g1.seed, ts: hc }));
    ok(regW.directory().gateways[0].weight === 1000, "self-attested weight clamped to MAX_WEIGHT");
    hc += 10;
    await regW.announce(buildAnnounce({ onion: g2.onion, weight: -5, onionSeedHex: g2.seed, ts: hc }));
    ok(regW.directory().gateways.find((g) => g.onion === g2.onion).weight === 0, "negative weight floored at 0");

    // per-onion re-announce throttle: a second announce for the same onion inside the window is
    // rejected BEFORE the expensive verify.
    let tc = 3_000_000;
    const regR = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", minReannounceSec: 5, now: () => tc });
    ok((await regR.announce(buildAnnounce({ onion: g1.onion, weight: 100, onionSeedHex: g1.seed, ts: tc }))).ok === true, "first announce accepted");
    ok((await regR.announce(buildAnnounce({ onion: g1.onion, weight: 100, onionSeedHex: g1.seed, ts: tc }))).reason === "rate-limited", "re-announce within window rate-limited");
    tc += 6;
    ok((await regR.announce(buildAnnounce({ onion: g1.onion, weight: 100, onionSeedHex: g1.seed, ts: tc }))).ok === true, "re-announce after the window accepted");

    // registry size cap: a NEW onion is refused when full; an existing one may still refresh.
    let fc = 4_000_000;
    const regF = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", maxEntries: 1, minReannounceSec: 0, now: () => fc });
    ok((await regF.announce(buildAnnounce({ onion: g1.onion, weight: 100, onionSeedHex: g1.seed, ts: fc }))).ok === true, "first onion fills the (size-1) registry");
    ok((await regF.announce(buildAnnounce({ onion: g2.onion, weight: 100, onionSeedHex: g2.seed, ts: fc }))).reason === "registry-full", "a new onion is refused when the registry is full");
    ok((await regF.announce(buildAnnounce({ onion: g1.onion, weight: 100, onionSeedHex: g1.seed, ts: fc }))).ok === true, "an already-listed onion still refreshes when full");

    // fail-closed stake: if the on-chain read THROWS while stake is required, reject (never admit).
    console.log("\nfail-closed stake:");
    const throwingStake = { isStaked: async () => { throw new Error("rpc down"); }, mode: "throwing" };
    const w = ethers.Wallet.createRandom(); // ethers already imported in the stake section above
    const opSig = await w.signMessage(operatorAuthMessage(g3.onion, w.address));
    const regS = makeRegistry({ signer, stake: throwingStake, admission: "stake", now: () => 5_000_000 });
    const aS = buildAnnounce({ onion: g3.onion, weight: 100, onionSeedHex: g3.seed, operator: w.address, operatorSig: opSig, ts: 5_000_000 });
    ok((await regS.announce(aS)).reason?.startsWith("stake-check-failed"), "a throwing on-chain stake read rejects (fail-closed), never admits");

    // oversized POST body is rejected by the server ingress cap.
    console.log("\nserver ingress cap:");
    const regB = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open" });
    const serverB = makeServer(regB, { signerPub: signer.pub });
    await new Promise((r) => serverB.listen(0, "127.0.0.1", r));
    const baseB = `http://127.0.0.1:${serverB.address().port}`;
    const big = await fetch(baseB + "/announce", { method: "POST", headers: { "content-type": "application/json" }, body: "x".repeat(200 * 1024) }).then((r) => ({ status: r.status })).catch(() => ({ status: "conn-reset" }));
    ok(big.status === 400 || big.status === "conn-reset", "oversized announce body is rejected (not buffered unbounded)");
    await new Promise((r) => serverB.close(r));

    // registrar advert (T-FEAT-7): /health carries `pay` ONLY when advertised; the default is unchanged.
    console.log("\nregistrar advert in /health:");
    ok(payAdvertFromEnv({}) === null && payAdvertFromEnv({ SHADE_TREE_REGISTRAR_ADVERTISE: "0" }) === null, "unset / 0 -> no advert");
    const adv = payAdvertFromEnv({ SHADE_TREE_REGISTRAR_ADVERTISE: "1", SHADE_TREE_PAY_ASSET: "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238", SHADE_TREE_PAY_PRICES: "8=100000,32=400000" });
    ok(adv && adv.port === 8878 && adv.protocols.join() === "x402,mpp" && adv.chain === "eip155:11155111" && adv.tiers["32"] === "400000", "=1 composes {port, protocols, asset, chain, tiers} from SHADE_TREE_PAY_*");
    ok(payAdvertFromEnv({ SHADE_TREE_REGISTRAR_ADVERTISE: "1", SHADE_TREE_PAY_ASSET: "nope", SHADE_TREE_PAY_PRICES: "8=1" }) === null && payAdvertFromEnv({ SHADE_TREE_REGISTRAR_ADVERTISE: "1", SHADE_TREE_PAY_ASSET: "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238", SHADE_TREE_PAY_PRICES: "8=x" }) === null && payAdvertFromEnv({ SHADE_TREE_REGISTRAR_ADVERTISE: "{bad" }) === null, "garbage asset / prices / JSON -> no advert (never a half advert)");
    ok(payAdvertFromEnv({ SHADE_TREE_REGISTRAR_ADVERTISE: '{"port":9999,"protocols":["x402"]}' }).port === 9999, "JSON literal form is passed through");
    const regP = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open" });
    const serverP = makeServer(regP, { signerPub: signer.pub, pay: adv });
    await new Promise((r) => serverP.listen(0, "127.0.0.1", r));
    const hp = await fetch(`http://127.0.0.1:${serverP.address().port}/health`).then((r) => r.json());
    ok(hp.ok && hp.pay && hp.pay.port === 8878 && hp.pay.asset === adv.asset && hp.signer === signer.pub, "/health includes `pay` when advertised");
    await new Promise((r) => serverP.close(r));
    const serverN = makeServer(regP, { signerPub: signer.pub });
    await new Promise((r) => serverN.listen(0, "127.0.0.1", r));
    const hn = await fetch(`http://127.0.0.1:${serverN.address().port}/health`).then((r) => r.json());
    ok(hn.ok && !("pay" in hn), "/health without an advert has no `pay` key (byte-identical default)");
    await new Promise((r) => serverN.close(r));
  } finally {
    await rm(work, { recursive: true, force: true });
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: bootnode selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
