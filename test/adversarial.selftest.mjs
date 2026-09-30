// Auditor-facing ADVERSARIAL SCENARIO suite for the discovery / directory / announce trust
// surface. The unit selftests (packages/node/lib/directory.selftest.mjs, packages/node/bootnode/selftest.mjs,
// test/fuzz.selftest.mjs) prove each primitive in isolation. THIS file does something
// different: it composes the real modules into end-to-end ATTACK scenarios, so an auditor has
// ONE place that reads "here is the attack, here is the attack executed against the real code,
// here is the proof it is defeated." Nothing here re-tests a unit assertion for its own sake;
// every check is the punchline of an attack narrative.
//
//   node test/adversarial.selftest.mjs
//
// Exit 0 = every modelled attack was defeated. No Tor, no chain, no real RLN proofs — this is
// the trust surface a client leans on BEFORE it ever dials a gateway (who is in the directory,
// did they prove control, is the operator staked), which is exactly where forgery is cheapest.
//
// Attacks covered:
//   1. POISONED DIRECTORY  — hostile bootnode signer grafts an onion it does not control.
//   2. MITM BOOTNODE       — the served directory is tampered on the wire / re-signed hostile.
//   3. FORGED ANNOUNCE     — the full announce forgery matrix against the live registry.
//   4. STAKE LAPSE         — an operator staked at announce time later unstakes.
//   5. REGISTRY DoS        — mint->announce flood + weight-grab against the DoS controls.
//   6. GATEWAY ENDPOINT DoS — slow-loris on the envelope, half-close crash, tunnel pinning
//                             (T-HARD-4; real handler on a real loopback socket).
//   7. BOOTNODE ENDPOINT DoS — fresh-onion verify burst vs the GLOBAL bucket (spy proves
//                             verify never runs past the cap), HTTP slow-loris cut off.
//   8. PAID ADMISSION (T-FEAT-7) — lives in its own files because it needs a chain: the wire
//                             parse matrix (packages/node/payments/wire.selftest.mjs: tampered x402 payloads,
//                             HMAC-broken / replayed / mis-nonced MPP credentials, spec golden)
//                             and the end-to-end attacks on the registrar over anvil
//                             (packages/node/payments/registrar.selftest.mjs §5: wrong amount / payTo /
//                             window / signature, replayed nonce, already-inserted leaf,
//                             oversize body+header, slow-loris, rate bucket).

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import net from "node:net";

import { generateOnionIdentity } from "../packages/node/bootnode/keygen.mjs";
import { buildAnnounce, operatorAuthMessage, verifyAnnounce } from "../packages/node/bootnode/announce.mjs";
import { makeRegistry, makeServer, loadOrMintSigner } from "../packages/node/bootnode/server.mjs";
import { MockStakeVerifier } from "../packages/node/lib/gateway-registry.mjs";
import {
  signDirectory, verifyDirectory, onionToPubkey, pickGateway,
} from "../packages/node/lib/directory.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };
const note = (msg) => console.log(`  note ${msg}`);

async function getJson(base, path) {
  const res = await fetch(base + path);
  return { status: res.status, json: await res.json() };
}
async function postJson(base, path, body) {
  const res = await fetch(base + path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  return { status: res.status, json: await res.json() };
}

async function main() {
  const work = await mkdtemp(join(tmpdir(), "shade-tree-adversarial-"));
  try {
    // Real onion identities used across the scenarios. Each `.onion` IS its ed25519 identity
    // key; whoever holds the seed controls the address and only they can sign for it.
    const victim   = await generateOnionIdentity(join(work, "victim"),   { label: "victim" });   // an honest gateway
    const attacker = await generateOnionIdentity(join(work, "attacker"), { label: "attacker" }); // the address traffic would be diverted to
    const honest   = await generateOnionIdentity(join(work, "honest"),   { label: "honest" });

    // =====================================================================================
    // SCENARIO 1 — POISONED DIRECTORY
    // The bootnode's OWN signer key is hostile (or stolen). It signs a directory that grafts
    // the attacker's onion under the VICTIM's pubkey: "this is the victim's gateway, dial it
    // here." The client PINS this very signer, so signature + provenance both pass. The graft
    // must still die on the onion<->pubkey binding: a v3 address IS a key, and the attacker's
    // address does not encode the victim's key.
    // =====================================================================================
    console.log("SCENARIO 1 — poisoned directory (hostile signer grafts an onion):");
    const hostileSigner = await loadOrMintSigner(join(work, "hostile-signer.key"));

    const poisoned = signDirectory({
      version: 1, issued: 1_000, signer: hostileSigner.pub,
      gateways: [{ onion: attacker.onion, pubkey: victim.pub, weight: 100, health: "up" }], // GRAFT
    }, hostileSigner.priv);

    // Sanity: this is a genuinely, correctly signed directory under the pinned signer — the
    // attack is NOT a broken signature. It fails purely on the address<->key binding.
    ok(onionToPubkey(poisoned.gateways[0].onion) !== poisoned.gateways[0].pubkey, "graft entry: onion address does not encode the claimed pubkey");
    const v1 = verifyDirectory(poisoned, hostileSigner.pub);
    ok(v1.ok === false && v1.reason?.startsWith("pubkey-onion-mismatch"), "client rejects the grafted onion (pubkey-onion-mismatch) even though it pins this signer");

    // Second face of the same attack: a directory that is perfectly well-formed but signed by
    // a signer the client did NOT pin. Provenance alone defeats it, before any binding check.
    const strangerSigner = await loadOrMintSigner(join(work, "stranger-signer.key"));
    const cleanButUnpinned = signDirectory({
      version: 1, issued: 1_001, signer: strangerSigner.pub,
      gateways: [{ onion: honest.onion, pubkey: honest.pub, weight: 100, health: "up" }],
    }, strangerSigner.priv);
    const v1b = verifyDirectory(cleanButUnpinned, hostileSigner.pub); // client pins the hostile/real signer, not the stranger
    ok(v1b.ok === false && v1b.reason === "signer-not-pinned", "directory signed by a non-pinned signer rejected (signer-not-pinned)");

    // =====================================================================================
    // SCENARIO 2 — MITM BOOTNODE
    // A real, honest bootnode serves a real signed directory. An on-path attacker (or a later-
    // compromised bootnode) swaps one entry's onion to the attacker's address so the client
    // dials the attacker while believing it is the honest gateway. Two variants:
    //   (a) MITM without the signer key — swaps the onion, cannot re-sign -> signature breaks.
    //   (b) MITM WITH the signer key    — re-signs the swap -> still dies on the binding.
    // =====================================================================================
    console.log("\nSCENARIO 2 — MITM bootnode (directory tampered on the wire):");
    const signer = await loadOrMintSigner(join(work, "signer.key"));
    const registry = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 900, minReannounceSec: 0 });
    const server = makeServer(registry, { signerPub: signer.pub });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    const base = `http://127.0.0.1:${server.address().port}`;
    try {
      ok((await postJson(base, "/announce", buildAnnounce({ onion: honest.onion, weight: 100, onionSeedHex: honest.seed }))).json.ok === true, "honest gateway announces to the real bootnode");
      const served = (await getJson(base, "/directory")).json;
      ok(verifyDirectory(served, signer.pub).ok, "the untampered served directory verifies against the pinned signer (baseline)");

      // (a) on-path swap, attacker has NO signer key: the onion is a signed field, so the
      //     signature over the canonical bytes no longer holds.
      const wireTampered = JSON.parse(JSON.stringify(served));
      wireTampered.gateways[0].onion = attacker.onion; // divert traffic, keep the honest pubkey
      const v2a = verifyDirectory(wireTampered, signer.pub);
      ok(v2a.ok === false && v2a.reason === "bad-signature", "on-path onion swap without the signer key breaks the signature (bad-signature)");

      // (b) the bootnode itself is hostile and re-signs after the swap with the REAL signer key.
      //     A validly-re-signed directory STILL cannot carry an onion whose key the signer does
      //     not encode: the binding is checked independently of who signed the list.
      const reSigned = signDirectory({
        version: served.version, issued: served.issued, signer: signer.pub,
        gateways: [{ onion: attacker.onion, pubkey: honest.pub, weight: 100, health: "up" }],
      }, signer.priv);
      const v2b = verifyDirectory(reSigned, signer.pub);
      ok(v2b.ok === false && v2b.reason?.startsWith("pubkey-onion-mismatch"), "even a validly-re-signed directory cannot bind the attacker's onion to the honest key (pubkey-onion-mismatch)");
    } finally {
      await new Promise((r) => server.close(r));
    }

    // =====================================================================================
    // SCENARIO 3 — FORGED ANNOUNCE (the attack matrix)
    // Everything an attacker can put in an /announce to get a gateway they do not control (or a
    // stale/replayed/unstaked one) admitted, run against the REAL registry.announce path. Each
    // row is a distinct forgery; each must be rejected with its specific reason.
    // =====================================================================================
    console.log("\nSCENARIO 3 — forged announce matrix (against the live registry):");
    const clock3 = 2_000_000;
    const reg3 = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 900, minReannounceSec: 0, now: () => clock3 });

    // row 0 — control: an honest announce is accepted (so the rejections below are the forgery,
    // not a broken harness).
    ok((await reg3.announce(buildAnnounce({ onion: honest.onion, weight: 100, onionSeedHex: honest.seed, ts: clock3 }))).ok === true, "control: an honest announce is accepted");

    // row 1 — forged onion signature (attacker does not hold the onion's key).
    const forged = buildAnnounce({ onion: victim.onion, weight: 100, onionSeedHex: victim.seed, ts: clock3 });
    forged.onionSig = forged.onionSig.replace(/.$/, (c) => (c === "0" ? "1" : "0"));
    ok((await reg3.announce(forged)).reason === "bad-onion-sig", "forged onion signature rejected (bad-onion-sig)");

    // row 2 — onion signed by the WRONG key (announces victim's address using attacker's seed).
    ok((await reg3.announce(buildAnnounce({ onion: victim.onion, weight: 100, onionSeedHex: attacker.seed, ts: clock3 }))).reason === "bad-onion-sig", "onion signed by a key that is not the address rejected (bad-onion-sig)");

    // row 3 — stale timestamp (a captured announce replayed far outside the freshness window).
    ok((await reg3.announce(buildAnnounce({ onion: victim.onion, weight: 100, onionSeedHex: victim.seed, ts: clock3 - 9_999 }))).reason?.startsWith("stale-ts"), "stale-dated announce rejected (stale-ts)");

    // row 4 — replayed nonce (a valid announce captured and re-submitted verbatim in-window).
    const replay = buildAnnounce({ onion: victim.onion, weight: 100, onionSeedHex: victim.seed, ts: clock3 });
    ok((await reg3.announce(replay)).ok === true, "first submission of a fresh announce accepted");
    ok((await reg3.announce(replay)).reason === "replayed-nonce", "verbatim replay of the same announce rejected (replayed-nonce)");

    // rows 5-6 — stake mode: an operator that never staked, and a stolen operator signature.
    const { ethers } = await import("ethers");
    const opWallet = ethers.Wallet.createRandom();
    const operator = opWallet.address;
    const opSig = await opWallet.signMessage(operatorAuthMessage(honest.onion, operator));
    const clockS = 2_100_000;
    const regStake = makeRegistry({ signer, stake: MockStakeVerifier({ allowlist: operator }), admission: "stake", ttlSec: 900, minReannounceSec: 0, now: () => clockS });

    ok((await regStake.announce(buildAnnounce({ onion: honest.onion, weight: 100, onionSeedHex: honest.seed, operator, operatorSig: opSig, ts: clockS }))).staked === true, "control: staked+authorized operator admitted and labelled staked");

    // row 5 — an operator not in the staked set (authorized signature, but no live stake).
    const stranger = ethers.Wallet.createRandom();
    const strangerSig = await stranger.signMessage(operatorAuthMessage(victim.onion, stranger.address));
    ok((await regStake.announce(buildAnnounce({ onion: victim.onion, weight: 100, onionSeedHex: victim.seed, operator: stranger.address, operatorSig: strangerSig, ts: clockS }))).reason === "not-staked", "unstaked operator rejected in stake mode (not-staked)");

    // row 6 — a stolen operator signature: opSig authorizes honest.onion, reused for victim.onion.
    ok((await regStake.announce(buildAnnounce({ onion: victim.onion, weight: 100, onionSeedHex: victim.seed, operator, operatorSig: opSig, ts: clockS }))).reason === "bad-operator-sig", "operator signature bound to a different onion (stolen sig) rejected (bad-operator-sig)");

    // =====================================================================================
    // SCENARIO 4 — STAKE LAPSE MID-SESSION
    // An operator is staked when it announces, is admitted, and appears in the directory. Later
    // it UNSTAKES (revocation == unstake). We model the chain by an isStaked that flips to false
    // and assert the lapse is observable/enforced by the three checks that actually run today.
    // =====================================================================================
    console.log("\nSCENARIO 4 — stake lapse mid-session (operator unstakes after admission):");
    let onChainStaked = true;
    const flippingStake = { isStaked: async () => onChainStaked, mode: "mock:flip" };
    let clock4 = 3_000_000;
    const reg4 = makeRegistry({ signer, stake: flippingStake, admission: "stake", ttlSec: 900, minReannounceSec: 0, now: () => clock4 });

    const opSig4 = await opWallet.signMessage(operatorAuthMessage(honest.onion, operator));
    const admit = await reg4.announce(buildAnnounce({ onion: honest.onion, weight: 100, onionSeedHex: honest.seed, operator, operatorSig: opSig4, ts: clock4 }));
    ok(admit.ok === true && admit.staked === true, "operator staked at announce time -> admitted and listed");
    ok(reg4.directory().gateways.some((g) => g.onion === honest.onion), "gateway is present in the served directory while staked");

    // ---- the operator unstakes on chain ----
    onChainStaked = false;

    // Enforcement 1 (live, works today): the raw on-chain read now returns false. Any client
    // doing the T-DEV-5 re-check would see the lapse directly.
    ok((await flippingStake.isStaked(operator)) === false, "after unstake the live on-chain isStaked(operator) returns false (observable to any re-checker)");

    // Enforcement 2 (live, works today): the entry cannot REFRESH. On the next heartbeat the
    // re-announce is rejected (not-staked), so the entry drops at TTL rather than living forever.
    clock4 += 10;
    const refresh = await reg4.announce(buildAnnounce({ onion: honest.onion, weight: 100, onionSeedHex: honest.seed, operator, operatorSig: opSig4, ts: clock4 }));
    ok(refresh.ok === false && refresh.reason === "not-staked", "an unstaked operator's re-announce is refused (not-staked) -> entry drops at TTL, cannot persist");

    // Enforcement 3 (PENDING): the bootnode's *already-served* directory still carries the stale
    // `staked` label until TTL/refresh. Closing that gap mid-session requires the CLIENT to
    // re-check GET /gateway/<onion> + isStaked itself and not trust the bootnode's label.
    const stale = reg4.directory().gateways.find((g) => g.onion === honest.onion);
    ok(stale && stale.staked === true, "bootnode's cached directory still shows staked=true (stale-positive) until TTL — this is the gap");
    note("client-side mid-session re-verification is PENDING T-DEV-5 (docs/history/SHIP-PLAN.md:103): the client must fetch GET /gateway/<onion> and re-check operatorSig + isStaked itself. Today the lapse is enforced on refresh + observable via the live on-chain read (asserted above), but the served label is not yet re-verified by the client mid-session.");

    // =====================================================================================
    // SCENARIO 5 — REGISTRY DoS
    // An attacker mints onions for free and floods /announce to (a) exhaust registry memory and
    // (b) self-assign a colossal selection weight to capture ~all client traffic (a concentration
    // / deanonymization lever). The size cap, per-onion throttle, and weight clamp must hold.
    // =====================================================================================
    console.log("\nSCENARIO 5 — registry DoS (mint->announce flood + weight grab):");
    let clock5 = 4_000_000;
    const MAX = 3;
    const regDoS = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 900, maxEntries: MAX, minReannounceSec: 5, now: () => clock5 });

    // Flood: mint FLOOD fresh onions (all crypto-valid — the attacker really holds each key) and
    // announce them. The registry must never grow past MAX; overflow onions get registry-full.
    const FLOOD = 8;
    let fullRejects = 0;
    const floodOnions = [];
    for (let i = 0; i < FLOOD; i++) {
      const id = await generateOnionIdentity(join(work, `flood-${i}`), { label: `flood-${i}` });
      floodOnions.push(id);
      const r = await regDoS.announce(buildAnnounce({ onion: id.onion, weight: 100, onionSeedHex: id.seed, ts: clock5 }));
      if (r.reason === "registry-full") fullRejects++;
    }
    ok(regDoS.size() === MAX, `registry size stays bounded at maxEntries=${MAX} under a ${FLOOD}-onion flood (never grows unbounded)`);
    ok(fullRejects === FLOOD - MAX, `every overflow onion is refused with registry-full (${fullRejects}/${FLOOD - MAX})`);

    // Per-onion throttle: an already-resident onion cannot spin the expensive verify path by
    // re-announcing inside the window; it is rejected cheaply BEFORE verification.
    const resident = floodOnions[0];
    ok((await regDoS.announce(buildAnnounce({ onion: resident.onion, weight: 100, onionSeedHex: resident.seed, ts: clock5 }))).reason === "rate-limited", "a resident onion re-announcing inside the window is rate-limited (cheap pre-verify reject)");

    // Weight grab: a gateway self-attests an astronomical weight to win ~100% of client picks.
    // The clamp caps it at MAX_WEIGHT=1000, so it can never dominate a fleet of honestly-weighted
    // peers. We prove the clamp AND that the resulting selection share is bounded, not ~100%.
    let clockW = 5_000_000;
    const regW = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 900, minReannounceSec: 0, now: () => clockW });
    await regW.announce(buildAnnounce({ onion: attacker.onion, weight: 1e12, onionSeedHex: attacker.seed, ts: clockW })); // greedy
    await regW.announce(buildAnnounce({ onion: honest.onion, weight: 1000, onionSeedHex: honest.seed, ts: clockW }));   // honest peer at max
    await regW.announce(buildAnnounce({ onion: victim.onion, weight: 1000, onionSeedHex: victim.seed, ts: clockW }));   // honest peer at max
    const dirW = regW.directory();
    const greedy = dirW.gateways.find((g) => g.onion === attacker.onion);
    ok(greedy.weight === 1000, "self-attested weight 1e12 is clamped to MAX_WEIGHT=1000 in the signed directory");

    // Empirically: with the clamp, the greedy gateway wins ~1/3 of picks against two equal peers,
    // NOT the ~100% its 1e12 claim intended. (Unclamped, 1e12/(1e12+2000) ~= 0.9999999998.)
    let greedyWins = 0;
    const N = 6000;
    for (let i = 0; i < N; i++) if (pickGateway(dirW)?.onion === attacker.onion) greedyWins++;
    const share = greedyWins / N;
    ok(share < 0.6, `weight clamp bounds the greedy gateway's traffic share to ${(share * 100).toFixed(1)}% (~33% expected; unclamped it would be ~100%), so it cannot capture the fleet`);

    // =====================================================================================
    // SCENARIO 6 — GATEWAY ENDPOINT DoS (T-HARD-4)
    // An unauthenticated peer (it has NO proof) tries to exhaust the gateway without ever
    // passing the gate: (a) slow-loris — connect and never finish the envelope, or dribble it
    // one byte at a time forever; (b) the half-close crash — send a partial envelope then FIN
    // (pre-fix this took the WHOLE gateway process down: an unhandled 'error' on writeAfterFIN);
    // (c) tunnel pinning — one admitted proof, replayed inside the honest-retry window, used to
    // hold N idle tunnels open. Executed against the REAL connection handler on a REAL loopback
    // TCP server; only verify is stubbed (no Groth16) and the knobs are tiny for speed.
    // =====================================================================================
    console.log("\nSCENARIO 6 — gateway endpoint DoS (slow-loris / half-close crash / tunnel pinning):");
    process.env.SHADE_TREE_EGRESS_ALLOW = "127.0.0.1:*"; // egress policy is built at import; allow the loopback echo target
    process.env.SHADE_TREE_ALLOW_PRIVATE_TARGETS = "1"; // isolated loopback attack harness only
    const { makeHandler, makeConnLimiter } = await import("../packages/node/gateway/gateway.mjs");
    const echo = net.createServer((c) => { c.on("data", (d) => c.write(d)); c.on("error", () => {}); });
    await new Promise((r) => echo.listen(0, "127.0.0.1", r));
    const stubVerify = async (env) => ({ ok: true, nullifier: String(env.nullifier), externalNullifier: "1", share: env.share || { x: "1", y: "2" } });
    const limiter6 = makeConnLimiter({ maxConns: 3, maxPerNullifier: 2 });
    const gw = net.createServer(makeHandler({ admit: async () => ({ ok: true, action: "first" }) }, { verify: stubVerify, envelopeTimeoutMs: 250, idleTimeoutMs: 0, limiter: limiter6 }));
    await new Promise((r) => gw.listen(0, "127.0.0.1", r));
    const gwPort = gw.address().port;
    const dial = () => new Promise((resolve, reject) => {
      const sock = net.connect(gwPort, "127.0.0.1"); const st = { sock, closed: false, buf: "" };
      sock.on("data", (d) => { st.buf += d.toString(); }); sock.on("error", () => {}); sock.on("close", () => { st.closed = true; });
      sock.once("connect", () => resolve(st)); sock.once("error", reject);
    });
    const until = async (pred, ms) => { const end = Date.now() + ms; while (Date.now() < end) { if (pred()) return true; await new Promise((r) => setTimeout(r, 5)); } return false; };
    const envOf = (n) => JSON.stringify({ v: 4, target: `127.0.0.1:${echo.address().port}`, nullifier: n, share: { x: "1", y: "2" }, nonce: "n" }) + "\n";
    try {
      // (a) slow-loris: silence, then dribble. Both die at the ABSOLUTE deadline.
      const t0 = Date.now();
      const silent = await dial();
      ok(await until(() => silent.closed, 3000) && Date.now() - t0 < 2000, "slow-loris (silence): connection cut at the envelope deadline, not held forever");
      ok(/bad-envelope:envelope timeout/.test(silent.buf), "…with the envelope-timeout reply");
      const t1 = Date.now();
      const drib = await dial();
      const drip = setInterval(() => { if (!drib.closed) drib.sock.write("x"); }, 20);
      ok(await until(() => drib.closed, 3000) && Date.now() - t1 < 2000, "slow-loris (dribble, one byte/20ms, no newline): still cut at the same deadline — activity does not re-arm it");
      clearInterval(drip);
      // (b) half-close crash: partial envelope + FIN. The process must survive and keep serving.
      const half = await dial(); half.sock.write("{\"partial\":"); half.sock.end();
      await until(() => half.closed, 3000);
      const after = await dial(); after.sock.write(envOf("alive"));
      ok(await until(() => /"ok":true/.test(after.buf), 3000), "half-close (partial envelope + FIN) no longer crashes the gateway: the next request is served (pre-fix: uncaught EPIPE killed the process)");
      after.sock.destroy();
      // (c) tunnel pinning: same nullifier replayed => capped per nullifier; sockets capped in total.
      await until(() => limiter6.total() === 0, 3000);
      const p1 = await dial(); p1.sock.write(envOf("pin")); await until(() => /"ok":true/.test(p1.buf), 3000);
      const p2 = await dial(); p2.sock.write(envOf("pin")); await until(() => /"ok":true/.test(p2.buf), 3000);
      const p3 = await dial(); p3.sock.write(envOf("pin"));
      ok(await until(() => p3.closed, 3000) && /nullifier-conn-limit/.test(p3.buf), "tunnel pinning: a 3rd concurrent tunnel on ONE nullifier is refused nullifier-conn-limit (cap 2)");
      await new Promise((r) => setTimeout(r, 50)); await until(() => limiter6.total() === 2, 3000);
      const q1 = await dial(); // 3rd socket, no envelope
      await until(() => limiter6.total() === 3, 3000);
      const q2 = await dial();
      ok(await until(() => q2.closed, 3000) && /too-many-connections/.test(q2.buf), "socket exhaustion: the (max+1)th concurrent connection is refused too-many-connections before any byte is read");
      for (const s of [p1, p2, q1]) s.sock.destroy();
      ok(await until(() => limiter6.total() === 0 && limiter6.trackedNullifiers() === 0, 3000), "every slot is released on close (no leak; per-nullifier map bounded by open sockets)");
    } finally {
      await new Promise((r) => gw.close(r)); await new Promise((r) => echo.close(r));
    }

    // =====================================================================================
    // SCENARIO 7 — BOOTNODE ENDPOINT DoS (T-HARD-4)
    // (a) The verify burst: scenario 5 proved the SIZE cap and the PER-ONION throttle, but an
    //     attacker minting fresh onions is neither "existing" (no throttle) nor refused until the
    //     registry is FULL — so up to maxEntries ed25519 verifies were reachable in one burst.
    //     The GLOBAL announce bucket must refuse the overflow BEFORE verify (spied).
    // (b) HTTP slow-loris against the bootnode's http.Server: partial headers, never finished.
    // =====================================================================================
    console.log("\nSCENARIO 7 — bootnode endpoint DoS (fresh-onion verify burst / HTTP slow-loris):");
    let clock7 = 6_000_000;
    let verifies = 0;
    const spyVerify = (rec, o) => { verifies++; return verifyAnnounce(rec, o); };
    const BURST = 3;
    const reg7 = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 900, maxEntries: 1000, minReannounceSec: 5,
      announceRate: 1, announceBurst: BURST, verify: spyVerify, now: () => clock7 });
    let throttled = 0;
    for (let i = 0; i < 8; i++) {
      const id = await generateOnionIdentity(join(work, `burst7-${i}`), { label: `burst7-${i}` });
      const r = await reg7.announce(buildAnnounce({ onion: id.onion, weight: 100, onionSeedHex: id.seed, ts: clock7 }));
      if (r.reason === "global-rate-limited") throttled++;
    }
    ok(throttled === 8 - BURST, `fresh-onion burst of 8 (registry NOT full): ${throttled} refused global-rate-limited`);
    ok(verifies === BURST, `verify ran exactly ${verifies} times == burst (${BURST}) — the throttle sits BEFORE signature verification`);
    const server7 = makeServer(reg7, { signerPub: signer.pub, limits: { headersTimeout: 300, requestTimeout: 600, keepAliveTimeout: 300, connectionsCheckingInterval: 50 } });
    await new Promise((r) => server7.listen(0, "127.0.0.1", r));
    try {
      const t7 = Date.now();
      const st = await new Promise((resolve, reject) => {
        const sock = net.connect(server7.address().port, "127.0.0.1"); const o = { sock, closed: false, buf: "" };
        sock.on("data", (d) => { o.buf += d.toString(); }); sock.on("error", () => {}); sock.on("close", () => { o.closed = true; });
        sock.once("connect", () => resolve(o)); sock.once("error", reject);
      });
      st.sock.write("POST /announce HTTP/1.1\r\nHost: b\r\nX-Slow: "); // headers never complete
      ok(await until(() => st.closed, 5000) && Date.now() - t7 < 4000 && /^HTTP\/1\.1 408/.test(st.buf), "HTTP slow-loris (headers never complete) is cut off with 408 at headersTimeout, not Node's 60s default");
    } finally {
      await new Promise((r) => server7.close(r));
    }
  } finally {
    await rm(work, { recursive: true, force: true });
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: adversarial scenario suite (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
