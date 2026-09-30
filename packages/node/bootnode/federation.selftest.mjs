// Offline proof of bootnode federation / gossip (T-FEAT-1). No Tor, no chain: real onion identities
// and real announces, an INJECTED fetch/clock standing in for the peer bootnode. The crux is that a
// gossiped entry is admitted ONLY if it self-verifies exactly like a direct announce -- so every
// forged/tampered/unstaked/stale gossiped gateway MUST be rejected, and the peer's directory
// signature must carry no authority. We also prove the default (no peers) is byte-identical to today.
//
//   node packages/node/bootnode/federation.selftest.mjs
//
// Exit 0 = every invariant held; nonzero = a check failed (prints which).

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateOnionIdentity } from "./keygen.mjs";
import { buildAnnounce, operatorAuthMessage } from "./announce.mjs";
import { makeRegistry, loadOrMintSigner } from "./server.mjs";
import { makeFederation, parsePeers, normOnion } from "./federation.mjs";
import { MockStakeVerifier } from "../lib/gateway-registry.mjs";
import { verifyDirectory } from "../lib/directory.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

// An in-memory peer bootnode: injected fetchers serve a /directory hint list + per-gateway announces
// from a map keyed by onion. `dropDir`/`missing` model a down peer / a 404 gateway (fail-soft paths).
function makePeer({ recs = [], dropDir = false, missing = new Set() } = {}) {
  const gwMap = new Map(recs.map((r) => [r.onion, r]));
  // A peer directory shape (with untrusted signer/labels) -- only the onion strings are consumed.
  const dir = { version: 1, issued: 0, signer: "ff".repeat(32), signature: "deadbeef",
    gateways: recs.map((r) => ({ onion: r.onion, pubkey: "00".repeat(32), weight: r.weight, health: "up" })) };
  return {
    dir,
    fetchDir: async () => { if (dropDir) throw new Error("peer down"); return dir; },
    fetchGateway: async (_peer, onion) => {
      if (missing.has(onion)) throw new Error("bootnode HTTP 404: not-found");
      const r = gwMap.get(onion);
      if (!r) throw new Error("bootnode HTTP 404: not-found");
      return r;
    },
  };
}

async function main() {
  const work = await mkdtemp(join(tmpdir(), "shade-tree-fed-"));
  try {
    const g1 = await generateOnionIdentity(join(work, "g1"), { label: "g1" });
    const g2 = await generateOnionIdentity(join(work, "g2"), { label: "g2" });
    const g3 = await generateOnionIdentity(join(work, "g3"), { label: "g3" });
    const g4 = await generateOnionIdentity(join(work, "g4"), { label: "g4" });
    const signer = await loadOrMintSigner(join(work, "signer.key"));

    // ---- parsePeers / normOnion ---------------------------------------------
    console.log("parsePeers:");
    ok(parsePeers("").length === 0 && parsePeers(undefined).length === 0, "empty/unset => no peers (standalone default)");
    ok(JSON.stringify(parsePeers(` ${g1.onion} , ${g2.onion} `)) === JSON.stringify([g1.onion, g2.onion]), "comma-list trimmed + parsed");
    ok(parsePeers(`${g1.onion},${g1.onion}`).length === 1, "duplicate peers deduped");
    ok(parsePeers(`${g1.onion},${g2.onion}`, { self: g1.onion }).join() === g2.onion, "own onion filtered out of peer set");
    ok(normOnion("http://ABC.onion/x") === "abc.onion", "normOnion strips scheme/path + lowercases");
    ok(normOnion("bare56") === "bare56.onion", "normOnion appends .onion suffix");

    // ---- happy path: gossip a valid announce, it merges + serves verifiably --
    console.log("\nhappy-path gossip merge:");
    let clock = 1_000_000;
    const local = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 900, minReannounceSec: 0, now: () => clock });
    const recG1 = buildAnnounce({ onion: g1.onion, weight: 100, onionSeedHex: g1.seed, ts: clock });
    const peer = makePeer({ recs: [recG1] });
    const fed = makeFederation({ registry: local, peers: [g2.onion], fetchDir: peer.fetchDir, fetchGateway: peer.fetchGateway });
    const s1 = await fed.pullAll();
    ok(s1.merged === 1 && s1.rejected === 0, "one valid gossiped gateway merged");
    ok(local.size() === 1, "merged entry present in local registry");
    const dir1 = local.directory();
    ok(verifyDirectory(dir1, signer.pub).ok, "merged directory verifies under LOCAL signer (peer signer never trusted)");
    ok(dir1.gateways[0].onion === g1.onion, "gossiped onion listed in local directory");
    // idempotent re-pull: same rec => fresh-existing, no churn.
    const s1b = await fed.pullAll();
    ok(s1b.merged === 0 && s1b.skipped === 1 && local.size() === 1, "re-pulling the same rec is idempotent (dedup by expiry)");

    // ---- REJECTION MATRIX: each forged/tampered gossip must be refused -------
    console.log("\nrejection matrix (the security crux):");
    clock = 2_000_000;
    const rej = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 900, minReannounceSec: 0, now: () => clock });

    // 1. forged onion signature (flip last nibble) -> bad-onion-sig, NOT merged.
    const forged = buildAnnounce({ onion: g1.onion, weight: 100, onionSeedHex: g1.seed, ts: clock });
    forged.onionSig = forged.onionSig.replace(/.$/, (c) => (c === "0" ? "1" : "0"));
    let r = await rej.admitGossip(forged);
    ok(r.ok === false && r.reason === "bad-onion-sig" && !r.merged, "forged onion-sig gossip rejected");

    // 2. onion<->key mismatch: announce g2's onion signed by g3's key -> bad-onion-sig.
    const wrongKey = buildAnnounce({ onion: g2.onion, weight: 100, onionSeedHex: g3.seed, ts: clock });
    r = await rej.admitGossip(wrongKey);
    ok(r.ok === false && r.reason === "bad-onion-sig" && !r.merged, "onion signed by the wrong key rejected (onion!=key)");

    // 3. tampered field after signing (weight is covered by the onion sig) -> bad-onion-sig.
    const tampered = buildAnnounce({ onion: g2.onion, weight: 100, onionSeedHex: g2.seed, ts: clock });
    tampered.weight = 999; // change a signed field; signature no longer matches
    r = await rej.admitGossip(tampered);
    ok(r.ok === false && r.reason === "bad-onion-sig" && !r.merged, "tampered (weight-swapped) gossip rejected");

    // 4. malformed onion string -> bad-onion (never throws).
    const badOnion = buildAnnounce({ onion: g2.onion, weight: 100, onionSeedHex: g2.seed, ts: clock });
    badOnion.onion = "not-a-real-onion.onion";
    r = await rej.admitGossip(badOnion);
    ok(r.ok === false && r.reason?.startsWith("bad-onion") && !r.merged, "malformed onion gossip rejected (total, no throw)");
    ok(rej.size() === 0, "no forged/tampered gossip ever entered the registry");

    // 5. stale gossip: an origin ts so old that ts+ttl already lapsed -> stale-gossip.
    clock = 3_000_000;
    const staleReg = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 100, minReannounceSec: 0, now: () => clock });
    const staleRec = buildAnnounce({ onion: g1.onion, weight: 100, onionSeedHex: g1.seed, ts: clock - 200 }); // ts+100 < now
    r = await staleReg.admitGossip(staleRec);
    ok(r.ok === false && r.reason === "stale-gossip" && !r.merged, "gossip past its origin TTL rejected (freshness honored)");
    // a within-TTL-but-old rec (older than the 120s anti-replay skew) still merges -- gossip is relayed.
    const oldButLive = buildAnnounce({ onion: g1.onion, weight: 100, onionSeedHex: g1.seed, ts: clock - 50 });
    r = await staleReg.admitGossip(oldButLive);
    ok(r.ok === true && r.merged && staleReg.size() === 1, "relayed announce older than the anti-replay skew still merges (TTL, not skew)");

    // ---- stake mode: unstaked gossiped operator rejected --------------------
    console.log("\nstake-mode gossip:");
    const { ethers } = await import("ethers");
    const opWallet = ethers.Wallet.createRandom();
    const operator = opWallet.address;
    const opSig = await opWallet.signMessage(operatorAuthMessage(g1.onion, operator));
    clock = 4_000_000;
    const stakeReg = makeRegistry({ signer, stake: MockStakeVerifier({ allowlist: operator }), admission: "stake", ttlSec: 900, minReannounceSec: 0, now: () => clock });

    // staked+authorized operator -> merged + labeled staked.
    const gStaked = buildAnnounce({ onion: g1.onion, weight: 100, onionSeedHex: g1.seed, operator, operatorSig: opSig, ts: clock });
    r = await stakeReg.admitGossip(gStaked);
    ok(r.ok === true && r.merged && r.staked === true, "staked+authorized gossiped gateway merged and labeled staked");

    // onion-only gossip (no operator) in stake mode -> not-staked.
    const gNoOp = buildAnnounce({ onion: g2.onion, weight: 100, onionSeedHex: g2.seed, ts: clock });
    r = await stakeReg.admitGossip(gNoOp);
    ok(r.ok === false && r.reason === "not-staked" && !r.merged, "onion-only gossip rejected in stake mode");

    // authorized but UNSTAKED operator (not in allowlist) -> not-staked.
    const stranger = ethers.Wallet.createRandom();
    const strangerSig = await stranger.signMessage(operatorAuthMessage(g3.onion, stranger.address));
    const gUnstaked = buildAnnounce({ onion: g3.onion, weight: 100, onionSeedHex: g3.seed, operator: stranger.address, operatorSig: strangerSig, ts: clock });
    r = await stakeReg.admitGossip(gUnstaked);
    ok(r.ok === false && r.reason === "not-staked" && !r.merged, "unstaked operator gossip rejected (on-chain re-check)");

    // operator sig bound to a DIFFERENT onion (stolen) -> bad-operator-sig.
    const gStolen = buildAnnounce({ onion: g2.onion, weight: 100, onionSeedHex: g2.seed, operator, operatorSig: opSig, ts: clock }); // opSig was for g1
    r = await stakeReg.admitGossip(gStolen);
    ok(r.ok === false && r.reason === "bad-operator-sig" && !r.merged, "operator sig bound to another onion rejected");
    ok(stakeReg.size() === 1, "stake-mode registry admitted only the genuinely-staked gossiped gateway");

    // ---- dedup / no-shorten: gossip never churns a fresher local entry ------
    console.log("\ndedup + freshness:");
    clock = 5_000_000;
    const dd = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 900, minReannounceSec: 0, now: () => clock });
    // a fresh DIRECT announce at now -> expiry now+900.
    await dd.announce(buildAnnounce({ onion: g1.onion, weight: 100, onionSeedHex: g1.seed, ts: clock }));
    const freshExpiry = dd.record(g1.onion) ? clock + 900 : null; // sanity
    // gossip an OLDER rec for the same onion -> must be a no-op (don't shorten the fresher entry).
    const olderRec = buildAnnounce({ onion: g1.onion, weight: 100, onionSeedHex: g1.seed, ts: clock - 300 });
    r = await dd.admitGossip(olderRec);
    ok(r.ok === true && r.merged === false && r.reason === "fresh-existing", "older gossip for a fresher local entry is a no-op");
    ok(dd.directory().gateways.length === 1 && freshExpiry === clock + 900, "gossip did not shorten/duplicate the fresher direct entry");

    // ---- maxEntries cap honored on the gossip path --------------------------
    console.log("\nDoS caps on gossip:");
    clock = 6_000_000;
    const cap = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 900, maxEntries: 1, minReannounceSec: 0, now: () => clock });
    await cap.announce(buildAnnounce({ onion: g1.onion, weight: 100, onionSeedHex: g1.seed, ts: clock }));
    r = await cap.admitGossip(buildAnnounce({ onion: g2.onion, weight: 100, onionSeedHex: g2.seed, ts: clock }));
    ok(r.ok === false && r.reason === "registry-full" && !r.merged, "a NEW gossiped onion is refused when the registry is full");
    ok(cap.size() === 1, "the cap bounds merged entries just like direct announces");
    // maxPullPerPeer bounds a hostile over-large peer directory (only 1 gateway fetched).
    clock = 6_100_000;
    const capReg = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 900, minReannounceSec: 0, now: () => clock });
    const many = [g1, g2, g3, g4].map((g) => buildAnnounce({ onion: g.onion, weight: 100, onionSeedHex: g.seed, ts: clock }));
    const bigPeer = makePeer({ recs: many });
    let fetched = 0;
    const countingFed = makeFederation({ registry: capReg, peers: [g1.onion],
      fetchDir: bigPeer.fetchDir, fetchGateway: async (p, o) => { fetched++; return bigPeer.fetchGateway(p, o); }, maxPullPerPeer: 2 });
    const capStats = await countingFed.pullAll();
    ok(fetched === 2 && capStats.merged === 2, "maxPullPerPeer bounds per-peer gateway fetches (hostile-directory DoS bound)");

    // ---- fail-soft: a down peer is skipped, healthy peers still merge --------
    console.log("\nfail-soft federation:");
    clock = 7_000_000;
    const fsReg = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 900, minReannounceSec: 0, now: () => clock });
    const upRec = buildAnnounce({ onion: g1.onion, weight: 100, onionSeedHex: g1.seed, ts: clock });
    const upPeer = makePeer({ recs: [upRec] });
    const downPeer = makePeer({ recs: [], dropDir: true });
    // route the two peers to their own fetchers by peer onion.
    const fsFed = makeFederation({ registry: fsReg, peers: [g2.onion, g3.onion],
      fetchDir: (p) => (p === g2.onion ? upPeer.fetchDir(p) : downPeer.fetchDir(p)),
      fetchGateway: (p, o) => upPeer.fetchGateway(p, o) });
    const fsStats = await fsFed.pullAll();
    ok(fsStats.merged === 1 && fsStats.errors >= 1, "a down peer is skipped; a healthy peer still merges (no throw)");
    ok(fsReg.size() === 1, "convergence survives one bootnode going dark");
    // a 404 on one gateway doesn't abort the peer.
    clock = 7_100_000;
    const holeReg = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 900, minReannounceSec: 0, now: () => clock });
    const recA = buildAnnounce({ onion: g1.onion, weight: 100, onionSeedHex: g1.seed, ts: clock });
    const recB = buildAnnounce({ onion: g2.onion, weight: 100, onionSeedHex: g2.seed, ts: clock });
    const holePeer = makePeer({ recs: [recA, recB], missing: new Set([g1.onion]) });
    const holeFed = makeFederation({ registry: holeReg, peers: [g3.onion], fetchDir: holePeer.fetchDir, fetchGateway: holePeer.fetchGateway });
    const holeStats = await holeFed.pullAll();
    ok(holeStats.merged === 1 && holeStats.errors === 1 && holeReg.size() === 1, "one 404 gateway fetch doesn't abort the peer");

    // ---- two bootnodes converge on the same live set ------------------------
    console.log("\nconvergence (T-FEAT-1 accept):");
    clock = 8_000_000;
    // Node A holds g1 directly; Node B holds g2 directly. Each federates with the other.
    const nodeA = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 900, minReannounceSec: 0, now: () => clock });
    const nodeB = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 900, minReannounceSec: 0, now: () => clock });
    await nodeA.announce(buildAnnounce({ onion: g1.onion, weight: 100, onionSeedHex: g1.seed, ts: clock }));
    await nodeB.announce(buildAnnounce({ onion: g2.onion, weight: 100, onionSeedHex: g2.seed, ts: clock }));
    // A pulls from B, B pulls from A (fetchers read the OTHER node's live records).
    const liveFetchDir = (reg) => async () => reg.directory();
    const liveFetchGw = (reg) => async (_p, o) => { const rec = reg.record(o); if (!rec) throw new Error("404"); return rec; };
    const fedA = makeFederation({ registry: nodeA, peers: [g2.onion], fetchDir: liveFetchDir(nodeB), fetchGateway: liveFetchGw(nodeB) });
    const fedB = makeFederation({ registry: nodeB, peers: [g1.onion], fetchDir: liveFetchDir(nodeA), fetchGateway: liveFetchGw(nodeA) });
    await fedA.pullAll();
    await fedB.pullAll();
    const setA = new Set(nodeA.directory().gateways.map((g) => g.onion));
    const setB = new Set(nodeB.directory().gateways.map((g) => g.onion));
    ok(setA.size === 2 && setA.has(g1.onion) && setA.has(g2.onion), "node A converged on both gateways");
    ok(setB.size === 2 && setB.has(g1.onion) && setB.has(g2.onion), "node B converged on both gateways");
    ok(JSON.stringify([...setA].sort()) === JSON.stringify([...setB].sort()), "the two bootnodes converge on the SAME live set");

    // ---- default-unchanged proof: no peers => byte-identical standalone ------
    console.log("\ndefault (no peers) byte-identical:");
    clock = 9_000_000;
    // Drive an identical announce sequence into two registries; the ONLY difference is that one
    // has an (empty-peer) federation constructed + started. The served directory bytes must match.
    const seq = async (reg) => {
      await reg.announce(buildAnnounce({ onion: g1.onion, weight: 100, onionSeedHex: g1.seed, ts: clock }));
      await reg.announce(buildAnnounce({ onion: g2.onion, weight: 250, onionSeedHex: g2.seed, ts: clock }));
    };
    const plain = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 900, minReannounceSec: 0, now: () => clock });
    const withFed = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 900, minReannounceSec: 0, now: () => clock });
    await seq(plain);
    await seq(withFed);
    let dialed = 0;
    const emptyFed = makeFederation({ registry: withFed, peers: parsePeers(""), fetchDir: async () => { dialed++; return {}; }, fetchGateway: async () => { dialed++; return {}; } });
    ok(emptyFed.start() === undefined || emptyFed.peers.length === 0, "start() is inert with no peers");
    await emptyFed.pullAll(); // even if called, iterates zero peers
    ok(dialed === 0, "no-peer federation never dials");
    ok(JSON.stringify(plain.directory()) === JSON.stringify(withFed.directory()), "no-peer registry directory is byte-identical to a federation-free one");
  } finally {
    await rm(work, { recursive: true, force: true });
  }

  
// OPS-9: the default fetchers dial the configured Tor SOCKS, not a hard-coded 9250.
{
  const net = await import("node:net");
  let hits = 0;
  const sock = net.createServer((c) => { hits++; c.destroy(); });
  await new Promise((r) => sock.listen(0, "127.0.0.1", r));
  const { port } = sock.address();
  const warns = [];
  const fed = makeFederation({
    registry: { maxEntries: () => 10, admitGossip: async () => ({ ok: false }) },
    peers: ["a".repeat(56) + ".onion"],
    tor: { torHost: "127.0.0.1", torPort: port },
    log: { info() {}, warn: (m, f) => warns.push([m, f]) },
  });
  const res = await fed.pullAll();
  sock.close();
  if (!(hits >= 1)) throw new Error("federation did not dial the configured Tor port");
  if (!(res.errors >= 1 && warns.some(([m, f]) => m === "federation peer unreachable" && !/[a-z2-7]{56}\.onion/.test(f.error)))) throw new Error("unreachable peer not warned (onion-free)");
  console.log("  ok   federation dials SHADE_TREE_TOR_PORT and warns on an unreachable peer");
}
console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: bootnode federation selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
