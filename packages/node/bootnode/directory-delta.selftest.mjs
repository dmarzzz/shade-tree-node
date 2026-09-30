// Directory delta protocol (T-FEAT-6): GET /directory/delta?since=<etag> returns only what
// CHANGED since a client's last view, instead of the whole signed directory each poll. This test
// spins the real in-process bootnode (real HTTP, real onion identities, real signed directory) and
// proves the delta is CORRECT (right added/removed) AND SAFE: reconstructing the new directory from
// the client's cached base + the delta yields a directory that verifyDirectory ACCEPTS under the
// pinned signer -- so a lying bootnode cannot smuggle a forged gateway through a delta (docs/adr/0003).
//
//   node packages/node/bootnode/directory-delta.selftest.mjs
//
// Exit 0 = all invariants held; nonzero = a check failed (prints which).

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateOnionIdentity } from "./keygen.mjs";
import { buildAnnounce } from "./announce.mjs";
import { makeRegistry, makeServer, loadOrMintSigner } from "./server.mjs";
import { MockStakeVerifier } from "../lib/gateway-registry.mjs";
import { verifyDirectory, signDirectory } from "../lib/directory.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

const getJSON = (base, path) => fetch(base + path).then((r) => r.json());
const announce = (base, rec) =>
  fetch(base + "/announce", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(rec) }).then((r) => r.json());

// Reconstruct the new directory the way an HONEST client would: unchanged entries come from the
// client's cached base directory (keyed by onion), `added` entries come from the delta, and the
// whole list is laid out in the delta's `order`. Returns the directory object (or null if an onion
// in `order` is neither cached nor in `added`, which would force a full re-fetch).
function reconstruct(cachedBaseDir, delta) {
  const byOnion = new Map();
  for (const g of cachedBaseDir.gateways) byOnion.set(g.onion, g);
  for (const g of delta.added) byOnion.set(g.onion, g);
  const gateways = [];
  for (const onion of delta.directory.order) {
    const g = byOnion.get(onion);
    if (!g) return null; // missing entry -> client must fetch full /directory
    gateways.push(g);
  }
  return {
    version: delta.directory.version,
    issued: delta.directory.issued,
    gateways,
    signer: delta.directory.signer,
    signature: delta.directory.signature,
  };
}

async function main() {
  const work = await mkdtemp(join(tmpdir(), "shade-tree-dir-delta-"));
  let server;
  try {
    const g1 = await generateOnionIdentity(join(work, "g1"), { label: "g1" });
    const g2 = await generateOnionIdentity(join(work, "g2"), { label: "g2" });
    const g3 = await generateOnionIdentity(join(work, "g3"), { label: "g3" });
    const signer = await loadOrMintSigner(join(work, "signer.key"));

    // Mutable, injected clock: pin it so `issued` (and thus the ETag) is stable between polls,
    // then ADVANCE it to let g2 TTL out while g1/g3 stay live via a fresh re-announce.
    let clock = Math.floor(Date.now() / 1000);
    const ttlSec = 900;
    const registry = makeRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec, minReannounceSec: 0, now: () => clock });
    server = makeServer(registry, { signerPub: signer.pub });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    const base = `http://127.0.0.1:${server.address().port}`;

    // --- version E1: announce g1, g2 -----------------------------------------
    console.log("version E1 (g1, g2):");
    ok((await announce(base, buildAnnounce({ onion: g1.onion, weight: 100, onionSeedHex: g1.seed, ts: clock }))).ok, "announce g1 accepted");
    ok((await announce(base, buildAnnounce({ onion: g2.onion, weight: 100, onionSeedHex: g2.seed, ts: clock }))).ok, "announce g2 accepted");

    const r1 = await fetch(base + "/directory");
    const E1 = r1.headers.get("etag");
    const dirE1 = await r1.json(); // the client's cached base view
    ok(typeof E1 === "string" && /^"[0-9a-f]{64}"$/.test(E1), "GET /directory carries a strong ETag (E1)");
    ok(dirE1.gateways.length === 2 && verifyDirectory(dirE1, signer.pub).ok, "E1 lists g1,g2 and verifies");

    // --- since === current -> empty delta ------------------------------------
    console.log("\nsince == current -> empty delta:");
    const empty = await getJSON(base, `/directory/delta?since=${encodeURIComponent(E1)}`);
    ok(!empty.full, "delta since current is not a full-refetch");
    ok(empty.added.length === 0 && empty.removed.length === 0, "empty delta: nothing added, nothing removed");
    ok(empty.unchanged === 2, "empty delta reports 2 unchanged");
    ok(empty.base === E1, "empty delta base == E1 (content unchanged)");

    // --- version E2: g3 joins, g2 TTLs out -----------------------------------
    // Advance past the TTL and re-announce only g1 and g3, so g2 expires on the next sweep.
    console.log("\nversion E2 (g3 joins, g2 TTLs out):");
    clock += ttlSec + 1;
    ok((await announce(base, buildAnnounce({ onion: g1.onion, weight: 100, onionSeedHex: g1.seed, ts: clock }))).ok, "re-announce g1 accepted (kept live)");
    ok((await announce(base, buildAnnounce({ onion: g3.onion, weight: 100, onionSeedHex: g3.seed, ts: clock }))).ok, "announce g3 accepted");

    const r2 = await fetch(base + "/directory");
    const E2 = r2.headers.get("etag");
    const dirE2 = await r2.json();
    ok(E2 && E2 !== E1, "ETag advanced to E2");
    ok(dirE2.gateways.length === 2 && dirE2.gateways.some((g) => g.onion === g3.onion) && !dirE2.gateways.some((g) => g.onion === g2.onion),
      "E2 lists g1,g3 (g2 dropped)");

    // --- the delta since E1 ---------------------------------------------------
    console.log("\ndelta since E1:");
    const delta = await getJSON(base, `/directory/delta?since=${encodeURIComponent(E1)}`);
    ok(!delta.full, "delta since E1 is served as a delta (E1 still in history)");
    ok(delta.base === E2, "delta base == E2 (current)");
    ok(delta.added.length === 1 && delta.added[0].onion === g3.onion, "delta reports g3 added (full entry)");
    ok(delta.removed.length === 1 && delta.removed[0] === g2.onion, "delta reports g2 removed (onion only)");
    ok(delta.unchanged === 1, "delta reports 1 unchanged (g1)");

    // --- CRITICAL: reconstruct from cached base + delta, verify under the pin ---
    console.log("\nreconstruct + verify (the delta cannot smuggle a forged gateway):");
    const rebuilt = reconstruct(dirE1, delta);
    ok(rebuilt !== null, "client reconstructs the new directory from cached E1 + delta");
    const v = verifyDirectory(rebuilt, signer.pub);
    ok(v.ok, "reconstructed directory verifies under the pinned signer");
    ok(rebuilt.gateways.length === 2 && rebuilt.gateways.some((g) => g.onion === g1.onion) && rebuilt.gateways.some((g) => g.onion === g3.onion),
      "reconstructed directory is exactly {g1, g3}");
    // And it equals what a plain full GET returned -- the delta path and the full path agree.
    ok(JSON.stringify(rebuilt) === JSON.stringify(dirE2), "reconstructed directory == the full /directory body (byte-for-byte)");

    // --- adversarial: a bootnode that LIES in `added` cannot forge a gateway ---
    // Forge a delta whose `added` grafts a hostile onion under a pubkey the attacker controls but
    // that is NOT the onion's own key -> verifyDirectory's onion<->pubkey binding rejects it. And
    // even a well-formed self-consistent extra entry can't survive: it was never in the signed list,
    // so the pinned signature over the reconstructed bytes fails.
    console.log("\nadversarial delta (forged added) is rejected on reconstruction:");
    const forgedEntry = { onion: g2.onion, pubkey: "00".repeat(32), weight: 1000, health: "up" }; // wrong pubkey for g2's onion
    const forgedDelta = {
      base: E2, since: E1, added: [delta.added[0], forgedEntry], removed: [], unchanged: 1,
      directory: { ...delta.directory, order: [...delta.directory.order, g2.onion] },
    };
    const forgedRebuilt = reconstruct(dirE1, forgedDelta);
    ok(forgedRebuilt !== null, "attacker's forged delta reconstructs into some directory");
    ok(!verifyDirectory(forgedRebuilt, signer.pub).ok, "forged directory is REJECTED (onion<->pubkey binding / signature) -- no injection via delta");

    // A signer other than the pin cannot rescue the forgery either: re-signing the forged list with
    // an attacker key fails because the client pins the real signer.
    const attacker = await loadOrMintSigner(join(work, "attacker.key"));
    const attackerSigned = signDirectory({ version: forgedRebuilt.version, issued: forgedRebuilt.issued, gateways: forgedRebuilt.gateways, signer: attacker.pub }, attacker.priv);
    ok(!verifyDirectory(attackerSigned, signer.pub).ok, "attacker-signed forgery still rejected against the pinned signer");

    // --- unknown `since` -> full:true ----------------------------------------
    console.log("\nunknown since -> full:true:");
    const unknown = await getJSON(base, `/directory/delta?since=${encodeURIComponent('"' + "de".repeat(32) + '"')}`);
    ok(unknown.full === true, "unknown since returns full:true (client fetches whole /directory)");
    ok(typeof unknown.base === "string", "full:true response still carries the current base etag");

    // Missing `since` altogether -> also full:true.
    const noSince = await getJSON(base, `/directory/delta`);
    ok(noSince.full === true, "missing since returns full:true");
  } finally {
    if (server) await new Promise((r) => server.close(r));
    await rm(work, { recursive: true, force: true });
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: directory-delta selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
