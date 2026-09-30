// Offline proof of client-side gateway reputation PERSISTENCE (T-FEAT-19) in packages/node/client/selection.mjs.
// No Tor, no live bootnode. reportHealth/reportResult mutate in-memory dir entries, which is lost on
// restart; this feature adds a small LOCAL, best-effort JSON cache (SHADE_TREE_HEALTH_CACHE) so a flaky
// gateway stays deprioritized across sessions until it proves healthy again.
//
// selection.mjs reads its env AT IMPORT TIME, so we drive persistence two ways:
//   1. the exported pure-ish helpers (loadHealthCache/saveHealthCache/seedHealthFromCache), which
//      take an explicit path and need no import-time env coupling, and
//   2. a full end-to-end write-through by importing the module with SHADE_TREE_HEALTH_CACHE set to a temp
//      file, then reading that file back off disk.
//
//   node packages/node/client/health-persistence.selftest.mjs
//
// Exit 0 = all invariants held; nonzero = a check failed (prints which).

import { mkdtemp, rm, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { generateKeyPairSync } from "node:crypto";
import { signDirectory, pubkeyToOnion } from "../lib/directory.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

const HERE = dirname(fileURLToPath(import.meta.url));
const SELECTION_PATH = join(HERE, "selection.mjs");

function newEd25519() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pub = publicKey.export({ format: "der", type: "spki" });
  const priv = privateKey.export({ format: "der", type: "pkcs8" });
  return {
    pub: Buffer.from(pub.subarray(pub.length - 32)).toString("hex"),
    priv: Buffer.from(priv.subarray(priv.length - 32)).toString("hex"),
  };
}

// A gateway whose pubkey is exactly the key encoded in its own v3 onion (verifyDirectory binding).
function mintGateway(weight, health) {
  const k = newEd25519();
  return { onion: pubkeyToOnion(k.pub), pubkey: k.pub, weight, health };
}

function mintSignedDirectory(gateways) {
  const signer = newEd25519();
  const dir = { version: 1, issued: Math.floor(Date.now() / 1000), gateways, signer: signer.pub };
  return { signed: signDirectory(dir, signer.priv), signer };
}

async function main() {
  const work = await mkdtemp(join(tmpdir(), "shade-tree-health-"));
  try {
    const gateways = [mintGateway(100, "up"), mintGateway(100, "up"), mintGateway(100, "up")];
    const { signed, signer } = mintSignedDirectory(gateways);
    const dirFile = join(work, "directory.signed.json");
    await writeFile(dirFile, JSON.stringify(signed, null, 2) + "\n");

    const cacheFile = join(work, "nested", "gateway-health.json"); // parent dir does not exist yet
    const victim = gateways[0].onion;              // .onion form (what the cache keys on)
    const victimShort = victim.replace(/\.onion$/, ""); // short form (what selectCandidates returns)

    // --- (1) reportResult failures WRITE THROUGH to the cache file --------------------------------
    console.log("write-through (module e2e):");
    process.env.SHADE_TREE_DIRECTORY = dirFile;
    process.env.SHADE_TREE_DIR_SIGNER = signer.pub;
    process.env.SHADE_TREE_HEALTH_CACHE = cacheFile;
    delete process.env.SHADE_TREE_BOOTNODE_ONION;
    const sel = await import(pathToFileURL(SELECTION_PATH).href);

    ok(sel.directoryEnabled() === true, "directoryEnabled() true with directory + pinned signer");
    await sel.selectCandidates();                  // triggers first load
    sel.reportResult(victimShort, { ok: false });
    sel.reportResult(victimShort, { ok: false });  // 2 fails -> "down" and persisted

    let onDisk = JSON.parse(await readFile(cacheFile, "utf8"));
    ok(onDisk && onDisk.entries && onDisk.entries[victim], "the failing gateway is written to the cache file");
    ok(onDisk.entries[victim].fails === 2, "the persisted fail count is 2");
    ok(typeof onDisk.entries[victim].lastSeen === "number", "the entry records lastSeen");
    // privacy: only onions from the signed directory are persisted, never arbitrary input
    sel.reportResult("bogusonion", { ok: false });
    onDisk = JSON.parse(await readFile(cacheFile, "utf8"));
    ok(!Object.keys(onDisk.entries).some((k) => k.startsWith("bogusonion")),
      "an onion NOT in the signed directory is never persisted (privacy guard)");

    // --- (2) a NEW load pointed at the same cache SEEDS the failing gateway as deprioritized ------
    console.log("\nseeding a fresh session from the persisted cache:");
    const persisted = sel.loadHealthCache(cacheFile);
    ok(persisted[victim] && persisted[victim].fails === 2, "loadHealthCache reads the persisted entry back");

    // Fresh directory view (fresh objects, all health "up"): seeding must knock the victim to "down".
    const freshGateways = gateways.map((g) => ({ ...g, health: "up" }));
    const freshDir = { ...signed, gateways: freshGateways };
    sel.seedHealthFromCache(freshDir, persisted, Date.now());
    const seededVictim = freshDir.gateways.find((g) => g.onion === victim);
    const seededOther = freshDir.gateways.find((g) => g.onion !== victim);
    ok(seededVictim.health === "down", "a previously-failing gateway seeds as health:down (deprioritized)");
    ok(seededVictim._fails === 2, "the seeded gateway carries its prior fail count");
    ok(seededOther.health === "up", "a gateway with no prior failures is untouched (stays up)");

    // --- (3) a SUCCESSFUL dial recovers the gateway ----------------------------------------------
    console.log("\nrecovery on a successful dial:");
    sel.reportResult(victimShort, { ok: true, latencyMs: 120 });
    const recovered = sel.loadHealthCache(cacheFile);
    ok(recovered[victim].fails === 0, "a successful dial resets the persisted fail count to 0");
    const recDir = { ...signed, gateways: gateways.map((g) => ({ ...g, health: "up" })) };
    sel.seedHealthFromCache(recDir, recovered, Date.now());
    ok(recDir.gateways.find((g) => g.onion === victim).health === "up",
      "after recovery the gateway no longer seeds as down");

    // decay: an entry not seen for a long time is NOT seeded (recovers) and is pruned
    const stale = { [victim]: { fails: 5, lastFail: 0, latencyMs: null, lastSeen: 1000 } };
    const decayDir = { ...signed, gateways: gateways.map((g) => ({ ...g, health: "up" })) };
    sel.seedHealthFromCache(decayDir, stale, Date.now()); // now >> lastSeen + decay window
    ok(decayDir.gateways.find((g) => g.onion === victim).health === "up",
      "a long-unseen entry decays: not seeded as down");
    ok(!stale[victim], "the decayed entry is pruned from the cache");

    // --- (4) the cache is BOUNDED under many entries ---------------------------------------------
    console.log("\nbounded cache size:");
    const boundFile = join(work, "bound", "health.json");
    process.env.SHADE_TREE_HEALTH_MAX = "50";
    // load a fresh module instance in a subprocess so SHADE_TREE_HEALTH_MAX is read at import
    const bigScript = `
import { pathToFileURL } from "node:url";
import { readFileSync } from "node:fs";
const sel = await import(${JSON.stringify(pathToFileURL(SELECTION_PATH).href)});
const cache = {};
for (let i = 0; i < 500; i++) cache["onion" + i] = { fails: 1, lastFail: 0, latencyMs: null, lastSeen: i };
sel.saveHealthCache(cache, ${JSON.stringify(boundFile)});
const back = sel.loadHealthCache(${JSON.stringify(boundFile)});
const keys = Object.keys(back);
// newest-lastSeen must be retained, oldest evicted
console.log(JSON.stringify({ count: keys.length, hasOldest: "onion0" in back, hasNewest: "onion499" in back }));
`;
    const { execFileSync } = await import("node:child_process");
    const out = execFileSync(process.execPath, ["--input-type=module", "-e", bigScript], {
      encoding: "utf8",
      env: { ...process.env, SHADE_TREE_HEALTH_MAX: "50", SHADE_TREE_HEALTH_CACHE: boundFile },
    });
    const bound = JSON.parse(out.trim().split("\n").pop());
    ok(bound.count === 50, `500 entries bound down to SHADE_TREE_HEALTH_MAX=50 (got ${bound.count})`);
    ok(bound.hasOldest === false, "the oldest-lastSeen entries were evicted");
    ok(bound.hasNewest === true, "the newest-lastSeen entries were retained");
    delete process.env.SHADE_TREE_HEALTH_MAX;

    // --- (5) unwritable cache path: selection still works, no throw ------------------------------
    console.log("\nunwritable cache path (fail soft):");
    // Make the parent a FILE so mkdir/write under it fails with ENOTDIR.
    const blocker = join(work, "blocker");
    await writeFile(blocker, "not a directory");
    const badPath = join(blocker, "sub", "health.json");
    ok(sel.saveHealthCache({ [victim]: { fails: 1, lastSeen: 1 } }, badPath) === false,
      "saveHealthCache returns false on an unwritable path (does not throw)");
    ok(Object.keys(sel.loadHealthCache(badPath)).length === 0,
      "loadHealthCache returns an empty map on an unreadable path (does not throw)");

    // A whole module instance pointed at an unwritable cache must still select normally.
    const unwritableScript = `
import { pathToFileURL } from "node:url";
const sel = await import(${JSON.stringify(pathToFileURL(SELECTION_PATH).href)});
const c = await sel.selectCandidates();
sel.reportResult(c[0].onion, { ok: false }); // must not throw even though persistence fails
console.log("CANDS:" + c.length);
`;
    let unwritableOut = "";
    try {
      unwritableOut = execFileSync(process.execPath, ["--input-type=module", "-e", unwritableScript], {
        encoding: "utf8",
        env: { ...process.env, SHADE_TREE_DIRECTORY: dirFile, SHADE_TREE_DIR_SIGNER: signer.pub, SHADE_TREE_HEALTH_CACHE: badPath, SHADE_TREE_BOOTNODE_ONION: "" },
      });
    } catch (e) {
      unwritableOut = "THREW:" + ((e.stderr || e.stdout || e.message) + "");
    }
    ok(/CANDS:3/.test(unwritableOut), `selection works with an unwritable cache (${unwritableOut.trim().split("\n").pop()})`);

    // OFF switch: SHADE_TREE_HEALTH_CACHE="" disables persistence and still selects.
    let offOut = "";
    try {
      offOut = execFileSync(process.execPath, ["--input-type=module", "-e", unwritableScript], {
        encoding: "utf8",
        env: { ...process.env, SHADE_TREE_DIRECTORY: dirFile, SHADE_TREE_DIR_SIGNER: signer.pub, SHADE_TREE_HEALTH_CACHE: "", SHADE_TREE_BOOTNODE_ONION: "" },
      });
    } catch (e) {
      offOut = "THREW:" + ((e.stderr || e.stdout || e.message) + "");
    }
    ok(/CANDS:3/.test(offOut), `selection works with persistence OFF (SHADE_TREE_HEALTH_CACHE="")`);
  } finally {
    await rm(work, { recursive: true, force: true });
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: health-persistence selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
