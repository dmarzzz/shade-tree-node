// Selftest for the OPTIONAL absolute directory freshness bound (T-FEAT-21).
//
// The monotonic issued FLOOR (directory-rollback.selftest.mjs) only stops rollback WITHIN a session.
// On a COLD start a fresh client with no prior state accepts whatever `issued` the bootnode first
// serves, so a bootnode that is far behind — or replaying a months-old but validly signed directory
// to a new client — is undetectable. SHADE_TREE_DIRECTORY_MAX_AGE_MS adds an absolute bound: a FRESH
// directory whose `issued` is older than now - max-age (plus a clock-skew grace) is rejected,
// failing closed to the last-good in-memory fleet exactly like the rollback guard.
//
// This drives the real packages/node/client/selection.mjs load path against a file-backed signed directory (no
// Tor, no chain). Because selection.mjs reads its config at module load, each scenario sets env and
// then dynamic-imports the module with a UNIQUE query string (?scenario=...) so ESM hands back a
// FRESH module instance that re-reads process.env — letting one process exercise both the OFF
// default and the armed bound.
//
//   node packages/node/client/directory-maxage.selftest.mjs
//
// Exit 0 = default (unset) is unaffected, within-bound loads, beyond-bound is rejected on first
// load, and a stale refresh fails closed to the last-good fleet.
//
// UNIT NOTE: directory `issued` is in SECONDS (bootnode makeRegistry: now = Math.floor(Date.now()/
// 1000)); the env bound is in MS. This test writes `issued` in seconds to match, and selection.mjs
// scales it (× 1000) before comparing.

import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

function newKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const priv = privateKey.export({ format: "der", type: "pkcs8" });
  const pub = publicKey.export({ format: "der", type: "spki" });
  return { priv: priv.subarray(priv.length - 32).toString("hex"), pub: pub.subarray(pub.length - 32).toString("hex") };
}

const nowSec = () => Math.floor(Date.now() / 1000);

async function main() {
  const { pubkeyToOnion, signDirectory } = await import("../lib/directory.mjs");
  const signer = newKey();

  // A directory with a single fresh gateway, signed by `signer`, declaring the given `issued`
  // (SECONDS). Returns the signed object so callers can read back the onion it swapped in.
  function signedDir(issued) {
    const g = newKey();
    const base = {
      version: 1,
      issued,
      gateways: [{ onion: pubkeyToOnion(g.pub), pubkey: g.pub, weight: 100, health: "up" }],
      signer: signer.pub,
    };
    return signDirectory(base, signer.priv);
  }

  const dir = mkdtempSync(join(tmpdir(), "shade-tree-maxage-"));
  const dirPath = join(dir, "directory.json");
  const writeDir = (issued) => { const d = signedDir(issued); writeFileSync(dirPath, JSON.stringify(d) + "\n"); return d; };

  // Common file-source config: no bootnode, reload every call, isolated health cache. Each scenario
  // additionally sets/clears SHADE_TREE_DIRECTORY_MAX_AGE_MS before its fresh import.
  function baseEnv() {
    process.env.SHADE_TREE_DIRECTORY = dirPath;
    process.env.SHADE_TREE_DIR_SIGNER = signer.pub;
    process.env.SHADE_TREE_DIRECTORY_REFRESH_MS = "0"; // every selectCandidates() re-reads the file
    process.env.SHADE_TREE_DIRECTORY_CACHE = join(dir, "nonexistent.lkg"); // no pre-seeded cache
    process.env.SHADE_TREE_HEALTH_CACHE = join(dir, "health.json");
    delete process.env.SHADE_TREE_BOOTNODE_ONION;
    delete process.env.SHADE_TREE_VERIFY_STAKE;
  }

  const ONE_HOUR_S = 3600;
  const ONE_HOUR_MS = 3600 * 1000;

  // --- Scenario A: OFF by default (env unset) — an ANCIENT directory still loads unchanged. ------
  // Proves the default path is byte-identical to today: no max-age check whatsoever.
  console.log("A. default (SHADE_TREE_DIRECTORY_MAX_AGE_MS unset): an ancient directory loads unaffected:");
  {
    baseEnv();
    delete process.env.SHADE_TREE_DIRECTORY_MAX_AGE_MS;
    delete process.env.SHADE_TREE_DIRECTORY_MAX_AGE_SKEW_MS;
    const ancient = writeDir(nowSec() - 400 * 24 * ONE_HOUR_S); // ~400 days old
    const sel = await import("./selection.mjs?scenario=off");
    sel._resetIssuedFloor();
    const out = await sel.selectCandidates();
    ok(out.length === 1, "ancient directory loads (no bound armed)");
    ok(out[0].onion === ancient.gateways[0].onion.replace(/\.onion$/, ""), "served the ancient directory's gateway verbatim");
  }

  // --- Scenario B: armed, WITHIN bound — a fresh directory loads. -------------------------------
  console.log("\nB. armed (max-age 1h): a within-bound directory loads:");
  {
    baseEnv();
    process.env.SHADE_TREE_DIRECTORY_MAX_AGE_MS = String(ONE_HOUR_MS);
    process.env.SHADE_TREE_DIRECTORY_MAX_AGE_SKEW_MS = "0"; // no grace, sharpen the bound for the test
    const fresh = writeDir(nowSec() - 60); // 1 minute old, well within 1h
    const sel = await import("./selection.mjs?scenario=within");
    sel._resetIssuedFloor();
    const out = await sel.selectCandidates();
    ok(out.length === 1, "within-bound directory loads");
    ok(out[0].onion === fresh.gateways[0].onion.replace(/\.onion$/, ""), "served the fresh directory's gateway");
  }

  // --- Scenario C: armed, BEYOND bound, COLD start — rejected on first load. ---------------------
  // No prior fleet exists, so fail-closed means selectCandidates throws (directory mode has nothing
  // to serve) rather than accepting a stale replay.
  console.log("\nC. armed (max-age 1h): a beyond-bound directory is REJECTED on first (cold) load:");
  {
    baseEnv();
    process.env.SHADE_TREE_DIRECTORY_MAX_AGE_MS = String(ONE_HOUR_MS);
    process.env.SHADE_TREE_DIRECTORY_MAX_AGE_SKEW_MS = "0";
    writeDir(nowSec() - 3 * ONE_HOUR_S); // 3 hours old, beyond the 1h bound
    const sel = await import("./selection.mjs?scenario=cold-stale");
    sel._resetIssuedFloor();
    let threw = false;
    try { await sel.selectCandidates(); } catch { threw = true; }
    ok(threw, "beyond-bound directory rejected on cold start (no stale fleet accepted)");
  }

  // --- Scenario D: armed — a stale REFRESH fails closed to the last-good in-memory fleet. --------
  console.log("\nD. armed (max-age 1h): a good load then a stale refresh keeps the last-good fleet:");
  {
    baseEnv();
    process.env.SHADE_TREE_DIRECTORY_MAX_AGE_MS = String(ONE_HOUR_MS);
    process.env.SHADE_TREE_DIRECTORY_MAX_AGE_SKEW_MS = "0";
    const good = writeDir(nowSec() - 60); // fresh
    const sel = await import("./selection.mjs?scenario=refresh");
    sel._resetIssuedFloor();
    const first = await sel.selectCandidates();
    ok(first.length === 1, "fresh directory loads as the working fleet");
    const goodOnion = good.gateways[0].onion.replace(/\.onion$/, "");
    ok(first[0].onion === goodOnion, "working fleet is the fresh gateway");

    // Drop the monotonic floor so the stale refresh is NOT a rollback (issued would still be > 0):
    // this isolates the MAX-AGE guard specifically, proving it fails closed to the live fleet on its
    // own, independent of the rollback guard.
    sel._resetIssuedFloor();
    writeDir(nowSec() - 5 * ONE_HOUR_S); // now serve a stale one (beyond the 1h bound)
    const second = await sel.selectCandidates();
    ok(second.length === 1, "still serving a fleet (did not go dark)");
    ok(second[0].onion === goodOnion, "stale refresh REJECTED — kept the last-good in-memory fleet");
  }

  // --- Scenario E: armed — the clock-skew grace widens the acceptance window. --------------------
  // A directory just past the RAW bound but inside bound + skew must still load, so a lagging client
  // clock doesn't spuriously reject a just-issued directory.
  console.log("\nE. armed (max-age 1h, skew 1h): a directory past the raw bound but within grace loads:");
  {
    baseEnv();
    process.env.SHADE_TREE_DIRECTORY_MAX_AGE_MS = String(ONE_HOUR_MS);
    process.env.SHADE_TREE_DIRECTORY_MAX_AGE_SKEW_MS = String(ONE_HOUR_MS); // 1h grace => 2h effective window
    const edge = writeDir(nowSec() - 90 * 60); // 90 min old: > 1h bound, < 2h bound+skew
    const sel = await import("./selection.mjs?scenario=skew");
    sel._resetIssuedFloor();
    const out = await sel.selectCandidates();
    ok(out.length === 1, "directory within bound + skew grace loads");
    ok(out[0].onion === edge.gateways[0].onion.replace(/\.onion$/, ""), "served the edge-of-grace gateway");
  }

  rmSync(dir, { recursive: true, force: true });
  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: directory-maxage selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
