// Selftest for scripts/record-canopy.mjs: writes the canopy into a copy of the committed
// sepolia-staging record under a TEMP network dir (never the committed file).
//
//   node scripts/record-canopy.selftest.mjs

import { cpSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { main, parseArgs } from "./record-canopy.mjs";
import { eldersOf, validateDeploymentRecord } from "../packages/node/lib/network-record.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };
const throws = (fn) => { try { fn(); return false; } catch { return true; } };
const HERE = dirname(fileURLToPath(import.meta.url));
const NETWORK = join(HERE, "..", "network");

// Real v3 onions (checksummed): the two Sepolia Elder Trees.
const A = "a4xt55gef66pifqebadjobjpy2drsoa63bdok4toisvenmyehslaz4id.onion";
const B = "k54vz4zu7l76qcqjclbfsd276j7uvtggpoyfxelusmpof2qizngxgrid.onion";
const SA = "1".repeat(64);
const SB = "2".repeat(64);
const COMMIT = "c".repeat(40);

const root = mkdtempSync(join(tmpdir(), "record-canopy-"));
try {
  for (const name of ["sepolia", "sepolia-staging"]) cpSync(join(NETWORK, name), join(root, name), { recursive: true });
  const quiet = { root, log: () => {} };

  ok(throws(() => parseArgs(["--network", "sepolia-staging", "--commit", COMMIT])), "an Elder is required");
  ok(throws(() => parseArgs(["--network", "sepolia-staging", "--commit", "abc", "--elder", `${A}=${SA}`])), "short commit refused");
  ok(throws(() => parseArgs(["--network", "sepolia-staging", "--commit", COMMIT, "--elder", `${A}=xyz`])), "bad signer refused");
  ok(throws(() => parseArgs(["--network", "sepolia-staging", "--commit", COMMIT, "--elder", `${A}=${SA}`, "--elders-from", "sepolia"])), "--elder and --elders-from are exclusive");
  ok(throws(() => main(["--network", "sepolia-staging", "--commit", COMMIT, "--elder", `${A}=${SA}`, "--elder", `${A}=${SB}`], quiet)), "a duplicate Elder is refused");

  const before = readFileSync(join(root, "sepolia-staging", "deployment.json"), "utf8");
  main(["--network", "sepolia-staging", "--commit", COMMIT, "--elder", `${A}=${SA}`, "--dry-run"], quiet);
  ok(readFileSync(join(root, "sepolia-staging", "deployment.json"), "utf8") === before, "--dry-run writes nothing");

  main(["--network", "sepolia-staging", "--commit", COMMIT, "--elder", `${A}=${SA}`, "--elder", `${B}=${SB}`], quiet);
  const rec = JSON.parse(readFileSync(join(root, "sepolia-staging", "deployment.json"), "utf8"));
  ok(validateDeploymentRecord(rec).ok, "the written record validates");
  ok(rec.schemaVersion === 2 && rec.status === "live", "schemaVersion 2, status live");
  ok(eldersOf(rec).map((e) => e.onion).join() === `${A},${B}`, "both Elders, primary first");
  ok(rec.elder.onion === A && rec.elder.gatewayRegistry === rec.elders[1].gatewayRegistry, "elder = elders[0], registry kept");
  ok(Object.values(rec.services).every((s) => s.commit === COMMIT), "every service pinned to the commit");
  ok(!/No canopy is recorded yet/.test(rec.note), "the pending note is replaced");
  ok(rec.admission.roots.staked.contract === JSON.parse(before).admission.roots.staked.contract, "the contracts half is untouched");

  const OTHER = "d".repeat(40);
  main(["--network", "sepolia-staging", "--commit", OTHER, "--elder", `${A}=${SA}`], quiet);
  const repinned = JSON.parse(readFileSync(join(root, "sepolia-staging", "deployment.json"), "utf8"));
  ok((repinned.note.match(/Canopy:/g) || []).length === 1 && repinned.note.includes(OTHER.slice(0, 12)), "a re-pin replaces the canopy sentence");

  main(["--network", "sepolia-staging", "--commit", COMMIT, "--elders-from", "sepolia"], quiet);
  const copied = JSON.parse(readFileSync(join(root, "sepolia-staging", "deployment.json"), "utf8"));
  const source = JSON.parse(readFileSync(join(root, "sepolia", "deployment.json"), "utf8"));
  ok(JSON.stringify(eldersOf(copied)) === JSON.stringify(eldersOf(source)), "--elders-from copies another network's canopy");
} finally {
  rmSync(root, { recursive: true, force: true });
}

if (failures) { console.log(`\nFAIL: record-canopy selftest (${failures})`); process.exit(1); }
console.log("\nPASS: record-canopy selftest");
