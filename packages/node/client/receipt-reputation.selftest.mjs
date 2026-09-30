// Selftest for client-side receipt reputation → quality-aware selection (T-FEAT-22).
//
// T-FEAT-13 gives the client a verifiable per-epoch egress-success receipt from each gateway; T-FEAT-22
// accumulates those outcomes into a SMALL, LOCAL, per-gateway quality tally (next to the health cache)
// that nudges weighted selection: a gateway with a strong recent VALID-receipt record earns a modest
// bonus over an equal-weight silent one, and a gateway that returns BAD receipts (the gate-then-drop
// signal) is deprioritized. The whole feature is OFF by default and, when off, selection is byte-
// identical to today's weight-only behavior.
//
// This drives the real packages/node/client/selection.mjs over a STATIC signed-directory source (no Tor, no chain):
// mint a signer + two equal-weight gateways, sign a directory, pin the signer, then drive reportReceipt
// and the selection ORDER directly — both by folding real outcomes and by injecting tally state. Env is
// set BEFORE importing selection.mjs because its config is read at module load.
//
//   node packages/node/client/receipt-reputation.selftest.mjs
//
// Exit 0 = all invariants held (default-off byte-identical, privacy-preserving tally, bonus/penalty +
// decay + bound). Nonzero = a check failed (prints which).

import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, writeFileSync, rmSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { execFileSync } from "node:child_process";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

const HERE = dirname(fileURLToPath(import.meta.url));
const SELECTION_PATH = join(HERE, "selection.mjs");

function newKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const priv = privateKey.export({ format: "der", type: "pkcs8" });
  const pub = publicKey.export({ format: "der", type: "spki" });
  return { priv: priv.subarray(priv.length - 32).toString("hex"), pub: pub.subarray(pub.length - 32).toString("hex") };
}

// Count how often each gateway lands in the FIRST (weighted-pick) selection slot over `n` independent
// selections — the same statistical style selection.selftest.mjs uses (selection is weighted-random).
async function firstSlotCounts(sel, n) {
  const counts = {};
  for (let i = 0; i < n; i++) {
    const c = (await sel.selectCandidates())[0].onion;
    counts[c] = (counts[c] || 0) + 1;
  }
  return counts;
}

async function main() {
  const { pubkeyToOnion, signDirectory } = await import("../lib/directory.mjs");
  const signer = newKey();
  const gA = newKey();
  const gB = newKey();
  const onionA = pubkeyToOnion(gA.pub);
  const onionB = pubkeyToOnion(gB.pub);
  const bareA = onionA.replace(/\.onion$/, "");
  const bareB = onionB.replace(/\.onion$/, "");

  const base = {
    version: 1,
    issued: Math.floor(Date.now() / 1000),
    gateways: [
      { onion: onionA, pubkey: gA.pub, weight: 100, health: "up" },
      { onion: onionB, pubkey: gB.pub, weight: 100, health: "up" },
    ],
    signer: signer.pub,
  };
  const signed = signDirectory(base, signer.priv);

  const work = mkdtempSync(join(tmpdir(), "shade-tree-receipt-"));
  const dirPath = join(work, "directory.json");
  const receiptCache = join(work, "receipts.json");
  writeFileSync(dirPath, JSON.stringify(signed) + "\n");

  // ---- default OFF: byte-identical + nothing persisted (separate process) -------------------
  // Config is captured at import, so the OFF proof must run in its own process with the flag UNSET.
  console.log("default OFF (SHADE_TREE_RECEIPT_SCORING unset), separate process:");
  const offCache = join(work, "receipts-off.json");
  const offScript = `
import { pathToFileURL } from "node:url";
import { existsSync } from "node:fs";
const sel = await import(${JSON.stringify(pathToFileURL(SELECTION_PATH).href)});
if (sel.receiptScoringEnabled() !== false) { console.error("SCORING-ON-UNEXPECTED"); process.exit(3); }
await sel.selectCandidates(); // load the fleet
// Hammer reportReceipt: with the flag off it must be a total no-op — no throw, no file.
for (let i = 0; i < 50; i++) sel.reportReceipt(${JSON.stringify(bareA)}, { valid: true });
if (existsSync(${JSON.stringify(offCache)})) { console.error("OFF-WROTE-FILE"); process.exit(4); }
const counts = {};
for (let i = 0; i < 3000; i++) { const o = (await sel.selectCandidates())[0].onion; counts[o] = (counts[o]||0)+1; }
const a = counts[${JSON.stringify(bareA)}] || 0, b = counts[${JSON.stringify(bareB)}] || 0;
// Equal weights, no adjustment → ~50/50; a bonused A would skew this. Assert it did NOT.
if (Math.abs(a - b) > 400) { console.error("OFF-SKEWED:" + a + "/" + b); process.exit(5); }
console.log("OFF-OK:" + a + "/" + b);
process.exit(0);`;
  let offCode = 0, offOut = "";
  try {
    offOut = execFileSync(process.execPath, ["--input-type=module", "-e", offScript], {
      encoding: "utf8",
      env: {
        ...process.env,
        SHADE_TREE_DIRECTORY: dirPath,
        SHADE_TREE_DIR_SIGNER: signer.pub,
        SHADE_TREE_BOOTNODE_ONION: "",
        SHADE_TREE_HEALTH_CACHE: join(work, "health-off.json"),
        SHADE_TREE_RECEIPT_CACHE: offCache,
        SHADE_TREE_DIRECTORY_REFRESH_MS: "0",
        SHADE_TREE_RECEIPT_SCORING: "", // explicitly OFF
      },
    });
  } catch (e) { offCode = e.status ?? 1; offOut = (e.stdout || "") + (e.stderr || ""); }
  ok(offCode === 0, `flag off: reportReceipt is a no-op, no file, selection unchanged (${offOut.trim()})`);

  // ---- flag ON: arm scoring for the in-process checks --------------------------------------
  process.env.SHADE_TREE_DIRECTORY = dirPath;
  process.env.SHADE_TREE_DIR_SIGNER = signer.pub;
  process.env.SHADE_TREE_RECEIPT_SCORING = "1";
  process.env.SHADE_TREE_RECEIPT_CACHE = receiptCache;
  process.env.SHADE_TREE_HEALTH_CACHE = join(work, "health.json");
  process.env.SHADE_TREE_DIRECTORY_REFRESH_MS = "0";
  delete process.env.SHADE_TREE_BOOTNODE_ONION;
  delete process.env.SHADE_TREE_VERIFY_STAKE;

  const sel = await import(pathToFileURL(SELECTION_PATH).href);
  console.log("\nflag ON (SHADE_TREE_RECEIPT_SCORING=1):");
  ok(sel.receiptScoringEnabled() === true, "receiptScoringEnabled() is true with the flag armed");

  // Load the fleet so reportReceipt has a directory to attribute onions to.
  await sel.selectCandidates();

  // Armed but NO receipts yet → identity adjustment → still ~50/50, and no file written.
  console.log("\narmed but no receipts yet — identity (still ~50/50, nothing persisted):");
  ok(!existsSync(receiptCache), "no tally file exists before any receipt is reported");
  {
    const c = await firstSlotCounts(sel, 3000);
    const a = c[bareA] || 0, b = c[bareB] || 0;
    ok(Math.abs(a - b) < 400, `no-tally selection is ~50/50 (${a}/${b}) — arming alone changes nothing`);
  }

  // ---- privacy: folding real receipts stores ONLY {score,samples,lastSeen} ------------------
  console.log("\nreportReceipt folds outcomes; tally is privacy-preserving:");
  for (let i = 0; i < 6; i++) sel.reportReceipt(bareA, { valid: true });
  ok(existsSync(receiptCache), "a tally file is written once a receipt is reported");
  const persisted = JSON.parse(readFileSync(receiptCache, "utf8"));
  ok(persisted.version === 1 && persisted.entries && persisted.entries[onionA], "tally keyed by the gateway's own .onion");
  ok(!persisted.entries[bareB] && !persisted.entries[onionB], "a gateway with no receipts has no tally entry");
  const eA = persisted.entries[onionA];
  ok(JSON.stringify(Object.keys(eA).sort()) === JSON.stringify(["lastSeen", "samples", "score"]),
    `entry holds ONLY {score,samples,lastSeen} — no receipt bytes/epoch/sig (keys: ${Object.keys(eA).join(",")})`);
  ok(eA.score > 0.9 && eA.score <= 1, `valid receipts drive score → ~1 (${eA.score.toFixed(3)})`);
  ok(typeof eA.samples === "number" && eA.samples <= 4, `samples is bounded/capped (${eA.samples})`);
  const rawText = readFileSync(receiptCache, "utf8");
  ok(!/"epoch"|"sig"|"nullifier"|"v"\s*:/.test(rawText), "no epoch / sig / nullifier / receipt-version anywhere in the file");

  // ---- privacy guard: an onion NOT in the signed directory is never persisted ---------------
  const strangerOnion = pubkeyToOnion(newKey().pub).replace(/\.onion$/, "");
  sel.reportReceipt(strangerOnion, { valid: true });
  const afterStranger = JSON.parse(readFileSync(receiptCache, "utf8")).entries;
  ok(!afterStranger[strangerOnion] && !afterStranger[strangerOnion + ".onion"],
    "reportReceipt for an unknown onion (not in the SIGNED directory) is dropped — never persisted");

  // ---- bonus vs penalty: inject extreme tally state and check the ORDER ----------------------
  // Inject A=all-valid, B=all-bad at full confidence → A weight 150, B weight 50 (bonus ±50%).
  console.log("\nstrong-receipt gateway preferred over a bad-receipt equal-weight one:");
  const now = Date.now();
  sel._setReceiptCache({
    [onionA]: { score: 1, samples: 4, lastSeen: now },
    [onionB]: { score: 0, samples: 4, lastSeen: now },
  });
  {
    const c = await firstSlotCounts(sel, 4000);
    const a = c[bareA] || 0, b = c[bareB] || 0;
    ok(a > b, `A (strong receipts) is picked first more than B (bad receipts): ${a} vs ${b}`);
    ok(a / (a + b) > 0.62, `the bonus/penalty is decisive, not marginal (A share ${(a / (a + b)).toFixed(3)})`);
  }

  // ---- decay: a stale tally fades to neutral → back to ~50/50 (not punished forever) ---------
  console.log("\na decayed (stale) tally fades to neutral — no lingering bonus/penalty:");
  const stale = now - 30 * 24 * 60 * 60 * 1000; // older than the 14d default decay
  sel._setReceiptCache({
    [onionA]: { score: 1, samples: 4, lastSeen: stale },
    [onionB]: { score: 0, samples: 4, lastSeen: stale },
  });
  {
    const c = await firstSlotCounts(sel, 3000);
    const a = c[bareA] || 0, b = c[bareB] || 0;
    ok(Math.abs(a - b) < 400, `stale tally ignored, selection returns to ~50/50 (${a}/${b})`);
  }

  // ---- bounded: the tally can never grow past SHADE_TREE_RECEIPT_MAX (oldest-lastSeen evicted) -----
  console.log("\ntally is bounded (oldest-lastSeen evicted past the cap):");
  const boundCache = join(work, "receipts-bound.json");
  const boundScript = `
import { pathToFileURL } from "node:url";
import { readFileSync } from "node:fs";
const sel = await import(${JSON.stringify(pathToFileURL(SELECTION_PATH).href)});
const big = {};
for (let i = 0; i < 20; i++) big["onion" + i] = { score: 1, samples: 4, lastSeen: 1000 + i };
sel._setReceiptCache(big);
sel.saveReceiptCache(); // bounds + writes through
const entries = JSON.parse(readFileSync(${JSON.stringify(boundCache)}, "utf8")).entries;
const keys = Object.keys(entries);
if (keys.length !== 5) { console.error("NOT-CAPPED:" + keys.length); process.exit(6); }
// oldest lastSeen (onion0..onion14) evicted; newest 5 (onion15..onion19) kept
if (!entries["onion19"] || entries["onion0"]) { console.error("WRONG-EVICTION"); process.exit(7); }
console.log("CAP-OK:" + keys.length);
process.exit(0);`;
  let boundCode = 0, boundOut = "";
  try {
    boundOut = execFileSync(process.execPath, ["--input-type=module", "-e", boundScript], {
      encoding: "utf8",
      env: {
        ...process.env,
        SHADE_TREE_RECEIPT_SCORING: "1",
        SHADE_TREE_RECEIPT_CACHE: boundCache,
        SHADE_TREE_RECEIPT_MAX: "5",
        SHADE_TREE_DIRECTORY: dirPath,
        SHADE_TREE_DIR_SIGNER: signer.pub,
      },
    });
  } catch (e) { boundCode = e.status ?? 1; boundOut = (e.stdout || "") + (e.stderr || ""); }
  ok(boundCode === 0, `tally capped at SHADE_TREE_RECEIPT_MAX with oldest-first eviction (${boundOut.trim()})`);

  rmSync(work, { recursive: true, force: true });
  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: receipt-reputation selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
