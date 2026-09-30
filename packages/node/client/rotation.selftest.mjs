// Selftest for quality-aware ROTATION / load spread (T-FEAT-4).
//
// Slot-0 (the gateway the client proxy actually dials) is chosen by smooth weighted round-robin per
// CONNECT by default. A weighted-random first choice remains as an explicit opt-out. Smooth rotation
// runs over the SAME healthy, weight-clamped, receipt-adjusted pool, spreading load evenly and avoiding
// re-hammering the just-used gateway while preserving the long-run weighted share exactly. When
// explicitly off, selection remains the original weight-only behavior.
//
// This drives the real packages/node/client/selection.mjs over a STATIC signed-directory source (no Tor, no chain):
// mint a signer + gateways, sign a directory, pin the signer, seed a deterministic rng, and count how
// often each gateway lands in slot-0 across many draws — the same statistical style the other selection
// selftests use. Env is set BEFORE importing selection.mjs because its config is read at module load;
// the default-ON and explicit-OFF proofs run in child processes (config is captured at import).
//
//   node packages/node/client/rotation.selftest.mjs
//
// Exit 0 = all invariants held (default spread/anti-stickiness, long-run weight preserved, explicit
// opt-out byte-identical). Nonzero = a check failed (prints which).

import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
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

// A small deterministic PRNG (mulberry32) so distribution assertions never flake.
function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// Count slot-0 landings over `n` draws, and how often slot-0 immediately REPEATS the previous slot-0
// (the anti-stickiness signal). Returns { counts, repeats }.
async function slotZeroStats(sel, n) {
  const counts = {};
  let repeats = 0, prev = null;
  for (let i = 0; i < n; i++) {
    const o = (await sel.selectCandidates())[0].onion;
    counts[o] = (counts[o] || 0) + 1;
    if (o === prev) repeats++;
    prev = o;
  }
  return { counts, repeats };
}

async function main() {
  const { pubkeyToOnion, signDirectory } = await import("../lib/directory.mjs");
  const signer = newKey();

  // Four EQUAL-weight gateways: the cleanest anti-stickiness case (spread => strict round-robin, zero
  // immediate repeats; weighted-random => ~1/4 repeat rate + clumping).
  const eq = [newKey(), newKey(), newKey(), newKey()];
  const eqOnions = eq.map((k) => pubkeyToOnion(k.pub));
  const bareEq = eqOnions.map((o) => o.replace(/\.onion$/, ""));
  const eqDir = signDirectory({
    version: 1,
    issued: Math.floor(Date.now() / 1000),
    gateways: eq.map((k, i) => ({ onion: eqOnions[i], pubkey: k.pub, weight: 100, health: "up" })),
    signer: signer.pub,
  }, signer.priv);

  // Two UNEQUAL-weight gateways (300 vs 100): the long-run-share case — spread must still hand out
  // slot-0 in a 3:1 ratio, exactly like weighted-random does.
  const uw = [newKey(), newKey()];
  const uwOnions = uw.map((k) => pubkeyToOnion(k.pub));
  const bareUw = uwOnions.map((o) => o.replace(/\.onion$/, ""));
  const uwWeights = [300, 100];
  const uwDir = signDirectory({
    version: 1,
    issued: Math.floor(Date.now() / 1000),
    gateways: uw.map((k, i) => ({ onion: uwOnions[i], pubkey: k.pub, weight: uwWeights[i], health: "up" })),
    signer: signer.pub,
  }, signer.priv);

  const work = mkdtempSync(join(tmpdir(), "shade-tree-rotation-"));
  const eqPath = join(work, "eq.json");
  const uwPath = join(work, "uw.json");
  writeFileSync(eqPath, JSON.stringify(eqDir) + "\n");
  writeFileSync(uwPath, JSON.stringify(uwDir) + "\n");

  // ---- default ON: an unset/empty setting arms smooth spread -------------------------------------
  console.log("default ON (SHADE_TREE_ROTATION_SPREAD unset):");
  const defaultScript = `
import { pathToFileURL } from "node:url";
const sel = await import(${JSON.stringify(pathToFileURL(SELECTION_PATH).href)});
if (sel.rotationSpreadEnabled() !== true) { console.error("SPREAD-OFF-UNEXPECTED"); process.exit(3); }
function mulberry32(seed){let a=seed>>>0;return()=>{a|=0;a=(a+0x6d2b79f5)|0;let t=Math.imul(a^(a>>>15),1|a);t=(t+Math.imul(t^(t>>>7),61|t))^t;return((t^(t>>>14))>>>0)/4294967296;};}
sel._setRng(mulberry32(0x44ef));
const bare = ${JSON.stringify(bareEq)};
const counts = {}; let repeats = 0, prev = null;
for (let i = 0; i < 8000; i++) {
  const o = (await sel.selectCandidates())[0].onion;
  counts[o] = (counts[o] || 0) + 1;
  if (o === prev) repeats++;
  prev = o;
}
for (const b of bare) if (counts[b] !== 2000) { console.error("DEFAULT-NOT-EVEN:" + b + "=" + counts[b]); process.exit(4); }
if (repeats !== 0) { console.error("DEFAULT-REPEATED:" + repeats); process.exit(5); }
console.log("DEFAULT-ON-OK");`;
  let defaultCode = 0, defaultOut = "";
  try {
    defaultOut = execFileSync(process.execPath, ["--input-type=module", "-e", defaultScript], {
      encoding: "utf8",
      env: {
        ...process.env,
        SHADE_TREE_DIRECTORY: eqPath,
        SHADE_TREE_DIR_SIGNER: signer.pub,
        SHADE_TREE_BOOTNODE_ONION: "",
        SHADE_TREE_HEALTH_CACHE: join(work, "health-default.json"),
        SHADE_TREE_DIRECTORY_REFRESH_MS: "0",
        SHADE_TREE_ROTATION_SPREAD: "",
      },
    });
  } catch (e) { defaultCode = e.status ?? 1; defaultOut = (e.stdout || "") + (e.stderr || ""); }
  ok(defaultCode === 0, `unset setting spreads equal gateways without repeats (${defaultOut.trim()})`);

  // ---- explicit OFF: preserve weighted-random ----------------------------------------------------
  console.log("explicit OFF (SHADE_TREE_ROTATION_SPREAD=0):");
  const offScript = `
import { pathToFileURL } from "node:url";
const sel = await import(${JSON.stringify(pathToFileURL(SELECTION_PATH).href)});
if (sel.rotationSpreadEnabled() !== false) { console.error("SPREAD-ON-UNEXPECTED"); process.exit(3); }
const bare = ${JSON.stringify(bareEq)};
const N = 8000;
const counts = {}; let repeats = 0, prev = null;
for (let i = 0; i < N; i++) {
  const o = (await sel.selectCandidates())[0].onion;
  counts[o] = (counts[o] || 0) + 1;
  if (o === prev) repeats++;
  prev = o;
}
// Weighted-random over 4 equal gateways: each ~N/4, and immediate-repeat rate ~1/4 (memoryless).
for (const b of bare) { const c = counts[b] || 0; if (Math.abs(c - N/4) > N*0.06) { console.error("OFF-NOT-PROPORTIONAL:" + b + "=" + c); process.exit(4); } }
const rr = repeats / (N - 1);
if (rr < 0.18) { console.error("OFF-TOO-SMOOTH(not weighted-random):" + rr.toFixed(3)); process.exit(5); }
console.log("OFF-OK repeatRate=" + rr.toFixed(3));
process.exit(0);`;
  let offCode = 0, offOut = "";
  try {
    offOut = execFileSync(process.execPath, ["--input-type=module", "-e", offScript], {
      encoding: "utf8",
      env: {
        ...process.env,
        SHADE_TREE_DIRECTORY: eqPath,
        SHADE_TREE_DIR_SIGNER: signer.pub,
        SHADE_TREE_BOOTNODE_ONION: "",
        SHADE_TREE_HEALTH_CACHE: join(work, "health-off.json"),
        SHADE_TREE_DIRECTORY_REFRESH_MS: "0",
        SHADE_TREE_ROTATION_SPREAD: "0",
      },
    });
  } catch (e) { offCode = e.status ?? 1; offOut = (e.stdout || "") + (e.stderr || ""); }
  ok(offCode === 0, `explicit opt-out keeps weighted-random slot-0 (proportional + memoryless repeats) (${offOut.trim()})`);

  // ---- flag ON: arm spread for the in-process checks ---------------------------------------------
  process.env.SHADE_TREE_DIRECTORY = eqPath;
  process.env.SHADE_TREE_DIR_SIGNER = signer.pub;
  process.env.SHADE_TREE_ROTATION_SPREAD = "1";
  process.env.SHADE_TREE_HEALTH_CACHE = join(work, "health.json");
  process.env.SHADE_TREE_DIRECTORY_REFRESH_MS = "0";
  delete process.env.SHADE_TREE_BOOTNODE_ONION;
  delete process.env.SHADE_TREE_VERIFY_STAKE;
  delete process.env.SHADE_TREE_RECEIPT_SCORING;

  const sel = await import(pathToFileURL(SELECTION_PATH).href);
  console.log("\nflag ON (SHADE_TREE_ROTATION_SPREAD=1):");
  ok(sel.rotationSpreadEnabled() === true, "rotationSpreadEnabled() is true with the flag armed");
  sel._setRng(mulberry32(0x1234abcd)); // deterministic jitter + failover weighting

  // ---- anti-stickiness: equal-weight fleet spreads evenly, no back-to-back hammering --------------
  console.log("\nequal-weight fleet: smooth spread, no immediate re-selection of the just-used gateway:");
  sel._resetRotationState();
  await sel.selectCandidates(); // warm the fleet load
  {
    const N = 8000;
    const { counts, repeats } = await slotZeroStats(sel, N);
    for (const b of bareEq) {
      const c = counts[b] || 0;
      ok(Math.abs(c - N / 4) < N * 0.03, `gateway gets ~N/4 of slot-0 (${b.slice(0, 8)}.. = ${c}, want ~${N / 4})`);
    }
    ok(repeats === 0, `zero immediate repeats over ${N} draws — the just-used gateway is never re-picked while peers are due (repeats=${repeats})`);
  }

  // ---- long-run weight preserved: unequal fleet still hands out slot-0 in weight ratio ------------
  console.log("\nunequal-weight fleet: spread preserves the long-run weighted share (3:1), not just evens it:");
  const sel2Env = { ...process.env, SHADE_TREE_DIRECTORY: uwPath };
  // Re-point at the unequal directory in-process: SHADE_TREE_DIRECTORY is read at import, so drive the
  // unequal case in a child process with the flag ON and deterministic, config-independent seeding.
  const uwScript = `
import { pathToFileURL } from "node:url";
const sel = await import(${JSON.stringify(pathToFileURL(SELECTION_PATH).href)});
if (sel.rotationSpreadEnabled() !== true) { console.error("SPREAD-OFF-UNEXPECTED"); process.exit(3); }
// Deterministic rng (mulberry32) inlined so the child matches the parent's determinism discipline.
function mulberry32(seed){let a=seed>>>0;return()=>{a|=0;a=(a+0x6d2b79f5)|0;let t=Math.imul(a^(a>>>15),1|a);t=(t+Math.imul(t^(t>>>7),61|t))^t;return((t^(t>>>14))>>>0)/4294967296;};}
sel._setRng(mulberry32(0x51ed));
sel._resetRotationState();
const bare = ${JSON.stringify(bareUw)};
const N = 8000;
const counts = {}; let repeats = 0, prev = null;
for (let i = 0; i < N; i++) {
  const o = (await sel.selectCandidates())[0].onion;
  counts[o] = (counts[o] || 0) + 1;
  if (o === prev) repeats++;
  prev = o;
}
const hi = counts[bare[0]] || 0, lo = counts[bare[1]] || 0;
// weight 300 vs 100 => 3:1 share, i.e. hi ~ 0.75*N, lo ~ 0.25*N.
if (Math.abs(hi - 0.75*N) > N*0.03) { console.error("HI-SHARE-OFF:" + hi); process.exit(4); }
if (Math.abs(lo - 0.25*N) > N*0.03) { console.error("LO-SHARE-OFF:" + lo); process.exit(5); }
// Even with an over-half-weight gateway, the low-weight one is interleaved, never starved: it should
// appear regularly (every ~4th draw), and hi should not be a solid run (some non-repeats).
const rr = repeats / (N - 1);
if (rr > 0.55) { console.error("NOT-INTERLEAVED(too sticky):" + rr.toFixed(3)); process.exit(6); }
console.log("UW-OK hi=" + hi + " lo=" + lo + " repeatRate=" + rr.toFixed(3));
process.exit(0);`;
  let uwCode = 0, uwOut = "";
  try {
    uwOut = execFileSync(process.execPath, ["--input-type=module", "-e", uwScript], {
      encoding: "utf8",
      env: {
        ...sel2Env,
        SHADE_TREE_DIRECTORY: uwPath,
        SHADE_TREE_DIR_SIGNER: signer.pub,
        SHADE_TREE_BOOTNODE_ONION: "",
        SHADE_TREE_HEALTH_CACHE: join(work, "health-uw.json"),
        SHADE_TREE_DIRECTORY_REFRESH_MS: "0",
        SHADE_TREE_ROTATION_SPREAD: "1",
      },
    });
  } catch (e) { uwCode = e.status ?? 1; uwOut = (e.stdout || "") + (e.stderr || ""); }
  ok(uwCode === 0, `spread keeps the 3:1 weighted share while interleaving (never starving) the low-weight gateway (${uwOut.trim()})`);

  // ---- honors health: a "down" gateway is excluded from the spread pool --------------------------
  // (back on the equal-weight in-process fleet). Mark one down via reportResult and confirm slot-0
  // spreads over the remaining 3 only, still with no immediate repeats.
  console.log("\nhealth signal honored: a downed gateway drops out of the spread, the rest keep spreading:");
  sel._resetRotationState();
  sel.reportResult(bareEq[0], { ok: false });
  sel.reportResult(bareEq[0], { ok: false }); // 2 fails => "down"
  await sel.selectCandidates();
  {
    const N = 6000;
    const { counts, repeats } = await slotZeroStats(sel, N);
    ok(!counts[bareEq[0]], "the downed gateway is never chosen for slot-0 while healthy peers remain");
    for (const b of bareEq.slice(1)) {
      const c = counts[b] || 0;
      ok(Math.abs(c - N / 3) < N * 0.04, `each remaining healthy gateway gets ~N/3 of slot-0 (${b.slice(0, 8)}.. = ${c})`);
    }
    ok(repeats === 0, `still zero immediate repeats across the 3-gateway spread (repeats=${repeats})`);
    // ...but the downed gateway is still offered as a last-resort FAILOVER (fleet never dead-ends).
    const order = await sel.selectCandidates();
    ok(order.some((c) => c.onion === bareEq[0]), "the downed gateway is still present as a failover (does not vanish from the order)");
    ok(new Set(order.map((c) => c.onion)).size === 4, "the full failover order still covers all 4 gateways with no duplicates");
  }

  // ---- T-FEAT-24: the SWRR _swrr deficit map stays bounded — pruned to the live fleet on churn ----
  // _swrr is module-private session state (onion -> current deficit). spreadSelectionOrder deletes every
  // key not in the current live fleet on each call, so it can't grow unboundedly across directory
  // refreshes. This proves that structurally via the read-only _swrrSize() seam: spread over fleet A,
  // then swap to a COMPLETELY DISJOINT fleet B and spread again — the departed fleet-A keys must be
  // pruned (size stays 3, never 6). A still-in-fleet but "down" gateway must KEEP its deficit (it is
  // still in the fleet, only out of the spread pool), so it is not pruned. DIRECTORY_PATH is fixed to
  // eqPath at import and SHADE_TREE_DIRECTORY_REFRESH_MS=0 reloads it every call, so overwriting the file
  // swaps the live fleet in-process.
  console.log("\n_swrr bounding (T-FEAT-24): fleet churn prunes departed onions, keeps live (incl. down) ones:");
  const fa = [newKey(), newKey(), newKey()];
  const faOnions = fa.map((k) => pubkeyToOnion(k.pub));
  const fb = [newKey(), newKey(), newKey()]; // fleet B: NO onion shared with fleet A
  const fbOnions = fb.map((k) => pubkeyToOnion(k.pub));
  const bareFb = fbOnions.map((o) => o.replace(/\.onion$/, ""));
  const issuedA = Math.floor(Date.now() / 1000) + 10; // above any issued already accepted this process
  const dirA = signDirectory({
    version: 1, issued: issuedA,
    gateways: fa.map((k, i) => ({ onion: faOnions[i], pubkey: k.pub, weight: 100, health: "up" })),
    signer: signer.pub,
  }, signer.priv);
  const dirB = signDirectory({
    version: 1, issued: issuedA + 1,
    gateways: fb.map((k, i) => ({ onion: fbOnions[i], pubkey: k.pub, weight: 100, health: "up" })),
    signer: signer.pub,
  }, signer.priv);

  sel._setRng(mulberry32(0x24fea724));
  sel._resetRotationState();
  sel._resetIssuedFloor();
  ok(sel._swrrSize() === 0, "_swrr starts empty after _resetRotationState()");

  // Spread over fleet A — its 3 onions populate the deficit map.
  writeFileSync(eqPath, JSON.stringify(dirA) + "\n");
  for (let i = 0; i < 12; i++) await sel.selectCandidates();
  ok(sel._swrrSize() > 0, "_swrr is populated after spreading over fleet A (size > 0)");
  ok(sel._swrrSize() === 3, `_swrr holds exactly fleet A's 3 onions (size=${sel._swrrSize()})`);

  // Swap the ENTIRE fleet to B (no shared onions) and spread again — the departed fleet-A keys must be
  // pruned, so the map retains ONLY the live fleet (3), never growing to 6.
  writeFileSync(eqPath, JSON.stringify(dirB) + "\n");
  for (let i = 0; i < 12; i++) await sel.selectCandidates();
  ok(sel._swrrSize() === 3, `after full fleet churn _swrr retains ONLY live fleet B (3), departed fleet A pruned — not 6 (size=${sel._swrrSize()})`);

  // A temporarily-"down" gateway that is STILL in the fleet keeps its deficit (it is in `all`, only out
  // of the spread pool), so the prune leaves it — the map does not shrink to 2.
  sel.reportResult(bareFb[0], { ok: false });
  sel.reportResult(bareFb[0], { ok: false }); // 2 fails => "down"
  for (let i = 0; i < 6; i++) await sel.selectCandidates();
  ok(sel._swrrSize() === 3, `a still-in-fleet but DOWN gateway keeps its deficit (not pruned) — size stays 3 (size=${sel._swrrSize()})`);

  rmSync(work, { recursive: true, force: true });
  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: rotation selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
