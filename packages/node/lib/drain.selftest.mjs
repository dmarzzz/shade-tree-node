// Operator drain flag (lib/drain.mjs) + the `draining` caps key it rides on.
//   1. canonicalCaps: `draining: true` is appended LAST and only when exactly true, so every
//      pre-existing caps object canonicalizes to byte-identical JSON (and hasCaps sees it).
//   2. The signed caps still verify with the key present (signCaps/verifyCapsSig round trip).
//   3. pickGateway / selection skip a draining node while a non-draining one exists, and fall
//      back to it when nothing else is left (same policy as health "down").
//   4. The watcher reports transitions once, boots silently when not draining, and announces
//      at once when the flag already exists at start.
//   5. buildGatewayCaps(draining:true) adds the key; with it false the object is unchanged.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync } from "node:crypto";
import { canonicalCaps, hasCaps, pickGateway, signCaps, verifyCapsSig, isDraining, pubkeyToOnion } from "./directory.mjs";
import { drainFilePath, drainPollMs, isDraining as flagSet, setDraining, makeDrainWatcher, drainingSince } from "./drain.mjs";
import { buildGatewayCaps } from "../bootnode/heartbeat.mjs";

let n = 0;
const ok = (c, m) => { assert.ok(c, m); n += 1; console.log(`  ok   ${m}`); };

// 1. canonical form
const base = { ports: [443], region: "eu", admits: ["staked"], session: { version: 1, classes: ["research-v1"] } };
const baseJson = JSON.stringify(canonicalCaps(base));
ok(JSON.stringify(canonicalCaps({ ...base, draining: false })) === baseJson, "draining:false canonicalizes byte-identical to absent");
ok(JSON.stringify(canonicalCaps({ ...base, draining: "yes" })) === baseJson, "a non-boolean draining is dropped");
const drained = JSON.stringify(canonicalCaps({ ...base, draining: true }));
ok(drained.endsWith(',"draining":true}'), "draining:true is appended LAST");
ok(drained.slice(0, -("," + '"draining":true').length - 1) + "}" === baseJson, "everything before the new key is unchanged");
ok(!hasCaps({ draining: false }) && hasCaps({ draining: true }), "hasCaps counts only draining:true");

// 2. signature round trip (raw ed25519 seed/pub hex, as lib/directory.selftest.mjs does)
function newKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const priv = privateKey.export({ format: "der", type: "pkcs8" });
  const pub = publicKey.export({ format: "der", type: "spki" });
  return { seed: priv.subarray(priv.length - 32).toString("hex"), pub: pub.subarray(pub.length - 32).toString("hex") };
}
const k = newKey();
const id = { onion: pubkeyToOnion(k.pub), seed: k.seed };
const sig = signCaps(id.onion, { ...base, draining: true }, id.seed);
ok(verifyCapsSig(id.onion, { ...base, draining: true }, sig), "signed caps verify with draining present");
ok(!verifyCapsSig(id.onion, base, sig), "the same signature does not cover caps without the key (it is signed state)");

// 3. selection
const dir = { gateways: [
  { onion: "a".repeat(56) + ".onion", pubkey: "", weight: 100, health: "up", caps: { draining: true } },
  { onion: "b".repeat(56) + ".onion", pubkey: "", weight: 1, health: "up" },
] };
let picksB = 0;
for (let i = 0; i < 50; i++) if (pickGateway(dir, { rng: () => i / 50 }).onion.startsWith("b")) picksB += 1;
ok(picksB === 50, "pickGateway never picks the draining node while another is healthy (weight 100 vs 1)");
ok(pickGateway({ gateways: [dir.gateways[0]] }).onion.startsWith("a"), "a draining node is still picked when it is the only one left");
ok(isDraining(dir.gateways[0]) && !isDraining(dir.gateways[1]) && !isDraining(null), "isDraining reads the signed caps only");

// 4. watcher + flag file
const tmp = mkdtempSync(join(tmpdir(), "drain-"));
try {
  const path = join(tmp, "draining");
  const env = { SHADE_TREE_DRAIN_FILE: path, SHADE_TREE_DRAIN_POLL_MS: "250" };
  ok(drainFilePath(env) === path && drainPollMs(env) === 250, "env overrides the flag path and poll interval");
  ok(drainPollMs({ SHADE_TREE_DRAIN_POLL_MS: "5" }) === 2000 && drainFilePath({}).endsWith("deploy-state/draining"), "defaults: 2000 ms and <repo>/deploy-state/draining");
  ok(!flagSet(env), "no flag -> not draining");
  const seen = [];
  const timers = [];
  const w = makeDrainWatcher({ path, pollMs: 250, onChange: (v) => seen.push(v), schedule: (fn) => { timers.push(fn); return 1; }, clear: () => {} });
  w.start();
  ok(seen.length === 0 && w.state() === false, "starting while not draining reports nothing");
  setDraining(true, env);
  timers[0]();
  ok(seen.length === 1 && seen[0] === true && w.state() === true, "flag appears -> one onChange(true)");
  timers[0](); timers[0]();
  ok(seen.length === 1, "no repeat while the state is unchanged");
  ok(drainingSince(env) !== null && drainingSince(env) >= 0, "drainingSince reads the flag's age");
  setDraining(false, env);
  timers[0]();
  ok(seen.length === 2 && seen[1] === false, "flag removed -> one onChange(false)");
  ok(drainingSince(env) === null, "drainingSince is null when not draining");
  setDraining(true, env);
  const seen2 = [];
  const w2 = makeDrainWatcher({ path, pollMs: 250, onChange: (v) => seen2.push(v), schedule: () => 1, clear: () => {} });
  w2.start();
  ok(seen2.length === 1 && seen2[0] === true, "starting while ALREADY draining announces it at once");
  ok(setDraining(false, env) === false, "setDraining(false) is idempotent and returns the new state");
} finally { rmSync(tmp, { recursive: true, force: true }); }

// 5. heartbeat caps builder
const envCaps = { SHADE_TREE_ADMIT: "staked", SHADE_TREE_GATEWAY_REGION: "eu" };
const off = buildGatewayCaps(envCaps, { draining: false });
const on = buildGatewayCaps(envCaps, { draining: true });
ok(JSON.stringify(buildGatewayCaps(envCaps)) === JSON.stringify(off), "draining:false leaves buildGatewayCaps output unchanged");
ok(on.draining === true && JSON.stringify(canonicalCaps(on)).endsWith(',"draining":true}'), "draining:true rides in the heartbeat caps, last");
ok(buildGatewayCaps({}, { draining: false }) === null, "no caps + not draining -> null (byte-identical announce)");
ok(buildGatewayCaps({}, { draining: true })?.draining === true, "draining alone is enough to attach caps (so a default node can still drain)");

console.log(`PASS: drain flag + draining caps (${n} checks)`);
