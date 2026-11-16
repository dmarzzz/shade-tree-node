// Selftest for packages/node/lib/prover-workers.mjs (SHADE_TREE_PROVER_WORKERS).
// Covers: the default (min(cpus, 4), the empty-cpus fallback), the parse surface against hostile
// values (empty, whitespace, non-numeric, 0, negative, fractions, exponent/hex/sign forms,
// trailing junk, huge, non-string), the config.mjs wiring for both roles that prove or verify,
// that the os.cpus() override is scoped to the build and restored on success, rejection and a
// synchronous throw, and that the init builds once, honors a cached engine, and fails closed on a
// bad value without touching os.cpus. Fast lane: no proof, no worker threads, no network.
// The end-to-end check (a real snarkjs engine gets the capped pool) is in the last block and
// builds only the bn128 engine (no zkey), then terminates it.
//
//   node packages/node/lib/prover-workers.selftest.mjs

import assert from "node:assert/strict";
import os from "node:os";
import { createRequire } from "node:module";
import {
  PROVER_WORKERS_VAR, DEFAULT_MAX_PROVER_WORKERS, MAX_PROVER_WORKERS,
  defaultProverWorkers, parseProverWorkers, isProverWorkers, withCpuCount, makeCurveInit,
} from "./prover-workers.mjs";
import { validateConfig } from "./config.mjs";

let n = 0;
const check = (cond, msg) => { assert.ok(cond, msg); n++; };

// ---- default ---------------------------------------------------------------
check(PROVER_WORKERS_VAR === "SHADE_TREE_PROVER_WORKERS", "variable name");
check(DEFAULT_MAX_PROVER_WORKERS === 4 && MAX_PROVER_WORKERS === 64, "bounds 4 / 64");
for (const [cpus, want] of [[1, 1], [2, 2], [3, 3], [4, 4], [5, 4], [16, 4], [128, 4]]) {
  check(defaultProverWorkers(cpus) === want, `default for ${cpus} cpus is ${want}`);
}
// ffjavascript uses 2 when os.cpus() is empty; never 0, never NaN.
for (const cpus of [0, -3, NaN, undefined, 2.5, "8"]) {
  check(defaultProverWorkers(cpus) === 2, `default for cpus=${String(cpus)} falls back to 2`);
}

// ---- parse: accepted --------------------------------------------------------
for (const raw of [undefined, null, "", "   ", "\t\n"]) {
  const r = parseProverWorkers(raw, 16);
  check(r.ok && r.workers === 4 && r.source === "default", `unset/empty ${JSON.stringify(raw)} -> default 4 on 16 cpus`);
}
check(parseProverWorkers("", 2).workers === 2, "empty on 2 cpus -> 2 (never more than the host has)");
for (const [raw, want] of [["1", 1], ["4", 4], ["16", 16], ["64", 64], [" 8 ", 8], ["08", 8], ["001", 1], [12, 12]]) {
  const r = parseProverWorkers(raw, 16);
  check(r.ok && r.workers === want && r.source === "env", `${JSON.stringify(raw)} -> ${want}`);
}
// An explicit value may exceed the host cpu count (ffjavascript would allow it too); the cap is 64.
check(parseProverWorkers("32", 4).workers === 32, "explicit value is not clamped to cpus");

// ---- parse: rejected (adversarial) -----------------------------------------
const BAD = [
  "0", "00", "-1", "-0", "+4", "65", "100", "999", "1000", "4294967297", "9".repeat(400),
  "1.5", "4.0", ".5", "1e1", "1E2", "0x10", "0b11", "0o7", "Infinity", "-Infinity", "NaN",
  "four", "4abc", "abc4", "4 4", "4,8", "4_0", "٤", "４", "4\u0000", "true", "[]", "{}",
  0, -1, 1.5, 65, NaN, Infinity, true, false, {}, [4, 8], { valueOf: () => 4 },
];
for (const raw of BAD) {
  let r;
  assert.doesNotThrow(() => { r = parseProverWorkers(raw, 16); }, `parse never throws on ${String(raw).slice(0, 20)}`);
  check(r.ok === false && /SHADE_TREE_PROVER_WORKERS must be an integer 1\.\.64/.test(r.reason), `rejects ${JSON.stringify(String(raw)).slice(0, 24)}`);
  check(isProverWorkers(raw) === false, `isProverWorkers rejects ${JSON.stringify(String(raw)).slice(0, 24)}`);
}
// A value whose toString throws must not crash the parser into an uncaught throw path the caller
// does not expect: parse is documented TOTAL. String() on a symbol throws, so wrap and assert.
{
  let r, threw = false;
  try { r = parseProverWorkers(Symbol("x"), 16); } catch { threw = true; }
  check(threw || r.ok === false, "a Symbol is rejected or throws (never accepted)");
}
check(isProverWorkers("4") && isProverWorkers(" 64 ") && !isProverWorkers("") && !isProverWorkers("  "), "isProverWorkers: explicit values only");

// ---- config.mjs wiring -------------------------------------------------------
for (const role of ["gateway", "client"]) {
  const base = role === "client" ? { SHADE_TREE_SECRET: "0x01", SHADE_TREE_ONION: undefined } : {};
  const bad = validateConfig(role, { ...base, SHADE_TREE_PROVER_WORKERS: "0" });
  check(bad.errors.some((e) => e.var === "SHADE_TREE_PROVER_WORKERS" && /1\.\.64/.test(e.problem)), `${role}: 0 is a config error on the right var`);
  const junk = validateConfig(role, { ...base, SHADE_TREE_PROVER_WORKERS: "4abc" });
  check(junk.errors.some((e) => e.var === "SHADE_TREE_PROVER_WORKERS"), `${role}: 4abc is a config error`);
  const good = validateConfig(role, { ...base, SHADE_TREE_PROVER_WORKERS: "2" });
  check(!good.errors.some((e) => e.var === "SHADE_TREE_PROVER_WORKERS"), `${role}: 2 is accepted`);
  const unset = validateConfig(role, { ...base });
  check(!unset.errors.some((e) => e.var === "SHADE_TREE_PROVER_WORKERS"), `${role}: unset is accepted`);
}

// ---- withCpuCount: scoped override, always restored ---------------------------
function fakeOs(count) {
  const real = Array.from({ length: count }, (_, i) => ({ model: `cpu${i}`, speed: 1, times: { user: 0, nice: 0, sys: 0, idle: 0, irq: 0 } }));
  const o = { cpus() { return real.slice(); } };
  o.original = o.cpus;
  return o;
}
{
  const o = fakeOs(16);
  const seen = await withCpuCount(o, 3, async () => o.cpus().length);
  check(seen === 3, "inside: cpus().length is the override");
  check(o.cpus === o.original && o.cpus().length === 16, "after resolve: original restored");
  await assert.rejects(withCpuCount(o, 2, async () => { throw new Error("boom"); }), /boom/);
  check(o.cpus === o.original, "after reject: original restored");
  await assert.rejects(withCpuCount(o, 2, () => { throw new Error("sync"); }), /sync/);
  check(o.cpus === o.original, "after a synchronous throw: original restored");
  const o0 = fakeOs(0);
  const entries = await withCpuCount(o0, 3, async () => o0.cpus());
  check(entries.length === 3 && entries.every((c) => c && typeof c.model === "string"), "empty host list: still well-formed entries");
  const big = fakeOs(2);
  const models = await withCpuCount(big, 5, async () => big.cpus().map((c) => c.model));
  check(models.join(",") === "cpu0,cpu1,cpu0,cpu1,cpu0", "entries reuse real records cyclically");
}

// ---- makeCurveInit -----------------------------------------------------------
{
  const o = fakeOs(16);
  let engine = null, builds = 0, seenCount = null;
  const ensure = makeCurveInit({
    osModule: o, env: {}, cached: () => engine,
    buildCurve: async () => { builds++; seenCount = o.cpus().length; engine = { tm: { concurrency: seenCount } }; return engine; },
  });
  const r1 = await ensure();
  check(r1.built && r1.workers === 4 && seenCount === 4 && builds === 1, "default: builds once with 4 of 16 cpus visible");
  check(o.cpus === o.original, "os.cpus restored after the build");
  const r2 = await ensure();
  check(!r2.built && builds === 1, "second call: cached engine, no rebuild");
  engine = null; // what RLN.cleanUp() does (curve.terminate nulls globalThis.curve_bn128)
  const r3 = await ensure();
  check(r3.built && builds === 2 && seenCount === 4, "after cleanUp the rebuild is capped again");
}
{
  const o = fakeOs(16);
  const env = { SHADE_TREE_PROVER_WORKERS: "16" };
  let seen = null, engine = null;
  const ensure = makeCurveInit({ osModule: o, env, cached: () => engine, buildCurve: async () => { seen = o.cpus().length; engine = {}; } });
  await ensure();
  check(seen === 16, "explicit 16 restores the old one-per-cpu pool");
  env.SHADE_TREE_PROVER_WORKERS = "1"; engine = null;
  await ensure();
  check(seen === 1, "env is re-read on a rebuild");
}
for (const bad of ["0", "-2", "x", "1e3", "99999999999999999999"]) {
  const o = fakeOs(16);
  let builds = 0;
  const ensure = makeCurveInit({ osModule: o, env: { SHADE_TREE_PROVER_WORKERS: bad }, cached: () => null, buildCurve: async () => { builds++; } });
  await assert.rejects(ensure(), /SHADE_TREE_PROVER_WORKERS must be an integer 1\.\.64/);
  check(builds === 0 && o.cpus === o.original, `bad ${bad}: fails closed, nothing built, os.cpus untouched`);
}
{
  // A cached engine wins even over a bad value: the pool already exists, nothing would change.
  const o = fakeOs(16);
  const ensure = makeCurveInit({ osModule: o, env: { SHADE_TREE_PROVER_WORKERS: "bad" }, cached: () => ({}), buildCurve: async () => { throw new Error("must not build"); } });
  check((await ensure()).built === false, "cached engine: no parse, no build");
}

// ---- end to end against the real snarkjs that rlnjs loads ---------------------
// Build only the bn128 engine (no circuit, no proof) with 2 workers and read the pool size back.
{
  const requireHere = createRequire(import.meta.url);
  const requireFromRln = createRequire(requireHere.resolve("rlnjs"));
  const snarkjs = requireFromRln("snarkjs");
  const prev = globalThis.curve_bn128;
  check(!prev, "no engine before the e2e block");
  const ensure = makeCurveInit({ osModule: os, env: { SHADE_TREE_PROVER_WORKERS: "2" }, buildCurve: () => snarkjs.curves.getCurveFromName("bn128") });
  const before = os.cpus;
  const r = await ensure();
  const curve = globalThis.curve_bn128;
  check(r.built && curve && curve.tm.concurrency === 2 && curve.tm.workers.length === 2, "real engine has exactly 2 workers");
  check(os.cpus === before, "real os.cpus restored");
  const again = await snarkjs.curves.getCurveFromName("bn128");
  check(again === curve, "snarkjs reuses the capped engine (does not build its own)");
  await curve.terminate();
  check(!globalThis.curve_bn128, "terminate clears the cached engine");
}

console.log(`PASS: prover-workers ${n} checks`);
