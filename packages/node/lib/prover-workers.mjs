// Prover worker-pool size for snarkjs (SHADE_TREE_PROVER_WORKERS).
//
// snarkjs does its Groth16 curve math (prove AND verify) on ffjavascript's bn128 engine. The
// first time that engine is built in a process, ffjavascript starts ONE worker thread per
// `os.cpus()` entry (capped at 64), and each worker holds its own wasm memory. The engine is then
// cached on `globalThis.curve_bn128` and reused for the life of the process. ffjavascript and
// snarkjs expose no knob for the count: only `singleThread`, which this code does not use.
//
// Measured once, on a 16-vCPU x86 box, for an isolated prover process (11 RLN proofs, then 10
// verifies): median peak RSS about 1.4 GiB with 16 workers and about 0.5 GiB with 4, with the
// median warm proof about 1.7x slower at 4 (see the PR that added this file for the numbers and
// method). Other CPU counts and a verify-only process were not measured. The default here is
// min(cpus, 4), and an operator can raise it (up to 64) or lower it (down to 1).
//
// How the cap works: before the first snarkjs call in this process, under the caller's snarkjs
// mutex, build the bn128 engine ourselves through the SAME snarkjs/ffjavascript instance that
// rlnjs uses, with `os.cpus()` temporarily replaced by a list of the chosen length. ffjavascript
// only reads `.length`. The original `os.cpus` is restored in a `finally`. The override is
// process-global for the whole asynchronous engine build: any code in the process that calls
// `os.cpus()` during that interval sees the replaced list. The caller's mutex (the one in
// rln.mjs) serializes only snarkjs calls made through that rln.mjs instance; it does not cover
// other code that calls snarkjs directly or unrelated `os.cpus()` readers. While the engine stays
// cached, later snarkjs calls reuse it and do not read `os.cpus()` again.
//
// A bad value fails closed: `ensureCurve()` throws with the variable name and the reason, so the
// prove or verify that needed the engine fails with a precise message instead of silently running
// an unbounded pool. `shade-tree` validates the variable at startup (packages/node/lib/config.mjs)
// so in practice a bad value stops the service before it starts.

export const PROVER_WORKERS_VAR = "SHADE_TREE_PROVER_WORKERS";
export const DEFAULT_MAX_PROVER_WORKERS = 4;
// ffjavascript itself never starts more than 64 workers; a larger value would be a silent no-op.
export const MAX_PROVER_WORKERS = 64;

// defaultProverWorkers(cpuCount) -> min(cpuCount, 4). ffjavascript falls back to 2 when
// os.cpus() is empty (some sandboxes); keep that fallback so an empty list never means 0.
export function defaultProverWorkers(cpuCount) {
  const n = Number.isInteger(cpuCount) && cpuCount > 0 ? cpuCount : 2;
  return Math.min(n, DEFAULT_MAX_PROVER_WORKERS);
}

// parseProverWorkers(raw, cpuCount) -> { ok:true, workers, source:"default"|"env" }
//                                    | { ok:false, reason }
// TOTAL: any input yields a result, never a throw. The input type is checked with `typeof` only;
// nothing is coerced with String(), toString or valueOf, so objects, arrays, symbols, proxies
// and values with a throwing toString are rejected, not converted.
// Accepted types: undefined / null (= unset, the default); a string (the environment case);
// a number that is an integer (treated as its decimal string). Everything else is ok:false.
// A string that is empty after trim = the default. Otherwise only a plain decimal integer 1..64
// is accepted: no sign, no exponent, no hex, no fraction, no trailing junk. `Number("1e3")`,
// `Number("0x10")` and `parseInt("4abc")` all "work" in JS, which is exactly why this does not
// use them.
const BAD_WORKERS = `${PROVER_WORKERS_VAR} must be an integer 1..${MAX_PROVER_WORKERS}`;
export function parseProverWorkers(raw, cpuCount) {
  if (raw === undefined || raw === null) return { ok: true, workers: defaultProverWorkers(cpuCount), source: "default" };
  let s;
  if (typeof raw === "string") s = raw.trim();
  else if (typeof raw === "number" && Number.isInteger(raw)) s = raw.toFixed(0);
  else return { ok: false, reason: BAD_WORKERS };
  if (s === "") return { ok: true, workers: defaultProverWorkers(cpuCount), source: "default" };
  if (!/^\d{1,3}$/.test(s)) return { ok: false, reason: BAD_WORKERS };
  const n = Number(s);
  if (n < 1 || n > MAX_PROVER_WORKERS) return { ok: false, reason: BAD_WORKERS };
  return { ok: true, workers: n, source: "env" };
}

// isProverWorkers(v): the config.mjs shape check. True only for an explicit value that
// parseProverWorkers accepts (unset or empty is handled by config.mjs as "optional, absent").
// Total like the parser: never throws, never coerces.
export function isProverWorkers(v) {
  const r = parseProverWorkers(v, 1);
  return r.ok === true && r.source === "env";
}

// withCpuCount(osModule, n, fn): run async fn with osModule.cpus() returning a list of length n,
// then restore the original function whatever fn does (resolve, reject, or throw synchronously).
// Entries reuse the real cpu records cyclically so a caller that reads more than .length still
// sees well-formed objects.
export async function withCpuCount(osModule, n, fn) {
  const original = osModule.cpus;
  const real = original.call(osModule);
  const fake = Array.from({ length: n }, (_, i) => (real.length ? real[i % real.length] : { model: "unknown", speed: 0, times: { user: 0, nice: 0, sys: 0, idle: 0, irq: 0 } }));
  osModule.cpus = () => fake.slice();
  try {
    return await fn();
  } finally {
    osModule.cpus = original;
  }
}

// makeCurveInit({ buildCurve, osModule, env, cached }) -> async ensureCurve() -> { built, workers }
//   buildCurve: () => Promise<curve>   builds (and caches) the bn128 engine, e.g. snarkjs
//               curves.getCurveFromName("bn128") from the snarkjs instance rlnjs loads.
//   cached:     () => truthy when an engine already exists (default: globalThis.curve_bn128).
// The env var is read on each call that has to build (so a test can change it, and so a
// `cleanUp()` that terminated the engine gets a capped engine again on the next proof, not an
// uncapped one built by snarkjs itself). The caller must hold its snarkjs mutex.
export function makeCurveInit({ buildCurve, osModule, env = process.env, cached = () => globalThis.curve_bn128 }) {
  return async function ensureCurve() {
    if (cached()) return { built: false, workers: null };
    const parsed = parseProverWorkers(env[PROVER_WORKERS_VAR], osModule.cpus().length);
    if (!parsed.ok) throw new Error(parsed.reason);
    await withCpuCount(osModule, parsed.workers, buildCurve);
    return { built: true, workers: parsed.workers };
  };
}
