// Timing / side-channel sanity check for the RLN VERIFY path in packages/node/lib/rln.mjs.
// Run: `node test/timing.selftest.mjs`
//
// THREAT: the gateway verifies a member's proof on every request. If verifyEnvelope's
// latency depended on WHICH member produced the proof, a gateway (or a network observer
// timing the gateway) could fingerprint members by how long their proofs take to verify —
// an anonymity break. Groth16 verification is data-oblivious w.r.t. the witness (same
// circuit, same public-input arity, a fixed pairing check), so verify time SHOULD be
// independent of the prover's identity. This test asserts that empirically.
//
// No chain, no network: builds an in-memory RLN group of several distinct members, makes
// ONE real Groth16 proof per member for a FIXED (target, nonce) so every envelope is valid
// and differs only in which member proved, then times verifyEnvelope many times per member.
//
// Same house style as packages/node/lib/rln.selftest.mjs (ok/failures counter, PASS/FAIL summary,
// cleanUp() so the snarkjs worker threads exit).
//
// COST NOTE: proof GENERATION is ~0.4s and is serialized behind rln.mjs's snark mutex, so we
// generate exactly ONE proof per member. VERIFY is ~30ms, so timing VERIFY_ITERS per member
// is cheap. Total wall is dominated by the N_MEMBERS generations (~2-3s), not the timing.
//
// TOLERANCE (and why it is loose): wall-clock latency on a shared CI box is noisy — GC,
// scheduler preemption, the snark worker's own thread hops, and turbo/thermal drift all add
// jitter that dwarfs any real per-member difference. This is a SANITY CHECK, not a rigorous
// constant-time proof: it can only catch GROSS member-dependence (e.g. one member verifying
// 2x+ slower), not a fine sub-millisecond leak. We therefore gate on the ROBUST statistic —
// the per-member MEDIAN (immune to occasional outlier verifies) — and require no member's
// median to exceed MAX_RATIO x the overall median. MAX_RATIO = 2.0 is loose enough to never
// flake on shared hardware yet tight enough that a witness-dependent verify (which would push
// one member's whole distribution up) trips it. Since Groth16 verify is oblivious by design,
// the observed spread is pure noise and medians land within a few percent of each other.

import {
  currentEpoch,
  requestSignal,
  proveForSlot,
  verifyEnvelope,
  identityFor,
  groupFromIdentities,
  toField,
  cleanUp,
} from "../packages/node/lib/rln.mjs";

let pass = 0;
let failures = 0;
function ok(cond, msg) {
  if (cond) { pass++; console.log("  ok  " + msg); }
  else { failures++; console.log("FAIL  " + msg); }
}

const N_MEMBERS = 5;      // distinct identities in the group (4-6 is plenty to see spread)
const VERIFY_ITERS = 20;  // timed verifies per member
const MAX_RATIO = 2.0;    // no member's median verify may exceed this x the overall median

const ms = (ns) => Number(ns) / 1e6; // hrtime.bigint() is nanoseconds
function median(xs) {
  const a = [...xs].sort((p, q) => p - q);
  const n = a.length;
  if (!n) return NaN;
  return n % 2 ? a[(n - 1) / 2] : (a[n / 2 - 1] + a[n / 2]) / 2;
}
const r2 = (x) => Math.round(x * 100) / 100;

async function main() {
  const epoch = currentEpoch();

  // Distinct field-element secrets, one per member. Fixed hex so the run is deterministic.
  const secrets = Array.from({ length: N_MEMBERS }, (_, i) =>
    toField("0x" + String(i + 1).repeat(2).padStart(2, "0").repeat(32).slice(0, 64))
  );
  const identities = secrets.map((s) => identityFor(s));
  const group = groupFromIdentities(identities);

  // A single FIXED request every member proves against, so envelopes differ ONLY by member.
  const target = "example.com:443";
  const nonce = "timing-fixed-nonce";
  const signal = requestSignal(target, nonce);
  const slot = 3;
  const recentRoots = new Set([group.root.toString()]);

  // One real proof per member -> one valid envelope per member.
  const envelopes = [];
  for (let i = 0; i < N_MEMBERS; i++) {
    const p = await proveForSlot(secrets[i], epoch, slot, signal, { group });
    envelopes.push({
      v: 4,
      target,
      nonce,
      proof: p.proof,
      nullifier: p.nullifier,
      externalNullifier: p.externalNullifier,
      share: p.share,
      artifact: p.artifact, // T-HARD-8: name the set, as every real client does
    });
  }

  // Sanity: every envelope must verify, else the timing below is meaningless.
  let allAccept = true;
  for (let i = 0; i < N_MEMBERS; i++) {
    const res = await verifyEnvelope(envelopes[i], recentRoots);
    if (res.ok !== true) { allAccept = false; console.log(`    member ${i} did not verify: ${res.reason}`); }
  }
  ok(allAccept, `all ${N_MEMBERS} member envelopes verify (timing precondition)`);

  // Warm up: prime the verifier (artifact load, JIT) OUTSIDE the timed region so the first
  // member is not penalized for a cold start it did not cause.
  for (let w = 0; w < 3; w++) await verifyEnvelope(envelopes[0], recentRoots);

  // Time VERIFY_ITERS verifies per member. Interleave members round-robin so any slow drift
  // (thermal, background load) is shared across members rather than charged to whoever went last.
  const times = Array.from({ length: N_MEMBERS }, () => []);
  for (let iter = 0; iter < VERIFY_ITERS; iter++) {
    for (let i = 0; i < N_MEMBERS; i++) {
      const t0 = process.hrtime.bigint();
      const res = await verifyEnvelope(envelopes[i], recentRoots);
      const t1 = process.hrtime.bigint();
      if (res.ok !== true) { failures++; console.log(`FAIL  member ${i} verify returned ${res.reason} mid-timing`); }
      times[i].push(ms(t1 - t0));
    }
  }

  const medians = times.map(median);
  const overall = median(medians);

  console.log("\n  per-member VERIFY median (ms), over " + VERIFY_ITERS + " iters each:");
  medians.forEach((m, i) => {
    const ratio = m / overall;
    console.log(`    member ${i}:  median ${r2(m)}  (ratio x${r2(ratio)})`);
  });
  console.log(`    overall median ${r2(overall)} ms;  spread ${r2(Math.min(...medians))}–${r2(Math.max(...medians))} ms`);

  // The gate: no member's median may be more than MAX_RATIO x the overall median. A
  // witness-dependent verify would lift one member's entire distribution, blowing this ratio.
  const worst = Math.max(...medians.map((m) => m / overall));
  ok(
    worst <= MAX_RATIO,
    `no member's median verify exceeds ${MAX_RATIO}x overall (worst x${r2(worst)}) — verify is member-independent`
  );

  console.log(`\n${failures ? "FAIL" : "PASS"} — ${pass} passed, ${failures} failed`);
  cleanUp();
  if (failures) { process.exit(1); }
  process.exit(0);
}

main().catch((e) => {
  console.error("SELFTEST THREW:", e);
  cleanUp();
  process.exit(1);
});
