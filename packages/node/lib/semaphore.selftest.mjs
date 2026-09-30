// T-TEST-3: unit test for the epoch + request-signal primitives (defined in packages/node/lib/rln.mjs,
// re-exported through packages/node/lib/semaphore.mjs, which is the public surface callers use). These are
// small pure functions but load-bearing:
//   - currentEpoch pins the nullifier scope; if it were non-monotonic or off-by-one, proofs would
//     DROP at epoch boundaries or a stale proof would verify.
//   - requestSignal MUST be deterministic in (target, nonce): the deterministic-retry invariant
//     reuses the same signal across gateway failover, so a nondeterministic signal would produce a
//     second distinct share on one nullifier and get an HONEST client wrongly slashed.
//
//   node packages/node/lib/semaphore.selftest.mjs

import { EPOCH_SECONDS, currentEpoch, K_SLOTS, requestSignal, MESSAGE } from "./semaphore.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

function main() {
  console.log("constants:");
  ok(Number.isFinite(EPOCH_SECONDS) && EPOCH_SECONDS > 0, `EPOCH_SECONDS is a positive number (${EPOCH_SECONDS})`);
  ok(Number.isInteger(K_SLOTS) && K_SLOTS > 0, `K_SLOTS is a positive integer (${K_SLOTS})`);
  ok(typeof MESSAGE === "bigint", "MESSAGE (v1 constant) is a bigint");

  console.log("\ncurrentEpoch:");
  const E = EPOCH_SECONDS * 1000; // one epoch in ms
  ok(typeof currentEpoch(0) === "bigint", "currentEpoch returns a bigint");
  ok(currentEpoch(0) === 0n, "epoch 0 at t=0");
  ok(currentEpoch(E - 1) === 0n, "still epoch 0 one ms before the boundary");
  ok(currentEpoch(E) === 1n, "epoch increments exactly at the boundary");
  ok(currentEpoch(E * 5 + 37) === 5n, "epoch = floor(t / EPOCH_SECONDS)");
  ok(currentEpoch(E) === currentEpoch(0) + 1n, "consecutive epochs differ by exactly 1");

  // monotonic non-decreasing across increasing time (never goes backwards)
  let mono = true, prev = -1n;
  for (let ms = 0; ms <= E * 10; ms += E / 7) { const e = currentEpoch(ms); if (e < prev) mono = false; prev = e; }
  ok(mono, "currentEpoch is monotonic non-decreasing in time");

  ok(typeof currentEpoch() === "bigint" && currentEpoch() >= 0n, "default arg (Date.now) yields a valid epoch");

  console.log("\nrequestSignal (deterministic-retry invariant):");
  const s1 = requestSignal("api.ipify.org:443", "deadbeef");
  ok(s1 === requestSignal("api.ipify.org:443", "deadbeef"), "same (target,nonce) => IDENTICAL signal (deterministic-retry)");
  ok(requestSignal("a.com:443", "n1") !== requestSignal("b.com:443", "n1"), "different target => different signal");
  ok(requestSignal("a.com:443", "n1") !== requestSignal("a.com:443", "n2"), "different nonce => different signal");
  ok(typeof s1 === "string" && s1.startsWith("shade-tree:v4\n"), "signal is a versioned string");
  // both fields are inside the signal, so neither can be swapped without changing it
  ok(requestSignal("x", "y") !== requestSignal("y", "x"), "target/nonce are not interchangeable (no field-swap collision)");
  // coerces non-strings deterministically (defensive)
  ok(requestSignal(443, 1) === requestSignal("443", "1"), "non-string args coerced deterministically");

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: semaphore selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
