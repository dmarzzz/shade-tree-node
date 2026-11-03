// Selftest for bench/rln/prove-verify.mjs (the RLN v4 timing benchmark, refs #63).
//
//   node bench/rln/prove-verify.selftest.mjs
//
// Checks the statistics and the markdown table on fixed inputs, then runs the real CLI once
// with tiny counts: it must produce a well-formed result whose every proof verified (the
// script throws if verifyEnvelope rejects one of its own envelopes), stamped with the commit,
// artifact id and host. Timings are not asserted beyond being positive: CI hardware varies,
// and test/timing.selftest.mjs already owns the "verify is member-independent" property.
// Listed in scripts/test-all.mjs SLOW_SUITES because it makes real Groth16 proofs.

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { stats, markdownRows } from "./prove-verify.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const run = (args) => new Promise((resolve) => {
  const c = spawn(process.execPath, [join(HERE, "prove-verify.mjs"), ...args]);
  let stdout = ""; let stderr = "";
  c.stdout.on("data", (d) => { stdout += d; });
  c.stderr.on("data", (d) => { stderr += d; });
  c.on("close", (status) => resolve({ status, stdout, stderr }));
});

assert.deepEqual(stats([]), { n: 0 });
assert.deepEqual(stats([3, 1, 2, NaN]), { n: 3, min: 1, p50: 2, p95: 3, max: 3, mean: 2 });
assert.equal(stats(Array.from({ length: 100 }, (_, i) => i + 1)).p95, 95);
console.log("  ok   stats: nearest-rank percentiles, NaN dropped");

const md = markdownRows([{ label: "box", host: { cpus: 2, cpu: "cpu", memGb: 4 }, prove: { coldMs: 900.4, warm: { n: 5, p50: 400, p95: 450 } },
  verify: { coldMs: 30, warm: { n: 50, p50: 12, p95: 14 } }, git: { commit: "0123456789abcdef", dirty: false }, artifact: "rln-ae43614cd02ebe95" }, {}]);
assert.match(md, /\| box \| 2 x cpu, 4 GB \| 900 ms \| 400 ms \| 450 ms \| 30 ms \| 12 ms \| 14 ms \| 5 \/ 50 \| 0123456789ab \| rln-ae43614cd02e \|/);
assert.match(md.split("\n")[3], /\| - \| - \|/, "a result with missing fields renders dashes, not a crash");
console.log("  ok   markdownRows: one row per result, tolerant of missing fields");

const bad = await run(["--prove", "0"]);
assert.equal(bad.status, 2);
assert.match(bad.stderr, /--prove/);
console.log("  ok   bad counts are refused");

const dir = mkdtempSync(join(tmpdir(), "rln-bench-"));
try {
  const out = join(dir, "r.json");
  const r = await run(["--label", "selftest", "--members", "2", "--prove", "2", "--verify", "3", "--out", out]);
  assert.equal(r.status, 0, r.stderr);
  const j = JSON.parse(readFileSync(out, "utf8"));
  assert.equal(j.bench, "rln/prove-verify");
  assert.equal(j.prove.warm.n, 2);
  assert.equal(j.verify.warm.n, 3);
  assert.ok(j.prove.coldMs > 0 && j.prove.warm.p50 > 0 && j.verify.coldMs > 0 && j.verify.warm.p50 > 0);
  assert.match(j.artifact, /^rln-[0-9a-f]+$/);
  assert.ok(j.git && "commit" in j.git);
  assert.equal(j.kSlots > 0, true);
  assert.match(j.command, /--prove 2/);
  const m = await run(["--markdown", out]);
  assert.equal(m.status, 0, m.stderr);
  assert.match(m.stdout, /\| selftest \|/);
  console.log("  ok   real run: proofs made and verified, result stamped, markdown renders");
} finally { rmSync(dir, { recursive: true, force: true }); }

console.log("PASS prove-verify");
