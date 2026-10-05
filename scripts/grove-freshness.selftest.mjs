import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  assessGroveFreshness,
  readSnapshotTime,
  DEFAULT_FAIL_MINUTES,
  DEFAULT_WARN_MINUTES,
} from "./grove-freshness.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const NOW = Date.parse("2026-10-05T07:30:00.000Z");
const snap = (version, observedAt, extra = {}) => JSON.stringify({
  schema: version === "v1" ? "shade-tree-public-grove-v1" : "shade-tree-public-grove-v2",
  network: "sepolia",
  observedAt,
  nodes: { announced: 3 },
  ...extra,
});
const at = (minutesAgo) => new Date(NOW - minutesAgo * 60_000).toISOString();
const both = (minutesAgo) => ({ v1: snap("v1", at(minutesAgo)), v2: snap("v2", at(minutesAgo)) });

assert.equal(DEFAULT_WARN_MINUTES, 45, "warning after three missed 15-minute cadences");
assert.equal(DEFAULT_FAIL_MINUTES, 120, "failure after eight missed cadences");

// A snapshot published in this run is at most one cadence old.
assert.deepEqual(readSnapshotTime(snap("v1", at(15)), { version: "v1", now: NOW }), { ok: true, observedAt: at(15), ageMinutes: 15 });
assert.equal(assessGroveFreshness({ snapshots: both(15), now: NOW }).level, "ok");
assert.equal(assessGroveFreshness({ snapshots: both(44), now: NOW }).level, "ok");

// Past the warning age the run stays green but carries an annotation.
const warned = assessGroveFreshness({ snapshots: both(45), now: NOW });
assert.equal(warned.level, "warning");
assert.match(warned.message, /45 minutes ago/);
assert.match(warned.message, /not publishing/);
assert.equal(assessGroveFreshness({ snapshots: both(119), now: NOW }).level, "warning");

// Past the failing age a green probe fails this dedicated check.
const failed = assessGroveFreshness({ snapshots: both(120), now: NOW });
assert.equal(failed.level, "error");
assert.equal(failed.ageMinutes, 120);

// The incident of 2026-09-29: selector left on the staging record, snapshot six days old.
const incident = assessGroveFreshness({
  snapshots: { v1: snap("v1", "2026-09-29T00:45:00.000Z"), v2: snap("v2", "2026-09-29T00:45:00.000Z") },
  now: NOW,
  networkSelector: "sepolia-staging",
});
assert.equal(incident.level, "error");
assert.match(incident.message, /observed at 2026-09-29T00:45:00\.000Z, 6 days ago/);
assert.match(incident.message, /SHADE_TREE_NETWORK=sepolia; it is "sepolia-staging"/);
assert.equal(/SHADE_TREE_NETWORK/.test(failed.message), false, "no selector hint when the selector is already sepolia");
assert.match(assessGroveFreshness({ snapshots: both(60), now: NOW, networkSelector: "" }).message, /unset or not a network name/);
assert.equal(/\$\(|`/.test(assessGroveFreshness({ snapshots: both(60), now: NOW, networkSelector: "$(id)`x`" }).message), false, "a hostile selector is not echoed");

// A probe that already failed keeps the run red for its own reason; this check only warns.
assert.equal(assessGroveFreshness({ snapshots: both(600), now: NOW, probeResult: "failure" }).level, "warning");
assert.equal(assessGroveFreshness({ snapshots: both(600), now: NOW, probeResult: "cancelled" }).level, "warning");
// --fail-minutes 0 turns the failure off; the warning stays.
assert.equal(assessGroveFreshness({ snapshots: both(600), now: NOW, failMinutes: 0 }).level, "warning");
assert.equal(assessGroveFreshness({ snapshots: both(600), now: NOW, failMinutes: "" }).level, "error", "an empty threshold is unset, not zero");
// Out-of-range thresholds fall back to the defaults rather than disabling the check.
assert.equal(assessGroveFreshness({ snapshots: both(600), now: NOW, warnMinutes: "nope", failMinutes: -5 }).level, "error");

// The verdict follows the older head: a fresh v1 does not hide a stale v2.
const split = assessGroveFreshness({ snapshots: { v1: snap("v1", at(15)), v2: snap("v2", at(300)) }, now: NOW });
assert.equal(split.level, "error");
assert.equal(split.ageMinutes, 300);

// An unreadable snapshot is a warning, never a failure, and says why.
for (const [name, snapshots, reason] of [
  ["missing v2", { v1: snap("v1", at(15)), v2: "" }, /v2: missing/],
  ["not JSON", { v1: "<html>", v2: snap("v2", at(15)) }, /v1: not-json/],
  ["wrong schema", { v1: snap("v2", at(15)), v2: snap("v2", at(15)) }, /v1: wrong-schema/],
  ["wrong network", { v1: snap("v1", at(15), { network: "sepolia-staging" }), v2: snap("v2", at(15)) }, /v1: wrong-network/],
  ["bad time", { v1: snap("v1", "yesterday"), v2: snap("v2", at(15)) }, /v1: bad-observed-at/],
  ["future time", { v1: snap("v1", at(-30)), v2: snap("v2", at(15)) }, /v1: observed-in-future/],
  ["nothing published", {}, /v1: missing, v2: missing/],
]) {
  const verdict = assessGroveFreshness({ snapshots, now: NOW });
  assert.equal(verdict.level, "warning", name);
  assert.match(verdict.message, reason, name);
  assert.equal(verdict.ageMinutes, null, name);
}
assert.equal(readSnapshotTime(snap("v1", at(-4)), { version: "v1", now: NOW }).ageMinutes, 0, "small clock skew reads as age 0");

// No count, onion or signer can reach the output: the message is built from timestamps only.
for (const verdict of [warned, failed, incident, split]) {
  assert.equal(/announced|onion|[0-9a-f]{64}/.test(verdict.message), false);
}

// CLI: annotation text and exit codes are what the workflow relies on.
const dir = mkdtempSync(join(tmpdir(), "grove-freshness-"));
try {
  const write = (name, text) => { const path = join(dir, name); writeFileSync(path, text); return path; };
  const cli = (args, env = {}) => spawnSync(process.execPath, [join(HERE, "grove-freshness.mjs"), ...args], {
    encoding: "utf8",
    env: { PATH: process.env.PATH, ...env },
  });
  const nowIso = (minutesAgo) => new Date(Date.now() - minutesAgo * 60_000).toISOString();
  const fresh = [write("f1.json", snap("v1", nowIso(10))), write("f2.json", snap("v2", nowIso(10)))];
  const old = [write("o1.json", snap("v1", nowIso(90))), write("o2.json", snap("v2", nowIso(90)))];
  const ancient = [write("a1.json", snap("v1", nowIso(9000))), write("a2.json", snap("v2", nowIso(9000)))];

  let run = cli(["--v1", fresh[0], "--v2", fresh[1], "--network-selector", "sepolia"]);
  assert.equal(run.status, 0);
  assert.match(run.stdout, /^OK: /);

  run = cli(["--v1", old[0], "--v2", old[1], "--network-selector", "sepolia"]);
  assert.equal(run.status, 0);
  assert.match(run.stdout, /^::warning title=public Grove snapshot stale::/);

  const summary = join(dir, "summary.md");
  run = cli(["--v1", ancient[0], "--v2", ancient[1]], { SHADE_TREE_NETWORK: "sepolia-staging", GITHUB_STEP_SUMMARY: summary });
  assert.equal(run.status, 1);
  assert.match(run.stdout, /^::error title=public Grove snapshot stale::.*6 days ago.*"sepolia-staging"/);
  assert.match(spawnSync("cat", [summary], { encoding: "utf8" }).stdout, /public Grove snapshot stale: /);

  run = cli(["--v1", ancient[0], "--v2", ancient[1], "--probe-result", "failure", "--network-selector", "sepolia"]);
  assert.equal(run.status, 0, "a failed probe is not failed a second time");
  run = cli(["--v1", ancient[0], "--v2", ancient[1], "--network-selector", "sepolia"], { GROVE_STALE_FAIL_MINUTES: "0" });
  assert.equal(run.status, 0, "GROVE_STALE_FAIL_MINUTES=0 keeps the check warning-only");
  run = cli(["--v1", join(dir, "absent.json"), "--v2", fresh[1], "--network-selector", "sepolia"]);
  assert.equal(run.status, 0);
  assert.match(run.stdout, /^::warning title=public Grove snapshot unreadable::.*v1: missing/);
} finally {
  rmSync(dir, { recursive: true, force: true });
}

console.log("PASS: public grove freshness selftest");
