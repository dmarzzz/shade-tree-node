// Is the published public Grove snapshot still being refreshed?
//
// The hosted uptime probe (.github/workflows/uptime-probe.yml) can be green while the publisher
// is skipped: a wrong SHADE_TREE_NETWORK selector, a probe that keeps ending UNKNOWN, or a
// publisher that never starts all leave the `network-state` branch untouched. This check reads
// the two published snapshots and reports their age, so a probe that stopped publishing is
// visible in the run instead of only on the public page.
//
//   node scripts/grove-freshness.mjs --v1 grove.json --v2 grove-v2.json
//     [--warn-minutes 45] [--fail-minutes 120] [--probe-result success] [--network-selector sepolia]
//
// Exit 0 with a ::warning:: annotation once the oldest snapshot is past the warning age; exit 1
// with an ::error:: once it is past the failing age. A probe job that already failed keeps the
// run red for its own reason, so this check only warns then. `--fail-minutes 0` never fails.
// A snapshot that cannot be read is a warning, never a failure: a transient fetch error must not
// turn the run red.
//
// No dependencies and no secrets: it needs neither `npm ci` nor the signing key. Signatures are
// checked by the Data API and the verify-public job; this check is about time only. Output holds
// timestamps and ages, never a count, an onion or a signer.

import { readFileSync, appendFileSync } from "node:fs";

export const GROVE_CADENCE_MINUTES = 15;
export const DEFAULT_WARN_MINUTES = 3 * GROVE_CADENCE_MINUTES;
export const DEFAULT_FAIL_MINUTES = 8 * GROVE_CADENCE_MINUTES;
export const GROVE_PUBLISH_NETWORK = "sepolia";
const SCHEMAS = { v1: "shade-tree-public-grove-v1", v2: "shade-tree-public-grove-v2" };
const FUTURE_SKEW_MS = 5 * 60_000;

function isoMillis(value) {
  if (typeof value !== "string") return NaN;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value ? parsed : NaN;
}

// readSnapshotTime(text, { version, now }) -> { ok: true, observedAt, ageMinutes } | { ok: false, reason }
export function readSnapshotTime(text, { version, now = Date.now() } = {}) {
  if (typeof text !== "string" || text.trim() === "") return { ok: false, reason: "missing" };
  let value;
  try { value = JSON.parse(text); } catch { return { ok: false, reason: "not-json" }; }
  if (value?.schema !== SCHEMAS[version]) return { ok: false, reason: "wrong-schema" };
  if (value?.network !== GROVE_PUBLISH_NETWORK) return { ok: false, reason: "wrong-network" };
  const observedMs = isoMillis(value?.observedAt);
  if (!Number.isFinite(observedMs)) return { ok: false, reason: "bad-observed-at" };
  if (observedMs > now + FUTURE_SKEW_MS) return { ok: false, reason: "observed-in-future" };
  return { ok: true, observedAt: value.observedAt, ageMinutes: Math.max(0, Math.floor((now - observedMs) / 60_000)) };
}

function minutes(value, fallback) {
  // An empty string is "not set" (an unset workflow variable arrives that way), not zero.
  if (value === undefined || value === null || String(value).trim() === "") return fallback;
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 && parsed <= 7 * 24 * 60 ? Math.floor(parsed) : fallback;
}

function ageText(ageMinutes) {
  if (ageMinutes < 120) return `${ageMinutes} minutes`;
  if (ageMinutes < 48 * 60) return `${Math.floor(ageMinutes / 60)} hours`;
  return `${Math.floor(ageMinutes / (24 * 60))} days`;
}

// assessGroveFreshness -> { level: "ok" | "warning" | "error", title, message, ageMinutes }
// `snapshots` is { v1: text, v2: text }. The verdict follows the OLDER of the two, because the
// page needs both heads. `probeResult` is the probe job's result in the same run.
export function assessGroveFreshness({
  snapshots = {},
  now = Date.now(),
  warnMinutes = DEFAULT_WARN_MINUTES,
  failMinutes = DEFAULT_FAIL_MINUTES,
  probeResult = "success",
  networkSelector = GROVE_PUBLISH_NETWORK,
} = {}) {
  const warnAt = minutes(warnMinutes, DEFAULT_WARN_MINUTES);
  const failAt = minutes(failMinutes, DEFAULT_FAIL_MINUTES);
  const selector = String(networkSelector || "").toLowerCase();
  const hint = selector === GROVE_PUBLISH_NETWORK
    ? ""
    : ` Publishing needs the repository variable SHADE_TREE_NETWORK=${GROVE_PUBLISH_NETWORK}; it is ${/^[a-z0-9-]{1,32}$/.test(selector) ? `"${selector}"` : "unset or not a network name"}.`;

  const read = Object.fromEntries(["v1", "v2"].map((version) => [version, readSnapshotTime(snapshots[version], { version, now })]));
  const unreadable = Object.entries(read).filter(([, r]) => !r.ok);
  if (unreadable.length > 0) {
    return {
      level: "warning",
      title: "public Grove snapshot unreadable",
      message: `Could not read a published snapshot from the network-state branch (${unreadable.map(([version, r]) => `${version}: ${r.reason}`).join(", ")}); its age was not measured this run.${hint}`,
      ageMinutes: null,
    };
  }

  const oldest = read.v1.ageMinutes >= read.v2.ageMinutes ? read.v1 : read.v2;
  const base = `The newest published public Grove snapshot was observed at ${oldest.observedAt}, ${ageText(oldest.ageMinutes)} ago (cadence ${GROVE_CADENCE_MINUTES} minutes).`;
  if (oldest.ageMinutes < warnAt) {
    return { level: "ok", title: "public Grove snapshot fresh", message: base, ageMinutes: oldest.ageMinutes };
  }
  const stale = `${base} The probe is not publishing: the public page and the Data API are serving old data.${hint}`;
  const failing = failAt > 0 && oldest.ageMinutes >= failAt && probeResult === "success";
  return {
    level: failing ? "error" : "warning",
    title: "public Grove snapshot stale",
    message: stale,
    ageMinutes: oldest.ageMinutes,
  };
}

function option(argv, name, fallback = null) {
  const exact = argv.indexOf(name);
  if (exact !== -1) return argv[exact + 1] ?? fallback;
  const inline = argv.find((arg) => arg.startsWith(name + "="));
  return inline ? inline.slice(name.length + 1) : fallback;
}

function readText(path) {
  if (!path) return "";
  try { return readFileSync(path, "utf8"); } catch { return ""; }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const argv = process.argv.slice(2);
  const verdict = assessGroveFreshness({
    snapshots: { v1: readText(option(argv, "--v1")), v2: readText(option(argv, "--v2")) },
    warnMinutes: option(argv, "--warn-minutes", process.env.GROVE_STALE_WARN_MINUTES ?? undefined) ?? undefined,
    failMinutes: option(argv, "--fail-minutes", process.env.GROVE_STALE_FAIL_MINUTES ?? undefined) ?? undefined,
    probeResult: option(argv, "--probe-result", "success"),
    networkSelector: option(argv, "--network-selector", process.env.SHADE_TREE_NETWORK || ""),
  });
  const line = verdict.level === "ok"
    ? `OK: ${verdict.message}`
    : `::${verdict.level} title=${verdict.title}::${verdict.message}`;
  console.log(line);
  if (process.env.GITHUB_STEP_SUMMARY) {
    try { appendFileSync(process.env.GITHUB_STEP_SUMMARY, `${verdict.title}: ${verdict.message}\n`); } catch { /* summary is best effort */ }
  }
  process.exit(verdict.level === "error" ? 1 : 0);
}
