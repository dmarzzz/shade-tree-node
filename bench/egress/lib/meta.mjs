// Reproducibility stamp for one benchmark run: the first JSONL row, `{"type":"meta", ...}`.
//
// A blocking number is only meaningful with its context: which exit (and which ASN it resolved
// to that night), which client versions, which commit of the harness and sites file, when. The
// stamp records all of it so a report can say where every number came from, and so two runs can
// be compared honestly (a Chromium bump changes fingerprints; an exit IP change changes
// reputation).
//
// Privacy: the exit lookup asks a public "what is my IP" service THROUGH the exit, so it learns
// the exit IP, which it sees anyway on every request. The stamp stores the IP so the operator can
// audit a run, and the report hides it unless --show-ips is passed: a published report should
// name an exit by ASN and country, not by address.

import { execFileSync } from "node:child_process";
import { isIP } from "node:net";
import os from "node:os";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describeExit } from "./exits.mjs";
import { fetchVia } from "./net.mjs";

export const HARNESS_VERSION = 2;

function safe(fn, dflt = null) { try { return fn(); } catch { return dflt; } }

export function gitInfo(cwd) {
  const commit = safe(() => execFileSync("git", ["rev-parse", "HEAD"], { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim());
  const dirty = safe(() => execFileSync("git", ["status", "--porcelain", "--", "bench"], { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim().length > 0);
  return { commit, dirty };
}

export function curlVersion(bin = "curl") {
  return safe(() => execFileSync(bin, ["--version"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).split("\n")[0].trim().slice(0, 160));
}

export function sha256File(path) {
  return safe(() => createHash("sha256").update(readFileSync(path)).digest("hex"));
}

export function hostClass() {
  const cpus = os.cpus() || [];
  return { os: `${os.platform()} ${os.release()}`, arch: os.arch(), cpu: cpus[0] ? cpus[0].model.trim() : null,
    cpus: cpus.length, memGb: Math.round(os.totalmem() / 2 ** 30) };
}

// Parse an ipinfo-style JSON reply into {ip, org, country}. Hostile input -> nulls.
export function parseIpInfo(text) {
  let j;
  try { j = JSON.parse(String(text)); } catch { return { ip: null, org: null, country: null }; }
  if (!j || typeof j !== "object") return { ip: null, org: null, country: null };
  const s = (v, n) => (typeof v === "string" ? v.slice(0, n) : null);
  return { ip: typeof j.ip === "string" && isIP(j.ip) ? j.ip : null, org: s(j.org, 120), country: s(j.country, 8) };
}

// Ask an IP-info endpoint through the exit. Default ipinfo.io (no key, rate limited, fine for a
// handful of lookups per run). `url` is injectable for tests.
export async function exitLookup(exit, { url = "https://ipinfo.io/json", timeoutMs = 20_000, ca } = {}) {
  const r = await fetchVia(exit, url, { headers: { accept: "application/json", "user-agent": "curl/8" }, timeoutMs, ca });
  if (r.transport || r.code !== 200) return { ip: null, org: null, country: null, error: r.transport || `http-${r.code}` };
  return parseIpInfo(r.body);
}

export function buildMeta({ runId, label, kind, exit, clients, passes, sitesPath, siteCount, args, versions = {}, root, startedAt, exitInfo = null, selectedSites = [] }) {
  return {
    type: "meta",
    harness: "bench/egress",
    harnessVersion: HARNESS_VERSION,
    run: runId,
    exit: label,
    exitKind: kind,
    exitSpec: describeExit(exit),
    exitInfo,
    exitAttribution: "sampled lookup only; not per-stream attribution",
    clients,
    passes,
    plannedSites: selectedSites.map(s => ({ tier: s.tier, site: s.site, urlHash: createHash("sha256").update(s.url).digest("hex") })),

    sites: { path: sitesPath, sha256: sitesPath ? sha256File(sitesPath) : null, count: siteCount },
    git: root ? gitInfo(root) : null,
    versions: { node: process.version, curl: curlVersion(), ...versions },
    host: hostClass(),
    startedAt,
    args: (args || []).map((v, i, xs) => {
      if (xs[i - 1] === "--exit" || v.startsWith("--exit=")) return "<redacted-exit>";
      if (v.includes("://")) return "<redacted-url>";
      return v;
    }),
  };
}
