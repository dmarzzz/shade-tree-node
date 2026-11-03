#!/usr/bin/env node
// Egress benchmark: one exit x clients x sites x passes -> JSONL. See bench/egress/README.md.
//
//   node bench/egress/run.mjs --real --label dc-fsn --kind datacenter --out runs/dc-fsn.jsonl
//   node bench/egress/run.mjs --real --label shadenet --kind shadenet --exit http://127.0.0.1:8888 --out runs/shadenet.jsonl
//   node bench/egress/run.mjs --real --label tor --kind tor --exit socks5://127.0.0.1:9050 --tor-control 127.0.0.1:9051 --out runs/tor.jsonl
//   xvfb-run -a node bench/egress/run.mjs --real --clients headed ...      (headed on a display-less Linux box)
//
// Without --real the harness only runs against loopback sites (that is how the selftest
// drives it). Under CI it refuses non-loopback sites even with --real.

import { randomUUID } from "node:crypto";
import { parseArgs } from "node:util";
import { appendFile, mkdir, readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseSites, selectSites, isLoopbackHost } from "./lib/sites.mjs";
import { parseExit, EXIT_KINDS, parseHostPort } from "./lib/exits.mjs";
import { CLIENTS } from "./lib/clients.mjs";
import { buildMeta, exitLookup } from "./lib/meta.mjs";
import { checkPlan, runMatrix } from "./lib/runner.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "../..");

const USAGE = `usage: node bench/egress/run.mjs --label L --kind K --out FILE.jsonl [options]
  --exit SPEC          direct (default) | http://host:port | socks5://host:port
  --kind K             ${EXIT_KINDS.join(" | ")}
  --clients LIST       comma list of ${CLIENTS.join(",")} (default curl,node,headless,headed)
  --sites FILE         sites file (default bench/egress/sites.txt)
  --only LIST          run only these site names
  --passes N           default 3
  --gap S              seconds between cells, plus 0-2 s jitter (default 4, min 2 for real sites)
  --pass-gap S         seconds between passes (default 60)
  --seed N             shuffle seed (default 7)
  --ua chrome|polite   curl/node user agent (default chrome; polite names the benchmark)
  --tor-control H:P    send NEWNYM before each site (null-auth control port only)
  --timeout S          per-cell timeout including browser setup (default 45)
  --settle-ms MS       browser settling inside the cell deadline (default 6000)
  --lookup-url URL     sampled exit lookup endpoint (real mode only)
  --shots DIR          screenshot every non-ok browser cell into DIR
  --no-exit-lookup     do not look up the exit IP/ASN through the exit
  --real               allow non-loopback sites (a real measurement)`;

function die(msg) { console.error(msg); process.exit(2); }

const { values: a } = (() => {
  try {
    return parseArgs({ options: {
      label: { type: "string" }, kind: { type: "string" }, out: { type: "string" },
      exit: { type: "string", default: "direct" }, clients: { type: "string", default: "curl,node,headless,headed" },
      sites: { type: "string", default: join(HERE, "sites.txt") }, only: { type: "string" },
      passes: { type: "string", default: "3" }, gap: { type: "string", default: "4" }, "pass-gap": { type: "string", default: "60" },
      seed: { type: "string", default: "7" }, ua: { type: "string", default: "chrome" }, "tor-control": { type: "string" },
      timeout: { type: "string", default: "45" }, shots: { type: "string" }, "no-exit-lookup": { type: "boolean", default: false },
      real: { type: "boolean", default: false }, help: { type: "boolean", default: false },
      "settle-ms": { type: "string", default: "6000" }, "lookup-url": { type: "string", default: "https://ipinfo.io/json" },
    } });
  } catch (e) { die(`${e.message}\n${USAGE}`); }
})();
if (a.help) { console.log(USAGE); process.exit(0); }
if (!a.label || !/^[A-Za-z0-9._-]{1,40}$/.test(a.label)) die(`--label is required ([A-Za-z0-9._-], max 40)\n${USAGE}`);
if (!EXIT_KINDS.includes(a.kind)) die(`--kind must be one of ${EXIT_KINDS.join(", ")}`);
if (!a.out) die("--out is required");
if (a.ua !== "chrome" && a.ua !== "polite") die("--ua must be chrome or polite");
const num = (k, min, max) => { const n = Number(a[k]); if (!Number.isFinite(n) || n < min || n > max) die(`--${k} must be a number in [${min}, ${max}]`); return n; };
const passes = num("passes", 1, 50);
const gapS = num("gap", 0, 3600);
const passGapS = num("pass-gap", 0, 86400);
const seed = num("seed", 0, 2 ** 32);
const timeoutS = num("timeout", 1, 600);
const settleMs = num("settle-ms", 0, 60000);

const ex = parseExit(a.exit);
if (!ex.ok) die(ex.error);
const parsed = parseSites(await readFile(a.sites, "utf8").catch((e) => die(`cannot read sites file: ${e.message}`)));
if (!parsed.ok) die(`sites file ${a.sites}:\n  ${parsed.errors.join("\n  ")}`);
const sel = selectSites(parsed.sites, a.only);
if (!sel.ok) die(sel.error);
const clients = a.clients.split(",").map((s) => s.trim()).filter(Boolean);
const plan = checkPlan({ sites: sel.sites, clients, gapS, real: a.real });
if (!plan.ok) die(plan.error);
const localOnly = !a.real || !!process.env.CI;
if (localOnly && ex.exit.type !== "direct" && !isLoopbackHost(ex.exit.host)) die("local mode requires loopback proxy");
if (localOnly && a["tor-control"] && !isLoopbackHost(parseHostPort(a["tor-control"])?.host || "")) die("local mode requires loopback control");
if (!Number.isInteger(passes) || !Number.isInteger(seed)) die("passes and seed must be integers");
process.umask(0o077);

await mkdir(dirname(resolve(a.out)), { recursive: true });
if (a.shots) await mkdir(a.shots, { recursive: true });
const startedAt = new Date().toISOString();
const runId = `${a.label}-${randomUUID()}`;
const write = (row) => appendFile(a.out, JSON.stringify(row) + "\n");

const versions = {};
if (clients.some((c) => c === "headless" || c === "headed")) {
  try { versions.playwright = JSON.parse(await readFile(join(ROOT, "node_modules/@playwright/test/package.json"), "utf8")).version; } catch { /* not installed */ }
  versions.chromium = "not separately probed; see installed Playwright version";
}
let exitInfo = null;
if (!localOnly && !a["no-exit-lookup"]) {
  exitInfo = await exitLookup(ex.exit, { url: a["lookup-url"] });
  // Through the member Proxy every CONNECT may pick a different node, so this lookup names one
  // exit the canopy used at the start, not the exit of every cell.
  if (a.kind === "shadenet") exitInfo.note = "one sample; each CONNECT may exit from a different node";
}
await write(buildMeta({ runId, label: a.label, kind: a.kind, exit: ex.exit, clients, passes, sitesPath: a.sites,
  siteCount: sel.sites.length, args: process.argv.slice(2), versions, root: ROOT, startedAt, exitInfo, selectedSites: sel.sites }));

// A separate lookup samples an exit; it does not attribute these cells or subresources.
const exitTag = !localOnly && a["tor-control"] && !a["no-exit-lookup"]
  ? async () => { const x = await exitLookup(ex.exit, { url: a["lookup-url"] }); return { exit_ip: x.ip, exit_org: x.org, exit_cc: x.country }; }
  : () => ({});

const controller = new AbortController();
const cancel = () => controller.abort();
process.once("SIGINT", cancel);
process.once("SIGTERM", cancel);
const counts = await runMatrix({ exit: ex.exit, label: a.label, kind: a.kind, clients, sites: sel.sites, passes, gapS, passGapS,
  seed, uaMode: a.ua, torControl: a["tor-control"] || null, timeoutS, shotsDir: a.shots || null, runId, write,
  log: (l) => console.log(l), settleMs, exitTag, localOnly, signal: controller.signal });
process.removeListener("SIGINT", cancel);
process.removeListener("SIGTERM", cancel);
if (controller.signal.aborted) process.exitCode = 130;
console.log(`done ${runId}: ${Object.entries(counts).map(([k, v]) => `${k}=${v}`).join(" ")}`);
