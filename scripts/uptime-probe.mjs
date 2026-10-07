// External uptime prober (T-MON-4): check fleet health from OUTSIDE, over Tor.
//
// An external monitor (cron, or an uptime service with a tor-capable runner) runs this
// standalone, dependency-light check on an interval. It reaches the bootnode the SAME way a
// client does -- a SOCKS dial through the local Tor daemon (packages/node/bootnode/fetch.mjs), no exit node,
// the bootnode never learns the monitor's IP -- fetches GET /health and GET /directory, and
// verifies the directory signature against the PINNED signer (packages/node/lib/directory.mjs verifyDirectory).
// So the check proves the fleet is not just reachable but serving an authentic, signer-pinned
// directory: a swapped/MITM'd bootnode fails signerOk, not just reachability.
//
//   node scripts/uptime-probe.mjs                 -> one-line JSON, exit 0 healthy / nonzero not
//   node scripts/uptime-probe.mjs --format nagios -> "OK|CRITICAL|UNKNOWN: ..." line, exit 0 / 2 / 3
//   ... --prom-file <path>                        -> also write node_exporter textfile metrics
//                                                    (atomic; for a second vantage point, OPS-7)
//
// Config (all SHADE_TREE_*):
//   SHADE_TREE_BOOTNODE_ONION   the bootnode v3 .onion  (production: fetched over Tor)
//   SHADE_TREE_TOR_HOST/PORT    local Tor SOCKS proxy   (default 127.0.0.1:9250)
//   SHADE_TREE_BOOTNODE_URL     plain http base, e.g. http://127.0.0.1:8877  (DEV ONLY; bypasses Tor)
//   SHADE_TREE_DIR_SIGNER       pinned directory-signer pubkey (hex) -- REQUIRED
//   SHADE_TREE_DIR_MAX_AGE_SEC  oldest accepted signed-directory issue time (default 300)
//   SHADE_TREE_DIR_FUTURE_SEC   accepted future clock skew for issue time (default 300)
//   SHADE_TREE_PROBE_ACCEPT_PRE_V4_CAPS  1 = observation-only verification of the earlier
//                                  research fleet's capability signatures (default off)
//   SHADE_TREE_NETWORK          <name>: default BOOTNODE_ONION + DIR_SIGNER from network/<name>/bootnode.json
//                         (explicit env wins; a pending record supplies nothing -> misconfig)
//   SHADE_TREE_PROBE_TIMEOUT_MS per-attempt timeout     (default 60000; a cold onion descriptor
//                               fetch plus rendezvous regularly exceeds 20 s)
//
// Outcomes (OPS-7): OK (exit 0); CRITICAL (exit 2 nagios / 1 json) when the Elder is unreachable
// or serves a bad directory; UNKNOWN (exit 3) when the probe's OWN Tor SOCKS port is down, so a
// broken runner never counts against the canopy. When SHADE_TREE_NETWORK names a record with a
// service pin and the Elder's /health reports its commit, `pinMatch` says whether they agree
// (informational; a mismatch is reported, not counted as downtime).
//
// PRIVACY: machine-readable output can include a COUNT for private monitoring, but the hosted
// workflow uses the count-free Nagios line. Neither mode prints gateway identities, and errors
// scrub any .onion. Fail-closed: any error reports UNHEALTHY and never hangs.

import http from "node:http";
import net from "node:net";
import { readFileSync, writeFileSync, renameSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { fetchOverTor } from "../packages/node/bootnode/fetch.mjs";
import { verifyDirectory } from "../packages/node/lib/directory.mjs";
import { applyNetworkEnv } from "../packages/node/lib/network-record.mjs";

const TOR_HOST = process.env.SHADE_TREE_TOR_HOST || "127.0.0.1";
const TOR_PORT = Number(process.env.SHADE_TREE_TOR_PORT || 9250);
const TIMEOUT_MS = Number(process.env.SHADE_TREE_PROBE_TIMEOUT_MS || 60000);
const HERE = dirname(fileURLToPath(import.meta.url));
const MAX_RESP = Number(process.env.SHADE_TREE_BOOTNODE_MAX_RESP || 2 * 1024 * 1024);
const boundedSeconds = (value, fallback) => {
  const parsed = Number(value ?? fallback);
  return Number.isInteger(parsed) && parsed >= 0 && parsed <= 3600 ? parsed : fallback;
};
const DIR_MAX_AGE_SEC = boundedSeconds(process.env.SHADE_TREE_DIR_MAX_AGE_SEC, 300);
const DIR_FUTURE_SEC = boundedSeconds(process.env.SHADE_TREE_DIR_FUTURE_SEC, 300);
const ACCEPT_PRE_V4_CAPS = /^(1|true|yes|on)$/i.test(process.env.SHADE_TREE_PROBE_ACCEPT_PRE_V4_CAPS || "");

// Never let an onion address leak into monitor logs via an error string.
const scrub = (s) => String(s == null ? "" : s).replace(/[a-z2-7]{56}\.onion/gi, "<onion>");

// Directory verifier reasons can include a short onion prefix for a local operator. Publicly
// hosted probe output needs only the bounded failure class, never that prefix.
const directoryReason = (reason) => {
  const label = String(reason || "verification-failed").split(":", 1)[0];
  return /^[a-z][a-z0-9-]{0,47}$/.test(label) ? label : "verification-failed";
};

// Parse --format nagios | --format=nagios | --nagios | --format json (default json).
function parseFormat(argv) {
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--nagios") return "nagios";
    if (a === "--format") return (argv[i + 1] || "json").toLowerCase();
    if (a.startsWith("--format=")) return a.slice("--format=".length).toLowerCase();
  }
  return "json";
}

// Bounded, timed plain-HTTP GET for DEV mode (SHADE_TREE_BOOTNODE_URL). Production goes over Tor via
// fetchOverTor, which already caps the read and times out. Both return parsed JSON or throw.
function plainGet(base, path) {
  return new Promise((resolve, reject) => {
    let req;
    const url = new URL(path, base);
    req = http.get(url, { timeout: TIMEOUT_MS }, (res) => {
      if (res.statusCode !== 200) { res.resume(); return reject(new Error(`HTTP ${res.statusCode}`)); }
      let buf = Buffer.alloc(0);
      res.on("data", (c) => {
        buf = Buffer.concat([buf, c]);
        if (buf.length > MAX_RESP) { res.destroy(); reject(new Error(`response exceeded ${MAX_RESP} bytes`)); }
      });
      res.on("end", () => { try { resolve(JSON.parse(buf.toString("utf8"))); } catch (e) { reject(e); } });
      res.on("error", reject);
    });
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", reject);
  });
}

// `preferUrl`: an EXPLICIT SHADE_TREE_BOOTNODE_URL (set before the SHADE_TREE_NETWORK record filled
// anything) beats a record-supplied onion — explicit env wins over the record, and since the
// sepolia record went live (2026-08-17) it always supplies an onion.
function makeFetcher({ preferUrl = false } = {}) {
  const onion = process.env.SHADE_TREE_BOOTNODE_ONION;
  const url = process.env.SHADE_TREE_BOOTNODE_URL;
  if (preferUrl && url) return (path) => plainGet(url, path);
  if (onion) {
    return (path) => fetchOverTor(onion, path, { torHost: TOR_HOST, torPort: TOR_PORT, timeoutMs: TIMEOUT_MS, maxBytes: MAX_RESP });
  }
  if (url) return (path) => plainGet(url, path);
  return null; // misconfigured
}

// Is the probe's own Tor SOCKS listener accepting connections? If not, the probe cannot say
// anything about the canopy (UNKNOWN), which is different from the canopy being down.
function localTorUp(host = TOR_HOST, port = TOR_PORT, timeoutMs = 3000) {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port });
    const done = (up) => { socket.destroy(); resolve(up); };
    socket.setTimeout(timeoutMs, () => done(false));
    socket.once("connect", () => done(true));
    socket.once("error", () => done(false));
  });
}

// The Elder commit the committed record pins, or null when no record/pin applies.
export function recordElderCommit(network = process.env.SHADE_TREE_NETWORK) {
  if (!network || !/^[a-z0-9-]{1,32}$/.test(network)) return null;
  try {
    const record = JSON.parse(readFileSync(join(HERE, "..", "network", network, "deployment.json"), "utf8"));
    const pin = String(record?.services?.elder?.commit || "").toLowerCase();
    return /^[0-9a-f]{40}$/.test(pin) ? pin : null;
  } catch {
    return null;
  }
}

export async function observeFleet() {
  // Fail-closed default: everything false / zero until proven otherwise.
  const result = { ok: false, bootnodeReachable: false, signerOk: false, directoryFresh: false, fleetSize: 0, ts: Math.floor(Date.now() / 1000) };
  let health = null;
  let directory = null;

  // SHADE_TREE_NETWORK: fill unset discovery inputs from the committed record; a broken record is a
  // misconfig (fail closed), never a throw out of probe().
  const explicitUrl = !!process.env.SHADE_TREE_BOOTNODE_URL && !process.env.SHADE_TREE_BOOTNODE_ONION;
  // The public census may deliberately observe a retired research deployment through explicit
  // onion/signer inputs. `allowRetired` only suppresses the record-level guard; retired records
  // still supply zero defaults, so the explicit coordinates remain mandatory.
  try { applyNetworkEnv(process.env, { allowRetired: true }); } catch (e) { result.reason = "misconfig:" + scrub(e.message).split("\n")[0]; return { result, health, directory }; }
  // A record with more than one Elder signer sets a comma-separated list (network-record.mjs);
  // verifyDirectory takes a list, and a joined string would match no signer.
  const pinnedSigner = (process.env.SHADE_TREE_DIR_SIGNER || "").split(",").map((s) => s.trim()).filter(Boolean);
  const fetchJson = makeFetcher({ preferUrl: explicitUrl });
  if (!fetchJson) { result.reason = "misconfig:set SHADE_TREE_BOOTNODE_ONION or SHADE_TREE_BOOTNODE_URL"; return { result, health, directory }; }
  if (!pinnedSigner.length) { result.reason = "misconfig:set SHADE_TREE_DIR_SIGNER (pinned signer)"; return { result, health, directory }; }

  if (process.env.SHADE_TREE_BOOTNODE_ONION && !(explicitUrl && process.env.SHADE_TREE_BOOTNODE_URL) && !(await localTorUp())) {
    result.status = "unknown";
    result.reason = "probe:local-tor-unavailable";
    return { result, health, directory };
  }

  try {
    health = await fetchJson("/health");
    result.bootnodeReachable = true;            // we got a 200 from the bootnode
    const healthOk = health?.ok === true;       // the bootnode's own self-report

    const dir = await fetchJson("/directory");
    const v = verifyDirectory(dir, pinnedSigner, { acceptPreV4Caps: ACCEPT_PRE_V4_CAPS });
    result.signerOk = v.ok;
    const nowSec = Math.floor(Date.now() / 1000);
    result.directoryFresh = v.ok
      && Number.isInteger(dir?.issued)
      && dir.issued >= nowSec - DIR_MAX_AGE_SEC
      && dir.issued <= nowSec + DIR_FUTURE_SEC;
    result.fleetSize = result.directoryFresh && Array.isArray(dir.gateways) ? dir.gateways.length : 0;
    result.ok = healthOk && result.signerOk && result.directoryFresh;
    if (result.directoryFresh) directory = dir; // exposed only to trusted local aggregators; never printed here

    const pin = recordElderCommit();
    const running = /^[0-9a-f]{40}$/.test(String(health?.commit || "")) ? health.commit : null;
    if (pin && running) result.pinMatch = running === pin;

    if (!v.ok) result.reason = "directory:" + directoryReason(v.reason);
    else if (!result.directoryFresh) result.reason = "directory:issued-outside-freshness-window";
    else if (!healthOk) result.reason = "bootnode health not ok";
  } catch (e) {
    // Unreachable, timeout, bad JSON, oversized body -> stay unhealthy, record a scrubbed reason.
    result.reason = scrub(e?.message || e);
  }
  return { result, health, directory };
}

export async function probe() {
  return (await observeFleet()).result;
}

function nagiosLine(r) {
  if (r.status === "unknown") return "UNKNOWN: probe-side Tor unavailable; canopy state not measured";
  if (r.ok) return "OK: bootnode reachable, signed directory fresh" + (r.pinMatch === false ? " (Elder commit differs from the record pin)" : "");
  if (!r.bootnodeReachable) return "CRITICAL: bootnode unreachable";
  if (!r.signerOk) return "CRITICAL: directory verification failed";
  if (!r.directoryFresh) return "CRITICAL: signed directory outside freshness window";
  return "CRITICAL: bootnode health not ok";
}

function parsePromFile(argv) {
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--prom-file") return argv[i + 1] || null;
    if (argv[i].startsWith("--prom-file=")) return argv[i].slice("--prom-file=".length) || null;
  }
  return null;
}

// node_exporter textfile collector format. Counts only; no onion, signer or gateway identity.
export function promLines(r) {
  const b = (v) => (v ? 1 : 0);
  const lines = [
    ["shade_tree_probe_ok", "1 = Elder reachable and serving a fresh, signer-verified directory.", b(r.ok)],
    ["shade_tree_probe_unknown", "1 = the probe's own Tor was unavailable; the canopy was not measured.", b(r.status === "unknown")],
    ["shade_tree_probe_bootnode_reachable", "1 = the Elder answered /health over Tor.", b(r.bootnodeReachable)],
    ["shade_tree_probe_directory_fresh", "1 = the signed directory verified and is inside the freshness window.", b(r.directoryFresh)],
    ["shade_tree_probe_fleet_size", "Nodes listed in the fresh signed directory.", Number(r.fleetSize) || 0],
    ["shade_tree_probe_last_run_timestamp_seconds", "Unix time of this probe run.", Number(r.ts) || Math.floor(Date.now() / 1000)],
  ];
  if (r.pinMatch !== undefined) lines.push(["shade_tree_probe_pin_match", "1 = the Elder runs the commit the record pins.", b(r.pinMatch)]);
  return lines.map(([name, help, value]) => `# HELP ${name} ${help}\n# TYPE ${name} gauge\n${name} ${value}`).join("\n") + "\n";
}

function writePromFile(path, r) {
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, promLines(r), { mode: 0o644 });
  renameSync(tmp, path);
}

// Only run when invoked directly; importing (the selftest) pulls probe() with no side effects.
if (import.meta.url === `file://${process.argv[1]}`) {
  const format = parseFormat(process.argv.slice(2));
  const promFile = parsePromFile(process.argv.slice(2));
  probe().then((result) => {
    if (promFile) {
      try { writePromFile(promFile, result); } catch (e) { console.error(`prom-file write failed: ${scrub(e?.message || e)}`); }
    }
    if (format === "nagios") {
      console.log(nagiosLine(result));
      process.exit(result.status === "unknown" ? 3 : result.ok ? 0 : 2); // Nagios: 0 OK, 2 CRITICAL, 3 UNKNOWN
    } else {
      // Ordered, machine-readable one-liner for private/operator monitoring.
      const { ok, bootnodeReachable, signerOk, directoryFresh, fleetSize, ts, reason, status, pinMatch } = result;
      console.log(JSON.stringify({ ok, bootnodeReachable, signerOk, directoryFresh, fleetSize, ts, ...(status ? { status } : {}), ...(pinMatch !== undefined ? { pinMatch } : {}), ...(reason ? { reason } : {}) }));
      process.exit(status === "unknown" ? 3 : ok ? 0 : 1);
    }
  }).catch(() => {
    // Last-resort fail-closed: even an unexpected throw reports unhealthy, never hangs or
    // reflects exception text into hosted/public logs.
    const ts = Math.floor(Date.now() / 1000);
    if (format === "nagios") { console.log("CRITICAL: probe failed"); process.exit(2); }
    console.log(JSON.stringify({ ok: false, bootnodeReachable: false, signerOk: false, directoryFresh: false, fleetSize: 0, ts, reason: "unexpected-probe-failure" }));
    process.exit(1);
  });
}
