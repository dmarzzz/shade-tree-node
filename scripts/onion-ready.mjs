// Wait until a rolled host is reachable again before the roll is called done (issue #254).
//
// A reconcile restarts Tor on the host (bootstrap.sh), so its onion service picks new
// introduction points and publishes a new descriptor. For the next few minutes clients that hold
// the old descriptor, or that ask a directory that does not have the new one yet, cannot connect:
// a fleet e2e or a one-shot fetch started right after the roll times out although every unit is
// active. This script is the gate between "units are active" and "clients can reach this host".
//
// It polls until ALL of the requested checks hold, or a bounded timeout passes:
//
//   --onion <addr>[:port]        a SOCKS connect through Tor to the onion succeeds, the given
//                                number of times in a row, each on a fresh circuit (repeatable;
//                                port defaults to 80). This is the dial a client makes: it needs
//                                the descriptor from a directory, an introduction and a rendezvous.
//   --heartbeat-metrics <url>    the node's heartbeat reports an accepted announce newer than
//                                --since, from every Elder Tree it announces to (or from at least
//                                one with --elders any). Loopback http only.
//   --elder <onion>=<signerhex>  that Elder's signed directory, fetched over Tor and verified
//                                against the signer, lists every --onion (repeatable). For a check
//                                from another machine, e.g. the Lab before the fleet e2e.
//   --expect-nodes <n>           with --elder and no --onion list to hand: every Elder must list
//                                at least n nodes, and every node an Elder lists is dialed too.
//
//   --since <unix seconds>       when the host's Tor and units were last restarted (default 0)
//   --elders all|any             how many Elders must have accepted the heartbeat (default all)
//   --timeout <seconds>          give up after this long (default 600; the heartbeat retries a
//                                failed first announce only after its 300 s interval)
//   --interval <seconds>         pause between rounds (default 10)
//   --consecutive <n>            successful dials in a row per onion (default 2)
//   --connect-timeout <seconds>  one dial (default 45)
//   --tor-host / --tor-port      Tor SOCKS (default 127.0.0.1:9050, the system Tor of a fleet host;
//                                SHADE_TREE_TOR_HOST / SHADE_TREE_TOR_PORT are read too)
//   --dry-run                    print the checks and limits, touch nothing, exit 0
//
// Exit 0: ready. Exit 1: timed out, with one line per check that never held and its last error.
// Exit 2: bad arguments. Output names onions by an 8-character prefix only.
//
// What a pass does NOT prove: a dial from the host's own Tor shows that at least one directory
// serves the new descriptor and that the introduction points work. It cannot show that every
// directory has it, so a client elsewhere can still need one retry.

import http from "node:http";
import { randomBytes } from "node:crypto";
import { fetchOverTor } from "../packages/node/bootnode/fetch.mjs";
import { verifyDirectory } from "../packages/node/lib/directory.mjs";

export const DEFAULTS = Object.freeze({ timeoutSec: 600, intervalSec: 10, consecutive: 2, connectTimeoutSec: 45, torHost: "127.0.0.1", torPort: 9050 });
const ONION_RE = /^[a-z2-7]{56}\.onion$/;
const short = (onion) => `${String(onion).slice(0, 8)}…`;
const scrub = (text) => String(text == null ? "" : text).replace(/[a-z2-7]{56}\.onion/gi, (m) => short(m)).split("\n")[0].slice(0, 200);

class UsageError extends Error {}

function intOption(name, raw, { min, max }) {
  const value = Number(raw);
  if (!Number.isInteger(value) || value < min || value > max) throw new UsageError(`${name} must be an integer from ${min} to ${max}`);
  return value;
}

// parseArgs(argv, env) -> plan. Throws UsageError on anything it does not understand.
export function parseArgs(argv, env = process.env) {
  const plan = {
    onions: [], elders: [], heartbeatMetrics: null, since: 0, elderRule: "all", dryRun: false, expectNodes: 0,
    timeoutSec: DEFAULTS.timeoutSec, intervalSec: DEFAULTS.intervalSec, consecutive: DEFAULTS.consecutive, connectTimeoutSec: DEFAULTS.connectTimeoutSec,
    torHost: env.SHADE_TREE_TOR_HOST || DEFAULTS.torHost,
    torPort: env.SHADE_TREE_TOR_PORT ? intOption("SHADE_TREE_TOR_PORT", env.SHADE_TREE_TOR_PORT, { min: 1, max: 65535 }) : DEFAULTS.torPort,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const value = () => {
      const next = argv[++i];
      if (next === undefined || next.startsWith("--")) throw new UsageError(`${arg} needs a value`);
      return next;
    };
    if (arg === "--dry-run") plan.dryRun = true;
    else if (arg === "--onion") {
      const [host, port = "80"] = value().toLowerCase().split(":");
      if (!ONION_RE.test(host)) throw new UsageError("--onion must be a v3 onion address, optionally with :port");
      plan.onions.push({ onion: host, port: intOption("--onion port", port, { min: 1, max: 65535 }) });
    } else if (arg === "--elder") {
      const [onion, signer = ""] = value().toLowerCase().split("=");
      if (!ONION_RE.test(onion) || !/^[0-9a-f]{64}$/.test(signer)) throw new UsageError("--elder must be <onion>=<64 hex signer>");
      plan.elders.push({ onion, signer });
    } else if (arg === "--heartbeat-metrics") {
      const url = new URL(value());
      if (url.protocol !== "http:" || !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname)) throw new UsageError("--heartbeat-metrics must be a loopback http URL");
      plan.heartbeatMetrics = url.href;
    } else if (arg === "--since") plan.since = intOption("--since", value(), { min: 0, max: 4_102_444_800 });
    else if (arg === "--elders") {
      plan.elderRule = value();
      if (!["all", "any"].includes(plan.elderRule)) throw new UsageError("--elders must be all or any");
    } else if (arg === "--expect-nodes") plan.expectNodes = intOption("--expect-nodes", value(), { min: 1, max: 1000 });
    else if (arg === "--timeout") plan.timeoutSec = intOption("--timeout", value(), { min: 1, max: 3600 });
    else if (arg === "--interval") plan.intervalSec = intOption("--interval", value(), { min: 1, max: 300 });
    else if (arg === "--consecutive") plan.consecutive = intOption("--consecutive", value(), { min: 1, max: 10 });
    else if (arg === "--connect-timeout") plan.connectTimeoutSec = intOption("--connect-timeout", value(), { min: 1, max: 300 });
    else if (arg === "--tor-host") plan.torHost = value();
    else if (arg === "--tor-port") plan.torPort = intOption("--tor-port", value(), { min: 1, max: 65535 });
    else throw new UsageError(`unknown argument: ${arg}`);
  }
  if (plan.expectNodes > 0 && plan.elders.length === 0) throw new UsageError("--expect-nodes needs at least one --elder");
  if (plan.onions.length === 0 && !plan.heartbeatMetrics && plan.expectNodes === 0) throw new UsageError("nothing to wait for: give --onion, --heartbeat-metrics, or --elder with --expect-nodes");
  if (plan.elders.length > 0 && plan.onions.length === 0 && plan.expectNodes === 0) throw new UsageError("--elder needs --onion (what to look for) or --expect-nodes (how many)");
  return plan;
}

// Value of an unlabelled gauge in Prometheus text, or null when it is absent.
export function metricValue(text, name) {
  for (const line of String(text).split("\n")) {
    if (line.startsWith(name + " ")) {
      const value = Number(line.slice(name.length + 1).trim());
      return Number.isFinite(value) ? value : null;
    }
  }
  return null;
}

// heartbeatAccepted(text, { since, elderRule }) -> { ok, reason }
export function heartbeatAccepted(text, { since = 0, elderRule = "all" } = {}) {
  const last = metricValue(text, "shade_tree_heartbeat_last_success_timestamp_seconds");
  const total = metricValue(text, "shade_tree_heartbeat_elders_total");
  const accepted = metricValue(text, "shade_tree_heartbeat_elders_accepted");
  if (last === null || total === null || accepted === null) return { ok: false, reason: "heartbeat metrics are missing the acceptance gauges" };
  if (total < 1) return { ok: false, reason: "the heartbeat has no Elder Tree configured yet" };
  if (last <= 0) return { ok: false, reason: "no announce has been accepted since the heartbeat started" };
  if (last < since) return { ok: false, reason: `the last accepted announce is ${Math.ceil(since - last)}s older than the restart` };
  const need = elderRule === "any" ? 1 : total;
  if (accepted < need) return { ok: false, reason: `accepted by ${accepted} of ${total} Elder Trees, need ${need}` };
  return { ok: true, reason: `accepted by ${accepted} of ${total} Elder Trees` };
}

async function socksDial({ onion, port, torHost, torPort, timeoutMs }) {
  const { SocksClient } = await import("socks");
  // Fresh SOCKS credentials put each dial on its own circuit (Tor's IsolateSOCKSAuth default), so
  // a second success is a second rendezvous, not a reused stream.
  const tag = randomBytes(8).toString("hex");
  const { socket } = await SocksClient.createConnection({
    proxy: { host: torHost, port: torPort, type: 5, userId: `ready-${tag}`, password: tag },
    command: "connect",
    destination: { host: onion, port },
    timeout: timeoutMs,
  });
  try { socket.destroy(); } catch { /* already closed */ }
  return true;
}

function httpGetText(url, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, { timeout: timeoutMs }, (res) => {
      if (res.statusCode !== 200) { res.resume(); reject(new Error(`HTTP ${res.statusCode}`)); return; }
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => { body += chunk; if (body.length > 1024 * 1024) req.destroy(new Error("metrics response too large")); });
      res.on("end", () => resolve(body));
      res.on("error", reject);
    });
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", reject);
  });
}

// waitUntilReady(plan, deps) -> { ready, elapsedSec, rounds, checks: [{ name, ok, detail }] }
// Every dependency is injectable; the selftest drives it with a fake clock and fake dials.
export async function waitUntilReady(plan, {
  dial = socksDial,
  fetchMetrics = httpGetText,
  fetchDirectory = (elder, opts) => fetchOverTor(elder.onion, "/directory", opts),
  verify = verifyDirectory,
  now = () => Date.now(),
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  log = (line) => console.log(line),
} = {}) {
  const started = now();
  const deadline = started + plan.timeoutSec * 1000;
  const connectMs = plan.connectTimeoutSec * 1000;
  const onionCheck = (target) => ({ kind: "onion", name: `onion ${short(target.onion)} port ${target.port} accepts a connection through Tor`, target, streak: 0, ok: false, detail: "not tried yet" });
  const listingName = plan.expectNodes > 0
    ? `at least ${plan.expectNodes} node${plan.expectNodes === 1 ? "" : "s"}`
    : plan.onions.length === 1 ? "the node" : `all ${plan.onions.length} nodes`;
  const checks = [
    ...plan.onions.map(onionCheck),
    ...(plan.heartbeatMetrics ? [{ kind: "heartbeat", name: `heartbeat accepted by ${plan.elderRule === "any" ? "an Elder Tree" : "every Elder Tree"}`, ok: false, detail: "not tried yet" }] : []),
    ...plan.elders.map((elder) => ({ kind: "elder", name: `Elder ${short(elder.onion)} lists ${listingName}`, elder, ok: false, detail: "not tried yet" })),
  ];

  const discovered = [];
  const runCheck = async (check) => {
    try {
      if (check.kind === "onion") {
        await dial({ onion: check.target.onion, port: check.target.port, torHost: plan.torHost, torPort: plan.torPort, timeoutMs: connectMs });
        check.streak += 1;
        check.ok = check.streak >= plan.consecutive;
        check.detail = `${check.streak} of ${plan.consecutive} connections in a row`;
      } else if (check.kind === "heartbeat") {
        const verdict = heartbeatAccepted(await fetchMetrics(plan.heartbeatMetrics), { since: plan.since, elderRule: plan.elderRule });
        check.ok = verdict.ok;
        check.detail = verdict.reason;
      } else {
        const directory = await fetchDirectory(check.elder, { torHost: plan.torHost, torPort: plan.torPort, timeoutMs: connectMs, attempts: 1 });
        const verdict = verify(directory, check.elder.signer);
        if (!verdict.ok) throw new Error(`directory failed verification (${String(verdict.reason || "unknown").split(":", 1)[0]})`);
        const listed = new Set((Array.isArray(directory.gateways) ? directory.gateways : []).map((g) => String(g?.onion || "").toLowerCase()));
        const missing = plan.onions.filter((target) => !listed.has(target.onion));
        const enough = listed.size >= plan.expectNodes;
        check.ok = missing.length === 0 && enough;
        check.detail = check.ok ? "listed"
          : !enough ? `lists ${listed.size} of the ${plan.expectNodes} expected nodes`
            : `not listed yet: ${missing.map((target) => short(target.onion)).join(", ")}`;
        // --expect-nodes: every node a verified directory lists must also accept a connection.
        if (plan.expectNodes > 0) {
          for (const onion of listed) {
            if (ONION_RE.test(onion) && !checks.some((other) => other.kind === "onion" && other.target.onion === onion && other.target.port === 80)) {
              discovered.push(onionCheck({ onion, port: 80 }));
            }
          }
        }
      }
    } catch (error) {
      if (check.kind === "onion") check.streak = 0;
      check.ok = false;
      check.detail = scrub(error?.message || error);
    }
  };

  let rounds = 0;
  for (;;) {
    rounds += 1;
    // Nodes found in an Elder's directory last round are dialed from this round on.
    for (const check of discovered.splice(0)) {
      if (!checks.some((other) => other.kind === "onion" && other.target.onion === check.target.onion && other.target.port === check.target.port)) checks.push(check);
    }
    // A check that already held is tried again only if it can regress cheaply (the heartbeat
    // gauge); a finished dial streak or a seen listing is not repeated.
    await Promise.all(checks.filter((check) => !check.ok || check.kind === "heartbeat").map(runCheck));
    const pending = [...checks.filter((check) => !check.ok), ...discovered];
    const elapsedSec = Math.round((now() - started) / 1000);
    if (pending.length === 0) {
      log(`ready after ${elapsedSec}s: ${checks.map((check) => check.name).join("; ")}`);
      return { ready: true, elapsedSec, rounds, checks };
    }
    log(`waiting (${elapsedSec}s of ${plan.timeoutSec}s): ${pending.map((check) => `${check.name} [${check.detail}]`).join("; ")}`);
    if (now() + plan.intervalSec * 1000 > deadline) return { ready: false, elapsedSec, rounds, checks };
    await sleep(plan.intervalSec * 1000);
  }
}

export function describePlan(plan) {
  return [
    `would wait up to ${plan.timeoutSec}s, checking every ${plan.intervalSec}s through Tor SOCKS ${plan.torHost}:${plan.torPort}:`,
    ...plan.onions.map((target) => `  onion ${short(target.onion)} port ${target.port}: ${plan.consecutive} connections in a row, ${plan.connectTimeoutSec}s each`),
    ...(plan.heartbeatMetrics ? [`  heartbeat at ${plan.heartbeatMetrics}: accepted by ${plan.elderRule === "any" ? "at least one Elder Tree" : "every Elder Tree"} after unix time ${plan.since}`] : []),
    ...plan.elders.map((elder) => `  Elder ${short(elder.onion)}: signed directory lists ${plan.expectNodes > 0 ? `at least ${plan.expectNodes} nodes, each of which must also accept connections` : "every onion above"}`),
  ].join("\n");
}

export function timeoutMessage(plan, result) {
  const pending = result.checks.filter((check) => !check.ok);
  return [
    `NOT READY after ${result.elapsedSec}s (limit ${plan.timeoutSec}s). The units may be active, but clients cannot rely on this host yet:`,
    ...pending.map((check) => `  - ${check.name}: ${check.detail}`),
    "Do not start the fleet e2e or roll the next host. Tor publishes a new onion descriptor after a restart and the heartbeat retries on its interval; run this check again, and if it still fails read `journalctl -u tor@default -u shade-tree-heartbeat -n 50` on the host.",
  ].join("\n");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  let plan;
  try { plan = parseArgs(process.argv.slice(2)); } catch (error) {
    console.error(`onion-ready: ${error instanceof UsageError ? error.message : "invalid arguments"}`);
    process.exit(2);
  }
  if (plan.dryRun) {
    console.log(describePlan(plan));
    process.exit(0);
  }
  const result = await waitUntilReady(plan);
  if (!result.ready) {
    console.error(timeoutMessage(plan, result));
    process.exit(1);
  }
  process.exit(0);
}
