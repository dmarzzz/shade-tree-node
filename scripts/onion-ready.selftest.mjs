// Selftest for scripts/onion-ready.mjs (issue #254). No Tor and no fleet: the wait loop runs on a
// fake clock with injected dials, and the real SOCKS dial and CLI run against a local SOCKS5 stub
// that refuses the first connections the way a not-yet-published onion does.

import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DEFAULTS, describePlan, heartbeatAccepted, metricValue, parseArgs, timeoutMessage, waitUntilReady } from "./onion-ready.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const onion = (char) => char.repeat(56) + ".onion";
const NODE = onion("a");
const ELDER = onion("e");
const SIGNER = "5".repeat(64);

// --- arguments --------------------------------------------------------------------------------
const plan = parseArgs(["--onion", NODE, "--heartbeat-metrics", "http://127.0.0.1:9103/metrics", "--since", "1700000000"], {});
assert.deepEqual(plan.onions, [{ onion: NODE, port: 80 }]);
assert.equal(plan.timeoutSec, 600, "default limit covers one 300 s heartbeat retry");
assert.equal(plan.consecutive, 2);
assert.equal(plan.torPort, 9050, "default is the fleet host's system Tor");
assert.equal(parseArgs(["--onion", `${NODE}:8879`], { SHADE_TREE_TOR_PORT: "9250" }).torPort, 9250);
assert.equal(parseArgs(["--onion", `${NODE}:8879`], {}).onions[0].port, 8879);
assert.deepEqual(DEFAULTS.timeoutSec, 600);
for (const bad of [
  [],
  ["--onion", "example.com"],
  ["--onion", NODE, "--timeout", "0"],
  ["--onion", NODE, "--timeout", "99999"],
  ["--onion", NODE, "--timeout"],
  ["--onion", NODE, "--bogus"],
  ["--onion", NODE, "--elders", "some"],
  ["--onion", NODE, "--elder", ELDER],
  ["--elder", `${ELDER}=${SIGNER}`, "--heartbeat-metrics", "http://127.0.0.1:9103/metrics"],
  ["--heartbeat-metrics", "http://10.0.0.5:9103/metrics"],
  ["--heartbeat-metrics", "https://127.0.0.1:9103/metrics"],
]) {
  assert.throws(() => parseArgs(bad, {}), /./, `rejects ${JSON.stringify(bad)}`);
}
const dry = describePlan(plan);
assert.match(dry, /would wait up to 600s/);
assert.equal(dry.includes(NODE), false, "the plan names onions by prefix only");

// --- heartbeat gauges -------------------------------------------------------------------------
const metrics = ({ last, total, accepted }) => [
  "# HELP shade_tree_heartbeat_last_success_timestamp_seconds Unix timestamp of the last accepted heartbeat.",
  "# TYPE shade_tree_heartbeat_last_success_timestamp_seconds gauge",
  `shade_tree_heartbeat_last_success_timestamp_seconds ${last}`,
  `shade_tree_heartbeat_elders_total ${total}`,
  `shade_tree_heartbeat_elders_accepted ${accepted}`,
  'shade_tree_heartbeat_attempts_total{outcome="accepted"} 4',
].join("\n");
assert.equal(metricValue(metrics({ last: 1700000100.5, total: 2, accepted: 2 }), "shade_tree_heartbeat_last_success_timestamp_seconds"), 1700000100.5);
assert.equal(metricValue("other 1", "shade_tree_heartbeat_elders_total"), null);
assert.equal(heartbeatAccepted(metrics({ last: 1700000100, total: 2, accepted: 2 }), { since: 1700000000 }).ok, true);
assert.match(heartbeatAccepted(metrics({ last: 0, total: 2, accepted: 0 }), { since: 1700000000 }).reason, /no announce has been accepted/);
assert.match(heartbeatAccepted(metrics({ last: 1699999000, total: 2, accepted: 2 }), { since: 1700000000 }).reason, /1000s older than the restart/, "an announce from before the restart does not count");
assert.match(heartbeatAccepted(metrics({ last: 1700000100, total: 2, accepted: 1 }), { since: 1700000000 }).reason, /accepted by 1 of 2 Elder Trees, need 2/);
assert.equal(heartbeatAccepted(metrics({ last: 1700000100, total: 2, accepted: 1 }), { since: 1700000000, elderRule: "any" }).ok, true);
assert.match(heartbeatAccepted(metrics({ last: 1700000100, total: 0, accepted: 0 })).reason, /no Elder Tree configured/);
assert.match(heartbeatAccepted("garbage").reason, /missing the acceptance gauges/);

// --- the wait loop on a fake clock -------------------------------------------------------------
function fakeClock() {
  let t = 1_700_000_000_000;
  const sleeps = [];
  return { now: () => t, sleep: async (ms) => { sleeps.push(ms); t += ms; }, advance: (ms) => { t += ms; }, sleeps };
}

// 1. The #254 shape: the onion refuses for three minutes, the heartbeat is accepted at four.
{
  const clock = fakeClock();
  const lines = [];
  const start = clock.now();
  const dials = [];
  const result = await waitUntilReady(parseArgs(["--onion", NODE, "--heartbeat-metrics", "http://127.0.0.1:9103/metrics", "--since", "1700000000"], {}), {
    now: clock.now,
    sleep: clock.sleep,
    log: (line) => lines.push(line),
    dial: async (target) => {
      dials.push(target);
      if (clock.now() - start < 180_000) throw new Error(`Socks5 proxy rejected connection - HostUnreachable (${NODE})`);
      return true;
    },
    fetchMetrics: async () => (clock.now() - start < 240_000
      ? metrics({ last: 0, total: 2, accepted: 0 })
      : metrics({ last: Math.floor(clock.now() / 1000), total: 2, accepted: 2 })),
  });
  assert.equal(result.ready, true);
  assert.equal(result.elapsedSec, 240, "declared ready only when the slower check holds");
  assert.ok(lines.at(-1).startsWith("ready after 240s"));
  assert.ok(lines.some((line) => /waiting \(0s of 600s\).*HostUnreachable/.test(line)), "progress lines carry the last error");
  assert.equal(lines.join("\n").includes(NODE), false, "full onion addresses are never logged");
  assert.deepEqual([dials[0].port, dials[0].torPort, dials[0].timeoutMs], [80, 9050, 45_000]);
  // 18 refused rounds, then exactly two successful dials: a finished streak is not dialed again.
  assert.equal(dials.length, 18 + 2);
}

// 2. A single lucky dial is not enough: the streak resets on a failure.
{
  const clock = fakeClock();
  const outcomes = [true, false, true, true];
  let calls = 0;
  const result = await waitUntilReady(parseArgs(["--onion", NODE], {}), {
    now: clock.now, sleep: clock.sleep, log: () => {},
    dial: async () => { const ok = outcomes[calls++]; if (!ok) throw new Error("timeout"); return true; },
  });
  assert.equal(result.ready, true);
  assert.equal(calls, 4);
  assert.equal(result.rounds, 4);
}

// 3. Bounded: an onion that never answers ends in a timeout with a message that says what and why.
{
  const clock = fakeClock();
  const short = parseArgs(["--onion", NODE, "--heartbeat-metrics", "http://127.0.0.1:9103/metrics", "--timeout", "60", "--interval", "10"], {});
  const result = await waitUntilReady(short, {
    now: clock.now, sleep: clock.sleep, log: () => {},
    dial: async () => { throw new Error("Proxy connection timed out"); },
    fetchMetrics: async () => metrics({ last: 1_700_000_050, total: 2, accepted: 2 }),
  });
  assert.equal(result.ready, false);
  assert.ok(result.elapsedSec <= 60, "never waits past the limit");
  assert.equal(clock.sleeps.length, 6);
  const message = timeoutMessage(short, result);
  assert.match(message, /^NOT READY after 60s \(limit 60s\)/);
  assert.match(message, /onion aaaaaaaa… port 80 accepts a connection through Tor: Proxy connection timed out/);
  assert.equal(/heartbeat accepted/.test(message), false, "checks that held are not listed as failures");
  assert.match(message, /Do not start the fleet e2e or roll the next host/);
}

// 4. A slow dial cannot stretch the wait far past the limit: the loop stops when the next round
//    would start after the deadline.
{
  const clock = fakeClock();
  const result = await waitUntilReady(parseArgs(["--onion", NODE, "--timeout", "100", "--interval", "10", "--connect-timeout", "45"], {}), {
    now: clock.now, sleep: clock.sleep, log: () => {},
    dial: async () => { clock.advance(45_000); throw new Error("timeout"); },
  });
  assert.equal(result.ready, false);
  assert.ok(result.elapsedSec <= 100 + 45, `bounded by limit plus one dial (${result.elapsedSec}s)`);
}

// 5. Elder listing from another vantage point: verified directory must list every onion.
{
  const clock = fakeClock();
  const other = onion("b");
  let fetches = 0;
  const listing = parseArgs(["--onion", NODE, "--onion", other, "--elder", `${ELDER}=${SIGNER}`, "--consecutive", "1"], {});
  const result = await waitUntilReady(listing, {
    now: clock.now, sleep: clock.sleep, log: () => {},
    dial: async () => true,
    fetchDirectory: async (elder, opts) => {
      assert.equal(elder.onion, ELDER);
      assert.equal(opts.attempts, 1, "one bounded fetch per round; the loop is the retry");
      fetches += 1;
      return { gateways: fetches < 3 ? [{ onion: NODE }] : [{ onion: NODE }, { onion: other }] };
    },
    verify: (directory, signer) => { assert.equal(signer, SIGNER); return { ok: true }; },
  });
  assert.equal(result.ready, true);
  assert.equal(fetches, 3);

  const forged = await waitUntilReady({ ...listing, timeoutSec: 20 }, {
    now: clock.now, sleep: clock.sleep, log: () => {},
    dial: async () => true,
    fetchDirectory: async () => ({ gateways: [{ onion: NODE }, { onion: other }] }),
    verify: () => ({ ok: false, reason: "bad-signature:aaaaaaaa" }),
  });
  assert.equal(forged.ready, false, "an unverified directory never counts as a listing");
  assert.match(forged.checks.find((check) => check.kind === "elder").detail, /failed verification \(bad-signature\)/);
}

// 6. --expect-nodes: the caller knows only the Elders (the Lab before a fleet e2e). Every Elder
//    must list enough nodes, and every listed node must accept connections.
{
  const clock = fakeClock();
  const [n1, n2, n3] = [onion("b"), onion("c"), onion("d")];
  const elder2 = onion("f");
  const discover = parseArgs(["--elder", `${ELDER}=${SIGNER}`, "--elder", `${elder2}=${SIGNER}`, "--expect-nodes", "3", "--consecutive", "1"], {});
  let round = 0;
  const dialed = [];
  const result = await waitUntilReady(discover, {
    now: clock.now, log: () => {},
    verify: () => ({ ok: true }),
    // The second Elder hears the third node two rounds late.
    fetchDirectory: async (elder) => ({ gateways: (elder.onion === ELDER || round >= 3 ? [n1, n2, n3] : [n1, n2]).map((o) => ({ onion: o })) }),
    dial: async (target) => { dialed.push(target.onion); if (target.onion === n3 && round < 4) throw new Error("timeout"); return true; },
    sleep: async (ms) => { round += 1; await clock.sleep(ms); },
  });
  assert.equal(result.ready, true);
  assert.deepEqual([...new Set(dialed)].sort(), [n1, n2, n3], "every node an Elder lists is dialed, once per node");
  assert.equal(result.checks.filter((check) => check.kind === "onion").length, 3);
  assert.ok(result.rounds >= 5, "not ready before the late node answers and the late Elder lists it");

  const tooFew = await waitUntilReady({ ...discover, timeoutSec: 30 }, {
    now: clock.now, sleep: clock.sleep, log: () => {},
    verify: () => ({ ok: true }),
    fetchDirectory: async () => ({ gateways: [{ onion: n1 }, { onion: n2 }] }),
    dial: async () => true,
  });
  assert.equal(tooFew.ready, false, "two reachable nodes do not satisfy --expect-nodes 3");
  assert.match(timeoutMessage(discover, tooFew), /lists at least 3 nodes: lists 2 of the 3 expected nodes/);
  assert.throws(() => parseArgs(["--expect-nodes", "3"], {}), /needs at least one --elder/);
}

// --- real dial + CLI against a local SOCKS5 stub ------------------------------------------------
// The stub speaks enough SOCKS5 for the `socks` client (username/password auth, CONNECT to a
// domain). It answers "host unreachable" for the first `refuse` requests, then succeeds.
function socksStub({ refuse }) {
  const seen = { requests: 0, users: new Set(), hosts: new Set() };
  const server = net.createServer((socket) => {
    let stage = "greeting";
    let buffer = Buffer.alloc(0);
    socket.on("error", () => {});
    socket.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (stage === "greeting" && buffer.length >= 2 && buffer.length >= 2 + buffer[1]) {
        buffer = buffer.subarray(2 + buffer[1]);
        socket.write(Buffer.from([5, 2]));
        stage = "auth";
      }
      if (stage === "auth" && buffer.length >= 2 && buffer.length >= 2 + buffer[1] + 1) {
        const userLength = buffer[1];
        const passLength = buffer[2 + userLength];
        if (buffer.length < 3 + userLength + passLength) return;
        seen.users.add(buffer.subarray(2, 2 + userLength).toString());
        buffer = buffer.subarray(3 + userLength + passLength);
        socket.write(Buffer.from([1, 0]));
        stage = "request";
      }
      if (stage === "request" && buffer.length >= 5 && buffer.length >= 7 + buffer[4]) {
        seen.hosts.add(buffer.subarray(5, 5 + buffer[4]).toString());
        seen.requests += 1;
        const reply = seen.requests <= refuse ? 4 : 0;
        socket.write(Buffer.from([5, reply, 0, 1, 0, 0, 0, 0, 0, 0]));
        if (reply !== 0) socket.end();
        stage = "done";
      }
    });
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({ server, port: server.address().port, seen })));
}

function cli(args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [join(HERE, "onion-ready.mjs"), ...args], { env: { PATH: process.env.PATH } });
    let stdout = "", stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}

{
  let serveFresh = false;
  const metricsServer = http.createServer((req, res) => {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end(serveFresh ? metrics({ last: Math.floor(Date.now() / 1000), total: 2, accepted: 2 }) : metrics({ last: 0, total: 2, accepted: 0 }));
    serveFresh = true; // the first poll sees "not accepted yet", later polls see an accepted announce
  });
  await new Promise((resolve) => metricsServer.listen(0, "127.0.0.1", resolve));
  const metricsUrl = `http://127.0.0.1:${metricsServer.address().port}/metrics`;
  const since = String(Math.floor(Date.now() / 1000) - 5);

  const recovering = await socksStub({ refuse: 2 });
  const ready = await cli(["--onion", NODE, "--heartbeat-metrics", metricsUrl, "--since", since, "--tor-port", String(recovering.port), "--interval", "1", "--timeout", "30", "--connect-timeout", "5"]);
  assert.equal(ready.status, 0, ready.stderr);
  assert.match(ready.stdout, /waiting \(\d+s of 30s\): onion aaaaaaaa… port 80 accepts a connection through Tor \[Socks5 proxy rejected connection/);
  assert.match(ready.stdout, /ready after \d+s/);
  assert.equal(recovering.seen.requests, 4, "two refused dials, then two accepted in a row");
  assert.equal(recovering.seen.users.size, 4, "every dial uses fresh SOCKS credentials (its own circuit)");
  assert.deepEqual([...recovering.seen.hosts], [NODE]);
  recovering.server.close();

  const dead = await socksStub({ refuse: Infinity });
  const timedOut = await cli(["--onion", NODE, "--tor-port", String(dead.port), "--interval", "1", "--timeout", "3", "--connect-timeout", "2"]);
  assert.equal(timedOut.status, 1);
  assert.match(timedOut.stderr, /^NOT READY after \ds \(limit 3s\)/);
  assert.match(timedOut.stderr, /onion aaaaaaaa… port 80 accepts a connection through Tor: /);
  assert.equal((timedOut.stdout + timedOut.stderr).includes(NODE), false);
  dead.server.close();
  metricsServer.close();

  const dryRun = await cli(["--onion", NODE, "--heartbeat-metrics", metricsUrl, "--tor-port", "1", "--dry-run"]);
  assert.equal(dryRun.status, 0);
  assert.match(dryRun.stdout, /would wait up to 600s/);
  const usage = await cli(["--onion", "not-an-onion"]);
  assert.equal(usage.status, 2);
  assert.match(usage.stderr, /onion-ready: --onion must be a v3 onion address/);
}

console.log("PASS: onion-ready selftest");
