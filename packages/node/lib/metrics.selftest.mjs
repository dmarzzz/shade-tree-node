// Self-test for the zero-dep metrics registry (T-MON-2).
//
//   node packages/node/lib/metrics.selftest.mjs
//
// Asserts: counters increment (per label set), the histogram buckets cumulatively with a
// correct _sum/_count and a +Inf bucket, gauges read a collect() callback at render time,
// label VALUES are escaped, and render() emits valid Prometheus exposition text (HELP/TYPE
// + series lines). Finally it spins the REAL bootnode http server in-process and proves
// operator metrics are absent from its Tor-mapped listener, but present on a separate
// loopback listener with private/no-store health and scrape responses.

import { request as httpRequest } from "node:http";
import {
  makeRegistry,
  makeMetricsServer,
  isLoopbackMetricsHost,
  isLoopbackMetricsRequestHost,
  listenMetrics,
  safeMetricsPort,
  registry as processMetrics,
  DEFAULT_LATENCY_BUCKETS,
} from "./metrics.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

function throws(fn, pattern, msg) {
  let error = null;
  try { fn(); } catch (e) { error = e; }
  ok(Boolean(error) && (!pattern || pattern.test(String(error.message))), msg);
}

// Pull `name{labels} value` lines out of exposition text into a lookup keyed by the full
// `name{labels}` (label suffix included), so we can assert exact values.
function parseExposition(text) {
  const help = new Map(), type = new Map(), values = new Map();
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    let m;
    if ((m = line.match(/^# HELP (\S+) (.*)$/))) { help.set(m[1], m[2]); continue; }
    if ((m = line.match(/^# TYPE (\S+) (\w+)$/))) { type.set(m[1], m[2]); continue; }
    if (line.startsWith("#")) continue;
    // metricSeries value  (value is the last whitespace-separated token)
    const sp = line.lastIndexOf(" ");
    if (sp === -1) { ok(false, `unparseable exposition line: ${JSON.stringify(line)}`); continue; }
    values.set(line.slice(0, sp), line.slice(sp + 1));
  }
  return { help, type, values };
}

function getWithHost(url, host) {
  return new Promise((resolve, reject) => {
    const req = httpRequest(url, { method: "GET", headers: { host } }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, text: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    req.end();
  });
}

async function main() {
  // === counters ============================================================
  console.log("counters:");
  {
    const reg = makeRegistry();
    const c = reg.counter("shade_tree_test_requests_total", "help text");
    c.inc({ result: "pass" });
    c.inc({ result: "pass" });
    c.inc({ result: "drop", reason: "bad-target" });
    c.inc({ result: "drop", reason: "bad-target" }, 3); // inc by N
    const { help, type, values } = parseExposition(reg.render());
    ok(help.get("shade_tree_test_requests_total") === "help text", "counter emits # HELP");
    ok(type.get("shade_tree_test_requests_total") === "counter", "counter emits # TYPE counter");
    ok(values.get('shade_tree_test_requests_total{result="pass"}') === "2", "counter accumulates per label set (pass=2)");
    // labels always render in sorted key order (reason before result), regardless of inc order
    ok(values.get('shade_tree_test_requests_total{reason="bad-target",result="drop"}') === "4", "counter inc-by-N + sorted labels (drop=4)");
    // label key order is normalized: {reason,result} and {result,reason} collapse to one series
    const c2 = reg.counter("shade_tree_test_requests_total");
    c2.inc({ result: "drop", reason: "bad-target" });
    ok(parseExposition(reg.render()).values.get('shade_tree_test_requests_total{reason="bad-target",result="drop"}') === "5",
      "label order normalized (same series regardless of key order)");
  }

  // === histogram ===========================================================
  console.log("\nhistogram:");
  {
    const reg = makeRegistry();
    const h = reg.histogram("shade_tree_test_latency_seconds", "latency", [0.1, 0.5, 1]);
    for (const v of [0.05, 0.2, 0.2, 3]) h.observe(v); // <=0.1:1, <=0.5:3, <=1:3, +Inf:4
    const { type, values } = parseExposition(reg.render());
    ok(type.get("shade_tree_test_latency_seconds") === "histogram", "histogram emits # TYPE histogram");
    ok(values.get('shade_tree_test_latency_seconds_bucket{le="0.1"}') === "1", "bucket le=0.1 cumulative == 1");
    ok(values.get('shade_tree_test_latency_seconds_bucket{le="0.5"}') === "3", "bucket le=0.5 cumulative == 3");
    ok(values.get('shade_tree_test_latency_seconds_bucket{le="1"}') === "3", "bucket le=1 cumulative == 3");
    ok(values.get('shade_tree_test_latency_seconds_bucket{le="+Inf"}') === "4", "bucket le=+Inf == total count 4");
    ok(values.get("shade_tree_test_latency_seconds_count") === "4", "_count == 4");
    ok(Math.abs(Number(values.get("shade_tree_test_latency_seconds_sum")) - 3.45) < 1e-9, "_sum == 3.45");
    // buckets are cumulative and non-decreasing
    const b = ["0.1", "0.5", "1"].map((le) => Number(values.get(`shade_tree_test_latency_seconds_bucket{le="${le}"}`)));
    ok(b[0] <= b[1] && b[1] <= b[2], "buckets are monotonically non-decreasing (cumulative)");
    ok(DEFAULT_LATENCY_BUCKETS.length > 0 && DEFAULT_LATENCY_BUCKETS.every((x, i, a) => i === 0 || a[i - 1] < x), "default buckets exported, sorted ascending");
  }

  // === gauge (collect callback) ===========================================
  console.log("\ngauge:");
  {
    const reg = makeRegistry();
    let backing = 0;
    reg.gauge("shade_tree_test_live", "live things").setCollect(() => backing);
    ok(parseExposition(reg.render()).values.get("shade_tree_test_live") === "0", "gauge reads collect() at render (0)");
    backing = 7;
    ok(parseExposition(reg.render()).values.get("shade_tree_test_live") === "7", "gauge re-reads collect() at each render (7)");
    // explicit .set also works and coexists with labels
    const reg2 = makeRegistry();
    reg2.gauge("shade_tree_test_set", "set gauge").set(42, { kind: "a" });
    ok(parseExposition(reg2.render()).values.get('shade_tree_test_set{kind="a"}') === "42", "gauge .set(value, labels)");
  }

  // === label value escaping ===============================================
  console.log("\nescaping:");
  {
    const reg = makeRegistry();
    reg.counter("shade_tree_test_escaped_total", "esc").inc({ reason: 'a"b\\c\nd' });
    const text = reg.render();
    // The rendered line must escape " \ and newline in the VALUE.
    ok(text.includes('shade_tree_test_escaped_total{reason="a\\"b\\\\c\\nd"} 1'), "label value escapes \\\" \\\\ and newline");
    // ...and stays on a single physical line (no raw newline leaked into output).
    const escLine = text.split("\n").find((l) => l.startsWith("shade_tree_test_escaped_total{"));
    ok(escLine && !escLine.includes("\t") && escLine.endsWith(" 1"), "escaped series stays one physical line");
  }

  // === exposition shape ====================================================
  console.log("\nexposition shape:");
  {
    const reg = makeRegistry();
    reg.counter("shade_tree_test_a_total", "a").inc();
    reg.histogram("shade_tree_test_b_seconds", "b", [1]).observe(0.5);
    const text = reg.render();
    ok(text.endsWith("\n"), "output ends with a trailing newline");
    // Every non-comment, non-empty line is `<series> <value>` with a numeric value.
    let allNumeric = true;
    for (const line of text.split("\n")) {
      if (!line || line.startsWith("#")) continue;
      const val = line.slice(line.lastIndexOf(" ") + 1);
      if (!/^(\+Inf|-Inf|NaN|-?\d+(\.\d+)?([eE][+-]?\d+)?)$/.test(val)) { allNumeric = false; break; }
    }
    ok(allNumeric, "every metric line ends in a valid numeric/±Inf value");
    // HELP precedes TYPE precedes samples for a metric.
    const iHelp = text.indexOf("# HELP shade_tree_test_a_total");
    const iType = text.indexOf("# TYPE shade_tree_test_a_total");
    const iSample = text.indexOf("\nshade_tree_test_a_total ");
    ok(iHelp !== -1 && iType > iHelp && iSample > iType, "HELP then TYPE then sample ordering");
  }

  // === defensive input handling ===========================================
  console.log("\ndefensive input handling:");
  {
    const reg = makeRegistry();
    const c = reg.counter("shade_tree_test_finite_total", "finite counter");
    c.inc({}, 2).inc({}, -1).inc({}, NaN).inc({}, Infinity);
    const g = reg.gauge("shade_tree_test_finite_gauge", "finite gauge");
    g.set(4).set(NaN).set(Infinity);
    const h = reg.histogram("shade_tree_test_finite_seconds", "finite histogram", [1]);
    h.observe(0.25).observe(-1).observe(NaN).observe(Infinity);
    const { values } = parseExposition(reg.render());
    ok(values.get("shade_tree_test_finite_total") === "2", "counter ignores negative and non-finite increments");
    ok(values.get("shade_tree_test_finite_gauge") === "4", "gauge ignores non-finite values without replacing its last good sample");
    ok(values.get("shade_tree_test_finite_seconds_count") === "1", "histogram ignores negative and non-finite observations");
    ok(values.get("shade_tree_test_finite_seconds_sum") === "0.25", "ignored histogram observations do not alter the sum");

    throws(() => reg.counter("9invalid_metric"), /invalid metric name/, "invalid metric names are rejected");
    throws(() => reg.counter("shade_tree_valid_total").inc({ "bad-label": "x" }), /invalid metric label name/,
      "invalid label names are rejected");
    throws(() => reg.gauge("shade_tree_test_finite_total"), /already registered as counter/,
      "re-registering a metric with a different type is rejected");
  }

  // === series ceiling ======================================================
  console.log("\nseries ceiling:");
  {
    const reg = makeRegistry({ maxSeries: 2 });
    const c = reg.counter("shade_tree_test_bounded_total", "bounded");
    c.inc({ reason: "one" }).inc({ reason: "two" }).inc({ reason: "three" });
    c.inc({ reason: "one" }, 2); // existing series remain writable after the ceiling
    const { values } = parseExposition(reg.render());
    ok(values.get('shade_tree_test_bounded_total{reason="one"}') === "3", "existing series can still be updated at the ceiling");
    ok(values.get('shade_tree_test_bounded_total{reason="two"}') === "1", "series below the ceiling are retained");
    ok(!values.has('shade_tree_test_bounded_total{reason="three"}'), "new series beyond the ceiling are dropped");
    ok(reg.droppedSeries() === 1, "registry reports dropped over-ceiling series");
  }

  // === collector isolation =================================================
  console.log("\ncollector isolation:");
  {
    const reg = makeRegistry();
    reg.gauge("shade_tree_test_broken_collect", "broken collector").setCollect(() => { throw new Error("collector sentinel"); });
    reg.counter("shade_tree_test_after_collect_total", "healthy neighbor").inc();
    let text = "", threw = false;
    try { text = reg.render(); } catch { threw = true; }
    ok(!threw, "a throwing gauge collector cannot fail a scrape");
    ok(text.includes("shade_tree_test_after_collect_total 1"), "other metrics still render after a collector throws");
    ok(!text.includes("collector sentinel"), "collector exception text is never exposed in the scrape");
  }

  // === listener boundary ===================================================
  console.log("\nlistener boundary:");
  {
    ok(isLoopbackMetricsHost("127.0.0.1") && isLoopbackMetricsHost("::1") && isLoopbackMetricsHost("LOCALHOST"),
      "loopback metrics hosts are recognized");
    ok(!isLoopbackMetricsHost("0.0.0.0") && !isLoopbackMetricsHost("192.0.2.1"),
      "wildcard and public interfaces are not recognized as loopback");
    ok(isLoopbackMetricsRequestHost("127.0.0.1:9100") && isLoopbackMetricsRequestHost("localhost") && isLoopbackMetricsRequestHost("[::1]:9100"),
      "literal loopback HTTP Host values are accepted");
    ok(!isLoopbackMetricsRequestHost("metrics.attacker.test") && !isLoopbackMetricsRequestHost("localhost.attacker.test") && !isLoopbackMetricsRequestHost(""),
      "DNS-rebinding and missing HTTP Host values are rejected");
    throws(() => listenMetrics({ port: 9100, host: "0.0.0.0", reg: makeRegistry() }), /must bind loopback/,
      "metrics listener refuses a wildcard bind");
    ok(safeMetricsPort(undefined, [["service", 8877]]) === 0 && safeMetricsPort("9100", [["service", 8877]]) === 9100,
      "metrics ports normalize off and a distinct listener");
    throws(() => safeMetricsPort("8877", [["Elder Tree backend", 8877]]), /collides with Elder Tree backend/,
      "metrics cannot reuse a Tor-mapped protocol port");
    throws(() => safeMetricsPort("not-a-port"), /integer in 0\.\.65535/,
      "malformed direct-run metrics ports fail closed");
  }

  // === Elder/public boundary + operator metrics end-to-end =================
  console.log("\nElder/public boundary + loopback operator metrics (in-process):");
  {
    const { mkdtemp, rm } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { generateOnionIdentity } = await import("../bootnode/keygen.mjs");
    const { buildAnnounce } = await import("../bootnode/announce.mjs");
    const { makeRegistry: makeBootRegistry, makeServer, loadOrMintSigner } = await import("../bootnode/server.mjs");
    const { MockStakeVerifier } = await import("./gateway-registry.mjs");

    const work = await mkdtemp(join(tmpdir(), "shade-tree-metrics-"));
    let server = null, metricsServer = null;
    try {
      const g1 = await generateOnionIdentity(join(work, "g1"), { label: "g1" });
      const signer = await loadOrMintSigner(join(work, "signer.key"));
      const reg = makeBootRegistry({ signer, stake: MockStakeVerifier({}), admission: "open", ttlSec: 900, minReannounceSec: 0 });
      server = makeServer(reg, { signerPub: signer.pub });
      await new Promise((r) => server.listen(0, "127.0.0.1", r));
      const base = `http://127.0.0.1:${server.address().port}`;

      let ready = false;
      metricsServer = makeMetricsServer(processMetrics, { live: () => true, ready: () => ready });
      await new Promise((r) => metricsServer.listen(0, "127.0.0.1", r));
      const metricsBase = `http://127.0.0.1:${metricsServer.address().port}`;

      // Drive the decision points: one accepted announce, one forged signature, two malformed
      // fields whose raw values must never become metric labels, and one directory fetch.
      const good = buildAnnounce({ onion: g1.onion, weight: 100, onionSeedHex: g1.seed });
      await fetch(base + "/announce", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(good) });
      const bad = buildAnnounce({ onion: g1.onion, weight: 100, onionSeedHex: g1.seed });
      bad.onionSig = bad.onionSig.replace(/.$/, (c) => (c === "0" ? "1" : "0"));
      await fetch(base + "/announce", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(bad) });
      const VERSION_SENTINEL = "UNTRUSTED_VERSION_METRIC_SENTINEL";
      const badVersion = { ...good, v: VERSION_SENTINEL };
      const badVersionRes = await fetch(base + "/announce", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(badVersion) });
      ok(badVersionRes.status === 400, "adversarial version value is rejected");
      const TS_SENTINEL = "UNTRUSTED_TIMESTAMP_METRIC_SENTINEL";
      const staleTs = { ...good, nonce: "stale-metric-sentinel", ts: TS_SENTINEL };
      const staleTsRes = await fetch(base + "/announce", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(staleTs) });
      ok(staleTsRes.status === 400, "adversarial timestamp value is rejected");
      await fetch(base + "/directory");

      // The Elder listener is mapped into Tor. Exact operator metrics must not exist there.
      const publicRes = await fetch(base + "/metrics");
      ok(publicRes.status === 404, "GET /metrics on the Elder listener -> 404");
      const publicText = await publicRes.text();
      ok(!publicText.includes("shade_tree_"), "Elder 404 response does not leak metric exposition");

      // The distinct operator listener carries the scrape and health endpoints.
      const res = await fetch(metricsBase + "/metrics");
      ok(res.status === 200, "GET /metrics on the operator listener -> 200");
      ok((res.headers.get("content-type") || "").includes("text/plain; version=0.0.4"), "/metrics uses Prometheus text content type");
      ok(res.headers.get("cache-control") === "private, no-store", "/metrics is private and never cacheable");
      ok(res.headers.get("x-content-type-options") === "nosniff", "/metrics disables content sniffing");
      ok(!res.headers.has("access-control-allow-origin"), "/metrics does not grant browser CORS access");
      const text = await res.text();
      const { type, values } = parseExposition(text);
      ok(type.get("shade_tree_bootnode_announces_total") === "counter", "bootnode exposes announces counter");
      ok(values.get('shade_tree_bootnode_announces_total{result="accepted"}') === "1", "one accepted announce counted");
      ok(values.get('shade_tree_bootnode_announces_total{reason="bad-onion-sig",result="rejected"}') === "1", "one rejected announce counted by reason");
      ok(values.get('shade_tree_bootnode_announces_total{reason="bad-version",result="rejected"}') === "1", "bad version uses a closed reason label");
      ok(values.get('shade_tree_bootnode_announces_total{reason="stale-ts",result="rejected"}') === "1", "stale timestamp uses a closed reason label");
      ok(!text.includes(VERSION_SENTINEL) && !text.includes(TS_SENTINEL), "raw attacker-controlled rejection values never enter metrics");
      ok(Number(values.get("shade_tree_bootnode_directory_fetches_total")) >= 1, "directory fetch counted");
      ok(values.get("shade_tree_bootnode_live_gateways") === "1", "live-gateways gauge reflects the one accepted onion");

      const live = await fetch(metricsBase + "/livez");
      ok(live.status === 200 && await live.text() === "ok\n", "GET /livez reports a live process");
      ok(live.headers.get("cache-control") === "private, no-store", "/livez is private and never cacheable");
      const notReady = await fetch(metricsBase + "/readyz");
      ok(notReady.status === 503 && await notReady.text() === "not ready\n", "GET /readyz returns 503 until the role is ready");
      ready = true;
      const nowReady = await fetch(metricsBase + "/readyz");
      ok(nowReady.status === 200 && await nowReady.text() === "ok\n", "GET /readyz returns 200 after readiness");
      const root = await fetch(metricsBase + "/");
      ok(root.status === 404 && !((await root.text()).includes("shade_tree_")), "operator listener exposes no index or accidental metric route");
      const rebound = await getWithHost(metricsBase + "/metrics", "metrics.attacker.test");
      ok(rebound.status === 421 && !rebound.text.includes("shade_tree_"), "attacker-controlled Host cannot read loopback metrics through DNS rebinding");
      ok(!rebound.headers["access-control-allow-origin"], "rejected Host response also grants no CORS access");
    } finally {
      if (metricsServer?.listening) await new Promise((r) => metricsServer.close(r));
      if (server?.listening) await new Promise((r) => server.close(r));
      await rm(work, { recursive: true, force: true });
    }
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: metrics selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
