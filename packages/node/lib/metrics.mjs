// A tiny, zero-dependency, in-process metrics registry (T-MON-2).
//
// Prometheus' text exposition format is just strings, so we do not pull in a client
// library: this module holds counters, gauges, and fixed-bucket histograms in memory and
// renders them as `# HELP` / `# TYPE` / `name{labels} value` lines.
//
// IMPORTING THIS MODULE INSTALLS NOTHING. It opens no socket and starts no server — it is
// pure in-process state. `serveMetrics()` (below) creates an HTTP server ONLY when called,
// and the gateway/bootnode call it only from main()/behind an env flag, so importing the
// registry never changes runtime behavior or binds a port.
//
// Design notes / correctness:
//   - Counters are monotonic (inc only). Gauges can be set() or fed by a collect() callback
//     (used for "current live size" style gauges read at scrape time).
//   - Histograms use cumulative `le` buckets plus `_sum` / `_count`, exactly as Prometheus
//     expects; +Inf is always emitted.
//   - Metric and label names are validated. Values are escaped and length-bounded.
//   - Every metric has a defensive series ceiling. Call sites must still use closed label enums;
//     the ceiling is the last line of defense against accidental cardinality growth.
//   - render() output is deterministic (metrics and label sets are emitted in sorted order)
//     so tests can assert on it byte-stably.

import http from "node:http";
import { buildCommit } from "./build-info.mjs"; // for makeMetricsServer only; importing never binds a port.

// Default latency buckets, in SECONDS (Prometheus convention: base-unit seconds).
export const DEFAULT_LATENCY_BUCKETS = [
  0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
];
export const DEFAULT_MAX_SERIES = 128;
const METRIC_NAME = /^[a-zA-Z_:][a-zA-Z0-9_:]*$/;
const LABEL_NAME = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
const MAX_LABEL_VALUE = 160;

// Escape a label VALUE per the exposition format.
function escapeLabelValue(v) {
  const value = String(v);
  const bounded = value.length <= MAX_LABEL_VALUE ? value : value.slice(0, MAX_LABEL_VALUE) + "[truncated]";
  return bounded.replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/"/g, '\\"');
}

// Deterministic canonical key + rendered `{a="1",b="2"}` suffix for a label set.
// Keys are sorted so {a,b} and {b,a} collapse to one series.
function labelParts(labels) {
  const keys = Object.keys(labels || {}).filter((k) => labels[k] !== undefined && labels[k] !== null).sort();
  for (const key of keys) if (!LABEL_NAME.test(key)) throw new Error(`invalid metric label name: ${key}`);
  if (keys.length === 0) return { key: "", suffix: "" };
  const inner = keys.map((k) => `${k}="${escapeLabelValue(labels[k])}"`).join(",");
  return { key: inner, suffix: `{${inner}}` };
}

export function makeRegistry({ maxSeries = DEFAULT_MAX_SERIES } = {}) {
  // name -> { type, help, ... }
  const metrics = new Map();

  function getOrCreate(name, type, help, extra = {}) {
    if (!METRIC_NAME.test(String(name))) throw new Error(`invalid metric name: ${name}`);
    let m = metrics.get(name);
    if (!m) {
      m = { name, type, help, series: new Map(), droppedSeries: 0, ...extra };
      metrics.set(name, m);
    } else if (m.type !== type) {
      throw new Error(`metric ${name} already registered as ${m.type}, not ${type}`);
    } else if (help && !m.help) {
      m.help = help;
    }
    return m;
  }

  function canCreateSeries(m, key) {
    if (m.series.has(key)) return true;
    if (m.series.size < maxSeries) return true;
    m.droppedSeries += 1;
    return false;
  }

  function counter(name, help) {
    const m = getOrCreate(name, "counter", help);
    return {
      inc(labels = {}, n = 1) {
        n = Number(n);
        if (!Number.isFinite(n) || n < 0) return this;
        const { key, suffix } = labelParts(labels);
        const cur = m.series.get(key);
        if (cur) cur.value += n;
        else if (canCreateSeries(m, key)) m.series.set(key, { suffix, value: n });
        return this;
      },
    };
  }

  // A gauge can be driven two ways:
  //   .set(value, labels)  -- explicit point-in-time value, and/or
  //   collect: () => number -- evaluated at render() time (for "current size" gauges).
  function gauge(name, help, collect) {
    const m = getOrCreate(name, "gauge", help, { collect });
    if (collect) m.collect = collect;
    return {
      set(value, labels = {}) {
        value = Number(value);
        if (!Number.isFinite(value)) return this;
        const { key, suffix } = labelParts(labels);
        if (canCreateSeries(m, key)) m.series.set(key, { suffix, value });
        return this;
      },
      setCollect(fn) { m.collect = fn; return this; },
    };
  }

  function histogram(name, help, buckets = DEFAULT_LATENCY_BUCKETS) {
    // Sorted, de-duplicated bucket upper bounds (finite; +Inf is implicit at render).
    const bounds = [...new Set(buckets)].filter((b) => Number.isFinite(b)).sort((a, b) => a - b);
    const m = getOrCreate(name, "histogram", help, { bounds });
    return {
      observe(value, labels = {}) {
        value = Number(value);
        if (!Number.isFinite(value) || value < 0) return this;
        const { key, suffix } = labelParts(labels);
        let h = m.series.get(key);
        if (!h) {
          if (!canCreateSeries(m, key)) return this;
          h = { suffix, labels: { ...labels }, counts: new Array(bounds.length).fill(0), sum: 0, count: 0 };
          m.series.set(key, h);
        }
        h.count += 1;
        h.sum += value;
        for (let i = 0; i < bounds.length; i++) if (value <= bounds[i]) h.counts[i] += 1; // cumulative
        return this;
      },
    };
  }

  function fmtNum(v) {
    if (v === Infinity) return "+Inf";
    if (v === -Infinity) return "-Inf";
    if (Number.isNaN(v)) return "NaN";
    return String(v);
  }

  // Render every metric in Prometheus text exposition format.
  function render() {
    const out = [];
    for (const name of [...metrics.keys()].sort()) {
      const m = metrics.get(name);
      if (m.help) out.push(`# HELP ${name} ${String(m.help).replace(/\\/g, "\\\\").replace(/\n/g, "\\n")}`);
      out.push(`# TYPE ${name} ${m.type}`);

      if (m.type === "histogram") {
        for (const key of [...m.series.keys()].sort()) {
          const h = m.series.get(key);
          const base = h.suffix; // e.g. `{route="x"}` or ``
          // cumulative bucket lines
          for (let i = 0; i < m.bounds.length; i++) {
            out.push(`${name}_bucket${withLe(base, fmtNum(m.bounds[i]))} ${h.counts[i]}`);
          }
          out.push(`${name}_bucket${withLe(base, "+Inf")} ${h.count}`);
          out.push(`${name}_sum${base} ${fmtNum(h.sum)}`);
          out.push(`${name}_count${base} ${h.count}`);
        }
        continue;
      }

      // counter / gauge
      const lines = new Map(); // key -> {suffix, value}
      for (const [key, s] of m.series) lines.set(key, s);
      if (m.type === "gauge" && typeof m.collect === "function") {
        try {
          const collected = m.collect();
          if (typeof collected === "number" && Number.isFinite(collected)) lines.set("", { suffix: "", value: collected });
          else if (Array.isArray(collected)) {
            for (const c of collected.slice(0, maxSeries)) {
              const { key, suffix } = labelParts(c.labels || {});
              if (Number.isFinite(Number(c.value))) lines.set(key, { suffix, value: Number(c.value) });
            }
          }
        } catch { /* one broken collector must not make the scrape endpoint fail */ }
      }
      for (const key of [...lines.keys()].sort()) {
        const s = lines.get(key);
        out.push(`${name}${s.suffix} ${fmtNum(s.value)}`);
      }
    }
    return out.join("\n") + "\n";
  }

  // Splice an `le="..."` label into an existing (possibly empty) label suffix.
  function withLe(suffix, le) {
    const lePair = `le="${le}"`;
    if (!suffix) return `{${lePair}}`;
    return `{${suffix.slice(1, -1)},${lePair}}`;
  }

  return {
    counter, gauge, histogram, render, size: () => metrics.size,
    droppedSeries: () => [...metrics.values()].reduce((sum, metric) => sum + metric.droppedSeries, 0),
    _metrics: metrics,
  };
}

// The process-wide shared registry. Modules register their metrics against this and the
// per-role /metrics endpoints render it.
export const registry = makeRegistry();

// Common process signals. Labels are fixed at startup and contain no node identity.
export function installRuntimeMetrics(reg = registry, { role = "service", version = "unknown", commit = buildCommit() } = {}) {
  const started = Date.now() / 1000;
  reg.gauge("shade_tree_build_info", "Build and role information (role, version, running commit); always 1.").set(1, { role, version, commit });
  reg.gauge("shade_tree_process_start_time_seconds", "Unix time when this process started.").set(started);
  reg.gauge("shade_tree_process_uptime_seconds", "Process uptime in seconds.").setCollect(() => Math.max(0, Date.now() / 1000 - started));
  reg.gauge("shade_tree_process_resident_memory_bytes", "Resident memory used by this process.").setCollect(() => process.memoryUsage().rss);
}

// Convenience: a loopback HTTP server that serves `render()` at GET /metrics. Creating the
// server does nothing until the caller invokes .listen(); importing this module never calls
// it. Kept here so the gateway (a TCP server, no http listener of its own) and any other
// non-HTTP role can expose metrics without duplicating transport. Zero external deps.
export function makeMetricsServer(reg = registry, { live = () => true, ready = live } = {}) {
  return http.createServer((req, res) => {
    const headers = { "cache-control": "private, no-store", "x-content-type-options": "nosniff" };
    // Loopback binding stops remote TCP clients, but a browser can still reach loopback and DNS
    // rebinding can preserve an attacker-controlled Host. Refuse every non-loopback Host before
    // rendering operational data. No CORS headers are emitted anywhere on this server.
    if (!isLoopbackMetricsRequestHost(req.headers.host)) {
      res.writeHead(421, { ...headers, "content-type": "text/plain; charset=utf-8" });
      res.end("misdirected request\n");
      return;
    }
    if (req.method === "GET" && req.url === "/metrics") {
      const body = reg.render();
      res.writeHead(200, { ...headers, "content-type": "text/plain; version=0.0.4; charset=utf-8", "content-length": Buffer.byteLength(body) });
      res.end(body);
    } else if (req.method === "GET" && (req.url === "/livez" || req.url === "/readyz")) {
      const ok = req.url === "/livez" ? Boolean(live()) : Boolean(ready());
      const body = ok ? "ok\n" : "not ready\n";
      res.writeHead(ok ? 200 : 503, { ...headers, "content-type": "text/plain; charset=utf-8", "content-length": Buffer.byteLength(body) });
      res.end(body);
    } else {
      res.writeHead(404, { ...headers, "content-type": "text/plain; charset=utf-8" });
      res.end("not found\n");
    }
  });
}

export function isLoopbackMetricsHost(host) {
  return ["127.0.0.1", "::1", "localhost"].includes(String(host || "").toLowerCase());
}

export function isLoopbackMetricsRequestHost(host) {
  const value = String(host || "").trim().toLowerCase();
  return /^(?:127\.0\.0\.1|localhost)(?::[0-9]{1,5})?$/.test(value)
    || /^\[::1\](?::[0-9]{1,5})?$/.test(value);
}

// Validate a metrics port before it is bound and keep it off any protocol listener in the
// same process. This check must run before listenMetrics(): otherwise metrics can win a bind
// race and occupy a port that Tor already maps to the intended protocol service.
export function safeMetricsPort(port, reserved = []) {
  const value = Number(port || 0);
  if (!Number.isInteger(value) || value < 0 || value > 65535) {
    throw new Error("metrics port must be an integer in 0..65535");
  }
  if (value === 0) return 0;
  for (const [label, raw] of reserved) {
    if (Number(raw) === value) throw new Error(`metrics port ${value} collides with ${label}`);
  }
  return value;
}

export function listenMetrics({ port, reg = registry, host = "127.0.0.1", live, ready } = {}) {
  const value = Number(port);
  if (!Number.isInteger(value) || value < 1 || value > 65535) throw new Error("metrics port must be an integer in 1..65535");
  if (!isLoopbackMetricsHost(host)) throw new Error("metrics must bind loopback (127.0.0.1, ::1, or localhost)");
  const server = makeMetricsServer(reg, { live, ready });
  server.listen(value, host);
  return server;
}
