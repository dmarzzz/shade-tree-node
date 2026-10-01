// In-process alerting for operators who run ONE node and no Prometheus (day-two ops).
//
// The node already exposes /metrics; monitoring/alerts.yml holds the fleet's Prometheus rules.
// This module evaluates the same conditions inside the process, from the local registry, and
// POSTs a small JSON document to a webhook on every transition (firing -> resolved), repeating a
// still-firing alert every `repeatMs` (4 h). Nothing is sent when no webhook is configured; a
// failing webhook is counted and logged (rate-limited), never thrown.
//
//   SHADE_TREE_ALERT_WEBHOOK         URL to POST to (unset = off). SHADENET_ALERT_WEBHOOK is an alias.
//   SHADE_TREE_ALERT_WEBHOOK_FORMAT  generic (default) | slack | discord | matrix
//   SHADE_TREE_ALERT_INSTANCE        instance label (default: os.hostname())
//   SHADE_TREE_ALERT_INTERVAL_MS     evaluation interval (default 30000; min 1000)
//   SHADE_TREE_ALERT_REPEAT_MS       re-send interval for a still-firing alert (default 4 h)
//
// Payloads (one alert per request):
//   generic: { source:"shadenet", version:1, role, instance, alert, severity, status, summary,
//              startsAt, ts }
//   slack:   { text }                                      (incoming webhook)
//   discord: { content }                                   (channel webhook)
//   matrix:  { text, msgtype:"m.text", ... generic fields } (hookshot generic webhook; template
//                                                           `{{ data.text }}`)
import os from "node:os";

export const DEFAULT_INTERVAL_MS = 30_000;
export const DEFAULT_REPEAT_MS = 4 * 60 * 60 * 1000;
const WEBHOOK_TIMEOUT_MS = 5000;
const FORMATS = new Set(["generic", "slack", "discord", "matrix"]);

export function alertConfig(env = process.env) {
  const url = (env.SHADE_TREE_ALERT_WEBHOOK || env.SHADENET_ALERT_WEBHOOK || "").trim();
  let format = String(env.SHADE_TREE_ALERT_WEBHOOK_FORMAT || "generic").trim().toLowerCase();
  if (!FORMATS.has(format)) format = "generic";
  const interval = Number(env.SHADE_TREE_ALERT_INTERVAL_MS);
  const repeat = Number(env.SHADE_TREE_ALERT_REPEAT_MS);
  return {
    url: url || null,
    format,
    instance: (env.SHADE_TREE_ALERT_INSTANCE || "").trim() || os.hostname(),
    intervalMs: Number.isFinite(interval) && interval >= 1000 ? Math.floor(interval) : DEFAULT_INTERVAL_MS,
    repeatMs: Number.isFinite(repeat) && repeat >= 60_000 ? Math.floor(repeat) : DEFAULT_REPEAT_MS,
  };
}

function line(event) {
  const where = event.instance ? ` (${event.instance})` : "";
  return `[shadenet] ${String(event.status).toUpperCase()} ${event.alert}${where}: ${event.summary}`;
}

export function formatPayload(format, event) {
  switch (format) {
    case "slack": return { text: line(event) };
    case "discord": return { content: line(event).slice(0, 1900) };
    case "matrix": return { text: line(event), msgtype: "m.text", ...event };
    default: return event;
  }
}

// POST one event. `fetchImpl` is injectable (tests). Resolves { ok, status } and never throws.
export function makeAlertSink({ url, format = "generic", role, instance, fetchImpl = globalThis.fetch, log = null, now = () => Date.now(), reg = null } = {}) {
  const counter = reg?.counter?.("shade_tree_alert_webhook_total", "Alert webhook deliveries by result=sent|failed.");
  let lastWarnAt = 0;
  const stats = { sent: 0, failed: 0, lastError: null };
  async function send(partial) {
    if (!url) return { ok: false, skipped: true };
    const event = {
      source: "shadenet", version: 1, role, instance,
      alert: partial.alert, severity: partial.severity || "warning", status: partial.status || "firing",
      summary: partial.summary || "", startsAt: partial.startsAt || new Date(now()).toISOString(), ts: new Date(now()).toISOString(),
    };
    const body = JSON.stringify(formatPayload(format, event));
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), WEBHOOK_TIMEOUT_MS);
    try {
      const res = await fetchImpl(url, { method: "POST", headers: { "content-type": "application/json" }, body, signal: ac.signal });
      if (!res.ok) throw new Error(`webhook HTTP ${res.status}`);
      stats.sent += 1;
      counter?.inc({ result: "sent" });
      return { ok: true, status: res.status };
    } catch (e) {
      stats.failed += 1;
      stats.lastError = String(e?.message || e).slice(0, 200);
      counter?.inc({ result: "failed" });
      if (log && now() - lastWarnAt > 60_000) {
        lastWarnAt = now();
        log.warn?.("alert webhook delivery failed", { event: "alert.webhook", alert: event.alert, errorType: e?.name || "Error" });
      }
      return { ok: false, error: stats.lastError };
    } finally { clearTimeout(t); }
  }
  return { send, stats, enabled: Boolean(url) };
}

// --- rules --------------------------------------------------------------------------------
// A rule: { name, severity, forTicks, when(ctx) -> false | summary string }. `ctx.values(name)`
// reads the registry; `ctx.now()` ms; `ctx.window` keeps per-rule history for rate rules.
const sum = (series) => series.reduce((s, x) => s + x.value, 0);
const first = (series) => (series.length ? series[0].value : null);

export function heartbeatRules({ intervalSec = 300 } = {}) {
  const stale = 3 * intervalSec;
  return [
    { name: "HeartbeatStale", severity: "critical", forTicks: 1, when: (c) => {
      const last = first(c.values("shade_tree_heartbeat_last_success_timestamp_seconds"));
      if (!last) return false;
      const age = Math.floor(c.now() / 1000 - last);
      return age > stale ? `no Elder Tree accepted a heartbeat for ${age}s (> ${stale}s); the node ages out of the canopy at the directory TTL` : false;
    } },
    { name: "HeartbeatNeverAccepted", severity: "critical", forTicks: 1, when: (c) => {
      const last = first(c.values("shade_tree_heartbeat_last_success_timestamp_seconds"));
      const up = first(c.values("shade_tree_process_uptime_seconds")) ?? 0;
      return (!last && up > stale) ? `no heartbeat accepted since start (${Math.floor(up)}s); check Tor, the Elder onion and the operator key` : false;
    } },
    { name: "EgressDown", severity: "critical", forTicks: 2, when: (c) => {
      const v = first(c.values("shade_tree_heartbeat_egress_check_up"));
      return v === 0 ? "local egress check failing; heartbeat skipped, node will age out" : false;
    } },
    { name: "ElderPartial", severity: "warning", forTicks: 2, when: (c) => {
      const total = first(c.values("shade_tree_heartbeat_elders_total")) ?? 0;
      const acc = first(c.values("shade_tree_heartbeat_elders_accepted")) ?? 0;
      return (total > 1 && acc > 0 && acc < total) ? `${acc} of ${total} Elder Trees accept this node's heartbeat` : false;
    } },
    { name: "Draining", severity: "info", forTicks: 1, when: (c) => (first(c.values("shade_tree_heartbeat_draining")) === 1 ? "node announced draining; clients deprioritise it until the flag is removed" : false) },
  ];
}

export function gatewayRules() {
  return [
    { name: "RootSourceDegraded", severity: "warning", forTicks: 2, when: (c) => {
      const bad = c.values("shade_tree_gateway_root_source_degraded").filter((s) => s.value > 0).map((s) => s.labels.source || "?");
      return bad.length ? `admission root source degraded: ${bad.join(",")} (serving the last good root)` : false;
    } },
    { name: "RpcEndpointFailing", severity: "warning", forTicks: 1, when: (c) => {
      const total = sum(c.values("shade_tree_rpc_failovers_total"));
      const w = c.window("rpc", total, 15 * 60 * 1000);
      return w.delta >= 3 ? `${w.delta} RPC failovers in the last 15 min (an endpoint in the record's list is failing)` : false;
    } },
    { name: "HighDropRate", severity: "warning", forTicks: 1, when: (c) => {
      const series = c.values("shade_tree_gateway_tunnels_total");
      const pass = sum(series.filter((s) => s.labels.result === "pass"));
      const drop = sum(series.filter((s) => s.labels.result === "drop"));
      const wp = c.window("pass", pass, 15 * 60 * 1000);
      const wd = c.window("drop", drop, 15 * 60 * 1000);
      const n = wp.delta + wd.delta;
      return (n >= 20 && wd.delta / n > 0.5) ? `${wd.delta} of ${n} tunnels dropped in 15 min (members failing the gate)` : false;
    } },
    { name: "Draining", severity: "info", forTicks: 1, when: (c) => (c.draining?.() ? "gateway draining (readyz 503); in-flight tunnels finish, new ones go elsewhere" : false) },
  ];
}

// --- evaluator ----------------------------------------------------------------------------
export function makeAlertEvaluator({ reg, sink, rules = [], intervalMs = DEFAULT_INTERVAL_MS, repeatMs = DEFAULT_REPEAT_MS, now = () => Date.now(), schedule = setInterval, clear = clearInterval, draining = null } = {}) {
  const state = new Map(); // name -> { trueTicks, firing, since, lastSent }
  const history = new Map(); // key -> [{ t, v }]
  const ctx = {
    values: (name) => (reg?.values ? reg.values(name) : []),
    now,
    draining,
    window(key, value, spanMs) {
      const t = now();
      const arr = history.get(key) || [];
      arr.push({ t, v: value });
      while (arr.length && arr[0].t < t - spanMs) arr.shift();
      history.set(key, arr);
      return { delta: Math.max(0, value - arr[0].v) };
    },
  };
  const sends = [];
  async function tick() {
    const t = now();
    for (const rule of rules) {
      let summary = false;
      try { summary = rule.when(ctx); } catch { summary = false; }
      const st = state.get(rule.name) || { trueTicks: 0, firing: false, since: null, lastSent: 0 };
      if (summary) {
        st.trueTicks += 1;
        if (!st.firing && st.trueTicks >= (rule.forTicks || 1)) {
          st.firing = true; st.since = t; st.lastSent = t;
          sends.push(sink.send({ alert: rule.name, severity: rule.severity, status: "firing", summary, startsAt: new Date(t).toISOString() }));
        } else if (st.firing && t - st.lastSent >= repeatMs) {
          st.lastSent = t;
          sends.push(sink.send({ alert: rule.name, severity: rule.severity, status: "firing", summary, startsAt: new Date(st.since).toISOString() }));
        }
      } else {
        st.trueTicks = 0;
        if (st.firing) {
          st.firing = false;
          sends.push(sink.send({ alert: rule.name, severity: rule.severity, status: "resolved", summary: "condition cleared", startsAt: new Date(st.since).toISOString() }));
          st.since = null;
        }
      }
      state.set(rule.name, st);
    }
    const pending = sends.splice(0);
    await Promise.allSettled(pending);
  }
  let timer = null;
  return {
    tick,
    start() { if (!sink?.enabled) return false; if (!timer) { timer = schedule(() => { tick().catch(() => {}); }, intervalMs); timer?.unref?.(); } return true; },
    stop() { if (timer) { clear(timer); timer = null; } },
    // One-off lifecycle notices (Started / Stopping). Sent as `info`, status `firing`, never repeated.
    lifecycle(alert, summary) { return sink?.enabled ? sink.send({ alert, severity: "info", status: "firing", summary }) : Promise.resolve({ ok: false, skipped: true }); },
    firing: () => [...state.entries()].filter(([, s]) => s.firing).map(([n]) => n),
  };
}

// Wire everything from env for a role. Returns a no-op evaluator when no webhook is set.
export function installAlerts({ role, reg, rules, env = process.env, log = null, draining = null, now = () => Date.now() } = {}) {
  const cfg = alertConfig(env);
  const sink = makeAlertSink({ url: cfg.url, format: cfg.format, role, instance: cfg.instance, log, reg, now });
  const evaluator = makeAlertEvaluator({ reg, sink, rules, intervalMs: cfg.intervalMs, repeatMs: cfg.repeatMs, now, draining });
  return { ...evaluator, enabled: sink.enabled, config: cfg, sink };
}
