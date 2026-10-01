// Webhook alerts without Prometheus (lib/alerts.mjs).
//   1. Config from env: off without a URL, alias SHADENET_ALERT_WEBHOOK, bounded intervals.
//   2. Sink: one POST per event, generic/slack/discord/matrix shapes, 5 s timeout, failures are
//      counted and never thrown, metric shade_tree_alert_webhook_total.
//   3. Evaluator: `forTicks` debounce, one firing notice, repeat after repeatMs, one resolved
//      notice, rate rules over a window, lifecycle notices, no-op when the sink is off.
//   4. Role rules: heartbeat (stale / never / egress / partial / draining) and gateway
//      (root degraded / rpc failovers / drop rate / draining) read the registry as documented.
import assert from "node:assert/strict";
import http from "node:http";
import { makeRegistry } from "./metrics.mjs";
import { alertConfig, formatPayload, makeAlertSink, makeAlertEvaluator, heartbeatRules, gatewayRules, installAlerts } from "./alerts.mjs";

let n = 0;
const ok = (c, m) => { assert.ok(c, m); n += 1; console.log(`  ok   ${m}`); };

// 1. config
ok(alertConfig({}).url === null && alertConfig({ SHADE_TREE_ALERT_WEBHOOK: " " }).url === null, "no URL -> alerts off");
ok(alertConfig({ SHADENET_ALERT_WEBHOOK: "http://x/y" }).url === "http://x/y", "SHADENET_ALERT_WEBHOOK alias works");
const cfg = alertConfig({ SHADE_TREE_ALERT_WEBHOOK: "http://x", SHADE_TREE_ALERT_WEBHOOK_FORMAT: "Slack", SHADE_TREE_ALERT_INTERVAL_MS: "10", SHADE_TREE_ALERT_REPEAT_MS: "5", SHADE_TREE_ALERT_INSTANCE: " node-1 " });
ok(cfg.format === "slack" && cfg.intervalMs === 30000 && cfg.repeatMs === 4 * 3600 * 1000 && cfg.instance === "node-1", "format is case-insensitive; too-small intervals fall back to defaults; instance trimmed");
ok(alertConfig({ SHADE_TREE_ALERT_WEBHOOK_FORMAT: "pagerduty" }).format === "generic", "unknown format -> generic");

// 2. sink against a local server
const received = [];
let failNext = 0;
const server = http.createServer((req, res) => {
  let body = "";
  req.on("data", (c) => { body += c; });
  req.on("end", () => {
    received.push({ path: req.url, ct: req.headers["content-type"], body: JSON.parse(body) });
    if (failNext > 0) { failNext -= 1; res.statusCode = 500; return res.end("no"); }
    res.statusCode = 204; res.end();
  });
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const url = `http://127.0.0.1:${server.address().port}/hook`;
const reg = makeRegistry();
let clock = 1_700_000_000_000;
const now = () => clock;
const sink = makeAlertSink({ url, format: "generic", role: "node", instance: "node-1", reg, now });
const r1 = await sink.send({ alert: "Test", severity: "warning", status: "firing", summary: "hello" });
ok(r1.ok === true && received.length === 1 && received[0].path === "/hook" && received[0].ct === "application/json", "one POST per event, JSON body");
const ev = received[0].body;
ok(ev.source === "shadenet" && ev.version === 1 && ev.role === "node" && ev.instance === "node-1" && ev.alert === "Test" && ev.status === "firing" && ev.summary === "hello" && typeof ev.ts === "string" && typeof ev.startsAt === "string", "generic payload carries every documented field");
failNext = 1;
const r2 = await sink.send({ alert: "Test", status: "resolved", summary: "x" });
ok(r2.ok === false && sink.stats.failed === 1 && sink.stats.sent === 1 && /HTTP 500/.test(sink.stats.lastError), "a non-2xx reply is a counted failure, not a throw");
ok(reg.values("shade_tree_alert_webhook_total").map((s) => `${s.labels.result}=${s.value}`).sort().join(",") === "failed=1,sent=1", "shade_tree_alert_webhook_total{result} counts both outcomes");
const dead = makeAlertSink({ url: "http://127.0.0.1:1/x", role: "node", instance: "i", reg, now });
const r3 = await dead.send({ alert: "A", summary: "s" });
ok(r3.ok === false && typeof r3.error === "string", "an unreachable webhook fails fast and quietly");
const offSink = makeAlertSink({ url: null, role: "node", instance: "i" });
ok((await offSink.send({ alert: "A" })).skipped === true && offSink.enabled === false, "no URL -> send is a no-op");
const sample = { source: "shadenet", version: 1, role: "node", instance: "n", alert: "GatewayDown", severity: "critical", status: "firing", summary: "down", startsAt: "t", ts: "t" };
ok(formatPayload("slack", sample).text === "[shadenet] FIRING GatewayDown (n): down", "slack: one text line");
ok(formatPayload("discord", sample).content.startsWith("[shadenet] FIRING GatewayDown"), "discord: content line");
const mx = formatPayload("matrix", sample);
ok(mx.msgtype === "m.text" && mx.text.startsWith("[shadenet]") && mx.alert === "GatewayDown", "matrix: text + msgtype + generic fields (hookshot template reads data.text)");
ok(formatPayload("generic", sample) === sample, "generic: the event itself");

// 3. evaluator semantics with an injected rule
received.length = 0;
let cond = false;
const rule = { name: "Thing", severity: "warning", forTicks: 2, when: () => (cond ? "thing is wrong" : false) };
const evalr = makeAlertEvaluator({ reg, sink, rules: [rule], intervalMs: 1000, repeatMs: 10_000, now });
await evalr.tick();
ok(received.length === 0, "false condition sends nothing");
cond = true; await evalr.tick();
ok(received.length === 0, "forTicks:2 -> the first true tick is debounced");
await evalr.tick();
ok(received.length === 1 && received[0].body.status === "firing" && received[0].body.alert === "Thing" && received[0].body.summary === "thing is wrong", "second true tick fires once");
ok(evalr.firing().join() === "Thing", "firing() lists it");
await evalr.tick(); await evalr.tick();
ok(received.length === 1, "still firing within repeatMs -> no re-send");
clock += 10_001; await evalr.tick();
ok(received.length === 2 && received[1].body.status === "firing" && received[1].body.startsAt === received[0].body.startsAt, "re-sent after repeatMs with the ORIGINAL startsAt");
cond = false; await evalr.tick();
ok(received.length === 3 && received[2].body.status === "resolved" && received[2].body.startsAt === received[0].body.startsAt, "clearing sends one resolved notice");
await evalr.tick();
ok(received.length === 3 && evalr.firing().length === 0, "and nothing more");
cond = true; await evalr.tick(); await evalr.tick();
ok(received.length === 4, "a fresh episode fires again after the debounce");
await evalr.lifecycle("Started", "up");
ok(received.length === 5 && received[4].body.severity === "info" && received[4].body.alert === "Started", "lifecycle notice is info/firing, sent once");
const offEval = makeAlertEvaluator({ reg, sink: offSink, rules: [rule], now });
ok(offEval.start() === false && (await offEval.lifecycle("x", "y")).skipped === true, "evaluator with no sink is a no-op (start() false)");
let scheduled = 0;
const ev2 = makeAlertEvaluator({ reg, sink, rules: [], now, schedule: () => { scheduled += 1; return { unref() {} }; }, clear: () => {} });
ok(ev2.start() === true && ev2.start() === true && scheduled === 1, "start() schedules once");
ev2.stop();

// 4. role rules against a registry
received.length = 0;
const hb = makeRegistry();
const last = hb.gauge("shade_tree_heartbeat_last_success_timestamp_seconds", "h");
const up = hb.gauge("shade_tree_process_uptime_seconds", "h");
const egress = hb.gauge("shade_tree_heartbeat_egress_check_up", "h");
const total = hb.gauge("shade_tree_heartbeat_elders_total", "h");
const acc = hb.gauge("shade_tree_heartbeat_elders_accepted", "h");
const drain = hb.gauge("shade_tree_heartbeat_draining", "h");
const hbSink = makeAlertSink({ url, role: "heartbeat", instance: "n", now });
const hbEval = makeAlertEvaluator({ reg: hb, sink: hbSink, rules: heartbeatRules({ intervalSec: 300 }), now });
last.set(clock / 1000); up.set(10); egress.set(1); total.set(2); acc.set(2); drain.set(0);
await hbEval.tick();
ok(received.length === 0, "healthy heartbeat: no alert");
clock += 901 * 1000; up.set(911);
await hbEval.tick();
ok(received.some((r) => r.body.alert === "HeartbeatStale" && /901s/.test(r.body.summary)), "HeartbeatStale after 3 intervals without an accepted announce");
received.length = 0; last.set(clock / 1000);
egress.set(0); await hbEval.tick(); ok(received.length === 1 && received[0].body.alert === "HeartbeatStale" && received[0].body.status === "resolved", "stale resolves when a heartbeat lands; EgressDown debounced (forTicks 2)");
received.length = 0; await hbEval.tick(); ok(received.length === 1 && received[0].body.alert === "EgressDown", "EgressDown on the second failing tick");
received.length = 0; egress.set(1); acc.set(1); await hbEval.tick(); await hbEval.tick();
ok(received.some((r) => r.body.alert === "EgressDown" && r.body.status === "resolved") && received.some((r) => r.body.alert === "ElderPartial" && /1 of 2/.test(r.body.summary)), "EgressDown resolves; ElderPartial names the count");
received.length = 0; acc.set(2); drain.set(1); await hbEval.tick();
ok(received.some((r) => r.body.alert === "Draining" && r.body.severity === "info") && received.some((r) => r.body.alert === "ElderPartial" && r.body.status === "resolved"), "Draining is an info alert; partial resolves");
const never = makeRegistry();
never.gauge("shade_tree_process_uptime_seconds", "h").set(1000);
never.gauge("shade_tree_heartbeat_last_success_timestamp_seconds", "h").set(0);
received.length = 0;
await makeAlertEvaluator({ reg: never, sink: hbSink, rules: heartbeatRules({ intervalSec: 300 }), now }).tick();
ok(received.length === 1 && received[0].body.alert === "HeartbeatNeverAccepted", "HeartbeatNeverAccepted when uptime passes 3 intervals with no success");

const gw = makeRegistry();
const degraded = gw.gauge("shade_tree_gateway_root_source_degraded", "h");
const failovers = gw.counter("shade_tree_rpc_failovers_total", "h");
const tunnels = gw.counter("shade_tree_gateway_tunnels_total", "h");
let draining = false;
const gwSink = makeAlertSink({ url, role: "node", instance: "n", now });
const gwEval = makeAlertEvaluator({ reg: gw, sink: gwSink, rules: gatewayRules(), now, draining: () => draining });
received.length = 0;
degraded.set(0, { source: "staked" }); await gwEval.tick(); await gwEval.tick();
ok(received.length === 0, "healthy gateway: no alert");
degraded.set(1, { source: "staked" }); await gwEval.tick(); await gwEval.tick();
ok(received.length === 1 && received[0].body.alert === "RootSourceDegraded" && /staked/.test(received[0].body.summary), "RootSourceDegraded names the source after two ticks");
received.length = 0; degraded.set(0, { source: "staked" });
failovers.inc({ endpoint: "0" }, 2); await gwEval.tick();
ok(received.length === 1 && received[0].body.status === "resolved", "2 failovers in the window is not yet an alert");
failovers.inc({ endpoint: "1" }, 1); received.length = 0; await gwEval.tick();
ok(received.length === 1 && received[0].body.alert === "RpcEndpointFailing" && /3 RPC failovers/.test(received[0].body.summary), "3 failovers inside 15 min fire RpcEndpointFailing");
received.length = 0; clock += 16 * 60 * 1000; await gwEval.tick();
ok(received.length === 1 && received[0].body.alert === "RpcEndpointFailing" && received[0].body.status === "resolved", "the window slides: resolved after 15 quiet minutes");
received.length = 0; tunnels.inc({ result: "pass" }, 5); tunnels.inc({ result: "drop", reason: "gate" }, 25); await gwEval.tick();
ok(received.length === 1 && received[0].body.alert === "HighDropRate" && /25 of 30/.test(received[0].body.summary), "HighDropRate: >50% drops over >=20 tunnels in the window");
received.length = 0; draining = true; await gwEval.tick();
ok(received.some((r) => r.body.alert === "Draining" && r.body.severity === "info"), "gateway Draining reads the injected drain state");

// installAlerts from env
const inst = installAlerts({ role: "node", reg: gw, rules: gatewayRules(), env: { SHADE_TREE_ALERT_WEBHOOK: url, SHADE_TREE_ALERT_WEBHOOK_FORMAT: "discord" } , now });
ok(inst.enabled === true && inst.config.format === "discord" && typeof inst.tick === "function", "installAlerts wires sink + evaluator from env");
ok(installAlerts({ role: "node", reg: gw, rules: [], env: {} }).enabled === false, "installAlerts without a URL is disabled");

server.close();
console.log(`PASS: webhook alerts (${n} checks)`);
