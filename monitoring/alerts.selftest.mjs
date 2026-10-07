// The alert rules must load in a real Prometheus (fast lane, no network). Until the ShadeNet
// monitor loaded them on 2026-09-28 they had never been evaluated, and three annotations used
// `\"` inside a folded YAML scalar, which stays a literal backslash and fails Go templating.
//   - every {{ ... }} template action is free of backslashes;
//   - alert names are unique;
//   - every rule has severity critical|warning and a component label;
//   - the compose bundle scrapes bootstrap.sh's default metrics ports;
//   - every shade_tree_* series an expression uses is documented in monitoring/README.md;
//   - when `promtool` is on PATH, `promtool check rules` passes (the authoritative check).
//
//   node monitoring/alerts.selftest.mjs

import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const rules = readFileSync(join(HERE, "alerts.yml"), "utf8");
const readme = readFileSync(join(HERE, "README.md"), "utf8");
let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

const actions = [...rules.matchAll(/\{\{([^}]*)\}\}/g)].map((m) => m[1]);
ok(actions.length > 0, `found ${actions.length} template actions`);
const escaped = actions.filter((a) => a.includes("\\"));
ok(escaped.length === 0, `no backslash inside a template action${escaped.length ? `: ${escaped.join(" | ")}` : ""}`);

const names = [...rules.matchAll(/^\s*- alert:\s*(\S+)/gm)].map((m) => m[1]);
ok(names.length >= 13, `${names.length} alert rules`);
ok(new Set(names).size === names.length, "alert names are unique");

// Every rule carries the labels the incident receiver maps (alertmanager.incidents.example.yml):
// one severity vocabulary, and a component.
const blocks = rules.split(/^\s*- alert:\s*/m).slice(1).map((b) => ({ name: b.split(/\s/)[0], body: b }));
const badSeverity = blocks.filter((b) => !/^\s*severity:\s*(critical|warning)\s*$/m.test(b.body)).map((b) => b.name);
ok(badSeverity.length === 0, `every rule has severity critical or warning${badSeverity.length ? `: ${badSeverity.join(", ")}` : ""}`);
const noComponent = blocks.filter((b) => !/^\s*component:\s*[a-z]+\s*$/m.test(b.body)).map((b) => b.name);
ok(noComponent.length === 0, `every rule has a component label${noComponent.length ? `: ${noComponent.join(", ")}` : ""}`);

// The compose bundle scrapes the ports bootstrap.sh gives each role.
const bootstrap = readFileSync(join(HERE, "..", "packages/node/bootnode/deploy/bootstrap.sh"), "utf8");
const defaultPort = (v) => (bootstrap.match(new RegExp(`${v}="\\$\\{${v}:-(\\d+)\\}"`)) || [])[1];
const compose = readFileSync(join(HERE, "compose/prometheus.yml"), "utf8");
const scraped = (job) => (compose.match(new RegExp(`job_name: ${job}\\s+static_configs:\\s+- targets: \\["127\\.0\\.0\\.1:(\\d+)"\\]`)) || [])[1];
for (const [job, v] of [["shade-tree-bootnode", "SHADE_TREE_ELDER_METRICS_PORT"], ["shade-tree-gateway", "SHADE_TREE_NODE_METRICS_PORT"], ["shade-tree-heartbeat", "SHADE_TREE_HEARTBEAT_METRICS_PORT"]]) {
  ok(defaultPort(v) && scraped(job) === defaultPort(v), `compose scrapes ${job} on ${defaultPort(v)} (got ${scraped(job)})`);
}

const documented = new Set([...readme.matchAll(/`(shade_tree_[a-z0-9_]+)`/g)].map((m) => m[1]));
const used = new Set([...rules.matchAll(/\b(shade_tree_[a-z0-9_]+?)(?:_bucket|_sum|_count)?\b/g)].map((m) => m[1]));
const missing = [...used].filter((m) => !documented.has(m));
ok(missing.length === 0, `every series used is documented${missing.length ? `: ${missing.join(", ")}` : ""}`);

const promtool = spawnSync("promtool", ["check", "rules", join(HERE, "alerts.yml")], { encoding: "utf8" });
if (promtool.error && promtool.error.code === "ENOENT") {
  console.log("  skip promtool not installed (CI and the monitor host run it)");
} else {
  ok(promtool.status === 0, `promtool check rules${promtool.status ? `: ${(promtool.stdout + promtool.stderr).trim().slice(0, 400)}` : ""}`);
}

if (failures) { console.log(`\nFAIL: ${failures} alert-rule check(s)`); process.exit(1); }
console.log("\nPASS: alert rules load");
