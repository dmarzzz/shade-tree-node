// Selftest for the uptime-probe scheduler bundle (T-DEPLOY-5 / GAP-8): the systemd timer+service
// pair, the crontab line, the env template, and .github/workflows/uptime-probe.yml.
//
// Nothing here runs Tor or the probe. It proves the SHIPPED FILES are well-formed and wired to the
// same script/vars the probe reads, so a typo in a unit or a cron field cannot ship green:
//   - service: oneshot, ExecStart -> scripts/uptime-probe.mjs, EnvironmentFile, sandbox keys,
//     SuccessExitStatus covers the probe's unhealthy codes (1 json / 2 nagios)
//   - timer: OnUnitActiveSec=5min, WantedBy=timers.target, Unit= names the service
//   - crontab: a 5-field schedule that runs the probe every 5 min and sources the env file
//   - env template: placeholders only (no real onion / signer), names the vars the probe reads
//   - workflow: parses as YAML when js-yaml is resolvable (it is a transitive dev dependency;
//     structural checks run regardless), schedule cron is valid and >= GitHub's 5-min floor,
//     workflow_dispatch present, every step after the config check is `if:`-guarded so an
//     unconfigured repo no-ops green with a ::notice::, vars/secrets names match the probe's env,
//     tor is installed + bootstrapped before the probe, no secret is echoed, the collector is
//     read-only, and an isolated publisher writes only the signed aggregate snapshot.
//
//   node monitoring/uptime/uptime-scheduler.selftest.mjs

import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const read = (p) => readFileSync(p, "utf8");

// Minimal INI parser for systemd units: { Section: { Key: [values...] } } (keys may repeat).
function parseUnit(text) {
  const out = {};
  let sec = null;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const m = line.match(/^\[([A-Za-z]+)\]$/);
    if (m) { sec = m[1]; out[sec] = out[sec] || {}; continue; }
    if (!sec) throw new Error(`key outside a section: ${line}`);
    const eq = line.indexOf("=");
    if (eq < 1) throw new Error(`bad unit line: ${line}`);
    const k = line.slice(0, eq).trim(), v = line.slice(eq + 1).trim();
    (out[sec][k] = out[sec][k] || []).push(v);
  }
  return out;
}
const one = (u, s, k) => (u[s] && u[s][k] ? u[s][k][0] : undefined);

// A 5-field cron expression; returns the minute step (or null if not a plain */N).
function cronFields(expr) {
  const f = expr.trim().split(/\s+/);
  if (f.length !== 5) return null;
  const okField = (x) => /^(\*|\d+|\*\/\d+|\d+-\d+|\d+(,\d+)+)$/.test(x);
  if (!f.every(okField)) return null;
  const m = f[0].match(/^\*\/(\d+)$/);
  return { fields: f, minuteStep: m ? Number(m[1]) : f[0] === "*" ? 1 : null };
}

function main() {
  console.log("systemd service:");
  const svcText = read(join(HERE, "shade-tree-uptime-probe.service"));
  let svc;
  try { svc = parseUnit(svcText); ok(true, "service parses as a systemd unit"); } catch (e) { ok(false, `service parses: ${e.message}`); svc = {}; }
  ok(one(svc, "Service", "Type") === "oneshot", "Type=oneshot (a timer-fired probe, not a daemon)");
  ok(/scripts\/uptime-probe\.mjs/.test(one(svc, "Service", "ExecStart") || ""), "ExecStart runs scripts/uptime-probe.mjs");
  ok(/--format nagios/.test(one(svc, "Service", "ExecStart") || ""), "ExecStart uses --format nagios (one status line per run)");
  ok(/uptime-probe\.env$/.test(one(svc, "Service", "EnvironmentFile") || ""), "EnvironmentFile points at /etc/shade-tree/uptime-probe.env");
  ok(one(svc, "Service", "SuccessExitStatus") === "1 2", "SuccessExitStatus=1 2 (probe's unhealthy codes do not fail the unit)");
  ok((svc.Service?.Environment || []).some((v) => /^SHADE_TREE_TOR_PORT=\d+$/.test(v)), "sets SHADE_TREE_TOR_PORT for the distro tor daemon");
  ok(one(svc, "Unit", "After")?.includes("tor.service"), "After=tor.service");
  for (const k of ["NoNewPrivileges", "ProtectSystem", "ProtectHome", "PrivateTmp", "RestrictAddressFamilies", "SystemCallFilter", "CapabilityBoundingSet", "MemoryMax"]) {
    ok(k in (svc.Service || {}), `sandbox key present: ${k}`);
  }
  ok(!("Install" in svc), "service has no [Install] (the timer is what gets enabled)");
  ok(!/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(svcText.replace(/127\.0\.0\.1/g, "")), "service contains no non-loopback IP");

  console.log("\nsystemd timer:");
  const tmrText = read(join(HERE, "shade-tree-uptime-probe.timer"));
  let tmr;
  try { tmr = parseUnit(tmrText); ok(true, "timer parses as a systemd unit"); } catch (e) { ok(false, `timer parses: ${e.message}`); tmr = {}; }
  ok(one(tmr, "Timer", "OnUnitActiveSec") === "5min", "OnUnitActiveSec=5min (SLI cadence)");
  ok(Boolean(one(tmr, "Timer", "OnBootSec")), "OnBootSec set (first run after boot)");
  ok(one(tmr, "Timer", "Unit") === "shade-tree-uptime-probe.service", "Unit= names the service");
  ok(one(tmr, "Install", "WantedBy") === "timers.target", "WantedBy=timers.target");
  ok(Boolean(one(tmr, "Timer", "RandomizedDelaySec")), "RandomizedDelaySec set (no lockstep)");

  console.log("\ncrontab:");
  const cron = read(join(HERE, "crontab.example"));
  const cronLines = cron.split("\n").filter((l) => l.trim() && !l.trim().startsWith("#"));
  ok(cronLines.length === 1, "exactly one active crontab line");
  const cl = cronLines[0] || "";
  const cf = cronFields(cl.split(/\s+/).slice(0, 5).join(" "));
  ok(cf && cf.minuteStep === 5, "cron schedule is a valid 5-field */5 minute line");
  ok(/scripts\/uptime-probe\.mjs/.test(cl), "cron line runs scripts/uptime-probe.mjs");
  ok(/--format nagios/.test(cl), "cron line uses --format nagios");
  ok(/uptime-probe\.env/.test(cl), "cron line sources /etc/shade-tree/uptime-probe.env");
  ok(/2>&1/.test(cl), "cron line captures stderr into the log");

  console.log("\nenv template:");
  const envT = read(join(HERE, "uptime-probe.env.example"));
  const active = envT.split("\n").filter((l) => l.trim() && !l.trim().startsWith("#"));
  ok(active.every((l) => /^[A-Z_]+=.*$/.test(l)), "every active line is KEY=value");
  ok(/#SHADE_TREE_NETWORK=your-v4-network/.test(envT), "template documents a current v4 network selector without activating a retired preset");
  ok(!active.some((l) => /^SHADE_TREE_NETWORK=sepolia$/.test(l)), "template never activates the retired Sepolia record");
  ok(/SHADE_TREE_BOOTNODE_ONION=/.test(envT) && /SHADE_TREE_DIR_SIGNER=/.test(envT), "template documents SHADE_TREE_BOOTNODE_ONION + SHADE_TREE_DIR_SIGNER");
  ok(!/[a-z2-7]{56}\.onion/.test(envT), "template carries no real onion");
  ok(!/\b[0-9a-f]{64}\b/.test(envT), "template carries no real 64-hex key");

  console.log("\nGitHub Actions workflow:");
  const wfPath = join(ROOT, ".github", "workflows", "uptime-probe.yml");
  const wf = read(wfPath);
  ok(!/\t/.test(wf), "workflow has no tab characters (YAML)");
  // Full YAML parse when js-yaml is resolvable (transitive dev dependency via eslint); the
  // structural checks below do not depend on it.
  let doc = null;
  try {
    const require = createRequire(import.meta.url);
    const yaml = require("js-yaml");
    doc = yaml.load(wf);
    ok(doc && typeof doc === "object", "workflow parses as YAML (js-yaml)");
  } catch (e) {
    if (/Cannot find module/.test(e.message)) console.log("  skip js-yaml not resolvable; structural checks only");
    else ok(false, `workflow YAML parse: ${e.message}`);
  }
  if (doc) {
    const on = doc.on || doc[true]; // YAML 1.1 parsers read a bare `on:` key as boolean true
    ok(on && on.schedule && Array.isArray(on.schedule) && on.schedule.length === 1, "on.schedule has one entry");
    const cronExpr = on?.schedule?.[0]?.cron || "";
    const parsed = cronFields(cronExpr);
    ok(parsed && parsed.minuteStep != null && parsed.minuteStep >= 5, `schedule cron "${cronExpr}" is valid and >= GitHub's 5-minute floor`);
    ok(on && "workflow_dispatch" in on, "workflow_dispatch present (manual run)");
    ok(doc.permissions && doc.permissions.contents === "read", "default permissions are read-only");
    const job = doc.jobs && doc.jobs.probe;
    ok(job && Array.isArray(job.steps) && job.steps.length >= 5, "jobs.probe has the step list");
    ok(job && job["timeout-minutes"] && job["timeout-minutes"] <= 15, "job has a short timeout");
    const env = job?.env || {};
    ok(/vars\.SHADE_TREE_BOOTNODE_ONION/.test(env.SHADE_TREE_BOOTNODE_ONION || "") && /secrets\.SHADE_TREE_BOOTNODE_ONION/.test(env.SHADE_TREE_BOOTNODE_ONION || ""), "SHADE_TREE_BOOTNODE_ONION from vars with secrets fallback");
    ok(/vars\.SHADE_TREE_DIR_SIGNER/.test(env.SHADE_TREE_DIR_SIGNER || ""), "SHADE_TREE_DIR_SIGNER from vars");
    ok(/vars\.SHADE_TREE_NETWORK/.test(env.SHADE_TREE_NETWORK || ""), "SHADE_TREE_NETWORK from vars (record alternative)");
    ok(String(env.SHADE_TREE_TOR_PORT) === "9050", "SHADE_TREE_TOR_PORT=9050 matches the tor --SocksPort used");
    const steps = job?.steps || [];
    const first = steps[0] || {};
    ok(first.id === "cfg" && /configured=/.test(first.run || "") && /::notice/.test(first.run || ""), "first step is the config check that emits ::notice:: when unset");
    ok(steps.slice(1).every((s) => typeof s.if === "string" && /steps\.cfg\.outputs\.configured == 'true'/.test(s.if)), "every later step is guarded on the config check (no-op green when unset)");
    const checkout = steps.find((s) => /actions\/checkout@/.test(s.uses || ""));
    const setupNode = steps.find((s) => /actions\/setup-node@/.test(s.uses || ""));
    ok(checkout?.with?.["persist-credentials"] === false, "collector checkout does not persist GitHub credentials");
    ok(/actions\/checkout@[0-9a-f]{40}$/.test(checkout?.uses || "") && /actions\/setup-node@[0-9a-f]{40}$/.test(setupNode?.uses || ""), "third-party actions are pinned to full commit SHAs");
    const runs = steps.map((s) => s.run || "").join("\n");
    ok(/apt-get install .*tor/.test(runs), "installs tor");
    ok(/--SocksPort 9050/.test(runs) && /Bootstrapped 100%/.test(runs), "starts tor on 9050 and waits for bootstrap");
    ok(/for attempt in 1 2/.test(runs) && /tor-\$attempt/.test(runs), "retries a stalled Tor bootstrap with a clean data directory");
    ok(/scripts\/uptime-probe\.mjs --format nagios/.test(runs), "runs the probe with --format nagios");
    ok(/scripts\/grove-snapshot\.mjs/.test(runs), "builds the public Grove snapshot with the allowlisting collector");
    const groveStep = steps.find((s) => s.id === "grove");
    ok(/secrets\.SHADE_TREE_GROVE_SIGNING_KEY/.test(groveStep?.env?.SHADE_TREE_GROVE_SIGNING_KEY || ""), "signing key is scoped to the aggregate-build step");
    ok(/SHADE_TREE_NETWORK:-.* != "sepolia"/.test(groveStep?.run || "") && /--network sepolia/.test(groveStep?.run || ""), "public publisher is bound to the versioned Sepolia Data API");
    ok(/::error/.test(runs), "a CRITICAL probe surfaces as an ::error::");
    ok(!/echo .*\$\{\{ ?secrets\./.test(wf) && !/echo "\$SHADE_TREE_DIR_SIGNER|echo "\$SHADE_TREE_BOOTNODE_ONION/.test(wf), "no secret / onion / signer is echoed");
    const probeStep = steps.find((s) => /probe \(over Tor/.test(s.name || ""));
    ok(probeStep && /SHADE_TREE_PROBE_SKIP != '1'/.test(probeStep.if), "probe step is also skipped when the network record is pending");
    ok(!/fleet=/.test(probeStep?.run || "") && !/nodes\.announced/.test(groveStep?.run || ""), "hosted workflow does not print the exact fleet count");

    const publisher = doc.jobs?.publish;
    const publishSteps = publisher?.steps || [];
    const publishRun = publishSteps.map((s) => s.run || "").join("\n");
    ok(publisher?.needs === "probe" && publisher?.permissions?.contents === "write", "write permission exists only in the dependent publisher job");
    ok(publishSteps.length === 1 && publishSteps.every((s) => !s.uses), "publisher checks out no code and invokes no external action");
    ok(/GROVE_SNAPSHOT_B64/.test(publishRun) && /git\/blobs/.test(publishRun) && /git\/trees/.test(publishRun), "publisher accepts only the encoded snapshot and uses the Git data API");
    ok(/path:\"grove\.json\"/.test(publishRun) && /parents:\[\]/.test(publishRun), "publisher creates a one-file parentless commit (no retained count history)");
    ok(!/npm|node scripts|checkout|git push/.test(publishRun), "publisher executes no repository code or dependency install");

    const publicVerify = doc.jobs?.["verify-public"];
    const publicRun = (publicVerify?.steps || []).map((s) => s.run || "").join("\n");
    ok(publicVerify?.needs === "publish" && publicVerify?.permissions?.contents === "read", "public data-plane check runs after publish with read-only permissions");
    // The origin lives in the step's env (GROVE_ORIGIN), the paths in its script.
    const publicOrigin = (publicVerify?.steps || []).map((s) => s.env?.GROVE_ORIGIN || "").join("\n");
    ok(/shade-tree-node\.vercel\.app/.test(publicOrigin + publicRun) && /\/grove\//.test(publicRun), "public data-plane check reaches the production Grove page");
    ok(/api\/v1\/data\/grove\/sepolia\/head/.test(publicRun) && /api\/v2\/data\/grove\/sepolia\/head/.test(publicRun), "public data-plane check reaches both signed heads");
    ok(/shade-tree-public-grove-v1/.test(publicRun) && /shade-tree-public-grove-v2/.test(publicRun), "public data-plane check validates both schema names");
    ok(/for attempt in \$\(seq 1 12\)/.test(publicRun) && /sleep 5/.test(publicRun), "public data-plane check allows bounded propagation time");

    // Freshness guard: a green probe that stopped publishing must show up in the run.
    ok(/::warning title=public Grove NOT published::/.test(groveStep?.run || "") && !/::notice[^\n]*SHADE_TREE_NETWORK must be sepolia/.test(groveStep?.run || ""), "a publisher skipped for a non-sepolia selector is a ::warning::, not a notice");
    const freshness = doc.jobs?.freshness;
    const freshSteps = freshness?.steps || [];
    const freshRun = freshSteps.map((s) => s.run || "").join("\n");
    ok(Array.isArray(freshness?.needs) && freshness.needs.includes("probe") && freshness.needs.includes("publish") && freshness?.if === "always()", "freshness check runs on every run, also when publish was skipped");
    ok(freshness?.permissions?.contents === "read" && freshness?.["timeout-minutes"] <= 5, "freshness check is read-only and short");
    ok(freshSteps[0]?.id === "cfg" && /secrets\.SHADE_TREE_GROVE_SIGNING_KEY != ''/.test(freshSteps[0]?.env?.HAS_GROVE_KEY || "") && freshSteps.slice(1).every((s) => /steps\.cfg\.outputs\.publisher == 'true'/.test(s.if || "")), "freshness check no-ops in a repository without the signing key and receives only a boolean");
    const freshCheckout = freshSteps.find((s) => /actions\/checkout@/.test(s.uses || ""));
    ok(/actions\/checkout@[0-9a-f]{40}$/.test(freshCheckout?.uses || "") && freshCheckout?.with?.["persist-credentials"] === false && freshSteps.filter((s) => s.uses).length === 1, "freshness check uses only the SHA-pinned checkout without credentials");
    ok(/refs\/heads\/network-state/.test(freshRun) && /scripts\/grove-freshness\.mjs/.test(freshRun) && /--probe-result "\$PROBE_RESULT"/.test(freshRun), "freshness check reads the published branch and runs scripts/grove-freshness.mjs");
    const freshEnv = freshSteps.find((s) => /grove-freshness\.mjs/.test(s.run || ""))?.env || {};
    ok(/needs\.probe\.result/.test(freshEnv.PROBE_RESULT || "") && Number(freshEnv.GROVE_STALE_WARN_MINUTES) >= 30 && Number(freshEnv.GROVE_STALE_WARN_MINUTES) <= 60 && Number(freshEnv.GROVE_STALE_FAIL_MINUTES) > Number(freshEnv.GROVE_STALE_WARN_MINUTES), "freshness thresholds: warn within the v2 API's 60-minute limit, fail later");
    ok(!/npm (ci|install)/.test(freshRun) && freshSteps.every((s) => Object.values(s.env || {}).every((v) => !/secrets\.SHADE_TREE_GROVE_SIGNING_KEY\s*\}\}/.test(String(v)))), "freshness check installs nothing and never receives the signing key");
    ok(doc.jobs?.probe?.needs === undefined && doc.jobs?.publish?.needs === "probe" && doc.jobs?.["verify-public"]?.needs === "publish", "probe, publish and verify-public do not depend on the freshness check");
  } else {
    // structural fallback
    ok(/^on:\n\s+schedule:\n\s+- cron: "\*\/(5|1[0-9]|[2-5][0-9]) \* \* \* \*"/m.test(wf), "on.schedule cron */N with N>=5 (structural)");
    ok(/workflow_dispatch:/.test(wf), "workflow_dispatch present (structural)");
    ok(/steps\.cfg\.outputs\.configured == 'true'/.test(wf) && /::notice/.test(wf), "config guard + ::notice present (structural)");
    ok(/permissions:\n  contents: read/.test(wf) && /publish:[\s\S]*permissions:\n      contents: write/.test(wf), "read-only collector and isolated write publisher (structural)");
    ok(/persist-credentials: false/.test(wf) && !/actions\/(?:checkout|setup-node)@v\d/.test(wf), "collector drops credentials and actions are SHA-pinned (structural)");
    ok(/parents:\[\]/.test(wf) && /path:\"grove\.json\"/.test(wf), "publisher emits a one-file parentless commit (structural)");
    ok(/verify-public:[\s\S]*needs: publish[\s\S]*shade-tree-node\.vercel\.app[\s\S]*api\/v1\/data\/grove[\s\S]*api\/v2\/data\/grove/.test(wf), "publisher is followed by a production data-plane check (structural)");
    ok(/::warning title=public Grove NOT published::/.test(wf) && !/::notice[^\n]*SHADE_TREE_NETWORK must be sepolia/.test(wf), "non-sepolia publisher skip is a ::warning:: (structural)");
    ok(/\n  freshness:\n[\s\S]*needs: \[probe, publish\][\s\S]*if: always\(\)[\s\S]*contents: read[\s\S]*refs\/heads\/network-state[\s\S]*scripts\/grove-freshness\.mjs/.test(wf), "freshness check runs on every run and reads the published branch (structural)");
  }

  console.log(failures ? `\n${failures} FAILED` : "\nall uptime-scheduler checks passed");
  process.exit(failures ? 1 : 0);
}

main();
