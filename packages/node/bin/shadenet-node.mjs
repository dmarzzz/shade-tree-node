#!/usr/bin/env node
// shadenet-node: the one-command front door for running a Shade Tree node.
//
//   shadenet-node run              Tor + node + heartbeat from the record alone (default)
//   shadenet-node check [--probe]  validate the record, RPCs, Tor, disk and ports; print the plan
//   shadenet-node identity         mint (or show) this node's onion identity without starting
//   shadenet-node status           what a running node is doing (reads <state>/status.json)
//   shadenet-node retire           stop announcing; the node leaves every Elder within the TTL
//   shadenet-node help
//
// Configuration: SHADENET_RECORD (required) plus up to ten knobs as SHADENET_* env or
// <state>/node.toml (packages/node/lib/node-config.mjs). Anything the knobs do not cover comes
// from the deployment record; any SHADE_TREE_* you set yourself still wins (the advanced layer).
//
// This is a supervisor, not a daemon framework: one Tor, one gateway, one heartbeat, restarted
// with backoff when they exit, all stopped together on SIGTERM. Inside the container it is PID 1.

import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync, statfsSync, chmodSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as sleep } from "node:timers/promises";
import { loadNodeConfig, checkJoinableRecord, deriveNodeEnv, renderTorrc, readOperatorKeyFile, redactEnv, KNOBS, GATEWAY_PORT, TOR_SOCKS_PORT } from "../lib/node-config.mjs";
import { generateOnionIdentity } from "../bootnode/keygen.mjs";
import { verifyOperatorSig } from "../bootnode/announce.mjs";
import { fetchOverTor } from "../bootnode/fetch.mjs";
import { resolveBuildCommit } from "../lib/build-info.mjs";
import { rpcUrlsOf, eldersOf } from "../lib/network-record.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "../../..");
const argv = process.argv.slice(2);
const cmd = argv.find((a) => !a.startsWith("--")) || "run";
const flag = (name) => argv.includes(`--${name}`);
const log = (...a) => console.error(`[shadenet-node] ${a.join(" ")}`);

function usage() {
  console.log(`shadenet-node: run a Shade Tree node from a deployment record

  shadenet-node run              start (default)
  shadenet-node check [--probe]  validate everything and print what would run; --probe reaches each Elder over Tor
  shadenet-node identity         mint or show the onion identity
  shadenet-node authorize --onion <onion> --key-file <file>
                                 sign the onion with the staked operator key, where the key lives
  shadenet-node status           running node's state
  shadenet-node retire           stop announcing (leaves every Elder's directory within the TTL)

Knobs (SHADENET_* env, or keys in <state>/node.toml):`);
  for (const k of KNOBS) console.log(`  ${k.env.padEnd(28)} ${k.what}${k.default !== undefined && k.default !== "" ? ` [${k.default}]` : ""}`);
  console.log("\nEverything else comes from the record. Any SHADE_TREE_* you set yourself wins (see docs/CONFIG.md).");
}

// ---- record ------------------------------------------------------------------------------
async function fetchRecord(src, stateDir) {
  let text;
  if (/^https:\/\//.test(src)) {
    const res = await fetch(src, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(20000) });
    if (!res.ok) throw new Error(`record: ${src} answered HTTP ${res.status}`);
    text = await res.text();
  } else {
    const p = src.startsWith("~") ? join(process.env.HOME || "", src.slice(1)) : resolve(src);
    if (!existsSync(p)) throw new Error(`record: ${p} does not exist`);
    text = readFileSync(p, "utf8");
  }
  let record;
  try { record = JSON.parse(text); } catch (e) { throw new Error(`record: not JSON (${e.message})`); }
  const j = checkJoinableRecord(record);
  if (!j.ok) throw new Error(`record is not joinable:\n  ${j.errors.join("\n  ")}`);
  mkdirSync(stateDir, { recursive: true });
  writeFileSync(join(stateDir, "record.json"), JSON.stringify(record, null, 2) + "\n");
  return record;
}

// ---- identity -----------------------------------------------------------------------------
async function ensureIdentity(hsDir) {
  const idPath = join(hsDir, "identity.local.json");
  if (!existsSync(idPath)) {
    await generateOnionIdentity(hsDir, { label: "shadenet-node" });
    log(`minted onion identity ${JSON.parse(readFileSync(idPath, "utf8")).onion}`);
  }
  chmodSync(hsDir, 0o700);
  return JSON.parse(readFileSync(idPath, "utf8"));
}

// ---- checks -------------------------------------------------------------------------------
async function rpcCall(url, method, params = [], attempts = 3) {
  let last;
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }), signal: AbortSignal.timeout(10000) });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      if (body.error) throw new Error(body.error.message || "rpc error");
      return body.result;
    } catch (e) { last = e; await sleep(500 * (i + 1)); }
  }
  throw last;
}

function portFree(port) {
  return new Promise((res) => {
    const s = createServer();
    s.once("error", () => res(false));
    s.listen(port, "127.0.0.1", () => s.close(() => res(true)));
  });
}

function torInfo() {
  const v = spawnSync("tor", ["--version"], { encoding: "utf8" });
  if (v.status !== 0) return { present: false };
  const m = spawnSync("tor", ["--list-modules"], { encoding: "utf8" });
  return { present: true, version: v.stdout.split("\n")[0].trim(), pow: /^pow:\s*yes/m.test(m.stdout || "") };
}

async function check({ probe = false, json = false } = {}) {
  const findings = []; // { level: ok|warn|fail, what }
  const ok = (w) => findings.push({ level: "ok", what: w });
  const warn = (w) => findings.push({ level: "warn", what: w });
  const fail = (w) => findings.push({ level: "fail", what: w });

  const cfg = loadNodeConfig();
  for (const e of cfg.errors) fail(`config: ${e}`);
  const { knobs } = cfg;
  if (cfg.tomlPath) ok(`node.toml read from ${cfg.tomlPath}`);
  let record = null, env = {};
  const hsDir = join(knobs.state, "hs-gateway");
  if (!cfg.errors.length) {
    try { record = await fetchRecord(knobs.record, knobs.state); ok(`record ${record.network} (${record.status}), set ${record.admission.roots.staked.contract}, ${eldersOf(record).length} Elder Tree(s)`); }
    catch (e) { fail(e.message); }
  }
  if (record) {
    const commit = resolveBuildCommit();
    const pin = record.services?.node?.commit || "";
    if (commit === "unknown") warn(`build commit unknown (not a release image or git checkout); the record pins ${pin.slice(0, 7)}`);
    else if (pin && !pin.startsWith(commit) && !commit.startsWith(pin)) warn(`this build is ${commit.slice(0, 7)}; the record pins ${pin.slice(0, 7)}. Run the release the record names unless you know why not`);
    else ok(`build ${commit.slice(0, 7)} matches the record's pin`);
    const staked = record.admission.roots.staked;
    let good = 0;
    for (const url of rpcUrlsOf(staked)) {
      try {
        const chain = parseInt(await rpcCall(url, "eth_chainId"), 16);
        const head = parseInt(await rpcCall(url, "eth_blockNumber"), 16);
        if (staked.chainId && chain !== staked.chainId) fail(`rpc ${url}: chain ${chain}, record expects ${staked.chainId}`);
        else { good++; ok(`rpc ${url}: chain ${chain}, head ${head}`); }
      } catch (e) { warn(`rpc ${url}: ${e.message} (the node fails over to the next one)`); }
    }
    if (!good) fail("no RPC in the record answers; the node cannot read the member set");
    const arts = record.artifacts?.accepted || [];
    for (const a of arts) {
      const p = resolve(ROOT, a.verificationKeyPath);
      if (existsSync(p)) ok(`proof artifact ${a.id} present`); else fail(`proof artifact ${a.id}: ${a.verificationKeyPath} missing in this build`);
    }
    env = deriveNodeEnv({ knobs, record, explicit: process.env, hsDir });
  }
  const tor = torInfo();
  if (!tor.present) fail("tor: not on PATH (the container image bundles it; on a host, apt install tor)");
  else {
    ok(`tor: ${tor.version}${tor.pow ? ", pow module" : ", no pow module"}`);
    if (knobs.pow && !tor.pow) fail("pow: enabled but this Tor has no pow module; set SHADENET_POW=0 or use a Tor built with it");
    mkdirSync(join(knobs.state, "tor"), { recursive: true, mode: 0o700 });
    const torrc = join(knobs.state, "torrc.check");
    writeFileSync(torrc, renderTorrc({ stateDir: knobs.state, hsDir, pow: knobs.pow && tor.pow }));
    const v = spawnSync("tor", ["--verify-config", "-f", torrc], { encoding: "utf8" });
    rmSync(torrc, { force: true });
    if (v.status === 0) ok("torrc verifies"); else fail(`torrc does not verify: ${(v.stdout + v.stderr).split("\n").filter((l) => /\[(warn|err)\]/.test(l)).join("; ")}`);
  }
  try {
    mkdirSync(knobs.state, { recursive: true });
    const st = statfsSync(knobs.state);
    const freeGiB = (st.bavail * st.bsize) / 2 ** 30;
    if (freeGiB < 1) fail(`state ${knobs.state}: ${freeGiB.toFixed(2)} GiB free; keep at least 1 GiB for Tor state and logs`);
    else ok(`state ${knobs.state}: ${freeGiB.toFixed(1)} GiB free`);
  } catch (e) { fail(`state ${knobs.state}: ${e.message}`); }
  for (const [name, port] of [["node", GATEWAY_PORT], ["tor socks", TOR_SOCKS_PORT]]) {
    if (await portFree(port)) ok(`${name} port ${port} free on loopback`); else fail(`${name} port ${port} already in use on loopback (another node here? stop it or set SHADE_TREE_GATEWAY_PORT / SHADE_TREE_TOR_PORT)`);
  }
  if (knobs.operator_key_file) {
    try { readOperatorKeyFile(String(knobs.operator_key_file)); ok("operator key file readable, owner-only, well-formed"); } catch (e) { fail(`operator_key_file: ${e.message}`); }
  } else if (knobs.operator && knobs.operator_sig) {
    if (existsSync(join(hsDir, "identity.local.json"))) {
      const id = JSON.parse(readFileSync(join(hsDir, "identity.local.json"), "utf8"));
      if (await verifyOperatorSig(id.onion, String(knobs.operator), String(knobs.operator_sig))) ok(`operator ${knobs.operator} authorised this onion`); else fail("operator_sig does not recover operator for this node's onion (sign operatorAuthMessage(onion, operator) again)");
    } else warn("operator_sig: cannot verify before the onion identity exists; run `shadenet-node identity` first, then sign");
  } else if (record && eldersOf(record).length && record.elder?.admission === "stake") {
    warn("this canopy admits staked operators only (elder.admission = stake): set operator_key_file, or operator + operator_sig, or your announces will be refused not-staked");
  }
  if (probe && record && tor.present && findings.every((f) => f.level !== "fail")) {
    log("probe: bootstrapping a temporary Tor to reach each Elder Tree (up to 3 minutes)…");
    const t = await startTor({ knobs, hsDir, tor, timeoutMs: 180000 }).catch((e) => { fail(`probe: ${e.message}`); return null; });
    if (t) {
      for (const e of eldersOf(record)) {
        try {
          const res = await fetchOverTor(e.onion, "/health", { torPort: TOR_SOCKS_PORT, timeoutMs: 30000, attempts: 2 });
          const h = JSON.parse(res.body.toString());
          ok(`Elder ${e.onion.slice(0, 16)}…: ${h.count} live node(s), commit ${String(h.commit || "").slice(0, 7)}`);
        } catch (err) { warn(`Elder ${e.onion.slice(0, 16)}…: ${err.message}`); }
      }
      t.kill("SIGTERM");
    }
  }
  const failed = findings.some((f) => f.level === "fail");
  if (json) console.log(JSON.stringify({ ok: !failed, findings, knobs: { ...knobs, operator_sig: knobs.operator_sig ? "…" : undefined }, env: redactEnv(env) }, null, 2));
  else {
    for (const f of findings) console.log(`${{ ok: "  ok  ", warn: " warn ", fail: " FAIL " }[f.level]} ${f.what}`);
    console.log(`\nknobs:`); for (const k of KNOBS) if (knobs[k.key] !== undefined && knobs[k.key] !== "") console.log(`  ${k.key.padEnd(18)} ${k.key === "operator_sig" ? "…" : knobs[k.key]}   (${cfg.sources[k.key]})`);
    if (record) { console.log(`\nwould run (cwd ${ROOT}):\n  tor -f ${join(knobs.state, "torrc")}\n  node packages/node/gateway/gateway.mjs\n  node packages/node/bootnode/heartbeat.mjs\nwith:`); for (const [k, v] of Object.entries(redactEnv(env))) console.log(`  ${k}=${v}`); }
    console.log(failed ? "\nresult: not ready (fix the FAIL lines above)" : "\nresult: ready to run");
  }
  return !failed;
}

// ---- processes ---------------------------------------------------------------------------
function startTor({ knobs, hsDir, tor, timeoutMs = 180000 }) {
  const torrc = join(knobs.state, "torrc");
  mkdirSync(join(knobs.state, "tor"), { recursive: true, mode: 0o700 });
  chmodSync(join(knobs.state, "tor"), 0o700);
  rmSync(join(knobs.state, "tor.log"), { force: true });
  writeFileSync(torrc, renderTorrc({ stateDir: knobs.state, hsDir, pow: knobs.pow && tor.pow, torLevel: process.env.SHADENET_TOR_LOG }));
  const child = spawn("tor", ["-f", torrc], { stdio: ["ignore", "pipe", "pipe"] });
  return new Promise((res, rej) => {
    let done = false;
    const timer = setTimeout(() => { if (!done) { done = true; child.kill("SIGTERM"); rej(new Error("tor did not bootstrap within the timeout (outbound to the Tor network blocked?)")); } }, timeoutMs);
    const onLine = (buf) => {
      for (const line of buf.toString().split("\n")) {
        if (!line.trim()) continue;
        if (/\[(warn|err)\]/.test(line) || /Bootstrapped (0|5|10|25|50|75|90|100)%/.test(line)) console.error(`[tor] ${line.replace(/^.*?\[/, "[")}`);
        if (!done && /Bootstrapped 100%/.test(line)) { done = true; clearTimeout(timer); res(child); }
      }
    };
    child.stdout.on("data", onLine); child.stderr.on("data", onLine);
    child.once("exit", (code) => { if (!done) { done = true; clearTimeout(timer); rej(new Error(`tor exited with ${code} before bootstrapping`)); } });
  });
}

function supervise(name, script, env, state) {
  let attempt = 0; let child = null; let stopping = false;
  const start = () => {
    child = spawn(process.execPath, [join(ROOT, script)], { cwd: ROOT, env: { ...process.env, ...env }, stdio: ["ignore", "inherit", "inherit"] });
    state.pids[name] = child.pid; writeStatus(state);
    const startedAt = Date.now();
    child.once("exit", (code, sig) => {
      delete state.pids[name]; writeStatus(state);
      if (stopping) return;
      if (Date.now() - startedAt > 60000) attempt = 0;
      const delay = Math.min(30000, 2000 * 2 ** attempt++);
      log(`${name} exited (${sig || code}); restarting in ${delay / 1000}s`);
      setTimeout(start, delay).unref();
    });
  };
  start();
  return { stop: (sig = "SIGTERM") => { stopping = true; if (child && child.exitCode === null) child.kill(sig); } };
}

function writeStatus(state) {
  try { writeFileSync(join(state.stateDir, "status.json"), JSON.stringify({ ...state, updatedAt: new Date().toISOString() }, null, 2) + "\n"); } catch {}
}

async function run() {
  const cfg = loadNodeConfig();
  if (cfg.errors.length) { for (const e of cfg.errors) log(`config: ${e}`); log("run `shadenet-node check` for the full picture"); process.exit(2); }
  const { knobs } = cfg;
  const hsDir = join(knobs.state, "hs-gateway");
  const record = await fetchRecord(knobs.record, knobs.state);
  const id = await ensureIdentity(hsDir);
  const tor = torInfo();
  if (!tor.present) { log("tor is not on PATH"); process.exit(2); }
  const env = deriveNodeEnv({ knobs, record, explicit: process.env, hsDir });
  if (knobs.operator_key_file) env.SHADE_TREE_GW_OPERATOR_KEY = readOperatorKeyFile(String(knobs.operator_key_file));
  const state = { stateDir: knobs.state, onion: id.onion, network: record.network, set: record.admission.roots.staked.contract, elders: eldersOf(record).map((e) => e.onion), commit: resolveBuildCommit(), recordPin: record.services?.node?.commit || null, metricsPort: Number(env.SHADE_TREE_METRICS_PORT || 0), startedAt: new Date().toISOString(), pids: {} };
  log(`node ${id.onion} joining ${record.network} (set ${state.set}) with ${state.elders.length} Elder Tree(s); admit ${env.SHADE_TREE_ADMIT}; tickets ${env.SHADE_TREE_SESSION_TICKETS === "1" ? "on" : "off"}`);
  if (state.recordPin && state.commit !== "unknown" && !state.recordPin.startsWith(state.commit)) log(`warning: build ${state.commit.slice(0, 7)} differs from the record's pin ${state.recordPin.slice(0, 7)}`);
  const torChild = await startTor({ knobs, hsDir, tor });
  state.pids.tor = torChild.pid; writeStatus(state);
  log("tor bootstrapped; onion descriptor publishes in about 30 s");
  const gateway = supervise("gateway", "packages/node/gateway/gateway.mjs", env, state);
  await sleep(1500);
  const heartbeat = supervise("heartbeat", "packages/node/bootnode/heartbeat.mjs", env, state);
  log("node and heartbeat started; `heartbeat accepted` in the log means an Elder lists this node");
  let shuttingDown = false;
  const shutdown = async (sig) => {
    if (shuttingDown) return; shuttingDown = true;
    log(`${sig}: stopping heartbeat, node, tor`);
    heartbeat.stop(); await sleep(500); gateway.stop();
    await sleep(Number(env.SHADE_TREE_SHUTDOWN_TIMEOUT_MS || 5000));
    torChild.kill("SIGTERM"); await sleep(1000);
    state.stoppedAt = new Date().toISOString(); writeStatus(state);
    process.exit(0);
  };
  process.on("SIGTERM", () => shutdown("SIGTERM")); process.on("SIGINT", () => shutdown("SIGINT"));
  torChild.once("exit", (code) => { if (!shuttingDown) { log(`tor exited (${code}); stopping everything so the supervisor restarts cleanly`); shutdown("tor-exit"); } });
}

async function identity() {
  const cfg = loadNodeConfig();
  const hsDir = join(cfg.knobs.state, "hs-gateway");
  const id = await ensureIdentity(hsDir);
  console.log(JSON.stringify({ onion: id.onion, identity: join(hsDir, "identity.local.json"), note: "keep identity.local.json private; it is the node's name. To authorise it offline: sign operatorAuthMessage(onion, operator) with the staked operator key and pass SHADENET_OPERATOR + SHADENET_OPERATOR_SIG." }, null, 2));
}

// Authorise an onion with the staked operator key WITHOUT putting the key on the node's box:
// run this where the key lives, paste the two values into the node's knobs.
async function authorize() {
  const onion = (argv[argv.indexOf("--onion") + 1] || "").trim();
  const keyFile = argv[argv.indexOf("--key-file") + 1];
  if (!argv.includes("--onion") || !argv.includes("--key-file") || !onion || !keyFile) { log("usage: shadenet-node authorize --onion <56-char>.onion --key-file <owner-only file with the operator key>"); process.exit(2); }
  const { ethers } = await import("ethers");
  const { operatorAuthMessage } = await import("../bootnode/announce.mjs");
  const key = readOperatorKeyFile(resolve(keyFile));
  const w = new ethers.Wallet(key);
  const sig = await w.signMessage(operatorAuthMessage(onion.endsWith(".onion") ? onion : `${onion}.onion`, w.address));
  console.log(JSON.stringify({ SHADENET_OPERATOR: w.address, SHADENET_OPERATOR_SIG: sig, onion, note: "durable: reusable across restarts; re-run only when the onion or the operator changes" }, null, 2));
}

async function status() {
  const cfg = loadNodeConfig();
  const p = join(cfg.knobs.state, "status.json");
  if (!existsSync(p)) { console.log(JSON.stringify({ running: false, state: cfg.knobs.state }, null, 2)); process.exit(flag("quiet") ? 1 : 0); }
  const st = JSON.parse(readFileSync(p, "utf8"));
  // The node's loopback metrics listener answers /readyz once it serves proofs (off when metrics=off).
  let ready = null;
  const metricsPort = Number(st.metricsPort || 0);
  if (metricsPort) { try { const r = await fetch(`http://127.0.0.1:${metricsPort}/readyz`, { signal: AbortSignal.timeout(3000) }); ready = r.ok; } catch { ready = false; } }
  const running = !st.stoppedAt && st.pids?.gateway && st.pids?.heartbeat && st.pids?.tor && ready !== false;
  if (!flag("quiet")) console.log(JSON.stringify({ running: !!running, ready, ...st }, null, 2));
  process.exit(running ? 0 : 1);
}

async function retire() {
  const cfg = loadNodeConfig();
  const p = join(cfg.knobs.state, "status.json");
  const st = existsSync(p) ? JSON.parse(readFileSync(p, "utf8")) : null;
  if (!st || st.stoppedAt || !st.pids?.heartbeat) { log("no running node in this state directory; nothing to retire"); process.exit(1); }
  try { process.kill(st.pids.heartbeat, "SIGTERM"); } catch {}
  log(`heartbeat stopped. ${st.onion} leaves every Elder Tree's directory within the TTL (15 minutes); open tunnels finish. Stop the node itself with SIGTERM (docker stop). To forget the identity for good, delete ${join(cfg.knobs.state, "hs-gateway")}.`);
}

try {
  if (cmd === "help" || flag("help") || cmd === "-h") usage();
  else if (cmd === "run") await run();
  else if (cmd === "check") process.exit((await check({ probe: flag("probe"), json: flag("json") })) ? 0 : 1);
  else if (cmd === "identity") await identity();
  else if (cmd === "authorize") await authorize();
  else if (cmd === "status") await status();
  else if (cmd === "retire") await retire();
  else { log(`unknown command ${cmd}`); usage(); process.exit(2); }
} catch (e) {
  log(e.message);
  process.exit(1);
}
