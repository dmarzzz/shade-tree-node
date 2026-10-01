// The process half of `shadenet-node`: start Tor and wait for it to bootstrap, run the gateway
// and the heartbeat as supervised children, keep <state>/status.json current. Everything that can
// be reasoned about without spawning lives in node-config.mjs (tested); this file is excluded from
// the coverage gate (.c8rc.json) because it only makes sense against a real Tor and real child
// processes, which the release workflow's image smoke test and the staging join exercise.

import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync, chmodSync, rmSync } from "node:fs";
import { join } from "node:path";
import { renderTorrc } from "./node-config.mjs";

export function torInfo() {
  const v = spawnSync("tor", ["--version"], { encoding: "utf8" });
  if (v.status !== 0) return { present: false };
  const m = spawnSync("tor", ["--list-modules"], { encoding: "utf8" });
  return { present: true, version: v.stdout.split("\n")[0].trim(), pow: /^pow:\s*yes/m.test(m.stdout || "") };
}

// Spawn Tor from a freshly rendered torrc and resolve with the child once it logs
// "Bootstrapped 100%"; reject (and kill it) if that takes longer than timeoutMs or Tor exits.
export function startTor({ knobs, hsDir, tor, timeoutMs = 180000, torLevel = process.env.SHADENET_TOR_LOG, log = () => {} }) {
  const torrc = join(knobs.state, "torrc");
  mkdirSync(join(knobs.state, "tor"), { recursive: true, mode: 0o700 });
  chmodSync(join(knobs.state, "tor"), 0o700);
  rmSync(join(knobs.state, "tor.log"), { force: true });
  writeFileSync(torrc, renderTorrc({ stateDir: knobs.state, hsDir, pow: knobs.pow && tor.pow, torLevel }));
  const child = spawn("tor", ["-f", torrc], { stdio: ["ignore", "pipe", "pipe"] });
  return new Promise((res, rej) => {
    let done = false;
    const timer = setTimeout(() => { if (!done) { done = true; child.kill("SIGTERM"); rej(new Error("tor did not bootstrap within the timeout (outbound to the Tor network blocked?)")); } }, timeoutMs);
    const onLine = (buf) => {
      for (const line of buf.toString().split("\n")) {
        if (!line.trim()) continue;
        if (/\[(warn|err)\]/.test(line) || /Bootstrapped (0|5|10|25|50|75|90|100)%/.test(line)) log(`[tor] ${line.replace(/^.*?\[/, "[")}`);
        if (!done && /Bootstrapped 100%/.test(line)) { done = true; clearTimeout(timer); res(child); }
      }
    };
    child.stdout.on("data", onLine); child.stderr.on("data", onLine);
    child.once("exit", (code) => { if (!done) { done = true; clearTimeout(timer); rej(new Error(`tor exited with ${code} before bootstrapping`)); } });
  });
}

export function writeStatus(state) {
  try { writeFileSync(join(state.stateDir, "status.json"), JSON.stringify({ ...state, updatedAt: new Date().toISOString() }, null, 2) + "\n"); } catch {}
}

// Run `node <script>` under `root` with `env`, restarting with exponential backoff (2 s .. 30 s,
// reset after a minute of uptime). Returns { stop() } which prevents further restarts.
export function supervise(name, script, { root, env, state, log = () => {} }) {
  let attempt = 0; let child = null; let stopping = false;
  const start = () => {
    child = spawn(process.execPath, [join(root, script)], { cwd: root, env: { ...process.env, ...env }, stdio: ["ignore", "inherit", "inherit"] });
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
