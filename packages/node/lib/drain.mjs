// Operator drain flag (day-two ops). A planned stop should not surprise clients: the operator
// touches ONE file, the heartbeat announces `draining: true` in its signed caps at once (clients
// deprioritise the node), the gateway's /readyz turns 503, and when the file is removed both go
// back. No new protocol: the flag is an ordinary caps key (lib/directory.mjs canonicalCaps).
//
//   SHADE_TREE_DRAIN_FILE   path of the flag file (default <repo>/deploy-state/draining, the one
//                           directory every unit can write; the operator creates it as root)
//   SHADE_TREE_DRAIN_POLL_MS how often the heartbeat looks for the file (default 2000)
//
// `shade-tree-node drain on|off|status` (packages/node/bin/shade-tree.mjs) is the operator face.
import { existsSync, writeFileSync, unlinkSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

export function drainFilePath(env = process.env) {
  const raw = env.SHADE_TREE_DRAIN_FILE;
  if (typeof raw === "string" && raw.trim() !== "") return raw.trim();
  return join(HERE, "../../..", "deploy-state", "draining");
}

export function drainPollMs(env = process.env) {
  const n = Number(env.SHADE_TREE_DRAIN_POLL_MS);
  return Number.isFinite(n) && n >= 200 ? Math.floor(n) : 2000;
}

// True when the flag file exists. TOTAL: an unreadable path reads as "not draining".
export function isDraining(env = process.env, path = drainFilePath(env)) {
  try { return existsSync(path); } catch { return false; }
}

// Seconds since the flag was set (mtime), or null when not draining.
export function drainingSince(env = process.env, path = drainFilePath(env), now = () => Date.now()) {
  try {
    const st = statSync(path);
    return Math.max(0, Math.floor((now() - st.mtimeMs) / 1000));
  } catch { return null; }
}

export function setDraining(on, env = process.env, path = drainFilePath(env)) {
  if (on) writeFileSync(path, `${new Date().toISOString()}\n`, { mode: 0o644 });
  else { try { unlinkSync(path); } catch (e) { if (e?.code !== "ENOENT") throw e; } }
  return isDraining(env, path);
}

// Poll the flag and call onChange(draining) on every transition. `schedule`/`clear` are
// injectable (tests). start() reports the initial state through onChange only when it is true,
// so a service that boots while already draining announces it at once.
export function makeDrainWatcher({ path, pollMs = 2000, onChange, schedule = setInterval, clear = clearInterval, exists = (p) => { try { return existsSync(p); } catch { return false; } } } = {}) {
  let current = null;
  let timer = null;
  const check = () => {
    const next = exists(path);
    if (next !== current) {
      const previous = current;
      current = next;
      if (previous !== null || next) {
        try { onChange?.(next); } catch { /* a listener must not kill the poll */ }
      }
    }
    return current;
  };
  return {
    start() { check(); if (!timer) { timer = schedule(check, pollMs); timer?.unref?.(); } return current; },
    stop() { if (timer) { clear(timer); timer = null; } },
    check,
    state: () => current === true,
  };
}
