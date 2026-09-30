// Crash-safe, cross-process RLN slot allocation.
//
// The state file is deliberately tiny and interoperable with the Rust client:
//   { "version": 1, "epoch": 42, "nextSlot": 3 }
// It is stored under the member's PUBLIC rate-commitment leaf. Neither the bearer
// secret, identity secret, nullifier, target, nor proof is persisted.

import {
  closeSync,
  constants,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmdirSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";

export const SLOT_STATE_VERSION = 1;
// Durable fsyncs can serialize slowly on loaded or network-backed home volumes.
// Ten seconds still fails closed on a stale lock while allowing a bounded burst of
// Proxy/Rust allocators to drain without sacrificing slot uniqueness.
export const DEFAULT_SLOT_LOCK_TIMEOUT_MS = 10_000;
const sleepCell = new Int32Array(new SharedArrayBuffer(4));

export class ShadeTreeSlotStateError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = "ShadeTreeSlotStateError";
    this.code = code;
    Object.assign(this, details);
  }
}

function stateError(code, path, message, cause) {
  return new ShadeTreeSlotStateError(code, `Shade Tree slot state ${message}: ${path}`, { path, cause });
}

function stateRoot(env = process.env) {
  const configured = env.SHADE_TREE_SLOT_STATE_DIR;
  if (configured !== undefined) {
    const value = String(configured).trim();
    if (!value || value === "0" || value.toLowerCase() === "off") {
      throw new ShadeTreeSlotStateError(
        "SHADE_TREE_SLOT_STATE_UNAVAILABLE",
        "SHADE_TREE_SLOT_STATE_DIR cannot disable safety; use unsafeAllowSlotReuseForTests only in an isolated slashing test",
      );
    }
    return value;
  }
  if (env.XDG_STATE_HOME) return join(env.XDG_STATE_HOME, "shade-tree", "rln-slots");
  if (process.platform === "win32" && env.LOCALAPPDATA) return join(env.LOCALAPPDATA, "shade-tree", "rln-slots");
  const home = env.HOME || homedir();
  if (!home) {
    throw new ShadeTreeSlotStateError("SHADE_TREE_SLOT_STATE_UNAVAILABLE", "cannot resolve a local state directory");
  }
  return join(home, ".local", "state", "shade-tree", "rln-slots");
}

// `leaf` is public enrollment data. Using it as the filename gives JS and Rust the
// same default coordinator without persisting any secret-derived bearer material.
export function defaultSlotStatePath({ leaf, env = process.env, dir } = {}) {
  const value = String(leaf ?? "");
  if (!/^[0-9]+$/.test(value)) {
    throw new ShadeTreeSlotStateError("SHADE_TREE_SLOT_STATE_UNAVAILABLE", "cannot derive state path from a non-decimal member leaf");
  }
  return join(dir || stateRoot(env), `${value}.json`);
}

function parseState(raw, path) {
  let value;
  try { value = JSON.parse(raw); }
  catch (cause) { throw stateError("SHADE_TREE_SLOT_STATE_CORRUPT", path, "is corrupt", cause); }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw stateError("SHADE_TREE_SLOT_STATE_CORRUPT", path, "is not an object");
  }
  const keys = Object.keys(value).sort();
  if (keys.join(",") !== "epoch,nextSlot,version" || value.version !== SLOT_STATE_VERSION) {
    throw stateError("SHADE_TREE_SLOT_STATE_CORRUPT", path, "has an unknown shape or version");
  }
  if (!Number.isSafeInteger(value.epoch) || value.epoch < 0 || !Number.isSafeInteger(value.nextSlot) || value.nextSlot < 0) {
    throw stateError("SHADE_TREE_SLOT_STATE_CORRUPT", path, "contains an invalid epoch or nextSlot");
  }
  return value;
}

function loadState(path) {
  try { return parseState(readFileSync(path, "utf8"), path); }
  catch (error) {
    if (error?.code === "ENOENT") return null;
    if (error instanceof ShadeTreeSlotStateError) throw error;
    throw stateError("SHADE_TREE_SLOT_STATE_UNAVAILABLE", path, "cannot be read", error);
  }
}

function syncDirectory(path) {
  // Windows does not permit opening a directory as a file descriptor. The state
  // file itself is still flushed before rename; Unix additionally flushes the
  // parent so the rename survives a power loss.
  if (process.platform === "win32") return;
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY);
    fsyncSync(fd);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function saveState(path, state) {
  const parent = dirname(path);
  const temp = join(parent, `.${process.pid}-${randomBytes(8).toString("hex")}.slot-state.tmp`);
  let fd;
  try {
    fd = openSync(temp, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
    writeFileSync(fd, JSON.stringify({ version: SLOT_STATE_VERSION, epoch: state.epoch, nextSlot: state.nextSlot }, null, 2) + "\n");
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(temp, path);
    syncDirectory(parent);
  } catch (cause) {
    if (fd !== undefined) { try { closeSync(fd); } catch {} }
    try { if (existsSync(temp)) unlinkSync(temp); } catch {}
    throw stateError("SHADE_TREE_SLOT_STATE_UNAVAILABLE", path, "cannot be durably updated", cause);
  }
}

function acquireLock(path, timeoutMs) {
  const lockPath = `${path}.lock`;
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      mkdirSync(lockPath, { mode: 0o700 });
      return lockPath;
    } catch (cause) {
      if (cause?.code !== "EEXIST") {
        throw stateError("SHADE_TREE_SLOT_STATE_UNAVAILABLE", path, "lock cannot be created", cause);
      }
      if (Date.now() >= deadline) {
        throw stateError("SHADE_TREE_SLOT_STATE_LOCKED", path, `remained locked for ${timeoutMs}ms`, cause);
      }
      // The critical section is a few local filesystem operations. A bounded synchronous
      // wait keeps nextSlot() synchronous while allowing racing Proxy/SDK processes through.
      Atomics.wait(sleepCell, 0, 0, 5);
    }
  }
}

// Allocate and DURABLY burn one slot before returning it. A local prover failure or
// process crash therefore costs capacity but can never cause a later process to reuse
// the same nullifier. Missing state is the one valid fresh-start case; corrupt,
// unavailable, stale-locked, or future-epoch state all fail closed.
export function allocatePersistentSlot({ path, epoch, limit, lockTimeoutMs = DEFAULT_SLOT_LOCK_TIMEOUT_MS }) {
  if (typeof path !== "string" || path.length === 0) {
    throw new ShadeTreeSlotStateError("SHADE_TREE_SLOT_STATE_UNAVAILABLE", "a persistent RLN slot state path is required");
  }
  const ep = BigInt(epoch);
  const k = Number(limit);
  if (ep < 0n || ep > BigInt(Number.MAX_SAFE_INTEGER) || !Number.isSafeInteger(k) || k < 1) {
    throw new ShadeTreeSlotStateError("SHADE_TREE_SLOT_STATE_UNAVAILABLE", "invalid epoch or slot limit");
  }
  const timeout = Number(lockTimeoutMs);
  if (!Number.isSafeInteger(timeout) || timeout < 0) {
    throw new ShadeTreeSlotStateError("SHADE_TREE_SLOT_STATE_UNAVAILABLE", "slot lock timeout must be a non-negative integer");
  }
  try { mkdirSync(dirname(path), { recursive: true, mode: 0o700 }); }
  catch (cause) { throw stateError("SHADE_TREE_SLOT_STATE_UNAVAILABLE", path, "directory cannot be created", cause); }

  const lockPath = acquireLock(path, timeout);
  let result;
  let failure;
  try {
    const saved = loadState(path);
    const current = Number(ep);
    if (saved && saved.epoch > current) {
      throw new ShadeTreeSlotStateError(
        "SHADE_TREE_SLOT_STATE_EPOCH_ROLLBACK",
        `Shade Tree slot state refuses epoch rollback from ${saved.epoch} to ${current}: ${path}`,
        { path, savedEpoch: saved.epoch, epoch: current },
      );
    }
    let nextSlot = !saved || saved.epoch < current ? 0 : saved.nextSlot;
    if (nextSlot > k) throw stateError("SHADE_TREE_SLOT_STATE_CORRUPT", path, `has nextSlot ${nextSlot} beyond limit ${k}`);
    if (nextSlot === k) {
      result = { exhausted: true, epoch: ep, used: k, nextSlot: k };
    } else {
      const slot = nextSlot;
      nextSlot += 1;
      saveState(path, { epoch: current, nextSlot });
      result = { exhausted: false, epoch: ep, slot, used: nextSlot, nextSlot };
    }
  } catch (error) {
    failure = error;
  }
  try { rmdirSync(lockPath); }
  catch (cause) {
    throw stateError("SHADE_TREE_SLOT_STATE_UNAVAILABLE", path, "lock cannot be released", cause);
  }
  if (failure) throw failure;
  return result;
}
