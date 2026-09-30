// Persistent RLN slot-state safety: restart/crash durability, process races, epoch
// monotonicity, fail-closed storage errors, and no bearer-secret persistence.

import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import {
  ShadeTreeSlotStateError,
  allocatePersistentSlot,
  defaultSlotStatePath,
} from "./slot-state.mjs";

let failures = 0;
async function test(name, fn) {
  try { await fn(); console.log("  PASS  " + name); }
  catch (error) { failures += 1; console.log("  FAIL  " + name + " :: " + (error?.stack || error)); }
}

const work = mkdtempSync(join(tmpdir(), "shade-tree-slot-state-"));
const moduleUrl = pathToFileURL(join(dirname(new URL(import.meta.url).pathname), "slot-state.mjs")).href;
const statePath = (name) => join(work, name, "slots.json");

await test("a process crash after allocation cannot make a restart reuse its slot", () => {
  const path = statePath("crash-restart");
  const script = `import { allocatePersistentSlot } from ${JSON.stringify(moduleUrl)}; allocatePersistentSlot({ path: ${JSON.stringify(path)}, epoch: 50n, limit: 8 }); process.abort();`;
  const crashed = spawnSync(process.execPath, ["--input-type=module", "-e", script], { encoding: "utf8" });
  assert.notEqual(crashed.status, 0, "the allocating child really crashed");
  assert.equal(allocatePersistentSlot({ path, epoch: 50n, limit: 8 }).slot, 1);
});

await test("racing processes atomically receive every slot exactly once", async () => {
  const path = statePath("process-race");
  const count = 16;
  const script = `import { allocatePersistentSlot } from ${JSON.stringify(moduleUrl)}; const r=allocatePersistentSlot({ path: ${JSON.stringify(path)}, epoch: 60n, limit: ${count} }); process.stdout.write(String(r.slot));`;
  const run = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--input-type=module", "-e", script], { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.once("error", reject);
    child.once("close", (code) => code === 0 ? resolve(Number(stdout)) : reject(new Error(`child ${code}: ${stderr}`)));
  });
  const slots = await Promise.all(Array.from({ length: count }, run));
  assert.deepEqual(slots.sort((a, b) => a - b), Array.from({ length: count }, (_, i) => i));
  assert.equal(allocatePersistentSlot({ path, epoch: 60n, limit: count }).exhausted, true);
});

await test("only an advancing protocol epoch resets an exhausted state", () => {
  const path = statePath("epochs");
  assert.equal(allocatePersistentSlot({ path, epoch: 70n, limit: 1 }).slot, 0);
  assert.equal(allocatePersistentSlot({ path, epoch: 70n, limit: 1 }).exhausted, true);
  assert.equal(allocatePersistentSlot({ path, epoch: 71n, limit: 1 }).slot, 0);
  assert.throws(
    () => allocatePersistentSlot({ path, epoch: 70n, limit: 1 }),
    (error) => error instanceof ShadeTreeSlotStateError && error.code === "SHADE_TREE_SLOT_STATE_EPOCH_ROLLBACK",
  );
});

await test("corrupt, locked, and unavailable state all fail closed", () => {
  const corrupt = statePath("corrupt");
  mkdirSync(dirname(corrupt), { recursive: true });
  writeFileSync(corrupt, '{"version":1,"epoch":1,"nextSlot":0,"secret":"nope"}\n');
  assert.throws(
    () => allocatePersistentSlot({ path: corrupt, epoch: 1n, limit: 8 }),
    (error) => error.code === "SHADE_TREE_SLOT_STATE_CORRUPT",
  );

  const locked = statePath("locked");
  mkdirSync(dirname(locked), { recursive: true });
  mkdirSync(`${locked}.lock`);
  assert.throws(
    () => allocatePersistentSlot({ path: locked, epoch: 1n, limit: 8, lockTimeoutMs: 10 }),
    (error) => error.code === "SHADE_TREE_SLOT_STATE_LOCKED",
  );

  const blocker = join(work, "not-a-directory");
  writeFileSync(blocker, "x");
  assert.throws(
    () => allocatePersistentSlot({ path: join(blocker, "slots.json"), epoch: 1n, limit: 8 }),
    (error) => error.code === "SHADE_TREE_SLOT_STATE_UNAVAILABLE",
  );
});

await test("the interoperable state stores only version, epoch, and nextSlot under a public leaf", () => {
  const secret = "bearer-secret-must-never-be-written";
  const leaf = "123456789012345678901234567890"; // public enrollment identifier
  const dir = join(work, "privacy");
  const path = defaultSlotStatePath({ leaf, dir });
  assert.equal(path, join(dir, `${leaf}.json`));
  allocatePersistentSlot({ path, epoch: 80n, limit: 8 });
  const raw = readFileSync(path, "utf8");
  assert.equal(raw.includes(secret), false);
  assert.deepEqual(Object.keys(JSON.parse(raw)).sort(), ["epoch", "nextSlot", "version"]);
  assert.deepEqual(JSON.parse(raw), { version: 1, epoch: 80, nextSlot: 1 });
});

rmSync(work, { recursive: true, force: true });
console.log(failures ? `\nSELFTEST FAILED: ${failures} case(s)` : "\nSELFTEST PASSED: all cases green");
process.exit(failures ? 1 : 0);
