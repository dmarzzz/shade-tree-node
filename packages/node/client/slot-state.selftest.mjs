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
  migrateLeafCursor,
} from "./slot-state.mjs";
import { readFileSync as readFile, existsSync } from "node:fs";

let failures = 0;
async function test(name, fn) {
  try { await fn(); console.log("  PASS  " + name); }
  catch (error) { failures += 1; console.log("  FAIL  " + name + " :: " + (error?.stack || error)); }
}

const ROOT = join(dirname(new URL(import.meta.url).pathname), "..", "..", "..");
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

await test("the interoperable state stores only version, epoch, and nextSlot under a public key", () => {
  const secret = "bearer-secret-must-never-be-written";
  const key = "123456789012345678901234567890"; // public identity commitment
  const dir = join(work, "privacy");
  const path = defaultSlotStatePath({ key, dir });
  assert.equal(path, join(dir, `${key}.json`));
  allocatePersistentSlot({ path, epoch: 80n, limit: 8 });
  const raw = readFileSync(path, "utf8");
  assert.equal(raw.includes(secret), false);
  assert.deepEqual(Object.keys(JSON.parse(raw)).sort(), ["epoch", "nextSlot", "version"]);
  assert.deepEqual(JSON.parse(raw), { version: 1, epoch: 80, nextSlot: 1 });
});

await test("two leaves of one secret share one per-epoch budget (B: no cross-set messageId reuse)", () => {
  // Keyed by the identity commitment, a tier-1 leaf and a tier-8 leaf of one secret resolve to
  // ONE cursor file, so the second leaf continues the cursor instead of reissuing messageId 0.
  const commitment = "77"; // one commitment, both leaves
  const dir = join(work, "shared-budget");
  const path = defaultSlotStatePath({ key: commitment, dir });
  // The new one-tier (limit 8) set proves first: messageIds 0,1,2.
  assert.equal(allocatePersistentSlot({ path, epoch: 100n, limit: 8 }).slot, 0);
  assert.equal(allocatePersistentSlot({ path, epoch: 100n, limit: 8 }).slot, 1);
  assert.equal(allocatePersistentSlot({ path, epoch: 100n, limit: 8 }).slot, 2);
  // The old tier-1 leaf of the SAME secret, same epoch, same file: exhausted, never a 2nd 0.
  assert.equal(allocatePersistentSlot({ path, epoch: 100n, limit: 1 }).exhausted, true);
  // Next epoch both tiers start fresh at 0 on the shared cursor.
  assert.equal(allocatePersistentSlot({ path, epoch: 101n, limit: 1 }).slot, 0);
  assert.equal(allocatePersistentSlot({ path, epoch: 101n, limit: 8 }).slot, 1);
});

await test("a higher-tier cursor exhausts a lower tier rather than reporting corruption", () => {
  const dir = join(work, "cross-tier");
  const path = defaultSlotStatePath({ key: "7", dir });
  for (let i = 0; i < 6; i += 1) assert.equal(allocatePersistentSlot({ path, epoch: 5n, limit: 8 }).slot, i);
  assert.equal(allocatePersistentSlot({ path, epoch: 5n, limit: 1 }).exhausted, true);
  assert.equal(allocatePersistentSlot({ path, epoch: 5n, limit: 4 }).exhausted, true);
  // Beyond the RLN range is still corrupt.
  writeFileSync(path, JSON.stringify({ version: 1, epoch: 5, nextSlot: 70000 }) + "\n");
  assert.throws(() => allocatePersistentSlot({ path, epoch: 5n, limit: 8 }), (e) => e.code === "SHADE_TREE_SLOT_STATE_CORRUPT");
});

await test("migrateLeafCursor seeds the new cursor from the legacy leaf file once", () => {
  // Mid-epoch upgrade: the legacy per-leaf file has advanced to nextSlot 2; the new
  // per-commitment file must continue at 2, never restart at 0.
  const dir = join(work, "migrate");
  const legacy = defaultSlotStatePath({ key: "111", dir });
  const fresh = defaultSlotStatePath({ key: "222", dir });
  allocatePersistentSlot({ path: legacy, epoch: 7n, limit: 8 });
  allocatePersistentSlot({ path: legacy, epoch: 7n, limit: 8 });
  assert.equal(existsSync(fresh), false);
  migrateLeafCursor(fresh, legacy);
  assert.deepEqual(JSON.parse(readFile(fresh, "utf8")), { version: 1, epoch: 7, nextSlot: 2 });
  assert.equal(allocatePersistentSlot({ path: fresh, epoch: 7n, limit: 8 }).slot, 2, "continues, never reissues 0 or 1");
  // Idempotent and non-destructive.
  migrateLeafCursor(fresh, legacy);
  assert.equal(JSON.parse(readFile(fresh, "utf8")).nextSlot, 3);
  assert.equal(existsSync(legacy), true);
  // No legacy file: fresh start, no throw, nothing created.
  const brandNew = defaultSlotStatePath({ key: "333", dir });
  migrateLeafCursor(brandNew, defaultSlotStatePath({ key: "444", dir }));
  assert.equal(existsSync(brandNew), false);
});

await test("the cursor is named by the identity commitment shared with the Rust client", () => {
  const vectors = JSON.parse(readFile(join(ROOT, "testdata", "identity", "vectors.json"), "utf8"));
  const path = defaultSlotStatePath({ key: vectors.identityCommitment, dir: "/state" });
  assert.equal(path, join("/state", `${vectors.identityCommitment}.json`));
});

rmSync(work, { recursive: true, force: true });
console.log(failures ? `\nSELFTEST FAILED: ${failures} case(s)` : "\nSELFTEST PASSED: all cases green");
process.exit(failures ? 1 : 0);
