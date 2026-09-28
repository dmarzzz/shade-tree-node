// OPS-17: the spent set survives a gateway restart (fast lane, temp dir only).
//   - an exported snapshot restores into a fresh set: a second distinct share under a restored
//     nullifier still slashes, and an exact late replay is still refused;
//   - expired entries are neither exported nor imported;
//   - the persister writes 0600 atomically, skips unchanged snapshots, tolerates a missing or
//     corrupt file, and SHADE_TREE_SPENT_STATE_FILE=off disables it.
//   node gateway/spent-state.selftest.mjs
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, statSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { makeSpentSet, makeSpentStatePersister, spentStatePath } from "./gateway.mjs";

let clock = 1_000_000;
const now = () => clock;
const slashed = [];
const mk = () => makeSpentSet({
  now,
  ttlMs: 120_000,
  replayWindowMs: 5_000,
  reconstruct: () => 7n,
  derive: () => "leaf",
  slash: async (commitment) => { slashed.push(commitment); },
});

const dir = mkdtempSync(join(tmpdir(), "shade-spent-"));
const path = join(dir, "spent-set.json");
try {
  const a = mk();
  assert.equal((await a.admit("n1", { x: "1", y: "10" }, { nonce: "k" })).action, "first");
  assert.equal((await a.admit("n2", { x: "2", y: "20" }, { nonce: "k" })).action, "first");
  const p = makeSpentStatePersister(a, { path });
  assert.equal(p.flush(), true, "first flush writes");
  assert.equal(p.flush(), false, "unchanged snapshot is not rewritten");
  assert.equal(statSync(path).mode & 0o777, 0o600, "snapshot is 0600");

  // Restart: a fresh set restores both nullifiers.
  clock += 30_000;
  const b = mk();
  assert.equal(makeSpentStatePersister(b, { path }).load(), 2);
  assert.equal((await b.admit("n1", { x: "1", y: "10" }, { nonce: "k" })).action, "replayed-envelope", "late exact replay still refused after restart");
  const r = await b.admit("n1", { x: "3", y: "30" }, { nonce: "k2" });
  assert.equal(r.action, "slash", "a second distinct share after restart still slashes");
  assert.deepEqual(slashed, ["leaf"]);
  assert.equal((await b.admit("n1", { x: "4", y: "40" })).action, "slashed", "slashed flag survives");

  // Expiry: entries older than ttl are dropped on export and on import.
  clock += 200_000;
  assert.equal(b.exportState().entries.length, 0, "expired entries are not exported");
  const c = mk();
  assert.equal(makeSpentStatePersister(c, { path }).load(), 0, "expired snapshot restores nothing");

  // Corrupt and missing files start empty.
  writeFileSync(path, "{not json");
  assert.equal(makeSpentStatePersister(mk(), { path }).load(), 0);
  assert.equal(makeSpentStatePersister(mk(), { path: join(dir, "absent.json") }).load(), 0);
  assert.equal(c.importState({ version: 2, entries: [] }), 0, "unknown snapshot version is ignored");

  // Path resolution.
  assert.equal(spentStatePath({ SHADE_TREE_SPENT_STATE_FILE: "off" }), null);
  assert.equal(spentStatePath({ SHADE_TREE_SPENT_STATE_FILE: path }), path);
  const disabled = makeSpentStatePersister(mk(), { path: null });
  assert.equal(disabled.flush(), false);
  assert.equal(existsSync(join(dir, "spent-set.json.tmp")), false, "no temp file left behind");
} finally {
  rmSync(dir, { recursive: true, force: true });
}
console.log("PASS: spent set persists across restarts");
