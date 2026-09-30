// Reputation tiers (T-FEAT-8) — the FAST half (no proofs; docs/adr/0006-reputation-tiers.md).
// The tier is the leaf's PRIVATE userMessageLimit: Poseidon2(Poseidon1(identitySecret), limit).
// This suite pins the pure surface every side derives from:
//   - normLimit / MAX_LIMIT: 1..65535 (RLN(20,16) range check), precise errors, no coercion
//   - parseTiers / SHADE_TREE_TIERS: ascending, distinct, always contains K_SLOTS
//   - deriveCommitment(secret, limit) / rateCommitmentOf(identity, limit): default == the pre-tier
//     leaf byte-for-byte; a different limit is a different leaf (a member cannot claim a tier)
//   - deriveCommitments + resolveSlashLeaf: picks the tier whose leaf is IN the set; falls back to
//     the default tier (resolved:false) with no leaves (on-chain root mode)
//   - identityFileFor(secret, limit): default file byte-identical; a tier writes `limit` last
//   - enroll --limit: the published leaf commits to that limit (real CLI, commitment-only mode)
//   - client: makeSlotPool wraps at the tier's K; ShadeTreeClient { limit } / SHADE_TREE_LIMIT
// The real-proof half (two tiers proven in ZK, gateway enforcement, forged tier) is
// test/reputation-tiers.selftest.mjs (slow lane).
//
//   node packages/node/lib/tiers.selftest.mjs

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { poseidon1, poseidon2 } from "poseidon-lite";
import {
  K_SLOTS, MAX_LIMIT, TIERS, normLimit, parseTiers, toField,
  identityFor, identitySecretOf, rateCommitmentOf, deriveCommitment, deriveCommitments, resolveSlashLeaf,
  groupFromIdentities, newGroup,
} from "./rln.mjs";
import { identityFileFor, serializeIdentityFile } from "./identity-file.mjs";
import { makeSlotPool, ShadeTreeClient } from "../client/shade-tree-client.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "../../..");

let failures = 0;
function ok(name) { console.log("  PASS  " + name); }
function bad(name, e) { failures++; console.log("  FAIL  " + name + "  ::  " + (e && e.stack || e)); }
async function test(name, fn) { try { await fn(); ok(name); } catch (e) { bad(name, e); } }

console.log("reputation tiers — fast half (T-FEAT-8):");

// ---- normLimit / MAX_LIMIT --------------------------------------------------------------------
await test("normLimit: default K_SLOTS; Number/bigint/decimal string all normalize to a bigint", () => {
  assert.equal(normLimit(), BigInt(K_SLOTS));
  assert.equal(normLimit(32), 32n);
  assert.equal(normLimit(32n), 32n);
  assert.equal(normLimit("32"), 32n);
  assert.equal(normLimit(MAX_LIMIT), 65535n);
  assert.equal(MAX_LIMIT, 2 ** 16 - 1, "RLN(20,16): LIMIT_BIT_SIZE=16");
});
await test("normLimit: rejects 0, negatives, > MAX_LIMIT, floats, hex, junk (precise, no coercion)", () => {
  for (const v of [0, -1, MAX_LIMIT + 1, 65536n, "65536", 1.5, "0x20", "", "abc", null, {}, [8], true]) {
    assert.throws(() => normLimit(v), /limit:/, `normLimit(${String(v)}) must throw`);
  }
});

// ---- parseTiers / SHADE_TREE_TIERS -------------------------------------------------------------------
await test("parseTiers: default = [K_SLOTS]; SHADE_TREE_TIERS is ascending, distinct, and always contains K", () => {
  assert.deepEqual(parseTiers(undefined), [K_SLOTS]);
  assert.deepEqual(parseTiers(""), [K_SLOTS]);
  assert.deepEqual(parseTiers("32"), [K_SLOTS, 32]);
  assert.deepEqual(parseTiers("64, 32,8,32"), [K_SLOTS, 32, 64]);
  assert.deepEqual(TIERS, parseTiers(process.env.SHADE_TREE_TIERS));
});
await test("parseTiers: a bad tier is a precise error (never silently dropped)", () => {
  assert.throws(() => parseTiers("8,x"), /SHADE_TREE_TIERS: bad tier "x"/);
  assert.throws(() => parseTiers("8,0"), /limit: out of range/);
  assert.throws(() => parseTiers("8,70000"), /limit: out of range/);
});

// ---- leaves ------------------------------------------------------------------------------------
const idA = identityFor(toField("0x" + "a1".repeat(32)));
const sA = identitySecretOf(idA);
await test("deriveCommitment(secret) == deriveCommitment(secret, K_SLOTS) == poseidon2(poseidon1(s), K) (pre-tier leaf unchanged)", () => {
  const want = poseidon2([poseidon1([sA]), BigInt(K_SLOTS)]).toString();
  assert.equal(deriveCommitment(sA), want);
  assert.equal(deriveCommitment(sA, K_SLOTS), want);
  assert.equal(rateCommitmentOf(idA).toString(), want);
  assert.equal(rateCommitmentOf(idA, K_SLOTS).toString(), want);
});
await test("a different limit is a different leaf: tiers 8 and 32 of the SAME identity never collide", () => {
  const l8 = deriveCommitment(sA, 8), l32 = deriveCommitment(sA, 32);
  assert.notEqual(l8, l32);
  assert.equal(l32, poseidon2([poseidon1([sA]), 32n]).toString());
  assert.equal(rateCommitmentOf(idA, 32).toString(), l32);
});
await test("deriveCommitment rejects an out-of-range limit (admission-time rule; the circuit would NOT catch > 65535)", () => {
  assert.throws(() => deriveCommitment(sA, 65536), /limit: out of range/);
  assert.throws(() => rateCommitmentOf(idA, 0), /limit: out of range/);
});
await test("groupFromIdentities accepts Identity (default tier) and { identity, limit } entries in ONE tree", () => {
  const idB = identityFor(toField("0x" + "b2".repeat(32)));
  const g = groupFromIdentities([idA, { identity: idB, limit: 32 }]);
  const g2 = newGroup([rateCommitmentOf(idA), rateCommitmentOf(idB, 32)]);
  assert.equal(g.root.toString(), g2.root.toString());
  assert.equal(g.indexOf(rateCommitmentOf(idB, 32)), 1);
  assert.equal(g.indexOf(rateCommitmentOf(idB, 8)), -1, "B's tier-8 leaf is NOT in the tree");
});

// ---- slash-leaf resolution -----------------------------------------------------------------------
await test("deriveCommitments lists one candidate per tier; resolveSlashLeaf picks the one IN the set", () => {
  const cands = deriveCommitments(sA, [8, 32]);
  assert.deepEqual(cands.map((c) => c.limit), [8, 32]);
  assert.equal(cands[1].commitment, deriveCommitment(sA, 32));
  const leaves = new Set([deriveCommitment(sA, 32)]); // A is enrolled at tier 32
  const r = resolveSlashLeaf(sA, { tiers: [8, 32], hasLeaf: (c) => leaves.has(String(c)) });
  assert.deepEqual([r.limit, r.resolved, r.commitment], [32, true, deriveCommitment(sA, 32)]);
});
await test("resolveSlashLeaf: no leaves (on-chain root mode) or no match => the DEFAULT tier's leaf, resolved:false (pre-tier behavior)", () => {
  const r1 = resolveSlashLeaf(sA, { tiers: [8, 32] });
  assert.deepEqual([r1.limit, r1.resolved, r1.commitment], [K_SLOTS, false, deriveCommitment(sA)]);
  const r2 = resolveSlashLeaf(sA, { tiers: [8, 32], hasLeaf: () => false });
  assert.deepEqual([r2.limit, r2.resolved, r2.commitment], [K_SLOTS, false, deriveCommitment(sA)]);
  const r3 = resolveSlashLeaf(sA); // process defaults (TIERS)
  assert.equal(r3.commitment, deriveCommitment(sA));
});

// ---- identity file -----------------------------------------------------------------------------
await test("identityFileFor: default tier writes exactly {identitySecret, leaf} (byte-identical); a tier adds `limit` LAST", () => {
  const sec = "0x" + "c3".repeat(32);
  const d = identityFileFor(sec);
  assert.deepEqual(Object.keys(d), ["identitySecret", "leaf"]);
  assert.equal(serializeIdentityFile(d), JSON.stringify({ identitySecret: d.identitySecret, leaf: d.leaf }, null, 2) + "\n");
  assert.equal(serializeIdentityFile(identityFileFor(sec, K_SLOTS)), serializeIdentityFile(d), "explicit K == default bytes");
  const t = identityFileFor(sec, 32);
  assert.deepEqual(Object.keys(t), ["identitySecret", "leaf", "limit"]);
  assert.equal(t.limit, 32);
  assert.equal(t.identitySecret, d.identitySecret, "same identitySecret");
  assert.equal(t.leaf, rateCommitmentOf(identityFor(sec), 32).toString(), "leaf commits to limit 32");
  assert.notEqual(t.leaf, d.leaf);
  const parsed = JSON.parse(serializeIdentityFile(t));
  assert.deepEqual(parsed, { identitySecret: t.identitySecret, leaf: t.leaf, limit: 32 });
  assert.throws(() => identityFileFor(sec, 65536), /limit: out of range/);
});

// ---- enroll --limit (real CLI, commitment-only: never touches members.json) --------------------
await test("enroll --limit 32 --commitment-only: stdout is a leaf that commits to limit 32 (recomputed from the stderr secret); default enrol == limit 8", () => {
  const run = (args) => spawnSync(process.execPath, [join(ROOT, "group", "enroll.mjs"), ...args], { cwd: ROOT, encoding: "utf8", timeout: 60_000 });
  const r = run(["--commitment-only", "--limit", "32"]);
  assert.equal(r.status, 0, r.stderr);
  const commitment = r.stdout.trim();
  const m = /secret value:\s*(0x[0-9a-fA-F]{64})/.exec(r.stderr);
  assert.ok(m, "stderr carries the secret");
  assert.match(r.stderr, /SHADE_TREE_LIMIT=32/, "stderr tells the member to run with SHADE_TREE_LIMIT=32");
  assert.equal(commitment, rateCommitmentOf(identityFor(m[1]), 32).toString(), "leaf == rateCommitmentOf(secret, 32)");
  assert.notEqual(commitment, rateCommitmentOf(identityFor(m[1])).toString(), "and NOT the tier-8 leaf");
  const d = run(["--commitment-only"]);
  const md = /secret value:\s*(0x[0-9a-fA-F]{64})/.exec(d.stderr);
  assert.equal(d.stdout.trim(), rateCommitmentOf(identityFor(md[1])).toString(), "default enrol is the K_SLOTS leaf");
  assert.doesNotMatch(d.stderr, /SHADE_TREE_LIMIT/, "default enrol does not mention SHADE_TREE_LIMIT");
  const bad1 = run(["--commitment-only", "--limit", "0"]);
  assert.equal(bad1.status, 2);
  assert.match(bad1.stderr, /limit: out of range/);
  const bad2 = run(["--commitment-only", "--limit=70000"]);
  assert.equal(bad2.status, 2);
});

// ---- client ------------------------------------------------------------------------------------
await test("makeSlotPool's explicit unsafe test seam wraps at the tier's K and hands `limit: K` to the prover", async () => {
  const calls = [];
  const pool = makeSlotPool({ secret: "0x01", K: 32, epochOf: () => 5n, loadGroupFn: async () => ({ group: "G" }), prove: async (s, ep, i, sig, opts) => { calls.push({ i, opts }); }, unsafeAllowSlotReuseForTests: true });
  assert.equal(pool.K, 32);
  const slots = [];
  for (let n = 0; n < 33; n++) slots.push(pool.nextSlot().slot);
  assert.equal(slots[31], 31);
  assert.equal(slots[32], 0, "the test-only seam wraps at K=32");
  await new Promise((r) => setTimeout(r, 20)); // let the background warm run
  assert.equal(calls.length, 1);
  assert.equal(calls[0].opts.limit, 32, "the warm proof is made at limit K");
  assert.equal(makeSlotPool({ secret: "0x01", epochOf: () => 5n, prove: async () => {} }).K, K_SLOTS, "default K_SLOTS");
  assert.throws(() => makeSlotPool({ secret: "0x01", K: 0 }), /limit: out of range/);
});
await test("ShadeTreeClient { limit } / SHADE_TREE_LIMIT sets the pool's K; default K_SLOTS", () => {
  const noop = { prove: async () => {}, onion: "x" };
  assert.equal(new ShadeTreeClient({ secret: "0x01", ...noop }).limit, K_SLOTS);
  assert.equal(new ShadeTreeClient({ secret: "0x01", limit: 32, ...noop }).pool.K, 32);
  const prev = process.env.SHADE_TREE_LIMIT;
  process.env.SHADE_TREE_LIMIT = "16";
  try {
    assert.equal(new ShadeTreeClient({ secret: "0x01", ...noop }).limit, 16);
    assert.equal(new ShadeTreeClient({ secret: "0x01", limit: 32, ...noop }).limit, 32, "opts.limit beats env");
    process.env.SHADE_TREE_LIMIT = "70000";
    assert.throws(() => new ShadeTreeClient({ secret: "0x01", ...noop }), /limit: out of range/);
  } finally {
    if (prev === undefined) delete process.env.SHADE_TREE_LIMIT; else process.env.SHADE_TREE_LIMIT = prev;
  }
});

console.log(failures ? `\nSELFTEST FAILED: ${failures} case(s)` : "\nSELFTEST PASSED: all cases green");
process.exit(failures ? 1 : 0);
