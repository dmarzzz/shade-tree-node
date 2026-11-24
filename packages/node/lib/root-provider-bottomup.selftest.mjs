// reconstructGroup builds the untracked prefix of the member log bottom-up (one tree build from a
// leaf array) instead of one Merkle-path update per log. This suite pins that the result is the
// SAME as the per-log replay it replaced, on histories where removals are interleaved with
// registers (the removal of member i follows register i+7, capped at the final register), and for
// every `trackFrom` a caller passes: Infinity (startup, full rescan), a finite poll boundary
// (NodeRootProvider's incremental poll), 0, past the end, negative and NaN.
//
// The oracle below is the previous reconstructGroup body, kept verbatim in shape: an empty
// newGroup(), then addMember / removeMember per ordered log. Equality is checked on root,
// transitions, live count, the commitment -> index map, the full leaf array, and Merkle proofs
// (sibling nodes, so the inner nodes match, not only the root).
//
//   node packages/node/lib/root-provider-bottomup.selftest.mjs

import { reconstructGroup, _internals } from "./root-provider.mjs";
import { newGroup, groupFromLeafArray, groupZeroValue } from "./rln.mjs";

const { TOPIC } = _internals;
let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

const REG = new Set([TOPIC.registered, TOPIC.registeredV4, TOPIC.inserted, TOPIC.deposit]);
const RM = new Set([TOPIC.exiting, TOPIC.withdrawn, TOPIC.slashed, TOPIC.slashedV4, TOPIC.paidSlashed]);

// The per-log replay (the implementation before the bottom-up prefix), as the oracle.
function perLogReplay(logs, trackFrom = Number.POSITIVE_INFINITY) {
  const ordered = [...logs].sort((a, b) => Number(BigInt(a.blockNumber) - BigInt(b.blockNumber)) || Number(BigInt(a.logIndex) - BigInt(b.logIndex)));
  const g = newGroup();
  const liveIndex = new Map();
  let active = 0;
  const transitions = [];
  for (let position = 0; position < ordered.length; position++) {
    const topic0 = (ordered[position].topics[0] || "").toLowerCase();
    const commitment = BigInt(ordered[position].topics[1]).toString();
    let changed = false;
    if (REG.has(topic0)) {
      if (liveIndex.has(commitment)) continue;
      liveIndex.set(commitment, g.members.length);
      g.addMember(BigInt(commitment));
      active++;
      changed = true;
    } else if (RM.has(topic0)) {
      const idx = liveIndex.get(commitment);
      if (idx === undefined) continue;
      g.removeMember(idx);
      liveIndex.delete(commitment);
      active--;
      changed = true;
    }
    if (changed && position >= trackFrom) transitions.push(active === 0 ? null : g.root.toString());
  }
  return { group: g, liveIndex, active, root: active === 0 ? null : g.root.toString(), transitions };
}

// Deterministic field elements (xorshift64*), so a failure reproduces.
let seed = 0x9e3779b97f4a7c15n;
const MASK = (1n << 64n) - 1n;
const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
function rand64() { seed ^= seed >> 12n; seed ^= (seed << 25n) & MASK; seed ^= seed >> 27n; return (seed * 0x2545f4914f6cdd1dn) & MASK; }
const fe = () => ((rand64() << 192n) | (rand64() << 128n) | (rand64() << 64n) | rand64()) % FIELD;
const word = (n) => `0x${BigInt(n).toString(16).padStart(64, "0")}`;
const hex = (n) => `0x${n.toString(16)}`;
const reg = (c, block, li = 0, topic = TOPIC.registeredV4) => ({ blockNumber: hex(block), logIndex: hex(li), topics: [topic, word(c)] });
const rm = (c, block, li = 0, topic = TOPIC.withdrawn) => ({ blockNumber: hex(block), logIndex: hex(li), topics: [topic, word(c)] });

// q24-shaped history: register i at key 2i; for a fraction `frac` of members, the removal of
// member i right after register min(n - 1, i + 7), so the last members' removals are capped at
// the final register. One log per block.
function interleaved(n, frac) {
  const ev = [];
  const commits = [];
  for (let i = 0; i < n; i++) { commits.push(fe()); ev.push({ key: 2 * i, kind: "reg", i, sub: 0 }); }
  let nrm = 0;
  for (let i = 0; i < n; i++) {
    if (Math.floor((i + 1) * frac) > Math.floor(i * frac)) ev.push({ key: 2 * Math.min(n - 1, i + 7) + 1, kind: "rm", i, sub: nrm++ });
  }
  ev.sort((a, b) => a.key - b.key || a.sub - b.sub);
  return ev.map((e, p) => (e.kind === "reg" ? reg(commits[e.i], 1000 + p) : rm(commits[e.i], 1000 + p)));
}

function same(a, b, label, proofAt = []) {
  const am = a.group.members.map(String);
  const bm = b.group.members.map(String);
  let good = a.root === b.root && a.active === b.active
    && JSON.stringify(a.transitions) === JSON.stringify(b.transitions)
    && JSON.stringify([...a.liveIndex]) === JSON.stringify([...b.liveIndex])
    && JSON.stringify(am) === JSON.stringify(bm)
    && String(a.group.root) === String(b.group.root);
  for (const i of proofAt) {
    if (i >= am.length) continue;
    const pa = a.group.generateMerkleProof ? a.group.generateMerkleProof(i) : a.group.merkleTree.createProof(i);
    const pb = b.group.generateMerkleProof ? b.group.generateMerkleProof(i) : b.group.merkleTree.createProof(i);
    good = good && JSON.stringify(pa, (_, v) => (typeof v === "bigint" ? v.toString() : v)) === JSON.stringify(pb, (_, v) => (typeof v === "bigint" ? v.toString() : v));
  }
  ok(good, label);
  return good;
}

// 1. groupFromLeafArray == newGroup on the same leaves, zero value from an empty group.
{
  const leaves = [fe(), fe(), fe(), fe(), fe()];
  const a = groupFromLeafArray(leaves);
  const b = newGroup(leaves);
  ok(String(a.root) === String(b.root), "groupFromLeafArray(leaves).root == newGroup(leaves).root");
  ok(groupZeroValue() === newGroup().zeroValue, "groupZeroValue() == an empty group's zeroValue");
  ok(String(groupFromLeafArray([]).root) === String(newGroup().root), "empty leaf array -> the empty-tree root");
  const c = newGroup(leaves);
  c.removeMember(2);
  const withZero = leaves.slice();
  withZero[2] = groupZeroValue();
  ok(String(groupFromLeafArray(withZero).root) === String(c.root), "zero value at a vacated slot == removeMember on that slot");
  const copy = leaves.slice();
  const d = groupFromLeafArray(copy);
  copy[0] = 7n;
  ok(String(d.root) === String(a.root) && String(d.members[0]) === String(leaves[0]), "the caller keeps its leaf array (the group holds a copy)");
  const e = groupFromLeafArray(leaves.slice(0, 3));
  e.addMember(leaves[3]);
  e.addMember(leaves[4]);
  ok(String(e.root) === String(a.root), "a bottom-up group accepts later appends (same root as built at once)");
}

// 2. q24 interleaved histories, startup (trackFrom = Infinity), several sizes and removal rates.
// (Sizes stay small: the per-log oracle costs one depth-20 path of Poseidon hashes per log.)
for (const [n, frac] of [[64, 0], [64, 0.3], [128, 0.5], [96, 1]]) {
  const logs = interleaved(n, frac);
  same(reconstructGroup(logs), perLogReplay(logs), `q24 history n=${n} removal rate ${frac} (${logs.length} logs): startup replay identical`, [0, 1, 7, Math.floor(n / 2), n - 1]);
}

// 3. Every trackFrom on one interleaved history (the incremental poll boundary can be any log),
//    plus the edge values. The shuffled copy checks the sort is still applied first.
{
  const logs = interleaved(16, 0.4);
  let all = true;
  for (let t = 0; t <= logs.length + 1 && all; t++) all = same(reconstructGroup(logs, { trackFrom: t }), perLogReplay(logs, t), `trackFrom=${t} of ${logs.length}: root, transitions, index map, leaves identical`, [0, 5, 15]);
  for (const t of [-1, Number.NaN, Number.POSITIVE_INFINITY, 1e9]) same(reconstructGroup(logs, { trackFrom: t }), perLogReplay(logs, t), `trackFrom=${t}: identical`);
  const shuffled = logs.map((l, i) => [((i * 7919) % 97), l]).sort((a, b) => a[0] - b[0]).map((x) => x[1]);
  same(reconstructGroup(shuffled, { trackFrom: 9 }), perLogReplay(logs, 9), "unordered input is sorted first (same result as ordered)");
}

// 4. Adversarial / edge logs: duplicate register (reorg echo), removal of an unknown or already
//    removed commitment, re-register after removal (fresh index, old slot stays zero), removal of
//    index 0, every member removed (null root), unknown topic, the other topic spellings, two
//    logs in one block ordered by logIndex. Checked at every trackFrom.
{
  const [a, b, c, d] = [fe(), fe(), fe(), fe()];
  const unknown = { blockNumber: hex(9), logIndex: "0x1", topics: ["0x" + "ab".repeat(32), word(a)] };
  const cases = {
    "duplicate register is skipped (no new index)": [reg(a, 1), reg(b, 2), reg(a, 3), reg(c, 4)],
    "removal of an unknown commitment is skipped": [reg(a, 1), rm(d, 2), reg(b, 3)],
    "double removal is skipped": [reg(a, 1), reg(b, 2), rm(a, 3), rm(a, 4), reg(c, 5)],
    "re-register after removal gets a fresh index": [reg(a, 1), reg(b, 2), rm(a, 3, 0, TOPIC.slashedV4), reg(a, 4), rm(b, 5, 0, TOPIC.exiting)],
    "every member removed -> null root": [reg(a, 1), reg(b, 2), rm(b, 3), rm(a, 4, 0, TOPIC.slashed)],
    "unknown topic is ignored": [reg(a, 1), unknown, reg(b, 10)],
    "paid set spellings (Inserted / Deposit / Slashed)": [reg(a, 1, 0, TOPIC.inserted), reg(b, 2, 0, TOPIC.deposit), rm(a, 3, 0, TOPIC.paidSlashed), reg(c, 4, 0, TOPIC.registered)],
    "same block, ordered by logIndex": [reg(b, 5, 1), reg(a, 5, 0), rm(a, 5, 2), reg(c, 5, 3)],
    "empty log": [],
  };
  for (const [name, logs] of Object.entries(cases)) {
    let all = true;
    for (let t = 0; t <= logs.length && all; t++) all = same(reconstructGroup(logs, { trackFrom: t }), perLogReplay(logs, t), `${name}, trackFrom=${t}`, [0, 1, 2, 3]);
    same(reconstructGroup(logs), perLogReplay(logs), `${name}, startup`, [0, 1, 2, 3]);
  }
  const r = reconstructGroup(cases["every member removed -> null root"]);
  ok(r.root === null && r.active === 0 && r.group.members.length === 2, "all removed: null root, 0 live, both slots kept");
  const rr = reconstructGroup(cases["re-register after removal gets a fresh index"]);
  ok(rr.liveIndex.get(a.toString()) === 2 && String(rr.group.members[0]) === String(groupZeroValue()), "re-registered commitment at index 2, index 0 stays zero");
}

// 5. A malformed commitment still throws, as before (BigInt of a non-numeric topic).
{
  let threw = false;
  try { reconstructGroup([{ blockNumber: "0x1", logIndex: "0x0", topics: [TOPIC.registeredV4, "0xzz"] }]); } catch { threw = true; }
  ok(threw, "a non-numeric commitment topic throws (unchanged)");
}

console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: root-provider-bottomup selftest (${failures} failure${failures === 1 ? "" : "s"})`);
process.exit(failures === 0 ? 0 : 1);
