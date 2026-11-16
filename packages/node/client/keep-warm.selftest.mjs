// Keep-warm across epochs (no chain, no proof): the slot pool drops its group at every epoch
// rollover; with a contract leaf source it now asks the chain whether the set is unchanged
// (revalidateContractGroup: currentRoot at storage slot 3, plus nextIndex/activeCount for a staked
// set) and reuses the previous group only on an explicit match. Everything else reloads.
// Runs the real makeLeafSourceLoader -> loadGroupFromContract -> makeSlotPool path against a
// loopback fake JSON-RPC that serves Member* logs, counters and the root slot.
//   - match -> reuse (no eth_getLogs), mismatch -> full reload, RPC error -> full reload
//   - adversarial answers (malformed words, missing block, zero slot, counter lies, revert,
//     a forged `prev`, non-boolean check results) never reuse a group
//   - paid sets are checked on the root alone; members.json groups are never revalidated
//
//   node packages/node/client/keep-warm.selftest.mjs
import http from "node:http";
import { makeLeafSourceLoader, makeSlotPool } from "./shade-tree-client.mjs";
import { _internals, reconstructGroup, revalidateContractGroup } from "../lib/root-provider.mjs";
import { identityFor, rateCommitmentOf } from "../lib/rln.mjs";

const { TOPIC } = _internals;
let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

const word = (n) => `0x${BigInt(n).toString(16).padStart(64, "0")}`;
const STAKED = "0x00000000000000000000000000000000000000a1";
const PAID = "0x00000000000000000000000000000000000000b2";
const SECRET = "0x1111";
const LIMIT = 8;
const leaf = (secret) => rateCommitmentOf(identityFor(secret), LIMIT);
const mine = leaf(SECRET);

// ---- fake chain ------------------------------------------------------------------------------
// One contract's state: ordered Member* logs; counters and root are derived from them unless a
// test overrides a field (`lie`), so "the chain" and "the replay" agree by default.
function chainState(kind, members) {
  return { kind, logs: [], lie: {}, members, add(c) { this.logs.push(reg(kind, c, this.logs.length)); }, remove(c) { this.logs.push(rm(kind, c, this.logs.length)); } };
}
function reg(kind, c, n) {
  return kind === "paid"
    ? { blockNumber: `0x${(10 + n).toString(16)}`, logIndex: "0x0", topics: [TOPIC.inserted, word(c)], data: "0x" }
    : { blockNumber: `0x${(10 + n).toString(16)}`, logIndex: "0x0", topics: [TOPIC.registeredV4, word(c), word(n)], data: "0x" };
}
function rm(kind, c, n) {
  return kind === "paid"
    ? { blockNumber: `0x${(10 + n).toString(16)}`, logIndex: "0x0", topics: [TOPIC.paidSlashed, word(c)], data: "0x" }
    : { blockNumber: `0x${(10 + n).toString(16)}`, logIndex: "0x0", topics: [TOPIC.exiting, word(c)], data: "0x" };
}
const chains = new Map();
const calls = [];
let fault = null; // (method, params) -> undefined | { error } | { result } | "drop"

function answer(method, params) {
  const f = fault && fault(method, params);
  if (f) return f;
  if (method === "eth_getBlockByNumber") return { result: { number: "0x64", stateRoot: word(1) } };
  const addr = String(method === "eth_call" ? params[0].to : params[0]?.address ?? params[0]).toLowerCase();
  const st = chains.get(addr);
  if (!st) return { result: method === "eth_getLogs" ? [] : word(0) };
  const replay = reconstructGroup(st.logs);
  if (method === "eth_getLogs") return { result: st.logs };
  if (method === "eth_getStorageAt") {
    if ("root" in st.lie) return { result: st.lie.root };
    return { result: replay.root == null ? word(7) : word(replay.root) }; // nonzero empty-tree root on chain
  }
  if (method === "eth_call") {
    if (st.kind === "paid") return { error: { code: 3, message: "execution reverted" } };
    const sel = params[0].data;
    if (sel === "0xfc7e9c6f") return { result: "nextIndex" in st.lie ? st.lie.nextIndex : word(replay.group.members.length) };
    if (sel === "0x4331ed1f") return { result: "activeCount" in st.lie ? st.lie.activeCount : word(replay.active) };
  }
  return { error: { code: -32601, message: "method not found" } };
}

const server = http.createServer((req, res) => {
  let body = "";
  req.on("data", (d) => { body += d; });
  req.on("end", () => {
    const { id, method, params } = JSON.parse(body);
    calls.push(method);
    const a = answer(method, params);
    if (a === "drop") { res.destroy(); return; }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ jsonrpc: "2.0", id, ...a }));
  });
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const RPC = `http://127.0.0.1:${server.address().port}`;
const count = (m) => calls.filter((c) => c === m).length;
const reset = () => { calls.length = 0; fault = null; };

const noStatic = async () => { throw new Error("ENOENT members.json"); };
function poolFor({ contracts, env = {}, only = "staked", epoch, extra = {} }) {
  const loader = makeLeafSourceLoader({ secret: SECRET, limit: LIMIT, env, contracts, rpcUrl: RPC, loadStatic: noStatic, only });
  const pool = makeSlotPool({ secret: SECRET, K: LIMIT, loadGroupFn: loader, epochOf: () => epoch.v, prove: async () => {}, ...extra });
  return { loader, pool };
}
const roll = async (pool, epoch) => { epoch.v += 1n; pool.ensureEpoch(); return pool.ensureGroup(); };

async function main() {
  console.log("client keep-warm across epochs (revalidated group reuse):");
  const staked = chainState("staked");
  staked.add(leaf("0x9")); staked.add(mine); staked.add(leaf("0x8")); staked.remove(leaf("0x9"));
  chains.set(STAKED, staked);

  // 1. match -> reuse
  reset();
  let epoch = { v: 1n };
  let { pool } = poolFor({ contracts: [{ address: STAKED, kind: "staked" }], epoch });
  pool.ensureEpoch();
  const g1 = await pool.ensureGroup();
  ok(count("eth_getLogs") === 1 && g1.indexOf(mine) === 1, "epoch 1: full load from the contract (one log replay)");
  calls.length = 0;
  const g2 = await roll(pool, epoch);
  ok(g2 === g1 && count("eth_getLogs") === 0, "epoch 2, set unchanged: the previous group is reused, no eth_getLogs");
  ok(calls.length === 4 && count("eth_getStorageAt") === 1 && count("eth_call") === 2 && count("eth_getBlockByNumber") === 1, "the check is 4 calls: header, root slot, nextIndex, activeCount");
  let s = pool.keepWarmStats();
  ok(s.enabled && s.loads === 1 && s.reused === 1 && s.reloadedChanged === 0 && s.reloadedError === 0, "keepWarmStats counts 1 load + 1 reuse");

  // 2. mismatch -> reload (a new member registered: root and both counters move)
  calls.length = 0;
  staked.add(leaf("0x7"));
  const g3 = await roll(pool, epoch);
  ok(g3 !== g1 && count("eth_getLogs") === 1 && g3.indexOf(leaf("0x7")) === 3 && g3.indexOf(mine) === 1, "set changed: full reload, the new group has the new member");
  s = pool.keepWarmStats();
  ok(s.loads === 2 && s.reloadedChanged === 1, "…counted as reloadedChanged");
  calls.length = 0;
  const g4 = await roll(pool, epoch);
  ok(g4 === g3 && count("eth_getLogs") === 0, "next epoch revalidates against the NEW load and reuses it");

  // 3. error -> reload
  calls.length = 0;
  fault = (m) => (m === "eth_getStorageAt" ? { error: { code: -32000, message: "upstream down" } } : undefined);
  const g5 = await roll(pool, epoch);
  ok(g5 !== g4 && count("eth_getLogs") === 1 && pool.keepWarmStats().reloadedError === 1, "check RPC error: full reload (fail closed), counted as reloadedError");
  calls.length = 0;
  fault = (m) => (m === "eth_getBlockByNumber" && calls.length === 1 ? "drop" : undefined);
  const g6 = await roll(pool, epoch);
  ok(g6 !== g5 && count("eth_getLogs") === 1, "check transport failure (connection dropped): full reload");
  fault = null;

  // 4. adversarial answers to the check itself: none may say "same"
  console.log("\nadversarial check answers:");
  const loaded = await makeLeafSourceLoader({ secret: SECRET, limit: LIMIT, contracts: [{ address: STAKED, kind: "staked" }], rpcUrl: RPC, loadStatic: noStatic, only: "staked" });
  const prev = await loaded();
  ok((await loaded.revalidate(prev)) === true, "control: an unchanged set revalidates true");
  const cases = [
    ["root slot shorter than 32 bytes", (m) => (m === "eth_getStorageAt" ? { result: "0x1234" } : undefined)],
    ["root slot not hex", (m) => (m === "eth_getStorageAt" ? { result: "0x" + "zz".repeat(32) } : undefined)],
    ["root slot null", (m) => (m === "eth_getStorageAt" ? { result: null } : undefined)],
    ["root slot a number, not a string", (m) => (m === "eth_getStorageAt" ? { result: 5 } : undefined)],
    ["root slot zero (unset / wrong address)", (m) => (m === "eth_getStorageAt" ? { result: word(0) } : undefined)],
    ["root slot one off", (m) => (m === "eth_getStorageAt" ? { result: word(BigInt(prev.root) + 1n) } : undefined)],
    ["no block", (m) => (m === "eth_getBlockByNumber" ? { result: null } : undefined)],
    ["block number not hex", (m) => (m === "eth_getBlockByNumber" ? { result: { number: "100" } } : undefined)],
    ["block number oversized", (m) => (m === "eth_getBlockByNumber" ? { result: { number: "0x" + "f".repeat(40) } } : undefined)],
    ["malformed JSON-RPC (no result)", (m) => (m === "eth_getStorageAt" ? { notResult: 1 } : undefined)],
    ["nextIndex lies (+1), root matches", (m, p) => (m === "eth_call" && p[0].data === "0xfc7e9c6f" ? { result: word(prev.group.members.length + 1) } : undefined)],
    ["activeCount lies (-1), root matches", (m, p) => (m === "eth_call" && p[0].data === "0x4331ed1f" ? { result: word(prev.count - 1) } : undefined)],
    ["counter word malformed", (m, p) => (m === "eth_call" && p[0].data === "0x4331ed1f" ? { result: "0x01" } : undefined)],
    ["counters revert on a staked set", (m) => (m === "eth_call" ? { error: { code: 3, message: "execution reverted" } } : undefined)],
  ];
  for (const [name, f] of cases) {
    fault = f;
    let out;
    try { out = await loaded.revalidate(prev); } catch (e) { out = `threw: ${e.message.slice(0, 40)}`; }
    ok(out !== true, `${name} -> not reused (${typeof out === "string" ? out : out})`);
  }
  fault = null;

  // a forged or copied prev cannot steer the check (the loader only revalidates its own results)
  calls.length = 0;
  ok((await loaded.revalidate({ ...prev })) === false && calls.length === 0, "a copied prev is not ours: false, no RPC call");
  ok((await loaded.revalidate(null)) === false && (await loaded.revalidate("x")) === false, "null / non-object prev: false");
  // the lib check refuses missing inputs loudly
  let err = null;
  try { await revalidateContractGroup({ contract: STAKED, rpcUrl: RPC, prev: { root: "1" } }); } catch (e) { err = e.message; }
  ok(/needs the previous loaded group/.test(err || ""), "revalidateContractGroup without a group throws");
  err = null;
  try { await revalidateContractGroup({ rpcUrl: RPC, prev }); } catch (e) { err = e.message; }
  ok(/needs a contract address/.test(err || ""), "revalidateContractGroup without a contract throws");
  const r = await revalidateContractGroup({ contract: STAKED, rpcUrl: RPC, prev: { ...prev, root: null } });
  ok(r.same === false && r.reason === "root", "a prev with no root (empty replay) is never reused");

  // non-boolean answers from a custom check never mean "reuse"
  for (const v of ["yes", 1, {}, undefined]) {
    epoch = { v: 1n };
    ({ pool } = poolFor({ contracts: [{ address: STAKED, kind: "staked" }], epoch, extra: { revalidateGroupFn: async () => v } }));
    pool.ensureEpoch();
    const a = await pool.ensureGroup();
    const b = await roll(pool, epoch);
    ok(a !== b && pool.keepWarmStats().loads === 2, `custom check returning ${JSON.stringify(v)} -> reload`);
  }

  // 5. paid set: root alone (no counters exist)
  console.log("\npaid set and opt-outs:");
  const paid = chainState("paid");
  paid.add(leaf("0x5")); paid.add(mine);
  chains.set(PAID, paid);
  reset();
  epoch = { v: 1n };
  ({ pool } = poolFor({ contracts: [{ address: PAID, kind: "paid" }], only: "paid", epoch }));
  pool.ensureEpoch();
  const p1 = await pool.ensureGroup();
  calls.length = 0;
  const p2 = await roll(pool, epoch);
  ok(p2 === p1 && count("eth_getLogs") === 0 && count("eth_call") === 0 && count("eth_getStorageAt") === 1 && calls.length === 2, "paid, unchanged: reused on the root alone (2 calls: header + root slot, no counters)");
  calls.length = 0;
  paid.remove(leaf("0x5"));
  const p3 = await roll(pool, epoch);
  ok(p3 !== p1 && count("eth_getLogs") === 1, "paid, a leaf zeroed in place (root moved): full reload");

  // 6. public-stake-v1 checks at the same finalized tag the load used
  reset();
  const seenTags = [];
  fault = (m, p) => { if (m === "eth_getBlockByNumber") seenTags.push(p[0]); return undefined; };
  epoch = { v: 1n };
  ({ pool } = poolFor({ contracts: [{ address: STAKED, kind: "staked" }], env: { SHADE_TREE_STAKE_PROFILE: "public-stake-v1" }, epoch }));
  pool.ensureEpoch();
  await pool.ensureGroup();
  seenTags.length = 0;
  await roll(pool, epoch);
  ok(seenTags.length === 1 && seenTags[0] === "finalized" && pool.keepWarmStats().reused === 1, "public-stake-v1: the check reads the finalized header, like the load");
  fault = null;

  // 7. members.json is never revalidated (local read; nothing on chain to compare)
  let staticLoads = 0;
  const staticLoader = makeLeafSourceLoader({ secret: SECRET, limit: LIMIT, contracts: [], loadStatic: async () => { staticLoads++; return { group: { members: [] }, root: "R", count: 0 }; } });
  epoch = { v: 1n };
  pool = makeSlotPool({ secret: SECRET, K: LIMIT, loadGroupFn: staticLoader, epochOf: () => epoch.v, prove: async () => {} });
  pool.ensureEpoch();
  await pool.ensureGroup();
  await roll(pool, epoch);
  ok(staticLoads === 2 && pool.keepWarmStats().reused === 0, "members.json group: reloaded every epoch, as before");

  // 8. opt-out and bare loaders keep the old behavior
  reset();
  epoch = { v: 1n };
  ({ pool } = poolFor({ contracts: [{ address: STAKED, kind: "staked" }], epoch, extra: { revalidateGroupFn: null } }));
  pool.ensureEpoch();
  await pool.ensureGroup();
  await roll(pool, epoch);
  ok(count("eth_getLogs") === 2 && pool.keepWarmStats().enabled === false, "revalidateGroupFn: null -> a full load every epoch (old behavior)");
  let bare = 0;
  epoch = { v: 1n };
  pool = makeSlotPool({ secret: SECRET, K: LIMIT, loadGroupFn: async () => { bare++; return { group: { members: [] } }; }, epochOf: () => epoch.v, prove: async () => {} });
  pool.ensureEpoch();
  await pool.ensureGroup();
  await roll(pool, epoch);
  ok(bare === 2 && pool.keepWarmStats().enabled === false, "a loader without .revalidate -> unchanged behavior");

  server.close();
  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: keep-warm selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); server.close(); process.exit(1); });
