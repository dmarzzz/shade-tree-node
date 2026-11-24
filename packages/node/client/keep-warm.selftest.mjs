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
//   - the whole-check deadline also bounds endpoint failover: no request starts after it
//   - generation fence: a check or full load from an older epoch that settles after a newer
//     epoch's reload (successful or failed) publishes nothing into the current cache
//
//   node packages/node/client/keep-warm.selftest.mjs
import http from "node:http";
import { makeLeafSourceLoader, makeSlotPool } from "./shade-tree-client.mjs";
import { _internals, reconstructGroup, revalidateContractGroup, KEEPWARM_CHECK_TIMEOUT_MS } from "../lib/root-provider.mjs";
import { identityFor, rateCommitmentOf, newGroup } from "../lib/rln.mjs";

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
// One chain with a block height. Every add/remove is mined in its own new block, so the chain
// HAS history: each read is answered AT the block it names (a number, or latest/finalized/safe =
// the head), from the logs mined at or before that block. A read that is not pinned to the
// header's number therefore sees the set as it is when the read arrives, not as it was at the
// header. Per contract: ordered Member* logs; counters and root are derived from them unless a
// test overrides a field (`lie`), so "the chain" and "the replay" agree by default.
let head = 100; // the header the fake serves for latest/finalized
function chainState(kind, members) {
  return { kind, logs: [], lie: {}, members, add(c) { this.logs.push(reg(kind, c, ++head)); }, remove(c) { this.logs.push(rm(kind, c, ++head)); } };
}
function reg(kind, c, b) {
  return kind === "paid"
    ? { blockNumber: `0x${b.toString(16)}`, logIndex: "0x0", topics: [TOPIC.inserted, word(c)], data: "0x" }
    : { blockNumber: `0x${b.toString(16)}`, logIndex: "0x0", topics: [TOPIC.registeredV4, word(c), word(b)], data: "0x" };
}
function rm(kind, c, b) {
  return kind === "paid"
    ? { blockNumber: `0x${b.toString(16)}`, logIndex: "0x0", topics: [TOPIC.paidSlashed, word(c)], data: "0x" }
    : { blockNumber: `0x${b.toString(16)}`, logIndex: "0x0", topics: [TOPIC.exiting, word(c)], data: "0x" };
}
const atBlock = (b) => (b === undefined || b === "latest" || b === "finalized" || b === "safe" ? head : /^0x[0-9a-f]+$/i.test(String(b)) ? Number(BigInt(b)) : NaN);
const chains = new Map();
const calls = [];
const reads = []; // { method, block } of every root-slot and counter read: the block param exactly as sent
let fault = null; // (method, params) -> undefined | { error } | { result } | "drop" | "hang"
let after = null; // (method, params) -> void, run once the reply is computed (e.g. mine a block)

function answer(method, params) {
  const f = fault && fault(method, params);
  if (f) return f;
  if (method === "eth_getBlockByNumber") {
    const n = atBlock(params[0]);
    return { result: Number.isFinite(n) && n <= head ? { number: `0x${n.toString(16)}`, stateRoot: word(1) } : null };
  }
  const addr = String(method === "eth_call" ? params[0].to : params[0]?.address ?? params[0]).toLowerCase();
  const blockParam = method === "eth_call" ? params[1] : method === "eth_getStorageAt" ? params[2] : undefined;
  if (blockParam !== undefined) reads.push({ what: method === "eth_call" ? params[0].data : "root", block: blockParam });
  const st = chains.get(addr);
  if (!st) return { result: method === "eth_getLogs" ? [] : word(0) };
  if (method === "eth_getLogs") {
    const from = atBlock(params[0].fromBlock ?? "0x0");
    const to = atBlock(params[0].toBlock);
    return { result: st.logs.filter((l) => Number(BigInt(l.blockNumber)) >= from && Number(BigInt(l.blockNumber)) <= to) };
  }
  const at = atBlock(blockParam);
  if (!Number.isFinite(at) || at > head) return { error: { code: -32000, message: "header not found" } };
  const replay = reconstructGroup(st.logs.filter((l) => Number(BigInt(l.blockNumber)) <= at));
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

// A held reply: the answer is computed (and serialized) when the request arrives, i.e. sampled at
// that moment's chain state, and only SENT when the test releases it. One-shot.
let hold = null; // { match(method, params), entered(), gate: Promise }
function holdNext(match) {
  let entered, release;
  const seen = new Promise((r) => { entered = r; });
  const gate = new Promise((r) => { release = r; });
  hold = { match, entered, gate };
  return { seen, release };
}

const server = http.createServer((req, res) => {
  let body = "";
  req.on("data", (d) => { body += d; });
  req.on("end", async () => {
    const { id, method, params } = JSON.parse(body);
    calls.push(method);
    const a = answer(method, params);
    if (after) after(method, params);
    if (a === "drop") { res.destroy(); return; }
    if (a === "hang") { hung.push({ res, closedAt: null, at: Date.now() }); const h = hung[hung.length - 1]; res.on("close", () => { h.closedAt = Date.now(); }); return; }
    const out = JSON.stringify({ jsonrpc: "2.0", id, ...a });
    if (hold && hold.match(method, params)) {
      const h = hold;
      hold = null;
      h.entered();
      await h.gate;
    }
    res.writeHead(200, { "content-type": "application/json" });
    res.end(out);
  });
});
const hung = []; // requests the fake never answers ("hang"); the client must give up on them
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const RPC = `http://127.0.0.1:${server.address().port}`;
const count = (m) => calls.filter((c) => c === m).length;
const reset = () => { calls.length = 0; reads.length = 0; fault = null; after = null; };

const noStatic = async () => { throw new Error("ENOENT members.json"); };
function poolFor({ contracts, env = {}, only = "staked", epoch, extra = {}, loadStatic = noStatic, loaderOpts = {} }) {
  const loader = makeLeafSourceLoader({ secret: SECRET, limit: LIMIT, env, contracts, rpcUrl: RPC, loadStatic, only, ...loaderOpts });
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

  // 4b. generation fence: a check or full load started in an older epoch settles late. It must
  // never publish into the current epoch's cache, nor turn a current-epoch failure into a success.
  console.log("\nstale epochs (generation fence):");
  const isNextIndex = (m, p) => m === "eth_call" && p[0].data === "0xfc7e9c6f";
  // Hold the LAST read of a staked check (activeCount): every answer the stale check gets was
  // sampled before the set changed, so it really concludes "unchanged" (same: true).
  const isActiveCount = (m, p) => m === "eth_call" && p[0].data === "0x4331ed1f";
  const isLogs = (m) => m === "eth_getLogs";
  const logsFail = (m) => (m === "eth_getLogs" ? { error: { code: -32603, message: "reload unavailable" } } : undefined);
  const settle = (p) => p.then((g) => ({ g }), (e) => ({ e }));
  const fenceSet = () => {
    const st = chainState("staked");
    st.add(mine);
    chains.set(STAKED, st);
    return st;
  };

  // (a) stale CHECK settles after a SUCCESSFUL newer reload (the review repro, success variant)
  {
    const st = fenceSet();
    reset();
    epoch = { v: 1n };
    ({ pool } = poolFor({ contracts: [{ address: STAKED, kind: "staked" }], epoch }));
    pool.ensureEpoch();
    const old = await pool.ensureGroup();
    const h = holdNext(isActiveCount); // epoch 2's check: root + nextIndex match, its last reply stalls
    epoch.v += 1n; pool.ensureEpoch();
    const pendingOld = settle(pool.ensureGroup());
    await h.seen;
    st.add(leaf("0x7")); // the set changes; epoch 3 sees the new root and reloads
    epoch.v += 1n; pool.ensureEpoch();
    const fresh = await pool.ensureGroup();
    ok(fresh !== old && fresh.members.length === 2, "(a) epoch 3: root moved, full reload has 2 members");
    h.release(); // epoch 2's reply arrives: at ITS block the set was unchanged
    const o = await pendingOld;
    const after = await pool.ensureGroup();
    ok(after === fresh, "(a) the stale epoch-2 check does not overwrite the epoch-3 group");
    ok(o.g === fresh, "(a) the stale caller is handed the current epoch's group, not the old one");
    const s2 = pool.keepWarmStats();
    ok(s2.reused === 0 && s2.staleDiscarded === 1, "(a) the stale 'same' is not counted as a reuse; staleDiscarded 1");
    calls.length = 0;
    const next = await roll(pool, epoch);
    ok(next === fresh && count("eth_getLogs") === 0, "(a) next epoch revalidates against the epoch-3 load (lastLoaded not clobbered)");
  }

  // (b) stale CHECK settles after a FAILED newer reload (the review repro, fail-reload variant)
  {
    const st = fenceSet();
    reset();
    epoch = { v: 1n };
    ({ pool } = poolFor({ contracts: [{ address: STAKED, kind: "staked" }], epoch }));
    pool.ensureEpoch();
    const old = await pool.ensureGroup();
    const h = holdNext(isActiveCount);
    epoch.v += 1n; pool.ensureEpoch();
    const pendingOld = settle(pool.ensureGroup());
    await h.seen;
    st.add(leaf("0x7"));
    fault = logsFail;
    epoch.v += 1n; pool.ensureEpoch();
    const cur = await settle(pool.ensureGroup());
    ok(cur.e && /reload unavailable/.test(cur.e.message), "(b) epoch 3: root moved, full reload fails");
    h.release();
    const o = await pendingOld;
    const after = await settle(pool.ensureGroup());
    ok(after.e && after.g === undefined, "(b) the stale successful check does not resurrect the old group: ensureGroup still fails");
    ok(o.e && o.g !== old, "(b) the stale caller gets the current epoch's failure, not the old group");
    fault = null;
    calls.length = 0;
    const next = await roll(pool, epoch);
    ok(next !== old && next.members.length === 2 && count("eth_getLogs") === 1, "(b) next epoch: root still differs from the old load, full reload");
  }

  // (c) stale FULL LOAD settles after a successful newer load
  {
    const st = fenceSet();
    reset();
    epoch = { v: 1n };
    ({ pool } = poolFor({ contracts: [{ address: STAKED, kind: "staked" }], epoch }));
    const h = holdNext(isLogs); // epoch 1's replay reply (1 member) stalls
    pool.ensureEpoch();
    const pendingOld = settle(pool.ensureGroup());
    await h.seen;
    st.add(leaf("0x7"));
    epoch.v += 1n; pool.ensureEpoch(); // nothing loaded yet: epoch 2 starts its own full load
    const fresh = await pool.ensureGroup();
    ok(fresh.members.length === 2, "(c) epoch 2: its own full load has 2 members");
    h.release();
    const o = await pendingOld;
    ok((await pool.ensureGroup()) === fresh && o.g === fresh, "(c) the stale epoch-1 load does not overwrite the epoch-2 group");
    calls.length = 0;
    const next = await roll(pool, epoch);
    ok(next === fresh && count("eth_getLogs") === 0, "(c) next epoch reuses the epoch-2 load: lastLoaded was not replaced by the stale one");
    ok(pool.keepWarmStats().staleDiscarded === 1, "(c) staleDiscarded 1");
  }

  // (d) stale FULL LOAD settles after a FAILED newer load
  {
    const st = fenceSet();
    reset();
    epoch = { v: 1n };
    ({ pool } = poolFor({ contracts: [{ address: STAKED, kind: "staked" }], epoch }));
    const h = holdNext(isLogs);
    pool.ensureEpoch();
    const pendingOld = settle(pool.ensureGroup());
    await h.seen;
    st.add(leaf("0x7"));
    fault = logsFail;
    epoch.v += 1n; pool.ensureEpoch();
    const cur = await settle(pool.ensureGroup());
    ok(cur.e && /reload unavailable/.test(cur.e.message), "(d) epoch 2: its full load fails");
    h.release();
    const o = await pendingOld;
    const after = await settle(pool.ensureGroup());
    ok(after.e && o.e && o.g === undefined, "(d) the stale epoch-1 load cannot satisfy epoch 2: both callers see the failure");
    fault = null;
    calls.length = 0;
    const next = await roll(pool, epoch);
    ok(next.members.length === 2 && count("eth_getLogs") === 1 && pool.keepWarmStats().reused === 0, "(d) next epoch: nothing to revalidate (stale load never became lastLoaded), full load");
  }

  // (e) stale check that ERRORS after a newer reuse: no reloadedError, no extra load into the new epoch
  {
    fenceSet();
    reset();
    epoch = { v: 1n };
    ({ pool } = poolFor({ contracts: [{ address: STAKED, kind: "staked" }], epoch }));
    pool.ensureEpoch();
    const g0 = await pool.ensureGroup();
    const h = holdNext(isNextIndex);
    epoch.v += 1n; pool.ensureEpoch();
    const pendingOld = settle(pool.ensureGroup());
    await h.seen;
    epoch.v += 1n; pool.ensureEpoch();
    const cur = await pool.ensureGroup(); // epoch 3's own check: unchanged -> reuse
    fault = (m) => (m === "eth_call" ? { error: { code: -32000, message: "late failure" } } : undefined);
    h.release(); // the held reply was already serialized as a success; force the next counter to fail
    const o = await pendingOld;
    fault = null;
    const s3 = pool.keepWarmStats();
    ok(cur === g0 && o.g === g0 && s3.loads === 1 && s3.reloadedError === 0, "(e) a late epoch-2 counter failure does not start a reload into epoch 3");
  }

  // 4c. every read of the check is pinned to the header's block number. The chain mines a block
  // that changes the set right after the header is served, so any read taken at a tag (or at the
  // head) instead of the header's number sees the NEW set and the check would say "changed".
  console.log("\none block for every read (pinning):");
  {
    const st = fenceSet();
    st.add(leaf("0x6"));
    reset();
    epoch = { v: 1n };
    ({ pool } = poolFor({ contracts: [{ address: STAKED, kind: "staked" }], env: { SHADE_TREE_STAKE_PROFILE: "public-stake-v1" }, epoch }));
    pool.ensureEpoch();
    const before = await pool.ensureGroup();
    reset();
    const headers = [];
    let mined = false;
    after = (m, p) => {
      if (m !== "eth_getBlockByNumber" || mined) return;
      headers.push(p[0]);
      mined = true;
      st.add(leaf("0x7")); // a new block with a new member, right after the header was sampled
    };
    const hdr = `0x${head.toString(16)}`; // the header the check is about to be served
    const g = await roll(pool, epoch);
    ok(headers[0] === "finalized" && mined, "the check's header read asks for the load's tag (finalized) and the chain then advances one block");
    ok(reads.length === 3 && reads.map((r) => r.what).join(",") === "root,0xfc7e9c6f,0x4331ed1f", "the check makes 3 state reads: root slot, nextIndex(), activeCount()");
    ok(reads.every((r) => r.block === hdr), `root, nextIndex() and activeCount() are all read at the header's block ${hdr} (got ${reads.map((r) => r.block).join(",")})`);
    ok(g === before && pool.keepWarmStats().reused === 1, "at the header's block the set was unchanged: reused (an unpinned read would see the new member)");
    after = null;
    calls.length = 0;
    const g2 = await roll(pool, epoch);
    ok(g2 !== before && g2.members.length === 3 && count("eth_getLogs") === 1, "next epoch's header includes the new block: full reload with the new member");
    // the same through the lib call, with the paid shape (root only)
    const paidSet = chainState("paid");
    paidSet.add(mine);
    chains.set(PAID, paidSet);
    const pl = makeLeafSourceLoader({ secret: SECRET, limit: LIMIT, contracts: [{ address: PAID, kind: "paid" }], rpcUrl: RPC, loadStatic: noStatic, only: "paid" });
    const pprev = await pl();
    reset();
    const phdr = `0x${head.toString(16)}`;
    let pmined = false;
    after = (m) => { if (m === "eth_getBlockByNumber" && !pmined) { pmined = true; paidSet.add(leaf("0x4")); } };
    const pr = await revalidateContractGroup({ contract: PAID, kind: "paid", prev: pprev, rpcUrl: RPC, blockTag: "latest" });
    after = null;
    ok(pr.same === true && pr.block === Number(phdr) && reads.length === 1 && reads[0].block === phdr, "paid set: the root slot is read at the header's block, not at latest");
  }

  // 4d. the check has its own short deadline for the WHOLE check, ahead of the fallback full load
  console.log("\ncheck deadline (a hanging RPC):");
  ok(KEEPWARM_CHECK_TIMEOUT_MS === 5000, "default whole-check deadline KEEPWARM_CHECK_TIMEOUT_MS = 5000 ms (the general RPC deadline is 15000 ms per call)");
  {
    fenceSet();
    reset();
    const BUDGET = 300;
    const lr = makeLeafSourceLoader({ secret: SECRET, limit: LIMIT, contracts: [{ address: STAKED, kind: "staked" }], rpcUrl: RPC, loadStatic: noStatic, only: "staked" });
    const p0 = await lr();
    // three endpoints that all hang on the root slot: a per-call deadline alone would wait once per endpoint
    const three = [RPC, RPC, RPC].join(",");
    fault = (m) => (m === "eth_getStorageAt" ? "hang" : undefined);
    hung.length = 0;
    const t0 = Date.now();
    let msg = null;
    try { await revalidateContractGroup({ contract: STAKED, prev: p0, rpcUrl: three, timeoutMs: BUDGET }); } catch (e) { msg = e.message; }
    const took = Date.now() - t0;
    ok(/timed out/.test(msg || "") && took >= BUDGET - 20 && took < BUDGET + 250, `3 hanging endpoints: the check rejects at its ${BUDGET} ms budget (took ${took} ms), not once per endpoint`);
    const until = Date.now() + 1500;
    while (hung.some((h) => h.closedAt == null) && Date.now() < until) await new Promise((r) => setTimeout(r, 20));
    // the deadline also bounds failover: endpoints 2 and 3 never get a request
    await new Promise((r) => setTimeout(r, 2 * BUDGET));
    ok(hung.length === 1 && hung.every((h) => h.closedAt != null && h.closedAt - t0 < BUDGET + 250), `only the first endpoint got a request, and it was aborted at the deadline (${hung.length} hung, closed after ${hung.map((h) => h.closedAt == null ? "never" : h.closedAt - t0 + " ms").join(", ")})`);
    fault = null;

    // in the pool: the hang costs the budget, then the fallback full load runs
    epoch = { v: 1n };
    ({ pool } = poolFor({ contracts: [{ address: STAKED, kind: "staked" }], epoch, loaderOpts: { checkTimeoutMs: BUDGET } }));
    pool.ensureEpoch();
    const a = await pool.ensureGroup();
    let ethCalls = 0; // root matches, then the check's first counter read hangs (the full load's own counter reads do not)
    fault = (m) => (m === "eth_call" && ethCalls++ === 0 ? "hang" : undefined);
    calls.length = 0;
    const t1 = Date.now();
    epoch.v += 1n; pool.ensureEpoch();
    const b = await pool.ensureGroup();
    const took2 = Date.now() - t1;
    const s5 = pool.keepWarmStats();
    ok(b !== a && count("eth_getLogs") === 1 && s5.reloadedError === 1 && s5.reused === 0, "a hanging counter read: the check gives up and the full load runs (reloadedError 1)");
    ok(took2 >= BUDGET - 20 && took2 < BUDGET + 1500, `time from rollover to the reloaded group ${took2} ms: the budget plus one local full load`);
    fault = null;
  }

  // 4d'. no request starts after the deadline, at any endpoint (fetch stubbed: zero network). Every
  // request start and abort is recorded until well after the budget, across the failover that
  // follows the aborted request. Two shapes: every endpoint hangs on the root read, and the first
  // endpoint fails fast so the deadline lands on the second one mid-failover.
  console.log("\ncheck deadline covers endpoint failover (stub fetch):");
  {
    const realFetch = globalThis.fetch;
    const prevGroup = { group: { members: [] }, root: "1", count: 0 };
    for (const shape of ["all hang", "first fails fast"]) {
      const BUDGET = 120;
      const events = [];
      const t0 = Date.now();
      const mark = (what, extra) => events.push({ what, ms: Date.now() - t0, ...extra });
      // fresh URLs per shape: the sticky-endpoint memory is keyed by the list
      const urls = [1, 2, 3].map((i) => `http://stub-${shape.replace(/ /g, "-")}-${i}.invalid`);
      globalThis.fetch = async (url, opts) => {
        const { method } = JSON.parse(opts.body);
        mark("start", { url, method });
        if (method === "eth_getBlockByNumber") return { json: async () => ({ result: { number: "0x64" } }) };
        if (shape === "first fails fast" && url === urls[0]) throw new TypeError("fetch failed");
        return new Promise((_, reject) => {
          opts.signal.addEventListener("abort", () => { mark("abort", { url, method, reason: String(opts.signal.reason?.message ?? opts.signal.reason) }); reject(opts.signal.reason); }, { once: true });
        });
      };
      let returned = null;
      try {
        try { await revalidateContractGroup({ contract: STAKED, prev: prevGroup, rpcUrl: urls, timeoutMs: BUDGET }); }
        catch (e) { returned = { ms: Date.now() - t0, msg: e.message }; }
        await new Promise((r) => setTimeout(r, 4 * BUDGET)); // past where endpoints 2 and 3 would have started
      } finally { globalThis.fetch = realFetch; }
      const starts = events.filter((e) => e.what === "start");
      const firstAbort = events.findIndex((e) => e.what === "abort");
      // by order, not only by clock: a start recorded after the deadline's abort is late even in the same ms
      const late = events.filter((e, i) => e.what === "start" && ((firstAbort !== -1 && i > firstAbort) || e.ms > BUDGET));
      const aborts = events.filter((e) => e.what === "abort");
      ok(returned && /timed out after 120ms/.test(returned.msg) && returned.ms < BUDGET + 250, `(${shape}) the check rejects at its ${BUDGET} ms budget (took ${returned && returned.ms} ms)`);
      ok(starts.length >= 2 && late.length === 0, `(${shape}) no request starts after the deadline: ${starts.length} starts, last at ${starts.length ? starts[starts.length - 1].ms : "-"} ms, ${late.length} after the expiry`);
      ok(aborts.length === 1 && aborts[0].ms < BUDGET + 250, `(${shape}) the one outstanding request is cancelled at the deadline (${aborts.length} aborts at ${aborts.map((a) => a.ms).join(",")} ms, reason: ${aborts[0] ? aborts[0].reason.slice(0, 60) : "-"})`);
    }
    // A per-request RPC timeout shorter than the budget (SHADE_TREE_RPC_TIMEOUT_MS=70): failover really
    // happens inside the budget (endpoint 2 starts at ~70 ms), and without the shared deadline it
    // would go on to endpoint 3 at ~140 ms. Every request must be closed by the deadline.
    {
      const BUDGET = 120;
      const prevEnv = process.env.SHADE_TREE_RPC_TIMEOUT_MS;
      process.env.SHADE_TREE_RPC_TIMEOUT_MS = "70";
      const events = [];
      const t0 = Date.now();
      const urls = [1, 2, 3].map((i) => `http://stub-short-${i}.invalid`);
      globalThis.fetch = async (url, opts) => {
        const { method } = JSON.parse(opts.body);
        events.push({ what: "start", url, method, ms: Date.now() - t0 });
        if (method === "eth_getBlockByNumber") return { json: async () => ({ result: { number: "0x64" } }) };
        return new Promise((_, reject) => {
          opts.signal.addEventListener("abort", () => { events.push({ what: "abort", url, ms: Date.now() - t0 }); reject(opts.signal.reason); }, { once: true });
        });
      };
      let msg = null;
      try {
        try { await revalidateContractGroup({ contract: STAKED, prev: prevGroup, rpcUrl: urls, timeoutMs: BUDGET }); } catch (e) { msg = e.message; }
        await new Promise((r) => setTimeout(r, 4 * BUDGET));
      } finally {
        globalThis.fetch = realFetch;
        if (prevEnv === undefined) delete process.env.SHADE_TREE_RPC_TIMEOUT_MS; else process.env.SHADE_TREE_RPC_TIMEOUT_MS = prevEnv;
      }
      const starts = events.filter((e) => e.what === "start" && e.method === "eth_getStorageAt");
      const aborts = events.filter((e) => e.what === "abort");
      const late = starts.filter((e) => e.ms > BUDGET);
      ok(/timed out after 120ms/.test(msg || "") && starts.length === 2 && late.length === 0 && aborts.length === 2 && aborts.every((a) => a.ms < BUDGET + 50), `(70 ms per request) failover to endpoint 2 inside the budget, none after it: ${starts.length} root reads at ${starts.map((s) => s.ms).join(",")} ms, aborts at ${aborts.map((a) => a.ms).join(",")} ms, ${late.length} after ${BUDGET} ms`);
    }
    // The request deadline is cut to the time left, so it normally ends with the budget anyway. With
    // the clock frozen that cut is a full budget from the request's own start, which here is 60 ms
    // late: only the check's cancel signal can stop the request at the budget.
    {
      const BUDGET = 120;
      const realNow = Date.now;
      const t0 = realNow();
      const events = [];
      const urls = [1, 2].map((i) => `http://stub-frozen-${i}.invalid`);
      globalThis.fetch = async (url, opts) => {
        const { method } = JSON.parse(opts.body);
        events.push({ what: "start", method, ms: realNow() - t0 });
        if (method === "eth_getBlockByNumber") { await new Promise((r) => setTimeout(r, 60)); return { json: async () => ({ result: { number: "0x64" } }) }; }
        return new Promise((_, reject) => {
          opts.signal.addEventListener("abort", () => { events.push({ what: "abort", ms: realNow() - t0, reason: String(opts.signal.reason?.message ?? opts.signal.reason) }); reject(opts.signal.reason); }, { once: true });
        });
      };
      Date.now = () => t0;
      try {
        try { await revalidateContractGroup({ contract: STAKED, prev: prevGroup, rpcUrl: urls, timeoutMs: BUDGET }); } catch { /* timed out */ }
        await new Promise((r) => setTimeout(r, 2 * BUDGET));
      } finally { Date.now = realNow; globalThis.fetch = realFetch; }
      const aborts = events.filter((e) => e.what === "abort");
      const starts = events.filter((e) => e.what === "start");
      ok(aborts.length === 1 && aborts[0].ms < BUDGET + 30 && /check timed out/.test(aborts[0].reason) && starts.length === 2, `(clock frozen) the check's expiry itself cancels the request in flight (${aborts.length} aborts at ${aborts.map((a) => a.ms).join(",")} ms, reason: ${aborts[0] ? aborts[0].reason.slice(0, 60) : "-"}; ${starts.length} starts)`);
    }
  }

  // 4e. a check that times out, then its LAST read (activeCount) answers late "unchanged" after the
  // set changed. The late reply must not undo the fallback, whether the fallback reload succeeds or fails.
  console.log("\nlate reply after the check deadline:");
  for (const variant of ["reload ok", "reload fails"]) {
    const st = fenceSet();
    reset();
    epoch = { v: 1n };
    ({ pool } = poolFor({ contracts: [{ address: STAKED, kind: "staked" }], epoch, loaderOpts: { checkTimeoutMs: 250 } }));
    pool.ensureEpoch();
    const old = await pool.ensureGroup();
    const h = holdNext(isActiveCount); // the check's LAST read, sampled while unchanged, sent only on release
    epoch.v += 1n; pool.ensureEpoch();
    const pending = settle(pool.ensureGroup());
    await h.seen;
    st.add(leaf("0x7")); // the set changes while the last read is held
    if (variant === "reload fails") fault = logsFail;
    const cur = await pending; // the check hits its 250 ms deadline, then the fallback full load runs
    h.release(); // the held "unchanged" reply arrives after the deadline
    await new Promise((r) => setTimeout(r, 50));
    const again = await settle(pool.ensureGroup());
    const s6 = pool.keepWarmStats();
    ok(s6.reloadedError === 1, `(${variant}) the held check counted as a failed check (reloadedError 1)`);
    if (variant === "reload ok") {
      ok(cur.g && cur.g !== old && cur.g.members.length === 2 && again.g === cur.g && s6.reused === 0, `(${variant}) the late reply does not replace the reloaded group with the old one`);
    } else {
      ok(cur.e && again.e && again.g === undefined && s6.reused === 0, `(${variant}) the late reply does not resurrect the old group: ensureGroup still fails`);
    }
    fault = null;
  }

  // 4f. discovery order is not sticky (members.json and earlier contracts are searched first)
  console.log("\ndiscovery order across epochs:");
  {
    // (i) a second contract configured AHEAD of the one that holds the leaf
    const OTHER = "0x00000000000000000000000000000000000000c3";
    const first = chainState("staked");
    first.add(leaf("0x5"));
    chains.set(OTHER, first);
    const st = fenceSet(); // STAKED holds the leaf
    st.add(leaf("0x6"));
    reset();
    epoch = { v: 1n };
    ({ pool } = poolFor({ contracts: [{ address: OTHER, kind: "staked" }, { address: STAKED, kind: "staked" }], epoch }));
    pool.ensureEpoch();
    const g1 = await pool.ensureGroup();
    ok(g1.members.length === 2 && g1.indexOf(mine) === 0, "(i) epoch 1: the leaf is found in the second configured contract");
    calls.length = 0;
    const g2 = await roll(pool, epoch);
    ok(count("eth_getStorageAt") === 0 && count("eth_getLogs") === 2 && pool.keepWarmStats().reused === 0 && g2.indexOf(mine) === 0, "(i) epoch 2, nothing changed: no reuse, the full discovery runs (both contracts replayed)");
    first.add(mine); // the earlier contract gains the leaf; the reused one is unchanged
    const g3 = await roll(pool, epoch);
    ok(g3.members.length === 2 && g3.indexOf(mine) === 1 && g3.indexOf(leaf("0x5")) === 0, "(i) epoch 3: the earlier contract now holds the leaf and wins, as on a fresh start");
    chains.delete(OTHER);

    // (ii) members.json (searched before every contract) gains the leaf
    let staticHas = false;
    let staticReads = 0;
    const loadStatic = async () => { staticReads++; return { group: newGroup(staticHas ? [leaf("0x3"), mine] : [leaf("0x3")]), count: staticHas ? 2 : 1 }; };
    fenceSet();
    reset();
    epoch = { v: 1n };
    ({ pool } = poolFor({ contracts: [{ address: STAKED, kind: "staked" }], only: "auto", loadStatic, epoch }));
    pool.ensureEpoch();
    await pool.ensureGroup();
    ok((await pool.leafSource()) === "staked", "(ii) epoch 1: members.json does not hold the leaf, the staked set does");
    calls.length = 0;
    staticReads = 0;
    await roll(pool, epoch);
    ok(pool.keepWarmStats().reused === 1 && count("eth_getLogs") === 0 && staticReads === 1, "(ii) epoch 2: members.json reread (still no leaf), the staked group is reused");
    staticHas = true;
    calls.length = 0;
    const gs = await roll(pool, epoch);
    ok(gs.indexOf(mine) === 1 && (await pool.leafSource()) === "invited" && count("eth_getStorageAt") === 0 && pool.keepWarmStats().reused === 1, "(ii) epoch 3: members.json now holds the leaf: no check, rediscovered as invited");
  }

  // 4g. the client's own leaf is removed from the reused set: the group must be dropped
  console.log("\nown leaf removed:");
  {
    const st = fenceSet();
    st.add(leaf("0x6"));
    reset();
    epoch = { v: 1n };
    ({ pool } = poolFor({ contracts: [{ address: STAKED, kind: "staked" }], epoch }));
    pool.ensureEpoch();
    const g1 = await pool.ensureGroup();
    await roll(pool, epoch);
    ok(pool.keepWarmStats().reused === 1, "epoch 2: unchanged, reused");
    st.remove(mine); // exit / slash of this member: zeroed in place, root and activeCount move
    const r1 = await settle(roll(pool, epoch));
    ok(r1.e && /is in none of/.test(r1.e.message) && r1.g === undefined, "epoch 3: own leaf removed -> the check says changed, the full discovery finds no leaf, ensureGroup fails");
    const r2 = await settle(pool.ensureGroup());
    ok(r2.e && r2.g !== g1, "the reused group is not handed out after the failure");
    calls.length = 0;
    const r3 = await settle(roll(pool, epoch));
    const s7 = pool.keepWarmStats();
    ok(r3.e && s7.reused === 1 && s7.reloadedChanged === 2 && count("eth_getLogs") === 1, "epoch 4: still compared against the last good load, still changed, still no group");
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
  fenceSet();
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
