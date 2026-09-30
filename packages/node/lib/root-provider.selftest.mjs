// T-TEST-3: unit test for reconstructRoot in packages/node/lib/root-provider.mjs — the function that rebuilds
// the on-chain admission root from Member* event logs. Gateway and client BOTH run this and must
// agree by construction, so a bug here silently breaks every proof (root mismatch => all DROP) or,
// worse, keeps a removed member admitted. Oracle: the same newGroup the code uses, fed the set we
// expect to survive, so the test fails on any ordering/dedup/removal defect.
//
//   node packages/node/lib/root-provider.selftest.mjs

import http from "node:http";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { reconstructRoot, reconstructGroup, parseContractList, configuredContracts, CompositeRootProvider, fetchMemberLogs, fromBlockFor, isLogRangeError, loadGroupFromContract, NodeRootProvider, LightClientRootProvider, _internals } from "./root-provider.mjs";
import { newGroup } from "./rln.mjs";
import { deployBlockForContract, parseFromBlocks, applyNetworkEnv } from "./network-record.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

// The Member* event topic0 hashes (keccak of the signatures), as hardcoded in root-provider.mjs.
const TOPIC = {
  registered: "0x0dbb6a3ed41d8f3d21e481b86d0e8bbf65a630b7dc4c5ee6c2c1a74561841e6d",
  exiting: "0x971e754215411b0ec07054d759063d876d53872b7d4b37294744e5a776604f37",
  withdrawn: "0x8f2d81dd61a3f7ff90ea7265e45192f03f643615dd2458e287d84aaac222ffe9",
  slashed: "0x707cd9719d0c14265b9e456f7add99095401f907e570e5cdd65a92920947c450",
  // rln-v4 (T-FEAT-8b): the register/slash events carry a trailing non-indexed `limit`.
  registeredV4: "0x509c8735bf3647b16c92625a43b5459d0b51845aa0f3ec846f9d24594e7b824b",
  slashedV4: "0x0a39eb0fcb6a37e10a529e106ae887cbd1721626fa57900170ed0c2437af3797",
  // PaidAccessSet (T-FEAT-7): Inserted / Deposit (append) + Slashed (zero in place), all
  // (commitment indexed, limit, index, root).
  inserted: "0x829b3fd9a2105b78eea5138f4d692eb507be107a9b265a9456ea94fb2db9f992",
  deposit: "0x9b776d199f09c774f5b205c9bc2ac6f40d508c347aaea919867eeaf06ebef0e9",
  paidSlashed: "0xac0c8be2061774c705c517af2a774ab5cb33a2d7fe7054dd4a2728433026029c",
};
const log = (topic0, commitment, block, logIndex = 0) => ({
  topics: [topic0, "0x" + BigInt(commitment).toString(16)],
  blockNumber: "0x" + BigInt(block).toString(16),
  logIndex: "0x" + BigInt(logIndex).toString(16),
});
// Oracle: the root the code SHOULD produce for a given surviving set, in registration order.
const rootOf = (commitments) => newGroup(commitments.map((c) => BigInt(c))).root.toString();

// Oracle for ZERO-IN-PLACE removal (T-DEV-2): build the tree by APPENDING every
// registration in index order, then removeMember() at the ORIGINAL index of each removed
// leaf. This is the Semaphore/RLN convention the contract's immutable append-only leaf
// `index` encodes (StakedReputationSet.nextIndex never renumbers survivors), expressed via
// the Group API on a DIFFERENT path than reconstructRoot's event replay — so it still
// catches an ordering/index bug. `registeredInOrder` is every commitment ever registered,
// in index order (including ones later removed); `removedIndices` are the vacated slots.
const rootWithRemovals = (registeredInOrder, removedIndices) => {
  const g = newGroup();
  for (const c of registeredInOrder) g.addMember(BigInt(c));
  for (const i of removedIndices) g.removeMember(i);
  return g.root.toString();
};

function main() {
  // Superseded roots expire by elapsed time even if no later membership change occurs. This is
  // the safety invariant that makes a finite on-chain unbonding period meaningful.
  {
    let now = 1_000;
    const push = _internals.makeFreshRootRing({ maxRoots: 2, freshnessMs: 60_000, now: () => now });
    ok(push("old").join() === "old", "freshness ring starts with the current root");
    now += 1_000;
    ok(push("new").join() === "new,old", "superseded root remains during its time window");
    now += 60_001;
    ok(push("new").join() === "new", "superseded root expires while the chain is otherwise idle");

    now = 1_000;
    const keepEveryFreshRoot = _internals.makeFreshRootRing({ maxRoots: Number.POSITIVE_INFINITY, freshnessMs: 60_000, now: () => now });
    keepEveryFreshRoot("one");
    now += 1_000; keepEveryFreshRoot("two");
    now += 1_000;
    ok(keepEveryFreshRoot("three").join() === "three,two,one", "time-bounded default does not evict a still-fresh root by count");
  }

  // 1. plain registrations, in order
  {
    const logs = [log(TOPIC.registered, 11, 1), log(TOPIC.registered, 22, 2), log(TOPIC.registered, 33, 3)];
    ok(reconstructRoot(logs) === rootOf([11, 22, 33]), "three registrations -> root of {11,22,33}");
  }

  // 2. out-of-order logs are sorted by (block, logIndex) before building
  {
    const inOrder = [log(TOPIC.registered, 11, 1), log(TOPIC.registered, 22, 2), log(TOPIC.registered, 33, 3)];
    const shuffled = [log(TOPIC.registered, 33, 3), log(TOPIC.registered, 11, 1), log(TOPIC.registered, 22, 2)];
    ok(reconstructRoot(shuffled) === reconstructRoot(inOrder), "log order does not change the root (sorted by block/logIndex)");
    // same-block ordering resolved by logIndex
    const byLogIndex = [log(TOPIC.registered, 22, 5, 1), log(TOPIC.registered, 11, 5, 0)];
    ok(reconstructRoot(byLogIndex) === rootOf([11, 22]), "same-block events ordered by logIndex");
  }

  // 3. removal is ZERO-IN-PLACE (T-DEV-2): exit / withdraw / slash vacate the leaf at its
  // ORIGINAL index; survivors KEEP their indices (they are NOT renumbered). Registered in
  // index order 11@0, 22@1, 33@2. Corrected from the earlier renumber assertion
  // (rootOf([11,33]) etc.), which built a fresh compacted tree and so DISAGREED with the
  // contract's immutable append-only index after any removal — the exact T-DEV-2 divergence.
  {
    const base = [log(TOPIC.registered, 11, 1), log(TOPIC.registered, 22, 2), log(TOPIC.registered, 33, 3)];
    ok(reconstructRoot([...base, log(TOPIC.exiting, 22, 4)]) === rootWithRemovals([11, 22, 33], [1]), "exiting vacates leaf@1 -> [11, _, 33] (indices preserved)");
    ok(reconstructRoot([...base, log(TOPIC.withdrawn, 11, 4)]) === rootWithRemovals([11, 22, 33], [0]), "withdrawn vacates leaf@0 -> [_, 22, 33]");
    ok(reconstructRoot([...base, log(TOPIC.slashed, 33, 4)]) === rootWithRemovals([11, 22, 33], [2]), "slashed vacates leaf@2 -> [11, 22, _]");
    ok(reconstructRoot([...base, log(TOPIC.slashed, 11, 4), log(TOPIC.exiting, 33, 5)]) === rootWithRemovals([11, 22, 33], [0, 2]), "multiple removals vacate leaf@0 and leaf@2 -> [_, 22, _]");
    // zero-in-place must NOT equal the old renumber-of-survivors root (regression guard).
    ok(reconstructRoot([...base, log(TOPIC.exiting, 22, 4)]) !== rootOf([11, 33]), "zero-in-place removal differs from the (wrong) renumber-of-survivors root");
  }

  // 4. re-registration after removal (T-DEV-2): the contract ALLOWS a slashed commitment to
  // register again with a FRESH index (test_ReRegister_AfterSlash), so a later register event
  // for the same commitment RE-ADMITS it at a new leaf while the old slot stays vacated.
  // Corrected from the earlier assertion (rootOf([22]), "stays removed"), which wrongly
  // dropped the legitimately re-registered member. Log: 11@0, 22@1, slash 11 (vacates @0),
  // 11 re-registers @2. Result: [_, 22, 11].
  {
    const logs = [log(TOPIC.registered, 11, 1), log(TOPIC.registered, 22, 2), log(TOPIC.slashed, 11, 3), log(TOPIC.registered, 11, 4)];
    ok(reconstructRoot(logs) === rootWithRemovals([11, 22, 11], [0]), "re-registration after slash re-admits at a fresh index -> [_, 22, 11]");
  }

  // 5. dedup: a repeated registration of the same commitment counts once, keeping first position
  {
    const logs = [log(TOPIC.registered, 11, 1), log(TOPIC.registered, 22, 2), log(TOPIC.registered, 11, 3)];
    ok(reconstructRoot(logs) === rootOf([11, 22]), "duplicate registration deduped (position preserved)");
  }

  // 6. empty / fully-removed set -> null (no root), never a throw
  {
    ok(reconstructRoot([]) === null, "no logs -> null root");
    ok(reconstructRoot([log(TOPIC.registered, 11, 1), log(TOPIC.exiting, 11, 2)]) === null, "register then remove the only member -> null");
  }

  // 7. determinism: identical logs always yield the identical root
  {
    const logs = [log(TOPIC.registered, 7, 1), log(TOPIC.registered, 8, 2), log(TOPIC.registered, 9, 3)];
    ok(reconstructRoot(logs) === reconstructRoot(logs.slice()), "deterministic: same logs -> same root");
  }

  // 8. rln-v4 event generation (T-FEAT-8b): MemberRegistered/MemberSlashed with a `limit`
  //    field have a different topic0 but the same topics[1] leaf; reconstruction is identical,
  //    and a mixed log (v3 + v4 shapes) replays as one history. The provider's own table must
  //    pin the exact hashes (recompute: ethers id('MemberRegistered(uint256,uint64,uint256)')).
  {
    ok(_internals.TOPIC.registeredV4 === TOPIC.registeredV4 && _internals.TOPIC.slashedV4 === TOPIC.slashedV4, "v4 topic0 hashes pinned in root-provider");
    const v3 = [log(TOPIC.registered, 11, 1), log(TOPIC.registered, 22, 2), log(TOPIC.registered, 33, 3), log(TOPIC.slashed, 22, 4)];
    const v4 = [log(TOPIC.registeredV4, 11, 1), log(TOPIC.registeredV4, 22, 2), log(TOPIC.registeredV4, 33, 3), log(TOPIC.slashedV4, 22, 4)];
    const mixed = [log(TOPIC.registered, 11, 1), log(TOPIC.registeredV4, 22, 2), log(TOPIC.registered, 33, 3), log(TOPIC.slashedV4, 22, 4)];
    const want = rootWithRemovals([11, 22, 33], [1]);
    ok(reconstructRoot(v4) === want, "v4 (limit-carrying) events reconstruct the same zero-in-place root");
    ok(reconstructRoot(v3) === reconstructRoot(v4) && reconstructRoot(mixed) === want, "v3 and v4 event shapes are interchangeable in one history");
    ok(reconstructRoot([log("0x" + "ab".repeat(32), 11, 1)]) === null, "an unknown topic0 is ignored (never admits a leaf)");
  }

  // 9. PaidAccessSet event generation (T-FEAT-7): Inserted/Deposit append, Slashed zeroes in
  //    place; the same replay, so a paid set and a staked set reconstruct identically. Plus
  //    reconstructGroup exposes the tree, the live index map and the live count for the client.
  {
    ok(_internals.TOPIC.inserted === TOPIC.inserted && _internals.TOPIC.deposit === TOPIC.deposit && _internals.TOPIC.paidSlashed === TOPIC.paidSlashed, "paid topic0 hashes pinned in root-provider (Inserted / Deposit / Slashed)");
    const paid = [log(TOPIC.inserted, 11, 1), log(TOPIC.deposit, 22, 2), log(TOPIC.inserted, 33, 3), log(TOPIC.paidSlashed, 22, 4)];
    const want = rootWithRemovals([11, 22, 33], [1]);
    ok(reconstructRoot(paid) === want, "paid events (insert, insert, insert, slash middle) reconstruct the zero-in-place root");
    const g = reconstructGroup(paid);
    ok(g.root === want && g.active === 2 && g.liveIndex.get("11") === 0 && g.liveIndex.get("33") === 2 && !g.liveIndex.has("22"), "reconstructGroup: root + live count + commitment->index map (slashed leaf gone, indices preserved)");
    ok(g.group.indexOf(33n) === 2 && g.group.members.length === 3, "reconstructGroup.group is the replayed tree (member proofs can be generated from it)");
    ok(reconstructGroup([]).root === null && reconstructGroup([]).active === 0, "empty log -> null root, 0 live");
  }

  // 10. contract lists (T-FEAT-7): SHADE_TREE_GROUP_CONTRACT as a comma list + SHADE_TREE_PAID_ACCESS_CONTRACT sugar.
  {
    ok(parseContractList("0xA").join() === "0xA" && parseContractList(" 0xA , 0xB,0xa ,, ").join() === "0xA,0xB" && parseContractList("").length === 0 && parseContractList(undefined).length === 0, "parseContractList: trims, drops empties, de-dupes case-insensitively; single = one-element list");
    const cs = configuredContracts({ SHADE_TREE_GROUP_CONTRACT: "0xA,0xB", SHADE_TREE_PAID_ACCESS_CONTRACT: "0xC" });
    ok(cs.map((c) => `${c.kind}:${c.address}`).join() === "staked:0xA,staked:0xB,paid:0xC", "configuredContracts: group list as staked, paid appended");
    ok(configuredContracts({}).length === 0 && configuredContracts({ SHADE_TREE_PAID_ACCESS_CONTRACT: "0xC" }).map((c) => c.kind).join() === "paid", "configuredContracts: none / paid-only");
    ok(configuredContracts({ SHADE_TREE_GROUP_CONTRACT: "0xC", SHADE_TREE_PAID_ACCESS_CONTRACT: "0xc" }).map((c) => `${c.kind}:${c.address}`).join() === "paid:0xC", "a paid address also in the group list is tagged paid once");
  }

  // 11. CompositeRootProvider: the union of children's roots, de-duplicated; a failing child is
  //     dropped from that refresh (errors[]) — only ALL failing throws; polling is covered by
  //     root-provider-poll.selftest.mjs.
  {
    const child = (contract, roots, { throws = false, leafCount = null } = {}) => ({
      contract,
      currentRoots: async () => { if (throws) throw new Error("rpc down"); return { roots, observedAtBlock: 10, finalized: true, leafCount }; },
      onChange: (cb) => { child.cbs = (child.cbs || []).concat(cb); return () => {}; },
      describe: () => ({ provider: "node", contract }),
    });
    const composite = CompositeRootProvider([child("0xA", ["1", "2"]), child("0xB", ["2", "3"], { leafCount: 5 }), child("0xC", [], { throws: true })]);
    return composite.currentRoots().then((r) => {
      ok(r.roots.join() === "1,2,3", "union of roots, de-duplicated, order preserved");
      ok(r.perSource.length === 3 && r.perSource[1].leafCount === 5 && r.perSource[2].error === "rpc down" && r.errors.length === 1, "perSource per child (leafCount passed through); the failing child is reported, not fatal");
      ok(r.observedAtBlock === 10 && r.finalized === true, "observedAtBlock/finalized summarized");
      const allBad = CompositeRootProvider([child("0xA", [], { throws: true })]);
      return allBad.currentRoots().then(() => ok(false, "all children failing must throw"), (e) => ok(/all root providers failed/.test(e.message), "all children failing -> throws (nothing to trust)"));
    }).then(() => {
      let threw = false;
      try { CompositeRootProvider([]); } catch { threw = true; }
      ok(threw, "an empty composite is refused");
    }).then(pagedLogs).then(() => {
      console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: root-provider selftest (${failures} failure${failures === 1 ? "" : "s"})`);
      process.exit(failures === 0 ? 0 : 1);
    }, (e) => { console.error(e); process.exit(1); });
  }
}

// 12. eth_getLogs paging (fleet crash-loop 2026-08-17: publicnode caps one call at 50k blocks and
//     the gateway scanned from 0x0): a fake RPC that REFUSES any range wider than `cap` with the
//     real publicnode message; fetchMemberLogs must recover the FULL log set in order by paging +
//     halving; small ranges stay ONE call; a non-range error is NOT retried; NodeRootProvider
//     reconstructs the same root through the paged path and then scans INCREMENTALLY (finalized).
//     Plus the start-block resolution: SHADE_TREE_FROM_BLOCKS > SHADE_TREE_FROM_BLOCK > network record > 0.
function fakeRpc({ logs, cap, head, storage = "0x0", message = (c) => `exceed maximum block range: ${c}`, resultCap = null, fail = null }) {
  const seen = []; // every eth_getLogs [from, to] asked, in order
  const blockTags = [];
  const state = { head, storage };
  const srv = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => { body += c; });
    req.on("end", () => {
      const j = JSON.parse(body);
      const reply = (result, error) => { res.setHeader("content-type", "application/json"); res.end(JSON.stringify(error ? { jsonrpc: "2.0", id: j.id, error } : { jsonrpc: "2.0", id: j.id, result })); };
      if (j.method === "eth_getBlockByNumber") {
        const tag = j.params[0];
        blockTags.push(tag);
        const n = tag === "latest" || tag === "finalized" ? state.head : Number(BigInt(tag));
        return reply(n == null ? null : { number: "0x" + n.toString(16), stateRoot: "0x" + "00".repeat(32) });
      }
      if (j.method === "eth_getLogs") {
        const f = j.params[0];
        const from = Number(BigInt(f.fromBlock));
        const to = f.toBlock === "latest" || f.toBlock === "finalized" ? state.head : Number(BigInt(f.toBlock));
        seen.push([from, to]);
        if (fail && fail(from, to)) return reply(null, { code: -32000, message: fail(from, to) });
        if (cap != null && to - from + 1 > cap) return reply(null, { code: -32000, message: message(cap) });
        const hit = logs.filter((l) => Number(BigInt(l.blockNumber)) >= from && Number(BigInt(l.blockNumber)) <= to && (!f.address || l.address.toLowerCase() === String(f.address).toLowerCase()));
        if (resultCap != null && hit.length > resultCap) return reply(null, { code: -32005, message: `query returned more than ${resultCap} results. Try with this block range [0x${from.toString(16)}, 0x${to.toString(16)}]` });
        return reply(hit);
      }
      if (j.method === "eth_getStorageAt") return reply(state.storage);
      reply(null);
    });
  });
  return new Promise((resolve) => srv.listen(0, "127.0.0.1", () => resolve({ url: `http://127.0.0.1:${srv.address().port}`, close: () => srv.close(), seen, blockTags, setHead: (n) => { state.head = n; }, setStorage: (v) => { state.storage = v; } })));
}

async function pagedLogs() {
  console.log("\neth_getLogs paging (public RPC range caps):");
  // The RPC last-known-good path has the same hard lifetime as the root ring. An outage may
  // bridge a short poll gap, but cannot keep an exited root alive through unbonding forever.
  {
    let now = 10_000;
    let fail = false;
    const cached = _internals.withCache(
      async () => {
        if (fail) throw new Error("rpc down");
        return { roots: ["current", "nearly-expired"], observedAtBlock: 1, finalized: true };
      },
      { maxStaleMs: 60_000, now: () => now },
    );
    await cached();
    fail = true;
    now += 60_000;
    const stale = await cached();
    ok(stale.stale === true && stale.roots.join() === "current", "last-known-good bridges an outage with only the current root, never extending retired roots toward 2F");
    now += 1;
    await cached().then(
      () => ok(false, "expired last-known-good roots must not be returned"),
      (e) => ok(e.message === "rpc down", "last-known-good roots fail closed after the freshness window"),
    );
  }
  const CONTRACT = "0x" + "ab".repeat(20);
  const T = _internals.TOPIC;
  const evlog = (topic0, c, block, idx = 0) => ({ ...log(topic0, c, block, idx), address: CONTRACT, data: "0x" });
  // 40 registrations spread over blocks 100..100_000 (one every ~2.5k blocks) + a slash + a v4 event.
  const commitments = Array.from({ length: 40 }, (_, i) => 1000 + i);
  const logs = commitments.map((c, i) => evlog(i % 2 ? T.registeredV4 : T.registered, c, 100 + i * 2500, i % 3));
  logs.push(evlog(T.slashedV4, 1005, 100_500, 0));
  const expectRoot = reconstructRoot(logs);
  const same = (a, b) => a.length === b.length && a.every((l, i) => l.blockNumber === b[i].blockNumber && l.logIndex === b[i].logIndex && l.topics[1] === b[i].topics[1]);
  const sortedLogs = [...logs].sort((a, b) => Number(BigInt(a.blockNumber) - BigInt(b.blockNumber)) || Number(BigInt(a.logIndex) - BigInt(b.logIndex)));

  // a. publicnode-style block-range cap (50k) with a 10k default chunk: 11 pages, all logs, in order.
  {
    const rpc = await fakeRpc({ logs, cap: 50_000, head: 101_000 });
    const got = await fetchMemberLogs({ contract: CONTRACT, rpcUrl: rpc.url, fromBlock: "0x0", toBlock: "latest", chunk: 10_000 });
    ok(same(got, sortedLogs), `10k pages under a 50k cap recover every log in order (${got.length}/${logs.length})`);
    ok(rpc.seen.length === 11 && rpc.seen[0][0] === 0 && rpc.seen[0][1] === 9_999 && rpc.seen[10][1] === 101_000, `11 contiguous windows [0..9999] ... [100000..101000] (${rpc.seen.length} calls)`);
    ok(reconstructRoot(got) === expectRoot, "the paged log set replays to the same root");
    // "latest" resolved ONCE: every window's toBlock is a number (no page re-reads the head)
    ok(rpc.seen.every(([, to]) => Number.isInteger(to)) , "toBlock resolved to a number once; pages use explicit ranges");
    rpc.close();
  }
  // b. HALVING: the RPC caps at 3_000 blocks but the chunk starts at 40k -> 40k,20k,10k,5k refused, 2.5k accepted.
  {
    const rpc = await fakeRpc({ logs, cap: 3_000, head: 101_000 });
    const got = await fetchMemberLogs({ contract: CONTRACT, rpcUrl: rpc.url, fromBlock: 0, toBlock: 101_000, chunk: 40_000 });
    ok(same(got, sortedLogs), "halving down to an accepted window still recovers every log in order");
    const widths = rpc.seen.map(([f, t]) => t - f + 1);
    ok(widths.slice(0, 5).join() === "40000,20000,10000,5000,2500", `refused windows halve 40000 -> 20000 -> 10000 -> 5000 -> 2500 (${widths.slice(0, 6).join(",")})`);
    ok(widths.slice(4).every((w) => w <= 2500) && rpc.seen[rpc.seen.length - 1][1] === 101_000, "then stays at the accepted width to the head");
    rpc.close();
  }
  // c. small range = ONE call (the pre-paging fast path, anvil / fresh set), even with a cap.
  {
    const rpc = await fakeRpc({ logs, cap: 50_000, head: 5_000 });
    const got = await fetchMemberLogs({ contract: CONTRACT, rpcUrl: rpc.url, fromBlock: "0x0", toBlock: "latest" });
    ok(rpc.seen.length === 1 && got.length === logs.filter((l) => Number(BigInt(l.blockNumber)) <= 5_000).length, "a range inside one chunk is a single eth_getLogs call");
    await loadGroupFromContract({ contract: CONTRACT, rpcUrl: rpc.url, fromBlock: "0x0" });
    ok(rpc.blockTags.at(-1) === "latest", "generic on-chain export preserves its explicit-tooling latest default");
    rpc.close();
  }
  // d. an RPC that cannot resolve the tag (stub without blocks) -> plain single call with the tag.
  {
    const rpc = await fakeRpc({ logs, cap: null, head: null });
    const got = await fetchMemberLogs({ contract: CONTRACT, rpcUrl: rpc.url, fromBlock: "0x0", toBlock: "latest" });
    ok(rpc.seen.length === 1 && got.length === 0, "unresolvable toBlock -> the single call with the tag (as before)");
    rpc.close();
  }
  // e. Infura-style RESULT-COUNT cap ("query returned more than N results") also halves.
  {
    const rpc = await fakeRpc({ logs, cap: null, resultCap: 6, head: 101_000 });
    const got = await fetchMemberLogs({ contract: CONTRACT, rpcUrl: rpc.url, fromBlock: 0, toBlock: 101_000, chunk: 100_000 });
    ok(same(got, sortedLogs), "a result-size cap (Infura wording) is paged the same way");
    rpc.close();
  }
  // f. a NON-range error is not retried and surfaces verbatim; the floor stops infinite halving.
  {
    const rpc = await fakeRpc({ logs, cap: null, head: 101_000, fail: (f) => (f === 20_000 ? "execution aborted (timeout = 5s)" : null) });
    let err = null;
    try { await fetchMemberLogs({ contract: CONTRACT, rpcUrl: rpc.url, fromBlock: 0, toBlock: 101_000, chunk: 10_000 }); } catch (e) { err = e; }
    ok(err && /execution aborted/.test(err.message) && rpc.seen.length === 3, `a non-range RPC error is thrown, not retried (${err && err.message})`);
    rpc.close();
    const rpc2 = await fakeRpc({ logs, cap: 2, head: 1_000 }); // narrower than the floor
    err = null;
    try { await fetchMemberLogs({ contract: CONTRACT, rpcUrl: rpc2.url, fromBlock: 0, toBlock: 1_000, chunk: 64 }); } catch (e) { err = e; }
    ok(err && isLogRangeError(err) && rpc2.seen.length <= 5, `halving stops at the floor (${_internals.LOGS_CHUNK_FLOOR}) and the range error surfaces (${rpc2.seen.length} tries)`);
    rpc2.close();
  }
  // g. the matcher against the real provider strings (see the table in root-provider.mjs).
  {
    const yes = [
      "eth_getLogs: exceed maximum block range: 50000",
      "Log response size exceeded. You can make eth_getLogs requests with up to a 2K block range and no limit on the response size, or you can request any block range with a cap of 10K logs in the response.",
      "query returned more than 10000 results. Try with this block range [0x1, 0x2710]",
      "eth_getLogs and eth_newFilter are limited to a 10,000 blocks range",
      "block range is too wide", "block range too large", "query exceeds max results 10000", "query timeout exceeded",
      "the response size should not greater than 20000000 bytes", "Block range limit exceeded", "limit exceeded",
    ];
    const no = ["fetch failed", "invalid argument 0: json: cannot unmarshal", "execution reverted", "unknown block", "rate limited"];
    ok(yes.every((m) => isLogRangeError(new Error(m))), "every known range/size cap message matches");
    ok(no.every((m) => !isLogRangeError(new Error(m))), "unrelated RPC errors do not match");
  }
  // h. NodeRootProvider end to end over the capped RPC: same root as the oracle, then INCREMENTAL
  //    (finalized): an unchanged head is no eth_getLogs at all; a moved head fetches only the new
  //    blocks; a head that moved BACKWARDS (RPC switched/behind) triggers a full rescan.
  {
    const rpc = await fakeRpc({ logs, cap: 50_000, head: 101_000 });
    const saved = { SHADE_TREE_FROM_BLOCK: process.env.SHADE_TREE_FROM_BLOCK, SHADE_TREE_FROM_BLOCKS: process.env.SHADE_TREE_FROM_BLOCKS, SHADE_TREE_LOGS_CHUNK: process.env.SHADE_TREE_LOGS_CHUNK, SHADE_TREE_CONFIRMATIONS: process.env.SHADE_TREE_CONFIRMATIONS };
    process.env.SHADE_TREE_FROM_BLOCK = "0x0"; process.env.SHADE_TREE_LOGS_CHUNK = "10000"; delete process.env.SHADE_TREE_FROM_BLOCKS; delete process.env.SHADE_TREE_CONFIRMATIONS;
    try {
      const p = NodeRootProvider({ rpcUrl: rpc.url, contract: CONTRACT });
      const r1 = await p.currentRoots();
      ok(r1.roots[0] === expectRoot && r1.leafCount === 39 && r1.finalized === true, "NodeRootProvider over a capped RPC: paged scan -> the oracle root (39 live leaves)");
      const calls1 = rpc.seen.length;
      ok(calls1 === 11, `first refresh paged the history (${calls1} windows)`);
      const r2 = await p.currentRoots();
      ok(rpc.seen.length === calls1 && r2.roots[0] === expectRoot, "same finalized head again -> NO eth_getLogs (incremental cache)");
      logs.push(evlog(T.inserted, 7777, 101_500, 0));
      const intermediateRoot = reconstructRoot(logs);
      logs.push(evlog(T.inserted, 8888, 101_500, 1));
      rpc.setHead(102_000);
      const r3 = await p.currentRoots();
      ok(rpc.seen.length === calls1 + 1 && rpc.seen[calls1][0] === 101_001 && rpc.seen[calls1][1] === 102_000, `head moved -> ONE window (${rpc.seen[calls1] && rpc.seen[calls1].join("..")}) after the last scanned block`);
      ok(r3.roots[0] === reconstructRoot(logs) && r3.leafCount === 41 && r3.roots[1] === intermediateRoot && r3.roots[2] === expectRoot, "every finalized mutation between polls enters the time ring, including the intermediate root");
      rpc.setHead(100_000); // RPC behind / switched
      const rolledBack = await p.currentRoots();
      ok(rpc.seen.length > calls1 + 1 && rpc.seen[calls1 + 1][0] === 0, "head moved backwards -> full rescan from the start block");
      ok(rolledBack.roots.length === 1, "a scan invalidation resets freshness history instead of timestamping replayed roots as new");
    } finally {
      for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
      rpc.close();
    }
  }
  // i. A long observation gap must not make historical transitions fresh at recovery time.
  {
    let now = 1_000;
    const recoveryLogs = [evlog(T.registeredV4, 1, 1, 0)];
    const rpc = await fakeRpc({ logs: recoveryLogs, cap: 50_000, head: 1 });
    const saved = { SHADE_TREE_FROM_BLOCK: process.env.SHADE_TREE_FROM_BLOCK, SHADE_TREE_FROM_BLOCKS: process.env.SHADE_TREE_FROM_BLOCKS, SHADE_TREE_CONFIRMATIONS: process.env.SHADE_TREE_CONFIRMATIONS };
    process.env.SHADE_TREE_FROM_BLOCK = "0x0"; delete process.env.SHADE_TREE_FROM_BLOCKS; delete process.env.SHADE_TREE_CONFIRMATIONS;
    try {
      const p = NodeRootProvider({ rpcUrl: rpc.url, contract: CONTRACT, freshnessMs: 60_000, now: () => now });
      const before = await p.currentRoots();
      recoveryLogs.push(evlog(T.registeredV4, 2, 2, 0), evlog(T.registeredV4, 3, 3, 0));
      rpc.setHead(3);
      now += 60_001;
      const recovered = await p.currentRoots();
      ok(before.roots[0] !== recovered.roots[0] && recovered.roots.join() === reconstructRoot(recoveryLogs),
        "recovery after freshness elapsed accepts only the current root, not replayed intermediate roots");
    } finally {
      for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
      rpc.close();
    }
  }
  // j. The light-provider ring observes the same hard freshness bound after a long outage.
  {
    let now = 2_000;
    const rpc = await fakeRpc({ logs: [], cap: null, head: 1, storage: "0x1" });
    try {
      const light = LightClientRootProvider({ contract: CONTRACT, rpcUrl: rpc.url, mode: "storageat", freshnessMs: 60_000, now: () => now });
      const before = await light.currentRoots();
      rpc.setHead(2); rpc.setStorage("0x3"); now += 60_001;
      const recovered = await light.currentRoots();
      ok(before.roots.join() === "1" && recovered.roots.join() === "3", "light-provider recovery after freshness elapsed accepts only the newly observed current root");
    } finally {
      rpc.close();
    }
  }
  // k. start-block resolution: SHADE_TREE_FROM_BLOCKS (per contract) > SHADE_TREE_FROM_BLOCK > the network
  //    record's deploy block (SHADE_TREE_NETWORK, else any record naming the address) > 0x0; and
  //    applyNetworkEnv fills BOTH from the record unless either is pinned.
  {
    const PAID = "0x4e8C2Bf5d3c5454A04837401095fce2646484111"; // network/sepolia paidAccessSet, deployBlocks 11510873
    const STAKED = "0xFe48De8b9aCA4386DC31C845d579ae62f04f9d25"; // stakedReputationSet, 11510541
    const OLD = "0xdAE242AE3eCD18e5F74d5e96332fCD4682EB20FC"; // superseded rln-v3, deployBlock 11279842
    const UNKNOWN = "0x" + "11".repeat(20);
    ok(fromBlockFor(PAID, {}) === "0xafa459" && fromBlockFor(STAKED, {}) === "0xafa30d", "no env: the committed sepolia record's per-contract deploy block (paid 11510873 = 0xafa459, staked 11510541 = 0xafa30d)");
    ok(fromBlockFor(OLD, {}) === "0x" + (11279842).toString(16), "a superseded generation's set resolves to ITS deploy block");
    ok(fromBlockFor(UNKNOWN, {}) === "0x0" && fromBlockFor(null, {}) === "0x0", "an address no record knows -> 0x0 (paging keeps it correct, just slow)");
    ok(fromBlockFor(PAID, { SHADE_TREE_FROM_BLOCK: "0x5" }) === "0x5", "SHADE_TREE_FROM_BLOCK beats the record");
    ok(fromBlockFor(PAID, { SHADE_TREE_FROM_BLOCK: "0x5", SHADE_TREE_FROM_BLOCKS: `${PAID.toLowerCase()}=7,${STAKED}=0x9` }) === "0x7" && fromBlockFor(STAKED, { SHADE_TREE_FROM_BLOCK: "0x5", SHADE_TREE_FROM_BLOCKS: `${PAID}=7,${STAKED}=0x9` }) === "0x9" && fromBlockFor(UNKNOWN, { SHADE_TREE_FROM_BLOCK: "0x5", SHADE_TREE_FROM_BLOCKS: `${PAID}=7` }) === "0x5", "SHADE_TREE_FROM_BLOCKS beats SHADE_TREE_FROM_BLOCK for the named contract (case-insensitive; decimal or hex); others fall through");
    let threw = null;
    try { fromBlockFor(PAID, { SHADE_TREE_FROM_BLOCKS: "0x1234=5" }); } catch (e) { threw = e.message; }
    ok(/SHADE_TREE_FROM_BLOCKS: bad entry/.test(threw || ""), "a malformed SHADE_TREE_FROM_BLOCKS entry throws (never silently scans from 0)");
    ok(parseFromBlocks("").size === 0 && parseFromBlocks(undefined).size === 0, "empty map ok");
    ok(deployBlockForContract(PAID, { env: {} }) === 11510873 && deployBlockForContract("nope", { env: {} }) === null, "deployBlockForContract: scans all records without SHADE_TREE_NETWORK; garbage -> null");
    // a temp record: SHADE_TREE_NETWORK resolution + applyNetworkEnv MIN + map, explicit env pinned
    const root = mkdtempSync(join(tmpdir(), "shade-tree-frombk-"));
    try {
      const A = "0x" + "aa".repeat(20), B = "0x" + "bb".repeat(20), G = "0x" + "cc".repeat(20);
      mkdirSync(join(root, "testnet"));
      writeFileSync(join(root, "testnet", "contracts.json"), JSON.stringify({
        network: "testnet", chainId: 31337, status: "live", deployer: A, rpcUrl: "http://127.0.0.1:8545",
        contracts: { stakedReputationSet: A, hasher: A, withdrawVerifier: A, gatewayRegistry: G, paidAccessSet: B },
        deployTxs: { stakedReputationSet: "0x" + "12".repeat(32) }, deployBlock: 100, deployBlocks: { paidAccessSet: 300, gatewayRegistry: 50 },
      }));
      ok(deployBlockForContract(B, { name: "testnet", root }) === 300 && deployBlockForContract(A, { name: "testnet", root }) === 100, "record: per-slot deployBlocks wins, else the batch deployBlock");
      const env = { SHADE_TREE_NETWORK: "testnet" };
      const filled = applyNetworkEnv(env, { root });
      ok(filled.includes("SHADE_TREE_FROM_BLOCK") && env.SHADE_TREE_FROM_BLOCK === "0x32" && env.SHADE_TREE_FROM_BLOCKS === `${A}=100,${B}=300,${G}=50`, `applyNetworkEnv fills SHADE_TREE_FROM_BLOCK = MIN deploy block (0x32 = 50) + the per-contract map (${env.SHADE_TREE_FROM_BLOCKS})`);
      ok(fromBlockFor(A, env) === "0x64" && fromBlockFor(B, env) === "0x12c" && fromBlockFor(UNKNOWN, env) === "0x32", "each configured set then scans from ITS deploy block; an unlisted address from the MIN");
      const pinned = { SHADE_TREE_NETWORK: "testnet", SHADE_TREE_FROM_BLOCK: "0x0" };
      applyNetworkEnv(pinned, { root });
      ok(pinned.SHADE_TREE_FROM_BLOCK === "0x0" && !("SHADE_TREE_FROM_BLOCKS" in pinned) && fromBlockFor(B, pinned) === "0x0", "an explicit SHADE_TREE_FROM_BLOCK pins BOTH (no derived map out-ranks it): explicit env always wins");
      const pinnedMap = { SHADE_TREE_NETWORK: "testnet", SHADE_TREE_FROM_BLOCKS: `${B}=7` };
      applyNetworkEnv(pinnedMap, { root });
      ok(!("SHADE_TREE_FROM_BLOCK" in pinnedMap) && fromBlockFor(B, pinnedMap) === "0x7" && deployBlockForContract(A, { env: pinnedMap, root }) === 100, "an explicit SHADE_TREE_FROM_BLOCKS pins the map (SHADE_TREE_FROM_BLOCK not derived); an unnamed contract still resolves its record deploy block");
    } finally { rmSync(root, { recursive: true, force: true }); }
  }
}

main();
