// replayVerified: a member-set replay must reproduce the contract's nextIndex/activeCount; a
// scan that does not is re-fetched with halved pages and fails closed at the floor.
// Reproduces the M7 rehearsal finding (2026-09-30): a public RPC pool answered a wide
// eth_getLogs with an EMPTY page, the client built a short tree and every tunnel was refused.
import assert from "node:assert/strict";
import { _internals, replayMatchesCounters, replayVerified, reconstructGroup } from "../packages/node/lib/root-provider.mjs";

const { TOPIC, LOGS_CHUNK_FLOOR } = _internals;
const word = (n) => `0x${BigInt(n).toString(16).padStart(64, "0")}`;
const registered = (commitment, index, block) => ({
  blockNumber: `0x${block.toString(16)}`,
  logIndex: "0x0",
  topics: [TOPIC.registeredV4, word(commitment), word(index)],
});
const exiting = (commitment, block) => ({ blockNumber: `0x${block.toString(16)}`, logIndex: "0x1", topics: [TOPIC.exiting, word(commitment)] });

const full = [registered(111, 0, 10), registered(222, 1, 11), exiting(111, 12), registered(333, 2, 13)];
const counters = { nextIndex: 3, activeCount: 2 };

// 1. A complete scan matches the counters first time.
{
  const calls = [];
  const out = await replayVerified({ contract: "0xset", toBlock: "0x20", counters, fetchAll: async (chunk) => { calls.push(chunk); return full; } });
  assert.deepEqual(calls, [10_000]);
  assert.equal(out.replay.active, 2);
  assert.equal(out.replay.group.members.length, 3);
  assert.equal(out.replay.root, reconstructGroup(full).root);
}

// 2. An empty wide page (the live failure) is retried with halved pages until the history arrives.
{
  const calls = [];
  const out = await replayVerified({ contract: "0xset", toBlock: "0x20", counters, fetchAll: async (chunk) => { calls.push(chunk); return chunk <= 2_500 ? full : []; } });
  assert.deepEqual(calls, [10_000, 5_000, 2_500]);
  assert.equal(out.logs.length, 4);
  assert.equal(out.replay.root, reconstructGroup(full).root);
}

// 3. A partial page that keeps a later slot but drops earlier ones is also a mismatch.
{
  const partial = [registered(333, 2, 13)];
  assert.equal(replayMatchesCounters(reconstructGroup(partial), counters), false);
  assert.equal(replayMatchesCounters(reconstructGroup(full), counters), true);
}

// 4. History that never arrives fails closed, naming the RPC, at the page floor.
{
  const calls = [];
  await assert.rejects(
    replayVerified({ contract: "0xset", rpcUrl: "https://rpc.example", toBlock: "0x20", counters, fetchAll: async (chunk) => { calls.push(chunk); return []; } }),
    /member log incomplete from https:\/\/rpc\.example: 0 slots \/ 0 live .* nextIndex 3 \/ activeCount 2 .* use another RPC/,
  );
  assert.equal(calls.at(-1), LOGS_CHUNK_FLOOR);
}

// 5. A set without counters (PaidAccessSet) is replayed as before.
{
  const out = await replayVerified({ contract: "0xpaid", toBlock: "0x20", counters: null, fetchAll: async () => [] });
  assert.equal(out.replay.active, 0);
}

console.log("root-provider-replay.selftest: ok");
