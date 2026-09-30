import assert from "node:assert/strict";
import { ethers } from "ethers";
import { makeEngine, makeStore } from "./registrar.mjs";
import { randomNonce, signAuthorization, tokenDomain } from "./eip3009.mjs";

const buyer = ethers.Wallet.createRandom();
const asset = ethers.Wallet.createRandom().address;
const payTo = ethers.Wallet.createRandom().address;
const nowMs = 1_800_000_000_000;
const offer = {
  asset,
  assetName: "Test USD",
  assetVersion: "1",
  chainId: 1,
  payTo,
  tiers: { "8": "100" },
  settleBufferSec: 5,
};
const domain = tokenDomain({ name: offer.assetName, version: offer.assetVersion, chainId: offer.chainId, asset });

async function authorization() {
  const auth = {
    from: buyer.address,
    to: payTo,
    value: "100",
    validAfter: "0",
    validBefore: String(Math.floor(nowMs / 1000) + 600),
    nonce: randomNonce(),
  };
  return { auth, signature: await signAuthorization(buyer, domain, auth) };
}

const forever = () => new Promise(() => {});
const fakeProvider = { getTransactionReceipt: async () => null };
const baseSet = (insert) => ({
  insert,
  limitOf: async () => 0n,
  burned: async () => false,
  currentRoot: async () => 0n,
  leafCount: async () => 0n,
  interface: { parseLog: () => null },
});

assert.throws(
  () => makeEngine({ offer, token: {}, set: {}, provider: {}, store: makeStore(null), confirmations: 0 }),
  /SHADE_TREE_PAY_CONFIRMATIONS must be a positive integer/,
);

// Old stores can contain a submitted state without the transaction hash. Neither the EIP-3009
// authorization bit (which also means "canceled") nor current leaf visibility can distinguish a
// final transaction from a pending or absent one, so both states require manual reconciliation.
{
  const store = makeStore(null);
  store.put({
    asset, from: buyer.address, nonce: `0x${"88".repeat(32)}`,
    commitment: "654", limit: 8, protocol: "x402", state: "settling", createdAt: nowMs,
  });
  store.put({
    asset, from: buyer.address, nonce: `0x${"99".repeat(32)}`,
    commitment: "456", limit: 8, protocol: "mpp", state: "inserting", createdAt: nowMs,
  });
  const token = {
    authorizationState: async () => { throw new Error("a canceled authorization is not proof of settlement"); },
  };
  const set = {
    limitOf: async () => { throw new Error("leaf visibility is not proof of insert finality"); },
  };
  const provider = {
    getTransactionReceipt: async () => { throw new Error("there is no hash to query"); },
  };
  const engine = makeEngine({ offer, token, set, provider, store, now: () => nowMs });
  assert.deepEqual(await engine.recover(), { resumed: 0, failed: 0, pending: 2 });
  assert.equal(store.byNonce(`0x${"88".repeat(32)}`)[0].state, "settling");
  assert.equal(store.byNonce(`0x${"99".repeat(32)}`)[0].state, "inserting");
}

// Restart reconciliation must honor the same confirmation depth as the original wait. A visible
// leaf is not a shortcut: with confirmations=2, both transactions remain pending at depth one.
{
  const settlementHash = `0x${"44".repeat(32)}`;
  const insertHash = `0x${"55".repeat(32)}`;
  let head = 20;
  const provider = {
    getTransactionReceipt: async (hash) => ({
      status: 1,
      blockNumber: hash === settlementHash || hash === insertHash ? 20 : 0,
      logs: [],
    }),
    getBlockNumber: async () => head,
  };
  const store = makeStore(null);
  store.put({
    asset, from: buyer.address, nonce: `0x${"66".repeat(32)}`,
    commitment: "789", limit: 8, protocol: "x402", state: "settling",
    settleTx: settlementHash, createdAt: nowMs,
  });
  store.put({
    asset, from: buyer.address, nonce: `0x${"77".repeat(32)}`,
    commitment: "987", limit: 8, protocol: "mpp", state: "inserting",
    settleTx: settlementHash, insertTx: insertHash, createdAt: nowMs,
  });
  const insert = async () => { throw new Error("one-confirmation recovery must not submit another insert"); };
  insert.staticCall = async () => {};
  const set = {
    ...baseSet(insert),
    limitOf: async (commitment) => commitment === "987" ? 8n : 0n,
  };
  const token = {
    authorizationState: async () => true,
    balanceOf: async () => 1_000n,
  };
  const engine = makeEngine({
    offer, token, set, provider, store, confirmations: 2,
    receiptDeadlineMs: 20, now: () => nowMs,
  });
  assert.deepEqual(await engine.recover(), { resumed: 0, failed: 0, pending: 2 });
  assert.equal(store.byNonce(`0x${"66".repeat(32)}`)[0].state, "settling");
  assert.equal(store.byNonce(`0x${"77".repeat(32)}`)[0].state, "inserting");
  head = 21;
}

// A settlement that keeps returning no receipt is bounded, retained as pending, and cannot be
// submitted a second time when the payer retries the identical authorization.
{
  const settleHash = `0x${"11".repeat(32)}`;
  let settleCalls = 0;
  let settleWaitArgs = null;
  const transfer = async () => {
    settleCalls++;
    return {
      hash: settleHash,
      wait: (...args) => { settleWaitArgs = args; return forever(); },
    };
  };
  transfer.staticCall = async () => {};
  const insert = async () => { throw new Error("insert must not run before settlement confirms"); };
  insert.staticCall = async () => {};
  const token = {
    transferWithAuthorization: transfer,
    authorizationState: async () => false,
    balanceOf: async () => 1_000n,
  };
  const store = makeStore(null);
  const engine = makeEngine({
    offer, token, set: baseSet(insert), provider: fakeProvider, store,
    receiptDeadlineMs: 20, now: () => nowMs,
  });
  const { auth, signature } = await authorization();
  const started = Date.now();
  const first = await engine.verifyAndSettle({ protocol: "x402", limit: 8, commitment: "123", authorization: auth, signature });
  assert.equal(first.ok, false);
  assert.equal(first.status, 503);
  assert.equal(first.reason, "in-progress");
  assert.match(first.detail, new RegExp(settleHash));
  assert.match(first.detail, /may still confirm/i);
  assert.ok(Date.now() - started < 500, "registrar settlement wait is operation-bounded");
  const pending = store.get(asset, buyer.address, auth.nonce);
  assert.equal(pending.state, "settling");
  assert.equal(pending.settleTx, settleHash);
  assert.deepEqual(settleWaitArgs, [1, 20]);

  const replay = await engine.verifyAndSettle({ protocol: "x402", limit: 8, commitment: "123", authorization: auth, signature });
  assert.equal(replay.status, 503);
  assert.equal(replay.reason, "in-progress");
  assert.equal(settleCalls, 1, "an unresolved settlement is never rebroadcast");
  assert.deepEqual(await engine.recover(), { resumed: 0, failed: 0, pending: 1 });
  assert.equal(store.get(asset, buyer.address, auth.nonce).state, "settling", "restart recovery preserves an ambiguous settlement");
}

// The same guarantee applies to the second transaction: payment remains settled, the insert hash
// is exposed for recovery, and an identical request cannot insert twice.
{
  const settleHash = `0x${"22".repeat(32)}`;
  const insertHash = `0x${"33".repeat(32)}`;
  let settleCalls = 0, insertCalls = 0;
  const transfer = async () => {
    settleCalls++;
    return { hash: settleHash, wait: async () => ({ status: 1, blockNumber: 9, logs: [] }) };
  };
  transfer.staticCall = async () => {};
  const insert = async () => {
    insertCalls++;
    return { hash: insertHash, wait: forever };
  };
  insert.staticCall = async () => {};
  const token = {
    transferWithAuthorization: transfer,
    authorizationState: async () => false,
    balanceOf: async () => 1_000n,
  };
  const store = makeStore(null);
  const engine = makeEngine({
    offer, token, set: baseSet(insert), provider: fakeProvider, store,
    receiptDeadlineMs: 20, now: () => nowMs,
  });
  const { auth, signature } = await authorization();
  const first = await engine.verifyAndSettle({ protocol: "mpp", limit: 8, commitment: "456", authorization: auth, signature });
  assert.equal(first.status, 503);
  assert.equal(first.reason, "in-progress");
  assert.match(first.detail, new RegExp(insertHash));
  const pending = store.get(asset, buyer.address, auth.nonce);
  assert.equal(pending.state, "inserting");
  assert.equal(pending.settleTx, settleHash);
  assert.equal(pending.insertTx, insertHash);

  const replay = await engine.verifyAndSettle({ protocol: "mpp", limit: 8, commitment: "456", authorization: auth, signature });
  assert.equal(replay.status, 503);
  assert.equal(settleCalls, 1);
  assert.equal(insertCalls, 1, "an unresolved insert is never rebroadcast");
  assert.deepEqual(await engine.recover(), { resumed: 0, failed: 0, pending: 1 });
  assert.equal(store.get(asset, buyer.address, auth.nonce).state, "inserting", "restart recovery preserves an ambiguous insert");
}

console.log("PASS: registrar receipt deadlines retain recoverable pending state without duplicate transactions");
