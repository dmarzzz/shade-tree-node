import assert from "node:assert/strict";
import { Interface, Wallet, keccak256 } from "ethers";
import {
  GroveOnchainError,
  applyIndexedBlocks,
  buildPublicOnchainActivity,
  collectOnchainActivity,
  reduceActivityEvents,
  settlementSigningPayload,
  validateLiveOnchainTarget,
  validPublicOnchainActivity,
} from "../packages/node/lib/grove-onchain.mjs";

const NOW = new Date("2026-08-25T12:00:00.000Z");
const BLOCK_TIME = "2026-08-25T06:00:00.000Z";
const HASH = (number) => `0x${number.toString(16).padStart(64, "0")}`;
const STAKED = "0x1000000000000000000000000000000000000001";
const PAID = "0x2000000000000000000000000000000000000002";
const ASSET = "0x3000000000000000000000000000000000000003";
const PAYEE = "0x4000000000000000000000000000000000000004";
const CODE = "0x60006000";
const SET_ABI = new Interface([
  "function activeCount() view returns (uint256)",
  "function liveCount() view returns (uint256)",
]);
const TOKEN_ABI = new Interface([
  "function transferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce,uint8 v,bytes32 r,bytes32 s)",
]);
const PAID_ABI = new Interface([
  "event Inserted(uint256 indexed commitment,uint256 limit,uint256 index,uint256 root)",
]);
const registrar = Wallet.createRandom();

const target = {
  network: "sepolia",
  chainId: 11155111,
  status: "live",
  protocolVersion: 4,
  release: "rln-v4-current",
  finality: { confirmations: 64, approvedRpcUrls: ["https://rpc-a.invalid", "https://rpc-b.invalid"] },
  activity: {
    contracts: {
      stakedReputationSet: { address: STAKED, deployBlock: 10, runtimeCodeHash: keccak256(CODE) },
      paidAccessSet: { address: PAID, deployBlock: 12, runtimeCodeHash: keccak256(CODE) },
    },
    payment: {
      attributionRule: "signed-registrar-chain-verified-v1",
      asset: { address: ASSET, decimals: 6, symbol: "USDC" },
      payee: PAYEE,
      registrarKeyId: "registrar-current",
      registrarPublicKey: registrar.address,
    },
    migration: { startsAtBlock: 10, retiresBeforeBlock: null },
  },
};

function event(kind, commitment, index, address = kind.startsWith("paid") ? PAID : STAKED) {
  return {
    kind,
    commitment: String(commitment),
    address,
    transactionHash: HASH(1_000 + index),
    logIndex: index,
    removed: false,
  };
}

const transitionEvents = [
  event("staked-registered", 1, 1),
  event("staked-exiting", 1, 2),
  event("staked-slashed", 1, 3),
  event("staked-withdrawn", 1, 4),
  event("staked-registered", 1, 5),
  event("paid-inserted", 1, 6),
  event("paid-slashed", 1, 7),
  event("paid-inserted", 1, 8),
];
const transitions = reduceActivityEvents([...transitionEvents, transitionEvents[0]], { chainId: target.chainId });
assert.equal(transitions.staked["1"], "active", "withdraw/slash followed by re-registration is active");
assert.equal(transitions.paid["1"], "live", "paid slash followed by reinsertion is live");
assert.equal(transitions.stakedSlashes, 1, "slash during exit does not double-decrement or double-count");
assert.equal(transitions.paidSlashes, 1);
assert.equal(Object.keys(transitions.seen).length, transitionEvents.length, "same chain/contract/transaction/log is idempotent");

const exiting = reduceActivityEvents([
  event("staked-registered", 9, 20),
  event("staked-exiting", 9, 21),
], { chainId: target.chainId });
assert.equal(Object.values(exiting.staked).filter((status) => status === "active").length, 0, "exit removes active commitment before withdrawal");

assert.throws(() => validateLiveOnchainTarget({ ...target, status: "retired" }), (error) => error.code === "target-retired");
assert.throws(() => validateLiveOnchainTarget({ ...target, chainId: 1 }), (error) => error.code === "target-chain-id" || error.code === "target-network");
assert.throws(() => validateLiveOnchainTarget({ ...target, protocolVersion: 3 }), (error) => error.code === "target-protocol-version");

const activityEvents = [];
for (let commitment = 1; commitment <= 10; commitment += 1) activityEvents.push(event("staked-registered", commitment, activityEvents.length));
for (let commitment = 1; commitment <= 5; commitment += 1) activityEvents.push(event("staked-slashed", commitment, activityEvents.length));
for (let commitment = 21; commitment <= 31; commitment += 1) activityEvents.push(event("paid-inserted", commitment, activityEvents.length));
for (let commitment = 21; commitment <= 25; commitment += 1) activityEvents.push(event("paid-slashed", commitment, activityEvents.length));

const facts = [];
const transactions = new Map();
const receipts = new Map();
for (let commitment = 26; commitment <= 30; commitment += 1) {
  const settlementTx = HASH(2_000 + commitment);
  const insertTx = HASH(3_000 + commitment);
  const atomicValue = "100";
  const nonce = HASH(4_000 + commitment);
  const data = TOKEN_ABI.encodeFunctionData("transferWithAuthorization", [
    registrar.address, PAYEE, atomicValue, 0, 9_999_999_999, nonce, 27, HASH(0), HASH(0),
  ]);
  transactions.set(settlementTx, { to: ASSET, data, value: 0 });
  receipts.set(settlementTx, { status: 1, blockNumber: 90, logs: [] });
  const inserted = PAID_ABI.encodeEventLog(PAID_ABI.getEvent("Inserted"), [commitment, 8, commitment, 123]);
  receipts.set(insertTx, { status: 1, blockNumber: 91, logs: [{ address: PAID, ...inserted }] });
  facts.push({ asset: ASSET, atomicValue, commitment: String(commitment), insertTx, payee: PAYEE, rail: commitment % 2 ? "mpp" : "x402", settlementTx });
}
// Commitment 31 is a direct/manual insert. It contributes to live membership but has no signed,
// chain-verified settlement fact and therefore must not become a payment.
const unsignedRegistrar = {
  schema: "shade-tree-registrar-settlements-v1",
  chainId: target.chainId,
  generatedAt: NOW.toISOString(),
  registrarKeyId: "registrar-current",
  settlements: facts,
};
const registrarAggregate = {
  ...unsignedRegistrar,
  attestation: {
    algorithm: "EIP-191",
    keyId: "registrar-current",
    signature: await registrar.signMessage(JSON.stringify(settlementSigningPayload(unsignedRegistrar))),
  },
};

function fakeRpc(overrides = {}) {
  return {
    getChainId: async () => target.chainId,
    getDelayedFinalizedBlock: async () => ({ number: 100, hash: HASH(100), time: BLOCK_TIME }),
    getCode: async () => CODE,
    call: async ({ to }) => to.toLowerCase() === STAKED.toLowerCase()
      ? SET_ABI.encodeFunctionResult("activeCount", [5])
      : SET_ABI.encodeFunctionResult("liveCount", [6]),
    getTransaction: async (hash) => transactions.get(hash),
    getTransactionReceipt: async (hash) => receipts.get(hash),
    ...overrides,
  };
}

const observation = await collectOnchainActivity({
  target,
  rpcs: [fakeRpc(), fakeRpc()],
  events: activityEvents,
  registrarAggregate,
  now: NOW,
});
assert.deepEqual(observation.membership, { activeStakedCommitments: 5, activePaidCommitments: 6 });
assert.deepEqual(observation.enforcement, { stakedSlashes: 5, paidSlashes: 5 });
assert.deepEqual(observation.settlements, { completedAccesses: 5, atomicValue: "500" }, "manual insert is not a completed payment");

const publicActivity = buildPublicOnchainActivity(observation);
assert.equal(validPublicOnchainActivity(publicActivity, { observedAt: NOW.toISOString() }), true);
assert.equal(publicActivity.membership.staked.activeCommitments, 5);
assert.equal(publicActivity.membership.paid.activeCommitments, 6);
assert.equal(publicActivity.settlements.completedAccesses, 5);
assert.equal(publicActivity.settlements.atomicValue, "500");
assert.equal(publicActivity.enforcement.staked.finalizedSlashes, 5);
assert.equal(JSON.stringify(publicActivity).includes("commitment"), true, "only the aggregate definition may use the word commitment");
assert.equal(JSON.stringify(publicActivity).includes('"commitment":'), false, "raw commitment fields are absent");
for (const secret of [facts[0].settlementTx, facts[0].insertTx, registrar.address, PAYEE]) {
  assert.equal(JSON.stringify(publicActivity).includes(secret), false, "public projection omits raw settlement identity facts");
}

const noAttribution = buildPublicOnchainActivity({ ...observation, settlements: null });
assert.deepEqual(noAttribution.settlements, {
  definition: "finalized-settlement-linked-to-finalized-insert",
  attributionRule: "signed-registrar-chain-verified-v1",
  status: "unavailable",
  unavailableReason: "attribution-unavailable",
});
const small = buildPublicOnchainActivity({
  ...observation,
  membership: { activeStakedCommitments: 0, activePaidCommitments: 4 },
  settlements: { completedAccesses: 0, atomicValue: "0" },
  enforcement: { stakedSlashes: 0, paidSlashes: 1 },
});
assert.equal(JSON.stringify(small).includes('"activeCommitments":0'), false, "small or zero values suppress instead of impersonating unavailable data");
assert.equal(JSON.stringify(small).includes('"finalizedSlashes":0'), false);
assert.equal(JSON.stringify(small).includes('"atomicValue":"0"'), false);
assert.equal(validPublicOnchainActivity(small, { observedAt: NOW.toISOString() }), true);

async function rejectsCode(promise, code) {
  await assert.rejects(promise, (error) => error instanceof GroveOnchainError && error.code === code);
}
await rejectsCode(collectOnchainActivity({ target, rpcs: [fakeRpc({ getChainId: async () => 1 }), fakeRpc({ getChainId: async () => 1 })], events: activityEvents, now: NOW }), "rpc-wrong-chain");
await rejectsCode(collectOnchainActivity({ target, rpcs: [fakeRpc(), fakeRpc({ getChainId: async () => 1 })], events: activityEvents, now: NOW }), "rpc-disagreement");
await rejectsCode(collectOnchainActivity({ target, rpcs: [fakeRpc({ getCode: async () => "0x6001" }), fakeRpc({ getCode: async () => "0x6001" })], events: activityEvents, now: NOW }), "runtime-code-mismatch");
await rejectsCode(collectOnchainActivity({ target, rpcs: [fakeRpc(), fakeRpc({ call: async () => { throw new Error("partial"); } })], events: activityEvents, now: NOW }), "rpc-counter");
const rewrittenValue = structuredClone(registrarAggregate);
rewrittenValue.settlements[0].atomicValue = "101";
await rejectsCode(collectOnchainActivity({ target, rpcs: [fakeRpc(), fakeRpc()], events: activityEvents, registrarAggregate: rewrittenValue, now: NOW }), "registrar-signature");
const failedInsertRpc = () => fakeRpc({
  getTransactionReceipt: async (hash) => hash === facts[0].insertTx ? { ...receipts.get(hash), status: 0 } : receipts.get(hash),
});
await rejectsCode(collectOnchainActivity({ target, rpcs: [failedInsertRpc(), failedInsertRpc()], events: activityEvents, registrarAggregate, now: NOW }), "settlement-not-finalized");

const blockA = { number: 10, hash: HASH(10), parentHash: HASH(9), events: [event("staked-registered", 77, 77)] };
const blockB = { number: 11, hash: HASH(11), parentHash: HASH(10), events: [event("staked-slashed", 77, 78)] };
const firstIndex = applyIndexedBlocks(null, [blockA, blockB], { chainId: target.chainId });
assert.equal(firstIndex.activity.staked["77"], "slashed");
const replacementB = { number: 11, hash: HASH(111), parentHash: HASH(10), events: [event("staked-exiting", 77, 79)] };
const rewound = applyIndexedBlocks(firstIndex, [replacementB], { chainId: target.chainId });
assert.equal(rewound.activity.staked["77"], "exiting", "hash mismatch rewinds and replays the canonical branch");
assert.equal(rewound.activity.stakedSlashes, 0, "orphaned slash is removed");
assert.deepEqual(applyIndexedBlocks(rewound, [replacementB], { chainId: target.chainId }), rewound, "backfill is idempotent");

console.log("PASS: Grove onchain collector, finality, attribution, privacy, and reorg contract");
