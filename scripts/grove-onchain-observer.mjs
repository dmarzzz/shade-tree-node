// Build the optional public Grove v2 onchain section from a current v4 deployment record.
// The observer deliberately has no default target: the checked-in Sepolia record is retired.

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { Interface, JsonRpcProvider } from "ethers";
import {
  buildPublicOnchainActivity,
  collectOnchainActivity,
  validateLiveOnchainTarget,
} from "../packages/node/lib/grove-onchain.mjs";

const STAKED = new Interface([
  "event MemberRegistered(uint256 indexed commitment,uint64 indexed index,uint256 limit)",
  "event MemberExiting(uint256 indexed commitment,uint64 exitInitiatedAt,uint64 withdrawableAt)",
  "event MemberWithdrawn(uint256 indexed commitment,address indexed recipient)",
  "event MemberSlashed(uint256 indexed commitment,address indexed receiver,uint256 limit)",
]);
const PAID = new Interface([
  "event Inserted(uint256 indexed commitment,uint256 limit,uint256 index,uint256 root)",
  "event Slashed(uint256 indexed commitment,uint256 limit,uint256 index,uint256 root)",
]);
const KIND = new Map([
  ["MemberRegistered", "staked-registered"],
  ["MemberExiting", "staked-exiting"],
  ["MemberWithdrawn", "staked-withdrawn"],
  ["MemberSlashed", "staked-slashed"],
  ["Inserted", "paid-inserted"],
  ["Slashed", "paid-slashed"],
]);

function option(argv, name, fallback = null) {
  const exact = argv.indexOf(name);
  if (exact !== -1) return argv[exact + 1] || fallback;
  const inline = argv.find((arg) => arg.startsWith(`${name}=`));
  return inline ? inline.slice(name.length + 1) : fallback;
}

async function json(path) {
  return JSON.parse(await readFile(resolve(path), "utf8"));
}

function normalizeLog(log) {
  return {
    address: log.address.toLowerCase(),
    blockHash: log.blockHash.toLowerCase(),
    blockNumber: Number(log.blockNumber),
    data: log.data.toLowerCase(),
    index: Number(log.index),
    topics: log.topics.map((topic) => topic.toLowerCase()),
    transactionHash: log.transactionHash.toLowerCase(),
  };
}

function providerAdapter(provider) {
  return {
    async getChainId() { return Number((await provider.getNetwork()).chainId); },
    async getDelayedFinalizedBlock({ before, confirmations }) {
      const head = await provider.getBlockNumber();
      let low = 0;
      let high = Math.max(0, head - confirmations + 1);
      const cutoff = Date.parse(before) / 1000;
      while (low < high) {
        const middle = Math.ceil((low + high) / 2);
        const block = await provider.getBlock(middle);
        if (!block) throw new Error("missing block during delayed-finality search");
        if (Number(block.timestamp) <= cutoff) low = middle;
        else high = middle - 1;
      }
      const block = await provider.getBlock(low);
      if (!block) throw new Error("missing delayed finalized block");
      return { number: Number(block.number), hash: block.hash.toLowerCase(), time: new Date(Number(block.timestamp) * 1000).toISOString() };
    },
    getCode: (address, block) => provider.getCode(address, block),
    call: (tx, block) => provider.call(tx, block),
    getTransaction: (hash) => provider.getTransaction(hash),
    getTransactionReceipt: (hash) => provider.getTransactionReceipt(hash),
  };
}

async function agreedLogs(providers, filter) {
  const results = await Promise.all(providers.map(async (provider) => (await provider.getLogs(filter)).map(normalizeLog)));
  const first = JSON.stringify(results[0]);
  if (results.some((logs) => JSON.stringify(logs) !== first)) throw new Error("rpc-disagreement");
  return results[0];
}

async function indexedEvents(target, providers, finalizedBlock, chunkSize) {
  const definitions = [
    { role: target.activity.contracts.stakedReputationSet, abi: STAKED },
    { role: target.activity.contracts.paidAccessSet, abi: PAID },
  ];
  const events = [];
  for (const { role, abi } of definitions) {
    const from = Math.max(role.deployBlock, target.activity.migration.startsAtBlock);
    const topics = [...abi.fragments]
      .filter((fragment) => fragment.type === "event")
      .map((fragment) => abi.getEvent(fragment.name).topicHash);
    for (let start = from; start <= finalizedBlock; start += chunkSize) {
      const end = Math.min(finalizedBlock, start + chunkSize - 1);
      const logs = await agreedLogs(providers, { address: role.address, fromBlock: start, toBlock: end, topics: [topics] });
      for (const log of logs) {
        const parsed = abi.parseLog(log);
        events.push({
          kind: KIND.get(parsed.name),
          commitment: parsed.args.commitment.toString(),
          address: log.address,
          transactionHash: log.transactionHash,
          logIndex: log.index,
          blockNumber: log.blockNumber,
          blockHash: log.blockHash,
          removed: false,
        });
      }
    }
  }
  return events.sort((left, right) => left.blockNumber - right.blockNumber || left.logIndex - right.logIndex);
}

export async function observeOnchainActivity({
  target,
  registrarAggregate = null,
  now = new Date(),
  chunkSize = 2_000,
} = {}) {
  validateLiveOnchainTarget(target);
  if (!Number.isSafeInteger(chunkSize) || chunkSize < 1 || chunkSize > 10_000) throw new Error("invalid log chunk size");
  const providers = target.finality.approvedRpcUrls.map((url) => new JsonRpcProvider(url, target.chainId, { staticNetwork: true }));
  const adapters = providers.map(providerAdapter);
  // Resolve the exact delayed finalized block once so log ranges and point reads share a head.
  const heads = await Promise.all(adapters.map((rpc) => rpc.getDelayedFinalizedBlock({
    before: new Date(new Date(now).getTime() - 6 * 60 * 60_000).toISOString(),
    confirmations: target.finality.confirmations,
  })));
  if (heads.some((head) => JSON.stringify(head) !== JSON.stringify(heads[0]))) throw new Error("rpc-disagreement");
  const events = await indexedEvents(target, providers, heads[0].number, chunkSize);
  const observation = await collectOnchainActivity({ target, rpcs: adapters, events, registrarAggregate, now });
  return buildPublicOnchainActivity(observation);
}

async function main() {
  const argv = process.argv.slice(2);
  const targetPath = option(argv, "--target", process.env.SHADE_TREE_GROVE_ONCHAIN_TARGET);
  const outPath = resolve(option(argv, "--out", "grove-onchain.json"));
  const registrarPath = option(argv, "--registrar", process.env.SHADE_TREE_GROVE_REGISTRAR_AGGREGATE);
  if (!targetPath) throw new Error("a current live v4 target record is required");
  const target = await json(targetPath);
  const registrarAggregate = registrarPath ? await json(registrarPath) : null;
  const activity = await observeOnchainActivity({
    target,
    registrarAggregate,
    chunkSize: Number(option(argv, "--chunk", "2000")),
  });
  await mkdir(dirname(outPath), { recursive: true });
  await writeFile(outPath, `${JSON.stringify(activity, null, 2)}\n`, "utf8");
  console.log("public Grove onchain activity: verified delayed aggregate written");
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(() => {
    // Target URLs, addresses, registrar facts, and RPC responses are intentionally not echoed.
    console.error("public Grove onchain activity unavailable: target or observation failed validation");
    process.exit(1);
  });
}
