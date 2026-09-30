import assert from "node:assert/strict";
import { ethers } from "ethers";
import {
  DEFAULT_RPC_TIMEOUT_MS,
  DEFAULT_TX_RECEIPT_TIMEOUT_MS,
  isLoopbackRpcUrl,
  isTransactionReceiptTimeout,
  jsonRpcCall,
  makeBoundedJsonRpcProvider,
  registrationKey,
  requireRpcChainId,
  rpcOrigin,
  rpcUrlList,
  rpcTimeoutMs,
  txReceiptTimeoutMs,
  waitForTransactionReceipt,
} from "./rpc-safety.mjs";

assert.equal(isLoopbackRpcUrl("http://127.0.0.1:8545"), true);
assert.equal(isLoopbackRpcUrl("http://localhost:8545"), true);
assert.equal(isLoopbackRpcUrl("http://[::1]:8545"), true);
assert.equal(isLoopbackRpcUrl("https://rpc.example"), false);
assert.equal(isLoopbackRpcUrl("not a URL"), false);

assert.equal(registrationKey({ rpcUrl: "http://127.0.0.1:8545", developmentKey: "dev" }), "dev");
assert.equal(registrationKey({ rpcUrl: "https://rpc.example", explicitKey: "secret", developmentKey: "dev" }), "secret");
assert.throws(
  () => registrationKey({ rpcUrl: "https://rpc.example", developmentKey: "dev", label: "member registration" }),
  /requires SHADE_TREE_REGISTER_KEY.*never used remotely/,
);

assert.equal(rpcTimeoutMs({}), DEFAULT_RPC_TIMEOUT_MS);
assert.equal(rpcTimeoutMs({ SHADE_TREE_RPC_TIMEOUT_MS: "37" }), 37);
assert.equal(rpcTimeoutMs({ SHADE_TREE_RPC_TIMEOUT_MS: "0" }), DEFAULT_RPC_TIMEOUT_MS);
assert.equal(rpcTimeoutMs({ SHADE_TREE_RPC_TIMEOUT_MS: "0.5" }), DEFAULT_RPC_TIMEOUT_MS);
assert.equal(rpcTimeoutMs({ SHADE_TREE_RPC_TIMEOUT_MS: "garbage" }), DEFAULT_RPC_TIMEOUT_MS);
assert.equal(txReceiptTimeoutMs({}), DEFAULT_TX_RECEIPT_TIMEOUT_MS);
assert.equal(txReceiptTimeoutMs({ SHADE_TREE_TX_RECEIPT_TIMEOUT_MS: "41" }), 41);
assert.equal(txReceiptTimeoutMs({ SHADE_TREE_TX_RECEIPT_TIMEOUT_MS: "0" }), DEFAULT_TX_RECEIPT_TIMEOUT_MS);
assert.equal(txReceiptTimeoutMs({ SHADE_TREE_TX_RECEIPT_TIMEOUT_MS: "garbage" }), DEFAULT_TX_RECEIPT_TIMEOUT_MS);
assert.equal(rpcOrigin("https://user:secret@rpc.example/private-key"), "https://rpc.example");

const pendingHash = `0x${"ab".repeat(32)}`;
let waitArgs = null;
const receiptStarted = Date.now();
await assert.rejects(
  waitForTransactionReceipt({
    hash: pendingHash,
    wait: (...args) => { waitArgs = args; return new Promise(() => {}); },
  }, { confirmations: 2, timeoutMs: 20, operation: "test settlement" }),
  (error) => isTransactionReceiptTimeout(error)
    && error.transactionHash === pendingHash
    && error.timeoutMs === 20
    && /may still confirm; check the transaction hash before retrying/.test(error.message),
);
assert.deepEqual(waitArgs, [2, 20], "the deadline is also passed into ethers wait()");
assert.ok(Date.now() - receiptStarted < 500, "responsive null receipt polling is bounded at the operation level");

await assert.rejects(
  waitForTransactionReceipt({ hash: pendingHash, wait: async () => { const e = new Error("ethers timeout"); e.code = "TIMEOUT"; throw e; } }, { timeoutMs: 50 }),
  (error) => isTransactionReceiptTimeout(error) && error.cause?.code === "TIMEOUT",
  "ethers' own wait timeout is normalized into a recoverable receipt error",
);
const mined = { status: 1, blockNumber: 7 };
assert.equal(await waitForTransactionReceipt({ hash: pendingHash, wait: async () => mined }, { timeoutMs: 50 }), mined);
const reverted = new Error("execution reverted");
await assert.rejects(
  waitForTransactionReceipt({ hash: pendingHash, wait: async () => { throw reverted; } }, { timeoutMs: 50 }),
  (error) => error === reverted,
  "non-timeout provider errors retain their original actionable detail",
);

let capturedSignal = null;
const stalledFetch = async (_url, options) => {
  capturedSignal = options.signal;
  return new Promise((_resolve, reject) => {
    // AbortSignal.timeout() deliberately unrefs its own timer. This ordinary timer keeps the
    // short-lived test process alive long enough to observe the abort.
    const hold = setTimeout(() => reject(new Error("test transport was not aborted")), 1000);
    options.signal.addEventListener("abort", () => { clearTimeout(hold); reject(options.signal.reason); }, { once: true });
  });
};
const started = Date.now();
await assert.rejects(
  jsonRpcCall("https://user:secret@rpc.example/private-key", "eth_chainId", [], { timeoutMs: 20, fetchImpl: stalledFetch }),
  (error) => /eth_chainId: RPC request timed out after 20ms at https:\/\/rpc\.example/.test(error.message)
    && !error.message.includes("secret") && !error.message.includes("private-key"),
);
assert.equal(capturedSignal.aborted, true);
assert.ok(Date.now() - started < 500, "stalled JSON-RPC request is cut promptly");

let probes = 0;
const provider = await makeBoundedJsonRpcProvider(ethers, "https://rpc.example/key", {
  timeoutMs: 1234,
  fetchImpl: async (_url, options) => {
    probes++;
    const body = JSON.parse(options.body);
    assert.equal(body.method, "eth_chainId");
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result: "0xaa36a7" }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  },
});
assert.equal(probes, 1, "provider construction performs one bounded chain-id probe");
assert.equal(provider._network.chainId, 11155111n);
assert.doesNotThrow(() => requireRpcChainId(provider._network.chainId, "11155111", { label: "staking RPC" }));
assert.throws(() => requireRpcChainId(1n, "11155111", { label: "staking RPC" }), /staking RPC chainId 1 does not match configured chainId 11155111; refusing to sign/);
assert.equal(provider._getConnection().timeout, 1234, "ethers transport inherits the request deadline");
provider.destroy();

// OPS-8: several comma-separated endpoints fail over in order and stick to the last good one.
assert.deepEqual(rpcUrlList(" https://a.example , https://b.example ,"), ["https://a.example", "https://b.example"]);
assert.equal(isLoopbackRpcUrl("http://127.0.0.1:8545,https://rpc.example"), false, "a list is loopback only if every entry is");
assert.equal(isLoopbackRpcUrl("http://127.0.0.1:8545,http://localhost:8546"), true);
const reply = (id, result) => new Response(JSON.stringify({ jsonrpc: "2.0", id, result }), { status: 200, headers: { "content-type": "application/json" } });
const calls = [];
const flaky = async (url, options) => {
  const body = JSON.parse(options.body);
  calls.push(new URL(url).host);
  if (url.startsWith("https://down.example")) throw new TypeError("fetch failed");
  if (url.startsWith("https://limited.example")) {
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, error: { code: -32005, message: "rate limit exceeded" } }), { status: 200 });
  }
  if (url.startsWith("https://revert.example")) {
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, error: { code: 3, message: "execution reverted" } }), { status: 200 });
  }
  return reply(body.id, "0xaa36a7");
};
assert.equal(await jsonRpcCall("https://down.example,https://limited.example,https://up.example", "eth_chainId", [], { fetchImpl: flaky }), "0xaa36a7");
assert.deepEqual(calls, ["down.example", "limited.example", "up.example"], "transport failure and rate limit both move on");
calls.length = 0;
assert.equal(await jsonRpcCall("https://down.example,https://limited.example,https://up.example", "eth_chainId", [], { fetchImpl: flaky }), "0xaa36a7");
assert.deepEqual(calls, ["up.example"], "the next call starts at the endpoint that last answered");
calls.length = 0;
await assert.rejects(jsonRpcCall("https://revert.example,https://up.example", "eth_call", [], { fetchImpl: flaky }), /execution reverted/);
assert.deepEqual(calls, ["revert.example"], "an execution revert is an answer, not an outage");
await assert.rejects(
  jsonRpcCall("https://down.example/k1,https://down.example/k2", "eth_chainId", [], { fetchImpl: flaky }),
  (error) => /all 2 RPC endpoints failed/.test(error.message) && !error.message.includes("k1"),
);
const { registry } = await import("./metrics.mjs");
assert.match(registry.render(), /shade_tree_rpc_failovers_total\{endpoint="0"\} \d+/);

const fallback = await makeBoundedJsonRpcProvider(ethers, "https://down.example,https://up.example", { fetchImpl: flaky });
assert.ok(fallback instanceof ethers.FallbackProvider, "a list builds a quorum-1 FallbackProvider");
fallback.destroy();
await assert.rejects(
  makeBoundedJsonRpcProvider(ethers, "https://up.example,https://mainnet.example", {
    fetchImpl: async (url, options) => reply(JSON.parse(options.body).id, url.includes("mainnet") ? "0x1" : "0xaa36a7"),
  }),
  /disagree on chainId/,
);

console.log("PASS: RPC keys, request and receipt deadlines, bounded ethers bootstrap, and endpoint failover");
