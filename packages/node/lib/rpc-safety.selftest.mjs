import assert from "node:assert/strict";
import { ethers } from "ethers";
import {
  DEFAULT_RPC_RETRIES,
  DEFAULT_RPC_TIMEOUT_MS,
  DEFAULT_TX_RECEIPT_TIMEOUT_MS,
  isLoopbackRpcUrl,
  isTransactionReceiptTimeout,
  jsonRpcCall,
  boundedFetchRequest,
  makeBoundedJsonRpcProvider,
  MAX_RPC_RETRIES,
  registrationKey,
  requireRpcChainId,
  retryAfterMs,
  RPC_RETRY_BUDGET_MS,
  rpcRetries,
  rpcRetryDelayMs,
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

// HTTP 429 (and 503 with Retry-After) backs off and resends; nothing else is retried.
assert.equal(rpcRetries({}), DEFAULT_RPC_RETRIES);
assert.equal(rpcRetries({ SHADE_TREE_RPC_RETRIES: "0" }), 0, "0 turns throttle retries off");
assert.equal(rpcRetries({ SHADE_TREE_RPC_RETRIES: "3" }), 3);
assert.equal(rpcRetries({ SHADE_TREE_RPC_RETRIES: "999" }), MAX_RPC_RETRIES, "the knob is capped");
assert.equal(rpcRetries({ SHADE_TREE_RPC_RETRIES: "-1" }), DEFAULT_RPC_RETRIES);
assert.equal(rpcRetries({ SHADE_TREE_RPC_RETRIES: "garbage" }), DEFAULT_RPC_RETRIES);
const now = Date.parse("2026-10-24T12:00:00Z");
assert.equal(retryAfterMs("3", now), 3000);
assert.equal(retryAfterMs("Sat, 24 Oct 2026 12:00:05 GMT", now), 5000, "an HTTP date is honoured");
assert.equal(retryAfterMs("Sat, 24 Oct 2026 11:00:00 GMT", now), 0, "a past date means now");
assert.equal(retryAfterMs("1.5", now), null);
assert.equal(retryAfterMs("soon", now), null);
assert.equal(retryAfterMs(null, now), null);
assert.equal(rpcRetryDelayMs(0, null, () => 0), 400);
assert.equal(rpcRetryDelayMs(3, null, () => 0), 3200);
assert.equal(rpcRetryDelayMs(9, null, () => 0), 6400, "exponent stops at 2^4");
assert.equal(rpcRetryDelayMs(0, 60_000, () => 0), 10_000, "Retry-After is capped at 10 s");
assert.equal(rpcRetryDelayMs(0, 2000, () => 0.999), 2299, "jitter is under 300 ms");

const throttled = (status, retryAfter) => new Response("rate limited", {
  status, headers: retryAfter == null ? {} : { "retry-after": retryAfter },
});
const scripted = (script) => {
  const seen = [];
  const fetchImpl = async (url, options) => {
    seen.push({ host: new URL(url).host, body: options.body });
    const step = script[Math.min(seen.length - 1, script.length - 1)];
    return typeof step === "function" ? step(url, options) : step();
  };
  return { seen, fetchImpl };
};
const ok = (_url, options) => reply(JSON.parse(options.body).id, "0x10");
let sleeps = [];
const sleep = async (ms) => { sleeps.push(ms); };

let t = scripted([() => throttled(429), () => throttled(429), ok]);
assert.equal(await jsonRpcCall("https://tdly.example", "eth_blockNumber", [], { fetchImpl: t.fetchImpl, sleep }), "0x10");
assert.equal(t.seen.length, 3, "429, 429, then the answer");
assert.equal(sleeps.length, 2);
assert.ok(sleeps[0] >= 400 && sleeps[0] < 700 && sleeps[1] >= 800 && sleeps[1] < 1100, `exponential backoff: ${sleeps}`);
assert.match(registry.render(), /shade_tree_rpc_throttle_retries_total\{status="429"\} \d+/);

sleeps = [];
t = scripted([() => throttled(429, "2"), ok]);
assert.equal(await jsonRpcCall("https://tdly.example", "eth_blockNumber", [], { fetchImpl: t.fetchImpl, sleep }), "0x10");
assert.ok(sleeps[0] >= 2000 && sleeps[0] < 2300, `Retry-After seconds honoured: ${sleeps}`);

sleeps = [];
t = scripted([() => throttled(429, new Date(Date.now() + 4000).toUTCString()), ok]);
await jsonRpcCall("https://tdly.example", "eth_blockNumber", [], { fetchImpl: t.fetchImpl, sleep });
assert.ok(sleeps[0] > 2500 && sleeps[0] < 4300, `Retry-After HTTP date honoured: ${sleeps}`);

sleeps = [];
t = scripted([() => throttled(429)]);
await assert.rejects(
  jsonRpcCall("https://tdly.example/key", "eth_call", [], { fetchImpl: t.fetchImpl, sleep, retries: 2 }),
  (error) => /eth_call: RPC request failed at https:\/\/tdly\.example: HTTP 429 \(still throttled after 2 retries\)/.test(error.message)
    && !error.message.includes("key"),
);
assert.equal(t.seen.length, 3, "max attempts = retries + 1");
assert.equal(sleeps.length, 2);

sleeps = [];
t = scripted([() => throttled(429, "10")]);
await assert.rejects(jsonRpcCall("https://tdly.example", "eth_call", [], { fetchImpl: t.fetchImpl, sleep, retries: MAX_RPC_RETRIES }), /HTTP 429/);
assert.ok(sleeps.reduce((a, b) => a + b, 0) <= RPC_RETRY_BUDGET_MS, `total waiting is bounded: ${sleeps}`);
assert.ok(sleeps.length < MAX_RPC_RETRIES, "the budget, not the attempt count, stopped a slow endpoint");

for (const [status, header] of [[500, null], [502, "1"], [503, null], [400, null]]) {
  sleeps = [];
  t = scripted([() => throttled(status, header), ok]);
  await assert.rejects(jsonRpcCall("https://tdly.example", "eth_call", [], { fetchImpl: t.fetchImpl, sleep }), new RegExp(`HTTP ${status}$`));
  assert.equal(t.seen.length, 1, `HTTP ${status} is not retried`);
  assert.equal(sleeps.length, 0);
}
sleeps = [];
t = scripted([() => throttled(503, "1"), ok]);
assert.equal(await jsonRpcCall("https://tdly.example", "eth_call", [], { fetchImpl: t.fetchImpl, sleep }), "0x10", "503 with Retry-After is a throttle");
assert.ok(sleeps[0] >= 1000 && sleeps[0] < 1300);

sleeps = [];
t = scripted([() => throttled(429), ok]);
await assert.rejects(jsonRpcCall("https://tdly.example", "eth_call", [], { fetchImpl: t.fetchImpl, sleep, retries: 0 }), /HTTP 429$/);
assert.equal(t.seen.length, 1, "retries: 0 sends once");

// A throttled eth_sendRawTransaction was refused before processing, so the same bytes are resent.
sleeps = [];
t = scripted([() => throttled(429), (_u, o) => reply(JSON.parse(o.body).id, `0x${"cd".repeat(32)}`)]);
assert.equal(await jsonRpcCall("https://tdly.example", "eth_sendRawTransaction", ["0xf86c"], { fetchImpl: t.fetchImpl, sleep }), `0x${"cd".repeat(32)}`);
assert.equal(t.seen[0].body, t.seen[1].body, "the resend is byte-identical");

// With a list, a throttled endpoint fails over without waiting; only the last one backs off.
sleeps = [];
t = scripted([() => throttled(429), ok]);
assert.equal(await jsonRpcCall("https://limited-a.example,https://open-b.example", "eth_call", [], { fetchImpl: t.fetchImpl, sleep }), "0x10");
assert.deepEqual(t.seen.map((c) => c.host), ["limited-a.example", "open-b.example"]);
assert.equal(sleeps.length, 0, "failover beats waiting");
sleeps = [];
t = scripted([() => throttled(429), () => throttled(429), ok]);
assert.equal(await jsonRpcCall("https://both-a.example,https://both-b.example", "eth_call", [], { fetchImpl: t.fetchImpl, sleep }), "0x10");
assert.deepEqual(t.seen.map((c) => c.host), ["both-a.example", "both-b.example", "both-b.example"]);
assert.equal(sleeps.length, 1, "all limited: the last endpoint waits and retries");

// The ethers transport (registration, slashing, settlement) uses the same schedule and honours
// delta-seconds Retry-After, which ethers alone reads as milliseconds.
const ethersReplies = (script) => {
  let n = 0;
  return async (req) => {
    const step = script[Math.min(n++, script.length - 1)];
    if (step === 429) return { statusCode: 429, statusMessage: "Too Many Requests", headers: { "retry-after": "1" }, body: null };
    const id = JSON.parse(ethers.toUtf8String(req.body)).id;
    return { statusCode: 200, statusMessage: "OK", headers: { "content-type": "application/json" }, body: ethers.toUtf8Bytes(JSON.stringify({ jsonrpc: "2.0", id, result: "0x10" })) };
  };
};
sleeps = [];
let request = boundedFetchRequest(ethers, "https://tdly.example", { timeoutMs: 5000, retries: 3, sleep });
request.getUrlFunc = ethersReplies([429, 429, 200]);
let ep = new ethers.JsonRpcProvider(request, ethers.Network.from(11155111n), { staticNetwork: true, batchMaxCount: 1 });
assert.equal(await ep.send("eth_blockNumber", []), "0x10");
assert.equal(sleeps.length, 2);
assert.ok(sleeps.every((ms) => ms >= 1000 && ms < 1300), `ethers path honours Retry-After seconds: ${sleeps}`);
ep.destroy();
sleeps = [];
request = boundedFetchRequest(ethers, "https://tdly.example", { timeoutMs: 5000, retries: 1, sleep });
request.getUrlFunc = ethersReplies([429]);
ep = new ethers.JsonRpcProvider(request, ethers.Network.from(11155111n), { staticNetwork: true, batchMaxCount: 1 });
await assert.rejects(ep.send("eth_blockNumber", []));
assert.equal(sleeps.length, 1, "ethers path stops at retries + 1 attempts without a wasted final sleep");
ep.destroy();

console.log("PASS: RPC keys, request and receipt deadlines, bounded ethers bootstrap, endpoint failover, and 429 backoff");
