// Exercise the real ethers adapter against loopback only. No wallet, signing or public RPC.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { JsonRpcProvider } from "ethers";
import { leftoverAtBlock } from "./funding-wallet.mjs";

const address = `0x${"12".repeat(20)}`;
const receipt = { blockNumber: 42 };
let replies = [];
let requests = [];
const server = createServer(async (req, res) => {
  let body = "";
  for await (const chunk of req) body += chunk;
  const handle = (rpc) => {
    const response = { jsonrpc: "2.0", id: rpc.id };
    if (rpc.method === "eth_chainId") return { ...response, result: "0x7a69" };
    requests.push({ method: rpc.method, params: rpc.params });
    if (rpc.method !== "eth_getBalance") return { ...response, error: { code: -32601, message: "unexpected method" } };
    return { ...response, ...(replies.shift() ?? { error: { code: -32000, message: "unexpected extra read" } }) };
  };
  const input = JSON.parse(body);
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(Array.isArray(input) ? input.map(handle) : handle(input)));
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
// Disable ethers' short request cache so accelerated retries still reach the stub.
// Production uses a 2-second delay, longer than the default cache interval.
const provider = new JsonRpcProvider(`http://127.0.0.1:${server.address().port}`, undefined, { cacheTimeout: -1 });
try {
  const missing = { error: { code: -32000, message: "header not found" } };
  for (const [answers, expected] of [
    [[{ result: "0x7b" }], 123n],
    [[missing, missing, { result: "0x7b" }], 123n],
    [[missing, missing, missing, missing, missing], null],
    [[{ result: "0x0" }], 0n],
  ]) {
    replies = [...answers];
    requests = [];
    const waits = [];
    const left = await leftoverAtBlock({
      block: receipt.blockNumber,
      getBalance: (tag) => provider.getBalance(address, tag),
      sleep: async (ms) => { waits.push(ms); },
    });
    assert.equal(left, expected);
    assert.equal(replies.length, 0);
    assert.deepEqual(requests, answers.map(() => ({ method: "eth_getBalance", params: [address, "0x2a"] })));
    assert.deepEqual(waits, Array(answers.length - 1).fill(2000));
  }
  console.log("PASS: funding leftover ethers RPC (initial/retries pinned, exhaustion null, real zero)");
} finally {
  provider.destroy();
  await new Promise((resolve) => server.close(resolve));
}
