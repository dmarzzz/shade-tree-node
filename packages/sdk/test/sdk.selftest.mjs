// @shadenet/sdk behaviour (no Tor, no chain): identities, network record, staking flows against a
// mock EIP-1193 wallet, a REAL Groth16 exit proof checked by snarkjs, proxy refusal mapping and
// daemon status.
//
//   node packages/sdk/test/sdk.selftest.mjs

import http from "node:http";
import net from "node:net";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { AbiCoder, Interface } from "ethers";
import * as sdk from "@shadenet/sdk";
import { proxyConnect } from "@shadenet/sdk/node";
import { identityFor, identitySecretOf, rateCommitmentOf } from "../../../lib/rln.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };
async function code(fn) {
  try { await fn(); return null; } catch (e) { return e.code ?? e.message; }
}

console.log("=== network record ===");
const net1 = sdk.resolveNetwork("sepolia");
ok(net1.staked.contract === "0xEB67Abf066c11D78856BccC63476ed14d51e4275", "staked contract from deployment.json");
ok(net1.staked.tiers.map((t) => t.limit).join(",") === "1,8" && net1.staked.tiers[0].bondWei === 100000000000000000n, "tiers and bonds from the record");
ok(net1.elder.canopySigner.length === 64, "canopy signer pinned from the record");
ok(await code(() => sdk.resolveNetwork("nope")) === "InvalidInput", "unknown network -> InvalidInput");

console.log("=== identity ===");
const id = await sdk.createIdentity();
ok(id.limit === 1 && /^[1-9][0-9]*$/.test(id.leaf), "createIdentity uses the default tier");
ok(sdk.rateCommitment(id.identitySecret, 1).toString() === id.leaf, "leaf = Poseidon2(Poseidon1(secret), limit)");
const back = sdk.importIdentity(sdk.serializeIdentity(id));
ok(back.leaf === id.leaf && back.identitySecret === id.identitySecret, "serialize -> import round trip");
ok(await code(() => sdk.importIdentity(sdk.serializeIdentity({ ...id, leaf: "5" }))) === "InvalidInput", "tampered leaf rejected");
ok(await code(() => sdk.createIdentity({ limit: 32 })) === "InvalidInput", "a tier the network doesn't offer is rejected");
const legacy = identityFor("111");
const legacyFile = { identitySecret: identitySecretOf(legacy).toString(), leaf: rateCommitmentOf(legacy, 8).toString() };
ok(sdk.importIdentity(JSON.stringify(legacyFile), { network: net1 }).limit === 8, "pre-tier identity file (no limit) is checked against the offered tiers");
ok(sdk.identityFileName(id).startsWith("shadenet-identity-"), "download file name");

console.log("=== errors ===");
ok(sdk.ERROR_CODES.length === 11, "11 error codes");
const budget = Object.assign(new Error("Shade Tree epoch budget exhausted"), { code: "SHADE_TREE_EPOCH_BUDGET_EXHAUSTED", retryAfterMs: 1234 });
const mapped = sdk.toShadeNetError(budget);
ok(mapped.code === "BudgetExhausted" && mapped.retryAfterMs === 1234 && mapped.cause === budget, "client budget error -> BudgetExhausted with retryAfterMs");
ok(sdk.toShadeNetError(new Error("ShadeTreeClient: your leaf 123.. (limit 1) is in none of: staked")).code === "NotAdmitted", "not in any set -> NotAdmitted");
ok(sdk.toShadeNetError(new Error("ShadeTreeClient.fetch: https:// only (the gateway egresses :443)")).code === "PortNotAllowed", "non-https -> PortNotAllowed");
ok(sdk.toShadeNetError(new Error("no verifiable directory (fresh: bad-signature)")).code === "Canopy", "directory failure -> Canopy");

console.log("=== staking (mock wallet) ===");
const iface = new Interface([
  "function register(uint256,uint256) payable", "function initiateExit(uint256,bytes)", "function withdraw(uint256,address,bytes)",
  "function bondFor(uint256) view returns (uint256)", "function isActive(uint256) view returns (bool)",
  "function limitOf(uint256) view returns (uint256)", "function withdrawableAt(uint256) view returns (uint256)",
]);
function mockWallet({ bond = null, active = false, limit = 0n, withdrawableAt = 0n, chain = 11155111n, finalizedLogs = [] } = {}) {
  const sent = [];
  return {
    sent,
    async request({ method, params }) {
      if (method === "eth_chainId") return `0x${chain.toString(16)}`;
      if (method === "eth_sendTransaction") { sent.push(params[0]); return "0x" + "ab".repeat(32); }
      if (method === "eth_getTransactionReceipt") return { status: "0x1" };
      if (method === "eth_getLogs") return finalizedLogs;
      if (method === "eth_getCode") return "0x6080";
      if (method === "eth_getBalance") return "0xde0b6b3a7640000"; // 1 ETH
      if (method === "eth_estimateGas") return "0x30d40";
      if (method === "eth_gasPrice") return "0x3b9aca00";
      if (method === "eth_call") {
        const tx = params[0];
        const fn = iface.parseTransaction({ data: tx.data });
        const enc = (v) => iface.encodeFunctionResult(fn.name, [v]);
        if (fn.name === "bondFor") return enc(bond ?? { 1: 100000000000000000n, 8: 800000000000000000n }[Number(fn.args[0])] ?? 0n);
        if (fn.name === "isActive") return enc(active);
        if (fn.name === "limitOf") return enc(limit);
        if (fn.name === "withdrawableAt") return enc(withdrawableAt);
        return "0x"; // simulation of a write succeeds
      }
      throw new Error(`unexpected ${method}`);
    },
  };
}
const FROM = "0x000000000000000000000000000000000000dEaD";
{
  const w = mockWallet();
  const s = sdk.createStaking({ provider: w });
  const r = await s.stake({ commitment: id.leaf, from: FROM });
  const tx = iface.parseTransaction({ data: w.sent[0].data });
  ok(tx.name === "register" && tx.args[0].toString() === id.leaf && tx.args[1] === 1n, "stake sends register(leaf, 1)");
  ok(BigInt(w.sent[0].value) === 100000000000000000n && w.sent[0].to === net1.staked.contract, "stake sends the record's bond to the record's contract");
  ok((await r.wait()).status === "0x1", "wait() returns the receipt");
}
{
  const w = mockWallet();
  await sdk.createStaking({ provider: w }).sponsor({ commitment: id.leaf, limit: 8, from: FROM });
  const tx = iface.parseTransaction({ data: w.sent[0].data });
  ok(tx.args[1] === 8n && BigInt(w.sent[0].value) === 800000000000000000n, "sponsor at tier 8 sends register(leaf, 8) with the tier-8 bond");
}
ok(await code(() => sdk.createStaking({ provider: mockWallet({ bond: 1n }) }).stake({ commitment: id.leaf, from: FROM })) === "Rpc", "bond disagreeing with the record -> refuse (Rpc)");
ok((await sdk.createStaking({ provider: mockWallet({ active: true }) }).stake({ commitment: id.leaf, from: FROM })).alreadyActive === true, "already active -> nothing sent");
ok(await code(() => sdk.createStaking({ provider: mockWallet({ chain: 1n }) }).stake({ commitment: id.leaf, from: FROM })) !== null, "wrong chain is refused");
{
  const st = await sdk.createStaking({ provider: mockWallet({ active: true, limit: 1n, finalizedLogs: [{}] }) }).memberStatus(id.leaf);
  ok(st.state === "active" && st.limit === 1 && st.finalized === true, "memberStatus active + finalized");
  const pending = await sdk.createStaking({ provider: mockWallet({ active: true, limit: 1n }) }).memberStatus(id.leaf);
  ok(pending.finalized === false, "memberStatus reports not finalized");
  const exiting = await sdk.createStaking({ provider: mockWallet({ limit: 1n, withdrawableAt: BigInt(Math.floor(Date.now() / 1000) + 3600) }) }).memberStatus(id.leaf);
  ok(exiting.state === "exiting" && exiting.withdrawableAt, "memberStatus exiting");
}

console.log("=== exit / withdraw proofs (real Groth16) ===");
{
  const fixture = JSON.parse(readFileSync(join(ROOT, "testdata", "withdraw-proof.json"), "utf8"));
  ok(sdk.exitContext(fixture.commitment) === fixture.exit.context, "exitContext matches the contract fixture");
  ok(sdk.withdrawContext(fixture.commitment, fixture.recipient) === fixture.withdraw.context, "withdrawContext matches the contract fixture");
  // The fixture's witness is identity secret 111 itself (a public test constant).
  const identity = { identitySecret: "111", leaf: fixture.commitment, limit: 8 };
  ok(sdk.rateCommitment(111n, 8).toString() === fixture.commitment, "fixture leaf = rateCommitment(111, 8)");
  const w = mockWallet({ limit: 8n });
  await sdk.createStaking({ provider: w }).exit({ identity, from: FROM });
  const tx = iface.parseTransaction({ data: w.sent[0].data });
  ok(tx.name === "initiateExit" && tx.args[0].toString() === identity.leaf, "exit sends initiateExit(leaf, proof)");
  const [a, b, c, idc] = AbiCoder.defaultAbiCoder().decode(["uint256[2]", "uint256[2][2]", "uint256[2]", "uint256"], tx.args[1]);
  ok(idc.toString() === fixture.identityCommitment, "proof carries the identity commitment");
  const snarkjs = await import("snarkjs");
  const vkey = JSON.parse(readFileSync(join(ROOT, "circuits", "rln", "withdraw_verification_key.json"), "utf8"));
  const proof = { pi_a: [a[0].toString(), a[1].toString(), "1"], pi_b: [[b[0][1].toString(), b[0][0].toString()], [b[1][1].toString(), b[1][0].toString()], ["1", "0"]], pi_c: [c[0].toString(), c[1].toString(), "1"], protocol: "groth16", curve: "bn128" };
  ok(await snarkjs.groth16.verify(vkey, [fixture.identityCommitment, fixture.exit.address], proof), "snarkjs verifies the exit proof against the withdraw VK");
  const w2 = mockWallet({ limit: 8n });
  await sdk.createStaking({ provider: w2 }).withdraw({ identity, recipient: fixture.recipient, from: FROM });
  ok(iface.parseTransaction({ data: w2.sent[0].data }).args[1] === fixture.recipient, "withdraw binds the recipient");
  ok(await code(() => sdk.proveAction({ identitySecret: "0", context: fixture.exit.context })) === "InvalidInput", "zero secret refused before proving");
}

console.log("=== proxy refusals ===");
{
  const echo = net.createServer((s) => s.pipe(s));
  await new Promise((r) => echo.listen(0, "127.0.0.1", r));
  const proxy = http.createServer();
  proxy.on("connect", (req, socket) => {
    if (req.url.startsWith("budget")) {
      socket.end("HTTP/1.1 429 Too Many Requests\r\nX-ShadeNet-Error: BudgetExhausted\r\nRetry-After: 42\r\n\r\n");
    } else if (req.url.startsWith("closed")) {
      socket.end("HTTP/1.1 403 Forbidden\r\n\r\n");
    } else {
      const up = net.connect(echo.address().port, "127.0.0.1", () => { socket.write("HTTP/1.1 200 Connection Established\r\n\r\n"); up.pipe(socket); socket.pipe(up); });
    }
  });
  await new Promise((r) => proxy.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${proxy.address().port}`;
  let err = null;
  try { await proxyConnect("budget.example:443", { proxy: url }); } catch (e) { err = e; }
  ok(err?.code === "BudgetExhausted" && err.retryAfterMs === 42000, "429 + X-ShadeNet-Error -> BudgetExhausted, retryAfterMs");
  err = null;
  try { await proxyConnect("closed.example:443", { proxy: url }); } catch (e) { err = e; }
  ok(err?.code === "NotAdmitted", "bare 403 -> NotAdmitted");
  const sock = await proxyConnect("example.com:443", { proxy: url });
  const reply = await new Promise((r) => { sock.once("data", (d) => r(d.toString())); sock.write("ping"); });
  ok(reply === "ping", "200 -> a live tunnel");
  sock.destroy();
  err = null;
  try { await proxyConnect("example.com:443", { proxy: "http://127.0.0.1:1" }); } catch (e) { err = e; }
  ok(err?.code === "Transport", "no proxy listening -> Transport");
  proxy.close(); echo.close();
}

console.log("=== daemon status ===");
{
  const fetchImpl = async (u) => ({ ok: true, status: 200, json: async () => ({ admitted: true, tier: 1, slotsLeft: 0, extra: 1, url: String(u) }) });
  const st = await sdk.daemonStatus({ fetchImpl });
  ok(st.admitted === true && st.slotsLeft === 0 && st.finalized === null && !("extra" in st), "status normalized to the documented fields");
  ok(await code(() => sdk.daemonStatus({ fetchImpl: async () => { throw new Error("ECONNREFUSED"); } })) === "Transport", "no daemon -> Transport");
}

if (failures) {
  console.log(`\nFAIL: ${failures} SDK check(s)`);
  process.exit(1);
}
console.log("\nPASS: @shadenet/sdk selftest");
process.exit(0); // snarkjs keeps worker threads alive
