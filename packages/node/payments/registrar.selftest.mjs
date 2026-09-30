// The 402 rails end to end on a throwaway anvil (T-FEAT-7): the REAL registrar (in-process HTTP
// server + engine over ethers), the REAL `shade-tree pay` client (group/pay.mjs, driven through the
// router as a child so argv/env plumbing is exercised), an EIP-3009 token (test/Eip3009Token.sol)
// and the REAL PaidAccessSet (contracts/PaidAccessSet.sol + RateCommitmentHasher + Poseidon libs)
// deployed with forge create. Slow
// lane (forge build + anvil + ~a dozen txs; in scripts/test-all.mjs SLOW_SUITES). Needs anvil +
// forge on PATH, else SKIPs honestly.
//
// Proves:
//   1. quote: GET /pay/quote(?limit) is 402 with BOTH challenges (PAYMENT-REQUIRED decodes to an
//      x402 v2 PaymentRequired; WWW-Authenticate parses to MPP evm/charge type=authorization
//      challenges), one entry per tier, prices == SHADE_TREE_PAY_PRICES; POST /pay without a payment
//      header is the same 402 with the MPP challenge digest-bound to the body.
//   2. x402 purchase: `shade-tree pay --protocol x402` -> 200 + PAYMENT-RESPONSE {success:true,
//      transaction} -> stablecoin moved buyer -> payTo (exact price), leaf inserted at the tier,
//      currentRoot changed and == the JS tree over the inserted leaves, buyer spent NO gas.
//   3. MPP purchase: `shade-tree pay --protocol mpp` (second buyer, tier 32) -> 200 + Payment-Receipt
//      {status:success, reference == settleTx, challengeId}; nonce == keccak256(id ‖ realm).
//   4. idempotency: identical replay -> 200 replayed:true, SAME insertTx, leafCount unchanged;
//      same nonce + different commitment -> 409; a used nonce presented as fresh -> 402.
//   5. adversarial (no funds move, no leaf inserted): wrong amount, wrong payTo, expired
//      validBefore, not-yet-valid, bad signature (wrong key / mauled), unknown limit, body.limit !=
//      paid tier, MPP tampered challenge (amount edited -> HMAC id no longer verifies), MPP wrong
//      nonce, MPP digest mismatch, oversize body (413), oversize header (431), garbage headers,
//      commitment already active (409, refused BEFORE settlement), insufficient balance.
//   6. hardening: slow-loris headers cut at headersTimeout; rate bucket answers 429+Retry-After.
//   7. crash recovery: an order stored `settled` (settle mined, insert missing) is inserted on
//      recover(); the identical POST afterwards is a replay.
//   8. --dry-run signs nothing (no tx, no balance change) and prints the authorization it would sign.
//
//   node packages/node/payments/registrar.selftest.mjs

import { spawn, spawnSync } from "node:child_process";
import net from "node:net";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ethers } from "ethers";
import { makeStore, makeEngine, makeServer, makeOffer, probeAsset, PAID_ACCESS_SET_ABI } from "./registrar.mjs";
import { EIP3009_ABI, tokenDomain, signAuthorization, randomNonce } from "./eip3009.mjs";
import { decodeX402Header, encodeX402Header, x402PaymentPayload, parseWwwAuthenticate, mppCredential, mppNonce, b64decode, jsonParseSafe, contentDigest } from "./wire.mjs";
import { newGroup } from "../lib/rln.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "../../..");
const ANVIL_KEY_0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"; // deployer + token owner + operator
const OPERATOR = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
// Buyers: fresh random wallets with the token only (never any ETH -> proves "no gas needed").
const BUYER_A = ethers.Wallet.createRandom();
const BUYER_B = ethers.Wallet.createRandom();
const COMMIT_A = "11302006078516901731073162965056551612114122314181142374993834332168998510316"; // JS golden leaf (111, 8)
const COMMIT_B = "6559234296040236204575836750760151586782987140458381330408475886232473073686";  // (222, 32)
const COMMIT_C = "15363698809722346745616993869789510363416645981863858152379739283427647190637"; // (111, 32)
const PRICES = "8=100000,32=400000";

async function rpc(url, method, params = []) {
  const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  const j = await res.json(); if (j.error) throw new Error(j.error.message); return j.result;
}
function portFree(port) {
  return new Promise((resolve) => { const s = net.createServer(); s.once("error", () => resolve(false)); s.listen(port, "127.0.0.1", () => s.close(() => resolve(true))); });
}
function forgeCreate(forgeBin, rpcUrl, target, args = [], libs = []) {
  const argv = ["create", target, "--rpc-url", rpcUrl, "--private-key", ANVIL_KEY_0, "--broadcast", "--json"];
  for (const l of libs) argv.push("--libraries", l);
  if (args.length) argv.push("--constructor-args", ...args);
  const r = spawnSync(forgeBin, argv, { cwd: ROOT, encoding: "utf8" });
  // --json prints a pretty-printed object (possibly after warnings): take from the first "{".
  const out = r.stdout || ""; const at = out.indexOf("{");
  let j = null; try { j = at >= 0 ? JSON.parse(out.slice(at, out.lastIndexOf("}") + 1)) : null; } catch { j = null; }
  if (r.status !== 0 || !j?.deployedTo) throw new Error(`forge create ${target} failed: ${(r.stderr || r.stdout).slice(-600)}`);
  return j.deployedTo;
}
async function http(base, method, path, { headers = {}, body = null } = {}) {
  const res = await fetch(base + path, { method, headers: { ...(body != null ? { "content-type": "application/json" } : {}), ...headers }, body: body == null ? undefined : (typeof body === "string" ? body : JSON.stringify(body)) });
  const text = await res.text();
  const h = {}; for (const [k, v] of res.headers) h[k] = v;
  let json = null; try { json = JSON.parse(text); } catch { /* not json */ }
  return { status: res.status, headers: h, text, json };
}
// shade-tree pay through the router (child process), returning { status, stdout, stderr }. Async (not
// spawnSync): the registrar it talks to is served by THIS process's event loop.
function shadeTreePay(args, env) {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, [join(ROOT, "packages/node/bin/shade-tree.mjs"), "pay", ...args], { cwd: ROOT, env: { PATH: process.env.PATH, HOME: process.env.HOME || "/", ...env } });
    let stdout = "", stderr = "";
    c.stdout.on("data", (d) => { stdout += d; }); c.stderr.on("data", (d) => { stderr += d; });
    c.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}

async function main() {
  console.log("402 rails end to end on anvil (T-FEAT-7): registrar + shade-tree pay, x402 + MPP:");
  const anvilBin = spawnSync("which", ["anvil"], { encoding: "utf8" }).stdout.trim();
  const forgeBin = spawnSync("which", ["forge"], { encoding: "utf8" }).stdout.trim();
  if (!anvilBin || !forgeBin) { console.log("  SKIP anvil/forge not on PATH"); return; }
  const port = 8560 + Math.floor(Math.random() * 200);
  if (!(await portFree(port))) { console.log("  SKIP anvil port busy"); return; }
  const url = `http://127.0.0.1:${port}`;
  const anvil = spawn(anvilBin, ["--port", String(port), "--silent", "--block-time", "1"], { stdio: "ignore" });
  const work = mkdtempSync(join(tmpdir(), "shade-tree-registrar-"));
  let server = null;
  try {
    let up = false;
    for (let i = 0; i < 60 && !up; i++) { try { await rpc(url, "eth_chainId"); up = true; } catch { await new Promise((r) => setTimeout(r, 250)); } }
    if (!up) { console.log("  SKIP anvil did not come up"); return; }

    // ---- deploy: Poseidon libs -> RateCommitmentHasher -> PaidAccessSet(operator, hasher, [8,32]); Eip3009Token
    const build = spawnSync(forgeBin, ["build"], { cwd: ROOT, encoding: "utf8" });
    ok(build.status === 0, "forge build");
    const pT2 = forgeCreate(forgeBin, url, "contracts/PoseidonT2.sol:PoseidonT2");
    const pT3 = forgeCreate(forgeBin, url, "contracts/PoseidonT3.sol:PoseidonT3");
    const libs = [`contracts/PoseidonT2.sol:PoseidonT2:${pT2}`, `contracts/PoseidonT3.sol:PoseidonT3:${pT3}`];
    const hasher = forgeCreate(forgeBin, url, "contracts/RateCommitmentHasher.sol:RateCommitmentHasher", [], libs);
    const setAddr = forgeCreate(forgeBin, url, "contracts/PaidAccessSet.sol:PaidAccessSet", [OPERATOR, hasher, "[8,32]"], libs);
    const tokenAddr = forgeCreate(forgeBin, url, "test/Eip3009Token.sol:Eip3009Token", ["Test USD", "tUSD", "6"]);
    ok(ethers.isAddress(setAddr) && ethers.isAddress(tokenAddr), `deployed PaidAccessSet ${setAddr} + Eip3009Token ${tokenAddr}`);
    const provider = new ethers.JsonRpcProvider(url, undefined, { polling: true, pollingInterval: 200 });
    const operator = new ethers.Wallet(ANVIL_KEY_0, provider);
    const token = new ethers.Contract(tokenAddr, EIP3009_ABI, operator);
    const set = new ethers.Contract(setAddr, PAID_ACCESS_SET_ABI, operator);
    const tokenW = new ethers.Contract(tokenAddr, ["function mint(address,uint256)"], operator);
    await (await tokenW.mint(BUYER_A.address, 1_000_000_000n)).wait(); // 1000 tUSD
    await (await tokenW.mint(BUYER_B.address, 1_000_000_000n)).wait();
    ok((await provider.getBalance(BUYER_A.address)) === 0n && (await provider.getBalance(BUYER_B.address)) === 0n, "buyers hold tUSD and ZERO ETH");

    // ---- registrar in-process
    const env = { SHADE_TREE_PAY_ASSET: tokenAddr, SHADE_TREE_PAY_PRICES: PRICES, SHADE_TREE_REGISTRAR_PORT: "0", SHADE_TREE_PAY_TIMEOUT: "120", SHADE_TREE_PAY_SETTLE_BUFFER: "5" };
    const offer = makeOffer(env);
    offer.payTo = OPERATOR;
    await probeAsset(offer, token, provider);
    ok(offer.assetName === "Test USD" && offer.assetVersion === "1" && offer.decimals === 6 && offer.chainId === 31337, `probeAsset: domain proven against on-chain DOMAIN_SEPARATOR (${offer.assetName} v${offer.assetVersion}, chain ${offer.chainId})`);
    process.env.SHADE_TREE_REGISTRAR_PAY_RATE = "1"; process.env.SHADE_TREE_REGISTRAR_PAY_BURST = "40"; // the adversarial section spends ~25 POSTs; section 6 drains the rest
    const storePath = join(work, "registrar-state.json");
    const store = makeStore(storePath);
    const engine = makeEngine({ offer, token, set, wallet: operator, provider, store, confirmations: 1 });
    server = makeServer(engine, { offer, store, set, limits: { headersTimeout: 1500, requestTimeout: 3000, connectionsCheckingInterval: 200 } });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    const base = `http://127.0.0.1:${server.address().port}`;
    const rootBefore = (await set.currentRoot()).toString();

    // ---- 1. quotes
    console.log("1. quotes:");
    const q = await http(base, "GET", "/pay/quote");
    ok(q.status === 402, "GET /pay/quote -> 402");
    const pr = decodeX402Header(q.headers["payment-required"]);
    ok(pr && pr.x402Version === 2 && pr.accepts.length === 2 && pr.accepts.every((a) => a.scheme === "exact" && a.network === "eip155:31337" && a.asset === tokenAddr && a.payTo === OPERATOR), "PAYMENT-REQUIRED: x402 v2, one exact/eip155:31337 entry per tier");
    ok(pr.accepts.map((a) => a.amount).join(",") === "100000,400000" && pr.accepts.map((a) => a.extra.limit).join(",") === "8,32" && pr.accepts[0].extra.name === "Test USD" && pr.accepts[0].extra.version === "1", "x402 accepts carry the tier prices + EIP-712 domain extra");
    const chs = String(q.headers["www-authenticate"]).split(/,\s*(?=Payment\s+id=)/).flatMap((l) => parseWwwAuthenticate(l));
    ok(chs.length === 2 && chs.every((c) => c.scheme === "Payment" && c.params.method === "evm" && c.params.intent === "charge" && c.params.id && c.params.realm && c.params.expires), `WWW-Authenticate: ${chs.length} MPP Payment challenges (evm/charge)`);
    const reqs = chs.map((c) => jsonParseSafe(b64decode(c.params.request, { url: true })));
    ok(reqs.map((r) => r.amount).join(",") === "100000,400000" && reqs.every((r) => r.currency === tokenAddr && r.recipient === OPERATOR && r.methodDetails.chainId === 31337 && r.methodDetails.credentialTypes[0] === "authorization"), "MPP requests: amount/currency/recipient/chainId/credentialTypes=[authorization]");
    ok(q.headers["content-type"].startsWith("application/problem+json") && q.json.type.endsWith("/payment-required") && q.json.pay.protocols.join() === "x402,mpp" && q.json.pay.tiers["32"] === "400000", "402 body: RFC 9457 problem + pay offer (protocols, tiers)");
    ok(q.headers["cache-control"] === "no-store", "402 is Cache-Control: no-store");
    const q8 = await http(base, "GET", "/pay/quote?limit=8");
    ok(decodeX402Header(q8.headers["payment-required"]).accepts.length === 1 && !String(q8.headers["www-authenticate"]).includes("Payment id=", 20), "?limit=8 narrows both rails to one tier");
    ok((await http(base, "GET", "/pay/quote?limit=16")).status === 400, "?limit=16 (not sold) -> 400");
    const bodyA = JSON.stringify({ commitment: COMMIT_A, limit: 8 });
    const qp = await http(base, "POST", "/pay", { body: bodyA });
    const chP = parseWwwAuthenticate(qp.headers["www-authenticate"])[0];
    ok(qp.status === 402 && chP && chP.params.digest === contentDigest(Buffer.from(bodyA)), "POST /pay without payment header -> 402 with the MPP challenge digest-bound to the body (RFC 9530)");
    const h = await http(base, "GET", "/health");
    ok(h.status === 200 && h.json.pay.asset === tokenAddr && h.json.leafCount === 0 && h.json.root === rootBefore && !("orders" in h.json), "/health advertises public chain state without private order volume");
    ok((await http(base, "GET", "/metrics")).status === 404, "the onion-facing registrar listener does not expose operator metrics");

    // ---- 2. x402 purchase via shade-tree pay
    console.log("2. x402 purchase (shade-tree pay --protocol x402):");
    const keyA = join(work, "buyer-a.key"); writeFileSync(keyA, BUYER_A.privateKey + "\n", { mode: 0o600 });
    const dry = await shadeTreePay(["--registrar-url", base, "--limit", "8", "--protocol", "x402", "--key-file", keyA, "--commitment", COMMIT_A, "--dry-run"], {});
    ok(dry.status === 0 && /dry-run: would sign/.test(dry.stderr) && /"to": "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"/.test(dry.stderr) && /"value": "100000"/.test(dry.stderr) && !dry.stderr.includes(BUYER_A.privateKey.slice(4, 20)), "--dry-run prints the authorization it would sign (to/value) and never the key");
    ok((await token.balanceOf(BUYER_A.address)) === 1_000_000_000n && Number(await set.leafCount()) === 0, "dry-run moved nothing");
    const p1 = await shadeTreePay(["--registrar-url", base, "--limit", "8", "--protocol", "x402", "--key-file", keyA, "--commitment", COMMIT_A, "--json"], {});
    const r1 = p1.status === 0 ? JSON.parse(p1.stdout) : null;
    ok(p1.status === 0 && r1 && r1.protocol === "x402" && /^0x[0-9a-f]{64}$/.test(r1.settleTx) && /^0x[0-9a-f]{64}$/.test(r1.insertTx) && r1.leafIndex === 0, `shade-tree pay x402 -> settleTx ${r1?.settleTx?.slice(0, 12)}… insertTx ${r1?.insertTx?.slice(0, 12)}… leafIndex 0 ${p1.status !== 0 ? p1.stderr.slice(-300) : ""}`);
    ok(r1 && r1.settlement && r1.settlement.success === true && r1.settlement.transaction === r1.settleTx && r1.settlement.network === "eip155:31337" && r1.settlement.payer === BUYER_A.address, "PAYMENT-RESPONSE: {success:true, transaction==settleTx, network, payer}");
    ok((await token.balanceOf(BUYER_A.address)) === 1_000_000_000n - 100_000n && (await token.balanceOf(OPERATOR)) === 100_000n, "exactly the tier price moved buyer -> payTo");
    ok((await set.limitOf(COMMIT_A)) === 8n && Number(await set.leafCount()) === 1, "leaf inserted at tier 8");
    const rootA = (await set.currentRoot()).toString();
    ok(rootA !== rootBefore && r1.root === rootA, "root changed and the receipt's root == currentRoot()");
    ok((await provider.getBalance(BUYER_A.address)) === 0n, "buyer still holds ZERO ETH (operator paid all gas)");
    ok(!p1.stderr.includes(BUYER_A.privateKey.slice(4, 20)) && !/0x[0-9a-fA-F]{130}/.test(p1.stderr + p1.stdout), "client output has no key and no signature");

    // ---- 3. MPP purchase via shade-tree pay (second buyer, tier 32)
    console.log("3. MPP purchase (shade-tree pay --protocol mpp):");
    const p2 = await shadeTreePay(["--registrar-url", base, "--limit", "32", "--protocol", "mpp", "--commitment", COMMIT_B, "--json"], { SHADE_TREE_PAY_KEY: BUYER_B.privateKey });
    const r2 = p2.status === 0 ? JSON.parse(p2.stdout) : null;
    ok(p2.status === 0 && r2 && r2.protocol === "mpp" && r2.leafIndex === 1 && /^0x[0-9a-f]{64}$/.test(r2.settleTx), `shade-tree pay mpp -> leafIndex 1, settleTx ${r2?.settleTx?.slice(0, 12)}… ${p2.status !== 0 ? p2.stderr.slice(-300) : ""}`);
    ok(r2 && r2.receipt && r2.receipt.status === "success" && r2.receipt.method === "evm" && r2.receipt.reference === r2.settleTx && r2.receipt.chainId === 31337 && typeof r2.receipt.challengeId === "string", "Payment-Receipt: {status:success, method:evm, reference==settleTx, chainId, challengeId}");
    ok(r2 && r2.nonce === mppNonce(r2.receipt.challengeId, offer.realm), "EIP-3009 nonce == keccak256(challenge.id ‖ realm)");
    ok((await token.balanceOf(BUYER_B.address)) === 1_000_000_000n - 400_000n && (await set.limitOf(COMMIT_B)) === 32n, "tier-32 price moved; leaf at tier 32");
    const rootB = (await set.currentRoot()).toString();
    // JS tree parity: leaves [A, B] in order == on-chain root
    const g = newGroup(); g.addMember(BigInt(COMMIT_A)); g.addMember(BigInt(COMMIT_B));
    ok(g.root.toString() === rootB, "on-chain root == JS newGroup([A, B]).root");
    const st = await http(base, "GET", `/pay/status/${r2.nonce}`);
    ok(st.status === 200 && st.json.orders[0].state === "inserted" && st.json.orders[0].insertTx === r2.insertTx, "/pay/status/<nonce> -> inserted order");

    // ---- 4. idempotency / replay
    console.log("4. idempotency:");
    const domain = tokenDomain({ name: offer.assetName, version: offer.assetVersion, chainId: 31337, asset: tokenAddr });
    const nowSec = () => Math.floor(Date.now() / 1000);
    const acc8 = pr.accepts[0];
    async function x402Post(wallet, commitment, limit, over = {}, sigOver = null) {
      const auth = { from: wallet.address, to: OPERATOR, value: acc8.amount, validAfter: "0", validBefore: String(nowSec() + 100), nonce: randomNonce(), ...over };
      const sig = sigOver || await signAuthorization(wallet, domain, auth);
      const accepted = { ...acc8, ...(over.value ? { amount: over.value } : {}) };
      const hdr = encodeX402Header(x402PaymentPayload(pr, accepted, auth, sig));
      const res = await http(base, "POST", "/pay", { headers: { "PAYMENT-SIGNATURE": hdr }, body: { commitment, limit } });
      return { ...res, auth, sig, hdr };
    }
    const first = await x402Post(BUYER_A, COMMIT_C, 32, { value: "400000" });
    ok(first.status === 200 && first.json.leafIndex === 2, "buyer A buys a second leaf (tier 32) directly over the wire");
    const replay = await http(base, "POST", "/pay", { headers: { "PAYMENT-SIGNATURE": first.hdr }, body: { commitment: COMMIT_C, limit: 32 } });
    ok(replay.status === 200 && replay.json.replayed === true && replay.json.insertTx === first.json.insertTx && Number(await set.leafCount()) === 3, "identical replay -> 200 replayed:true, same insertTx, no second insert");
    const diff = await http(base, "POST", "/pay", { headers: { "PAYMENT-SIGNATURE": first.hdr }, body: { commitment: "777", limit: 32 } });
    ok(diff.status === 409 && diff.json.err === "nonce-used", "same nonce, different commitment -> 409 nonce-used");
    const opBal = await token.balanceOf(OPERATOR);
    ok(opBal === 100_000n + 400_000n + 400_000n, "no double charge");

    // ---- 5. adversarial
    console.log("5. adversarial (nothing moves, nothing inserted):");
    const leafCount0 = Number(await set.leafCount());
    const balA0 = await token.balanceOf(BUYER_A.address);
    const wrongAmount = await x402Post(BUYER_A, "1001", 8, { value: "99999" });
    ok(wrongAmount.status === 402 && decodeX402Header(wrongAmount.headers["payment-response"]).success === false, `wrong amount -> 402 + PAYMENT-RESPONSE success:false (${decodeX402Header(wrongAmount.headers["payment-response"]).errorReason})`);
    const wrongTo = await x402Post(BUYER_A, "1002", 8, { to: BUYER_B.address });
    ok(wrongTo.status === 402, "wrong payTo -> 402");
    const expired = await x402Post(BUYER_A, "1003", 8, { validBefore: String(nowSec() - 1) });
    ok(expired.status === 402 && /expired/.test(decodeX402Header(expired.headers["payment-response"]).errorReason), "expired validBefore -> 402 expired");
    const soon = await x402Post(BUYER_A, "1004", 8, { validBefore: String(nowSec() + 2) });
    ok(soon.status === 402, "validBefore inside the settle buffer -> 402 (tx could not mine in time)");
    const future = await x402Post(BUYER_A, "1005", 8, { validAfter: String(nowSec() + 1000) });
    ok(future.status === 402, "validAfter in the future -> 402");
    const badSig = await x402Post(BUYER_A, "1006", 8, {}, await signAuthorization(BUYER_B, domain, { from: BUYER_A.address, to: OPERATOR, value: acc8.amount, validAfter: "0", validBefore: String(nowSec() + 100), nonce: randomNonce() }));
    ok(badSig.status === 402 && /signature/.test(decodeX402Header(badSig.headers["payment-response"]).errorReason), "signature by another key -> 402 bad-signature");
    const mauled = await x402Post(BUYER_A, "1007", 8, {}, "0x" + "11".repeat(65));
    ok(mauled.status === 402, "garbage 65-byte signature -> 402");
    const badLimit = await http(base, "POST", "/pay", { headers: { "PAYMENT-SIGNATURE": first.hdr }, body: { commitment: "1008", limit: 16 } });
    ok(badLimit.status === 400 && badLimit.json.err === "unknown-limit", "unknown limit in body -> 400");
    const mismatch = await x402Post(BUYER_A, "1009", 32); // pays tier-8 price, asks tier 32
    ok(mismatch.status === 402, "body.limit != the tier paid for -> 402");
    const already = await x402Post(BUYER_A, COMMIT_A, 8);
    ok(already.status === 409 && already.json.err === "already-member" && !(await token.authorizationState(BUYER_A.address, already.auth.nonce)), "commitment already active -> 409 BEFORE any settlement (nonce still unused)");
    // Audit 2.3.3 / #113 regression: a slash burns the identity's leaves (every tier); a repeat
    // purchase of a burned leaf is refused BEFORE settlement, so the buyer is never charged for a
    // leaf PaidAccessSet.insert would reject.
    const slashable = new ethers.Contract(setAddr, ["function slash(uint256,uint256,uint256,address)", "function burned(uint256) view returns (bool)"], operator);
    await (await slashable.slash(COMMIT_A, 111, 8, OPERATOR)).wait();
    ok(await slashable.burned(COMMIT_A) && await slashable.burned(COMMIT_C), "slashing (111, 8) burns that identity's leaf at tier 8 AND tier 32");
    const balBeforeBurned = await token.balanceOf(BUYER_A.address);
    const burnedBuy = await x402Post(BUYER_A, COMMIT_A, 8);
    ok(burnedBuy.status === 409 && burnedBuy.json.err === "burned-commitment", "repeat purchase of a burned leaf -> 409 burned-commitment");
    ok((await token.balanceOf(BUYER_A.address)) === balBeforeBurned && !(await token.authorizationState(BUYER_A.address, burnedBuy.auth.nonce)), "the buyer is not charged and the authorization nonce stays unused");
    ok((await set.limitOf(COMMIT_A)) === 0n, "no membership was created for the burned leaf");
    const zeroLeaf = await x402Post(BUYER_A, "0", 8);
    ok(zeroLeaf.status === 400 && !(await token.authorizationState(BUYER_A.address, zeroLeaf.auth.nonce)), "commitment 0 (the tree's empty-slot sentinel) -> 400 before any settlement");
    const poor = ethers.Wallet.createRandom();
    const broke = await x402Post(poor, "1010", 8);
    ok(broke.status === 402 && decodeX402Header(broke.headers["payment-response"]).errorReason === "insufficient_funds", "unfunded payer -> 402 insufficient_funds");
    const usedNonce = await x402Post(BUYER_A, "1011", 32, { nonce: first.auth.nonce, value: "400000" });
    ok(usedNonce.status === 409, `re-using an on-chain-consumed nonce (different order) -> ${usedNonce.status} nonce-used`);
    // MPP: tampered request (amount edited) breaks the HMAC id
    const qm = await http(base, "POST", "/pay", { body: bodyA });
    const cm = parseWwwAuthenticate(qm.headers["www-authenticate"])[0].params;
    const mppPost = async (wallet, ch, body, payloadOver = {}) => {
      const reqM = jsonParseSafe(b64decode(ch.request, { url: true }));
      const auth = { from: wallet.address, to: reqM.recipient, value: reqM.amount, validAfter: "0", validBefore: String(Math.floor(Date.parse(ch.expires) / 1000)), nonce: mppNonce(ch.id, ch.realm), ...payloadOver };
      const sig = await signAuthorization(wallet, domain, auth);
      const cred = mppCredential(ch, { type: "authorization", ...auth, signature: sig });
      return http(base, "POST", "/pay", { headers: { Authorization: `Payment ${cred}` }, body });
    };
    const tamperedReq = { ...cm, request: Buffer.from(JSON.stringify({ ...jsonParseSafe(b64decode(cm.request, { url: true })), amount: "1" })).toString("base64url") };
    const t1 = await mppPost(BUYER_A, tamperedReq, bodyA);
    ok(t1.status === 402 && t1.json.type.endsWith("/invalid-challenge") && t1.headers["www-authenticate"], "MPP: edited request (amount) -> HMAC id no longer verifies -> 402 invalid-challenge + fresh challenge");
    const t2 = await mppPost(BUYER_A, cm, bodyA, { nonce: randomNonce() });
    ok(t2.status === 402 && t2.json.type.endsWith("/verification-failed"), "MPP: nonce != keccak256(id ‖ realm) -> 402 verification-failed");
    const t3 = await mppPost(BUYER_A, cm, JSON.stringify({ commitment: "1012", limit: 8 }));
    ok(t3.status === 402 && /digest/.test(t3.json.detail), "MPP: different body than the digest-bound challenge -> 402");
    const t4 = await http(base, "POST", "/pay", { headers: { Authorization: "Payment !!!notbase64" }, body: bodyA });
    ok(t4.status === 402 && t4.json.type.endsWith("/malformed-credential"), "MPP: malformed credential -> 402 malformed-credential");
    const t5 = await http(base, "POST", "/pay", { headers: { Authorization: "Bearer abc" }, body: bodyA });
    ok(t5.status === 402, "MPP: non-Payment Authorization scheme -> 402 challenge");
    const t6 = await http(base, "POST", "/pay", { headers: { "PAYMENT-SIGNATURE": "%%%" }, body: bodyA });
    ok(t6.status === 402 && decodeX402Header(t6.headers["payment-response"]).errorReason === "invalid_payment_payload", "x402: garbage PAYMENT-SIGNATURE -> 402 invalid_payment_payload");
    const t7 = await http(base, "POST", "/pay", { headers: { "PAYMENT-SIGNATURE": encodeX402Header({ x402Version: 1, accepted: acc8, payload: {} }) }, body: bodyA });
    ok(t7.status === 402 && decodeX402Header(t7.headers["payment-response"]).errorReason === "invalid_x402_version", "x402 v1 payload -> invalid_x402_version");
    const big = await http(base, "POST", "/pay", { headers: { "PAYMENT-SIGNATURE": first.hdr }, body: JSON.stringify({ commitment: COMMIT_A, limit: 8, pad: "x".repeat(5000) }) });
    ok(big.status === 413, "oversize body -> 413");
    const bigHdr = await http(base, "POST", "/pay", { headers: { "PAYMENT-SIGNATURE": "A".repeat(9000) }, body: bodyA }).catch((e) => ({ status: "conn:" + e.message }));
    ok(bigHdr.status === 431 || String(bigHdr.status).startsWith("conn:"), `oversize header -> ${bigHdr.status} (431 or connection dropped)`);
    ok(Number(await set.leafCount()) === leafCount0 && (await token.balanceOf(BUYER_A.address)) === balA0, "adversarial section: no leaf inserted, no funds moved");

    // ---- 6. hardening
    console.log("6. hardening:");
    const loris = await new Promise((resolve) => {
      const s = net.connect(server.address().port, "127.0.0.1", () => s.write("POST /pay HTTP/1.1\r\nHost: x\r\nX-Slow: "));
      const t0 = Date.now(); let data = "";
      s.on("data", (c) => { data += c; }); s.on("close", () => resolve({ ms: Date.now() - t0, data })); s.on("error", () => {});
      setTimeout(() => { try { s.destroy(); } catch {} resolve({ ms: 99999, data }); }, 8000);
    });
    ok(loris.ms < 6000, `slow-loris headers cut by the server after ~headersTimeout (${loris.ms}ms, ${/408/.test(loris.data) ? "408" : "closed"})`);
    let got429 = 0;
    for (let i = 0; i < 80; i++) { const r = await http(base, "POST", "/pay", { headers: { "PAYMENT-SIGNATURE": "zz" }, body: bodyA }); if (r.status === 429) { got429++; ok(r.headers["retry-after"] >= "1", "429 carries Retry-After"); break; } }
    ok(got429 === 1, "POST /pay token bucket -> 429 under a burst");

    // ---- 7. crash recovery
    console.log("7. crash recovery (settled, insert missing):");
    const auth7 = { from: BUYER_B.address, to: OPERATOR, value: "100000", validAfter: "0", validBefore: String(nowSec() + 100), nonce: randomNonce() };
    const sig7 = await signAuthorization(BUYER_B, domain, auth7);
    const s7 = ethers.Signature.from(sig7);
    const tx7 = await token.transferWithAuthorization(auth7.from, auth7.to, auth7.value, auth7.validAfter, auth7.validBefore, auth7.nonce, s7.v, s7.r, s7.s);
    await tx7.wait();
    store.put({ asset: tokenAddr, from: BUYER_B.address, nonce: auth7.nonce, commitment: "424242", limit: 8, protocol: "x402", state: "settled", settleTx: tx7.hash, createdAt: Date.now() });
    const store2 = makeStore(storePath);
    const engine2 = makeEngine({ offer, token, set, wallet: operator, provider, store: store2, confirmations: 1 });
    const rec = await engine2.recover();
    ok(rec.resumed === 1 && rec.failed === 0 && (await set.limitOf("424242")) === 8n, "recover(): the settled-but-not-inserted order gets its insert");
    ok(store2.mppSecret() === store.mppSecret(), "MPP challenge secret survives a restart (unexpired challenges stay valid)");
    const rep7 = await engine2.verifyAndSettle({ protocol: "x402", limit: 8, commitment: "424242", authorization: auth7, signature: sig7 });
    ok(rep7.ok && rep7.replayed && rep7.order.state === "inserted", "the identical POST after recovery is a replay (no second charge/insert)");
    const stuck = { asset: tokenAddr, from: BUYER_B.address, nonce: randomNonce(), commitment: "434343", limit: 8, protocol: "mpp", state: "settling", createdAt: Date.now() };
    store2.put(stuck);
    const rec2 = await engine2.recover();
    ok(rec2.pending === 1 && rec2.failed === 0 && store2.get(tokenAddr, BUYER_B.address, stuck.nonce).state === "settling", "a legacy 'settling' order without a tx hash stays pending for manual reconciliation");
  } finally {
    if (server) await new Promise((r) => server.close(r));
    anvil.kill();
    rmSync(work, { recursive: true, force: true });
  }
  console.log(failures ? `\n${failures} FAILED` : "\nall green");
  process.exit(failures ? 1 : 0);
}
main().catch((e) => { console.error(e); process.exit(1); });
