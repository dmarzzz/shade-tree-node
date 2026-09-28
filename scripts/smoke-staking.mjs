#!/usr/bin/env node
// Staking smoke test against a deployed ShadeNet StakedReputationSet, with REAL Groth16 exit and
// withdraw proofs (circuits/rln/withdraw.wasm + withdraw_final.zkey):
//
//   A: registerIdentity -> initiateExit -> (unbonding) -> withdraw to a fresh recipient
//   B: registerIdentity -> slash with its revealed identity secret (bounty to the caller, rest burned)
//
// On an anvil fork, --warp skips the unbonding window. On Sepolia the run stops after the exit
// and records its state; rerun with --resume once the window has passed.
//
//   node scripts/smoke-staking.mjs --rpc-url <url> --contract <set> --warp --key <hex>
//   node scripts/smoke-staking.mjs --rpc-url <url> --contract <set> [--state <file>]      (Sepolia)
//   node scripts/smoke-staking.mjs --rpc-url <url> --contract <set> --resume [--state <file>]
//
// The funding key comes from --key or SHADE_TREE_SMOKE_KEY. The smoke identities are throwaway
// testnet secrets; the state file (default cache/smoke-<contract>.local.json) is gitignored.

import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as snarkjs from "snarkjs";
import { poseidon1, poseidon2 } from "poseidon-lite";
import { AbiCoder, Contract, JsonRpcProvider, NonceManager, Wallet, ZeroAddress, getAddress } from "ethers";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const ABI = [
  "function registerIdentity(uint256 identityCommitment, uint256 limit) payable returns (uint256)",
  "function initiateExit(uint256 commitment, bytes proof)",
  "function withdraw(uint256 commitment, address recipient, bytes proof)",
  "function slash(uint256 commitment, uint256 secret, uint256 limit, address receiver)",
  "function exitContext(uint256 commitment) view returns (bytes32)",
  "function withdrawContext(uint256 commitment, address recipient) view returns (bytes32)",
  "function bondFor(uint256 limit) view returns (uint256)",
  "function allowedLimits() view returns (uint256[])",
  "function isActive(uint256 commitment) view returns (bool)",
  "function withdrawableAt(uint256 commitment) view returns (uint256)",
  "function currentRoot() view returns (uint256)",
  "function SLASH_REWARD_DIVISOR() view returns (uint256)",
  "function UNBONDING() view returns (uint256)",
  "event SlashPayout(uint256 indexed commitment, address indexed receiver, uint256 burned, uint256 reward)",
];

function parseArgs(argv) {
  const opts = { rpcUrl: null, contract: null, key: process.env.SHADE_TREE_SMOKE_KEY || null, warp: false, resume: false, state: null };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--rpc-url") opts.rpcUrl = argv[++i];
    else if (arg === "--contract") opts.contract = argv[++i];
    else if (arg === "--key") opts.key = argv[++i];
    else if (arg === "--state") opts.state = argv[++i];
    else if (arg === "--warp") opts.warp = true;
    else if (arg === "--resume") opts.resume = true;
    else throw new Error(`unknown argument ${arg}`);
  }
  if (!opts.rpcUrl || !opts.contract || !opts.key) throw new Error("--rpc-url, --contract and --key (or SHADE_TREE_SMOKE_KEY) are required");
  opts.contract = getAddress(opts.contract);
  opts.state ??= join(ROOT, "cache", `smoke-${opts.contract.toLowerCase()}.local.json`);
  return opts;
}

const check = (cond, message) => {
  if (!cond) throw new Error(`smoke: ${message}`);
  console.log(`  ok   ${message}`);
};

function newIdentity() {
  const secret = BigInt("0x" + randomBytes(32).toString("hex")) % FIELD;
  return { secret: secret.toString(), idc: poseidon1([secret]).toString() };
}

async function authProof(identity, context) {
  const address = BigInt(context) % FIELD;
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    { identitySecret: identity.secret, address: address.toString() },
    join(ROOT, "circuits/rln/withdraw.wasm"),
    join(ROOT, "circuits/rln/withdraw_final.zkey"),
  );
  if (publicSignals[0] !== identity.idc || publicSignals[1] !== address.toString()) throw new Error("withdraw proof has unexpected public signals");
  const [a, b, c] = JSON.parse("[" + (await snarkjs.groth16.exportSolidityCallData(proof, publicSignals)) + "]");
  return AbiCoder.defaultAbiCoder().encode(["uint256[2]", "uint256[2][2]", "uint256[2]", "uint256"], [a, b, c, identity.idc]);
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const provider = new JsonRpcProvider(opts.rpcUrl, undefined, { cacheTimeout: -1 });
  const wallet = new NonceManager(new Wallet(opts.key, provider));
  const set = new Contract(opts.contract, ABI, wallet);
  const save = (state) => { mkdirSync(dirname(opts.state), { recursive: true }); writeFileSync(opts.state, JSON.stringify(state, null, 2) + "\n", { mode: 0o600 }); };

  let state;
  if (opts.resume) {
    if (!existsSync(opts.state)) throw new Error(`no smoke state at ${opts.state}`);
    state = JSON.parse(readFileSync(opts.state, "utf8"));
  } else {
    const limit = Number((await set.allowedLimits())[0]);
    const bond = await set.bondFor(limit);
    state = { contract: opts.contract, limit, bond: bond.toString(), a: newIdentity(), b: newIdentity(), recipient: Wallet.createRandom().address, done: [] };
    console.log(`smoke: ${opts.contract} tier ${limit}, bond ${bond} wei`);

    for (const who of ["a", "b"]) {
      const member = state[who];
      const rootBefore = await set.currentRoot();
      member.leaf = (await set.registerIdentity.staticCall(member.idc, limit, { value: bond })).toString();
      await (await set.registerIdentity(member.idc, limit, { value: bond })).wait();
      check(member.leaf === poseidon2([BigInt(member.idc), BigInt(limit)]).toString(), `${who}: the set derived leaf Poseidon2(idc, ${limit})`);
      check(await set.isActive(member.leaf), `${who}: registered and active`);
      check((await set.currentRoot()) !== rootBefore, `${who}: the on-chain root moved`);
    }
    state.done.push("register");

    const exitCtx = await set.exitContext(state.a.leaf);
    await (await set.initiateExit(state.a.leaf, await authProof(state.a, exitCtx))).wait();
    check(!(await set.isActive(state.a.leaf)), "a: exit authorized by a real Groth16 proof bound to chain, set and index");
    state.withdrawableAt = (await set.withdrawableAt(state.a.leaf)).toString();
    state.done.push("exit");

    // The burn goes to address(0), which can also collect block rewards (anvil's coinbase), so the
    // split is read from the SlashPayout event and the sink balance is only bounded below.
    const burnBefore = await provider.getBalance(ZeroAddress);
    const receiver = Wallet.createRandom().address;
    const slashReceipt = await (await set.slash(state.b.leaf, state.b.secret, limit, receiver)).wait();
    const divisor = await set.SLASH_REWARD_DIVISOR();
    const reward = bond / divisor;
    const payout = slashReceipt.logs.map((log) => { try { return set.interface.parseLog(log); } catch { return null; } }).find((log) => log?.name === "SlashPayout");
    check((await provider.getBalance(receiver)) === reward, `b: slash paid the bounty bond/${divisor} to the caller's receiver`);
    check(payout?.args.burned === bond - reward && payout?.args.reward === reward, "b: SlashPayout reports the rest of the bond burned");
    check((await provider.getBalance(ZeroAddress)) - burnBefore >= bond - reward, "b: the burn reached address(0)");
    check(!(await set.isActive(state.b.leaf)), "b: slashed leaf left the set");
    state.done.push("slash");
    save(state);
  }

  if (opts.warp) {
    await provider.send("evm_increaseTime", [Number(await set.UNBONDING()) + 1]);
    await provider.send("evm_mine", []);
  }
  const now = BigInt((await provider.getBlock("latest")).timestamp);
  if (now < BigInt(state.withdrawableAt)) {
    console.log(`smoke: a is unbonding until ${state.withdrawableAt} (chain time ${now}); rerun with --resume after that. State: ${opts.state}`);
    return;
  }
  const withdrawCtx = await set.withdrawContext(state.a.leaf, state.recipient);
  await (await set.withdraw(state.a.leaf, state.recipient, await authProof(state.a, withdrawCtx))).wait();
  check((await provider.getBalance(state.recipient)) === BigInt(state.bond), "a: withdraw paid the whole bond to a fresh recipient after unbonding");
  state.done.push("withdraw");
  save(state);
  console.log("smoke: register -> exit -> withdraw -> slash all passed");
}

main().then(() => process.exit(0)).catch((error) => {
  console.error(error.shortMessage || error.message);
  process.exit(1);
});
