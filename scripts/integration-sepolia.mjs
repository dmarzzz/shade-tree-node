// Full integration test against LIVE Sepolia + the real gateway:
//   two members stake on-chain, one uses the gateway normally, one over-spends its
//   per-epoch rate cap, and the gateway reconstructs its secret and SLASHES its bond
//   on-chain. Every step is timestamped for the deployment report.
//
// Transport: the client talks to a LOCAL gateway over TCP (exactly the bytes Tor
// delivers to a fleet gateway) so the test isolates the stake/use/over-spend/slash
// protocol from onion-descriptor propagation. Membership gates on group/members.json
// (the single rateCommitment leaf, same value on-chain); staking + slashing are real
// Sepolia transactions.
//
// NOT RUN in the P2 phase (no testnet funds here). Kept on the current v4 envelope +
// single-leaf + identitySecret-reveal path so it is ready for the live phase.
//
// Run:  SHADE_TREE_SCRATCH=/path/to/wallet-fixtures node scripts/integration-sepolia.mjs

import net from "node:net";
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { ethers } from "ethers";
import { deriveCommitment, identitySecretOf, identityFor, currentEpoch, requestSignal, proveForSlot, loadGroup } from "../lib/semaphore.mjs";
import { makeSlotPool, buildEnvelope } from "../client/shim.mjs";

// A member's identitySecret + rateCommitment leaf from the app seed (single-leaf model).
const idsecOf = (seed) => identitySecretOf(identityFor(seed));
const leafOf = (seed) => deriveCommitment(idsecOf(seed)); // == on-chain hasher.commitmentOf(identitySecret)

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SC = process.env.SHADE_TREE_SCRATCH;
if (!SC) throw new Error("SHADE_TREE_SCRATCH must point to the local wallet-fixture directory");
const dep = JSON.parse(readFileSync(join(ROOT, "contracts", "deployed.local.json"), "utf8"));
const RPC = dep.rpcUrl;
const SET = dep.stakedReputationSet;
const wallet = (f) => JSON.parse(readFileSync(join(SC, f), "utf8"))[0];
const slasher = wallet("sepolia-slasher.json");
const memberAW = wallet("memberA.json");
const memberBW = wallet("memberB.json");
const keys = JSON.parse(readFileSync(join(ROOT, "keys.local.json"), "utf8"));
const alice = keys[0], bob = keys[1]; // secrets whose identity leaves are in members.json

const provider = new ethers.JsonRpcProvider(RPC);
const ABI = [
  "function BOND() view returns (uint256)",
  "function members(uint256) view returns (uint256 bond, uint64 index, uint64 exitInitiatedAt)", // rln-v3 shape (this script targets the rln-v3 run; rln-v4 tiers: scripts/integration-tiers.mjs)
  "function register(uint256 commitment) payable",
  "function activeCount() view returns (uint256)",
];

const T0 = Date.now();
const stamp = () => new Date(T0 + (Date.now() - T0)).toISOString().replace("T", " ").replace("Z", "");
const trace = [];
function log(step, msg) { const line = `[${stamp()}] [+${((Date.now() - T0) / 1000).toFixed(1)}s] ${step}: ${msg}`; console.log(line); trace.push(line); }

// Send an explicit v4 envelope to the local gateway over TCP; resolve its ack line.
function sendEnvelope(envelope, timeoutMs = 45000) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(8443, "127.0.0.1", () => sock.write(JSON.stringify(envelope) + "\n"));
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => { sock.destroy(); reject(new Error("no ack in " + timeoutMs + "ms")); }, timeoutMs);
    sock.on("data", (c) => {
      buf = Buffer.concat([buf, c]);
      const nl = buf.indexOf(0x0a);
      if (nl === -1) return;
      clearTimeout(timer);
      const ack = JSON.parse(buf.subarray(0, nl).toString());
      sock.destroy();
      resolve(ack);
    });
    sock.on("error", (e) => { clearTimeout(timer); reject(e); });
  });
}

let gw, gwOut = "";
function startGateway() {
  return new Promise((resolve, reject) => {
    gw = spawn(process.execPath, [join(ROOT, "gateway", "gateway.mjs")], {
      cwd: ROOT,
      env: { ...process.env,
        // T-FEAT-9: the gateway admits invited (members.json) ONLY by default; this integration
        // proves against the staked set, so admit it explicitly (SHADE_TREE_ADMIT in the caller's env wins).
        SHADE_TREE_ADMIT: process.env.SHADE_TREE_ADMIT || (process.env.SHADE_TREE_GROUP_CONTRACT ? "invited,staked" : "invited"),
        SHADE_TREE_EPOCH_SECONDS: "120",
        SHADE_TREE_SLASH_KEY: slasher.private_key,
        SHADE_TREE_SLASH_RECEIVER: slasher.address, // slashed bond -> slasher
      },
    });
    const onData = (d) => {
      const s = d.toString(); gwOut += s;
      s.split("\n").filter(Boolean).forEach((l) => log("gateway", l));
      if (s.includes("gateway up on")) resolve();
    };
    gw.stdout.on("data", onData);
    gw.stderr.on("data", onData);
    gw.on("exit", (c) => { if (c) reject(new Error("gateway exited " + c)); });
    setTimeout(() => reject(new Error("gateway did not start")), 15000);
  });
}
async function waitForSlashTx(ms = 60000) {
  const start = Date.now();
  while (Date.now() - start < ms) {
    const m = gwOut.match(/SLASH mined block (\d+)/);
    if (m) return { block: Number(m[1]), hash: (gwOut.match(/SLASH tx (0x[0-9a-fA-F]+)/) || [])[1] };
    await new Promise((r) => setTimeout(r, 1000));
  }
  return null;
}

async function main() {
  const set = new ethers.Contract(SET, ABI, provider);
  const BOND = await set.BOND();
  log("setup", `Sepolia StakedReputationSet ${SET} bond=${ethers.formatEther(BOND)} ETH rpc=${RPC}`);
  const commA = leafOf(alice.secret); // rateCommitment — the single on-chain + tree leaf
  const commB = leafOf(bob.secret);
  log("setup", `member ALICE (normal) leaf-commitment ${commA.slice(0, 20)}.. staking wallet ${memberAW.address}`);
  log("setup", `member BOB   (abuser) leaf-commitment ${commB.slice(0, 20)}.. staking wallet ${memberBW.address}`);

  // 1. stake both on-chain
  const wA = new ethers.Wallet(memberAW.private_key, provider);
  const wB = new ethers.Wallet(memberBW.private_key, provider);
  log("stake", "ALICE register+bond ...");
  let tx = await new ethers.Contract(SET, ABI, wA).register(commA, { value: BOND });
  let r = await tx.wait();
  log("stake", `ALICE staked: tx ${tx.hash} block ${r.blockNumber}`);
  log("stake", "BOB register+bond ...");
  tx = await new ethers.Contract(SET, ABI, wB).register(commB, { value: BOND });
  r = await tx.wait();
  log("stake", `BOB staked: tx ${tx.hash} block ${r.blockNumber}`);
  log("stake", `on-chain activeCount=${await set.activeCount()}  (both bonds held)`);

  // 2. start the gateway (wired for on-chain slashing on Sepolia)
  await startGateway();

  // 3. ALICE uses the gateway normally — 3 tunnels, auto slot rotation (slots 0,1,2)
  const poolA = makeSlotPool({ secret: alice.secret });
  for (let i = 0; i < 3; i++) {
    const target = ["example.com:443", "api.ipify.org:443", "cloudflare.com:443"][i];
    const tBuild = Date.now();
    const { envelope, slot } = await buildEnvelope({ secret: alice.secret, target, pool: poolA });
    log("alice", `tunnel ${i + 1}: built envelope slot=${slot} nullifier=${envelope.nullifier.slice(0, 12)}.. (${Date.now() - tBuild}ms) -> sending`);
    const tSend = Date.now();
    const ack = await sendEnvelope(envelope);
    log("alice", `tunnel ${i + 1}: gateway ack ${JSON.stringify(ack)} (round-trip ${Date.now() - tSend}ms)`);
  }
  log("alice", "3/3 within budget — normal use OK, no slash");

  // 4. BOB over-spends: TWO distinct signals on the SAME slot 0 => same nullifier, two
  //    shares => the gateway reconstructs BOB's secret and slashes his bond on-chain.
  const group = (await loadGroup()).group;
  const epoch = currentEpoch();
  const target = "example.com:443";
  const n1 = "b-n1";
  const e1 = await proveForSlot(bob.secret, epoch, 0, requestSignal(target, n1), { group });
  const env1 = { v: 4, target, nonce: n1, proof: e1.proof, nullifier: e1.nullifier, externalNullifier: e1.externalNullifier, share: e1.share };
  log("bob", `over-spend 1/2: slot 0 first signal, nullifier ${e1.nullifier.slice(0, 12)}.. -> sending`);
  log("bob", `over-spend 1/2: gateway ack ${JSON.stringify(await sendEnvelope(env1))}`);
  const n2 = "b-n2";
  const e2 = await proveForSlot(bob.secret, epoch, 0, requestSignal(target, n2), { group });
  const env2 = { v: 4, target, nonce: n2, proof: e2.proof, nullifier: e2.nullifier, externalNullifier: e2.externalNullifier, share: e2.share };
  log("bob", `over-spend 2/2: slot 0 SECOND distinct signal (same nullifier) -> this is the rate violation -> sending`);
  const ack2 = await sendEnvelope(env2, 90000); // slash mines before ack
  log("bob", `over-spend 2/2: gateway ack ${JSON.stringify(ack2)}`);

  // 5. wait for the on-chain slash tx the gateway submitted
  const slash = await waitForSlashTx();
  if (slash) log("slash", `on-chain slash mined: tx ${slash.hash} block ${slash.block}`);
  else log("slash", "WARN: no slash tx observed in gateway output");

  // 6. verify on-chain outcome
  const mA = await set.members(commA), mB = await set.members(commB);
  log("verify", `ALICE bond on-chain = ${ethers.formatEther(mA.bond)} ETH (intact expected)`);
  log("verify", `BOB   bond on-chain = ${ethers.formatEther(mB.bond)} ETH (0 = slashed expected)`);
  log("verify", `slasher balance = ${ethers.formatEther(await provider.getBalance(slasher.address))} ETH (slash reward depends on the deployed contract policy)`);
  const pass = mA.bond === BOND && mB.bond === 0n;
  log("result", pass ? "PASS — honest member intact, over-spender slashed on-chain" : "FAIL — see bonds above");

  gw.kill();
  console.log("\n" + trace.join("\n"));
  process.exit(pass ? 0 : 1);
}
main().catch((e) => { console.error(e); if (gw) gw.kill(); process.exit(1); });
