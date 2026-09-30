// register-gateway: stake a gateway operator bond into GatewayRegistry (contracts/GatewayRegistry.sol).
//
// This is OPTIONAL — bootnode admission defaults to `open` and a gateway can announce with only
// its onion-control signature. Stake it when you want the bootnode/clients to be able to require
// skin-in-the-game (admission=stake), or simply to fund the address that will pay gas to slash
// member over-spenders. The stake binds to the operator ADDRESS (msg.sender), never to an onion,
// so one stake can back many/rotating onions and the fleet is never enumerable on chain.
//
// After staking, authorize your onion off chain and hand it to the heartbeat:
//   SHADE_TREE_GW_OPERATOR_KEY=<this key> shade-tree-node heartbeat --bootnode <onion>
// (the heartbeat signs operatorAuthMessage(onion, operator) durably; see packages/node/bootnode/heartbeat.mjs).
//
// Config:
//   SHADE_TREE_RPC_URL           JSON-RPC endpoint            (default: deployed.rpcUrl or anvil)
//   SHADE_TREE_GATEWAY_REGISTRY  GatewayRegistry address      (default: network/<SHADE_TREE_NETWORK>/contracts.json
//                                                        contracts.gatewayRegistry, else deployed.gatewayRegistry)
//   SHADE_TREE_REGISTER_KEY      operator private key         (default: anvil account #1)
//   SHADE_TREE_BOND              bond in wei                  (default: on-chain BOND())

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { networkDefault } from "../packages/node/lib/network-record.mjs";
import { makeBoundedJsonRpcProvider, registrationKey, waitForTransactionReceipt } from "../packages/node/lib/rpc-safety.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const DEPLOYED_PATH = join(HERE, "..", "contracts", "deployed.local.json");
// anvil's deterministic account #1 — dev only, so the member (#0) and gateway operators differ.
const ANVIL_KEY_1 = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

async function readDeployed() {
  try { return JSON.parse(await readFile(DEPLOYED_PATH, "utf8")); } catch { return {}; }
}

async function main() {
  const deployed = await readDeployed();
  // Resolution: explicit env > committed network record (SHADE_TREE_NETWORK) > deployer-local cache.
  const rpcUrl = process.env.SHADE_TREE_RPC_URL || networkDefault("SHADE_TREE_RPC_URL") || deployed.rpcUrl || "http://127.0.0.1:8545";
  const address = process.env.SHADE_TREE_GATEWAY_REGISTRY || networkDefault("SHADE_TREE_GATEWAY_REGISTRY") || deployed.gatewayRegistry || deployed.GatewayRegistry;
  const key = registrationKey({
    rpcUrl,
    explicitKey: process.env.SHADE_TREE_REGISTER_KEY,
    developmentKey: ANVIL_KEY_1,
    label: "gateway registration",
  });
  if (!address) {
    console.error("no GatewayRegistry address: set SHADE_TREE_GATEWAY_REGISTRY, or SHADE_TREE_NETWORK=<name> with contracts.gatewayRegistry recorded, or write contracts/deployed.local.json");
    process.exit(1);
  }

  let ethers;
  try { ({ ethers } = await import("ethers")); }
  catch { console.error("register-gateway needs the `ethers` dependency."); process.exit(1); }

  const provider = await makeBoundedJsonRpcProvider(ethers, rpcUrl);
  const wallet = new ethers.Wallet(key, provider);
  const abi = ["function register() payable", "function BOND() view returns (uint256)", "function isStaked(address) view returns (bool)"];
  const contract = new ethers.Contract(address, abi, wallet);

  if (await contract.isStaked(wallet.address)) {
    console.log(`operator ${wallet.address} is already staked; nothing to do.`);
    return;
  }
  const bond = process.env.SHADE_TREE_BOND ?? (await contract.BOND());
  console.log(`register gateway operator`);
  console.log(`  contract: ${address}`);
  console.log(`  rpc:      ${rpcUrl}`);
  console.log(`  operator: ${wallet.address}`);
  console.log(`  bond:     ${bond} wei`);

  const tx = await contract.register({ value: bond });
  console.log(`  tx:       ${tx.hash}  (waiting...)`);
  const rcpt = await waitForTransactionReceipt(tx, { operation: "gateway registration" });
  console.log(`  mined in block ${rcpt.blockNumber}; operator staked. Authorize your onion via the heartbeat.`);
}

main().catch((e) => { console.error("register-gateway failed:", e.shortMessage || e.message); process.exit(1); });
