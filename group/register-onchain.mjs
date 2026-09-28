// register-onchain: stake a self-enrolled identity into the on-chain
// StakedReputationSet (docs/ONCHAIN.md). The sibling of self-enrollment: enroll.mjs
// generates the identity locally and prints its identity commitment; this posts that
// identity commitment with the tier's bond, and the contract derives the member leaf
// Poseidon2(idc, limit) itself (launch audit 2.1.4), so the member is admitted to the
// *canonical*, tamper-evident on-chain root the gateway reads through its RootProvider.
//
// registerIdentity() is permissionless: anyone may pay the bond for any identity, but
// only the secret-holder can ever spend or exit it. In production the bond is
// funded from a Layer-0 shielded (Railgun / Privacy Pools) fresh address so the
// funding identity never links to the member (R1). For the local anvil demo we
// fund from a well-known anvil dev key.
//
// Usage:
//   node group/register-onchain.mjs <identity-commitment> [--limit N]
//   shade-tree register-member <identity-commitment> --limit 32
//
// Reputation tiers (T-FEAT-8b, docs/adr/0006-reputation-tiers.md): `--limit N` (or SHADE_TREE_LIMIT)
// is the tier the identity was ENROLLED at (`shade-tree enroll --limit N`); the set derives the
// leaf at that tier and prices the bond per tier (`bondFor(limit)`), so the amount is read from
// the contract for that tier. Default = 8 (the pre-tier K).
//
// Config (all overridable by env; defaults read contracts/deployed.local.json):
//   SHADE_TREE_RPC_URL        JSON-RPC endpoint         (default: deployed.rpcUrl or anvil)
//   SHADE_TREE_GROUP_CONTRACT StakedReputationSet addr  (default: deployed.StakedReputationSet)
//   SHADE_TREE_REGISTER_KEY   funding private key       (default: anvil account #0)
//   SHADE_TREE_LIMIT          tier limit (== --limit)   (default: 8)
//   SHADE_TREE_BOND           bond in wei               (default: on-chain bondFor(limit) / BOND())
//
// NB: needs the `ethers` dependency (see final report). Imported lazily so this
// file still parses without it.

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { poseidon2 } from "poseidon-lite";
import { normLimit, K_SLOTS, FIELD } from "../lib/rln.mjs";
import { parseContractList } from "../lib/root-provider.mjs";
import { makeBoundedJsonRpcProvider, registrationKey, requireRpcChainId, waitForTransactionReceipt } from "../lib/rpc-safety.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const DEPLOYED_PATH = join(HERE, "..", "contracts", "deployed.local.json");

// anvil's deterministic account #0 — dev only, funded on a fresh anvil.
const ANVIL_KEY_0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

async function readDeployed() {
  try {
    return JSON.parse(await readFile(DEPLOYED_PATH, "utf8"));
  } catch {
    return {}; // fall back entirely to env
  }
}

// --limit <n> | --limit=<n> (or SHADE_TREE_LIMIT): the tier the leaf was enrolled at.
const argv = process.argv.slice(2);
let limitArg = process.env.SHADE_TREE_LIMIT || null;
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === "--limit") { limitArg = argv[i + 1]; argv.splice(i, 2); break; }
  if (argv[i].startsWith("--limit=")) { limitArg = argv[i].slice("--limit=".length); argv.splice(i, 1); break; }
}
const LIMIT = normLimit(limitArg == null || limitArg === "" ? K_SLOTS : limitArg); // throws on a bad tier

async function readIdentityCommitment() {
  const arg = argv[0];
  if (arg && !arg.startsWith("--")) return arg.trim();
  // else read a single commitment from stdin (pipe from enroll --commitment-only)
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  const s = Buffer.concat(chunks).toString("utf8").trim();
  if (s) return s.split(/\s+/)[0];
  console.error("usage: node group/register-onchain.mjs <identity-commitment> [--limit N]   (or pipe one on stdin)");
  process.exit(1);
}

async function main() {
  const raw = await readIdentityCommitment();
  if (!/^[1-9][0-9]*$/.test(raw) || BigInt(raw) >= FIELD) {
    console.error("the identity commitment must be a non-zero canonical decimal BN254 field element");
    process.exit(1);
  }
  const identityCommitment = BigInt(raw);
  // The leaf registerIdentity will derive; printed, and used for the already-staked check.
  const commitment = poseidon2([identityCommitment, LIMIT]);
  const deployed = await readDeployed();

  const rpcUrl = process.env.SHADE_TREE_RPC_URL || deployed.rpcUrl || "http://127.0.0.1:8545";
  // SHADE_TREE_GROUP_CONTRACT may be a comma list since T-FEAT-7 (several sets trusted by the gateway);
  // a stake goes to the FIRST — the canonical staked set. (Paid access is inserted by the operator, docs/PAYMENTS.md.)
  const address = parseContractList(process.env.SHADE_TREE_GROUP_CONTRACT)[0] || deployed.StakedReputationSet || deployed.address;
  const key = registrationKey({
    rpcUrl,
    explicitKey: process.env.SHADE_TREE_REGISTER_KEY,
    developmentKey: ANVIL_KEY_0,
    label: "member registration",
  });
  if (!address) {
    console.error("no StakedReputationSet address: set SHADE_TREE_GROUP_CONTRACT or write contracts/deployed.local.json");
    process.exit(1);
  }

  let ethers;
  try {
    ({ ethers } = await import("ethers"));
  } catch {
    console.error("register-onchain needs the `ethers` dependency (add it to package.json; see report).");
    process.exit(1);
  }

  const provider = await makeBoundedJsonRpcProvider(ethers, rpcUrl);
  const expectedChainId = process.env.SHADE_TREE_CHAIN_ID || deployed.chainId || null;
  if (expectedChainId != null && expectedChainId !== "") {
    const actual = (await provider.getNetwork()).chainId;
    requireRpcChainId(actual, expectedChainId, { label: "staking RPC" });
  }
  const wallet = new ethers.Wallet(key, provider);
  const abi = [
    "function registerIdentity(uint256 identityCommitment, uint256 limit) payable returns (uint256)",
    "function bondFor(uint256 limit) view returns (uint256)",
    "function isActive(uint256 commitment) view returns (bool)",
  ];
  const contract = new ethers.Contract(address, abi, wallet);

  let tierBond;
  try { tierBond = await contract.bondFor(LIMIT); } catch {
    console.error(`contract ${address} has no bondFor(); it is not a ShadeNet staking set`);
    process.exit(1);
  }
  if (tierBond === 0n) {
    console.error(`tier ${LIMIT} is not admitted by ${address} (bondFor(${LIMIT}) == 0); enroll at an admitted tier`);
    process.exit(1);
  }
  const bond = process.env.SHADE_TREE_BOND ?? deployed.bond ?? tierBond;
  if (await contract.isActive(commitment)) {
    console.log(`member leaf ${commitment} is already staked; nothing to do.`);
    return;
  }

  console.log(`registerIdentity(${identityCommitment}, ${LIMIT})`);
  console.log(`  leaf:     ${commitment}`);
  console.log(`  contract: ${address}`);
  console.log(`  rpc:      ${rpcUrl}`);
  console.log(`  from:     ${wallet.address}`);
  console.log(`  limit:    ${LIMIT}`);
  console.log(`  bond:     ${bond} wei`);

  const tx = await contract.registerIdentity(identityCommitment, LIMIT, { value: bond });
  console.log(`  tx:       ${tx.hash}  (waiting for confirmation...)`);
  const rcpt = await waitForTransactionReceipt(tx, { operation: "member registration" });
  console.log(`  mined in block ${rcpt.blockNumber}; member staked. Public admission begins after this block reaches finality.`);
}

main().catch((e) => {
  console.error("register failed:", e.shortMessage || e.message);
  process.exit(1);
});
