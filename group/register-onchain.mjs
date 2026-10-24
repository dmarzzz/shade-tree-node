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
// With no SHADE_TREE_REGISTER_KEY on a remote RPC, the command pays from a funding wallet of its
// own, the way zkAPI's client and the Rust `shadenet register-member` do: it creates an
// owner-only key at --funding-key (SHADE_TREE_FUNDING_KEY; default
// $XDG_CONFIG_HOME/shade-tree/funding.key, i.e. ~/.config/shade-tree/funding.key, so the same
// wallet is found from any directory) once, prints the
// wallet's address and the amount to send (the tier's bond plus a gas reserve), waits for the
// balance to cover it (--wait-timeout seconds, default 3600; 0 quotes once and exits 4 if
// unfunded), then stakes. The same command resumes after Ctrl-C; the key file is reused.
//
// Usage:
//   node group/register-onchain.mjs <identity-commitment> [--limit N] [--funding-key <path>] [--wait-timeout <s>]
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
//   SHADE_TREE_FUNDING_KEY    funding wallet key file   (default: ~/.config/shade-tree/funding.key; == --funding-key)
//   SHADE_TREE_FUNDING_POLL_MS balance poll interval    (default: 15000)
//
// NB: needs the `ethers` dependency (see final report). Imported lazily so this
// file still parses without it.

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { poseidon2 } from "poseidon-lite";
import { normLimit, K_SLOTS, FIELD } from "../packages/node/lib/rln.mjs";
import { parseContractList } from "../packages/node/lib/root-provider.mjs";
import { isLoopbackRpcUrl, makeBoundedJsonRpcProvider, requireRpcChainId, waitForTransactionReceipt } from "../packages/node/lib/rpc-safety.mjs";
import {
  DEFAULT_FUNDING_POLL_MS,
  DEFAULT_WAIT_TIMEOUT_SECS,
  EXIT_NOT_FUNDED,
  FUNDING_PRIVACY,
  REGISTER_GAS_CEILING,
  chainLabel,
  defaultFundingKeyPath,
  formatEth,
  loadOrCreateFundingWallet,
  quoteFunding,
  waitForFunding,
} from "../packages/node/lib/funding-wallet.mjs";

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
function takeFlag(name, fallback) {
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === name) { const v = argv[i + 1]; argv.splice(i, 2); return v; }
    if (argv[i].startsWith(`${name}=`)) { const v = argv[i].slice(name.length + 1); argv.splice(i, 1); return v; }
  }
  return fallback;
}
const LIMIT = normLimit((() => { const v = takeFlag("--limit", process.env.SHADE_TREE_LIMIT || null); return v == null || v === "" ? K_SLOTS : v; })()); // throws on a bad tier
const FUNDING_KEY_PATH = (() => {
  const raw = takeFlag("--funding-key", null);
  if (raw === undefined || raw === "" || (raw != null && raw.startsWith("--"))) { console.error("--funding-key needs a path"); process.exit(2); }
  return raw ?? process.env.SHADE_TREE_FUNDING_KEY ?? defaultFundingKeyPath();
})();
const WAIT_TIMEOUT_SECS = (() => {
  const raw = takeFlag("--wait-timeout", null);
  if (raw == null) return DEFAULT_WAIT_TIMEOUT_SECS;
  if (!/^\d+$/.test(raw)) { console.error("--wait-timeout must be a number of seconds"); process.exit(2); }
  return Number(raw);
})();
const FUNDING_POLL_MS = Number(process.env.SHADE_TREE_FUNDING_POLL_MS) > 0 ? Number(process.env.SHADE_TREE_FUNDING_POLL_MS) : DEFAULT_FUNDING_POLL_MS;

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
  // An explicit key, the public Anvil key on a loopback RPC, or (remote, no key) the funding wallet.
  let key = process.env.SHADE_TREE_REGISTER_KEY || (isLoopbackRpcUrl(rpcUrl) ? ANVIL_KEY_0 : null);
  let funding = null;
  if (!key) {
    funding = loadOrCreateFundingWallet(FUNDING_KEY_PATH);
    key = funding.key;
  }
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

  if (funding) {
    const staked = await fundFromOwnWallet({ provider, contract, wallet, funding, commitment });
    if (staked) return;
  }

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
  if (funding) {
    // What is left is the unspent gas reserve; it is tied to the stake on chain.
    const left = await provider.getBalance(wallet.address).catch(() => 0n);
    if (left > 0n) {
      const chainId = Number((await provider.getNetwork()).chainId);
      console.log(`  leftover: ${formatEth(left, chainId)} stays in ${FUNDING_KEY_PATH} (the unspent gas reserve).`);
      console.log("            It is tied to this stake on chain: keep it for a later top-up, or send it to a");
      console.log("            fresh address, not back to the wallet that funded it.");
    }
  }
}

// The funding path: quote bond + gas reserve for the funding wallet, print the address and the
// amount, poll the balance until it covers the quote or the deadline passes. Returns true when the
// leaf turned out to be staked already (nothing to do).
async function fundFromOwnWallet({ provider, contract, wallet, funding, commitment }) {
  const chainId = Number((await provider.getNetwork()).chainId);
  const getQuote = async () => {
    if (await contract.isActive(commitment)) return null;
    const bond = await contract.bondFor(LIMIT);
    if (bond === 0n) throw new Error(`tier ${LIMIT} is not admitted (bondFor(${LIMIT}) == 0)`);
    const fees = await provider.getFeeData();
    const gasPrice = fees.gasPrice ?? 0n;
    const maxFee = fees.maxFeePerGas != null && fees.maxFeePerGas > gasPrice ? fees.maxFeePerGas : gasPrice;
    const balance = await provider.getBalance(wallet.address);
    return quoteFunding({ bond, maxFeePerGas: maxFee, balance, chainId });
  };
  const eth = (wei) => formatEth(wei, chainId);
  const report = (event) => {
    const q = event.quote;
    switch (event.kind) {
      case "quote":
        console.log("No funded key was given (SHADE_TREE_REGISTER_KEY), so this machine's funding wallet pays:");
        console.log(`  wallet:   ${FUNDING_KEY_PATH}  (${funding.created ? "created now" : "existing"}; owner-only; keep it, it holds the gas money)`);
        console.log(`  address:  ${wallet.address}`);
        console.log(`  bond:     ${eth(q.bond)} (tier ${LIMIT})`);
        console.log(`  gas:      up to ${eth(q.gasReserve)} reserved (${REGISTER_GAS_CEILING} gas at the current fee, rounded up to a 0.002 ETH x 2^k step)`);
        console.log(`  balance:  ${eth(q.balance)}`);
        break;
      case "progress":
        console.log(`\nSend ${eth(event.send)} to ${wallet.address} (${chainLabel(chainId)}).`);
        if (event.first) {
          console.log(FUNDING_PRIVACY);
          if (WAIT_TIMEOUT_SECS === 0) console.log("Not waiting (--wait-timeout 0); run the same command again once it has arrived.");
          else console.log(`Waiting for it: checking every ${Math.max(1, Math.round(FUNDING_POLL_MS / 1000))} s, for up to ${WAIT_TIMEOUT_SECS} s. Ctrl-C stops; the same command resumes.`);
        } else {
          console.log(`  balance ${eth(q.balance)}, ${eth(q.shortfall)} still needed`);
        }
        break;
      case "rpc-error":
        console.error(`  rpc: ${event.error.shortMessage || event.error.message}; checking again in ${Math.max(1, Math.round(event.pollMs / 1000))} s`);
        break;
      case "funded":
        console.log(`funded: ${eth(q.balance)} covers the bond and gas reserve; staking.`);
        break;
      default:
        break;
    }
  };
  let quote;
  try {
    quote = await waitForFunding({ getQuote, timeoutMs: WAIT_TIMEOUT_SECS * 1000, pollMs: FUNDING_POLL_MS, report });
  } catch (e) {
    if (e.code === EXIT_NOT_FUNDED) {
      console.error(`register-member: funding wallet ${wallet.address} ${e.message.replace(/^funding wallet /, "")}`);
      process.exit(EXIT_NOT_FUNDED);
    }
    throw e;
  }
  if (quote === null) {
    console.log(`member leaf ${commitment} is already staked; nothing to do.`);
    return true;
  }
  return false;
}

main().catch((e) => {
  console.error("register failed:", e.shortMessage || e.message);
  process.exit(1);
});
