#!/usr/bin/env node
// Deploy the ShadeNet staking contracts for one network from its economics file, read every
// value back from the chain, and write the network's deployment record. This is the one script
// the staging rehearsal (M7) and the production launch (M8) run; between them only
// network/<net>/economics.json (H2) and the ceremony's verifier (H3) change.
//
//   node scripts/deploy-contracts.mjs --network sepolia-staging --fork
//       rehearse on an anvil fork of Sepolia: deploy, read back, then run the staking smoke
//       (register -> exit -> 24 h -> withdraw -> slash) with time warped; writes nothing under network/
//   node scripts/deploy-contracts.mjs --network sepolia-staging --broadcast [--verify]
//       deploy for real; writes network/<net>/deployment.json and network/<net>/contracts-deploy.json
//   node scripts/deploy-contracts.mjs --network sepolia-staging --from-broadcast <run-latest.json> [--verify]
//       the creations are already on chain (a broadcast that stopped before the record was written):
//       send nothing, take addresses and hashes from forge's broadcast file, then read back, write
//       the record and verify exactly as --broadcast does
//
// Options:
//   --network <name>         network/<name>/economics.json is the input            (required)
//   --rpc-url <url>          Sepolia RPC (also the fork source)   (SHADE_TREE_RPC_URL, else public)
//   --gateway-registry <0x>  GatewayRegistry to record (reused, never redeployed)
//                            (default: network/sepolia/deployment.json elder.gatewayRegistry)
//   --fork | --broadcast | --from-broadcast <file>
//                            rehearse on a fork, send real transactions, or record transactions
//                            already sent (exactly one)
//   --verify                 after --broadcast or --from-broadcast: source-verify on Sourcify, and
//                            on Etherscan when ETHERSCAN_API_KEY is set
//
// The deployer key comes from SHADE_TREE_DEPLOYER_KEY (hex) or, with --key-from-sops <file>, from
// the sops-encrypted vault_shadenet_deployer_key (agent-devops secrets/shadenet/deployer.sops.yml;
// SOPS_AGE_KEY_FILE must be set). It is passed to forge through the environment, never argv.

import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { Wallet, getAddress } from "ethers";
import { validateDeploymentRecord as validateClientRecord } from "../packages/node/lib/network-record.mjs";
import { validateDeploymentRecord as preflightRecord, validatePublicStakeOnchain } from "../deploy/v4/preflight.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SEPOLIA = 11155111;
const MIN_UNBONDING = 3720; // ratePolicy root freshness 60 + epoch 60 + slash confirmation 3600
// ADR 0012: the record carries an RPC failover list. A full-history endpoint goes first (publicnode
// answered eth_getLogs / receipts with nothing during the M7 rehearsal); publicnode stays as fallback.
// Both replay the member set's eth_getLogs from a set's deploy block (checked 2026-10-06);
// publicnode intermittently answers that with "pruned history unavailable" (task 19).
const PUBLIC_RPCS = ["https://rpc.sepolia.ethpandaops.io", "https://sepolia.gateway.tenderly.co"];
const rpcList = (v) => String(v).split(",").map((s) => s.trim()).filter(Boolean);
const ANVIL_KEY_0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const fail = (message) => { console.error(`deploy-contracts: ${message}`); process.exit(1); };

export function parseArgs(argv) {
  const opts = { network: null, rpcUrls: rpcList(process.env.SHADE_TREE_RPC_URL || PUBLIC_RPCS.join(",")), gatewayRegistry: null, fork: false, broadcast: false, fromBroadcast: null, verify: false, keyFromSops: null };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const value = () => { const v = argv[++i]; if (v == null || v.startsWith("--")) throw new Error(`${arg} needs a value`); return v; };
    if (arg === "--network") opts.network = value();
    else if (arg === "--rpc-url") opts.rpcUrls = rpcList(value());
    else if (arg === "--gateway-registry") opts.gatewayRegistry = value();
    else if (arg === "--key-from-sops") opts.keyFromSops = value();
    else if (arg === "--fork") opts.fork = true;
    else if (arg === "--broadcast") opts.broadcast = true;
    else if (arg === "--from-broadcast") opts.fromBroadcast = value();
    else if (arg === "--verify") opts.verify = true;
    else throw new Error(`unknown argument ${arg}`);
  }
  if (!opts.network || !/^[a-z0-9-]+$/.test(opts.network)) throw new Error("--network <name> is required");
  if ([opts.fork, opts.broadcast, opts.fromBroadcast !== null].filter(Boolean).length !== 1) throw new Error("pass exactly one of --fork, --broadcast or --from-broadcast <file>");
  if (opts.verify && opts.fork) throw new Error("--verify only applies to --broadcast and --from-broadcast");
  return opts;
}

// ---- economics ----------------------------------------------------------------------------

export function validateEconomics(econ, network) {
  const errors = [];
  const bad = (field, problem) => errors.push(`${field}: ${problem}`);
  const isWei = (v) => typeof v === "string" && /^[1-9][0-9]*$/.test(v);
  if (econ?.schemaVersion !== 1) bad("schemaVersion", "must be 1");
  if (econ?.network !== network) bad("network", `must be "${network}"`);
  if (!["placeholder", "final"].includes(econ?.status)) bad("status", "must be placeholder or final");
  if (typeof econ?.decisionRef !== "string" || !econ.decisionRef) bad("decisionRef", "must say who set these numbers and when");
  const tiers = Array.isArray(econ?.tiers) ? econ.tiers : [];
  if (tiers.length === 0) bad("tiers", "must be a non-empty array");
  tiers.forEach((tier, i) => {
    if (!Number.isInteger(tier?.limit) || tier.limit < 1 || tier.limit > 65535) bad(`tiers[${i}].limit`, "must be 1..65535");
    if (!isWei(tier?.bondWei)) bad(`tiers[${i}].bondWei`, "must be a positive decimal wei string");
    if (i > 0 && !(tier?.limit > tiers[i - 1]?.limit)) bad("tiers", "must be strictly ascending by limit");
  });
  if (!tiers.some((tier) => tier.limit === 8)) bad("tiers", "must include limit 8 (the contract's DEFAULT_LIMIT, always admitted)");
  if (!tiers.some((tier) => tier.limit === econ?.defaultLimit)) bad("defaultLimit", "must be one of the tiers");
  if (!Number.isInteger(econ?.unbondingSeconds) || econ.unbondingSeconds < MIN_UNBONDING) bad("unbondingSeconds", `must be an integer >= ${MIN_UNBONDING} (F + E + C)`);
  const divisor = econ?.slash?.rewardDivisor;
  if (!Number.isInteger(divisor) || divisor < 2 || divisor > 1000) bad("slash.rewardDivisor", "must be an integer in 2..1000 (at least half of a slashed bond burns)");
  if (typeof econ?.sessionTickets !== "boolean") bad("sessionTickets", "must be true or false");
  return errors;
}

// The production network (network/sepolia) broadcasts only after both human gates: final
// economics (H2) and a completed trusted-setup ceremony whose keys the lock records (H3).
export function productionGate(opts, econ, lock) {
  if (opts.network !== "sepolia" || !(opts.broadcast || opts.fromBroadcast)) return null;
  if (econ.status !== "final") return "the production network deploys only from final economics (H2); status is still placeholder";
  if (lock?.ceremony?.status !== "complete" || lock?.trust === "UNTRUSTED-TESTNET") {
    return "the production network deploys only with ceremony keys (H3); testdata/zk-artifacts.lock.json still records the dev setup";
  }
  return null;
}

export function deployEnv(econ, { gatewayRegistry, deployOut, rpcUrl }) {
  const tier8 = econ.tiers.find((tier) => tier.limit === 8);
  const extra = econ.tiers.filter((tier) => tier.limit !== 8);
  return {
    SHADE_TREE_PUBLIC_STAKE_PROFILE: "1",
    SHADE_TREE_DEPLOY_STAKED: "1",
    SHADE_TREE_DEPLOY_REGISTRY: "0",
    SHADE_TREE_GATEWAY_REGISTRY: gatewayRegistry,
    SHADE_TREE_DEPLOY_REAL_VERIFIER: "1",
    SHADE_TREE_BOND_WEI: tier8.bondWei,
    SHADE_TREE_TIER_LIMITS: extra.map((tier) => tier.limit).join(","),
    SHADE_TREE_TIER_BONDS_WEI: extra.map((tier) => tier.bondWei).join(","),
    SHADE_TREE_UNBONDING: String(econ.unbondingSeconds),
    SHADE_TREE_MIN_UNBONDING: String(MIN_UNBONDING),
    SHADE_TREE_SLASH_REWARD_DIVISOR: String(econ.slash.rewardDivisor),
    SHADE_TREE_DEPLOY_OUT: deployOut,
    SHADE_TREE_RPC_URL: rpcUrl,
  };
}

// The 2026-09-30 production deploy stopped after three of four contract creations: the deployer
// held 0.007 ETH and the gas price doubled mid-run, so the set had to be finished by hand. A
// broadcast now starts only when the deployer can pay for all four creations at several times
// the current gas price.
export const DEPLOY_GAS = 5_000_000n; // the four CREATE gas limits forge sets sum to 4,853,545 (fork run, 2026-10-05)
export const GAS_PRICE_HEADROOM = 4n;
const ethString = (wei) => { const s = BigInt(wei).toString().padStart(19, "0"); return `${s.slice(0, -18)}.${s.slice(-18, -12)}`; };
export function gasGate({ balanceWei, gasPriceWei }) {
  const need = DEPLOY_GAS * BigInt(gasPriceWei) * GAS_PRICE_HEADROOM;
  if (BigInt(balanceWei) >= need) return null;
  return `the deployer holds ${ethString(balanceWei)} ETH; four contract creations need up to ${ethString(need)} ETH (${DEPLOY_GAS} gas at ${GAS_PRICE_HEADROOM}x the current gas price of ${BigInt(gasPriceWei)} wei). Fund it or wait for gas to fall: a deploy that stops part-way has to be finished by hand`;
}

// What DeployRegistry.s.sol writes to SHADE_TREE_DEPLOY_OUT, rebuilt from forge's broadcast file:
// the way back when the creations are mined but the run stopped before the record was written.
const CREATED = ["RateCommitmentHasher", "WithdrawGroth16Verifier", "WithdrawVerifier", "StakedReputationSet"];
export function deployedFromBroadcast(run) {
  if (Number(run?.chain) !== SEPOLIA) throw new Error("the broadcast file is not a Sepolia run");
  const creates = (run.transactions || []).filter((tx) => tx.transactionType === "CREATE");
  if (creates.map((tx) => tx.contractName).join(",") !== CREATED.join(",")) throw new Error(`the broadcast file must hold exactly the creations ${CREATED.join(", ")}`);
  for (const tx of creates) {
    const receipt = (run.receipts || []).find((r) => r.transactionHash === tx.hash);
    if (!receipt || BigInt(receipt.status ?? 0) !== 1n) throw new Error(`${tx.contractName} ${tx.hash} has no successful receipt in the broadcast file`);
  }
  const at = (name) => getAddress(creates.find((tx) => tx.contractName === name).contractAddress);
  return { stakedReputationSet: at("StakedReputationSet"), hasher: at("RateCommitmentHasher"), verifier: at("WithdrawVerifier") };
}

// ---- chain helpers --------------------------------------------------------------------------

async function rpc(url, method, params = []) {
  const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  const body = await res.json();
  if (body.error) throw new Error(`${method}: ${body.error.message}`);
  return body.result;
}

async function freePort() {
  return new Promise((resolve) => { const s = createServer(); s.listen(0, "127.0.0.1", () => { const { port } = s.address(); s.close(() => resolve(port)); }); });
}

async function startFork(forkUrl) {
  const port = await freePort();
  const url = `http://127.0.0.1:${port}`;
  const anvil = spawn("anvil", ["--fork-url", forkUrl, "--port", String(port), "--silent"], { stdio: "ignore" });
  for (let i = 0; i < 300; i++) {
    try { await rpc(url, "eth_chainId"); return { url, stop: () => anvil.kill() }; } catch { await new Promise((r) => setTimeout(r, 200)); }
  }
  anvil.kill();
  throw new Error("anvil fork did not come up");
}

function deployerKey(opts) {
  if (opts.fork) return ANVIL_KEY_0;
  if (opts.keyFromSops) {
    const r = spawnSync("sops", ["-d", "--extract", '["vault_shadenet_deployer_key"]', opts.keyFromSops], { encoding: "utf8" });
    if (r.status !== 0) fail("could not decrypt the deployer key (is SOPS_AGE_KEY_FILE set?)");
    return "0x" + r.stdout.trim().replace(/^0x/, "");
  }
  if (process.env.SHADE_TREE_DEPLOYER_KEY) return process.env.SHADE_TREE_DEPLOYER_KEY;
  fail("no deployer key: set SHADE_TREE_DEPLOYER_KEY or pass --key-from-sops <file>");
}

function sha256File(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

// ---- main ----------------------------------------------------------------------------------

async function main() {
  let opts;
  try { opts = parseArgs(process.argv.slice(2)); } catch (error) { fail(error.message); }
  const netDir = join(ROOT, "network", opts.network);
  const econPath = join(netDir, "economics.json");
  if (!existsSync(econPath)) fail(`${econPath} does not exist`);
  const econ = JSON.parse(readFileSync(econPath, "utf8"));
  const econErrors = validateEconomics(econ, opts.network);
  if (econErrors.length) fail(`economics.json is invalid:\n  ${econErrors.join("\n  ")}`);
  const lock = JSON.parse(readFileSync(join(ROOT, "testdata/zk-artifacts.lock.json"), "utf8"));
  const gate = productionGate(opts, econ, lock);
  if (gate) fail(gate);

  const manifest = JSON.parse(readFileSync(join(ROOT, "deploy/v4/public-stake-v1-bytecode.json"), "utf8"));
  const liveRecord = JSON.parse(readFileSync(join(ROOT, "network/sepolia/deployment.json"), "utf8"));
  const gatewayRegistry = opts.gatewayRegistry || liveRecord.elder?.gatewayRegistry;
  if (!/^0x[0-9a-fA-F]{40}$/.test(gatewayRegistry || "")) fail("no GatewayRegistry to record; pass --gateway-registry");

  const fork = opts.fork ? await startFork(opts.rpcUrls[0]) : null;
  const url = fork ? fork.url : opts.rpcUrls[0];
  try {
    const chainId = Number(BigInt(await rpc(url, "eth_chainId")));
    if (chainId !== SEPOLIA) fail(`RPC chain id ${chainId} is not Sepolia`);
    for (const [name, address] of Object.entries(manifest.libraryAddresses)) {
      const code = await rpc(url, "eth_getCode", [address, "latest"]);
      if (!code || code === "0x") fail(`pinned library ${name} is not deployed at ${address}`);
    }
    const key = opts.fromBroadcast ? null : deployerKey(opts);
    const deployer = key ? new Wallet(key).address : null;
    if (fork) await rpc(url, "anvil_setBalance", [deployer, "0x21e19e0c9bab2400000"]);
    else if (key) {
      const [balanceWei, gasPriceWei] = [BigInt(await rpc(url, "eth_getBalance", [deployer, "latest"])), BigInt(await rpc(url, "eth_gasPrice"))];
      const short = gasGate({ balanceWei, gasPriceWei });
      if (short) fail(short);
      console.log(`  deployer ${deployer} holds ${ethString(balanceWei)} ETH; gas price ${gasPriceWei} wei`);
    }

    console.log(`deploy-contracts: ${opts.network} (${econ.status} economics) on ${fork ? "an anvil fork of Sepolia" : "Sepolia"}${opts.fromBroadcast ? `, recording ${opts.fromBroadcast} (nothing is sent)` : ""}`);
    for (const tier of econ.tiers) console.log(`  tier ${tier.limit}: ${tier.bondWei} wei`);
    console.log(`  unbonding ${econ.unbondingSeconds}s, slash bounty 1/${econ.slash.rewardDivisor}, registry ${gatewayRegistry}`);

    const broadcastFile = opts.fromBroadcast || join(ROOT, "broadcast/DeployRegistry.s.sol", String(SEPOLIA), "run-latest.json");
    let deployed;
    if (opts.fromBroadcast) {
      try { deployed = deployedFromBroadcast(JSON.parse(readFileSync(broadcastFile, "utf8"))); } catch (error) { fail(`${broadcastFile}: ${error.message}`); }
    } else {
      mkdirSync(join(ROOT, "cache"), { recursive: true });
      const deployOut = join(ROOT, "cache", `deploy-${opts.network}-${Date.now()}.local.json`);
      const libs = Object.entries(manifest.libraryAddresses).flatMap(([name, address]) => ["--libraries", `contracts/${name}.sol:${name}:${address}`]);
      const forge = spawnSync("forge", ["script", "contracts/script/DeployRegistry.s.sol:DeployRegistry", "--rpc-url", url, "--broadcast", "--slow", ...libs], {
        cwd: ROOT, encoding: "utf8", timeout: 900_000,
        env: { ...process.env, ...deployEnv(econ, { gatewayRegistry, deployOut, rpcUrl: opts.rpcUrls[0] }), SHADE_TREE_DEPLOYER_KEY: key },
      });
      if (forge.status !== 0) fail(`forge script failed:\n${(forge.stdout || "").split("\n").slice(-25).join("\n")}\n${forge.stderr || ""}`);
      deployed = JSON.parse(readFileSync(deployOut, "utf8"));
      rmSync(deployOut, { force: true });
    }

    const run = JSON.parse(readFileSync(broadcastFile, "utf8"));
    const setTx = run.transactions.find((tx) => tx.contractName === "StakedReputationSet" && tx.transactionType === "CREATE");
    // A pooled public RPC can answer a fresh receipt with null; ask again, then fall back to the
    // receipt forge itself waited for, so a deployed set never ends without its record.
    let receipt = null;
    for (let attempt = 0; attempt < 4 && !receipt; attempt++) receipt = await rpc(url, "eth_getTransactionReceipt", [setTx.hash]).catch(() => null);
    receipt ??= (run.receipts || []).find((r) => r.transactionHash === setTx.hash);
    if (!receipt) fail(`no receipt for the set's creation ${setTx.hash}; the contracts are deployed, rebuild the record from broadcast/ before anything else`);

    const staked = {
      profile: "public-stake-v1",
      // ShadeNet sets take the identity commitment and derive the leaf (registerIdentity); clients
      // (@shadenet/sdk, the Get access page) switch ABI on this field.
      registerInput: "identityCommitment",
      chainId: SEPOLIA,
      contract: deployed.stakedReputationSet,
      deployTx: setTx.hash,
      rpcUrl: opts.rpcUrls[0],
      // ADR 0012: failover order for every reader of the record (nodes, both SDKs, the site).
      rpcUrls: opts.rpcUrls,
      deployBlock: Number(BigInt(receipt.blockNumber)),
      hasher: deployed.hasher,
      withdrawVerifier: deployed.verifier,
      defaultLimit: econ.defaultLimit,
      tiers: econ.tiers.map(({ limit, bondWei }) => ({ limit, bondWei })),
      unbondingSeconds: econ.unbondingSeconds,
      minUnbondingSeconds: MIN_UNBONDING,
      slashRewardDivisor: econ.slash.rewardDivisor,
    };
    const commit = spawnSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).stdout.trim();
    const record = withEconomicsFlags(buildRecord(opts.network, netDir, liveRecord, staked, gatewayRegistry, commit), econ);

    const shape = [...validateClientRecord(record).errors, ...preflightRecord(record, { requireLive: false }).errors];
    if (shape.length) fail(`record is invalid: ${JSON.stringify(shape)}`);
    // A pooled public RPC can serve state from before the creations for a few seconds (the
    // 2026-10-05 production deploy read "no deployed bytecode" one block after the set was mined).
    let onchain;
    for (let attempt = 0; ; attempt++) {
      onchain = await validatePublicStakeOnchain(record, { rpcUrl: url, bytecodeManifest: manifest });
      if (onchain.ok || fork || attempt >= 5) break;
      await new Promise((resolve) => setTimeout(resolve, 6000));
    }
    if (!onchain.ok) {
      // run-latest.json is replaced by the next forge run (a --fork rehearsal included); name the stamped copy.
      const stampedPath = join(dirname(broadcastFile), `run-${run.timestamp}.json`);
      const stamped = !opts.fromBroadcast && existsSync(stampedPath) ? stampedPath : broadcastFile;
      fail(`read-back failed: ${JSON.stringify(onchain.errors)}${fork ? "" : `\n  The creations are on chain and no record was written. Do not deploy again: rerun with --from-broadcast ${relative(ROOT, stamped)} in place of --broadcast.`}`);
    }
    console.log(`  read back OK: ${staked.contract} (block ${staked.deployBlock}), bytecode matches the pinned manifest`);

    const audit = {
      network: opts.network,
      deployedAt: new Date(opts.fromBroadcast && Number.isFinite(run.timestamp) ? run.timestamp : Date.now()).toISOString(),
      commit,
      economicsSha256: sha256File(econPath),
      economicsStatus: econ.status,
      artifactsLockSha256: sha256File(join(ROOT, "testdata/zk-artifacts.lock.json")),
      artifactsTrust: lock.trust ?? null,
      ceremonyStatus: lock.ceremony?.status ?? null,
      deployer: run.transactions[0]?.transaction?.from ?? null,
      transactions: run.transactions.filter((tx) => tx.transactionType === "CREATE").map((tx) => ({ contract: tx.contractName, address: tx.contractAddress, hash: tx.hash })),
      ...(opts.fromBroadcast ? { note: "recorded with --from-broadcast: the creations were already on chain (the --broadcast run stopped before the record was written) and this run sent nothing" } : {}),
    };

    if (fork) {
      console.log("  fork rehearsal: running the staking smoke (register -> exit -> 24 h -> withdraw -> slash)");
      const smoke = spawnSync(process.execPath, [join(ROOT, "scripts/smoke-staking.mjs"), "--rpc-url", url, "--contract", staked.contract, "--warp", "--key", ANVIL_KEY_0], { cwd: ROOT, encoding: "utf8", stdio: "inherit", timeout: 900_000 });
      if (smoke.status !== 0) fail("staking smoke failed on the fork");
      console.log("deploy-contracts: fork rehearsal passed; nothing written under network/");
      return;
    }

    mkdirSync(netDir, { recursive: true });
    writeFileSync(join(netDir, "deployment.json"), JSON.stringify(record, null, 2) + "\n");
    writeFileSync(join(netDir, "contracts-deploy.json"), JSON.stringify(audit, null, 2) + "\n");
    console.log(`  wrote network/${opts.network}/deployment.json and contracts-deploy.json`);
    if (opts.verify) await verifySources(audit, staked, econ, manifest);
  } finally {
    fork?.stop();
  }
}

export function buildRecord(network, netDir, liveRecord, staked, gatewayRegistry, commit) {
  const existing = existsSync(join(netDir, "deployment.json")) ? JSON.parse(readFileSync(join(netDir, "deployment.json"), "utf8")) : null;
  const base = existing ?? {
    schemaVersion: 1,
    network,
    status: "pending",
    protocol: liveRecord.protocol,
    ratePolicy: liveRecord.ratePolicy,
    security: { ...liveRecord.security, decisionRef: `${network}: ShadeNet staging rehearsal contracts (M1)` },
    // The canopy for this network pins its own service commits when ops brings it up (M4);
    // until then the record names the commit whose contracts were deployed. `version` is the
    // release the fleet runs (package.json, lockstep with the crates); `shadenet doctor`
    // compares versions, not commits, so a tagged release is clean against its own record.
    services: Object.fromEntries(["elder", "node", "heartbeat"].map((name) => [name, { repository: liveRecord.services.elder.repository, commit, version: JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version }])),
    elder: { onion: null, canopySigner: null, admission: "stake", gatewayRegistry },
    admission: {
      defaultPath: "staked",
      paths: ["staked"],
      roots: { invited: null, staked: null, paid: null },
      operatorAuthorization: { approved: true, decisionRef: `${network}: Dan authorized the ShadeNet staging rehearsal deploy, 2026-09-28` },
    },
    artifacts: liveRecord.artifacts,
    created: new Date().toISOString().slice(0, 10),
    note: `${network}: ShadeNet contracts deployed by scripts/deploy-contracts.mjs from network/${network}/economics.json. No canopy is recorded yet.`,
  };
  return { ...base, admission: { ...base.admission, roots: { ...base.admission.roots, staked } } };
}

// H2's session-ticket switch (ADR 0011) rides in the record next to the economics it belongs to:
// the node role, the heartbeat and both SDKs read `sessionTickets` from here.
export function withEconomicsFlags(record, econ) {
  return { ...record, sessionTickets: econ.sessionTickets === true };
}

async function verifySources(audit, staked, econ, manifest) {
  const libs = Object.entries(manifest.libraryAddresses).flatMap(([name, address]) => ["--libraries", `contracts/${name}.sol:${name}:${address}`]);
  const tier8 = econ.tiers.find((tier) => tier.limit === 8);
  const extra = econ.tiers.filter((tier) => tier.limit !== 8);
  const byName = Object.fromEntries(audit.transactions.map((tx) => [tx.contract, tx.address]));
  const txByAddress = Object.fromEntries(audit.transactions.map((tx) => [tx.address.toLowerCase(), tx.hash]));
  const encode = (types, values) => spawnSync("cast", ["abi-encode", `f(${types})`, ...values], { encoding: "utf8" }).stdout.trim();
  const targets = [
    ["RateCommitmentHasher", byName.RateCommitmentHasher, null],
    ["WithdrawGroth16Verifier", byName.WithdrawGroth16Verifier, null],
    ["WithdrawVerifier", byName.WithdrawVerifier, encode("address", [byName.WithdrawGroth16Verifier])],
    ["StakedReputationSet", staked.contract, encode("uint256,uint256,uint256,address,address,uint256[],uint256[],uint256", [
      tier8.bondWei, String(econ.unbondingSeconds), String(MIN_UNBONDING), staked.withdrawVerifier, staked.hasher,
      `[${extra.map((tier) => tier.limit).join(",")}]`, `[${extra.map((tier) => tier.bondWei).join(",")}]`, String(econ.slash.rewardDivisor),
    ])],
  ];
  const verifiers = [["sourcify", []]];
  if (process.env.ETHERSCAN_API_KEY) verifiers.push(["etherscan", ["--etherscan-api-key", process.env.ETHERSCAN_API_KEY]]);
  else console.log("  ETHERSCAN_API_KEY unset: Etherscan verification skipped (Sourcify only)");
  for (const [verifier, extraArgs] of verifiers) {
    for (const [name, address, args] of targets) {
      if (verifier === "sourcify") {
        const result = await verifyOnSourcify(name, address, txByAddress[address.toLowerCase()], libs).catch((error) => `FAILED\n${error.message}`);
        console.log(`  sourcify ${name} ${address}: ${result}`);
        continue;
      }
      const r = spawnSync("forge", ["verify-contract", address, `contracts/${name}.sol:${name}`, "--chain", "sepolia", "--verifier", verifier, "--watch", ...libs, ...(args ? ["--constructor-args", args] : []), ...extraArgs], { cwd: ROOT, encoding: "utf8", timeout: 600_000 });
      console.log(`  ${verifier} ${name} ${address}: ${r.status === 0 ? "verified" : "FAILED\n" + (r.stdout || "") + (r.stderr || "")}`);
    }
  }
}

// Sourcify retired the v1 /verify endpoint that `forge verify-contract --verifier sourcify` (1.3.x)
// posts to, so submit forge's standard JSON input to the v2 API and poll the job. Sourcify reads the
// constructor arguments from the creation transaction.
const SOURCIFY = "https://sourcify.dev/server";
export async function verifyOnSourcify(name, address, creationTransactionHash, libs) {
  const input = spawnSync("forge", ["verify-contract", address, `contracts/${name}.sol:${name}`, "--chain", "sepolia", ...libs, "--show-standard-json-input"], { cwd: ROOT, encoding: "utf8", maxBuffer: 64 << 20 });
  if (input.status !== 0) throw new Error(input.stderr || "forge --show-standard-json-input failed");
  const artifact = JSON.parse(readFileSync(join(ROOT, "out", `${name}.sol`, `${name}.json`), "utf8"));
  const response = await fetch(`${SOURCIFY}/v2/verify/${SEPOLIA}/${address}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      stdJsonInput: JSON.parse(input.stdout),
      compilerVersion: artifact.metadata.compiler.version,
      contractIdentifier: `contracts/${name}.sol:${name}`,
      ...(creationTransactionHash ? { creationTransactionHash } : {}),
    }),
  });
  const submitted = await response.json();
  if (response.status === 409) return "verified (already on Sourcify)";
  if (!response.ok) throw new Error(`${response.status} ${submitted.message || JSON.stringify(submitted)}`);
  for (let attempt = 0; attempt < 60; attempt++) {
    await new Promise((resolve) => setTimeout(resolve, 5000));
    const job = await (await fetch(`${SOURCIFY}/v2/verify/${submitted.verificationId}`)).json();
    if (!job.isJobCompleted) continue;
    if (job.error) throw new Error(job.error.message || JSON.stringify(job.error));
    return `verified (${job.contract.creationMatch || job.contract.runtimeMatch})`;
  }
  throw new Error(`Sourcify job ${submitted.verificationId} did not finish in 5 minutes`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => fail(error.stack || error.message));
}
