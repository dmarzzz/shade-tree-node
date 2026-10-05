// scripts/deploy-contracts.mjs unit checks (fast lane, no chain): economics validation, the env
// handed to DeployRegistry.s.sol, argument parsing and the production gates. The end-to-end
// rehearsal (`--fork`) needs a Sepolia RPC and runs by hand or in the staging workflow.
//
//   node scripts/deploy-contracts.selftest.mjs

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DEPLOY_GAS, GAS_PRICE_HEADROOM, deployEnv, deployedFromBroadcast, gasGate, parseArgs, productionGate, validateEconomics } from "./deploy-contracts.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };
const copy = (v) => JSON.parse(JSON.stringify(v));
const throws = (fn) => { try { fn(); return false; } catch { return true; } };

for (const network of ["sepolia", "sepolia-staging"]) {
  const econ = JSON.parse(readFileSync(join(ROOT, "network", network, "economics.json"), "utf8"));
  ok(validateEconomics(econ, network).length === 0, `network/${network}/economics.json is valid`);
}
const econ = JSON.parse(readFileSync(join(ROOT, "network/sepolia/economics.json"), "utf8"));
const errs = (mutate) => { const e = copy(econ); mutate(e); return validateEconomics(e, "sepolia"); };
ok(errs((e) => { e.tiers = e.tiers.filter((t) => t.limit !== 8); }).some((m) => m.startsWith("tiers")), "tier 8 is required (the contract always admits it)");
ok(errs((e) => { e.defaultLimit = 2; }).some((m) => m.startsWith("defaultLimit")), "the default tier must be admitted");
const two = (e) => { e.tiers = [{ limit: 1, bondWei: "1" }, ...e.tiers.filter((t) => t.limit === 8)]; e.defaultLimit = 1; };
ok(errs(two).length === 0, "a table with a tier beside 8 is still valid");
ok(errs((e) => { two(e); e.tiers.reverse(); }).some((m) => m.startsWith("tiers")), "tiers must ascend");
ok(errs((e) => { e.tiers = [{ limit: 8, bondWei: "10000000000000000" }]; e.defaultLimit = 8; }).length === 0, "tier 8 alone is a valid table (the one tier the contract always admits)");
ok(!("sponsorSeats" in econ), "production economics carries no sponsor seat pool (decided 2026-10-05)");
ok(errs((e) => { e.tiers[0].bondWei = "0"; }).some((m) => m.startsWith("tiers[0]")), "a zero bond is rejected");
ok(errs((e) => { e.unbondingSeconds = 3719; }).some((m) => m.startsWith("unbondingSeconds")), "unbonding below F+E+C is rejected");
ok(errs((e) => { e.slash.rewardDivisor = 1; }).some((m) => m.startsWith("slash")), "a slash split that burns under half is rejected");
ok(errs((e) => { e.network = "mainnet"; }).some((m) => m.startsWith("network")), "the file must name its own network");

const env = deployEnv(econ, { gatewayRegistry: "0x94ECeD0C1c7a8793a5c901c8C1995C8E7039A868", deployOut: "/tmp/x.json", rpcUrl: "https://rpc" });
const tier8 = econ.tiers.find((t) => t.limit === 8);
const extra = econ.tiers.filter((t) => t.limit !== 8);
ok(env.SHADE_TREE_BOND_WEI === tier8.bondWei && env.SHADE_TREE_TIER_LIMITS === extra.map((t) => t.limit).join(",") && env.SHADE_TREE_TIER_BONDS_WEI === extra.map((t) => t.bondWei).join(","), "tier 8 becomes BOND; the other tiers become the extra table");
const oneTier = deployEnv({ ...copy(econ), tiers: [{ limit: 8, bondWei: "10000000000000000" }], defaultLimit: 8 }, { gatewayRegistry: "0x94ECeD0C1c7a8793a5c901c8C1995C8E7039A868", deployOut: "/tmp/x.json", rpcUrl: "https://rpc" });
ok(oneTier.SHADE_TREE_BOND_WEI === "10000000000000000" && oneTier.SHADE_TREE_TIER_LIMITS === "" && oneTier.SHADE_TREE_TIER_BONDS_WEI === "", "a one-tier table deploys with empty extra limits and bonds");
ok(env.SHADE_TREE_SLASH_REWARD_DIVISOR === "10" && env.SHADE_TREE_UNBONDING === "86400" && env.SHADE_TREE_MIN_UNBONDING === "3720", "slash split, unbonding and the F+E+C floor are passed through");
ok(env.SHADE_TREE_DEPLOY_REAL_VERIFIER === "1" && env.SHADE_TREE_DEPLOY_REGISTRY === "0" && env.SHADE_TREE_PUBLIC_STAKE_PROFILE === "1", "public profile: real verifier, registry reused");
ok(!Object.keys(env).some((k) => /KEY/.test(k)), "no key rides in the economics env");

ok(throws(() => parseArgs(["--network", "sepolia"])), "exactly one of --fork / --broadcast is required");
ok(throws(() => parseArgs(["--network", "sepolia", "--fork", "--broadcast"])), "--fork and --broadcast are exclusive");
ok(throws(() => parseArgs(["--network", "sepolia", "--fork", "--verify"])), "--verify needs --broadcast");
ok(parseArgs(["--network", "sepolia-staging", "--broadcast", "--verify"]).verify, "staging broadcast with verification parses");
ok(parseArgs(["--network", "sepolia", "--from-broadcast", "run-latest.json", "--verify"]).fromBroadcast === "run-latest.json", "recording an already-sent deploy parses, with verification");
ok(throws(() => parseArgs(["--network", "sepolia", "--broadcast", "--from-broadcast", "run-latest.json"])) && throws(() => parseArgs(["--network", "sepolia", "--from-broadcast"])), "--from-broadcast is its own mode and needs the file");

const devLock = { trust: "UNTRUSTED-TESTNET", ceremony: { status: "not-run" } };
const doneLock = { trust: "CEREMONY", ceremony: { status: "complete" } };
const finalEcon = { ...copy(econ), status: "final" };
const placeholderEcon = { ...copy(econ), status: "placeholder" };
ok(/H2/.test(productionGate({ network: "sepolia", broadcast: true }, placeholderEcon, doneLock) || ""), "production refuses placeholder economics (H2)");
ok(/H3/.test(productionGate({ network: "sepolia", broadcast: true }, finalEcon, devLock) || ""), "production refuses dev proving keys (H3)");
ok(productionGate({ network: "sepolia", broadcast: true }, finalEcon, doneLock) === null, "production proceeds with final economics and ceremony keys");
ok(productionGate({ network: "sepolia", fork: true, broadcast: false }, econ, devLock) === null, "a fork rehearsal of production is always allowed");
ok(productionGate({ network: "sepolia-staging", broadcast: true }, econ, devLock) === null, "staging deploys with placeholder economics and dev keys");

ok(/H2/.test(productionGate({ network: "sepolia", fromBroadcast: "run-latest.json" }, placeholderEcon, doneLock) || ""), "recording a production deploy passes the same gates as sending one");

// --from-broadcast: forge's broadcast file stands in for the script's own output.
const created = (name, n) => ({ transactionType: "CREATE", contractName: name, contractAddress: `0x${String(n).repeat(40)}`, hash: `0x${String(n).repeat(64)}` });
const runFile = {
  chain: 11155111,
  transactions: [created("RateCommitmentHasher", 1), created("WithdrawGroth16Verifier", 2), created("WithdrawVerifier", 3), created("StakedReputationSet", 4)],
};
runFile.receipts = runFile.transactions.map((tx) => ({ transactionHash: tx.hash, status: "0x1" }));
const fromRun = deployedFromBroadcast(runFile);
ok(fromRun.hasher === `0x${"1".repeat(40)}` && fromRun.verifier === `0x${"3".repeat(40)}` && fromRun.stakedReputationSet === `0x${"4".repeat(40)}`, "a broadcast file yields the hasher, the exit verifier (not the Groth16 one) and the set");
ok(throws(() => deployedFromBroadcast({ ...runFile, chain: 1 })), "a broadcast file from another chain is refused");
ok(throws(() => deployedFromBroadcast({ ...runFile, transactions: runFile.transactions.slice(0, 3) })), "a broadcast file that stops before the set is refused");
ok(throws(() => deployedFromBroadcast({ ...runFile, receipts: runFile.receipts.map((r, i) => (i === 3 ? { ...r, status: "0x0" } : r)) })), "a reverted creation is refused");

// The deploy of 2026-09-30: 0.007 ETH against a 2 gwei price stopped after three creations.
const GWEI = 10n ** 9n;
ok(/holds 0\.007000 ETH/.test(gasGate({ balanceWei: 7n * 10n ** 15n, gasPriceWei: 2n * GWEI }) || ""), "a deployer that cannot pay for every creation at the headroom price is refused before anything is sent");
ok(gasGate({ balanceWei: DEPLOY_GAS * GWEI * GAS_PRICE_HEADROOM, gasPriceWei: GWEI }) === null && gasGate({ balanceWei: DEPLOY_GAS * GWEI * GAS_PRICE_HEADROOM - 1n, gasPriceWei: GWEI }) !== null, "the gas gate is exactly the deploy gas at the headroom multiple of the current price");

if (failures) { console.log(`\nFAIL: ${failures} deploy-contracts check(s)`); process.exit(1); }
console.log("\nPASS: deploy-contracts selftest");
