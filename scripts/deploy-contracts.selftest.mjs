// scripts/deploy-contracts.mjs unit checks (fast lane, no chain): economics validation, the env
// handed to DeployRegistry.s.sol, argument parsing and the production gates. The end-to-end
// rehearsal (`--fork`) needs a Sepolia RPC and runs by hand or in the staging workflow.
//
//   node scripts/deploy-contracts.selftest.mjs

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { deployEnv, parseArgs, productionGate, validateEconomics } from "./deploy-contracts.mjs";

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
ok(errs((e) => { e.tiers.reverse(); }).some((m) => m.startsWith("tiers")), "tiers must ascend");
ok(errs((e) => { e.tiers[0].bondWei = "0"; }).some((m) => m.startsWith("tiers[0]")), "a zero bond is rejected");
ok(errs((e) => { e.unbondingSeconds = 3719; }).some((m) => m.startsWith("unbondingSeconds")), "unbonding below F+E+C is rejected");
ok(errs((e) => { e.slash.rewardDivisor = 1; }).some((m) => m.startsWith("slash")), "a slash split that burns under half is rejected");
ok(errs((e) => { e.network = "mainnet"; }).some((m) => m.startsWith("network")), "the file must name its own network");

const env = deployEnv(econ, { gatewayRegistry: "0x94ECeD0C1c7a8793a5c901c8C1995C8E7039A868", deployOut: "/tmp/x.json", rpcUrl: "https://rpc" });
ok(env.SHADE_TREE_BOND_WEI === "800000000000000000" && env.SHADE_TREE_TIER_LIMITS === "1" && env.SHADE_TREE_TIER_BONDS_WEI === "100000000000000000", "tier 8 becomes BOND; the other tiers become the extra table");
ok(env.SHADE_TREE_SLASH_REWARD_DIVISOR === "10" && env.SHADE_TREE_UNBONDING === "86400" && env.SHADE_TREE_MIN_UNBONDING === "3720", "slash split, unbonding and the F+E+C floor are passed through");
ok(env.SHADE_TREE_DEPLOY_REAL_VERIFIER === "1" && env.SHADE_TREE_DEPLOY_REGISTRY === "0" && env.SHADE_TREE_PUBLIC_STAKE_PROFILE === "1", "public profile: real verifier, registry reused");
ok(!Object.keys(env).some((k) => /KEY/.test(k)), "no key rides in the economics env");

ok(throws(() => parseArgs(["--network", "sepolia"])), "exactly one of --fork / --broadcast is required");
ok(throws(() => parseArgs(["--network", "sepolia", "--fork", "--broadcast"])), "--fork and --broadcast are exclusive");
ok(throws(() => parseArgs(["--network", "sepolia", "--fork", "--verify"])), "--verify needs --broadcast");
ok(parseArgs(["--network", "sepolia-staging", "--broadcast", "--verify"]).verify, "staging broadcast with verification parses");

const devLock = { trust: "UNTRUSTED-TESTNET", ceremony: { status: "not-run" } };
const doneLock = { trust: "CEREMONY", ceremony: { status: "complete" } };
const finalEcon = { ...copy(econ), status: "final" };
ok(/H2/.test(productionGate({ network: "sepolia", broadcast: true }, econ, doneLock) || ""), "production refuses placeholder economics (H2)");
ok(/H3/.test(productionGate({ network: "sepolia", broadcast: true }, finalEcon, devLock) || ""), "production refuses dev proving keys (H3)");
ok(productionGate({ network: "sepolia", broadcast: true }, finalEcon, doneLock) === null, "production proceeds with final economics and ceremony keys");
ok(productionGate({ network: "sepolia", fork: true, broadcast: false }, econ, devLock) === null, "a fork rehearsal of production is always allowed");
ok(productionGate({ network: "sepolia-staging", broadcast: true }, econ, devLock) === null, "staging deploys with placeholder economics and dev keys");

if (failures) { console.log(`\nFAIL: ${failures} deploy-contracts check(s)`); process.exit(1); }
console.log("\nPASS: deploy-contracts selftest");
