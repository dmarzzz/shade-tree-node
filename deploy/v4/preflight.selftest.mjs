// Pure/controller-side tests for the Protocol v4 deployment record gate.

import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { artifactIdOf } from "../../packages/node/lib/zk-artifacts.mjs";
import { loadDeploymentRecord, validateDeploymentRecord, validatePinnedCheckout, validatePublicStakeOnchain } from "./preflight.mjs";
import { AbiCoder, Interface } from "ethers";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const SCRIPT = join(HERE, "preflight.mjs");
const EXAMPLE = join(HERE, "deployment.example.json");
const VKEY_REL = "circuits/rln/verification_key.json";
const vkey = readFileSync(join(ROOT, VKEY_REL));
const ARTIFACT_ID = artifactIdOf("rln", vkey);
const ARTIFACT_SHA = createHash("sha256").update(vkey).digest("hex");
const ONION = "kssrk54kb5kngr4jjdzjouecwjh5ayzbzhamwmvju4kz63vno7hy4uyd.onion";
const SIGNER = "11".repeat(32);
const COMMIT = spawnSync("git", ["-C", ROOT, "rev-parse", "HEAD"], { encoding: "utf8" }).stdout.trim();
const REPO = "https://github.com/example/shade-tree-node";
const CONTRACT = "0x" + "22".repeat(20);

let failures = 0;
const ok = (condition, message) => {
  if (condition) console.log(`  ok   ${message}`);
  else { console.log(`  FAIL ${message}`); failures++; }
};
const copy = (value) => JSON.parse(JSON.stringify(value));
const fields = (result) => result.errors.map((error) => error.field);

function liveRecord() {
  const service = { repository: REPO, commit: COMMIT };
  return {
    schemaVersion: 1,
    network: "research-v4",
    status: "live",
    protocol: { min: 4, max: 4 },
    security: { proofArtifacts: "untrusted-testnet", scope: "disposable-research", decisionRef: "fixture-only" },
    services: { elder: { ...service }, node: { ...service }, heartbeat: { ...service } },
    elder: { onion: ONION, canopySigner: SIGNER, admission: "open", gatewayRegistry: null },
    admission: {
      defaultPath: "invited",
      paths: ["invited"],
      roots: { invited: { membersSha256: "33".repeat(32) }, staked: null, paid: null },
      operatorAuthorization: null,
    },
    artifacts: {
      accepted: [{ id: ARTIFACT_ID, verificationKeyPath: VKEY_REL, sha256: ARTIFACT_SHA }],
      legacy: ARTIFACT_ID,
    },
    created: "2026-08-25",
    note: "fixture",
  };
}

console.log("live record:");
const live = liveRecord();
ok(validateDeploymentRecord(live, { repoRoot: ROOT }).ok, "complete invited-only v4 record is deployable");
ok(!validateDeploymentRecord(live).ok && fields(validateDeploymentRecord(live)).includes("artifacts"), "live preflight requires a repository root for byte verification");
ok(validatePinnedCheckout(live, { repoRoot: ROOT }).ok, "runtime files and artifact bytes exist at the immutable service commit");

console.log("pending template:");
const pending = loadDeploymentRecord(EXAMPLE);
ok(validateDeploymentRecord(pending, { requireLive: false, repoRoot: ROOT }).ok, "null placeholder template is structurally valid in review mode");
const pendingDeploy = validateDeploymentRecord(pending, { repoRoot: ROOT });
ok(!pendingDeploy.ok && fields(pendingDeploy).includes("status") && fields(pendingDeploy).includes("elder.onion") && fields(pendingDeploy).includes("artifacts.accepted"), "pending template fails closed as a deployment input");

console.log("identity and protocol pins:");
for (const [label, mutate, field] of [
  ["pre-v4 protocol", (r) => { r.protocol = { min: 3, max: 4 }; }, "protocol"],
  ["bad Elder onion", (r) => { r.elder.onion = "203.0.113.1"; }, "elder.onion"],
  ["bad signer", (r) => { r.elder.canopySigner = "abcd"; }, "elder.canopySigner"],
  ["floating ref", (r) => { r.services.node.commit = "main"; }, "services.node.commit"],
  ["credentialed repo", (r) => { r.services.node.repository = "https://token@example.com/repo"; }, "services.node.repository"],
]) {
  const rec = copy(live); mutate(rec);
  ok(!validateDeploymentRecord(rec, { repoRoot: ROOT }).ok && fields(validateDeploymentRecord(rec, { repoRoot: ROOT })).includes(field), `${label} is rejected`);
}
const drift = copy(live); drift.services.heartbeat.commit = "cd".repeat(20);
ok(fields(validateDeploymentRecord(drift, { repoRoot: ROOT })).includes("services"), "single-checkout deploy refuses per-service commit drift");
const unsafeProduction = copy(live); unsafeProduction.security.scope = "production";
ok(fields(validateDeploymentRecord(unsafeProduction, { repoRoot: ROOT })).includes("security"), "untrusted proof artifacts cannot be labeled production");
const falseTrust = copy(live); falseTrust.security = { proofArtifacts: "trusted-ceremony", scope: "production", decisionRef: "not-real" };
ok(fields(validateDeploymentRecord(falseTrust, { repoRoot: ROOT })).includes("security.proofArtifacts"), "production trust claim must match a completed trusted ceremony in the artifact lock");

console.log("admission fail-closed rules:");
const staked = copy(live);
staked.admission.paths = ["invited", "staked"];
staked.admission.roots.staked = { contract: CONTRACT, rpcUrl: "https://rpc.example.test", deployBlock: 42 };
staked.admission.operatorAuthorization = { approved: true, decisionRef: "operator-change-42" };
staked.ratePolicy = { scope: "grove-v4", window: "fixed", epochSeconds: 120, previousEpochsAccepted: 1, rootFreshnessSeconds: 120, payloadBytesPerSlot: 41943040, slashConfirmationSeconds: 3600 };
ok(validateDeploymentRecord(staked, { repoRoot: ROOT }).ok, "staked admission needs a contract root and explicit operator authorization reference");
const publicStake = copy(staked);
publicStake.network = "sepolia";
publicStake.admission.defaultPath = "staked";
publicStake.ratePolicy = { ...staked.ratePolicy, epochSeconds: 60, rootFreshnessSeconds: 60, crossGateway: "best-effort-fleet-tally" };
publicStake.admission.roots.staked = {
  ...staked.admission.roots.staked,
  profile: "public-stake-v1",
  chainId: 11155111,
  deployTx: "0x" + "44".repeat(32),
  hasher: CONTRACT,
  withdrawVerifier: CONTRACT,
  defaultLimit: 1,
  tiers: [
    { limit: 1, bondWei: "100000000000000000" },
    { limit: 8, bondWei: "800000000000000000" },
  ],
  unbondingSeconds: 86400,
  minUnbondingSeconds: 3720,
};
ok(validateDeploymentRecord(publicStake, { repoRoot: ROOT }).ok, "public-stake-v1 exact Sepolia economics and safety window pass");
ok(fields(validateDeploymentRecord(staked, { repoRoot: ROOT, requireStakeProfile: "public-stake-v1" })).includes("admission.roots.staked.profile"), "a rollout-required public profile cannot be bypassed by an absent marker");
const publicIface = new Interface([
  "function BOND() view returns (uint256)", "function UNBONDING() view returns (uint256)",
  "function bondFor(uint256) view returns (uint256)", "function allowedLimits() view returns (uint256[])",
  "function hasher() view returns (address)", "function withdrawVerifier() view returns (address)",
  "function groth16() view returns (address)", "function SLASH_REWARD_DIVISOR() view returns (uint256)",
]);
const publicConstructor = AbiCoder.defaultAbiCoder().encode(
  ["uint256", "uint256", "uint256", "address", "address", "uint256[]", "uint256[]", "uint256"],
  [800_000_000_000_000_000n, 86_400n, 3_720n, CONTRACT, CONTRACT, [1n], [100_000_000_000_000_000n], 10n],
);
const syntheticRuntime = "0x73" + CONTRACT.slice(2) + "00";
const syntheticRuntimeSpec = {
  runtimeBytes: 22,
  normalizedSha256: "04e68fb0a3de2c1165a3333264659a15b4ccf7bf2be2e0747172124bc62293f4",
  zeroRanges: [{ start: 1, length: 20 }],
  links: { PoseidonT2: [{ start: 1, length: 20 }], PoseidonT3: [{ start: 1, length: 20 }] },
};
const syntheticLibrarySpec = { ...syntheticRuntimeSpec };
delete syntheticLibrarySpec.links;
const publicBytecodeManifest = {
  schemaVersion: 1,
  profile: "public-stake-v1",
  contracts: {
    staking: syntheticRuntimeSpec,
    hasher: syntheticRuntimeSpec,
    withdrawVerifier: syntheticRuntimeSpec,
    groth16: syntheticRuntimeSpec,
  },
  libraries: { PoseidonT2: syntheticLibrarySpec, PoseidonT3: syntheticLibrarySpec },
};
const publicRpc = async (_url, method, params) => {
  if (method === "eth_chainId") return "0xaa36a7";
  if (method === "eth_getTransactionReceipt") return { status: "0x1", blockNumber: "0x2a", contractAddress: CONTRACT };
  if (method === "eth_getCode") return syntheticRuntime;
  if (method === "eth_getTransactionByHash") return { to: null, input: "0x6000" + publicConstructor.slice(2) };
  if (method === "eth_call") {
    const selector = params[0].data.slice(0, 10);
    for (const name of ["BOND", "UNBONDING", "bondFor", "allowedLimits", "hasher", "withdrawVerifier", "groth16", "SLASH_REWARD_DIVISOR"]) {
      if (publicIface.getFunction(name).selector !== selector) continue;
      if (name === "SLASH_REWARD_DIVISOR") return publicIface.encodeFunctionResult(name, [10n]);
      if (name === "BOND") return publicIface.encodeFunctionResult(name, [800_000_000_000_000_000n]);
      if (name === "UNBONDING") return publicIface.encodeFunctionResult(name, [86_400n]);
      if (name === "allowedLimits") return publicIface.encodeFunctionResult(name, [[1n, 8n]]);
      if (name === "hasher" || name === "withdrawVerifier" || name === "groth16") return publicIface.encodeFunctionResult(name, [CONTRACT]);
      const [limit] = publicIface.decodeFunctionData(name, params[0].data);
      return publicIface.encodeFunctionResult(name, [limit === 1n ? 100_000_000_000_000_000n : 800_000_000_000_000_000n]);
    }
  }
  throw new Error(`unexpected ${method}`);
};
ok((await validatePublicStakeOnchain(publicStake, { rpcCall: publicRpc, bytecodeManifest: publicBytecodeManifest })).ok, "public profile receipt, pinned runtime bytecode, constructor, and getters match the record");
let actualRuntimeRpc = null;
const runtimeRpc = async (url, method, params) => { actualRuntimeRpc = url; return publicRpc(url, method, params); };
{
  // ADR 0012: a fallback endpoint with pruned history (null receipt, null tx) passes the
  // state-only check, and the primary still fails closed on the same answers.
  const pruned = async (url, method, params) => (method === "eth_getTransactionReceipt" || method === "eth_getTransactionByHash") ? null : runtimeRpc(url, method, params);
  const fallback = await validatePublicStakeOnchain(publicStake, { rpcCall: pruned, rpcUrl: "https://fallback.example.test", bytecodeManifest: publicBytecodeManifest, history: false });
  ok(fallback.ok, `a fallback endpoint with pruned deploy history passes the state-only check (${fallback.errors.map((e) => e.field).join(",") || "no errors"})`);
  const primary = await validatePublicStakeOnchain(publicStake, { rpcCall: pruned, rpcUrl: "https://primary.example.test", bytecodeManifest: publicBytecodeManifest });
  ok(!primary.ok && primary.errors.some((e) => e.field === "onchain.deployTx"), "the primary endpoint still fails closed on a missing receipt");
}
ok((await validatePublicStakeOnchain(publicStake, { rpcCall: runtimeRpc, rpcUrl: "https://runtime-rpc.example.test", bytecodeManifest: publicBytecodeManifest })).ok && actualRuntimeRpc === "https://runtime-rpc.example.test",
  "rollout can preflight the exact operator runtime RPC instead of only the public record RPC");
const wrongChainRpc = async (url, method, params) => method === "eth_chainId" ? "0x1" : publicRpc(url, method, params);
ok((await validatePublicStakeOnchain(publicStake, { rpcCall: wrongChainRpc, bytecodeManifest: publicBytecodeManifest })).errors.some((error) => error.field === "onchain.chainId"), "public on-chain gate rejects a non-Sepolia RPC");
const wrongBondRpc = async (url, method, params) => method === "eth_call" && params[0].data.startsWith(publicIface.getFunction("bondFor").selector)
  ? publicIface.encodeFunctionResult("bondFor", [1n])
  : publicRpc(url, method, params);
ok((await validatePublicStakeOnchain(publicStake, { rpcCall: wrongBondRpc, bytecodeManifest: publicBytecodeManifest })).errors.some((error) => error.field.startsWith("onchain.bondFor")), "public on-chain gate rejects a drifted tier bond");
const wrongCodeRpc = async (url, method, params) => method === "eth_getCode" && params[0].toLowerCase() === publicStake.admission.roots.staked.contract.toLowerCase()
  ? "0x6001"
  : publicRpc(url, method, params);
ok((await validatePublicStakeOnchain(publicStake, { rpcCall: wrongCodeRpc, bytecodeManifest: publicBytecodeManifest })).errors.some((error) => error.field === "onchain.bytecode.staking"), "public on-chain gate rejects look-alike staking runtime bytecode");
// Economics are config (economics.json); the record must keep their shape, and the on-chain gate
// above checks every recorded bond against bondFor() on the deployed set.
const noTier8 = copy(publicStake); noTier8.admission.roots.staked.tiers = noTier8.admission.roots.staked.tiers.filter((tier) => tier.limit !== 8);
ok(fields(validateDeploymentRecord(noTier8, { repoRoot: ROOT })).includes("admission.roots.staked.tiers"), "public profile must list the always-admitted tier 8");
const badDefault = copy(publicStake); badDefault.admission.roots.staked.defaultLimit = 2;
ok(fields(validateDeploymentRecord(badDefault, { repoRoot: ROOT })).includes("admission.roots.staked.defaultLimit"), "public profile default tier must be an admitted tier");
const shortExit = copy(publicStake); shortExit.admission.roots.staked.unbondingSeconds = 300;
ok(fields(validateDeploymentRecord(shortExit, { repoRoot: ROOT })).includes("admission.roots.staked.minUnbondingSeconds"), "public profile cannot shorten unbonding below root freshness + epoch + slash confirmation");
const badSplit = copy(publicStake); badSplit.admission.roots.staked.slashRewardDivisor = 1;
ok(fields(validateDeploymentRecord(badSplit, { repoRoot: ROOT })).includes("admission.roots.staked.slashRewardDivisor"), "public profile slash split stays inside the contract's bound");
const wrongPublicDefault = copy(publicStake); wrongPublicDefault.admission.defaultPath = "invited";
ok(fields(validateDeploymentRecord(wrongPublicDefault, { repoRoot: ROOT })).includes("admission.defaultPath"), "public profile must be the deployed client default");
const zeroPublicBlock = copy(publicStake); zeroPublicBlock.admission.roots.staked.deployBlock = 0;
ok(fields(validateDeploymentRecord(zeroPublicBlock, { repoRoot: ROOT })).includes("admission.roots.staked.deployBlock"), "public profile requires a positive deployment block");
for (const [field, value] of [["epochSeconds", 120], ["rootFreshnessSeconds", 120], ["payloadBytesPerSlot", 4_194_304], ["slashConfirmationSeconds", 3_599]]) {
  const drifted = copy(publicStake); drifted.ratePolicy[field] = value;
  ok(fields(validateDeploymentRecord(drifted, { repoRoot: ROOT })).includes("ratePolicy"), `public profile rejects drifted ${field}`);
}
const badRpc = copy(staked); badRpc.admission.roots.staked.rpcUrl = "https://token@example.test";
ok(fields(validateDeploymentRecord(badRpc, { repoRoot: ROOT })).includes("admission.roots.staked.rpcUrl"), "credentialed staking RPC URLs are rejected");
// ADR 0012: the failover list.
const listed = copy(staked); listed.admission.roots.staked.rpcUrls = ["https://rpc.example.test", "https://fallback.example.test"];
ok(!fields(validateDeploymentRecord(listed, { repoRoot: ROOT })).some((f) => f.startsWith("admission.roots.staked.rpc")), "rpcUrls with rpcUrl as its first entry is accepted");
const mismatched = copy(listed); mismatched.admission.roots.staked.rpcUrls = ["https://fallback.example.test", "https://rpc.example.test"];
ok(fields(validateDeploymentRecord(mismatched, { repoRoot: ROOT })).includes("admission.roots.staked.rpcUrl"), "rpcUrl must equal rpcUrls[0]");
const credentialed = copy(listed); credentialed.admission.roots.staked.rpcUrls[1] = "https://token@fallback.example.test";
ok(fields(validateDeploymentRecord(credentialed, { repoRoot: ROOT })).includes("admission.roots.staked.rpcUrls"), "a credentialed fallback endpoint is rejected");
const tooMany = copy(listed); tooMany.admission.roots.staked.rpcUrls = ["https://rpc.example.test", ...Array.from({ length: 5 }, (_, i) => `https://f${i}.example.test`)];
ok(fields(validateDeploymentRecord(tooMany, { repoRoot: ROOT })).includes("admission.roots.staked.rpcUrls"), "more than five endpoints are rejected");
const doubled = copy(listed); doubled.admission.roots.staked.rpcUrls = ["https://rpc.example.test", "https://rpc.example.test"];
ok(fields(validateDeploymentRecord(doubled, { repoRoot: ROOT })).includes("admission.roots.staked.rpcUrls"), "a duplicated endpoint is rejected");
const badDeployBlock = copy(staked); badDeployBlock.admission.roots.staked.deployBlock = -1;
ok(fields(validateDeploymentRecord(badDeployBlock, { repoRoot: ROOT })).includes("admission.roots.staked.deployBlock"), "negative staking deploy blocks are rejected");
const noAuth = copy(staked); noAuth.admission.operatorAuthorization = null;
ok(fields(validateDeploymentRecord(noAuth, { repoRoot: ROOT })).includes("admission.operatorAuthorization"), "on-chain admission without operator authorization is rejected");
const noRoot = copy(staked); noRoot.admission.roots.staked = null;
ok(fields(validateDeploymentRecord(noRoot, { repoRoot: ROOT })).includes("admission.roots.staked"), "named admission path without its root is rejected");
const order = copy(staked); order.admission.paths = ["staked", "invited"];
ok(fields(validateDeploymentRecord(order, { repoRoot: ROOT })).includes("admission.paths"), "admission paths must use the canonical anonymity order");
const stakeElder = copy(live); stakeElder.elder.admission = "stake";
ok(fields(validateDeploymentRecord(stakeElder, { repoRoot: ROOT })).includes("elder.gatewayRegistry"), "stake-gated Elder needs a registry contract");

console.log("artifact integrity:");
for (const [label, mutate, field] of [
  ["wrong sha", (r) => { r.artifacts.accepted[0].sha256 = "44".repeat(32); }, "artifacts.accepted[0].sha256"],
  ["wrong content id", (r) => { r.artifacts.accepted[0].id = "rln-aaaaaaaaaaaaaaaa"; }, "artifacts.accepted[0].id"],
  ["path traversal", (r) => { r.artifacts.accepted[0].verificationKeyPath = "../verification_key.json"; }, "artifacts.accepted[0].verificationKeyPath"],
  ["missing file", (r) => { r.artifacts.accepted[0].verificationKeyPath = "circuits/rln/missing.json"; }, "artifacts.accepted[0].verificationKeyPath"],
  ["empty accepted set", (r) => { r.artifacts.accepted = []; }, "artifacts.accepted"],
]) {
  const rec = copy(live); mutate(rec);
  ok(!validateDeploymentRecord(rec, { repoRoot: ROOT }).ok && fields(validateDeploymentRecord(rec, { repoRoot: ROOT })).includes(field), `${label} is rejected`);
}

console.log("CLI:");
const work = mkdtempSync(join(tmpdir(), "shade-tree-v4-preflight-"));
try {
  const livePath = join(work, "deployment.json");
  writeFileSync(livePath, JSON.stringify(live));
  const good = spawnSync(process.execPath, [SCRIPT, "--record", livePath, "--repo-root", ROOT], { encoding: "utf8" });
  ok(good.status === 0 && /deployable v4 record/.test(good.stdout), "CLI accepts a complete live record");
  const review = spawnSync(process.execPath, [SCRIPT, "--record", EXAMPLE, "--repo-root", ROOT, "--allow-pending"], { encoding: "utf8" });
  ok(review.status === 0 && /valid v4 record/.test(review.stdout), "CLI reviews the pending template without declaring it deployable");
  const blocked = spawnSync(process.execPath, [SCRIPT, "--record", EXAMPLE, "--repo-root", ROOT], { encoding: "utf8" });
  ok(blocked.status === 1 && /deployment preflight failed/.test(blocked.stderr), "CLI blocks the pending template in deploy mode");
  const missingPin = copy(live); missingPin.services.elder.commit = missingPin.services.node.commit = missingPin.services.heartbeat.commit = "ff".repeat(20);
  writeFileSync(livePath, JSON.stringify(missingPin));
  const pinBlocked = spawnSync(process.execPath, [SCRIPT, "--record", livePath, "--repo-root", ROOT], { encoding: "utf8" });
  ok(pinBlocked.status === 1 && /not a commit available/.test(pinBlocked.stderr), "CLI refuses a syntactically valid commit that the controller cannot verify");
  const unknown = spawnSync(process.execPath, [SCRIPT, "--wat"], { encoding: "utf8" });
  ok(unknown.status === 1 && /unknown argument/.test(unknown.stderr), "CLI rejects unknown flags");
} finally {
  rmSync(work, { recursive: true, force: true });
}

console.log(failures ? `\n${failures} FAILED` : "\nall v4 preflight checks passed");
process.exit(failures ? 1 : 0);
