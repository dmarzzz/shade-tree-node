// Selftest for packages/node/lib/network-record.mjs — the network/<name>/{contracts,bootnode}.json schema +
// the SHADE_TREE_NETWORK -> SHADE_TREE_* defaults resolver (T-DEPLOY-5, GAP-2 / GAP-10).
//
// Covers: contracts.json accepts a present-null AND a present-address gatewayRegistry, rejects
// malformed addresses / tx hashes / blocks / contradictory tx-without-address; bootnode.json
// live-vs-pending rules, signer allowlist arrays, IP smuggling rejected; the COMMITTED
// network/sepolia records validate; env resolution fills only UNSET keys (env beats file), a
// pending bootnode falls back to the static directory, a null registry supplies no default,
// networkDefault never throws; adversarial: bad network names cannot escape network/.
//
//   node packages/node/lib/network-record.selftest.mjs
//
// Exit 0 = all invariants held. Filesystem: a temp dir only (plus a read of network/sepolia).

import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKeyPairSync } from "node:crypto";
import { pubkeyToOnion } from "./directory.mjs";
import {
  validateContractsRecord, validateBootnodeRecord, validateDeploymentRecord, contractAddress, isNetworkName, isTxHash,
  loadNetworkRecords, envDefaultsFromRecords, networkEnvDefaults, applyNetworkEnv, applyClientNetworkEnv, networkDefault,
} from "./network-record.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };
const errFields = (res) => res.errors.map((e) => e.field);

function newEd() {
  const { publicKey } = generateKeyPairSync("ed25519");
  const der = publicKey.export({ format: "der", type: "spki" });
  return der.subarray(der.length - 32).toString("hex");
}
const SIGNER = newEd();
const SIGNER2 = newEd();
const ONION = pubkeyToOnion(newEd());
const ADDR = "0x" + "ab".repeat(20);
const ADDR2 = "0x" + "cd".repeat(20);
const TX = "0x" + "12".repeat(32);

const goodContracts = () => ({
  network: "testnet", chainId: 31337, status: "live", deployer: ADDR, rpcUrl: "http://127.0.0.1:8545",
  contracts: { stakedReputationSet: ADDR, hasher: ADDR, withdrawVerifier: ADDR, gatewayRegistry: null },
  deployTxs: { stakedReputationSet: TX, gatewayRegistry: null },
  deployBlock: 100, deployBlocks: {},
});
const goodBootnode = () => ({ network: "testnet", status: "live", onion: ONION, signer: SIGNER, admission: "open" });
const goodDeployment = () => ({
  schemaVersion: 1,
  network: "testnet",
  status: "live",
  protocol: { min: 4, max: 4 },
  elder: { onion: ONION, canopySigner: SIGNER, admission: "open", gatewayRegistry: null },
});

function main() {
  console.log("contracts.json schema:");
  {
    ok(validateContractsRecord(goodContracts()).ok, "valid record with gatewayRegistry: null passes (present-null)");
    const c = goodContracts(); c.contracts.gatewayRegistry = ADDR2; c.deployTxs.gatewayRegistry = TX; c.deployBlocks.gatewayRegistry = 200;
    ok(validateContractsRecord(c).ok, "valid record with gatewayRegistry address + tx + block passes (present-address)");
    ok(contractAddress(c, "gatewayRegistry") === ADDR2, "contractAddress returns the address");
    ok(contractAddress(goodContracts(), "gatewayRegistry") === null, "contractAddress is null for a null slot");
    ok(contractAddress(goodContracts(), "nope") === null, "contractAddress is null for a missing slot");
    const missing = goodContracts(); delete missing.contracts.gatewayRegistry;
    ok(validateContractsRecord(missing).ok, "a record WITHOUT the gatewayRegistry key is still valid (missing == null)");

    const b1 = goodContracts(); b1.contracts.gatewayRegistry = "0x1234";
    ok(errFields(validateContractsRecord(b1)).includes("contracts.gatewayRegistry"), "short address rejected on contracts.gatewayRegistry");
    const b2 = goodContracts(); b2.contracts.gatewayRegistry = "pending";
    ok(!validateContractsRecord(b2).ok, "the string 'pending' is not an accepted address (null is the representation)");
    const b3 = goodContracts(); b3.deployTxs.gatewayRegistry = TX; // tx but slot null
    ok(errFields(validateContractsRecord(b3)).includes("deployTxs.gatewayRegistry"), "tx hash for a null slot is contradictory -> rejected");
    const b4 = goodContracts(); b4.deployTxs.stakedReputationSet = "0xzz";
    ok(errFields(validateContractsRecord(b4)).includes("deployTxs.stakedReputationSet"), "malformed tx hash rejected");
    const b5 = goodContracts(); b5.deployBlock = "100";
    ok(errFields(validateContractsRecord(b5)).includes("deployBlock"), "string deployBlock rejected (must be a JSON number)");
    const b6 = goodContracts(); b6.deployBlocks = { gatewayRegistry: 5 };
    ok(errFields(validateContractsRecord(b6)).includes("deployBlocks.gatewayRegistry"), "block for a null slot rejected");
    const b7 = goodContracts(); b7.chainId = "11155111";
    ok(errFields(validateContractsRecord(b7)).includes("chainId"), "string chainId rejected");
    const b8 = goodContracts(); b8.status = "deployed";
    ok(errFields(validateContractsRecord(b8)).includes("status"), "unknown status rejected");
    const b9 = goodContracts(); b9.contracts = [];
    ok(errFields(validateContractsRecord(b9)).includes("contracts"), "contracts must be an object");
    ok(!validateContractsRecord(null).ok && !validateContractsRecord("x").ok && !validateContractsRecord([]).ok, "non-object records rejected (total)");
    ok(isTxHash(TX) && !isTxHash(TX.slice(0, 40)) && !isTxHash(TX.slice(2)), "isTxHash: 0x + 64 hex only");
  }

  console.log("\npayments slots (T-FEAT-7): payAsset + registrar + paidAccessSet:");
  {
    const c = goodContracts();
    c.contracts.paidAccessSet = ADDR2;
    c.payAsset = { address: ADDR, name: "USDC", symbol: "USDC", version: "2", decimals: 6, kind: "usdc", deployTx: null, note: "Circle testnet USDC" };
    c.registrar = { port: 8878, protocols: ["x402", "mpp"], prices: { "8": "100000", "32": "400000" }, note: "on the bootnode onion" };
    ok(validateContractsRecord(c).ok, "record with paidAccessSet + payAsset + registrar passes");
    const d = envDefaultsFromRecords({ dir: "/nonexistent", contracts: c, bootnode: null });
    ok(d.SHADE_TREE_PAID_ACCESS_CONTRACT === ADDR2 && d.SHADE_TREE_PAY_ASSET === ADDR && d.SHADE_TREE_REGISTRAR_PORT === "8878", "-> SHADE_TREE_PAID_ACCESS_CONTRACT / SHADE_TREE_PAY_ASSET / SHADE_TREE_REGISTRAR_PORT defaults");
    const n = goodContracts(); n.payAsset = null; n.registrar = null;
    ok(validateContractsRecord(n).ok && !("SHADE_TREE_PAY_ASSET" in envDefaultsFromRecords({ dir: "/x", contracts: n, bootnode: null })), "null payAsset/registrar = not sold here (valid, no defaults)");
    const bad = [
      [(r) => { r.payAsset = { address: "0x12" }; }, "payAsset.address"],
      [(r) => { r.payAsset = { address: ADDR, decimals: 300 }; }, "payAsset.decimals"],
      [(r) => { r.payAsset = { address: ADDR, deployTx: "0xzz" }; }, "payAsset.deployTx"],
      [(r) => { r.payAsset = "usdc"; }, "payAsset"],
      [(r) => { r.registrar = { port: 0, protocols: ["x402"] }; }, "registrar.port"],
      [(r) => { r.registrar = { port: 8878, protocols: ["l402"] }; }, "registrar.protocols"],
      [(r) => { r.registrar = { port: 8878, protocols: [] }; }, "registrar.protocols"],
      [(r) => { r.registrar = { port: 8878, protocols: ["mpp"], prices: { "8": 100000 } }; }, "registrar.prices"],
      [(r) => { r.registrar = { port: 8878, protocols: ["mpp"], note: "box at 10.0.0.1" }; }, "registrar.note"],
    ];
    for (const [mut, field] of bad) {
      const r = goodContracts(); mut(r);
      const res = validateContractsRecord(r);
      ok(!res.ok && res.errors.some((e) => e.field === field), `rejects bad ${field}`);
    }
  }

  console.log("\nbootnode.json schema:");
  {
    ok(validateBootnodeRecord(goodBootnode()).ok, "live record with onion + signer + admission passes");
    ok(validateBootnodeRecord({ network: "t", status: "pending", onion: null, signer: null, admission: "open" }).ok, "pending template with nulls passes");
    const arr = goodBootnode(); arr.signer = [SIGNER, SIGNER2];
    ok(validateBootnodeRecord(arr).ok, "signer may be an array (rotation overlap allowlist)");
    const sd = { ...goodBootnode(), status: "pending", onion: null, signer: null, staticDirectory: { path: "directory.json", signer: SIGNER } };
    ok(validateBootnodeRecord(sd).ok, "staticDirectory { path, signer } accepted");

    const l1 = { ...goodBootnode(), onion: null };
    ok(errFields(validateBootnodeRecord(l1)).includes("onion"), "live WITHOUT onion rejected");
    const l2 = { ...goodBootnode(), signer: null };
    ok(errFields(validateBootnodeRecord(l2)).includes("signer"), "live WITHOUT signer rejected");
    const l3 = { ...goodBootnode(), onion: "10.0.0.7" };
    ok(errFields(validateBootnodeRecord(l3)).includes("onion") && /never an IP/.test(validateBootnodeRecord(l3).errors[0].problem), "an IP in `onion` is rejected with the IP message");
    const l4 = { ...goodBootnode(), note: "box at 165.227.118.154" };
    ok(errFields(validateBootnodeRecord(l4)).includes("note"), "an IP smuggled into `note` is rejected");
    const l5 = { ...goodBootnode(), signer: "0x" + SIGNER };
    ok(errFields(validateBootnodeRecord(l5)).includes("signer"), "0x-prefixed signer rejected (SHADE_TREE_DIR_SIGNER is bare hex)");
    const l6 = { ...goodBootnode(), signer: [] };
    ok(errFields(validateBootnodeRecord(l6)).includes("signer"), "empty signer array rejected");
    const l7 = { ...goodBootnode(), admission: "closed" };
    ok(errFields(validateBootnodeRecord(l7)).includes("admission"), "unknown admission rejected");
    const l8 = { ...goodBootnode(), status: "up" };
    ok(errFields(validateBootnodeRecord(l8)).includes("status"), "unknown status rejected");
    const l9 = { ...goodBootnode(), staticDirectory: { path: "../../etc/passwd", signer: SIGNER } };
    ok(errFields(validateBootnodeRecord(l9)).includes("staticDirectory.path"), "staticDirectory.path may not escape the network dir");
    const l10 = { ...goodBootnode(), staticDirectory: { path: "/abs/dir.json", signer: SIGNER } };
    ok(errFields(validateBootnodeRecord(l10)).includes("staticDirectory.path"), "absolute staticDirectory.path rejected");
    const l11 = { ...goodBootnode(), gatewayRegistry: "0xnope" };
    ok(errFields(validateBootnodeRecord(l11)).includes("gatewayRegistry"), "optional gatewayRegistry must be address|null");
    ok(!validateBootnodeRecord(null).ok && !validateBootnodeRecord(42).ok, "non-object rejected (total)");
  }

  console.log("\ndeployment.json client-discovery schema:");
  {
    ok(validateDeploymentRecord(goodDeployment()).ok, "live v4 deployment with Elder trust pair passes");
    const pending = goodDeployment(); pending.status = "pending"; pending.elder.onion = null; pending.elder.canopySigner = null;
    ok(validateDeploymentRecord(pending).ok, "pending deployment may carry null Elder inputs");
    const old = goodDeployment(); old.protocol = { min: 3, max: 3 };
    ok(errFields(validateDeploymentRecord(old)).includes("protocol"), "live non-v4 deployment cannot become a client default");
    const badOnion = goodDeployment(); badOnion.elder.onion = "10.0.0.7";
    ok(errFields(validateDeploymentRecord(badOnion)).includes("elder.onion"), "deployment Elder rejects IPs");
    const badSigner = goodDeployment(); badSigner.elder.canopySigner = "abcd";
    ok(errFields(validateDeploymentRecord(badSigner)).includes("elder.canopySigner"), "deployment Elder rejects malformed signer pins");
    const publicProfile = goodDeployment();
    publicProfile.network = "sepolia";
    publicProfile.ratePolicy = { scope: "grove-v4", window: "fixed", epochSeconds: 60, previousEpochsAccepted: 1, rootFreshnessSeconds: 60, payloadBytesPerSlot: 41943040, slashConfirmationSeconds: 3600, crossGateway: "best-effort-fleet-tally" };
    publicProfile.admission = {
      defaultPath: "staked",
      paths: ["invited", "staked"],
      roots: {
        invited: null,
        paid: null,
        staked: {
          profile: "public-stake-v1", chainId: 11155111, contract: ADDR, deployTx: TX,
          deployBlock: 42, rpcUrl: "https://rpc.example.test", hasher: ADDR2,
          withdrawVerifier: ADDR2, defaultLimit: 1,
          tiers: [{ limit: 1, bondWei: "100000000000000000" }, { limit: 8, bondWei: "800000000000000000" }],
          unbondingSeconds: 86400, minUnbondingSeconds: 3720,
        },
      },
    };
    ok(validateDeploymentRecord(publicProfile).ok, "public stake profile validates in the client-facing record loader");
    const defaults = envDefaultsFromRecords({ dir: "/x", deployment: publicProfile, contracts: null, bootnode: null });
    ok(defaults.SHADE_TREE_GROUP_CONTRACT === ADDR && defaults.SHADE_TREE_RPC_URL === "https://rpc.example.test" && defaults.SHADE_TREE_CHAIN_ID === "11155111" && defaults.SHADE_TREE_STAKE_PROFILE === "public-stake-v1" && defaults.SHADE_TREE_FROM_BLOCK === "0x2a", "live public set address/RPC/chain/profile/deploy block become client defaults");

    const clientRoot = mkdtempSync(join(tmpdir(), "shade-tree-client-profile-"));
    const clientDir = join(clientRoot, "sepolia"); mkdirSync(clientDir);
    writeFileSync(join(clientDir, "deployment.json"), JSON.stringify(publicProfile));
    try {
      const custom = { SHADE_TREE_GROUP_CONTRACT: ADDR2 };
      const customApplied = applyClientNetworkEnv(custom, { root: clientRoot, defaultNetwork: "sepolia" });
      ok(customApplied.length === 0 && Object.keys(custom).length === 1 && custom.SHADE_TREE_GROUP_CONTRACT === ADDR2,
        "an explicit custom group contract does not inherit bundled chain/profile/RPC defaults");

      const rpcOnly = { SHADE_TREE_RPC_URL: "https://operator.example.test" };
      const rpcApplied = applyClientNetworkEnv(rpcOnly, { root: clientRoot, defaultNetwork: "sepolia" });
      ok(rpcApplied.includes("SHADE_TREE_GROUP_CONTRACT") && rpcOnly.SHADE_TREE_RPC_URL === "https://operator.example.test" && rpcOnly.SHADE_TREE_CHAIN_ID === "11155111",
        "an RPC-only override retains the bundled public profile while preserving the explicit RPC");
    } finally {
      rmSync(clientRoot, { recursive: true, force: true });
    }
    ok(defaults.SHADE_TREE_EPOCH_SECONDS === "60" && defaults.SHADE_TREE_ROOT_FRESHNESS_SECONDS === "60" && defaults.SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES === "41943040", "rate policy becomes exact runtime defaults");
    ok(defaults.SHADE_TREE_LEAF_SOURCE === "staked" && defaults.SHADE_TREE_LIMIT === "1" && defaults.SHADE_TREE_TIERS === "1,8", "public profile defaults clients to the record's default-tier staked leaf");
    // One tier (the production table since 2026-10-05): tier 8 alone, and its own default.
    const oneTier = structuredClone(publicProfile);
    oneTier.admission.roots.staked.tiers = [{ limit: 8, bondWei: "10000000000000000" }];
    oneTier.admission.roots.staked.defaultLimit = 8;
    const oneTierDefaults = envDefaultsFromRecords({ dir: "/x", deployment: oneTier, contracts: null, bootnode: null });
    ok(validateDeploymentRecord(oneTier).ok && oneTierDefaults.SHADE_TREE_LIMIT === "8" && oneTierDefaults.SHADE_TREE_TIERS === "8", "a one-tier public profile validates and sets both the client tier and the node tier list to 8");
    const strayDefault = structuredClone(oneTier); strayDefault.admission.roots.staked.defaultLimit = 1;
    ok(errFields(validateDeploymentRecord(strayDefault)).includes("admission.roots.staked.defaultLimit"), "a default tier the set does not admit is refused");
    const wrongDefault = structuredClone(publicProfile); wrongDefault.admission.defaultPath = "invited";
    ok(errFields(validateDeploymentRecord(wrongDefault)).includes("admission.defaultPath"), "public profile cannot silently default clients to invited admission");
    const zeroDeployBlock = structuredClone(publicProfile); zeroDeployBlock.admission.roots.staked.deployBlock = 0;
    ok(errFields(validateDeploymentRecord(zeroDeployBlock)).includes("admission.roots.staked.deployBlock"), "public profile requires a positive deployment block");
    for (const [field, value] of [["epochSeconds", 120], ["rootFreshnessSeconds", 120], ["payloadBytesPerSlot", 4_194_304], ["slashConfirmationSeconds", 3_599]]) {
      const drifted = structuredClone(publicProfile); drifted.ratePolicy[field] = value;
      ok(errFields(validateDeploymentRecord(drifted)).includes("ratePolicy"), `public profile rejects drifted ${field}`);
    }
  }

  console.log("\nnetwork names:");
  {
    ok(isNetworkName("sepolia") && isNetworkName("anvil-local") && isNetworkName("mainnet"), "plain names accepted");
    for (const bad of ["../sepolia", "sepolia/..", "Sepolia", "", "a b", "sep.olia", "-x", "x".repeat(65)]) {
      ok(!isNetworkName(bad), `bad name rejected: ${JSON.stringify(bad)}`);
    }
    let threw = false;
    try { loadNetworkRecords("../lib"); } catch { threw = true; }
    ok(threw, "loadNetworkRecords refuses a path-traversal name");
    threw = false;
    try { loadNetworkRecords("no-such-network-zzz"); } catch (e) { threw = /no such network/.test(e.message); }
    ok(threw, "loadNetworkRecords throws on an unknown network");
  }

  console.log("\ncommitted network/sepolia records:");
  {
    const r = loadNetworkRecords("sepolia");
    ok(r.deployment?.status === "live" && r.deployment.protocol.min === 4, "network/sepolia/deployment.json loads as current v4");
    ok(r.contracts && r.contracts.chainId === 11155111, "network/sepolia/contracts.json loads + validates");
    ok("gatewayRegistry" in r.contracts.contracts, "sepolia contracts.json carries the gatewayRegistry slot");
    ok(r.contracts.status === "retired" && r.bootnode?.status === "retired", "pre-v4 Sepolia records are retained as retired migration evidence");
    const d = envDefaultsFromRecords(r);
    ok(d.SHADE_TREE_BOOTNODE_ONION === r.deployment.elder.onion && d.SHADE_TREE_DIR_SIGNER.split(",")[0] === r.deployment.elder.canopySigner,
      "current v4 deployment supplies Elder onion + signer while retired records supply nothing");
    // ADR 0012: every Elder Tree and every canopy signer of the record reach the client.
    ok(d.SHADE_TREE_BOOTNODE_ONIONS === r.deployment.elders.map((e) => e.onion).join(",") && d.SHADE_TREE_DIR_SIGNER === r.deployment.elders.map((e) => e.canopySigner).join(","),
      "elders[] become SHADE_TREE_BOOTNODE_ONIONS and the union of canopy signers becomes SHADE_TREE_DIR_SIGNER");
    ok(d.SHADE_TREE_RPC_URL === r.deployment.admission.roots.staked.rpcUrls.join(",") && d.SHADE_TREE_RPC_URL.startsWith(r.deployment.admission.roots.staked.rpcUrl + ","),
      "the record's rpcUrls become the comma-separated SHADE_TREE_RPC_URL failover list, rpcUrl first");
    ok(networkEnvDefaults("sepolia").SHADE_TREE_BOOTNODE_ONION === r.deployment.elder.onion,
      "selecting Sepolia resolves the current v4 Elder, not retired discovery");
    const s = JSON.stringify(r.bootnode);
    ok(!/\b(?:\d{1,3}\.){3}\d{1,3}\b/.test(s), "sepolia bootnode.json contains no IPv4 address");
  }

  console.log("\nenv resolution (temp network dir):");
  {
    const root = mkdtempSync(join(tmpdir(), "shade-tree-net-"));
    const dir = join(root, "testnet"); mkdirSync(dir);
    const c = goodContracts(); c.contracts.gatewayRegistry = ADDR2;
    writeFileSync(join(dir, "contracts.json"), JSON.stringify(c));
    writeFileSync(join(dir, "bootnode.json"), JSON.stringify({ ...goodBootnode(), signer: [SIGNER, SIGNER2], admission: "stake" }));
    writeFileSync(join(dir, "directory.json"), "{}");

    const d = networkEnvDefaults("testnet", { root });
    ok(d.SHADE_TREE_BOOTNODE_ONION === ONION, "live bootnode onion -> SHADE_TREE_BOOTNODE_ONION");
    ok(d.SHADE_TREE_DIR_SIGNER === `${SIGNER},${SIGNER2}`, "signer array -> comma-joined SHADE_TREE_DIR_SIGNER (rotation allowlist)");
    ok(d.SHADE_TREE_BOOTNODE_ADMISSION === "stake", "admission -> SHADE_TREE_BOOTNODE_ADMISSION");
    ok(d.SHADE_TREE_GATEWAY_REGISTRY === ADDR2, "gatewayRegistry address -> SHADE_TREE_GATEWAY_REGISTRY");
    ok(d.SHADE_TREE_GROUP_CONTRACT === ADDR, "stakedReputationSet -> SHADE_TREE_GROUP_CONTRACT");
    ok(!("SHADE_TREE_PAID_ACCESS_CONTRACT" in d), "no paidAccessSet slot -> no SHADE_TREE_PAID_ACCESS_CONTRACT default");
    ok(!("SHADE_TREE_DIRECTORY" in d), "with a live bootnode the static directory is NOT wired (bootnode wins)");
    // T-FEAT-7: a paidAccessSet slot resolves to SHADE_TREE_PAID_ACCESS_CONTRACT (env still beats file)
    const cp = goodContracts(); cp.contracts.paidAccessSet = ADDR2; cp.deployTxs.paidAccessSet = TX; cp.deployBlocks.paidAccessSet = 300;
    ok(validateContractsRecord(cp).ok, "paidAccessSet slot + tx + block validates");
    writeFileSync(join(dir, "contracts.json"), JSON.stringify(cp));
    const dpaid = networkEnvDefaults("testnet", { root });
    ok(dpaid.SHADE_TREE_PAID_ACCESS_CONTRACT === ADDR2 && dpaid.SHADE_TREE_GROUP_CONTRACT === ADDR, "paidAccessSet -> SHADE_TREE_PAID_ACCESS_CONTRACT next to SHADE_TREE_GROUP_CONTRACT");
    const envp = { SHADE_TREE_NETWORK: "testnet", SHADE_TREE_PAID_ACCESS_CONTRACT: "explicit" };
    applyNetworkEnv(envp, { root });
    ok(envp.SHADE_TREE_PAID_ACCESS_CONTRACT === "explicit", "explicit SHADE_TREE_PAID_ACCESS_CONTRACT is NOT overwritten by the record");
    const cpn = goodContracts(); cpn.contracts.paidAccessSet = null;
    writeFileSync(join(dir, "contracts.json"), JSON.stringify(cpn));
    ok(!("SHADE_TREE_PAID_ACCESS_CONTRACT" in networkEnvDefaults("testnet", { root })), "null paidAccessSet supplies no SHADE_TREE_PAID_ACCESS_CONTRACT");
    const cpb = goodContracts(); cpb.contracts.paidAccessSet = "0x1234";
    ok(errFields(validateContractsRecord(cpb)).includes("contracts.paidAccessSet"), "malformed paidAccessSet address rejected");
    writeFileSync(join(dir, "contracts.json"), JSON.stringify(c));

    // env beats file
    const env = { SHADE_TREE_NETWORK: "testnet", SHADE_TREE_DIR_SIGNER: "explicit", SHADE_TREE_BOOTNODE_ONION: "" };
    const filled = applyNetworkEnv(env, { root });
    ok(env.SHADE_TREE_DIR_SIGNER === "explicit", "explicit env SHADE_TREE_DIR_SIGNER is NOT overwritten by the record");
    ok(env.SHADE_TREE_BOOTNODE_ONION === ONION && filled.includes("SHADE_TREE_BOOTNODE_ONION"), "empty-string env counts as unset and is filled");
    ok(env.SHADE_TREE_GATEWAY_REGISTRY === ADDR2, "unset SHADE_TREE_GATEWAY_REGISTRY filled from the record");
    ok(applyNetworkEnv({}, { root }).length === 0, "no SHADE_TREE_NETWORK -> applyNetworkEnv is a no-op");
    const clientDefault = {};
    applyClientNetworkEnv(clientDefault, { root, defaultNetwork: "testnet" });
    ok(clientDefault.SHADE_TREE_BOOTNODE_ONION === ONION && clientDefault.SHADE_TREE_DIR_SIGNER === `${SIGNER},${SIGNER2}`,
      "client with no explicit source receives the bundled network's Elder+signer pair");
    const clientPinned = { SHADE_TREE_ONION: ONION };
    ok(applyClientNetworkEnv(clientPinned, { root, defaultNetwork: "testnet" }).length === 0 && !clientPinned.SHADE_TREE_BOOTNODE_ONION,
      "explicit pinned gateway suppresses the bundled Elder default");
    const clientStatic = { SHADE_TREE_NETWORK: "testnet", SHADE_TREE_DIRECTORY: "/operator/fleet.json", SHADE_TREE_DIR_SIGNER: SIGNER };
    ok(applyClientNetworkEnv(clientStatic, { root }).length === 0 && !clientStatic.SHADE_TREE_BOOTNODE_ONION,
      "explicit discovery source also wins over a named network profile");

    // pending bootnode + static fallback + null registry
    writeFileSync(join(dir, "bootnode.json"), JSON.stringify({ network: "testnet", status: "pending", onion: null, signer: null, admission: "open", staticDirectory: { path: "directory.json", signer: SIGNER } }));
    writeFileSync(join(dir, "contracts.json"), JSON.stringify(goodContracts()));
    const p = networkEnvDefaults("testnet", { root });
    ok(!("SHADE_TREE_BOOTNODE_ONION" in p), "pending bootnode (onion null) supplies no SHADE_TREE_BOOTNODE_ONION");
    ok(p.SHADE_TREE_DIRECTORY === join(dir, "directory.json") && p.SHADE_TREE_DIR_SIGNER === SIGNER, "pending bootnode falls back to staticDirectory path + its signer");
    ok(!("SHADE_TREE_GATEWAY_REGISTRY" in p), "null gatewayRegistry supplies no SHADE_TREE_GATEWAY_REGISTRY");
    ok(!("SHADE_TREE_BOOTNODE_ADMISSION" in p) || p.SHADE_TREE_BOOTNODE_ADMISSION === "open", "admission still reported for a pending record");

    // static directory path missing on disk -> not wired
    rmSync(join(dir, "directory.json"));
    const q = networkEnvDefaults("testnet", { root });
    ok(!("SHADE_TREE_DIRECTORY" in q) && !("SHADE_TREE_DIR_SIGNER" in q), "staticDirectory whose file is absent is not wired");

    // retired bootnode supplies nothing, including a configured static fallback
    writeFileSync(join(dir, "directory.json"), "{}");
    writeFileSync(join(dir, "bootnode.json"), JSON.stringify({ ...goodBootnode(), status: "retired", staticDirectory: { path: "directory.json", signer: SIGNER } }));
    const rt = networkEnvDefaults("testnet", { root });
    ok(!("SHADE_TREE_BOOTNODE_ONION" in rt) && !("SHADE_TREE_DIRECTORY" in rt) && !("SHADE_TREE_DIR_SIGNER" in rt), "retired bootnode supplies no live or static discovery defaults");

    // retired contracts remain provenance but supply no runtime defaults
    writeFileSync(join(dir, "bootnode.json"), JSON.stringify(goodBootnode()));
    const retiredContracts = { ...goodContracts(), status: "retired" };
    writeFileSync(join(dir, "contracts.json"), JSON.stringify(retiredContracts));
    const rc = networkEnvDefaults("testnet", { root });
    ok(!("SHADE_TREE_RPC_URL" in rc) && !("SHADE_TREE_GROUP_CONTRACT" in rc), "retired contracts supply no RPC or contract defaults");

    writeFileSync(join(dir, "bootnode.json"), JSON.stringify({ ...goodBootnode(), status: "retired" }));
    let retiredAll = false;
    try { networkEnvDefaults("testnet", { root }); } catch (e) { retiredAll = /retired deployment record/.test(e.message); }
    ok(retiredAll, "a wholly retired named network is rejected before any SDK/CLI fallback");
    writeFileSync(join(dir, "contracts.json"), JSON.stringify(goodContracts()));

    // invalid record throws (never silently ignored)
    writeFileSync(join(dir, "bootnode.json"), JSON.stringify({ ...goodBootnode(), onion: null }));
    let threw = false;
    try { networkEnvDefaults("testnet", { root }); } catch (e) { threw = /invalid record/.test(e.message) && /onion/.test(e.message); }
    ok(threw, "an invalid bootnode.json throws naming the field");
    writeFileSync(join(dir, "bootnode.json"), "{not json");
    threw = false;
    try { networkEnvDefaults("testnet", { root }); } catch (e) { threw = /invalid JSON/.test(e.message); }
    ok(threw, "malformed JSON throws");
    rmSync(join(dir, "bootnode.json"));
    const noBoot = networkEnvDefaults("testnet", { root });
    ok(noBoot.SHADE_TREE_RPC_URL && !("SHADE_TREE_BOOTNODE_ONION" in noBoot), "a network with contracts.json but no bootnode.json still resolves contract defaults");

    // networkDefault never throws
    ok(networkDefault("SHADE_TREE_GATEWAY_REGISTRY", { SHADE_TREE_NETWORK: "no-such-network-zzz" }) === null, "networkDefault -> null on unknown network (no throw)");
    ok(networkDefault("SHADE_TREE_GATEWAY_REGISTRY", {}) === null, "networkDefault -> null without SHADE_TREE_NETWORK");
    ok(networkDefault("SHADE_TREE_GATEWAY_REGISTRY", { SHADE_TREE_NETWORK: "../x" }) === null, "networkDefault -> null on a traversal name");

    rmSync(root, { recursive: true, force: true });
  }

  console.log(failures ? `\n${failures} FAILED` : "\nall network-record checks passed");
  process.exit(failures ? 1 : 0);
}

main();
