// On-chain reputation tiers (T-FEAT-8b) + on-chain root (T-DEV-9c) end to end on a throwaway
// anvil, with the REAL contracts (deployed by contracts/script/DeployRegistry.s.sol with a
// two-tier table via SHADE_TREE_TIER_LIMITS/SHADE_TREE_TIER_BONDS_WEI), the REAL `shade-tree register-member
// --limit`, the REAL gateway process in ON-CHAIN ROOT MODE, REAL RLN Groth16 proofs, and the
// REAL tiered on-chain slasher. Slow suite (real proving + a forge broadcast; in
// scripts/test-all.mjs SLOW_SUITES, skipped by SHADE_TREE_FAST=1). Requires anvil + forge on PATH
// and TCP :8443 free (the gateway's fixed listen port); otherwise SKIPs honestly.
//
// Proves (scripts/integration-tiers.mjs runTierIntegration):
//   stake at tier 8 and tier 32 (each exactly bondFor(limit), limit recorded);
//   currentRoot() == JS groupFromIdentities root; the gateway's NodeRootProvider reconstructs it
//   from the rln-v4 (limit-carrying) events; requests at both tiers PASS (BOB at slot 20);
//   over-spend at tier 32 -> gateway reconstructs the secret, resolves the tier via limitOf,
//   slash(leaf, secret, 32, receiver) burns >=90% of the TIER-32 bond and pays <=10% bounty;
//   ALICE intact; wrong-limit slash reverts; root == JS tree with the slashed leaf zeroed in place.
// Plus, directly: LightClientRootProvider (proof mode, eth_getProof) reads the SAME root from
// storage slot 3 of the tiered contract — the T-DEV-9c property, locally.
//
//   node test/onchain-tiers.selftest.mjs

import { spawn, spawnSync } from "node:child_process";
import net from "node:net";
import { mkdtempSync, rmSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const ANVIL_KEY_0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"; // deployer + funder
const ANVIL_KEY_1 = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"; // gateway slasher hot key
const ANVIL_ADDR_2 = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"; // slash receiver (not the slasher, so the delta is exact)

async function rpc(url, method, params = []) {
  const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  const j = await res.json();
  if (j.error) throw new Error(j.error.message);
  return j.result;
}

function portFree(port) {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.once("error", () => resolve(false));
    s.listen(port, "127.0.0.1", () => s.close(() => resolve(true)));
  });
}

// A local TCP "egress target": accepts and holds the connection (the gateway acks ok:true on
// connect and then relays; nothing needs to flow for this test).
function localTarget() {
  return new Promise((resolve) => {
    const srv = net.createServer((sock) => { sock.on("error", () => {}); });
    srv.listen(0, "127.0.0.1", () => resolve({ port: srv.address().port, close: () => srv.close() }));
  });
}

async function main() {
  console.log("on-chain tiers + on-chain root, end to end on anvil (T-FEAT-8b / T-DEV-9c):");
  const anvilBin = spawnSync("which", ["anvil"], { encoding: "utf8" }).stdout.trim();
  const forgeBin = spawnSync("which", ["forge"], { encoding: "utf8" }).stdout.trim();
  if (!anvilBin || !forgeBin) { console.log("  SKIP anvil/forge not on PATH"); return; }
  if (!(await portFree(8443))) { console.log("  SKIP tcp 127.0.0.1:8443 busy (the gateway's fixed listen port)"); return; }

  const port = 18545 + Math.floor(Math.random() * 1000);
  const url = `http://127.0.0.1:${port}`;
  const anvil = spawn(anvilBin, ["--port", String(port), "--silent"], { stdio: "ignore" });
  const work = mkdtempSync(join(tmpdir(), "shade-tree-tiers-"));
  const targets = [await localTarget(), await localTarget()];
  try {
    let up = false;
    for (let i = 0; i < 100 && !up; i++) { try { await rpc(url, "eth_chainId"); up = true; } catch { await new Promise((r) => setTimeout(r, 100)); } }
    if (!up) { console.log("  SKIP anvil did not come up"); return; }

    // 1. deploy with the persistent deployer + a two-tier table (8 => 1e15, 32 => 4e15) and the
    //    REAL Groth16 exit-auth verifier (the same shape as the Sepolia rln-v4 deploy).
    const outJson = join(ROOT, "cache", `tiers-selftest-${port}.local.json`); // fs_permissions: under the repo
    const dep = spawnSync(forgeBin, ["script", "contracts/script/DeployRegistry.s.sol:DeployRegistry", "--rpc-url", url, "--broadcast", "--private-key", ANVIL_KEY_0, "-vv"], {
      cwd: ROOT, encoding: "utf8", timeout: 300000,
      env: {
        ...process.env, SHADE_TREE_BOND_WEI: "1000000000000000", SHADE_TREE_TIER_LIMITS: "32", SHADE_TREE_TIER_BONDS_WEI: "4000000000000000",
        SHADE_TREE_DEPLOY_REAL_VERIFIER: "1", SHADE_TREE_DEPLOY_OUT: outJson, SHADE_TREE_RPC_URL: url,
      },
    });
    ok(dep.status === 0 && existsSync(outJson), "DeployRegistry.s.sol broadcast on anvil with SHADE_TREE_TIER_LIMITS=32 SHADE_TREE_TIER_BONDS_WEI=4e15 SHADE_TREE_DEPLOY_REAL_VERIFIER=1");
    if (dep.status !== 0) { console.log((dep.stdout || "").split("\n").slice(-15).join("\n"), dep.stderr); return; }
    ok(/tier\s+32/.test(dep.stdout) && /REAL Groth16 exit-auth/.test(dep.stdout), "deploy log names tier 32 + the real exit-auth verifier");
    const deployed = JSON.parse(readFileSync(outJson, "utf8"));
    ok(deployed.slashPayout?.policy === "burn-90-reward-10-v1" && deployed.slashPayout.rewardDivisor === 10 && /^0x0{40}$/.test(deployed.slashPayout.burnAddress), "deployment records the immutable slash penalty policy");
    const set = deployed.stakedReputationSet;
    ok(/^0x[0-9a-fA-F]{40}$/.test(set), `StakedReputationSet deployed at ${set}`);
    rmSync(outJson, { force: true });

    // 2. the full loop through the shared module (real gateway process, real proofs).
    const { runTierIntegration } = await import("../scripts/integration-tiers.mjs");
    const r = await runTierIntegration({
      rpcUrl: url, set, slashKey: ANVIL_KEY_1, registerKey: ANVIL_KEY_0, receiver: ANVIL_ADDR_2,
      confirmations: 1,
      targets: targets.map((t) => `127.0.0.1:${t.port}`),
      gatewayEnv: { SHADE_TREE_EGRESS_ALLOW: targets.map((t) => `127.0.0.1:${t.port}`).join(","), SHADE_TREE_ALLOW_PRIVATE_TARGETS: "1", SHADE_TREE_EPOCH_SECONDS: "120" },
      settle: () => rpc(url, "evm_mine", []), // anvil: one block so head-1 covers the stakes
      sink: (line) => { if (!/^\[.*\] gateway/.test(line) || /SLASH|root source|slash: on-chain|tiers:/.test(line)) console.log("    " + line); },
    });
    for (const c of r.checks) ok(c.ok, c.name);
    ok(r.pass, "integration PASS (tier-8 member intact, tier-32 over-spender slashed at its tier)");

    // 3. T-DEV-9c locally: the light provider proves the tiered contract's root from slot 3.
    process.env.SHADE_TREE_CONFIRMATIONS = "1";
    const { LightClientRootProvider, NodeRootProvider } = await import("../lib/root-provider.mjs");
    await rpc(url, "evm_mine", []);
    const light = LightClientRootProvider({ contract: set, rpcUrl: url });
    const lr = await light.currentRoots();
    const { ethers } = await import("ethers");
    const c = new ethers.Contract(set, ["function currentRoot() view returns (uint256)"], new ethers.JsonRpcProvider(url, undefined, { staticNetwork: true }));
    const onChain = (await c.currentRoot()).toString();
    ok(lr.roots.length === 1 && lr.roots[0] === onChain && lr.verified === true, `LightClientRootProvider (eth_getProof, slot 3) proves the tiered contract's currentRoot (${onChain.slice(0, 16)}..)`);
    const node = NodeRootProvider({ contract: set, rpcUrl: url });
    const nr = await node.currentRoots();
    ok(nr.roots[0] === onChain, "NodeRootProvider (rln-v4 event reconstruction) == on-chain root == light-client root");
  } finally {
    for (const t of targets) t.close();
    anvil.kill();
    rmSync(work, { recursive: true, force: true });
  }
}

main().then(() => {
  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: onchain-tiers selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}).catch((e) => { console.error(e); process.exit(1); });
