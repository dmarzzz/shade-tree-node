// Selftest for `shade-tree exit-gateway` / `shade-tree withdraw-gateway` / `shade-tree gateway-status`
// (group/exit-gateway.mjs): the operator-side exit half of GatewayRegistry. Spawns the real
// CLI as a child for every case.
//
// Part 1 (always, offline): calldata encoding + argument/key validation. `--dry-run` against an
//   unreachable RPC must still print the exact target + calldata (initiateExit() selector,
//   withdraw(address) selector + padded recipient) and exit 0 without a chain; the signer is
//   never echoed; bad addresses / unknown flags / missing mode fail fast.
// Part 2 (when `anvil` is on PATH and out/GatewayRegistry.sol/GatewayRegistry.json exists or
//   `forge build` can make it): the full lifecycle on a throwaway anvil — deploy, register via
//   `shade-tree register-gateway`, status, withdraw-before-exit refused (NotExiting), exit --dry-run
//   changes nothing, exit mines + leaves the active set, exit again is a no-op, withdraw refused
//   while StillBonded, time-warp, withdraw --dry-run changes nothing, withdraw pays --recipient
//   exactly BOND, withdraw again refused (NotStaked); --key-file and --keystore signer paths.
//   Otherwise Part 2 is SKIPPED (printed as such) and the selftest still passes on Part 1.
//
//   node group/exit-gateway.selftest.mjs

import { spawn, spawnSync } from "node:child_process";
import http from "node:http";
import { mkdtemp, rm, writeFile, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import pkg from "js-sha3";
const { keccak256 } = pkg;

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const CLI = join(ROOT, "packages", "node", "bin", "shade-tree.mjs");
const ARTIFACT = join(ROOT, "out", "GatewayRegistry.sol", "GatewayRegistry.json");

const REG = "0x1111111111111111111111111111111111111111";
const RCPT = "0x2222222222222222222222222222222222222222";
const ANVIL_KEY_0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ANVIL_KEY_1 = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const ANVIL_ADDR_1 = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
const KEY_1_HEX = ANVIL_KEY_1.slice(2);

function cleanEnv(extra = {}) {
  const base = {};
  for (const [k, v] of Object.entries(process.env)) if (!k.startsWith("SHADE_TREE_")) base[k] = v;
  return { ...base, ...extra };
}
function shadeTree(args, env = {}, timeout = 60_000) {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", env: cleanEnv(env), timeout });
  if (r.error) throw r.error;
  return { code: r.status, out: (r.stdout || "") + (r.stderr || "") };
}
function shadeTreeAsync(args, env = {}, timeout = 10_000) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], { env: cleanEnv(env), stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", (chunk) => { out += chunk; });
    child.stderr.on("data", (chunk) => { out += chunk; });
    const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("child command timed out")); }, timeout);
    child.on("error", reject);
    child.on("close", (code) => { clearTimeout(timer); resolve({ code, out }); });
  });
}
const sel = (sig) => "0x" + keccak256(sig).slice(0, 8);

async function rpc(url, method, params = []) {
  const r = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  const j = await r.json();
  if (j.error) throw new Error(JSON.stringify(j.error));
  return j.result;
}

async function part1() {
  console.log("offline: calldata + validation (RPC unreachable):");
  const OFF = { SHADE_TREE_GATEWAY_REGISTRY: REG, SHADE_TREE_RPC_URL: "http://127.0.0.1:1" };
  const ex = shadeTree(["exit-gateway", "--dry-run"], OFF);
  ok(ex.code === 0, "`exit-gateway --dry-run` with the RPC down exits 0 (nothing to broadcast)");
  ok(ex.out.includes(`to=${REG} value=0 data=${sel("initiateExit()")}`), "prints target + initiateExit() calldata (selector matches keccak)");
  ok(/DRY-RUN/.test(ex.out) && /nothing broadcast/.test(ex.out), "banner says DRY-RUN and that nothing was broadcast");
  ok(/rpc unreachable/i.test(ex.out), "explains the RPC was unreachable so status/simulation was skipped");
  ok(!ex.out.includes(KEY_1_HEX), "the (dev default) private key is never printed");
  ok(ex.out.includes(ANVIL_ADDR_1), "the derived operator address is printed instead");

  const wd = shadeTree(["withdraw-gateway", "--dry-run", "--recipient", RCPT], OFF);
  const want = sel("withdraw(address)") + "0".repeat(24) + RCPT.slice(2);
  ok(wd.code === 0 && wd.out.includes(`data=${want}`), "withdraw(address) calldata = selector + 32-byte padded --recipient");
  const wdDefault = shadeTree(["withdraw-gateway", "--dry-run"], OFF);
  ok(wdDefault.out.includes(`data=${sel("withdraw(address)")}${"0".repeat(24)}${ANVIL_ADDR_1.slice(2).toLowerCase()}`) && /default: the operator/.test(wdDefault.out),
    "withdraw without --recipient defaults the recipient to the operator address");

  // --operator only (no signer) is enough for a dry-run / status
  const nokey = shadeTree(["exit-gateway", "--dry-run", "--operator", RCPT], { ...OFF, SHADE_TREE_RPC_URL: "http://10.255.255.1:1" });
  ok(nokey.code === 0 && nokey.out.includes(RCPT) && /address only/.test(nokey.out), "--dry-run with --operator and no key on a non-loopback RPC works (address only)");
  // non-loopback + no key + not dry-run: refuse before touching anything (RPC also unreachable => exit 1 either way)
  const send = shadeTree(["exit-gateway"], { ...OFF, SHADE_TREE_RPC_URL: "http://10.255.255.1:1" }, 20_000);
  ok(send.code === 1 && !/DRY-RUN/.test(send.out), "a real send with the RPC unreachable exits 1 (never pretends)");

  console.log("\nvalidation:");
  ok(shadeTree(["exit-gateway", "--bogus"], OFF).code === 2, "unknown flag => exit 2");
  ok(shadeTree(["exit-gateway", "--recipient", RCPT], OFF).code === 2, "--recipient on exit => exit 2 (withdraw only)");
  ok(shadeTree(["exit-gateway", "--dry-run", "--operator", "0xnope"], OFF).code === 1, "malformed --operator => exit 1");
  ok(shadeTree(["withdraw-gateway", "--dry-run", "--recipient", "12345"], OFF).code === 1, "malformed --recipient => exit 1");
  ok(shadeTree(["exit-gateway", "--dry-run"], { SHADE_TREE_RPC_URL: "http://127.0.0.1:1" }).code === 1, "no registry address anywhere => exit 1");
  ok(shadeTree(["exit-gateway", "--dry-run", "--operator", RCPT], { ...OFF, SHADE_TREE_REGISTER_KEY: "0xdead" }).code === 1, "malformed SHADE_TREE_REGISTER_KEY => exit 1");
  const mism = shadeTree(["exit-gateway", "--dry-run", "--operator", RCPT], { ...OFF, SHADE_TREE_REGISTER_KEY: ANVIL_KEY_1 });
  ok(mism.code === 1 && /!= signer/.test(mism.out), "--operator that differs from the signer's address => exit 1 (stakes key to msg.sender)");
  const direct = spawnSync(process.execPath, [join(HERE, "exit-gateway.mjs")], { encoding: "utf8", env: cleanEnv(OFF) });
  ok(direct.status === 2 && /mode required/.test(direct.stderr), "direct invocation without a mode => exit 2");
  const help = shadeTree(["withdraw-gateway", "--help"]);
  ok(help.code === 0 && /withdraw/.test(help.out), "`shade-tree withdraw-gateway --help` exits 0");
  const top = shadeTree(["help"]);
  ok(/exit-gateway/.test(top.out) && /withdraw-gateway/.test(top.out) && /gateway-status/.test(top.out) && /\bidentity\b/.test(top.out), "`shade-tree help` lists exit-gateway, withdraw-gateway, gateway-status, identity");

  const stalledRpc = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => { body += chunk; });
    req.on("end", () => {
      let payload;
      try { payload = JSON.parse(body); } catch { res.statusCode = 400; return res.end(); }
      if (payload.method === "eth_chainId") {
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ jsonrpc: "2.0", id: payload.id, result: "0x1" }));
      }
      // Every post-probe request intentionally stalls until the bounded provider aborts it.
    });
  });
  await new Promise((resolve) => stalledRpc.listen(0, "127.0.0.1", resolve));
  try {
    const bounded = await shadeTreeAsync(["gateway-status", "--operator", RCPT], {
      SHADE_TREE_GATEWAY_REGISTRY: REG,
      SHADE_TREE_RPC_URL: `http://127.0.0.1:${stalledRpc.address().port}`,
      SHADE_TREE_RPC_TIMEOUT_MS: "150",
    });
    ok(bounded.code === 1 && /timeout|timed out/i.test(bounded.out), "post-probe GatewayRegistry reads obey SHADE_TREE_RPC_TIMEOUT_MS");
  } finally {
    stalledRpc.closeAllConnections?.();
    await new Promise((resolve) => stalledRpc.close(resolve));
  }
}

async function part2() {
  console.log("\nlive lifecycle on a throwaway anvil:");
  const anvilBin = spawnSync("which", ["anvil"], { encoding: "utf8" }).stdout.trim();
  if (!anvilBin) { console.log("  SKIP anvil not on PATH (Part 1 covered calldata + validation)"); return; }
  if (!existsSync(ARTIFACT)) {
    const fb = spawnSync("forge", ["build"], { cwd: ROOT, encoding: "utf8", timeout: 300_000 });
    if (fb.status !== 0 || !existsSync(ARTIFACT)) { console.log("  SKIP forge build unavailable/failed; no GatewayRegistry artifact"); return; }
  }
  let ethers;
  try { ({ ethers } = await import("ethers")); } catch { console.log("  SKIP ethers not installed"); return; }

  const port = 18545 + Math.floor(Math.random() * 1000);
  const url = `http://127.0.0.1:${port}`;
  const anvil = spawn(anvilBin, ["--port", String(port), "--silent"], { stdio: "ignore" });
  const work = await mkdtemp(join(tmpdir(), "shade-tree-exitgw-"));
  try {
    let up = false;
    for (let i = 0; i < 100 && !up; i++) { try { await rpc(url, "eth_chainId"); up = true; } catch { await new Promise((r) => setTimeout(r, 100)); } }
    if (!up) { console.log("  SKIP anvil did not come up"); return; }

    const art = JSON.parse(await readFile(ARTIFACT, "utf8"));
    const provider = new ethers.JsonRpcProvider(url, undefined, { staticNetwork: true });
    const deployer = new ethers.Wallet(ANVIL_KEY_0, provider);
    const BOND = 10n ** 15n, UNBONDING = 60n;
    const factory = new ethers.ContractFactory(art.abi, art.bytecode.object, deployer);
    const c = await factory.deploy(BOND, UNBONDING, UNBONDING, ethers.ZeroAddress);
    await c.waitForDeployment();
    const reg = await c.getAddress();
    const ENV = { SHADE_TREE_RPC_URL: url, SHADE_TREE_GATEWAY_REGISTRY: reg };
    const isStaked = (a) => c.isStaked(a);
    const stakes = (a) => c.stakes(a);

    // register the operator with the existing command (anvil #1 default), then status
    const r = shadeTree(["register-gateway"], ENV);
    ok(r.code === 0 && (await isStaked(ANVIL_ADDR_1)) === true, "`shade-tree register-gateway` stakes anvil #1 (fixture)");
    const s0 = shadeTree(["gateway-status"], ENV);
    ok(s0.code === 0 && /state:\s+staked \(active\)/.test(s0.out) && s0.out.includes(`BOND:     ${BOND}`) && s0.out.includes(`UNBONDING: ${UNBONDING}`), "`shade-tree gateway-status` reads staked (active) + BOND/UNBONDING");
    ok(!s0.out.includes(KEY_1_HEX), "status never prints the key");
    const sOther = shadeTree(["gateway-status", "--operator", RCPT], { ...ENV, SHADE_TREE_REGISTER_KEY: "" });
    ok(sOther.code === 0 && /not staked/.test(sOther.out), "gateway-status --operator <unstaked> reports not staked");

    // withdraw before exit: refused (NotExiting), state unchanged
    const w0 = shadeTree(["withdraw-gateway"], ENV);
    ok(w0.code === 1 && /NotExiting/.test(w0.out) && (await isStaked(ANVIL_ADDR_1)) === true, "withdraw before exit is refused (NotExiting) and nothing changes");

    // exit --dry-run: simulate ok, no state change
    const ed = shadeTree(["exit-gateway", "--dry-run"], ENV);
    ok(ed.code === 0 && /simulate: ok/.test(ed.out) && /nothing broadcast/.test(ed.out), "exit --dry-run simulates ok and does not broadcast");
    ok((await isStaked(ANVIL_ADDR_1)) === true && (await stakes(ANVIL_ADDR_1)).exitInitiatedAt === 0n, "after exit --dry-run the operator is still active (no tx)");

    // exit for real: leaves the active set, withdrawableAt set
    const e1 = shadeTree(["exit-gateway"], ENV);
    const st1 = await stakes(ANVIL_ADDR_1);
    ok(e1.code === 0 && /mined in block/.test(e1.out) && /withdrawable at/.test(e1.out), "`shade-tree exit-gateway` mines initiateExit and reports withdrawableAt");
    ok((await isStaked(ANVIL_ADDR_1)) === false && st1.exitInitiatedAt !== 0n && st1.bond === BOND, "operator left the active set; bond still held (slashable)");
    ok(!e1.out.includes(KEY_1_HEX), "exit never prints the key");
    const wAt = st1.exitInitiatedAt + UNBONDING;
    ok(e1.out.includes(`withdrawable at ${wAt}`), "reported withdrawableAt == exitInitiatedAt + UNBONDING from the event");

    // exit again: no-op
    const e2 = shadeTree(["exit-gateway"], ENV);
    ok(e2.code === 0 && /already exiting/.test(e2.out), "second exit is a no-op (AlreadyExiting) with exit 0");

    // withdraw while bonded: refused with time left
    const w1 = shadeTree(["withdraw-gateway"], ENV);
    ok(w1.code === 1 && /StillBonded/.test(w1.out) && /s to go/.test(w1.out), "withdraw during UNBONDING is refused (StillBonded) and says how long");
    ok((await stakes(ANVIL_ADDR_1)).bond === BOND, "bond untouched by the refused withdraw");

    // warp past UNBONDING
    await rpc(url, "evm_increaseTime", [Number(UNBONDING) + 1]);
    await rpc(url, "evm_mine", []);
    const s1 = shadeTree(["gateway-status"], ENV);
    ok(/state:\s+exiting/.test(s1.out) && /NOW \(window elapsed\)/.test(s1.out), "status after the warp: exiting, withdrawable NOW");

    // withdraw --dry-run: simulate ok, balances unchanged
    const balBefore = await provider.getBalance(RCPT);
    const wd = shadeTree(["withdraw-gateway", "--dry-run", "--recipient", RCPT], ENV);
    ok(wd.code === 0 && /simulate: ok/.test(wd.out) && /nothing broadcast/.test(wd.out), "withdraw --dry-run simulates ok and does not broadcast");
    ok((await provider.getBalance(RCPT)) === balBefore && (await stakes(ANVIL_ADDR_1)).bond === BOND, "after withdraw --dry-run nothing moved");

    // withdraw for real via --key-file (signer path), paying --recipient exactly BOND
    const keyFile = join(work, "op.key");
    await writeFile(keyFile, ANVIL_KEY_1 + "\n", { mode: 0o600 });
    const w2 = shadeTree(["withdraw-gateway", "--recipient", RCPT, "--key-file", keyFile], { ...ENV, SHADE_TREE_REGISTER_KEY: "" });
    ok(w2.code === 0 && /paid to/.test(w2.out) && /--key-file/.test(w2.out), "`shade-tree withdraw-gateway --key-file` mines withdraw(recipient)");
    ok((await provider.getBalance(RCPT)) - balBefore === BOND, "recipient received exactly BOND");
    ok((await stakes(ANVIL_ADDR_1)).bond === 0n, "stake record cleared");
    ok(!w2.out.includes(KEY_1_HEX), "withdraw never prints the key (from --key-file)");

    // withdraw again: NotStaked
    const w3 = shadeTree(["withdraw-gateway"], ENV);
    ok(w3.code === 1 && /NotStaked/.test(w3.out), "withdraw after withdraw is refused (NotStaked)");
    const e3 = shadeTree(["exit-gateway"], ENV);
    ok(e3.code === 1 && /NotStaked/.test(e3.out), "exit when unstaked is refused (NotStaked)");

    // keystore signer path (Foundry-style encrypted JSON) with SHADE_TREE_KEYSTORE_PASSWORD; light scrypt for test speed
    const ksJson = await ethers.encryptKeystoreJson({ address: ANVIL_ADDR_1, privateKey: ANVIL_KEY_1 }, "hunter2", { scrypt: { N: 1 << 10 } });
    const ksPath = join(work, "op.keystore");
    await writeFile(ksPath, ksJson, { mode: 0o600 });
    const ks = shadeTree(["gateway-status", "--keystore", ksPath], { ...ENV, SHADE_TREE_KEYSTORE_PASSWORD: "hunter2", SHADE_TREE_REGISTER_KEY: "" });
    ok(ks.code === 0 && ks.out.includes(ANVIL_ADDR_1) && /--keystore/.test(ks.out), "--keystore decrypts with SHADE_TREE_KEYSTORE_PASSWORD and derives the operator address");
    const ksBad = shadeTree(["gateway-status", "--keystore", ksPath], { ...ENV, SHADE_TREE_KEYSTORE_PASSWORD: "wrong", SHADE_TREE_REGISTER_KEY: "" });
    ok(ksBad.code === 1 && /could not decrypt/.test(ksBad.out), "wrong keystore password => exit 1");
    const acct = shadeTree(["gateway-status", "--account", "op"], { ...ENV, SHADE_TREE_KEYSTORE_PASSWORD: "hunter2", FOUNDRY_KEYSTORES: work, SHADE_TREE_REGISTER_KEY: "" });
    ok(acct.code === 1 && /keystore not found/.test(acct.out), "--account <name> resolves under the keystores dir (missing name => not found)");
    await writeFile(join(work, "op"), ksJson, { mode: 0o600 });
    const acct2 = shadeTree(["gateway-status", "--account", "op"], { ...ENV, SHADE_TREE_KEYSTORE_PASSWORD: "hunter2", FOUNDRY_KEYSTORES: work, SHADE_TREE_REGISTER_KEY: "" });
    ok(acct2.code === 0 && acct2.out.includes(ANVIL_ADDR_1) && /--account op/.test(acct2.out), "--account op (FOUNDRY_KEYSTORES override) decrypts and derives the operator address");
    ok(!ks.out.includes(KEY_1_HEX) && !acct2.out.includes(KEY_1_HEX), "keystore paths never print the key");
  } finally {
    anvil.kill("SIGTERM");
    await rm(work, { recursive: true, force: true });
  }
}

async function main() {
  await part1();
  await part2();
  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: shade-tree exit-gateway selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
