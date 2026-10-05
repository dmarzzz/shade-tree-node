// M7 launch-gate line "stake from the browser", run for real against a Sepolia record, the way a
// member does it: `shadenet init` makes the identity on this machine, the Get access page takes
// only the public identity commitment (through the link fragment that a release's `init` prints,
// or the value this script reads from the identity file, never in the browser), a wallet backed by
// a funded key stakes it in headless Chromium (the page sees a normal EIP-1193 provider; signing
// happens here, in Node), the page's own finality countdown runs to "admitted", and the seat is
// proven end to end with the Rust CLI: `shadenet fetch` through the canopy with that identity.
//
//   node scripts/rehearsal/browser-stake.mjs --network sepolia --key-file funded.key \
//        --shadenet /path/to/shadenet [--out DIR] [--tier 8] [--fetch-url https://api.ipify.org?format=json]
//
// Testnet only. The key file holds a Sepolia private key (hex, with or without 0x), owner-only.
import { chromium } from "@playwright/test";
import { JsonRpcProvider, Wallet } from "ethers";
import { spawn, spawnSync } from "node:child_process";
import { cpSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { identityCommitmentOf, leafFromIdentityCommitment } from "../../packages/node/lib/identity-core.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const args = parse(process.argv.slice(2));
const network = args.network || "sepolia";
const recordPath = join(ROOT, "network", network, "deployment.json");
const record = JSON.parse(readFileSync(recordPath, "utf8"));
const staked = record.admission.roots.staked;
const rpcUrl = args["rpc-url"] || staked.rpcUrl;
const tier = Number(args.tier || staked.defaultLimit || 1);
const out = resolve(args.out || join(ROOT, "cache", `browser-stake-${network}-${Date.now()}`));
const shadenetBin = args.shadenet || "shadenet";
const fetchUrl = args["fetch-url"] || "https://api.ipify.org?format=json";
const port = Number(args.port || 4189);
if (!args["key-file"]) die("--key-file is required (a funded Sepolia key; testnet only)");
if (!staked.tiers.some((t) => Number(t.limit) === tier)) die(`tier ${tier} is not in the ${network} record`);
mkdirSync(out, { recursive: true });

const report = { network, contract: staked.contract, rpcUrl, tier, startedAt: new Date().toISOString(), steps: [] };
const step = (name, data) => { report.steps.push({ name, at: new Date().toISOString(), ...data }); console.log(`step ${name}:`, JSON.stringify(data)); };
const finish = (ok) => { report.ok = ok; report.finishedAt = new Date().toISOString(); writeFileSync(join(out, "report.json"), `${JSON.stringify(report, null, 2)}\n`); console.log(`report: ${join(out, "report.json")}`); };

// 1. Build the page from the record into a private tree (the committed site is untouched).
const siteOut = join(out, "site");
mkdirSync(join(siteOut, "docs"), { recursive: true });
cpSync(join(ROOT, "docs", "post"), join(siteOut, "docs", "post"), { recursive: true });
const built = spawnSync(process.execPath, [join(ROOT, "scripts/build-stake-site.mjs")], {
  cwd: ROOT, env: { ...process.env, SHADENET_SITE_NETWORK: network, SHADENET_SITE_OUT: siteOut }, encoding: "utf8",
});
if (built.status !== 0) die(`site build failed:\n${built.stdout}${built.stderr}`);
step("build", { network, siteOut, output: built.stdout.trim() });

// 2. The identity, made by the CLI on this machine. The secret stays in the file; the page gets
// the identity commitment. A release whose `init` prints the Get access link prints exactly this.
const shadenetDir = join(out, "shadenet");
const init = spawnSync(shadenetBin, ["--network", recordPath, "init", "--dir", shadenetDir, "--limit", String(tier), "--offline", "--json"], { encoding: "utf8" });
if (init.status !== 0) die(`shadenet init failed (${init.status}):\n${init.stdout}${init.stderr}`);
const identityPath = join(shadenetDir, "identity.json");
const identity = JSON.parse(readFileSync(identityPath, "utf8"));
if (!/^\d{70,80}$/.test(String(identity.leaf)) || !identity.identitySecret) die("shadenet init wrote no usable identity file");
const printed = JSON.parse(init.stdout);
const commitment = printed.identityCommitment ? String(printed.identityCommitment) : identityCommitmentOf(identity.identitySecret).toString();
const leaf = leafFromIdentityCommitment(commitment, tier).toString();
if (leaf !== String(identity.leaf)) die(`the identity file's leaf is not Poseidon2(identityCommitment, ${tier}); the file was made for another tier`);
step("identity", { file: identityPath, identityCommitment: commitment, leaf, limit: identity.limit, commitmentPrintedByInit: Boolean(printed.identityCommitment) });

// 3. Serve the page.
const server = spawn(process.execPath, [join(ROOT, "scripts/serve-site.mjs")], {
  cwd: ROOT, env: { ...process.env, SITE_ROOT: join(siteOut, "docs", "post"), PORT: String(port) }, stdio: ["ignore", "pipe", "pipe"],
});
server.stderr.on("data", (d) => process.stderr.write(`[serve] ${d}`));
await waitFor(async () => (await fetch(`http://127.0.0.1:${port}/stake/`)).ok, 15_000, "site server");
const link = `http://127.0.0.1:${port}/stake/#c=${commitment}&limit=${tier}&leaf=${leaf}`;
step("serve", { url: `http://127.0.0.1:${port}/stake/`, link });

// 4. A real wallet: the page talks EIP-1193, Node signs with the funded key and forwards reads to the RPC.
const provider = new JsonRpcProvider(rpcUrl, undefined, { staticNetwork: true, cacheTimeout: -1 });
const key = readFileSync(args["key-file"], "utf8").trim().replace(/^0x/, "");
const wallet = new Wallet(`0x${key}`, provider);
const sent = [];
async function walletRpc(method, params) {
  switch (method) {
    case "eth_requestAccounts":
    case "eth_accounts":
      return [wallet.address];
    case "eth_chainId":
      return `0x${(await provider.getNetwork()).chainId.toString(16)}`;
    case "wallet_switchEthereumChain":
    case "wallet_addEthereumChain":
      return null;
    case "eth_sendTransaction": {
      const tx = params[0];
      const response = await wallet.sendTransaction({ to: tx.to, data: tx.data, value: tx.value ? BigInt(tx.value) : 0n, gasLimit: tx.gas ? BigInt(tx.gas) : undefined });
      sent.push({ hash: response.hash, to: tx.to, value: tx.value, data: tx.data });
      return response.hash;
    }
    default:
      return provider.send(method, params);
  }
}

const browser = await chromium.launch();
const context = await browser.newContext();
const page = await context.newPage();
page.on("pageerror", (e) => console.error("[page error]", e.message));
await page.exposeFunction("__shadenetWalletRpc", (method, params) => walletRpc(method, params ?? []));
await page.addInitScript(() => {
  /* global window */
  window.ethereum = {
    isShadeNetRehearsalWallet: true,
    on() {},
    removeListener() {},
    request: ({ method, params }) => window.__shadenetWalletRpc(method, params ?? []),
  };
});

let ok = false;
try {
  // The link opens step 2 with the commitment filled in and checked against its leaf.
  await page.goto(link, { waitUntil: "networkidle" });
  await page.locator('[data-panel="stake"]:not([hidden])').waitFor({ timeout: 30_000 });
  const shown = (await page.locator("[data-commitment-shown]").textContent()).trim();
  if (!shown.startsWith(commitment.slice(0, 10)) || !shown.endsWith(commitment.slice(-8))) throw new Error(`the page shows another commitment: ${shown}`);
  step("open", { title: await page.title(), shown });

  // Connect the wallet, then stake at the shown bond. One button carries both actions.
  const primary = page.locator("[data-primary]");
  await primary.click();
  const stakeLabel = new RegExp(`^Stake [\\d.]+ Sepolia ETH$`);
  await primary.filter({ hasText: stakeLabel }).waitFor({ timeout: 60_000 });
  const label = (await primary.textContent()).trim();
  await primary.click();
  await page.locator("[data-status]").filter({ hasText: /Stake confirmed/ }).waitFor({ timeout: 10 * 60_000 });
  const receipt = await provider.getTransactionReceipt(sent[0].hash);
  step("stake", { button: label, tx: sent[0].hash, to: sent[0].to, value: sent[0].value, block: receipt?.blockNumber, status: receipt?.status });

  // The page's own finality countdown, then its admitted check against the contract.
  await page.locator("[data-member-state]").filter({ hasText: /Admitted/ }).waitFor({ timeout: 30 * 60_000 });
  step("admitted", { text: (await page.locator("[data-member-state]").textContent()).trim() });
  await page.screenshot({ path: join(out, "stake-admitted.png") });
  await page.locator('[data-panel="stake"] [data-next-start]').click();
  step("start", { text: (await page.locator("[data-start-state]").textContent()).trim() });

  // Hand-off: the identity the CLI made works through the canopy once nodes refresh the root.
  const member = spawnSync(shadenetBin, ["--network", recordPath, "member-status", "--identity", identityPath, "--json"], { encoding: "utf8" });
  step("member-status", { exit: member.status, out: member.stdout.trim().slice(0, 600), err: member.stderr.trim().slice(0, 300) });
  let fetched = null;
  const deadline = Date.now() + 6 * 60_000;
  while (Date.now() < deadline) {
    const r = spawnSync(shadenetBin, ["--network", recordPath, "fetch", "--identity", identityPath, fetchUrl], { encoding: "utf8", timeout: 180_000 });
    fetched = { exit: r.status, out: r.stdout.trim().slice(0, 400), err: r.stderr.trim().split("\n").slice(-3).join("\n").slice(0, 600) };
    if (r.status === 0) break;
    await new Promise((res) => setTimeout(res, 20_000));
  }
  step("fetch-through-canopy", fetched);
  ok = fetched?.exit === 0;
} catch (error) {
  report.error = error.message;
  await page.screenshot({ path: join(out, "failure.png"), fullPage: true }).catch(() => {});
  console.error(`browser stake failed: ${error.message}`);
} finally {
  await browser.close();
  server.kill();
  finish(ok);
  process.exit(ok ? 0 : 1);
}

function parse(argv) {
  const o = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith("--")) { const k = argv[i].slice(2); const v = argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[++i] : true; o[k] = v; }
  }
  return o;
}
function die(msg) { console.error(msg); process.exit(2); }
async function waitFor(fn, ms, what) {
  const until = Date.now() + ms;
  while (Date.now() < until) { try { if (await fn()) return; } catch {} await new Promise((r) => setTimeout(r, 500)); }
  throw new Error(`timed out waiting for ${what}`);
}
