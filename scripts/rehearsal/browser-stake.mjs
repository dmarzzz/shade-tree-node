// M7 launch-gate line "stake from the browser", run for real against a Sepolia record:
// builds the Get access page from network/<name>/deployment.json, serves it locally, drives it
// in headless Chromium with a wallet backed by a funded key (the page sees a normal EIP-1193
// provider; signing happens here, in Node), saves the identity the page created, waits for the
// page's own finality countdown, then proves the seat works end to end with the Rust CLI:
// `shadenet fetch` through the canopy using the downloaded identity file.
//
//   node scripts/rehearsal/browser-stake.mjs --network sepolia-staging --key-file funded.key \
//        --shadenet /path/to/shadenet [--out DIR] [--tier 1] [--fetch-url https://api.ipify.org?format=json]
//
// Testnet only. The key file holds a Sepolia private key (hex, with or without 0x), owner-only.
import { chromium } from "@playwright/test";
import { JsonRpcProvider, Wallet } from "ethers";
import { spawn, spawnSync } from "node:child_process";
import { cpSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const args = parse(process.argv.slice(2));
const network = args.network || "sepolia-staging";
const record = JSON.parse(readFileSync(join(ROOT, "network", network, "deployment.json"), "utf8"));
const staked = record.admission.roots.staked;
const rpcUrl = args["rpc-url"] || staked.rpcUrl;
const tier = Number(args.tier || staked.defaultLimit || 1);
const out = resolve(args.out || join(ROOT, "cache", `browser-stake-${network}-${Date.now()}`));
const shadenetBin = args.shadenet || "shadenet";
const fetchUrl = args["fetch-url"] || "https://api.ipify.org?format=json";
const port = Number(args.port || 4189);
if (!args["key-file"]) die("--key-file is required (a funded Sepolia key; testnet only)");
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

// 2. Serve it.
const server = spawn(process.execPath, [join(ROOT, "scripts/serve-site.mjs")], {
  cwd: ROOT, env: { ...process.env, SITE_ROOT: join(siteOut, "docs", "post"), PORT: String(port) }, stdio: ["ignore", "pipe", "pipe"],
});
server.stderr.on("data", (d) => process.stderr.write(`[serve] ${d}`));
await waitFor(async () => (await fetch(`http://127.0.0.1:${port}/stake/`)).ok, 15_000, "site server");
step("serve", { url: `http://127.0.0.1:${port}/stake/` });

// 3. A real wallet: the page talks EIP-1193, Node signs with the funded key and forwards reads to the RPC.
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
const context = await browser.newContext({ acceptDownloads: true });
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
  await page.goto(`http://127.0.0.1:${port}/stake/`, { waitUntil: "networkidle" });
  step("open", { title: await page.title(), heading: (await page.locator("h1").first().textContent())?.trim() });

  // Create an identity in the tab, download it, confirm the save.
  if (tier !== Number(staked.defaultLimit || 1)) await page.locator(`[data-tier="${tier}"], input[name=tier][value="${tier}"]`).first().click();
  await page.getByRole("button", { name: "create identity" }).click();
  // The page shows the public commitment a sponsor would stake (for a ShadeNet set that is the
  // identity commitment, not the leaf); the identity file holds the leaf and the secret.
  const shown = (await page.locator("[data-leaf]").textContent({ timeout: 30_000 })).replace(/\D/g, "");
  if (!/^\d{70,80}$/.test(shown)) throw new Error(`no commitment on the page: ${shown}`);
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "download identity.json" }).click();
  const download = await downloadPromise;
  const identityPath = join(out, "identity.json");
  await download.saveAs(identityPath);
  const identity = JSON.parse(readFileSync(identityPath, "utf8"));
  if (!/^\d{70,80}$/.test(String(identity.leaf))) throw new Error("downloaded identity has no leaf");
  await page.locator("[data-recovery-check]").check();
  step("identity", { shownCommitment: shown, leaf: String(identity.leaf), limit: identity.limit, file: identityPath });

  // Connect the wallet and stake at the shown bond.
  await page.getByRole("button", { name: "connect wallet" }).first().click();
  await page.locator("[data-status]").filter({ hasText: /Wallet connected/ }).waitFor({ timeout: 60_000 });
  const stakeButton = page.getByRole("button", { name: /^stake [\d.]+ Sepolia ETH$/ });
  await stakeButton.waitFor({ state: "visible" });
  const label = (await stakeButton.textContent()).trim();
  await waitFor(async () => stakeButton.isEnabled(), 30_000, "stake button");
  await stakeButton.click();
  await page.locator("[data-status]").filter({ hasText: /Stake confirmed/ }).waitFor({ timeout: 10 * 60_000 });
  const receipt = await provider.getTransactionReceipt(sent[0].hash);
  step("stake", { button: label, tx: sent[0].hash, to: sent[0].to, value: sent[0].value, block: receipt?.blockNumber, status: receipt?.status });

  // The page's own finality countdown.
  await page.locator("[data-finality]").filter({ hasText: /Finalized/ }).waitFor({ timeout: 30 * 60_000 });
  step("finality", { text: (await page.locator("[data-finality]").textContent()).trim() });

  // Read status through the wallet, as a person would.
  const statusButton = page.getByRole("button", { name: /check status through my wallet/ });
  if (await statusButton.isEnabled()) {
    await statusButton.click();
    await page.locator("[data-status]").filter({ hasText: /Status read/ }).waitFor({ timeout: 60_000 });
    step("status-through-wallet", { text: (await page.locator("[data-status]").textContent()).trim() });
  }
  await page.screenshot({ path: join(out, "stake-finalized.png"), fullPage: true });

  // Hand-off: the same identity file works in the CLI, through the canopy, once nodes refresh the root.
  const recordPath = join(ROOT, "network", network, "deployment.json");
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
