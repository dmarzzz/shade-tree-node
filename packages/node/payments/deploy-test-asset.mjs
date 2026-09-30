// deploy-test-asset — put the EIP-3009 TEST stablecoin (test/Eip3009Token.sol, "Test USD"/tUSD,
// 6 decimals) on a testnet and mint it to buyer addresses, for fleets whose testnet has no faucet
// stablecoin at hand (Circle's Sepolia USDC faucet is captcha-gated). Real USDC is a one-env swap
// afterwards (SHADE_TREE_PAY_ASSET=0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238 on Sepolia; the registrar
// probes name()/version()/DOMAIN_SEPARATOR() and adapts). NOT for value.
//
//   SHADE_TREE_REGISTRAR_KEY=0x… SHADE_TREE_RPC_URL=https://… node packages/node/payments/deploy-test-asset.mjs [--mint <addr>=<units>]... [--asset <existing>]
//
// Prints the token address + tx hashes as JSON on stdout (never the key). Needs `forge build` first
// (reads out/Eip3009Token.sol/Eip3009Token.json).

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { ethers } from "ethers";
import { networkDefault } from "../lib/network-record.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ART = join(HERE, "../../..", "out", "Eip3009Token.sol", "Eip3009Token.json");

async function main() {
  const key = process.env.SHADE_TREE_REGISTRAR_KEY;
  if (!key) { console.error("SHADE_TREE_REGISTRAR_KEY (deployer/minter key) is required"); process.exit(1); }
  const rpc = process.env.SHADE_TREE_RPC_URL || networkDefault("SHADE_TREE_RPC_URL");
  if (!rpc) { console.error("SHADE_TREE_RPC_URL is required"); process.exit(1); }
  const argv = process.argv.slice(2);
  const mints = []; let asset = null; let name = "Test USD", symbol = "tUSD";
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--mint") { const [a, u] = String(argv[++i]).split("="); mints.push({ to: ethers.getAddress(a), units: BigInt(u) }); }
    else if (argv[i] === "--asset") asset = ethers.getAddress(argv[++i]);
    else if (argv[i] === "--name") name = argv[++i];
    else if (argv[i] === "--symbol") symbol = argv[++i];
    else { console.error(`unknown arg ${argv[i]}`); process.exit(2); }
  }
  const provider = new ethers.JsonRpcProvider(rpc);
  const wallet = new ethers.Wallet(key, provider);
  const out = { deployer: wallet.address, chainId: Number((await provider.getNetwork()).chainId), rpc, txs: {} };
  const art = JSON.parse(readFileSync(ART, "utf8"));
  let token;
  if (!asset) {
    const factory = new ethers.ContractFactory(art.abi, art.bytecode.object, wallet);
    console.error(`deploying Eip3009Token("${name}", "${symbol}", 6) from ${wallet.address}…`);
    token = await factory.deploy(name, symbol, 6);
    const rcpt = await token.deploymentTransaction().wait(1);
    out.asset = await token.getAddress(); out.deployTx = rcpt.hash; out.deployBlock = rcpt.blockNumber; out.deployGas = Number(rcpt.gasUsed);
    console.error(`  deployed ${out.asset} in block ${rcpt.blockNumber} (gas ${rcpt.gasUsed})`);
  } else {
    token = new ethers.Contract(asset, art.abi, wallet);
    out.asset = asset;
  }
  for (const m of mints) {
    const tx = await token.mint(m.to, m.units);
    const rcpt = await tx.wait(1);
    out.txs[`mint:${m.to}`] = rcpt.hash;
    console.error(`  minted ${m.units} to ${m.to}: ${rcpt.hash}`);
  }
  out.name = await token.name(); out.symbol = await token.symbol(); out.version = await token.version(); out.decimals = Number(await token.decimals());
  out.domainSeparator = await token.DOMAIN_SEPARATOR();
  console.log(JSON.stringify(out, null, 2));
}
main().catch((e) => { console.error("deploy-test-asset failed:", e.shortMessage || e.message); process.exit(1); });
