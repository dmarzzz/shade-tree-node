// shade-tree-node doctor — a quick local health check. Confirms the environment can run the pieces
// before you try to, and points at the fix when something is missing. Read-only.

import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import net from "node:net";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const run = promisify(execFile);

let warn = 0, bad = 0;
const okLine = (m) => console.log(`  ok   ${m}`);
const warnLine = (m) => { console.log(`  warn ${m}`); warn++; };
const badLine = (m) => { console.log(`  FAIL ${m}`); bad++; };

async function has(cmd, args = ["--version"]) {
  try { const { stdout } = await run(cmd, args); return stdout.trim().split("\n")[0]; } catch { return null; }
}
function portOpen(host, port, timeout = 500) {
  return new Promise((resolve) => {
    const s = net.connect({ host, port });
    const done = (v) => { try { s.destroy(); } catch {} resolve(v); };
    s.once("connect", () => done(true));
    s.once("error", () => done(false));
    setTimeout(() => done(false), timeout);
  });
}

console.log("shade-tree-node doctor\n");

// node
const major = Number(process.versions.node.split(".")[0]);
major >= 20 ? okLine(`node ${process.versions.node}`) : badLine(`node ${process.versions.node} (need >= 20; see package.json engines)`);

// deps
existsSync(join(ROOT, "node_modules", "socks")) && existsSync(join(ROOT, "node_modules", "@semaphore-protocol"))
  ? okLine("node_modules present (socks, @semaphore-protocol)")
  : badLine("dependencies missing — run `npm install`");
existsSync(join(ROOT, "node_modules", "ethers")) ? okLine("ethers present (on-chain stake/slash)") : warnLine("ethers missing — on-chain register/slash/verify degrade to dry-run");

// tor
const tor = await has("tor", ["--version"]);
tor ? okLine(tor) : warnLine("tor not on PATH — the gateway/bootnode/client need a Tor daemon (see docs/QUICKSTART.md)");
const torHost = process.env.SHADE_TREE_TOR_HOST || "127.0.0.1";
const explicitTorPort = process.env.SHADE_TREE_TOR_PORT;
const torPorts = explicitTorPort ? [Number(explicitTorPort)] : [9250, 9050, 9150, 9260];
let reachableTorPort = null;
for (const port of torPorts) {
  if (await portOpen(torHost, port)) { reachableTorPort = port; break; }
}
reachableTorPort
  ? okLine(`Tor SOCKS reachable at ${torHost}:${reachableTorPort}`)
  : warnLine(`no Tor SOCKS at ${torHost}:${torPorts.join(",")} (start Tor, or set SHADE_TREE_TOR_PORT)`);

// foundry (only needed to deploy/test the contracts)
const forge = await has("forge", ["--version"]);
forge ? okLine(forge) : warnLine("forge not on PATH — only needed to build/deploy the contracts");

// onion identity
existsSync(join(ROOT, "tor", "hs", "identity.local.json"))
  ? okLine("gateway onion identity present (tor/hs/identity.local.json)")
  : warnLine("no onion identity yet — run `shade-tree-node keygen tor/hs` before announcing to a bootnode");

// deployed contracts
existsSync(join(ROOT, "contracts", "deployed.local.json"))
  ? okLine("contracts/deployed.local.json present (on-chain mode configured)")
  : warnLine("no deployed.local.json — running in members.json / mock-stake mode (fine for local dev)");

console.log(`\n${bad ? "issues found" : "ready"}: ${bad} failure(s), ${warn} warning(s)`);
process.exit(bad ? 1 : 0);
