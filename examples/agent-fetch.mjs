// Example: use the fleet WITHOUT the local client proxy — call ShadeTreeClient directly.
//
// This is the "Option A" client shape for your own code (e.g. a searxng-style agent doing
// many queries): no local proxy process, just a library call that proves and routes one tunnel.
// Each fetch mints a fresh RLN proof (fresh nullifier / slot) and rotates gateways.
//
// Prereqs:
//   - an enrolled member secret in SHADE_TREE_SECRET (or edit below),
//   - a running client Tor SOCKS (scripts/start-tor-client.sh -> 9260),
//   - a current v4 Elder Tree + its pinned Canopy signer,
//   - the operator-supplied tier and member source for that enrollment.
//
// Run:
//   SHADE_TREE_SECRET=0x… \
//   SHADE_TREE_BOOTNODE_ONION=<operator-supplied-v4-elder>.onion \
//   SHADE_TREE_DIR_SIGNER=<operator-supplied-64-hex-signer> \
//   SHADE_TREE_LIMIT=<operator-supplied-tier> \
//   SHADE_TREE_MEMBERS_FILE=<operator-supplied-members.json> \
//   SHADE_TREE_TOR_PORT=9260 \
//   node examples/agent-fetch.mjs  https://api.ipify.org  https://cloudflare.com/cdn-cgi/trace

import { ShadeTreeClient, cleanUp } from "../packages/node/client/shade-tree-client.mjs";

for (const name of ["SHADE_TREE_SECRET", "SHADE_TREE_BOOTNODE_ONION", "SHADE_TREE_DIR_SIGNER", "SHADE_TREE_LIMIT"]) {
  if (!process.env[name]) {
    console.error(`set ${name} from a current v4 operator profile; retired network records are not compatible`);
    process.exit(1);
  }
}
if (!process.env.SHADE_TREE_MEMBERS_FILE && !process.env.SHADE_TREE_GROUP_CONTRACT && !process.env.SHADE_TREE_PAID_ACCESS_CONTRACT) {
  console.error("set the operator-supplied member source: SHADE_TREE_MEMBERS_FILE, SHADE_TREE_GROUP_CONTRACT, or SHADE_TREE_PAID_ACCESS_CONTRACT");
  process.exit(1);
}

const urls = process.argv.slice(2);
if (!urls.length) urls.push("https://api.ipify.org");

const shadeTree = new ShadeTreeClient({
  // reads SHADE_TREE_SECRET / SHADE_TREE_DIRECTORY / SHADE_TREE_DIR_SIGNER / SHADE_TREE_TOR_PORT from env by
  // default; pass them explicitly here if you prefer.
});

for (const url of urls) {
  const t0 = Date.now();
  try {
    const res = await shadeTree.fetch(url);
    console.log(`GET ${url}  ->  ${res.status}  (${Date.now() - t0}ms)`);
    console.log(`     body: ${res.body.trim().slice(0, 120).replace(/\n/g, " ")}`);
  } catch (e) {
    console.log(`GET ${url}  ->  ERROR ${e.message}`);
  }
}

cleanUp(); // terminate snarkjs workers so the process exits
