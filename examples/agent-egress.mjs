// Example: an AI agent (or any of your own code) egressing through a Grove with no
// local Proxy process; this is the direct-library style. Public docs call the local protocol
// client the Proxy, an egress gateway a Shade Tree node, and the discovery bootnode the Elder
// Tree. Environment variables and response fields retain their protocol names.
//
// It constructs a ShadeTreeClient from env, does one HTTPS fetch to an echo-IP service, and
// prints the egress IP. That IP belongs to the selected node, not this machine. The client
// opens a Tor onion connection carrying an RLN membership proof. The node application sees
// the target and traffic metadata, but TLS content stays encrypted end to end.
//
// NOTE: a fetch requires current v4 admission plus an Elder Tree announcing at least one
// reachable node, and a local Tor SOCKS port. The checked-in Sepolia records are retired
// pre-v4 history, not runnable configuration. Obtain current values from an operator or run
// the local loop in docs/QUICKSTART.md.
//
// Prereqs (all from env; flags on `shade-tree proxy` map to these same vars):
//   SHADE_TREE_SECRET          an enrolled member secret     (`shade-tree enroll`)
//   SHADE_TREE_BOOTNODE_ONION  the Elder Tree's Tor v3 onion  (signed Canopy over Tor)
//   SHADE_TREE_DIR_SIGNER      its pinned Canopy signer pubkey
//   SHADE_TREE_TOR_PORT        local Tor SOCKS port            (optional; default 9250,
//                                                          bundled helper is 9260)
//
// Run:
//   SHADE_TREE_SECRET=0x… \
//   SHADE_TREE_BOOTNODE_ONION=<56-char>.onion \
//   SHADE_TREE_DIR_SIGNER=<canopy-signer-pubkey> \
//   node examples/agent-egress.mjs

import { ShadeTreeClient, cleanUp } from "../packages/node/client/shade-tree-client.mjs";

for (const v of ["SHADE_TREE_SECRET", "SHADE_TREE_BOOTNODE_ONION", "SHADE_TREE_DIR_SIGNER"]) {
  if (!process.env[v]) {
    console.error(`set ${v} (see the header of this file / docs/ADAPTERS.md)`);
    process.exit(1);
  }
}

// Reads SHADE_TREE_SECRET / SHADE_TREE_BOOTNODE_ONION / SHADE_TREE_DIR_SIGNER / SHADE_TREE_TOR_PORT from env.
// SHADE_TREE_BOOTNODE_ONION selects Elder Tree discovery: the client pulls the signed
// Canopy over Tor, verifies it against SHADE_TREE_DIR_SIGNER, and selects a node per tunnel.
const shadeTree = new ShadeTreeClient();

try {
  const t0 = Date.now();
  // Each direct-library fetch opens a fresh tunnel, mints a fresh proof, and picks a possibly
  // different node. Proxy integrations select when their HTTP client opens a new CONNECT tunnel.
  const res = await shadeTree.fetch("https://api.ipify.org?format=json");
  const egressIp = JSON.parse(res.body).ip;
  const via = res.gateway?.onion ? `${String(res.gateway.onion).slice(0, 16)}..onion` : "node";
  console.log(`egress IP: ${egressIp}   (via ${via}, ${Date.now() - t0}ms)`);
  console.log("that is the node's IP; its application received the Tor-side connection.");
} catch (e) {
  console.error(`fetch failed: ${e.message}`);
  console.error("do you have current v4 admission, an Elder Tree with a reachable node, and local Tor? See docs/QUICKSTART.md");
  process.exitCode = 1;
} finally {
  cleanUp(); // terminate snarkjs workers so the process exits
}
