// leaves — export an on-chain set's ORDERED leaves as a members.json (T-FEAT-7): the bridge for
// the Rust client, whose `shade-tree egress --members <f>` reads only the static `{ version, members[] }`
// file. A StakedReputationSet / PaidAccessSet keeps its tree on chain and in its event log; this
// rebuilds it exactly as the gateway does (lib/root-provider.mjs reconstructGroup: append at the
// contract's index, ZERO IN PLACE on slash/exit) and writes the leaf array INCLUDING the in-place
// zeros, so the Rust tree (crates/shadenet-rln, same zero value) reproduces the on-chain root.
//
// Usage:
//   shade-tree leaves --contract <addr> [--out <path>] [--rpc-url <url>] [--from-block <hex|dec>]
//   shade-tree leaves --contract 0xPaid --out members.json && shade-tree egress --members members.json …
//
// stdout = the JSON only (redirectable); stderr = a summary (root, live count). Contract default:
// SHADE_TREE_PAID_ACCESS_CONTRACT, else the first SHADE_TREE_GROUP_CONTRACT. Nothing secret is involved.

import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { loadGroupFromContract, parseContractList } from "../lib/root-provider.mjs";

const USAGE = "usage: shade-tree leaves --contract <addr> [--out <path>] [--from-block <n>]   (rpc: SHADE_TREE_RPC_URL / --rpc-url)";

export function parseArgs(argv) {
  const opts = { contract: null, out: null, fromBlock: null };
  const withValue = { contract: "contract", out: "out", "from-block": "fromBlock" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") { console.log(USAGE); process.exit(0); }
    if (!a.startsWith("--")) { console.error(`leaves: unexpected argument ${a}\n${USAGE}`); process.exit(2); }
    const eq = a.indexOf("=");
    const key = eq === -1 ? a.slice(2) : a.slice(2, eq);
    if (!(key in withValue)) { console.error(`leaves: unknown flag --${key}\n${USAGE}`); process.exit(2); }
    const val = eq === -1 ? argv[++i] : a.slice(eq + 1);
    if (val === undefined || val === "" || val.startsWith("--")) { console.error(`leaves: --${key} needs a value\n${USAGE}`); process.exit(2); }
    opts[withValue[key]] = val;
  }
  return opts;
}

// The members.json document for a reconstructed group: version 2, ordered leaves incl. zeros.
export function membersFileFor(group) {
  return { version: 2, members: group.members.map(String) };
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const contract = opts.contract || process.env.SHADE_TREE_PAID_ACCESS_CONTRACT || parseContractList(process.env.SHADE_TREE_GROUP_CONTRACT)[0] || null;
  if (!contract) { console.error("leaves: no contract — pass --contract 0x.. (or set SHADE_TREE_PAID_ACCESS_CONTRACT / SHADE_TREE_GROUP_CONTRACT)"); process.exit(1); }
  if (!/^0x[0-9a-fA-F]{40}$/.test(contract)) { console.error(`leaves: not an address: ${contract}`); process.exit(1); }
  const rpcUrl = process.env.SHADE_TREE_RPC_URL || "http://127.0.0.1:8545";
  let fromBlock;
  if (opts.fromBlock != null) fromBlock = /^0x/i.test(opts.fromBlock) ? opts.fromBlock : "0x" + BigInt(opts.fromBlock).toString(16);
  else if (process.env.SHADE_TREE_FROM_BLOCK) fromBlock = process.env.SHADE_TREE_FROM_BLOCK;
  let r;
  try { r = await loadGroupFromContract({ contract, rpcUrl, ...(fromBlock ? { fromBlock } : {}) }); }
  catch (e) { console.error(`leaves: cannot read ${contract} via ${rpcUrl}: ${e.message}`); process.exit(1); }
  const doc = membersFileFor(r.group);
  const bytes = JSON.stringify(doc, null, 2) + "\n";
  console.error(`shade-tree leaves — ${contract}: ${r.count} live leaves in ${doc.members.length} slots; root ${r.root || "(empty)"}`);
  if (opts.out) {
    const out = resolve(opts.out);
    writeFileSync(out, bytes);
    console.error(`  wrote:  ${out}   (members.json shape; feed it to \`shade-tree egress --members\`)`);
  } else {
    process.stdout.write(bytes);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => { console.error("leaves failed:", e.message); process.exit(1); });
}
