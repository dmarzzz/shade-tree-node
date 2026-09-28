// join — the guided front door. One command that walks a new participant through
// joining the fleet, in whichever role they play:
//
//   node group/join.mjs [member] [label]   -> become a MEMBER: self-enroll an identity,
//                                             print the bearer secret + commitment, and the
//                                             EXACT next commands (optional on-chain stake,
//                                             then `shade-tree proxy ...`).
//   node group/join.mjs node [hsDir]       -> become a SHADE TREE NODE operator: mint an
//                                             onion identity and print the EXACT next commands
//                                             (optional stake, then `shade-tree-node node` + heartbeat).
//   node group/join.mjs gateway [hsDir]    -> compatibility alias for `node`.
//
// This composes the EXISTING flows — it never reimplements crypto. The member path spawns
// `group/enroll.mjs --commitment-only` (the real self-enrollment; the secret is generated on
// THIS machine and never leaves it) and reformats its output into a scripted guide. The gateway
// path calls generateOnionIdentity() from bootnode/keygen.mjs.
//
// Stream contract (mirrors enroll's commitment-only mode, so the secret is never captured by a
// pipe or scrolled into a shared log):
//   stdout -> the human guide: role banner, commitment/onion, and numbered copy-paste next steps.
//   stderr -> the bearer SECRET value with its "keep this local" note and a hidden-read command.
// The Proxy command reads SHADE_TREE_SECRET from the environment and never embeds the raw hex,
// so stdout carries no secret material.

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { generateOnionIdentity } from "../bootnode/keygen.mjs";
import { K_SLOTS, normLimit, identityFor, identityCommitmentOf } from "../lib/rln.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ENROLL = join(HERE, "enroll.mjs");

const args = process.argv.slice(2);
let limitArg = process.env.SHADE_TREE_LIMIT;
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--limit") { limitArg = args[i + 1]; args.splice(i, 2); break; }
  if (args[i].startsWith("--limit=")) { limitArg = args[i].slice("--limit=".length); args.splice(i, 1); break; }
}
let memberLimit;
try { memberLimit = Number(normLimit(limitArg ?? K_SLOTS)); }
catch (error) { process.stderr.write(`join: --${error.message}\n`); process.exit(2); }
const positionals = args.filter((a) => !a.startsWith("--"));
const mode = ["node", "gateway"].includes(positionals[0]) ? "node" : "member";

const out = (s = "") => process.stdout.write(s + "\n");
const err = (s = "") => process.stderr.write(s + "\n");

const SECRET_RE = /secret value:\s*(0x[0-9a-fA-F]{64})/i;

function joinMember() {
  // The role is MEMBER when positionals[0] is "member" or absent. An optional local-only label
  // is handed straight to enroll: the token after "member", or a lone token that isn't a role.
  const label = positionals[0] === "member" ? positionals[1] : positionals[0];
  const enrollArgs = ["--commitment-only", "--limit", String(memberLimit), ...(label ? [label] : [])];

  // Compose the REAL self-enrollment: commitment on the child's stdout, secret on its stderr.
  const r = spawnSync(process.execPath, [ENROLL, ...enrollArgs], { encoding: "utf8", timeout: 60_000 });
  if (r.error) throw r.error;
  if (r.status !== 0) {
    process.stderr.write(r.stderr || "enroll failed\n");
    process.exit(r.status || 1);
  }
  const commitment = (r.stdout || "").trim().split(/\s+/)[0];
  const secret = (r.stderr.match(SECRET_RE) || [])[1];
  if (!commitment || !secret) {
    process.stderr.write("join: could not read commitment/secret from enroll\n" + (r.stderr || ""));
    process.exit(1);
  }

  // --- the guide (stdout) ---------------------------------------------------
  out("shade-tree-node join — you are joining as a MEMBER of the reputation set.");
  out("You generated this identity locally; only the commitment ever leaves this machine.");
  out("");
  out("  commitment:   " + commitment + "   (public; hand this to the operator or stake it on chain)");
  out("  tier limit:   " + memberLimit + "   (the Proxy must use this same per-epoch limit)");
  out("");
  out("Next steps:");
  out("");
  out("  1. Keep your secret (printed on stderr below). It is a BEARER credential: whoever holds");
  out("     it can egress as you until the set is rotated. Load it without shell history:");
  out("");
  out("       read -s SHADE_TREE_SECRET && export SHADE_TREE_SECRET");
  out("       # paste only the exact secret value from stderr at the hidden prompt");
  out("");
  out("  2. Load the Elder Tree onion and its Canopy signer from the same Grove operator:");
  out("");
  out("       read -r SHADE_TREE_BOOTNODE_ONION && export SHADE_TREE_BOOTNODE_ONION");
  out("       read -r SHADE_TREE_DIR_SIGNER && export SHADE_TREE_DIR_SIGNER");
  out("");
  out("  3a. Invited access: load the operator's member-list path, then run the Proxy:");
  out("");
  out("       read -r SHADE_TREE_MEMBERS_FILE && export SHADE_TREE_MEMBERS_FILE");
  out("       shade-tree proxy --limit " + memberLimit + " --leaf-source invited");
  out("");
  out("  3b. Staked access: load the operator's RPC and staked-set address, then fund the");
  out("      registration key through a hidden prompt for this one transaction only:");
  out("");
  out("       read -r SHADE_TREE_RPC_URL && export SHADE_TREE_RPC_URL");
  out("       read -r SHADE_TREE_GROUP_CONTRACT && export SHADE_TREE_GROUP_CONTRACT");
  out("       read -s SHADE_TREE_REGISTER_KEY");
  out("       SHADE_TREE_REGISTER_KEY=\"$SHADE_TREE_REGISTER_KEY\" shade-tree register-member " + identityCommitmentOf(identityFor(secret)).toString() + " --limit " + memberLimit);
  out("       unset SHADE_TREE_REGISTER_KEY");
  out("       shade-tree proxy --limit " + memberLimit + " --leaf-source staked");
  out("");
  out("     Paid access has a separate buying step: docs/PAYMENTS.md.");

  // --- the secret (stderr; never on stdout) ---------------------------------
  err("");
  err("Keep THIS SECRET private — it stays on your machine and the operator never sees it:");
  err("");
  err("  secret value: " + secret);
  err("");
  err("Load it without putting the value in shell history:");
  err("  read -s SHADE_TREE_SECRET && export SHADE_TREE_SECRET");
  err("  export SHADE_TREE_LIMIT=" + memberLimit);
  err("");
  process.exit(0);
}

async function joinNode() {
  // hsDir: positional after "node" / legacy "gateway", else env override (tests), else the repo default.
  const hsDir = positionals[1] || process.env.SHADE_TREE_JOIN_HSDIR || "tor/hs-gateway";
  const force = args.includes("--force");
  const id = await generateOnionIdentity(hsDir, { label: "gateway", force });

  out("shade-tree-node join: you are joining as a SHADE TREE NODE operator.");
  out("Minted a fresh onion identity that Tor can publish and this node can use to sign announcements.");
  out("");
  out("  onion:        " + id.onion);
  out("  hsDir:        " + id.dir + "   (point Tor's HiddenServiceDir here)");
  out("  identity:     " + join(id.dir, "identity.local.json") + "   (announce-signing seed; keep secret)");
  out("");
  out("SAFETY: disposable research only. Do not use real funds or sensitive traffic.");
  out("The private-target guard is closed. Public rollout remains blocked by issue #6");
  out("(untrusted development Groth16 artifacts) and the other deployment gates.");
  out("");
  out("Next steps:");
  out("");
  out("  1. (optional) Stake a gateway operator bond. Load the public chain profile, then");
  out("     keep the funded operator key out of argv and shell history:");
  out("");
  out("       read -r SHADE_TREE_RPC_URL && export SHADE_TREE_RPC_URL");
  out("       read -r SHADE_TREE_GATEWAY_REGISTRY && export SHADE_TREE_GATEWAY_REGISTRY");
  out("       read -s SHADE_TREE_REGISTER_KEY");
  out("       SHADE_TREE_REGISTER_KEY=\"$SHADE_TREE_REGISTER_KEY\" shade-tree register-gateway");
  out("       unset SHADE_TREE_REGISTER_KEY");
  out("");
  out("  2. Run the egress gateway (verifies member proofs, tunnels :443):");
  out("");
  out("       shade-tree-node node");
  out("");
  out("  3. Announce it to an Elder Tree and keep it live:");
  out("");
  out("       shade-tree-node heartbeat --bootnode <elder-onion> \\");
  out("         --identity " + join(id.dir, "identity.local.json"));
  out("");
  out("     (get <elder-onion> from the Grove operator; its Canopy signer is the pin Proxies need.)");

  // The announce-signing seed lives in identity.local.json (mode 0600); flag it on stderr so a
  // piped/logged stdout never implies the seed itself is safe to share.
  err("");
  err("Keep the announce-signing seed private: " + join(id.dir, "identity.local.json"));
  err("");
  process.exit(0);
}

if (mode === "node") {
  try {
    await joinNode();
  } catch (error) {
    err(`shade-tree-node join node: ${error.message}`);
    process.exit(1);
  }
} else {
  joinMember();
}
