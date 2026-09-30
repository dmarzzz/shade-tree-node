// Self-enrollment: a MEMBER admits itself to the reputation set.
//
// This is the honesty fix for adversarial-review finding #1: the operator must
// stop holding member secrets. So THIS TOOL IS RUN BY THE MEMBER, not the
// operator. The member generates its own Identity locally, keeps the secret, and
// the ONLY value that ever leaves the machine is the commitment. The operator (or
// the on-chain StakedReputationSet) admits the commitment; it never sees, stores,
// or generates the secret. That is what "self-enrollment" means, and it is the
// difference between "the operator can impersonate every member" and "the operator
// can impersonate no one."
//
// Usage (run by the member):
//   node group/enroll.mjs                 -> new identity; print secret + commitment,
//                                            and seed the local demo set (group/members.json)
//   node group/enroll.mjs <label>         -> label the member (local only, never in the set)
//   node group/enroll.mjs --commitment-only [label]
//                                         -> print ONLY the commitment on stdout (secret +
//                                            guidance to stderr); do NOT touch members.json.
//                                            Pipe/hand the commitment to the operator, or:
//                                            node group/register-onchain.mjs <commitment> --limit <n>
//   node group/enroll.mjs --limit 32 ...  -> enrol at a reputation TIER (T-FEAT-8): the leaf
//                                            commits to userMessageLimit=32 instead of the
//                                            default K (8). The member must then run its client
//                                            with the SAME limit (SHADE_TREE_LIMIT=32 / identity file
//                                            `limit`) — a leaf carries exactly one tier. Whether
//                                            a member MAY hold a tier is the operator's / the
//                                            contract's admission call (docs/adr/0006).
//
// The secret is a bearer credential. Whoever holds it can egress as this member
// until the set is rotated. It is printed here for the MEMBER to keep and is never
// persisted by this tool.

import { readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { identityFor, identityCommitmentOf, rateCommitmentOf, MEMBERS_PATH, loadGroup, K_SLOTS, normLimit } from "../packages/node/lib/rln.mjs";

const args = process.argv.slice(2);
const commitmentOnly = args.includes("--commitment-only") || args.includes("--no-local");
// --limit <n> | --limit=<n>: the tier limit baked into the leaf (default K_SLOTS). Validated
// (1..MAX_LIMIT) before anything is derived; the value is consumed so it is never mistaken for
// the label.
let limitArg = null;
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--limit") { limitArg = args[i + 1]; args.splice(i, 2); break; }
  if (args[i].startsWith("--limit=")) { limitArg = args[i].slice("--limit=".length); args.splice(i, 1); break; }
}
let limit;
try { limit = Number(normLimit(limitArg ?? process.env.SHADE_TREE_LIMIT ?? K_SLOTS)); }
catch (e) { console.error("enroll: --" + e.message); process.exit(2); }
const label = args.find((a) => !a.startsWith("--")) || "member-" + randomBytes(2).toString("hex");

// The identity is generated HERE, on the member's machine. The secret never leaves.
// 0x-hex so the lib's toField() parses it as a field element; identityFor(secret) is the
// SAME derivation proveForSlot uses. The published leaf is the RLN rateCommitment
// (Poseidon2(Poseidon1(identitySecret), K)) — the exact leaf the gateway verifies proofs
// against AND the leaf the on-chain slash names (a reconstructed identitySecret ->
// deriveCommitment() lands here). One coherent leaf, no scheme flag.
const secret = "0x" + randomBytes(32).toString("hex");
const commitment = rateCommitmentOf(identityFor(secret), limit).toString();
// What the staking contract takes: it derives the leaf above from this and the tier.
const identityCommitment = identityCommitmentOf(identityFor(secret)).toString();
const tierNote = limit === K_SLOTS ? "" : `   (tier limit ${limit}: run the client with SHADE_TREE_LIMIT=${limit})`;

function printRegistrationGuide(write) {
  write("To stake this identity on the bundled public Sepolia Grove, load a funded key");
  write("without putting the key in argv or shell history (contract/RPC/tier come from the record):");
  write("  read -s SHADE_TREE_REGISTER_KEY");
  write(`  SHADE_TREE_REGISTER_KEY="$SHADE_TREE_REGISTER_KEY" shade-tree register-member ${identityCommitment} --limit ${limit}`);
  write("  unset SHADE_TREE_REGISTER_KEY");
  write("");
  write("For another Grove, explicitly supply its network/contract, RPC, and matching tier.");
}

if (commitmentOnly) {
  // Machine path: stdout is the commitment alone, so it can be piped straight to
  // the on-chain register or handed to the operator. The secret goes to stderr so
  // it is visible to the human running this but never captured by a pipe.
  process.stderr.write("Self-enrollment (commitment-only). Keep this secret PRIVATE; it never leaves your machine:\n");
  process.stderr.write("\n  secret value: " + secret + "\n");
  process.stderr.write("\nLoad it without putting the value in shell history:\n");
  process.stderr.write("  read -s SHADE_TREE_SECRET && export SHADE_TREE_SECRET\n");
  if (limit !== K_SLOTS) process.stderr.write("  export SHADE_TREE_LIMIT=" + limit + "   (this leaf's tier; the client must prove with it)\n");
  process.stderr.write("\nSubmit the commitment below (stdout) to the operator, or stake it on chain.\n\n");
  printRegistrationGuide((line) => process.stderr.write(line + "\n"));
  process.stderr.write("\n");
  process.stdout.write(commitment + "\n");
  process.exit(0);
}

// Local demo path: seed the commitment into the PoC set so the whole thing stays
// runnable without a chain. Only the COMMITMENT is written; the secret is not.
let doc = { version: 2, members: [] };
if (existsSync(MEMBERS_PATH)) doc = JSON.parse(await readFile(MEMBERS_PATH, "utf8"));
if (!doc.members.includes(commitment)) doc.members.push(commitment);
await writeFile(MEMBERS_PATH, JSON.stringify(doc, null, 2) + "\n");

const { root, count } = await loadGroup();

console.log("Self-enrolled a member (you generated the identity; only the commitment left this machine).");
console.log("  label:        " + label + "   (local only, never enters the set)");
console.log("  commitment:   " + commitment + "   (public leaf; added to the set)");
console.log("  identity commitment: " + identityCommitment + "   (public; stake this on chain)");
console.log("  tier limit:   " + limit + (limit === K_SLOTS ? "   (default K)" : "   (per-epoch budget baked into the leaf)") + tierNote);
console.log("  set size:     " + count);
console.log("  group root:   " + root);
console.log("");
console.log("Keep THIS SECRET private (the operator never sees it):");
console.log("");
console.log("  secret value: " + secret);
console.log("");
console.log("Load it without putting the value in shell history:");
console.log("  read -s SHADE_TREE_SECRET && export SHADE_TREE_SECRET");
if (limit !== K_SLOTS) console.log("  export SHADE_TREE_LIMIT=" + limit);
console.log("");
printRegistrationGuide(console.log);
