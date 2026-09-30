// Seed a clean, fully-labeled demo reputation set you can hand out.
//
// Unlike enroll.mjs (which appends one member and forgets the label), this writes
// the WHOLE set at once and records each label -> secret mapping to a gitignored
// keyring, so every key in the set is known and shareable. Use it to mint a batch
// of demo identities; use enroll.mjs for the real one-at-a-time admission flow.
//
// Usage:
//   node group/seed-demo-members.mjs                 # alice..heidi (8)
//   node group/seed-demo-members.mjs ava ben cleo    # custom labels
//
// Outputs (at repo root):
//   group/members.json      the public reputation set (commitments only) -- OVERWRITTEN
//   keys.local.json         { label, secret, commitment }[]   (gitignored, private)
//   demo-keys.local.md      a human-readable card to pass around (gitignored, private)

import { writeFile } from "node:fs/promises";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { identityFor, rateCommitmentOf, MEMBERS_PATH } from "../packages/node/lib/rln.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

const DEFAULT = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi"];
const labels = process.argv.slice(2);
const names = labels.length ? labels : DEFAULT;

// Secrets are 0x-hex field elements so the lib's toField()/identityFor() parse them.
// The leaf is the RLN rateCommitment = Poseidon2(Poseidon1(identitySecret), K) — the exact
// depth-20 tree leaf proveForSlot() proves against and the on-chain hasher stores.
const keys = names.map((label) => {
  const secret = "0x" + randomBytes(32).toString("hex");
  const commitment = rateCommitmentOf(identityFor(secret)).toString(); // rateCommitment leaf
  return { label, secret, commitment };
});

// 1. The public reputation set: rateCommitment leaves only. Safe to ship anywhere.
await writeFile(
  MEMBERS_PATH,
  JSON.stringify({ version: 2, members: keys.map((k) => k.commitment) }, null, 2) + "\n"
);

// 2. The private keyring: machine-readable.
await writeFile(join(ROOT, "keys.local.json"), JSON.stringify(keys, null, 2) + "\n");

// 3. The private keyring: human-readable card to pass around.
const card =
  `# demo reputation set (${keys.length} members)\n\n` +
  `Each person gets ONE line below. The secret is theirs to keep; it proves\n` +
  `membership without ever being sent. Everyone shares the same public set\n` +
  `(group/members.json), which is already baked in. Hand a member their block:\n\n` +
  keys
    .map(
      (k) =>
        `## ${k.label}\n\n` +
        "```bash\n" +
        `export SHADE_TREE_SECRET=${k.secret}\n` +
        "```\n\n" +
        `commitment (public, in the set): \`${k.commitment}\`\n`
    )
    .join("\n") +
  `\n---\nKeep this file private. The secrets above are bearer credentials:\n` +
  `whoever holds one can egress as that member until you rotate the set.\n`;
await writeFile(join(ROOT, "demo-keys.local.md"), card);

console.log(`seeded ${keys.length} members into group/members.json`);
console.log(`private keyring: keys.local.json  +  demo-keys.local.md  (both gitignored)`);
console.log("");
for (const k of keys) console.log(`  ${k.label.padEnd(7)} commitment ${k.commitment.slice(0, 22)}..`);
