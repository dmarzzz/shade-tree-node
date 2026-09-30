// identity — export THIS member's identity file for the Rust client (`shade-tree egress --identity`).
//
// The Rust `shade-tree egress` (crates/shadenet-cli, `--features live`) does not read SHADE_TREE_SECRET; it
// takes the derived Semaphore-v3 identitySecret and the RLN rateCommitment leaf as a JSON file:
//
//   { "identitySecret": "<dec>", "leaf": "<dec>" }
//
// This command derives that file from the member's app secret with the JS reference
// (packages/node/lib/identity-file.mjs -> packages/node/lib/rln.mjs), so the Rust client is the SAME member as the JS client
// (same secret -> same identitySecret -> same leaf == the member's group/members.json entry).
//
// Usage (via the router or directly):
//   shade-tree identity                              -> identity JSON on stdout
//   shade-tree identity --out identity.json          -> write the file (mode 0600), summary on stderr
//   shade-tree identity --secret-file ./.secret      -> read the secret from a file
//   shade-tree identity --secret 0x...               -> (router flag; sets SHADE_TREE_SECRET — lands in argv,
//                                                 prefer the env or --secret-file)
//
// Secret source, first match wins:
//   1. --secret-file <path>   2. SHADE_TREE_SECRET (what `--secret` sets)   3. ./.secret (cwd)
//
// Stream contract: stdout carries ONLY the identity JSON (and only when --out is absent), so
// `shade-tree identity > id.json` is safe. stderr carries the human summary: the public leaf and the
// output path. The app secret and identitySecret are NEVER printed to stderr/logs.
//
// The leaf depends on the member's tier limit (`--limit` / SHADE_TREE_LIMIT; bundled current
// network defaultLimit = 1, direct-script development fallback K = SHADE_TREE_SLOTS = 8)
// like every rateCommitment in the system: derive with the limit the leaf was enrolled with, or the
// leaf will not be in the tree. A non-default limit is written into the file (`limit`) so the Rust
// client proves with it (T-FEAT-8).

import { readFileSync, writeFileSync, chmodSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { identityFileFor, serializeIdentityFile } from "../packages/node/lib/identity-file.mjs";
import { K_SLOTS, normLimit } from "../packages/node/lib/rln.mjs";

const USAGE = "usage: shade-tree identity [--out <path>] [--secret-file <path>] [--limit <n>]   (secret: --secret-file | SHADE_TREE_SECRET | ./.secret; limit: --limit | SHADE_TREE_LIMIT | bundled default)";

function parseArgs(argv) {
  const opts = { out: null, secretFile: null, limit: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") { console.log(USAGE); process.exit(0); }
    if (!a.startsWith("--")) { console.error(`identity: unexpected argument ${a}\n${USAGE}`); process.exit(2); }
    const eq = a.indexOf("=");
    const key = eq === -1 ? a.slice(2) : a.slice(2, eq);
    const val = eq === -1 ? argv[++i] : a.slice(eq + 1);
    if (key !== "out" && key !== "secret-file" && key !== "limit") { console.error(`identity: unknown flag --${key}\n${USAGE}`); process.exit(2); }
    if (val === undefined || val === "" || val.startsWith("--")) { console.error(`identity: --${key} needs a value\n${USAGE}`); process.exit(2); }
    if (key === "out") opts.out = val; else if (key === "limit") opts.limit = val; else opts.secretFile = val;
  }
  return opts;
}

// Resolve the secret without ever echoing it. Returns { secret, source } where source is a
// human label safe to print.
export function resolveSecret({ secretFile, env = process.env, cwd = process.cwd() } = {}) {
  if (secretFile) {
    if (!existsSync(secretFile)) throw new Error(`secret file not found: ${secretFile}`);
    return { secret: readFileSync(secretFile, "utf8").trim(), source: `--secret-file ${secretFile}` };
  }
  if (env.SHADE_TREE_SECRET && env.SHADE_TREE_SECRET.trim()) return { secret: env.SHADE_TREE_SECRET.trim(), source: "SHADE_TREE_SECRET" };
  const dot = resolve(cwd, ".secret");
  if (existsSync(dot)) return { secret: readFileSync(dot, "utf8").trim(), source: "./.secret" };
  throw new Error("no secret: pass --secret-file <path>, set SHADE_TREE_SECRET (or --secret), or put it in ./.secret");
}

// Write the identity file with owner-only permissions (0600), even if the path already existed
// with looser bits. Never logs the contents.
export function writeIdentityFile(path, bytes) {
  writeFileSync(path, bytes, { mode: 0o600 });
  chmodSync(path, 0o600);
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  let secret, source;
  try { ({ secret, source } = resolveSecret({ secretFile: opts.secretFile })); }
  catch (e) { console.error(`identity: ${e.message}`); process.exit(1); }
  if (!secret) { console.error("identity: the secret is empty"); process.exit(1); }

  // Validate the shape ourselves so a malformed value is never echoed back by a library error
  // (BigInt("...") quotes its input): 0x-hex or decimal digits, as `shade-tree enroll` mints.
  if (!/^(0x[0-9a-fA-F]+|[0-9]+)$/.test(secret)) {
    console.error(`identity: the secret from ${source} is not 0x-hex or decimal (value not shown)`);
    process.exit(1);
  }
  let limit;
  try { limit = Number(normLimit(opts.limit ?? process.env.SHADE_TREE_LIMIT ?? K_SLOTS)); }
  catch (e) { console.error(`identity: ${e.message}`); process.exit(2); }
  let file;
  try { file = identityFileFor(secret, limit); }
  catch { console.error(`identity: cannot derive from the secret (${source}) (value not shown)`); process.exit(1); }
  const bytes = serializeIdentityFile(file);

  console.error(`shade-tree identity — Rust client identity file (secret from ${source}; limit=${limit}${limit === K_SLOTS ? ` = K (SHADE_TREE_SLOTS)` : " (tier; written into the file)"})`);
  console.error(`  leaf (public; must be in the fleet's members.json):  ${file.leaf}`);
  if (opts.out) {
    const out = resolve(opts.out);
    try { writeIdentityFile(out, bytes); }
    catch (e) { console.error(`identity: cannot write ${out}: ${e.message}`); process.exit(1); }
    console.error(`  wrote:  ${out}   (mode 0600 — SECRET material: keep local, delete when done)`);
    console.error(`  next (Rust -live binary): shade-tree egress --identity ${opts.out} --members group/members.json --bootnode-onion <BN_ONION> --signer <SIGNER> --target <host:port>`);
  } else {
    process.stdout.write(bytes);
    console.error(`  (identity JSON on stdout — SECRET material; redirect only into a 0600 file, e.g. --out)`);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) main();
