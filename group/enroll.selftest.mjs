// Self-enrollment SECURITY selftest. Spawns the REAL enroll CLI and proves the one
// property the honesty fix depends on: in commitment-only mode, the ONLY value that leaves
// on stdout — the channel piped to the operator / register-onchain — is the commitment, and
// the member's bearer secret NEVER appears there. The secret is emitted on stderr (for the
// human at the keyboard), so a pipe captures the commitment alone.
//
// Stream contract, read straight from group/enroll.mjs:
//   node group/enroll.mjs --commitment-only  -> stdout: commitment ONLY (one line)
//                                                stderr: secret value + hidden-read guidance
//                                                (does NOT touch members.json)
//   node group/enroll.mjs                     -> stdout (console.log): BOTH secret + commitment
//                                                (and seeds group/members.json)
//
//   node group/enroll.selftest.mjs
//
// Exit 0 = the secret never rides the operator channel; nonzero = a check failed (prints which).

import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { identityFor, identityCommitmentOf, rateCommitmentOf, FIELD } from "../lib/rln.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const ENROLL = join(HERE, "enroll.mjs");
const MEMBERS = join(HERE, "members.json");

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

// Run the CLI with stdout and stderr captured SEPARATELY (the whole point is which stream
// carries what). Never merged — a merge would defeat the test.
function runEnroll(extraArgs = []) {
  const r = spawnSync(process.execPath, [ENROLL, ...extraArgs], {
    cwd: ROOT,
    encoding: "utf8",
    timeout: 60_000,
  });
  if (r.error) throw r.error;
  return { status: r.status, stdout: r.stdout, stderr: r.stderr };
}

// A well-formed rateCommitment leaf: a single decimal big-integer token, a valid BN254 field
// element (0 < c < FIELD).
function isFieldElement(tok) {
  if (!/^[0-9]+$/.test(tok)) return false;
  let n;
  try { n = BigInt(tok); } catch { return false; }
  return n > 0n && n < FIELD;
}

const SECRET_RE = /secret value:\s*(0x[0-9a-fA-F]{64})/i;

function main() {
  // === 1. commitment-only mode: stdout is the commitment ALONE, secret is NOT on stdout ===
  console.log("commitment-only mode (the operator channel):");
  const c1 = runEnroll(["--commitment-only"]);
  ok(c1.status === 0, "exits 0");

  const outTokens = c1.stdout.trim().split(/\s+/).filter(Boolean);
  ok(outTokens.length === 1, "stdout carries exactly ONE token (no secret, no chatter)");
  const commitment = outTokens[0];
  ok(isFieldElement(commitment), "that token is a well-formed field-element commitment");

  // The secret lives on STDERR in this mode; pull it out so we can prove it is absent from stdout.
  const m = c1.stderr.match(SECRET_RE);
  ok(!!m, "the secret value is emitted on STDERR");
  ok(/read -s SHADE_TREE_SECRET && export SHADE_TREE_SECRET/.test(c1.stderr), "stderr gives a hidden-read command instead of an inline export");
  ok(!/export SHADE_TREE_SECRET=0x/.test(c1.stderr), "stderr does not make the secret a shell-history command");
  const secret = m ? m[1] : "__no-secret-found__";

  // The security assertion: the operator channel (stdout) must not leak the bearer secret in
  // any form — not the raw hex, not the env-var line, not a 0x blob.
  ok(!c1.stdout.includes(secret), "the secret hex does NOT appear on stdout");
  ok(!/SHADE_TREE_SECRET/.test(c1.stdout), "no SHADE_TREE_SECRET export line on stdout");
  ok(!/0x[0-9a-fA-F]{8,}/.test(c1.stdout), "no 0x-hex blob on stdout at all");

  // The commitment on stdout is the REAL leaf derived from the secret on stderr — same
  // derivation the gateway/on-chain slash uses (rateCommitmentOf(identityFor(secret))).
  let derived = "__underivable__";
  try { derived = rateCommitmentOf(identityFor(secret)).toString(); } catch { /* left as sentinel */ }
  ok(derived === commitment, "stdout commitment == rateCommitmentOf(identityFor(secret)) (leaf matches the secret)");
  let idc = "__underivable__";
  try { idc = identityCommitmentOf(identityFor(secret)).toString(); } catch { /* sentinel */ }
  ok(new RegExp(`shade-tree register-member ${idc} --limit 8`).test(c1.stderr), "default enrollment prints a registration command for the identity commitment at the exact tier");
  ok(!new RegExp(`register-member ${commitment}`).test(c1.stderr), "the registration command never stakes the leaf itself");
  ok(/read -s SHADE_TREE_REGISTER_KEY/.test(c1.stderr) && /SHADE_TREE_REGISTER_KEY="\$SHADE_TREE_REGISTER_KEY" shade-tree register-member/.test(c1.stderr) && /unset SHADE_TREE_REGISTER_KEY/.test(c1.stderr), "remote registration guidance keeps the funded key hidden, process-scoped, and cleared");
  ok(!/--register-key\s+/.test(c1.stderr), "registration guidance never puts the funded key in argv");

  const tiered = runEnroll(["--commitment-only", "--limit", "32"]);
  const tieredCommitment = tiered.stdout.trim();
  const tieredSecret = (tiered.stderr.match(SECRET_RE) || [])[1];
  let tieredDerived = "__underivable__";
  try { tieredDerived = rateCommitmentOf(identityFor(tieredSecret), 32).toString(); } catch { /* sentinel */ }
  ok(tiered.status === 0 && tieredDerived === tieredCommitment, "tier-32 enrollment derives a tier-32 leaf");
  let tieredIdc = "__underivable__";
  try { tieredIdc = identityCommitmentOf(identityFor(tieredSecret)).toString(); } catch { /* sentinel */ }
  ok(new RegExp(`shade-tree register-member ${tieredIdc} --limit 32`).test(tiered.stderr), "tier-32 enrollment prints a matching tier-32 registration command");

  // === 2. two commitment-only runs generate a FRESH identity each time ===
  console.log("\nfreshness (identity generated locally, per run):");
  const c2 = runEnroll(["--commitment-only"]);
  ok(c2.status === 0, "second run exits 0");
  const commitment2 = c2.stdout.trim();
  ok(isFieldElement(commitment2), "second run's stdout is a well-formed commitment");
  ok(commitment2 !== commitment, "two runs produce DIFFERENT commitments (fresh identity each time)");

  // commitment-only mode must not seed the local set (leaves members.json untouched).
  const before = readFileSync(MEMBERS, "utf8");
  ok(!before.includes(commitment) && !before.includes(commitment2) && !before.includes(tieredCommitment),
     "commitment-only runs did NOT write into members.json");

  // === 3. default mode differs: BOTH secret and commitment appear (difference is real) ===
  // Default mode seeds members.json as a side effect; snapshot and restore so the tree is
  // left exactly as found (this selftest changes no other file).
  console.log("\ndefault mode (local demo path):");
  const snapshot = readFileSync(MEMBERS, "utf8");
  let d;
  try {
    d = runEnroll([]);
  } finally {
    writeFileSync(MEMBERS, snapshot); // restore regardless of outcome
  }
  ok(d.status === 0, "exits 0");
  const dm = d.stdout.match(SECRET_RE);
  ok(!!dm, "default mode DOES print the member's secret value on stdout");
  ok(/read -s SHADE_TREE_SECRET && export SHADE_TREE_SECRET/.test(d.stdout) && !/export SHADE_TREE_SECRET=0x/.test(d.stdout), "default guidance uses a hidden read rather than an inline secret export");
  const dCommit = (d.stdout.match(/commitment:\s+([0-9]+)/) || [])[1];
  ok(dCommit != null && isFieldElement(dCommit), "default mode also prints a well-formed commitment");
  const dIdc = (d.stdout.match(/identity commitment:\s+([0-9]+)/) || [])[1];
  ok(dIdc != null && dm && dIdc === identityCommitmentOf(identityFor(dm[1])).toString(), "default mode prints the identity commitment of the printed secret");
  ok(new RegExp(`shade-tree register-member ${dIdc} --limit 8`).test(d.stdout), "default local-demo output retains the exact registration tier");
  ok(dm && dCommit && dm[1] !== dCommit, "secret and commitment are distinct values");
  ok(readFileSync(MEMBERS, "utf8") === snapshot, "members.json restored to its pre-test contents");

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: enroll selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
