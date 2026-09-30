// Guided-onboarding selftest. Spawns the REAL CLI (`node packages/node/bin/shade-tree.mjs join ...`) for both
// roles and proves the front door does its two jobs without ever mishandling a secret:
//
//   shade-tree join member   -> self-enrolls: prints a well-formed commitment + the EXACT Proxy
//                         command on stdout, and the bearer secret on STDERR only (never stdout,
//                         mirroring enroll's commitment-only stream contract).
//   shade-tree join node     -> mints a real .onion identity into a temp dir and prints the node +
//                         heartbeat next commands; the announce-signing seed stays off stdout.
//
//   node group/join.selftest.mjs
//
// Exit 0 = all invariants held; nonzero = a check failed (prints which). Temp files are cleaned
// up. Spawns are fast/offline (keygen + a nested enroll --commitment-only; no services).

import { spawnSync } from "node:child_process";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { identityFor, identityCommitmentOf, rateCommitmentOf, FIELD } from "../packages/node/lib/rln.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const CLI = join(ROOT, "packages", "node", "bin", "shade-tree.mjs");

// Run the CLI keeping stdout and stderr SEPARATE — the whole point is which stream carries what.
function shadeTree(args, opts = {}) {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    cwd: ROOT,
    encoding: "utf8",
    env: { ...process.env, ...(opts.env || {}) },
    timeout: opts.timeout || 60_000,
  });
  if (r.error) throw r.error;
  return { code: r.status, stdout: r.stdout || "", stderr: r.stderr || "" };
}

const SECRET_RE = /secret value:\s*(0x[0-9a-fA-F]{64})/i;

function isFieldElement(tok) {
  if (!/^[0-9]+$/.test(tok)) return false;
  let n; try { n = BigInt(tok); } catch { return false; }
  return n > 0n && n < FIELD;
}

async function main() {
  // === 1. join member: guide on stdout, secret on stderr ONLY ==============
  console.log("join member:");
  const m = shadeTree(["join", "member"], { timeout: 40_000 });
  ok(m.code === 0, "`shade-tree join member` exits 0");
  ok(/joining as a MEMBER/i.test(m.stdout), "stdout announces the MEMBER role");

  // The commitment the guide prints must be a real leaf, and it must be derivable from the
  // secret on stderr (rateCommitmentOf(identityFor(secret))) — proving it composed the real
  // enroll flow, not printed a placeholder.
  const commitment = (m.stdout.match(/commitment:\s+([0-9]+)/) || [])[1];
  ok(commitment != null && isFieldElement(commitment), "stdout prints a well-formed field-element commitment");

  const secret = (m.stderr.match(SECRET_RE) || [])[1];
  ok(!!secret, "the bearer secret value is emitted on STDERR");
  ok(/read -s SHADE_TREE_SECRET && export SHADE_TREE_SECRET/.test(m.stderr) && !/export SHADE_TREE_SECRET=0x/.test(m.stderr), "the secret handoff uses a hidden read rather than an inline export");

  // Stream contract: the secret must NEVER ride stdout in any form.
  ok(secret ? !m.stdout.includes(secret) : true, "the secret hex does NOT appear on stdout");
  ok(!/SHADE_TREE_SECRET=0x[0-9a-fA-F]{64}/.test(m.stdout), "no concrete SHADE_TREE_SECRET=0x... value on stdout");

  let derived = "__underivable__";
  try { derived = rateCommitmentOf(identityFor(secret)).toString(); } catch { /* sentinel */ }
  ok(derived === commitment, "stdout commitment == rateCommitmentOf(identityFor(secret)) (composed real enroll)");

  // The whole point of the guide: the EXACT next commands, copy-paste ready.
  ok(/shade-tree proxy --limit 8 --leaf-source invited/.test(m.stdout), "prints the invited `shade-tree proxy ...` command");
  ok(/shade-tree proxy --limit 8 --leaf-source staked/.test(m.stdout), "prints the staked `shade-tree proxy ...` command");
  ok(!/shade-tree proxy[\s\S]{0,80}--secret/.test(m.stdout), "the generated Proxy command keeps the bearer secret out of argv");
  ok(/read -r SHADE_TREE_BOOTNODE_ONION/.test(m.stdout), "the guide loads the operator-supplied Elder onion");
  ok(/read -r SHADE_TREE_DIR_SIGNER/.test(m.stdout), "the guide loads the operator-supplied Canopy signer");
  ok(/read -r SHADE_TREE_MEMBERS_FILE/.test(m.stdout), "the invited branch requires the operator-supplied member list");
  ok(/read -r SHADE_TREE_RPC_URL/.test(m.stdout) && /read -r SHADE_TREE_GROUP_CONTRACT/.test(m.stdout), "the staked branch requires the operator-supplied chain profile");
  let idc = "__underivable__";
  try { idc = identityCommitmentOf(identityFor(secret)).toString(); } catch { /* sentinel */ }
  ok(new RegExp(`shade-tree register-member ${idc}`).test(m.stdout), "prints the optional `shade-tree register-member <identity-commitment>` step");
  ok(/read -s SHADE_TREE_REGISTER_KEY/.test(m.stdout) && /SHADE_TREE_REGISTER_KEY="\$SHADE_TREE_REGISTER_KEY" shade-tree register-member/.test(m.stdout) && /unset SHADE_TREE_REGISTER_KEY/.test(m.stdout), "the registration key is hidden, process-scoped, and cleared");
  ok(!/--register-key\s+/.test(m.stdout), "the generated guide never puts the registration key in argv");

  const tiered = shadeTree(["join", "member", "--limit", "32"], { timeout: 40_000 });
  const tieredCommitment = (tiered.stdout.match(/commitment:\s+([0-9]+)/) || [])[1];
  const tieredSecret = (tiered.stderr.match(SECRET_RE) || [])[1];
  let tieredDerived = "__underivable__";
  try { tieredDerived = rateCommitmentOf(identityFor(tieredSecret), 32).toString(); } catch { /* sentinel */ }
  ok(tiered.code === 0 && tieredDerived === tieredCommitment, "`join --limit 32` bakes tier 32 into the enrolled leaf");
  ok(/tier limit:\s+32/.test(tiered.stdout) && /proxy --limit 32 --leaf-source invited/.test(tiered.stdout) && /proxy --limit 32 --leaf-source staked/.test(tiered.stdout), "tiered join prints the matching Proxy limit");
  let tieredIdc = "__underivable__";
  try { tieredIdc = identityCommitmentOf(identityFor(tieredSecret)).toString(); } catch { /* sentinel */ }
  ok(new RegExp(`register-member ${tieredIdc} --limit 32`).test(tiered.stdout), "tiered join prints the matching registration limit");
  ok(/export SHADE_TREE_LIMIT=32/.test(tiered.stderr), "tiered join tells the member to retain the exact limit");

  // default (no role) behaves as member too
  const def = shadeTree(["join"], { timeout: 40_000 });
  ok(def.code === 0 && /joining as a MEMBER/i.test(def.stdout), "`shade-tree join` (no role) defaults to member");

  // === 2. join node: mint an onion into a temp dir, print node/heartbeat ===
  console.log("\njoin node:");
  const work = await mkdtemp(join(tmpdir(), "shade-tree-join-"));
  try {
    const hsDir = join(work, "hs");
    const g = shadeTree(["join", "node", hsDir], { timeout: 40_000 });
    ok(g.code === 0, "`shade-tree join node <hsDir>` exits 0");
    ok(/joining as a SHADE TREE NODE/i.test(g.stdout), "stdout announces the Shade Tree node role");

    // It actually minted a real onion identity into the temp dir.
    ok(existsSync(join(hsDir, "hostname")), "keygen wrote a `hostname` into the temp hsDir");
    ok(existsSync(join(hsDir, "identity.local.json")), "keygen wrote `identity.local.json` into the temp hsDir");
    const onion = (g.stdout.match(/onion:\s+(\S+\.onion)/) || [])[1];
    ok(!!onion, "stdout prints a minted .onion address");
    let firstIdentity = null;
    if (existsSync(join(hsDir, "identity.local.json"))) {
      firstIdentity = JSON.parse(await readFile(join(hsDir, "identity.local.json"), "utf8"));
      ok(firstIdentity.onion === onion, "the printed onion matches identity.local.json");
      // The announce-signing seed is a secret — it must not be spilled onto stdout.
      ok(firstIdentity.seed && !g.stdout.includes(firstIdentity.seed), "the announce-signing seed does NOT appear on stdout");
    }

    // The EXACT next commands for a node operator.
    ok(/SAFETY: disposable research only/.test(g.stdout) && /private-target guard is closed/.test(g.stdout) && /issue #6/.test(g.stdout) && /untrusted development Groth16 artifacts/.test(g.stdout) && /other deployment gates/.test(g.stdout) && !/issue #73/.test(g.stdout) && /Do not use real funds or sensitive traffic/.test(g.stdout),
       "prints only the remaining deployment blockers before the node command");
    ok(/SHADE_TREE_REGISTER_KEY="\$SHADE_TREE_REGISTER_KEY" shade-tree register-gateway/.test(g.stdout) && /unset SHADE_TREE_REGISTER_KEY/.test(g.stdout), "prints a process-scoped optional `shade-tree register-gateway` step");
    ok(!/--register-key\s+/.test(g.stdout), "the node guide keeps the operator key out of argv");
    ok(/shade-tree-node node/.test(g.stdout), "prints the `shade-tree node` command");
    ok(/shade-tree-node heartbeat --bootnode <elder-onion>/.test(g.stdout), "prints the `shade-tree heartbeat --bootnode <onion>` command");
    ok(new RegExp(`--identity ${join(hsDir, "identity.local.json").replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`).test(g.stdout),
       "the heartbeat command points --identity at the minted identity file");

    const rerun = shadeTree(["join", "node", hsDir], { timeout: 40_000 });
    const preserved = JSON.parse(await readFile(join(hsDir, "identity.local.json"), "utf8"));
    ok(rerun.code !== 0 && /refusing to overwrite onion identity/.test(rerun.stderr), "a rerun refuses to rotate an existing node identity");
    ok(firstIdentity && preserved.onion === firstIdentity.onion && preserved.seed === firstIdentity.seed, "a refused rerun preserves the onion and announcement seed");

    const forced = shadeTree(["join", "node", hsDir, "--force"], { timeout: 40_000 });
    const rotated = JSON.parse(await readFile(join(hsDir, "identity.local.json"), "utf8"));
    ok(forced.code === 0 && firstIdentity && rotated.onion !== firstIdentity.onion, "`--force` performs an explicit identity rotation");

    const legacyDir = join(work, "legacy-hs");
    const legacy = shadeTree(["join", "gateway", legacyDir], { timeout: 40_000 });
    ok(legacy.code === 0 && /joining as a SHADE TREE NODE/i.test(legacy.stdout), "`join gateway` remains a compatibility alias");
  } finally {
    await rm(work, { recursive: true, force: true });
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: join selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
