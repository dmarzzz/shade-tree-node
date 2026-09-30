// Offline proof that the shade-tree CLI (packages/node/bin/shade-tree.mjs) validates config BEFORE spawning a service
// (T-DEV-7b wiring of packages/node/lib/config.mjs). Like shade-tree.selftest.mjs it SPAWNS the real CLI as a child
// for every case — no importing internals — so it exercises exactly the fail-fast an operator
// gets on the command line. It never starts a long-running service: the "proceeds" case uses
// --help, and the one command it lets past validation (client --no-validate) fails fast on its
// own missing-secret guard, not by hanging on a Tor dial.
//
//   node packages/node/bin/shade-tree-validate.selftest.mjs
//
// Exit 0 = all invariants held; nonzero = a check failed (prints which).

import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, "shade-tree.mjs");

// A clean env with all ambient SHADE_TREE_* stripped, so a var in the operator's shell can never make a
// "should fail" case pass (or vice versa). Cases layer only the SHADE_TREE_* they mean to test on top.
function cleanEnv(extra = {}) {
  const base = {};
  for (const [k, v] of Object.entries(process.env)) if (!k.startsWith("SHADE_TREE_")) base[k] = v;
  return { ...base, ...extra };
}

function shadeTreeCli(args, env = {}, timeout = 10_000) {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8", env: cleanEnv(env), timeout });
  if (r.error) throw r.error;
  return { code: r.status, out: (r.stdout || "") + (r.stderr || "") };
}

// The distinctive banner the CLI prints ONLY when it rejects config (so we can tell a validation
// failure apart from a module's own later error).
const VALIDATION_MARKER = /config invalid for role/i;

function main() {
  // --- client with NO discovery/secret: must fail fast on validation, not start the proxy ------
  console.log("client (no SHADE_TREE_SECRET / no discovery):");
  const bad = shadeTreeCli(["client"]);
  ok(bad.code !== 0, "`shade-tree client` (empty config) exits nonzero");
  ok(VALIDATION_MARKER.test(bad.out), "`shade-tree client` fails with the config-validation banner");
  ok(/SHADE_TREE_SECRET/.test(bad.out), "the config error names the missing SHADE_TREE_SECRET");
  ok(!/Shade Tree client:/.test(bad.out), "the client proxy never started — validation ran first");

  // --- bootnode: no required config, so --help still short-circuits and exits 0 ---------------
  console.log("\nbootnode --help (proceeds past wiring, no server):");
  const bhelp = shadeTreeCli(["bootnode", "--help"]);
  ok(bhelp.code === 0, "`shade-tree bootnode --help` exits 0 (validation wiring did not block it)");
  ok(!VALIDATION_MARKER.test(bhelp.out), "`shade-tree bootnode --help` prints no validation error");

  // --- bootnode with a BAD optional var: validation runs for bootnode too, fails fast, no server
  console.log("\nbootnode --port bogus (validation runs for bootnode, no server bound):");
  const bboot = shadeTreeCli(["bootnode", "--port", "not-a-port"]);
  ok(bboot.code !== 0, "`shade-tree bootnode --port not-a-port` exits nonzero");
  ok(VALIDATION_MARKER.test(bboot.out), "bad bootnode port is caught by config validation");
  ok(/SHADE_TREE_BOOTNODE_PORT/.test(bboot.out), "the error names SHADE_TREE_BOOTNODE_PORT");

  // --- client --no-validate with bad config: skips validation, attempts to run (fails LATER) --
  console.log("\nclient --no-validate (bad config, bypasses the check):");
  const skip = shadeTreeCli(["client", "--no-validate"]);
  ok(skip.code !== 0, "`shade-tree client --no-validate` still exits nonzero (client proxy's own guard)");
  ok(!VALIDATION_MARKER.test(skip.out), "`--no-validate` bypassed validation (no config-validation banner)");
  ok(/set SHADE_TREE_SECRET/.test(skip.out), "it reached the client proxy, which failed on its own missing-secret guard");

  // --- opt-out via env var, same bypass -------------------------------------------------------
  console.log("\nclient with SHADE_TREE_SKIP_VALIDATE=1 (env opt-out):");
  const skipEnv = shadeTreeCli(["client"], { SHADE_TREE_SKIP_VALIDATE: "1" });
  ok(!VALIDATION_MARKER.test(skipEnv.out), "SHADE_TREE_SKIP_VALIDATE=1 also bypasses validation");

  // --- a command with NO role is never validated ----------------------------------------------
  console.log("\nunvalidated commands (help/version still unchanged):");
  const ver = shadeTreeCli(["version"]);
  ok(ver.code === 0 && !VALIDATION_MARKER.test(ver.out), "`shade-tree version` unaffected by validation wiring");
  const help = shadeTreeCli(["help"]);
  ok(help.code === 0 && !VALIDATION_MARKER.test(help.out), "`shade-tree help` unaffected by validation wiring");

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: shade-tree validate wiring selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
