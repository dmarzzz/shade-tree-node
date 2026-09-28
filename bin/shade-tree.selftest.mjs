// Offline proof that the shade-tree CLI router (bin/shade-tree.mjs) behaves. It SPAWNS the real CLI as a
// child (node:child_process) for every case — no importing internals — so it exercises exactly
// what a user gets on the command line: help/version/unknown-command exit codes and output, the
// doctor health check, and the flag plumbing that maps clean --flags onto the SHADE_TREE_* env the
// underlying modules read. The one live command it runs is `keygen`, which is fast and offline;
// it never launches a long-running service (bootnode/gateway/client) — those are --help only.
//
//   node bin/shade-tree.selftest.mjs
//
// Exit 0 = all invariants held; nonzero = a check failed (prints which).

import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, rm, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const CLI = join(HERE, "shade-tree.mjs");

// Run the CLI with args; return { code, out } where out is stdout+stderr combined so we can
// assert on messages regardless of which stream the CLI chose.
function shadeTreeCli(args, opts = {}) {
  const r = spawnSync(process.execPath, [CLI, ...args], {
    encoding: "utf8",
    env: { ...process.env, ...(opts.env || {}) },
    timeout: opts.timeout || 60_000,
  });
  if (r.error) throw r.error;
  return { code: r.status, out: (r.stdout || "") + (r.stderr || "") };
}

async function main() {
  const pkg = JSON.parse(await readFile(join(ROOT, "package.json"), "utf8"));

  // --- help ------------------------------------------------------------------
  console.log("help:");
  const help = shadeTreeCli(["help"]);
  ok(help.code === 0, "`shade-tree help` exits 0");
  ok(/\brun\b/.test(help.out) && /\bkeygen\b/.test(help.out) && /\bbootnode\b/.test(help.out), "`shade-tree help` lists the commands (run, keygen, bootnode)");
  ok(/\bidentity\b/.test(help.out) && /\bexit-gateway\b/.test(help.out) && /\bwithdraw-gateway\b/.test(help.out) && /\bgateway-status\b/.test(help.out),
    "`shade-tree help` lists identity, exit-gateway, withdraw-gateway, gateway-status (T-DEPLOY-5 GAP-4/GAP-12)");
  ok(/\bjoin\b/.test(help.out) && /\bbackup\b/.test(help.out) && /\brestore\b/.test(help.out), "`shade-tree help` lists join, backup, restore");
  // no args behaves as help too
  ok(shadeTreeCli([]).code === 0, "`shade-tree` with no command exits 0 (prints help)");
  const runHelp = shadeTreeCli(["run", "--help"]);
  ok(runHelp.code === 0 && /process-scoped|scoped HTTP\(S\) proxy/i.test(runHelp.out), "`shade-tree run --help` describes scoped routing and exits 0");
  const proxyHelp = shadeTreeCli(["proxy", "--help"]);
  ok(proxyHelp.code === 0 && /read -s SHADE_TREE_SECRET/.test(proxyHelp.out) && /--limit N/.test(proxyHelp.out) && /docs\/AGENT\.md/.test(proxyHelp.out), "`shade-tree proxy --help` gives the secret, tier, and agent-guide path");
  const nodeHelp = shadeTreeCli(["node", "--help"]);
  ok(nodeHelp.code === 0 && /shade-tree-node join node/.test(nodeHelp.out) && /development ZK setup/.test(nodeHelp.out), "`shade-tree node --help` gives the guided setup and deployment boundary");

  // --- version ---------------------------------------------------------------
  console.log("\nversion:");
  const ver = shadeTreeCli(["version"]);
  ok(ver.code === 0, "`shade-tree version` exits 0");
  ok(ver.out.trim() === pkg.version, `\`shade-tree version\` prints package.json version (${pkg.version})`);

  // --- unknown command -------------------------------------------------------
  console.log("\nunknown command:");
  const bad = shadeTreeCli(["no-such-command"]);
  ok(bad.code !== 0, "`shade-tree no-such-command` exits nonzero");
  ok(/unknown command/i.test(bad.out), "`shade-tree no-such-command` explains it is an unknown command");

  // --- doctor (health check; 0 or 1 both fine, it's advisory) -----------------
  console.log("\ndoctor:");
  const doc = shadeTreeCli(["doctor"]);
  ok(doc.code === 0 || doc.code === 1, "`shade-tree doctor` runs and exits 0 or 1 (health check)");
  ok(/shade-tree-node doctor/.test(doc.out), "`shade-tree doctor` prints its `shade-tree doctor` banner");

  // --- --help short-circuits BEFORE running a service -------------------------
  // A durable service (bootnode) must print its help and exit 0 without ever binding a port.
  console.log("\ncommand --help:");
  const bhelp = shadeTreeCli(["bootnode", "--help"], { timeout: 10_000 });
  ok(bhelp.code === 0, "`shade-tree bootnode --help` exits 0 (never starts the service)");
  ok(/bootnode/.test(bhelp.out), "`shade-tree bootnode --help` prints the bootnode command help");
  // the on-chain exit commands must never reach a chain from --help either
  const ehelp = shadeTreeCli(["exit-gateway", "--help"], { timeout: 10_000 });
  ok(ehelp.code === 0 && /initiateExit|unbonding/i.test(ehelp.out), "`shade-tree exit-gateway --help` exits 0 (no RPC touched)");
  const ihelp = shadeTreeCli(["identity", "--help"], { timeout: 10_000 });
  ok(ihelp.code === 0 && /--out/.test(ihelp.out), "`shade-tree identity --help` exits 0 and names --out");
  const heartbeatMetrics = shadeTreeCli(["heartbeat", "--metrics-port", "70000"], { timeout: 10_000 });
  ok(heartbeatMetrics.code !== 0 && /SHADE_TREE_HEARTBEAT_METRICS_PORT/.test(heartbeatMetrics.out) && !/SHADE_TREE_METRICS_PORT:/.test(heartbeatMetrics.out), "heartbeat remaps common --metrics-port to its dedicated metrics listener");
  const tieredEnroll = shadeTreeCli(["enroll", "--commitment-only", "--limit", "32"], { timeout: 40_000 });
  ok(tieredEnroll.code === 0 && /export SHADE_TREE_LIMIT=32/.test(tieredEnroll.out), "enroll receives the tier selected by the top-level --limit flag");

  // --- live flag plumbing: keygen mints an onion into a positional dir --------
  // Proves BOTH positional passthrough (<hsDir>) and the module-parsed --label flag (which is
  // NOT in FLAG_ENV, so it must fall through to the child as `--label test`).
  console.log("\nkeygen (live flag + positional passthrough):");
  const work = await mkdtemp(join(tmpdir(), "shade-tree-cli-"));
  try {
    const hsDir = join(work, "hs");
    const kg = shadeTreeCli(["keygen", hsDir, "--label", "test"], { timeout: 30_000 });
    ok(kg.code === 0, "`shade-tree keygen <dir> --label test` exits 0");
    ok(existsSync(join(hsDir, "hostname")), "keygen wrote a `hostname` file into the positional dir");
    ok(existsSync(join(hsDir, "identity.local.json")), "keygen wrote `identity.local.json` into the positional dir");
    if (existsSync(join(hsDir, "identity.local.json"))) {
      const id = JSON.parse(await readFile(join(hsDir, "identity.local.json"), "utf8"));
      ok(id.label === "test", "the --label test flag reached the module (identity.local.json.label === 'test')");
      ok(typeof id.onion === "string" && id.onion.endsWith(".onion"), "keygen minted a .onion address");
    }
  } finally {
    await rm(work, { recursive: true, force: true });
  }

  // --- static check of the FLAG_ENV mapping table ----------------------------
  // The env mapping is the CLI's whole contract: flags and SHADE_TREE_* env vars stay one-to-one so
  // either works. Importing the CLI to read FLAG_ENV would run main(); instead assert the
  // documented pairs exist in the source text.
  console.log("\nFLAG_ENV mapping (static):");
  const src = await readFile(CLI, "utf8");
  const pairs = [
    ["port", "SHADE_TREE_BOOTNODE_PORT"],
    ["secret", "SHADE_TREE_SECRET"],
    ["bootnode", "SHADE_TREE_BOOTNODE_ONION"],
    ["admission", "SHADE_TREE_BOOTNODE_ADMISSION"],
    ["shim-port", "SHADE_TREE_SHIM_PORT"],
    ["directory", "SHADE_TREE_DIRECTORY"],
    ["dir-signer", "SHADE_TREE_DIR_SIGNER"],
    ["directory-refresh-ms", "SHADE_TREE_DIRECTORY_REFRESH_MS"],
    ["rotation-spread", "SHADE_TREE_ROTATION_SPREAD"],
    ["network", "SHADE_TREE_NETWORK"],
    ["log-level", "SHADE_TREE_LOG_LEVEL"],
    ["log-format", "SHADE_TREE_LOG_FORMAT"],
    ["metrics-port", "SHADE_TREE_METRICS_PORT"],
    ["heartbeat-metrics-port", "SHADE_TREE_HEARTBEAT_METRICS_PORT"],
    ["gateway-port", "SHADE_TREE_GATEWAY_PORT"],
  ];
  for (const [flag, env] of pairs) {
    // matches:  port: "SHADE_TREE_BOOTNODE_PORT"   or   "shim-port": "SHADE_TREE_SHIM_PORT"
    const re = new RegExp(`(?:"${flag}"|\\b${flag})\\s*:\\s*"${env}"`);
    ok(re.test(src), `FLAG_ENV maps --${flag} -> ${env}`);
  }
  ok(/flags, "quiet"[\s\S]*SHADE_TREE_LOG_LEVEL = "warn"/.test(src), "--quiet lowers routine output to warn unless a level is explicit");
  ok(/flags, "no-banner"[\s\S]*SHADE_TREE_BANNER = "never"/.test(src), "--no-banner suppresses terminal art");
  ok(/flags, "no-rotation-spread"[\s\S]*SHADE_TREE_ROTATION_SPREAD = "0"/.test(src), "--no-rotation-spread opts out of the default smooth rotation");

  // --- --network / SHADE_TREE_NETWORK (lib/network-record.mjs) --------------------------------------
  // `record-deploy` has no config role and its --dry-run writes nothing, so it is the safe live
  // command to prove the wrapper resolves network/<name>/ records into env before spawning.
  console.log("\n--network (SHADE_TREE_NETWORK record resolution):");
  const badNet = shadeTreeCli(["record-deploy", "--network", "no-such-network-zzz", "--address", "0x" + "ab".repeat(20), "--dry-run"]);
  ok(badNet.code === 1 && /SHADE_TREE_NETWORK=no-such-network-zzz/.test(badNet.out) && /no such network/.test(badNet.out), "`--network <unknown>` fails fast in the wrapper before spawning");
  const trav = shadeTreeCli(["record-deploy", "--network", "../lib", "--dry-run"]);
  ok(trav.code === 1 && /bad network name/.test(trav.out), "`--network ../x` (traversal) is rejected");
  const dry = shadeTreeCli(["record-deploy", "--network", "sepolia", "--address", "0x" + "ab".repeat(20), "--force", "--dry-run"]);
  ok(dry.code === 0 && /supplied .*SHADE_TREE_BOOTNODE_ONION/.test(dry.out) && /SHADE_TREE_DIR_SIGNER/.test(dry.out) && /dry-run:/.test(dry.out),
    "`--network sepolia` supplies the current v4 Elder pair while ignoring retired pre-v4 records");
  const viaEnv = shadeTreeCli(["record-deploy", "--address", "0x" + "ab".repeat(20), "--force", "--dry-run"], { env: { SHADE_TREE_NETWORK: "sepolia" } });
  ok(viaEnv.code === 0 && /supplied .*SHADE_TREE_BOOTNODE_ONION/.test(viaEnv.out) && /dry-run:/.test(viaEnv.out),
    "SHADE_TREE_NETWORK=sepolia resolves the current v4 deployment");

  // Preserve positive coverage with an ephemeral active record. This tests both record-to-env
  // default resolution and the child spawn for a synthetic contract-bearing network.
  const activeName = `selftest-active-${process.pid}`;
  const activeDir = join(ROOT, "network", activeName);
  await mkdir(activeDir);
  try {
    await writeFile(join(activeDir, "contracts.json"), JSON.stringify({
      network: activeName,
      chainId: 31_337,
      status: "live",
      rpcUrl: "http://127.0.0.1:8545",
      contracts: { gatewayRegistry: "0x" + "11".repeat(20) },
    }, null, 2) + "\n");
    const active = shadeTreeCli(["record-deploy", "--network", activeName, "--address", "0x" + "ab".repeat(20), "--force", "--dry-run"]);
    ok(active.code === 0 && /supplied .*SHADE_TREE_GATEWAY_REGISTRY/.test(active.out) && /SHADE_TREE_RPC_URL/.test(active.out) && /dry-run:/.test(active.out), "an active network record still supplies defaults and runs the child");
    ok(!/SHADE_TREE_GATEWAY_REGISTRY=|SHADE_TREE_RPC_URL=/.test(active.out.replace(/supplied [^\n]*/g, "")), "resolved values are never printed (only the variable names)");
  } finally {
    await rm(activeDir, { recursive: true, force: true });
  }
  const helpRd = shadeTreeCli(["record-deploy", "--help"]);
  ok(helpRd.code === 0 && /record-deploy/.test(helpRd.out), "`shade-tree record-deploy --help` is wired");

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: shade-tree CLI selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
