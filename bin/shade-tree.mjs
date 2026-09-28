#!/usr/bin/env node
// shade-tree — one entrypoint for Shade Tree.
//
// Every subcommand is a thin router: it maps clean --flags onto the SHADE_TREE_* environment the
// underlying module already reads (so flags and env vars stay in one-to-one sync and either
// works), then runs that module as a child so its own main() and lifecycle are unchanged.
//
//   shade-tree <command> [--flags] [args]
//
// Run `shade-tree help` for the command list, or `shade-tree <command> --help` for a command's flags.

import { spawn } from "node:child_process";
import { createConnection } from "node:net";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { readFileSync } from "node:fs";
import { validateConfig, formatErrors } from "../lib/config.mjs";
import { applyClientNetworkEnv, applyNetworkEnv, DEFAULT_CLIENT_NETWORK } from "../lib/network-record.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
const DEFAULT_NO_PROXY = ["127.0.0.1", "localhost", "::1", "host.docker.internal"];

// flag -> SHADE_TREE_ env var. A flag is valid for any command; it simply sets env, which is
// harmless where unused, and keeps the surface small and uniform.
const FLAG_ENV = {
  // global
  network: "SHADE_TREE_NETWORK",
  "rpc-url": "SHADE_TREE_RPC_URL",
  "tor-host": "SHADE_TREE_TOR_HOST",
  "tor-port": "SHADE_TREE_TOR_PORT",
  "epoch-seconds": "SHADE_TREE_EPOCH_SECONDS",
  "log-level": "SHADE_TREE_LOG_LEVEL",
  "log-format": "SHADE_TREE_LOG_FORMAT",
  "metrics-port": "SHADE_TREE_METRICS_PORT",
  "heartbeat-metrics-port": "SHADE_TREE_HEARTBEAT_METRICS_PORT",
  // bootnode
  port: "SHADE_TREE_BOOTNODE_PORT",
  admission: "SHADE_TREE_BOOTNODE_ADMISSION",
  ttl: "SHADE_TREE_BOOTNODE_TTL",
  "signer-key": "SHADE_TREE_BOOTNODE_SIGNER_KEY",
  "stake-mode": "SHADE_TREE_STAKE_MODE",
  "gateway-registry": "SHADE_TREE_GATEWAY_REGISTRY",
  "stake-allowlist": "SHADE_TREE_STAKE_ALLOWLIST",
  // gateway
  "gateway-port": "SHADE_TREE_GATEWAY_PORT",
  "group-contract": "SHADE_TREE_GROUP_CONTRACT",
  "root-provider": "SHADE_TREE_ROOT_PROVIDER",
  "slash-key": "SHADE_TREE_SLASH_KEY",
  "slash-contract": "SHADE_TREE_SLASH_CONTRACT",
  // client
  secret: "SHADE_TREE_SECRET",
  onion: "SHADE_TREE_ONION",
  bootnode: "SHADE_TREE_BOOTNODE_ONION",
  directory: "SHADE_TREE_DIRECTORY",
  "dir-signer": "SHADE_TREE_DIR_SIGNER",
  "directory-refresh-ms": "SHADE_TREE_DIRECTORY_REFRESH_MS",
  "rotation-spread": "SHADE_TREE_ROTATION_SPREAD",
  "shim-port": "SHADE_TREE_SHIM_PORT",
  // gateway announce / heartbeat
  identity: "SHADE_TREE_GW_IDENTITY",
  weight: "SHADE_TREE_GW_WEIGHT",
  interval: "SHADE_TREE_BOOTNODE_HEARTBEAT",
  "operator-key": "SHADE_TREE_GW_OPERATOR_KEY",
  operator: "SHADE_TREE_GW_OPERATOR",
  "operator-sig": "SHADE_TREE_GW_OPERATOR_SIG",
  "register-key": "SHADE_TREE_REGISTER_KEY",
  bond: "SHADE_TREE_BOND",
  // tiers / paid access (T-FEAT-7): the member's tier limit is read from SHADE_TREE_LIMIT by client,
  // identity and register-member alike, so `--limit` maps to it for every command.
  limit: "SHADE_TREE_LIMIT",
  "paid-access-contract": "SHADE_TREE_PAID_ACCESS_CONTRACT",
  roots: "SHADE_TREE_ROOTS",           // DEPRECATED alias of --admit (T-FEAT-9)
  // admission policy + payment rails (T-FEAT-9, docs/adr/0008)
  admit: "SHADE_TREE_ADMIT",                     // gateway: invited[,staked][,paid] (default invited = max-anon)
  "pay-protocols": "SHADE_TREE_PAY_PROTOCOLS",   // registrar / bootnode advert: x402,mpp subset
  "leaf-source": "SHADE_TREE_LEAF_SOURCE",       // client: auto|invited|staked|paid
  "max-anon": "SHADE_TREE_MAX_ANON",             // client: only invited-only gateways (bare flag => "true")
};

// command -> { script, help }. `long` marks a durable service (just for the help hint).
const COMMANDS = {
  run:               { help: "run an agent with process-scoped Shade Tree routing: shade-tree run [--proxy http://127.0.0.1:8888] -- <command> [args]" },
  keygen:            { script: "bootnode/keygen.mjs",       help: "mint an onion identity (refuses overwrite): shade-tree-node keygen <hsDir> [--label name] [--force]" },
  elder:             { script: "bootnode/server.mjs",       help: "run the Elder Tree, which signs the canopy directory", long: true },
  bootnode:          { script: "bootnode/server.mjs",       help: "legacy alias for `elder`", long: true },
  heartbeat:         { script: "bootnode/heartbeat.mjs",    help: "keep this node announced to the Elder Tree", long: true },
  join:              { script: "group/join.mjs",            help: "guided front door: `shade-tree-node join [member]` or `shade-tree-node join node`; make an identity + print the next commands (`gateway` remains an alias)" },
  enroll:            { script: "group/enroll.mjs",          help: "generate a member identity + print its secret/commitment" },
  identity:          { script: "group/identity.mjs",         help: "export the Rust client's --identity file {identitySecret, leaf} from your secret: shade-tree identity [--out <path>] [--secret-file <path>] (secret: --secret-file | SHADE_TREE_SECRET | ./.secret)" },
  "register-member": { script: "group/register-onchain.mjs", help: "stake a member commitment into StakedReputationSet: shade-tree register-member <commitment> [--limit N] (current Sepolia default: 1)" },
  pay:               { script: "group/pay.mjs",              help: "BUY a membership leaf over HTTP 402 (x402 or MPP; stablecoin, no gas): shade-tree-node pay --bootnode <onion> --limit 8|32 [--protocol x402|mpp] [--key-file <buyer-key>] [--dry-run]" },
  leaves:            { script: "group/leaves.mjs",           help: "export an on-chain set's ordered leaves as a members.json for the Rust client: shade-tree leaves --contract 0x.. [--out members.json]" },
  "register-gateway":{ script: "group/register-gateway.mjs", help: "stake a gateway operator bond into GatewayRegistry" },
  // exit/withdraw/status share one script (group/exit-gateway.mjs); `prepend` selects the mode.
  "exit-gateway":    { script: "group/exit-gateway.mjs", prepend: ["exit"],     help: "start the GatewayRegistry unbonding clock for this operator (leave the active set; stay slashable for UNBONDING): shade-tree-node exit-gateway [--dry-run]" },
  "withdraw-gateway":{ script: "group/exit-gateway.mjs", prepend: ["withdraw"], help: "after UNBONDING, reclaim the gateway bond: shade-tree-node withdraw-gateway [--recipient 0x..] [--dry-run]" },
  "gateway-status":  { script: "group/exit-gateway.mjs", prepend: ["status"],   help: "read-only: this operator's GatewayRegistry stake state (staked / exiting / withdrawableAt): shade-tree-node gateway-status [--operator 0x..]" },
  "sign-directory":  { script: "group/sign-directory.mjs",  help: "sign a static fleet directory (offline discovery)" },
  node:              { script: "gateway/gateway.mjs",       help: "run a proof-gated Shade Tree egress node", long: true },
  gateway:           { script: "gateway/gateway.mjs",       help: "legacy alias for `node`", long: true },
  proxy:             { script: "client/shim.mjs",           help: "run the local HTTP-CONNECT proxy", long: true },
  client:            { script: "client/shim.mjs",           help: "legacy alias for `proxy`", long: true },
  shim:              { script: "client/shim.mjs",           help: "legacy alias for `proxy`", long: true },
  doctor:            { script: "scripts/doctor.mjs",        help: "check the local setup (node, tor, keys, deps)" },
  // backup/restore share one script (scripts/backup.mjs); `prepend` selects the mode. The
  // passphrase is passed only via SHADE_TREE_BACKUP_PASSPHRASE (never on argv), inherited into the child.
  backup:            { script: "scripts/backup.mjs", prepend: ["backup"],  help: "encrypt & back up secret key material (onion seeds + signer key): shade-tree-node backup <srcDir> <outFile> (SHADE_TREE_BACKUP_PASSPHRASE)" },
  restore:           { script: "scripts/backup.mjs", prepend: ["restore"], help: "restore an encrypted key backup: shade-tree-node restore <inFile> <destDir> [--force] (SHADE_TREE_BACKUP_PASSPHRASE)" },
  "record-deploy":   { script: "scripts/record-deploy.mjs", help: "record a broadcast contract deploy into network/<name>/contracts.json: shade-tree-node record-deploy --network <name> --from-broadcast <run-latest.json>" },
};

// command -> config ROLE (lib/config.mjs). Before spawning a service we validate the effective
// SHADE_TREE_* env for its role and fail fast on a misconfig, instead of surfacing an opaque crash deep
// inside Tor/RPC/crypto. Only commands whose role's required vars genuinely apply are listed:
//   - heartbeat is gateway-SIDE, so it shares the gateway role.
//   - client/shim share the client role (SHADE_TREE_SECRET + a discovery source are the real needs).
//   - register-member maps to member-enroll (the on-chain member registration vars).
// Deliberately NOT validated (skipped): keygen/enroll/join/sign-directory/doctor read no service
// config, and register-gateway has no role whose required vars map cleanly (its bond/registry/
// register-key inputs don't match any ROLE_SPEC), so we do not guess — it spawns unvalidated.
const COMMAND_ROLE = {
  elder: "bootnode",
  bootnode: "bootnode",
  node: "gateway",
  gateway: "gateway",
  heartbeat: "gateway",
  proxy: "client",
  client: "client",
  shim: "client",
  "register-member": "member-enroll",
};

function parse(argv) {
  const flags = {}, positionals = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") { flags.help = true; continue; }
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      if (eq !== -1) { flags[a.slice(2, eq)] = a.slice(eq + 1); }
      else if (i + 1 < argv.length && !argv[i + 1].startsWith("--")) { flags[a.slice(2)] = argv[++i]; }
      else { flags[a.slice(2)] = "true"; }
    } else positionals.push(a);
  }
  return { flags, positionals };
}

function topHelp() {
  console.log(`shade-tree ${pkg.version}: Shade Tree\n`);
  console.log("usage: shade-tree <command> [--flags] [args]\n");
  const order = ["run", "proxy", "node", "elder", "join", "keygen", "heartbeat", "enroll", "identity", "register-member", "pay", "leaves", "register-gateway", "exit-gateway", "withdraw-gateway", "gateway-status", "sign-directory", "doctor", "backup", "restore", "record-deploy", "client", "shim", "gateway", "bootnode"];
  for (const name of order) console.log(`  ${name.padEnd(18)}${COMMANDS[name].help}`);
  console.log(`\ncommon flags: --bootnode <onion> --secret <hex> --port N --admission open|stake --stake-mode onchain|mock`);
  console.log(`operator output: --log-level debug|info|warn|error|off --log-format auto|pretty|text|json --metrics-port N --banner|--no-banner --quiet`);
  console.log(`admission (T-FEAT-9): node --admit invited[,staked][,paid] (default invited); proxy --leaf-source auto|invited|staked|paid, --max-anon`);
  console.log(`every --flag maps to an SHADE_TREE_* env var (see docs/CLI.md); flags override the environment.`);
  console.log(`--network <name> (SHADE_TREE_NETWORK) fills unset vars from network/<name> records; clients default to ${DEFAULT_CLIENT_NETWORK}.`);
}

function runHelp() {
  console.log(`shade-tree run: start one command with scoped HTTP(S) proxy settings\n`);
  console.log("usage: shade-tree run [--proxy URL] [--no-proxy HOSTS] [--check-timeout-ms N] -- <command> [args]");
  console.log("\nThe local proxy is checked before launch. If it is unavailable, the command is not run.");
  console.log("Only the child receives proxy variables; the current shell and unrelated services are unchanged.");
  console.log("Proxy credentials and other inherited SHADE_TREE_* settings are stripped from the child.");
  console.log("Uppercase and lowercase HTTP(S)/WSS proxy variables are set; inherited ALL_PROXY is removed.");
  console.log("Loopback services bypass the proxy. Add other agent-local hosts with --no-proxy.");
  console.log("Software that ignores standard proxy environment variables is not routed by this wrapper.");
}

function proxyHelp(command = "proxy") {
  console.log(`shade-tree ${command}: run the loopback HTTP-CONNECT Proxy for one or more local agents\n`);
  console.log("usage: shade-tree proxy [--bootnode ONION --dir-signer HEX] [--limit N] [--tor-port N]");
  console.log("   or: shade-tree proxy --onion NODE_ONION [--limit N] [--tor-port N]\n");
  console.log("Load the member secret without putting it in shell history or process arguments:");
  console.log("  read -s SHADE_TREE_SECRET && export SHADE_TREE_SECRET\n");
  console.log("The bundled Sepolia profile uses public staked tier 1; invited/alternate profiles also set");
  console.log("SHADE_TREE_MEMBERS_FILE and their exact tier. Start Tor first, then route one child with:");
  console.log("  shade-tree run -- your-agent\n");
  console.log(`Discovery defaults to the bundled current v4 ${DEFAULT_CLIENT_NETWORK} Elder and refreshes its signed Canopy about every five minutes.`);
  console.log("An explicit --bootnode/--dir-signer, --directory/--dir-signer, or --onion overrides discovery.");
  console.log("New tunnels rotate smoothly across healthy weighted gateways by default; --no-rotation-spread restores weighted-random first picks.");
  console.log("The bundled staking contract/RPC/tier/rate policy need no flags; alternate canopies do.");
  console.log("Guide: https://github.com/dmarzzz/shade-tree-node/blob/main/docs/AGENT.md");
}

function nodeHelp(command = "node") {
  console.log(`shade-tree ${command}: run the proof-gated destination-facing Shade Tree node\n`);
  console.log("usage: shade-tree-node node --admit invited[,staked][,paid] [operator flags]\n");
  console.log("A node verifies one RLN proof before each CONNECT tunnel and publishes no direct listener;");
  console.log("Tor maps its onion service to the loopback gateway. Keep private services unreachable.");
  console.log("Public rollout remains blocked by the deployment gates and development ZK setup.\n");
  console.log("Guided local setup: shade-tree-node join node");
  console.log("Guide: https://github.com/dmarzzz/shade-tree-node/blob/main/docs/OPERATOR.md");
}

function parseRunArgs(argv) {
  if (argv.length === 1 && (argv[0] === "--help" || argv[0] === "-h")) return { help: true };
  const separator = argv.indexOf("--");
  if (separator === -1) throw new Error("missing `--` before the command");
  const { flags, positionals } = parse(argv.slice(0, separator));
  if (positionals.length) throw new Error(`unexpected argument before \`--\`: ${positionals[0]}`);
  const allowed = new Set(["proxy", "no-proxy", "check-timeout-ms"]);
  const unknown = Object.keys(flags).find((flag) => !allowed.has(flag));
  if (unknown) throw new Error(`unknown run flag: --${unknown}`);
  const command = argv[separator + 1];
  if (!command) throw new Error("missing command after `--`");
  return { flags, command, args: argv.slice(separator + 2) };
}

function proxyUrlFor(flags, env) {
  const fallbackPort = Number(env.SHADE_TREE_SHIM_PORT || 8888);
  const raw = flags.proxy || env.SHADE_TREE_PROXY_URL || `http://127.0.0.1:${fallbackPort}`;
  let url;
  try { url = new URL(raw); } catch { throw new Error(`invalid proxy URL: ${raw}`); }
  if (url.protocol !== "http:") throw new Error("the preview supports an http:// CONNECT proxy URL only");
  if (!url.hostname || url.pathname !== "/" || url.search || url.hash) {
    throw new Error(`proxy URL must contain only a host and port: ${raw}`);
  }
  return url;
}

function noProxyFor(flags, env) {
  const extra = flags["no-proxy"] ?? env.SHADE_TREE_NO_PROXY ?? "";
  if (extra === "true") throw new Error("--no-proxy requires a comma-separated value");
  const values = [...DEFAULT_NO_PROXY, ...String(extra).split(",")]
    .map((value) => value.trim())
    .filter(Boolean);
  if (values.includes("*")) throw new Error("a wildcard `*` in --no-proxy would bypass Shade Tree");
  return [...new Set(values)].join(",");
}

function checkProxy(url, timeoutMs) {
  const port = Number(url.port || 80);
  const host = url.hostname.replace(/^\[|\]$/g, "");
  return new Promise((resolve, reject) => {
    let settled = false;
    const socket = createConnection({ host, port });
    const timer = setTimeout(() => {
      done(new Error(`proxy check timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    const done = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (error) reject(error); else resolve();
    };
    socket.once("connect", () => done());
    socket.once("error", (error) => done(error));
  });
}

function scopedProxyEnv(base, proxyUrl, noProxy) {
  const env = { ...base };
  // The Proxy owns every SHADE_TREE_* credential and operator setting. The agent child needs
  // only the three scoped routing markers installed below. In particular, a user commonly
  // exports SHADE_TREE_SECRET to start the Proxy from one terminal; inheriting it here would
  // hand the member credential to the very agent process the Proxy is meant to isolate.
  for (const key of Object.keys(env)) {
    if (key.startsWith("SHADE_TREE_")) delete env[key];
  }
  for (const key of ["ALL_PROXY", "all_proxy"]) delete env[key];
  Object.assign(env, {
    HTTPS_PROXY: proxyUrl,
    https_proxy: proxyUrl,
    HTTP_PROXY: proxyUrl,
    http_proxy: proxyUrl,
    WSS_PROXY: proxyUrl,
    wss_proxy: proxyUrl,
    NO_PROXY: noProxy,
    no_proxy: noProxy,
    NODE_USE_ENV_PROXY: "1",
    SHADE_TREE_ACTIVE: "1",
    SHADE_TREE_PROXY_URL: proxyUrl,
    SHADE_TREE_NO_PROXY: noProxy,
  });
  return env;
}

function forwardChild(child, label) {
  let settled = false;
  const forwarded = new Map();
  const stopForwarding = () => {
    for (const [signal, handler] of forwarded) process.removeListener(signal, handler);
  };
  child.once("error", (error) => {
    if (settled) return;
    settled = true;
    stopForwarding();
    console.error(`${label}: could not start child: ${error.message}`);
    process.exit(127);
  });
  child.once("exit", (code, signal) => {
    if (settled) return;
    settled = true;
    stopForwarding();
    if (signal) process.kill(process.pid, signal); else process.exit(code ?? 1);
  });
  for (const signal of ["SIGINT", "SIGTERM"]) {
    const handler = () => { try { child.kill(signal); } catch {} };
    forwarded.set(signal, handler);
    process.on(signal, handler);
  }
}

async function runScoped(argv) {
  let parsed;
  try { parsed = parseRunArgs(argv); } catch (error) {
    console.error(`shade-tree run: ${error.message}\n`);
    runHelp();
    process.exit(2);
  }
  if (parsed.help) { runHelp(); process.exit(0); }

  let url, noProxy, timeoutMs;
  try {
    url = proxyUrlFor(parsed.flags, process.env);
    noProxy = noProxyFor(parsed.flags, process.env);
    timeoutMs = Number(parsed.flags["check-timeout-ms"] || process.env.SHADE_TREE_PROXY_CHECK_TIMEOUT_MS || 2000);
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30_000) {
      throw new Error("--check-timeout-ms must be an integer from 1 to 30000");
    }
    await checkProxy(url, timeoutMs);
  } catch (error) {
    console.error(`shade-tree run: local proxy unavailable; command not started (${error.message})`);
    process.exit(1);
  }

  const proxyUrl = url.toString().replace(/\/$/, "");
  const env = scopedProxyEnv(process.env, proxyUrl, noProxy);
  const child = spawn(parsed.command, parsed.args, { stdio: "inherit", env, shell: false });
  forwardChild(child, "shade-tree run");
}

async function main() {
  const [, , cmd, ...rest] = process.argv;
  if (!cmd || cmd === "help" || cmd === "--help" || cmd === "-h") { topHelp(); process.exit(0); }
  if (cmd === "version" || cmd === "--version") { console.log(pkg.version); process.exit(0); }
  const entry = COMMANDS[cmd];
  if (!entry) { console.error(`unknown command: ${cmd}\n`); topHelp(); process.exit(1); }
  if (cmd === "run") { await runScoped(rest); return; }

  const { flags, positionals } = parse(rest);
  if (flags.help) {
    if (["proxy", "client", "shim"].includes(cmd)) proxyHelp(cmd);
    else if (["node", "gateway"].includes(cmd)) nodeHelp(cmd);
    else console.log(`shade-tree ${cmd}: ${entry.help}`);
    process.exit(0);
  }

  // Opt-out for unusual setups: `--no-validate` (or SHADE_TREE_SKIP_VALIDATE=1) bypasses the config
  // check below. Consume the flag here so it never leaks to the child as a passthrough arg.
  const skipValidate = "no-validate" in flags || process.env.SHADE_TREE_SKIP_VALIDATE === "1";
  delete flags["no-validate"];

  const env = { ...process.env };
  const passthrough = []; // flags the module parses itself (e.g. keygen --label)
  if (Object.hasOwn(flags, "quiet")) {
    if (!Object.hasOwn(flags, "log-level")) env.SHADE_TREE_LOG_LEVEL = "warn";
    delete flags.quiet;
  }
  if (Object.hasOwn(flags, "banner")) {
    env.SHADE_TREE_BANNER = flags.banner === "true" ? "always" : flags.banner;
    delete flags.banner;
  }
  if (Object.hasOwn(flags, "no-banner")) {
    env.SHADE_TREE_BANNER = "never";
    delete flags["no-banner"];
  }
  if (Object.hasOwn(flags, "no-rotation-spread")) {
    env.SHADE_TREE_ROTATION_SPREAD = "0";
    delete flags["no-rotation-spread"];
  }
  for (const [flag, val] of Object.entries(flags)) {
    // Heartbeat owns a dedicated metrics variable because it runs beside the node. Keep the
    // common --metrics-port interface useful by routing it to that variable for this command.
    const envKey = cmd === "heartbeat" && flag === "metrics-port"
      ? "SHADE_TREE_HEARTBEAT_METRICS_PORT"
      : FLAG_ENV[flag];
    if (envKey) env[envKey] = val;
    else { passthrough.push(`--${flag}`); if (val !== "true") passthrough.push(val); }
  }

  // Named network records fill unset values. Client commands additionally use the bundled current
  // v4 profile when no discovery source was supplied. Explicit flags/env always win, and non-client
  // services never inherit that client default.
  const role = COMMAND_ROLE[cmd];
  const usesClientNetwork = role === "client" || ["enroll", "identity", "register-member"].includes(cmd);
  if (env.SHADE_TREE_NETWORK || usesClientNetwork) {
    try {
      const filled = usesClientNetwork ? applyClientNetworkEnv(env) : applyNetworkEnv(env);
      if (filled.length) {
        const network = env.SHADE_TREE_NETWORK || DEFAULT_CLIENT_NETWORK;
        console.error(`shade-tree ${cmd}: network "${network}" supplied ${filled.join(", ")}`);
      }
    } catch (e) {
      const network = env.SHADE_TREE_NETWORK || DEFAULT_CLIENT_NETWORK;
      console.error(`shade-tree ${cmd}: SHADE_TREE_NETWORK=${network}: ${e.message}`);
      process.exit(1);
    }
  }

  // Fail fast on invalid config BEFORE spawning a service: print exactly which SHADE_TREE_* var is
  // wrong and why, then exit nonzero (never start the long-running process on a known-bad env).
  if (role && !skipValidate) {
    const result = validateConfig(role, env);
    if (!result.ok) {
      console.error(`shade-tree ${cmd}: config invalid for role "${role}":`);
      console.error(formatErrors(result));
      console.error(`\nfix the above, or pass --no-validate (or set SHADE_TREE_SKIP_VALIDATE=1) to bypass.`);
      process.exit(1);
    }
  }

  const child = spawn(process.execPath, [join(ROOT, entry.script), ...(entry.prepend || []), ...positionals, ...passthrough], { stdio: "inherit", env });
  forwardChild(child, `shade-tree ${cmd}`);
}

main().catch((error) => { console.error(`shade-tree: ${error.message}`); process.exit(1); });
