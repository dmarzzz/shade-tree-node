// exit-gateway: the operator-side EXIT half of GatewayRegistry (contracts/GatewayRegistry.sol) —
// the dual of group/register-gateway.mjs and the rollback for a staked gateway
// (docs/OPERATOR.md section 6). One script, three modes selected by the first argument (the
// shade-tree router prepends it: `shade-tree-node exit-gateway` / `shade-tree-node withdraw-gateway` / `shade-tree-node gateway-status`):
//
//   exit      initiateExit()        operator-only. Start the UNBONDING clock and leave the active
//                                   set (bootnode admission=stake stops admitting this operator on
//                                   its next refresh). You STAY SLASHABLE for the whole window.
//   withdraw  withdraw(recipient)   operator-only. After UNBONDING, if not slashed, the BOND is paid
//                                   to --recipient (default: the operator address itself).
//   status    (read-only)           staked? exiting? withdrawableAt, BOND/UNBONDING, chain time.
//
// Every mode reads the on-chain state FIRST and refuses to send a tx the contract would revert
// (NotStaked / AlreadyExiting / NotExiting / StillBonded), printing why and, for StillBonded, when.
// `--dry-run` prints the target, from, calldata and an eth_call simulation and NEVER broadcasts.
//
// Signer (the operator key that called register()), first match wins — never on argv:
//   --key-file <path>          hex private key in a file (0600)
//   --account <name>           Foundry encrypted keystore ~/.foundry/keystores/<name>
//                              (`cast wallet import <name> --interactive`), or --keystore <json path>;
//                              password from SHADE_TREE_KEYSTORE_PASSWORD or an interactive prompt (no echo)
//   SHADE_TREE_REGISTER_KEY          env (same var register-gateway uses); SHADE_TREE_GW_OPERATOR_KEY (the
//                              heartbeat's) is accepted as a fallback — it is the same operator key
//   (dev) anvil account #1     ONLY when the RPC is a loopback URL, mirroring register-gateway
// `status` and `--dry-run` need no key: give --operator 0x.. (SHADE_TREE_GW_OPERATOR) instead.
// The key is never printed; only the derived address is.
//
// Config (same names as register-gateway):
//   SHADE_TREE_RPC_URL           JSON-RPC endpoint            (default: deployed.rpcUrl or anvil)
//   SHADE_TREE_GATEWAY_REGISTRY  GatewayRegistry address      (default: deployed.gatewayRegistry)
//
// Usage: node group/exit-gateway.mjs <exit|withdraw|status> [--dry-run] [--recipient 0x..]
//          [--operator 0x..] [--key-file <p> | --account <n> | --keystore <p>]

import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { makeBoundedJsonRpcProvider, rpcTimeoutMs, waitForTransactionReceipt } from "../packages/node/lib/rpc-safety.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const DEPLOYED_PATH = join(HERE, "..", "contracts", "deployed.local.json");
// anvil's deterministic account #1 — dev only (register-gateway's default operator).
const ANVIL_KEY_1 = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

export const ABI = [
  "function initiateExit()",
  "function withdraw(address recipient)",
  "function isStaked(address) view returns (bool)",
  "function withdrawableAt(address) view returns (uint256)",
  "function stakes(address) view returns (uint256 bond, uint64 index, uint64 exitInitiatedAt)",
  "function BOND() view returns (uint256)",
  "function UNBONDING() view returns (uint256)",
  "event GatewayExiting(address indexed operator, uint64 exitInitiatedAt, uint64 withdrawableAt)",
  "event GatewayWithdrawn(address indexed operator, address indexed recipient)",
];

const MODES = new Set(["exit", "withdraw", "status"]);
const USAGE = "usage: node group/exit-gateway.mjs <exit|withdraw|status> [--dry-run] [--recipient 0x..] [--operator 0x..] [--key-file <p> | --account <n> | --keystore <p>]";

function parseArgs(argv) {
  const opts = { mode: null, dryRun: false, recipient: null, operator: null, keyFile: null, account: null, keystore: null };
  const withValue = { recipient: "recipient", operator: "operator", "key-file": "keyFile", account: "account", keystore: "keystore" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") { console.log(USAGE); process.exit(0); }
    if (!a.startsWith("--")) {
      if (opts.mode === null && MODES.has(a)) { opts.mode = a; continue; }
      console.error(`exit-gateway: unexpected argument ${a}\n${USAGE}`); process.exit(2);
    }
    const eq = a.indexOf("=");
    const key = eq === -1 ? a.slice(2) : a.slice(2, eq);
    if (key === "dry-run") { opts.dryRun = true; continue; }
    if (!(key in withValue)) { console.error(`exit-gateway: unknown flag --${key}\n${USAGE}`); process.exit(2); }
    const val = eq === -1 ? argv[++i] : a.slice(eq + 1);
    if (val === undefined || val === "" || val.startsWith("--")) { console.error(`exit-gateway: --${key} needs a value\n${USAGE}`); process.exit(2); }
    opts[withValue[key]] = val;
  }
  if (!opts.mode) { console.error(`exit-gateway: mode required (exit | withdraw | status)\n${USAGE}`); process.exit(2); }
  return opts;
}

async function readDeployed() {
  try { return JSON.parse(await readFile(DEPLOYED_PATH, "utf8")); } catch { return {}; }
}

function isLoopback(url) {
  try { const h = new URL(url).hostname; return h === "127.0.0.1" || h === "localhost" || h === "::1" || h === "[::1]"; } catch { return false; }
}

// Prompt for a keystore password on the controlling TTY with echo suppressed. Never logged.
async function promptPassword(label) {
  if (!process.stdin.isTTY) throw new Error("keystore password: set SHADE_TREE_KEYSTORE_PASSWORD (stdin is not a TTY)");
  const rl = createInterface({ input: process.stdin, output: process.stderr, terminal: true });
  const mute = () => {};
  rl._writeToOutput = mute; // hide the echo
  process.stderr.write(label);
  const pw = await new Promise((res) => rl.question("", res));
  rl.close();
  process.stderr.write("\n");
  return pw;
}

// Resolve the operator signer. Returns { wallet, how } (how = a printable label, never the key),
// or { wallet: null } when only an address is available/needed.
async function resolveSigner(opts, { ethers, provider, rpcUrl, env = process.env }) {
  const fromKey = (key, how) => {
    const k = key.trim();
    if (!/^(0x)?[0-9a-fA-F]{64}$/.test(k)) throw new Error(`${how}: not a 32-byte hex private key (value not shown)`);
    return { wallet: new ethers.Wallet(k.startsWith("0x") ? k : "0x" + k, provider), how };
  };
  if (opts.keyFile) {
    if (!existsSync(opts.keyFile)) throw new Error(`--key-file not found: ${opts.keyFile}`);
    return fromKey(await readFile(opts.keyFile, "utf8"), `--key-file ${opts.keyFile}`);
  }
  if (opts.account || opts.keystore) {
    const path = opts.keystore || join(env.FOUNDRY_KEYSTORES || join(homedir(), ".foundry", "keystores"), opts.account);
    if (!existsSync(path)) throw new Error(`keystore not found: ${path}`);
    const json = await readFile(path, "utf8");
    const password = env.SHADE_TREE_KEYSTORE_PASSWORD ?? (await promptPassword(`keystore password for ${opts.account || path}: `));
    let w;
    try { w = await ethers.Wallet.fromEncryptedJson(json, password); }
    catch { throw new Error(`keystore ${path}: could not decrypt (wrong password?)`); }
    return { wallet: w.connect(provider), how: opts.account ? `--account ${opts.account}` : `--keystore ${path}` };
  }
  if (env.SHADE_TREE_REGISTER_KEY) return fromKey(env.SHADE_TREE_REGISTER_KEY, "SHADE_TREE_REGISTER_KEY");
  if (env.SHADE_TREE_GW_OPERATOR_KEY) return fromKey(env.SHADE_TREE_GW_OPERATOR_KEY, "SHADE_TREE_GW_OPERATOR_KEY");
  // dev default only when no explicit --operator was given (an explicit address means "look at
  // that operator", not "sign as anvil #1").
  if (isLoopback(rpcUrl) && !opts.operator && !env.SHADE_TREE_GW_OPERATOR) return fromKey(ANVIL_KEY_1, "anvil account #1 (dev default; loopback RPC)");
  return { wallet: null, how: null };
}

const iso = (sec) => new Date(Number(sec) * 1000).toISOString();

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const deployed = await readDeployed();
  const rpcUrl = process.env.SHADE_TREE_RPC_URL || deployed.rpcUrl || "http://127.0.0.1:8545";
  const address = process.env.SHADE_TREE_GATEWAY_REGISTRY || deployed.gatewayRegistry || deployed.GatewayRegistry;
  if (!address) {
    console.error("no GatewayRegistry address: set SHADE_TREE_GATEWAY_REGISTRY or write contracts/deployed.local.json");
    process.exit(1);
  }

  let ethers;
  try { ({ ethers } = await import("ethers")); }
  catch { console.error("exit-gateway needs the `ethers` dependency."); process.exit(1); }
  if (!ethers.isAddress(address)) { console.error(`SHADE_TREE_GATEWAY_REGISTRY is not an address: ${address}`); process.exit(1); }
  const iface = new ethers.Interface(ABI);

  // --- offline part first: the calldata is a pure function of (mode, recipient) -----------------
  const operatorFlag = opts.operator || process.env.SHADE_TREE_GW_OPERATOR || null;
  if (operatorFlag && !ethers.isAddress(operatorFlag)) { console.error(`--operator is not an address: ${operatorFlag}`); process.exit(1); }
  if (opts.recipient && !ethers.isAddress(opts.recipient)) { console.error(`--recipient is not an address: ${opts.recipient}`); process.exit(1); }
  if (opts.recipient && opts.mode !== "withdraw") { console.error("--recipient only applies to withdraw"); process.exit(2); }

  const verb = { exit: "exit-gateway (initiateExit)", withdraw: "withdraw-gateway (withdraw)", status: "gateway-status" }[opts.mode];
  console.log(`shade-tree ${verb}${opts.dryRun ? "  [DRY-RUN: nothing will be broadcast]" : ""}`);
  console.log(`  contract: ${address}`);
  console.log(`  rpc:      ${rpcUrl}`);

  // --- rpc + signer ------------------------------------------------------------------------------
  let chainId;
  let provider = null;
  try {
    provider = await makeBoundedJsonRpcProvider(ethers, rpcUrl, { timeoutMs: rpcTimeoutMs() });
    chainId = (await provider.getNetwork()).chainId;
  }
  catch (e) {
    console.error(`  rpc:      UNREACHABLE (${e.message})`);
    if (!opts.dryRun) { console.error("exit-gateway failed: RPC unreachable"); process.exit(1); }
  }

  let wallet = null, how = null;
  const needsKey = !opts.dryRun && opts.mode !== "status";
  try { ({ wallet, how } = await resolveSigner(opts, { ethers, provider, rpcUrl })); }
  catch (e) { console.error(`exit-gateway failed: ${e.message}`); process.exit(1); }
  const operator = wallet ? wallet.address : operatorFlag;
  if (needsKey && !wallet) {
    console.error("exit-gateway failed: no operator key (use --key-file / --account / --keystore, or SHADE_TREE_REGISTER_KEY); this mode signs a tx");
    process.exit(1);
  }
  if (!operator) {
    console.error("exit-gateway failed: need an operator — pass --operator 0x.. (or SHADE_TREE_GW_OPERATOR) or a signer");
    process.exit(1);
  }
  if (operatorFlag && wallet && operatorFlag.toLowerCase() !== wallet.address.toLowerCase()) {
    console.error(`exit-gateway failed: --operator ${operatorFlag} != signer address ${wallet.address} (the contract keys stakes to msg.sender)`);
    process.exit(1);
  }
  console.log(`  operator: ${operator}${how ? `   (signer: ${how})` : "   (address only; no signer)"}`);
  if (chainId !== undefined) console.log(`  chainId:  ${chainId}`);

  const recipient = opts.mode === "withdraw" ? (opts.recipient || operator) : null;
  const calldata = opts.mode === "exit" ? iface.encodeFunctionData("initiateExit", [])
    : opts.mode === "withdraw" ? iface.encodeFunctionData("withdraw", [recipient]) : null;
  if (calldata) {
    console.log(`  tx:       to=${address} value=0 data=${calldata}`);
    if (recipient) console.log(`  recipient:${recipient}${opts.recipient ? "" : "   (default: the operator; pass --recipient to redirect)"}`);
  }

  if (!provider) { // dry-run with the chain unreachable: calldata printed; nothing else to do
    console.log("  status:   skipped (rpc unreachable)  — dry-run complete, nothing broadcast");
    return;
  }

  // --- on-chain state -----------------------------------------------------------------------------
  const contract = new ethers.Contract(address, ABI, wallet || provider);
  let st;
  try {
    const [stake, staked, wAt, bond, unbonding, block] = await Promise.all([
      contract.stakes(operator), contract.isStaked(operator), contract.withdrawableAt(operator),
      contract.BOND(), contract.UNBONDING(), provider.getBlock("latest"),
    ]);
    st = { bond: stake.bond, index: stake.index, exitInitiatedAt: stake.exitInitiatedAt, staked, wAt, BOND: bond, UNBONDING: unbonding, now: BigInt(block.timestamp) };
  } catch (e) {
    console.error(`exit-gateway failed: cannot read GatewayRegistry at ${address}: ${e.shortMessage || e.message} (wrong address/chain?)`);
    process.exit(1);
  }
  const state = st.bond === 0n ? "not staked" : st.exitInitiatedAt === 0n ? "staked (active)" : "exiting";
  console.log(`  state:    ${state}`);
  console.log(`  BOND:     ${st.BOND} wei   UNBONDING: ${st.UNBONDING} s   chain time: ${iso(st.now)}`);
  if (st.bond !== 0n) console.log(`  stake:    bond=${st.bond} wei index=${st.index}${st.exitInitiatedAt !== 0n ? ` exitInitiatedAt=${iso(st.exitInitiatedAt)}` : ""}`);
  if (st.wAt !== 0n) {
    const left = st.wAt - st.now;
    console.log(`  withdrawableAt: ${st.wAt} (${iso(st.wAt)})${left > 0n ? `  — in ${left} s` : "  — NOW (window elapsed)"}`);
  }
  if (opts.mode === "status") return;

  // --- preflight: refuse what the contract would revert, with the reason ---------------------------
  const refuse = (msg) => { console.error(`exit-gateway: refusing to send — ${msg}`); process.exit(1); };
  if (opts.mode === "exit") {
    if (st.bond === 0n) refuse("operator is not staked (NotStaked); nothing to exit");
    if (st.exitInitiatedAt !== 0n) { console.log(`  already exiting (AlreadyExiting); withdraw after ${iso(st.wAt)} with: shade-tree-node withdraw-gateway`); return; }
  } else {
    if (st.bond === 0n) refuse("operator is not staked (NotStaked); nothing to withdraw (already withdrawn or slashed?)");
    if (st.exitInitiatedAt === 0n) refuse("operator has not started exiting (NotExiting); run `shade-tree-node exit-gateway` first, then wait UNBONDING");
    if (st.now < st.wAt) refuse(`still bonded (StillBonded) until ${iso(st.wAt)} — ${st.wAt - st.now} s to go`);
  }

  // --- simulate (both modes; dry-run stops here) --------------------------------------------------
  const from = operator;
  try {
    await provider.call({ to: address, from, data: calldata });
    console.log(`  simulate: ok (eth_call from ${from} does not revert)`);
  } catch (e) {
    const reason = e.revert?.name || e.shortMessage || e.message;
    console.error(`  simulate: REVERT (${reason})`);
    if (opts.dryRun) { console.log("  dry-run complete — nothing broadcast"); process.exit(1); }
    console.error("exit-gateway failed: simulation reverted; not sending"); process.exit(1);
  }
  if (opts.dryRun) { console.log("  dry-run complete — nothing broadcast"); return; }

  // --- send ---------------------------------------------------------------------------------------
  const tx = opts.mode === "exit" ? await contract.initiateExit() : await contract.withdraw(recipient);
  console.log(`  tx:       ${tx.hash}  (waiting...)`);
  const rcpt = await waitForTransactionReceipt(tx, {
    operation: opts.mode === "exit" ? "gateway exit" : "gateway withdrawal",
  });
  if (opts.mode === "exit") {
    const ev = rcpt.logs.map((l) => { try { return iface.parseLog(l); } catch { return null; } }).find((p) => p && p.name === "GatewayExiting");
    const wAt = ev ? ev.args.withdrawableAt : st.now + st.UNBONDING;
    console.log(`  mined in block ${rcpt.blockNumber}; exiting. Bond withdrawable at ${wAt} (${iso(wAt)}) via: shade-tree-node withdraw-gateway`);
    console.log(`  next:     stop announcing — systemctl disable --now shade-tree-heartbeat shade-tree-gateway (docs/OPERATOR.md section 6)`);
  } else {
    console.log(`  mined in block ${rcpt.blockNumber}; bond ${st.bond} wei paid to ${recipient}. Stake record cleared.`);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => { console.error("exit-gateway failed:", e.shortMessage || e.message); process.exit(1); });
}
