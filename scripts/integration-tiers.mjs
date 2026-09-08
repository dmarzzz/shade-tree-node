// integration-tiers: the stake -> use -> over-spend -> slash loop against a TIERED
// StakedReputationSet (rln-v4, T-FEAT-8b) with the REAL gateway process in ON-CHAIN ROOT MODE
// and REAL RLN Groth16 proofs. One module, two callers:
//
//   * test/onchain-tiers.selftest.mjs  — a throwaway anvil (deployed by contracts/script/
//     DeployRegistry.s.sol with a two-tier table), local TCP egress targets; asserts everything.
//   * node scripts/integration-tiers.mjs — LIVE Sepolia (or any chain): env-driven, prints the
//     timestamped timeline that network/sepolia/integration-report-rln-v4.md records.
//
// Flow (mirrors network/sepolia/integration-report-rln.md, now with tiers):
//   1. ALICE stakes at tier 8 (bondFor(8)), BOB at tier 32 (bondFor(32)) — via the real
//      `shade-tree register-member --limit N` command (group/register-onchain.mjs);
//   2. the ON-CHAIN currentRoot() equals the JS groupFromIdentities([{A,8},{B,32}]) root;
//   3. the gateway starts with SHADE_TREE_GROUP_CONTRACT (NodeRootProvider reconstructs the SAME
//      root from the rln-v4 events) + SHADE_TREE_SLASH_CONTRACT/SHADE_TREE_SLASH_KEY (tiered slasher);
//   4. ALICE: 3 tunnels at slots 0..2 (tier 8) -> PASS; BOB: a tunnel at slot 20 (a budget
//      only tier 32 has) -> PASS;
//   5. BOB over-spends slot 0 (two distinct signals, one nullifier) -> the gateway reconstructs
//      his identitySecret, resolves the tier ON CHAIN (limitOf), and submits
//      slash(leaf32, secret, 32, receiver) -> >=90% of BOB's TIER-32 bond burns, <=10% bounty;
//   6. a wrong-limit slash of ALICE (limit 32 for a tier-8 leaf) REVERTS (BadLimit) — proven
//      by a static call — and ALICE's bond is intact; the on-chain root now equals the JS tree
//      with BOB's leaf zeroed in place.
//
// Env (CLI mode; the selftest passes an options object):
//   SHADE_TREE_RPC_URL, SHADE_TREE_GROUP_CONTRACT (the rln-v4 set), SHADE_TREE_SLASH_KEY (gateway hot key; also
//   the staking funder unless SHADE_TREE_REGISTER_KEY is set), SHADE_TREE_SLASH_RECEIVER (default: the
//   slasher address), SHADE_TREE_MEMBER_A_SECRET / SHADE_TREE_MEMBER_B_SECRET (app seeds, 0x-hex; default:
//   fresh random ones — printed as commitments only), SHADE_TREE_CONFIRMATIONS (gateway root depth;
//   default 1 here so a fresh stake is visible without waiting for finality),
//   SHADE_TREE_TARGETS (comma list of host:port the gateway egresses to; default example.com:443,
//   api.ipify.org:443, cloudflare.com:443), SHADE_TREE_REPORT_OUT (write the timeline there).
//
// The gateway's egress connect is what acks ok:true, so the targets must be reachable from
// where this runs (the selftest uses local listeners + SHADE_TREE_EGRESS_ALLOW).

import net from "node:net";
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { ethers } from "ethers";
import {
  identityFor, identitySecretOf, rateCommitmentOf, groupFromIdentities, newGroup, deriveCommitment,
  currentEpoch, requestSignal, proveForSlot, toField, EPOCH_SECONDS,
} from "../lib/rln.mjs";
import { makeSlotPool, buildEnvelope } from "../client/shade-tree-client.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const CLI = join(ROOT, "bin", "shade-tree.mjs");
const GATEWAY_PORT = 8443; // gateway/gateway.mjs LISTEN_PORT (fixed; Tor maps the onion here)

export const SET_ABI = [
  "function SLASH_REWARD_DIVISOR() view returns (uint256)",
  "function SLASH_BURN_ADDRESS() view returns (address)",
  "event SlashPayout(uint256 indexed commitment, address indexed receiver, uint256 burned, uint256 reward)",
  "function BOND() view returns (uint256)",
  "function bondFor(uint256 limit) view returns (uint256)",
  "function allowedLimits() view returns (uint256[])",
  "function limitOf(uint256 commitment) view returns (uint256)",
  "function currentRoot() view returns (uint256)",
  "function activeCount() view returns (uint256)",
  "function members(uint256) view returns (uint256 bond, uint64 index, uint64 exitInitiatedAt, uint32 limit)",
  "function slash(uint256 commitment, uint256 secret, uint256 limit, address receiver)",
  "function withdrawVerifier() view returns (address)",
  "function hasher() view returns (address)",
  "error BadLimit()",
  "error BadSecret()",
  "error NotMember()",
];

// A member: app seed -> identity -> identitySecret -> tier leaf.
export function memberOf(seedHex, limit) {
  const identity = identityFor(toField(seedHex));
  const identitySecret = identitySecretOf(identity);
  const leaf = rateCommitmentOf(identity, limit).toString();
  return { seed: seedHex, identity, identitySecret, leaf, limit };
}

function makeLog(sink) {
  const T0 = Date.now();
  const trace = [];
  const log = (step, msg) => {
    const line = `[+${((Date.now() - T0) / 1000).toFixed(1).padStart(6)}s] ${step.padEnd(7)} ${msg}`;
    (sink || console.log)(line);
    trace.push(line);
  };
  return { log, trace };
}

// Send one explicit v4 envelope to the local gateway over TCP; resolve its ack line.
export function sendEnvelope(envelope, { port = GATEWAY_PORT, timeoutMs = 90000 } = {}) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(port, "127.0.0.1", () => sock.write(JSON.stringify(envelope) + "\n"));
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => { sock.destroy(); reject(new Error("no ack in " + timeoutMs + "ms")); }, timeoutMs);
    sock.on("data", (c) => {
      buf = Buffer.concat([buf, c]);
      const nl = buf.indexOf(0x0a);
      if (nl === -1) return;
      clearTimeout(timer);
      let ack;
      try { ack = JSON.parse(buf.subarray(0, nl).toString()); } catch (e) { reject(e); return; }
      sock.destroy();
      resolve(ack);
    });
    sock.on("error", (e) => { clearTimeout(timer); reject(e); });
  });
}

// Spawn the REAL gateway process. Resolves when it prints "gateway up on"; `out` accumulates
// its log so callers can grep the SLASH lines (same substrings integration-sepolia.mjs used).
export function startGateway(env, { log, timeoutMs = 60000 } = {}) {
  const st = { proc: null, out: "" };
  st.ready = new Promise((resolve, reject) => {
    st.proc = spawn(process.execPath, [join(ROOT, "gateway", "gateway.mjs")], { cwd: ROOT, env: { ...process.env, ...env } });
    const onData = (d) => {
      const s = d.toString(); st.out += s;
      s.split("\n").filter(Boolean).forEach((l) => log && log("gateway", l));
      if (s.includes("gateway up on")) resolve();
    };
    st.proc.stdout.on("data", onData);
    st.proc.stderr.on("data", onData);
    st.proc.on("exit", (c) => { if (c) reject(new Error("gateway exited " + c)); });
    setTimeout(() => reject(new Error("gateway did not start")), timeoutMs).unref();
  });
  st.stop = () => { try { st.proc.kill(); } catch { /* gone */ } };
  return st;
}

async function waitFor(pred, ms, stepMs = 500) {
  const start = Date.now();
  while (Date.now() - start < ms) {
    const v = await pred();
    if (v) return v;
    await new Promise((r) => setTimeout(r, stepMs));
  }
  return null;
}

// Stake `member` at its tier through the real CLI (`shade-tree register-member <leaf> --limit N`).
export function stakeViaCli(member, { rpcUrl, set, key }) {
  const r = spawnSync(process.execPath, [CLI, "register-member", member.leaf, "--limit", String(member.limit), "--rpc-url", rpcUrl, "--group-contract", set], {
    cwd: ROOT, encoding: "utf8", env: { ...process.env, SHADE_TREE_REGISTER_KEY: key, SHADE_TREE_NETWORK: "" }, timeout: 180000,
  });
  const out = (r.stdout || "") + (r.stderr || "");
  const tx = (out.match(/tx:\s+(0x[0-9a-fA-F]{64})/) || [])[1] || null;
  const block = Number((out.match(/mined in block (\d+)/) || [])[1] || 0) || null;
  return { code: r.status, out, tx, block };
}

/**
 * Run the whole loop. Returns { pass, checks: [{ ok, name }], trace, txs }.
 * opts: { rpcUrl, set, slashKey, registerKey?, receiver?, seedA?, seedB?, confirmations?, targets?,
 *         gatewayEnv?, log?, settle? (async () => {} to advance the chain one block, e.g. anvil_mine) }
 */
export async function runTierIntegration(opts) {
  const {
    rpcUrl, set, slashKey, registerKey = slashKey, receiver = null,
    seedA = "0x" + randomBytes(32).toString("hex"), seedB = "0x" + randomBytes(32).toString("hex"),
    confirmations = 1, targets = ["example.com:443", "api.ipify.org:443", "cloudflare.com:443"],
    gatewayEnv = {}, settle = null, sink = null,
  } = opts;
  const { log, trace } = makeLog(sink);
  const checks = [];
  const check = (ok, name) => { checks.push({ ok, name }); log(ok ? "ok" : "FAIL", name); return ok; };
  const txs = {};

  const provider = new ethers.JsonRpcProvider(rpcUrl, undefined, { staticNetwork: true });
  const slasher = new ethers.Wallet(slashKey, provider);
  const rcv = receiver || slasher.address;
  const c = new ethers.Contract(set, SET_ABI, provider);
  const [bond8, bond32, tiers, chainId] = await Promise.all([c.bondFor(8), c.bondFor(32), c.allowedLimits(), provider.getNetwork().then((n) => Number(n.chainId))]);
  // This acceptance run requires a fresh slash-burn-v1 set. An old compatible ABI
  // must not produce a passing report for a penalty it does not actually enforce.
  const [rewardDivisor, burnAddress] = await Promise.all([c.SLASH_REWARD_DIVISOR(), c.SLASH_BURN_ADDRESS()]);
  if (rewardDivisor !== 10n || burnAddress !== ethers.ZeroAddress) throw new Error("expected slash-burn-v1 (90% burn, 10% bounty)");
  const reward32 = bond32 / rewardDivisor;
  const burn32 = bond32 - reward32;
  log("setup", `StakedReputationSet ${set} chainId=${chainId} tiers=[${tiers.map(String).join(",")}] bond(8)=${ethers.formatEther(bond8)} ETH bond(32)=${ethers.formatEther(bond32)} ETH epoch ${currentEpoch()} (${EPOCH_SECONDS}s)`);
  check(bond32 > 0n && bond8 > 0n, "contract admits tiers 8 and 32 (bondFor nonzero)");

  const A = memberOf(seedA, 8);
  const B = memberOf(seedB, 32);
  log("setup", `member ALICE tier 8  leaf ${A.leaf.slice(0, 20)}..`);
  log("setup", `member BOB   tier 32 leaf ${B.leaf.slice(0, 20)}..`);
  const rcvBefore = await provider.getBalance(rcv);
  const burnBefore = await provider.getBalance(burnAddress);

  // 1. stake both at their tiers via the CLI
  let gw = null;
  try {
    for (const [name, m] of [["ALICE", A], ["BOB", B]]) {
      log("stake", `${name} register(leaf, ${m.limit}) + bond ${ethers.formatEther(m.limit === 8 ? bond8 : bond32)} ETH ...`);
      const r = stakeViaCli(m, { rpcUrl, set, key: registerKey });
      txs[`stake${name}`] = { tx: r.tx, block: r.block };
      check(r.code === 0 && !!r.tx, `${name} staked at tier ${m.limit} via \`shade-tree register-member --limit ${m.limit}\` (tx ${r.tx ? r.tx.slice(0, 12) + ".." : "none"} block ${r.block})`);
      if (r.code !== 0) log("stake", r.out.trim().split("\n").slice(-3).join(" | "));
    }
    const [mA, mB, active] = await Promise.all([c.members(A.leaf), c.members(B.leaf), c.activeCount()]);
    check(mA.bond === bond8 && Number(mA.limit) === 8, "ALICE on-chain: bond == bondFor(8), limit 8 recorded");
    check(mB.bond === bond32 && Number(mB.limit) === 32, "BOB   on-chain: bond == bondFor(32), limit 32 recorded");
    log("stake", `activeCount=${active} limitOf(A)=${await c.limitOf(A.leaf)} limitOf(B)=${await c.limitOf(B.leaf)}`);

    // 2. on-chain root == JS root of the two tier leaves
    const g = groupFromIdentities([{ identity: A.identity, limit: 8 }, { identity: B.identity, limit: 32 }]);
    const onChainRoot = (await c.currentRoot()).toString();
    check(onChainRoot === g.root.toString(), `currentRoot() == JS groupFromIdentities([{A,8},{B,32}]).root (${onChainRoot.slice(0, 16)}..)`);

    // Let the confirmation depth cover the stakes before the gateway reads its root.
    if (settle) await settle();
    else {
      const need = (txs.stakeBOB.block || 0) + confirmations;
      await waitFor(async () => (await provider.getBlockNumber()) >= need, 120000, 2000);
    }

    // 3. the REAL gateway in on-chain root mode + tiered on-chain slasher
    gw = startGateway({
      SHADE_TREE_RPC_URL: rpcUrl,
      SHADE_TREE_GROUP_CONTRACT: set,        // on-chain root mode (NodeRootProvider event reconstruction)
      SHADE_TREE_ADMIT: "staked",            // T-FEAT-9: admit the staked set ALONE (the default would be invited/members.json only)
      SHADE_TREE_ROOT_PROVIDER: "node",
      SHADE_TREE_CONFIRMATIONS: String(confirmations),
      SHADE_TREE_FROM_BLOCK: "0x" + Math.max(0, (txs.stakeALICE.block || 1) - 1).toString(16),
      SHADE_TREE_SLASH_CONTRACT: set,
      SHADE_TREE_SLASH_KEY: slashKey,
      SHADE_TREE_SLASH_RECEIVER: rcv,
      SHADE_TREE_TIERS: "8,32",
      SHADE_TREE_HELIOS_RPC_URL: "",
      SHADE_TREE_NETWORK: "",
      ...gatewayEnv,
    }, { log });
    await gw.ready;
    check(/rln-v4 tiered/.test(gw.out), "gateway detected the rln-v4 tiered slash ABI (DEFAULT_LIMIT probe)");
    check(/root source: on-chain RootProvider/.test(gw.out) && !/recentRoots=0\b/.test(gw.out), "gateway loaded its admission root from the chain (on-chain root mode)");

    // 4. normal use at both tiers
    const loadGroupFn = async () => ({ group: g });
    const poolA = makeSlotPool({ secret: A.seed, K: 8, loadGroupFn });
    for (let i = 0; i < 3; i++) {
      const target = targets[i % targets.length];
      const t0 = Date.now();
      const { envelope, slot } = await buildEnvelope({ secret: A.seed, target, pool: poolA });
      const ack = await sendEnvelope(envelope);
      log("alice", `tunnel ${i + 1} slot ${slot} nullifier ${envelope.nullifier.slice(0, 12)}.. -> ${JSON.stringify(ack)} (${Date.now() - t0}ms)`);
      check(ack.ok === true, `ALICE (tier 8) tunnel ${i + 1} at slot ${slot} accepted`);
    }
    // BOB at slot 20: a messageId only a tier-32 leaf can prove (>= 8, < 32). Built through the
    // same client path as ALICE at K=32: drain the pool to slot 20 (it wraps at K, proves at 32).
    const epoch = currentEpoch();
    const poolB = makeSlotPool({ secret: B.seed, K: 32, loadGroupFn });
    let bobEnv = null;
    for (let s = 0; s <= 20; s++) {
      const built = await buildEnvelope({ secret: B.seed, target: targets[0], pool: poolB });
      if (built.slot === 20) { bobEnv = built; break; }
    }
    check(!!bobEnv && bobEnv.slot === 20, "BOB (tier 32) built a slot-20 proof (a budget tier 8 cannot have)");
    const ack20 = await sendEnvelope(bobEnv.envelope);
    log("bob", `slot 20 nullifier ${bobEnv.envelope.nullifier.slice(0, 12)}.. -> ${JSON.stringify(ack20)}`);
    check(ack20.ok === true, "BOB (tier 32) slot-20 tunnel accepted by the gateway");

    // 5. BOB over-spends slot 0: two distinct signals under one nullifier -> slash on chain.
    // The gateway recomputes signal = requestSignal(target, nonce), so each envelope carries its
    // nonce; distinct nonces => distinct signals (x) under the SAME nullifier (slot 0, this epoch).
    const n1 = "b-n1-" + randomBytes(4).toString("hex");
    const e1 = await proveForSlot(B.seed, epoch, 0, requestSignal(targets[0], n1), { group: g, limit: 32 });
    const env1 = { v: 4, target: targets[0], nonce: n1, proof: e1.proof, nullifier: e1.nullifier, externalNullifier: e1.externalNullifier, share: e1.share };
    const n2 = "b-n2-" + randomBytes(4).toString("hex");
    const e2 = await proveForSlot(B.seed, epoch, 0, requestSignal(targets[0], n2), { group: g, limit: 32 });
    const env2 = { v: 4, target: targets[0], nonce: n2, proof: e2.proof, nullifier: e2.nullifier, externalNullifier: e2.externalNullifier, share: e2.share };
    log("bob", `over-spend 1/2 slot 0 nullifier ${e1.nullifier.slice(0, 12)}.. -> sending`);
    const a1 = await sendEnvelope(env1);
    log("bob", `over-spend 1/2 -> ${JSON.stringify(a1)}`);
    log("bob", `over-spend 2/2 slot 0 SECOND distinct signal (same nullifier) -> the violation -> sending`);
    const a2 = await sendEnvelope(env2, { timeoutMs: 180000 });
    log("bob", `over-spend 2/2 -> ${JSON.stringify(a2)}`);
    check(a1.ok === true && a2.ok === false && a2.err === "over-spend-slashed", "BOB's second distinct signal on slot 0 is dropped over-spend-slashed");

    const slashed = await waitFor(async () => {
      const m = gw.out.match(/SLASH mined block (\d+)/);
      return m ? { block: Number(m[1]), hash: (gw.out.match(/SLASH tx (0x[0-9a-fA-F]+)/) || [])[1] } : null;
    }, 180000, 1000);
    txs.slash = slashed;
    check(!!slashed, `gateway submitted the on-chain slash (tx ${slashed ? slashed.hash.slice(0, 12) + ".." : "none"} block ${slashed && slashed.block})`);
    check(/SLASH tx .*?(?:\blimit=32\b|"limit":32(?:[,}]))/.test(gw.out), "the slash named tier 32 (resolved via limitOf on chain, not the default tier)");

    // 6. outcomes: BOB loses the whole bond, >=90% reaches the fixed sink, <=10% bounty.
    const [mA2, mB2, active2] = await Promise.all([c.members(A.leaf), c.members(B.leaf), c.activeCount()]);
    check(mB2.bond === 0n && (await c.limitOf(B.leaf)) === 0n, "BOB's tier-32 bond is gone (slashed)");
    check(mA2.bond === bond8 && Number(mA2.limit) === 8, "ALICE's tier-8 bond is intact");
    check(active2 === 1n, "activeCount == 1");
    const rcvAfter = await provider.getBalance(rcv);
    log("verify", `receiver ${rcv} balance delta ${ethers.formatEther(rcvAfter - rcvBefore)} ETH (bounty ${ethers.formatEther(reward32)}; penalty ${ethers.formatEther(burn32)} ETH)`);
    if (rcv.toLowerCase() !== slasher.address.toLowerCase()) check(rcvAfter - rcvBefore === reward32, "receiver got only the tier-32 bounty");
    check((await provider.getBalance(burnAddress)) - burnBefore >= burn32, "fixed burn address received at least 90% of the tier-32 bond");
    check(gw.out.includes(`"burnedWei":"${burn32}"`) && gw.out.includes(`"rewardWei":"${reward32}"`), "gateway reports the mined SlashPayout split");
    const g2 = newGroup([BigInt(A.leaf), BigInt(B.leaf)]);
    g2.removeMember(1);
    check((await c.currentRoot()).toString() === g2.root.toString(), "currentRoot() == JS tree with BOB's leaf zeroed in place");

    // wrong-limit slash of ALICE reverts (BadLimit): a static call with limit 32 for a tier-8 leaf
    const cs = c.connect(slasher);
    let wrongLimit = "did-not-revert";
    try { await cs.slash.staticCall(A.leaf, BigInt(A.identitySecret), 32, rcv); }
    catch (e) { wrongLimit = (e && (e.data || e.message)) || "revert"; }
    const badLimitSel = ethers.id("BadLimit()").slice(0, 10);
    check(wrongLimit !== "did-not-revert" && (String(wrongLimit).includes(badLimitSel) || /BadLimit/.test(String(wrongLimit))), "wrong-limit slash of ALICE (limit 32 for a tier-8 leaf) reverts BadLimit");
    // ...and the right limit with the RIGHT secret would succeed (static; we do NOT slash ALICE)
    let rightOk = false;
    try { await cs.slash.staticCall(A.leaf, BigInt(A.identitySecret), 8, rcv); rightOk = true; } catch { rightOk = false; }
    check(rightOk, "control: the same slash at limit 8 simulates fine (not broadcast)");
    check(deriveCommitment(A.identitySecret, 8) === A.leaf, "JS deriveCommitment(secret, 8) == ALICE's leaf (slash-leaf formula)");
  } finally {
    if (gw) gw.stop();
  }

  const pass = checks.every((k) => k.ok);
  log("result", pass ? "PASS — tier-8 member intact, tier-32 over-spender slashed at its tier on chain" : `FAIL — ${checks.filter((k) => !k.ok).length} check(s) failed`);
  return { pass, checks, trace, txs, members: { A: { leaf: A.leaf, limit: 8 }, B: { leaf: B.leaf, limit: 32 } }, chainId };
}

// ---- CLI --------------------------------------------------------------------------------
if (import.meta.url === `file://${process.argv[1]}`) {
  const rpcUrl = process.env.SHADE_TREE_RPC_URL;
  const set = process.env.SHADE_TREE_GROUP_CONTRACT;
  const slashKey = process.env.SHADE_TREE_SLASH_KEY;
  if (!rpcUrl || !set || !slashKey) {
    console.error("integration-tiers: need SHADE_TREE_RPC_URL, SHADE_TREE_GROUP_CONTRACT (rln-v4 set), SHADE_TREE_SLASH_KEY");
    process.exit(2);
  }
  const targets = (process.env.SHADE_TREE_TARGETS || "").split(",").map((s) => s.trim()).filter(Boolean);
  runTierIntegration({
    rpcUrl, set, slashKey,
    registerKey: process.env.SHADE_TREE_REGISTER_KEY || slashKey,
    receiver: process.env.SHADE_TREE_SLASH_RECEIVER || null,
    seedA: process.env.SHADE_TREE_MEMBER_A_SECRET || undefined,
    seedB: process.env.SHADE_TREE_MEMBER_B_SECRET || undefined,
    confirmations: Number(process.env.SHADE_TREE_CONFIRMATIONS || 1),
    targets: targets.length ? targets : undefined,
  }).then((r) => {
    if (process.env.SHADE_TREE_REPORT_OUT) {
      writeFileSync(process.env.SHADE_TREE_REPORT_OUT, JSON.stringify({ pass: r.pass, chainId: r.chainId, txs: r.txs, members: r.members, checks: r.checks, trace: r.trace }, null, 2) + "\n");
      console.log("wrote", process.env.SHADE_TREE_REPORT_OUT);
    }
    process.exit(r.pass ? 0 : 1);
  }).catch((e) => { console.error(e); process.exit(1); });
}
