#!/usr/bin/env node
// record-deploy: write a broadcast contract deployment into network/<name>/contracts.json in ONE
// command (T-DEPLOY-5 / GAP-2, docs/history/GO-LIVE.md rows 3.2 + 7.1).
//
// `forge script ... --broadcast` leaves the truth in two places the repo does NOT commit:
// contracts/deployed.local.json (addresses only) and broadcast/<Script>/<chainId>/run-latest.json
// (addresses + tx hashes + receipts with block numbers). This script lifts address + tx + block
// from that receipt bundle (or from explicit flags) into the committed record, validates the
// result with packages/node/lib/network-record.mjs, and writes it atomically. It never talks to a chain and
// never broadcasts anything.
//
//   node scripts/record-deploy.mjs --network devnet \
//        --from-broadcast broadcast/DeployRegistry.s.sol/11155111/run-latest.json
//   node scripts/record-deploy.mjs --network devnet --contract gatewayRegistry \
//        --address 0x... --tx 0x... --block 1234567
//   (or: shade-tree-node record-deploy --network <name> --from-broadcast <run-latest.json>)
//
// Flags:
//   --network <name>        network/<name>/contracts.json to update   (or SHADE_TREE_NETWORK)
//   --from-broadcast <p>    Foundry run-latest.json to read address/tx/block from
//   --contract <slot>       which slot to record (default gatewayRegistry; e.g. paidAccessSet); with
//                           --from-broadcast the CREATE whose contractName maps to that slot is used
//   --all                   with --from-broadcast: record EVERY CREATE with a known slot mapping
//   --address/--tx/--block  manual values (no broadcast file needed); --block is a decimal int
//   --status <s>            also set the record's top-level status (live|pending|retired)
//   --force                 overwrite a slot that already holds an address (default: refuse)
//   --dry-run               print the would-be record, write nothing
//
// Guards: the broadcast file's chain must equal the record's chainId; an existing NON-null slot is
// not overwritten without --force (contracts are immutable; a second deploy is a conscious act);
// the merged record must pass validateContractsRecord before anything is written.

import { readFileSync, writeFileSync, renameSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { isEthAddress } from "../packages/node/lib/config.mjs";
import { validateContractsRecord, isTxHash, isNetworkName, NETWORK_ROOT } from "../packages/node/lib/network-record.mjs";

// Foundry contractName -> contracts.json slot. Extend when a new contract joins the record.
export const CONTRACT_SLOTS = {
  GatewayRegistry: "gatewayRegistry",
  StakedReputationSet: "stakedReputationSet",
  RateCommitmentHasher: "hasher",
  MockCommitmentHasher: "hasher",
  WithdrawVerifier: "withdrawVerifier",
  MockWithdrawVerifier: "withdrawVerifier",
  WithdrawGroth16Verifier: "withdrawGroth16Verifier", // the snarkJS-exported pairing verifier WithdrawVerifier wraps (rln-v4)
  PaidAccessSet: "paidAccessSet", // T-FEAT-7 fixed-denomination deposit/sweep set (docs/PAYMENTS.md)
};

export function parseArgs(rawArgv) {
  const f = { network: process.env.SHADE_TREE_NETWORK || null, contract: "gatewayRegistry", all: false, force: false, dryRun: false };
  // normalize --flag=value into --flag value
  const argv = rawArgv.flatMap((a) => (a.startsWith("--") && a.includes("=") ? [a.slice(0, a.indexOf("=")), a.slice(a.indexOf("=") + 1)] : [a]));
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const val = () => { const v = argv[++i]; if (v === undefined) throw new Error(`${a} needs a value`); return v; };
    if (a === "--network") f.network = val();
    else if (a === "--from-broadcast") f.fromBroadcast = val();
    else if (a === "--contract") f.contract = val();
    else if (a === "--all") f.all = true;
    else if (a === "--address") f.address = val();
    else if (a === "--tx") f.tx = val();
    else if (a === "--block") f.block = val();
    else if (a === "--status") f.status = val();
    else if (a === "--force") f.force = true;
    else if (a === "--dry-run") f.dryRun = true;
    else if (a === "--help" || a === "-h") f.help = true;
    else throw new Error(`unknown argument: ${a}`);
  }
  return f;
}

// Pull { slot: { address, tx, block } } out of a Foundry run-latest.json. Pure over the parsed
// bundle. Only CREATE transactions count; a receipt is matched by transactionHash for the block.
export function deploymentsFromBroadcast(bundle) {
  const out = {};
  const receipts = new Map();
  for (const r of bundle?.receipts || []) if (r && r.transactionHash) receipts.set(String(r.transactionHash).toLowerCase(), r);
  for (const t of bundle?.transactions || []) {
    if (!t || t.transactionType !== "CREATE") continue;
    const slot = CONTRACT_SLOTS[t.contractName];
    if (!slot) continue;
    const rc = receipts.get(String(t.hash || "").toLowerCase());
    const blockRaw = rc?.blockNumber;
    const block = blockRaw == null ? null : Number(BigInt(String(blockRaw)));
    out[slot] = { address: t.contractAddress || rc?.contractAddress || null, tx: t.hash || null, block, contractName: t.contractName };
  }
  return out;
}

// Merge one deployment into a record (returns a NEW record; validates; throws on any guard).
export function applyDeployment(record, slot, { address, tx, block }, { force = false } = {}) {
  if (!slot || !/^[a-zA-Z][a-zA-Z0-9]*$/.test(slot)) throw new Error(`bad contract slot: ${slot}`);
  if (!isEthAddress(address)) throw new Error(`${slot}: address must be a 0x 20-byte address (got ${address})`);
  if (tx != null && !isTxHash(tx)) throw new Error(`${slot}: tx must be a 0x 32-byte hash (got ${tx})`);
  if (block != null && !(Number.isInteger(block) && block >= 0)) throw new Error(`${slot}: block must be a non-negative integer (got ${block})`);
  const next = JSON.parse(JSON.stringify(record));
  next.contracts = next.contracts || {};
  const existing = next.contracts[slot];
  if (isEthAddress(existing) && existing.toLowerCase() !== address.toLowerCase() && !force) {
    throw new Error(`${slot} already recorded as ${existing}; refusing to overwrite without --force`);
  }
  next.contracts[slot] = address;
  // A free-form `pending` note that named this slot is now stale; drop it.
  if (typeof next.pending === "string" && next.pending.includes(slot)) delete next.pending;
  next.deployTxs = next.deployTxs || {};
  next.deployTxs[slot] = tx ?? next.deployTxs[slot] ?? null;
  next.deployBlocks = next.deployBlocks || {};
  if (block != null) next.deployBlocks[slot] = block;
  else if (next.deployBlocks[slot] === undefined) next.deployBlocks[slot] = null;
  const v = validateContractsRecord(next);
  if (!v.ok) throw new Error("merged record invalid:\n" + v.errors.map((e) => `  ${e.field}: ${e.problem}`).join("\n"));
  return next;
}

export function recordDeploy(flags, { root = NETWORK_ROOT, log = console.log } = {}) {
  if (!isNetworkName(flags.network || "")) throw new Error("--network <name> (or SHADE_TREE_NETWORK) is required, e.g. --network devnet");
  const path = join(root, flags.network, "contracts.json");
  if (!existsSync(path)) throw new Error(`no record at ${path} (create network/${flags.network}/contracts.json first, see network/README.md)`);
  const record = JSON.parse(readFileSync(path, "utf8"));
  const v0 = validateContractsRecord(record);
  if (!v0.ok) throw new Error(`${path} is already invalid; fix it first:\n` + v0.errors.map((e) => `  ${e.field}: ${e.problem}`).join("\n"));

  let deployments = {}; // slot -> { address, tx, block }
  if (flags.fromBroadcast) {
    const bundle = JSON.parse(readFileSync(flags.fromBroadcast, "utf8"));
    if (bundle.chain != null && Number(bundle.chain) !== Number(record.chainId)) {
      throw new Error(`broadcast chain ${bundle.chain} != record chainId ${record.chainId} (wrong network?)`);
    }
    const found = deploymentsFromBroadcast(bundle);
    if (flags.all) deployments = found;
    else {
      if (!found[flags.contract]) throw new Error(`no CREATE for slot "${flags.contract}" in ${flags.fromBroadcast} (found: ${Object.keys(found).join(", ") || "none"})`);
      deployments = { [flags.contract]: found[flags.contract] };
    }
    // Manual flags override what the bundle said (e.g. a hand-corrected block).
    if (flags.address || flags.tx || flags.block) {
      const d = deployments[flags.contract] || (deployments[flags.contract] = {});
      if (flags.address) d.address = flags.address;
      if (flags.tx) d.tx = flags.tx;
      if (flags.block) d.block = Number(flags.block);
    }
  } else {
    if (!flags.address) throw new Error("need --from-broadcast <run-latest.json> or --address 0x.. (with --tx / --block)");
    deployments = { [flags.contract]: { address: flags.address, tx: flags.tx ?? null, block: flags.block != null ? Number(flags.block) : null } };
  }

  let next = record;
  for (const [slot, d] of Object.entries(deployments)) next = applyDeployment(next, slot, d, { force: flags.force });
  if (flags.status) {
    next.status = flags.status;
    const v = validateContractsRecord(next);
    if (!v.ok) throw new Error("record invalid after --status:\n" + v.errors.map((e) => `  ${e.field}: ${e.problem}`).join("\n"));
  }

  const json = JSON.stringify(next, null, 2) + "\n";
  for (const [slot, d] of Object.entries(deployments)) log(`${flags.network}: ${slot} = ${d.address}${d.tx ? ` tx ${d.tx}` : ""}${d.block != null ? ` block ${d.block}` : ""}`);
  if (flags.dryRun) { log(json); log(`dry-run: ${path} not written`); return { path, record: next, written: false }; }
  const tmp = path + ".tmp";
  writeFileSync(tmp, json);
  renameSync(tmp, path);
  log(`wrote ${path}`);
  return { path, record: next, written: true };
}

const HERE = dirname(fileURLToPath(import.meta.url));
if (import.meta.url === `file://${process.argv[1]}` || process.argv[1] === join(HERE, "record-deploy.mjs")) {
  try {
    const flags = parseArgs(process.argv.slice(2));
    if (flags.help) {
      console.log("usage: record-deploy --network <name> (--from-broadcast <run-latest.json> [--contract <slot>|--all] | --address 0x.. [--tx 0x..] [--block N]) [--status live] [--force] [--dry-run]");
      process.exit(0);
    }
    recordDeploy(flags);
  } catch (e) {
    console.error(`record-deploy: ${e.message}`);
    process.exit(1);
  }
}
