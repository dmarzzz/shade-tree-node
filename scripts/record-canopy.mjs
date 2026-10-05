#!/usr/bin/env node
// record-canopy: write the canopy that serves a network into network/<name>/deployment.json
// in ONE command, after scripts/deploy-contracts.mjs wrote the contracts half ("No canopy is
// recorded yet"). Staging (M7) and production (M8) use it the same way.
//
//   node scripts/record-canopy.mjs --network sepolia-staging --commit <sha> \
//        --elder <onion>=<canopySigner> [--elder <onion>=<canopySigner> ...] [--status live]
//   node scripts/record-canopy.mjs --network sepolia-staging --commit <sha> --elders-from sepolia
//
// Flags:
//   --network <name>        record to update (network/<name>/deployment.json)
//   --commit <sha>          40-hex shade-tree-node commit every service (elder, node, heartbeat) runs
//   --elder <onion>=<hex>   an Elder Tree and its 64-hex ed25519 canopy signer; repeat, primary first
//   --elders-from <name>    take the Elder list from another network's record (the same canopy)
//   --status <s>            record status after the write (default live)
//   --dry-run               print the record, write nothing
//
// The record moves to schemaVersion 2 (`elders[]`, with `elder` = elders[0]); each Elder keeps
// the record's admission mode and GatewayRegistry. The merged record must pass
// both record validators (client discovery + deploy/v4 preflight) before anything is written. It never talks to a chain or an Elder.

import { readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { NETWORK_ROOT, isNetworkName, validateDeploymentRecord as validateClientRecord } from "../packages/node/lib/network-record.mjs";
import { validateDeploymentRecord as preflightRecord } from "../deploy/v4/preflight.mjs";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const ONION = /^[a-z2-7]{56}\.onion$/;
const SIGNER = /^[0-9a-f]{64}$/;

export function parseArgs(argv) {
  const opts = { elders: [], status: "live", dryRun: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const value = () => {
      if (i + 1 >= argv.length) throw new Error(`${arg} needs a value`);
      return argv[++i];
    };
    if (arg === "--network") opts.network = value();
    else if (arg === "--commit") opts.commit = value();
    else if (arg === "--elder") {
      const [onion, signer, extra] = value().split("=");
      if (extra !== undefined || !ONION.test(onion || "") || !SIGNER.test(signer || "")) {
        throw new Error("--elder takes <56-char v3 onion>.onion=<64-hex canopy signer>");
      }
      opts.elders.push({ onion, canopySigner: signer });
    } else if (arg === "--elders-from") opts.eldersFrom = value();
    else if (arg === "--status") opts.status = value();
    else if (arg === "--dry-run") opts.dryRun = true;
    else throw new Error(`unknown flag ${arg}`);
  }
  if (!isNetworkName(opts.network || "")) throw new Error("--network <name> is required");
  if (!/^[0-9a-f]{40}$/.test(opts.commit || "")) throw new Error("--commit must be a 40-hex commit");
  if (!opts.elders.length === !opts.eldersFrom) throw new Error("give --elder (repeatable) or --elders-from, not both");
  if (opts.eldersFrom && !isNetworkName(opts.eldersFrom)) throw new Error("--elders-from must be a network name");
  return opts;
}

function readRecord(name, root) {
  return JSON.parse(readFileSync(join(root, name, "deployment.json"), "utf8"));
}

/// The release version the fleet runs, read from the repo's package.json (kept in lockstep with
/// the Rust crate versions by scripts/release-check.mjs). The record stamps this next to each
/// service commit so `shadenet doctor` compares releases, not commits (a tagged release names an
/// earlier fleet commit but the same version).
export function releaseVersion(root = REPO_ROOT) {
  return JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;
}

export function withCanopy(record, { commit, version, elders, status }) {
  if (!elders.length) throw new Error("no Elder Trees to record");
  const onions = new Set();
  for (const elder of elders) {
    if (onions.has(elder.onion)) throw new Error(`${elder.onion} is listed twice`);
    onions.add(elder.onion);
  }
  const { admission, gatewayRegistry } = record.elder || {};
  const full = elders.map(({ onion, canopySigner }) => ({ onion, canopySigner, admission, gatewayRegistry }));
  const next = {
    ...record,
    schemaVersion: 2,
    status,
    services: Object.fromEntries(Object.entries(record.services).map(([name, service]) => [name, { ...service, commit, ...(version ? { version } : {}) }])),
    elder: full[0],
    elders: full,
    note: String(record.note || "")
      .replace(/ ?No canopy is recorded yet\.?/, "")
      .replace(/ ?Canopy: \d+ Elder Trees? at [0-9a-f]{12}, recorded by scripts\/record-canopy\.mjs\./g, "")
      .trim()
      + ` Canopy: ${full.length} Elder Tree${full.length === 1 ? "" : "s"} at ${commit.slice(0, 12)}, recorded by scripts/record-canopy.mjs.`,
  };
  // Both validators: the client's discovery rules and the fleet's full preflight (live).
  const errors = [...validateClientRecord(next).errors, ...preflightRecord(next, { requireLive: status === "live", repoRoot: REPO_ROOT }).errors];
  if (errors.length) throw new Error(`record would be invalid:\n  ${errors.map((e) => `${e.field}: ${e.problem}`).join("\n  ")}`);
  return next;
}

export function main(argv = process.argv.slice(2), { root = NETWORK_ROOT, log = console.log } = {}) {
  const opts = parseArgs(argv);
  const record = readRecord(opts.network, root);
  const elders = opts.eldersFrom
    ? (readRecord(opts.eldersFrom, root).elders || []).map(({ onion, canopySigner }) => ({ onion, canopySigner }))
    : opts.elders;
  const next = withCanopy(record, { commit: opts.commit, version: releaseVersion(), elders, status: opts.status });
  const text = `${JSON.stringify(next, null, 2)}\n`;
  if (opts.dryRun) { log(text); return next; }
  const path = join(root, opts.network, "deployment.json");
  writeFileSync(`${path}.tmp`, text);
  renameSync(`${path}.tmp`, path);
  log(`record-canopy: ${opts.network} now lists ${elders.length} Elder Tree(s) at ${opts.commit.slice(0, 12)} (status ${opts.status})`);
  return next;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try { main(); } catch (error) { console.error(`record-canopy: ${error.message}`); process.exit(1); }
}
