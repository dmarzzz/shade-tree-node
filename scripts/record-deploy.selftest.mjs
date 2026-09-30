// Selftest for scripts/record-deploy.mjs — the one-command "broadcast -> network/<name>/contracts.json"
// recorder (T-DEPLOY-5 / GAP-2). Drives it against a TEMP network dir with a synthetic Foundry
// run-latest.json (never the committed sepolia record, never a chain).
//
// Covers: broadcast parsing (CREATE only, receipt block matched by hash, known contractName ->
// slot), a null gatewayRegistry slot gets address + tx + block in one call, deployTxs/deployBlocks
// created when absent, chain-id mismatch refused, overwrite refused without --force, manual
// --address/--tx/--block path, --dry-run writes nothing, invalid inputs rejected, --all records
// several slots, the stale `pending` note is dropped, and the CLI exit codes (spawned).
//
//   node scripts/record-deploy.selftest.mjs

import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { deploymentsFromBroadcast, applyDeployment, recordDeploy, parseArgs, CONTRACT_SLOTS } from "./record-deploy.mjs";
import { validateContractsRecord } from "../packages/node/lib/network-record.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };
const HERE = dirname(fileURLToPath(import.meta.url));

const REG = "0x" + "aa".repeat(20);
const SET = "0x" + "bb".repeat(20);
const TX1 = "0x" + "11".repeat(32);
const TX2 = "0x" + "22".repeat(32);

const baseRecord = () => ({
  network: "testnet", chainId: 31337, status: "live", rpcUrl: "http://127.0.0.1:8545",
  contracts: { stakedReputationSet: SET, gatewayRegistry: null },
  deployTxs: { stakedReputationSet: TX2, gatewayRegistry: null },
  deployBlock: 100,
  pending: "contracts.gatewayRegistry is null: not deployed yet",
});

const bundle = () => ({
  chain: 31337,
  transactions: [
    { hash: TX1, transactionType: "CREATE", contractName: "GatewayRegistry", contractAddress: REG },
    { hash: TX2, transactionType: "CALL", contractName: "GatewayRegistry", contractAddress: REG },
    { hash: "0x" + "33".repeat(32), transactionType: "CREATE", contractName: "SomethingElse", contractAddress: "0x" + "cc".repeat(20) },
  ],
  receipts: [
    { transactionHash: TX1, blockNumber: "0x1e240", contractAddress: REG }, // 123456
  ],
});

function setup(rec = baseRecord()) {
  const root = mkdtempSync(join(tmpdir(), "shade-tree-record-"));
  mkdirSync(join(root, "testnet"));
  writeFileSync(join(root, "testnet", "contracts.json"), JSON.stringify(rec, null, 2) + "\n");
  const bpath = join(root, "run-latest.json");
  writeFileSync(bpath, JSON.stringify(bundle()));
  return { root, bpath, recPath: join(root, "testnet", "contracts.json") };
}
const quiet = { log: () => {} };

function main() {
  console.log("broadcast parsing:");
  {
    const d = deploymentsFromBroadcast(bundle());
    ok(d.gatewayRegistry && d.gatewayRegistry.address === REG, "CREATE GatewayRegistry -> gatewayRegistry slot with address");
    ok(d.gatewayRegistry.tx === TX1, "tx hash lifted from the transaction");
    ok(d.gatewayRegistry.block === 123456, "block number decoded from the receipt's hex blockNumber");
    ok(Object.keys(d).length === 1, "CALL txs and unknown contractNames are ignored");
    ok(Object.keys(deploymentsFromBroadcast({})).length === 0 && Object.keys(deploymentsFromBroadcast(null)).length === 0, "empty / null bundle -> no deployments (total)");
    const noRc = bundle(); noRc.receipts = [];
    ok(deploymentsFromBroadcast(noRc).gatewayRegistry.block === null, "no receipt -> block null (address + tx still recorded)");
    ok(CONTRACT_SLOTS.StakedReputationSet === "stakedReputationSet" && CONTRACT_SLOTS.WithdrawVerifier === "withdrawVerifier", "slot map covers the record's contracts");
    ok(CONTRACT_SLOTS.PaidAccessSet === "paidAccessSet", "slot map covers the T-FEAT-7 PaidAccessSet");
    const paidB = bundle();
    paidB.transactions.push({ hash: TX2, transactionType: "CREATE", contractName: "PaidAccessSet", contractAddress: SET });
    paidB.receipts.push({ transactionHash: TX2, blockNumber: "0x64", contractAddress: SET });
    const dp = deploymentsFromBroadcast(paidB);
    ok(dp.paidAccessSet && dp.paidAccessSet.address === SET && dp.paidAccessSet.tx === TX2 && dp.paidAccessSet.block === 100, "CREATE PaidAccessSet -> paidAccessSet slot with address + tx + block");
  }

  console.log("\napplyDeployment:");
  {
    const next = applyDeployment(baseRecord(), "gatewayRegistry", { address: REG, tx: TX1, block: 123456 });
    ok(next.contracts.gatewayRegistry === REG && next.deployTxs.gatewayRegistry === TX1 && next.deployBlocks.gatewayRegistry === 123456, "null slot -> address + tx + block in one merge");
    ok(validateContractsRecord(next).ok, "merged record validates");
    ok(!("pending" in next), "stale `pending` note naming the slot is dropped");
    ok(baseRecord().contracts.gatewayRegistry === null, "input record is not mutated (fresh copy)");
    const noTxs = baseRecord(); delete noTxs.deployTxs;
    const n2 = applyDeployment(noTxs, "gatewayRegistry", { address: REG, tx: null, block: null });
    ok(n2.deployTxs.gatewayRegistry === null && n2.deployBlocks.gatewayRegistry === null, "deployTxs/deployBlocks created with null when unknown");
    let threw = false;
    try { applyDeployment(baseRecord(), "stakedReputationSet", { address: REG }); } catch (e) { threw = /refusing to overwrite/.test(e.message); }
    ok(threw, "an existing different address is not overwritten without force");
    ok(applyDeployment(baseRecord(), "stakedReputationSet", { address: REG }, { force: true }).contracts.stakedReputationSet === REG, "force overwrites");
    ok(applyDeployment(baseRecord(), "stakedReputationSet", { address: SET, tx: TX2 }).contracts.stakedReputationSet === SET, "re-recording the SAME address is idempotent (no force needed)");
    for (const [label, d] of [["bad address", { address: "0x12" }], ["bad tx", { address: REG, tx: "0xzz" }], ["negative block", { address: REG, block: -1 }], ["float block", { address: REG, block: 1.5 }]]) {
      threw = false;
      try { applyDeployment(baseRecord(), "gatewayRegistry", d); } catch { threw = true; }
      ok(threw, `${label} rejected`);
    }
    threw = false;
    try { applyDeployment(baseRecord(), "../evil", { address: REG }); } catch { threw = true; }
    ok(threw, "bad slot name rejected");
  }

  console.log("\nrecordDeploy (temp dir):");
  {
    const { root, bpath, recPath } = setup();
    const r = recordDeploy({ network: "testnet", fromBroadcast: bpath, contract: "gatewayRegistry" }, { root, ...quiet });
    ok(r.written && existsSync(recPath), "writes the record");
    const on = JSON.parse(readFileSync(recPath, "utf8"));
    ok(on.contracts.gatewayRegistry === REG && on.deployTxs.gatewayRegistry === TX1 && on.deployBlocks.gatewayRegistry === 123456, "on-disk record has address + tx + block");
    ok(on.contracts.stakedReputationSet === SET && on.deployBlock === 100, "unrelated fields preserved");
    ok(!existsSync(recPath + ".tmp"), "no temp file left behind (atomic rename)");
    // second run: same address, idempotent; different address needs --force
    ok(recordDeploy({ network: "testnet", fromBroadcast: bpath, contract: "gatewayRegistry" }, { root, ...quiet }).written, "re-running with the same broadcast is idempotent");
    let threw = false;
    try { recordDeploy({ network: "testnet", contract: "gatewayRegistry", address: SET }, { root, ...quiet }); } catch (e) { threw = /--force/.test(e.message); }
    ok(threw, "a different address without --force is refused");
    ok(recordDeploy({ network: "testnet", contract: "gatewayRegistry", address: SET, force: true }, { root, ...quiet }).record.contracts.gatewayRegistry === SET, "--force overwrites");
    rmSync(root, { recursive: true, force: true });
  }
  {
    const { root, bpath, recPath } = setup();
    const before = readFileSync(recPath, "utf8");
    const r = recordDeploy({ network: "testnet", fromBroadcast: bpath, contract: "gatewayRegistry", dryRun: true }, { root, ...quiet });
    ok(!r.written && readFileSync(recPath, "utf8") === before, "--dry-run leaves the file untouched");
    ok(r.record.contracts.gatewayRegistry === REG, "--dry-run still returns the merged record");

    // chain mismatch
    const wrong = JSON.parse(readFileSync(bpath, "utf8")); wrong.chain = 11155111;
    writeFileSync(bpath, JSON.stringify(wrong));
    let threw = false;
    try { recordDeploy({ network: "testnet", fromBroadcast: bpath, contract: "gatewayRegistry" }, { root, ...quiet }); } catch (e) { threw = /chain/.test(e.message); }
    ok(threw, "broadcast chain != record chainId is refused");
    writeFileSync(bpath, JSON.stringify(bundle()));

    // missing slot in bundle
    threw = false;
    try { recordDeploy({ network: "testnet", fromBroadcast: bpath, contract: "withdrawVerifier" }, { root, ...quiet }); } catch (e) { threw = /no CREATE for slot/.test(e.message); }
    ok(threw, "slot absent from the broadcast is an error naming what was found");

    // manual path with tx + block, plus --status
    const m = recordDeploy({ network: "testnet", contract: "gatewayRegistry", address: REG, tx: TX1, block: "777", status: "live" }, { root, ...quiet });
    ok(m.record.deployBlocks.gatewayRegistry === 777 && m.record.deployTxs.gatewayRegistry === TX1 && m.record.status === "live", "manual --address/--tx/--block (+ --status) path");
    threw = false;
    try { recordDeploy({ network: "testnet", contract: "gatewayRegistry", address: REG, status: "bogus" }, { root, ...quiet }); } catch (e) { threw = /status/.test(e.message); }
    ok(threw, "bad --status refused");
    threw = false;
    try { recordDeploy({ network: "testnet", contract: "gatewayRegistry" }, { root, ...quiet }); } catch (e) { threw = /--from-broadcast|--address/.test(e.message); }
    ok(threw, "neither broadcast nor address -> usage error");
    threw = false;
    try { recordDeploy({ network: "nope", address: REG, contract: "gatewayRegistry" }, { root, ...quiet }); } catch (e) { threw = /no record at/.test(e.message); }
    ok(threw, "unknown network -> error");
    threw = false;
    try { recordDeploy({ network: "../x", address: REG, contract: "gatewayRegistry" }, { root, ...quiet }); } catch (e) { threw = /--network/.test(e.message); }
    ok(threw, "traversal network name refused");

    // --all with a two-CREATE bundle
    const two = bundle();
    two.transactions.push({ hash: TX2, transactionType: "CREATE", contractName: "StakedReputationSet", contractAddress: SET });
    two.receipts.push({ transactionHash: TX2, blockNumber: "0x64", contractAddress: SET });
    writeFileSync(bpath, JSON.stringify(two));
    const all = recordDeploy({ network: "testnet", fromBroadcast: bpath, all: true }, { root, ...quiet });
    ok(all.record.contracts.gatewayRegistry === REG && all.record.contracts.stakedReputationSet === SET && all.record.deployBlocks.stakedReputationSet === 100, "--all records every known CREATE");
    // a paidAccessSet added to a record that never had the slot: address + tx + block appear, nothing else moves
    const paidOnly = { chain: 31337, transactions: [{ hash: TX1, transactionType: "CREATE", contractName: "PaidAccessSet", contractAddress: REG }], receipts: [{ transactionHash: TX1, blockNumber: "0x2a", contractAddress: REG }] };
    writeFileSync(bpath, JSON.stringify(paidOnly));
    const pa = recordDeploy({ network: "testnet", fromBroadcast: bpath, contract: "paidAccessSet" }, { root, ...quiet });
    ok(pa.record.contracts.paidAccessSet === REG && pa.record.deployTxs.paidAccessSet === TX1 && pa.record.deployBlocks.paidAccessSet === 42, "--contract paidAccessSet fills a NEW slot with address + tx + block");
    ok(pa.record.contracts.stakedReputationSet === SET && validateContractsRecord(pa.record).ok, "existing slots untouched; merged record validates");

    // pre-existing invalid record refused
    writeFileSync(recPath, JSON.stringify({ network: "testnet", chainId: "x", contracts: {} }));
    threw = false;
    try { recordDeploy({ network: "testnet", address: REG, contract: "gatewayRegistry" }, { root, ...quiet }); } catch (e) { threw = /already invalid/.test(e.message); }
    ok(threw, "an already-invalid record is refused (fix it first)");
    rmSync(root, { recursive: true, force: true });
  }

  console.log("\nparseArgs + CLI:");
  {
    const f = parseArgs(["--network=sepolia", "--from-broadcast", "b.json", "--all", "--dry-run", "--block", "5"]);
    ok(f.network === "sepolia" && f.fromBroadcast === "b.json" && f.all && f.dryRun && f.block === "5", "--flag=value and --flag value both parse");
    let threw = false;
    try { parseArgs(["--wat"]); } catch { threw = true; }
    ok(threw, "unknown flag rejected");
    const { root, bpath, recPath } = setup();
    const cli = (args) => spawnSync(process.execPath, [join(HERE, "record-deploy.mjs"), ...args], { encoding: "utf8" });
    // The CLI uses NETWORK_ROOT (repo network/), so drive it with --dry-run against sepolia only,
    // and prove the writing path via the temp root through the API above.
    const help = cli(["--help"]);
    ok(help.status === 0 && /usage/.test(help.stdout), "--help exits 0");
    // --force: network/sepolia already records a GatewayRegistry; --dry-run guarantees no write.
    const dry = cli(["--network", "sepolia", "--address", REG, "--tx", TX1, "--block", "42", "--force", "--dry-run"]);
    ok(dry.status === 0 && /dry-run/.test(dry.stdout) && /gatewayRegistry = /.test(dry.stdout), "CLI --dry-run against network/sepolia exits 0 and prints the slot");
    ok(JSON.parse(readFileSync(join(HERE, "..", "network", "sepolia", "contracts.json"), "utf8")).contracts.gatewayRegistry !== REG, "CLI --dry-run did not touch the committed sepolia record");
    const bad = cli(["--network", "sepolia", "--address", "0x12"]);
    ok(bad.status === 1 && /record-deploy:/.test(bad.stderr), "CLI bad input exits 1 with a prefixed error");
    const none = cli([]);
    ok(none.status === 1, "CLI with no args exits 1");
    void bpath; void recPath;
    rmSync(root, { recursive: true, force: true });
  }

  console.log(failures ? `\n${failures} FAILED` : "\nall record-deploy checks passed");
  process.exit(failures ? 1 : 0);
}

main();
