// T-FEAT-7 `shade-tree leaves` (fast lane, no chain): the on-chain-set -> members.json exporter for the
// Rust client, driven against a tiny local JSON-RPC stub that serves a PaidAccessSet event log
// (Inserted, Inserted, Slashed) — so this also exercises fetchMemberLogs/loadGroupFromContract over
// the wire. Asserts the {version:2, members[]} shape, the in-place ZERO for the slashed slot (the
// Rust tree reproduces the on-chain root only with it), stdout/--out behavior and the errors.
//
//   node group/leaves.selftest.mjs

import http from "node:http";
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { membersFileFor, parseArgs } from "./leaves.mjs";
import { newGroup } from "../packages/node/lib/rln.mjs";
import { _internals } from "../packages/node/lib/root-provider.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };
const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, "..", "packages", "node", "bin", "shade-tree.mjs");
const CONTRACT = "0x" + "ab".repeat(20);

const log = (topic0, commitment, block, logIndex = 0) => ({
  address: CONTRACT, topics: [topic0, "0x" + BigInt(commitment).toString(16).padStart(64, "0")],
  blockNumber: "0x" + BigInt(block).toString(16), logIndex: "0x" + BigInt(logIndex).toString(16), data: "0x",
});

// Async spawn (the stub server lives in THIS process, so a spawnSync would deadlock it).
function run(args, env) {
  return new Promise((resolve) => {
    const c = spawn(process.execPath, [CLI, ...args], { env });
    let stdout = "", stderr = "";
    c.stdout.on("data", (d) => { stdout += d; });
    c.stderr.on("data", (d) => { stderr += d; });
    c.on("close", (status) => resolve({ status, stdout, stderr }));
  });
}

function rpcStub(logs) {
  const seen = [];
  const srv = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => { body += c; });
    req.on("end", () => {
      const j = JSON.parse(body);
      seen.push(j);
      const result = j.method === "eth_getLogs" ? logs.filter((l) => l.address.toLowerCase() === String(j.params[0].address).toLowerCase()) : j.method === "eth_chainId" ? "0x7a69" : null;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ jsonrpc: "2.0", id: j.id, result }));
    });
  });
  return new Promise((resolve) => srv.listen(0, "127.0.0.1", () => resolve({ url: `http://127.0.0.1:${srv.address().port}`, close: () => srv.close(), seen })));
}

async function main() {
  console.log("shade-tree leaves — on-chain set -> members.json for the Rust client (T-FEAT-7):");
  const T = _internals.TOPIC;
  const logs = [log(T.inserted, 11, 1), log(T.inserted, 22, 2), log(T.inserted, 33, 3), log(T.paidSlashed, 22, 4)];
  const stub = await rpcStub(logs);
  const work = mkdtempSync(join(tmpdir(), "shade-tree-leaves-"));
  try {
    // pure helpers
    const g = newGroup([11n, 22n, 33n]); g.removeMember(1);
    const doc = membersFileFor(g);
    ok(doc.version === 2 && doc.members.length === 3 && doc.members[0] === "11" && doc.members[2] === "33" && doc.members[1] === g.zeroValue.toString(), "membersFileFor: {version:2, members[]} with the tree ZERO at the slashed index (indices preserved)");
    ok(newGroup(doc.members.map(BigInt)).root.toString() === g.root.toString(), "re-adding the exported members (zeros included) reproduces the root the gateway trusts");
    const opts = parseArgs(["--contract", CONTRACT, "--out", "x.json", "--from-block=0x10"]);
    ok(opts.contract === CONTRACT && opts.out === "x.json" && opts.fromBlock === "0x10", "parseArgs: --contract --out --from-block (both forms)");

    // the CLI over the stub: stdout JSON
    const env = { ...process.env, SHADE_TREE_RPC_URL: stub.url, SHADE_TREE_NETWORK: "", SHADE_TREE_PAID_ACCESS_CONTRACT: "", SHADE_TREE_GROUP_CONTRACT: "" };
    let r = await run(["leaves", "--contract", CONTRACT], env);
    let parsed = null;
    try { parsed = JSON.parse(r.stdout); } catch { parsed = null; }
    ok(r.status === 0 && parsed && parsed.version === 2 && parsed.members.join() === doc.members.join(), "`shade-tree leaves --contract` prints the members.json document on stdout (root == the JS tree with the slashed slot zeroed)");
    ok(/2 live leaves in 3 slots/.test(r.stderr) && new RegExp(`root ${g.root.toString()}`).test(r.stderr), "summary on stderr: live count, slot count, root");
    ok(stub.seen.some((q) => q.method === "eth_getLogs" && q.params[0].address === CONTRACT), "the stub received eth_getLogs for the contract");
    // --out writes the file, stdout stays empty
    const out = join(work, "members.json");
    r = await run(["leaves", "--contract", CONTRACT, "--out", out], env);
    ok(r.status === 0 && r.stdout === "" && existsSync(out) && JSON.parse(readFileSync(out, "utf8")).members.length === 3 && /wrote:/.test(r.stderr), "--out writes the file (stdout empty), says so on stderr");
    // contract default from SHADE_TREE_PAID_ACCESS_CONTRACT
    r = await run(["leaves"], { ...env, SHADE_TREE_PAID_ACCESS_CONTRACT: CONTRACT });
    ok(r.status === 0 && JSON.parse(r.stdout).members.length === 3, "no --contract: SHADE_TREE_PAID_ACCESS_CONTRACT is the default (--paid-access-contract)");
    // errors
    r = await run(["leaves"], env);
    ok(r.status === 1 && /no contract/.test(r.stderr), "no contract anywhere -> exit 1 with the hint");
    r = await run(["leaves", "--contract", "0x12"], env);
    ok(r.status === 1 && /not an address/.test(r.stderr), "a non-address contract -> exit 1");
    r = await run(["leaves", "--contract", CONTRACT, "--bogus", "1"], env);
    ok(r.status === 2 && /unknown flag --bogus/.test(r.stderr), "an unknown flag -> usage, exit 2");
    r = await run(["leaves", "--contract", CONTRACT], { ...env, SHADE_TREE_RPC_URL: "http://127.0.0.1:1" });
    ok(r.status === 1 && /cannot read/.test(r.stderr), "unreachable RPC -> exit 1 naming the contract + rpc");
  } finally {
    stub.close();
    rmSync(work, { recursive: true, force: true });
  }
  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: leaves selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
