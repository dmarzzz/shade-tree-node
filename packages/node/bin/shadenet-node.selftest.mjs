// Selftest for the `shadenet-node` CLI: every command short of `run` (which needs a real Tor),
// driven as a child process against a temp state dir, a file record and a stub JSON-RPC server.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyOperatorSig } from "../bootnode/announce.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "../../..");
const CLI = join(HERE, "shadenet-node.mjs");
const work = mkdtempSync(join(tmpdir(), "shadenet-node-"));
const state = join(work, "state");

// Async on purpose: the stub RPC below lives in this process, so the loop must keep running
// while the CLI child talks to it.
function cli(args, env = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], { cwd: ROOT, env: { ...process.env, SHADENET_STATE: state, SHADENET_RECORD: "", SHADENET_SETS: "", ...env } });
    let out = "", err = "";
    child.stdout.on("data", (c) => out += c); child.stderr.on("data", (c) => err += c);
    child.on("close", (code) => resolve({ code, out, err }));
  });
}

// A stub Sepolia RPC: chain id 11155111, a fixed head.
const rpc = createServer((req, res) => {
  let body = ""; req.on("data", (c) => body += c); req.on("end", () => {
    const { id, method } = JSON.parse(body || "{}");
    const result = method === "eth_chainId" ? "0xaa36a7" : method === "eth_blockNumber" ? "0xb44f00" : null;
    res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ jsonrpc: "2.0", id, result }));
  });
});
await new Promise((r) => rpc.listen(0, "127.0.0.1", r));
const rpcUrl = `http://127.0.0.1:${rpc.address().port}`;

const staging = JSON.parse(readFileSync(join(ROOT, "network/sepolia-staging/deployment.json"), "utf8"));
const production = JSON.parse(readFileSync(join(ROOT, "network/sepolia/deployment.json"), "utf8"));
const record = structuredClone(staging);
record.admission.roots.staked.rpcUrls = [rpcUrl]; record.admission.roots.staked.rpcUrl = rpcUrl;
const recordPath = join(work, "record.json"); writeFileSync(recordPath, JSON.stringify(record));
const retiredPath = join(work, "retired.json"); writeFileSync(retiredPath, JSON.stringify({ ...record, status: "retired" }));

try {
  // help lists every knob
  { const r = await cli(["help"]); assert.equal(r.code, 0); for (const k of ["SHADENET_RECORD", "SHADENET_SETS", "SHADENET_OPERATOR_SIG", "SHADENET_POW"]) assert.match(r.out, new RegExp(k)); }
  // run without a record refuses with the one-line reason, exit 2
  { const r = await cli(["run"]); assert.equal(r.code, 2); assert.match(r.err, /set SHADENET_RECORD/); }
  // identity mints once and is stable
  { const r = await cli(["identity"]); assert.equal(r.code, 0, r.err); const id = JSON.parse(r.out); assert.match(id.onion, /^[a-z2-7]{56}\.onion$/); assert.ok(existsSync(join(state, "hs-gateway/identity.local.json")));
    const again = JSON.parse((await cli(["identity"])).out); assert.equal(again.onion, id.onion, "identity is reused, never re-minted");
    // authorize signs the onion where the key lives; the signature recovers the operator
    const keyFile = join(work, "operator.key"); writeFileSync(keyFile, "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d\n", { mode: 0o600 });
    const a = await cli(["authorize", "--onion", id.onion, "--key-file", keyFile]); assert.equal(a.code, 0, a.err);
    const auth = JSON.parse(a.out); assert.equal(auth.SHADENET_OPERATOR, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"); assert.equal(await verifyOperatorSig(id.onion, auth.SHADENET_OPERATOR, auth.SHADENET_OPERATOR_SIG), true);
    assert.equal((await cli(["authorize"])).code, 2, "authorize needs --onion and --key-file");
    // check: the operator pair is verified against the minted onion; the stub RPC answers; the derived env is printed
    const c = await cli(["check", "--json"], { SHADENET_RECORD: recordPath, SHADENET_OPERATOR: auth.SHADENET_OPERATOR, SHADENET_OPERATOR_SIG: auth.SHADENET_OPERATOR_SIG, SHADENET_SETS: `${production.admission.roots.staked.contract}@${production.admission.roots.staked.deployBlock}` });
    const report = JSON.parse(c.out);
    const text = report.findings.map((f) => `${f.level} ${f.what}`).join("\n");
    assert.match(text, /ok record sepolia-staging/); assert.ok(text.includes(`ok rpc ${rpcUrl}: chain 11155111, head 11816704`), text);
    assert.match(text, /ok operator 0x7099.*authorised this onion/); assert.match(text, /ok proof artifact rln-/); assert.match(text, /state .* GiB free/);
    assert.equal(report.ok, !report.findings.some((f) => f.level === "fail")); assert.equal(c.code, report.ok ? 0 : 1);
    assert.equal(report.env.SHADE_TREE_GROUP_CONTRACT, `${staging.admission.roots.staked.contract},${production.admission.roots.staked.contract}`, "sets: the record's set first, then the extra one");
    assert.equal(report.env.SHADE_TREE_RPC_URL, rpcUrl); assert.match(report.env.SHADE_TREE_GW_OPERATOR_SIG, /…$/, "secrets are redacted in the report");
    assert.equal(report.knobs.operator_sig, "…");
    // a wrong signature is a FAIL finding
    const bad = JSON.parse((await cli(["check", "--json"], { SHADENET_RECORD: recordPath, SHADENET_OPERATOR: auth.SHADENET_OPERATOR, SHADENET_OPERATOR_SIG: "0x" + "11".repeat(65) })).out);
    assert.ok(bad.findings.some((f) => f.level === "fail" && /operator_sig does not recover/.test(f.what)));
  }
  // node.toml is read from the state dir; env beats it; the plan prints the mapped knob
  { writeFileSync(join(state, "node.toml"), '[node]\nweight = 42\nregion = "eu"\n');
    const r = JSON.parse((await cli(["check", "--json"], { SHADENET_RECORD: recordPath, SHADENET_WEIGHT: "7" })).out);
    assert.equal(r.env.SHADE_TREE_GW_WEIGHT, "7"); assert.equal(r.env.SHADE_TREE_GATEWAY_REGION, "eu"); assert.match(r.findings.map((f) => f.what).join(), /node\.toml read from/);
    rmSync(join(state, "node.toml")); }
  // the human report names the plan and says ready or not
  { const r = await cli(["check"], { SHADENET_RECORD: recordPath }); assert.match(r.out, /would run \(cwd/); assert.match(r.out, /result: (ready to run|not ready)/); }
  // a retired record is refused as not joinable
  { const r = await cli(["check"], { SHADENET_RECORD: retiredPath }); assert.equal(r.code, 1); assert.match(r.out, /not joinable[\s\S]*only live or staging/); }
  // a bad knob is a FAIL finding, not a crash
  { const r = await cli(["check", "--json"], { SHADENET_RECORD: recordPath, SHADENET_WEIGHT: "0" }); const j = JSON.parse(r.out); assert.equal(r.code, 1); assert.ok(j.findings.some((f) => /config: weight/.test(f.what))); }
  // status with nothing running: not running, exit 1 under --quiet
  { assert.equal((await cli(["status", "--quiet"])).code, 1); const r = await cli(["status"]); assert.equal(JSON.parse(r.out).running, false);
    mkdirSync(state, { recursive: true }); writeFileSync(join(state, "status.json"), JSON.stringify({ stateDir: state, onion: "x.onion", pids: {}, stoppedAt: "2026-10-01T00:00:00Z" }));
    assert.equal((await cli(["status", "--quiet"])).code, 1, "a stopped node is not running"); }
  // retire with nothing to retire says so
  { const r = await cli(["retire"]); assert.equal(r.code, 1); assert.match(r.err, /nothing to retire/); }
  // unknown command
  { const r = await cli(["frobnicate"]); assert.equal(r.code, 2); assert.match(r.err, /unknown command/); }
  console.log("PASS: shadenet-node CLI (help, run refusal, identity, authorize, check, node.toml, status, retire)");
} finally {
  rpc.close(); rmSync(work, { recursive: true, force: true });
}
