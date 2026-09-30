// Integration selftest: the CLIENT wires a verified receipt into the quality tally (T-FEAT-23).
//
// T-FEAT-22 shipped the accumulation engine (reportReceipt) + scoring in packages/node/client/selection.mjs but
// deliberately left the ONE call site in packages/node/client/shade-tree-client.mjs unwired. T-FEAT-23 wires it: right
// after connect()'s `const receipt = this._verifyReceipt(...)`, the client now calls
//   if (receipt.present) reportReceipt(usedOnion, { valid: receipt.valid === true });
//
// This drives a REAL connect()-path — a real ShadeTreeClient over a real SIGNED directory, a real proof
// pipeline, and the real _verifyReceipt / reportReceipt seam — with only the network + heavy-crypto
// leaves mocked (no Tor, no sockets, no zk proving): a module resolve hook redirects packages/node/lib/semaphore.mjs
// (proving) and packages/node/lib/receipt.mjs (receipt verification) to in-memory mocks, exactly as
// packages/node/gateway/shim.selftest.mjs does. A fake `socks` client returns a fake socket that replays an injected
// gateway ack (optionally carrying a receipt). Each scenario runs in its OWN child process because
// selection.mjs captures SHADE_TREE_RECEIPT_SCORING at import.
//
// Asserts:
//   (a) flag ON + receipt.present + valid  -> the tally is written and the dialed onion's score rises
//   (a') flag ON + receipt.present + bogus -> the tally is written and the onion's score is driven DOWN
//   (b) flag OFF + receipt.present         -> no tally file is EVER written; the returned receipt
//                                             evidence is byte-identical to the ON run (additive)
//   (c) flag ON + receipt ABSENT (legacy)  -> receipt.present is false; the tally is never touched
//
//   node packages/node/client/receipt-integration.selftest.mjs
//
// Exit 0 = every invariant held; nonzero = a check failed (prints which).

import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, writeFileSync, rmSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { execFileSync } from "node:child_process";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

const HERE = dirname(fileURLToPath(import.meta.url));
const SHADE_TREE_CLIENT_PATH = join(HERE, "shade-tree-client.mjs");

function newKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const priv = privateKey.export({ format: "der", type: "pkcs8" });
  const pub = publicKey.export({ format: "der", type: "spki" });
  return { priv: priv.subarray(priv.length - 32).toString("hex"), pub: pub.subarray(pub.length - 32).toString("hex") };
}

// ---- in-memory mocks (heavy-crypto + network leaves only) ------------------------------------
// Mock packages/node/lib/semaphore.mjs: a canned proof shaped exactly how connect()/buildEnvelope reads it
// (envelope.proof.snarkProof.{publicSignals,proof.pi_*}, proof.epoch, proof.rlnIdentifier). No zk.
const MOCK_SEMAPHORE = `
export const K_SLOTS = 8;
export function normLimit(l = K_SLOTS) { return BigInt(l); } // T-FEAT-8 tier limit (mock: identity)
export function currentEpoch() { return 7n; }
export function requestSignal(target, nonce) { return "sig(" + target + "|" + nonce + ")"; }
export async function proveForSlot(secret, epoch, i, signal, opts) {
  return {
    proof: {
      epoch: String(epoch), rlnIdentifier: "1",
      snarkProof: { publicSignals: { x: signal }, proof: { pi_a: ["a"], pi_b: [["b"]], pi_c: ["c"] } },
    },
    nullifier: "null#" + i,
    externalNullifier: "extnull(" + epoch + ")",
    share: { x: signal, y: "y(" + i + "," + signal + ")" },
  };
}
export async function loadGroup() { return { group: null, root: "ROOT", count: 1 }; }
export function cleanUp() {}

// T-HARD-8 artifact negotiation surface (mocked: one artifact set, no lock/vkey reads).
export function clientArtifactIds() { return ["rln-mock0000000000"]; }
export function selectArtifact(gatewayIds, clientIds) { return { ok: true, id: clientIds[0] }; }
export function getArtifactSet() { return { accepted: new Map(), ids: ["rln-mock0000000000"], legacyId: "rln-mock0000000000", legacyAccepted: true, explicit: false }; }
`;

// Mock packages/node/lib/receipt.mjs: validity is driven by the INJECTED receipt's marker, so the test controls
// the (valid | bogus | absent) axis without real signing. Mirrors the real return shape.
const MOCK_RECEIPT = `
export function verifyReceipt(rec, { onion = null, epoch = null } = {}) {
  if (!rec || typeof rec !== "object") return { ok: false, reason: "no-receipt" };
  if (rec.kind === "valid") return { ok: true, onion, pubkey: "PUB", epoch: String(epoch) };
  return { ok: false, reason: "bad-sig" };
}
`;

const LOADER = `
let redirects = {};
export async function initialize(data) { redirects = data; }
export async function resolve(specifier, context, next) {
  if (specifier.endsWith("lib/semaphore.mjs")) return { url: redirects.semaphore, shortCircuit: true };
  if (specifier.endsWith("lib/receipt.mjs")) return { url: redirects.receipt, shortCircuit: true };
  return next(specifier, context);
}
`;

// The child script: register the loader, import the REAL ShadeTreeClient against the mocked leaves, drive a
// real connect() over a fake socks/socket replaying the injected ack, and print the receipt evidence.
// It writes nothing itself — the tally file (if any) is written by the real reportReceipt seam, and the
// PARENT inspects it on disk. `SHADE_TREE_TEST_ACK` selects valid | bogus | absent.
function childScript({ loaderHref, semaphoreHref, receiptHref, shadeTreeHref }) {
  return `
import { register } from "node:module";
import { EventEmitter } from "node:events";
register(${JSON.stringify(loaderHref)}, {
  parentURL: import.meta.url,
  data: { semaphore: ${JSON.stringify(semaphoreHref)}, receipt: ${JSON.stringify(receiptHref)} },
});
const { ShadeTreeClient } = await import(${JSON.stringify(shadeTreeHref)});

// A fake socket that, on the client's first write (the envelope), replays a one-line gateway ack.
function fakeSocket(ackLine) {
  const s = new EventEmitter();
  s.setNoDelay = () => {};
  s.destroy = () => { s.destroyed = true; };
  s.end = (cb) => { if (typeof cb === "function") cb(); };
  let replied = false;
  s.write = (data, enc, cb) => {
    const done = typeof enc === "function" ? enc : cb;
    if (!replied) { replied = true; process.nextTick(() => s.emit("data", Buffer.from(ackLine, "utf8"))); }
    if (typeof done === "function") done();
    return true;
  };
  return s;
}

const mode = process.env.SHADE_TREE_TEST_ACK;
const ack = { ok: true };
if (mode === "valid") ack.receipt = { kind: "valid" };
else if (mode === "bogus") ack.receipt = { kind: "bogus" };
// mode === "absent": no receipt field (a legacy gateway with receipts OFF)
const fakeSocks = { createConnection: async () => ({ socket: fakeSocket(JSON.stringify(ack) + "\\n") }) };

const client = new ShadeTreeClient({
  secret: "test-secret",
  directory: process.env.SHADE_TREE_DIRECTORY,
  dirSigner: process.env.SHADE_TREE_DIR_SIGNER,
  socksClient: fakeSocks,
  socksIsolation: false,
  slotStatePath: process.env.SHADE_TREE_SLOT_STATE_PATH,
});
const tunnel = await client.connect("example.com:443");
console.log("RESULT:" + JSON.stringify(tunnel.shadeTree.receipt));
process.exit(0);
`;
}

function runChild(env) {
  const script = childScript(paths);
  let code = 0, out = "";
  try {
    out = execFileSync(process.execPath, ["--input-type=module", "-e", script], {
      encoding: "utf8",
      env: { ...process.env, ...env },
    });
  } catch (e) { code = e.status ?? 1; out = (e.stdout || "") + (e.stderr || ""); }
  const m = out.match(/RESULT:(.*)/);
  return { code, out: out.trim(), receipt: m ? JSON.parse(m[1]) : null };
}

// ---- fixtures: signer + one gateway + a signed directory -------------------------------------
const { pubkeyToOnion, signDirectory } = await import("../lib/directory.mjs");
const signer = newKey();
const gA = newKey();
const onionA = pubkeyToOnion(gA.pub);

const signed = signDirectory({
  version: 1,
  issued: Math.floor(Date.now() / 1000),
  gateways: [{ onion: onionA, pubkey: gA.pub, weight: 100, health: "up" }],
  signer: signer.pub,
}, signer.priv);

const work = mkdtempSync(join(tmpdir(), "shade-tree-receipt-int-"));
const dirPath = join(work, "directory.json");
writeFileSync(dirPath, JSON.stringify(signed) + "\n");

// mock + loader modules on disk (resolved by the child's register hook)
writeFileSync(join(work, "semaphore-mock.mjs"), MOCK_SEMAPHORE);
writeFileSync(join(work, "receipt-mock.mjs"), MOCK_RECEIPT);
writeFileSync(join(work, "loader.mjs"), LOADER);
const paths = {
  loaderHref: pathToFileURL(join(work, "loader.mjs")).href,
  semaphoreHref: pathToFileURL(join(work, "semaphore-mock.mjs")).href,
  receiptHref: pathToFileURL(join(work, "receipt-mock.mjs")).href,
  shadeTreeHref: pathToFileURL(SHADE_TREE_CLIENT_PATH).href,
};

const baseEnv = {
  SHADE_TREE_DIRECTORY: dirPath,
  SHADE_TREE_DIR_SIGNER: signer.pub,
  SHADE_TREE_BOOTNODE_ONION: "",
  SHADE_TREE_DIRECTORY_REFRESH_MS: "0",
  SHADE_TREE_HEALTH_CACHE: "", // no health persistence noise
  SHADE_TREE_SLOT_STATE_PATH: join(work, "rln-slots.json"),
};

// ================================================================================================
// (a) flag ON + a VALID present receipt -> tally written, dialed onion's score rises
// ================================================================================================
console.log("flag ON + valid present receipt — connect() folds it into the tally:");
{
  const cache = join(work, "receipts-on-valid.json");
  const r = runChild({ ...baseEnv, SHADE_TREE_RECEIPT_SCORING: "1", SHADE_TREE_RECEIPT_CACHE: cache, SHADE_TREE_TEST_ACK: "valid" });
  ok(r.code === 0, `connect() completed (${r.out.split("\n").pop()})`);
  ok(r.receipt && r.receipt.present === true && r.receipt.valid === true, "tunnel.shadeTree.receipt is present+valid");
  ok(existsSync(cache), "a tally file was written once a verified receipt was reported");
  if (existsSync(cache)) {
    const t = JSON.parse(readFileSync(cache, "utf8"));
    const e = t.entries && t.entries[onionA];
    ok(!!e, "tally is keyed by the dialed gateway's own .onion");
    ok(e && JSON.stringify(Object.keys(e).sort()) === JSON.stringify(["lastSeen", "samples", "score"]),
      `entry holds ONLY {score,samples,lastSeen} (keys: ${e ? Object.keys(e).join(",") : "-"})`);
    ok(e && e.score > 0.5, `a valid receipt drives the score up (${e ? e.score.toFixed(3) : "-"} > 0.5)`);
    ok(e && e.samples === 1, `exactly one outcome was folded (samples=${e ? e.samples : "-"})`);
  }
}

// ================================================================================================
// (a') flag ON + a BOGUS present receipt -> tally written, score driven DOWN (gate-then-drop signal)
// ================================================================================================
console.log("\nflag ON + bogus present receipt — folded as a NEGATIVE outcome:");
{
  const cache = join(work, "receipts-on-bogus.json");
  const r = runChild({ ...baseEnv, SHADE_TREE_RECEIPT_SCORING: "1", SHADE_TREE_RECEIPT_CACHE: cache, SHADE_TREE_TEST_ACK: "bogus" });
  ok(r.code === 0, `connect() completed even though the receipt was bogus (not fatal) (${r.out.split("\n").pop()})`);
  ok(r.receipt && r.receipt.present === true && r.receipt.valid === false, "tunnel.shadeTree.receipt is present but valid:false");
  ok(existsSync(cache), "a bogus-but-present receipt is still entered into the tally");
  if (existsSync(cache)) {
    const e = JSON.parse(readFileSync(cache, "utf8")).entries[onionA];
    ok(e && e.score < 0.5, `a bogus receipt drives the score DOWN (${e ? e.score.toFixed(3) : "-"} < 0.5)`);
  }
}

// ================================================================================================
// (b) flag OFF + a present receipt -> NO tally file ever; returned evidence byte-identical to ON
// ================================================================================================
console.log("\nflag OFF + present receipt — no tally file, behavior byte-identical:");
let onReceiptJSON;
{
  const cache = join(work, "receipts-off.json");
  const r = runChild({ ...baseEnv, SHADE_TREE_RECEIPT_SCORING: "", SHADE_TREE_RECEIPT_CACHE: cache, SHADE_TREE_TEST_ACK: "valid" });
  ok(r.code === 0, `connect() completed with scoring off (${r.out.split("\n").pop()})`);
  ok(!existsSync(cache), "flag off: NO tally file is written (reportReceipt is a total no-op)");
  onReceiptJSON = JSON.stringify(r.receipt);
}
{
  // Re-run the identical connect WITH the flag on and compare the returned receipt evidence: the
  // wiring must not change the tunnel/receipt path at all — only the (separate) tally file appears.
  const cache = join(work, "receipts-on-compare.json");
  const r = runChild({ ...baseEnv, SHADE_TREE_RECEIPT_SCORING: "1", SHADE_TREE_RECEIPT_CACHE: cache, SHADE_TREE_TEST_ACK: "valid" });
  ok(JSON.stringify(r.receipt) === onReceiptJSON,
    "the receipt evidence returned to the caller is byte-identical whether the flag is on or off");
}

// ================================================================================================
// (c) flag ON + an ABSENT receipt (legacy gateway) -> present:false, tally never touched
// ================================================================================================
console.log("\nflag ON + absent receipt (legacy gateway) — never entered into the tally:");
{
  const cache = join(work, "receipts-absent.json");
  const r = runChild({ ...baseEnv, SHADE_TREE_RECEIPT_SCORING: "1", SHADE_TREE_RECEIPT_CACHE: cache, SHADE_TREE_TEST_ACK: "absent" });
  ok(r.code === 0, `connect() completed against a receipts-off gateway (${r.out.split("\n").pop()})`);
  ok(r.receipt && r.receipt.present === false, "tunnel.shadeTree.receipt.present is false (nothing to report)");
  ok(!existsSync(cache), "receipt.present=false never touches the tally (fully additive opt-out)");
}

rmSync(work, { recursive: true, force: true });
console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: receipt-integration selftest (${failures} failure${failures === 1 ? "" : "s"})`);
process.exit(failures === 0 ? 0 : 1);
