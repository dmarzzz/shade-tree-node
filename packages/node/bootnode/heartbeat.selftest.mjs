// T-TEST-3: unit selftest for the gateway heartbeat (packages/node/bootnode/heartbeat.mjs) — the last module
// without one. Everything runs in-process with injected fakes: no Tor, no network beyond one
// deliberately-refused loopback connect, no chain. Five properties:
//
//   1. OPERATOR RESOLUTION. Every source + precedence path of resolveOperator: onion-only
//      (neither var, and ethers is never even imported), SHADE_TREE_GW_OPERATOR_KEY (signs
//      operatorAuthMessage — byte-matched against the pinned Shade Tree domain vector below
//      (using the key/address from testdata/vectors.json; 0x-optional, whitespace-tolerant), a pre-computed
//      SHADE_TREE_GW_OPERATOR + SHADE_TREE_GW_OPERATOR_SIG pair (verified locally; wins over the key), and
//      every misconfiguration FAILING FAST: half a pair, malformed address/sig, a sig that does
//      not recover the operator (wrong onion / wrong operator), a malformed key, a well-formed
//      but invalid secp256k1 key.
//   2. ANNOUNCE BYTES. announceOnce builds a record whose canonical bytes + onionSig match the
//      pinned announce vector for the vector's {ts, nonce}, whose operator/operatorSig match
//      the pinned operator vector, that verifyAnnounce accepts, and that goes to POST /announce
//      with the configured Tor host/port; ts+nonce are fresh per call.
//   3. TICK BEHAVIOUR (makeBeat / runHeartbeat). Accepted / rejected / skipped-by-egress /
//      failed outcomes are logged + returned; the tick NEVER throws — a hostile bootnode reply
//      (null, array, string, number, wrong-typed ok, missing ttl), a throwing transport, a
//      throwing egress probe, garbage HTTP, a non-200, non-JSON, and a real ECONNREFUSED to a
//      closed loopback port all end in a logged retry-next-interval, not a crash. runHeartbeat
//      schedules the tick at exactly intervalSec*1000 with a fake scheduler and keeps announcing
//      through an outage (fail, then recover) with no state to reset.
//   4. CONFIG. heartbeatConfig defaults + overrides; missing bootnode fails fast; identity file
//      load (env path, missing fields, malformed JSON, missing file) all fail with a message.
//   5. LOG HYGIENE (dynamic, mirrors test/log-hygiene.selftest.mjs). Under a full captured
//      runHeartbeat with a real onion seed + a real operator key, and under every resolveOperator
//      error path, neither the seed hex nor the key hex (with or without 0x) ever reaches a log
//      sink or an error message — the public onion prefix and operator ADDRESS prefix do.
//
//   node packages/node/bootnode/heartbeat.selftest.mjs
//
// Exit 0 = all invariants held.

import { readFileSync } from "node:fs";
import { createServer } from "node:net";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import {
  loadIdentity, resolveOperator, announceOnce, makeBeat, makeFanoutBeat, runHeartbeat, heartbeatConfig, egressCheckEnabled,
} from "./heartbeat.mjs";
import { buildAnnounce, verifyAnnounce, verifyOperatorSig, canonicalAnnounceBytes, operatorAuthMessage } from "./announce.mjs";
import { postOverTor, parseHttp } from "./fetch.mjs";
import { pubkeyToOnion } from "../lib/directory.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const V = JSON.parse(readFileSync(join(HERE, "../../..", "testdata", "vectors.json"), "utf8"));

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

async function throwsWith(fn, re) {
  try { await fn(); return { threw: false, message: "" }; } catch (e) { return { threw: re.test(e.message), message: e.message }; }
}

// A fresh onion identity (raw ed25519 seed + the v3 onion whose key IS that pub).
function newOnion() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const priv = privateKey.export({ format: "der", type: "pkcs8" });
  const pub = publicKey.export({ format: "der", type: "spki" });
  const pubHex = pub.subarray(pub.length - 32).toString("hex");
  return { seed: priv.subarray(priv.length - 32).toString("hex"), onion: pubkeyToOnion(pubHex) };
}

// Capture every console/stdout/stderr sink while fn runs (same shape as test/log-hygiene).
async function withCapture(fn) {
  const buf = [];
  const push = (s) => buf.push(String(s));
  const orig = {
    log: console.log, error: console.error, warn: console.warn, info: console.info, debug: console.debug,
    so: process.stdout.write.bind(process.stdout), se: process.stderr.write.bind(process.stderr),
  };
  console.log = console.error = console.warn = console.info = console.debug = (...a) => push(a.join(" "));
  process.stdout.write = (s) => { push(s); return true; };
  process.stderr.write = (s) => { push(s); return true; };
  try { await fn(); } finally {
    console.log = orig.log; console.error = orig.error; console.warn = orig.warn;
    console.info = orig.info; console.debug = orig.debug;
    process.stdout.write = orig.so; process.stderr.write = orig.se;
  }
  return buf.join("\n");
}

// A loopback port that is definitely closed (bind, read, release).
async function closedPort() {
  const srv = createServer();
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;
  await new Promise((r) => srv.close(r));
  return port;
}

const VID = { onion: V.onion, seed: V.onionSeed };
// The repository-wide vector file is also consumed by historical interoperability fixtures
// outside this operator surface. Pin the current signed-domain vector here so this test proves
// the exact v1 authorization text without rewriting those historical bytes.
const OA = {
  ...V.operatorAnnounce,
  operatorAuthMessage: `Shade Tree gateway operator authorization\nonion=${V.onion}\noperator=${V.operatorAnnounce.operator.toLowerCase()}`,
  operatorSig: "0x9e50686e4a58a1566a9fce04a78c9ab0071ac03dc0f93de15026107ec88ffad810b350a14b181f8697882bd79c556c50a619141f741391df1ed6e1fb7940b1851b",
};

async function main() {
  // ===================================================================================
  console.log("1. operator resolution (every source + precedence path):");
  let ethersImports = 0;
  const countingEthers = () => { ethersImports++; return import("ethers"); };

  const none = await resolveOperator(V.onion, {}, { importEthers: countingEthers });
  ok(none.operator === null && none.operatorSig === null, "no operator env -> onion-only {null,null}");
  ok(ethersImports === 0, "onion-only path never imports ethers");
  ok(JSON.stringify(await resolveOperator(V.onion, { SHADE_TREE_UNRELATED: "x" })) === JSON.stringify(none), "unrelated env -> still onion-only");

  // Key path, byte-matched against the pinned Shade Tree authorization vector.
  const fromKey = await resolveOperator(V.onion, { SHADE_TREE_GW_OPERATOR_KEY: OA.operatorPriv }, { importEthers: countingEthers });
  ok(ethersImports === 1, "key path imports ethers (lazily, once)");
  ok(fromKey.operator === OA.operator, "SHADE_TREE_GW_OPERATOR_KEY -> operator address == pinned vector operator");
  ok(fromKey.operatorSig === OA.operatorSig, "SHADE_TREE_GW_OPERATOR_KEY -> operatorSig BYTE-MATCHES the pinned personal_sign vector");
  ok(await verifyOperatorSig(V.onion, fromKey.operator, fromKey.operatorSig), "key-derived sig passes verifyOperatorSig (the bootnode's check)");
  const noPrefix = await resolveOperator(V.onion, { SHADE_TREE_GW_OPERATOR_KEY: OA.operatorPriv.slice(2) });
  ok(noPrefix.operatorSig === OA.operatorSig, "key without 0x prefix -> same sig");
  const padded = await resolveOperator(V.onion, { SHADE_TREE_GW_OPERATOR_KEY: `  ${OA.operatorPriv}\n` });
  ok(padded.operatorSig === OA.operatorSig, "key with surrounding whitespace -> trimmed, same sig");
  // The sig is onion-bound: a different onion yields a different sig from the same key.
  const other = newOnion();
  const otherSig = await resolveOperator(other.onion, { SHADE_TREE_GW_OPERATOR_KEY: OA.operatorPriv });
  ok(otherSig.operator === OA.operator && otherSig.operatorSig !== OA.operatorSig, "same key, other onion -> same operator, DIFFERENT (onion-bound) sig");
  ok(await verifyOperatorSig(other.onion, otherSig.operator, otherSig.operatorSig), "...and it verifies for that onion");

  // Pre-computed pair path.
  ethersImports = 0;
  const pair = await resolveOperator(V.onion, { SHADE_TREE_GW_OPERATOR: OA.operator, SHADE_TREE_GW_OPERATOR_SIG: OA.operatorSig }, { importEthers: countingEthers });
  ok(pair.operator === OA.operator && pair.operatorSig === OA.operatorSig, "SHADE_TREE_GW_OPERATOR + _SIG pair -> returned as given (verified locally)");
  ok(ethersImports === 0, "pair path never touches the Wallet path (no key needed on the box)");
  const lower = await resolveOperator(V.onion, { SHADE_TREE_GW_OPERATOR: OA.operator.toLowerCase(), SHADE_TREE_GW_OPERATOR_SIG: OA.operatorSig });
  ok(lower.operator === OA.operator.toLowerCase(), "lowercase operator address accepted (verification is case-insensitive)");
  // Precedence: pair wins over a (different) key.
  const otherKey = "0x" + randomBytes(32).toString("hex");
  const prec = await resolveOperator(V.onion, { SHADE_TREE_GW_OPERATOR: OA.operator, SHADE_TREE_GW_OPERATOR_SIG: OA.operatorSig, SHADE_TREE_GW_OPERATOR_KEY: otherKey });
  ok(prec.operator === OA.operator && prec.operatorSig === OA.operatorSig, "precedence: pre-computed pair WINS over SHADE_TREE_GW_OPERATOR_KEY");
  // Key + only half a pair -> the key path (the half pair is ignored because the key is authoritative).
  const keyHalf = await resolveOperator(V.onion, { SHADE_TREE_GW_OPERATOR: OA.operator, SHADE_TREE_GW_OPERATOR_KEY: OA.operatorPriv });
  ok(keyHalf.operatorSig === OA.operatorSig, "operator + key (no sig) -> key path signs");

  // Misconfigurations FAIL FAST (previously a silent onion-only downgrade / per-beat rejection).
  ok((await throwsWith(() => resolveOperator(V.onion, { SHADE_TREE_GW_OPERATOR: OA.operator }), /must be set together/)).threw, "operator WITHOUT sig (no key) -> startup error, not silent onion-only");
  ok((await throwsWith(() => resolveOperator(V.onion, { SHADE_TREE_GW_OPERATOR_SIG: OA.operatorSig }), /must be set together/)).threw, "sig WITHOUT operator -> startup error");
  ok((await throwsWith(() => resolveOperator(V.onion, { SHADE_TREE_GW_OPERATOR: "dEaD", SHADE_TREE_GW_OPERATOR_SIG: OA.operatorSig }), /SHADE_TREE_GW_OPERATOR is not/)).threw, "malformed operator address -> error");
  ok((await throwsWith(() => resolveOperator(V.onion, { SHADE_TREE_GW_OPERATOR: OA.operator, SHADE_TREE_GW_OPERATOR_SIG: "0xabc" }), /SHADE_TREE_GW_OPERATOR_SIG is not/)).threw, "malformed operator sig -> error");
  ok((await throwsWith(() => resolveOperator(other.onion, { SHADE_TREE_GW_OPERATOR: OA.operator, SHADE_TREE_GW_OPERATOR_SIG: OA.operatorSig }), /does not recover/)).threw, "pinned sig presented for a DIFFERENT onion -> does-not-recover error (sig is onion-bound)");
  ok((await throwsWith(() => resolveOperator(V.onion, { SHADE_TREE_GW_OPERATOR: V.operator, SHADE_TREE_GW_OPERATOR_SIG: OA.operatorSig }), /does not recover/)).threw, "pinned sig with a DIFFERENT operator address -> does-not-recover error");
  const flipped = OA.operatorSig.slice(0, -2) + (OA.operatorSig.endsWith("1c") ? "1b" : "1c");
  ok((await throwsWith(() => resolveOperator(V.onion, { SHADE_TREE_GW_OPERATOR: OA.operator, SHADE_TREE_GW_OPERATOR_SIG: flipped }), /does not recover/)).threw, "sig with flipped recovery byte -> does-not-recover error");

  // ===================================================================================
  console.log("\n1b. malformed operator KEY: rejected, and the key bytes never reach the error/log:");
  const badKeys = {
    "too short": "0xdeadbeefcafe",
    "65 hex chars (one typo char appended)": OA.operatorPriv + "5",
    "63 hex chars (one char dropped)": OA.operatorPriv.slice(0, -1),
    "non-hex junk": "0xzz" + "4".repeat(62),
    "well-formed but not a valid secp256k1 scalar (>= curve order)": "0x" + "ff".repeat(32),
    "zero scalar": "0x" + "00".repeat(32),
  };
  for (const [label, key] of Object.entries(badKeys)) {
    const r = await throwsWith(() => resolveOperator(V.onion, { SHADE_TREE_GW_OPERATOR_KEY: key }), /SHADE_TREE_GW_OPERATOR_KEY is not/);
    const bare = key.replace(/^0x/, "");
    ok(r.threw && !r.message.includes(bare) && !r.message.includes(bare.slice(0, 20)), `${label}: rejected + key bytes absent from the error message`);
  }
  // Even if ethers echoed the value, the error is sanitized: inject a fake ethers whose Wallet
  // throws the raw value back (what a non-redacting library would do).
  const echoingEthers = async () => ({ ethers: { Wallet: class { constructor(k) { throw new Error(`invalid private key value="${k}"`); } } } });
  const rEcho = await throwsWith(() => resolveOperator(V.onion, { SHADE_TREE_GW_OPERATOR_KEY: OA.operatorPriv }, { importEthers: echoingEthers }), /not a valid secp256k1/);
  ok(rEcho.threw && !rEcho.message.includes(OA.operatorPriv.slice(2)), "a value-echoing Wallet error is replaced by a sanitized message (key bytes absent)");

  // ===================================================================================
  console.log("\n2. announce construction + signing (byte-match vs pinned vectors):");
  // Deterministic build for the vector's {ts,nonce}: canonical bytes + onionSig pinned.
  const pinned = buildAnnounce({ onion: V.onion, weight: 100, onionSeedHex: V.onionSeed, ts: V.announce.ts, nonce: V.announce.nonce, operator: fromKey.operator, operatorSig: fromKey.operatorSig });
  ok(canonicalAnnounceBytes(pinned).toString("hex") === V.canonicalAnnounceBytesHex, "canonical announce bytes == pinned vector");
  ok(pinned.onionSig === V.announceOnionSig, "onionSig == pinned vector (RFC 8032 deterministic)");
  ok(pinned.operator === OA.operator.toLowerCase() && pinned.operatorSig === OA.operatorSig, "operator (lowercased) + operatorSig == pinned operatorAnnounce vector");
  ok(operatorAuthMessage(V.onion, OA.operator) === OA.operatorAuthMessage, "operatorAuthMessage == pinned vector text");

  // announceOnce: capture what would go on the wire.
  const sent = [];
  const fakePost = async (onion, path, rec, opts) => { sent.push({ onion, path, rec, opts }); return { ok: true, staked: true, ttl: 900 }; };
  const r1 = await announceOnce({ id: VID, bootnode: "bootnode.onion", op: fromKey, weight: 42, torHost: "127.0.0.9", torPort: 9999, caps: null, post: fakePost });
  await announceOnce({ id: VID, bootnode: "bootnode.onion", op: fromKey, weight: 42, torHost: "127.0.0.9", torPort: 9999, caps: null, post: fakePost });
  ok(r1.ok === true && sent.length === 2, "announceOnce returns the transport reply");
  ok(sent[0].onion === "bootnode.onion" && sent[0].path === "/announce", "POSTs to <bootnode>/announce");
  ok(sent[0].opts.torHost === "127.0.0.9" && sent[0].opts.torPort === 9999, "threads the configured Tor SOCKS host/port to the transport");
  const s0 = sent[0].rec;
  ok(s0.onion === V.onion && s0.weight === 42 && s0.v === 1, "record carries onion, weight, v=1");
  ok(s0.operator === OA.operator.toLowerCase() && s0.operatorSig === OA.operatorSig, "record carries the resolved (pinned) operator + sig");
  ok(s0.caps === undefined && s0.capsSig === undefined, "caps:null -> no caps keys (byte-identical legacy announce)");
  ok((await verifyAnnounce(s0, { now: s0.ts })).ok === true, "the announce verifyAnnounce ACCEPTS (onion control + operator sig)");
  ok(sent[0].rec.nonce !== sent[1].rec.nonce && /^[0-9a-f]{32}$/.test(s0.nonce), "each announce has a fresh 16-byte hex nonce");
  ok(Math.abs(s0.ts - Math.floor(Date.now() / 1000)) <= 2, "ts is the current time (fresh per announce)");
  ok(!("seed" in s0) && !JSON.stringify(s0).includes(V.onionSeed), "the onion SEED is never in the announce record");
  // Onion-only announce: no operator keys at all.
  await announceOnce({ id: VID, bootnode: "b.onion", op: none, weight: 100, torHost: "h", torPort: 1, caps: null, post: fakePost });
  ok(!("operator" in sent[2].rec) && !("operatorSig" in sent[2].rec), "onion-only op -> no operator/operatorSig keys");
  ok((await verifyAnnounce(sent[2].rec, { now: sent[2].rec.ts })).ok === true, "onion-only announce verifies");

  // ===================================================================================
  console.log("\n3. tick behaviour (makeBeat): outcomes logged, never throws:");
  const logs = [];
  const log = (s) => logs.push(s);
  const up = async () => ({ healthy: true, target: "t", reason: "" });
  const down = async () => ({ healthy: false, target: "example.com:443", reason: "ECONNREFUSED" });
  const tick = (announce, egress = up, enabled = true) => makeBeat({ announce, egress, enabled, log })();

  let r = await tick(async () => ({ ok: true, staked: true, ttl: 900 }));
  ok(r.ok === true && logs.at(-1) === "announced (staked=true, ttl=900s)", "accepted -> `announced (staked=true, ttl=900s)`");
  r = await tick(async () => ({ ok: true, ttl: 300 }));
  ok(logs.at(-1) === "announced (staked=false, ttl=300s)", "accepted without staked -> staked=false");
  r = await tick(async () => ({ ok: false, err: "not-staked" }));
  ok(r.ok === false && r.err === "not-staked" && logs.at(-1) === "announce rejected: not-staked", "rejected -> `announce rejected: <err>`");
  r = await tick(async () => ({ ok: "true", ttl: 1 }));
  ok(r.ok === false && logs.at(-1).startsWith("announce rejected:"), "ok:'true' (string, not boolean) is NOT treated as accepted");
  for (const [label, reply] of [["null", null], ["array", [1, 2]], ["string", "ok"], ["number", 200], ["undefined", undefined]]) {
    r = await tick(async () => reply);
    ok(r.ok === false && r.err === "malformed response" && logs.at(-1).includes("malformed response"), `hostile reply ${label} -> rejected as malformed, no throw`);
  }
  r = await tick(async () => ({ ok: true }));
  ok(r.ok === true && logs.at(-1) === "announced (staked=false, ttl=undefineds)", "reply missing ttl -> still handled (no throw)");
  r = await tick(async () => { throw new Error("bootnode POST failed after 4 attempts: socks timeout"); });
  ok(r.failed === true && logs.at(-1) === "announce failed: bootnode POST failed after 4 attempts: socks timeout (will retry next interval)", "transport throw -> `announce failed: ... (will retry next interval)`");
  let announced = 0;
  r = await tick(async () => { announced++; return { ok: true }; }, down);
  ok(r.skipped === true && announced === 0 && logs.at(-1).startsWith("egress DOWN (example.com:443 ECONNREFUSED); SKIP announce"), "egress DOWN -> announce SKIPPED + logged");
  let probed = 0;
  r = await tick(async () => { announced++; return { ok: true }; }, async () => { probed++; return { healthy: false }; }, false);
  ok(r.ok === true && announced === 1 && probed === 0, "SHADE_TREE_EGRESS_CHECK=0 -> announces unconditionally, probe not even called");
  r = await tick(async () => ({ ok: true }), async () => { throw new Error("probe exploded"); });
  ok(r.failed === true && logs.at(-1).includes("probe exploded"), "a throwing egress probe is contained (failed, retry next interval)");
  // Real transport-shaped failures through the tick.
  r = await tick(async () => parseHttp(Buffer.from("garbage with no header terminator")));
  ok(r.failed === true && logs.at(-1).includes("no HTTP header terminator"), "garbage HTTP -> failed (parseHttp throws, tick contains it)");
  r = await tick(async () => parseHttp(Buffer.from("HTTP/1.1 500 Internal\r\nContent-Length: 4\r\n\r\nboom")));
  ok(r.failed === true && logs.at(-1).includes("bootnode HTTP 500"), "non-200 -> failed with status");
  r = await tick(async () => parseHttp(Buffer.from("HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\n{nope}")));
  ok(r.failed === true && logs.at(-1).startsWith("announce failed:"), "200 with non-JSON body -> failed, no throw");
  // A REAL unreachable bootnode: Tor SOCKS port is closed on loopback (no Tor needed).
  const dead = await closedPort();
  const t0 = Date.now();
  r = await tick(() => announceOnce({ id: VID, bootnode: V.onion, op: none, weight: 100, torHost: "127.0.0.1", torPort: dead, caps: null,
    post: (o, p, b, opts) => postOverTor(o, p, b, { ...opts, attempts: 1, timeoutMs: 3000 }) }));
  ok(r.failed === true && /failed after 1 attempts/.test(logs.at(-1)) && /ECONNREFUSED|connect/i.test(logs.at(-1)), "unreachable Tor/bootnode (closed loopback SOCKS port) -> `announce failed: bootnode POST failed after 1 attempts: ...`");
  ok(Date.now() - t0 < 3000, "unreachable path returns promptly (no hang)");

  // ===================================================================================
  console.log("\n4. config + identity load:");
  ok((await throwsWith(async () => heartbeatConfig({}), /set SHADE_TREE_BOOTNODE_ONION/)).threw, "no SHADE_TREE_BOOTNODE_ONION -> fail fast");
  const dc = heartbeatConfig({ SHADE_TREE_BOOTNODE_ONION: "b.onion" });
  ok(dc.intervalSec === 300 && dc.weight === 100 && dc.torHost === "127.0.0.1" && dc.torPort === 9250, "defaults: 300s, weight 100, 127.0.0.1:9250");
  const oc = heartbeatConfig({ SHADE_TREE_BOOTNODE_ONION: "b.onion", SHADE_TREE_BOOTNODE_HEARTBEAT: "60", SHADE_TREE_GW_WEIGHT: "7", SHADE_TREE_TOR_HOST: "10.0.0.2", SHADE_TREE_TOR_PORT: "9050" });
  ok(oc.intervalSec === 60 && oc.weight === 7 && oc.torHost === "10.0.0.2" && oc.torPort === 9050, "overrides parsed");
  // ADR 0012: every Elder Tree; the primary stays first and is added when the list omits it.
  ok(JSON.stringify(dc.bootnodes) === JSON.stringify(["b.onion"]), "one Elder -> bootnodes = [bootnode]");
  const fan = heartbeatConfig({ SHADE_TREE_BOOTNODE_ONION: "a.onion", SHADE_TREE_BOOTNODE_ONIONS: " a.onion, b.onion ,c.onion,b.onion" });
  ok(fan.bootnode === "a.onion" && JSON.stringify(fan.bootnodes) === JSON.stringify(["a.onion", "b.onion", "c.onion"]), "SHADE_TREE_BOOTNODE_ONIONS: trimmed, deduplicated, primary first");
  const fan2 = heartbeatConfig({ SHADE_TREE_BOOTNODE_ONION: "z.onion", SHADE_TREE_BOOTNODE_ONIONS: "a.onion,b.onion" });
  ok(fan2.bootnode === "z.onion" && JSON.stringify(fan2.bootnodes) === JSON.stringify(["z.onion", "a.onion", "b.onion"]), "an explicit primary missing from the list is put first");
  const fan3 = heartbeatConfig({ SHADE_TREE_BOOTNODE_ONIONS: "a.onion,b.onion" });
  ok(fan3.bootnode === "a.onion" && fan3.bootnodes.length === 2, "the list alone is enough; its first entry is the primary");
  ok(egressCheckEnabled({}) === true && egressCheckEnabled({ SHADE_TREE_EGRESS_CHECK: "0" }) === false && egressCheckEnabled({ SHADE_TREE_EGRESS_CHECK: "1" }) === true, "egressCheckEnabled: default ON, `0` OFF");

  const files = { "/id/good.json": JSON.stringify(VID), "/id/noseed.json": JSON.stringify({ onion: V.onion }), "/id/bad.json": "{not json", "/id/arr.json": "[1,2]" };
  const fakeRead = async (p) => { if (p in files) return files[p]; const e = new Error(`ENOENT: no such file or directory, open '${p}'`); e.code = "ENOENT"; throw e; };
  const id = await loadIdentity({ SHADE_TREE_GW_IDENTITY: "/id/good.json" }, { readFile: fakeRead });
  ok(id.onion === V.onion && id.seed === V.onionSeed, "loadIdentity reads SHADE_TREE_GW_IDENTITY path -> {onion, seed}");
  ok((await throwsWith(() => loadIdentity({ SHADE_TREE_GW_IDENTITY: "/id/noseed.json" }, { readFile: fakeRead }), /missing onion\/seed/)).threw, "identity missing seed -> error naming keygen");
  ok((await throwsWith(() => loadIdentity({ SHADE_TREE_GW_IDENTITY: "/id/arr.json" }, { readFile: fakeRead }), /missing onion\/seed/)).threw, "identity that is not an object -> error");
  ok((await throwsWith(() => loadIdentity({ SHADE_TREE_GW_IDENTITY: "/id/bad.json" }, { readFile: fakeRead }), /JSON/)).threw, "malformed identity JSON -> error");
  ok((await throwsWith(() => loadIdentity({ SHADE_TREE_GW_IDENTITY: "/id/nope.json" }, { readFile: fakeRead }), /ENOENT/)).threw, "missing identity file -> ENOENT surfaces");
  let defaultPath = "";
  await loadIdentity({}, { readFile: async (p) => { defaultPath = p; return JSON.stringify(VID); } });
  ok(defaultPath.endsWith(join("tor", "hs", "identity.local.json")), "no SHADE_TREE_GW_IDENTITY -> default tor/hs/identity.local.json");

  // ===================================================================================
  console.log("\n4b. makeFanoutBeat (ADR 0012): one egress check, one announce per Elder, partial acceptance:");
  {
    const flogs = [];
    const seen = [];
    let down = new Set();
    const fanAnnounce = async (elder) => { seen.push(elder); if (down.has(elder)) throw new Error(`no circuit to ${elder}`); return { ok: true, staked: true, ttl: 900 }; };
    let egressCalls = 0;
    const fanBeat = makeFanoutBeat({ bootnodes: ["aaaaaaaaaaaaaaaaaaaaaaaa.onion", "bbbbbbbbbbbbbbbbbbbbbbbb.onion"], announce: fanAnnounce, egress: async () => { egressCalls++; return { healthy: true }; }, enabled: true, log: (s) => flogs.push(s) });
    let r = await fanBeat();
    ok(r.ok === true && r.accepted === 2 && r.total === 2 && egressCalls === 1 && seen.length === 2, "both Elders announced after ONE egress check; cycle ok with accepted=2");
    ok(r.results.length === 2 && r.results.every((x) => x.ok === true && x.bootnode.endsWith(".onion")), "per-Elder results carry the Elder and its outcome");
    ok(flogs.filter((l) => /^\[aaaaaaaaaaaaaaaa\.\.onion\] announced \(staked=true, ttl=900s\)$/.test(l)).length === 1 && flogs.filter((l) => /^\[bbbbbbbbbbbbbbbb\.\.onion\] announced/.test(l)).length === 1, "each Elder's log line is tagged with its prefix");
    down = new Set(["bbbbbbbbbbbbbbbbbbbbbbbb.onion"]);
    r = await fanBeat();
    ok(r.ok === true && r.accepted === 1 && r.results[1].failed === true && /no circuit/.test(r.results[1].err), "one Elder down: cycle still ok (listed on the other), the failure is in results");
    ok(flogs.some((l) => l === "announced to 1 of 2 Elder Trees (the rest will be retried next interval)"), "partial acceptance is logged");
    down = new Set(["aaaaaaaaaaaaaaaaaaaaaaaa.onion", "bbbbbbbbbbbbbbbbbbbbbbbb.onion"]);
    r = await fanBeat();
    ok(r.ok === false && r.accepted === 0 && /no circuit/.test(r.err), "every Elder down: cycle not ok, error names the transport failure");
    const before = seen.length;
    const gated = makeFanoutBeat({ bootnodes: ["aaaaaaaaaaaaaaaaaaaaaaaa.onion", "bbbbbbbbbbbbbbbbbbbbbbbb.onion"], announce: fanAnnounce, egress: async () => ({ healthy: false, target: "example.com:443", reason: "ECONNREFUSED" }), enabled: true, log: (s) => flogs.push(s) });
    r = await gated();
    ok(r.skipped === true && seen.length === before, "egress DOWN skips every Elder (no announce at all)");
    const thrower = makeFanoutBeat({ bootnodes: ["aaaaaaaaaaaaaaaaaaaaaaaa.onion"], announce: fanAnnounce, egress: async () => { throw new Error("probe crashed"); }, enabled: true, log: (s) => flogs.push(s) });
    r = await thrower();
    ok(r.failed === true && /probe crashed/.test(r.err), "an egress probe that throws is a transport failure, never a crash");
  }

  console.log("\n5. runHeartbeat with a fake scheduler: interval, outage recovery, wiring:");
  const gw = newOnion();
  const opKey = "0x" + randomBytes(32).toString("hex");
  const env = { SHADE_TREE_BOOTNODE_ONION: V.onion, SHADE_TREE_BOOTNODE_HEARTBEAT: "7", SHADE_TREE_GW_WEIGHT: "55", SHADE_TREE_TOR_HOST: "127.0.0.3", SHADE_TREE_TOR_PORT: "9150",
    SHADE_TREE_GW_IDENTITY: "/gw/identity.local.json", SHADE_TREE_GW_OPERATOR_KEY: opKey, SHADE_TREE_EGRESS_ALLOW: "*:443,*:8443", SHADE_TREE_GATEWAY_REGION: "eu" };
  const calls = [];
  let fail = false;
  const fakeAnnounce = async (args) => { calls.push(args); if (fail) throw new Error("tor circuit failed"); return { ok: true, staked: true, ttl: 900 }; };
  let scheduled = null;
  const fakeSchedule = (fn, ms) => { scheduled = { fn, ms }; return { fake: true }; };
  const rlogs = [];
  const h = await runHeartbeat({ env, log: (s) => rlogs.push(s), schedule: fakeSchedule, announce: fakeAnnounce, egress: up, identity: gw });
  ok(h.first.ok === true && calls.length === 1, "first beat runs immediately at startup");
  ok(scheduled && scheduled.ms === 7000, "re-announce scheduled at exactly SHADE_TREE_BOOTNODE_HEARTBEAT*1000 ms");
  const a0 = calls[0];
  ok(a0.id.onion === gw.onion && a0.id.seed === gw.seed && a0.bootnode === V.onion && a0.weight === 55 && a0.torHost === "127.0.0.3" && a0.torPort === 9150, "announce receives identity, bootnode, weight, tor host/port from env");
  ok(a0.op.operator && a0.op.operatorSig && await verifyOperatorSig(gw.onion, a0.op.operator, a0.op.operatorSig), "operator resolved from SHADE_TREE_GW_OPERATOR_KEY and its sig verifies for THIS onion");
  ok(JSON.stringify(a0.caps.ports) === "[443,8443]" && a0.caps.region === "eu", "caps built from env and threaded to the announce");
  ok(calls[0].op === calls[0].op && rlogs[0].startsWith(`heartbeat: ${gw.onion.slice(0, 16)}..onion -> ${V.onion.slice(0, 16)}..onion every 7s (operator ${a0.op.operator.slice(0, 10)}..)`), "startup banner: onion prefix -> bootnode prefix, interval, operator prefix");
  ok(rlogs.some((l) => l.startsWith("egress self-check: ON")) && rlogs.some((l) => l.startsWith("capabilities advertised (signed):")), "startup logs egress-check + caps state");
  // Outage then recovery: ticks 2,3 fail, tick 4 recovers; the SAME beat keeps going, op reused.
  fail = true; await scheduled.fn(); await scheduled.fn(); fail = false; await scheduled.fn();
  ok(calls.length === 4, "scheduled ticks call announce every interval (3 more ticks -> 4 announces)");
  ok(rlogs.filter((l) => l.startsWith("announce failed: tor circuit failed (will retry next interval)")).length === 2, "outage ticks log `announce failed ... (will retry next interval)`");
  ok(rlogs.filter((l) => l === "announced (staked=true, ttl=900s)").length === 2, "first + recovered ticks log `announced`");
  ok(JSON.stringify(h.bootnodes) === JSON.stringify([V.onion]) && !rlogs.some((l) => l.startsWith("heartbeat: announcing to")), "single Elder: no fan-out banner, one announce per tick (byte-identical path)");
  // ADR 0012: with several Elders, one tick announces to each of them.
  {
    const fcalls = [];
    const fenv = { ...env, SHADE_TREE_BOOTNODE_ONIONS: `${V.onion},${newOnion().onion}` };
    const fl = [];
    const fh = await runHeartbeat({ env: fenv, log: (s) => fl.push(s), schedule: fakeSchedule, announce: async (a) => { fcalls.push(a.bootnode); return { ok: true, staked: true, ttl: 900 }; }, egress: up, identity: gw });
    ok(fh.bootnodes.length === 2 && fcalls.length === 2 && fcalls[0] === V.onion && fcalls[1] === fenv.SHADE_TREE_BOOTNODE_ONIONS.split(",")[1], "two Elders: the first tick announces to both, primary first");
    ok(fh.first.ok === true && fh.first.accepted === 2 && fl.some((l) => l.startsWith("heartbeat: announcing to 2 Elder Trees (")), "fan-out banner names the count; first beat accepted by both");
  }
  ok(calls[3].op === calls[0].op && calls[3].id === calls[0].id, "operator auth + identity resolved ONCE and reused across ticks (durable)");
  // Onion-only + egress-check OFF + no caps env: banner variants.
  const rlogs2 = [];
  const h2 = await runHeartbeat({ env: { SHADE_TREE_BOOTNODE_ONION: V.onion, SHADE_TREE_EGRESS_CHECK: "0" }, log: (s) => rlogs2.push(s), schedule: fakeSchedule, announce: fakeAnnounce, egress: async () => { throw new Error("must not probe"); }, identity: gw });
  ok(h2.first.ok === true && rlogs2[0].endsWith("every 300s (onion-only)"), "onion-only banner + default interval");
  ok(rlogs2.some((l) => l.startsWith("egress self-check: OFF")) && rlogs2.some((l) => l.startsWith("capabilities: none")), "OFF + none banners");
  ok(calls.at(-1).caps === null && !("operator" in buildAnnounce({ onion: gw.onion, onionSeedHex: gw.seed, operator: calls.at(-1).op.operator, operatorSig: calls.at(-1).op.operatorSig })), "unconfigured -> caps null, no operator");
  ok((await throwsWith(() => runHeartbeat({ env: {}, log: () => {}, schedule: fakeSchedule, announce: fakeAnnounce, identity: gw }), /set SHADE_TREE_BOOTNODE_ONION/)).threw, "runHeartbeat without a bootnode fails fast");
  ok((await throwsWith(() => runHeartbeat({ env: { SHADE_TREE_BOOTNODE_ONION: V.onion, SHADE_TREE_GW_OPERATOR: OA.operator }, log: () => {}, schedule: fakeSchedule, announce: fakeAnnounce, identity: gw }), /must be set together/)).threw, "runHeartbeat with half an operator pair fails at startup (before any announce)");

  // ===================================================================================
  console.log("\n6. log hygiene (dynamic): seed + operator key never reach a log sink:");
  const captured = await withCapture(async () => {
    const hh = await runHeartbeat({ env, schedule: fakeSchedule, announce: fakeAnnounce, egress: up, identity: gw });
    fail = true; await hh.beat(); fail = false;
    await hh.beat();
    // default log sink (console.log) is what production uses — exercised here under capture
  });
  const keyBare = opKey.slice(2);
  ok(captured.length > 0 && captured.includes('"msg":"heartbeat configured"') && captured.includes('"msg":"heartbeat accepted"'), "control: structured heartbeat events reach the real console sinks");
  const configuredLog = captured.split("\n").filter(Boolean).map((line) => { try { return JSON.parse(line); } catch { return null; } }).find((record) => record?.msg === "heartbeat configured");
  ok(configuredLog?.authMode === "staked-operator", "heartbeat configuration keeps its bounded auth mode visible");
  ok(!captured.includes(gw.seed), "onion SEED hex never appears in captured logs");
  ok(!captured.includes(keyBare) && !captured.includes(opKey), "operator KEY hex (with or without 0x) never appears in captured logs");
  ok(!captured.includes(gw.onion.slice(0, 16)) && !captured.includes(a0.op.operator.slice(0, 10)), "onion and operator identifiers are absent from default logs");
  ok(!captured.includes(a0.op.operator), "the full operator address is not logged");
  // Every operator-resolution error path under capture: message must not carry the key/seed.
  const badEnvs = [
    { SHADE_TREE_GW_OPERATOR_KEY: opKey + "5" }, { SHADE_TREE_GW_OPERATOR_KEY: opKey.slice(0, -1) }, { SHADE_TREE_GW_OPERATOR_KEY: "0x" + "ff".repeat(32) },
    { SHADE_TREE_GW_OPERATOR: OA.operator }, { SHADE_TREE_GW_OPERATOR: OA.operator, SHADE_TREE_GW_OPERATOR_SIG: flipped },
  ];
  let errCaptured = "";
  for (const bad of badEnvs) {
    errCaptured += await withCapture(async () => {
      try { await runHeartbeat({ env: { SHADE_TREE_BOOTNODE_ONION: V.onion, ...bad }, schedule: fakeSchedule, announce: fakeAnnounce, identity: gw }); }
      catch (e) { console.error(e); } // exactly what main() does
    });
  }
  ok(errCaptured.split("SHADE_TREE_GW_OPERATOR").length >= badEnvs.length, "control: every misconfig printed an error via console.error(e)");
  ok(!errCaptured.includes(keyBare) && !errCaptured.includes(keyBare.slice(0, 24)), "no misconfig error ever echoes the (mistyped) operator key bytes");
  ok(!errCaptured.includes(gw.seed), "no misconfig error ever echoes the onion seed");

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: heartbeat selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
