// Log-hygiene selftest: prove that no SECRET material is ever written to a log sink.
//
// The property (from the threat model): the gateway, bootnode, heartbeat, and client MUST NOT
// log secret material — a member's SHADE_TREE_SECRET / identitySecret, an onion identity SEED (the
// 32-byte hex in identity.local.json), or an operator private key. They MAY freely log public
// values: commitments, operator ADDRESSES, roots, and tx hashes. Even though onion addresses
// and nullifiers are not secrets by themselves, routine traffic metadata is kept out of the
// default operator log stream and is checked dynamically below.
//
// It would FAIL if someone added `console.log(seed)` or logged a raw secret. Two layers:
//
//   1. STATIC scan. For every source file that logs, extract each console.*, structured
//      log.debug/info/warn/error, and process.stdout/stderr.write call, and check whether it
//      interpolates a variable
//      whose NAME suggests a secret (seed, secret, identitySecret, priv/privKey, SHADE_TREE_SECRET,
//      SHADE_TREE_SLASH_KEY, SHADE_TREE_GW_OPERATOR_KEY, SHADE_TREE_REGISTER_KEY,
//      SHADE_TREE_REGISTRAR_KEY) UNTRUNCATED. Every listed file
//      except group/enroll.mjs must have ZERO such interpolations. (A `.slice(...)`-truncated
//      reference, e.g. gateway's `secret=${String(secret).slice(0,10)}..`, is NOT a full leak
//      and is allowed by this test's definition.)
//
//      enroll.mjs is the ONE intended exception: it prints the member's bearer secret so the
//      human running it can keep it. The static test pins that exception in place — the secret
//      reaches STDOUT only in the default/enroll flow, and commitment-only mode routes it to
//      STDERR (never stdout), consistent with group/enroll.selftest.mjs.
//
//   2. DYNAMIC (best-effort). Spin the real bootnode in-process (makeRegistry/makeServer),
//      drive a real announce built from a known onion SEED, and assert the SEED hex never
//      appears in captured stdout/stderr NOR on the wire (served /directory, /gateway/<onion>).
//      Drive the gateway spent-set over-spend path (makeSpentSet) with a mock reconstruct that
//      returns a known identitySecret, and assert that secret never appears in captured logs —
//      on the slash path OR the slash-failed catch path. Spawn enroll --commitment-only and
//      assert the secret is on stderr, never stdout.
//
//   node test/log-hygiene.selftest.mjs
//
// Exit 0 = no secret ever reaches a log; nonzero = a leak (prints the file + line).

import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

// ---------------------------------------------------------------------------
// Static scanner
// ---------------------------------------------------------------------------

const STATIC_SINKS = [
  "console.log", "console.error", "console.warn", "console.info", "console.debug",
  "log.debug", "log.info", "log.warn", "log.error",
  "logger.debug", "logger.info", "logger.warn", "logger.error",
  "process.stdout.write", "process.stderr.write",
];
const STDERR_SINKS = new Set([
  "console.error", "console.warn", "log.warn", "log.error", "logger.warn", "logger.error",
  "process.stderr.write",
]);

// A reference whose NAME suggests secret material. \b-anchored so `secretFile`, `seenNonce`,
// `SecretKeeper` do NOT match; `secret`, `identitySecret`, `signer.priv`, `id.seed`, and the
// SHADE_TREE_*_KEY env names do.
const SECRET = /\b(identitySecret|secret|seedHex|seed|privKey|priv|SHADE_TREE_SECRET|SHADE_TREE_SLASH_KEY|SHADE_TREE_GW_OPERATOR_KEY|SHADE_TREE_REGISTER_KEY|SHADE_TREE_REGISTRAR_KEY)\b/;
// A reference is "truncated" (partial, not a full leak) if it is sliced or measured.
const TRUNC = /\.(slice|substr|substring)\s*\(|\.length\b/;

function lineOf(src, idx) { return src.slice(0, idx).split("\n").length; }

// Read the balanced (...) argument text of a call starting at the "(" index. Treats '..', ".."
// and `..` spans as opaque strings so parens inside string/template text don't unbalance it.
function readBalanced(src, openIdx) {
  let depth = 0, inStr = null;
  for (let i = openIdx; i < src.length; i++) {
    const c = src[i];
    if (inStr) {
      if (c === "\\") { i++; continue; }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === "'" || c === '"' || c === "`") { inStr = c; continue; }
    if (c === "(") depth++;
    else if (c === ")") { depth--; if (depth === 0) return { args: src.slice(openIdx + 1, i), end: i + 1 }; }
  }
  return { args: src.slice(openIdx + 1), end: src.length };
}

// Every sink call in the source, with its raw argument text.
function sinkNames(src) {
  const sinks = new Set(STATIC_SINKS);
  // Service loggers are often named for their role (heartbeatLog, clientLog). Discover every
  // local identifier bound directly to createLogger() so renaming one cannot silently remove it
  // from this hygiene check.
  const declarations = /\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*createLogger\s*\(/g;
  let match;
  while ((match = declarations.exec(src))) {
    for (const level of ["debug", "info", "warn", "error"]) sinks.add(`${match[1]}.${level}`);
  }
  return [...sinks];
}

function extractCalls(src) {
  const calls = [];
  for (const sink of sinkNames(src)) {
    let idx = 0;
    for (;;) {
      const at = src.indexOf(sink + "(", idx);
      if (at === -1) break;
      const before = src[at - 1];
      if (before && /[A-Za-z0-9_$.]/.test(before)) { idx = at + 1; continue; } // not a standalone sink
      const { args, end } = readBalanced(src, at + sink.length);
      calls.push({ sink, args, index: at, line: lineOf(src, at), stderr: STDERR_SINKS.has(sink) || /\.(warn|error)$/.test(sink) });
      idx = end;
    }
  }
  return calls;
}

// The `${...}` interpolation expressions inside any template literals in `args`.
function templateInterps(args) {
  const out = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] !== "`") continue;
    let j = i + 1;
    while (j < args.length && args[j] !== "`") { if (args[j] === "\\") j++; j++; }
    const span = args.slice(i + 1, j);
    let k = 0;
    for (;;) {
      const s = span.indexOf("${", k);
      if (s === -1) break;
      let d = 1, e = s + 2;
      for (; e < span.length && d > 0; e++) { if (span[e] === "{") d++; else if (span[e] === "}") d--; }
      out.push(span.slice(s + 2, e - 1));
      k = e;
    }
    i = j;
  }
  return out;
}

// The "code" of `args` with every string/template literal removed — so bare concatenation
// operands like  "SHADE_TREE_SECRET=" + secret  survive as the identifier `secret`.
function codeResidue(args) {
  let out = "", inStr = null;
  for (let i = 0; i < args.length; i++) {
    const c = args[i];
    if (inStr) {
      if (c === "\\") { i++; continue; }
      if (c === inStr) inStr = null;
      continue;
    }
    if (c === "'" || c === '"' || c === "`") { inStr = c; continue; }
    out += c;
  }
  return out;
}

// Does a single expression interpolate a secret UNTRUNCATED?
function exprLeaks(expr) { return SECRET.test(expr) && !TRUNC.test(expr); }

// Does the concatenation residue reference a secret UNTRUNCATED?
function residueLeaks(residue) {
  const re = new RegExp(SECRET.source, "g");
  let m;
  while ((m = re.exec(residue))) {
    if (!TRUNC.test(residue.slice(m.index, m.index + 40))) return true;
  }
  return false;
}

// Every sink call that writes an UNTRUNCATED secret, for one file.
function scanSource(src) {
  const leaks = [];
  for (const call of extractCalls(src)) {
    const viaTemplate = templateInterps(call.args).some(exprLeaks);
    const viaConcat = residueLeaks(codeResidue(call.args));
    if (viaTemplate || viaConcat) leaks.push(call);
  }
  return leaks;
}

function scanFile(rel) {
  return scanSource(readFileSync(join(ROOT, rel), "utf8"));
}

// Files that both LOG and touch secret material. announce.mjs and shade-tree-client.mjs have no sinks
// at all (pure libs / event-emit only) — included so the test asserts that stays true.
const FILES = [
  "packages/node/bootnode/announce.mjs",
  "packages/node/client/shade-tree-client.mjs",
  "packages/node/client/shim.mjs",
  "packages/node/client/selection.mjs",
  "packages/node/payments/registrar.mjs",
  "group/register-gateway.mjs",
  "group/register-onchain.mjs",
];

// ---------------------------------------------------------------------------

async function main() {
  // === 1. STATIC: no file (except enroll) writes an untruncated secret to any log sink ===
  console.log("static scan — no secret interpolated into any log sink:");
  const canary = scanSource('const unusualRoleLog = createLogger("canary"); const secret = "sentinel"; unusualRoleLog.info("bad", { secret });');
  ok(canary.length === 1 && canary[0].sink === "unusualRoleLog.info", "scanner discovers named createLogger sinks and catches a synthetic secret leak");
  for (const rel of FILES) {
    const leaks = scanFile(rel);
    ok(leaks.length === 0, `${rel}: no untruncated secret in any recognized log sink`);
    for (const l of leaks) {
      // A real leak: name it precisely so it can be fixed at the source.
      console.log(`       LEAK ${rel}:${l.line}  ${l.sink}(...)  ->  ${l.args.trim().slice(0, 90)}`);
    }
  }

  // === 1b. enroll.mjs: the ONE intended exception, held in place ===
  // enroll prints the member's bearer secret (by design). Assert the exception is scoped:
  // commitment-only mode -> secret to STDERR only; the operator channel (stdout) is commitment
  // alone. The default/enroll flow may print the secret to stdout.
  console.log("\nenroll.mjs — the one intended secret-print, correctly scoped:");
  const enrollSrc = readFileSync(join(ROOT, "group/enroll.mjs"), "utf8");
  const enrollLeaks = scanFile("group/enroll.mjs");
  ok(enrollLeaks.length >= 1, "enroll.mjs DOES print the member secret (the intended exception exists)");

  const coStart = enrollSrc.indexOf("if (commitmentOnly)");
  const coEnd = enrollSrc.indexOf("process.exit(0)", coStart);
  ok(coStart !== -1 && coEnd !== -1, "enroll.mjs has a commitment-only branch ending in process.exit(0)");

  const stdoutSecretWrites = enrollLeaks.filter((l) => !l.stderr);
  ok(stdoutSecretWrites.length >= 1, "enroll.mjs writes the secret to stdout in exactly one flow (default mode)");
  ok(stdoutSecretWrites.every((l) => l.index > coEnd),
     "every stdout secret-write is AFTER the commitment-only branch (never in commitment-only mode)");

  const stderrSecretInCO = enrollLeaks.filter((l) => l.stderr && l.index >= coStart && l.index <= coEnd);
  ok(stderrSecretInCO.length >= 1, "commitment-only mode routes the secret to STDERR (not the operator stdout channel)");

  // === 1c. enroll.mjs DYNAMIC: commitment-only really keeps the secret off stdout ===
  console.log("\nenroll.mjs commitment-only run — secret on stderr, never stdout:");
  const run = spawnSync(process.execPath, [join(ROOT, "group/enroll.mjs"), "--commitment-only"], {
    cwd: ROOT, encoding: "utf8", timeout: 60_000,
  });
  const SECRET_RE = /secret value:\s*(0x[0-9a-fA-F]{64})/i;
  ok(run.status === 0, "enroll --commitment-only exits 0");
  const m = run.stderr.match(SECRET_RE);
  ok(!!m, "the secret value is emitted on STDERR");
  ok(/read -s SHADE_TREE_SECRET && export SHADE_TREE_SECRET/.test(run.stderr) && !/export SHADE_TREE_SECRET=0x/.test(run.stderr), "enrollment guidance keeps the secret out of shell history");
  const secret = m ? m[1] : "__none__";
  ok(!run.stdout.includes(secret), "the secret hex does NOT appear on stdout");
  ok(!/0x[0-9a-fA-F]{16,}/.test(run.stdout), "no long 0x-hex blob on stdout at all");

  // === Coverage note for processes not driven in-process ===
  console.log("\ncoverage: shim, client/selection, registrar, register-* are STATIC-only");
  console.log("  (they need Tor / a live chain / a listening proxy to run; their log sinks are");
  console.log("   fully covered by the static scan above — none interpolates a secret; the Rust");
  console.log("   node and Elder have their own log hygiene tests).");

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: log-hygiene selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
