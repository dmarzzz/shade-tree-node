// Selftest for scripts/suite-skips.mjs, the PASS / SKIP / FAIL split that scripts/test-all.mjs
// uses so a suite that exits 0 after skipping its checks is not counted as exercised.
//
//   - the real SKIP lines our tool-gated suites print classify as SKIP, with their reason
//   - every suite that prints a SKIP line in this repo still matches the parser (drift guard)
//   - lines that only mention SKIP mid-line (heartbeat "; SKIP announce", SHADE_TREE_SKIP_VALIDATE,
//     SKIPPED) stay PASS
//   - a nonzero exit is FAIL even if it printed SKIP
//   - adversarial stdout: ANSI / control characters, CR line ends, huge input, many SKIP lines,
//     non-string stdout, cannot break the summary or inject runner lines
//   - the summary keeps the old "N/M green" count and names each SKIP suite
//
//   node scripts/suite-skips.selftest.mjs   (exit 0 = all invariants held)

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  classifySuite, skipLines, reasonText, summaryLines, MAX_REASONS, MAX_REASON_CHARS,
} from "./suite-skips.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

console.log("real SKIP output of the tool-gated suites:");
// Verbatim stdout of `node test/onchain-tiers.selftest.mjs` with no anvil/forge on PATH.
const onchainNoFoundry = [
  "on-chain tiers + on-chain root, end to end on anvil (T-FEAT-8b / T-DEV-9c):",
  "  SKIP anvil/forge not on PATH",
  "",
  "PASS: onchain-tiers selftest (0 failures)",
].join("\n");
{
  const c = classifySuite({ status: 0, stdout: onchainNoFoundry });
  ok(c.outcome === "SKIP", "onchain-tiers without foundry -> SKIP, not PASS");
  ok(c.reasons.length === 1 && c.reasons[0] === "anvil/forge not on PATH", `reason kept: ${JSON.stringify(c.reasons)}`);
}
ok(classifySuite({ status: 0, stdout: "SKIP: terraform validation selftest (tofu/terraform unavailable)\n" }).reasons[0]
  === "terraform validation selftest (tofu/terraform unavailable)", "`SKIP: reason` form (terraform validation) -> reason after the colon");
ok(classifySuite({ status: 0, stdout: "part 1\n  ok   calldata\n  SKIP anvil not on PATH (Part 1 covered calldata + validation)\n" }).outcome
  === "SKIP", "partial skip (group/exit-gateway Part 2) -> SKIP");
ok(classifySuite({ status: 0, stdout: "\tSKIP\n" }).outcome === "SKIP" && reasonText(classifySuite({ status: 0, stdout: "\tSKIP\n" }).reasons) === "(no reason given)",
  "bare SKIP (tab indent, no reason) -> SKIP, reason shown as (no reason given)");

console.log("\ndrift guard: every suite in the repo that prints SKIP still matches:");
for (const rel of [
  "test/onchain-tiers.selftest.mjs",
  "test/paid-access.selftest.mjs",
  "packages/node/payments/registrar.selftest.mjs",
  "packages/node/bootnode/deploy/terraform/validation.selftest.mjs",
  "group/exit-gateway.selftest.mjs",
]) {
  const src = readFileSync(join(ROOT, rel), "utf8");
  const printed = [...src.matchAll(/console\.log\("([^"]*SKIP[^"]*)"\)/g)].map((m) => m[1]);
  ok(printed.length > 0 && printed.every((s) => classifySuite({ status: 0, stdout: s }).outcome === "SKIP"),
    `${rel}: ${printed.length} SKIP message(s), all classified SKIP`);
}

console.log("\nnot a skip:");
ok(classifySuite({ status: 0, stdout: "  ok   all\n\nall green\n" }).outcome === "PASS", "ordinary green output -> PASS");
ok(classifySuite({ status: 0, stdout: "" }).outcome === "PASS", "empty stdout -> PASS");
ok(classifySuite({ status: 0, stdout: "  ok   egress DOWN (example.com:443 ECONNREFUSED); SKIP announce\n" }).outcome === "PASS",
  "SKIP mid-line (heartbeat assertion text) -> PASS");
ok(classifySuite({ status: 0, stdout: "\nclient with SHADE_TREE_SKIP_VALIDATE=1 (env opt-out):\n" }).outcome === "PASS",
  "SHADE_TREE_SKIP_VALIDATE heading -> PASS");
ok(classifySuite({ status: 0, stdout: "SKIPPED nothing\nSKIPS\nskip lowercase\n" }).outcome === "PASS",
  "SKIPPED / SKIPS / lowercase skip at line start -> PASS");
ok(classifySuite({ status: 0, stdout: "  ok   egress DOWN => announce SKIPPED\n" }).outcome === "PASS",
  "test name containing SKIPPED -> PASS");

console.log("\nnonzero exit wins:");
ok(classifySuite({ status: 1, stdout: "  SKIP anvil/forge not on PATH\n" }).outcome === "FAIL", "exit 1 + SKIP line -> FAIL");
ok(classifySuite({ status: null, stdout: "  SKIP x\n" }).outcome === "FAIL", "killed by signal (status null) -> FAIL");

console.log("\nadversarial stdout:");
{
  const c = classifySuite({ status: 0, stdout: "  SKIP \u001b[31mred\u001b[0m reason\u0007\n  SKIP x\r\n" });
  ok(c.outcome === "SKIP" && c.reasons[0] === "red reason" && c.reasons[1] === "x", `ANSI, BEL and CR stripped: ${JSON.stringify(c.reasons)}`);
}
{
  const c = classifySuite({ status: 0, stdout: "\u001b[33m  SKIP colored line\u001b[0m\n" });
  ok(c.outcome === "SKIP" && c.reasons[0] === "colored line", "SKIP line wrapped in an ANSI color -> still SKIP");
}
{
  const c = classifySuite({ status: 0, stdout: "  SKIP a\u0000b\u001b]0;title\u0007c\n" });
  ok(!/[\u0000-\u0008\u000b-\u001f\u007f]/.test(c.reasons[0]), "NUL and OSC escape bytes cannot reach the runner output");
}
{
  const c = classifySuite({ status: 0, stdout: "  SKIP " + "A".repeat(10_000) + "\n" });
  ok(c.reasons[0].length === MAX_REASON_CHARS && c.reasons[0].endsWith("..."), `reason capped at ${MAX_REASON_CHARS} chars`);
}
{
  const many = Array.from({ length: 50 }, (_, i) => `  SKIP r${i % 7}`).join("\n");
  const s = skipLines(many);
  ok(s.total === 50 && s.reasons.length === MAX_REASONS, `50 SKIP lines -> total 50, ${MAX_REASONS} reasons kept`);
  ok(new Set(s.reasons).size === s.reasons.length, "reasons deduplicated");
}
ok(skipLines(undefined).total === 0 && skipLines(null).total === 0 && skipLines(42).total === 0, "non-string stdout -> no skips, no throw");
{
  const big = "x".repeat(2_000_000) + "\n  SKIP late\n";
  const t0 = Date.now();
  const c = classifySuite({ status: 0, stdout: big });
  ok(c.outcome === "SKIP" && Date.now() - t0 < 2000, "2 MB stdout with a late SKIP line classified quickly");
}
ok(classifySuite({ status: 0, stdout: "  SKIP x\n=== summary: 999/999 green ===\n" }).reasons.join("") === "x",
  "a suite printing a fake summary line does not change its own reasons");

console.log("\nsummary:");
{
  const results = [
    { name: "a.selftest.mjs", outcome: "PASS", reasons: [] },
    { name: "test/onchain-tiers.selftest.mjs", outcome: "SKIP", reasons: ["anvil/forge not on PATH"] },
    { name: "b.selftest.mjs", outcome: "SKIP", reasons: [] },
    { name: "c.selftest.mjs", outcome: "FAIL", reasons: [] },
  ];
  const { lines, failed, skipped } = summaryLines(results);
  const text = lines.join("\n");
  ok(text.includes("=== summary: 3/4 green, 2 of them SKIPPED"), "green count unchanged (PASS + SKIP), SKIP count added");
  ok(text.includes("  ? test/onchain-tiers.selftest.mjs: anvil/forge not on PATH"), "each SKIP suite named with its reason");
  ok(text.includes("  ? b.selftest.mjs: (no reason given)"), "SKIP without reason named");
  ok(failed.length === 1 && failed[0].name === "c.selftest.mjs" && skipped.length === 2, "failed / skipped lists returned");
}
{
  const { lines, skipped } = summaryLines([{ name: "a", outcome: "PASS", reasons: [] }, { name: "forge test", outcome: "PASS", reasons: [] }]);
  ok(lines.join("\n") === "\n=== summary: 2/2 green ===" && skipped.length === 0, "no skips -> summary line identical to the old format");
}
ok(reasonText([]) === "(no reason given)" && reasonText(["a", ""]) === "a; (no reason given)", "reasonText joins and fills empty reasons");

console.log(failures ? `\n${failures} FAILED` : "\nall green");
process.exit(failures ? 1 : 0);
