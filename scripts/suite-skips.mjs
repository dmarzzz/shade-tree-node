// Suite outcome classification for scripts/test-all.mjs: tell a suite that ran its checks
// from one that exited 0 after skipping them.
//
// Several selftests skip their work when a tool is missing and still exit 0 (the anvil/forge
// suites print `  SKIP anvil/forge not on PATH` and return). The runner only looks at the exit
// status and hides a passing suite's stdout, so before this module such a suite showed up as
// PASS and counted as green, the same as one that ran every check. That hid real failures: the
// on-chain over-spend steps were red on main while CI listed both suites as PASS.
//
// A suite is SKIP when it exits 0 and its stdout has at least one line that starts with the
// word SKIP (after leading spaces): `SKIP reason`, `SKIP: reason`, or a bare `SKIP`. A line that
// only mentions SKIP later on (`... ; SKIP announce`, `SHADE_TREE_SKIP_VALIDATE`, `SKIPPED`)
// does not count. A suite that skips only part of its work (group/exit-gateway runs Part 1 and
// skips Part 2 without anvil) is SKIP too: the point is that something was not exercised.
// A nonzero exit is FAIL whatever it printed. SKIP is reported, not failed: the
// exit code of the runner is unchanged.
//
//   node scripts/suite-skips.selftest.mjs

// A suite's stdout is untrusted text (a selftest can print anything). Bound what we keep.
export const MAX_REASONS = 5;
export const MAX_REASON_CHARS = 200;

// `SKIP` at the start of a line (after spaces or tabs), then end of line, a colon or whitespace.
const SKIP_LINE = /^[ \t]*SKIP(?::|[ \t]|$)[ \t]*(.*)$/;

// Control characters other than tab, plus ANSI escape sequences, are dropped from a reason so a
// suite cannot rewrite the runner's own output lines.
const ANSI = /\u001b\[[0-9;?]*[ -/]*[@-~]/g;
const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g;

function cleanReason(raw) {
  const s = raw.replace(ANSI, "").replace(CONTROL, "").trim();
  return s.length > MAX_REASON_CHARS ? s.slice(0, MAX_REASON_CHARS - 3) + "..." : s;
}

// Every SKIP line in `stdout`, as reasons (text after the SKIP word, "" if none), in order,
// deduplicated, at most MAX_REASONS. `total` is the number of SKIP lines before the cap.
export function skipLines(stdout) {
  if (typeof stdout !== "string" || stdout.length === 0) return { reasons: [], total: 0 };
  const reasons = [];
  let total = 0;
  for (const line of stdout.split("\n")) {
    const m = SKIP_LINE.exec(line.replace(/\r$/, "").replace(ANSI, ""));
    if (!m) continue;
    total++;
    const reason = cleanReason(m[1]);
    if (reasons.length < MAX_REASONS && !reasons.includes(reason)) reasons.push(reason);
  }
  return { reasons, total };
}

// PASS | SKIP | FAIL for one finished suite (`status` = exit code, null if killed by a signal).
export function classifySuite({ status, stdout }) {
  if (status !== 0) return { outcome: "FAIL", reasons: [] };
  const { reasons, total } = skipLines(stdout);
  return total > 0 ? { outcome: "SKIP", reasons } : { outcome: "PASS", reasons: [] };
}

// One-line reason text for a SKIP suite.
export function reasonText(reasons) {
  const shown = reasons.map((r) => r || "(no reason given)");
  return shown.length ? shown.join("; ") : "(no reason given)";
}

// Summary lines for results [{ name, outcome: PASS|SKIP|FAIL, reasons }].
// "green" counts suites that exited 0 (PASS + SKIP), as before; SKIP suites are then named so a
// green run with skipped work cannot be read as full coverage.
export function summaryLines(results) {
  const failed = results.filter((r) => r.outcome === "FAIL");
  const skipped = results.filter((r) => r.outcome === "SKIP");
  const green = results.length - failed.length;
  const lines = [];
  lines.push(
    `\n=== summary: ${green}/${results.length} green` +
    (skipped.length ? `, ${skipped.length} of them SKIPPED (exit 0 but printed SKIP: some or all checks not run)` : "") +
    " ==="
  );
  if (skipped.length) {
    lines.push("SKIPPED (exit 0, some or all checks not run; install the missing tool to exercise them):");
    for (const s of skipped) lines.push(`  ? ${s.name}: ${reasonText(s.reasons)}`);
  }
  return { lines, failed, skipped };
}
