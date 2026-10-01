// Every public error code the SDK can raise is documented in docs/ERRORS.md with a cause and a
// fix (not just "report it"), and the Rust `explain()` table covers the node refusal reasons the
// gateway actually emits. Agents read these columns; an undocumented code is a dead end.
//
//   node test/errors-doc.selftest.mjs

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

const errorRs = readFileSync(join(ROOT, "crates/shadenet/src/error.rs"), "utf8");
const codes = errorRs.match(/pub const ERROR_CODES: &\[&str\] = &\[([\s\S]*?)\];/)[1]
  .match(/"([a-z_]+)"/g).map((s) => s.replace(/"/g, ""));
ok(codes.length >= 14, `ERROR_CODES parsed from error.rs (${codes.length})`);

const doc = readFileSync(join(ROOT, "docs/ERRORS.md"), "utf8");
const rows = new Map();
for (const line of doc.split("\n")) {
  const m = line.match(/^\| `([a-z_]+)` \| (\d+) \| ([^|]+) \| ([^|]+) \| ([^|]+) \| ([^|]+) \|$/);
  if (m) rows.set(m[1], { http: m[2], what: m[3].trim(), cause: m[5].trim(), fix: m[6].trim() });
}
for (const code of [...codes, "busy", "proxy_auth_required"]) {
  const row = rows.get(code);
  ok(row, `ERRORS.md documents \`${code}\``);
  if (!row) continue;
  ok(row.cause.length > 0 && row.cause !== "—" || code === "internal", `${code}: typical cause column is filled`);
  ok(row.fix.length > 8 && !/^report it$/i.test(row.fix), `${code}: fix column says what to run`);
}
ok(/X-ShadeNet-Cause/.test(doc) && /problems\[\]/.test(doc) && /shadenet doctor/.test(doc), "ERRORS.md explains the cause header, problems[] and the doctor");

// Node refusal reasons the gateway emits must each have an explanation branch in Rust.
const gateway = readFileSync(join(ROOT, "packages/node/gateway/gateway.mjs"), "utf8");
const dropLabels = [...gateway.matchAll(/"(wrong-group-root|root-not-recent|stale-external-nullifier|session-unsupported|bad-version|unsupported-version|invalid-proof|payload-limit)"/g)].map((m) => m[1]);
const explained = errorRs.slice(errorRs.indexOf("pub fn explain_reason"), errorRs.indexOf("impl Error {"));
for (const label of new Set(dropLabels)) {
  ok(explained.includes(`"${label}"`), `explain_reason covers node reason \`${label}\``);
}
ok(/X-ShadeNet-Cause/.test(readFileSync(join(ROOT, "crates/shadenet/src/proxy.rs"), "utf8")), "the proxy sends X-ShadeNet-Cause");
ok(/problems/.test(readFileSync(join(ROOT, "specs/local-api.openapi.yaml"), "utf8")), "the local API spec documents problems[]");

if (failures) { console.log(`FAIL: ${failures} check(s)`); process.exit(1); }
console.log(`PASS: error codes documented with cause and fix (${codes.length} codes)`);
