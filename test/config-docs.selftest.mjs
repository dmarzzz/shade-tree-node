// OPS-16: every SHADE_TREE_* variable the server roles read is documented in docs/CONFIG.md, so an
// operator never has to read source to find a knob. Scans gateway/, bootnode/, payments/ and lib/
// (not tests) for environment reads: process.env.X, env.X, env["X"] and envInt("X", ...).
//   node test/config-docs.selftest.mjs
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DIRS = ["gateway", "bootnode", "payments", "lib"];
const READ = /(?:process\.env|\benv)(?:\.|\[\s*["'])(SHADE_TREE_[A-Z0-9_]*[A-Z0-9])|\benv(?:Int|Num|Bool)?\(\s*["'](SHADE_TREE_[A-Z0-9_]*[A-Z0-9])["']/g;

const used = new Map();
for (const dir of DIRS) {
  for (const name of readdirSync(join(ROOT, dir))) {
    if (!name.endsWith(".mjs") || name.includes("selftest")) continue;
    const src = readFileSync(join(ROOT, dir, name), "utf8");
    for (const m of src.matchAll(READ)) {
      const v = m[1] || m[2];
      if (!used.has(v)) used.set(v, `${dir}/${name}`);
    }
  }
}
const docs = new Set(readFileSync(join(ROOT, "docs", "CONFIG.md"), "utf8").match(/SHADE_TREE_[A-Z0-9_]+/g));
const missing = [...used].filter(([v]) => !docs.has(v)).sort();
if (used.size < 100) { console.log(`FAIL: scanner found only ${used.size} variables; the pattern is broken`); process.exit(1); }
if (missing.length) {
  console.log(`FAIL: ${missing.length} server variable(s) not in docs/CONFIG.md:`);
  for (const [v, file] of missing) console.log(`  ${v}  (${file})`);
  process.exit(1);
}
console.log(`PASS: all ${used.size} server SHADE_TREE_* variables are documented`);
