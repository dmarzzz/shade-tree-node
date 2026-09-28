// A browser app can bundle @shadenet/sdk with a stock esbuild config: no externals, no node
// polyfills, and snarkjs split into a lazy chunk. Reports the sizes a staking page pays.
//
//   node packages/sdk/test/browser-bundle.selftest.mjs

import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

const tmp = mkdtempSync(join(tmpdir(), "shadenet-browser-"));
try {
  const cases = {
    everything: `export * from "@shadenet/sdk";`,
    staking: `export { createIdentity, importIdentity, createStaking } from "@shadenet/sdk";`,
  };
  for (const [name, contents] of Object.entries(cases)) {
    const outdir = join(tmp, name);
    const { metafile } = await build({
      stdin: { contents, resolveDir: ROOT, loader: "js" },
      bundle: true, splitting: true, format: "esm", platform: "browser", minify: true,
      outdir, metafile: true, logLevel: "silent",
    });
    const outputs = Object.entries(metafile.outputs);
    const entry = outputs.find(([, o]) => o.entryPoint);
    const entryText = readFileSync(join(ROOT, entry[0]), "utf8");
    ok(!/["']node:[a-z/]+["']/.test(entryText.replace(/import\("\.\/[^"]+"\)/g, "")), `${name}: entry has no node: builtin imports`);
    ok(outputs.some(([f, o]) => f !== entry[0] && o.bytes > 200 * 1024), `${name}: snarkjs is in a separate lazy chunk`);
    console.log(`       ${name}: entry ${(entry[1].bytes / 1024).toFixed(1)} KiB, total ${(outputs.reduce((n, [, o]) => n + o.bytes, 0) / 1024).toFixed(1)} KiB`);
    if (name === "staking") ok(entry[1].bytes < 110 * 1024, "staking: entry under 110 KiB");
  }
} finally {
  rmSync(tmp, { recursive: true, force: true });
}

if (failures) {
  console.log(`\nFAIL: ${failures} browser bundle check(s)`);
  process.exit(1);
}
console.log("\nPASS: @shadenet/sdk bundles for the browser");
