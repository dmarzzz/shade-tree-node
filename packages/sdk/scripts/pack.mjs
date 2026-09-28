// Build the publishable @shadenet/sdk into packages/sdk/.pack and run `npm pack` there.
//
// In the repository the SDK's src/ imports the shared wire code in ../../lib (ADR-0010: one JS
// implementation). A published package can't reach outside itself, so this bundles:
//   dist/index.mjs    isomorphic entry, Node crypto backend
//   dist/browser.mjs  isomorphic entry, @noble crypto backend ("browser" export condition)
//   dist/node.mjs     Node entry (egress, JS client)
// with every npm dependency left external, and copies the files the Node code reads relative to
// its own location (circuits, the artifact lock, network records, the invited member list).
//
//   node packages/sdk/scripts/pack.mjs             -> writes the .tgz into packages/sdk/.pack
//   node packages/sdk/scripts/pack.mjs --dry-run   -> lists what would be published

import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
import { build } from "esbuild";

const SDK = join(dirname(fileURLToPath(import.meta.url)), "..");
const ROOT = join(SDK, "..", "..");
const OUT = join(SDK, ".pack");
const dryRun = process.argv.includes("--dry-run");

const pkg = JSON.parse(readFileSync(join(SDK, "package.json"), "utf8"));
const external = Object.keys(pkg.dependencies);

rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });

const common = { bundle: true, format: "esm", target: "es2022", legalComments: "inline", logLevel: "warning", absWorkingDir: ROOT, external };
await build({ ...common, entryPoints: [join(SDK, "src", "index.mjs")], outfile: join(OUT, "dist", "index.mjs"), platform: "node" });
await build({ ...common, entryPoints: [join(SDK, "src", "index.mjs")], outfile: join(OUT, "dist", "browser.mjs"), platform: "browser", external: [...external, "node:*"] });
await build({ ...common, entryPoints: [join(SDK, "src", "node.mjs")], outfile: join(OUT, "dist", "node.mjs"), platform: "node" });

const RESOURCES = [
  "circuits/rln/rln.wasm", "circuits/rln/rln_final.zkey", "circuits/rln/verification_key.json",
  "circuits/rln/withdraw.wasm", "circuits/rln/withdraw_final.zkey", "circuits/rln/withdraw_verification_key.json",
  "circuits/rln/ARTIFACTS.md", "testdata/zk-artifacts.lock.json", "group/members.json", "network", "LICENSE",
];
for (const rel of RESOURCES) cpSync(join(ROOT, rel), join(OUT, rel), { recursive: true, filter: (src) => !/\.md$/.test(src) || src.endsWith("ARTIFACTS.md") });
cpSync(join(SDK, "README.md"), join(OUT, "README.md"));

const published = {
  ...pkg,
  exports: {
    ".": { browser: "./dist/browser.mjs", default: "./dist/index.mjs" },
    "./node": "./dist/node.mjs",
    "./package.json": "./package.json",
  },
  files: ["dist", "circuits", "testdata", "group", "network", "README.md", "LICENSE"],
  publishConfig: { access: "public" },
};
for (const key of ["scripts", "//exports"]) delete published[key];
writeFileSync(join(OUT, "package.json"), `${JSON.stringify(published, null, 2)}\n`);

const args = ["pack", "--json", ...(dryRun ? ["--dry-run"] : [])];
const [result] = JSON.parse(execFileSync("npm", args, { cwd: OUT, encoding: "utf8" }));
console.log(`${result.name}@${result.version}: ${result.entryCount} files, ${(result.size / 1024).toFixed(0)} KiB packed, ${(result.unpackedSize / 1024).toFixed(0)} KiB unpacked${dryRun ? " (dry run)" : ` -> ${join(OUT, result.filename)}`}`);
