#!/usr/bin/env node
// Registry publish rehearsal (RUST-13). Nothing is uploaded.
//
//   node scripts/release/publish-dry-run.mjs
//
// Every workspace crate and npm workspace package is listed with its status. A crate or
// package that opts into publishing (Cargo `publish` not false; npm `private` not true)
// must pass `cargo publish --dry-run` / `npm publish --dry-run`, or this exits nonzero.
// Ones that haven't opted in are reported, never failed, so the gate tightens as each
// crate is made publishable.
import { spawnSync } from "node:child_process";
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dirname, "..", "..");
const rows = [];
let failed = 0;

function run(cmd, args) {
  const r = spawnSync(cmd, args, { cwd: ROOT, encoding: "utf8", maxBuffer: 64 << 20 });
  return { ok: r.status === 0, out: `${r.stdout}${r.stderr}` };
}

function lastError(out) {
  // Prefer the root cause cargo prints under "Caused by:", else the first error line.
  const lines = out.split("\n");
  const cause = lines.findIndex((l) => l.startsWith("Caused by:"));
  const picked = cause >= 0
    ? lines.slice(cause + 1).filter((l) => l.trim()).slice(0, 2)
    : lines.filter((l) => l.startsWith("error")).slice(0, 1);
  return picked.join(" ").replace(/\s+/g, " ").replaceAll("|", "/").trim().slice(0, 200);
}

// Cargo: `cargo metadata` gives members, their publish setting and path dependencies.
const meta = JSON.parse(run("cargo", ["metadata", "--no-deps", "--format-version", "1", "--locked"]).out);
for (const pkg of meta.packages) {
  const publishable = !(Array.isArray(pkg.publish) && pkg.publish.length === 0);
  if (!publishable) {
    const probe = run("cargo", ["package", "-p", pkg.name, "--locked", "--allow-dirty", "--no-verify"]);
    rows.push([`crate ${pkg.name}`, "publish = false", probe.ok ? "packages" : `would fail: ${lastError(probe.out)}`]);
    continue;
  }
  const r = run("cargo", ["publish", "-p", pkg.name, "--dry-run", "--locked"]);
  rows.push([`crate ${pkg.name}`, "publishable", r.ok ? "dry-run ok" : `FAIL: ${lastError(r.out)}`]);
  if (!r.ok) failed++;
}

// npm workspaces (root package.json `workspaces`), when present.
const rootPkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
for (const ws of rootPkg.workspaces ?? []) {
  const manifest = join(ROOT, ws, "package.json");
  if (!existsSync(manifest)) continue;
  const pkg = JSON.parse(readFileSync(manifest, "utf8"));
  if (pkg.private) {
    rows.push([`npm ${pkg.name}`, "private", "not published"]);
    continue;
  }
  const r = run("npm", ["publish", "--dry-run", "--workspace", ws]);
  rows.push([`npm ${pkg.name}`, "publishable", r.ok ? "dry-run ok" : `FAIL: ${lastError(r.out)}`]);
  if (!r.ok) failed++;
}

const table = ["| Package | Status | Result |", "|---|---|---|", ...rows.map((r) => `| ${r.join(" | ")} |`)].join("\n");
console.log(table);
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `## Publish dry-run\n\n${table}\n`);
if (failed) {
  console.error(`\n${failed} publishable package(s) failed the dry run`);
  process.exit(1);
}
