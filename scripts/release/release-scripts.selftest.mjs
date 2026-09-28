// Release packaging scripts (fast lane, no network): package.sh names and hashes both the
// shadenet and shade-tree assets and falls back to one binary before the rename lands;
// homebrew-formula.mjs renders a formula only from well-formed .sha256 files and rejects
// bad versions, repos and tampered checksum files.
//
//   node scripts/release/release-scripts.selftest.mjs
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const HERE = import.meta.dirname;
let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };
const sha = (buf) => createHash("sha256").update(buf).digest("hex");

const work = mkdtempSync(join(tmpdir(), "shadenet-release-"));
try {
  const pkg = (target, suffix) => spawnSync("bash", [join(HERE, "package.sh"), target, "0.7.0", suffix], {
    cwd: work, encoding: "utf8", env: { ...process.env, GITHUB_OUTPUT: join(work, `out-${target}`) },
  });

  // Before the rename: only shade-tree exists; both asset names carry its bytes.
  mkdirSync(join(work, "target/aarch64-apple-darwin/release"), { recursive: true });
  writeFileSync(join(work, "target/aarch64-apple-darwin/release/shade-tree"), "old-binary");
  let r = pkg("aarch64-apple-darwin", "-live");
  ok(r.status === 0, "package.sh succeeds with only the shade-tree binary");
  const a = readFileSync(join(work, "dist/shadenet-0.7.0-aarch64-apple-darwin-live"), "utf8");
  const b = readFileSync(join(work, "dist/shade-tree-0.7.0-aarch64-apple-darwin-live"), "utf8");
  ok(a === "old-binary" && b === "old-binary", "fallback ships the same bytes under both names");
  const line = readFileSync(join(work, "dist/shadenet-0.7.0-aarch64-apple-darwin-live.sha256"), "utf8");
  ok(line === `${sha("old-binary")}  shadenet-0.7.0-aarch64-apple-darwin-live\n`, ".sha256 is '<hex>  <file>'");
  const out = readFileSync(join(work, "out-aarch64-apple-darwin"), "utf8");
  ok(/^artifacts<<PATHS\ndist\/shadenet-[^\n]+\ndist\/shade-tree-[^\n]+\nPATHS$/m.test(out), "GITHUB_OUTPUT lists both artifacts");

  // After the rename: each asset comes from its own binary.
  mkdirSync(join(work, "target/x86_64-unknown-linux-musl/release"), { recursive: true });
  writeFileSync(join(work, "target/x86_64-unknown-linux-musl/release/shade-tree"), "alias");
  writeFileSync(join(work, "target/x86_64-unknown-linux-musl/release/shadenet"), "primary");
  r = pkg("x86_64-unknown-linux-musl", "-live");
  ok(r.status === 0
    && readFileSync(join(work, "dist/shadenet-0.7.0-x86_64-unknown-linux-musl-live"), "utf8") === "primary"
    && readFileSync(join(work, "dist/shade-tree-0.7.0-x86_64-unknown-linux-musl-live"), "utf8") === "alias",
  "each asset comes from the binary of the same name");

  // No binary at all fails loudly.
  r = pkg("aarch64-unknown-linux-gnu", "");
  ok(r.status !== 0 && /no CLI binary/.test(r.stderr), "package.sh fails with no binary");

  // Formula.
  const formula = (...args) => spawnSync(process.execPath, [join(HERE, "homebrew-formula.mjs"), ...args], { cwd: work, encoding: "utf8" });
  r = formula("--version", "0.7.0", "--repo", "dmarzzz/shade-tree-node");
  const rb = r.status === 0 ? readFileSync(join(work, "dist/shadenet.rb"), "utf8") : "";
  ok(rb.includes(`sha256 "${sha("old-binary")}"`) && rb.includes(`sha256 "${sha("primary")}"`), "formula carries both platform hashes");
  ok(/on_macos do\n    on_arm do/.test(rb) && /on_linux do\n    on_intel do/.test(rb) && !/on_macos do[\s\S]*on_intel do[\s\S]*on_linux/.test(rb), "only packaged platforms appear");
  ok(rb.includes("releases/download/v0.7.0/shadenet-0.7.0-aarch64-apple-darwin-live"), "formula points at the release asset");
  ok(formula("--version", "0.7.0; rm -rf /", "--repo", "dmarzzz/x").status !== 0, "rejects a malformed version");
  ok(formula("--version", "0.7.0", "--repo", "evil repo").status !== 0, "rejects a malformed repo");
  writeFileSync(join(work, "dist/shadenet-0.7.0-aarch64-apple-darwin-live.sha256"), "zz  shadenet-0.7.0-aarch64-apple-darwin-live\n");
  ok(formula("--version", "0.7.0", "--repo", "dmarzzz/shade-tree-node").status !== 0, "rejects a tampered .sha256");
  ok(formula("--version", "9.9.9", "--repo", "dmarzzz/shade-tree-node").status !== 0, "fails when no live asset exists");
} finally {
  rmSync(work, { recursive: true, force: true });
}

if (failures) { console.log(`\nFAIL: ${failures} release-script check(s)`); process.exit(1); }
console.log("\nPASS: release scripts selftest");
