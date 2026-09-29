import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const ROOT = join(fileURLToPath(new URL("..", import.meta.url)));
const SCRIPT = join(ROOT, "scripts/release-check.mjs");
const fixture = mkdtempSync(join(tmpdir(), "shade-tree-release-check-"));
const workflow = readFileSync(join(ROOT, ".github/workflows/release.yml"), "utf8");

assert.match(workflow, /fetch-depth: 0/, "release ancestry check receives full git history");
assert.match(workflow, /node scripts\/release-check\.mjs/, "tag workflow runs the locally tested release gate");
assert.match(workflow, /prerelease: \$\{\{ contains\(needs\.set-version\.outputs\.version, '-'\) \}\}/, "hyphenated versions publish as prereleases");
assert.match(workflow, /make_latest: \$\{\{ !contains/, "a prerelease never becomes Latest");
assert.match(workflow, /\*-\* \]\] \|\| echo "-t \$image:latest"/, "a prerelease image gets no :latest");
assert.match(workflow, /HOMEBREW_TAP_TOKEN unset/, "the tap update is a notice without its secret");
assert.match(workflow, /needs: \[set-version, default, live\]/, "publication waits for metadata and every binary build");
assert.match(workflow, /body_path: release-metadata\/release-notes\.md/, "publication uses validated changelog notes");
assert.match(workflow, /Revalidate the remote tag before publication/, "publication rechecks the mutable remote tag");
assert.match(workflow, /object_sha.*RELEASE_COMMIT/, "publication compares the peeled tag with the event commit");
assert.match(
  workflow,
  /Download packaged artifacts[\s\S]*Revalidate the remote tag before publication[\s\S]*Attach to Release/,
  "the mutable tag is rechecked after downloads and immediately before release mutation",
);

function write(path, contents) {
  const absolute = join(fixture, path);
  mkdirSync(join(absolute, ".."), { recursive: true });
  writeFileSync(absolute, contents);
}

function git(...args) {
  return execFileSync("git", args, { cwd: fixture, encoding: "utf8" }).trim();
}

function run(...args) {
  return spawnSync(process.execPath, [SCRIPT, "--root", fixture, ...args], {
    cwd: fixture,
    encoding: "utf8",
  });
}

write("package.json", '{"name":"fixture","version":"1.2.3"}\n');
write("Cargo.toml", '[workspace]\nmembers = ["one", "nested/two"]\n');
write("crates/one/Cargo.toml", '[package]\nname = "one"\nversion = "1.2.3"\n');
write("crates/nested/two/Cargo.toml", '[package]\nname = "two"\nversion = "1.2.3"\n');
write(
  "CHANGELOG.md",
  "# Changelog\n\n## 1.2.3 — Fixture\n\nResearch preview.\n\n### Added\n\n- A release gate.\n\n## 1.2.2\n\n- Earlier.\n",
);
git("init", "-b", "main");
git("config", "user.name", "Release Test");
git("config", "user.email", "release@example.invalid");
git("add", ".");
git("commit", "-m", "release");
git("tag", "v1.2.3");

const good = run(
  "--tag", "v1.2.3",
  "--commit", "HEAD",
  "--main-ref", "main",
  "--notes-output", "generated/release-notes.md",
);
assert.equal(good.status, 0, good.stderr);
assert.match(good.stdout, /2 Rust crates, package\.json, CHANGELOG\.md/);
assert.equal(
  readFileSync(join(fixture, "generated/release-notes.md"), "utf8"),
  "## 1.2.3 — Fixture\n\nResearch preview.\n\n### Added\n\n- A release gate.\n",
  "release notes are exactly the matching changelog section",
);

write("CHANGELOG.md", "# Changelog\n\n## 1.2.3 — Fixture\n\n### Added\n\n## 1.2.2\n\n- Earlier.\n");
const emptyNotes = run("--tag", "v1.2.3", "--commit", "HEAD", "--main-ref", "main");
assert.notEqual(emptyNotes.status, 0);
assert.match(emptyNotes.stderr, /section for 1\.2\.3 has no release-note content/);
write(
  "CHANGELOG.md",
  "# Changelog\n\n## 1.2.3 — Fixture\n\nResearch preview.\n\n### Added\n\n- A release gate.\n\n## 1.2.2\n\n- Earlier.\n",
);

const wrongTag = run("--tag", "v1.2.4", "--main-ref", "main");
assert.notEqual(wrongTag.status, 0);
assert.match(wrongTag.stderr, /does not match package\.json version/);

write("crates/nested/two/Cargo.toml", '[package]\nname = "two"\nversion = "1.2.2"\n');
const wrongCrate = run("--tag", "v1.2.3", "--main-ref", "main");
assert.notEqual(wrongCrate.status, 0);
assert.match(wrongCrate.stderr, /crates\/nested\/two\/Cargo\.toml: 1\.2\.2/);
write("crates/nested/two/Cargo.toml", '[package]\nname = "two"\nversion = "1.2.3"\n');

git("switch", "--detach");
write("off-main.txt", "not releasable\n");
git("add", "off-main.txt");
git("commit", "-m", "off main");
git("tag", "-f", "v1.2.3");
const offMain = run("--tag", "v1.2.3", "--commit", "HEAD", "--main-ref", "main");
assert.notEqual(offMain.status, 0);
assert.match(offMain.stderr, /is not contained in main/);

rmSync(fixture, { recursive: true, force: true });
console.log("release-check selftest passed");
