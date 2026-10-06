#!/usr/bin/env node

// Fail closed before a tag can fan out into release builds. This keeps the
// release workflow's policy in a locally testable script instead of duplicating
// fragile manifest/changelog parsing in YAML.

import { execFileSync } from "node:child_process";
import {
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function fail(message) {
  throw new Error(message);
}

function cargoManifests(dir, found = []) {
  for (const entry of readdirSync(dir)) {
    if (entry === "target" || entry === ".git") continue;
    const path = join(dir, entry);
    const stat = statSync(path);
    if (stat.isDirectory()) cargoManifests(path, found);
    else if (entry === "Cargo.toml") found.push(path);
  }
  return found.sort();
}

function cargoPackageVersion(contents, path) {
  const packageBlock = contents.match(/(?:^|\n)\[package\][ \t]*\n([\s\S]*?)(?=\n\[[^\n]+\]|$)/);
  if (!packageBlock) return null; // The Cargo.toml workspace root is not a crate.
  const version = packageBlock[1].match(/^[ \t]*version[ \t]*=[ \t]*"([^"]+)"[ \t]*$/m);
  if (!version) fail(`${path}: [package] must declare an explicit string version`);
  return version[1];
}

export function validateVersions(root, tag) {
  const match = /^v(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$/.exec(tag);
  if (!match) fail(`release tag must be exactly v<semver>; got ${JSON.stringify(tag)}`);
  const tagVersion = match[1];

  const packageJson = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  if (packageJson.version !== tagVersion) {
    fail(`tag ${tag} does not match package.json version ${JSON.stringify(packageJson.version)}`);
  }
  // A lockfile that lags package.json is rewritten by `npm install` on every host, and the
  // deploy role's git checkout (force=no) then refuses the next roll ("Local modifications").
  const lock = JSON.parse(readFileSync(join(root, "package-lock.json"), "utf8"));
  for (const [where, version] of [["package-lock.json version", lock.version], ['package-lock.json packages[""].version', lock.packages?.[""]?.version]]) {
    if (version !== tagVersion) fail(`tag ${tag} does not match ${where} ${JSON.stringify(version)}; run npm install --package-lock-only`);
  }

  const crateVersions = [];
  for (const manifest of cargoManifests(join(root, "crates"))) {
    const rel = relative(root, manifest);
    const version = cargoPackageVersion(readFileSync(manifest, "utf8"), rel);
    if (version === null) continue;
    crateVersions.push([rel, version]);
  }
  if (crateVersions.length === 0) fail("no Rust crate manifests found under crates/");

  // Internal path dependencies need a version requirement to package for crates.io, and it
  // must be the release version so the published crates resolve to each other.
  const depProblems = [];
  for (const manifest of cargoManifests(join(root, "crates"))) {
    const rel = relative(root, manifest);
    for (const line of readFileSync(manifest, "utf8").split("\n")) {
      const dep = line.match(/^[ \t]*([A-Za-z0-9_-]+)[ \t]*=[ \t]*\{([^}]*\bpath[ \t]*=[^}]*)\}/);
      if (!dep) continue;
      const version = dep[2].match(/\bversion[ \t]*=[ \t]*"=?([^"]+)"/);
      if (!version) depProblems.push(`  ${rel}: path dependency ${dep[1]} has no version requirement`);
      else if (version[1] !== tagVersion) depProblems.push(`  ${rel}: path dependency ${dep[1]} requires ${version[1]}`);
    }
  }
  if (depProblems.length > 0) {
    fail(`tag ${tag} does not match every internal Rust dependency:\n${depProblems.join("\n")}`);
  }

  const mismatches = crateVersions.filter(([, version]) => version !== tagVersion);
  if (mismatches.length > 0) {
    fail(
      `tag ${tag} does not match every Rust crate:\n${mismatches
        .map(([path, version]) => `  ${path}: ${version}`)
        .join("\n")}`,
    );
  }

  return { version: tagVersion, crateVersions };
}

export function extractChangelogSection(changelog, version) {
  const escaped = version.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const heading = new RegExp(`^##[ \\t]+${escaped}(?:[ \\t]|$)`);
  const lines = changelog.split(/\r?\n/);
  const start = lines.findIndex((line) => heading.test(line));
  if (start === -1) fail(`CHANGELOG.md has no section for ${version}`);
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i += 1) {
    if (/^##[ \t]+/.test(lines[i])) {
      end = i;
      break;
    }
  }
  const section = lines.slice(start, end).join("\n").trim();
  const hasContent = lines
    .slice(start + 1, end)
    .some((line) => line.trim() && !/^\s*#{1,6}(?:\s|$)/.test(line));
  if (!hasContent) fail(`CHANGELOG.md section for ${version} has no release-note content`);
  return `${section}\n`;
}

function git(root, args) {
  try {
    return execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  } catch (error) {
    const detail = error.stderr?.trim() || error.message;
    fail(`git ${args.join(" ")} failed: ${detail}`);
  }
}

export function validateTagCommitOnMain(root, tag, commit, mainRef) {
  const tagCommit = git(root, ["rev-parse", `refs/tags/${tag}^{commit}`]);
  const requestedCommit = git(root, ["rev-parse", `${commit}^{commit}`]);
  if (tagCommit !== requestedCommit) {
    fail(`tag ${tag} resolves to ${tagCommit}, but the workflow checked out ${requestedCommit}`);
  }
  git(root, ["rev-parse", "--verify", `${mainRef}^{commit}`]);
  try {
    execFileSync("git", ["merge-base", "--is-ancestor", tagCommit, mainRef], {
      cwd: root,
      stdio: "ignore",
    });
  } catch {
    fail(`tagged commit ${tagCommit} is not contained in ${mainRef}`);
  }
  return tagCommit;
}

function parseArgs(argv) {
  const values = { root: SCRIPT_ROOT, commit: "HEAD", mainRef: "origin/main" };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const key = {
      "--tag": "tag",
      "--commit": "commit",
      "--main-ref": "mainRef",
      "--notes-output": "notesOutput",
      "--root": "root",
    }[arg];
    if (!key || i + 1 >= argv.length) fail(`unknown or incomplete argument: ${arg}`);
    values[key] = argv[++i];
  }
  if (!values.tag) fail("--tag is required");
  values.root = resolve(values.root);
  return values;
}

export function main(argv = process.argv.slice(2)) {
  const args = parseArgs(argv);
  const { version, crateVersions } = validateVersions(args.root, args.tag);
  const tagCommit = validateTagCommitOnMain(args.root, args.tag, args.commit, args.mainRef);
  const notes = extractChangelogSection(
    readFileSync(join(args.root, "CHANGELOG.md"), "utf8"),
    version,
  );
  if (args.notesOutput) {
    const output = resolve(args.root, args.notesOutput);
    mkdirSync(dirname(output), { recursive: true });
    writeFileSync(output, notes, { encoding: "utf8", mode: 0o644 });
  }
  console.log(
    `release gate passed: ${args.tag} -> ${tagCommit} (${crateVersions.length} Rust crates, package.json, CHANGELOG.md)`,
  );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    console.error(`release gate failed: ${error.message}`);
    process.exitCode = 1;
  }
}
