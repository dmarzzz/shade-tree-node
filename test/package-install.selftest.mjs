// The website advertises a Git install, so exercise the artifact npm actually installs.
// This catches missing `files` entries and dependency-layout assumptions that a checkout hides.

import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const work = await mkdtemp(join(tmpdir(), "shade-tree-package-"));
const prefix = join(work, "prefix");
const hsDir = join(work, "operator-hs");

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd || ROOT,
    env: { ...process.env, ...(options.env || {}) },
    encoding: "utf8",
    timeout: options.timeout || 120_000,
  });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, `${command} ${args.join(" ")} failed:\n${result.stdout}\n${result.stderr}`);
  return result;
}

try {
  const packed = JSON.parse(run("npm", ["pack", "--pack-destination", work, "--json"]).stdout);
  const tarball = join(work, packed[0].filename);
  run("npm", ["install", "--global", "--prefix", prefix, tarball]);

  const npmRoot = run("npm", ["root", "--global", "--prefix", prefix]).stdout.trim();
  const installed = join(npmRoot, "shade-tree-node");
  for (const path of [
    "assets/shade-tree-readme-banner.webp",
    "packages/node/bin/shade-tree.mjs",
    "packages/node/bootnode/fetch.mjs",
    "packages/node/client/shim.mjs",
    "packages/node/gateway/gateway.mjs",
    "group/join.mjs",
    "scripts/doctor.mjs",
    "specs/README.md",
    "specs/protocol.md",
    "specs/data-api.md",
    "specs/data-api.openapi.yaml",
    "docs/PROTOCOL.md",
    "docs/PUBLIC-GROVE.md",
  ]) assert.ok(existsSync(join(installed, path)), `packed install is missing ${path}`);

  const imports = [
    "packages/node/lib/rln.mjs",
    "packages/node/client/selection.mjs",
    "packages/node/client/shim.mjs",
    "packages/node/gateway/gateway.mjs",
    "packages/node/bootnode/server.mjs",
  ].map((path) => pathToFileURL(join(installed, path)).href);
  run(process.execPath, ["--input-type=module", "-e", `await Promise.all(${JSON.stringify(imports)}.map((url) => import(url)))`], { cwd: work });

  const cli = join(prefix, "bin", "shade-tree-node");
  const joined = run(cli, ["join", "node", hsDir], { cwd: work });
  assert.match(joined.stdout, /joining as a SHADE TREE NODE operator/);
  assert.match(joined.stdout, /SAFETY: disposable research only/);
  assert.match(joined.stdout, /private-target guard is closed/);
  assert.doesNotMatch(joined.stdout, /issue #73/);
  assert.match(joined.stdout, /issue #6/);
  assert.match(joined.stdout, /untrusted development Groth16 artifacts/);
  assert.match(joined.stdout, /shade-tree-node node/);
  assert.ok(existsSync(join(hsDir, "hostname")), "installed CLI did not mint the node onion identity");
  assert.ok(existsSync(join(hsDir, "identity.local.json")), "installed CLI did not write the node announcement identity");

  const identity = JSON.parse(await readFile(join(hsDir, "identity.local.json"), "utf8"));
  assert.ok(identity.seed && !joined.stdout.includes(identity.seed), "installed onboarding printed the announcement seed");
  console.log("PASS: packaged Git install loads agent and operator runtimes");
} finally {
  await rm(work, { recursive: true, force: true });
}
