import assert from "node:assert/strict";
import { mkdtempSync, realpathSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, parse, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalFuturePath, validateOutputPath } from "./build-inputs.mjs";

// Exercise the output boundary without invoking a compiler, download, or setup.
const repo = realpathSync(resolve(dirname(fileURLToPath(import.meta.url)), "../.."));
const scratch = mkdtempSync(join(tmpdir(), "shade-tree-build-guards-"));
try {
  for (const path of [repo, join(repo, "circuits"), dirname(repo)]) {
    assert.throws(() => validateOutputPath(path), /outside, and not an ancestor/);
  }
  assert.throws(() => validateOutputPath(parse(repo).root), /filesystem root/);

  const alias = join(scratch, "project-alias");
  symlinkSync(repo, alias, process.platform === "win32" ? "junction" : "dir");
  for (const path of [alias, join(alias, "not-yet-created", "build")]) {
    assert.throws(() => validateOutputPath(path), /outside, and not an ancestor/);
  }

  const canonicalScratch = realpathSync(scratch);
  assert.equal(validateOutputPath(scratch), canonicalScratch);
  const futureBuild = join(scratch, "not-yet-created", "build");
  assert.equal(validateOutputPath(futureBuild), join(canonicalScratch, "not-yet-created", "build"));
  assert.equal(canonicalFuturePath(futureBuild), join(canonicalScratch, "not-yet-created", "build"));
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
console.log("build-inputs output guards: ok");
