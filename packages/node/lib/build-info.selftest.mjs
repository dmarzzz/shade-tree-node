// OPS-3: the running commit resolves from env, a detached checkout, a branch ref or packed-refs,
// and never from anything that is not 40 hex (fast lane, temp dirs only).
//   node packages/node/lib/build-info.selftest.mjs
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { resolveBuildCommit, buildCommit } from "./build-info.mjs";

const A = "a".repeat(40);
const B = "b".repeat(40);
const C = "c".repeat(40);
const repo = (files) => {
  const root = mkdtempSync(join(tmpdir(), "shade-build-info-"));
  for (const [path, body] of Object.entries(files)) {
    mkdirSync(join(root, ".git", path, ".."), { recursive: true });
    writeFileSync(join(root, ".git", path), body);
  }
  return root;
};
const roots = [];
const r = (files) => { const root = repo(files); roots.push(root); return root; };

assert.equal(resolveBuildCommit({ env: { SHADE_TREE_BUILD_COMMIT: A.toUpperCase() }, root: "/nonexistent" }), A, "env pin wins, lowercased");
assert.equal(resolveBuildCommit({ env: { SHADE_TREE_BUILD_COMMIT: "abc" }, root: r({ HEAD: B + "\n" }) }), B, "a malformed env pin is ignored");
assert.equal(resolveBuildCommit({ env: {}, root: r({ HEAD: B + "\n" }) }), B, "detached checkout");
assert.equal(resolveBuildCommit({ env: {}, root: r({ HEAD: "ref: refs/heads/main\n", "refs/heads/main": C + "\n" }) }), C, "loose branch ref");
assert.equal(resolveBuildCommit({ env: {}, root: r({ HEAD: "ref: refs/heads/main\n", "packed-refs": `# pack-refs\n${A} refs/heads/main\n` }) }), A, "packed ref");
assert.equal(resolveBuildCommit({ env: {}, root: r({ HEAD: "ref: refs/../../etc/passwd\n" }) }), "unknown", "ref traversal refused");
assert.equal(resolveBuildCommit({ env: {}, root: "/nonexistent" }), "unknown", "not a checkout");
assert.match(buildCommit(), /^([0-9a-f]{40}|unknown)$/);
for (const root of roots) rmSync(root, { recursive: true, force: true });
console.log("PASS: build commit resolution");
