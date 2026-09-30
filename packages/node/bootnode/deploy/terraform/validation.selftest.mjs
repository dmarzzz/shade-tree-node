// Functional input-validation checks for the standalone droplet module. The
// fixture contains no providers or resources, so this never contacts
// DigitalOcean and does not need credentials.

import assert from "node:assert/strict";
import { copyFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const binary = ["tofu", "terraform"].find((name) =>
  spawnSync(name, ["version"], { stdio: "ignore" }).status === 0,
);

if (!binary) {
  console.log("SKIP: terraform validation selftest (tofu/terraform unavailable)");
  process.exit(0);
}

const work = mkdtempSync(join(tmpdir(), "shade-tree-tf-validation-"));
copyFileSync(join(HERE, "variables.tf"), join(work, "variables.tf"));

const validMembers = JSON.stringify({ version: 2, members: ["1"] });
const base = [
  "-input=false",
  "-lock=false",
  "-no-color",
  "-var=do_token=test-only",
  "-var=ssh_public_key=ssh-ed25519 AAAATEST",
  `-var=members_json=${validMembers}`,
];

function run(args) {
  return spawnSync(binary, args, {
    cwd: work,
    encoding: "utf8",
    timeout: 60_000,
  });
}

try {
  const init = run(["init", "-backend=false", "-input=false", "-no-color"]);
  assert.equal(init.status, 0, init.stderr || init.stdout);

  const valid = run(["plan", ...base]);
  assert.equal(valid.status, 0, valid.stderr || valid.stdout);

  const invalidCases = [
    ["numeric member", `-var=members_json=${JSON.stringify({ version: 2, members: [1] })}`, "members_json must be a v2 document"],
    ["out-of-field member", `-var=members_json=${JSON.stringify({ version: 2, members: ["21888242871839275222246405745257275088548364400416034343698204186575808495617"] })}`, "members_json must be a v2 document"],
    ["non-GitHub repository", "-var=git_repo=https://example.com/repo", "git_repo must be an HTTPS GitHub repository URL"],
    ["shell metacharacter in ref", "-var=git_ref=main;touch-bad", "git_ref must be a shell-safe branch"],
    ["privileged backend port", "-var=gateway_port=80", "gateway_port must be an integer in 1024..65535"],
  ];

  for (const [name, value, message] of invalidCases) {
    const result = run(["plan", ...base, value]);
    assert.notEqual(result.status, 0, `${name} unexpectedly planned successfully`);
    assert.match(`${result.stdout}\n${result.stderr}`, new RegExp(message.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")), name);
  }

  console.log(`PASS: terraform validation selftest (${invalidCases.length + 1} plans)`);
} finally {
  rmSync(work, { recursive: true, force: true });
}
