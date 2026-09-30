// The public role names are proxy, node, and Elder. Older command names remain exact routers to
// the same implementation and config role.

import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

let failures = 0;
const ok = (condition, message) => {
  if (condition) console.log(`  ok   ${message}`);
  else { console.log(`  FAIL ${message}`); failures++; }
};

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const CLI = join(ROOT, "packages", "node", "bin", "shade-tree.mjs");
const cleanEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("SHADE_TREE_")));

function run(command, ...args) {
  return spawnSync(process.execPath, [CLI, command, ...args], {
    cwd: ROOT,
    env: cleanEnv,
    encoding: "utf8",
  });
}

const groups = [
  { publicName: "proxy", oldNames: ["client", "shim"], role: "client", invalidArgs: ["--secret", "not-a-field"] },
  { publicName: "node", oldNames: ["gateway"], role: "gateway", invalidArgs: ["--admit", "unknown"] },
  { publicName: "elder", oldNames: ["bootnode"], role: "bootnode", invalidArgs: ["--port", "nope"] },
];

console.log("command help:");
for (const group of groups) {
  for (const command of [group.publicName, ...group.oldNames]) {
    const result = run(command, "--help");
    ok(result.status === 0 && result.stdout.startsWith(`shade-tree ${command}:`), `${command} is a recognized command`);
  }
}

console.log("\nconfig role mapping:");
for (const group of groups) {
  for (const command of [group.publicName, ...group.oldNames]) {
    const result = run(command, ...group.invalidArgs);
    const output = result.stdout + result.stderr;
    ok(result.status !== 0 && output.includes(`config invalid for role "${group.role}"`), `${command} validates as the ${group.role} implementation`);
  }
}

const top = run("help");
ok(top.status === 0 && /\n  proxy\s/.test(top.stdout) && /\n  node\s/.test(top.stdout) && /\n  elder\s/.test(top.stdout), "top-level help leads with all three public roles");
ok(/legacy alias for `proxy`/.test(top.stdout) && /legacy alias for `node`/.test(top.stdout) && /legacy alias for `elder`/.test(top.stdout), "top-level help keeps the old names visible");

console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: role aliases selftest (${failures} failure${failures === 1 ? "" : "s"})`);
process.exit(failures === 0 ? 0 : 1);
