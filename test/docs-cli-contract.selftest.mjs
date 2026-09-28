// Static contract for the copyable public instructions. These checks intentionally target the
// current guides, not dated integration reports: historical receipts may quote old commands, while
// a guide must never teach those commands again.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const PUBLIC_GUIDES = [
  "README.md",
  "docs/AGENT.md",
  "docs/CLI.md",
  "docs/CLIENTS.md",
  "docs/CONFIG.md",
  "docs/history/DEPLOY.md",
  "docs/JOIN.md",
  "docs/OPERATOR.md",
  "docs/OVERVIEW.md",
  "docs/QUICKSTART.md",
  "network/README.md",
  "network/sepolia/README.md",
  "crates/INSTALL.md",
];

const docs = new Map(await Promise.all(PUBLIC_GUIDES.map(async (path) => [
  path,
  await readFile(join(ROOT, path), "utf8"),
])));

function shellFences(markdown) {
  return [...markdown.matchAll(/```(?:ba)?sh\s*\n([\s\S]*?)```/g)].map((match) => match[1]).join("\n");
}

for (const [path, markdown] of docs) {
  const shell = shellFences(markdown);
  assert.doesNotMatch(shell, /--secret(?:=|\s+)(?:0x|<)/, `${path}: bearer secrets must not appear in argv examples`);
  assert.doesNotMatch(shell, /--(?:register|operator)-key(?:=|\s+)/, `${path}: operator keys must not appear in argv examples`);
  assert.doesNotMatch(
    shell,
    /(?:export\s+)?SHADE_TREE_(?:SECRET|REGISTER_KEY|GW_OPERATOR_KEY|SLASH_KEY)=(?:0x|<)/,
    `${path}: secret values must not be typed into shell history`,
  );
}

for (const path of ["docs/QUICKSTART.md", "docs/JOIN.md", "docs/CLI.md"]) {
  const markdown = docs.get(path);
  for (const match of markdown.matchAll(/shade-tree register-member[^\n]*(?:\\\n[^\n]*){0,3}/g)) {
    if (!/--rpc-url/.test(match[0])) continue; // loopback/default examples need no explicit key
    const prefix = markdown.slice(Math.max(0, match.index - 220), match.index);
    assert.match(prefix, /SHADE_TREE_REGISTER_KEY="\$SHADE_TREE_REGISTER_KEY"/, `${path}: remote register-member must receive a hidden, process-scoped key`);
  }
}

const pkg = JSON.parse(await readFile(join(ROOT, "package.json"), "utf8"));
const overview = docs.get("docs/OVERVIEW.md");
assert.match(overview, new RegExp(`shade-tree-${pkg.version.replaceAll(".", "\\.")}-<target>-live`), "OVERVIEW uses the current Rust release asset name");
assert.doesNotMatch(overview, /shade-tree-0\.1\.1-/, "OVERVIEW contains no stale v0.1.1 asset name");

for (const path of ["docs/OVERVIEW.md", "crates/INSTALL.md"]) {
  const identityCommands = docs
    .get(path)
    .split("\n")
    .filter((line) => /shade-tree(?:-[^\s]+)?\s+(?:enroll|identity)\b/.test(line));
  assert.ok(identityCommands.length > 0, `${path}: expected a Rust identity-generation command`);
  assert.ok(identityCommands.every((line) => /--limit/.test(line)), `${path}: every Rust identity command must carry the exact enrolled tier`);
}

const quickstart = docs.get("docs/QUICKSTART.md");
assert.match(quickstart, /--HiddenServiceDir \.\/tor\/hs-bootnode[\s\S]*--HiddenServicePort "80 127\.0\.0\.1:8877"/, "local loop publishes the Elder Tree onion");
assert.match(quickstart, /--HiddenServiceDir \.\/tor\/hs-gateway[\s\S]*--HiddenServicePort "80 127\.0\.0\.1:8443"/, "local loop publishes the node onion");
assert.match(quickstart, /checked-in `tor\/torrc`[\s\S]{0,180}single-node config/, "local loop distinguishes its two-service Tor command from the checked-in single-node torrc");

const clients = docs.get("docs/CLIENTS.md");
assert.match(clients, /`shade-tree proxy` command fails before startup[^.]*without\s+its pinned signer/, "CLIENTS documents routed signer validation as fail-fast");

const config = docs.get("docs/CONFIG.md");
for (const name of [
  "SHADE_TREE_SOCKS_ISOLATION",
  "SHADE_TREE_PAY_HTTP_TIMEOUT_MS",
  "SHADE_TREE_PROXY_URL",
  "SHADE_TREE_NO_PROXY",
  "SHADE_TREE_PROXY_CHECK_TIMEOUT_MS",
]) assert.match(config, new RegExp(`\\b${name}\\b`), `CONFIG documents ${name}`);

console.log("PASS: public CLI/install docs preserve safe, tiered, copyable commands");
