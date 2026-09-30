// Offline proof of `shade-tree run`: proxy variables are scoped to the child, inherited escape
// hatches are removed, argv/exit status pass through, and an unavailable local proxy prevents the
// command from starting. The TCP listener only satisfies the fail-closed preflight; no traffic is
// sent through it by these environment-inspection children.

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const CLI = join(HERE, "shade-tree.mjs");

function runCli(args, { env = {} } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, ...args], {
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.once("error", reject);
    child.once("close", (code, signal) => resolve({ code, signal, stdout, stderr, out: stdout + stderr }));
  });
}

const childProbe = String.raw`
const keys = [
  "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "WSS_PROXY", "wss_proxy",
  "NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy", "NODE_USE_ENV_PROXY",
  "SHADE_TREE_ACTIVE", "SHADE_TREE_PROXY_URL", "SHADE_TREE_NO_PROXY",
  "SHADE_TREE_SECRET", "SHADE_TREE_REGISTER_KEY", "SHADE_TREE_DIRECTORY",
  "SHADE_TREE_LOG_LEVEL", "AGENT_TOKEN",
];
console.log(JSON.stringify({ env: Object.fromEntries(keys.map((key) => [key, process.env[key] ?? null])), argv: process.argv.slice(1) }));
`;

async function main() {
  const server = createServer((socket) => socket.end());
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const port = server.address().port;
  const proxy = `http://127.0.0.1:${port}`;

  const parentHttps = process.env.HTTPS_PROXY;
  const good = await runCli([
    "run", "--proxy", proxy, "--no-proxy", "ollama.local,127.0.0.1", "--",
    process.execPath, "-e", childProbe, "child-arg",
  ], {
    env: {
      HTTPS_PROXY: "http://ambient.invalid:1",
      https_proxy: "http://ambient-lower.invalid:2",
      NO_PROXY: "*",
      no_proxy: "*",
      ALL_PROXY: "socks5://ambient.invalid:3",
      all_proxy: "socks5://ambient-lower.invalid:4",
      SHADE_TREE_SECRET: "must-not-reach-agent",
      SHADE_TREE_REGISTER_KEY: "must-not-reach-agent",
      SHADE_TREE_DIRECTORY: "/operator-only/directory.json",
      SHADE_TREE_LOG_LEVEL: "debug",
      AGENT_TOKEN: "ordinary-child-env-is-preserved",
    },
  });
  assert.equal(good.code, 0, good.out);
  const observed = JSON.parse(good.stdout.trim());
  for (const key of ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "WSS_PROXY", "wss_proxy"]) {
    assert.equal(observed.env[key], proxy, `${key} points at the checked local proxy`);
  }
  assert.equal(observed.env.ALL_PROXY, null, "inherited ALL_PROXY is removed");
  assert.equal(observed.env.all_proxy, null, "inherited all_proxy is removed");
  assert.equal(observed.env.NODE_USE_ENV_PROXY, "1");
  assert.equal(observed.env.SHADE_TREE_ACTIVE, "1");
  assert.equal(observed.env.SHADE_TREE_PROXY_URL, proxy);
  assert.equal(observed.env.NO_PROXY, "127.0.0.1,localhost,::1,host.docker.internal,ollama.local");
  assert.equal(observed.env.no_proxy, observed.env.NO_PROXY);
  assert.equal(observed.env.SHADE_TREE_NO_PROXY, observed.env.NO_PROXY);
  for (const key of ["SHADE_TREE_SECRET", "SHADE_TREE_REGISTER_KEY", "SHADE_TREE_DIRECTORY", "SHADE_TREE_LOG_LEVEL"]) {
    assert.equal(observed.env[key], null, `${key} is Proxy/operator state and is stripped from the agent child`);
  }
  assert.equal(observed.env.AGENT_TOKEN, "ordinary-child-env-is-preserved", "unrelated agent configuration remains available");
  assert.deepEqual(observed.argv, ["child-arg"], "child argv after `--` is preserved");
  assert.equal(process.env.HTTPS_PROXY, parentHttps, "the wrapper does not mutate its parent shell");

  const childExit = await runCli(["run", "--proxy", proxy, "--", process.execPath, "-e", "process.exit(23)"]);
  assert.equal(childExit.code, 23, "child exit status is propagated");

  const missingExecutable = await runCli(["run", "--proxy", proxy, "--", "shade-tree-command-that-does-not-exist"]);
  assert.equal(missingExecutable.code, 127, "a missing child executable returns the conventional status 127");
  assert.match(missingExecutable.out, /could not start child/);

  const missingCommand = await runCli(["run", "--proxy", proxy, process.execPath]);
  assert.equal(missingCommand.code, 2);
  assert.match(missingCommand.out, /missing `--`/);

  const wildcard = await runCli([
    "run", "--proxy", proxy, "--no-proxy", "*", "--",
    process.execPath, "-e", "console.log('WILDCARD_CHILD_STARTED')",
  ]);
  assert.notEqual(wildcard.code, 0);
  assert.doesNotMatch(wildcard.out, /WILDCARD_CHILD_STARTED/);
  assert.match(wildcard.out, /would bypass Shade Tree/);

  await new Promise((resolve) => server.close(resolve));
  const unavailable = await runCli([
    "run", "--proxy", proxy, "--check-timeout-ms", "250", "--",
    process.execPath, "-e", "console.log('UNAVAILABLE_CHILD_STARTED')",
  ]);
  assert.notEqual(unavailable.code, 0);
  assert.doesNotMatch(unavailable.out, /UNAVAILABLE_CHILD_STARTED/);
  assert.match(unavailable.out, /local proxy unavailable; command not started/);

  console.log("PASS: shade-tree run scopes proxy env and fails closed before spawn");
}

main().catch((error) => { console.error(error); process.exit(1); });
