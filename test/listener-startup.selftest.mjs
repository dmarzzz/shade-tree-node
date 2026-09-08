// Exercise the real service entrypoints while their port is already occupied.
import assert from "node:assert/strict";
import net from "node:net";
import { once } from "node:events";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const occupied = net.createServer();
try {
  occupied.listen(0, "127.0.0.1");
  await once(occupied, "listening");
  const port = String(occupied.address().port);
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("SHADE_TREE_")));
  Object.assign(env, {
    SHADE_TREE_GATEWAY_HOST: "127.0.0.1",
    SHADE_TREE_GATEWAY_PORT: port,
    SHADE_TREE_SHIM_PORT: port,
    SHADE_TREE_MEMBERS_FILE: `${root}group/members.json`,
    SHADE_TREE_ADMIT: "invited",
    SHADE_TREE_SECRET: "111", // public test identity; no proof or external dial is made
    SHADE_TREE_LOG_FORMAT: "json",
    SHADE_TREE_LOG_LEVEL: "info",
  });
  for (const [entry, override] of [
    ["gateway/gateway.mjs", "SHADE_TREE_GATEWAY_PORT"],
    ["client/shim.mjs", "SHADE_TREE_SHIM_PORT"],
  ]) {
    const result = spawnSync(process.execPath, [entry], { cwd: root, env, encoding: "utf8", timeout: 15000 });
    assert.ifError(result.error);
    assert.equal(result.status, 1, `${entry}: exits promptly with failure`);
    assert.doesNotMatch(result.stderr, /Unhandled 'error' event|node:events|\n\s+at /, "no raw stack trace");
    const records = result.stderr.trim().split("\n").map((line) => JSON.parse(line));
    const failure = records.find((record) => record.event === "service.failed");
    assert.equal(failure?.code, "EADDRINUSE", `${entry}: precise failure code`);
    assert.match(failure.msg, new RegExp(`port ${port} is already in use`));
    assert.ok(failure.msg.includes(override), "names the port override");
    assert.doesNotMatch(result.stdout, /"event":"service.ready"/, "never advertises readiness");
  }
} finally {
  if (occupied.listening) await new Promise((resolve) => occupied.close(resolve));
}
console.log("PASS: occupied node and Proxy ports fail with actionable diagnostics");
