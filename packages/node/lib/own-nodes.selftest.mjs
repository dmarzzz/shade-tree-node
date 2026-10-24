// Selftest for own-node exclusion (roadmap #369 M0, packages/node/lib/own-nodes.mjs): where the
// client learns its own nodes (env, the avoid-nodes file, SHADENET_STATE) and how `shadenet-node
// run` registers itself. The rule's normalization and filter are pinned cross-client in
// testdata/vectors.json `ownNodes` (test/vectors.selftest.mjs). No network.
//
//   node packages/node/lib/own-nodes.selftest.mjs

import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pubkeyToOnion } from "./directory.mjs";
import { loadOwnNodes, registerOwnNode, avoidNodesPath, configDir, excludeOwnNodes, normalizeOwnNode } from "./own-nodes.mjs";

const A = pubkeyToOnion("33".repeat(32));
const B = pubkeyToOnion("44".repeat(32));
const C = pubkeyToOnion("55".repeat(32));
const work = mkdtempSync(join(tmpdir(), "shadenet-own-nodes-"));
let passed = 0;
const test = (name, fn) => { fn(); passed++; console.log(`  ok   ${name}`); };

try {
  test("config dir: XDG_CONFIG_HOME wins, then ~/.config; Windows uses APPDATA only", () => {
    assert.equal(configDir({ XDG_CONFIG_HOME: "/x", HOME: "/h" }, "linux"), join("/x", "shadenet"));
    assert.equal(configDir({ HOME: "/h" }, "darwin"), join("/h", ".config", "shadenet"));
    assert.equal(configDir({ APPDATA: "C:/a", HOME: "/h" }, "win32"), join("C:/a", "shadenet"));
    assert.equal(configDir({ HOME: "/h" }, "win32"), null);
    assert.equal(avoidNodesPath({}, "linux"), null);
  });

  test("no sources: an empty set, and the rule returns the same array reference", () => {
    const found = loadOwnNodes({ env: { XDG_CONFIG_HOME: join(work, "empty") } });
    assert.equal(found.nodes.size, 0);
    const gws = [{ onion: A }];
    assert.equal(excludeOwnNodes(gws, found.nodes).gateways, gws);
  });

  test("all three sources are merged: env, the avoid-nodes file, and $SHADENET_STATE/hs-gateway/hostname", () => {
    const cfg = join(work, "cfg");
    mkdirSync(join(cfg, "shadenet"), { recursive: true });
    writeFileSync(join(cfg, "shadenet", "avoid-nodes"), `# home connection\n${B}\n`);
    const state = join(work, "state");
    mkdirSync(join(state, "hs-gateway"), { recursive: true });
    writeFileSync(join(state, "hs-gateway", "hostname"), `${C}\n`);
    const found = loadOwnNodes({ env: { XDG_CONFIG_HOME: cfg, SHADENET_AVOID_NODES: A.toUpperCase(), SHADENET_STATE: state } });
    assert.deepEqual([...found.nodes].sort(), [A, B, C].sort());
    assert.deepEqual(found.sources.map((s) => s.count), [1, 1, 1]);
  });

  test("the legacy SHADE_TREE_AVOID_NODES name is read when SHADENET_AVOID_NODES is unset", () => {
    const found = loadOwnNodes({ env: { XDG_CONFIG_HOME: join(work, "empty"), SHADE_TREE_AVOID_NODES: `${A},${B}` } });
    assert.deepEqual([...found.nodes], [A, B]);
  });

  test("unreadable sources are skipped, junk is reported, nothing throws", () => {
    const found = loadOwnNodes({ env: { HOME: join(work, "nohome"), SHADENET_STATE: join(work, "nostate"), SHADENET_AVOID_NODES: "junk, also-junk" }, platform: "linux" });
    assert.equal(found.nodes.size, 0);
    assert.deepEqual(found.junk, ["junk", "also-junk"]);
  });

  test("registerOwnNode appends once (0600 file), keeps hand-written entries, and is then read back", () => {
    const env = { XDG_CONFIG_HOME: join(work, "reg") };
    const file = avoidNodesPath(env, "linux");
    mkdirSync(join(work, "reg", "shadenet"), { recursive: true });
    writeFileSync(file, `${B}`); // hand-written, no trailing newline
    const first = registerOwnNode(A.replace(/\.onion$/, ""), { env, platform: "linux", now: () => new Date("2026-10-24T00:00:00Z") });
    assert.equal(first.added, true);
    assert.equal(registerOwnNode(A.toUpperCase(), { env, platform: "linux" }).added, false, "idempotent");
    const text = readFileSync(file, "utf8");
    assert.match(text, /^.+\n# added by shadenet-node run, 2026-10-24\n.+\n$/);
    assert.deepEqual([...loadOwnNodes({ env, platform: "linux" }).nodes], [B, A]);
    if (process.platform !== "win32") {
      const fresh = { XDG_CONFIG_HOME: join(work, "reg2") };
      registerOwnNode(A, { env: fresh, platform: "linux" });
      assert.equal(statSync(avoidNodesPath(fresh, "linux")).mode & 0o777, 0o600);
    }
  });

  test("registerOwnNode refuses junk and a missing config dir without writing", () => {
    assert.equal(registerOwnNode("not-an-onion", { env: { XDG_CONFIG_HOME: join(work, "junk") } }).added, false);
    assert.equal(registerOwnNode(A, { env: {}, platform: "linux" }).added, false);
  });

  test("the rule accepts bare-string entries and keeps entries whose onion does not parse", () => {
    const own = new Set([normalizeOwnNode(A)]);
    const r = excludeOwnNodes([A.replace(/\.onion$/, ""), "garbage", { onion: B }], own);
    assert.deepEqual(r.gateways, ["garbage", { onion: B }]);
    assert.deepEqual(r.excluded, [A]);
  });
} finally {
  rmSync(work, { recursive: true, force: true });
}
console.log(`\nPASS: own-nodes selftest (${passed} checks)`);
