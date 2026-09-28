// OPS-12: role secrets load from $CREDENTIALS_DIRECTORY; explicit env wins; bounded and fail-loud.
//   node lib/credentials.selftest.mjs
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadCredentials, SECRET_CREDENTIALS } from "./credentials.mjs";

const dir = mkdtempSync(join(tmpdir(), "shade-creds-"));
try {
  writeFileSync(join(dir, "SHADE_TREE_SLASH_KEY"), "0x" + "11".repeat(32) + "\n");
  writeFileSync(join(dir, "SHADE_TREE_GW_OPERATOR_KEY"), "0x" + "22".repeat(32));
  const env = { CREDENTIALS_DIRECTORY: dir, SHADE_TREE_GW_OPERATOR_KEY: "explicit" };
  assert.deepEqual(loadCredentials(SECRET_CREDENTIALS, { env }), ["SHADE_TREE_SLASH_KEY"]);
  assert.equal(env.SHADE_TREE_SLASH_KEY, "0x" + "11".repeat(32), "file value, trimmed");
  assert.equal(env.SHADE_TREE_GW_OPERATOR_KEY, "explicit", "an explicit env var wins");
  assert.deepEqual(loadCredentials(SECRET_CREDENTIALS, { env: {} }), [], "no CREDENTIALS_DIRECTORY -> nothing");
  assert.deepEqual(loadCredentials(["../../etc/passwd", "PATH"], { env: { CREDENTIALS_DIRECTORY: dir } }), [], "only SHADE_TREE_* names");
  writeFileSync(join(dir, "SHADE_TREE_REGISTRAR_KEY"), "");
  assert.throws(() => loadCredentials(["SHADE_TREE_REGISTRAR_KEY"], { env: { CREDENTIALS_DIRECTORY: dir } }), /empty or larger/);
  writeFileSync(join(dir, "SHADE_TREE_FLEET_TALLY_TOKEN"), "x".repeat(5000));
  assert.throws(() => loadCredentials(["SHADE_TREE_FLEET_TALLY_TOKEN"], { env: { CREDENTIALS_DIRECTORY: dir } }), /empty or larger/);
} finally {
  rmSync(dir, { recursive: true, force: true });
}
console.log("PASS: systemd credentials load role secrets");
