// systemd credentials for role secrets (OPS-12). A unit that sets
//   LoadCredential=SHADE_TREE_SLASH_KEY:/etc/shade-tree/credentials/SHADE_TREE_SLASH_KEY
// gets the file in $CREDENTIALS_DIRECTORY, readable only by the service and never shown by
// `systemctl show` or in /proc/<pid>/environ, unlike Environment=. Each role calls
// loadCredentials() at the top of main(); an explicitly set environment variable still wins,
// so existing Environment= deployments keep working unchanged.
import { readFileSync } from "node:fs";
import { join } from "node:path";

export const SECRET_CREDENTIALS = Object.freeze([
  "SHADE_TREE_SLASH_KEY",
  "SHADE_TREE_GW_OPERATOR_KEY",
  "SHADE_TREE_REGISTRAR_KEY",
  "SHADE_TREE_FLEET_TALLY_TOKEN",
]);

const NAME = /^SHADE_TREE_[A-Z0-9_]{1,64}$/;
const MAX_BYTES = 4096;

export function loadCredentials(names = SECRET_CREDENTIALS, { env = process.env, dir = env.CREDENTIALS_DIRECTORY } = {}) {
  const loaded = [];
  if (!dir) return loaded;
  for (const name of names) {
    if (!NAME.test(name) || (env[name] !== undefined && env[name] !== "")) continue;
    let value;
    try { value = readFileSync(join(dir, name)); } catch { continue; }
    if (value.length === 0 || value.length > MAX_BYTES) throw new Error(`credential ${name} is empty or larger than ${MAX_BYTES} bytes`);
    env[name] = value.toString("utf8").trim();
    loaded.push(name);
  }
  return loaded;
}
