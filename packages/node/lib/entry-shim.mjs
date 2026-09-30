// Compatibility for the top-level entry shims (gateway/gateway.mjs, bootnode/server.mjs, ...)
// kept for one minor release after the node moved to packages/node/. The real entry points run
// main() only when `import.meta.url` matches process.argv[1]; when a shim is what was invoked,
// point argv[1] at the moved file BEFORE the shim's re-export evaluates it, so a live unit
// whose ExecStart still names the old path keeps working until the fleet roll re-points it.
import { existsSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(fileURLToPath(import.meta.url), "../../../..");
const argv1 = process.argv[1] ? resolve(process.argv[1]) : "";
const rel = argv1 ? relative(ROOT, argv1) : "";
if (rel && !rel.startsWith("..") && !rel.startsWith(`packages${sep}`)) {
  const moved = join(ROOT, "packages", "node", rel);
  if (existsSync(moved)) process.argv[1] = moved;
}
