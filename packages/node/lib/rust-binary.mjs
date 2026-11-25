// Where a Rust binary of this repository is (ADR 0014, ADR 0015): a build in this checkout
// first, then the one on PATH, so a developer runs what they just built and an installed CLI
// runs the release. `null` when there is none.
import { existsSync } from "node:fs";
import { delimiter, join } from "node:path";

export function rustBinary(root, name) {
  const built = ["release", "debug"]
    .map((profile) => join(root, "target", profile, name))
    .find((path) => existsSync(path));
  if (built) return built;
  const onPath = (process.env.PATH || "").split(delimiter).some((dir) => dir && existsSync(join(dir, name)));
  return onPath ? name : null;
}
