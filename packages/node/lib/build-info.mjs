// The commit a long-running role is executing (OPS-3), so the monitor and the public Elder
// /health can show which pin the canopy actually runs. Resolution, first match wins:
//   1. SHADE_TREE_BUILD_COMMIT (40 hex), for packaged installs without a .git directory;
//   2. the checkout's .git/HEAD: a detached SHA (how Ansible and bootstrap.sh deploy) or a
//      branch ref resolved through refs/ or packed-refs;
//   3. "unknown".
// Reads files only; never spawns git. Cached for the life of the process.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const SHA = /^[0-9a-f]{40}$/;
let cached;

export function resolveBuildCommit({ env = process.env, root = ROOT } = {}) {
  const pinned = String(env.SHADE_TREE_BUILD_COMMIT || "").trim().toLowerCase();
  if (SHA.test(pinned)) return pinned;
  try {
    const head = readFileSync(join(root, ".git", "HEAD"), "utf8").trim();
    if (SHA.test(head)) return head;
    const ref = /^ref: (refs\/[A-Za-z0-9._/-]+)$/.exec(head)?.[1];
    if (!ref || ref.includes("..")) return "unknown";
    try {
      const loose = readFileSync(join(root, ".git", ref), "utf8").trim();
      if (SHA.test(loose)) return loose;
    } catch { /* fall through to packed-refs */ }
    const packed = readFileSync(join(root, ".git", "packed-refs"), "utf8");
    for (const line of packed.split("\n")) {
      const [sha, name] = line.trim().split(" ");
      if (name === ref && SHA.test(sha)) return sha;
    }
  } catch { /* not a checkout */ }
  return "unknown";
}

export function buildCommit() {
  if (cached === undefined) cached = resolveBuildCommit();
  return cached;
}
