// The published @shadenet/sdk works outside this repository: pack the tarball, unpack it into a
// scratch node_modules (dependencies linked from this checkout, no network), and use both entries
// from there, including a real exit proof over the packaged circuit.
//
//   node packages/sdk/test/pack.selftest.mjs

import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const SDK = join(dirname(fileURLToPath(import.meta.url)), "..");
const ROOT = join(SDK, "..", "..");
let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

execFileSync(process.execPath, [join(SDK, "scripts", "pack.mjs")], { stdio: "inherit" });
const pkg = JSON.parse(readFileSync(join(SDK, ".pack", "package.json"), "utf8"));
const tarball = join(SDK, ".pack", `shadenet-sdk-${pkg.version}.tgz`);

const work = mkdtempSync(join(tmpdir(), "shadenet-sdk-pack-"));
try {
  const dest = join(work, "node_modules", "@shadenet", "sdk");
  mkdirSync(dest, { recursive: true });
  execFileSync("tar", ["-xzf", tarball, "-C", dest, "--strip-components=1"]);
  for (const dep of Object.keys(pkg.dependencies)) {
    const target = join(work, "node_modules", dep);
    mkdirSync(dirname(target), { recursive: true });
    symlinkSync(join(ROOT, "node_modules", dep), target, "dir");
  }
  ok(!/node:crypto/.test(readFileSync(join(dest, "dist", "browser.mjs"), "utf8")), "browser build carries no node:crypto");
  ok(!/\.\.\/\.\.\/lib\//.test(readFileSync(join(dest, "dist", "node.mjs"), "utf8")), "the wire code is bundled, not referenced outside the package");

  const V = JSON.parse(readFileSync(join(ROOT, "testdata", "vectors.json"), "utf8"));
  const smoke = `
    import * as sdk from "@shadenet/sdk";
    import * as node from "@shadenet/sdk/node";
    const V = ${JSON.stringify({ onion: V.onion, onionPub: V.onionPub, signerPub: V.signerPub, sig: V.directorySignature })};
    const out = {};
    const id = await sdk.createIdentity();
    out.identity = sdk.importIdentity(sdk.serializeIdentity(id)).leaf === id.leaf;
    out.network = sdk.resolveNetwork("sepolia").staked.tiers.length > 0;
    const dir = { version: 1, issued: 1000000, gateways: [{ onion: V.onion, pubkey: V.onionPub, weight: 100, health: "up" }], signer: V.signerPub, signature: V.sig };
    out.canopy = sdk.verifyCanopy(dir, { signers: [V.signerPub] }).nodes.length === 1;
    const proof = await node.proveAction({ identitySecret: "111", context: sdk.exitContext("1") });
    out.proof = typeof proof === "string" && proof.length === 2 + 9 * 64;
    out.client = typeof node.createClient === "function" && typeof node.proxyFetch === "function";
    console.log(JSON.stringify(out));
    process.exit(0);
  `;
  writeFileSync(join(work, "smoke.mjs"), smoke);
  const result = JSON.parse(execFileSync(process.execPath, [join(work, "smoke.mjs")], { cwd: work, encoding: "utf8" }).trim().split("\n").pop());
  ok(result.identity, "packaged: identity round trip");
  ok(result.network, "packaged: bundled network record");
  ok(result.canopy, "packaged: canopy verification");
  ok(result.proof, "packaged: exit proof from the packaged circuit");
  ok(result.client, "packaged: Node egress entry loads");
} finally {
  rmSync(work, { recursive: true, force: true });
  rmSync(join(SDK, ".pack"), { recursive: true, force: true });
}

if (failures) {
  console.log(`\nFAIL: ${failures} packaged SDK check(s)`);
  process.exit(1);
}
console.log("\nPASS: packaged @shadenet/sdk works outside the repository");
