// Shared conformance vectors (testdata/vectors.json, normative per ADR-0010) through the JS SDK,
// twice: once in Node, and once through the real browser bundle (esbuild, "browser" condition,
// @noble crypto backend) loaded back into this process. Both must reproduce every byte.
//
//   node packages/sdk/test/vectors.selftest.mjs

import { readFileSync, writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { build } from "esbuild";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..", "..");
const V = JSON.parse(readFileSync(join(ROOT, "testdata", "vectors.json"), "utf8"));

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };
const hex = (b) => Buffer.from(b).toString("hex");

// The wire functions the SDK exposes, re-exported from one entry so both builds see the same code.
const entry = (spec) => `
export { verifyCanopy, ShadeNetError } from ${JSON.stringify(spec(join(HERE, "..", "src", "index.mjs")))};
export { canonicalDirectoryBytes, canonicalCapsBytes, onionToPubkey, pubkeyToOnion, verifyCapsSig,
  ed25519Sign, ed25519PubFromSeed } from ${JSON.stringify(spec(join(ROOT, "packages", "node", "lib", "directory.mjs")))};
`;

async function suite(label, m) {
  console.log(`=== ${label} ===`);
  const dir = { version: 1, issued: 1000000, gateways: [{ onion: V.onion, pubkey: V.onionPub, weight: 100, health: "up" }] };
  ok(hex(m.canonicalDirectoryBytes(dir)) === V.canonicalDirectoryBytesHex, "canonicalDirectoryBytes");
  ok(m.ed25519PubFromSeed(V.signerSeed) === V.signerPub, "signer pubkey from seed");
  ok(m.ed25519Sign(m.canonicalDirectoryBytes(dir), V.signerSeed) === V.directorySignature, "directory signature (deterministic Ed25519)");
  ok(m.onionToPubkey(V.onion) === V.onionPub && m.pubkeyToOnion(V.onionPub) === V.onion, "onion <-> pubkey");

  const signed = { ...dir, signer: V.signerPub, signature: V.directorySignature };
  const view = m.verifyCanopy(signed, { signers: [V.signerPub] });
  ok(view.nodes.length === 1 && view.nodes[0].pubkey === V.onionPub, "verifyCanopy accepts the vector directory");
  let code = null;
  try { m.verifyCanopy(signed, { signers: [V.onionPub] }); } catch (e) { code = e.code; }
  ok(code === "Canopy", "verifyCanopy rejects an unpinned signer with code Canopy");
  try { m.verifyCanopy({ ...signed, issued: 1000001 }, { signers: [V.signerPub] }); code = null; } catch (e) { code = e.code; }
  ok(code === "Canopy", "verifyCanopy rejects a tampered directory");

  const caps = V.capabilities;
  ok(hex(m.canonicalCapsBytes(V.onion, caps.caps)) === caps.canonicalCapsBytesHex, "canonicalCapsBytes");
  ok(m.verifyCapsSig(V.onion, caps.caps, caps.capsSig), "capsSig verifies");
  const withCaps = { version: 1, issued: 1000000, gateways: [{ onion: V.onion, pubkey: V.onionPub, weight: 100, health: "up", caps: caps.caps, capsSig: caps.capsSig }] };
  ok(hex(m.canonicalDirectoryBytes(withCaps)) === caps.directoryWithCaps.canonicalBytesHex, "directory-with-caps bytes");
  ok(m.verifyCanopy({ ...withCaps, signature: caps.directoryWithCaps.signature }, { signers: [V.signerPub] }).nodes[0].caps.region === "eu", "directory with caps verifies");

  const th = V.thresholdDirectory;
  const thDir = { version: th.version, issued: th.issued, gateways: [{ onion: th.onion, pubkey: th.onionPub, weight: 100, health: "up" }], signers: th.signers, signatures: th.signatures, threshold: th.threshold };
  ok(m.verifyCanopy(thDir, { signers: th.signers }).nodes.length === 1, "threshold (M-of-N) canopy verifies");
}

const tmp = mkdtempSync(join(tmpdir(), "shadenet-vectors-"));
try {
  // Node build: the source modules as they are.
  const nodeEntry = join(tmp, "node.mjs");
  writeFileSync(nodeEntry, entry((p) => pathToFileURL(p).href));
  await suite("node", await import(pathToFileURL(nodeEntry).href));

  // Browser build: bundle with the "browser" condition, so #crypto resolves to @noble.
  const out = join(tmp, "browser.mjs");
  await build({
    stdin: { contents: entry((p) => p), resolveDir: ROOT, loader: "js" },
    bundle: true, format: "esm", platform: "browser", outfile: out, logLevel: "silent",
    external: ["snarkjs", "node:*"],
  });
  ok(!/node:crypto/.test(readFileSync(out, "utf8")), "browser bundle does not reference node:crypto");
  await suite("browser bundle (@noble backend)", await import(pathToFileURL(out).href));
} finally {
  rmSync(tmp, { recursive: true, force: true });
}

if (failures) {
  console.log(`\nFAIL: ${failures} SDK vector check(s)`);
  process.exit(1);
}
console.log("\nPASS: SDK conformance vectors (node + browser bundle)");
