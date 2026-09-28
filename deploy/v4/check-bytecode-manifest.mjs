#!/usr/bin/env node
// Recompute the normalized public-stake-v1 runtime identities from Foundry artifacts.
// Run after `forge build` or `forge test`; CI fails if source/compiler output drifts without
// an explicitly reviewed manifest update.
//
//   node deploy/v4/check-bytecode-manifest.mjs           check (CI)
//   node deploy/v4/check-bytecode-manifest.mjs --write   rewrite zeroRanges/runtimeBytes/sha256
//                                                        after a reviewed contract change

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const MANIFEST_PATH = join(ROOT, "deploy/v4/public-stake-v1-bytecode.json");
const manifest = JSON.parse(readFileSync(MANIFEST_PATH, "utf8"));
const write = process.argv.includes("--write");
const fail = (message) => { throw new Error(`public-stake-v1 bytecode manifest: ${message}`); };
const cleanRanges = (ranges) => ranges.map(({ start, length }) => ({ start, length })).sort((a, b) => a.start - b.start || a.length - b.length);

if (manifest.schemaVersion !== 1 || manifest.profile !== "public-stake-v1") fail("wrong schema/profile");
if (JSON.stringify(manifest.compiler) !== JSON.stringify({ solc: "0.8.24", optimizer: true, runs: 200 })) fail("compiler pin drifted from foundry.toml");
if (Object.keys(manifest.contracts || {}).sort().join(",") !== "groth16,hasher,staking,withdrawVerifier") fail("contract graph is incomplete or has unknown entries");
if (Object.keys(manifest.libraries || {}).sort().join(",") !== "PoseidonT2,PoseidonT3") fail("linked-library graph is incomplete or has unknown entries");
if (Object.keys(manifest.libraryAddresses || {}).sort().join(",") !== "PoseidonT2,PoseidonT3") fail("linked-library addresses are incomplete or have unknown entries");

for (const section of ["contracts", "libraries"]) {
  for (const [name, spec] of Object.entries(manifest[section] || {})) {
    const artifact = JSON.parse(readFileSync(join(ROOT, "out", spec.artifact), "utf8"));
    const bytecode = artifact?.deployedBytecode?.object;
    if (typeof bytecode !== "string") fail(`${name}: missing Foundry deployedBytecode`);
    let normalized = bytecode.replace(/^0x/, "");
    if (write && spec.links) {
      // The build links the pinned library addresses (test:bytecode-manifest --libraries); find them.
      for (const library of Object.keys(spec.links)) {
        const needle = manifest.libraryAddresses[library].toLowerCase().replace(/^0x/, "");
        const hay = normalized.toLowerCase();
        const found = [];
        for (let i = hay.indexOf(needle); i !== -1; i = hay.indexOf(needle, i + 2)) {
          if (i % 2 === 0) found.push({ start: i / 2, length: 20 });
        }
        spec.links[library] = found;
      }
    }
    const metadataLength = Number.parseInt(normalized.slice(-4), 16) + 2;
    const metadataRange = { start: normalized.length / 2 - metadataLength, length: metadataLength };
    const requiredRanges = cleanRanges([
      ...Object.values(artifact.deployedBytecode.immutableReferences || {}).flat(),
      ...Object.values(spec.links || {}).flat(),
      ...(section === "libraries" ? [{ start: 1, length: 20 }] : []),
      metadataRange,
    ]);
    if (write) spec.zeroRanges = requiredRanges;
    const zeroRanges = cleanRanges(spec.zeroRanges);
    if (JSON.stringify(zeroRanges) !== JSON.stringify(requiredRanges)) fail(`${name}.zeroRanges does not cover exactly its immutables, links, library self-address, and metadata`);
    for (const [library, ranges] of Object.entries(spec.links || {})) {
      const expected = manifest.libraryAddresses[library]?.toLowerCase().replace(/^0x/, "");
      if (!expected || ranges.some(({ start, length }) => length !== 20 || normalized.slice(start * 2, (start + length) * 2).toLowerCase() !== expected)) {
        fail(`${name}: compiled link does not equal pinned ${library} address`);
      }
    }
    for (const { start, length } of zeroRanges) {
      normalized = normalized.slice(0, start * 2) + "0".repeat(length * 2) + normalized.slice((start + length) * 2);
    }
    if (!/^[0-9a-f]*$/i.test(normalized)) fail(`${name}: unresolved bytecode placeholders remain`);
    const actual = {
      runtimeBytes: normalized.length / 2,
      normalizedSha256: createHash("sha256").update(Buffer.from(normalized, "hex")).digest("hex"),
      zeroRanges,
    };
    if (write) Object.assign(spec, { runtimeBytes: actual.runtimeBytes, normalizedSha256: actual.normalizedSha256 });
    for (const field of ["runtimeBytes", "normalizedSha256"]) {
      if (JSON.stringify(actual[field] ?? null) !== JSON.stringify(spec[field] ?? null)) fail(`${name}.${field} does not match current Foundry output`);
    }
  }
}

if (write) {
  const text = JSON.stringify(manifest, null, 2)
    .replace(/\{\s+"start": (\d+),\s+"length": (\d+)\s+\}/g, '{ "start": $1, "length": $2 }')
    .replace(/\{\s+"solc": ("[^"]+"),\s+"optimizer": (\w+),\s+"runs": (\d+)\s+\}/, '{ "solc": $1, "optimizer": $2, "runs": $3 }');
  writeFileSync(MANIFEST_PATH, text + "\n");
  console.log("public-stake-v1 bytecode manifest rewritten from current Foundry output; review the diff");
} else {
  console.log("public-stake-v1 bytecode manifest matches current Foundry output");
}
