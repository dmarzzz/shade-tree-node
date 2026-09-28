// PSE RLN ceremony adoption check (launch decision D3). Reproduces, from public inputs only, the
// evidence that PSE's finalized RLN trusted setup (ceremony.pse.dev "RLN Trusted Setup Ceremony",
// circom-rln 17f0fed) can replace this repo's dev proving keys:
//
//   1. PSE's published initial (00000) and final zkeys match the pinned hashes below.
//   2. Every cryptographic section of PSE's initial zkey is byte-identical to one built from
//      circom-rln 17f0fed compiled with circom v2.1.5 --O2 and the Hermez powersOfTau28 power 13.
//      (Section 10's csHash differs: it is snarkjs-version bookkeeping, not key material.)
//   3. snarkjs verifyFromInit accepts the whole contribution chain from that initial zkey to the
//      final zkey (RLN: 60 contributions + beacon; withdraw: 62 + beacon).
//   4. Witnesses from the reproduced WASM prove under the final zkeys and verify under their keys.
//
//   node scripts/ceremony/pse-check.mjs --work <dir> --circom <circom-2.1.5 binary> --circom-rln <src dir>
//
// Needs `npm ci --prefix scripts/ceremony`. Downloads ~35 MB into --work. Runs nothing that
// changes repository files; the adoption itself is a separate reviewed PR (docs/ceremony/PSE-ADOPTION.md).

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const snarkjs = require("snarkjs");

const BUCKET = "https://rln-trusted-setup-ceremony-pse-p0tion-production.s3.eu-central-1.amazonaws.com";
const PTAU = {
  name: "powersOfTau28_hez_final_13.ptau",
  url: "https://fastfourier.nyc3.cdn.digitaloceanspaces.com/powers-of-tau/powersOfTau28_hez_final_13.ptau",
  sha256: "95751b5207f20aa822f01109902315c01c15250303feacea2b8aa7dc9fdfeefd",
};
export const PSE = {
  rln: {
    prefix: "rln-20",
    source: "circuits/rln.circom",
    init: "3b5499f002173787a6d931e0cb8a4a09091c66cb47d4324150154e6fabd66ee2",
    final: "ae30d3d4b29d9dab8c65ff181644a3eb57c2c0fa9f687ea3baf8c7f711d7946a",
    contributions: 60,
  },
  withdraw: {
    prefix: "rln-withdraw",
    source: "circuits/withdraw.circom",
    init: "def04ae8e7ed939105e4dce98e0bcf2b946060e2ecdd45694e9500448b6db158",
    final: "c8c778bc0123b43071ae2d218d88f343d7be05d6b1a843c695289c6c3d7cf8e5",
    contributions: 62,
  },
};
const CIRCOM_RLN_COMMIT = "17f0fed7d8d19e8b127fd0b3e5295a4831193a0d";

const sha256 = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
const fail = (message) => { console.error(`pse-check: FAIL ${message}`); process.exit(1); };
const ok = (message) => console.log(`  ok   ${message}`);
const quiet = { info: () => {}, warn: () => {}, error: (m) => console.error(m), debug: () => {} };

async function fetchPinned(url, path, digest) {
  if (!existsSync(path)) {
    const res = await fetch(url);
    if (!res.ok) fail(`download ${url}: HTTP ${res.status}`);
    writeFileSync(path, Buffer.from(await res.arrayBuffer()));
  }
  if (sha256(path) !== digest) fail(`${path} sha256 ${sha256(path)} != pinned ${digest}`);
}

// zkey = "zkey" magic, version, n sections, then (type u32, size u64, bytes) per section.
export function zkeySections(path) {
  const b = readFileSync(path);
  const out = new Map();
  let offset = 12;
  const count = b.readUInt32LE(8);
  for (let i = 0; i < count; i++) {
    const type = b.readUInt32LE(offset);
    const size = Number(b.readBigUInt64LE(offset + 4));
    out.set(type, b.subarray(offset + 12, offset + 12 + size));
    offset += 12 + size;
  }
  return out;
}

async function main() {
  const { values } = parseArgs({ options: { work: { type: "string" }, circom: { type: "string" }, "circom-rln": { type: "string" } } });
  if (!values.work || !values.circom || !values["circom-rln"]) fail("usage: --work <dir> --circom <circom 2.1.5> --circom-rln <circom-rln checkout>");
  const work = resolve(values.work);
  const src = resolve(values["circom-rln"]);
  mkdirSync(join(work, "build"), { recursive: true });

  const head = spawnSync("git", ["-C", src, "rev-parse", "HEAD"], { encoding: "utf8" }).stdout.trim();
  if (head !== CIRCOM_RLN_COMMIT) fail(`circom-rln checkout is ${head}, expected ${CIRCOM_RLN_COMMIT}`);
  const version = spawnSync(values.circom, ["--version"], { encoding: "utf8" }).stdout.trim();
  if (!/2\.1\.5/.test(version)) fail(`circom is "${version}", expected 2.1.5`);

  const ptau = join(work, PTAU.name);
  await fetchPinned(PTAU.url, ptau, PTAU.sha256);
  ok(`phase 1: ${PTAU.name} sha256 pinned`);

  for (const [name, spec] of Object.entries(PSE)) {
    console.log(`== ${name} (${spec.prefix})`);
    const init = join(work, `${spec.prefix}_00000.zkey`);
    const final = join(work, `${spec.prefix}_final.zkey`);
    await fetchPinned(`${BUCKET}/circuits/${spec.prefix}/contributions/${spec.prefix}_00000.zkey`, init, spec.init);
    await fetchPinned(`${BUCKET}/circuits/${spec.prefix}/contributions/${spec.prefix}_final.zkey`, final, spec.final);
    ok("PSE initial and final zkeys match the pinned hashes");

    const compiled = spawnSync(values.circom, [spec.source, "--r1cs", "--wasm", "--O2", "--prime", "bn128", "-o", join(work, "build")], { cwd: src, encoding: "utf8" });
    if (compiled.status !== 0) fail(`circom: ${compiled.stderr}`);
    const r1cs = join(work, "build", `${name}.r1cs`);
    const wasm = join(work, "build", `${name}_js`, `${name}.wasm`);
    const ours = join(work, `ours-${name}_00000.zkey`);
    await snarkjs.zKey.newZKey(r1cs, ptau, ours, quiet);
    const a = zkeySections(init);
    const b = zkeySections(ours);
    for (const [type, bytes] of a) {
      if (type === 10) continue; // MPC params: csHash is snarkjs-version bookkeeping
      if (!b.get(type)?.equals(bytes)) fail(`section ${type} of PSE's initial zkey differs from the reproduction`);
    }
    ok("initial zkey key material is byte-identical to circom 2.1.5 --O2 + Hermez ptau 13 (section 10 csHash excluded)");

    const log = [];
    const chain = await snarkjs.zKey.verifyFromInit(init, ptau, final, { ...quiet, info: (m) => log.push(String(m)) });
    if (!chain) fail("verifyFromInit rejected the contribution chain");
    const contributions = log.filter((line) => /^contribution #/.test(line)).length;
    if (contributions !== spec.contributions + 1) fail(`chain has ${contributions} entries, expected ${spec.contributions} + beacon`);
    ok(`verifyFromInit: ${spec.contributions} contributions + beacon accepted`);

    const vkey = await snarkjs.zKey.exportVerificationKey(final, quiet);
    const input = name === "withdraw"
      ? { identitySecret: "111", address: "12345" }
      : null;
    if (input) {
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasm, final, quiet);
      if (!(await snarkjs.groth16.verify(vkey, publicSignals, proof, quiet))) fail("withdraw proof did not verify under PSE's key");
      ok("reproduced WASM proves under PSE's final zkey and verifies under its key");
    }
    writeFileSync(join(work, `${spec.prefix}_verification_key.json`), JSON.stringify(vkey, null, 2) + "\n");
  }
  console.log("pse-check: PASS (RLN proving is exercised end to end by the repo's JS and Rust interop with SHADE_TREE_ZK_* pointing at the work dir; see docs/ceremony/PSE-ADOPTION.md)");
  process.exit(0);
}

if (import.meta.url === `file://${process.argv[1]}`) main().catch((e) => fail(e.stack || e.message));
