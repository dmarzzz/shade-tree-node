// ZK artifact provenance selftest (ship-plan T-HARD-1, autonomous half).
//
// Recomputes sha256 + byte size of every ZK artifact the code loads (circuits/rln/*, the
// Solidity Groth16 verifiers, the exit-auth proof fixture) against testdata/zk-artifacts.lock.json
// and FAILS on any mismatch or missing lock entry — so a silently swapped wasm/zkey/vkey/verifier
// cannot land through `npm test` (ci.yml). Also asserts the lock's `provenance` declaration: today
// every artifact is "dev-testnet-untrusted" (circom-rln dev phase-2, circuits/rln/ARTIFACTS.md).
// After the human-run ceremony (docs/CEREMONY.md), the operator regenerates the lock with
// `--provenance=ceremony` AND flips EXPECTED_PROVENANCE below in the same commit — this test is
// deliberately loud about which regime the tree is in.
//
// Cross-consistency (the artifacts must move as a SET):
//   - VK constants embedded in the Solidity verifiers == the JSON verification keys
//   - contracts/RlnGroth16Verifier.sol == circuits/rln/Verifier.sol modulo the header comment
//   - the Rust `live` binary include_bytes!'s the SAME three circuits/rln files (path check on
//     crates/shadenet-rln/src/prover.rs, no cargo build), so the lock hashes cover it
//   - circuits/rln/ARTIFACTS.md's hash table agrees with the lock (docs cannot drift from bytes)
//   - (T-HARD-8) each circuit's `artifactId` in the lock == `<circuit>-<sha256(vkey)[0:16]>`
//     (the id the gateway/client/Rust derive at runtime; packages/node/lib/zk-artifacts.mjs), the Rust `live`
//     binary embeds the SAME lock file for its startup self-check, and release.yml runs this test
//
//   node test/zk-artifacts.selftest.mjs   (exit 0 = all invariants held)

import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import {
  ROOT, LOCK_PATH, ARTIFACTS, PROVENANCE_DEV, PROVENANCES, checkLock, readLock, measure, buildLock, artifactIdFor, VKEY_OF,
} from "../scripts/zk-artifacts-lock.mjs";
import { artifactIdOfFile, builtinArtifactId, lockArtifactIds } from "../packages/node/lib/zk-artifacts.mjs";

// FLIP THIS to "ceremony" in the same commit that pins ceremony output (docs/CEREMONY.md §7).
const EXPECTED_PROVENANCE = PROVENANCE_DEV;

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

// ---- 1. lock exists, every artifact hashes to what the lock says ----------------------------
console.log("lock vs disk (sha256 + bytes):");
const lock = readLock();
ok(lock !== null, `lock file present: ${LOCK_PATH}`);
const problems = lock ? checkLock(lock) : ["no lock"];
for (const p of problems) console.log(`       ${p}`);
ok(problems.length === 0, `checkLock: ${ARTIFACTS.length} artifacts, ${problems.length} problem(s)`);
ok(lock?.version === 1, "lock.version === 1");

// Independent recompute here (not just via checkLock) so a bug in the shared helper cannot
// self-certify: hash each file again inline and compare to the lock.
let inline = 0;
for (const a of ARTIFACTS) {
  const e = lock?.artifacts?.[a.path];
  const h = createHash("sha256").update(readFileSync(join(ROOT, a.path))).digest("hex");
  if (e && e.sha256 === h) inline++;
}
ok(inline === ARTIFACTS.length, `inline sha256 recompute matches lock for ${inline}/${ARTIFACTS.length}`);

// ---- 2. no unlisted ZK artifact in circuits/rln ---------------------------------------------
console.log("\ncoverage (every ZK file in circuits/rln has a lock entry):");
const zkExt = /\.(wasm|zkey|sol)$|verification_key\.json$/;
const unlisted = readdirSync(join(ROOT, "circuits", "rln"))
  .filter((n) => zkExt.test(n))
  .map((n) => `circuits/rln/${n}`)
  .filter((p) => !lock?.artifacts?.[p]);
ok(unlisted.length === 0, `no unlisted artifact in circuits/rln (${unlisted.join(", ") || "none"})`);
const solVerifiers = readdirSync(join(ROOT, "contracts"))
  .filter((n) => /Groth16Verifier\.sol$/.test(n))
  .map((n) => `contracts/${n}`)
  .filter((p) => !lock?.artifacts?.[p]);
ok(solVerifiers.length === 0, `every contracts/*Groth16Verifier.sol has a lock entry (${solVerifiers.join(", ") || "none unlisted"})`);

// ---- 3. provenance declaration --------------------------------------------------------------
console.log("\nprovenance declaration:");
const entries = Object.entries(lock?.artifacts || {});
ok(entries.every(([, e]) => typeof e.provenance === "string" && PROVENANCES.has(e.provenance)),
  `every entry has provenance in {${[...PROVENANCES].join(", ")}}`);
const notExpected = entries.filter(([, e]) => e.provenance !== EXPECTED_PROVENANCE).map(([p]) => p);
ok(notExpected.length === 0, `every entry provenance === "${EXPECTED_PROVENANCE}" (${notExpected.join(", ") || "all"})`);
if (EXPECTED_PROVENANCE === PROVENANCE_DEV) {
  ok(lock?.trust === "UNTRUSTED-TESTNET", `lock.trust === UNTRUSTED-TESTNET (artifacts are NOT ceremony output)`);
  ok(lock?.ceremony?.status === "not-run", "lock.ceremony.status === not-run");
} else {
  ok(lock?.trust === "CEREMONY", "lock.trust === CEREMONY");
  const c = lock?.ceremony || {};
  ok(Array.isArray(c.contributors) && c.contributors.length >= 2, "ceremony.contributors has >= 2 entries");
  ok(Array.isArray(c.transcriptSha256) && c.transcriptSha256.length === c.contributors.length, "one transcript hash per contributor");
  ok(typeof c.finalContributionHash === "string" && c.finalContributionHash.length >= 64, "ceremony.finalContributionHash present");
  ok(typeof c.beacon === "string" && c.beacon.length >= 32, "ceremony.beacon recorded");
}
ok(typeof lock?.ptau?.sha256 === "string" && /^[0-9a-f]{64}$/.test(lock.ptau.sha256), "ptau sha256 recorded (phase-1 file is not in-repo)");
ok(entries.every(([, e]) => Number.isInteger(e.bytes) && e.bytes > 0), "every entry has a positive integer byte size");
ok(entries.every(([, e]) => typeof e.role === "string" && e.role.length > 0), "every entry has a role");

// ---- 4. artifacts move as a set: JSON VK == Solidity VK constants -----------------------------
console.log("\nset-consistency (JSON vkey <-> Solidity verifier constants):");
function solConstants(relPath) {
  const src = readFileSync(join(ROOT, relPath), "utf8");
  const out = {};
  for (const m of src.matchAll(/uint256 constant (\w+)\s*=\s*(\d+);/g)) out[m[1]] = m[2];
  return out;
}
function vkMatchesSol(vkPath, solPath) {
  const vk = JSON.parse(readFileSync(join(ROOT, vkPath), "utf8"));
  const c = solConstants(solPath);
  const same = (a, b) => JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());
  const g2 = (name, arr) => same([c[`${name}x1`], c[`${name}x2`]], arr[0]) && same([c[`${name}y1`], c[`${name}y2`]], arr[1]);
  let good = c.alphax === vk.vk_alpha_1[0] && c.alphay === vk.vk_alpha_1[1];
  good = good && g2("beta", vk.vk_beta_2) && g2("gamma", vk.vk_gamma_2) && g2("delta", vk.vk_delta_2);
  for (let i = 0; i < vk.IC.length; i++) good = good && c[`IC${i}x`] === vk.IC[i][0] && c[`IC${i}y`] === vk.IC[i][1];
  good = good && c[`IC${vk.IC.length}x`] === undefined; // no extra IC points
  const src = readFileSync(join(ROOT, solPath), "utf8");
  const nPub = Number((src.match(/uint\[(\d+)\] calldata _pubSignals/) || [])[1]);
  return { good, nPub, nPublic: vk.nPublic, nIC: vk.IC.length };
}
for (const [vkPath, solPath] of [
  ["circuits/rln/verification_key.json", "contracts/RlnGroth16Verifier.sol"],
  ["circuits/rln/verification_key.json", "circuits/rln/Verifier.sol"],
  ["circuits/rln/withdraw_verification_key.json", "contracts/WithdrawGroth16Verifier.sol"],
]) {
  const r = vkMatchesSol(vkPath, solPath);
  ok(r.good, `${solPath} VK constants == ${vkPath}`);
  ok(r.nPub === r.nPublic && r.nIC === r.nPublic + 1, `${solPath} verifyProof takes uint[${r.nPublic}] pubSignals, IC has ${r.nIC} points`);
}
// contracts/RlnGroth16Verifier.sol must be circuits/rln/Verifier.sol + a header comment only.
const stripComments = (s) => s.split("\n").filter((l) => !l.trim().startsWith("///")).join("\n");
ok(stripComments(readFileSync(join(ROOT, "contracts/RlnGroth16Verifier.sol"), "utf8")) === stripComments(readFileSync(join(ROOT, "circuits/rln/Verifier.sol"), "utf8")),
  "contracts/RlnGroth16Verifier.sol == circuits/rln/Verifier.sol modulo /// comments");

// ---- 5. Rust live binary embeds the SAME files (path check, no cargo build) -----------------
console.log("\nrust embedded artifacts (crates/shadenet-rln/src/prover.rs include_bytes! paths):");
const prover = readFileSync(join(ROOT, "crates/shadenet-rln/src/prover.rs"), "utf8");
for (const f of ["rln.wasm", "rln_final.zkey", "verification_key.json"]) {
  ok(prover.includes(`"/../../circuits/rln/${f}"`), `prover.rs include_bytes! -> circuits/rln/${f} (covered by the lock hash)`);
}
ok(/#\[cfg\(feature = "embedded-artifacts"\)\]\s*mod embedded/.test(prover), "embedding is behind the embedded-artifacts feature (live binary)");

// ---- 6. docs cannot drift from bytes: ARTIFACTS.md hash table == lock ------------------------
console.log("\ncircuits/rln/ARTIFACTS.md hash table vs lock:");
const md = readFileSync(join(ROOT, "circuits/rln/ARTIFACTS.md"), "utf8");
let mdRows = 0, mdOk = 0;
for (const m of md.matchAll(/\| `([\w.]+)` \| `([0-9a-f]{64})` \|/g)) {
  const [, name, h] = m;
  const p = `circuits/rln/${name}`;
  if (!lock?.artifacts?.[p]) continue;
  mdRows++;
  if (lock.artifacts[p].sha256 === h) mdOk++; else console.log(`       ARTIFACTS.md says ${name} = ${h}, lock says ${lock.artifacts[p].sha256}`);
}
ok(mdRows >= 7 && mdOk === mdRows, `ARTIFACTS.md table rows agree with the lock (${mdOk}/${mdRows})`);
const ptauMd = md.match(/sha256 `([0-9a-f]{64})`/);
ok(ptauMd && ptauMd[1] === lock?.ptau?.sha256, "ARTIFACTS.md ptau sha256 == lock.ptau.sha256");

// ---- 6b. artifact ids (T-HARD-8): lock == runtime derivation; Rust embeds the lock; release runs this
console.log("\nartifact ids (lock <-> runtime <-> Rust) + release gate:");
for (const [circuit, vkPath] of Object.entries(VKEY_OF)) {
  const declared = lock?.circuits?.[circuit]?.artifactId;
  ok(declared === artifactIdOfFile(join(ROOT, vkPath), circuit), `lock circuits.${circuit}.artifactId == artifactIdOf(${vkPath}) (${declared})`);
  ok(declared === artifactIdFor(circuit, lock.artifacts[vkPath].sha256), `circuits.${circuit}.artifactId is literally the vkey's lock sha256 prefix`);
}
ok(builtinArtifactId() === lock?.circuits?.rln?.artifactId, "lib/zk-artifacts builtinArtifactId() (what a default gateway accepts / client sends) == lock rln artifactId");
ok(lock?.circuits?.rln?.previousArtifactId === null, "previousArtifactId is null (no ceremony has rotated the rln set); lockArtifactIds().previous mirrors it");
ok(lockArtifactIds()?.previous === null && lockArtifactIds()?.current === lock?.circuits?.rln?.artifactId, "lockArtifactIds() reads {current, previous} from the lock");
// rotation memory: rebuilding the lock over a prev whose rln id differs keeps that id as previousArtifactId
const rotated = buildLock({ prev: { ...lock, circuits: { ...lock.circuits, rln: { ...lock.circuits.rln, artifactId: "rln-0123456789abcdef", previousArtifactId: null } } } });
ok(rotated.circuits.rln.previousArtifactId === "rln-0123456789abcdef" && rotated.circuits.rln.artifactId === lock.circuits.rln.artifactId,
  "buildLock over a prev with a different rln id records it as previousArtifactId (the default legacy id after a ceremony)");
ok(buildLock({ prev: lock }).circuits.rln.previousArtifactId === lock.circuits.rln.previousArtifactId, "buildLock over an unchanged prev keeps previousArtifactId as-is");
for (const circuit of Object.keys(VKEY_OF)) {
  ok(md.includes(`| \`${circuit}\` | \`${lock.circuits[circuit].artifactId}\` |`), `ARTIFACTS.md artifact-id table names ${circuit} = ${lock.circuits[circuit].artifactId} (docs cannot drift from the lock)`);
}
const artifactsRs = readFileSync(join(ROOT, "crates/shadenet-rln/src/artifacts.rs"), "utf8");
ok(artifactsRs.includes('"/../../testdata/zk-artifacts.lock.json"'), "crates/shadenet-rln/src/artifacts.rs include_str!s THIS lock (the live binary self-checks its embedded bytes against it)");
ok(/#\[cfg\(feature = "embedded-artifacts"\)\]\s*pub const LOCK/.test(artifactsRs), "the embedded lock is behind the embedded-artifacts feature (live binary)");
const releaseYml = readFileSync(join(ROOT, ".github/workflows/release.yml"), "utf8");
ok(releaseYml.includes("node test/zk-artifacts.selftest.mjs"), "release.yml runs test/zk-artifacts.selftest.mjs (a tag build cannot embed drifted artifacts)");
ok(/lock-check:[\s\S]*needs:[\s\S]*lock-check/.test(releaseYml) || /needs: \[set-version, lock-check\]/.test(releaseYml), "release.yml build jobs depend on the lock-check job");

// ---- 7. negative: a tampered lock is caught by checkLock -------------------------------------
console.log("\nnegative (checkLock catches drift):");
const tampered = JSON.parse(JSON.stringify(lock));
tampered.artifacts["circuits/rln/rln_final.zkey"].sha256 = "00".repeat(32);
ok(checkLock(tampered).some((p) => p.startsWith("sha256 mismatch circuits/rln/rln_final.zkey")), "sha256 tamper on rln_final.zkey is reported");
const dropped = JSON.parse(JSON.stringify(lock));
delete dropped.artifacts["circuits/rln/verification_key.json"];
ok(checkLock(dropped).some((p) => p === "no lock entry for circuits/rln/verification_key.json"), "missing lock entry is reported");
const badProv = JSON.parse(JSON.stringify(lock));
badProv.artifacts["circuits/rln/rln.wasm"].provenance = "trust-me";
ok(checkLock(badProv).some((p) => p.startsWith("bad provenance for circuits/rln/rln.wasm")), "unknown provenance value is reported");
const halfCeremony = JSON.parse(JSON.stringify(lock));
halfCeremony.trust = "CEREMONY";
ok(checkLock(halfCeremony).some((p) => p.startsWith("trust must be UNTRUSTED-TESTNET")), "trust=CEREMONY with dev artifacts is reported");
const badId = JSON.parse(JSON.stringify(lock));
badId.circuits.rln.artifactId = "rln-0000000000000000";
ok(checkLock(badId).some((p) => p.startsWith("circuits.rln.artifactId")), "a hand-edited rln artifactId is reported (id must be the vkey hash prefix)");
const badPrev = JSON.parse(JSON.stringify(lock));
badPrev.circuits.rln.previousArtifactId = lock.circuits.rln.artifactId;
ok(checkLock(badPrev).some((p) => p.startsWith("circuits.rln.previousArtifactId")), "previousArtifactId equal to the current id is reported");
// measure() on a nonexistent path reports missing (used by checkLock's missing-artifact branch)
ok(measure({ path: "circuits/rln/does-not-exist.zkey" }).missing === true, "measure() flags a missing artifact");

console.log(failures ? `\n${failures} FAILED` : "\nall zk-artifacts invariants held");
if (EXPECTED_PROVENANCE === PROVENANCE_DEV) {
  console.log("NOTE: artifacts are dev-testnet-untrusted (no ceremony has been run). See docs/CEREMONY.md.");
}
process.exit(failures ? 1 : 0);
