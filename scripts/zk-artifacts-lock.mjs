// ZK artifact provenance lock (T-HARD-1, autonomous half).
//
// (Re)generates testdata/zk-artifacts.lock.json: sha256 + byte size + role + provenance for
// every ZK artifact the code loads (gateway/client via lib/rln.mjs, the Rust `live` binary via
// include_bytes! in rust/shade-tree-rln/src/prover.rs, the Solidity verifiers, and the exit-auth
// proof fixture bound to the withdraw VK). test/zk-artifacts.selftest.mjs recomputes every hash
// against this file, so `npm test` (ci.yml) fails on any silent artifact swap.
//
//   node scripts/zk-artifacts-lock.mjs            # rewrite the lock from the files on disk
//   node scripts/zk-artifacts-lock.mjs --check    # verify only (exit 1 on drift); same logic
//                                                 # the selftest uses
//
// PROVENANCE IS NOT INFERRED FROM BYTES. The `provenance` field is a declaration the operator
// makes: every artifact is "dev-testnet-untrusted" today (circom-rln's dev phase-2: two hard-coded
// contributions + a fixed beacon, see circuits/rln/ARTIFACTS.md). After a real ceremony
// (docs/CEREMONY.md) the operator regenerates the lock with --provenance=ceremony and fills in
// the `ceremony` block by hand (transcript hashes, contributor list, ptau). This script never
// upgrades provenance on its own: rerunning without --provenance keeps whatever the existing
// lock says per artifact, and a brand-new lock defaults to dev-testnet-untrusted.

import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
export const ROOT = join(HERE, "..");
export const LOCK_PATH = join(ROOT, "testdata", "zk-artifacts.lock.json");

export const PROVENANCE_DEV = "dev-testnet-untrusted";
export const PROVENANCE_CEREMONY = "ceremony";
export const PROVENANCES = new Set([PROVENANCE_DEV, PROVENANCE_CEREMONY]);

// The artifact set. Path is repo-relative. `circuit` groups files that MUST move as a set
// (swap the zkey => regenerate vkey + verifier + fixture together). `loadedBy` is documentation
// for the reader (which code path reads the bytes) — not used for verification.
export const ARTIFACTS = [
  { path: "circuits/rln/rln.wasm", circuit: "rln", role: "witness-calculator (circom wasm, RLN(20,16))",
    loadedBy: ["lib/rln.mjs proveForSlot (client)", "rust/shade-tree-rln/src/prover.rs (embedded, live binary)", "rust/shade-tree-rln/src/main.rs (probe)"] },
  { path: "circuits/rln/rln_final.zkey", circuit: "rln", role: "groth16 proving key (phase-2 output)",
    loadedBy: ["lib/rln.mjs proveForSlot (client)", "rust/shade-tree-rln/src/prover.rs (embedded, live binary)"] },
  { path: "circuits/rln/verification_key.json", circuit: "rln", role: "groth16 verification key (exported from rln_final.zkey)",
    loadedBy: ["lib/rln.mjs verifyEnvelope (gateway)", "rust/shade-tree-rln/src/prover.rs (embedded self-check)", "rust/shade-tree-rln/interop/verify-envelope.mjs"] },
  { path: "circuits/rln/Verifier.sol", circuit: "rln", role: "solidity groth16 verifier (snarkjs export of rln_final.zkey; provenance copy, not deployed)",
    loadedBy: ["contracts/RlnGroth16Verifier.sol is this file + a header comment"] },
  { path: "contracts/RlnGroth16Verifier.sol", circuit: "rln", role: "solidity groth16 verifier for the RLN membership circuit (VK == verification_key.json); NOT wired on-chain yet",
    loadedBy: ["forge build (compiles); no contract references it"] },
  { path: "circuits/rln/withdraw.wasm", circuit: "withdraw", role: "witness-calculator (circom wasm, withdraw / exit-auth)",
    loadedBy: ["testdata/gen-withdraw-proof.mjs", "rust/shade-tree-rln/src/withdraw.rs (exit-member / withdraw-member)"] },
  { path: "circuits/rln/withdraw_final.zkey", circuit: "withdraw", role: "groth16 proving key (phase-2 output)",
    loadedBy: ["testdata/gen-withdraw-proof.mjs", "rust/shade-tree-rln/src/withdraw.rs"] },
  { path: "circuits/rln/withdraw_verification_key.json", circuit: "withdraw", role: "groth16 verification key (exported from withdraw_final.zkey)",
    loadedBy: ["testdata/gen-withdraw-proof.mjs (local verify)", "rust/shade-tree-rln/src/withdraw.rs (self-verify)"] },
  { path: "contracts/WithdrawGroth16Verifier.sol", circuit: "withdraw", role: "solidity groth16 verifier for the withdraw circuit (VK == withdraw_verification_key.json); wrapped by contracts/WithdrawVerifier.sol, DEPLOYED (network/sepolia/contracts.json)",
    loadedBy: ["contracts/WithdrawVerifier.sol", "contracts/script/DeployRegistry.s.sol", "test/WithdrawVerifier.t.sol"] },
  { path: "testdata/withdraw-proof.json", circuit: "withdraw", role: "exit-auth proof fixture bound to withdraw_verification_key.json (regenerate: node testdata/gen-withdraw-proof.mjs)",
    loadedBy: ["test/WithdrawVerifier.t.sol", "test/StakedReputationSet*.t.sol"] },
];

// The upstream phase-1 (Powers of Tau) file the current artifacts were built from. It is NOT
// in the repo (~300MB); the hash is recorded so a verifier can confirm the ptau they fetch is
// the same one. Source: circuits/rln/ARTIFACTS.md.
export const PTAU = {
  file: "powersOfTau28_hez_final_14.ptau",
  power: 14,
  sha256: "489be9e5ac65d524f7b1685baac8a183c6e77924fdb73d2b8105e335f277895d",
  ceremony: "Hermez / Perpetual Powers of Tau (BN254), phase-1 only",
  note: "not stored in-repo; verify the fetched file's sha256 against this value before any phase-2 (docs/CEREMONY.md)",
};

export function sha256File(abs) {
  return createHash("sha256").update(readFileSync(abs)).digest("hex");
}

export function measure(entry) {
  const abs = join(ROOT, entry.path);
  if (!existsSync(abs)) return { path: entry.path, missing: true };
  return { path: entry.path, sha256: sha256File(abs), bytes: statSync(abs).size };
}

// ---- artifact ids (T-HARD-8) ------------------------------------------------------------
// Each circuit's artifact SET is named by a content-derived id: `<circuit>-<sha256(vkey)[0:16]>`
// (lib/zk-artifacts.mjs artifactIdOf), i.e. literally the vkey's lock hash prefix. The gateway
// accepts a set of ids (SHADE_TREE_ZK_ARTIFACTS), the envelope carries one, so a ceremony swap can run
// as a dual-VK window. The lock records `circuits.<c>.artifactId` (checked == derived from the
// vkey on disk) and, for rln, `previousArtifactId`: when a regeneration sees the rln vkey hash
// CHANGE, the outgoing id is kept as previousArtifactId (the default legacy id a field-less
// envelope maps to, so un-upgraded clients get a precise `artifact-retired` after the window).
export const VKEY_OF = {
  rln: "circuits/rln/verification_key.json",
  withdraw: "circuits/rln/withdraw_verification_key.json",
};
export function artifactIdFor(circuit, sha256hex) {
  return `${circuit}-${sha256hex.slice(0, 16)}`;
}

export function readLock(path = LOCK_PATH) {
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf8"));
}

// Build the lock object from disk. `provenanceOverride` (string|null) applies to every artifact;
// otherwise each artifact keeps its provenance from `prev` (or PROVENANCE_DEV if new).
export function buildLock({ prev = null, provenanceOverride = null } = {}) {
  const artifacts = {};
  for (const a of ARTIFACTS) {
    const m = measure(a);
    if (m.missing) throw new Error(`artifact missing on disk: ${a.path}`);
    const prevEntry = prev?.artifacts?.[a.path];
    artifacts[a.path] = {
      circuit: a.circuit,
      role: a.role,
      sha256: m.sha256,
      bytes: m.bytes,
      provenance: provenanceOverride ?? prevEntry?.provenance ?? PROVENANCE_DEV,
      loadedBy: a.loadedBy,
    };
  }
  const anyDev = Object.values(artifacts).some((e) => e.provenance === PROVENANCE_DEV);
  // rln artifact id + rotation memory: the vkey hash changed since `prev` => the outgoing id
  // becomes previousArtifactId (a rerun with an unchanged vkey keeps whatever prev recorded).
  const rlnId = artifactIdFor("rln", artifacts[VKEY_OF.rln].sha256);
  const prevRln = prev?.circuits?.rln || {};
  const rlnPrevious = prevRln.artifactId && prevRln.artifactId !== rlnId
    ? prevRln.artifactId
    : (prevRln.previousArtifactId ?? null);
  return {
    _note:
      "ZK artifact provenance lock (ship-plan T-HARD-1). sha256 + bytes are RECOMPUTED by " +
      "test/zk-artifacts.selftest.mjs on every `npm test`; `provenance` is a DECLARATION, not a " +
      "measurement. Regenerate with `node scripts/zk-artifacts-lock.mjs`; see docs/CEREMONY.md " +
      "for how the ceremony output replaces these entries.",
    version: 1,
    trust: anyDev ? "UNTRUSTED-TESTNET" : "CEREMONY",
    trustNote: anyDev
      ? "Every artifact below is circom-rln's DEV phase-2 output (2 hard-coded contributions + fixed beacon; circuits/rln/ARTIFACTS.md). Genuine Groth16, but whoever holds the toxic waste can forge membership / exit-auth proofs. NOT for real funds or real anonymity."
      : "All artifacts declared as multi-party ceremony output; see `ceremony` for transcripts.",
    ptau: PTAU,
    ceremony: prev?.ceremony ?? {
      status: "not-run",
      note: "Filled in by hand after docs/CEREMONY.md phase 2: id, date, contributors[], transcriptSha256[], finalContributionHash, beacon, publishedAt.",
    },
    circuits: {
      rln: {
        family: "rate-limiting-nullifier/circom-rln", tag: "v1.0.0", commit: "17f0fed7d8d19e8b127fd0b3e5295a4831193a0d", main: "RLN(20,16)", constraints: 12390, nPublic: 5,
        artifactId: rlnId,
        previousArtifactId: rlnPrevious,
      },
      withdraw: {
        family: "rate-limiting-nullifier/circom-rln", tag: "v1.0.0", commit: "17f0fed7d8d19e8b127fd0b3e5295a4831193a0d", main: "Withdraw", nPublic: 2,
        artifactId: artifactIdFor("withdraw", artifacts[VKEY_OF.withdraw].sha256),
      },
    },
    artifacts,
  };
}

// Compare the lock against disk. Returns a list of human-readable problems (empty = clean).
export function checkLock(lock) {
  const problems = [];
  if (!lock || typeof lock !== "object") return ["lock file missing or not an object"];
  const seen = new Set();
  for (const a of ARTIFACTS) {
    const e = lock.artifacts?.[a.path];
    if (!e) { problems.push(`no lock entry for ${a.path}`); continue; }
    seen.add(a.path);
    const m = measure(a);
    if (m.missing) { problems.push(`artifact missing on disk: ${a.path}`); continue; }
    if (e.sha256 !== m.sha256) problems.push(`sha256 mismatch ${a.path}: lock=${e.sha256} disk=${m.sha256}`);
    if (e.bytes !== m.bytes) problems.push(`byte-size mismatch ${a.path}: lock=${e.bytes} disk=${m.bytes}`);
    if (!PROVENANCES.has(e.provenance)) problems.push(`bad provenance for ${a.path}: ${JSON.stringify(e.provenance)}`);
    if (e.circuit !== a.circuit) problems.push(`circuit label drift for ${a.path}: lock=${e.circuit} expected=${a.circuit}`);
  }
  for (const p of Object.keys(lock.artifacts || {})) {
    if (!seen.has(p)) problems.push(`lock entry ${p} is not in the ARTIFACTS list of scripts/zk-artifacts-lock.mjs`);
  }
  // Artifact ids must be exactly the vkey hash prefixes (T-HARD-8): a hand-edited id would let
  // the gateway/client/Rust disagree with the lock on the name of the set.
  for (const [circuit, vkPath] of Object.entries(VKEY_OF)) {
    const e = lock.artifacts?.[vkPath];
    const declared = lock.circuits?.[circuit]?.artifactId;
    if (!e) continue; // reported above
    if (declared !== artifactIdFor(circuit, e.sha256)) {
      problems.push(`circuits.${circuit}.artifactId ${JSON.stringify(declared)} != ${artifactIdFor(circuit, e.sha256)} (sha256 prefix of ${vkPath})`);
    }
  }
  const prevId = lock.circuits?.rln?.previousArtifactId;
  if (prevId != null && (typeof prevId !== "string" || !/^rln-[0-9a-f]{16}$/.test(prevId) || prevId === lock.circuits?.rln?.artifactId)) {
    problems.push(`circuits.rln.previousArtifactId must be null or a distinct rln-<hex16> id (got ${JSON.stringify(prevId)})`);
  }
  const anyDev = Object.values(lock.artifacts || {}).some((e) => e.provenance === PROVENANCE_DEV);
  if (anyDev && lock.trust !== "UNTRUSTED-TESTNET") problems.push(`trust must be UNTRUSTED-TESTNET while any artifact is ${PROVENANCE_DEV} (got ${lock.trust})`);
  if (!anyDev && lock.trust !== "CEREMONY") problems.push(`trust must be CEREMONY when no artifact is ${PROVENANCE_DEV} (got ${lock.trust})`);
  return problems;
}

function main() {
  const args = process.argv.slice(2);
  const check = args.includes("--check");
  const provArg = args.find((a) => a.startsWith("--provenance="));
  const provenanceOverride = provArg ? provArg.slice("--provenance=".length) : null;
  if (provenanceOverride && !PROVENANCES.has(provenanceOverride)) {
    console.error(`--provenance must be one of: ${[...PROVENANCES].join(", ")}`);
    process.exit(2);
  }
  if (check) {
    const problems = checkLock(readLock());
    if (problems.length) { console.error("zk-artifacts lock: DRIFT\n  " + problems.join("\n  ")); process.exit(1); }
    console.log(`zk-artifacts lock: OK (${ARTIFACTS.length} artifacts match ${LOCK_PATH})`);
    return;
  }
  const lock = buildLock({ prev: readLock(), provenanceOverride });
  writeFileSync(LOCK_PATH, JSON.stringify(lock, null, 2) + "\n");
  console.log(`wrote ${LOCK_PATH} (${ARTIFACTS.length} artifacts, trust=${lock.trust})`);
  for (const [p, e] of Object.entries(lock.artifacts)) console.log(`  ${e.sha256}  ${String(e.bytes).padStart(8)}  ${p}  [${e.provenance}]`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
