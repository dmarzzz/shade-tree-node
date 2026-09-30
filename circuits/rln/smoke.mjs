// Phase-0 GATE smoke test: prove a full rlnjs@3.3.0 round-trip against the
// locally-built circom-rln v1.0.0 Groth16 artifacts in this directory.
//
// Run with the repo's Node:  node circuits/rln/smoke.mjs
//
// What it proves:
//   1. RLN identity creation + registration at userMessageLimit=8 (app K_SLOTS).
//   2. A valid proof for one message verifies true against OUR wasm/zkey/vkey.
//   3. Two proofs at the SAME epoch reusing messageId 0 (same external nullifier,
//      distinct x = signal hash) trip a BREACH in the cache and recover the
//      identitySecret, which must equal the identity's secret.
//
// If this prints "GATE PASSED", the artifacts + rlnjs round-trip on this machine.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  RLN,
  MemoryRLNRegistry,
  MemoryMessageIDCounter,
  Status,
  calculateIdentityCommitment,
} from "rlnjs";
import { poseidon2 } from "poseidon-lite";

const __dir = dirname(fileURLToPath(import.meta.url));
const wasmFilePath = join(__dir, "rln.wasm");
const finalZkeyPath = join(__dir, "rln_final.zkey");
const verificationKey = JSON.parse(
  readFileSync(join(__dir, "verification_key.json"), "utf8"),
);

const RLN_IDENTIFIER = 1n; // app id; any unique bigint
const TREE_DEPTH = 20; // circom-rln RLN(20,16)
const USER_MESSAGE_LIMIT = 8n; // matches packages/node/lib/rln.mjs K_SLOTS=8
const EPOCH = 42n;

function assert(cond, msg) {
  if (!cond) {
    console.error("ASSERT FAILED:", msg);
    RLN.cleanUp();
    process.exit(1);
  }
}

async function main() {
  // Shared registry (the reputation set). One physical member; the receiver
  // verifies/collects proofs from the network.
  const registry = new MemoryRLNRegistry(RLN_IDENTIFIER, TREE_DEPTH);

  // ---- the member (spammer) -------------------------------------------------
  const rln = await RLN.create({
    rlnIdentifier: RLN_IDENTIFIER,
    registry,
    treeDepth: TREE_DEPTH,
    wasmFilePath,
    finalZkeyPath,
    verificationKey,
  });

  // The member's own secret, computed the same way rlnjs computes it internally:
  //   identitySecret = Poseidon(2)([ nullifier, trapdoor ])
  const expectedSecret = poseidon2([
    rln.identity.getNullifier(),
    rln.identity.getTrapdoor(),
  ]);
  console.log("identityCommitment :", rln.identityCommitment.toString());
  console.log("expected secret    :", expectedSecret.toString());
  // Sanity: commitment == Poseidon(1)([identitySecret]).
  assert(
    calculateIdentityCommitment(expectedSecret) === rln.identityCommitment,
    "identity commitment does not match Poseidon(1)([identitySecret])",
  );

  // (1) register at limit 8
  await rln.register(USER_MESSAGE_LIMIT, new MemoryMessageIDCounter(USER_MESSAGE_LIMIT));
  assert(await rln.isRegistered(), "identity not registered after register()");
  console.log("registered with userMessageLimit =", USER_MESSAGE_LIMIT.toString());

  // ---- the receiver (gateway) ----------------------------------------------
  // Independent identity; only its cache + verifier matter. It gathers proofs
  // off the wire via saveProof and detects spam automatically.
  const receiver = await RLN.create({
    rlnIdentifier: RLN_IDENTIFIER,
    registry,
    treeDepth: TREE_DEPTH,
    wasmFilePath,
    finalZkeyPath,
    verificationKey,
  });

  // (2) one valid proof, verify true, and land as VALID in the receiver cache.
  // NOTE: rln.createProof auto-saves to the *member's own* cache and THROWS if a
  // reuse would breach, so the breach must be observed by the receiver instead.
  const proofA = await rln.createProof(EPOCH, "message-A"); // messageId 0
  const okA = await receiver.verifyProof(EPOCH, "message-A", proofA);
  assert(okA === true, "valid proof A did not verify true");
  console.log("proof A verifyProof :", okA);

  const savedA = await receiver.saveProof(proofA);
  assert(savedA.status === Status.VALID, `proof A save status ${savedA.status} != VALID`);
  console.log("proof A saveProof   : VALID");

  // Re-saving the exact same proof is a DUPLICATE, not a breach.
  const savedDup = await receiver.saveProof(proofA);
  assert(savedDup.status === Status.DUPLICATE, `re-save status ${savedDup.status} != DUPLICATE`);
  console.log("proof A re-save     : DUPLICATE");

  // (3) BREACH: a second sender with the SAME identity and a fresh counter
  // reuses messageId 0 at the SAME epoch -> same external/internal nullifier,
  // distinct x (different message) -> secret-sharing collision.
  const rlnSpam = await RLN.create({
    rlnIdentifier: RLN_IDENTIFIER,
    registry,
    identity: rln.identity, // same member identity
    treeDepth: TREE_DEPTH,
    wasmFilePath,
    finalZkeyPath,
    verificationKey,
  });
  await rlnSpam.setMessageIDCounter(new MemoryMessageIDCounter(USER_MESSAGE_LIMIT));
  const proofB = await rlnSpam.createProof(EPOCH, "message-B"); // messageId 0 again

  const savedB = await receiver.saveProof(proofB);
  console.log("proof B saveProof   :", Status[savedB.status]);
  assert(savedB.status === Status.BREACH, `proof B save status ${savedB.status} != BREACH`);
  assert(savedB.secret !== undefined, "BREACH did not return a recovered secret");

  console.log("recovered secret   :", savedB.secret.toString());
  assert(
    savedB.secret === expectedSecret,
    "recovered secret != identity secret",
  );
  // And it must reconstruct the same leaf commitment.
  assert(
    calculateIdentityCommitment(savedB.secret) === rln.identityCommitment,
    "recovered secret does not derive the identity commitment",
  );

  console.log("\nGATE PASSED: rlnjs@3.3.0 full round-trip green against local circom-rln artifacts.");
  RLN.cleanUp();
  process.exit(0);
}

main().catch((e) => {
  console.error("GATE FAILED (exception):", e);
  RLN.cleanUp();
  process.exit(1);
});
