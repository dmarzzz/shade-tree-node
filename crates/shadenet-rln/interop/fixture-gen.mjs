// RLN interop fixture generator (T-RUST-2b RLN-INTEROP).
//
// Emits, for a FIXED test identity/epoch/messageId/target and a (CLI-overridable)
// nonce, everything the Rust probe needs to prove against the repo's circom-rln
// artifacts and everything needed to check its output against the rlnjs reference:
//   - circuit witness inputs (identitySecret, userMessageLimit, messageId,
//     pathElements[20], identityPathIndex[20], x, externalNullifier),
//   - the merkle root, rlnIdentifier, epoch,
//   - rlnjs's OWN reference public signals (y,root,nullifier,x,externalNullifier)
//     from proveForSlot, so the Rust proof's public signals can be asserted equal.
//
// Usage: node fixture-gen.mjs [nonceHex] > fixture.json
import {
  identityFor, identitySecretOf, rateCommitmentOf, newGroup,
  externalNullifierFor, requestSignal, proveForSlot, K_SLOTS, RLN_IDENTIFIER,
  calculateSignalHash, cleanUp,
} from "../../../lib/rln.mjs";

const SECRET = "12345678901234567890"; // fixed app seed secret (field element)
const EPOCH = 42n;
// Reputation tier (T-FEAT-8): SHADE_TREE_INTEROP_LIMIT / SHADE_TREE_INTEROP_SLOT let run.sh also drive a
// tier-32 leaf at a slot >= 8 (the leaf commits to the limit; default = K_SLOTS, slot 3).
const LIMIT = Number(process.env.SHADE_TREE_INTEROP_LIMIT || K_SLOTS);
const MESSAGE_ID = Number(process.env.SHADE_TREE_INTEROP_SLOT || 3); // slot i, 0<=i<LIMIT
const TARGET = "example.com:443";
const NONCE = process.argv[2] || "0123456789abcdef0123456789abcdef";

const identity = identityFor(SECRET);
const identitySecret = identitySecretOf(identity);
const leaf = rateCommitmentOf(identity, LIMIT);
const group = newGroup([leaf]); // single-member group; member at index 0
const index = group.indexOf(leaf);
const mp = group.generateMerkleProof(index);

const signal = requestSignal(TARGET, NONCE);
const x = calculateSignalHash(signal);
const extNull = externalNullifierFor(EPOCH);

// rlnjs reference proof (its own public signals) for the SAME inputs.
const ref = await proveForSlot(SECRET, EPOCH, MESSAGE_ID, signal, { group, limit: LIMIT });

// arity-2 IMT siblings are flat field elements; normalize defensively.
const pathElements = mp.siblings.map((s) => (Array.isArray(s) ? s[0] : s)).map(String);
const identityPathIndex = mp.pathIndices.map(Number);

console.log(JSON.stringify({
  secret: SECRET,
  epoch: String(EPOCH),
  rlnIdentifier: String(RLN_IDENTIFIER),
  userMessageLimit: String(LIMIT),
  messageId: String(MESSAGE_ID),
  target: TARGET,
  nonce: NONCE,
  signal,
  identitySecret: String(identitySecret),
  leaf: String(leaf),
  root: String(mp.root),
  pathElements,
  identityPathIndex,
  x: String(x),
  externalNullifier: String(extNull),
  ref_publicSignals: {
    y: String(ref.share.y),
    root: String(mp.root),
    nullifier: String(ref.nullifier),
    x: String(ref.share.x),
    externalNullifier: String(ref.externalNullifier),
  },
}, null, 2));
cleanUp();
