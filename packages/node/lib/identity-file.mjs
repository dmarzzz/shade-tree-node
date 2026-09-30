// identity-file: the ONE place the Rust client's `--identity` file is derived and serialized.
//
// The Rust `shade-tree egress` (crates/shadenet-cli, `--features live`) does not derive an identity from
// the app secret; it takes the two field elements it needs as inputs:
//
//   { "identitySecret": "<dec>",   // Semaphore-v3 identitySecret = Poseidon2(nullifier, trapdoor)
//     "leaf":           "<dec>" }  // RLN rateCommitment = Poseidon2(Poseidon1(identitySecret), K)
//
// Both come from the JS reference (packages/node/lib/rln.mjs): identityFor(secret) is the SAME derivation the
// JS client's proveForSlot uses, and rateCommitmentOf() is the SAME leaf `shade-tree enroll` publishes
// and the on-chain slash names. So a member's Rust and JS clients are the same member, and the
// leaf here is exactly the entry in group/members.json.
//
// Consumers: `shade-tree identity` (group/identity.mjs, the operator/member-facing command) and the
// Rust interop harness (crates/shadenet-rln/interop/egress-derive.mjs). They MUST agree byte-for-byte,
// which is why the serialization lives here too and group/identity.selftest.mjs pins both.
//
// NOTE: the leaf depends on the member's tier limit (T-FEAT-8; default K = SHADE_TREE_SLOTS = 8) exactly
// like every other rateCommitment in the system — derive with the limit the leaf was enrolled with,
// or the leaf will not be in the tree. A NON-default limit is written as a third field,
//   { "identitySecret": ..., "leaf": ..., "limit": 32 }
// which the Rust client reads as its default `--k`. At the default limit the field is OMITTED, so
// every pre-tier identity file is byte-identical (Rust treats a missing `limit` as K_SLOTS).

import { identityFor, identitySecretOf, rateCommitmentOf, K_SLOTS, normLimit } from "./rln.mjs";

// identityFileFor(secret, limit = K_SLOTS) -> { identitySecret, leaf[, limit] } (decimal strings,
// as the Rust side parses; `limit` a Number, present only when != K_SLOTS).
// `secret` is the app secret (0x-hex or decimal; toField() normalizes it) — the SHADE_TREE_SECRET value.
export function identityFileFor(secret, limit = K_SLOTS) {
  if (typeof secret !== "string" || secret.trim() === "") throw new Error("identityFileFor: empty secret");
  const lim = Number(normLimit(limit));
  const identity = identityFor(secret.trim());
  const file = {
    identitySecret: identitySecretOf(identity).toString(),
    leaf: rateCommitmentOf(identity, lim).toString(),
  };
  if (lim !== K_SLOTS) file.limit = lim;
  return file;
}

// The exact on-disk bytes: 2-space JSON + trailing newline (what the harness has always written,
// what the Rust client parses). Key order is fixed by construction above; `limit` last, and only
// when the file carries a non-default tier.
export function serializeIdentityFile(file) {
  const out = { identitySecret: file.identitySecret, leaf: file.leaf };
  if (file.limit != null && Number(file.limit) !== K_SLOTS) out.limit = Number(file.limit);
  return JSON.stringify(out, null, 2) + "\n";
}
