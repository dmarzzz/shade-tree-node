// Layer-2 acceptance (the real interop criterion): assemble the wire envelope from
// the RUST-generated proof exactly as client/shade-tree-client.mjs buildEnvelope does, and
// assert lib/rln.mjs verifyEnvelope ACCEPTS it — including check 2b target-binding
// (recomputing x from the envelope's target+nonce) and the Groth16 verify against the
// repo's verification_key.json.
//
// Usage: node verify-envelope.mjs <rust-envelope.json>
import { readFileSync } from "node:fs";
import { verifyEnvelope, EPOCH_SECONDS, cleanUp } from "../../../lib/rln.mjs";

const r = JSON.parse(readFileSync(process.argv[2], "utf8"));

const envelope = {
  v: 4,
  target: r.target,
  nonce: r.nonce,
  proof: {
    snarkProof: { proof: r.proof, publicSignals: r.publicSignals },
    epoch: r.epoch,
    rlnIdentifier: r.rlnIdentifier,
  },
  nullifier: r.nullifier,
  externalNullifier: r.externalNullifier,
  share: r.share,
};
// T-HARD-8: a Rust envelope may name the artifact set it proved with; the JS gateway resolves
// it against its accepted set (absent => legacy/built-in id, as before).
if (r.artifact) envelope.artifact = r.artifact;

// The proof was built for epoch=r.epoch; pin nowMs so currentEpoch(nowMs) == that epoch
// (verifyEnvelope check-1 accepts this-or-last epoch's external nullifier).
const nowMs = Number(BigInt(r.epoch) * BigInt(EPOCH_SECONDS) * 1000n);
const recentRoots = [r.publicSignals.root];

const res = await verifyEnvelope(envelope, recentRoots, nowMs);
console.log("verifyEnvelope ->", JSON.stringify(res));
if (!res.ok) {
  console.error("FAIL: verifyEnvelope rejected the Rust envelope:", res.reason);
  cleanUp();
  process.exit(1);
}
const okFields =
  res.nullifier === r.nullifier &&
  res.externalNullifier === r.externalNullifier &&
  res.share.x === r.share.x &&
  res.share.y === r.share.y;
console.log(okFields
  ? "PASS: verifyEnvelope ACCEPTED the Rust envelope (authoritative fields match)."
  : "WARN: accepted but returned fields differ.");
cleanUp();
process.exit(okFields ? 0 : 1);
