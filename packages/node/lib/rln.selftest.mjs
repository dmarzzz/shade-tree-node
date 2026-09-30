// Self-test for packages/node/lib/rln.mjs — the REAL RLN circuit path. Run: `node packages/node/lib/rln.selftest.mjs`
// No chain, no network: builds an in-memory RLN group, produces real Groth16 proofs
// against circuits/rln/{rln.wasm,rln_final.zkey,verification_key.json}, and asserts the
// crypto invariants the demo's correctness rests on. Calls RLN.cleanUp() at the end so
// the snarkjs worker threads exit.

import {
  FIELD,
  K_SLOTS,
  RLN_IDENTIFIER,
  currentEpoch,
  EPOCH_SECONDS,
  requestSignal,
  externalNullifierFor,
  reconstructSecret,
  deriveCommitment,
  identityFor,
  identitySecretOf,
  rateCommitmentOf,
  proveForSlot,
  verifyEnvelope,
  groupFromIdentities,
  toField,
  cleanUp,
  calculateRateCommitment,
} from "./rln.mjs";

let pass = 0;
const fail = [];
function ok(name, cond) {
  if (cond) { pass++; console.log("  ok  " + name); }
  else { fail.push(name); console.log("FAIL  " + name); }
}

async function main() {
  const epoch = currentEpoch();
  // Pin "now" to a fixed point inside `epoch` and pass it to every verifyEnvelope call. Proof
  // generation takes seconds, so without this a real epoch-boundary rollover mid-test would make
  // the "accepts one-epoch skew" case (proved at epoch-1, verified at wall-clock now) intermittently
  // fail when `now` crossed into epoch+1. Deterministic clock => no flake.
  const nowMs = Number(epoch) * EPOCH_SECONDS * 1000 + 1000;

  // Canonical field-element secrets (0x-hex) for a small group; `secret` is the member.
  const secret = toField("0x" + "b96d0584614e2d620d19601d278b93278bf0a2479d2bf0ab2d5ec3ae36960f53");
  const other1 = toField("0x" + "11".repeat(32));
  const other2 = toField("0x" + "22".repeat(32));

  const idMember = identityFor(secret);
  const idA = identityFor(other1);
  const idB = identityFor(other2);
  // member sits at index 2; the group holds real rateCommitment leaves.
  const group = groupFromIdentities([idA, idB, idMember]);

  const memberLeaf = rateCommitmentOf(idMember).toString();
  const identitySecret = identitySecretOf(idMember);

  // ---- 1. good envelope: proveForSlot -> verifyEnvelope accepts -------------
  const i = 5;
  const sig = requestSignal("example.com:443", "req-good");
  const p = await proveForSlot(secret, epoch, i, sig, { group });
  ok("proveForSlot returns a proof + share + nullifier",
    !!(p && p.proof && p.share && p.nullifier && p.externalNullifier));
  ok("proof's public root == group root",
    p.proof.snarkProof.publicSignals.root === group.root.toString());
  ok("externalNullifier == externalNullifierFor(epoch)",
    p.externalNullifier === externalNullifierFor(epoch).toString());

  const env = {
    v: 4,
    target: "example.com:443",
    nonce: "req-good", // matches the signal proved above, so the target binding holds
    proof: p.proof,
    nullifier: p.nullifier,
    externalNullifier: p.externalNullifier,
    share: p.share,
  };
  const recentRoots = new Set([group.root.toString()]); // gateway keeps a Set
  const res = await verifyEnvelope(env, recentRoots, nowMs);
  ok("verifyEnvelope accepts a good envelope", res.ok === true);
  ok("verifyEnvelope echoes authoritative nullifier", res.nullifier === p.nullifier);
  ok("verifyEnvelope echoes the share", res.share.x === p.share.x && res.share.y === p.share.y);

  // ---- 2. over-spend: same identity+epoch+messageId, DIFFERENT signals ------
  // -> two shares -> reconstruct identitySecret -> deriveCommitment == the leaf.
  const sigA = requestSignal("example.com:443", "spam-A");
  const sigB = requestSignal("example.com:443", "spam-B");
  const pA = await proveForSlot(secret, epoch, i, sigA, { group });
  const pB = await proveForSlot(secret, epoch, i, sigB, { group });
  ok("same slot+epoch => same nullifier", pA.nullifier === pB.nullifier);
  ok("different signals => different share.x", pA.share.x !== pB.share.x);

  const recovered = reconstructSecret(pA.share, pB.share);
  ok("two shares reconstruct the identitySecret", recovered === identitySecret.toString());
  ok("deriveCommitment(recovered) == member's leaf", deriveCommitment(recovered) === memberLeaf);
  ok("deriveCommitment(recovered) == rlnjs getRateCommitment()",
    deriveCommitment(recovered) === calculateRateCommitment(idMember.commitment, BigInt(K_SLOTS)).toString());

  // ---- 3. retry (same secret/epoch/slot/signal) reproduces share+nullifier --
  const pRetry = await proveForSlot(secret, epoch, i, sigA, { group });
  ok("retry reproduces identical share (no new info)",
    pRetry.share.x === pA.share.x && pRetry.share.y === pA.share.y);
  ok("retry reproduces identical nullifier", pRetry.nullifier === pA.nullifier);
  let threw = false;
  try { reconstructSecret(pA.share, pRetry.share); } catch { threw = true; }
  ok("identical-x shares cannot reconstruct", threw);

  // ---- 4. K distinct messageIds => K distinct nullifiers in one epoch -------
  const nulls = new Set();
  for (let m = 0; m < K_SLOTS; m++) {
    const pm = await proveForSlot(secret, epoch, m, requestSignal("h:1", "const"), { group });
    nulls.add(pm.nullifier);
  }
  ok("K distinct messageIds => K distinct nullifiers", nulls.size === K_SLOTS);

  // ---- 5. verifyEnvelope rejects tampered envelopes ------------------------
  const badRoot = await verifyEnvelope(env, new Set(["999"]), nowMs);
  ok("rejects wrong root", badRoot.ok === false && badRoot.reason === "wrong-group-root");

  const envXmismatch = { ...env, share: { x: "1234", y: env.share.y } };
  const badX = await verifyEnvelope(envXmismatch, recentRoots, nowMs);
  ok("rejects share.x != proof x", badX.ok === false && badX.reason === "signal-mismatch");

  // 2b. target binding: a captured proof re-submitted with a DIFFERENT target is rejected, so a
  // malicious gateway cannot redirect a member's proof to another destination.
  const targetSwap = await verifyEnvelope({ ...env, target: "evil.example:443" }, recentRoots, nowMs);
  ok("rejects a swapped target (proof not bound to it)", targetSwap.ok === false && targetSwap.reason === "target-not-bound");
  const nonceSwap = await verifyEnvelope({ ...env, nonce: "different" }, recentRoots, nowMs);
  ok("rejects a swapped nonce", nonceSwap.ok === false && nonceSwap.reason === "target-not-bound");
  const noNonce = await verifyEnvelope({ ...env, nonce: undefined }, recentRoots, nowMs);
  ok("fails closed when the nonce is missing (target unverifiable)", noNonce.ok === false && noNonce.reason === "unbound-target");

  // 2b defense-in-depth: the signal is newline-delimited, so a target/nonce carrying the delimiter
  // (or an unbounded nonce) is rejected BEFORE hashing, keeping (target,nonce)->signal injective.
  const nlTarget = await verifyEnvelope({ ...env, target: "a.com:443\nx" }, recentRoots, nowMs);
  ok("rejects a target containing the delimiter (injection) before hashing", nlTarget.reason === "bad-signal-field");
  const nlNonce = await verifyEnvelope({ ...env, nonce: "req\ngood" }, recentRoots, nowMs);
  ok("rejects a nonce containing the delimiter", nlNonce.reason === "bad-signal-field");
  const bigNonce = await verifyEnvelope({ ...env, nonce: "z".repeat(500) }, recentRoots, nowMs);
  ok("rejects an over-long nonce (hasher-abuse guard)", bigNonce.reason === "bad-signal-field");

  // stale externalNullifier: prove for an ancient epoch, then verify at `now`.
  const staleP = await proveForSlot(secret, epoch - 10n, i, sig, { group });
  const staleEnv = { ...env, proof: staleP.proof, externalNullifier: staleP.externalNullifier, share: staleP.share };
  const badEpoch = await verifyEnvelope(staleEnv, recentRoots, nowMs);
  ok("rejects stale externalNullifier", badEpoch.ok === false && badEpoch.reason === "stale-external-nullifier");

  // one-epoch skew IS accepted (prove at previous epoch, verify now).
  const prevP = await proveForSlot(secret, epoch - 1n, i, sig, { group });
  const prevEnv = { ...env, proof: prevP.proof, externalNullifier: prevP.externalNullifier, share: prevP.share };
  const prevRes = await verifyEnvelope(prevEnv, recentRoots, nowMs);
  ok("accepts one-epoch skew (previous epoch)", prevRes.ok === true);

  // ---- 6. field sanity ------------------------------------------------------
  ok("FIELD is the BN254 scalar prime", FIELD % 2n === 1n && FIELD > 2n ** 253n);
  ok("RLN_IDENTIFIER is a bigint", typeof RLN_IDENTIFIER === "bigint");

  console.log(`\n${pass} passed, ${fail.length} failed`);
  cleanUp();
  if (fail.length) { console.error("FAILURES:", fail); process.exit(1); }
}

main().catch((e) => {
  console.error("SELFTEST THREW:", e);
  cleanUp();
  process.exit(1);
});
