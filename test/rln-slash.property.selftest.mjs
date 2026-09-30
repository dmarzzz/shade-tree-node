// Property test for the RLN slash math in packages/node/lib/rln.mjs. Run: `node test/rln-slash.property.selftest.mjs`
// No chain, no network: builds an in-memory RLN group, produces REAL Groth16 proofs against
// circuits/rln/{rln.wasm,rln_final.zkey,verification_key.json}, and asserts the Shamir-slash
// invariants over MANY randomized rounds. Same house style as packages/node/lib/rln.selftest.mjs (ok/failures
// counter, PASS/FAIL summary, cleanUp() so the snarkjs worker threads exit).
//
// The slash property, restated per round over random (epoch, slot, nonce):
//   1. Two DISTINCT signals on the SAME (secret, epoch, slot) => same nullifier, distinct share.x,
//      and reconstructSecret(a,b) === the member's identitySecret, whose deriveCommitment() === leaf.
//      (An over-spend always reveals EXACTLY the right secret — the thing a gateway slashes.)
//   2. One signal alone can never reconstruct (a single share is one point on the line).
//   3. Two shares from DIFFERENT nullifiers (different slot, or different member) must NOT
//      reconstruct the secret — cross-nullifier interpolation is meaningless.
//   4. Identical shares (same x) cannot reconstruct (throws) — an honest replay is never a slash.
//
// NOTE ON COST: each real Groth16 proof is ~0.4s and is serialized behind rln.mjs's snark mutex,
// and each round makes ~4-5 proofs. We therefore CAP at ROUNDS = 15 (~30-40s wall). This is a
// property test, not a fuzzing farm; 15 randomized rounds is plenty to exercise the invariant.

import {
  currentEpoch,
  requestSignal,
  proveForSlot,
  reconstructSecret,
  deriveCommitment,
  identityFor,
  identitySecretOf,
  rateCommitmentOf,
  groupFromIdentities,
  toField,
  K_SLOTS,
  cleanUp,
} from "../packages/node/lib/rln.mjs";

let pass = 0;
let failures = 0;
function ok(cond, msg) {
  if (cond) { pass++; console.log("  ok  " + msg); }
  else { failures++; console.log("FAIL  " + msg); }
}

const ROUNDS = 15; // capped: real proofs ~0.4s each, ~4-5 per round (see NOTE ON COST above)
const randInt = (n) => Math.floor(Math.random() * n);

async function main() {
  const seed = Date.now();
  console.log(`# RLN slash property test — ${ROUNDS} rounds, seed(log)=${seed}`);

  // Small group: the member under test + two decoys, all with real rateCommitment leaves.
  const secret = toField("0x" + "b96d0584614e2d620d19601d278b93278bf0a2479d2bf0ab2d5ec3ae36960f53");
  const decoy1 = toField("0x" + "11".repeat(32));
  const decoy2 = toField("0x" + "22".repeat(32));

  const idMember = identityFor(secret);
  const idD1 = identityFor(decoy1);
  const idD2 = identityFor(decoy2);
  const group = groupFromIdentities([idD1, idMember, idD2]);

  const memberLeaf = rateCommitmentOf(idMember).toString();
  const identitySecret = identitySecretOf(idMember).toString();

  for (let r = 0; r < ROUNDS; r++) {
    // Randomize the epoch, slot, and both nonces this round.
    const epoch = currentEpoch() - BigInt(randInt(3));   // this / previous epochs
    const slot = randInt(K_SLOTS);                        // 0 <= slot < K
    const nonceA = "spend-A-" + randInt(1e9);
    let nonceB = "spend-B-" + randInt(1e9);
    if (nonceB === nonceA) nonceB += "x";               // ensure distinct signals
    const tag = `r${r}(epoch=${epoch},slot=${slot})`;

    const sigA = requestSignal("example.com:443", nonceA);
    const sigB = requestSignal("example.com:443", nonceB);

    // --- Property 1: over-spend on the SAME (secret, epoch, slot) reveals the secret --------
    const pA = await proveForSlot(secret, epoch, slot, sigA, { group });
    const pB = await proveForSlot(secret, epoch, slot, sigB, { group });

    ok(pA.nullifier === pB.nullifier, `${tag}: same (epoch,slot) => same nullifier`);
    ok(pA.share.x !== pB.share.x, `${tag}: distinct signals => distinct share.x`);

    const recovered = reconstructSecret(pA.share, pB.share);
    ok(recovered === identitySecret, `${tag}: two shares reconstruct the member's identitySecret`);
    ok(deriveCommitment(recovered) === memberLeaf, `${tag}: deriveCommitment(recovered) === member's leaf`);

    // --- Property 2: one share alone can never reconstruct ---------------------------------
    // A single (x,y) point underdetermines the degree-1 line; the only "reconstruct" call you
    // can make from one share is with itself, and identical-x must throw (never yields a secret).
    let oneShareReconstructed = false;
    try { reconstructSecret(pA.share, pA.share); oneShareReconstructed = true; } catch { /* expected */ }
    ok(!oneShareReconstructed, `${tag}: a single share alone cannot reconstruct`);

    // --- Property 3: two shares from DIFFERENT nullifiers must NOT recover the secret -------
    // 3a. Same member, DIFFERENT slot => different nullifier.
    let otherSlot = randInt(K_SLOTS);
    if (otherSlot === slot) otherSlot = (slot + 1) % K_SLOTS;
    const pOtherSlot = await proveForSlot(secret, epoch, otherSlot, sigB, { group });
    ok(pOtherSlot.nullifier !== pA.nullifier, `${tag}: different slot => different nullifier`);
    let crossSlot;
    let crossSlotThrew = false;
    try { crossSlot = reconstructSecret(pA.share, pOtherSlot.share); } catch { crossSlotThrew = true; }
    ok(crossSlotThrew || crossSlot !== identitySecret,
      `${tag}: cross-slot shares do NOT reconstruct the secret`);

    // 3b. DIFFERENT member (a decoy), same slot => different nullifier + different secret.
    const pDecoy = await proveForSlot(decoy1, epoch, slot, sigB, { group });
    ok(pDecoy.nullifier !== pA.nullifier, `${tag}: different member => different nullifier`);
    let crossMember;
    let crossMemberThrew = false;
    try { crossMember = reconstructSecret(pA.share, pDecoy.share); } catch { crossMemberThrew = true; }
    ok(crossMemberThrew || crossMember !== identitySecret,
      `${tag}: cross-member shares do NOT reconstruct the member's secret`);

    // --- Property 4: identical shares (same x) cannot reconstruct — honest replay is no slash -
    const pReplay = await proveForSlot(secret, epoch, slot, sigA, { group });
    ok(pReplay.share.x === pA.share.x && pReplay.share.y === pA.share.y,
      `${tag}: honest replay reproduces the identical share`);
    let replayThrew = false;
    try { reconstructSecret(pA.share, pReplay.share); } catch { replayThrew = true; }
    ok(replayThrew, `${tag}: identical-x replay shares cannot reconstruct (throws)`);
  }

  console.log(`\n${failures ? "FAIL" : "PASS"} — ${pass} passed, ${failures} failed over ${ROUNDS} rounds`);
  cleanUp();
  process.exit(failures ? 1 : 0);
}

main().catch((e) => {
  console.error("SELFTEST THREW:", e);
  cleanUp();
  process.exit(1);
});
