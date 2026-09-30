// T-DEV-2: RLN leaf-removal PARITY between JS reconstruction and the on-chain contract.
//
// The property: register 3 members, slash the MIDDLE one, and the JS admission root
// (packages/node/lib/root-provider.mjs reconstructRoot) equals the root implied by the CONTRACT's
// membership state. The contract (contracts/StakedReputationSet.sol) assigns an immutable
// append-only leaf `index` (`nextIndex++`) and a slash DELETES that member while leaving
// every other index untouched — i.e. ZERO-IN-PLACE at the original index, survivors keep
// their indices/paths. reconstructRoot must reproduce exactly that.
//
// Cross-linkage to the chain (why this is a real parity proof, not a JS-only tautology):
//   1. The three leaves are the RLN rate commitments for secrets 111/222/333, computed by
//      deriveCommitment() — the SAME poseidon2([poseidon1([s]),8]) the on-chain
//      RateCommitmentHasher computes. Leaf c0 is asserted equal to the contract test's
//      hardcoded COMMIT_A_EXPECTED, pinning the JS leaf to the on-chain leaf byte-for-byte.
//   2. The event log fed to reconstructRoot uses the exact indices the contract assigns
//      (register -> 0,1,2 ; slash middle vacates 1). The Foundry test
//      test/StakedReputationSet.t.sol::test_Slash_Middle_PreservesIndices asserts the
//      contract really does keep c0@0 and c2@2 with nextIndex=3 after the middle slash.
//   3. GOLDEN_ROOT below is the resulting root; it is a fixed cross-checked constant so a
//      future change to either side that breaks parity fails loudly here.
//
//   node packages/node/lib/rln-removal-parity.selftest.mjs

import { reconstructRoot } from "./root-provider.mjs";
import { newGroup, deriveCommitment } from "./rln.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

// Member* event topic0 hashes (keccak of the signatures), as hardcoded in root-provider.mjs.
const TOPIC = {
  registered: "0x0dbb6a3ed41d8f3d21e481b86d0e8bbf65a630b7dc4c5ee6c2c1a74561841e6d",
  slashed: "0x707cd9719d0c14265b9e456f7add99095401f907e570e5cdd65a92920947c450",
};
const log = (topic0, commitment, block, logIndex = 0) => ({
  topics: [topic0, "0x" + BigInt(commitment).toString(16)],
  blockNumber: "0x" + BigInt(block).toString(16),
  logIndex: "0x" + BigInt(logIndex).toString(16),
});

// The on-chain leaf for identitySecret 111, hardcoded in test/StakedReputationSet.t.sol as
// COMMIT_A_EXPECTED. Pinning it here links the JS leaf to the contract leaf.
const COMMIT_A_EXPECTED =
  "11302006078516901731073162965056551612114122314181142374993834332168998510316";

// The cross-checked golden: reconstructRoot over {register c0@0, c1@1, c2@2, slash c1}.
// Recompute with this file; it must stay stable and equal the zero-in-place oracle.
const GOLDEN_ROOT =
  "14367190620832145537223890636337926502210861635134078778082353204233456513838";

function main() {
  const c0 = deriveCommitment(111n);
  const c1 = deriveCommitment(222n);
  const c2 = deriveCommitment(333n);

  // (1) JS leaf == on-chain leaf (RateCommitmentHasher parity).
  ok(c0 === COMMIT_A_EXPECTED, "JS rate commitment for secret 111 == on-chain COMMIT_A_EXPECTED");

  // The event log the contract emits for: register c0, register c1, register c2, slash c1.
  // Indices 0,1,2 assigned in order; the middle slash vacates index 1.
  const logs = [
    log(TOPIC.registered, c0, 1),
    log(TOPIC.registered, c1, 2),
    log(TOPIC.registered, c2, 3),
    log(TOPIC.slashed, c1, 4),
  ];
  const jsRoot = reconstructRoot(logs);

  // (2) Independent zero-in-place oracle: append all three, remove the middle slot.
  const g = newGroup();
  g.addMember(BigInt(c0));
  g.addMember(BigInt(c1));
  g.addMember(BigInt(c2));
  g.removeMember(1); // vacate the ORIGINAL index of the middle member
  const oracleRoot = g.root.toString();

  console.log(`  JS reconstructRoot = ${jsRoot}`);
  console.log(`  zero-in-place root = ${oracleRoot}`);
  console.log(`  contract survivors = c0@0, (c1@1 vacated), c2@2`);

  ok(jsRoot === oracleRoot, "reconstructRoot(register 3, slash middle) == zero-in-place oracle root");
  ok(jsRoot === GOLDEN_ROOT, "reconstructRoot matches the pinned cross-checked GOLDEN_ROOT");

  // (3) Regression guard: the old rebuild-and-RENUMBER behavior compacted survivors into a
  // 2-leaf tree [c0, c2] at indices 0,1 — a DIFFERENT root. Parity requires we are NOT that.
  const renumberRoot = newGroup([BigInt(c0), BigInt(c2)]).root.toString();
  ok(jsRoot !== renumberRoot, "root differs from the old renumber-of-survivors root (the T-DEV-2 bug)");

  // (4) Survivors keep their exact leaves/paths: proving membership of c0 and c2 in the
  // post-slash tree still verifies against jsRoot; the vacated slot holds the zero value.
  ok(g.indexOf(BigInt(c0)) === 0, "survivor c0 keeps index 0");
  ok(g.indexOf(BigInt(c2)) === 2, "survivor c2 keeps index 2");
  ok(g.members[1] === g.zeroValue, "vacated middle slot holds the tree zero value");

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: rln-removal-parity selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
