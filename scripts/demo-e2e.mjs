// End-to-end demo of the RLN loop, against a real anvil + real crypto.
//
// Exercises increments A+B+C from docs/NEXT-VERSION.md WITHOUT Tor (the tunnel is the
// existing PoC path; this script proves the staking/slashing/rotation protocol):
//   1. stake two members on-chain (register + bond),
//   2. anonymous egress-gate: real RLN membership proof per slot, rotating slots
//      => distinct unlinkable nullifiers (increment B),
//   3. force a slot over-spend: reuse a slot (messageId) in the same epoch with a new
//      signal => same nullifier, different x; the gateway collects two shares,
//      reconstructs the identitySecret, and SLASHES the over-spender's bond (increment C),
//   4. replay of the same signal is deduped, NOT slashed (increment A invariant),
//   5. the clean member's time-locked exit: withdraw blocked before U, allowed after.
//
// SINGLE-LEAF model (retained by the rln-v4 contracts): there is ONE leaf per member — the rateCommitment
//   rateCommitment = Poseidon(2)([ Poseidon(1)([identitySecret]), K ])
// It is BOTH the membership-tree leaf the RLN proof is against AND the on-chain staked
// leaf. A slash reveals the member's identitySecret (not the app seed), and
// deriveCommitment(identitySecret) == the on-chain hasher.commitmentOf(identitySecret)
// == that same leaf. The v2 two-view split (Semaphore identity Group + a separate
// Poseidon(secret) on-chain leaf) is GONE.
//
// Prereqs: anvil running + `forge script script/Deploy.s.sol:Deploy` done (deployed.local.json).
// Run:  node scripts/demo-e2e.mjs   (proving is ~0.4s/proof, so this takes ~15-30s)

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { ethers } from "ethers";
import {
  identityFor, identitySecretOf, deriveCommitment, groupFromIdentities, newGroup,
  rateCommitmentOf, currentEpoch, requestSignal, proveForSlot, verifyEnvelope,
  reconstructSecret, toField, cleanUp,
} from "../lib/rln.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const dep = JSON.parse(readFileSync(join(HERE, "..", "contracts", "deployed.local.json"), "utf8"));
const RPC = process.env.SHADE_TREE_RPC_URL || dep.rpcUrl || "http://127.0.0.1:8545";
const ADDR = dep.stakedReputationSet;

const ABI = [
  "function BOND() view returns (uint256)",
  "function UNBONDING() view returns (uint256)",
  "function activeCount() view returns (uint256)",
  "function members(uint256) view returns (uint256 bond, uint64 index, uint64 exitInitiatedAt, uint32 limit)",
  "function register(uint256 commitment) payable", // == register(commitment, 8): the default tier (T-FEAT-8b)
  "function initiateExit(uint256 commitment, bytes proof)",
  "function withdraw(uint256 commitment, address recipient, bytes proof)",
  "function slash(uint256 commitment, uint256 secret, address receiver)",
];

// anvil well-known keys
const K0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"; // deployer / member funder
const K1 = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"; // gateway slasher hot key

const provider = new ethers.JsonRpcProvider(RPC);
const funder = new ethers.Wallet(K0, provider);
const slasher = new ethers.Wallet(K1, provider);

// The exit-auth proof for MockWithdrawVerifier is a REVEALED identitySecret:
// proof = abi.encode(uint256 identitySecret), authorized iff
// hasher.commitmentOf(identitySecret) == leaf (the rateCommitment). NOT the app seed.
const enc = (identitySecret) => ethers.AbiCoder.defaultAbiCoder().encode(["uint256"], [BigInt(toField(identitySecret))]);

// A member's identitySecret + rateCommitment leaf from the app seed.
const idsecOf = (seed) => identitySecretOf(identityFor(seed));
const leafOf = (seed) => deriveCommitment(idsecOf(seed)); // string; == rateCommitmentOf(identityFor(seed))

let PASS = 0, FAIL = 0;
const ok = (c, m) => { if (c) { PASS++; console.log(`  ✓ ${m}`); } else { FAIL++; console.log(`  ✗ ${m}`); } };
const h = (s) => console.log(`\n── ${s}`);

async function reverts(p) {
  try { await p; return false; } catch { return true; }
}

async function main() {
  const set = new ethers.Contract(ADDR, ABI, funder);
  const BOND = await set.BOND();
  const UNBONDING = Number(await set.UNBONDING());
  console.log(`gateway/set @ ${ADDR}  bond=${ethers.formatEther(BOND)} ETH  unbonding=${UNBONDING}s  epoch=${currentEpoch()}`);

  // Two members; secrets are canonical field elements (member-generated, self-enrollment).
  const secretA = 0x1111111111111111111111111111111111111111111111111111111111n;
  const secretB = 0x2222222222222222222222222222222222222222222222222222222222n;
  const idA = identityFor(secretA), idB = identityFor(secretB);
  const idsecA = idsecOf(secretA), idsecB = idsecOf(secretB);
  // a couple of extra decoys so the membership anonymity set isn't 2
  const decoyIds = [3n, 4n, 5n].map((s) => identityFor(s));

  // ONE leaf per member = the rateCommitment. The SAME value is the RLN-tree leaf and
  // the on-chain staked leaf. Group built from the identities' rateCommitments so the
  // JS root == the circuit root the proofs are generated against.
  const group = groupFromIdentities([idA, idB, ...decoyIds]);
  const membershipRoots = [group.root.toString()];

  // On-chain staked leaves == the rateCommitments (identical to the group leaves).
  const commA = leafOf(secretA);
  const commB = leafOf(secretB);
  ok(commA === rateCommitmentOf(idA).toString(), "member A leaf == rateCommitment (single-leaf model)");
  ok(group.indexOf(BigInt(commA)) !== -1, "member A's rateCommitment IS the group leaf (one tree, one leaf)");

  h("1. stake two members on-chain (register + bond)");
  await (await set.register(commA, { value: BOND })).wait();
  await (await set.register(commB, { value: BOND })).wait();
  ok((await set.activeCount()) === 2n, "activeCount == 2 after two registrations");
  ok((await set.members(commA)).bond === BOND, "member A bond staked");

  h("2. anonymous egress-gate + slot rotation (increment B)");
  const epoch = currentEpoch();
  // tunnel 1: member A, slot 0
  const sig1 = requestSignal("example.com:443", "req-1");
  const env1 = await pack(await proveForSlot(secretA, epoch, 0, sig1, { group }), "example.com:443", "req-1");
  const v1 = await verifyEnvelope(env1, membershipRoots);
  ok(v1.ok, `tunnel 1 verifies (nullifier ${short(v1.nullifier)})`);
  // tunnel 2: member A, slot 1 -> DIFFERENT nullifier (unlinkable to tunnel 1)
  const sig2 = requestSignal("api.other.com:443", "req-2");
  const env2 = await pack(await proveForSlot(secretA, epoch, 1, sig2, { group }), "api.other.com:443", "req-2");
  const v2 = await verifyEnvelope(env2, membershipRoots);
  ok(v2.ok && v2.nullifier !== v1.nullifier, `tunnel 2 verifies with a DISTINCT nullifier (${short(v2.nullifier)}) => unlinkable rotation`);
  // member B, slot 0 -> valid member, different person
  const envB = await pack(await proveForSlot(secretB, epoch, 0, requestSignal("x.com:443", "b-1"), { group }), "x.com:443", "b-1");
  ok((await verifyEnvelope(envB, membershipRoots)).ok, "member B also gates in");
  // a true outsider: proves against its OWN singleton group -> wrong root -> rejected
  const outGroup = newGroup([rateCommitmentOf(identityFor(999n))]);
  const outsider = await pack(await proveForSlot(999n, epoch, 0, requestSignal("x.com:443", "o"), { group: outGroup }), "x.com:443", "o");
  ok(!(await verifyEnvelope(outsider, membershipRoots)).ok, "outsider (wrong root) is rejected");

  h("3. gateway share-collecting spent-set: replay vs over-spend");
  // The gateway keys shares by `nullifier` alone (there is no public slot). Model it
  // exactly as gateway.mjs does.
  const spent = new Map();      // nullifier -> firstShare
  const seenSignal = new Set(); // (nullifier + share.x) for replay dedup
  let slashed = null;
  async function feed(env) {
    const v = await verifyEnvelope(env, membershipRoots);
    if (!v.ok) return v.reason;
    const key = String(v.nullifier);
    const sigKey = `${key}:${v.share.x}`;
    if (seenSignal.has(sigKey)) return "replay-deduped"; // identical signal: no new share, no slash
    seenSignal.add(sigKey);
    const first = spent.get(key);
    if (!first) { spent.set(key, v.share); return "egress-first-share"; }
    // second DISTINCT signal under one nullifier => reconstruct identitySecret + slash
    const secret = reconstructSecret(first, v.share); // identitySecret
    slashed = { commitment: deriveCommitment(secret), secret };
    return "OVER-SPEND-reconstructed";
  }
  // env1 first share recorded
  ok((await feed(env1)) === "egress-first-share", "tunnel 1 first share recorded");
  // replay env1 verbatim -> deduped, no slash
  ok((await feed(env1)) === "replay-deduped", "identical replay of tunnel 1 is deduped (NOT slashed)");
  // member A over-spends slot 0: a NEW distinct signal reusing messageId 0 => same
  // nullifier (same identity+epoch+messageId), different x => the L+1-th point.
  const sig1b = requestSignal("evil-scrape.com:443", "req-1-overspend");
  const env1b = await pack(await proveForSlot(secretA, epoch, 0, sig1b, { group }), "evil-scrape.com:443", "req-1-overspend");
  ok(env1b.nullifier === env1.nullifier, "over-spend reuses slot 0 => SAME nullifier as tunnel 1");
  const r = await feed(env1b);
  ok(r === "OVER-SPEND-reconstructed", "second DISTINCT signal on the same nullifier triggers reconstruction");
  ok(slashed && slashed.secret === idsecA.toString(), "reconstructed secret == member A's identitySecret");
  ok(slashed && slashed.commitment === commA, "deriveCommitment(identitySecret) == member A's on-chain leaf");

  h("4. on-chain slash of the over-spender (increment C)");
  const receiver = ethers.Wallet.createRandom().address;
  const balBefore = await provider.getBalance(receiver);
  const setAsSlasher = set.connect(slasher);
  await (await setAsSlasher.slash(slashed.commitment, BigInt(toField(slashed.secret)), receiver)).wait();
  ok((await set.members(commA)).bond === 0n, "member A's on-chain bond is burned (slashed)");
  ok((await set.activeCount()) === 1n, "activeCount drops to 1");
  ok((await provider.getBalance(receiver)) - balBefore === BOND / 10n, "slash paid only the 10% bounty to the receiver");
  ok(await reverts(set.withdraw(commA, receiver, enc(idsecA))), "slashed member A cannot withdraw (bond gone)");

  h("5. clean member B: time-locked exit + withdraw (increment C, R4)");
  await (await set.initiateExit(commB, enc(idsecB))).wait();
  ok(Number((await set.members(commB)).exitInitiatedAt) > 0, "member B exit initiated (unbonding clock started)");
  ok((await set.activeCount()) === 0n, "member B left the active set immediately");
  ok(await reverts(set.withdraw(commB, funder.address, enc(idsecB))), "withdraw BLOCKED before unbonding elapses");
  // fast-forward past the unbonding window
  await provider.send("evm_increaseTime", [UNBONDING + 1]);
  await provider.send("evm_mine", []);
  const recip = ethers.Wallet.createRandom().address;
  const rb = await provider.getBalance(recip);
  await (await set.withdraw(commB, recip, enc(idsecB))).wait();
  // evm_mine above advanced the chain outside ethers' block tracking, so read the
  // recipient balance pinned to a freshly-fetched tip (not a possibly-stale "latest").
  const tip = await provider.getBlockNumber();
  ok((await provider.getBalance(recip, tip)) - rb === BOND, "withdraw AFTER unbonding returns the bond to a fresh recipient");
  ok((await set.members(commB)).bond === 0n, "member B fully exited");

  console.log(`\n${FAIL === 0 ? "✓ ALL PASS" : "✗ FAILURES"} — ${PASS} passed, ${FAIL} failed`);
}

// Pack a proveForSlot result into the explicit v4 wire envelope the gateway consumes.
// target + nonce ride along so the gateway can BIND the proof to this target (verifyEnvelope 2b);
// they MUST be the same pair the signal was built from.
async function pack(p, target, nonce) {
  return { v: 4, target, nonce, proof: p.proof, nullifier: p.nullifier, externalNullifier: p.externalNullifier, share: p.share };
}
const short = (s) => String(s).slice(0, 10) + "…";

main()
  .then(() => { cleanUp(); process.exit(FAIL === 0 ? 0 : 1); })
  .catch((e) => { console.error(e); cleanUp(); process.exit(1); });
