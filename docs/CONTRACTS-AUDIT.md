# CONTRACTS-AUDIT.md

Auditor's guide and written invariants for the Solidity contracts in `contracts/`.
Reference implementation, unaudited, testnet-only. This document is prep for an external
review (task T-HARD-6); it does not modify any source.

Scope: `contracts/*.sol`. Design rationale lives in `docs/ONCHAIN.md` (and `docs/PAYMENTS.md`
for the paid-access set); this file is the audit map, the invariant list, and the run
instructions.

Solc: `0.8.24`, optimizer on, 200 runs (`foundry.toml`). Two contracts carry the built-in
0.8 checked-arithmetic guarantee; `RlnGroth16Verifier.sol` is a snarkJS export pinned to
`>=0.7.0 <0.9.0` and is out of scope for hand review (machine-generated, see below).

---

## 1. Contract inventory

The current `StakedReputationSet` source implements **slash-burn-v1**: at least 90% of
each slashed bond goes to the constant zero-address sink and at most 10% is a bounty.
The deployed addresses listed below predate this change and retain their old payout
rules; a source merge does not upgrade them. See [migration](ONCHAIN-DEPLOY.md#slash-burn-v1-migration).

| Contract | File | Purpose | Deployment status |
|---|---|---|---|
| `StakedReputationSet` | `StakedReputationSet.sol` | Member admission gate: per-tier fixed-bond, refundable, slashable, time-locked-exit stake keyed by RLN rate-commitment (anonymous leaf), with the depth-20 Poseidon incremental tree ON CHAIN (`currentRoot` at storage slot 3, T-DEV-9) and a reputation-tier table fixed at construction (`register(commitment, limit)` / `bondFor(limit)` / `slash(commitment, secret, limit, receiver)`, T-FEAT-8b). No owner. | Sepolia `0xFe48De8b9aCA4386DC31C845d579ae62f04f9d25` was deployed in the historical `rln-v4-tiers` bundle (`network/sepolia/contracts.json`, 2026-08-17) and is explicitly reused by the live envelope-v4 research Grove in `network/sepolia/deployment.json` since 2026-09-03. Superseded within the earlier experiment: `0xdAE242AE…20FC` (`rln-v3`, no on-chain tree, hasher pinned K=8). |
| `PaidAccessSet` | `PaidAccessSet.sol` | The PAID-ACCESS membership tree (T-FEAT-7 Layer 1, `docs/PAYMENTS.md`): the staked set's structural sibling — same depth-20 Poseidon incremental tree ON CHAIN (`currentRoot` at slot 3), same leaf via the same tiered hasher, same immutable allowed-tier table, same zero-in-place `slash(commitment, secret, limit, receiver)` — but NO funds: `insert` / `insertBatch` are `onlyOperator` and not payable (payment settles OFF chain over HTTP 402 rails; the operator/registrar inserts after settlement), no exit / withdraw / sweep / receive, `slash` pays nothing. `operator` rotates by two-step `setOperator` / `acceptOperator`. | **Historical Sepolia experiment** `0x4e8C2Bf5d3c5454A04837401095fce2646484111` (`contracts.paidAccessSet`, deployed 2026-08-17 block 11510873; record now retired). Smoke evidence remains in `network/sepolia/integration-report-paid-access.md`. |
| `GatewayRegistry` | `GatewayRegistry.sol` | Gateway-operator bond keyed by operator **address**; owner-gated slash. The gateway-side dual of the member stake, deliberately minimal and optional. | Sepolia `0x94ECeD0C1c7a8793a5c901c8C1995C8E7039A868` is recorded in `network/sepolia/contracts.json` and explicitly reused by the live research Grove in `network/sepolia/deployment.json`; local deploy params are mirrored in `test/GatewayRegistry.t.sol`. |
| `RateCommitmentHasher` | `RateCommitmentHasher.sol` | Real Poseidon rate-commitment hasher, TIERED: `commitmentOf(secret, limit) = Poseidon(2)([Poseidon(1)([secret]), limit])` (`1 <= limit <= 65535`, else `BadLimit`) and the byte-equivalent default `commitmentOf(secret)` at `K = 8`. Implements `ICommitmentHasher` (both overloads). | Historical Sepolia rln-v4 address `0x29e9D6ae8d46A9D86D6A92a43307850e0FA06586`; the containing record is retired. Superseded there: `0x08F9a754…ae6D` (K pinned). |
| `MockCommitmentHasher` | `MockCommitmentHasher.sol` | Deprecated-name alias: empty subclass of `RateCommitmentHasher` kept so the deploy script keeps compiling. Fully correct rate-commitment hasher. | Alias only; the historical deployed `hasher` was the rate-commitment hasher. |
| `WithdrawVerifier` (+ `WithdrawGroth16Verifier`) | `WithdrawVerifier.sol` / `WithdrawGroth16Verifier.sol` | The **real** ZK exit/withdraw authorizer (T-DEV-1): Groth16 proof of knowledge of the identity secret behind a leaf, `context` reduced into the field as the circuit's public `address` input (binds exit vs. withdraw-to-recipient), then `Poseidon(2)([identityCommitment, limit]) == commitment` ties it to the registered leaf at the tier the SET recorded (`verify(commitment, limit, context, proof)`, T-FEAT-8b). Implements `IWithdrawVerifier`. Foundry: `test/WithdrawVerifier.t.sol`, `test/StakedReputationSet.tiers.t.sol::test_RealVerifier_TiedToRecordedLimit`. | Historical Sepolia rln-v4 addresses `0x522409038aA03FFF998d33C60A37486975695351` / `0x6B26a9B6BEdcB711C35947f988fdFF168AFD507E`; the record is retired and the VK is the untrusted dev phase-2 (T-HARD-1). |
| `MockWithdrawVerifier` | `MockWithdrawVerifier.sol` | Demo exit/withdraw authorizer. Accepts a **revealed** secret (`proof == abi.encode(secret)`), returns true iff `hasher.commitmentOf(secret, limit) == commitment`. Implements `IWithdrawVerifier`. NOT zero-knowledge. | Local anvil demo only (`script/Deploy.s.sol`); was live as `withdrawVerifier` `0x5A6FD01d…dbDB2` on the superseded rln-v3. |
| `PoseidonT2` / `PoseidonT3` | `PoseidonT2.sol` / `PoseidonT3.sol` | Vendored Poseidon permutation libraries (t=2 single-input, t=3 two-input) over BN254. Called by `RateCommitmentHasher.commitmentOf`. | Deployed transitively with the hasher. Machine-generated field arithmetic; out of scope for hand review. |
| `RlnGroth16Verifier` (`Groth16Verifier`) | `RlnGroth16Verifier.sol` | snarkJS-exported Groth16 verifier for the deployed RLN membership artifacts. **NOT wired into `StakedReputationSet`** in this build; membership proofs are verified off-chain by the gateway against `circuits/rln/verification_key.json`. | Kept verbatim as provenance. Out of scope for hand review (generated; do not edit). |

### Trust / authority model (the honest asymmetry)

- `StakedReputationSet.register` / `initiateExit` / `withdraw` / `slash` are all
  **permissionless**. No `owner`, no admin. A member acts by cryptographic proof, never by
  `msg.sender` identity, so the member stays anonymous (`initiateExit` and `withdraw` are
  gated by `withdrawVerifier.verify`, not by caller; `slash` is gated by possession of a
  `(commitment, secret)` pair such that `hasher.commitmentOf(secret) == commitment`).
- Member `slash` is permissionless **because member over-spend is cryptographically
  provable**: reconstructing the identity secret from L+1 RLN shares yields exactly the
  authorization `slash` checks (`StakedReputationSet.slash`, line ~172). An honest member's
  secret remains private from outsiders. A member knows its own secret and can self-slash;
  the mandatory burn prevents recovering the full stake through that path.
- `GatewayRegistry.slash` is **owner-gated** (`onlyOwner` via `if (msg.sender != owner)
  revert NotOwner()`), the one deliberate asymmetry. Gateway misbehavior (censoring,
  tampering, downtime) is a subjective off-chain judgment, so slashing authority is a
  governance role rather than a cryptographic predicate. `register` / `initiateExit` /
  `withdraw` on the registry remain permissionless / operator-only.
- `PaidAccessSet.insert` / `insertBatch` / `setOperator` are **operator-gated** (`onlyOperator`:
  `if (msg.sender != operator) revert NotOperator()`), the second deliberate asymmetry: whether a
  buyer has PAID is settled off chain (402 rail), so admission is the registrar's attestation, not
  a cryptographic predicate — the trust PAYMENTS.md names (operator honors a payment / a valid
  proof) and no more. `slash` stays **permissionless** and cryptographically gated exactly like the
  staked set's; `acceptOperator` is gated to the nominee.
- `GatewayRegistry` keys by operator **address** on purpose: a gateway serves a public
  egress IP and is not anonymous, so `msg.sender` keying is honest and lets the operator
  manage the bond with an ordinary key. `owner` is a single key; a DAO / timelock is future
  (section 3).

---

## 2. Written invariants an auditor should check

Several are already encoded as Foundry invariant tests
(`test/*.invariant.t.sol`, 4096 calls/run, both suites green).

**I1. `activeCount` == number of currently-active stakes.**
Active = staked and not exiting. Encoded:
`GatewayRegistryInvariantTest.invariant_activeCountMatchesLiveActiveStakes` and
`StakedReputationSetInvariantTest.invariant_activeCountMatchesActiveMembers`.
Source: `activeCount++` only in `register`; `activeCount--` in `initiateExit`, in
`withdraw` never (already decremented at exit), and in `slash` only `if (wasActive)`
where `wasActive = exitInitiatedAt == 0`. The `wasActive` guard is what prevents a
double-decrement when an already-exiting stake is slashed
(`StakedReputationSet.slash` / `GatewayRegistry.slash`).

**I2. Contract ETH balance == Σ live bonds (per tier), with all lifecycle outflows accounted for.**
Live = bond still held (active OR exiting). Encoded:
`invariant_ethEqualsSumOfLiveBonds` in both suites (registry: `balance == ghostLive * BOND`;
set: `balance == ghostLiveWei`, with tier-1 and tier-8 members). Registration requires
exactly `bondFor(limit)`. Withdrawal returns the whole recorded bond. Member slashing
splits the whole recorded bond into `floor(bond / 10)` reward and the remainder sent to
`SLASH_BURN_ADDRESS`; neither part stays in the set. The invariant also tracks cumulative
burns and receiver balances separately from honest withdrawals. This equality covers the
modeled lifecycle; forced unsolicited ETH is outside that accounting model.

**I3. A slashed or withdrawn stake cannot be re-withdrawn (delete-before-payout, CEI).**
Both `withdraw` and `slash` execute `delete members[commitment]` /
`delete stakes[operator]` **before** the `.call{value: amount}` payout. Any re-entrant or
subsequent `withdraw` / `slash` on the same key hits `if (bond == 0) revert NotMember()`
(resp. `NotStaked`), because `delete` zeroes `bond`. Confirmed by
`test_Slash_WorksDuringUnbonding_AndBlocksLaterWithdraw` (slash then later withdraw reverts
`NotMember`) and by the balance invariant.

**I4. Exit and self-slash cannot recover a slashable bond in full.**
`slash` succeeds whether the stake is active or mid-unbonding: it only checks
`bond != 0`, never `exitInitiatedAt`. `initiateExit` leaves the active set but does NOT
return funds and does NOT delete the record, so the bond stays fully slashable for the
entire `UNBONDING` window. `withdraw` additionally requires
`block.timestamp >= exitInitiatedAt + UNBONDING`. The constructor enforces
`unbonding >= minUnbonding` so a misconfigured short window cannot open the escape.
Confirmed by `test_owner_can_slash_while_exiting` (registry) and
`test_Slash_WorksDuringUnbonding_AndBlocksLaterWithdraw` (set), and by the fuzz test
`testFuzz_slash_anyStakedPays(address,bool exiting)`.

For member stakes, both slash overloads additionally impose `burned = bond - floor(bond / 10)`
regardless of `msg.sender` or the named receiver. The receiver controls only the bounty;
no caller or owner can redirect the burn. Active and exiting self-slash and both orderings
of competing keeper/member transactions are fuzzed over the full uint256 bond range in
`test/StakedReputationSet.slash-penalty.t.sol`. The same suite checks rounding, tiny bonds,
a rejecting receiver's atomic rollback, retry, reentry, and root slot 3. Honest withdrawal
still returns the whole stake after its delay. This economics fix does not address the
other admission or proof-context findings in #113.

**I5. `bondFor(limit)` is the only accepted deposit for tier `limit`.**
`register(commitment, limit)` reverts `BadLimit` unless `bondFor(limit) != 0` (the tier is
in the immutable table) and `BadBond` unless `msg.value == bondFor(limit)` exactly (not
`>=`, not `<=`). The one-argument `register(commitment)` is `register(commitment, 8)` and
requires `BOND` (`bondFor(8) == BOND` always). No other function is `payable`. Confirmed by
`test_Register_RequiresExactBond`, `testFuzz_register_wrongBondReverts` (any `value != BOND`
reverts and leaves zero contract balance), `test_Register_Tier32_RequiresTierBond`,
`test_Register_UnadmittedTier_Reverts`, `testFuzz_register_tierBondAdmits`.

**I6. The onion is NEVER stored on chain.**
`GatewayRegistry` keys the stake by operator **address** and stores only
`{bond, index, exitInitiatedAt}` (`struct Stake`). There is no field, event, or argument
carrying an onion address anywhere in the contract. A v3 `.onion` is an ed25519 public key;
storing it would make the fleet publicly enumerable and permanently bind each onion to its
funding address. The onion→stake binding is an off-chain operator signature
(`bootnode/announce`), so a single stake can rotate across many onions.

**I7. Append-only index monotonicity.**
`nextIndex` only ever increments (`nextIndex++` in `register`); it is never reset or
decremented, even on withdraw/slash/re-register. A re-registered commitment gets a fresh
higher index. Confirmed by `test_Register_AppendOnlyIndex` and
`test_ReRegister_AfterWithdraw` (re-register yields index 1). This backs the off-chain
tree rebuild in `lib/root-provider.mjs`.

**I8. Membership leaf == the crypto side's rate commitment, at the member's tier.**
`RateCommitmentHasher.commitmentOf(s, limit) == Poseidon(2)([Poseidon(1)([s]), limit])` must
equal `poseidon-lite`'s `poseidon2([poseidon1([s]), BigInt(limit)])` (`lib/rln.mjs
deriveCommitment(s, limit)`), and `commitmentOf(s) == commitmentOf(s, 8)`. If these drift, a
reconstructed secret would slash the wrong leaf (silent `BadSecret`). Pinned on-chain by
`test/Poseidon.t.sol` (five JS↔Solidity vectors at K=8), `test_Slash_RateCommitmentLeaf_RevealedSecret_Pays`,
and `test/StakedReputationSet.tiers.t.sol` (`test_Hasher_MatchesJsTierGoldens`: 111/222/1 at 32
and 64; `testFuzz_hasher_tiersDistinctAndDefaultEqual`).

**I9. A successful slash uses the recorded tier and splits its entire bond.**
`slash(commitment, secret, limit, receiver)` reverts `NotMember` (no bond), `BadLimit`
(`m.limit != limit`), then `BadSecret` (`hasher.commitmentOf(secret, limit) != commitment`),
in that order. The source amount is `m.bond == bondFor(m.limit)`; at most one tenth is
paid to the receiver and the rest goes to the fixed sink. The three-argument `slash` is
the `limit = 8` claim. This check does not prove a raw leaf was admitted at the correct
tier; wrong-tier admission remains an open finding in #113. Encoded: `test_Slash_Tier32_OnlyWithLimit32_BurnsTierBond`,
`test_Slash_Tier8_OnlyWithLimit8`, `testFuzz_slash_onlyAtRecordedLimit` (any other limit,
0..70000, reverts and is a no-op), and the invariant handler's `slash` (the OTHER tier's
claim must revert before the right one succeeds, every call). Live: the Sepolia rln-v4
integration slashed a tier-32 leaf at limit 32 and proved (static call) that limit 32 on a
tier-8 leaf reverts `BadLimit` (`network/sepolia/integration-report-rln-v4.md`).

**I10. The tier table is immutable and well-formed; `currentRoot` stays at slot 3.**
The constructor rejects a limit of 0, `> MAX_LIMIT` (65535, the circuit's `LessThan(16)`
soundness bound), a duplicate of `DEFAULT_LIMIT`, a non-ascending or duplicate extra, a zero
bond, and a length mismatch (`test_Constructor_RejectsBadTierTables`); there is no setter
and no owner, so no tier can be added, removed, or repriced after deployment (a new table is
a new deployment). The tier mappings are declared AFTER the tree state so
`ROOT_STORAGE_SLOT == 3` is unchanged (`test_Root_KnownStorageSlot`,
`test_Root_StorageSlotUnchangedByTierTable`, `test_Root_MixedTiers_EqualsJsNewGroup`, which
also pins a two-tier tree's root to the JS `newGroup` golden).

**I11. On-chain root == off-chain reconstruction, across both event generations.**
`currentRoot` after any register / exit / slash sequence equals `lib/root-provider.mjs
reconstructRoot` over the emitted events (zero-in-place removal at the leaf's immutable
index): `test_Root_RegisterThreeSlashMiddle_EqualsReconstructRoot` (rln-v3-style single tier)
and `test_Root_MixedTiers_EqualsJsNewGroup` (rln-v4, mixed tiers). rln-v4's
`MemberRegistered(commitment, index, limit)` / `MemberSlashed(commitment, receiver, limit)`
have a different topic0 from rln-v3's; the reconstruction accepts both and treats them
identically (`lib/root-provider.selftest.mjs` §8), and the anvil end-to-end suite
`test/onchain-tiers.selftest.mjs` checks on-chain `currentRoot()` == NodeRootProvider
(events) == LightClientRootProvider (eth_getProof of slot 3) == JS `groupFromIdentities`.

**I12. `PaidAccessSet` never holds ETH.**
No function is `payable`; there is no `receive` and no `fallback`, so a plain transfer and a
value-carrying call both revert (`test_NoFunds_EthCannotEnter`), and no function sends value.
Balance is 0 at every state (`invariant_noFundsEver`, `testFuzz_sequence_matchesReference`).
Payment lives on the 402 rail; the chain never sees it. `slash` therefore has nothing to burn:
it zeroes the leaf and pays nothing (`test_Slash_RequiresRecordedTierAndSecret_MovesNothing`,
`testFuzz_slash_onlyAtRecordedTier` — which also shows the REFERENCE staked set DID pay for the
same op).

**I13. Only the current operator inserts; the tier table is immutable; duplicates are policy.**
`insert` / `insertBatch` revert `NotOperator` for any other caller (`test_Insert_OnlyOperator`,
`testFuzz_insert_onlyOperator(address)`, and the invariant handler tries a stranger AND the
non-current identity before every insert), `BadLimit` for a tier not in the constructor table
(`isAllowedLimit`; `test_Insert_UnlistedTierReverts`, `testFuzz_insert_unlistedLimitReverts`
over 0..70000), `AlreadyInserted` for a LIVE commitment at any tier; a SLASHED commitment may be
re-inserted and gets a FRESH index (`test_Insert_DuplicatePolicy`). `insertBatch` is
all-or-nothing, one `Inserted` per leaf, array order == index order, and equals the same
singles (`test_InsertBatch_AllOrNothing_EmitsPerLeaf`, `testFuzz_insertBatch_equalsSingles`).
The constructor rejects an empty table, limit 0 / > `MAX_LIMIT`, non-ascending / duplicate,
a table without `DEFAULT_LIMIT` (8), and a zero hasher (`test_Constructor_RejectsBadTables`);
there is no setter.

**I14. `leafCount == inserts` (append-only), `liveCount == inserts − slashes`, `root == the
staked set's root for the same leaves`, `currentRoot` at slot 3.**
`nextIndex` only increments (`_insert`), so `leafCount()` counts every appended leaf, slashed
ones included (their index is never reused); `liveCount` is `++` in `_insert`, `--` in `slash`
(guarded by `l.limit != 0`, so never underflows). The tree code is a verbatim copy of the staked
set's; `test_Root_ParityWithStakedReputationSet` and the fuzz / invariant suites drive a
`StakedReputationSet` REFERENCE through the same register/slash sequence and assert equal roots
after every step (`invariant_rootEqualsReference`, `testFuzz_sequence_matchesReference`), the
JS goldens are pinned (`test_Root_MatchesJsGoldens`: `newGroup([A8,B32,C8,D32])` and minus index
2), and `vm.load(addr, bytes32(3)) == currentRoot()` is asserted after inserts AND after an
operator rotation (`test_Root_StorageSlot3`; the operator lives after the tree in storage).

**I15. Operator transfer is two-step and un-hijackable.**
`setOperator(to)` only records `pendingOperator` (`onlyOperator`); the role moves only when
`to` itself calls `acceptOperator()` (`NotPendingOperator` for anyone else, including after a
cancel with `setOperator(0)` and after a completed transfer — no replay), and `pendingOperator`
is cleared on accept (`test_Operator_TwoStepTransfer`, `testFuzz_operator_twoStep(address,
address)`, `invariant_operatorIsGhost` across random rotations between two identities). No
timelock: a compromised operator key can rotate away immediately (a rotation is also the
recovery path), which is the accepted single-key limitation (section 3).

---

## 3. Known limitations / not-yet-real

- **`MockWithdrawVerifier` is a local-demo placeholder** (revealed secret in calldata, ignores
  `context`). The **historical rln-v4 Sepolia experiment (2026-08-17) wired the real Groth16
  `WithdrawVerifier`** (`network/sepolia/contracts.json` `withdrawVerifier` /
  `withdrawGroth16Verifier`), so on chain exit / withdraw authorization is a genuine
  proof-of-knowledge bound to the action + recipient — but its VK is still the untrusted dev
  phase-2 (T-HARD-1): trustworthy for testnet only. The mock remains only in
  `script/Deploy.s.sol` (anvil demo, `scripts/demo-e2e.mjs`).
- **The tier a leaf is staked at is DECLARED, not proven.** `register(commitment, limit)`
  cannot look inside `commitment`; it prices and records the tier the registrant names. A
  member whose leaf was built at limit X but who declares Y != X gets a leaf the contract can
  never slash (`hasher.commitmentOf(secret, Y) != leaf` => `BadSecret`) — but ALSO one it can
  never exit or withdraw (the verifier ties the proof to the leaf at the RECORDED limit Y), so
  the bond is locked forever, i.e. forfeited without a slash tx. The gateway still enforces the
  leaf's REAL budget X (the circuit does, not the contract), so the mismatch never buys extra
  requests: an over-spend is still dropped `over-spend-slashed`; only the on-chain burn degrades
  to a permanent lock. Documented in `docs/ONCHAIN.md` "Tiers on chain"; a leaf-tier proof at
  registration is a possible follow-up, not a soundness gap.
- **ZK artifacts come from an untrusted ceremony.** `circuits/rln/` was built with a local,
  untrusted phase-2 (two hard-coded entropy contributions + a fixed beacon;
  `circuits/rln/ARTIFACTS.md` "Trust / honesty note"). Fine for testnet. A real deployment
  needs a proper multi-party phase-2 and regenerated `rln_final.zkey` + verifier +
  `verification_key.json` together. Hardening this is task **T-HARD-1**.
- **RLN leaf-removal parity is now verified against an on-chain slash** (I11): the anvil
  end-to-end suite and the live Sepolia rln-v4 run both compare `currentRoot()` after the
  slash with the JS zero-in-place tree (`network/sepolia/integration-report-rln-v4.md`).
- **`owner` is a single key.** `GatewayRegistry.owner` is one address with sole slash +
  ownership-transfer authority. `transferOwnership` is a plain single-step transfer (no
  two-step accept, no timelock). A DAO / timelock / fraud-proof verifier is a future drop-in
  (`StakedReputationSet` has no owner at all, so only the registry carries this risk).
- **Re-registration allowed.** A withdrawn or slashed commitment is `delete`d, so it can be
  re-registered (`test_ReRegister_AfterSlash`). Harmless for an append-only tree and a
  slashed secret is already public; add a burned-commitment set to forbid it outright.
- **`PaidAccessSet` admission is an operator attestation.** Whether a leaf was PAID for is
  decided off chain (402 rail + registrar); the contract records only that the operator inserted
  it. A dishonest or compromised operator key can insert unpaid leaves (griefing the anonymity
  set is the worst case: every inserted leaf still has its own RLN budget and is slashable) or
  decline to insert paid ones (the PAYMENTS.md trust). No timelock on operator rotation; the
  operator is a single key until rotated to a multisig. The tier is DECLARED at insert exactly
  as at `register` (same lock-not-slash consequence for a mismatch; the registrar should derive
  the tier from what was paid for).
- **No explicit reentrancy guard.** Safe today by construction (CEI + delete-before-call;
  section 4), but add a guard before mainnet as defense in depth (`contracts/README.md`).

---

## 4. Reentrancy / overflow / access-control walk-through

Every external function, why it is safe. Both `StakedReputationSet` (`SRS`) and
`GatewayRegistry` (`GR`) are solc `0.8.24`, so all arithmetic is checked (overflow/underflow
revert). No `unchecked` blocks exist in either contract.

**`register` (SRS `register(uint256 commitment)`, GR `register()`)** — permissionless,
`payable`.
- Access: none by design (anonymous member / permissionless operator).
- Deposit guard: `if (msg.value != BOND) revert BadBond()` (I5). Exact-match only.
- Duplicate guard: `if (_exists(...)) revert AlreadyStaked/AlreadyMember` where `_exists`
  tests `bond != 0`.
- Reentrancy: no external call. State writes (`stakes/members[...] = ...`, `activeCount++`,
  `nextIndex++`) then `emit`. Nothing to re-enter.
- Overflow: `activeCount++` / `nextIndex++` checked by 0.8; `nextIndex` is `uint64`,
  practically unreachable.

**`initiateExit` (SRS `initiateExit(commitment, proof)`, GR `initiateExit()`)** —
starts unbonding clock.
- Access: SRS is ZK-authorized — `if (!withdrawVerifier.verify(commitment, context, proof))
  revert BadProof()`, with `context = keccak256("SHADE_TREE_EXIT", commitment)`. GR is
  operator-only implicitly: it reads `stakes[msg.sender]` and reverts `NotStaked` if the
  caller has none, so a non-operator cannot exit another's stake.
- Preconditions: `bond != 0` (`NotStaked`/`NotMember`) and `exitInitiatedAt == 0`
  (`AlreadyExiting`).
- Effect: sets `exitInitiatedAt = uint64(block.timestamp)`, `activeCount--`. Bond NOT
  returned and record NOT deleted — this is what keeps it slashable (I4).
- Reentrancy: the only external call is the `staticcall`-shaped `withdrawVerifier.verify`
  (a `view` interface) and it runs BEFORE the state write; a malicious verifier can revert
  or lie but cannot re-enter to move funds (no funds move here). GR has no external call.
- Overflow: `activeCount--` cannot underflow because it is guarded by `bond != 0 &&
  exitInitiatedAt == 0`, i.e. the stake is currently counted in `activeCount` (I1). Verified
  by the invariant suite.

**`withdraw` (SRS `withdraw(commitment, recipient, proof)`, GR `withdraw(recipient)`)** —
time-locked payout. This is the CEI-critical path.
- Access: SRS re-verifies the proof against
  `context = keccak256("SHADE_TREE_WITHDRAW", commitment, recipient)` (`BadProof`). GR is
  operator-only via `stakes[msg.sender]`.
- Preconditions: `bond != 0` (`NotMember`/`NotStaked`), `exitInitiatedAt != 0`
  (`NotExiting`), and `block.timestamp >= exitInitiatedAt + UNBONDING` (`StillBonded`).
  The timelock arithmetic `uint256(exitInitiatedAt) + UNBONDING` is checked; widened to
  `uint256` so no `uint64` overflow.
- CEI ordering (the key point): read `amount = bond`, then **`delete` the record**, then
  `emit`, then `(bool ok, ) = recipient.call{value: amount}("")`, then
  `if (!ok) revert PayoutFailed()`. Because the record is deleted before the call, a
  re-entrant `withdraw` finds `bond == 0` and reverts `NotMember`/`NotStaked` (I3). No state
  is read after the call. The raw `.call` is the recommended ETH-transfer form; failure
  reverts the whole tx, so a rejecting recipient cannot strand the record in a half-deleted
  state (the `delete` is rolled back with the revert).
- `activeCount`: NOT touched here — it was already decremented at `initiateExit`. This is
  required for I1 (no double count).

**`slash` (SRS `slash(commitment, secret, receiver)`, GR `slash(operator, receiver)`)** —
SRS burns >=90% and rewards <=10%; GR retains its owner-directed full payout.
- Access: **SRS permissionless but cryptographically gated** —
  `if (hasher.commitmentOf(secret) != commitment) revert BadSecret()`. Authorization IS
  possession of a secret that hashes to the leaf. The member can supply its own secret;
  the fixed penalty makes self-slash costly.
  **GR owner-gated** — `if (msg.sender != owner) revert NotOwner()` first line.
- Precondition: `bond != 0` (`NotMember`/`NotStaked`).
- Works active or exiting: no `exitInitiatedAt` gate, closing the dodge (I4).
- CEI: `amount = bond`, capture `wasActive = exitInitiatedAt == 0`, **`delete`**,
  `if (wasActive) activeCount--`, `emit`, and (SRS) zero the active leaf before transfers.
  SRS sends `amount - amount / 10` to the fixed sink, then sends a nonzero `amount / 10`
  bounty to `receiver`; both calls check `PayoutFailed`, reverting the entire transaction
  on failure. GR sends the full amount to its receiver. Delete-before-payout protects
  the old bond from reentry (I3). `wasActive` guard prevents
  double-decrement of `activeCount` when slashing a mid-unbonding stake (I1).
- Overflow: `activeCount--` guarded by `wasActive` (only decrement when it was counted).
- SRS note: `hasher.commitmentOf` is an external `view` call to `RateCommitmentHasher`
  BEFORE any state change; a hostile hasher is a config-trust assumption, not a reentrancy
  vector (it cannot move funds and runs pre-delete).

**`PaidAccessSet.insert(commitment, limit)` / `insertBatch(commitments[], limits[])`** —
operator-gated, NOT payable.
- Access: `onlyOperator` (`NotOperator`) first.
- Guards: `_allowed[limit]` (`BadLimit`), `leaves[commitment].limit == 0` (`AlreadyInserted`);
  batch: `commitments.length != 0 && == limits.length` (`BadBatch`), then per leaf; any revert
  unwinds the whole batch.
- Effects: `nextIndex++`, `leaves[c] = {index, limit}`, `liveCount++`, `_updateLeaf` (20
  Poseidon2 library calls — `PoseidonT3` is a linked external library, i.e. `DELEGATECALL` into
  known code; a config-trust assumption shared with the staked set, not a reentrancy vector),
  then `emit Inserted(.., currentRoot)`. No value, no calls to arbitrary addresses.
- Overflow: `nextIndex` `uint64` / `liveCount` checked; `uint32(limit)` is safe because
  `limit <= MAX_LIMIT = 65535` is enforced by the table.

**`PaidAccessSet.slash(commitment, secret, limit, receiver)`** — permissionless, secret-gated.
- Same gate order as the staked set: `NotInserted` (`l.limit == 0`), `BadLimit`
  (`l.limit != limit`), `BadSecret` (`hasher.commitmentOf(secret, limit) != commitment`, an
  external `view` call BEFORE any state change).
- Effects: `delete leaves[c]`, `liveCount--` (guarded by `l.limit != 0`, cannot underflow),
  `_updateLeaf(idx, _zeroes[0])`, `emit Slashed`. **No payout**: `receiver` is unused (kept for
  call-shape parity), so there is no `.call{value:}` and no reentrancy surface at all here.

**`PaidAccessSet.setOperator(to)` / `acceptOperator()`**
- `setOperator`: `onlyOperator`; writes `pendingOperator = to` (0 cancels), emits. No call.
- `acceptOperator`: `msg.sender != 0 && == pendingOperator` (`NotPendingOperator`); sets
  `operator = msg.sender`, clears `pendingOperator`, emits. No call. Two-step so a wrong `to`
  cannot brick issuance (contrast GR `transferOwnership`, single-step).
- Storage: `operator` / `pendingOperator` are declared AFTER the tree and the tier table, so
  slot 3 is untouched (`test_Root_StorageSlot3` asserts it across a rotation).

**Views** (`PaidAccessSet`: `isAllowedLimit`, `allowedLimits`, `leafCount`, `liveCount`,
`commitmentOf`, `limitOf`, `leaves`, `currentRoot`, `treeZeroValue`, `operator`,
`pendingOperator`, `hasher`) are read-only.

**`transferOwnership` (GR only, `transferOwnership(address to)`)**
- Access: `if (msg.sender != owner) revert NotOwner()`.
- Effect: `emit OwnerTransferred(owner, to); owner = to`. Single-step (limitation, section
  3 — a fat-fingered `to`, incl. `address(0)`, would brick slashing; no zero-address check).
- No external call, no funds, no reentrancy surface.

**Views** (`isActive`/`isStaked`, `withdrawableAt`, `members`/`stakes`, `activeCount`,
`nextIndex`, `owner`, `BOND`, `UNBONDING`) are read-only and side-effect free.
`withdrawableAt` returns 0 for a non-existent or non-exiting key rather than reverting.

**Constructor guards (both):** `if (bond == 0) revert BadBond()`;
`if (unbonding < minUnbonding) revert UnbondingTooShort()`. `minUnbonding` is caller-supplied
so the operator pins the window to `F + E + C` (freshness + epoch + slash-confirmation) and
a too-short lock is rejected at deploy (`test_constructor_rejects_*`,
`test_Constructor_Rejects*`). GR `owner` defaults to `msg.sender` when passed `address(0)`.

---

## 5. Running the tests (fuzz + invariants)

Toolchain: Foundry (`forge 1.3.2` verified in this environment). No `forge install` needed —
the harness declares its own cheatcode interface in `test/Cheats.sol` / `test/FuzzHelpers.sol`
(this repo reserves `lib/` for Track 2's `.mjs` crypto, not Solidity deps; `foundry.toml`).

```
forge build
forge test                 # full suite: 117 tests, 12 suites, all green (2026-08-17, T-FEAT-7 Layer 1)
forge test -vvv            # traces on failure
forge test --match-contract StakedReputationSetInvariantTest
forge test --match-contract PaidAccessSet     # unit (14) + fuzz (7) + invariants (4)
forge snapshot             # gas snapshot
```

Fuzz + invariant depth is set inline, not in `foundry.toml`:

- Unit fuzz (`test/*.fuzz.t.sol`): Foundry default 256 runs per `testFuzz_*`.
- Invariants (`test/*.invariant.t.sol`) pin `/// forge-config: default.invariant.runs = 64`
  and `default.invariant.depth = 64` above each `invariant_*` function → 64 × 64 = 4096
  calls per invariant. Targets are registered without forge-std via `targetContracts()` /
  `targetSelectors()` returning the local `FuzzSelector` struct (ABI-shape match to
  `StdInvariant.FuzzSelector`; see `test/FuzzHelpers.sol`).

Last local run in this environment (2026-08-17, after T-FEAT-7 Layer 1): **117 passed, 0 failed,
0 skipped** (the 92 pre-existing + 25 `PaidAccessSet`: 14 unit, 7 fuzz at 256 runs, 4 invariants
at 4096 calls — `invariant_noFundsEver`, `invariant_leafCountEqualsInserts`,
`invariant_rootEqualsReference`, `invariant_operatorIsGhost` — all green). Gas (forge, optimizer
200): `PaidAccessSet` deploy 2,071,378 (4,839 bytes; libraries linked), `insert` ~1.26M
(20 Poseidon2; median 0.90M on a warm path), `insertBatch` ~1.26M per leaf (max observed
6.17M for 6), `slash` ~0.91M, `setOperator` ~47.7k, `acceptOperator` ~28.3k. Live Sepolia:
deploy 2,071,319, `insert(leaf, 8)` 1,263,222 gas at ~1.08 gwei. Earlier (rln-v4): **92 passed**; both
`invariant_ethEqualsSumOfLiveBonds` (now per-tier wei) and the `activeCount` invariants
green at 4096 calls, 0 reverts; the tiers suite `test/StakedReputationSet.tiers.t.sol` (17)
and the tier fuzz tests (`testFuzz_register_tierBondAdmits`, `testFuzz_slash_onlyAtRecordedLimit`,
`testFuzz_hasher_tiersDistinctAndDefaultEqual`, 256 runs each) green. Gas (forge, optimizer
200): `register(commitment, limit)` ~1.28M (20 Poseidon2 for the on-chain tree; same as the
one-argument form), `slash(.., limit, ..)` ~0.92M, `initiateExit` ~0.92M, `withdraw` ~90k,
`RateCommitmentHasher.commitmentOf(s, limit)` ~55.8k. Live Sepolia rln-v4: register 1,283,077 /
921,848 gas, slash 919,847 gas at ~1.0 gwei.

Static analysis: run `slither .` if installed (see section 6). A `slither.config.json` is
committed at the repo root: it forces the Foundry framework (so solc 0.8.24 from
`foundry.toml` is used), excludes dependencies, and filters `node_modules`, `lib`, `test`,
and the machine-generated `RlnGroth16Verifier.sol` / `PoseidonT2.sol` / `PoseidonT3.sol`
(snarkJS/generated field arithmetic that would only produce noise).

---

## 6. Slither results

**slither was NOT run in this environment** — `command -v slither` found nothing and, per
task constraints, it was not installed. To run it:

```
pip install slither-analyzer
slither .
```

The committed `slither.config.json` is ready for that run (forces `compile_force_framework:
foundry`, `exclude_dependencies: true`, and `filter_paths` excluding tests + generated
verifier/Poseidon files). Expected hand-review posture going in: the in-scope contracts use
strict checks-effects-interactions with delete-before-payout on every `.call` (section 4),
so the common Slither high/medium detectors to scrutinize are `reentrancy-eth` /
`reentrancy-no-eth` (expected: none real — state is deleted before the external call) and
`arbitrary-send-eth` (expected: benign — `withdraw` sends to a proof-bound / operator-named
recipient, member `slash` to a fixed burn sink plus a caller-named bounty receiver). `low-level-calls` will fire
on the intentional `.call{value:}` payouts (informational). Populate this section with the
actual `slither . 2>&1 | tail` summary (high/medium counts, or "no high/medium") once run.
