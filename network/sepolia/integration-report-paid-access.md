# Live Sepolia smoke — PaidAccessSet (T-FEAT-7 Layer 1, paid-access membership tree)

> **Historical pre-v4 receipt.** “Live” below records the result on 2026-08-17. The Sepolia
> profile is retired and no longer supplies current Shade Tree runtime defaults.

**Result: PASS.** The `PaidAccessSet` — the operator-inserted paid-access membership tree of
`docs/PAYMENTS.md` (payment settles OFF chain over HTTP 402 rails; the contract only records
which leaves the operator admitted) — is live on Sepolia next to the rln-v4 staked set. One
leaf was inserted at tier 8 from the operator key; the on-chain `currentRoot()` equals the JS
`newGroup([leaf]).root` and storage slot 3; the negative paths (non-operator insert, unlisted
tier, live duplicate, wrong-limit / wrong-secret slash) all revert with the named errors; the
contract's balance is 0 before, during and after (it has no payable surface). Date: 2026-08-17.
Task: T-FEAT-7 (`docs/history/SHIP-PLAN.md`), design `docs/PAYMENTS.md`, contract notes
`docs/ONCHAIN.md` "Paid access set", audit `docs/CONTRACTS-AUDIT.md` I12–I15.

## What this contract is (and is not)

- **Is:** the structural sibling of `StakedReputationSet` — same depth-20 Poseidon(2)
  incremental tree, same leaf (`Poseidon2(Poseidon1(secret), limit)` via the SAME live tiered
  `RateCommitmentHasher`), same immutable allowed-tier table `{8, 32}`, same zero-in-place
  slash, `currentRoot` at the SAME storage slot 3 — so the light-client root provider and the
  gateway's tiered slasher (`DEFAULT_LIMIT` / `allowedLimits` / `limitOf` / `slash(c, s, limit,
  receiver)`) work against it unchanged. The gateway trusts the UNION of both sets' roots.
- **Is not:** a place money goes. `insert(commitment, limit)` / `insertBatch` are
  `onlyOperator` and NOT payable; there is no `deposit`, no price, no `sweep`, no `receive`.
  The stablecoin settles to the operator on the 402 rail (x402 / MPP); the operator (registrar)
  then inserts the buyer's leaf. `slash` zeroes the leaf and pays nothing (no bond is held;
  `receiver` is kept for call-shape parity). Operator rotation is a two-step
  `setOperator` / `acceptOperator`.
- **Pivot note:** a payable, per-tier-priced `deposit`/`sweep` variant was designed and
  Foundry-tested first (PR body of the T-FEAT-7 (1/3) PR) but NEVER broadcast; the design moved
  to off-chain 402 settlement before deploy, so no abandoned contract exists on chain.

## Deployment (fresh, this run)

| Item | Value |
|---|---|
| PaidAccessSet | [`0x4e8C2Bf5d3c5454A04837401095fce2646484111`](https://sepolia.etherscan.io/address/0x4e8C2Bf5d3c5454A04837401095fce2646484111) |
| deploy tx / block | `0x9835d062d007642dc739b6e2bae434f81286f25ea807f4d99dc74a2c880e4086` / 11510873 |
| deploy gas | 2,071,319 at ~1.08 gwei ≈ 0.0022 ETH (one CREATE; both Poseidon libraries reused via `--libraries`) |
| operator (registrar / insert authority) | `0xc8606C75E003EDA7C0a377B4708AbEC6EB7a7f02` (fleet operator hot key; `SHADE_TREE_PAY_OPERATOR` unset ⇒ deployer) |
| hasher (reused, rln-v4 tiered) | `0x29e9D6ae8d46A9D86D6A92a43307850e0FA06586` (`SHADE_TREE_COMMITMENT_HASHER`) |
| PoseidonT2 / PoseidonT3 (linked, reused) | `0xA20D550b5b3b99c0abB6E51d68d2a39955E69b55` / `0x82Cb42c70208a92DD5938b5f4D67C7d2313bE022` |
| params | `SHADE_TREE_PAY_LIMITS=8,32` → `allowedLimits() == [8, 32]`, `DEFAULT_LIMIT` 8, `MAX_LIMIT` 65535; no prices on chain |
| receipt bundle | [`paid-access-broadcast.json`](paid-access-broadcast.json); recorded with `shade-tree record-deploy --network sepolia --contract paidAccessSet --from-broadcast …` |

Verified with `cast call` right after the broadcast: `currentRoot()` ==
`10354334201938752428558948798274962999644820234654929486063894213598717249307` (the empty
depth-20 tree root) == `cast storage <addr> 3`, `leafCount()` 0, `liveCount()` 0,
`DEFAULT_LIMIT()` 8, `MAX_LIMIT()` 65535, `ROOT_STORAGE_SLOT()` 3, `operator()` as above,
`pendingOperator()` 0x0, `hasher()` as above, `allowedLimits()` `[8, 32]`, `isAllowedLimit(8)`
true / `(16)` false, `treeZeroValue()` `312829776…409292` (keccak(GROUP_ID)>>8),
`commitmentOf(111, 8)` == `11302006078516901731073162965056551612114122314181142374993834332168998510316`
(the JS golden, `test/Poseidon.t.sol`), balance 0.

## Smoke (one insert at tier 8, from the operator key)

A fresh identity secret was generated for the run (never recorded; leaf =
`deriveCommitment(secret, 8)`), and the expected root was computed off chain first
(`lib/rln.mjs newGroup([leaf]).root`).

```
leaf                                  3173469406562808608136455723690012297332154121683446842802892401114468614068
expected root (JS newGroup([leaf]))   6430323861468492113547438473981076657535586200031679816061979000753954952048
static  insert(leaf, 8)  from 0x…dEaD (not the operator)   -> reverted 0x7c214f04 = NotOperator()
static  insert(leaf, 16) from the operator                  -> reverted 0x1e0267bb = BadLimit()   (16 not in the table)
send    insert(leaf, 8)  from the operator
        tx 0x67afe076d8557fb416784fc1e2e583789269ccd7c8a5cbd94bcf523d63f93a32  block 11510877  gasUsed 1,263,222  status 1
        1 log: topic0 0x829b3fd9…f992 == keccak("Inserted(uint256,uint256,uint256,uint256)"), topic1 = leaf,
               data = (limit 8, index 0, root 6430323861468492113547438473981076657535586200031679816061979000753954952048)
after   currentRoot()  == 6430323861468492113547438473981076657535586200031679816061979000753954952048   == JS root  ✓
        storage slot 3 == the same value                                                                     ✓
        leafCount() 1  liveCount() 1  limitOf(leaf) 8  leaves(leaf) == (index 0, limit 8)                    ✓
static  insert(leaf, 8) again from the operator             -> reverted 0x17bdf310 = AlreadyInserted()
static  slash(leaf, 1, 32, receiver)                        -> reverted 0x1e0267bb = BadLimit()   (recorded tier is 8)
static  slash(leaf, 1, 8, receiver)                         -> reverted 0xe1dcd597 = BadSecret()
static  slash(leaf, <secret>, 8, receiver)                  -> simulates OK (NOT broadcast: the smoke leaf stays live as the set's first member)
balance 0 wei before / after (nothing payable; a value-carrying insert reverts, see test_NoFunds_EthCannotEnter)
```

## Spend (this task, from the operator hot key)

Balance 0.04300 → 0.03946 ETH: deploy ≈ 0.0022 ETH + insert ≈ 0.0014 ETH ≈ **0.0035 ETH**
(cap 0.01). Nothing is held by the contract.

## Honesty / scope

- This is Layer 1 only. The **402 registrar** (x402 / MPP settlement → `insert`), the
  gateway's **root union** (`SHADE_TREE_PAID_ACCESS_CONTRACT`, one root provider per contract,
  `roots: members.json + staked(0x…) + paid(0x…)` startup line, anonymity-set floor log) and
  the **client** flow are the other two thirds of T-FEAT-7 and are NOT exercised here.
- The event-replay root provider needs the two new topics (`Inserted` / `Slashed(commitment,
  limit, index, root)`; both carry the post-update root); the light-client provider (slot 3)
  is unchanged. At the time, `SHADE_TREE_NETWORK=sepolia` resolved
  `SHADE_TREE_PAID_ACCESS_CONTRACT` to this address. The retired profile no longer does.
- The trust statement is unchanged from `docs/PAYMENTS.md`: the operator can decline to
  insert or to honor a valid proof (buyer–seller trust); what the chain gives is a public,
  provable record of exactly which leaves were admitted, and payer↔user unlinkability at
  redemption. The tier is DECLARED at insert (the contract cannot see inside a leaf), as in the
  staked set.
- Reference implementation, unaudited, testnet-only.
