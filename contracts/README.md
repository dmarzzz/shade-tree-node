# contracts/

Reference contracts for the on-chain staked reputation set. Design and rationale live
in [`docs/ONCHAIN.md`](../docs/ONCHAIN.md); this README is just the map.

## StakedReputationSet.sol

The admission gate: a fixed-bond, refundable, slashable, time-locked-exit staking
contract adapted from the Rate-Limiting-Nullifier `RLN.sol` registry shape. Reference
implementation, **unaudited, testnet-only**.

Two pieces are abstracted behind interfaces (both have real implementations in this dir):

- `IWithdrawVerifier` — `verify(commitment, limit, context, proof)`: the ZK proof that
  authorizes `initiateExit` / `withdraw` without revealing the member (proof of knowledge of
  the identity secret, bound to a per-action context, tied to the leaf at the member's
  RECORDED tier). Real: `WithdrawVerifier.sol` (Groth16); demo: `MockWithdrawVerifier.sol`.
- `ICommitmentHasher` — `commitmentOf(secret, limit)` (and the default-tier
  `commitmentOf(secret)`) recomputes the RLN rate-commitment leaf so `slash` can check a
  reconstructed secret against its commitment at the claimed tier. Real:
  `RateCommitmentHasher.sol` (Poseidon over BN254).

**Reputation tiers on chain (T-FEAT-8b, rln-v4-tiers).** A tier is the leaf's private
`userMessageLimit` (`docs/adr/0006-reputation-tiers.md`). The set records it:
`registerIdentity(identityCommitment, limit)` derives the leaf `Poseidon2(idc, limit)` on chain
(so the tier is proven, not declared; launch audit 2.1.4) and requires `bondFor(limit)` from an
immutable constructor table
(`extraLimits[]` / `extraBonds[]`, default tier `8 => BOND` always present, no owner /
setter), `limitOf(commitment)` / `allowedLimits()` are the views,
`slash(commitment, secret, limit, receiver)` recomputes the leaf at the claimed limit
(`BadLimit` if it is not the recorded one, `BadSecret` if the secret does not hash to the
leaf there) and burns that tier's bond, and the events carry the limit. The one-argument
`register` / three-argument `slash` overloads are the limit-8 path, byte-equivalent to the
rln-v3 contract. `docs/ONCHAIN.md` "Tiers on chain".

The Merkle root is maintained **off chain** in this reference: members and indices live
in a mapping and are emitted as events (`MemberRegistered` / `MemberExiting` /
`MemberWithdrawn` / `MemberSlashed`); the gateway and clients rebuild the tree from the
log and verify their local root against it (ROADMAP #2).

**Both root providers are now supported (T-DEV-9).** `StakedReputationSet` ALSO maintains
the identical RLN depth-20 Poseidon(2) incremental Merkle tree on chain and commits the
current root to a fixed storage slot (`currentRoot`, `ROOT_STORAGE_SLOT = 3`), updated on
every membership change with the SAME zero-in-place removal semantics as the off-chain
`reconstructRoot` (register = insert at the append index; exit / slash-while-active = zero
the leaf at its original index). So `currentRoot` equals the off-chain reconstructRoot root
by construction (pinned to the `lib/rln-removal-parity` golden in
`test/StakedReputationSet.t.sol::test_Root_*`). The light-client provider
(`lib/root-provider.mjs`, `LightClientRootProvider`) proves that slot with `eth_getProof`
and verifies the account + storage Merkle-Patricia proofs against a block's state root — so
it no longer trusts an RPC's event replay for the root's VALUE. What it still trusts is the
state root itself (fetched at a confirmed depth); validating that header against the beacon
sync committee (Helios) is the filed follow-up **T-DEV-9b**, with a `trustedStateRoot` hook
already in place to inject a verified root. Cost: 20 Poseidon(2) hashes per membership
change (~1.25M gas / register on the vendored pure-Solidity Poseidon; fine for testnet).
See docs/ONCHAIN.md, "Reading the root".

## PaidAccessSet.sol (T-FEAT-7 Layer 1)

The paid-access membership tree of [`docs/PAYMENTS.md`](../docs/PAYMENTS.md): the staked set's
structural sibling — same on-chain depth-20 Poseidon tree (`currentRoot` at slot 3), same leaf
via the same tiered `RateCommitmentHasher`, same immutable allowed-tier table, same
zero-in-place `slash(commitment, secret, limit, receiver)` — with **no funds on chain**:
payment settles OFF chain over HTTP 402 rails (x402 / MPP) to the operator, who then
`insert(commitment, limit)` / `insertBatch(..)`s the buyer's leaf (`onlyOperator`, not
payable). No exit / withdraw / sweep / receive; `slash` zeroes the leaf and pays nothing;
`operator` rotates by two-step `setOperator` / `acceptOperator`. The gateway unions this
tree's root with the staked set's. `docs/ONCHAIN.md` "Paid access set", deploy
`contracts/script/DeployPaidAccess.s.sol` (`docs/ONCHAIN-DEPLOY.md` §9), audit
`docs/CONTRACTS-AUDIT.md` I12–I15. Live on Sepolia (`network/sepolia/contracts.json`
`contracts.paidAccessSet`).

## Known simplifications (reference scope)

- `UNBONDING` must be `>= F + E + C` (freshness window + epoch + slash-confirmation
  margin); the constructor enforces a caller-supplied `minUnbonding` lower bound, but
  pinning the actual value to the gateway's live epoch parameters is an operator step.
- A withdrawn or slashed commitment can be re-registered (it is `delete`d, so it no
  longer `_exists`) and gets a fresh leaf index. Exit and withdraw proofs bind that index,
  the chain id and the set address (launch audit 2.2.1), so a proof captured from the old
  stake does not authorize the new one. A slashed identity's secret is public, so anyone
  can re-register it and later exit it; that only costs them a bond. Add a burned-commitment
  set if you want to forbid it outright.
- No reentrancy guard is strictly needed (state is deleted before the external payout
  and there are no post-transfer reads), but add one before mainnet as defense in depth.

## Deploy (intended)

Local `anvil` (or a mainnet fork) first, then Sepolia L1, then L1 mainnet, per
ONCHAIN.md (we target Ethereum L1, not an L2). A Foundry or Hardhat script should:

1. deploy the verifier + hasher (real RLN artifacts, or mocks for local e2e),
2. deploy `StakedReputationSet(bond, unbonding, minUnbonding, verifier, hasher, extraLimits, extraBonds)`,
3. point the gateway/shim at it via `SHADE_TREE_GROUP_CONTRACT` / `SHADE_TREE_RPC_URL` /
   `SHADE_TREE_GROUP_ID`.

Foundry: `script/Deploy.s.sol` (local anvil demo stack, tiers {8, 32}) and
`contracts/script/DeployRegistry.s.sol` (the persistent env-parameterised deployer,
`docs/ONCHAIN-DEPLOY.md`; `SHADE_TREE_TIER_LIMITS` / `SHADE_TREE_TIER_BONDS_WEI` for the tier table).
