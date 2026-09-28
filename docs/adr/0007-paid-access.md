# ADR 0007: Paid access is an operator-inserted leaf in a second on-chain tree, redeemed with the same RLN proof

- Status: Accepted; the gateway / root / slash / client half is shipped (T-FEAT-7 2/3, this
  ADR's PR); the `PaidAccessSet` contract (ship/pay-contract) and the HTTP 402 registrar
  service are the companion slices. SUPERSEDES the payment rail in `docs/PAYMENTS.md`
  "Layer 1" as originally written (a native-ETH `deposit(commitment) payable` / `sweep()`
  contract): per the user's decision of 2026-08-17 payments settle over HTTP 402 rails (x402 +
  MPP, USDC on Sepolia) handled by a registrar, and the contract is operator-insert-only. The
  rest of that design — the on-chain tree, off-chain redemption via the existing RLN proof, no
  facilitator, Layer 0 as the buyer's choice — is unchanged and is what this ADR records.
- Date: 2026-08-17
- Task: T-FEAT-7 (docs/history/SHIP-PLAN.md) — payments / anonymous access funding

## Context

Membership was granted (a friend's leaf in `members.json`) or staked (`register-member`, a
refundable bond in `StakedReputationSet`, ADR 0006 tiers). `docs/PAYMENTS.md` designed a third
way in: access that is BOUGHT, under four requirements (anonymous, cheap, ergonomic, scalable)
and one sharpened constraint (no facilitator party: only the chain and the operator you are
paying). Its key move is that redemption is the proof the gateway already verifies — a
membership proof against a second tree, the paid set — so nothing per-message changes.

Its Layer 1 was a payable contract: `deposit(commitment) payable` at one fixed denomination,
`sweep()` to the operator, the deposit event feeding the tree. Two things moved before build:

1. Tiers shipped (ADR 0006): a leaf is `Poseidon2(Poseidon1(identitySecret), limit)`, so a paid
   leaf carries its tier too, and "one fixed denomination" becomes "one fixed price per tier"
   (the tier bucket is public either way — it is public for staked members already).
2. The user decided (2026-08-17) that the money should move over HTTP 402 rails (x402 + MPP,
   USDC), not as native-ETH deposits: better rails for a service, stablecoin pricing, and the
   402 flow is where the buyer's identity decorrelation actually happens. That makes the
   contract's job smaller: it RECORDS paid leaves; it does not custody funds.

## Decision

1. **A second on-chain tree, structurally the sibling of `StakedReputationSet`.** `PaidAccessSet`
   keeps the identical incremental depth-20 Poseidon(2) tree with `currentRoot` at storage slot
   3 (so `LightClientRootProvider` works unchanged), the identical leaf (tiered
   `RateCommitmentHasher`), `limitOf` / `leafCount` / `allowedLimits` / `DEFAULT_LIMIT`, and the
   identical `slash(commitment, secret, limit, receiver)` (prove the secret, zero the leaf — no
   bond to burn). What it drops: exit / withdraw (nothing is refundable) and, after the pivot,
   anything payable: `insert(commitment, limit)` / `insertBatch` are `onlyOperator`. The
   payment itself is an off-chain 402 exchange between buyer and registrar; the registrar
   inserts the buyer's rateCommitment. Live on Sepolia (PR #50); the anvil selftest deploys it
   from its forge artifact.
2. **The gateway trusts a UNION of root sources, not one.** `SHADE_TREE_GROUP_CONTRACT` became a comma
   list (single value byte-equivalent), `SHADE_TREE_PAID_ACCESS_CONTRACT` appends the paid set, and
   `SHADE_TREE_ROOTS` (default: `static` while `members.json` exists + `onchain` for every contract)
   selects sources — the fleet keeps admitting members.json friends WHILE admitting staked and
   paid leaves. One `RootProvider` (node or light) per contract, unioned by
   `lib/root-provider.mjs:CompositeRootProvider`; a failing child is dropped from that refresh,
   never blanks the union. `gateway/gateway.mjs:initRoots` / `resolveRootSources`. Startup:
   `roots: members.json + staked(0x…) + paid(0x…)`.
3. **Redemption is unchanged (subscription semantics).** Same envelope, same proof, nullifier
   scoped to the epoch: a paid leaf earns a fresh `limit` budget every epoch until it is slashed
   (open item 2 of PAYMENTS.md: subscription, not pay-as-you-go; expiry is a follow-up).
4. **Slashing routes to the contract that holds the leaf.** After an over-spend the gateway
   resolves the tier (`resolveSlashLeaf`) and asks each configured contract — the primary
   `SHADE_TREE_SLASH_CONTRACT` first, then the group list, then the paid set — whether it holds a
   live leaf of the reconstructed secret (`limitOf != 0`; `isActive` on rln-v3), and submits
   ONE slash to that contract (`gateway/gateway.mjs:makeRoutingSlasher`). A paid over-spender
   loses its paid leaf; a staked one its bond; held by none → the primary gets the default
   claim as before.
5. **The anonymity-set floor is logged, not enforced.** `SHADE_TREE_PAID_MIN_LEAVES` (default 8):
   `paid-access anonymity set: N leaves (floor K=8)`, WARN below it, never refuse (open item 3:
   a deployment parameter, not a proven bound; hide nothing, gate nothing).
6. **Live root, not a pinned snapshot** (open item 1). The gateway reads the current confirmed
   root (`finalized`, or `head - SHADE_TREE_CONFIRMATIONS`) plus the freshness ring
   (`SHADE_TREE_FRESHNESS_ROOTS`), exactly as for the staked set — reorg safety comes from the
   confirmation depth, and a proof built against a just-superseded root still verifies inside
   the ring. No separate per-epoch pin was needed.
7. **Clients discover which set holds their leaf.** The JS client tries `members.json`, then each
   configured contract in order, rebuilding that tree from its event log
   (`lib/root-provider.mjs:loadGroupFromContract`; `client/shade-tree-client.mjs:makeLeafSourceLoader`)
   and proving against it; a leaf found nowhere is a precise error naming every source. The
   Rust client keeps its static `--members` file: `shade-tree leaves --contract <addr>` exports any
   on-chain set in that shape (`group/leaves.mjs`, zeros preserved).

## Consequences

- No facilitator is added: the buyer touches the chain (to be inserted) and the operator /
  registrar (to pay), and the gateway still cannot tell which leaf a proof opens.
- Trust: prepaid buyer-seller trust in the operator (a paid member refused a valid proof, or
  never inserted, has no on-chain recourse) — the same trust `docs/PAYMENTS.md` accepted
  ("irreducible for any prepaid service"), sharpened by the pivot: the operator's insert key is
  the paid set's admission authority (a stolen key mints admissions, never money).
- Leak ledger additions: the payment (rail, payer, timing) and the insert tx are visible where
  they happen; the TIER BUCKET is public in the insert event; which ROOT a proof opens (static /
  staked / paid) is public to the gateway. Use stays unlinkable to all of them. Mitigations:
  Layer 0 (fresh address / account through a pool of the buyer's choice), batched inserts
  (dwell time), a healthy paid crowd (the floor).
- The gateway's slasher now consults the root contracts as targets (routing). A single
  configured contract is byte-identical to before.
- Registrar / 402 specifics (prices, rails, receipts) are documented by the registrar slice, not
  here; the contract's `allowedLimits()` is the only on-chain trace of the tier table.

## Alternatives considered

- **Native-ETH `deposit() payable` + `sweep()` on the contract** (PAYMENTS.md as written).
  Rejected 2026-08-17 by user decision in favour of 402 rails: stablecoin pricing, an existing
  payment protocol, and no funds custody in an unaudited contract. The tree/redemption design
  survives intact.
- **One tree for everything** (insert paid leaves into `StakedReputationSet`). Rejected: that
  contract's admission is a bond posted by anyone (permissionless `register`), and mixing an
  operator-inserted leaf into it would either need an owner backdoor on the staked set or a fake
  bond; a sibling contract keeps each set's admission rule honest and lets the gateway name the
  source it trusts.
- **Replacing members.json when a contract is configured** (the pre-T-FEAT-7 behavior). Rejected:
  the fleet's friends must keep egressing while paid/staked leaves are admitted; the union is
  the least surprising default, and `SHADE_TREE_ROOTS=onchain` restores the old behavior explicitly.
- **Pinning a per-epoch root snapshot** (open item 1). Not needed: confirmation depth + the
  freshness ring already bound reorgs and just-superseded roots.
- **Refusing proofs below the anonymity floor.** Rejected (PAYMENTS.md open item 3): the floor
  is not a proven bound; refusing would deny service on a heuristic. Log it, gauge it, warn.

## References

- `docs/PAYMENTS.md` (design of record + "Shipped" section), `docs/adr/0006-reputation-tiers.md`
- `lib/root-provider.mjs` (`CompositeRootProvider`, `configuredContracts`, `parseContractList`,
  `reconstructGroup`, `loadGroupFromContract`, paid event topics)
- `gateway/gateway.mjs` (`resolveRootSources`, `describeRootSources`, `initRoots`,
  `PAID_MIN_LEAVES`, `makeRoutingSlasher`, `makeOnchainSlasher.holds`)
- `client/shade-tree-client.mjs` (`makeLeafSourceLoader`), `group/leaves.mjs`, `contracts/PaidAccessSet.sol`
- Tests: `test/paid-access.selftest.mjs` (anvil, real proofs), `gateway/root-sources.selftest.mjs`,
  `client/leaf-source.selftest.mjs`, `group/leaves.selftest.mjs`, `lib/root-provider.selftest.mjs`
- zk-creds "insertion equals issuance": Rosenberg, White, Garman, Miers, IEEE S&P 2023
