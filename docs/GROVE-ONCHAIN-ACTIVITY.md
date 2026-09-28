# Canopy v2 onchain activity

The optional canopy v2 `onchain` section is a delayed, finalized aggregate from a current
envelope-v4 deployment. It is not enabled for the checked-in Sepolia deployment: that record is
`status: "retired"`, predates envelope v4, lacks runtime code hashes and lacks an immutable payment
attribution source. The observer refuses it before making an RPC request.

## Definitions

- Staked membership is `StakedReputationSet.activeCount` at one finalized block. Exit removes a
  commitment before withdrawal; slash while exiting does not decrement it again.
- Paid membership is `PaidAccessSet.liveCount` at the same block. Classes remain separate; a
  commitment in both is not deduplicated or called a person.
- A completed settlement requires a signed immutable registrar fact plus independently verified,
  finalized EIP-3009 settlement calldata and a successful `PaidAccessSet.Inserted` event for the
  same commitment. Asset, payee and atomic value must match. Direct/manual inserts, failed inserts,
  and unrelated token transfers do not count.
- Finalized `MemberSlashed` and `Slashed` events are counted separately. Gateway decision metrics
  are not authoritative.

`nextIndex`, `leafCount`, mutable prices, retired tUSD facts, and the old registrar store are never
substitutes for these definitions.

## Required live inputs

The explicit target record must be `status: "live"`, `protocolVersion: 4`, and provide chain ID;
confirmation policy; approved HTTPS RPCs; inclusive migration and retirement boundaries; current
staked and paid addresses, deployment blocks and keccak256 runtime-code hashes; and an immutable
payment asset, decimals, payee, registrar key ID/EIP-191 signer, and
`signed-registrar-chain-verified-v1` attribution rule. There is deliberately no default target.

The signed registrar aggregate freezes asset, atomic value, payee, rail, settlement transaction,
insert transaction and the private collector-side commitment. Price changes cannot rewrite
history. The public projection contains none of the commitments, payer/payee identities, registrar
orders, or transaction hashes.

Run the target-independent observer only after those inputs exist:

```bash
node scripts/grove-onchain-observer.mjs \
  --target /secure/current-v4-record.json \
  --registrar /secure/signed-registrar-aggregate.json \
  --out /tmp/grove-onchain.json

SHADE_TREE_GROVE_SIGNING_KEY="$(< /secure/grove-private.pem)" \
  node scripts/grove-snapshot.mjs --network sepolia --relay 1 \
  --onchain /tmp/grove-onchain.json --out /tmp/grove-v2.json
```

## Finality, failures and privacy

The collector selects one block at least six hours behind collection and below the confirmation
head. All approved RPCs must agree on chain, block, code, counters, transactions and receipts. Logs
are fetched in bounded chunks and deduplicated by chain, contract, transaction hash and log index.
Indexed block hashes permit rewind/replay on a changed canonical branch; backfill is idempotent.

A retired/missing target, wrong chain, code mismatch, removed log, partial read, RPC disagreement,
counter/event disagreement, non-final receipt, bad registrar signature, failed attribution or
migration-boundary mismatch makes the observation unavailable. Failure is never zero. If the
optional input cannot be verified, `onchain` is omitted; v1 and relay-only v2 remain compatible.

Publication is delayed by at least six hours. Each staked, paid, settlement and enforcement value
has a minimum contract cohort of five. Values below five, including verified zero, are
`suppressed` with `minimum-cohort`; unconfigured payment attribution is `unavailable` with no
amount. This does not claim five commitments are five people. Delay, no raw history, separate
contract classes, and no identity dimensions limit differencing. Published cumulative values
cannot be made private again, so they remain delayed and cohort-gated permanently. A shorter delay,
lower cohort, timeline, per-tier split or second network requires a new privacy review and schema.
