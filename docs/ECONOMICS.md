# ShadeNet economics (H2)

Status: set 2026-10-05 for the Sepolia research preview, succeeding the two-tier table of
2026-09-30, whose set stays admitted while its members move over (see "The previous set"). The numbers live in one file,
[`network/sepolia/economics.json`](../network/sepolia/economics.json); this page is the reasoning
behind them and the list of what each number is traced to. Change the file, not this page: the
Get access page, both SDKs and the client read the deployment record the file produces.

Every number below carries its source class: **[record]** the deployment record or economics
file, **[contract]** the Solidity or a value read from the deployed set, **[spec]** the protocol
spec or an ADR, **[vendor]** a DigitalOcean price list read with `doctl` on 2026-09-30 and not
read again for this revision, **[measured]** something this repo ran (the transaction named, or
the fork rehearsal), **[assumption]** a choice with no measurement behind it. Nothing on this
page was measured against real users. The new set has had no member other than the smoke test's
two throwaway identities; the previous set has one.

## The decision in one table

| Field | Value | Why, in one line |
|---|---|---|
| `tiers[0]` | limit 8, bond **0.01 Sepolia ETH** | the only tier: eight proof slots per 60-second epoch for one faucet-sized bond |
| `defaultLimit` | 8 | the only tier, so the page and `shadenet init` have nothing to choose |
| `sessionTickets` | **true** | a slot buys a book of six tunnels at one node instead of one tunnel |
| `unbondingSeconds` | 86 400 (24 h) | slash evidence crosses the fleet asynchronously; a day gives a human slasher one attention cycle |
| `slash.rewardDivisor` | 10 | 10 % bounty to the slasher, 90 % burned: self-slashing to skip unbonding loses 90 % |

There is no sponsor seat pool. The 2026-09-30 table carried `sponsorSeats` (24 seats funded by the
project); the field is gone from the file and nothing in the code read it **[record; decision of
2026-10-05: no ETH giveaways]**. Anyone may still stake someone else's commitment from the Get
access page.

Bonds are refundable collateral on a testnet. They are not revenue and they are not real money,
so the tuning targets are abuse resistance (what misuse costs) and an easy first stake, not income.

The set that carries this table is `0x789967F0bDD7f3a96fb60F6D315e93F103b5680b`, deployed in block
11 847 802 **[record, measured: transaction
`0x821cf83121fb14a640290ad7592dac284066d0b4dd66abd876abba5ab339da6b`]**. Read back from it:
`allowedLimits()` = `[8]`, `bondFor(8)` = 0.01 ETH, `bondFor(1)` = 0, `UNBONDING()` = 86 400,
`SLASH_REWARD_DIVISOR()` = 10 **[contract, read 2026-10-05]**.

## Why one tier, and why 8

**The contract fixes the table at deployment and always admits tier 8.** `DEFAULT_LIMIT = 8` is a
constant, extra tiers are optional constructor arguments, and the set has no owner
**[contract: `contracts/StakedReputationSet.sol`]**. So the only one-tier table that needs no
Solidity change is tier 8 alone, and a different limit means a new set. That is why the limit is
8 and not some other generous number **[contract]**; whether 8 is the right size for the product
is an **[assumption]**.

**What it changes for a member.** The previous default tier gave one slot a minute. Tier 8 gives
eight, and with session tickets on each slot opens a book of six tunnels: up to 48 tunnels a
minute where the old default gave six **[spec: ADR 0011 "a tier-8 member may open 8 books (48
tunnels, 320 MiB) per epoch"; `crates/shadenet/src/scheduler.rs` computes `tier x tickets`]**.

**The bond did not go up with the limit.** The old table priced tier 8 at eight tier-1 bonds
(0.08 ETH) so that a big tier could not undercut eight small ones. With one tier there is nothing
to undercut, and 0.01 ETH is kept so that the first stake stays one faucet visit
**[assumption: faucet drip sizes were not measured]**. The cost of that choice is that a slot is
eight times cheaper to misuse than it was: see "What misuse costs".

**The tier is not visible in a proof.** An earlier version of this page said the tier is "a
public input of every proof". That was wrong. The RLN proof has five public signals,
`[y, root, nullifier, x, externalNullifier]`, and the member's limit is a private input that the
circuit range-checks against the leaf. Checked for this revision against
`circuits/rln/verification_key.json` (`nPublic` is 5), `circuits/rln/ARTIFACTS.md` (the signal
order), `contracts/RlnGroth16Verifier.sol` (`uint[5] _pubSignals`) and the prover call in
`packages/node/lib/rln.mjs` (`userMessageLimit` is a witness input) **[contract, spec:
`docs/THREAT-MODEL.md` "Reputation tiers"]**. What is public is the registration: the
`MemberRegistered` event carries the limit and the transaction carries the bond **[contract]**.
A node that verifies a proof cannot tell which tier made it, so tiers never split the set that
stands behind a proof. One tier is a simplification (no choice on the page, one bond, one number
to explain), not an anonymity requirement.

## What a slot is and what it costs the operator

**What a slot buys.** The rate policy, not the economics file, fixes this: a member has `limit`
proof slots per fixed 60-second epoch, and each slot carries up to 40 MiB of combined relayed
bytes **[record: `ratePolicy.epochSeconds` = 60, `payloadBytesPerSlot` = 41 943 040]**. With
session tickets on, a slot is one `research-v1` book: six single-use tunnel tickets at one node,
valid 90 s, four tunnels open at once, still inside that slot's 40 MiB and shaped at 64 KiB/s up
and 512 KiB/s down for the whole book **[spec: ADR 0011, `docs/design/SESSION-TICKETS.md`]**. The
byte ceiling is keyed by the proof's slot, so a book can never relay more than the slot it was
bought with **[spec: ADR 0011]**.

**What the fleet costs.** Five DigitalOcean droplets, all `s-1vcpu-2gb`: one Elder, three egress
nodes and the Lab runner **[measured on 2026-09-30: `doctl compute droplet list`]**. That size
lists at $12.00 per month each, so the droplet fleet is $60 per month, of which the three egress
nodes are $36 **[vendor]**. The second Elder runs on the operator's own machine at no marginal
cost **[assumption]**. Each droplet includes 2 000 GiB of outbound transfer a month, and more
costs $0.01 per GiB **[vendor, as quoted in ADR 0009]**.

**Bandwidth, worst case.** One member who fills every slot of every epoch relays
8 x 40 MiB = 320 MiB a minute **[record: limit x `payloadBytesPerSlot`]**. Over a 30-day month
(43 200 epochs) that is 13 500 GiB of payload, or about 15 525 GiB billable with the 1.15
transport multiplier ADR 0009 uses for TCP, TLS and Tor overhead **[spec: ADR 0009's formula]**.
The three egress nodes include 6 000 GiB a month between them **[vendor]**, so:

| Saturating members, all month | Billable GiB | Over the included 6 000 | Overage at $0.01 per GiB |
|---|---|---|---|
| 1 | 15 525 | 9 525 | about $95 |
| 2 | 31 050 | 25 050 | about $250 |
| 3 | 46 575 | 40 575 | about $406 |

One saturating member uses the three nodes' included transfer in about 11.6 days, and every
further one adds about $155 a month **[inference from the record and vendor numbers above]**.
Under the old default tier the same member cost one eighth of that (1 941 GiB a month, inside the
included transfer). The shaping does not lower the worst case: at 576 KiB/s a book reaches its
40 MiB in about 71 seconds, inside its 90-second life, so the byte cap is the number that binds
**[inference from ADR 0011's numbers]**.

Three things this arithmetic leaves out, stated so nobody reads it as a bound:

- It assumes each slot's cap is enforced once across the canopy. The record says cross-node
  enforcement is best effort (`crossGateway: best-effort-fleet-tally`) **[record]**; how many
  extra bytes a member could get by presenting one slot to several nodes was not measured.
- It counts only the three egress nodes' included transfer. The provider pools included transfer
  across an account's droplets **[vendor, as quoted in ADR 0009]**, so the real allowance may be
  larger; the bill was not checked.
- No byte totals per member have ever been recorded. Text-oriented search and fetch was estimated
  at about 4 MiB per session in ADR 0009, a tenth of the cap **[spec]**; a member who uses all
  eight slots for that workload relays about 32 MiB a minute, a tenth of the worst case
  **[inference]**.

**The lever, if the worst case matters.** The 40 MiB cap is not a field of the economics file.
The `public-stake-v1` profile pins it: `packages/node/lib/network-record.mjs`,
`deploy/v4/preflight.mjs` and the Ansible role each refuse a record with any other
`payloadBytesPerSlot`, and the `research-v1` session class carries the same number in
`crates/shadenet-proto/src/session.rs` **[spec, checked in code 2026-10-05]**. Lowering it is a
change to those four places and a fleet roll, not a record edit. The cheaper controls are
operational: watch transfer per node, and slash or stop admitting a set that is being abused.

## What misuse costs

A double-spend of one slot in one epoch (two different signals from one slot) reveals the
identity secret, and anyone can then slash the bond **[spec: `docs/PUBLIC-STAKING.md`]**. The
slasher gets `bond / 10` = 0.001 ETH; the rest, 0.009 ETH, burns to `address(0)` **[contract;
measured on the new set: slash transaction
`0x1d90055a3e96dc2639688f2236a4e44e01bbe8dadc144093966faffaa1907d46`, `SlashPayout` reports
exactly that split]**.

Two honest consequences of keeping the bond at 0.01 ETH while the limit went to 8:

- The bond now stands behind eight slots, not one: 0.00125 ETH of collateral per slot per epoch
  where the old default tier had 0.01 **[record]**. On Sepolia the binding limit on a Sybil
  attacker is the faucets' drip, not the price, since testnet ETH has no market **[assumption]**.
- The bounty does not cover the slasher's gas at today's price. The slash used 954 181 gas at
  1.10 gwei, 0.00105 ETH, against a 0.001 ETH bounty **[measured: same transaction]**. An earlier
  version of this page assumed slashing cost "far less than 0.001 ETH"; it does not. Slashing is
  run by the operator, who pays the difference.

## The previous set

The two-tier set `0xDEB294E6e9ad6A3FcBDeFfD1F67aC9678AC94bBC` (tier 1 at 0.01 ETH, tier 8 at
0.08 ETH, deployed 2026-09-30) is not retired. It took its first member on 2026-10-05, a tier-1
seat staked in block 11 847 864 **[contract: `activeCount()` = 1, transaction
`0xab3a4198071ac48ec570a433ce66d313abc26eb35614d471cd005a3bbf35139b`]**, about an hour after the
new set went up. A set's table cannot change, so that member keeps one slot a minute there until
they move.

Both sets stay admitted for a transition. The record names one staked root, the new set; a node
admits further sets through its own configuration (`SHADENET_SETS`, the role's
`shade_tree_extra_sets`) and advertises the union in its signed `caps.sets`, which is how the
fleet already served the staging set beside production **[spec: `docs/OPERATOR.md` "Serving two
canopies from one node", `docs/STAGING-REHEARSAL.md` section 12]**. A client only uses nodes that
advertise its own record's set, so a v0.7.1 client (bundled record: the previous set) keeps
working for as long as the nodes list `0xDEB2…4bBC`. Slashing on the previous set still resolves
a tier-1 leaf: the node's slasher unions its tier list with each set's own `allowedLimits()`
**[spec: `packages/node/gateway/gateway.mjs` `makeOnchainSlasher`]**.

Moving costs a member one more bond for a day: stake a new tier-8 identity on the new set (0.01
ETH), exit the old seat, and withdraw its 0.01 ETH after 24 hours **[contract]**. Nothing
refunds the gas, about 0.001 ETH per step at 1 gwei **[measured, above]**. The Get access page is
built from the new record and cannot exit a tier-1 identity; the CLI can
(`shadenet exit-member --contract 0xDEB2…4bBC --identity identity.json`).

## Session tickets: on

Unchanged from 2026-09-30. ADR 0011 leaves the choice to this file and records the trade.

- The workload the product is for is a search plus a handful of result origins. A v4 proof is
  bound to one destination, so with tickets off a slot fetches one origin. With tickets on a
  six-origin session fits in one slot **[spec: ADR 0011]**.
- It costs the operator nothing per slot: the 40 MiB cap and the shaping are per slot
  **[spec: ADR 0011]**.
- It does not change how many proofs a member makes per epoch **[spec: ADR 0011 "one proof, six
  tunnels"]**.

What it costs: the six tunnels of one book are visibly one session to the node that serves them,
and per-tunnel node rotation is gone for the life of a book (90 s). The proof still hides which
member. A member who prefers one proof per tunnel sets `SHADENET_SESSION_TICKETS=0`; the record's
`true` is the default, not a lock **[spec: ADR 0011]**.

The nodes have run with the switch on since the fleet roll of 2026-10-01 **[measured:
`docs/LAUNCH-REPORT.md` "Fleet", `docs/STAGING-REHEARSAL.md` section 12]**. The fleet has not yet
served a member of this set.

## Unbonding: 24 hours

The contract's floor is 3 720 s: root freshness 60 + epoch 60 + slash confirmation 3 600
**[contract, record: `minUnbondingSeconds`]**. Slash evidence is gathered by a fleet tally that
is asynchronous and fail-open **[spec: `docs/PUBLIC-STAKING.md`]** and slashing is submitted by
an operator key, not by the nodes themselves. A day gives that path one human attention cycle
before a double-spender can withdraw; the floor does not. Kept at 86 400. With one tier there is
no tier change to double-fund for a day.

## What a stake costs, measured

Gas on the new set, at about 1.0 to 1.1 gwei on 2026-10-05 **[measured]**:

| Step | Gas | Transaction |
|---|---|---|
| Deploy all four contracts | 3 733 509 (0.0039 ETH) | set `0x821cf831…da6b`, hasher `0xb03bd4d8…5c87`, verifiers `0xb30a957f…5249` and `0x50e4b8b4…68b2` |
| First registration | 1 317 674 | `0xe63c30103fae5b157db6347ea035449a03e45198af2269875aee3d455ffe2b21` |
| Second registration | 956 445 | `0x72e2b2307c37ea19899f18c043b50cb12f25775cafd808f3bd4d0c12fb46133a` |
| Exit, with a real Groth16 proof | 1 105 193 | `0x7cb22be6faf88e54af5bd9468fac5b3325fe20563e21068039a7b70c59d37231` |
| Slash | 954 181 | `0x1d90055a3e96dc2639688f2236a4e44e01bbe8dadc144093966faffaa1907d46` |

So a new member needs the 0.01 ETH bond plus roughly 0.001 ETH of gas at 1 gwei. Leaving costs
gas twice more, an exit (about 0.0011 ETH at 1 gwei) and, 24 hours later, a withdraw that returns
the whole bond **[measured; the withdraw has run only on the fork until the smoke test
resumes]**.

The smoke test (`scripts/smoke-staking.mjs`) is not free: it stakes two bonds, slashes one
(0.009 ETH burned, 0.001 ETH to a throwaway receiver) and withdraws the other to a throwaway
recipient, so each run costs 0.02 ETH plus gas that does not come back **[measured: deployer
balance 2.0041 ETH before the deploy, 1.9757 ETH after the deploy and the smoke]**.

## What Dan can change, and where

| To change | Edit | Then |
|---|---|---|
| The bond | `tiers[0].bondWei` in `network/sepolia/economics.json` | a new set: `node scripts/deploy-contracts.selftest.mjs`, `node scripts/deploy-contracts.mjs --network sepolia --fork`, then `--broadcast --verify`; the nodes keep admitting the old set until its members have restaked |
| Add a tier beside 8 | another entry in `tiers[]`, and `defaultLimit` | the same: tiers are constructor arguments, so a new set |
| A single tier other than 8 | not possible with this contract | `DEFAULT_LIMIT` is a Solidity constant; it needs a contract change, a new bytecode manifest and a new set |
| Session tickets | `sessionTickets` | no new set: the record carries the switch; rebuild the record and roll the fleet |
| Unbonding, slash split | `unbondingSeconds` (at least 3 720), `slash.rewardDivisor` (2 to 1000) | a new set (both are constructor arguments) |
| The 40 MiB per slot | not in this file | a profile change, see "The lever" above |
| Freeze or unfreeze the decision | `status`: `"final"` deploys, `"placeholder"` refuses | the production gate in `deploy-contracts.mjs` |

## Scope

This page decides the tier table, the bond, the ticket switch, unbonding and the slash split. It
does not claim anything about demand, retention or what a slot is worth to anyone. It does not
change the rate policy (epoch, cap, shaping), the contract, the circuits, the proof keys or any
signed string: the limit is a private input of the same circuit, so the set deployed on
2026-10-05 uses the same verifier bytecode and the same PSE ceremony keys as the previous set
**[contract: `deploy/v4/public-stake-v1-bytecode.json`, read back at deploy]**.
