# ShadeNet launch economics (H2)

Status: set 2026-09-30 for the Sepolia research preview. The numbers live in one file,
[`network/sepolia/economics.json`](../network/sepolia/economics.json); this page is the reasoning
behind them and the list of what each number is traced to. Change the file, not this page, and
the page, both SDKs and the docs follow the deployment record the file produces.

Every number below carries its source class: **[record]** the deployment record or economics
file, **[contract]** the Solidity, **[spec]** the protocol spec or an ADR, **[vendor]** a
DigitalOcean price list read with `doctl` on 2026-09-30, **[measured]** something this repo ran
(the M7 staging rehearsal or the fork rehearsal), **[assumption]** a choice with no measurement
behind it. Nothing on this page was measured against real users; the canopy has served only
rehearsal traffic.

## The decision in one table

| Field | Value | Why, in one line |
|---|---|---|
| `tiers[0]` | limit 1, bond **0.01 Sepolia ETH** | one faucet visit, one research session per minute |
| `tiers[1]` | limit 8, bond **0.08 Sepolia ETH** | linear: eight slots cost eight bonds, so a big tier never undercuts eight small ones |
| `defaultLimit` | 1 | what the page and `shadenet init` stake unless told otherwise |
| `sessionTickets` | **true** | a slot buys a book of six tunnels at one node instead of one tunnel; the product's workload is a search plus a few result pages |
| `unbondingSeconds` | 86 400 (24 h) | slash evidence crosses the fleet asynchronously; a day gives a human slasher one attention cycle |
| `slash.rewardDivisor` | 10 | 10 % bounty to the slasher, 90 % burned: self-slashing to skip unbonding loses 90 % |
| `sponsorSeats` | 24 seats at the tier-1 bond (0.24 ETH) | agent preview seats funded at M8 so an agent needs no faucet |

Bonds are refundable collateral on a testnet. They are not revenue and they are not real money,
so the tuning targets are abuse resistance (what a slot costs to misuse) and a healthy anonymity
set (how many honest members stand behind each proof), not income.

## What a slot is and what it costs the operator

**What a slot buys.** The rate policy, not the economics file, fixes this: one proof slot per fixed
60-second epoch per tier limit, up to 40 MiB of combined relayed bytes per slot **[record:
`ratePolicy.epochSeconds`, `payloadBytesPerSlot` = 41 943 040]**. With session tickets off a slot
is one target-bound HTTPS `CONNECT` tunnel. With them on (this decision) a slot is one
`research-v1` book: six single-use tunnel tickets at one node, valid 90 s, four tunnels open at
once, still inside that slot's 40 MiB and shaped at 64 KiB/s up and 512 KiB/s down for the whole
book **[spec: ADR 0011, `docs/design/SESSION-TICKETS.md`]**. The byte ceiling is keyed by the
proof's slot, so a book can never relay more than the slot it was bought with **[spec: ADR 0011]**.

**What the fleet costs.** Five DigitalOcean droplets, all `s-1vcpu-2gb`: one Elder
(`shade-elder-v4-02`), three egress nodes (`shade-node-v4-04/05/06`) and the Lab runner
**[measured: `doctl compute droplet list`]**. That size lists at **$12.00 per month** each
**[vendor]**, so the droplet fleet is $60 per month, of which the three egress nodes that relay
member traffic are $36. The second Elder runs on orbital-one, Dan's own machine, at no marginal
cost **[assumption]**. The plan includes 2 000 GiB of outbound transfer per droplet and charges
$0.01 per additional GiB **[vendor, as quoted in ADR 0009]**.

**Bandwidth per slot, worst case.** A tier-1 member who saturates every epoch relays 40 MiB per
minute, about 1 941 GiB per month **[spec: ADR 0009's arithmetic, 40 MiB × 43 200 epochs × 1.15
overhead]**. Three egress nodes include 6 000 GiB per month between them, so roughly three
continuously saturated tier-1 members fill the included transfer before overage starts at $0.01
per GiB **[inference from the two vendor numbers above]**. Session tickets do not change this:
the 40 MiB cap and the shaping are per slot, not per tunnel, so six tunnels in a book share the
same 40 MiB **[spec: ADR 0011]**. What tickets change is tunnels per slot (six instead of one),
which costs the node six `RELAY_BEGIN`s on one circuit and no extra proof verification
**[spec: ADR 0011]**.

**What M7 actually served.** The staging rehearsal drove a browser-staked tier-1 seat, a
sponsored tier-1 seat for Hermes and a sponsored tier-8 seat for a SearXNG stack through the
canopy; Google answered a search through three tunnels on three nodes **[measured:
`docs/STAGING-REHEARSAL.md`]**. No byte totals were recorded per tunnel; text-oriented
search-and-fetch was estimated at about 4 MiB per session in ADR 0009, a tenth of the cap
**[spec]**.

## Tiers and bonds

**Two tiers, not more.** The tier is public: it is the leaf's `userMessageLimit`, visible at
registration and a public input of every proof **[contract, spec: `docs/ONCHAIN.md` "the tier
itself is public at registration", `specs/protocol.md` RLN `userMessageLimit`]**. Every extra
tier therefore splits the anonymity set into another group the nodes can tell apart. Tier 8 must
exist because the contract always admits its `DEFAULT_LIMIT` **[contract: `DEFAULT_LIMIT = 8`]**,
so the smallest honest table is {1, 8}, and that is the table. A middle tier was considered and
dropped for this reason **[assumption: no user data says a middle tier is wanted]**.

**0.01 ETH at tier 1.** The previous placeholder, 0.1 ETH, was flagged by the launch audit as hard
to fund from faucets and a poor fit for "research agent" users
(`~/shadenet-launch/audit/staking-page.md`, items 5 and 2.x). On Sepolia the binding limit on a
Sybil attacker is the faucets' daily drip, not the price, since testnet ETH has no market
**[assumption]**; so the bond's job is to make one misuse cost one bond, and its size only has to
be large enough that losing it is felt and small enough that a newcomer can get it in one sitting.
One hundredth of an ETH is what a single faucet visit yields on the faucets the Get access page
links to **[assumption: the page's own copy says "faucet drips are usually smaller than a bond",
written when the bond was 0.1; drip sizes were not re-measured today]**.

**Linear pricing.** Tier 8 costs exactly eight tier-1 bonds **[record]**. A volume discount would
make one tier-8 identity cheaper per slot than eight tier-1 identities and push everyone who
wants throughput into the small, more identifiable tier-8 set; linear keeps the per-slot cost
constant, which is also what the contract's fixed-denomination rule wants (amounts never
fingerprint a member within a tier, R1) **[contract]**. The staking page and the Rust and JS SDKs
already read the table from the record; nothing multiplies or discounts anywhere in code.

**What misuse costs.** A double-spend of one slot in one epoch (two different targets from one
proof) is slash evidence **[spec: `docs/PUBLIC-STAKING.md`]**. The slasher gets `bond / 10`
= 0.001 ETH at tier 1 and 0.008 ETH at tier 8; the rest burns to `address(0)` **[contract,
measured in the fork rehearsal: "slash paid the bounty bond/10", "the burn reached
address(0)"]**. The bounty is meant to cover the slasher's gas, not to reward hunting; at
Sepolia's usual sub-gwei prices a slash transaction costs far less than 0.001 ETH
**[assumption: slash gas was not measured in this pass]**.

## Session tickets: on

The switch was built so H2 could choose; ADR 0011 leaves the choice open and records the trade.
The choice here is **on**, for these reasons:

- The workload the product is for is a search plus a handful of result origins. A v4 proof is
  bound to one destination, so with tickets off a tier-1 member fetches one origin per minute and
  a six-origin session takes six minutes; the audit called that "a poor match for research agent
  users" **[audit, item 4]**. With tickets on the same session fits in one epoch.
- It costs the operator nothing per slot: the 40 MiB cap and the shaping are per slot **[spec]**.
- It does not change how many proofs a member makes per epoch, so the anonymity arithmetic
  (proofs per epoch per tier set) is the same either way **[spec: ADR 0011 "one proof, six
  tunnels"]**.

What it costs, stated plainly so the page can say it: the six tunnels of one book are visibly
one session to the node that serves them, and per-tunnel node rotation is gone for the life of a
book (90 s). The proof still hides which member. A member who prefers one proof per tunnel and
rotation sets `SHADENET_SESSION_TICKETS=0`; the record's `true` is the default, not a lock
**[spec: ADR 0011]**.

What is not yet true: session tickets were implemented on 2026-09-30 (#205) and the M7 rehearsal
ran with the switch **off**. The staging redeploy that this decision triggers is the first fleet
run with it on; if that run's end-to-end fails, the switch goes back to `false` and this section
says so.

## Unbonding: 24 hours

The contract's floor is 3 720 s: root freshness 60 + epoch 60 + slash confirmation 3 600
**[contract, record: `minUnbondingSeconds`]**. Slash evidence is gathered by a fleet tally that
is asynchronous and fail-open **[spec: `docs/PUBLIC-STAKING.md`]** and slashing is submitted by
an operator key, not by the nodes themselves. A day gives that path one human attention cycle
before a double-spender can withdraw; the floor does not. The cost falls on tier changes, which
double-fund for a day since a tier is baked into the leaf **[audit, "no tier upgrade"]**; at
0.01 to 0.08 testnet ETH that is bearable. Kept at 86 400.

## Sponsor seats and the launch cohort

`sponsorSeats` is 24 seats at the tier-1 bond **[record]**. These are the agent preview seats
the runbook funds at M8 so an agent can be admitted without a faucet or a wallet (the sponsor
stakes the agent's public commitment; the agent keeps the secret). Twenty-four covers a cohort of
about twenty invited people with a few spare, each running one agent **[assumption]**.

Day-one funding, all from the deployer key at M8 (`docs/LAUNCH-RUNBOOK.md` step 5):

| Item | Amount |
|---|---|
| Launch cohort, 20 members at tier 1 | 0.20 ETH |
| Agent preview seats, 24 at tier 1 | 0.24 ETH |
| Smoke (two tier-1 bonds; one returns after 24 h, one is 90 % burned) | 0.02 ETH |
| Gas for deploy, verification, smoke, 44 registrations | about 0.03 ETH **[assumption: the staging deploy plus smoke used about 0.02]** |
| **Deployer balance to have at M8** | **about 0.5 Sepolia ETH** |

That is a third of the 1.5 ETH the roadmap budgeted when the tier-1 bond was 0.1. The day-one
anonymity set is therefore about 44 tier-1 leaves and zero tier-8 leaves; a shared stack such
as the SearXNG recipe wants a tier-8 seat, funded ad hoc at 0.08 ETH each.

## What Dan can change, and where

| To change | Edit | Then |
|---|---|---|
| A bond, a tier, the default tier | `tiers[]`, `defaultLimit` in `network/sepolia/economics.json` | `node scripts/deploy-contracts.selftest.mjs`, then `node scripts/deploy-contracts.mjs --network sepolia --fork` |
| Session tickets | `sessionTickets` | same two commands; the record carries the switch, the node role and both SDKs read it |
| Unbonding, slash split | `unbondingSeconds` (≥ 3 720), `slash.rewardDivisor` (2..1000) | same |
| Seats to fund at M8 | `sponsorSeats.count`, `sponsorSeats.bondWeiEach` | nothing to redeploy; the runbook reads the file |
| Freeze or unfreeze the decision | `status`: `"final"` deploys, `"placeholder"` refuses | the production gate in `deploy-contracts.mjs` |

Copy the same values into `network/sepolia-staging/economics.json` to rehearse them on staging
first (`scripts/staging-up.sh`), which is what this decision did.

## Scope

This page decides bond sizes, the ticket switch, unbonding, the slash split and the seat budget.
It does not claim anything about demand, retention or what a slot is worth to anyone; no user
has paid a bond yet. It does not change the rate policy (epoch, cap, shaping), the contract,
the circuits or any signed string.
