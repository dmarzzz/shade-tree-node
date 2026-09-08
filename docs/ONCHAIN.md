# On-chain staked reputation set: max-anonymous admission with slashing

**Status: design doc; the core is built.** `contracts/StakedReputationSet.sol` (stake,
ZK-authorized exit/withdraw via `contracts/WithdrawVerifier.sol`, permissionless slash by
secret reconstruction, on-chain incremental tree + `currentRoot` accessor) was deployed on
Sepolia as release `rln-v3` (`network/sepolia/contracts.json`; that deployment used
`MockWithdrawVerifier`, see `docs/CONTRACTS-AUDIT.md` section 3). The Sepolia record is now
retired pre-v4 history and must not be used as a current client, gateway, or staking preset.
The gateway reads a v4 operator's root through `lib/root-provider.mjs`
(`SHADE_TREE_GROUP_CONTRACT`; `node` provider, plus the EIP-1186
`light` provider, whose stateRoot is anchored to the beacon sync committee when the opt-in Helios
sidecar is on, `SHADE_TREE_HELIOS_RPC_URL`, T-DEV-9b); `contracts/GatewayRegistry.sol`
was deployed in that experiment at `0x94ECeD0C1c7a8793a5c901c8C1995C8E7039A868` (block 11509783,
`network/sepolia/contracts.json`). Read the design below for the reasoning; read
`docs/CONTRACTS-AUDIT.md` for the invariants as implemented. This is ROADMAP-v1 item #2 ("On-chain reputation
set") sharpened on two axes the roadmap deliberately left open:

1. **Max anonymity of enrollment.** ROADMAP-v1 #2 parks enroller privacy as out of
   scope, noting that "enrollment is now publicly timestamped and linkable to the
   address that paid the gas." This doc closes that link.
2. **Staking with slashing.** Admission is a bonded stake. It is refundable (unstake
   to get it back), slashable by the egress (claim a spammer's bond), and the exit
   is time-locked for protocol security.

## Relationship to the other docs

- **ROADMAP-v1 #2** is the baseline: move the set from `group/members.json` to an
  on-chain Semaphore group so the Merkle root is canonical, public, and
  tamper-evident, and the gateway reads it through a pluggable root provider (its own
  node, or a light client) instead of holding a synced file.
  Everything there still holds; this adds the stake, the anonymity, and the slash.
- **PAYMENTS.md** is a sibling, not a duplicate. That doc *sells access*: a
  fixed-denomination deposit, an operator `sweep`, no refund, redeemed off chain.
  This doc *gates admission*: a bond the **member** owns and can reclaim, that the
  **gateway** can slash on abuse. They share two building blocks — the Railgun-style
  Layer-0 funding hop and the on-chain Merkle root — and differ on who owns the funds
  and whether there is slashing. You can run either, or both (stake to get in, prepay
  to use).
- **adversarial-review.md** frames why this matters: finding #1 (the operator must
  stop holding member secrets — self-enrollment), finding #2 and #10 (admission is
  the sybil boundary *and* the unblockability boundary; abuse needs a cost). Staking
  is the "cost" those findings ask for; slashing is the eviction path.
- **ROADMAP-v1 #1** (unlinkable per-tunnel nullifiers) and **FLEET.md** (the gateway
  fleet) compose with this doc. The slashing mechanism below is RLN; #1 is the same
  RLN machinery pointed at unlinkability, and the fleet is where slashing has to go
  from single-node to shared. Cross-references are called out inline.

## Requirements, restated

| # | Requirement | Where it is met |
|---|---|---|
| R1 | Max anonymous: unlinkable funding source ↔ member | Layer-0 shielded funding (Railgun / Privacy Pools) into a fresh staking address; permissionless commitment registration; ZK-authorized, recipient-specified refund |
| R2 | Refundable: unstake to reclaim the bond | `withdraw`, authorized by a ZK proof of the commitment secret, paid to a caller-specified fresh address |
| R3 | Slashable with a mandatory economic loss | Permissionless `slash` sends >=90% of the member bond to the fixed burn address and <=10% to the caller-named bounty receiver, including on self-slash |
| R4 | Time-locked exit | `initiateExit` starts an unbonding delay `U`; the bond stays slashable for the whole `U`; `withdraw` only after |
| R5 | Gateway monitors its own nodes for double-spend / replay and for member exits | Per-nullifier share-collecting spent-set + recent-roots tracking; distinguishes replay (dedup, no slash) from over-spend (reconstruct, slash) |

## The core tension, and why it forces RLN

An anonymous gate that can slash a *specific* spammer's stake is a contradiction on
its face: to slash you must name the leaf, but the whole design exists so you cannot
see the leaf. Stock Semaphore cannot resolve this. Its nullifier is
`H(secret, scope)`, one-way; the gateway learns the nullifier and never the
commitment. There is nothing to slash on.

**RLN resolves it, and slashing is exactly what RLN was built for.** In an RLN proof
the member also emits a Shamir secret-share of its identity secret, evaluated at a
point derived from the message, on a polynomial whose degree equals the rate limit.
For a limit of `L` signals per epoch the polynomial has degree `L`, so:

- **Up to `L` signals in an epoch reveal `≤ L` shares.** A degree-`L` polynomial needs
  `L + 1` points to interpolate, so `L` shares reveal **nothing** about the constant
  term. Honest members are safe and stay anonymous.
- **The `L + 1`-th distinct signal in the same epoch reveals one share too many.** Now
  anyone holding the shares interpolates the constant term, which is the identity
  secret. From the secret you derive the identity commitment (the leaf), and call
  `slash(commitment, secret, ...)` on chain.

So **cheating is the only thing that deanonymizes you**, and only to your pseudonymous
leaf, never to a real identity (the Layer-0 hop keeps even a slashed member unlinked
to a person). This is the minimal, intended disclosure.

**The gateway is the reconstructor.** RLN's canonical deployment gossips shares on a
public network so anyone can reconstruct. We do not need that: the gateway is a single
verifier and it *already receives every signal directed at it* inside the Tor tunnel,
so it holds the shares itself and reconstructs locally. This is strictly simpler than
public RLN and it reconciles with ROADMAP-v1 #1's remark that "our proof never leaves the
Tor-encrypted tunnel to a single verifier, so there is no public share to slash on."
Correct — there is no *public* share. There is a **private** share, held by the one
verifier, and it becomes reconstructable only on a provable rate violation. The single
gateway is a feature here, not a limitation. Multi-node slashing would require pooling
shares; the current privacy-preserving fleet tally deliberately does not do that.

**Consequence for the code.** The proof is no longer stock Semaphore; it is RLN.
Adopt the [rate-limiting-nullifier](https://rate-limiting-nullifier.github.io/rln-docs/)
project's circuit and artifacts (`rlnjs` / `zerokit` / the circom `rln` circuit)
rather than hand-rolling one. The RLN circuit already does Merkle membership + a
Poseidon nullifier + the share evaluation in one proof, and its tree is a Poseidon
incremental Merkle tree compatible with the Semaphore/LeanIMT group we already build.
So `lib/semaphore.mjs` swaps `@semaphore-protocol/proof` for an RLN prover/verifier;
the group machinery is largely reusable.

**Two budget knobs, kept distinct.** The RLN degree `L` sets the *slashable* threshold
(exceeding it is provable over-spend). The gateway's own in-memory `Map` budget can
still rate-limit *below* `L` without slashing, so ordinary throttling stays a soft
refusal and only genuine abuse burns a bond. Set `L` at the hard ceiling you are
willing to slash on; set the soft budget wherever you want to start refusing.

## The contract

Prior art is direct: the RLN project ships an on-chain registry (`RLN.sol`) that is
already a staked-registration + slashing + delayed-withdrawal contract. Our
`StakedReputationSet` is that shape, adapted to our egress semantics and our anonymity
requirements. Reference interface (see `contracts/StakedReputationSet.sol` for the
commented reference implementation):

```solidity
BOND        // fixed denomination of the DEFAULT tier (limit 8); one denomination PER TIER,
            // so stake amounts never fingerprint a member within a tier
bondFor(limit) / allowedLimits()   // the immutable tier table (T-FEAT-8b): limit => bond
UNBONDING   // exit time-lock; must satisfy the ordering constraint below
currentRoot // the on-chain Semaphore/RLN group root (depth-20 Poseidon tree, storage slot 3)

register(uint256 commitment, uint256 limit) payable     // register(commitment) == limit 8
    // permissionless. msg.value == bondFor(limit). addMember(commitment); record the bond
    // AND the tier. The commitment binds the bond to a secret only its holder knows. Anyone
    // may pay to register any commitment; only the secret-holder can ever spend or exit it.

initiateExit(bytes withdrawProof)
    // authorized by a ZK proof of knowledge of the secret behind `commitment`,
    // NOT by msg.sender. Marks the member exiting, starts the UNBONDING clock,
    // and removes the commitment from the admission root.

withdraw(bytes withdrawProof, address recipient)
    // after UNBONDING elapses and the bond was not slashed: pay BOND to `recipient`
    // (a fresh, caller-specified shielded address), delete the member.

slash(uint256 commitment, uint256 secret, uint256 limit, address receiver)   // 3-arg == limit 8
    // permissionless. Verify the revealed secret matches the commitment AT THE CLAIMED TIER
    // (commitment == Poseidon2(Poseidon1(secret), limit), limit == the recorded tier), remove
    // the member, burn bond - floor(bond / 10), and pay floor(bond / 10) to `receiver`.
    // The member knows its own secret too; self-slash enforces the same economic loss.
```

### Mandatory slash penalty (slash-burn-v1)

Every successful slash of a `StakedReputationSet` member removes the whole recorded bond.
`reward = floor(bond / 10)` goes to the caller-named `receiver`; `burned = bond - reward`
goes to `SLASH_BURN_ADDRESS`, the constant zero address. `SLASH_REWARD_DIVISOR` is the
constant 10. There is no admin, configurable treasury or destination override. For a
1 ETH bond, a self-slasher can recover at most 0.1 ETH and loses at least 0.9 ETH, before
gas. Rounding favors the penalty: a 1–9 wei bond is entirely burned.

This closes the full-refund strategy of staking, exceeding the limit, then self-slashing
or front-running a gateway's slash. Either transaction order leaves the same mandatory
loss. A competing transaction cannot claim the deleted bond again. The bounty remains
front-runnable; it is an incentive available to any successful submitter, not a guaranteed
payment to the gateway that detected the violation. Honest timed withdrawals still
return the full bond.

Both existing slash selectors enforce this split. `MemberSlashed` remains unchanged for
root reconstruction; the additional `SlashPayout(commitment, receiver, burned, reward)`
event reports the exact amounts. Membership and root updates precede transfers. A failed
nonzero bounty transfer reverts the entire transaction, including the burn, so a caller
can retry with a receiver that accepts ETH. Zero rewards do not call the receiver.

“Burn” here means sending ETH to the zero-address sink; it is not Ethereum's protocol-level
base-fee supply burn. This rule concerns refundable member stakes. `PaidAccessSet` holds no
fee or bond to divide, and `GatewayRegistry` retains its separate owner-gated slash policy.

This policy applies to **fresh deployments of this source**. Existing addresses keep their
old full-payout economics. See [the migration procedure](ONCHAIN-DEPLOY.md#slash-burn-v1-migration).
It fixes audit finding 2.1.1 only; the admission/tier, proof replay and identity/privacy
findings remain tracked in [#113](https://github.com/dmarzzz/shade-tree-node/issues/113).

**Why authorization is a ZK proof, not `msg.sender`.** This is what makes R1 hold.
`register` is permissionless: it publishes a commitment and posts the bond from a
fresh Railgun-funded address, and the identity secret is generated locally and never
touches the chain. `initiateExit` and `withdraw` cannot key off `msg.sender`, because
the member is anonymous and its on-chain addresses are throwaway; instead they carry a
ZK proof "I know the secret behind this commitment" (a withdraw-scoped nullifier) and
name the refund recipient in the call. This is the Tornado withdrawal pattern
(prove knowledge, pay to a specified recipient) and it keeps both the fund-in and the
fund-out endpoints as unlinkable shielded addresses. `slash` needs no authorization at
all: possession of a valid `(commitment, secret)` pair *is* the authorization, and
that pair only exists after a proven over-spend.

## The exit time-lock, reconciled with the freshness window (R4, R5)

This is the protocol-security core, and it is where the three clocks in the system
have to be ordered correctly or the slash is dodgeable.

Three clocks:

- **`E` — epoch length.** Nullifier rotation and rate-budget window (today 86400s;
  shorter for tighter unlinkability).
- **`F` — root freshness window.** The on-chain analog of today's "this-epoch or
  last-epoch" skew tolerance (ROADMAP-v1 #2): the gateway accepts a proof built against
  any root that was current within the last `F`. So a commitment removed from the root
  at time `T` can still authorize egress until `T + F`, using a proof against a
  pre-removal root.
- **`U` — unbonding delay.** From `initiateExit` to a permitted `withdraw`.

**The constraint: `U ≥ F + E + C`**, where `C` is a confirmation margin for the
gateway to land a slash transaction.

Reasoning, the escape it closes:

1. A member calls `initiateExit`. The commitment leaves the *current* root, but proofs
   against pre-removal roots stay valid until those roots age out of the freshness
   window, i.e. until `T + F`. The member can still egress — and still over-spend —
   during that window.
2. An over-spend inside that window produces a reconstructable secret. The gateway
   needs time to submit `slash` and have it confirm: the margin `C`.
3. The epoch term `E` covers the front-run where a member initiates exit at the very
   end of an epoch and over-spends in the next epoch under a root that is still fresh.

Bounding `U ≥ F + E + C` guarantees the bond is still on chain and still slashable for
the entire period during which any proof it ever authorized could still be redeemed
and its abuse detected. **The bond stays fully slashable for the whole of `U`**; a
slash during unbonding makes `withdraw` revert. That is the "you cannot spam and then
instantly unstake to dodge the slash" property, the same rationale as an Ethereum
validator exit queue or a Cosmos unbonding period, stated in our terms.

Concretely, with `E = 1h`, `F = 1` epoch, and `C ≈ 13min` of L1 finality (~2 epochs),
`U ≥ ~2.25h`; round to `U = 24h` for margin and for ordinary staking-exit ergonomics.
`U` is a deployment parameter, but it must never be set below `F + E + C`, and the
contract should encode that lower bound so a misconfiguration cannot open the escape.

## Double-spend and replay monitoring on the gateway's own nodes (R5)

The gateway maintains, per epoch, a spent-set keyed by RLN nullifier that collects
*shares*, not just a count. Two failure modes must be told apart, and getting them
mixed up is the way to either miss abuse or slash an honest retry:

- **Replay of the identical signal** (same nullifier, same evaluation point / same
  share): this is a duplicate, **not** a rate violation. It reveals no new share, so
  it must be deduped and refused (or served idempotently) and it must **never** trigger
  a slash. This is why the RLN message has to be **bound to the request** — the target
  `host:port` plus a per-connection anti-replay salt — so an honest retry (which
  reuses the same signal) is distinguishable from a genuinely distinct new signal.
  (This also finally closes adversarial-review finding #8, "MESSAGE is a constant";
  binding the message is required here, not optional.)

  **Client invariant — the signal must be deterministic per logical request.** This is
  the one place a rogue gateway has a lever: it cannot forge a member's shares (it lacks
  the secret), but it *can* fail requests to induce the client to retry, and if the shim
  generated a *fresh* signal per retry those would be distinct points and a forced retry
  storm could push an honest member past `L` and get them slashed. So the shim must make
  the signal a deterministic function of the logical request (target `host:port` + a
  stable per-tunnel nonce) and **reuse the same signal on every retry of that request**.
  Then an induced retry reproduces the *same* share (same evaluation point, no new
  information) and the rogue-gateway "force retries to manufacture an over-spend" attack
  does nothing. This invariant lives in the shim, and it is load-bearing: without it, a
  gateway can slash honest members by making them retry.
- **A distinct signal under the same epoch nullifier beyond degree `L`** (the real
  over-spend): the gateway now holds `L + 1` shares for that nullifier, interpolates
  the secret, derives the commitment, and slashes. This is the slashable event, and it
  is provable: the shares themselves are the evidence.

**Membership and root freshness.** The gateway tracks the on-chain group — the current
root plus every root inside the freshness window `F` — refreshed on `MemberAdded` /
`MemberRemoved` / exit events. `checkProof`'s single-root equality test becomes
membership in that recent-root set. When a member calls `initiateExit`, the gateway
sees the removal and immediately stops accepting *new-root* proofs from it, but keeps
honoring *old-root* proofs until they age out at `T + F`, and **keeps that nullifier's
share-set alive for the whole window** so a late over-spend is still caught and still
slashable (which is exactly why `U` must cover `F`).

## Reading the root: a modular provider, on Ethereum L1

We target **Ethereum L1**, not an L2. This is the same argument PAYMENTS.md makes for
L1: every L2 runs a single sequencer, which is exactly the "one specific party" that
can censor, reorder, and observe, and the admission root is the last place we want a
trusted intermediary. L1 has no single sequencer, its finality is real (Casper FFG,
~2 epochs / ~13 min), and — a bonus for a sybil gate — enrollment costing real L1 gas
is a *feature*: every member pays gas plus the bond, which raises the sybil and
unblockability cost (adversarial-review #3, #10) rather than being a tax.

**How the gateway reads the root is pluggable, behind one interface.** The gateway does
not care *how* it learned the current root; it only needs the set of roots it will
accept proofs against right now. So the source is a `RootProvider` with a single shape
(see `lib/root-provider.mjs`):

```
RootProvider.currentRoots() -> {
  roots: [string],        // current root + every root still inside the freshness window F
  observedAtBlock: number,
  finalized: bool
}
RootProvider.onChange(cb)  -> unsubscribe   // optional: refresh promptly on membership change
```

`checkProof` consumes `currentRoots()` and nothing else, so the two providers below are
interchangeable at config time (`SHADE_TREE_ROOT_PROVIDER=node|light`) with no change to the
gate:

- **`NodeRootProvider` (trusted local node).** `eth_call` the group contract's `root()`,
  backfill the recent-root set from `MemberAdded` / `MemberRemoved` logs, read at a
  confirmation depth (finalized, or `head − N`). The trust is a node the operator runs.
  **This is the solo-staker path, and for them it is not a compromise but the optimum**:
  someone running this next to their own validator already operates a trusted local
  node, so reading its state is fully trust-minimized *for them* with zero extra
  machinery. Just point `SHADE_TREE_RPC_URL` at `localhost:8545`.
- **`LightClientRootProvider` (Helios-style).** For operators who do *not* run a full
  node — e.g. someone running many gateways — validate block headers against the sync
  committee, then verify the root's storage slot with an `eth_getProof` state proof
  against the validated `stateRoot`. Now the RPC is a dumb data pipe: a hostile RPC can
  cause unavailability but cannot forge a root, because it cannot produce a valid
  Merkle-Patricia proof for a root that is not in state. The trust is Ethereum
  consensus, not a provider.

The two providers are **not fully symmetric**, and it constrains the contract: a light
client can only prove a root that lives in an **on-chain storage slot**, so the
light-client path *requires* the group's root to be maintained on chain. **As of T-DEV-9
this is done:** `StakedReputationSet` maintains the identical RLN depth-20 Poseidon(2)
incremental tree on chain and commits the current root to a fixed slot
(`currentRoot`, `ROOT_STORAGE_SLOT = 3`), with the same zero-in-place removal semantics as
the off-chain `reconstructRoot`, so the two roots are equal by construction (pinned to the
`lib/rln-removal-parity` golden in `test/StakedReputationSet.t.sol::test_Root_*`). The node
provider can instead reconstruct the tree from `Member*` events, because there you already
trust the node's log view. Both paths now work against the same contract.

*Event reconstruction against a public RPC (node provider, shipped 2026-08-17 fix).*
`NodeRootProvider` / `loadGroupFromContract` page `eth_getLogs` in `SHADE_TREE_LOGS_CHUNK` windows
(default 10000; halved on a range/size refusal — publicnode caps at 50k blocks, Infura/QuickNode
at 10k, Alchemy free at 2k), resolve the head block once per refresh so every page is consistent,
start each contract at its deploy block from the network record (`deployBlocks`, or
`SHADE_TREE_FROM_BLOCK` / `SHADE_TREE_FROM_BLOCKS`), and on finalized reads keep the replayed log and only fetch
new blocks afterwards. The gateway fails SOFT at startup when the chain is unreadable but
`members.json` gives a root (`shade_tree_gateway_root_source_degraded`), and closed when nothing would be
trusted. `docs/OPERATOR.md` "Public RPC log-range caps"; `docs/CONFIG.md`.

*Trust chain of the shipped light client.* `LightClientRootProvider` verifies the account
+ storage Merkle-Patricia proofs from `eth_getProof` against a block's `stateRoot`, so a
hostile RPC cannot forge the root's **value**. Where that `stateRoot` comes from is the last
link, and it is a switch (T-DEV-9b, `docs/LIGHT-CLIENT.md` "Decision, how-to and receipt"):

- `SHADE_TREE_HELIOS_RPC_URL` **unset** (default): the header is fetched from the RPC at the
  confirmed depth and *trusted*. The gateway logs `stateRootSource: rpc header (TRUSTED, not
  verified; …)` at startup and results carry `stateRootVerified:false`. A lying RPC can pair a
  fake header with a proof consistent with it (the `THREAT-MODEL.md` "RPC lies about the
  stateRoot" lever).
- `SHADE_TREE_HELIOS_RPC_URL` **set** to a local Helios verifying RPC (`lib/helios-root.mjs`,
  sidecar via `bootnode/deploy/bootstrap.sh SHADE_TREE_HELIOS=1`): the header comes from Helios,
  i.e. it chains to a beacon **sync-committee**-signed execution payload; the RPC's header for
  the same block is only cross-checked and a divergence is rejected with a precise
  `stateRoot mismatch` reason. Now the whole chain — sync committee → `stateRoot` → account
  proof → storage proof → root — is verified end to end and there is **no RPC trust** left:
  the RPC can withhold, not lie. The residual trust is the sync committee (2/3-honest) plus
  Helios' weak-subjectivity checkpoint. Startup logs `stateRootSource: helios (sync-committee
  verified)`; results carry `stateRootVerified:true`.

A `SHADE_TREE_LIGHT_MODE=storageat` fallback (trusts the RPC for the value, no proof) exists for RPCs
without `eth_getProof` and is clearly the weaker mode (the Helios anchor does not help it).
Live receipt against the Sepolia contract with a Helios anchor: `docs/LIGHT-CLIENT.md`.

Both providers read at a **confirmation depth**, and this is what ties back to the
unbonding constraint. Reading *finalized* state means a reorg can never retroactively
change the admission set out from under an in-flight slash, at the cost of ~13 min of
enrollment latency (a new member waits for finality before egressing — fine for a
slowly-changing set). Reading `head − N` trades a small reorg risk for lower latency.
Either way, on L1 the slash-confirmation margin `C` is cleanly "one finality period," so
`C ≈ 13 min` and the `U ≥ F + E + C` bound lands comfortably at the ~24h we already
picked. L1 makes these margins *cleaner* than an L2 would, where finality is muddier.

**Liveness.** Reading the root adds a chain-liveness assumption to a system that is
otherwise fully local. Mitigate as ROADMAP-v1 #2 says — cache the last-known root and keep
gating against it if the provider is unreachable — with one caveat: *slashing* needs the
chain live to land the transaction, so an extended outage degrades to "still gating,
temporarily cannot slash." Both providers implement the same last-known-good cache, so
this behaves identically whichever source is configured.

**On a Rust rewrite.** This modular seam is also where a language choice lives. Helios
is a Rust crate, so a light-client-native gateway wants to *embed* it rather than shell
out to a sidecar, and the RLN verify on the hot path is equally at home in Rust. The
`RootProvider` interface is deliberately language-agnostic so the port, if we take it,
is bounded: reimplement the gateway + the two providers behind the same contract, keep
the circuit artifacts and the Solidity untouched. The recommendation is to build the
trusted-node provider first in the current Node stack (it is the solo-staker path and
needs no light client at all), prove the on-chain gate end to end, and treat "rewrite in
Rust to embed Helios" as a deliberate follow-on once the light-client path is the one
we actually need — not a prerequisite.

## Fleet composition: where single-node slashing still breaks (see FLEET.md)

Everything above is correct for **one** node. Across a fleet, slashing remains local.
A slash needs two distinct RLN shares under one nullifier on the same node. Shade Tree
does not send shares between nodes because those are the values that reconstruct the
member secret once the threshold is crossed.

The optional fleet tally is deliberately smaller. It sends only `(nullifier, epoch)`
after a destination connection succeeds. A peer that has received the announcement
rejects a later envelope under that nullifier. This reduces cross-node replay after
propagation without exposing a share, target, nonce, or member identifier.

The guarantee is best-effort. Tally pushes are asynchronous and fail-open, so concurrent
attempts, dropped pushes, and partitions can still establish at different nodes. A
distributed over-spend is not slashable unless both shares land on one node. Pooling
shares could strengthen enforcement, but it would create a materially different privacy
boundary and is not part of this implementation.

**On "one canonical root" (FLEET.md seam #1): one on-chain *source*, two distinct
lists.** Members and gateways are different node types — a member is an identity
commitment that proves membership, a gateway is an operator advertising an onion — so
they are not literally the same Merkle tree, and "the fleet shares the reputation set's
root" should be read as "the fleet directory is published by the same on-chain contract
system, from the same canonical source, verified the same way," not "gateways are leaves
in the member group." Concretely: one deployment, a member registry (this doc's
`StakedReputationSet`) and a gateway registry (a sibling contract holding
`{ onion, pubkey, weight }` advertisements, each self-authenticated because a v3 onion
*is* its key), both readable over the same RPC with no separate signer to trust. FLEET's
static-signed directory is the interim; this is its endgame, and it removes the pinned
directory signer in favor of the on-chain gateway registry.

## Max-anonymity leak ledger (R1)

| Link | Where it breaks | Residual to mitigate |
|---|---|---|
| funding identity → member | Layer-0 hop through a large shared pool (Railgun / Privacy Pools, user's choice, no mandated party) into a fresh staking address | pool anonymity set; fixed `BOND` denomination so the amount never fingerprints |
| staking address → member | `register` is a permissionless post of `(commitment, BOND)` from a shielded fresh address; the secret is generated locally and never revealed on chain | timing correlation between a shielded deposit and the `register` tx → dwell time, batch registrations per epoch |
| fund-in address → fund-out address | `withdraw` is authorized by a ZK proof of the secret and pays a caller-named fresh recipient, not `msg.sender`, so stake and unstake share no address-graph link | the *commitment* appears in both `register` and the exit path (it must, to be a tree leaf), so the two are linkable **via the pseudonymous leaf** — but that link carries no identity |
| gateway → which member, on honest use | RLN nullifier is one-way below the slash threshold `L` | none: honest members are cryptographically anonymous to the gateway |
| gateway → which member, on spam | reconstruction reveals the leaf | intended and minimal: only a proven over-spender, only to the pseudonymous leaf, still no real identity (Layer-0) |
| client IP → anything | the whole exchange rides the existing Tor onion | standard Tor caveats only (see adversarial-review #11) |

The one claim **not** to overstate: `register` and `withdraw` are *not* fully
unlinkable — the public commitment threads them. What is unlinkable is the identity and
the address graph. Neither endpoint links to a person, and the money in and the money
out are different shielded addresses; the only common thread is a pseudonymous leaf
that reveals nothing, exactly as any staking system's account is linkable to itself.

## What changes in the codebase

- **`lib/semaphore.mjs`** → gains an RLN mode: `generateProof` / `verifyProof` swap to
  an RLN prover/verifier (rlnjs / zerokit artifacts), plus nullifier + share
  extraction. `loadGroup` gains an on-chain mode behind `SHADE_TREE_GROUP_CONTRACT` /
  `SHADE_TREE_RPC_URL` / `SHADE_TREE_GROUP_ID`, with the JSON path kept as an offline cache whose
  root is verified against chain. The RLN message becomes request-bound (target +
  anti-replay salt), not the constant `1n`.
- **`gateway/gateway.mjs`** → `TRUSTED_ROOT` becomes a refreshed recent-roots set fed
  by a `RootProvider` (below); `spend()` becomes a share-collecting spent-set that
  reconstructs and slashes on threshold; add an on-chain slash submitter behind
  `SHADE_TREE_SLASH_KEY` (an operational hot key, deliberately separate from any member
  anonymity — the gateway slashing is not anonymous and does not need to be). Reorder
  the cheap public checks before the SNARK verify, as adversarial-review #4 recommends.
- **`lib/root-provider.mjs`** (new) → the pluggable root source behind
  `SHADE_TREE_ROOT_PROVIDER=node|light`: `NodeRootProvider` (trusted local node, the
  solo-staker path) and `LightClientRootProvider` (Helios-style state proofs, the
  run-many path), both returning the same `currentRoots()` shape with a shared
  last-known-good cache. See "Reading the root" above.
- **`group/enroll.mjs`** → self-enrollment first (member generates its `Identity`
  locally, submits only the `commitment`; closes adversarial-review #1), then a
  sibling that submits `register(commitment)` on chain with the bond.
- **`contracts/`** → `StakedReputationSet.sol` (reference implementation adapted from
  RLN.sol semantics) + deploy scripts. Ethereum L1 target: local `anvil` (or a mainnet
  fork) first, then Sepolia L1, then L1 mainnet. Semaphore/RLN have L1 deployments to
  reuse.
- **Circuit artifacts** → adopt the rate-limiting-nullifier circuit; do not hand-roll.
  This is the one heavy new artifact and it must be audited before any mainnet money.

## Tiers on chain (T-FEAT-8b — DEPLOYED, rln-v4-tiers, 2026-08-17)

Off chain, a reputation tier is the leaf's `userMessageLimit` (`docs/adr/0006-reputation-tiers.md`):
`rateCommitment = Poseidon2(Poseidon1(identitySecret), limit)`, one tree for every tier, the
circuit range-checking the private `messageId` under the private `limit`. Since the rln-v4
redeploy (`network/sepolia/contracts.json`, release `rln-v4-tiers`,
`0xFe48De8b9aCA4386DC31C845d579ae62f04f9d25`) the contract side matches:

1. **Tiered hasher.** `RateCommitmentHasher.commitmentOf(secret, limit) =
   Poseidon2(Poseidon1(secret), limit)` for `1 <= limit <= 65535` (`MAX_LIMIT`, the
   circuit's `LessThan(16)` soundness bound; `BadLimit` outside), and the one-argument
   `commitmentOf(secret)` stays the byte-equivalent `K = 8` leaf. `ICommitmentHasher` declares
   both overloads. Goldens: `test/StakedReputationSet.tiers.t.sol` vs `lib/tiers.selftest.mjs`
   / `rust/shade-tree-rln/tests/tree_parity.rs`.
2. **Stake -> tier at admission.** `register(commitment, limit)` requires
   `msg.value == bondFor(limit)` from a **fixed, small tier table set in the constructor**
   (`extraLimits[]` / `extraBonds[]`; the default tier `8 => BOND` is always present; Sepolia:
   `8 => 0.001 ETH, 32 => 0.004 ETH`) — one denomination PER TIER, so stake amounts still never
   fingerprint a member within a tier (R1); the tier itself is public at registration (as it is
   in `members.json`) and in the `MemberRegistered(commitment, index, limit)` event, but never
   at proof time. **No owner, no setter**: the table is immutable, a new table is a new
   deployment (the set stays permissionless and un-upgradeable, unlike an owner-governed
   table which would add a key that can reprice or close tiers). `limitOf(commitment)` /
   `allowedLimits()` / `bondFor(limit)` are the views; `Member` gained a `limit` field.
   `register(commitment)` is `register(commitment, 8)`.
3. **Tiered slash.** `slash(commitment, secret, limit, receiver)`: the slasher supplies the
   reconstructed secret AND the tier; the contract requires `limit == m.limit` (`BadLimit`)
   and `hasher.commitmentOf(secret, limit) == commitment` (`BadSecret`), then removes the
   recorded bond and applies the mandatory >=90% burn / <=10% bounty.
   `slash(commitment, secret, receiver)` is the limit-8 claim with the same penalty.
   `MemberSlashed(commitment, receiver, limit)` remains unchanged; `SlashPayout` reports the split.
4. **Exit-auth at a tier.** `IWithdrawVerifier.verify(commitment, limit, context, proof)`:
   the set passes the RECORDED limit, and the real Groth16 `WithdrawVerifier` ties the
   circuit's identity commitment to the leaf at that limit
   (`Poseidon2(identityCommitment, limit) == commitment`); the same identity's proof for its
   tier-32 leaf never authorizes its tier-8 leaf and vice-versa (the context binds the leaf).
5. **Root reconstruction is unchanged** (a leaf is a leaf): `lib/root-provider.mjs` accepts
   both event generations (rln-v3 topic0 without `limit`, rln-v4 with), so one provider reads
   either deployment; `currentRoot` stays at storage slot 3 (the tier mappings are declared
   after the tree state), so the light-client / freshness-window paths are untouched.

**Gateway slash path (`gateway/gateway.mjs`).** `resolveSlashTier(secret)` names the leaf
+ tier locally (members.json leaves, `SHADE_TREE_TIERS`); in on-chain root mode (no local leaves)
the on-chain slasher (`makeOnchainSlasher`) probes the contract once at startup
(`DEFAULT_LIMIT()` => rln-v4 tiered ABI; else the rln-v3 three-argument ABI), unions
`SHADE_TREE_TIERS` with `allowedLimits()`, and at slash time asks `limitOf(candidateLeaf)` for each
tier's leaf of the reconstructed secret, then submits `slash(leaf, secret, limit, receiver)`.
The startup log line `slash: on-chain … abi="rln-v4 tiered" tiers=[8,32]` says which. Live
proof: the Sepolia rln-v4 run (`network/sepolia/integration-report-rln-v4.md`) slashed a
tier-32 leaf at limit 32 from a gateway holding only roots (tx `0xfff760a6…494c`, block
11510548) and showed limit 32 on a tier-8 leaf reverting `BadLimit`.

**Honest limits.** (a) The tier is DECLARED at registration, not proven: a leaf built at X
registered as Y != X is unslashable AND unexitable (the bond is locked forever), and the
gateway still enforces the leaf's real budget X, so the mismatch buys nothing
(`docs/CONTRACTS-AUDIT.md` §3). (b) During the 2026-08-17 Sepolia experiment, the fleet
gateways' `SHADE_TREE_SLASH_CONTRACT` still pointed at the superseded rln-v3 set until their
units were flipped (`docs/ONCHAIN-DEPLOY.md` §8); the later rln-v4 record is retained as
historical evidence, not as a current staking preset.
(c) `MAX_LIMIT` is enforced on chain and in `lib/rln.mjs normLimit`; the table on Sepolia is
{8, 32}, other tiers need a new deployment.

Foundry: `test/StakedReputationSet.tiers.t.sol` (tier-32 leaf slashes only with limit 32,
tier-8 only with 8, JS goldens, immutable-table validation, mixed-tier root == JS `newGroup`,
real Groth16 exit proof at the recorded tier), the tier fuzz tests in
`test/StakedReputationSet.fuzz.t.sol`, and the two-tier invariant handler
(`test/StakedReputationSet.invariant.t.sol`, balance == Σ per-tier bonds). End to end:
`test/onchain-tiers.selftest.mjs` (anvil, real gateway, real proofs, real slasher).

## Paid access set (T-FEAT-7 Layer 1 — DEPLOYED next to rln-v4, 2026-08-17)

`docs/PAYMENTS.md` buys access instead of staking for it. Its Layer 1 is
`contracts/PaidAccessSet.sol` (`network/sepolia/contracts.json` `contracts.paidAccessSet`,
`0x4e8C2Bf5d3c5454A04837401095fce2646484111`), a **second membership tree** that sits next to
the staked set and is read the same way:

1. **Same tree, same leaf, same slot.** The identical depth-20 Poseidon(2) incremental tree
   (`_updateLeaf` / `_nodeAt` are a verbatim copy of the staked set's; the deployed staked set is
   immutable so the code is duplicated, not refactored, and
   `test/PaidAccessSet.t.sol::test_Root_ParityWithStakedReputationSet` drives both contracts
   through the same leaf sequence and asserts identical roots after every step), the identical
   leaf `Poseidon2(Poseidon1(identitySecret), limit)` via the SAME live tiered
   `RateCommitmentHasher` (`commitmentOf(secret, limit)`), the identical immutable
   allowed-tier table (`allowedLimits()`, `DEFAULT_LIMIT` 8, `MAX_LIMIT` 65535; Sepolia
   `{8, 32}`), the identical zero-in-place removal, and `currentRoot` at the identical
   `ROOT_STORAGE_SLOT = 3` — so `LightClientRootProvider` proves it with the same `eth_getProof`
   path, and the gateway's tiered slasher (`DEFAULT_LIMIT` / `allowedLimits` / `limitOf` /
   `slash(commitment, secret, limit, receiver)`) drives it unchanged.
2. **No money on chain.** Payment settles OFF this contract over HTTP 402 rails (x402 / MPP,
   USDC or another stablecoin on the same chain) with a **registrar** the operator runs; the
   stablecoin goes straight to the operator's address in that settlement. The contract's only
   job is to be the membership tree the operator **inserts into after settlement**:
   `insert(commitment, limit)` and `insertBatch(commitments[], limits[])` are `onlyOperator`
   and NOT payable (batching an issuance round is what grows that round's anonymity set,
   PAYMENTS.md open item 3). There is no `deposit`, no price, no `sweep`, no `receive` /
   `fallback`: ETH cannot enter (`test_NoFunds_EthCannotEnter`, `invariant_noFundsEver`).
   Nothing is refundable: no exit / withdraw. Redemption is off chain, to the gateway, with the
   ordinary RLN membership proof against this tree's root.
3. **Slash = zero the leaf, pay nothing.** `slash(commitment, secret, limit, receiver)` has
   the staked set's exact signature and gate order (`NotInserted` → `BadLimit` if `limit` is not
   the recorded tier → `BadSecret` if the secret does not hash to the leaf there), zeroes the
   leaf in place and refreshes the root; there is no bond to burn, so `receiver` receives
   nothing (kept for call-shape parity so one gateway slasher drives both sets). The over-spender
   loses the access they bought.
4. **Operator = registrar key, two-step rotation.** `setOperator(to)` nominates,
   `acceptOperator()` (only the nominee) takes the role; the old key keeps inserting until the
   new one proves it holds the key (a fat-fingered address cannot brick issuance). The operator
   can ONLY insert at the fixed tiers and hand the role over — it cannot add tiers, move or
   remove a leaf, or pause. `pendingOperator()` is public.
5. **Events carry the post-update root.** `Inserted(commitment indexed, limit, index, root)` /
   `Slashed(commitment indexed, limit, index, root)`, so an event reader can cross-check its
   reconstruction event by event. NOTE their topic0 differs from the staked set's
   `MemberRegistered` / `MemberSlashed`; an event-replay root provider adds these two topics,
   the light-client provider (slot 3) needs nothing. `leafCount()` (= `nextIndex`, slashed
   leaves included) is the anonymity-set figure the gateway logs against its floor;
   `liveCount()` is the leaves currently in the root.

**Gateway.** Trusts the UNION of roots: static `members.json` (PoC fallback) ∪ each contract
in `SHADE_TREE_GROUP_CONTRACT` (comma-separated) ∪ `SHADE_TREE_PAID_ACCESS_CONTRACT` (sugar that appends), one root provider per
contract; the slasher resolves which contract holds a reconstructed leaf (`limitOf != 0`) and
calls that contract's `slash`. Startup: `roots: members.json + staked(0x…) + paid(0x…)` and
`paid-access anonymity set: N leaves (floor K=SHADE_TREE_PAID_MIN_LEAVES)` — WARN, never refuse,
below the floor. (Gateway/client wiring is T-FEAT-7 parts 2/3.)

**Honest limits.** (a) The trust statement of PAYMENTS.md stands: the operator could take a
payment and not insert, or insert and refuse to honor a valid proof — buyer–seller trust,
irreducible for a prepaid service, no third party added. What the chain gives is a PUBLIC,
light-client-provable record of exactly which leaves were admitted, and payer↔user
UNLINKABILITY at redemption (a zk membership proof over the tree). The 402 rail sees the payer;
this contract never does. (b) The tier is DECLARED at insert (the contract cannot see inside a
leaf), exactly as at `register`; a mismatch buys nothing (the gateway enforces the leaf's real
budget) and makes the leaf unslashable at the declared tier — the registrar should derive the
tier from what was paid for. (c) The operator is one key with the sole insert authority; a lost
key means no new members until the pending-transfer path was prepared (rotate to a multisig
early). (d) `leafCount()` is a floor on anonymity, not a proof: batch and dwell.

Foundry: `test/PaidAccessSet.t.sol` (14: only the operator inserts, single + batch all-or-nothing,
allowed tiers only, live duplicate reverts / slashed re-insert appends fresh, events carry the
post-update root, slash gate order + pays nothing, no ETH can enter, two-step transfer, slot 3
by `vm.load`, JS `newGroup` goldens, parity with the live staked set's tree code),
`test/PaidAccessSet.fuzz.t.sol` (7: any secret / tier / caller / batch size vs the reference
staked set), `test/PaidAccessSet.invariant.t.sol` (4: balance 0 forever, `leafCount ==
inserts`, `root == reference` and `== slot 3`, operator == ghost across rotations; 4096 calls
each). Live: `network/sepolia/integration-report-paid-access.md`.

## Honest scope: what this does not solve

- **The RLN circuit is a real dependency and a real audit surface.** Adopt upstream,
  and treat "unaudited circuit + real bonds" as testnet-only until reviewed.
- **Stake is not proof-of-personhood.** It raises the sybil and unblockability cost
  (adversarial-review #3, #10) but a funded adversary can still buy in, become a
  member, and enumerate the fleet's egress IPs (finding #10). If unblockability against
  a well-capitalized adversary matters, compose the admission gate with an invite graph
  or World ID (both Semaphore-based, so they compose cleanly), not stake alone.
- **Chain-liveness for slashing.** Gating survives a root-provider outage on the
  last-known root (either provider mode); slashing does not, because it must land a
  transaction. Extended outages degrade to "gating, temporarily unable to slash."
- **The bond and its existence are public.** The fixed denomination hides *which*
  member and *how much beyond one unit*, but not *that* there is a staked set of a
  known size and unit bond. That is inherent to an on-chain, auditable set and is the
  point of putting it on chain.

## References

- **RLN (rate-limiting nullifier)** — the direct prior art for staked, slashable,
  anonymous rate limiting, including the on-chain `RLN.sol` registry
  (staked registration + slash + delayed withdrawal) and the circom circuit:
  `rate-limiting-nullifier` docs, `rln.waku.org`.
- **Semaphore v4 + LeanIMT** — the group/tree machinery reused under the RLN proof.
- **Shamir secret sharing / polynomial interpolation** — the slashing primitive: `L`
  shares hide the secret, `L + 1` reconstruct it.
- **Tornado-style prove-knowledge-then-withdraw-to-recipient** — the unlinkable,
  ZK-authorized refund pattern used by `withdraw`.
- **Railgun (proof-of-innocence, broadcaster network) / Privacy Pools** — the Layer-0
  shielded funding hop; user's choice of rail, no mandated party (same stance as
  PAYMENTS.md Layer 0).

Numbers and library maturity above should be re-verified against current sources before
this is built. The design does not depend on any single figure.
