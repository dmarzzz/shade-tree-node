# Fleet: egress discovery and per-tunnel gateway selection

**Status: design; most of it is now built.** The directory library, its signature and
onion-control binding, per-tunnel selection, and the shim wiring are written and
tested (`lib/directory.mjs`, `client/selection.mjs`, `group/directory.example.json`,
the `SHADE_TREE_DIRECTORY` path in `client/shim.mjs`); live discovery through a bootnode is
`bootnode/` (`docs/BOOTNODE.md`); the shared per-epoch spent-nullifier tally across
gateways is `gateway/fleet-tally.mjs` (`SHADE_TREE_FLEET_TALLY_PEERS`, T-FEAT-20/20b, opt-in,
authenticated with `SHADE_TREE_FLEET_TALLY_TOKEN`, fail-open, and memory-bounded — it shares only
`(nullifier, epoch)`, so a later replay to a second gateway is rejected after propagation;
concurrent or partitioned attempts remain fail-open, and cross-gateway *share* exchange
for reconstruction is not wired). What is
*not* built is the on-chain-sourced directory (the onion is deliberately never on chain,
ADR 0002; `GatewayRegistry` stakes an operator address only). The "fleet budget does not
compose" section below is the original analysis that motivated the tally. This expands
[ROADMAP v1](ROADMAP-v1.md) item 3 into a spec; read that first for the framing.

The PoC has one gateway and the client pins it (`SHADE_TREE_ONION` or `tor/hs/hostname`).
Two costs, from the roadmap, restated so this doc stands alone:

- **No discovery.** Onion addresses are handed out of band. There is no way to add or
  retire a gateway without re-handing addresses, and no live view of which are up.
  Tor will not do this for us: v3 descriptors sit under a *blinded* key on the HSDir
  hashring precisely so gateways cannot be enumerated. The directory is an app-layer
  object we build.
- **Pinning concentrates trust.** The pinned gateway sees *all* of a member's egress
  for the epoch: every `host:port`, all timing and volume, bucketed under one constant
  per-epoch nullifier. The member stays anonymous (no IP, no name) but becomes one
  coherent profile to one operator.

To be precise, and this is the same correction the roadmap makes: the problem is not
that the client knows its own exit. A Tor client knows its own exit too; path
selection is client-side. Tor's property is that no single *relay* knows both ends,
not that the client is blind. The problem is the inverse, one operator knowing the
whole of one anonymous member. The fix is not to hide the exit from the client but to
stop any one exit from seeing all of a member.

## The directory

A signed list of gateways. One entry is `{ onion, pubkey, weight, health }`:

```json
{
  "version": 1,
  "issued": 1784052435,
  "gateways": [
    { "onion": "7bmg…d7id.onion", "pubkey": "f858…c31d", "weight": 100, "health": "up" }
  ],
  "signer": "189f…1321",
  "signature": "4c68…8d01"
}
```

- **`onion`** — the gateway's v3 address, dialed exactly as the shim dials the pinned
  onion today.
- **`pubkey`** — the ed25519 identity key encoded in that address. A v3 onion *is*
  base32(`pubkey ‖ checksum ‖ version`), so `pubkey` is derivable from `onion` and the
  loader checks they agree. It is carried explicitly for the on-chain mode and as fast
  documentation, not as a second source of truth.
- **`weight`** — relative selection probability. A cold, low-capacity, or freshly
  added gateway carries less traffic.
- **`health`** — the signer's last-known liveness (`up` / `down`). The client keeps
  its *own* runtime health on top of this (below); the field is the publisher's view.

**Signature.** The whole list is ed25519-signed by the directory signer over a
canonical serialization (fixed field order, whitespace-independent; see
`canonicalDirectoryBytes`). The signer's **public key is pinned in the client** at
bundle time. A swapped or edited file fails the check and is rejected, not trusted.
There is deliberately no trust-on-first-use default: an unpinned directory is exactly
the poisoning surface the signature exists to close. The current v4 Sepolia profile supplies a
bundled pin; every explicit Elder or static directory must supply its matching
`SHADE_TREE_DIR_SIGNER`.

**Onion-control binding, two layers.** A poisoned or mis-signed directory must not be
able to graft a hostile address:

1. **Static, offline, already enforced.** Each entry's `pubkey` must equal
   `onionToPubkey(onion)`. Because the address *is* the key, an attacker who does not
   hold a gateway's onion key cannot produce a `(onion, pubkey)` pair that both parses
   and matches. Grafting `bob.onion` under `alice`'s key fails the binding; grafting
   it under `bob`'s real key means it *is* Bob's onion. This is checked at load with no
   network round-trip.
2. **Live, on connect (scaffolded, wire into the handshake).** The gateway signs a
   fresh client-chosen challenge with its onion identity key; the shim verifies against
   the key in the address (`verifyOnionControl`). This proves the gateway on the far
   end of the rendezvous actually holds the advertised onion's key, closing a directory
   that lists an onion whose descriptor an attacker temporarily controls. The check
   exists in `lib/directory.mjs`; adding the challenge to the envelope handshake is the
   remaining integration, and it does not touch `gateway.mjs`'s verify path.

**Distribution, in three stages.**

- **Now (chosen, interim, and openly not good enough).** The directory JSON is
  **committed to the GitHub repo and updated on each gateway deploy.** Clients get it
  with the code. This is the curated model with git as the distribution channel: the
  trust root is repo push access, so there is no rogue-service problem (only a maintainer
  adds gateways), at the cost of centralizing on the repo and coupling directory updates
  to commits. The signed-directory loader still applies (the committed file can carry the
  signature; verification is belt-and-suspenders over the git channel). **This is a
  placeholder, not the answer** — real discovery is an open question (see below); we
  ship this to unblock the fleet and revisit.
- **Next (built).** Serve the same signed JSON over its own onion so clients refresh live
  without a new commit. The signer key stays pinned; only the *list* moves. The loader
  already fetches-verify-cache with a refresh interval and a last-known-good fallback,
  so this stage is a fetch source, not new trust. This is the bootnode (`bootnode/`,
  [BOOTNODE.md](BOOTNODE.md)), with federation and an M-of-N threshold-signed directory.
- **Endgame (revised).** The original endgame — source the fleet from the **same on-chain
  group as the reputation set** (see [ONCHAIN.md](ONCHAIN.md)) so there is no separate
  signer — was narrowed by ADR 0002 (`docs/adr/0002-onion-never-on-chain.md`): the
  **stake** is on chain (`GatewayRegistry`, keyed by operator address) but the onion never
  is; the onion↔stake binding is the operator's signature on the announce, re-checkable
  by clients (`SHADE_TREE_VERIFY_STAKE`). Rebuilding the gateway *set* purely from chain is not
  a client path (see the status map in [ROADMAP.md](ROADMAP.md)). See
  [the reconciliation with ONCHAIN.md](#reconciliation-with-onchainmd) below.

## Per-tunnel selection in the shim (shim-as-router)

`curl` stays dumb; the shim is the router. Per CONNECT:

1. **Pick.** Smooth weighted round-robin over the healthy fleet by default. Equal-weight
   gateways alternate on successive tunnels; unequal weights retain their proportional share.
   This is the app-layer analog of Tor rotating circuits, except our "exits" are destinations
   (onion services), so selection lives in the shim, not in Tor's relay path selection.
2. **Failover.** Build a full try-order (the spread pick, then the rest as weighted-random
   fallbacks). Dial in order; on a dial timeout move to the next gateway. Once a socket
   is up and the envelope is sent, the request is committed to that gateway; failover
   is dial-time only.
3. **Feedback.** Report per-dial success/latency back into the in-memory health of the
   fleet. Two consecutive failures mark a gateway `down` and selection skips it until a
   later refresh; a persistently slow gateway loses effective weight via a latency
   EWMA. This health is the client's local view and is never written back to the signed
   file.

`SHADE_TREE_ONION` still forces a single gateway when a caller genuinely wants a fixed egress IP.
Without any explicit source, the client fetches the signed canopy directory from the bundled Elder and uses
the default spread. `SHADE_TREE_ROTATION_SPREAD=0` opts out to a weighted-random first choice.

**Rotation adds no extra proof.** Each new tunnel consumes its own RLN slot and fresh proof. The
gateway is selected before that proof is minted, and the proof is gateway-independent: the same
trusted root + epoch verifies at any gateway loading the same `members.json`. If setup fails over,
the client reuses that tunnel's proof across candidates rather than consuming another slot.

## How it composes with items 1 and 2

State this precisely, because rotation on its own is a weaker guarantee than it looks.

| Setup | What each gateway sees of a member |
|---|---|
| 1 gateway (PoC today) | 100% of targets, under one constant per-epoch nullifier |
| N gateways, **non-colluding**, rotation only | ~1/N of targets each, each under the *same* per-epoch nullifier |
| N gateways, **colluding**, rotation only | 100% reassembled: they join their logs on the shared per-epoch nullifier |
| N gateways + item 1 (distinct nullifier per tunnel) | ~1/N each, and colluding gateways **cannot** rejoin: no shared key across requests |

The load-bearing line: **rotation alone does not defeat colluding gateways.** A
member's per-epoch nullifier is constant, so a colluding set matches it across their
logs and rebuilds the whole profile regardless of how the requests were spread. You
need [item 1](ROADMAP-v1.md#1-unlinkable-rate-limiting-decouple-linkability-from-the-rate-window)
(a distinct nullifier per tunnel) for rotation to actually buy anything against
collusion. **Rotation + per-tunnel unlinkable nullifiers** is the combination that
delivers "no operator, even a colluding set, can profile a member." Neither piece is
sufficient alone. Against a purely *non*-colluding fleet, rotation alone already cuts
each operator's view to ~1/N, which is the honest win it does deliver.

With [item 2](ROADMAP-v1.md#2-on-chain-reputation-set-ethereum), the fleet and the
membership read one root, and rotation stays free because the proof is still
root-and-epoch scoped, not gateway-scoped.

## The hard cost: fleet budget does not compose

This was the genuinely unbuilt part when the doc was written, and the reason it exists.
Since then the shared nullifier tally (T-FEAT-20/20b, `gateway/fleet-tally.mjs`) covers the
replay-to-a-second-gateway case; the per-gateway `Map` below is still the local budget.

Each gateway keeps its rate budget in a per-process in-memory `Map`
(`budget` in `gateway/gateway.mjs`): `scope -> Map<nullifier, count>`, capped at
`RATE_LIMIT` (30) redemptions per member per epoch. Nothing crosses process
boundaries. So a member who spreads requests across `N` gateways gets **`N × RATE_LIMIT`**
aggregate, because each gateway sees only the fraction of that nullifier's redemptions
that landed on it and none is near its own cap. Rotation forces a choice.

**Option (a): accept an `N×` fleet budget.** Simplest, and honest if the intended
budget is really "per member per gateway." Set per-gateway `RATE_LIMIT` to
`intended / N`. Fragile: it assumes a fixed `N` and even spreading, and it silently
loosens as the fleet grows. No new infrastructure.

**Option (b): shared nullifier accounting.** Gateways share a spent-set so a member's
budget is counted once across the fleet. Two shapes:

- **Shared spent-set store.** A common `scope -> Map<nullifier, count>`, e.g. a small
  replicated KV the gateways read-modify-write on spend. Strong (a true global cap) but
  it is a new stateful dependency, a new availability and trust surface, and a
  synchronous hop on the hot path.
- **Gossiped per-epoch tallies.** Each gateway periodically publishes its
  `nullifier -> count` for the epoch to a common tally; gateways sum before granting.
  Eventually-consistent, cheaper, but a member can briefly overspend inside the gossip
  window. Fine if the cap is soft.

**Shared accounting reintroduces a cross-gateway linkage point.** A shared spent-set is,
by construction, a place where one nullifier is observed across gateways, which is the
profiling join we spread traffic to avoid. It is safe **only when paired with item 1**:
per-tunnel nullifiers make the shared tally a set of unrelated counters instead of a
member's cross-gateway profile. So the ordering constraint is real: ship item 1 before,
or with, shared budget accounting, never shared accounting alone.

### Interaction with ONCHAIN.md slashing

[ONCHAIN.md](ONCHAIN.md) adds RLN-style slashing: on a same-epoch rate violation the
gateway reconstructs the over-spender's secret from two Shamir shares and slashes their
on-chain stake. That detection is **per-gateway** as written: one gateway needs to see
two same-epoch shares from one nullifier to reconstruct. A member who spreads a rate
violation across two *different* gateways gives each gateway only one share, so neither
gateway alone can reconstruct, and neither slashes. The double-spend is invisible to
both.

The built tally does **not** share RLN shares. It announces only `(nullifier, epoch)`
after an egress connection succeeds. Once that announcement reaches a peer, the peer
rejects a later attempt under the same nullifier. This is useful replay suppression,
but it is asynchronous and fail-open. Concurrent attempts, dropped pushes, and
partitions can still establish on different nodes.

Cross-node slashing remains unbuilt by design. It would require sharing the RLN values
that reconstruct a member secret once the threshold is crossed, which creates a much
stronger privacy boundary than the current count-only tally. A distributed over-spend
is slashable only if both shares land on one node.

## The directory as a trust and availability surface

A new object means new failure modes. The mitigations are the ones the scaffolding
implements.

| Failure | Effect if unmitigated | Mitigation (built unless noted) |
|---|---|---|
| Directory file swapped | Client steered to hostile gateways | Pinned signer; bad signature rejected |
| Explicit source lacks a signer pin | First fetch could be trusted blindly | Reject it; only the bundled profile supplies its own pin |
| Poisoned list grafts hostile onion | Egress via attacker's IP | Static `pubkey == onionToPubkey(onion)` binding at load |
| Listed onion an attacker briefly fronts | Egress via attacker | Live onion-control challenge (`verifyOnionControl`; wire into handshake) |
| Directory onion dead / unreachable | Fleet unusable | Last-known-good cache; `loadDirectory` degrades to previous good list |
| Stale list, some gateways gone | Dial timeouts | Per-tunnel failover + local health marks them `down` |
| Signer key compromised | Attacker signs a hostile list | Rotate the pin (bundle update); endgame: on-chain root removes the signer entirely |

The invariant: a dead or poisoned directory degrades to the **previous good fleet**,
never to nothing and never to a single hostile gateway. `loadDirectory` verifies fresh
against the pin, caches on success, and on any failure falls back to the re-verified
last-known-good cache; only if neither verifies does it throw.

## Rogue gateways and service staking

The tables above stop an attacker grafting *someone else's* onion, because a v3 onion is
its key and the loader enforces `pubkey == onionToPubkey(onion)`. They do **not** stop an
attacker registering their *own* hostile onions — cheaply, and in bulk. That is a
distinct threat (a rogue service, not a poisoned entry), and it is the one that motivates
staking the gateways, not just the members.

**What a rogue listed gateway can and cannot do.** Start with what it *cannot*, because
it bounds the damage: it is on the far side of Tor rendezvous, so it never learns a
client IP; it cannot break TLS (end to end to the destination); and merely being listed
does not let it enumerate *other* gateways' egress IPs (that is the member-side attack of
adversarial-review #10, separate). What it *can* do:

| Capability | Effect |
|---|---|
| Log metadata | Harvest `(nullifier, destination host:port, timing, volume)` for the traffic it wins — the adversarial-review #5 profile, for its share of the fleet |
| Censor / degrade | Accept a proof then drop or stall the egress; indistinguishable from downtime, forces failover |
| Refuse to cooperate | Skip best-effort tally pushes or local slashing, weakening cross-node replay suppression and enforcement (docs/ONCHAIN.md) |
| **Sybil the directory** | Register many hostile gateways / high `weight` to capture a large traffic share, amplifying all of the above |

The last row is the amplifier and the reason "should the service stake?" is the right
question. Without a registration cost, one operator lists a hundred gateways, wins
~`100/(N+100)` of the fleet's traffic, and every harm above scales with that share.

**Service staking helps — but know exactly what it buys.** Bond each gateway
registration and the Sybil amplifier gets expensive: capturing a given fraction of fleet
weight now costs capital in proportion, the same argument that stakes the members applied
to the services. It also puts skin in the game and deters casual griefing. So yes, stake
the gateways.

**The asymmetry that matters:** member slashing and gateway slashing are not the same
kind of thing.

- A member's abuse (over-spend) is **cryptographically provable** — the RLN shares
  reconstruct the secret — so member slashing is objective and automatic (docs/ONCHAIN.md).
- A gateway's core abuse is mostly **not externally provable.** Metadata logging is
  invisible from outside; censorship is indistinguishable from downtime; refusing to
  contribute shares is hard to attribute. So a gateway bond cannot be slashed on the
  harms we most care about without a subjective judge or a challenge protocol, which
  reintroduces the governance surface the rest of the design avoids.

So service staking buys **Sybil-cost and skin-in-the-game, not clean automatic
slashing.** The defenses against a rogue gateway's *primary* harm — metadata — stay
where they already are, client-side and cryptographic: per-tunnel rotation across the
fleet plus item 1's per-tunnel nullifiers, so no single gateway (rogue or honest) ever
sees enough to build a profile in the first place, backed by health/reputation feedback
that down-weights misbehaving or unreliable gateways regardless of their stake. Staking
complements those; it does not replace them. Concretely:

- **Weight by stake with diminishing returns and a per-operator cap**, so a whale cannot
  buy fleet dominance and a bonded Sybil fleet cannot concentrate traffic.
- **Reputation / health lowers effective weight** on latency, failed dials, and any
  detected fault, independent of stake — a well-funded bad actor still loses traffic as
  it misbehaves.
- **Slash only on provable faults**, and design the small set of them deliberately
  (e.g. equivocating on the advertised onion key, or a detectable double-count in the
  shared tally). Do not pretend the bond is slashable on the unprovable harms. The
  provable-fault set is an open design question, tracked with the on-chain gateway
  registry, and it is thin on purpose.

**Where this lands relative to discovery.** Registration cost and discovery are the same
question: a curated signed directory has no rogue-service problem at all (the signer vets
entries) but does not scale to permissionless operators; a permissionless on-chain
gateway registry scales but *needs* the stake + weighting + reputation above to keep
rogue services from dominating; a permissioned-and-staked registry is the hardest to
Sybil and the least open. The staking design in this section is what makes the
permissionless option safe enough to consider.

### A rogue gateway is a free both-ends vantage

One more capability, because it is the worst case and it is why rotation exists. A
gateway is an *endpoint* of the tunnel, not a relay, so it sees the exact
application-layer payload sizes and timing (it forwards your real bytes to the clearnet
destination). That makes a rogue gateway an ideal "one end" for the classic Tor both-ends
correlation attack (adversarial-review
[#11](adversarial-review.md#11-tor-layer--network-adversaries-relay-positions-correlation-self-deanon)):
an adversary who runs the gateway *and* also owns the client's entry guard (or an AS on
the client's uplink) can match volume+timing between the two ends and link **client IP ↔
nullifier ↔ destination**, fully deanonymizing that request.

This is not defeated by padding, for two reasons worth recording so the idea is not
re-litigated: (1) the gateway→destination leg is plain TLS to a server you do not control,
so hiding sizes there needs the *destination* to honor a padding scheme (TLS record
padding, HTTP/2 padding frames) — you cannot do it unilaterally; and (2) even if you
could, timing correlation defeats size-padding, and no deployed Tor padding defense closes
the gap. Padding belongs to the network-observer project, not here.

The mitigations are structural, and they are exactly the two features this next version
adopts:

- **Per-tunnel rotation** cuts the fraction of your traffic any one gateway (rogue or
  honest) receives to ~1/N, so a rogue gateway can only correlate the share that lands on
  it.
- **Per-tunnel nullifiers** (ROADMAP-v1 #1) cap the *blast radius* of each successful
  correlation to a **single request** instead of the whole epoch. With the constant
  per-epoch nullifier, one correlation hit attributes every request that epoch; with
  per-tunnel nullifiers it attributes one stream.
- **Entry guards** (Tor) make owning the client end expensive — becoming someone's first
  hop needs a large share of guard bandwidth, not just "a bunch of nodes" — and
  **AS-diverse gateways** (below) lower the odds one network sees both ends.

None of this *beats* a true both-ends adversary; nothing deployed does. It makes owning
the client end costly and caps the damage of each hit to one request. That is the honest
guarantee, and it is why rotation + per-tunnel nullifiers are load-bearing here, not
cosmetic.

## AS diversity (adversarial-review finding 11)

The fleet is the right place to fix the single-datacenter-AS both-ends exposure, and
it is a real requirement, not a nicety.
[Adversarial-review finding 11](adversarial-review.md#11-tor-layer--network-adversaries-relay-positions-correlation-self-deanon)
flags that the PoC gateway lives in one datacenter AS (DigitalOcean), so the
gateway-side leg is disproportionately observable to an AS/IXP that already sits on a
large share of Tor path probability, and a datacenter egress IP is itself a weak
fingerprint. Adding IPs at the *same* provider adds gateways without adding diversity:
the same AS still sees the same fraction of both-ends paths.

So directory construction should be an **AS-diversity budget, not an IP count**: spread
gateways across distinct ASes and hosting providers (ideally some non-datacenter
egress), and let `weight` account for it. The directory schema does not encode AS
(keeping it minimal and not leaking operator topology into a signed public file), but
the *publishing policy* should treat "N gateways across N ASes" as the target and "N
gateways in one AS" as failing the point. The example directory notes this per entry.
This is a policy on how the list is assembled, enforced by the human who signs it, not
a cryptographic check.

## Explicitly out of scope: multi-hop gateways

Gateway A forwarding to a gateway B that A selects is **not** the plan. It only moves
the knowledge to A and doubles the latency. Per the framing above and in the roadmap,
knowing your own exit is not the threat; one operator seeing all of a member is. Client-
side per-tunnel rotation addresses that threat directly. Multi-hop pays real latency to
hide the exit from the client, which was never what needed hiding. If a future threat
model wants the client blind to its exit, that is a different project with a different
justification; it is not this one.

## What is built here

| File | What it is |
|---|---|
| `lib/directory.mjs` | Load + verify a signed directory (ed25519, pinned signer), onion↔pubkey binding, onion-control check, weighted `pickGateway` / `selectionOrder`, `reportHealth`, last-known-good `loadDirectory`. On-chain mode is a TODO behind the same shape. |
| `client/selection.mjs` | Shim-facing: `directoryEnabled()`, `selectCandidates()` (weighted pick + failover order), `reportResult()`. Refreshes lazily, carries health across refresh, degrades to cache. |
| `client/shim.mjs` | `SHADE_TREE_DIRECTORY` path: per-CONNECT candidate order with dial-timeout failover and health feedback. `SHADE_TREE_ONION` and the single-onion path are unchanged. |
| `group/directory.example.json` | A signed 3-gateway example with real, internally-consistent v3 onions. |
| `group/sign-directory.mjs` | Mint the signer key and (re)sign a directory; with no args mints the example. |
| `bootnode/deploy/bootstrap.sh` | Fleet bring-up per box. `SHADE_TREE_BOOTNODE_ONION=<onion>` = gateway-only box that joins an existing bootnode (no local bootnode unit/HS); `SHADE_TREE_ENABLE_POW=1` = onion PoW defense (default `0`); `SHADE_TREE_GATEWAY_REGION=<bucket>` = region in signed caps. Table: `bootnode/deploy/README.md`. |

Enable directory mode:

```bash
export SHADE_TREE_DIRECTORY=group/directory.example.json
export SHADE_TREE_DIR_SIGNER=<pinned signer pubkey printed by sign-directory.mjs>
# SHADE_TREE_SECRET as usual; the shim now rotates gateways per tunnel with failover.
```

The one-line integration is already in the shim's connect handler
(`const onions = await candidateOnions()`); with no `SHADE_TREE_DIRECTORY` set,
`candidateOnions()` returns the single pinned onion and nothing changes.

## Reconciliation with ONCHAIN.md

Two seams touch the parallel on-chain track. Both are now resolved in
[ONCHAIN.md](ONCHAIN.md); recorded here so the coupling is visible from this side too.

1. **One canonical root, or two: one *source*, two lists.** Members and gateways are
   different node types (a member is an identity commitment; a gateway is an operator
   advertising an onion), so they are not the same Merkle tree. The endgame is one
   on-chain contract *system* — a member registry (`StakedReputationSet`) and a sibling
   gateway registry of `{ onion, pubkey, weight }` advertisements, each self-authenticated
   because a v3 onion *is* its key — read over the same RPC, verified the same way, with
   no separate signer to trust. So "the fleet shares the reputation set's root" means
   "same canonical on-chain source," not "gateways are leaves in the member group." This
   doc's static-signed directory is the interim; the on-chain gateway registry is its
   endgame and it retires the pinned directory signer.

2. **The shared tally schema is fixed.** Fleet-wide budget and cross-gateway slashing
   both require the shared tally from option (b), and ONCHAIN.md states the same
   per-gateway-slashing limitation from its side. The two docs agree on one shape: the
   tally is keyed `(nullifier, epoch)` and holds `{ count, shares }` — `count` for the
   budget cap, `shares` for slashing, and any gateway that observes the `L + 1`-th share
   reconstructs and slashes. Whether that tally lives in a replicated KV, a gossip
   tally, or on chain is an implementation choice; the key and the two values are the
   contract between the two designs, and it must still be paired with item 1's
   per-tunnel nullifiers so the shared tally is a set of unrelated counters, not a
   profile.
