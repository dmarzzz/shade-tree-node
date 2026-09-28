# Roadmap v1: milestone design notes (1–5)

> **History.** Kept as written for the record; it describes an earlier version and is not a current runbook. Current docs: [docs index](../README.md).

The original milestone-by-milestone design for the pieces beyond the proof of concept,
kept for the reasoning (including the tiers not taken). Every milestone here is now built;
the forward-looking roadmap is [`ROADMAP.md`](../ROADMAP.md) and the shipping backlog is
[`SHIP-PLAN.md`](SHIP-PLAN.md). ADRs and other docs cite these milestones as
`ROADMAP-v1.md #1` … `#5`.

**Status (2026-08).** Most of this doc is now built on the `deploy/onchain-staked-fleet`
line and extended by `feat/bootnode-and-productionize`:

| # | milestone | status |
|---|---|---|
| 1 | Unlinkable rate limiting | **built** as real RLN (fresh per-tunnel share, over-spend reconstructs + slashes) — `lib/rln.mjs`, `contracts/rln/`. Supersedes the slot scheme sketched below. |
| 2 | On-chain reputation set | **built** — `contracts/StakedReputationSet.sol` (live on Sepolia), `lib/root-provider.mjs`. |
| 3 | Egress discovery + fleet rotation | **built (static)** — signed directory + client rotation (`lib/directory.mjs`). Made **live** by milestone 4. |
| 4 | Live discovery: the bootnode | **built** — `bootnode/`, `contracts/GatewayRegistry.sol`, `docs/BOOTNODE.md`. |
| 5 | Productionization + deploy | **in progress** — `shade-tree` CLI, Docker, `docs/QUICKSTART.md`; live droplet deploy prepped in `bootnode/deploy/`. |

Sections 1-3 below are the original design notes (kept for the reasoning, including the
tiers not taken); 4-5 are the newer milestones.

### 1. Unlinkable rate limiting (decouple linkability from the rate window)

**Problem.** The gate rate-limits per member by scoping the nullifier to the
current epoch (`scope = floor(now / 86400)`, a day by default). That scope is
public and shared, so every request a member makes within the day carries the
same nullifier. The
gateway can count them, which is the point, but it can also link them. Shrinking
the epoch shrinks the linkable window but also shrinks the budget, so it looks like
rate limiting and unlinkability trade off against each other.

**They don't.** The trick is to stop publishing the scope. Make the epoch long, let
a member scope each request to a *different* epoch of their choosing, and prove in
zero knowledge only that the chosen epoch `e` is in range, for example
`present - W <= e <= present`, without revealing which `e`. Now:

- each request uses a distinct, member-chosen `e`, so each carries a distinct
  nullifier and the requests are **mutually unlinkable**, even to the gateway,
- the number of valid `e` values in the window (`W + 1`) bounds how many distinct
  nullifiers a member can present, so the **rate is still capped**: roughly one
  fresh nullifier per epoch sustained, with a burst of `W + 1`.

It turns out this ships in two tiers, and the first one needs **no custom circuit
at all.**

**Tier 1: public slots, stock Semaphore (buildable now).** Publish `K` scope slots
per epoch, `scope_i = H(epoch, i)` for `i` in `[0, K)`. The client uses a different
slot for each request and generates one ordinary Semaphore proof per slot. The
gateway accepts a proof only if its `scope` is in the published slot set for the
current or previous epoch, and dedups per nullifier as it does today. This already
breaks the tension:

- each slot yields a distinct nullifier `H(secret, scope_i)`, and those nullifiers
  are **mutually unlinkable** to the gateway, so a member's requests across slots
  cannot be tied together,
- a member has exactly `K` valid scopes per epoch, so the **rate is capped at `K`**
  no matter how they interleave them.

The cost is that the client now generates up to `K` proofs per epoch instead of one.
At ~0.7s per proof (see [proof overhead](#proof-overhead)) that is the difference
between a per-tunnel stall and a non-issue: **precompute the epoch's `K` proofs in
the background at epoch rollover and rotate through them per tunnel**, so the hot
path is just "pick the next unused proof," near zero latency. `K = 30` is ~21s of
background work per hour, fully parallel across cores. This is the bulk-generate-and-
rotate strategy, and it is what makes per-tunnel unlinkability usable. The only
residual leak is that the gateway learns *which slot index* a request used (not who
used it), so it sees the slot-usage histogram but never a member.

**Tier 2: hidden slots, custom circuit (hardening).** To also hide the slot index,
and to get a sliding-window budget instead of a fixed per-epoch `K`, move the scope
inside the proof: prove in zero knowledge that the chosen epoch `e` satisfies
`present - W <= e <= present` (and `i < K`) without revealing `e` or `i`. Now the
gateway learns nothing but a fresh nullifier and the fact that it is in-budget.

- A custom circuit replaces the stock Semaphore proof: Merkle membership, a
  Poseidon nullifier over a *private* scope, and a comparator enforcing the range
  bound on `e` (and `i < K`). `present` is a public input the gateway pins to its
  clock.
- The gateway keeps a spent-nullifier set across the last `W + 1` epochs instead of
  just the current and previous epoch. Bounded by `K * W * activeMembers`.
- No slashing. RLN reconstructs an over-spender's secret from Shamir shares revealed
  in *public* messages. Our proof never leaves the Tor-encrypted tunnel to a single
  verifier, so there is no public share to slash on and nothing to reconstruct. The
  gateway simply refuses a nullifier once its budget is spent. This is strictly
  simpler than RLN and a better fit for the single-verifier setting.

**Cost.** Tier 1 is a small change to the gateway's scope check plus a precompute
loop in the shim, both on stock Semaphore. Tier 2 adds a circuit to write, audit,
and ship artifacts for, in exchange for hiding the slot index and a more flexible
budget. Tier 1 is the next thing to build; Tier 2 is the hardening after it.

### Proof overhead

Measured locally (Apple Silicon, `@semaphore-protocol` v4), so the numbers above are
grounded:

| Reputation set | Merkle depth | Proof size | Generate (warm) | Verify |
|---|---|---|---|---|
| 1 member | 1 | 882 B | ~470 ms | ~32 ms |
| 100 | 7 | 882 B | ~784 ms | ~30 ms |
| 1000 | 10 | 884 B | ~891 ms | ~30 ms |

Takeaways: the proof is **tiny and fixed-size** (~0.9 KB, a Groth16 proof plus
public signals, independent of set size), verification is **cheap and constant**
(~30 ms, so the gateway can verify thousands/sec/core), and **generation is the only
real cost** (~0.5–0.9s warm, growing slowly with tree depth, plus a one-time ~2–4s
cold start for artifact load). Today the shim pays one generation per epoch and
caches it, so cost is negligible. The bulk-precompute strategy above keeps it
negligible even when every request wants its own nullifier.

### 2. On-chain reputation set (Ethereum)

**Problem.** Today the reputation set is `group/members.json`, a file the gateway
and every client must hold byte-identical or proofs fail the root check. The trust
root is whoever runs `enroll.mjs`. There is no public audit trail, no shared source
of truth, and updating the set means redistributing a file out of band.

**Goal.** Source the set from an Ethereum contract so the Merkle root is canonical,
public, and tamper-evident, admission is enforced on-chain, and the gateway and
clients both read the same root from the same place with no file to sync.

**Design.**

- Deploy Semaphore's on-chain group contract (`Semaphore.sol` maintains a group's
  members, exposes the current Merkle root, and accepts proofs against recent roots
  within a freshness window). Members are added by `addMember(groupId, commitment)`,
  gated by whatever admission policy you want in front of it: `onlyOwner`, a stake
  deposit, a token balance, a DAO vote, or a World ID proof (itself Semaphore-based,
  so it composes cleanly).
- The gateway stops calling `loadGroup()` on JSON and instead reads the group's
  current root, plus the recent roots inside the freshness window, from the contract
  over RPC, refreshing on `MemberAdded` events. `checkProof`'s single-root equality
  test becomes membership in that recent-root set. The freshness window is the
  on-chain analog of the current "this epoch or last epoch" skew tolerance: a proof
  built against a root that was current a block ago still verifies.
- Clients derive the leaves from `MemberAdded` event logs and rebuild the tree
  locally, then check the local root against the on-chain root before trusting it.
  No `members.json` to ship. `members.json` can stay as an offline cache whose root
  is verified against chain.

**What changes.**

- `lib/semaphore.mjs`: `loadGroup()` gains an on-chain mode behind
  `SHADE_TREE_GROUP_CONTRACT` / `SHADE_TREE_RPC_URL` / `SHADE_TREE_GROUP_ID`, with the JSON path kept
  as the offline default.
- `gateway/gateway.mjs`: `TRUSTED_ROOT` becomes a refreshed set of recent roots.
- `group/enroll.mjs`: grows a sibling that submits `addMember` on-chain.
- New `contracts/` with the group contract and a deploy script.

**Cost and honest scope.**

- Adds an RPC dependency and a chain-liveness assumption to a system that is
  otherwise fully local. Mitigate by caching the last-known root: if the RPC is
  down, the gate keeps working against the last root it saw.
- Enrollment now costs gas and confirmation latency. Fine for a slowly-changing set;
  use an L2 (Base, Optimism, Arbitrum) to keep it cheap. Semaphore has deployments
  there.
- No new identity leakage. Only commitments go on-chain, exactly as in
  `members.json` today, and a commitment reveals nothing about who holds the secret.
  One new exposure: enrollment is now publicly timestamped and linkable to the
  address that paid the gas. If admission is stake- or token-based that linkage is
  inherent. If you need enroller privacy, relay the `addMember` call through a
  meta-transaction or a privacy pool. Out of scope here.

### 3. Egress discovery and per-tunnel gateway selection (the fleet)

**Problem.** The PoC has exactly one gateway, and the client pins it ahead of time:
the shim dials whatever single onion `SHADE_TREE_ONION` (or the local `hostname` file)
names (`client/shim.mjs`). That carries two costs.

- **No discovery.** Onion addresses are handed out of band (the bundle ships one
  baked-in default). There is no way to add or retire a gateway without re-handing
  addresses, and no live notion of which gateways are up. The network will not do
  this for us: onion descriptors are stored under a *blinded* key on the HSDir
  hashring precisely so the gateways cannot be enumerated, so the directory has to
  be something we build at the app layer.
- **Pinning concentrates trust.** Whichever gateway a client pins sees *all* of that
  client's egress for the epoch — every target `host:port`, all timing and volume —
  bucketed under one constant nullifier. The member stays anonymous (no IP, no name)
  but becomes a complete, coherent profile to that one operator.

To be precise about the second cost: the problem is **not** that the client knows
its own exit. A Tor client knows its own exit too; path selection runs client-side.
Tor's property is that no single *relay* knows both ends, not that the client is
blind to its path. The problem is the inverse — one operator knowing the whole of
one anonymous member. The fix is therefore not to hide the exit from the client but
to stop any one exit from seeing all of a member.

**Goal.** A directory of live gateways plus **per-tunnel, client-side selection**,
so the client never commits to a single operator and a member's traffic spreads
across the fleet. This is the app-layer analog of Tor rotating circuits, except our
"exits" are destinations (onion services), so the selection lives in the shim, not
in Tor's relay path selection.

**Design.**

- **Directory.** A small signed list of `{ onion, pubkey, weight, health }`,
  refreshable. Start as a static signed JSON distributed with the member bundle and
  served as its own onion for live updates; pin the signer key in the client. The
  natural endgame is to source it from the same on-chain group as the reputation set
  (#2), so the fleet and the membership share one canonical, tamper-evident root.
  Gateways prove control of their advertised onion so a poisoned directory cannot
  graft in a hostile address.
- **Selection in the shim.** Per-connection weighted-random pick from the live set,
  with health/latency feedback and failover to the next gateway on dial timeout.
  `curl` stays dumb — the shim is the router (shim-as-router). Optionally expose a
  pin (`SHADE_TREE_ONION` still forces one gateway) for debugging or when a caller really
  wants a fixed egress IP.
- **Rotation is free, cryptographically.** The membership proof is
  gateway-independent: same trusted root + same epoch verifies at *any* gateway that
  loads the same `members.json`. So rotating gateways needs no new proof and no new
  circuit — the shim reuses the cached proof and just dials a different onion.

**Why this is the privacy win, and how it composes with #1.** With one gateway, that
operator sees 100% of a member's (metadata-only) targets under one nullifier. Spread
per-tunnel across `N` non-colluding gateways and each sees only ~`1/N`. Rotation
alone does **not** defeat *colluding* gateways: they can still reassemble the profile
by matching the member's constant per-epoch nullifier across their logs. Ship #1
(a distinct nullifier per tunnel) and even colluding gateways cannot tie the
requests together. **Rotation + per-tunnel unlinkable nullifiers** is the
combination that actually delivers "no operator, even a colluding set, can profile a
member." Neither piece is sufficient alone.

**Cost and honest scope.**

- **The rate limit does not compose across the fleet.** Each gateway keeps its budget
  in an in-memory per-process `Map` (`gateway/gateway.mjs`), so a member who spreads
  requests across `N` gateways gets `N`× their intended budget. Rotation forces a
  choice: either accept a fleet budget of `N`× per member, or share nullifier
  accounting across gateways (a shared spent-set store, or gateways publishing
  per-epoch nullifier counts to a common tally). Shared accounting reintroduces a
  cross-gateway linkage point — unless it is paired with #1, whose per-tunnel
  nullifiers keep the shared tally from also being a profile.
- **The directory is a new trust and availability surface.** Who signs it, how it is
  distributed, and what stops a stale or poisoned directory from steering a member to
  a hostile gateway. Mitigate with a pinned signer, gateway onion-control proofs, and
  a cached last-known-good list so a dead directory degrades to the previous fleet
  rather than to nothing.
- **Multi-hop gateways are explicitly not the plan.** Hiding the final egress from the
  client (gateway A forwards to a gateway B that A picks) only moves the knowledge to
  A and doubles latency. Knowing your own exit is not the threat, so we do not pay to
  hide it.

### 4. Live discovery: the bootnode (realizes #3)

**Problem.** Milestone 3 shipped discovery as a *signed static file* (`group/sign-directory.mjs`
→ `lib/directory.mjs`). Complete, but hand-maintained: adding or retiring a gateway means
re-signing and re-shipping a file, and there is no live notion of which gateways are up.

**Design (built).** A **bootnode**: the dynamic version of that exact signed shape, published
as its own v3 onion service (`bootnode/server.mjs`). Gateways announce themselves; the bootnode
holds live ones for a TTL and serves the union as a signed directory `lib/directory.mjs`
already knows how to verify. Two things kept it honest:

- **The onion is never on chain.** A v3 `.onion` *is* an ed25519 public key, so putting it on
  chain would make the whole fleet enumerable and bind each onion to its paying address forever
  — the property Tor's blinded HSDir descriptors exist to destroy. Instead the on-chain
  `GatewayRegistry` (`contracts/GatewayRegistry.sol`) stakes only an **operator address**, and
  the onion↔operator link lives only in the signed announce (`bootnode/announce.mjs`). One stake
  can rotate across many onions; the fleet stays un-enumerable on chain.
- **The bootnode is a cache and a discovery trust boundary.** Every announce carries onion-control
  proof and may carry operator-stake authorization. The bootnode verifies those at admission.
  Proxies pin the directory signer and trust it to choose the candidate list. A compromised signer
  can omit, reorder, or add entries. Onion/key binding prevents it from making an existing onion
  terminate at another key; optional stake and capability checks narrow the remaining trust.

**Stake is optional.** Bootnode admission defaults to `open` (onion control is the only hard
requirement); `admission=stake` requires a live bond. Staking is the opt-in hardening tier and a
natural home for the on-chain funds a gateway needs anyway (it is the party that pays gas to
slash member over-spenders). Gateway slashing is governed, not permissionless — the one honest
asymmetry vs the member slash, because gateway misbehavior is a subjective off-chain judgment
where a member over-spend is a cryptographic proof.

**How it composes with #1.** Rotation across the fleet plus RLN's per-tunnel unlinkable
nullifiers is still the combination that stops even a colluding set of operators from profiling a
member. The bootnode changes *how the fleet is discovered*, not that argument.

### 5. Productionization and deployment

**Problem.** The system worked but was operated by hand: env-var-only config, shell scripts, no
one command, no image, no quickstart. Hard for a new operator or a new gateway to join.

**Design (in progress).**

- **One CLI.** `shade-tree <command> [--flags]` (`bin/shade-tree.mjs`) fronts every role — `keygen`,
  `bootnode`, `heartbeat`, `gateway`, `client`, `enroll`, `register-member`, `register-gateway`,
  `doctor`. Each `--flag` maps one-to-one onto the existing `SHADE_TREE_*` env var, so flags and env
  stay in sync and either works. `shade-tree doctor` checks the local setup before you run anything.
- **Containers.** A single image with the CLI entrypoint (`docker run … bootnode --port …`) plus
  a compose that wires Tor + bootnode + gateway + client for a local fleet.
- **Docs.** `docs/QUICKSTART.md` (stand up a bootnode + a gateway + a client from scratch),
  `docs/CLI.md`, `docs/CONFIG.md` (every `SHADE_TREE_*` var), `docs/BOOTNODE.md` (the discovery design).
- **Live fleet.** `bootnode/deploy/` prepares a fresh droplet: install Tor (from the official
  repo for `pow: yes`), mint the onion identity, run the bootnode + a gateway as systemd units,
  and print the bootnode onion + pinned signer for clients. One command on a rented box.

**Honest scope.** Reproducible standalone binaries (Node SEA) are documented as a best-effort
path; Docker + a globally-installable CLI are the supported distribution. Onion-key backup and
fleet monitoring remain operator responsibilities.
