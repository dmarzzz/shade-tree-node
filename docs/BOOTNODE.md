# Elder Tree: live node discovery

The proof of concept pinned one gateway. The [fleet directory](FLEET.md) made that a
*signed static file*. The **Elder Tree**, called the bootnode in code and wire docs,
makes it live: nodes announce themselves, the bootnode holds live ones for a TTL, and it
serves the union as a signed directory called the **canopy directory**.
[`packages/node/lib/directory.mjs`](../packages/node/lib/directory.mjs) already knows how to verify that shape. It is the
dynamic realization of roadmap milestone 3.

## What it is

A small HTTP service (`packages/node/bootnode/server.mjs`) published as its **own v3 onion service**, so
Proxies reach it through a Tor SOCKS dial with no exit node. The
bootnode never learns a client IP.

```
POST /announce         a gateway registers/renews itself (see "The announce" below)
GET  /directory        the current signed directory of live gateways
GET  /gateway/<onion>  the stored signed announce for one gateway (zero-trust re-verification)
GET  /health           liveness + count + admission policy
```

## What it verifies and what clients trust

### The onion is never on chain

A v3 `.onion` address *is* an ed25519 public key. Putting it on chain would make the whole
fleet publicly enumerable and permanently bind each onion to the address that paid for it.
That is the exact property Tor's blinded HSDir descriptors exist to avoid. The on-chain
[`GatewayRegistry`](../contracts/GatewayRegistry.sol) stakes only an **operator address**.
The onion lives only in the signed announce the operator hands the bootnode. One stake can
rotate across many onions; the fleet is never enumerable on chain.

### The bootnode is a discovery authority

The bootnode verifies onion control before accepting a direct or gossiped announcement.
In stake mode it also verifies the operator authorization and live bond. Those checks protect
the service's registry.

The directory consumed by a Proxy is a smaller object. It does not include the announcement's
`onionSig`, so `verifyDirectory` authenticates the list with the pinned signer and checks that
each onion matches its listed public key. It does not prove live onion control. A compromised
signer can omit, reorder, or add an internally consistent entry, including a malicious onion
it controls. It cannot make an existing onion terminate at a different key. When capabilities
are present, their onion-key signature remains independently verifiable.

`GET /gateway/<onion>` exposes the stored announcement for deeper checks. Clients can enable
`SHADE_TREE_VERIFY_STAKE=1` to re-verify entries that claim operator stake. That check is off
by default, and onion-only entries still rely on the pinned directory signer for selection.

## The announce

`packages/node/bootnode/announce.mjs` builds it; the bootnode and clients verify it. Shape:

```jsonc
{
  "v": 1,
  "onion": "<56-char>.onion",
  "weight": 100,
  "ts": 1789000000,          // fresh; a stale/future ts is rejected (replay window)
  "nonce": "<hex>",          // one-shot within the window
  "onionSig": "<ed25519>",   // by the onion's OWN key over {v,onion,weight,ts,nonce}  (onion control)
  "operator": "0x..",        // optional (admission=stake)
  "operatorSig": "<ecdsa>"   // personal_sign("Shade Tree gateway operator authorization\nonion=..\noperator=..")
}
```

The **onion signature is refreshed every heartbeat** (fresh `ts`/`nonce`, cheap, local). The
**operator signature is durable**: signed once, reused every heartbeat, revoked only by
unstaking. This is possible because a gateway holds the 32-byte seed behind its onion (see
[keygen](#the-onion-identity)), so it can sign with node's built-in crypto and no new
dependency.

## Admission policy

`--admission open` (default) requires only onion control. Discovery is permissionless.
`--admission stake` additionally requires a live, authorized operator bond. Staking is the
opt-in hardening tier, and a natural home for the on-chain funds a gateway needs anyway (it
is the party that pays gas to slash member over-spenders). Gateway slashing is **governed**
(owner-only), not permissionless; the one honest asymmetry vs the member slash, because a
member over-spend is a cryptographic proof while gateway misbehavior is a subjective
judgment. See [`GatewayRegistry.sol`](../contracts/GatewayRegistry.sol).

## The onion identity

`shade-tree keygen <hsDir>` (`packages/node/bootnode/keygen.mjs`) mints one ed25519 seed and writes both:

- Tor's HS key files (`hs_ed25519_secret_key`, `hs_ed25519_public_key`, `hostname`) so Tor
  publishes exactly this onion, and
- `identity.local.json` holding the seed, so the gateway can sign announces.

This works because a v3 onion's public key *is* the standard ed25519 public key of the seed:
`h = SHA-512(seed); a = clamp(h[:32]); A = a·B; onion = base32(A ‖ checksum ‖ 0x03)`. Tor's
expanded secret key derives the same `A`, so one seed is both "the key Tor publishes with"
and "the key we sign with."

## Liveness

A bootnode entry is soft state with a TTL (`--ttl`, default 900s). A gateway proves liveness
by continuing to announce (`shade-tree heartbeat`, every `--interval` seconds); a dead gateway ages
out without anyone deregistering it. Clients cache the last-known-good directory, so a dead or
poisoned bootnode degrades to the previous good fleet, never to nothing.

The heartbeat itself keeps no state and never backs off: each tick egress-checks, announces, and
logs one of `announced`, `announce rejected: <reason>` (the bootnode said no, or replied with
something that is not a JSON object), or `announce failed: <err> (will retry next interval)` (the
bootnode was unreachable over Tor). Every outcome is retried on the next `--interval`; a rejected
or unreachable gateway simply ages out via the TTL. Operator configuration is resolved once at
startup and fails fast on any misconfiguration (see `docs/CONFIG.md`, `SHADE_TREE_GW_OPERATOR*`);
`packages/node/bootnode/heartbeat.selftest.mjs` pins operator resolution, the announce bytes against
`testdata/vectors.json`, every failure path, and that no seed or operator key ever reaches a log.

### Surviving a restart

The live set is in-memory by default, so a bootnode restart would blank the fleet until every
gateway's next heartbeat. Set `SHADE_TREE_BOOTNODE_STORE=<path>` (the deploy sets it automatically) to
turn on **write-through persistence**: every accepted announce is mirrored to a small JSON file
and reloaded on boot. Reload is not blind trust; each stored record is re-run through the same
announce verification (onion control, and in stake mode a live on-chain `isStaked` re-check), and
any entry already past its TTL is dropped. Freshness on reload is the **TTL** (how long an
accepted gateway stays listed), not the announce anti-replay window; so a restart minutes after
the last heartbeat keeps the fleet, while a stale or tampered store can never resurrect a
long-dead gateway or inject an onion nobody controls.

## Federation (multiple bootnodes)

The bootnode is the one new single-point-of-availability the fleet adds. **Federation** closes
that: run more than one bootnode and let them gossip, so discovery survives any one going dark.
Off by default; with no `SHADE_TREE_BOOTNODE_PEERS` set, a bootnode is byte-for-byte the standalone one
above.

```bash
# each bootnode lists the OTHER bootnodes' onions
SHADE_TREE_BOOTNODE_PEERS=<peerA>.onion,<peerB>.onion \
SHADE_TREE_BOOTNODE_ONION=<this-bootnode>.onion \
SHADE_TREE_BOOTNODE_FED_INTERVAL=60 \
  shade-tree elder ...
```

| env | default | meaning |
|---|---|---|
| `SHADE_TREE_BOOTNODE_PEERS` | *(empty → off)* | comma-list of peer bootnode onions to federate with |
| `SHADE_TREE_BOOTNODE_FED_INTERVAL` | `60` | seconds between pull cycles |
| `SHADE_TREE_BOOTNODE_FED_MAX_PULL` | `maxEntries` | max gateways pulled per peer per cycle (bounds a hostile peer) |
| `SHADE_TREE_BOOTNODE_ONION` | *(unset)* | this bootnode's own onion, filtered out of the peer set |

### Gossip re-verifies announcements

A pull loop (`packages/node/bootnode/federation.mjs`, a self-unref'd timer) periodically fetches each peer's
`GET /directory` over Tor, and for **each listed onion** pulls that gateway's stored signed announce
from the peer's `GET /gateway/<onion>`. Every pulled announce is then re-run through the **same real
`verifyAnnounce` path a direct announce takes** (`registry.admitGossip`) before it is merged:

- **The peer's directory signature is never trusted as authority over entries.** The peer's
  `/directory` is used only as a *hint list of onion strings*; its signer, pubkey, weight, health and
  operator/staked labels carry no admission weight. Admission comes entirely from re-verifying the
  per-gateway announce. That is why federation pulls `/gateway/<onion>` rather than trusting
  `/directory` alone (the directory shape omits the `onionSig`/`ts`/`nonce`/`operatorSig` needed to
  re-verify an entry, so it is not independently re-verifiable per entry).
- **A forged / tampered / unstaked gossiped gateway is rejected exactly as a direct announce would
  be**: the v3 `.onion` *is* its ed25519 key, so a swapped onion or a flipped signed field breaks the
  onion signature (`bad-onion-sig`); in stake mode the operator sig is re-checked and `isStaked` is
  re-read on **this** bootnode's own chain view (`not-staked` / `bad-operator-sig`). So gossip can add
  nothing a live gateway could not have announced to us directly.

### Loop / DoS bounding

- **Freshness is the origin announce's own TTL.** A merged entry expires at `ts + ttl` of the
  announce the origin gateway signed. Gossip never refreshes it, so a peer cannot keep a dead gateway
  alive by re-gossiping a fixed old record, and an entry never re-propagates its own TTL. Re-pulling
  the same record is idempotent (dedup by onion + expiry; gossip never shortens a fresher local entry,
  e.g. one heartbeated to us directly). An announce whose `ts + ttl` already lapsed is dropped
  (`stale-gossip`).
- **The existing DoS caps still hold.** `maxEntries` bounds what is admitted (a new gossiped onion is
  refused when full); `SHADE_TREE_BOOTNODE_FED_MAX_PULL` bounds how many gateways we fetch from any one peer,
  so a hostile peer advertising a giant directory cannot make us do unbounded per-gateway fetches.
- **Fail-soft.** A down peer (fetch throws) is skipped; one failing gateway fetch doesn't abort the
  peer; one failing peer doesn't abort the cycle. Federation is strictly additive; it only *consumes*
  peers, exposing no new endpoint and no new linkability/DoS surface. Persistence + sweep are
  unchanged: a merged entry is written through and re-verified on reload like any other.

*Accept (proven offline in `packages/node/bootnode/federation.selftest.mjs`, injected fetch + clock):* two bootnodes
converge on the same live set; the forged/tampered/unstaked/stale rejection matrix; dedup + no-shorten;
the caps; fail-soft over a dark peer; and a no-peer registry directory byte-identical to a
federation-free one.

## Deploying it (`bootstrap.sh` tunables that concern the bootnode)

`packages/node/bootnode/deploy/bootstrap.sh` brings up bootnode + gateway on one box by default. Two knobs change
that shape (full table: `packages/node/bootnode/deploy/README.md`, `docs/CONFIG.md` "Deploy"):

| env | default | meaning |
|---|---|---|
| `SHADE_TREE_BOOTNODE_ONION` | *(unset → this box runs its own bootnode)* | set to an existing bootnode's onion for a **gateway-only** box: no `shade-tree-bootnode` unit, no bootnode HS; the heartbeat announces to that remote bootnode |
| `SHADE_TREE_ENABLE_POW` | `0` | onion PoW DoS defense on the bootnode + gateway onions this box publishes (`1` = on; off by default because `pow: no` client tors cannot reach a PoW onion) |

## Endpoint hardening (T-HARD-4)

The registry's DoS controls (`maxEntries`, `minReannounceSec`, the weight clamp) bound *what is
resident*. Two more levers are bounded at the endpoint itself (`packages/node/bootnode/server.mjs`):

### The global announce token bucket

`minReannounceSec` throttles a *resident* onion and `maxEntries` refuses new ones once *full*,
but an attacker minting fresh onions is neither. Until the registry fills, every fresh
crypto-valid announce can reach the ed25519 verifier. Up to `maxEntries` verifies could arrive in one burst.
`makeAnnounceBucket` sits directly in front of `verifyAnnounce` and bounds the **rate** at
which any announces reach signature verification, whoever sends them. A throttled announce
costs a Map lookup and an add; never a verify. Rejections are `429 global-rate-limited` with
`Retry-After`; per-onion `rate-limited` and `registry-full` are checked *first* and consume no
token, so an attacker's cheap rejects never starve a legitimate heartbeat. Store reload on
boot is exempt (local work, still fully re-verified).

Sizing (defaults; every number derives from the registry constants + the fleet heartbeat):

```
legit sustained load  = N gateways × 1 announce / SHADE_TREE_BOOTNODE_HEARTBEAT,   N ≤ maxEntries
                      = maxEntries / heartbeat = 10000 / 300 = 33.3 announces/s at FULL capacity
rate  (refill/s)      = 2 × maxEntries / heartbeat = 66.7/s          SHADE_TREE_BOOTNODE_ANNOUNCE_RATE
burst (capacity)      = max(100, maxEntries / 10)  = 1000            SHADE_TREE_BOOTNODE_ANNOUNCE_BURST
```

So a fleet at the registry cap, heartbeating at the default cadence, draws half the refill and
the bucket never drains; a fleet of up to `burst` gateways re-announcing in perfect lockstep
(a fleet-wide restart) passes in one instant and is fully refilled before its next beat; an
attacker minting fresh onions gets at most `burst` verifies up front and then `rate`/s (1000,
then 66.7/s, instead of 10000 in one burst). A throttled legit heartbeat is not lost: it retries at
its next beat (TTL 900 s = 3 beats), so a healthy gateway is never aged out by the bucket. Only
fleets *larger* than `burst` that restart in lockstep need `SHADE_TREE_BOOTNODE_ANNOUNCE_BURST` raised.

### HTTP slow-client limits

Node's `http.Server` defaults leave slow-loris open (headers 60 s, whole request 300 s, headers
16 KiB, enforced every 30 s). Every bootnode request is small and fast, so `makeServer` sets:
headers within `SHADE_TREE_BOOTNODE_HEADERS_TIMEOUT_MS` (10 s), whole request within
`SHADE_TREE_BOOTNODE_REQUEST_TIMEOUT_MS` (30 s) → `408` + close; idle keep-alive closed after
`SHADE_TREE_BOOTNODE_KEEPALIVE_TIMEOUT_MS` (5 s); headers over `SHADE_TREE_BOOTNODE_MAX_HEADER_BYTES`
(8 KiB) → `431`; enforced every `SHADE_TREE_BOOTNODE_CONN_CHECK_MS` (1 s). The 64 KiB body cap on
`/announce` is unchanged.

*Accept (proven in `packages/node/bootnode/hardening.selftest.mjs`, real sockets + a verify spy):* a
fresh-onion burst gets exactly `burst` verifies and the rest are `429` with verify never called;
cheap rejects consume no token; reload is exempt; N gateways at heartbeat cadence (random phase
and lockstep) never hit the bucket at default sizing; slow-loris headers/body are cut with
`408`; oversized headers `431`; idle keep-alive closed. `test/adversarial.selftest.mjs`
scenario 7 replays the burst + slow-loris as attack narratives.

## Client side

Load the member secret into `SHADE_TREE_SECRET` as shown in the
[agent guide](AGENT.md), then run:

```bash
shade-tree proxy --bootnode <elder-onion> --dir-signer <directory-signer-pubkey>
```

The client fetches `/directory` over Tor (`packages/node/bootnode/fetch.mjs`), verifies it against the
pinned signer, and feeds it into the existing weighted rotation + failover
(`packages/node/client/selection.mjs`). Everything downstream, including the per-tunnel RLN proof and
gateway and slot rotation, is unchanged. The bootnode only changes *how the fleet is discovered*.

## Verify it end to end (no Tor, no chain)

```bash
node packages/node/bootnode/selftest.mjs
```

Mints real onion identities, runs the real HTTP bootnode, and asserts every adversarial case
is rejected (forged onion sig, wrong key, stale ts, replayed nonce, unstaked operator, stolen
operator sig) while honest announces are served in a directory that verifies against the
pinned signer.
