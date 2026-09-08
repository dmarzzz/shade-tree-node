# Shade Tree Grove Data API

The [Grove](https://shade-tree-node.vercel.app/grove/) is a deliberately small
public view of Shade Tree. It shows how many gateway identities appeared in the
last signed directory that the hosted observer could verify. It is topology,
not territory: there are no locations, identities, traffic paths, or selectable
nodes on the page.

This document is the authoritative contract for what the view means, which
surfaces exist, and what its collector is allowed to publish. The compact
[`data-api.openapi.yaml`](data-api.openapi.yaml) describes only the currently
implemented public read endpoint; prose here also records privacy and evolution
rules that OpenAPI cannot express.

## What the count means

The exact number counts gateway identities in the bootnode directory at
observation time. The observer fetches `/directory` over Tor and verifies its
signature against the pinned directory signer before counting entries. The
visual canopy regenerates one tree for each unit in that aggregate count, using
only the count and rounded observation time. A tree does not reveal or persist
the identity of a particular node; all non-geographic positions regenerate on
each observation.

Public copy calls the bootnode the **Elder Tree** and its signed directory the
**Canopy**. These names do not change the observer input or the signed schema.

The Sepolia source now points at the disposable Protocol v4 research Grove
recorded in [`network/sepolia/deployment.json`](../network/sepolia/deployment.json):
one dedicated Elder Tree and three dedicated Shade Tree nodes. The fleet is
invited-only and uses explicitly untrusted testnet proof artifacts; it is not a
production security claim. The hosted observer's earlier read-only pre-v4
compatibility switch is disabled. Client discovery, routing, announcements, and
node admission remain v4-only.

The count means **announced within the bootnode TTL**. It does not necessarily
mean the gateway was independently reachable. When optional active probing is
enabled, the signed directory can mark an entry down; the public aggregate does
not retain that per-node health dimension. An entry remains present until its
announcement expires.

The count is also not a count of people, operators, physical machines, public
IPs, or independent organizations. One operator can announce more than one
gateway identity. It is the directory visible through this observer and this
bootnode, not a claim about every Shade Tree deployment.

Publishing an exact total makes growth and churn observable. That is an
intentional privacy tradeoff. The view avoids adding the much more identifying
dimensions that could explain which node caused a change. The project keeps
only a bounded public history, but any third party can archive a count once it
has been published.

## Publication path

```text
node heartbeat
    -> Elder Tree directory (Canopy)
    -> signed directory fetched over Tor
    -> pinned signature + freshness verification
    -> aggregate-only snapshot signed by the observer
    -> generated network-state snapshot
    -> Vercel Grove API schema + signature verification
    -> /api/v1/data/grove/sepolia/head (count-only v1, unchanged)
    -> /api/v2/data/grove/sepolia/head (v2 with isolated relay and optional onchain aggregates)
    -> browser signature verification
```

The scheduled observer runs every 15 minutes. It accepts a signed directory only
when its issue time is within the five-minute freshness and future-skew window.
It then signs the canonical aggregate with a dedicated Ed25519 publication key.
The hosted publisher runs only when its network selector is exactly `sepolia`;
a missing or different selector leaves the last valid snapshot untouched.
The browser pins the corresponding key from
[`network/grove-signing-public.pem`](../network/grove-signing-public.pem) and
refuses an unsigned, malformed, future-dated, or incorrectly signed payload.
It prefers the v2 head, then falls back to the separately verified v1 count head
when v2's stricter freshness gate is unavailable. It accepts an older valid v1
snapshot so the last verified count can remain visible, then labels that view
stale as it ages. The bundled signed reference is the final fallback, not the
first response to a delayed v2 observation.

The read-only observer passes the two versioned signed JSON envelopes to a separate minimal publisher;
the publisher checks out no code and receives repository write permission only
for that step. It creates a parentless commit containing `grove.json`,
`grove-v2.json`, and a minimal `docs/post/vercel.json` that disables Vercel
deployments for the generated `network-state` branch, so the branch itself
carries no old commit chain and cannot create failed preview noise. A
dependency-free Vercel Function reads that snapshot from a fixed, versioned
GitHub Contents API URL, caps the response at 64 KiB, checks its exact schema
and publication signature, and serves it as JSON from
`/api/v1/data/grove/sepolia/head`. `/api/grove` and the earlier
`/grove/network.json` path are compatibility aliases to that same handler. A
Grove visitor never contacts the bootnode or GitHub directly from their
browser. The function requests GitHub's raw representation without an upstream
cache before applying its own edge policy. Unsupported query parameters are
rejected before the upstream read, preventing caller-controlled cache variants
from bypassing that policy.

The API gives browsers a 60-second cache and sets a five-minute Vercel edge
policy with one hour of stale-while-revalidate. It gives the upstream read four
seconds. The origin derives an `ETag` from the SHA-256 hash of its exact response
bytes. Vercel can expose the weak `W/` form after content transfer; both forms
carry the same opaque hash and participate in weak `If-None-Match` comparison.
The response also carries
`X-Shade-Tree-Schema: shade-tree-public-grove-v1`; a matching conditional
request receives `304`. A failed read, malformed envelope, or bad signature
returns a generic, non-cacheable `503` with `Retry-After: 60`. It never
translates failure into a zero count. The page then uses its bundled signed
reference and labels that view accordingly.

The Vercel Function does not dial the Elder Tree. Its runtime has no Tor daemon.
The scheduled, Tor-capable observer remains the only process that contacts the
onion service, so visitor demand cannot create bootnode traffic. Combining the
Tor read and public API in one process would require a managed container with a
Tor sidecar, which adds infrastructure without improving this data contract.

## Launch and update runbook

The data plane has two independently deployed pieces. A GitHub Actions observer
reads the Elder over Tor and force-updates the generated `network-state` branch;
the already-deployed Vercel Function reads and verifies that branch. A new valid
snapshot therefore does not require a Vercel deployment.

Before enabling publication, an operator needs the public Elder onion and its
pinned Canopy signer plus a repository secret named
`SHADE_TREE_GROVE_SIGNING_KEY`. That private Ed25519 key must match
[`network/grove-signing-public.pem`](../network/grove-signing-public.pem), which
is pinned by both the API and browser. Configure the public observer inputs as
repository variables, not secrets:

```bash
gh variable set SHADE_TREE_BOOTNODE_ONION --repo <owner/repo> --body <elder.onion>
gh variable set SHADE_TREE_DIR_SIGNER --repo <owner/repo> --body <canopy-signer-hex>
gh variable set SHADE_TREE_NETWORK --repo <owner/repo> --body sepolia
gh variable set SHADE_TREE_PROBE_ACCEPT_PRE_V4_CAPS --repo <owner/repo> --body 0
gh workflow run uptime-probe.yml --repo <owner/repo> --ref <reviewed-ref>
```

The run is complete only when both `fleet uptime probe (over Tor)` and
`publish signed aggregate` pass. The dependent `verify public Grove data plane`
job then checks the production Grove page and both signed heads, closing the gap
between a successful publisher and a failed public consumer. Verify the generated
head and production consumer independently:

```bash
gh api 'repos/<owner/repo>/contents/grove-v2.json?ref=network-state'
curl --fail --show-error \
  https://shade-tree-node.vercel.app/api/v2/data/grove/sepolia/head
```

Deploy Vercel only when the function, schema, static site, or pinned publication
key changes. The linked project root is `docs/post`; from that directory, review
the project link and deploy with `vercel --prod`, then repeat the endpoint and
Grove-page checks. Never put the Grove signing private key in Vercel: the
function verifies snapshots and does not sign them.

The three-node research Grove immediately supplies announced count and bounded
growth history. Relay-byte publication is intentionally still suppressed: the
v2 contract requires at least five reporting node identities, and unavailable
or sub-cohort input is never represented as zero. Enabling private relay
reporting on only these three nodes would not make a public byte total eligible.

Operator Prometheus endpoints are a separate, loopback-only system. The Elder
Tree, nodes, heartbeats, registrars, and Proxies do not upload those metrics to
the observer. The Grove publication path cannot read or publish them.

## API surfaces

The API separates producers from public observers in the same structural way a
relay separates submission and data-query roles. The roles do not share routes
or credentials.

### Node publisher and discovery plane

Nodes already publish signed liveness records to the Elder Tree with
`POST /announce`. The Elder serves `/directory`, `/directory/delta`,
`/gateway/<onion>`, and `/health` over its onion service. These routes are the
discovery protocol defined in
[`docs/WIRE-SPEC.md`](../docs/WIRE-SPEC.md), not the public aggregate Data
API. They can expose node-level records and must not be mirrored onto the Grove
website.

Opt-in relay telemetry uses a different signed plane: nodes send
`shade-tree-relay-report-v1` to `POST /telemetry/relay` only after their normal
announcement is accepted. It is never a field of `/announce` or `/directory`.
`GET /telemetry/aggregate` exposes only an Elder-signed delayed cohort aggregate;
there is no route for raw contributions. The full accounting and rejection rules
are in [`docs/RELAY-TELEMETRY.md`](../docs/RELAY-TELEMETRY.md).

### Aggregate publisher plane

There is no HTTP aggregate-publisher endpoint today. The implemented publisher
is the scheduled workflow: a Tor-capable observer produces one signed,
aggregate-only JSON object, then a separate minimal job force-updates the
parentless `network-state` branch with two signed snapshots and the branch-only
deployment config. The publisher receives no raw directory, operator metrics,
or Grove signing key.

A future authenticated replacement may use a route such as
`PUT /api/v1/publisher/grove/{network}/head`. That route is **proposed, not
implemented**, and is intentionally absent from the OpenAPI artifact. Before it
can ship it must enforce the current 64 KiB and exact-schema checks, verify the
publication signature, require the path and body networks to match, accept an
identical retry idempotently, and reject a timestamp rollback or conflicting
same-time body. A valid signature alone is insufficient to prevent replay of an
old public snapshot.

Any optional node statistics beyond the relay-byte protocol are a different,
future protocol. They must not be added to `/announce` or inferred from
loopback Prometheus scrapes.

### Public observer plane

The implemented public endpoint is:

```http
GET /api/v1/data/grove/sepolia/head
Accept: application/json
```

On success it returns the exact signed `shade-tree-public-grove-v1` envelope.
The handler does not wrap, filter, or re-sign it. It sets no CORS header, so the
supported browser consumer is same-origin. Server-side HTTP clients can still
read the public response.

| Status | Meaning |
| --- | --- |
| `200` | Exact verified signed envelope; cache and schema headers present |
| `304` | The request's `If-None-Match` weakly matches the current response-byte ETag |
| `400` | Query parameters are unsupported; body is only `{"error":"unsupported_query"}` |
| `503` | Upstream unavailable, oversized, malformed, wrong content type, wrong schema, or bad signature; body is only `{"error":"network_snapshot_unavailable"}` |

`/api/grove` and `/grove/network.json` remain aliases for existing clients. A
missing observation never produces a synthetic `200` with a zero count.

V2 is additive at a new endpoint and leaves that v1 contract byte-for-byte
unchanged:

```http
GET /api/v2/data/grove/sepolia/head
Accept: application/json
```

Its envelope is `shade-tree-public-grove-v2` and requires the independent
top-level `relay` object. Each fixed 6-hour and 24-hour window includes its
start/end, reporting-node coverage, and either a positive rounded byte string or
a suppression reason. `roundedBytes` is absent for `minimum-cohort` and
`unavailable`; unavailable is never encoded as zero. A second optional top-level `onchain`
object appears only after a current v4 target, runtime code, delayed finalized block, counters,
event index, and registrar attribution all verify. It keeps admission and slash classes separate
and suppresses exact values below a five-commitment contract cohort. See
[`docs/GROVE-ONCHAIN-ACTIVITY.md`](../docs/GROVE-ONCHAIN-ACTIVITY.md). The v2 handler additionally
rejects a head or relay generation time older than one hour. Its machine-readable contract is served from
`/api/v2/openapi.json` and checked into `docs/post/openapi-v2.json`.

There is no public history-query or pagination endpoint. V1 carries its bounded
history inside the signed head. An immutable snapshot store and a separately
reviewed signed response contract must exist before a future historical Data API
is advertised.

## What a pulse means

The animation has two pulse strengths:

- A quiet halo begins when the browser checks the same-origin signed snapshot.
- A full canopy pulse appears when a verified snapshot has a new `observedAt`
  value. That value is cadence-rounded and signed only after the observer fetched
  and verified the Canopy over Tor.

Neither pulse is a client, heartbeat, tunnel, destination, traffic, or node
reachability event. The Elder Tree is not in the traffic path. The animation does
not require a pulse endpoint, query feed, client identifier, or new public field.

The browser verifies the publication signature, not the raw directory. That
signature attests that the project observer completed the pinned directory and
freshness checks. Changing the observation process or rotating the publication
key still requires a reviewed site release.

If the bootnode is unreachable, its health check fails, or the directory
signature cannot be verified, the observer publishes nothing. A failed
observation is never translated into a zero count. The site keeps its last
verified snapshot and labels it stale as it ages.

## Allowed public fields

The `shade-tree-public-grove-v1` envelope contains only:

- the network label and a cadence-rounded observation time;
- the announced count;
- up to 97 aggregate count samples, enough for the 96 boundary-to-boundary
  intervals in a complete 24-hour window at the hosted cadence, but potentially
  spanning as much as 48 hours when scheduled observations are missed;
- whole-number announced node-hours derived from that count history;
- booleans that describe the verification and privacy contract.

History is treated as untrusted input every time a snapshot is built. It is
carried forward only when its publication signature verifies and its schema,
network, and cadence match the new observation. Only `at` and `announced` are
retained; malformed, future, old, or excess samples are discarded. Announced
node-hours cap each sample's validity at 30 minutes from its original
observation time before clipping to the 24-hour window, and floor the total to
whole hours. This prevents a stalled collector or an expired sample just before
the window from inventing availability. They are not a measure of successful
traffic or delivered cover.

The exact JSON shape is:

```jsonc
{
  "schema": "shade-tree-public-grove-v1",
  "network": "sepolia",
  "observedAt": "<cadence-rounded ISO-8601 timestamp>",
  "source": {
    "bootnodeReachable": true,
    "directoryVerified": true,
    "definition": "announced-within-ttl",
    "cadenceMinutes": 15
  },
  "nodes": { "announced": 0 },
  "growth": {
    "windowHours": 24,
    "announcedNodeHours": null,
    "samples": 1
  },
  "privacy": {
    "identities": false,
    "locations": false,
    "traffic": false,
    "stablePositions": false,
    "futureSharedStatsMinReportingNodes": 5
  },
  "history": [{ "at": "<ISO-8601 timestamp>", "announced": 0 }],
  "attestation": {
    "algorithm": "Ed25519",
    "keyId": "grove-2026-08",
    "signature": "<base64 signature>"
  }
}
```

The attestation signs a canonical allowlist reconstructed in fixed field order;
it does not sign arbitrary caller-provided keys or HTTP headers. The consumer
pins the publication key. This is distinct from the Elder's directory signer:
the publication signature attests that the project observer completed its
pinned-directory and freshness checks, while the browser never receives the raw
directory.

`bootnodeReachable` and `directoryVerified` are always true in a published v1
head because a failed observation publishes nothing. They are not uptime
percentages. `network` is observer configuration signed by the publication key,
not a field supplied by the directory. An old but correctly signed head remains
valid and is presented as stale; clients must use signed `observedAt`, not HTTP
cache age, for freshness.

The v1 collector projection must never publish:

- onion addresses or prefixes, gateway or signer public keys, operator
  addresses, or stable pseudonyms;
- IP addresses, ASN, region, country, coordinates, or inferred location;
- capability documents, per-node health rows, or generated positions derived
  from a node identity;
- client counts, destinations, request or tunnel counts, timing, byte totals,
  logs, errors, query counts, pulse counts, or raw Prometheus metrics; or
- the signed directory or any other raw bootnode response.

The canopy is regenerated from only the aggregate count and rounded snapshot
time. It renders exactly one non-geographic tree for each announced identity;
positions are not stable across observations. Its roots are an illustration of
announcements, not observed traffic.

## Safe derivations

Consumers may derive snapshot age, windowed minimum/maximum/mean announced
count, sample coverage, and missing intervals from the signed history. They
must filter samples to the requested time window first; the bounded history can
span more than 24 hours after collector gaps. Subtracting the first observed
count from the last is only an endpoint delta across available samples. It must
not be presented as exact windowed change when the boundary or intervening
samples are missing.

These remain count statistics. An endpoint delta is not unique churn, joins,
or departures, and node-hours are not uptime or successful traffic. V1 cannot
derive implementation language or version, Rust-versus-Node population,
operators, reachability, capacity, usage, latency, geography, admission mix, or
stake. In particular, directory `operator` and `staked` labels are not covered
by the directory's canonical signature and are never an aggregate source.

## Shared relay statistics

Nodes may now opt into the relay-byte protocol described above. It uses a
separate report rather than the persisted directory announcement. The threshold
applies only to relay usage; it does not suppress the existing exact base census,
whose small-cohort disclosure is the explicit tradeoff described above. The
enforced contract is:

- publish no aggregate below five reporting nodes; this threshold would not
  prove five independent operators;
- delay publication by at least six hours and use coarse, fixed buckets;
- retain reports in Elder memory only, with no raw query endpoint, logs,
  federation, or individual contribution view;
- heavily round any released total and label it self-reported; and
- reassess differencing attacks across repeated snapshots before release.

The Grove receives only the signed aggregate bin and contains no per-node usage
record. Local operator metrics do not enter this path. Small groves stay quiet.
The inherited `privacy.traffic: false` flag continues to mean that no traffic
path, event, or per-node record is present; the isolated `relay` section is the
only reviewed aggregate-usage exception.

## Versioning and evolution

V1 remains count-only and exact-key. Relay telemetry is carried by the reviewed
`shade-tree-public-grove-v2` envelope at the v2 endpoint under the isolated
top-level `relay` field; it was not silently appended to v1. Optional `onchain` composes beside
`relay` and is signed with it. Relay-only v2 envelopes remain valid.

The following changes also require a new contract and implementation rather
than copy changes:

- a second network or a network selector;
- immutable or paginated historical snapshots;
- publication-key rotation or a multi-key overlap window;
- any health, capability, implementation, stake, latency, or usage aggregate
  beyond the exact reviewed `relay` section; and
- an authenticated HTTP publisher or optional-statistics report endpoint.

A v2 validator should enforce internal relationships that v1 currently trusts
the publication signer to construct: the last history count equals
`nodes.announced`, `observedAt` is cadence-aligned, history respects its age
bound, and `announcedNodeHours` recomputes from the signed history. Publisher
storage should also reject timestamp regression. These hardening rules do not
change what v1 means.

## Reproduce the aggregate

With Tor running and the same discovery variables used by the uptime probe:

```bash
SHADE_TREE_GROVE_SIGNING_KEY="$(< /path/to/grove-private.pem)" \
  node scripts/grove-snapshot.mjs \
  --network sepolia \
  --previous ./grove.previous.json \
  --out ./grove.json
SHADE_TREE_GROVE_SIGNING_KEY="$(< /path/to/grove-private.pem)" \
  node scripts/grove-snapshot.mjs \
  --network sepolia \
  --previous ./grove-v2.previous.json \
  --relay 1 \
  --out ./grove-v2.json
node scripts/grove-snapshot.selftest.mjs
```

The output file is safe to inspect or publish only if the collector exits zero
and its attestation verifies against the pinned public key. The self-test
enforces the allowlist, freshness boundary, history authentication, and signing
contract, and checks that representative identity and capability fields cannot
survive serialization.
