# Fleet status page

A tiny, read-only web view of fleet health, read from a bootnode's `/health` + `/directory`.
It shows whether the bootnode is up, how many gateways are live, each gateway's weight/health,
and whether the signed directory verifies against a **pinned** signer.

It is a *cache viewer*, not a trust root: the signature check is the real
[`packages/node/lib/directory.mjs`](../packages/node/lib/directory.mjs) `verifyDirectory` path, so a lying bootnode shows up
as `signerOk: false`, not as a forged fleet.

## Run it

Point it at a bootnode and pin the directory signer (the pubkey the bootnode prints on boot).

Local / dev — a plain-http bootnode (no Tor):

```bash
SHADE_TREE_BOOTNODE_URL=http://127.0.0.1:8877 \
SHADE_TREE_DIR_SIGNER=<bootnode-signer-pubkey-hex> \
node web/status-server.mjs
# -> http://127.0.0.1:8090
```

Production — the bootnode's v3 onion, reached over the local Tor SOCKS proxy:

```bash
SHADE_TREE_BOOTNODE_ONION=<56-char>.onion \
SHADE_TREE_DIR_SIGNER=<bootnode-signer-pubkey-hex> \
SHADE_TREE_TOR_PORT=9250 \
node web/status-server.mjs
```

### Config (all `SHADE_TREE_*`)

| Var                   | Meaning                                                    | Default       |
| --------------------- | ---------------------------------------------------------- | ------------- |
| `SHADE_TREE_BOOTNODE_ONION` | bootnode v3 onion, reached over Tor (`packages/node/bootnode/fetch.mjs`) | —             |
| `SHADE_TREE_BOOTNODE_URL`   | *or* a plain-http bootnode base URL (local/dev)            | —             |
| `SHADE_TREE_DIR_SIGNER`     | pinned directory-signer pubkey (hex)                       | — (unverified)|
| `SHADE_TREE_STATUS_PORT`    | loopback port for this page                                | `8090`        |
| `SHADE_TREE_TOR_PORT`       | local Tor SOCKS port (onion path)                          | `9250`        |
| `SHADE_TREE_TOR_HOST`       | local Tor SOCKS host                                       | `127.0.0.1`   |

Set exactly one of `SHADE_TREE_BOOTNODE_URL` (dev) or `SHADE_TREE_BOOTNODE_ONION` (Tor). Without
`SHADE_TREE_DIR_SIGNER` the page still runs but reports `signerOk: false` — the directory is shown
unverified.

## Endpoints

- `GET /` — the HTML status page (self-contained, no external assets/CDN; polls the API every ~15s).
  Renders a fleet-size **sparkline** + a bootnode-**reachability strip** from `/api/history`.
- `GET /api/status` — the JSON summary:

  ```jsonc
  {
    "bootnodeReachable": true,
    "fleetSize": 3,
    "gateways": [{ "onionShort": "abcd…16 chars", "weight": 100, "health": "up", "staked": true }],
    "signerOk": true,
    "admission": "stake",
    "signerPinned": "…",
    "lastFetch": "2026-08-13T…Z",
    "history": { "count": 12, "cap": 120, "oldest": "…Z", "newest": "…Z", "reachableCount": 12 }
  }
  ```

- `GET /api/history` — a bounded, in-memory **trend buffer** (a ring of the last `cap` samples,
  default **120** ≈ 30 min at the 15s poll). One sample is appended each time `/api/status` is
  computed; the buffer never grows past `cap` and is never persisted:

  ```jsonc
  {
    "cap": 120,
    "count": 12,
    "samples": [{ "ts": "2026-08-13T…Z", "bootnodeReachable": true, "signerOk": true, "fleetSize": 3 }]
  }
  ```

  History is **counts + booleans only** — no gateway, onion, or operator field ever enters it, so
  the trend endpoint is exactly as privacy-scrubbed as `/api/status`.

## Privacy

A status board is a public surface; the fleet is deliberately **non-enumerable** (v3 onions live
only in signed announces, never on chain). So this page never emits an operator identity or a full
`.onion` address:

- every onion is **truncated** to its first 16 characters (`onionShort`), enough to eyeball-distinguish
  two gateways, far short of the 56 chars that would make the fleet enumerable;
- operator identity collapses to a single `staked: true/false` badge — the operator **address is
  dropped** before it leaves the process. Entries with no operator field carry no staked badge.

## Security posture

- **Read-only, no auth.** Everything served is already-public, privacy-scrubbed data.
- **Loopback by default.** It binds `127.0.0.1`, so it is off the network until an operator
  chooses to front it (e.g. behind an authenticated reverse proxy or its own onion).
- **No new dependencies.** `node:http` plus the existing `packages/node/bootnode/fetch.mjs` (Tor) and
  `packages/node/lib/directory.mjs` (verify).

## Test

```bash
node web/status.selftest.mjs          # /api/status + privacy scrub
node web/status-history.selftest.mjs  # /api/history trend buffer: bounded + scrubbed
```

`status.selftest.mjs` stands up a mock bootnode (real `/health` + `signDirectory`'d `/directory`),
runs the status server against it, and asserts the right `fleetSize`, `signerOk` true for the pinned
signer and false for a wrong one, and that no full onion or operator address appears in the output.

`status-history.selftest.mjs` drives `/api/status` past the ring cap and asserts the trend buffer
stays bounded, that each sample is `{ ts, bootnodeReachable, signerOk, fleetSize }` (counts +
booleans only), and that no full onion or operator address leaks into `/api/history`.

Both are auto-discovered by `node scripts/test-all.mjs`.
