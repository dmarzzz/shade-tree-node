# network/

Canonical deployment artifacts, one folder per network. Everything that identifies an
active or retired deployment — contract addresses, the fleet's discovery inputs, the gateway
onion directory, deploy metadata — lives here and is committed, so the repo records what is
deployed where without making a retired record runnable.

```
network/
  <network-name>/            e.g. sepolia, mainnet, anvil-local
    contracts.json           deployed contract addresses + chainId + deployer + tx/block
    bootnode.json            the fleet's discovery record: bootnode onion, pinned signer, admission
    directory.json           signed gateway fleet directory (onions, pubkeys, weights)
    README.md                human-readable deployment record
```

### Several Elder Trees (`deployment.json` schemaVersion 2)

A network can run several Elder Trees, each with its own canopy signer. Version 2 lists them all
in `elders[]` and keeps `elder` equal to `elders[0]`, so a reader that knows one Elder still
works:

```json
"schemaVersion": 2,
"elder":  { "onion": "a4xt…onion", "canopySigner": "e0ce…", "admission": "stake", "gatewayRegistry": "0x94EC…" },
"elders": [ { "onion": "a4xt…onion", "canopySigner": "e0ce…", … },
            { "onion": "k54v…onion", "canopySigner": "3d5b…", … } ]
```

Clients fetch every Elder's canopy directory, verify each against that Elder's own signer, and
use the union of the verified node lists; an unreachable Elder only removes its own directory
(its last-known-good copy is still used). The Rust SDK does this in `shadenet::Client`; the
JavaScript SDK exposes `network.elders`, `verifyCanopy` (tries each Elder's signer, or pin one with
`{ elder }`) and `mergeCanopies`. Version 1 records (one `elder`) remain valid.

Nodes announce to every Elder too (ADR 0012): `SHADE_TREE_NETWORK` (and the bootstrap preset)
turn `elders[]` into `SHADE_TREE_BOOTNODE_ONIONS`, the heartbeat POSTs one signed announce per
Elder each interval, and the JS client (`packages/node/client`, so the Lab runner and
`@shadenet/sdk/node`) tries the Elders in record order and takes the first directory that
verifies. With the primary Elder down, the second one keeps a fresh canopy instead of ageing out
after its TTL.

### RPC failover (`admission.roots.staked.rpcUrls`)

The staked root names its execution RPC twice: `rpcUrl` (one endpoint, kept for readers that
know one) and `rpcUrls` (the same endpoint first, then fallbacks, at most five). Every reader
takes the list: `SHADE_TREE_NETWORK` fills `SHADE_TREE_RPC_URL` with it comma-separated (the node,
the heartbeat and the JS client already try such a list in order), the Rust client replays the
member set from the first endpoint that returns complete history, `@shadenet/sdk` moves to the
next endpoint on a transport failure, and `deploy/v4/preflight.mjs` checks each one on chain.
Put a full-history endpoint first: during the M7 rehearsal a pooled public RPC answered
`eth_getLogs`, a deploy receipt and archive reads with nothing, and every client that trusted
it built a wrong member tree. `scripts/deploy-contracts.mjs` writes the list from
`SHADE_TREE_RPC_URL` / `--rpc-url` (comma-separated; default ethpandaops then publicnode).

Local anvil deploys write `contracts/deployed.local.json` (gitignored) instead — only
real networks get a committed `network/<name>/` record.

Records carry the **public discovery handles only**: onions, pubkeys, contract addresses.
Never an IP, never a key. The validator (`packages/node/lib/network-record.mjs`) rejects a record that
puts an IP into a discovery field.

## Pointing a component at a network: `SHADE_TREE_NETWORK`

`SHADE_TREE_NETWORK=<name>` (or `shade-tree --network <name>`) makes every component read the records
under `network/<name>/` as **defaults** for the env vars it already consumes
(`packages/node/lib/network-record.mjs`, `applyNetworkEnv`). Explicit env / flags always win; the record
only fills what is unset:

| record | fills (when the value is non-null) |
|---|---|
| `bootnode.json` `onion` | `SHADE_TREE_BOOTNODE_ONION` (client discovery, heartbeat target, uptime probe) |
| `bootnode.json` `signer` | `SHADE_TREE_DIR_SIGNER` (array → comma-joined rotation allowlist) |
| `bootnode.json` `admission` | `SHADE_TREE_BOOTNODE_ADMISSION` |
| `bootnode.json` `staticDirectory` | `SHADE_TREE_DIRECTORY` + `SHADE_TREE_DIR_SIGNER` — **only** when the record has no live bootnode onion (cold path) |
| `contracts.json` `contracts.gatewayRegistry` | `SHADE_TREE_GATEWAY_REGISTRY` (bootnode stake admission, `shade-tree register-gateway`, client stake re-verification) |
| `contracts.json` `contracts.stakedReputationSet` | `SHADE_TREE_GROUP_CONTRACT` (gateway on-chain root + slashing target) |
| `contracts.json` `rpcUrl` | `SHADE_TREE_RPC_URL` |

Resolution order everywhere: **explicit env/flag > `network/<name>/` record > `contracts/deployed.local.json` (deployer-box cache) > dev default.**
`shade-tree` fails fast (exit 1) on an unknown network name or an invalid record; the library
paths (`packages/node/lib/gateway-registry.mjs`, `group/register-gateway.mjs`) treat an unresolvable
record as "no default". Wired today: `packages/node/bin/shade-tree.mjs` (every command), `packages/node/client/selection.mjs`
(so `node packages/node/client/shim.mjs` and the SDK honour it), `packages/node/bootnode/heartbeat.mjs`,
`packages/node/lib/gateway-registry.mjs`, `group/register-gateway.mjs`, `scripts/uptime-probe.mjs`.

```bash
# A current, non-retired record can configure the whole stack by name:
read -s SHADE_TREE_SECRET
read -r SHADE_TREE_LIMIT
SHADE_TREE_SECRET="$SHADE_TREE_SECRET" SHADE_TREE_LIMIT="$SHADE_TREE_LIMIT" \
  SHADE_TREE_NETWORK=<current-v4-network> shade-tree proxy
unset SHADE_TREE_SECRET
unset SHADE_TREE_LIMIT
SHADE_TREE_NETWORK=<current-v4-network> shade-tree heartbeat
read -s SHADE_TREE_REGISTER_KEY
SHADE_TREE_REGISTER_KEY="$SHADE_TREE_REGISTER_KEY" \
  SHADE_TREE_NETWORK=<current-v4-network> shade-tree register-gateway
unset SHADE_TREE_REGISTER_KEY

# With no current record, pin values supplied by the v4 fleet operator instead:
read -s SHADE_TREE_SECRET
SHADE_TREE_SECRET="$SHADE_TREE_SECRET" shade-tree proxy --limit <operator-tier> \
  --bootnode <v4-bootnode.onion> --dir-signer <v4-signer-hex>
unset SHADE_TREE_SECRET
```

The `unset` after a Proxy or heartbeat runs when that long-running process stops. The hidden reads
keep bearer and operator keys out of argv and shell history.

The legacy `sepolia` runtime preset (`bootnode.json`, the full `contracts.json` bundle, and signed
directories) is retired pre-v4 history and cannot be used in place of `<current-v4-network>`.
The separate `network/sepolia/deployment.json` is current v4 research-deployment metadata. It
publishes a runnable, explicit Sepolia staking profile while reusing only the compatible staking
set and gateway registry from `contracts.json` and naming the active archival RPC and deploy block
beside them; it does not reactivate
the legacy preset or invited credentials.

## `contracts.json` schema

```jsonc
{
  "network": "sepolia",                 // == the folder name ([a-z0-9-])
  "chainId": 11155111,                  // number
  "status": "live",                     // live | pending | retired
  "release": "rln-v3",                  // free-form
  "deployer": "0x…",                    // address | null
  "rpcUrl": "https://…",                // public JSON-RPC used as SHADE_TREE_RPC_URL default
  "params": { … },                      // free-form: bond, unbonding, …
  "contracts": {                        // slot -> address | null (null = NOT deployed yet)
    "stakedReputationSet": "0x…",
    "hasher": "0x…",
    "withdrawVerifier": "0x…",
    "gatewayRegistry": null,            // present-null until the GatewayRegistry broadcast lands
    "paidAccessSet": "0x…"              // T-FEAT-7 paid-access membership tree (docs/PAYMENTS.md); optional
  },
  "deployTxs":    { "<slot>": "0x<64 hex>" | null, … },
  "deployBlock":  11279842,             // block of the original deploy batch (number)
  "deployBlocks": { "<slot>": 12345678, … },   // per-contract, for slots deployed later
  "circuit": { … }, "note": "…", "liveIntegration": { … }   // documentation, not validated
}
```

Rules enforced by `validateContractsRecord` (`packages/node/lib/network-record.mjs`): every `contracts.*`
value is a 0x 20-byte address **or `null`**; a missing slot means the same as null; a
`deployTxs`/`deployBlocks` entry for a slot that is not an address is a contradiction and
rejected; blocks are JSON numbers. A loader that needs an address calls
`contractAddress(record, "gatewayRegistry")` and gets `null` for a pending slot — never a
placeholder string.

`SHADE_TREE_NETWORK=<name>` resolves `contracts.stakedReputationSet` → `SHADE_TREE_GROUP_CONTRACT`,
`contracts.paidAccessSet` → `SHADE_TREE_PAID_ACCESS_CONTRACT` (the gateway unions both roots),
`contracts.gatewayRegistry` → `SHADE_TREE_GATEWAY_REGISTRY` and `rpcUrl` → `SHADE_TREE_RPC_URL`; a null /
missing slot supplies no default. A record with `status: retired` supplies no runtime defaults;
selecting a wholly retired network by name fails clearly instead of falling through to a local
gateway. Its addresses and deploy blocks remain available as historical provenance. Free-form documentation keys (`gatewayRegistry`,
`paidAccessSet`, `liveIntegration`, …) are not validated.

### Recording a deploy in one command

`forge script … --broadcast` leaves the addresses in `contracts/deployed.local.json` and the
tx hashes + receipts in `broadcast/<Script>.s.sol/<chainId>/run-latest.json` (both
gitignored). Lift them into the committed record with:

```bash
NETWORK_NAME=your-v4-network
node scripts/record-deploy.mjs --network "$NETWORK_NAME" \
  --from-broadcast broadcast/DeployRegistry.s.sol/11155111/run-latest.json
# or:  shade-tree record-deploy --network "$NETWORK_NAME" --from-broadcast …
# manual: --contract gatewayRegistry --address 0x… --tx 0x… --block N
# a new slot next to a live release (T-FEAT-7): --contract paidAccessSet --from-broadcast broadcast/DeployPaidAccess.s.sol/<chainId>/run-latest.json
# flags:  --all (every known CREATE in the bundle) --status live --force --dry-run
```

It refuses a chain-id mismatch, refuses to overwrite a slot that already holds a different
address without `--force` (contracts are immutable), validates the merged record, and writes
atomically. It never broadcasts anything.

## `bootnode.json` schema

```jsonc
{
  "network": "sepolia",
  "status": "pending",                  // live | pending | retired
  "onion": null,                        // bootnode v3 .onion  | null   -> SHADE_TREE_BOOTNODE_ONION
  "signer": null,                       // 64-hex ed25519 | [hex, …] | null -> SHADE_TREE_DIR_SIGNER
  "admission": "open",                  // open | stake  (what the bootnode unit enforces)
  "staticDirectory": {                  // optional cold-path fallback (docs/INCIDENT.md #1)
    "path": "directory.json",           //   relative to network/<name>/, no `..`
    "signer": "189f…1321"               //   the STATIC directory's pinned signer
  },
  "deployedRef": null,                  // optional: git ref / release the fleet runs
  "updated": "2026-08-17",              // optional
  "note": "…"                           // optional; may not contain an IP
}
```

Rules (`validateBootnodeRecord`): `status: live` **requires** non-null `onion` and `signer`
(a live record without discovery inputs is a lie); `pending` tolerates nulls and is the
committed template state before T-DEPLOY-1 (GO-LIVE row 7.1); `retired` supplies no defaults.
`signer` as an array is the signer-rotation overlap allowlist (`packages/node/client/selection.mjs`) and is
joined with `,` into `SHADE_TREE_DIR_SIGNER`. `gatewayRegistry` may appear here as address|null
for readability, but `contracts.json` is its canonical home.

Onions and pubkeys are the discovery handle and belong here; **IPs never do**.

## Static fallback

The client points at a network with `SHADE_TREE_NETWORK=<name>` (above), or by hand with
`SHADE_TREE_DIRECTORY=network/<name>/directory.json` + `SHADE_TREE_DIR_SIGNER` and (for on-chain
slashing) `SHADE_TREE_GROUP_CONTRACT` + `SHADE_TREE_RPC_URL` from that network's `contracts.json`.
