# @shadenet/sdk

The ShadeNet JavaScript SDK, for browsers and Node. It creates and checks member identities,
stakes, sponsors, exits and withdraws, verifies a canopy, reads a local daemon's status, and in
Node opens proof-gated tunnels.

Status: research preview on Sepolia. The proof keys come from the RLN trusted setup ceremony
that Privacy & Scaling Explorations (PSE) ran in 2023, adopted and re-verified by this project,
not run by it. See the [research preview statement](../../SECURITY.md#status) for what that means.

The Rust SDK (`shadenet` crate) has the same operations and error codes. The protocol spec and
`testdata/vectors.json` are normative for both ([ADR-0010](../../docs/adr/0010-two-sdks-one-spec.md)).

## Entry points

| Import | Where | What |
|---|---|---|
| `@shadenet/sdk` | browser and Node | identities, network records, staking, exit and withdraw proofs, canopy verification, daemon status, errors |
| `@shadenet/sdk/node` | Node only | everything above, plus egress through a local proxy or in process over Tor SOCKS |

A browser can't open raw TCP or Tor circuits. Pages do identity, staking, proofs and
verification themselves, and reach the network through a local `shade-tree proxy` daemon.

## Network records

Every address, tier, bond and signer comes from a deployment record
(`network/<name>/deployment.json`), never from constants in code.

```js
import { resolveNetwork, tierFor } from "@shadenet/sdk";

const net = resolveNetwork("sepolia");     // or resolveNetwork(recordObject)
net.staked.contract;                       // "0x7899…680b"
net.staked.tiers;                          // [{ limit: 8, bondWei: 10000000000000000n }]
net.staked.defaultLimit;                   // 8
net.elder.canopySigner;                    // pinned Ed25519 key (hex)
tierFor(net, 8).bondWei;                   // 10000000000000000n
```

## Identities

An identity is `{ identitySecret, leaf, limit }` (decimal strings, `limit` a number). The leaf is
public; the secret is a bearer credential.

```js
import { createIdentity, importIdentity, serializeIdentity, downloadIdentity } from "@shadenet/sdk";

const id = await createIdentity({ limit: 8 });  // WebCrypto randomness; a tier the network offers
serializeIdentity(id);                          // the identity file bytes the Rust CLI reads
importIdentity(fileText);                       // checks the leaf matches the secret and tier
downloadIdentity(id);                           // browser: save the file; nothing is persisted
```

`createIdentity` and the Rust `shade-tree enroll` / `identity` commands produce the same
identity for the same seed.

## Staking

`createStaking({ network, provider })` works with any EIP-1193 provider: `window.ethereum` in a
page, or `jsonRpcProvider(url)` for reads. Before any signature it checks the chain, that the
contract is deployed there, that the on-chain bond equals the record's, that the call
simulates, and that the wallet holds the value plus estimated gas.

```js
import { createStaking } from "@shadenet/sdk";

const staking = createStaking({ network: "sepolia", provider: window.ethereum });

await staking.memberStatus(id.leaf);
// { state: "none" | "active" | "exiting" | "withdrawable", limit, withdrawableAt, finalized }

const sent = await staking.stake({ commitment: id.leaf, limit: 1, from: account, onSent: (hash) => {} });
if (!sent.alreadyActive) await sent.wait();       // receipt, or null if still pending after 3 min

await staking.sponsor({ commitment: memberLeaf, limit: 1, from: sponsorAccount }); // no secret needed

await staking.exit({ identity: id, from: account, artifacts });                    // starts unbonding
await staking.withdraw({ identity: id, recipient: freshAddress, from: account, artifacts });
```

`exit` and `withdraw` prove knowledge of the identity secret with Groth16 over the withdraw
circuit, so the secret never leaves the tab. In Node the committed circuit is the default. In a
browser, pass `artifacts: { wasm, zkey }` as URLs or bytes (`withdraw.wasm` is 1.6 MB,
`withdraw_final.zkey` 188 KB). snarkjs loads lazily, so a page that only stakes never downloads
it. The page's CSP needs `script-src 'wasm-unsafe-eval'` for the prover. Proving runs on the
main thread, so no `worker-src` is needed.

`finalized` turns true once the registration is in a finalized block, which is when nodes admit
the leaf. Until then egress fails with `NotFinalized`.

## Canopy

```js
import { verifyCanopy } from "@shadenet/sdk";

const { nodes, signer, issued } = verifyCanopy(directoryJson, { network: "sepolia", maxAgeSeconds: 3600 });
// nodes: [{ onion, pubkey, weight, health, caps }]
```

This runs the gateway's own verification code (`packages/node/lib/directory.mjs`): the pinned signer or an
M-of-N threshold, the onion-to-key binding of every entry, and each entry's onion-signed
capabilities. In a browser the same code runs on a `@noble` crypto backend. The shared vectors
test checks both builds byte for byte.

## Daemon status

```js
import { daemonStatus } from "@shadenet/sdk";

await daemonStatus({ daemon: "http://127.0.0.1:8118" });
// { admitted, finalized, tier, slotsLeft, slotsPerEpoch, epochResetsAt, canopy, network }
```

This reads `GET /_shadenet/status` from the local Rust proxy. Fields an older daemon doesn't
report come back as `null`.

## Egress (Node)

```js
import { proxyFetch, proxyConnect, createClient } from "@shadenet/sdk/node";

// Through a running `shade-tree proxy` (recommended)
const res = await proxyFetch("https://example.com/", { proxy: "http://127.0.0.1:8118" });
const socket = await proxyConnect("example.com:443");

// In process, over a local Tor SOCKS port
const client = createClient({ secret, limit: 1, network: "sepolia", torPort: 9050 });
await client.fetch("https://example.com/");
```

ShadeNet egresses HTTPS on port 443 only.

## Errors

Every failure is a `ShadeNetError` with a `code`. The codes match the Rust SDK:

| Code | Meaning | What to do |
|---|---|---|
| `NotAdmitted` | the leaf is in no admission set the nodes honour | stake, or have a sponsor stake it |
| `NotFinalized` | registered, but not in a finalized block yet | wait for finality (about 15 minutes on Sepolia) |
| `BudgetExhausted` | every slot this epoch is spent; `retryAfterMs` says when the next opens | retry after `retryAfterMs` |
| `PortNotAllowed` | the target is not HTTPS on 443 | use an `https://` URL on port 443 |
| `NoEligibleNode` | no node fits (admission path, artifacts, protocol) | check `daemonStatus()`; try later |
| `NodeRefused` | a node answered and refused the proof | retried automatically on another node; persistent means misconfiguration |
| `Transport` | Tor, SOCKS, TLS or the local proxy failed | check the daemon or Tor |
| `Canopy` | the directory is missing, stale or fails verification | refresh; never bypass |
| `Rpc` | the RPC failed or disagrees with the record | check the RPC; a bond mismatch means the record is out of date |
| `Wallet` | no wallet, wrong chain, rejected, or not enough funds | JS only |
| `InvalidInput` | a malformed argument | JS only |

`toShadeNetError(error)` maps an error from the lower-level JS client and keeps the original on
`cause`.

## Development

```sh
npm test --workspace @shadenet/sdk          # behaviour, vectors (Node + browser bundle), bundle sizes
node packages/sdk/scripts/pack.mjs --dry-run
```

In this repository, `src/` imports the shared wire code from `../node/lib`, so there is one JS
implementation. `scripts/pack.mjs` bundles `dist/` for publishing.
