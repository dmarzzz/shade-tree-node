![A low-poly grove crossed by an amber network path](assets/shade-tree-readme-banner.webp)

# ShadeNet

Cover for local agents.

The canopy of Shade Trees gives agents anonymous egress when the clearnet [won’t let them
through][research-note].

[![CI][ci-badge]][ci-url]
[![real Tor E2E][e2e-badge]][e2e-url]
[![release][release-badge]][release-url]
[![MIT][license-badge]][license-url]

Add ShadeNet to an agent. Run a Shade Tree node to provide cover. The two
sides meet through a proof-gated Tor onion service, one admitted CONNECT tunnel
at a time.

*The best shade asks for proof, not a name.*

[Site][site] · [Canopy][canopy] · [Research][research-note] · [Docs](docs/README.md) ·
[Protocol](specs/protocol.md) · [Security](SECURITY.md)

ShadeNet is not affiliated with Shade Network or Shade Protocol.

> [!WARNING]
> Research preview. The code is unaudited and the included ZK artifacts are for
> development. The legacy Sepolia contract and directory records are retired
> pre-v4 history. [`network/sepolia/deployment.json`](network/sepolia/deployment.json)
> separately records the live, disposable v4 research canopy behind the public
> aggregate map; it admits invited and explicitly self-staked Sepolia testnet
> members through a stake-gated Elder. Do not rely on this preview for real
> funds or sensitive use.

## Implementation maturity

Maturity describes implementation scope and validation, not security assurance.
Both implementations are research previews under the warning above.

| Implementation | Status | Current scope | Validation |
| --- | --- | --- | --- |
| **Node.js / JavaScript** | Full-stack reference preview | Proxy and SDK, Shade Tree node, Elder Tree, membership/operator tools, and contributor harnesses. This remains the operator and in-process JavaScript path. | Full suite on Node.js 20, 22, and 24; bootstrap E2E; best-effort real-Tor E2E. |
| **Rust** | Primary agent distribution preview | The checksummed `-live` binary creates identities, runs the embedded-Arti CONNECT Proxy, launches one proxy-scoped agent, and exposes the reusable Rust egress client. It does not provide a Shade Tree node or Elder Tree. | All-target, all-feature Cargo CI; shared v4 conformance vectors; Rust-to-JavaScript proof and Proxy interop; scheduled real-Hermes/Arti E2E gate. |

Use the checksummed Rust [`-live` release](crates/INSTALL.md) for agents. It needs
neither Node.js nor a client-side Tor daemon. Use the Node.js implementation for
canopy operation, the JavaScript SDK, and repository development.

## Agent developers

Start with the complete [no-Node agent guide](docs/AGENT.md). The installer
detects the platform, downloads the matching checksum, verifies both its digest
and filename, and installs without sudo into `~/.local/bin`:

```sh
curl -q -fsSL --proto '=https' --proto-redir '=https' \
  https://raw.githubusercontent.com/dmarzzz/shade-tree-node/main/scripts/install.sh | SHADENET_VERSION=v0.7.1 sh
shadenet --version
```

Automatic mode first tries the selected release's self-contained `-live` agent
and falls back to its verifier-only binary only when that live asset is absent.
On Apple Silicon it detects Rosetta shells and still selects the native arm64
live build. v0.7.1 is the latest release; pin it with `SHADENET_VERSION=v0.7.1` if you need a
fixed build. v0.6.0 installs only the older `shade-tree` binary, without `init`, `status` or
`mcp`, and has no Intel macOS live build. The
[installer options and manual verification steps](crates/INSTALL.md) cover the rest. Checksums
provide transfer integrity; GitHub attestations provide the stronger build
provenance check.

The bundled Sepolia canopy defaults to public staked tier 1: the bond in the
current network record (`shadenet init` prints it; the [Get access][stake] page
shows it) buys one CONNECT tunnel per fixed 60-second epoch with a 40 MiB
combined payload ceiling. `init` creates an owner-only identity, a proxy token
and `config.toml`; then stake the leaf from a separately funded testnet key, or
have a sponsor stake it from the Get access page:

```bash
shadenet init
chmod 600 funded-sepolia.key
shadenet register-member --identity ~/.config/shadenet/identity.json --key-file funded-sepolia.key
shadenet status --wait        # returns once the registration is final
```

The current contract, RPC, deployment block, tiers, Elders, signer, and rate
policy are bundled defaults; `--network path/to/deployment.json` selects another
canopy. Start the self-contained Proxy and, in another terminal, route only the
agent process:

```bash
shadenet proxy
shadenet run --no-proxy api.openai.com -- your-agent
```

`shadenet run` passes proxy variables only to its child and refuses to launch
if the authenticated Proxy preflight fails. It puts the local token only in the
child's proxy URLs; the raw `SHADENET_PROXY_TOKEN` and other operator settings
are removed from the child environment. Keep the model API host on
`--no-proxy`: it has its own network path and would waste tunnels. Software that
ignores proxy variables must be configured with the authenticated URL
`http://shadenet:$SHADENET_PROXY_TOKEN@127.0.0.1:8118`. Agents that speak MCP
can use `shadenet mcp` instead (`shadenet_fetch`, `shadenet_status`,
`shadenet_search`). Rust applications
can use the [`shadenet` SDK crate](crates/README.md); JavaScript applications can import
[`ShadeTreeClient`](docs/SDK.md). The exact public semantics and their non-atomic
cross-gateway caveat are recorded in
[`docs/PUBLIC-STAKING.md`](docs/PUBLIC-STAKING.md).

The same live binary can reclaim an unslashed bond without revealing the identity secret:

```bash
shadenet exit-member --identity ~/.config/shadenet/identity.json --key-file gas.key
# Wait until `shadenet member-status` reports its withdrawal time has passed.
shadenet withdraw-member --identity ~/.config/shadenet/identity.json \
  --recipient 0xFRESH_SEPOLIA_ADDRESS --key-file gas.key
```

The gas payer may be unrelated to both the original funder and recipient. Each action is authorized
by a locally generated Groth16 proof; only the public commitment and action-bound proof reach the
chain.

## How it works

![ShadeNet reputation gate and network path](docs/post/fig/shade-tree-readme.svg)

ShadeNet is a Tor-based egress layer. The node sees Tor, not the Proxy host's
source IP. Each CONNECT tunnel carries a Groth16 RLN proof that a
rate-commitment leaf belongs to an admitted Merkle root without revealing which
leaf. The proof binds the target-and-nonce signal to a private per-epoch message
slot. The node verifies it before egress and uses epoch-scoped nullifiers to
enforce its view of the member's tunnel limit.

## Roles

| Name | What it does |
| --- | --- |
| Proxy | Runs beside the agent, reads the signed canopy directory, and opens each tunnel through Tor |
| Shade Tree node | Verifies the proof and makes the destination-facing connection |
| Elder Tree | The bootnode that caches signed announcements and serves the canopy |
| canopy | A group of Shade Tree nodes and the signed directory that lists them (formerly Grove and Canopy) |

The Elder Tree is outside the traffic path. Its pinned signer controls discovery
and can omit, reorder, or add candidates. See the [threat
model](docs/THREAT-MODEL.md) for the exact trust boundary.

[Tor exit addresses are public][tor-exit-list], and [shared traffic often trips
abuse controls][tor-captchas]. ShadeNet gates each tunnel and publishes no
egress-IP list. Destinations still see and can block a node IP.

## Run a node

A Shade Tree node is a Tor onion service with a proof-gated CONNECT gateway.
Its public IP becomes the destination-facing egress IP.

Nodes reject loopback, private, link-local, documentation, multicast, and other
special-purpose destination addresses after DNS resolution. The explicit
`SHADE_TREE_ALLOW_PRIVATE_TARGETS=1` escape hatch is for isolated local tests
only. Public deployment remains blocked on the other [deployment
gates](docs/DEPLOYMENT-PLAN.md), including replacement ZK artifacts.

For a local research node, install the current CLI and let the guided command
prepare its onion identity:

```bash
git clone https://github.com/dmarzzz/shade-tree-node.git
cd shade-tree-node
npm ci && npm link
shade-tree-node join node
```

A node can run near GPU workers, model servers, or an Ethereum validator. Give
egress a dedicated public IP when possible. Keep validator keys and
authenticated RPC endpoints out of the node. Read the [operator
guide](docs/OPERATOR.md) and current [deployment plan](docs/DEPLOYMENT-PLAN.md).

Interactive services grow one small ASCII tree when ready. Bootstrap installs
use structured JSON logs and separate loopback metrics for each role. See the
[monitoring guide](monitoring/README.md).

## Boundaries

- The destination sees the node IP and can share or block it.
- The node sees the destination hostname, port, timing, and byte counts. With
  HTTPS it does not terminate application TLS.
- Tor does not stop an observer who can watch both ends from correlating timing.
- Enrollment through staked or paid sets can create public onchain links.
- A node can refuse, delay, truncate, or misroute a valid tunnel.
- Co-located services keep separate trust boundaries only if the operator does.
- Replay and rate accounting are strongest per node. The optional cross-node
  tally is fail-open and suppresses later replays only after propagation, so
  concurrent attempts can still pass on different nodes.
- Client RLN slots are durably coordinated across Proxy, SDK, and Rust processes
  under the member's public leaf. The state contains only `{version, epoch,
  nextSlot}` and fails closed if it is corrupt, unavailable, or remains locked.
  Allocation happens before proving, so a crash or local proof failure consumes a
  slot; state resets only when the protocol epoch advances.

One proof admits one CONNECT tunnel, not one HTTP request. HTTP/2 and keep-alive
can carry many requests inside it. Both opaque traffic directions share a 40 MiB
allowance per RLN epoch slot on each node; reaching it closes the tunnel. Read the [protocol](specs/protocol.md) and
[threat model](docs/THREAT-MODEL.md) for the exact guarantees.

## Repository

| Path | Role |
| --- | --- |
| [`packages/node/`](packages/node/) | The JS node: `gateway/` (proof gate and destination tunnel), `bootnode/` (Elder Tree discovery service and operator tools), `client/` (local proxy, discovery, node rotation), `lib/` |
| [`packages/sdk/`](packages/sdk/) | `@shadenet/sdk`, the JavaScript SDK (browser and Node) |
| [`crates/`](crates/) | Rust binary, reusable egress/protocol crates, and RLN prover |
| [`contracts/`](contracts/) | Optional Sepolia membership and operator sets |
| [`network/`](network/) | Signed test-network records |
| [`specs/`](specs/) | Canonical protocol and public Data API contracts |

```bash
npm ci
npm run test:fast       # quick first check; skips slow proof/onchain suites and Foundry
npm test                # full pre-PR check
cargo test --workspace
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the test layout. Report security
issues through the private channel in [SECURITY.md](SECURITY.md). Ask questions
in [Discussions](https://github.com/dmarzzz/shade-tree-node/discussions).
ShadeNet is open source under the [MIT license](LICENSE).

[ci-badge]: https://github.com/dmarzzz/shade-tree-node/actions/workflows/ci.yml/badge.svg
[ci-url]: https://github.com/dmarzzz/shade-tree-node/actions/workflows/ci.yml
[e2e-badge]: https://github.com/dmarzzz/shade-tree-node/actions/workflows/real-tor-e2e.yml/badge.svg
[e2e-url]: https://github.com/dmarzzz/shade-tree-node/actions/workflows/real-tor-e2e.yml
[release-badge]: https://img.shields.io/github/v/release/dmarzzz/shade-tree-node
[release-url]: https://github.com/dmarzzz/shade-tree-node/releases/latest
[license-badge]: https://img.shields.io/badge/license-MIT-59624f.svg
[license-url]: LICENSE
[stake]: https://shadenet.xyz/stake/
[site]: https://shadenet.xyz
[canopy]: https://shadenet.xyz/canopy/
[research-note]: https://shadenet.xyz/research/
[tor-exit-list]: https://support.torproject.org/abuse/ban-tor/
[tor-captchas]: https://support.torproject.org/tor-browser/encountering-issues/captchas/
