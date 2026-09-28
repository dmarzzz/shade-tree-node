# Adapters: routing a tool or an agent through the canopy

This closes the loop back to the project's origin use case. A SearXNG instance run over a
raw Tor exit was blocked by many destinations (the README ["Not done, and why it
matters"](OVERVIEW.md#not-done-and-why-it-matters) and
[`exit-blocking-benchmark.md`](exit-blocking-benchmark.md)). An adapter points that same
SearXNG instance, an AI agent, or another tool at a proof-gated node IP.

Public docs call the local protocol client the **Proxy**, the egress gateway a **Shade Tree
node**, and the discovery bootnode the **Elder Tree**. Source paths, environment variables,
and flags retain `client`, `gateway`, and `bootnode` where compatibility matters.

## Install for an agent

Install the current CLI directly from GitHub:

```bash
npm install --global git+https://github.com/dmarzzz/shade-tree-node.git
```

This is not an npm registry release. You still need Tor and a current access
profile from a v4 canopy operator. Start with the short [agent guide](AGENT.md).
Use a repository checkout for SDK development or the bundled Tor helper.

Stand up a canopy first ([`QUICKSTART.md`](QUICKSTART.md)): an Elder Tree, at least one Shade
Tree node, and a local Tor SOCKS port. Then pick a style.

| You have | Use | Why |
|---|---|---|
| A tool that honors an HTTP proxy (SearXNG, `curl`, most HTTP libs) | **Proxy style**: run `shade-tree proxy`, point the tool at `http://127.0.0.1:8888` | No code change; the Proxy proves and selects a node for every connection |
| Your own code doing many requests (an agent) | **Library style**: call `ShadeTreeClient` directly | One proof per tunnel, no extra Proxy process, direct access to the node selected |

Both mint a fresh RLN proof and select a node per CONNECT tunnel. Selection can return the
same node again. Both have the protocol boundaries described below. The Proxy is the library
behind an HTTP-CONNECT front end (`client/shim.mjs` over
`client/shade-tree-client.mjs`).

The live Rust binary offers the same loopback CONNECT boundary on port `8118`
with Arti embedded, so a client-side Tor daemon is unnecessary. It is the
self-contained sidecar choice for Rust services and agents in any language; see
[Clients, Option C](CLIENTS.md#option-c-self-contained-rust-proxy-embedded-arti).
The in-process Rust library remains roadmap work.

## Shared env

Both styles read the same environment (each maps 1:1 to a `shade-tree proxy` flag; see
[`CONFIG.md`](CONFIG.md)):

| Env | Flag | What |
|---|---|---|
| `SHADE_TREE_SECRET` | `--secret` | An enrolled member secret (`shade-tree enroll`). Required. |
| `SHADE_TREE_BOOTNODE_ONION` | `--bootnode` | The Elder Tree's Tor v3 onion. The Proxy pulls its signed canopy directory over Tor and selects a node per tunnel. |
| `SHADE_TREE_DIR_SIGNER` | `--dir-signer` | The Elder Tree's pinned signer pubkey. The Canopy is rejected unless it verifies against this. |
| `SHADE_TREE_TOR_PORT` | `--tor-port` | Local Tor SOCKS port. Optional; default `9250` (the bundled `scripts/start-tor-client.sh` runs `9260`). |

Static-file discovery (`SHADE_TREE_DIRECTORY` + `SHADE_TREE_DIR_SIGNER`, no Elder Tree) also works; see
[`CONFIG.md`](CONFIG.md). `SHADE_TREE_BOOTNODE_ONION` wins if both are set.

## Style 1: HTTP proxy (SearXNG, curl, any proxy-honoring tool)

Run the Proxy. It binds `127.0.0.1:8888` (override with `SHADE_TREE_SHIM_PORT`):

```bash
read -s SHADE_TREE_SECRET && export SHADE_TREE_SECRET
```

Paste the member secret at the hidden prompt, then run:

```bash
shade-tree proxy \
  --bootnode <elder-onion> \
  --dir-signer <elder-signer-pubkey>
```

Then point any tool at it. Generic form:

```bash
http_proxy=http://127.0.0.1:8888 https_proxy=http://127.0.0.1:8888 \
  curl https://api.ipify.org?format=json
# or explicitly:
curl -x http://127.0.0.1:8888 https://api.ipify.org?format=json
```

The IP returned is the node's, not the Proxy host's.

### Important: HTTPS / `:443` only

The Proxy implements HTTP **CONNECT** only, and a node egresses **TCP CONNECT to `:443`
only** (TLS stays end-to-end to the target; the node relays ciphertext). So every target
you route through it must be reachable over HTTPS. Plain-`http://` egress is not tunneled.
For SearXNG this is fine (its default engines use HTTPS), but scope or disable any
HTTP-only engine.

### SearXNG `settings.yml`

SearXNG routes engine fetches through the proxies under `outgoing.proxies` (httpx-style).
The value is the Proxy:

```yaml
# searxng settings.yml
outgoing:
  request_timeout: 6.0        # onion + proof adds latency; give engines room
  proxies:
    all://:
      - http://127.0.0.1:8888
```

Config-key confidence:

- **Confident** (verified against SearXNG's official
  [`settings_outgoing`](https://docs.searxng.org/admin/settings/settings_outgoing.html) docs):
  the top-level key is `outgoing.proxies`; values are httpx mount patterns, and the documented
  example uses the `all://` key with a **list** of proxy URLs, with plain `http://host:port`
  proxy URLs accepted. An HTTP-CONNECT Proxy like this one is a valid value.
- **Verify against your SearXNG version**: whether your build also accepts the shorthand
  `http:` / `https:` keys (older/alternate form) instead of the httpx `all://` /
  `https://` mount keys. If you want to scope to HTTPS only (matching the `:443`-only node),
  use `https://:` in place of `all://:`; confirm your version parses it before relying on it.

If SearXNG runs in Docker, `127.0.0.1` is the container's own loopback, not the host; run
the Proxy inside the same network namespace or point the tool at the Proxy's reachable
address. See [`docker/README.md`](../docker/README.md) for the bundled compose wiring.

## Style 2: library (`ShadeTreeClient`, for an agent)

For your own code doing many requests, skip the Proxy process and call the client library directly. It is
dependency-free beyond the repo itself:

```js
import { ShadeTreeClient, cleanUp } from "./client/shade-tree-client.mjs";

const shadeTree = new ShadeTreeClient();                        // reads the shared env above
const res = await shadeTree.fetch("https://api.ipify.org?format=json");
console.log(JSON.parse(res.body).ip, "via", res.gateway.onion);   // node onion; field keeps its wire name
cleanUp();                                           // stop snarkjs workers on exit
```

`shadeTree.connect("host:443")` is the lower-level form: a raw duplex tunnel to the target for
your own TLS/protocol. `shadeTree.fetch()` is HTTPS-only for the same `:443` reason as above.

The integration example is [`examples/agent-egress.mjs`](../examples/agent-egress.mjs). It
parses without a canopy, but a fetch requires current v4 admission and discovery values from
an operator. The retired Sepolia records are not a connection profile.

## Privacy note

Whichever style: **each CONNECT tunnel runs selection and carries a fresh RLN proof.**
Selection may choose the same node again. The proof has a per-tunnel nullifier (reusing
one nullifier on a second distinct signal is a provable over-spend), so proof transcripts do
not expose a stable member identifier. The onion transport keeps the Proxy's source IP out of
the node application connection, and TLS keeps application content encrypted end to end. The
serving node still sees the destination, timing, lifetime, and traffic volume, which may
correlate tunnels.
