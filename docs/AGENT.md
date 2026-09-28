# Agent guide

ShadeNet gives an agent anonymous, unlinkable egress. A local proxy proves in
zero knowledge that the agent's member has paid for access (an RLN membership
proof) and a Shade Tree node, reached as a Tor onion service, opens the
connection to the destination. The node never learns who is asking; the
destination sees the node's IP, not yours.

One binary, `shadenet`, does everything on the agent side. It embeds Tor, so you
need neither Node.js nor a system Tor daemon. (`shade-tree` is the same binary
under its old name, kept for one release.)

> [!WARNING]
> Research preview on Sepolia. The ZK artifacts are from an untrusted testnet
> setup and the staking wallet is linked to the public member leaf. Do not use
> it for real funds or sensitive work.

## Quickstart

```sh
curl -fsSL --proto '=https' --proto-redir '=https' \
  https://raw.githubusercontent.com/dmarzzz/shade-tree-node/main/scripts/install.sh | sh
shadenet init
```

`init` creates an owner-only identity, a proxy token and
`~/.config/shadenet/config.toml`, then prints what is left: staking the leaf,
waiting for finality, starting the proxy. With a funded Sepolia key:

```sh
chmod 600 funded-sepolia.key
shadenet register-member --identity ~/.config/shadenet/identity.json --key-file funded-sepolia.key
shadenet status --wait        # returns once the registration is final (about 13 minutes)
shadenet proxy                # leave running, or install it as a service (below)
shadenet run --no-proxy api.openai.com -- your-agent
```

That is the whole path. The rest of this page explains each step and the
choices an agent developer has.

## 1. Install

The installer detects your platform, downloads the matching release asset and
its checksum, verifies both the digest and the file name, and installs
`shadenet` (and the `shade-tree` alias) into `~/.local/bin` without sudo.
See the [installation guide](../crates/INSTALL.md) for targets, Windows,
attestations and source builds.

## 2. Get admitted

A member is admitted by staking its public leaf. For the bundled public Sepolia
canopy the current record admits tier 1 (one CONNECT tunnel per fixed 60-second
epoch, 40 MiB per tunnel) for a 0.1 Sepolia ETH bond, and tier 8 for 0.8.
`shadenet init` prints the values in force, read from the network record.

```sh
shadenet register-member --identity ~/.config/shadenet/identity.json --key-file funded-sepolia.key
```

The key signs locally and never reaches the RPC. The funding wallet can be any
wallet: a person can **sponsor** an agent by staking the agent's leaf from their
own wallet (`shadenet register-member <leaf> --key-file theirs.key`, or the
"Get access" page). The identity file stays with the agent either way.

Nodes accept only finalized registrations. `shadenet status` distinguishes
`not_admitted` from `not_finalized`; `shadenet status --wait` returns when the
member is `ready`.

To leave: `shadenet exit-member --identity … --key-file gas.key`, wait out the
unbonding period shown by `shadenet member-status`, then
`shadenet withdraw-member --identity … --recipient 0xFRESH --key-file gas.key`.
Both proofs are built locally; the gas wallet can be unrelated to the funder.

For an invited or custom canopy, ask its operator for the tier, the member set
or contract, and (only if not bundled) the network record, then pass
`--network path/to/deployment.json` or `--members members.json`.

`identity.json` holds the member secret. It is never sent anywhere, it is the
only way to exit and withdraw, and it is never accepted on a command line.

## 3. Run the proxy

```sh
shadenet proxy
```

The proxy listens on `127.0.0.1:8118` and requires the token `init` wrote, even
on loopback: loopback is shared by every account on the host. It keeps the
verified canopy fresh in the background, reuses the member set, and holds many
tunnels at once; proving is bounded separately so long-lived tunnels never
block new ones.

To keep it running:

```sh
shadenet init --service systemd > ~/.config/systemd/user/shadenet-proxy.service
systemctl --user daemon-reload && systemctl --user enable --now shadenet-proxy
# macOS: shadenet init --service launchd > ~/Library/LaunchAgents/xyz.shadenet.proxy.plist
```

Ask it how things stand at any time:

```sh
shadenet status --json
curl -s -H "Authorization: Bearer $(cat ~/.config/shadenet/proxy-token)" \
  http://127.0.0.1:8118/_shadenet/status
```

Both report `state`, `admitted`, `finalized`, `tier`, `slotsUsed`, `slotsLeft`,
`epochResetsInSeconds`, canopy size and age, and the last error. The endpoint is
specified in [`specs/local-api.openapi.yaml`](../specs/local-api.openapi.yaml).

## 4. Connect the agent

Pick one of three ways.

**Scoped environment (any program).** `shadenet run` checks the proxy, then
starts one command with `HTTPS_PROXY`, `HTTP_PROXY` and `WSS_PROXY` pointing at
it. Only that child sees them; the token and every `SHADENET_*`/`SHADE_TREE_*`
variable are removed from its environment.

```sh
shadenet run --no-proxy api.openai.com,api.anthropic.com -- your-agent
shadenet run --no-proxy api.openai.com -- hermes
```

**Keep the model API off ShadeNet.** Every connection a routed agent opens
spends a tunnel, including calls to its own model. List the model host in
`--no-proxy` (loopback hosts such as a local Ollama bypass automatically).

**MCP tools (the agent chooses per request).** `shadenet mcp` serves
`shadenet_fetch`, `shadenet_status` and, with `--searxng-url`,
`shadenet_search`. The agent keeps its normal network and uses ShadeNet only for
the fetches that need it.

```sh
hermes mcp add shadenet --command shadenet --args mcp
claude mcp add shadenet -- shadenet mcp
```

**Explicit proxy URL (programs that ignore proxy variables).** Point them at
`http://shadenet:<token>@127.0.0.1:8118`. The proxy speaks HTTP CONNECT only and
nodes serve port 443; TLS runs end to end to the destination.

[Adapters](ADAPTERS.md) has recipes for SearXNG, Hermes, Claude Code, Codex,
curl, Python and Rust.

## 5. When a request fails

A refused CONNECT answers with a status, an `X-ShadeNet-Error` code, a JSON body
and, when waiting helps, `Retry-After`:

| Status | Code | Meaning |
|---|---|---|
| 403 | `not_admitted`, `not_finalized` | Register, or wait for finality |
| 403 | `port_not_allowed` | Nodes serve HTTPS on 443 only |
| 429 | `budget_exhausted` | This epoch's tunnels are spent; `Retry-After` is the reset |
| 502 | `node_refused` | A node refused; the body has its reason |
| 503 | `no_eligible_node`, `canopy`, `rpc`, `transport`, `busy` | Temporary; retry after `Retry-After` |

The full table, exit codes and budget arithmetic are in
[ERRORS.md](ERRORS.md). `shadenet doctor` checks the whole local setup at once.

## Rust applications

Rust programs can use the SDK the CLI is built on:

```rust
let client = shadenet::Client::new(
    shadenet::Config::builder().identity_file("identity.json").build()?,
)?;
let page = client.fetch(shadenet::FetchRequest::get("https://example.com/")).await?;
```

See [`crates/README.md`](../crates/README.md) and
[`crates/shadenet/examples`](../crates/shadenet/examples). JavaScript
applications use the JavaScript SDK ([SDK.md](SDK.md)).

## What the node sees

- The target host, port, timing, duration and traffic volume of each tunnel.
- Not the request path or body (TLS runs to the destination), and not who you
  are: the proof shows only that some admitted member is asking, within budget.
- One proof admits one CONNECT tunnel, not every request inside it.
- Tor does not stop an observer who watches both ends from correlating timing.
- A SearXNG query that fans out to several routed engines creates several
  tunnels close together in time; nodes may link them to one another, though
  not to you.

Read the [threat model](THREAT-MODEL.md) for the exact guarantees.

## Contributor integration test

Repository contributors can run a disposable local canopy, the embedded-Arti
proxy and a real Hermes one-shot with `npm run test:hermes`; see
[`test/HERMES-E2E.md`](../test/HERMES-E2E.md).
