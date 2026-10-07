# Agent guide

ShadeNet gives an agent anonymous, unlinkable egress. A local proxy proves in
zero knowledge that the agent's member has staked for access (an RLN membership
proof) and a Shade Tree node, reached as a Tor onion service, opens the
connection to the destination. The node never learns who is asking; the
destination sees the node's IP, not yours.

One binary, `shadenet`, does everything on the agent side. It embeds Tor, so you
need neither Node.js nor a system Tor daemon. (`shade-tree` is the same binary
under its old name, kept for one release.)

> [!WARNING]
> ShadeNet is a research preview on Sepolia. The code is unaudited, the proof keys
> come from a trusted setup, and it should not be considered secure against a
> motivated actor: do not use it for real funds or sensitive traffic. See the full
> [research preview statement](../SECURITY.md#status).

## Quickstart

```sh
curl -fsSL --proto '=https' --proto-redir '=https' \
  https://raw.githubusercontent.com/dmarzzz/shade-tree-node/main/scripts/install.sh | sh
shadenet init
```

`init` creates an owner-only identity, a proxy token and
`~/.config/shadenet/config.toml`, then prints what is left: staking the identity commitment,
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

A member is admitted by staking its identity commitment; the contract derives the public leaf from it. For the bundled public Sepolia
canopy the record admits one tier, limit 8: eight proof slots per fixed 60-second
epoch, 40 MiB per slot, each slot a six-tunnel book at one node when the record
turns session tickets on. The bond in force comes from the record;
`shadenet init` prints it. The launch numbers and their reasoning are in
[ECONOMICS.md](ECONOMICS.md).

```sh
shadenet register-member --identity ~/.config/shadenet/identity.json --key-file funded-sepolia.key
```

The key signs locally and never reaches the RPC. The funding wallet can be any
wallet: a person can **sponsor** an agent by staking the agent's identity commitment from their
own wallet (`shadenet register-member <identity-commitment> --key-file theirs.key`, or the
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

**The agent's own traffic stays off ShadeNet.** Every connection a routed
agent opens spends a tunnel, including calls to its own model and the telemetry
its runtime sends. `shadenet run` keeps your `NO_PROXY`, bypasses loopback, and
bypasses the model-API and telemetry hosts agents talk to for themselves
(`anthropic.com`, `openai.com`, `googleapis.com`, `datadoghq.com`, `sentry.io`,
`statsig.com`, ...) by default; `--no-default-bypass` turns that off and
`--no-proxy` adds hosts. To allow only some destinations through ShadeNet, start
the proxy with an allow-list: `shadenet proxy --targets .wikipedia.org,api.ipify.org`
(`SHADENET_TARGETS`, or `targets` in `config.toml`). Every other host is refused
at once with `403 target_not_allowed`, spending nothing.

**MCP tools (the agent chooses per request).** `shadenet mcp` serves
`shadenet_fetch`, `shadenet_status`, `shadenet_plan` and, with `--searxng-url`,
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

## 5. Bursts, the queue and planning

The budget is per epoch (60 seconds on the public network): a tier-`K` member
proves `K` times per epoch, and with session tickets each proof opens six
tunnels at one node. An agent that fires ten fetches at once does not get nine
refusals: the proxy holds the requests whose budget is spent and opens them at
the next epoch boundary, in arrival order, for up to two epochs. A tunnel that
waited answers `200 Connection Established` with `X-ShadeNet-Queued: <seconds>`.
Only a request that would wait longer than that is refused with
`429 budget_exhausted`; its `Retry-After` and `X-ShadeNet-ETA` are the
queue-aware estimate.

Ask before a batch:

```sh
shadenet plan --url https://a.example/x --url https://b.example/y   # or --count 12
shadenet plan --count 12 --json
```

The plan says how many tunnels are available now, how many epochs the batch
needs, and a lower bound on the seconds until its last tunnel can open. The MCP tool `shadenet_plan` returns the same
object, and `shadenet status` / `GET /_shadenet/status` carry `queue` (depth,
next slot, capacity) and `plan` for one more tunnel.

While `shadenet proxy` runs, `shadenet status`, `shadenet plan` and
`shadenet fetch` talk to it instead of starting their own client: no Tor
bootstrap, no canopy fetch, and a fetch shares the proxy's session books and
queue. `--direct` forces an own client. A sequential agent (one connection at a
time, every few seconds) keeps its session book at nodes that serve
`research-v2` (60 s idle); at older nodes a book closes after 15 s idle.

Knobs, on `proxy`, `mcp` and `fetch`: `--max-wait <secs>`
(`SHADENET_QUEUE_MAX_WAIT_SECS`, `queue_max_wait_secs` in `config.toml`; default
two epochs) and `--no-queue` for the old refuse-at-once contract. `shadenet
proxy` also keeps a circuit to the two best nodes warm (`--warm N`, `--no-warm`,
`SHADENET_WARM_NODES`), so the first fetch after a quiet spell skips the onion
rendezvous, and `status` lists each node with its measured latency. A first
request still pays for proving and opening a session book (8 s or more); with
`--preopen` (`SHADENET_PREOPEN=1`, `preopen_books = true`; on main for v0.7.5, not in
the v0.7.4 release) the proxy opens a
book ahead: one at start, then again while requests came in within the last 10
minutes. Each book is one proof of the epoch's budget, and it keeps at least one
proof for a request. After a
node reports it could not reach a destination (`upstream:*`), the client tries
once on another node before giving up. ADR 0013 has the design.

## 6. When a request fails

A refused CONNECT answers with a status, an `X-ShadeNet-Error` code, an
`X-ShadeNet-Cause` sentence, and a JSON body with `cause` and `fix` (plus
`Retry-After` when waiting helps). Read the cause, not the status: every
failure the rehearsals hit was environmental and the code alone pointed the
wrong way.

| Status | Code | Read the cause for |
|---|---|---|
| 403 | `not_admitted`, `not_finalized` | which set the leaf is missing from, or how long until finality |
| 403 | `port_not_allowed` | nodes serve HTTPS on 443 only |
| 429 | `budget_exhausted` | the epoch reset and what spent the budget; with the queue on only a request that could not be held within `--max-wait` sees it, and `X-ShadeNet-ETA` is the queue-aware estimate |
| 502 | `node_refused` | the node's reason; a `wrong-group-root` ack names the node's root, leaf count and block |
| 503 | `rpc`, `canopy`, `transport`, `no_eligible_node`, `busy` | which RPC dropped history, which Elder is down, whether Tor is bootstrapped |

Before retrying, read `problems[]` from `GET /_shadenet/status` (or the
`shadenet_status` tool): the state's cause and fix, canopy sources that fell
back, the last error, and the operators' open incidents ("node-06 restarting
since 22:11Z"). When the fix says so, run `shadenet doctor`: it checks the
local setup and the canopy side (every RPC, every Elder, your identity in
other records, the state directories Tor needs) and prints the command that
clears each failing line. The full table is in [ERRORS.md](ERRORS.md).

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
- One proof buys one epoch slot, not every request inside a tunnel. With session tickets on
  (as in the live record) that slot is a book of six single-use tunnel tickets at one node; with
  tickets off it is a single CONNECT tunnel.
- Tor does not stop an observer who watches both ends from correlating timing.
- A SearXNG query that fans out to several routed engines creates several
  tunnels close together in time; nodes may link them to one another, though
  not to you.

Read the [threat model](THREAT-MODEL.md) for the exact guarantees.

## Contributor integration test

Repository contributors can run a disposable local canopy, the embedded-Arti
proxy and a real Hermes one-shot with `npm run test:hermes`; see
[`test/HERMES-E2E.md`](../test/HERMES-E2E.md).
