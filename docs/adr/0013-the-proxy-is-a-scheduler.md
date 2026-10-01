# ADR 0013: The proxy is a scheduler, not a gate

- Status: Accepted
- Date: 2026-10-01
- Task: agent-side pain point 2 of the launch review ("the budget model fights how agents
  actually fetch"); Dan's direction after launch: ergonomics first, no free seats

## Context

A tier-`K` member proves at most `K` times per epoch (60 s on the public network). With
session tickets (ADR 0011) one proof opens a book of six tunnels at one node. The local proxy
answered a spent budget with `429 budget_exhausted` and a `Retry-After`, and the MCP tools
returned the same code. That is correct and honest, and it is the wrong shape for the caller:
an agent fires ten fetches in a burst, the proxy refuses nine, the agent reads `Retry-After`
(or does not), sleeps, retries, and the operator sees a tool that "fails all the time". The
agent had no way to ask what a batch would cost before running it, and no way to know which
tier would have fit it.

Two smaller frictions sat next to that one. Concurrent tunnels to the same node each opened
their own session book, spending a proof each instead of sharing one. And the first tunnel
after a quiet spell paid the whole onion rendezvous, which the rehearsals measured in tens of
seconds right after a node restart; a node that could not reach a destination (`upstream:*`)
ended the request even when another node would have served it.

## Decision

1. **A spent budget queues the request.** `Client::connect` (and so `shadenet proxy`,
   `shadenet mcp` and `shadenet fetch`) holds a request whose epoch budget is spent until the
   next boundary and tries again, staggered by arrival so slots go out in order. The request is
   refused with `429 budget_exhausted` only when the wait would exceed the queue's maximum, two
   epochs by default (`--max-wait`, `SHADENET_QUEUE_MAX_WAIT_SECS`, `queue_max_wait_secs`). The
   refusal's `Retry-After` and the new `X-ShadeNet-ETA` header carry the queue-aware ETA: the
   boundary plus one epoch per full capacity of requests ahead. A tunnel that waited answers
   `200 Connection Established` with `X-ShadeNet-Queued: <seconds>`. `--no-queue` (or a maximum
   of 0) restores the old behaviour exactly, which the proxy concurrency harness still checks.
   SDK callers opt in through `Config::queue_max_wait`; the SDK default is unchanged.
2. **Agents can plan.** `shadenet plan --url … | --count N` and the MCP tool `shadenet_plan`
   compute, from the record's rate policy, the member's tier, the slots used this epoch, the
   tickets open in live books and the queue depth: how many tunnels are available now, how many
   epochs the batch needs, a lower bound on the seconds until its last tunnel can open, and the
   tier at which it would fit in one epoch. The arithmetic is `shadenet::scheduler`, pure and
   tested; `/_shadenet/status` and `shadenet status` carry the same `queue` and `plan` objects.
3. **One book per node at a time.** Session initialization is serialized per client: a second
   tunnel to a node whose book is being opened waits for it and spends a ticket instead of
   proving its own book. The in-call fallback to one proof per tunnel on `session-unsupported`
   (#226) is unchanged.
4. **Warm circuits and one retry elsewhere.** `shadenet proxy` keeps a stream to the two best
   nodes fresh every minute (`--warm N`, `--no-warm`, `SHADENET_WARM_NODES`, `warm_nodes`); the
   dials measure latency, which `status` reports per node with the canopy's health word and the
   client's own failure count, best node first. After a node refuses a tunnel for an
   `upstream:*` reason the client tries once more on another node, spending a new ticket or
   slot, and never replays a proof (a replayed envelope is a double-spend to the fleet tally).

5. **The agent's own traffic stays off ShadeNet** (dogfood #230). `shadenet run` keeps the
   caller's `NO_PROXY`, and adds a default bypass list of model-API and telemetry hosts
   (`anthropic.com`, `openai.com`, `datadoghq.com`, `sentry.io`, `statsig.com`, ...;
   `--no-default-bypass` turns it off). For an allow-list, `shadenet proxy --targets
   .wikipedia.org,api.ipify.org` (`SHADENET_TARGETS`, `targets` in `config.toml`) refuses every
   other host with `403 target_not_allowed` before anything is spent.
6. **A book survives a sequential agent** (dogfood #231). `research-v1` closes a book after
   15 s idle, so a curl-style agent that fetches every 20 s paid a proof per fetch and its tier-1
   budget bought one tunnel per minute, which is exactly what the H2 ticket decision was meant to
   fix. `research-v2` is the same class with a 60 s idle timeout. Nodes advertise every class
   they serve; clients take the best one they know and fall back to `research-v1` at nodes that
   do not advertise v2. A node must be rolled to serve it; until then nothing changes.
7. **A refusal before egress does not burn the slot** (dogfood #232, #233). A plain tunnel
   envelope binds no node, and a node that refuses the root (`wrong-group-root`, `gate:*`) has
   neither spent nor published anything, so the transport sends the identical bytes to the next
   candidate instead of failing. The fleet tally only hears a nullifier after a successful egress,
   so this is a retry, not a replay. A session initialization binds its node and cannot move;
   there the one retry elsewhere (4) applies. An onion dial that fails is tried once more at the
   same node before the transport moves on: a hidden-service rendezvous often fails once.
8. **One-shots use the running proxy** (dogfood #236). `shadenet status`, `plan` and `fetch`
   look for a proxy on the configured listen address and, when one answers with the local
   token, read its status, ask it for the plan (`GET /_shadenet/plan?count=N`) or fetch through
   its CONNECT path. No Tor bootstrap, no canopy fetch, and the fetch shares the proxy's books
   and queue. `--direct` starts an own client as before.

## Consequences

- An agent that fires a burst sees its fetches complete in arrival order across epochs instead
  of a wall of 429s. The ETA it would have had to compute is now a header and a tool.
- Latency goes up for the requests that would have been refused: they wait instead. The cap is
  explicit and short (two epochs), and callers that want the old contract have `--no-queue`.
- The retry on another node can spend a second slot on a destination that is simply down. It is
  bounded to one and skipped when nothing is available, and `retry_other_node` turns it off.
- Warm-up dials are visible to nodes as short connections with no envelope, once a minute from
  each proxy. They carry no proof and spend nothing.
- Wire strings and proofs are untouched. `research-v2` adds a class id to the session signal
  and a node-side table entry; the JS SDK keeps the old contract until it gets the same
  scheduler.
- The default bypass list names vendors. It is a list of hosts an agent runtime talks to for
  itself, not an endorsement, and an operator who wants those hosts on ShadeNet turns it off.
