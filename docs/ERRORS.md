# ShadeNet error codes

Every failure in the Rust SDK, the `shadenet` CLI, the local proxy and the MCP
server carries one stable code. The same code appears as:

- the `X-ShadeNet-Error` header and `error.code` in the JSON body of a refused
  `CONNECT` (with `Retry-After` when waiting helps, and `X-ShadeNet-ETA` on a
  `429`: the seconds until a slot is expected, requests queued ahead included);
- `error.code` in `shadenet … --json` output and in MCP tool results
  (`isError: true`);
- `shadenet::Error::code()` in Rust.

Every refusal also names its **cause** and **fix**: the `X-ShadeNet-Cause` header on a refused
`CONNECT`, and `error.cause` / `error.fix` in every JSON body. The cause is derived from the
error's content, so `rpc` says which endpoint dropped history and `node_refused` with
`wrong-group-root` says how many leaves the node has and at what block. `shadenet doctor`
runs the same diagnosis for the whole setup, canopy side included (see below).

| Code | HTTP | Exit | What happened | Typical cause | Fix |
|---|---|---|---|---|---|
| `not_admitted` | 403 | 2 | Your leaf is not in the set the canopy's nodes accept | Never staked here, or staked in another network's set (an identity from the staging page on the production record) | `shadenet doctor` names the record that has it; else `shadenet register-member --identity identity.json --key-file <funded key>`, or hand the commitment to a sponsor |
| `not_finalized` | 403 | 2 | Registered, but the block is not final yet; nodes read the finalized set | Sepolia finality (about 13 minutes) plus one node root refresh (60 s) | `shadenet status --wait` returns when final |
| `port_not_allowed` | 403 | 2 | No node egresses to that port. Nodes serve HTTPS on 443 | An http:// URL or a non-443 port | Use https on port 443 |
| `budget_exhausted` | 429 | 4 | The budget queue could not hold the request within its maximum wait (two epochs by default, ADR 0013), or one tunnel hit its payload cap. A request that fits is held, not refused, and opens with `X-ShadeNet-Queued` | A burst of fetches to new hosts, or a model API routed through the proxy | Wait `Retry-After` / `X-ShadeNet-ETA` seconds (queue-aware), reuse open connections, or run `shadenet plan` before the next batch |
| `no_eligible_node` | 503 | 2 | No node fits your admission path, the network's rate policy or a capability you asked for | The nodes advertise (signed `caps.sets`) that they read a different admission set than this record, so every proof would be `wrong-group-root`; an artifact, rate-policy or admission mismatch; a `--region`/`--proto` filter | `shadenet doctor` (the `admission set` line names the set the nodes read); run against that record or stake there; drop the filters |
| `canopy` | 503 | 2 | The signed canopy could not be fetched or verified and there is no last-known-good copy | Tor cannot reach any Elder Tree from here (first run on a blocked network) | `shadenet doctor` (the `tor` and `elder` lines); retry |
| `rpc` | 503 | 2 | Reading the member set over JSON-RPC failed | A public RPC pool returned an empty `eth_getLogs` page, a null receipt or 429 from a pruned or busy backend; the client fails closed instead of building a wrong tree | `shadenet doctor --rpc` rates every endpoint; put a full-history one first with `SHADENET_RPC_URL=<url>,<fallback>` |
| `transport` | 503 | 3 | Every candidate node failed at the Tor or TCP level | Onion descriptors republishing for a few minutes after a node restart; a bad circuit; a group-writable Arti state dir (Arti refuses to start) | Retry in a minute; `shadenet doctor` checks the state directories and umask; persistent failures on every node mean Tor is blocked here |
| `node_refused` | 502 | 1 | A node answered and refused the proof or target. `reason` has its code | `wrong-group-root`: your member set differs from the node's (the ack now carries the node's `roots`, `rootBlock`, `rootLeaves`); `session-unsupported`: that node cannot open ticket books; `bad-artifact`/`bad-version`: old binary | `shadenet doctor --rpc` says which side is stale; the client retries another node by itself; upgrade for artifact/version |
| `busy` | 503 | – | The proxy is at its tunnel or setup limit | More concurrent CONNECTs than the proxy allows | Retry after `Retry-After` |
| `target_not_allowed` | 403 | – | The host is outside the proxy's `--targets` allow-list; nothing was spent | An agent runtime opening a connection the operator did not allow (its own telemetry, a model API) | Use an allowed host, or start the proxy without `--targets`; see `shadenet run`'s default bypass list |
| `proxy_auth_required` | 407 | – | Missing or wrong proxy token | The agent was not given the token `shadenet init` wrote | Send `Proxy-Authorization: Basic base64(shadenet:<token>)` |
| `config` | 500 | 2 | Bad local configuration or input | Missing identity, a locked identity without its passphrase, a bad record path | Run `shadenet doctor` and fix the first `fail` line |
| `artifact` | 500 | 2 | The embedded ZK artifacts do not match their lock, or no node accepts them | A binary older than the ceremony adoption, or a modified binary | Upgrade to the release the record pins |
| `slot_state` | 500 | 3 | The RLN slot file is locked, corrupt or unwritable. Fails closed so no nullifier is reused | Two proxies on one identity, or an unwritable state directory | `shadenet doctor` prints the path and the lock holder. Never delete it inside an epoch |
| `prove` | 500 | 3 | Proof construction failed | Corrupt artifacts or identity | `shadenet doctor`; report it with the output |
| `internal` | 500 | 3 | Anything else local | — | Retry once, then report `shadenet doctor --json` |

Exit code 0 means success. `shadenet status` also exits with the state:
0 `ready`, 2 `not_admitted`/`not_finalized`/`no_identity`, 3 `degraded`,
4 `budget_exhausted`.

## `problems[]` before you retry

`GET /_shadenet/status`, `shadenet status --json` and the `shadenet_status` MCP tool carry a
`problems` array: one entry per thing standing between the agent and a tunnel, each with
`kind` (`state`, `canopy`, `last_error`, `incident`), `code`, `cause` and `fix`. Incidents are
what the canopy's operators declared (an Elder restarting, a node being rolled) and carry
`component`, `instance` and `since`. An agent that reads `problems` before retrying knows
whether to wait, to switch RPC, or to stop and ask its operator. Empty means nothing is wrong.

## `shadenet doctor`

Runs every check on the local setup and the canopy side, one line each: `ok`, `warn` or
`fail`, what was found, and for anything not ok, the cause and the exact command that fixes
it. `--json` for agents, `--offline` to skip Tor and RPC, `--rpc` for the endpoint checks
only, `--records <path,…>` to look for the identity in other deployment records.

| Line | What it checks | The failure it was written for |
|---|---|---|
| `version` | binary version and commit against the record's node commit | a client pinned to a release with no `shadenet` binary |
| `identity`, `identity permissions` | the file parses, holds a secret, is mode 600 | a commitment-only file handed to an agent |
| `tor state dir`, `tor cache dir`, `cache dir`, `umask` | nothing in the path is group- or world-writable | Arti refusing to start under umask 002 |
| `rpc <endpoint>` (one per `rpcUrls`) | head block and latency, the deploy receipt, a complete member log verified against the contract counters | an empty `eth_getLogs` page that became `gate:wrong-group-root` |
| `member set` | the complete endpoints agree on the finalized root | two endpoints at different heads |
| `elder <onion>` (one per Elder) | reachable over Tor, directory verifies under the pinned signer, is younger than the 900 s TTL, lists nodes; open incidents | an Elder whose directory stopped refreshing |
| `admission set` | how many listed nodes advertise the set they read (`caps.sets`) and whether it is this record's; a pre-0.7.1 fleet advertises none and the line says so | every node refusing `wrong-group-root` while status said ready, because the fleet had moved to another network's set (#234) |
| `canopy`, `tor`, `admission` | the merged canopy, Tor bootstrap, this identity's state | |
| `identity in <network>` | when not admitted: whether the leaf lives in another record's set | a staging identity on the production record |
| `root` | after a `wrong-group-root` refusal: our replay root against the roots the node advertised | which side is stale |

## Seeing a refusal from curl

A refused CONNECT is answered by the proxy, not the destination, so `curl -w '%{http_code}'`
prints `000`. Use `-w '%{http_connect}'` for the proxy's status (429, 502, 407) and `-i` or `-v`
to see the `X-ShadeNet-Error` header and the JSON body.

## Budget arithmetic

One tunnel spends one RLN slot. A tier-`K` member has `K` slots per epoch. The
public Sepolia record currently sets a 60-second epoch, 40 MiB per slot, and
one tier, limit 8; `shadenet init` and `shadenet status` print the live values from
the record, which change when the network's economics do. With session tickets
on (the public record), one slot opens a book of six tunnels at one node, so an
epoch can open `6K` tunnels and tickets left in a live book cost nothing.

`shadenet plan --count N` (or `--url …`, or the MCP tool `shadenet_plan`) does
the arithmetic against the live numbers: tunnels available now, epochs needed,
seconds until the batch's last tunnel can open, and the tier that fits it in
one epoch. The proxy applies the same arithmetic when it queues a request:
`status.queue.nextSlotInSeconds` is the wait a new request would see.

- One HTTPS request to a new host is one tunnel. Keep-alive and HTTP/2 reuse one
  tunnel for many requests to the same host within its payload cap.
- A SearXNG query fans out to one tunnel per engine routed through ShadeNet.
  Route only the engines that block Tor or datacenter IPs.
- Keep model APIs off ShadeNet (`shadenet run --no-proxy api.openai.com -- …`):
  the model call would otherwise spend a slot every epoch.
