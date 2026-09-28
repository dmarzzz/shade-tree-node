# ShadeNet error codes

Every failure in the Rust SDK, the `shadenet` CLI, the local proxy and the MCP
server carries one stable code. The same code appears as:

- the `X-ShadeNet-Error` header and `error.code` in the JSON body of a refused
  `CONNECT` (with `Retry-After` when waiting helps);
- `error.code` in `shadenet … --json` output and in MCP tool results
  (`isError: true`);
- `shadenet::Error::code()` in Rust.

| Code | HTTP | Exit | What happened | What to do |
|---|---|---|---|---|
| `not_admitted` | 403 | 2 | Your leaf is not in the set the canopy's nodes accept | Register it: `shadenet register-member --identity identity.json --key-file <funded key>`, or ask a sponsor to stake your leaf |
| `not_finalized` | 403 | 2 | Registered, but the block is not final yet; nodes read the finalized set | Wait. About 13 minutes on Sepolia. `shadenet status --wait` polls for you |
| `port_not_allowed` | 403 | 2 | No node egresses to that port. Nodes serve HTTPS on 443 | Use https on port 443 |
| `budget_exhausted` | 429 | 4 | This epoch's tunnels are used up, or one tunnel hit its payload cap | Wait `Retry-After` seconds (the epoch reset), reuse open connections, or stake a higher tier |
| `no_eligible_node` | 503 | 2 | No node fits your admission path, the network's rate policy or a capability you asked for | Check `shadenet status`; drop `--region`/`--proto` requirements; retry later |
| `canopy` | 503 | 2 | The signed canopy could not be fetched or verified and there is no last-known-good copy | Check Tor reachability with `shadenet doctor`; retry |
| `rpc` | 503 | 2 | Reading the member set over JSON-RPC failed | Retry, or set `SHADENET_RPC_URL` to another Sepolia endpoint |
| `transport` | 503 | 3 | Every candidate node failed at the Tor or TCP level | Retry; a new tunnel picks other nodes. Persistent failures mean Tor is blocked here |
| `node_refused` | 502 | 1 | A node answered and refused the proof or target. `reason` has its code | See `reason`; `wrong-group-root` clears on retry, anything else is a bug worth reporting |
| `busy` | 503 | – | The proxy is at its tunnel or setup limit | Retry after `Retry-After` |
| `proxy_auth_required` | 407 | – | Missing or wrong proxy token | Send `Proxy-Authorization: Basic base64(shadenet:<token>)` |
| `config` | 500 | 2 | Bad local configuration or input | Run `shadenet doctor` |
| `artifact` | 500 | 2 | The embedded ZK artifacts do not match their lock, or no node accepts them | Upgrade the binary |
| `slot_state` | 500 | 3 | The RLN slot file is locked, corrupt or unwritable. Fails closed so no nullifier is reused | Check the path `shadenet doctor` prints. Never delete it inside an epoch |
| `prove` | 500 | 3 | Proof construction failed | Report it |
| `internal` | 500 | 3 | Anything else local | Report it |

Exit code 0 means success. `shadenet status` also exits with the state:
0 `ready`, 2 `not_admitted`/`not_finalized`/`no_identity`, 3 `degraded`,
4 `budget_exhausted`.

## Budget arithmetic

One tunnel spends one RLN slot. A tier-`K` member has `K` slots per epoch. The
public Sepolia record currently sets a 60-second epoch, 40 MiB per slot, and
tiers 1 and 8; `shadenet init` and `shadenet status` print the live values from
the record, which change when the network's economics do.

- One HTTPS request to a new host is one tunnel. Keep-alive and HTTP/2 reuse one
  tunnel for many requests to the same host within its payload cap.
- A SearXNG query fans out to one tunnel per engine routed through ShadeNet.
  Route only the engines that block Tor or datacenter IPs.
- Keep model APIs off ShadeNet (`shadenet run --no-proxy api.openai.com -- …`):
  the model call would otherwise spend a slot every epoch.
