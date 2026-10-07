# Adapters: routing tools and agents through ShadeNet

Every recipe here uses the local `shadenet` proxy or the `shadenet mcp` server,
both from the one `shadenet` binary. Set it up first with the
[agent guide](AGENT.md) (`shadenet init`, stake, `shadenet proxy`).

Everything that follows assumes:

- the proxy runs at `127.0.0.1:8118`;
- its token is in `~/.config/shadenet/proxy-token`;
- the proxy user name is `shadenet` (`shade-tree` is also accepted for one release).

```sh
TOKEN="$(cat ~/.config/shadenet/proxy-token)"
PROXY="http://shadenet:$TOKEN@127.0.0.1:8118"
```

Two protocol facts shape every adapter:

- **HTTPS on 443 only.** The proxy speaks HTTP CONNECT and nodes egress to port
  443. TLS runs end to end to the destination. Plain `http://` URLs and other
  ports are refused locally with `403 port_not_allowed` before a slot is spent.
- **One tunnel per new connection.** Each CONNECT spends one RLN slot of a small
  per-epoch budget ([budget arithmetic](ERRORS.md#budget-arithmetic)). Reuse
  connections (keep-alive, HTTP/2) and route only the traffic that needs it.

## curl

```sh
curl -x "$PROXY" 'https://api.ipify.org?format=json'   # prints the node's IP, not yours
```

Or through `run`, which also keeps the token out of your shell's environment:

```sh
shadenet run -- curl -s 'https://api.ipify.org?format=json'
```

A refusal is a JSON body and an `X-ShadeNet-Error` header; `curl -i -x …`
shows them. See [ERRORS.md](ERRORS.md).

## Python (httpx, requests)

```python
import os, httpx

token = open(os.path.expanduser("~/.config/shadenet/proxy-token")).read().strip()
proxy = f"http://shadenet:{token}@127.0.0.1:8118"
# pip install 'httpx[http2]'
with httpx.Client(proxy=proxy, http2=True, timeout=60) as client:   # one tunnel, many requests
    print(client.get("https://api.ipify.org?format=json").json())
```

`requests` takes `proxies={"https": proxy}`. Both honour `HTTPS_PROXY`, so
`shadenet run -- python agent.py` works without code changes. A runnable
version is [`examples/python-httpx.py`](../examples/python-httpx.py).

## Hermes

Two options:

- **MCP (recommended).** Hermes keeps its normal network and calls
  `shadenet_fetch` when a site blocks Tor or datacenter IPs:

  ```sh
  hermes mcp add shadenet --command shadenet --args mcp
  ```

  Add `--env SHADENET_SEARXNG_URL=http://127.0.0.1:8080` before `--args` to expose
  `shadenet_search` too. The skill file in
  [`examples/hermes/SKILL.md`](../examples/hermes/SKILL.md) tells the model
  when to use it.

- **Everything through ShadeNet.** Keep the model endpoint out:

  ```sh
  shadenet run --no-proxy api.openai.com,openrouter.ai -- hermes gateway
  ```

## Claude Code, Codex and other MCP clients

```sh
claude mcp add shadenet -- shadenet mcp
```

```toml
# ~/.codex/config.toml
[mcp_servers.shadenet]
command = "shadenet"
args = ["mcp"]
```

The OpenAI Agents SDK (`MCPServerStdio(params={"command": "shadenet", "args":
["mcp"]})`) and the LangChain MCP adapters use the same stdio command.

The tools:

| Tool | Arguments | Returns |
|---|---|---|
| `shadenet_fetch` | `url` (https), `method`, `headers`, `body`, `max_bytes` | `status`, `headers`, `body` (text, or base64 with `bodyEncoding`), `gateway`, `epoch`, `truncated` |
| `shadenet_status` | none | the [status object](../specs/local-api.openapi.yaml) |
| `shadenet_plan` | `urls` or `count` | the plan object: `availableNow`, `epochsNeeded`, `completesInSeconds`, `fitsNow`, `advice` |
| `shadenet_search` | `query`, `engines`, `categories`, `max_results` | `results` with `title`, `url`, `content`, `engine` |

Failures come back with `isError: true` and `{"error": {"code", "message",
"cause", "fix", "retryAfterSeconds"}}` so the model can wait out a spent budget instead of
retrying blindly.

## SearXNG

SearXNG fans one query out to many engines. Route only the engines that block
Tor or datacenter IPs through ShadeNet; the rest stay on their usual network.
A complete Docker Compose recipe is in
[`examples/searxng/`](../examples/searxng/): the `shadenet` proxy container and
SearXNG share one network namespace, so the proxy never listens beyond loopback.

The settings that matter (keys verified against SearXNG's
`searx/network/network.py`):

```yaml
use_default_settings: true
outgoing:
  request_timeout: 20.0     # a cold tunnel is canopy + proof + onion rendezvous
  max_request_timeout: 30.0
  networks:
    shadenet:
      proxies:
        all://:
          - http://shadenet:__SHADENET_TOKEN__@127.0.0.1:8118
      enable_http: false          # nodes egress 443 only; never burn a slot on http://
      retries: 0                  # a retry is another tunnel
      keepalive_expiry: 55.0      # reuse the tunnel within the 60 s epoch
      max_keepalive_connections: 4
engines:
  - name: google
    network: shadenet
  - name: bing
    network: shadenet
```

`settings.yml` cannot read environment variables, so the recipe renders the
token into it at start-up and keeps the file private.

## Rust

```rust
let client = std::sync::Arc::new(shadenet::Client::new(
    shadenet::Config::builder().identity_file("identity.json").build()?,
)?);
client.spawn_canopy_refresh();
let response = client.fetch(shadenet::FetchRequest::get("https://example.com/")).await?;
let tunnel = client.connect("example.com:443").await?;   // or a raw stream for your own TLS
```

Runnable examples: [`crates/shadenet/examples`](../crates/shadenet/examples)
(`cargo run -p shadenet --example fetch -- https://example.com/`).

## JavaScript

Use the JavaScript SDK ([SDK.md](SDK.md)) in Node or the browser, or point any
Node HTTP client at the proxy (`undici`'s `ProxyAgent`, or
`NODE_USE_ENV_PROXY=1` with `shadenet run`).

## Privacy note

Each tunnel carries a fresh RLN proof and a per-tunnel nullifier, so proofs do
not expose a stable member identifier. Tor keeps your IP from the node, and TLS
keeps content from it. The node still sees the destination, timing, duration and
volume of each tunnel, which can correlate tunnels that happen close together,
such as one SearXNG query's engine fan-out.
