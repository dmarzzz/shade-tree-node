# SearXNG through ShadeNet

A private SearXNG whose reputation-blocked engines (Google, Bing, DuckDuckGo by
default) reach the web through ShadeNet, while the rest use SearXNG's normal
network.

```text
browser/agent ──▶ 127.0.0.1:8080 ─┐
                                  │  one network namespace
            SearXNG ──▶ 127.0.0.1:8118 shadenet proxy ──Tor──▶ Shade Tree node ──▶ google.com
```

## Run it

```sh
cd examples/searxng
shadenet init --dir ./shadenet --offline                 # identity.json + proxy-token here
shadenet register-member --identity ./shadenet/identity.json --key-file funded-sepolia.key
shadenet status --identity ./shadenet/identity.json --wait   # until the stake is final
SHADENET_UID=$(id -u) SHADENET_GID=$(id -g) docker compose up -d
```

Open <http://127.0.0.1:8080>. `docker compose logs shadenet` shows the proxy's
JSON logs; its status endpoint is reachable from the host only through the
container (`docker compose exec` is unavailable in the distroless image), so use
`shadenet status --identity ./shadenet/identity.json` on the host instead.

`./state` holds the RLN slot state and canopy cache. Keep it: deleting it inside
an epoch could reuse a nullifier and get the member slashed.

## Use it from an agent

```sh
shadenet mcp --searxng-url http://127.0.0.1:8080    # adds the shadenet_search tool
```

or query `http://127.0.0.1:8080/search?q=…&format=json` directly.

## Budget

Each query spends one tunnel per routed engine (fewer while keep-alive
connections last). On the public tier 1 (one tunnel per 60-second epoch) that is
one routed engine per minute, so trim `engines:` in `settings.yml` to one engine
or stake tier 8. `shadenet status` shows what is left.

## Notes

- `settings.yml` in the container holds the proxy token. The rendered copy lives
  in a Docker volume only the containers can read.
- Nodes serve HTTPS only; `enable_http: false` keeps SearXNG from spending a
  tunnel on a plain-http engine request.
- Engines routed through ShadeNet share a small set of node IPs with other
  members, which is the point: they are not your IP and not a known Tor exit.
