# Staging rehearsal (M7)

Date: 2026-09-30 · Canopy: `sepolia-staging` (StakedReputationSet `0xf117FDEA83ac57d15D9394A2B56873C32d227B7E`, Sepolia block 11803707) · Fleet at `4c98573` (shade-elder-v4-02, shade-node-v4-04/05/06, the Lab, the second Elder on orbital-one) · Client binaries: the release-workflow build of main `e8776f1` (run 36504554404), then the build of `m7/rehearsal` (run 36768147231) once the member-set fix existed.

This is the M7 exit of the launch roadmap: every launch-gate line run against the staging canopy with dev keys and placeholder economics, before any human gate. Each section gives the command, the result and the evidence. Nothing here touched the production record (`network/sepolia`).

## Summary

| # | Gate line | Result |
|---|---|---|
| 0 | 24 h staking cycle: register → exit → withdraw → slash | pass |
| 1 | Stake from the browser, then use the seat | pass |
| 2 | Sponsor an agent seat; Hermes fetches through the canopy | pass (proxy, MCP tool, a model-driven Hermes call) with the fixed client |
| 3 | SearXNG through the canopy | pass with the fixed client and the fixed example |
| 4 | Elder failover | pass |
| 5 | RPC outage on a node | pass |
| 6 | Alert round trip to Matrix | pass (synthetic and real) |
| 7 | Release from a tag, fleet roll | pass |
| 8 | Production deploy script, fork dry run | pass |
| 9 | Uptime-probe flap | runner-side; explained in section 9 |

Two real defects came out of the rehearsal and were fixed the same day: a member-set replay that trusted an RPC's silently empty `eth_getLogs` page (section 2, PR #207), and a SearXNG example that the current SearXNG image rejected (section 3, PR #207).

## 0. The 24 h staking cycle

`scripts/staging-up.sh --resume` after the unbonding window (`withdrawableAt` 1790723436) finished the smoke that the staging deploy started on 2026-09-28:

```
  ok   a: withdraw paid the whole bond to a fresh recipient after unbonding
smoke: register -> exit -> withdraw -> slash all passed
```

State file `cache/smoke-0xf117….local.json`: `done: [register, exit, slash, withdraw]`. The withdraw is the one step that needs a real day on Sepolia; it ran against the real contract with a real Groth16 proof.

## 1. Stake from the browser

The production page is built from `network/sepolia/deployment.json`, which still points at the retired set `0xEB67…4275`, so the rehearsal needed a page built from the staging record. `scripts/build-stake-site.mjs` now takes `SHADENET_SITE_NETWORK` and `SHADENET_SITE_OUT`, and `scripts/rehearsal/browser-stake.mjs` runs the gate line end to end: build the page from the record, serve it, drive it in headless Chromium with a wallet whose signing happens in Node from a funded testnet key, save the identity the page creates, wait for the page's own finality countdown, read status through the wallet, then use the saved identity file with the Rust CLI through the canopy.

```
node scripts/rehearsal/browser-stake.mjs --network sepolia-staging --key-file <deployer.key> --shadenet <shadenet> --out <dir>
```

| Step | Evidence |
|---|---|
| page | `Get Access · ShadeNet`, "Stake without giving us an identity." |
| identity | leaf `10688862495977904825195572412930049892441183268691601350328834221021184317535`, tier 1; the page shows the identity commitment a sponsor would stake, the file holds the leaf and the secret |
| stake | button `stake 0.001 Sepolia ETH`; tx `0x613978fe452c5358bf62be58e665dd8a23c85c119f01a7c2661f50fa9e221900`, block 11816706, status 1, to `0xf117…7B7E`, value 0.001 ETH |
| finality | page: "Finalized. Nodes accept this membership once their next root refresh lands, usually within a minute." |
| status through wallet | "Status read through your wallet's RPC. This page sent it nowhere else." |
| member-status (CLI) | `status: active, index 6, limit 1, bondWei 1000000000000000` |
| fetch through the canopy | `fetch: HTTP 200 via keo2oo4nuwxedwgv55v2dzz5y7ijxinuczk6jwz2yh2hdc5ki3v5klad.onion:80 (epoch 29846618)`, body `{"ip":"174.138.53.191"}` |

Report and screenshot: the harness writes `report.json` and `stake-finalized.png` under `--out`.

## 2. Sponsor an agent seat; Hermes through the canopy

Hermes runs on orbital-one. The `shadenet_client` role in agent-devops (`shadenet_client: true`, `shadenet_client_network_record_src` = the staging record, `shadenet_client_install_method: local`) installs the binary, keeps the identity on the box, runs `shadenet proxy` as a lingering user service on `127.0.0.1:8118`, registers `shadenet mcp` with Hermes and installs the skill. The play printed the leaf; the seat was sponsored from the deployer key without the secret leaving the box:

```
registerIdentity(8633865008286614177589958619619158646198085622687148532735425301861386698282, 1)
  tx: 0x0b7d3fcc6c37c37c18b3d80d5bf9cf96ac811b351726d2d803e3df5fab4b0cb7  mined in block 11816666
```

`shadenet status --json` went `not_finalized` → `ready` (`admitted: true, finalized: true`) 12 minutes later.

**What failed first.** Every tunnel was refused `gate:wrong-group-root`. The client's member set (`shadenet leaves`) had 3 live leaves in 3 slots; the nodes and the JS reconstruction had 5 live leaves in 7 slots. The record's RPC, `ethereum-sepolia-rpc.publicnode.com`, answered a 10 000-block `eth_getLogs` for the set with an **empty array** (9 000- and 10 001-block ranges too), while 5 000- and 12 000-block ranges returned the seven early logs; another RPC returned everything. A pruned backend behind the pool's load balancer answers some ranges with nothing and no error. Both SDKs page `eth_getLogs` in 10 000-block windows and had no way to notice.

**Fix (PR #207).** The Rust `leaves::fetch_members` and the JS root provider (`NodeRootProvider` refresh and the client's `loadGroupFromContract`) read the contract's own `nextIndex()` and `activeCount()` at the scan block and require the replay to reproduce both; a mismatch re-scans with halved pages down to the floor, then fails closed naming the RPC. The Rust replay also rejects a `MemberRegistered` whose indexed slot is past the next free slot. A node restarting into that answer would have built the same wrong root, so the fleet roll (section 7) carries the fix.

| Check | Evidence |
|---|---|
| proxy CONNECT (curl through `127.0.0.1:8118`) | `{"ip":"161.35.146.3"} http=200` |
| MCP `shadenet_status` over stdio | `admitted: true`, `admissionSet: 0xf117…7B7E`, canopy `eligible: 3` |
| MCP `shadenet_fetch` over stdio | refused `gate:wrong-group-root` with the unfixed binary (each `shadenet mcp` start re-scans the set and hit the empty page) |
| Hermes one-shot, unfixed binary | Hermes called `mcp__shadenet__shadenet_fetch` (the wiring works end to end); the same refusal came back |
| Hermes one-shot, fixed binary (`694ddd0`, the release-workflow build of the fix) | `hermes chat --oneshot -q "Call the shadenet_fetch tool with url https://api.ipify.org?format=json …"` → `{"ip":"137.184.43.116"}` (a Shade Tree node's address, not orbital-one's) |

The fixed client, run three times against the same RPC from a laptop: `5 live leaves in 7 slots; root 1502159…8493` twice (the nodes' root), then `eth_getLogs: RPC HTTP 429 Too Many Requests`, a loud failure instead of a wrong tree.

## 3. SearXNG through the canopy

`examples/searxng` on orbital-one with the image built from `docker/shadenet.Dockerfile` and the aarch64 musl live binary (`docker build` without BuildKit needs `COPY` without `--chmod`, which the Dockerfile now tolerates by chmod'ing the binary first). A tier-8 seat was created with `shadenet init --dir ./shadenet --offline --limit 8` and sponsored (tx `0xe5bde3869c2a56a89092c960e682ca3f91426d830e647768e920d7fa66048a7c`, block 11816698); it reached `ready`.

Three defects in the example, all fixed in PR #207:

- `settings.yml` used `keepalive_expiry` and `max_keepalive_connections` under `outgoing.networks`; `searxng/searxng:2026.9.30` rejects both (`Network.__init__() got an unexpected keyword argument`) and the worker exits in a restart loop. Removed.
- The proxy's home (`./state`) was created group-writable on a host with umask 002, and Arti refuses to start: `Incorrect permissions: "${HOME}/" is u=rwx,g=rwx,o=rx; must be g-w`. The README and compose header now say `mkdir -m 0755 state`.
- `request_timeout: 8.0` is shorter than a cold tunnel (canopy fetch, proof, onion rendezvous); raised to 20 s. `SEARXNG_PORT` for a host where 8080 is taken.

With the unfixed binary the routed engines timed out (section 2). With the image rebuilt from the fixed binary (`shadenet:dev-694ddd0`) and a fresh `state` directory:

```
canopy verified nodes=3 sources=2
/search?q=…&format=json&engines=google      HTTP 200, 10 results
/search?q=…&format=json&engines=duckduckgo  HTTP 200, 0 results, unresponsive: CAPTCHA (DuckDuckGo's answer to the node's address)
/search?q=…&format=json&engines=bing        HTTP 200, 0 results (engine parse; the tunnel opened)
tunnel accepted gateway=keo2oo4n…onion:80 target=html.duckduckgo.com:443
tunnel accepted gateway=2kuuulht…onion:80 target=www.google.com:443
tunnel accepted gateway=a6cuyv5v…onion:80 target=www.bing.com:443
```

Three engines, three different nodes, three proof-gated tunnels; Google answered through ShadeNet.

## 4. Elder failover

`systemctl stop shade-tree-bootnode` on shade-elder-v4-02 at 19:52:24Z; started again at 19:56:04Z.

| Check | Evidence |
|---|---|
| Rust client (record lists both Elders) | `WARN some canopy sources fell back or failed problems=Elder Tree a4xt55…` then `canopy verified nodes=3 sources=2 from_cache=false` and `fetch: HTTP 200 via keo2oo4n…onion:80 (epoch 29846633)` |
| Hermes proxy on orbital-one | same: `canopy verified nodes=3 sources=2` from the second Elder |
| alert | `BootnodeDown shade-elder-v4-02` active in Alertmanager at +200 s (rule `for: 2m`); relay posted to Matrix at 19:54:59Z and 19:55:34Z; resolved notification at 20:00:35Z |

Left for M8: the nodes announce to one Elder (`SHADE_TREE_BOOTNODE_ONION` in the v4 role) and the Lab runner is pinned to it too, so with the primary Elder down the second Elder's directory ages out after the 900 s TTL and the Lab's probe fails. Nodes should announce to every Elder in the record.

## 5. RPC outage on a node

On shade-node-v4-06, `127.0.0.1 ethereum-sepolia-rpc.publicnode.com` in `/etc/hosts` for 150 s (the record's RPC; the fleet wrapper adds `rpc.sepolia.ethpandaops.io` as the fallback), then restored.

```
before:      shade_tree_gateway_root_source_degraded{source="staked"} 0
after 150s:  shade_tree_gateway_root_source_degraded{source="staked"} 0  shade_tree_rpc_failovers_total{endpoint="0"} 1
```

The gateway failed over to the second endpoint and never degraded its root source.

## 6. Alert round trip

Synthetic: `POST /api/v2/alerts` (`RehearsalRoundTrip`, `endsAt` +3 min) to the ShadeNet Alertmanager on orbital-one → relay `POST /alert` at 19:12:42Z, `healthz {"sent": 24, "failed": 0}`; the resolved notification at 19:17:41Z. Real: section 4.

## 7. Release from a tag; fleet roll

The RELEASE track tagged `v0.7.0-rc.1` = `db56701` (after PR #207). The staging record was re-pinned to that commit (`scripts/record-canopy.mjs --network sepolia-staging --commit db5670…`, then `scripts/shade-tree-v4-record.sh sepolia-staging m7/rehearsal-report` in agent-devops), and the fleet rolled with `scripts/shade-tree-v4-deploy.sh` and, for the second Elder, the tag's `bootstrap.sh` with `SHADE_TREE_REF=db5670…`.

**What failed first.** The role's fail-closed preflight on the controller (`deploy/v4/preflight.mjs --require-stake-profile public-stake-v1`) failed on some hosts with `onchain.deployTx: deployment receipt is missing (via ethereum-sepolia-rpc.publicnode.com)`: the same RPC pool answered `eth_getTransactionReceipt` for the 13 000-block-old deploy transaction with `null` from a pruned backend; the next call succeeded. Each host's preflight is a separate call, so a four-host roll needed several attempts. The preflight now retries a missing receipt up to four times before calling it a finding (this PR); the roll finished with `SHADE_TREE_SOURCE_ROOT` at the pinned commit with that retry applied.

| Host | Evidence |
|---|---|
| orbital-one (second Elder) | `shade_tree_build_info{commit="db5670…",role="elder",version="0.7.0-rc.1"}`, `ExecStart=… /opt/shade-tree/packages/node/bootnode/server.mjs` |
| shade-node-v4-05 | `shade_tree_build_info{commit="db5670…",role="node",version="0.7.0-rc.1"}`, `ExecStart=… /opt/shade-tree/packages/node/gateway/gateway.mjs` |
| shade-elder-v4-02 | `shade_tree_build_info{commit="db5670…",role="elder",version="0.7.0-rc.1"}`, `ExecStart=… /opt/shade-tree/packages/node/bootnode/server.mjs` |
| shade-node-v4-04, shade-node-v4-06 | `shade_tree_build_info{commit="db5670…",role="node",version="0.7.0-rc.1"}`, `ExecStart=… /opt/shade-tree/packages/node/gateway/gateway.mjs` |
| the Lab | re-pinned by the wrapper (`shade_tree_lab_runner` ok=26 changed=3); `/health` ok |
| fleet e2e (`scripts/shade-tree-v4-e2e.sh`) | exit 0: canopy verified (3 nodes), staked proof-gated requests through the nodes ok |
| a client after the roll | `canopy verified nodes=3 sources=2`, `fetch: HTTP 200 via keo2oo4n…onion:80 (epoch 29846670)` |
| the tag's release workflow (run 36770369044) | one job failed on a runner network error installing rustup (`fetch failed`), re-run: **success**, every target, attestations and checksums |

After the roll: the vendored `shade_tree_v4` role in agent-devops was removed and the wrapper now requires the upstream role in the pinned checkout (agent-devops #25); the ten `packages/node` entry-point shims from #202 are removed (#208). Not done, listed: per-host age recipients for the SOPS files (more than an hour of work; do it with the M8 roll).

## 8. Production deploy script, fork dry run

`node scripts/deploy-contracts.mjs --network sepolia --fork --rpc-url https://ethereum-sepolia-rpc.publicnode.com`:

```
  ok   a: withdraw paid the whole bond to a fresh recipient after unbonding
smoke: register -> exit -> withdraw -> slash all passed
deploy-contracts: fork rehearsal passed; nothing written under network/
```

## 9. The uptime-probe flap

The hosted probe (`uptime-probe.yml` on a GitHub runner, over Tor) failed 17 times between 2026-09-28 19:52Z and 2026-09-29 12:52Z with `CRITICAL: bootnode unreachable`, then went green for the following 30 hours (200 runs checked). Prometheus on orbital-one has the second vantage point for the same window: the Lab's probe (`shade_tree_probe_ok`) was 1 throughout except one 15-minute sample during the fleet roll, and both Elders' `up` were 1 throughout. The Elder was reachable; the GitHub runner's Tor client was not reaching the onion. Nothing on our side changed when it stopped. The hosted probe stays the coarse signal it is documented as; the Lab timer is the SLI.

## Left for M8

- The record's RPC. `ethereum-sepolia-rpc.publicnode.com` answered three different historical reads with nothing today (empty `eth_getLogs` pages, a `null` receipt, a 429). Both fixes above make the clients and the preflight notice; the M8 record should still name an endpoint with full history first and keep publicnode as a fallback, or the fleet wrapper's fallback list should be in the record.
- Nodes announce to every Elder in the record; the Lab runner reads the record's `elders[]`.
- A second node off DigitalOcean (needs Dan's Hetzner or Vultr token), the DigitalOcean token rotation, per-host age recipients.
- The staging seats sponsored today (Hermes on orbital-one, the SearXNG stack, the browser identity) stay in the staging set; they are not production seats.
