# Monitoring

Local Prometheus metrics, a Grafana dashboard, and alert rules for Shade Tree
operators. The dashboard and alerts use series emitted by the Elder Tree and
Shade Tree node. The Proxy, heartbeat, and registrar expose their own local
signals for operators who run those roles.

Files:

- `grafana-dashboard.json` is an importable Grafana dashboard (`$datasource` / `$job` / `$instance`
  template vars).
- `alerts.yml` contains Prometheus alerting rules grounded in `docs/SLO.md`.
- `uptime/` contains the external uptime probe scheduler bundle (systemd timer and service, crontab
  line, env template) + `.github/workflows/uptime-probe.yml`; see `UPTIME.md`.
- This README explains how to scrape, import, and load the rules.

## Metrics

| Metric | Type | Labels | Source |
|---|---|---|---|
| `shade_tree_bootnode_announces_total` | counter | `result` (accepted\|rejected), `reason` (on reject) | `packages/node/bootnode/server.mjs` |
| `shade_tree_bootnode_directory_fetches_total` | counter | none | `packages/node/bootnode/server.mjs` |
| `shade_tree_bootnode_directory_delta_fetches_total` | counter | `result` | `packages/node/bootnode/server.mjs` |
| `shade_tree_bootnode_live_gateways` | gauge | none | `packages/node/bootnode/server.mjs` |
| `shade_tree_bootnode_connections` | gauge | none | `packages/node/bootnode/server.mjs` |
| `shade_tree_gateway_tunnels_total` | counter | `result` (pass\|drop), `reason` (on drop) | `packages/node/gateway/gateway.mjs` |
| `shade_tree_gateway_slashes_total` | counter | none | `packages/node/gateway/gateway.mjs` |
| `shade_tree_gateway_tunnel_closes_total` | counter | `reason` (idle-timeout\|payload-limit\|upstream-error) | `packages/node/gateway/gateway.mjs` (separate from `tunnels_total` because these tunnels already counted as pass) |
| `shade_tree_gateway_active_tunnels` | gauge | none | `packages/node/gateway/gateway.mjs` |
| `shade_tree_gateway_connections` | gauge | none | `packages/node/gateway/gateway.mjs` |
| `shade_tree_gateway_agent_to_destination_payload_bytes_total` | counter | none | `packages/node/gateway/gateway.mjs` |
| `shade_tree_gateway_destination_to_agent_payload_bytes_total` | counter | none | `packages/node/gateway/gateway.mjs` |
| `shade_tree_gateway_verify_seconds` | histogram | `le` (on `_bucket`) | `packages/node/gateway/gateway.mjs` |
| `shade_tree_gateway_upstream_connect_seconds` | histogram | `le` (on `_bucket`) | `packages/node/gateway/gateway.mjs` |
| `shade_tree_gateway_trusted_roots` | gauge | `source` (invited\|staked\|paid) | `packages/node/gateway/gateway.mjs` |
| `shade_tree_gateway_root_source_degraded` | gauge | `source` | `packages/node/gateway/gateway.mjs` |
| `shade_tree_gateway_paid_access_leaves` | gauge | none | `packages/node/gateway/gateway.mjs` |
| `shade_tree_proxy_tunnels_total` | counter | `result`, bounded `reason` | `packages/node/client/shim.mjs` |
| `shade_tree_proxy_active_tunnels` | gauge | none | `packages/node/client/shim.mjs` |
| `shade_tree_proxy_connect_seconds` | histogram | `le` (on `_bucket`) | `packages/node/client/shim.mjs` |
| `shade_tree_proxy_proof_seconds` | histogram | `le` (on `_bucket`) | `packages/node/client/shim.mjs` |
| `shade_tree_proxy_tor_dial_seconds` | histogram | `le` (on `_bucket`) | `packages/node/client/shim.mjs` |
| `shade_tree_proxy_failovers_total` | counter | none | `packages/node/client/shim.mjs` |
| `shade_tree_proxy_canopy_refresh_total` | counter | `result` (query\|verified\|cache\|error) | `packages/node/client/shim.mjs` |
| `shade_tree_proxy_candidates` | gauge | none | `packages/node/client/shim.mjs` |
| `shade_tree_heartbeat_attempts_total` | counter | `outcome` (accepted\|rejected\|egress-unhealthy\|transport-error) | `packages/node/bootnode/heartbeat.mjs` |
| `shade_tree_heartbeat_last_success_timestamp_seconds` | gauge | none | `packages/node/bootnode/heartbeat.mjs` |
| `shade_tree_heartbeat_egress_check_up` | gauge | none | `packages/node/bootnode/heartbeat.mjs` |
| `shade_tree_heartbeat_draining` | gauge | none | `packages/node/bootnode/heartbeat.mjs` (1 while the operator drain flag is announced) |
| `shade_tree_alert_webhook_total` | counter | `result` (sent\|failed) | `packages/node/lib/alerts.mjs` (gateway + heartbeat, when a webhook is set) |
| `shade_tree_registrar_payments_total` | counter | `protocol` (unknown\|x402\|mpp), `result` (challenged\|inserted\|replayed\|rejected\|failed), bounded `reason` on non-success outcomes | `packages/node/payments/registrar.mjs` |
| `shade_tree_registrar_quotes_total` | counter | `route` (quote\|pay) | `packages/node/payments/registrar.mjs` |
| `shade_tree_registrar_txs_total` | counter | `kind` (settle\|insert), `result` (ok\|failed) | `packages/node/payments/registrar.mjs` |
| `shade_tree_registrar_orders` / `shade_tree_registrar_inflight` | gauge | none | `packages/node/payments/registrar.mjs` |
| `shade_tree_rpc_failovers_total` | counter | `endpoint` (list index that failed; never the URL) | `packages/node/lib/rpc-safety.mjs` (any role with `SHADE_TREE_RPC_URL`) |
| `shade_tree_build_info` | gauge | `role`, `version`, `commit` (running checkout, or `unknown`) | every long-running role |
| `shade_tree_process_start_time_seconds` | gauge | none | every long-running role |
| `shade_tree_process_uptime_seconds` | gauge | none | every long-running role |
| `shade_tree_process_resident_memory_bytes` | gauge | none | every long-running role |

Histograms expose `_bucket`, `_sum`, and `_count` series in seconds. Buckets are
`DEFAULT_LATENCY_BUCKETS` in `packages/node/lib/metrics.mjs`. Node metrics keep the
`shade_tree_gateway_*` prefix for dashboard compatibility.

`shade_tree_registrar_payments_total` increments once for every completed
`POST /pay`, including the headerless 402 challenge and early HTTP rejects.
Requests rejected before a payment rail is selected use `protocol="unknown"`.
The reason vocabulary is closed in `packages/node/payments/registrar.mjs`; unexpected library
or payer-controlled strings collapse to `reason="other"`.

`shade_tree_bootnode_live_gateways` means announced within the Elder Tree TTL.
It is not an independent reachability count unless active probing is enabled.
`shade_tree_gateway_active_tunnels` counts established egress tunnels;
`shade_tree_gateway_connections` also includes pre-verification sockets.

## Local endpoints

Every metrics listener is separate from the role's protocol listener and is
hard-bound to loopback. It serves only `GET /metrics`, `GET /livez`, and
`GET /readyz`. Metrics are not available through an Elder Tree, node, or
registrar onion. The HTTP listener also rejects non-loopback `Host` values and
does not enable browser CORS access.

| Role | Runtime variable | Bootstrap port |
|---|---|---:|
| Elder Tree | `SHADE_TREE_METRICS_PORT` | 9100 |
| Shade Tree node | `SHADE_TREE_METRICS_PORT` | 9101 |
| Registrar | `SHADE_TREE_METRICS_PORT` | 9102 |
| Heartbeat | `SHADE_TREE_HEARTBEAT_METRICS_PORT` | 9103 |
| Proxy | `SHADE_TREE_METRICS_PORT` | choose a free local port |

The listeners are off when their port is `0` or unset in a direct invocation.
`bootstrap.sh` enables the four service ports shown above. Set a Proxy port
explicitly, especially when it shares a host with another role.

Because they bind loopback, Prometheus running elsewhere reaches them one of two ways:

1. **Prometheus on the same box**: scrape `127.0.0.1:<port>` directly. This is simplest for a single-box
   reference deploy.
2. **SSH tunnel**: forward each remote loopback port to a distinct local port on the Prometheus
   host, then scrape the forwarded ports. Example:

   ```sh
   # Elder Tree metrics 9100 -> local 19100; node metrics 9101 -> local 19101
   ssh -N -L 19100:127.0.0.1:9100 operator@bootnode-host &
   ssh -N -L 19101:127.0.0.1:9101 operator@gateway-1-host &
   ```

Do not proxy these listeners through Tor, publish them, or bind them to a public
interface. They carry fleet shape, health, and coarse traffic signal.

Operator metrics stay on the machine. Nodes do not send them to the Elder Tree,
and the public Grove does not ingest them. Labels are bounded and exclude
destinations, onion addresses, nullifiers, operator addresses, contract
addresses, and request identifiers. Treat stored Prometheus data as sensitive
operational data anyway. Keep retention short enough for your needs and limit
access to the monitoring system.

## Prometheus scrape config

Add to `prometheus.yml`. The `job` names here (`shade-tree-bootnode`, `shade-tree-gateway`) are what `alerts.yml`
matches on, so keep them in sync if you rename. Targets shown for the SSH-tunnel case; swap for the
real `127.0.0.1:<port>` if Prometheus runs on the box.

```yaml
scrape_configs:
  - job_name: shade-tree-bootnode
    metrics_path: /metrics
    scheme: http
    scrape_interval: 15s
    static_configs:
      # tunnel:  ssh -L 19100:127.0.0.1:9100 operator@bootnode-host
      # on-box:  replace with 127.0.0.1:9100
      - targets: ["127.0.0.1:19100"]
        labels:
          instance: bootnode-1

  - job_name: shade-tree-gateway
    metrics_path: /metrics
    scheme: http
    scrape_interval: 15s
    static_configs:
      # Tunnel each node's loopback listener to a distinct local port.
      - targets: ["127.0.0.1:19101"]
        labels:
          instance: gateway-1
      - targets: ["127.0.0.1:19102"]
        labels:
          instance: gateway-2

  - job_name: shade-tree-heartbeat
    metrics_path: /metrics
    scheme: http
    scrape_interval: 15s
    static_configs:
      # On-box target. Tunnel 9103 to a distinct local port when Prometheus is remote.
      - targets: ["127.0.0.1:9103"]
        labels:
          instance: gateway-1-heartbeat

rule_files:
  - /etc/prometheus/rules/shade-tree-alerts.yml   # this repo's monitoring/alerts.yml
```

The `up` series for the bootnode, gateway, and heartbeat jobs are synthesized by
Prometheus from each scrape outcome. The matching down alerts use those series.

## Import the dashboard

1. Grafana -> Dashboards -> New -> Import.
2. Upload `grafana-dashboard.json` (or paste it).
3. When prompted, pick your Prometheus data source for the `DS_PROMETHEUS` input; it binds the
   dashboard's `$datasource` variable.
4. The `$job` and `$instance` variables auto-populate from `label_values(up, job)` and
   `label_values(up{job=~"$job"}, instance)`. Leave both on `All` to see the whole fleet, or narrow
   to one gateway/bootnode.

Panels: fleet size (`shade_tree_bootnode_live_gateways`), directory fetch rate, announce accept/reject by
reason + rejection fraction, active tunnels, slash events, gateway pass/drop by reason + drop
fraction, and `verifyEnvelope` p50/p95/p99 (histogram_quantile over
`shade_tree_gateway_verify_seconds_bucket`) plus mean verify time and verifies/sec.

## Alerts without Prometheus (webhook)

Set `SHADE_TREE_ALERT_WEBHOOK` (and optionally `SHADE_TREE_ALERT_WEBHOOK_FORMAT`) on the gateway
and heartbeat units (`bootstrap.sh` renders both when the variable is set) and the node evaluates
the rules below in-process every 30 s, POSTing one JSON document per transition and repeating a
still-firing alert every 4 h. No Alertmanager, no Prometheus.

| Rule | Role | Condition | Severity |
|---|---|---|---|
| `HeartbeatStale` | heartbeat | last accepted announce older than 3 intervals | critical |
| `HeartbeatNeverAccepted` | heartbeat | no announce accepted 3 intervals after start | critical |
| `EgressDown` | heartbeat | local egress check failing for 2 evaluations | critical |
| `ElderPartial` | heartbeat | some but not all Elder Trees accept the announce (2 evaluations) | warning |
| `Draining` | both | operator drain flag set | info |
| `RootSourceDegraded` | gateway | an admission root source degraded for 2 evaluations | warning |
| `RpcEndpointFailing` | gateway | 3+ RPC failovers in 15 min | warning |
| `HighDropRate` | gateway | more than half of 20+ tunnels dropped in 15 min | warning |
| `GatewayStarted` / `GatewayStopping` / `HeartbeatStarted` / `HeartbeatStopping` | both | lifecycle, once | info |

Payloads (`SHADE_TREE_ALERT_WEBHOOK_FORMAT`):

- `generic` (default): `{"source":"shadenet","version":1,"role":"node","instance":"<host>","alert":"HeartbeatStale","severity":"critical","status":"firing|resolved","summary":"...","startsAt":"<iso>","ts":"<iso>"}`
- `slack`: `{"text":"[shadenet] FIRING HeartbeatStale (host): ..."}` for an incoming webhook
- `discord`: `{"content":"[shadenet] FIRING ..."}` for a channel webhook
- `matrix`: the generic fields plus `text` and `msgtype: "m.text"`, for a matrix-hookshot generic
  webhook whose template is `{{ data.text }}`

The URL may carry a token, so bootstrap only accepts `https://` (or a loopback `http://` relay).
Delivery is counted in `shade_tree_alert_webhook_total{result}`; failures are logged at most once
a minute and never affect the node.

## One-node compose bundle

`monitoring/compose/docker-compose.yml` runs Prometheus (rules from `alerts.yml`, scraping the
three loopback listeners of this host) and Grafana (dashboard provisioned) on the host network,
both bound to 127.0.0.1:

```bash
cd monitoring/compose
GRAFANA_ADMIN_PASSWORD=... docker compose --profile monitoring up -d
# Grafana http://127.0.0.1:3000 (admin), Prometheus http://127.0.0.1:9090
```

Host networking is required: the node's metrics listeners refuse any non-loopback `Host` header,
so a bridged container could not scrape them. Edit `prometheus.yml` if your metrics ports differ.

## Load the alert rules

Point Prometheus's `rule_files` at `alerts.yml` (see the snippet above), then reload:

```sh
promtool check rules monitoring/alerts.yml    # validate first
curl -X POST http://localhost:9090/-/reload   # if --web.enable-lifecycle is set
```

Route them through Alertmanager as you see fit; every rule carries a `severity` label
(`critical`/`warning`) and a `component` label (`bootnode`/`gateway`/`heartbeat`/`fleet`) to route on.

## What each alert means operationally

Grounded in `docs/SLO.md` and cross-referenced to the runbooks in `docs/INCIDENT.md`.

| Alert | Severity | Meaning | SLO / runbook |
|---|---|---|---|
| `BootnodeDown` | critical | Bootnode `/metrics` unscrapable (`up==0`). Discovery degraded; clients fall back to LKG cache, so rarely member-visible, but burns bootnode-availability budget. | SLO 2.2; INCIDENT.md #1 (verify-false -> #2) |
| `FleetTooSmall` | critical | `shade_tree_bootnode_live_gateways < 2`. No failover spread, target metadata 1/1 not 1/N. Add gateways before egress-success burns. | SLO 2.3; INCIDENT.md #3 |
| `FleetEmpty` | critical | `< 1` live gateway. No member can egress. Never cleared by weakening admission. | SLO 2.3, section 5; INCIDENT.md #3 |
| `AnnounceRejectionSpike` | warning | >80% of announces rejected with real volume. Rejections are the gate working; a sustained spike = forged announces / misconfig / full registry. Not an outage. | SLO section 1 |
| `GatewayDown` | warning | One gateway unscrapable. Individual gateway uptime is explicitly NOT an SLO; the fleet routes around it. Escalates only if it drives `FleetTooSmall`. | SLO section 4; INCIDENT.md #3 |
| `RootSourceDegraded` | warning | A staked or paid root source is on last-known-good state or unavailable. Check its provider and start-block configuration. | INCIDENT.md #6 |
| `SlashSpike` | warning | Elevated `shade_tree_gateway_slashes_total` rate. A slash is the RLN rate limit working (over-spend caught), never error budget; but a spike warrants a look (broken client / prober). | SLO sections 3-4; INCIDENT.md #7 |
| `HighDropRate` | warning | >50% of tunnel attempts dropped. Gate DROPs are correct rejections -> read the reason mix. `root-not-recent` spike = config mismatch (align epoch/slots/identifier/root, widen freshness); dial/upstream drops = capacity, add gateways. | SLO 2.1, section 3; INCIDENT.md #6 |
| `VerifyLatencyP95High` | warning | `verifyEnvelope` p95 > 50ms. Server-side verify CPU only (Tor RTT excluded by design). Near the ~30 verify/s/core ceiling: add cores/gateways, never skip a verify check. | SLO 2.4, section 5 |
| `VerifyLatencyP99High` | warning | `verifyEnvelope` p99 > 100ms. Tail verify latency climbing; check jitter / saturation, add capacity. | SLO 2.4, section 3 |
| `HeartbeatStale` | critical | The process is up but no announce has been accepted for 15 minutes. The node will age out of the Canopy. | INCIDENT.md #3 |
| `HeartbeatNeverAccepted` | critical | The heartbeat has run for 15 minutes without one accepted announce. Check startup configuration and Tor reachability. | INCIDENT.md #3 |
| `HeartbeatDown` | warning | The heartbeat metrics process is not scrapeable. Confirm the service and local port before fleet membership expires. | INCIDENT.md #3 |

The hard line from `docs/SLO.md` section 5 applies to every response here: no alert is ever cleared by
weakening the gate, admitting an unverified gateway, serving an unverifiable directory, narrowing the
anonymity set, or skipping a `verifyEnvelope` check. When a target and a correctness/anonymity
property conflict, the property wins.

## Calibration note

Every threshold in `alerts.yml` is a defensible default, not a measured commitment. The SLO doc flags
its availability targets `[NEEDS DATA]`: recalibrate the fractions, `for:` windows, and rate thresholds
against the first 30 days of real metrics. `docs/SLO.md` section 3 also calls for multi-window
burn-rate alerts once a real error-budget baseline exists; those are deliberately NOT included here
because they need production event volumes to set the burn multipliers honestly.
