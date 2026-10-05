# Operator runbook

> [!NOTE]
> Public-host deployment is open: the proof keys come from the adopted PSE trusted setup
> (`docs/ceremony/PSE-VERIFICATION.md`) and the Sepolia canopy runs `v0.7.0`. Still a research
> preview on a testnet; see [DEPLOYMENT-PLAN.md](DEPLOYMENT-PLAN.md).

For running a Shade Tree node or Elder Tree. Every command here exists in
`packages/node/bin/shade-tree.mjs` or the deploy scripts. For the full config surface see
[CONFIG.md](CONFIG.md); for the discovery design see [BOOTNODE.md](BOOTNODE.md).

Two ways to invoke the CLI:

- Workstation with the repo: run `npm ci && npm link` once, then `shade-tree-node <cmd>`. Use this
  path for the full local canopy, tests, code changes, and any future deployment work.
- On a bootstrapped droplet (repo at `/opt/shade-tree`, not linked): run it explicitly,
  e.g. `sudo -u shade-tree-node node /opt/shade-tree/packages/node/bin/shade-tree.mjs <cmd>`.

`shade-tree help` lists commands; `shade-tree <cmd> --help` prints one-line help. Every `--flag`
just sets the matching `SHADE_TREE_*` env var (see [CLI.md](CLI.md)).

Note the two Tor SOCKS ports: the local-dev repo Tor runs SOCKS on **9250**; a
droplet bootstrapped by `bootstrap.sh` uses the **system Tor on 9050**. The curl
examples below use 9050 (droplet). Adjust for local dev.

---

## 1. Deploy a gateway + bootnode

One command on a fresh Ubuntu 24.04 box. It installs Node 24 + Tor (official repo,
so onion PoW is available), mints the onion identities, writes and starts the
systemd units, and prints the bootnode onion, its pinned signer, the gateway onion,
and the client command. Idempotent (re-running reuses keys and units).

```bash
ssh root@<droplet-ip>
curl -fsSL https://raw.githubusercontent.com/dmarzzz/shade-tree-node/main/packages/node/bootnode/deploy/bootstrap.sh \
  | sudo env SHADE_TREE_MEMBERS_FILE=/root/operator-members.json bash
```

Or, if the repo is already on the box:

```bash
sudo env SHADE_TREE_MEMBERS_FILE=/root/operator-members.json bash packages/node/bootnode/deploy/bootstrap.sh
```

It creates three `Restart=always` units:

| unit | what it runs | source |
|---|---|---|
| `shade-tree-bootnode` | discovery service | `packages/node/bootnode/server.mjs` |
| `shade-tree-gateway` | access-gated egress node | `packages/node/gateway/gateway.mjs` |
| `shade-tree-heartbeat` | announces the gateway to the local bootnode | `packages/node/bootnode/heartbeat.mjs` |

Tunables are env vars on the `curl | bash` line, e.g. `SHADE_TREE_ADMISSION=stake`,
`SHADE_TREE_BOOTNODE_PORT`, `SHADE_TREE_GATEWAY_PORT`, `SHADE_TREE_DIR`, `SHADE_TREE_REF=<tag|sha>` to pin the
git ref the box clones (fetch the script from that same ref), `SHADE_TREE_ENABLE_POW=1` (onion PoW
DoS defense; **off by default** because a `pow: no` client tor cannot reach a PoW onion),
`SHADE_TREE_GATEWAY_REGION=eu`. Full table: `packages/node/bootnode/deploy/README.md` "Tunables". Every value
is validated before anything is installed.

Firewall: the gateway and bootnode are onion services and take **no inbound clearnet
ports**. Inbound-22-only + outbound-allow (UFW) is correct. Never expose the loopback
backends (8877 / 8443).

Wait ~30s for descriptor propagation, then verify (see day-2 below).

---

## 2. Join the fleet as a new gateway operator

### One container, one record URL

The node image bundles Tor, the node and its heartbeat, and takes everything it needs from the
deployment record. It mints an onion identity on first start, announces to every Elder Tree in the
record, and keeps the identity, Tor state and spent set in the `/state` volume.

```bash
docker run -d --name shadenet-node --restart unless-stopped \
  -e SHADENET_RECORD=https://raw.githubusercontent.com/dmarzzz/shade-tree-node/main/network/sepolia/deployment.json \
  -v shadenet-node:/state \
  ghcr.io/dmarzzz/shadenet-node:0.7.1
docker logs -f shadenet-node        # "heartbeat accepted" once per Elder means the node is listed
```

Check first, start nothing: the same image validates the record, every RPC in it, Tor, disk and
ports, and prints the exact environment it would run with. `--probe` bootstraps a temporary Tor and
reads each Elder's `/health`.

```bash
docker run --rm -e SHADENET_RECORD=https://raw.githubusercontent.com/dmarzzz/shade-tree-node/main/network/sepolia/deployment.json \
  ghcr.io/dmarzzz/shadenet-node:0.7.1 check --probe
```

The Sepolia canopy's Elders admit staked operators (`elder.admission = stake`): the operator
address must hold a bond in the gateway registry and each onion must carry that operator's
signature. Without both, every Elder answers `not-staked` and the log says
`heartbeat rejected ... err: not-staked` with the fix. Do this before the first `docker run -d`.
The key never has to be on the node's box: mint the identity there, stake and sign where the key
lives (the same image does both), hand the node the two values:

```bash
# on the node's box: mint the onion identity into the volume
docker run --rm -v shadenet-node:/state -e SHADENET_RECORD=... ghcr.io/dmarzzz/shadenet-node:0.7.1 identity
#   -> { "onion": "<56 chars>.onion", ... }

# where the operator key lives (operator.key: one line, 64 hex, chmod 600)
# once per operator: stake the bond (0.001 Sepolia ETH, `BOND()` on the registry), a no-op if already staked
read -s KEY && SHADE_TREE_REGISTER_KEY="$KEY" docker run --rm -e SHADE_TREE_REGISTER_KEY \
  --entrypoint node ghcr.io/dmarzzz/shadenet-node:0.7.1 packages/node/bin/shade-tree.mjs register-gateway \
  --gateway-registry 0x94ECeD0C1c7a8793a5c901c8C1995C8E7039A868 --rpc-url https://rpc.sepolia.ethpandaops.io; unset KEY
# per node: sign its onion
docker run --rm -v "$PWD":/k:ro ghcr.io/dmarzzz/shadenet-node:0.7.1 authorize --onion <onion> --key-file /k/operator.key
#   -> { "SHADENET_OPERATOR": "0x…", "SHADENET_OPERATOR_SIG": "0x…" }

# back on the node's box
docker run -d --name shadenet-node --restart unless-stopped \
  --security-opt no-new-privileges:true --cap-drop ALL --read-only --tmpfs /tmp \
  --memory 1g --log-opt max-size=20m \
  -e SHADENET_RECORD=... -e SHADENET_OPERATOR=0x… -e SHADENET_OPERATOR_SIG=0x… \
  -v shadenet-node:/state ghcr.io/dmarzzz/shadenet-node:0.7.1
docker exec shadenet-node node packages/node/bin/shadenet-node.mjs status   # "listed": Elders that accepted
```

The hardening flags are the ones `examples/node/compose.yml` sets: no privilege escalation, no
capabilities, a read-only root with `/tmp` in memory, a memory cap and bounded logs. The node needs
none of what they take away. One bond backs every onion an operator signs; the key file is read
inside the container only for `authorize` and `register-gateway`, which exit straight after.

Serving two canopies from one node (the staging set beside production, or a private set beside
the public one): `SHADENET_SETS=0x<contract>@<deployBlock>` adds a staked set to the record's; the
node scans each from its own deploy block and the directory advertises both. The same knob is
`SHADENET_SETS` on the `bootstrap.sh` line and `shade_tree_extra_sets` in the Ansible role.

The knobs, all optional except the record (`shadenet-node help` lists them; the full table is
[CONFIG.md](CONFIG.md#operator-front-door-shadenet-node)): `SHADENET_ADMIT` (staked, invited,staked, staked,paid),
`SHADENET_MEMBERS_FILE`, `SHADENET_ALLOW` / `SHADENET_DENY` (egress policy), `SHADENET_WEIGHT` (how
much traffic lands here), `SHADENET_REGION`, `SHADENET_METRICS` (loopback port or off), `SHADENET_LOG`,
`SHADENET_OPERATOR_KEY_FILE` or `SHADENET_OPERATOR` + `SHADENET_OPERATOR_SIG`, `SHADENET_POW`. The same
keys work in `/state/node.toml`. Any `SHADE_TREE_*` variable set explicitly still wins, so the
advanced surface is unchanged.

Day two: `docker exec shadenet-node node packages/node/bin/shadenet-node.mjs status` (onion, pins,
readiness), `docker exec shadenet-node curl -s 127.0.0.1:9101/metrics`, `docker stop shadenet-node`
to retire (the node leaves every Elder's directory within the 15-minute TTL; the identity stays in
the volume, `docker volume rm shadenet-node` forgets it). Compose recipe: `examples/node/compose.yml`.

### Fresh box, one command (systemd, no container)

`bootstrap.sh` with `SHADE_TREE_BOOTNODE_ONION` set installs **only** tor + `shade-tree-gateway` +
`shade-tree-heartbeat` — no bootnode unit, no bootnode onion — and points the heartbeat at the
existing bootnode:

### Join the Sepolia canopy with bootstrap.sh

```bash
ssh root@<new-ubuntu-24.04-host>
install -d -m 0700 /root/shadenet-creds
# your staked operator key (see "Stake the operator" below); a file, never argv or shell history
install -m 0600 /dev/stdin /root/shadenet-creds/SHADE_TREE_GW_OPERATOR_KEY < /path/to/operator.key
curl -fsSL --proto '=https' https://raw.githubusercontent.com/dmarzzz/shade-tree-node/main/packages/node/bootnode/deploy/bootstrap.sh \
  | SHADENET_NETWORK=sepolia SHADE_TREE_CREDENTIALS_FROM=/root/shadenet-creds bash
journalctl -u shade-tree-heartbeat -f -o cat  # msg="heartbeat accepted" once Tor is ready
```

`SHADENET_NETWORK=sepolia` reads `network/sepolia/deployment.json` and fills everything a node
needs to join: the Elder onion and signer, the staked-root contract, RPC endpoints, deploy block,
tiers, epoch, root freshness, payload budget, accepted proof artifacts, and `SHADE_TREE_REF` set
to the record's immutable node commit. Anything you set explicitly wins. The node admits staked
members; add `SHADE_TREE_MEMBERS_FILE=<file>` to also admit an invited set.

Secrets are systemd credentials: every unit carries `ImportCredential=SHADE_TREE_*`, and
`SHADE_TREE_CREDENTIALS_FROM` copies `SHADE_TREE_*` files into `/etc/credstore` (root, 0600).
The process reads them from `$CREDENTIALS_DIRECTORY`; they never appear in `Environment=`,
`systemctl show` or `/proc/<pid>/environ`. To rotate a key, replace the file in `/etc/credstore`
and restart the unit.

The bootstrap also installs a pinned, checksum-verified Node.js (`SHADE_TREE_NODE_VERSION`,
default 24.20.0) and caps journald (`SHADE_TREE_JOURNAL_MAX_USE=500M`,
`SHADE_TREE_JOURNAL_RETENTION=14day`). Optional: `SHADE_TREE_GATEWAY_REGION=<na|sa|eu|af|as|oc|aq|unknown>`.

### Add the next node on a second provider / ASN

The current disposable v4 research canopy spans three regions but one provider and ASN. Before
adding another long-lived node, place it on a different provider network so one DigitalOcean or
AS14061 incident cannot remove the whole canopy. This changes failure independence; it does not by
itself make the anonymity set larger or the untrusted testnet artifacts production-safe.

Use a fresh Ubuntu 24.04 host with a dedicated public address, root or passwordless `sudo`, outbound
traffic allowed, and **only TCP 22 from the reviewed operator CIDR inbound**. Do not expose the
gateway, heartbeat, or metrics ports. Record the provider account owner, region, instance size,
admin CIDR, abuse contact, teardown method, and identity-backup location before bootstrap.

| Target | Image / access | Provider firewall | Operator note |
|---|---|---|---|
| Hetzner Cloud | Ubuntu 24.04, SSH key, non-root sudo user or root | inbound 22/tcp from the operator `/32`; outbound allow | Record the project owner and server rescue path. |
| OVHcloud VPS | Ubuntu 24.04, SSH key | provider firewall plus host UFW with the same SSH-only rule | Record the control-panel owner and reinstall/recovery path. |
| Bare metal / colocated | Ubuntu 24.04, remote-console access, dedicated egress address | upstream ACL plus host UFW; no management subnet reachable from egress | Keep BMC, storage, validator, wallet, and authenticated RPC networks physically or logically separate. |

Before announcing, verify the address is not in the Elder provider's ASN. Run this from the
operator workstation and save the returned organization string in the deployment receipt:

```bash
curl -fsS "https://ipinfo.io/<new-node-public-ip>/org"
```

Then use gateway-only mode against the existing v4 Elder. Fetch the bootstrap script from the same
reviewed immutable ref that `SHADE_TREE_REF` names; do not mix `main` at download time with an older
service checkout:

```bash
export SHADE_TREE_REF=<reviewed-tag-or-commit>
curl -fsSL "https://raw.githubusercontent.com/dmarzzz/shade-tree-node/$SHADE_TREE_REF/packages/node/bootnode/deploy/bootstrap.sh" \
  -o /tmp/shade-tree-bootstrap.sh
sudo env \
  SHADE_TREE_REF="$SHADE_TREE_REF" \
  SHADE_TREE_BOOTNODE_ONION=<v4-elder.onion> \
  SHADE_TREE_BOOTNODE_SIGNER=<pinned-canopy-signer> \
  SHADE_TREE_MEMBERS_FILE=/root/operator-members.json \
  SHADE_TREE_GATEWAY_REGION=<na|sa|eu|af|as|oc|aq|unknown> \
  bash /tmp/shade-tree-bootstrap.sh
```

`SHADE_TREE_BOOTNODE_SIGNER` is printed into the client handoff; the heartbeat authenticates its own
announcement and does not trust that value. If the Elder requires staked operator admission, fund
and register a provider-specific operator key with `shade-tree register-gateway`, then load the
heartbeat signing key from a root-only environment file as described above. Do not reuse a slash or
operator hot key merely because two nodes share an owner.

Finish by checking `shade-tree-heartbeat` reports `accepted`, the signed canopy directory adds exactly the new
Protocol v4 onion, the node's `/readyz` is healthy on loopback, all non-SSH clearnet ports remain
closed, and a real invited CONNECT returns the new provider address. Give the provider abuse contact
a concise description: the public IP is an access-gated HTTPS CONNECT egress; complaints identify
the node address, not the private member behind an RLN proof. Preserve logs under the project's
traffic-metadata limits and follow [INCIDENT.md](INCIDENT.md) rather than promising attribution.

### By hand

If you did not use `bootstrap.sh` (bringing your own host, or a non-systemd setup):

### a. Mint an onion identity

```bash
shade-tree-node keygen tor/hs-gateway --label gateway
```

This writes Tor's HS key files (`hs_ed25519_secret_key`, `hs_ed25519_public_key`,
`hostname`) plus `identity.local.json` (the announce-signing seed) into the dir. Point
your Tor daemon's `HiddenServiceDir` at it with `HiddenServicePort 80 127.0.0.1:8443`.

### b. (Optional) stake the operator

Only needed for a `--admission stake` bootnode, or to fund the address that pays gas
to slash member over-spenders. Stake binds to the operator **address**, never to an
onion (one stake can back rotating onions).

```bash
read -s SHADE_TREE_REGISTER_KEY
SHADE_TREE_REGISTER_KEY="$SHADE_TREE_REGISTER_KEY" \
shade-tree register-gateway \
  --gateway-registry 0x<GatewayRegistry> \
  --rpc-url https://<rpc-endpoint>
unset SHADE_TREE_REGISTER_KEY
```

`--bond` is optional (defaults to the on-chain `BOND()`). The command is a no-op if
the operator is already staked. Paste the funded operator key at the hidden prompt; the
one-shot environment assignment keeps its value out of argv and `unset` clears it afterward.

### c. Run the gateway and heartbeat

```bash
shade-tree-node node                                       # the egress; verifies proofs, tunnels :443

shade-tree-node heartbeat \
  --bootnode <bootnode-onion> \
  --identity tor/hs-gateway/identity.local.json
```

For a staked bootnode, add the operator key so the heartbeat signs the durable
onion<->operator authorization:

```bash
read -s SHADE_TREE_GW_OPERATOR_KEY
SHADE_TREE_GW_OPERATOR_KEY="$SHADE_TREE_GW_OPERATOR_KEY" shade-tree-node heartbeat \
  --bootnode <bootnode-onion> \
  --identity tor/hs-gateway/identity.local.json
unset SHADE_TREE_GW_OPERATOR_KEY
```

The final `unset` runs after the heartbeat stops. For a durable service, load the key from the
root-readable environment file described below instead of placing it in a command or shell history.

The heartbeat re-announces every `--interval` seconds (default 300). Confirm you are
listed:

```bash
curl --socks5-hostname 127.0.0.1:9050 http://<bootnode-onion>/directory
```

---

## 3. Day-2 operations

### Restart without dropping a connection

A gateway restart used to refuse every connection Tor handed it for the 4 to 5 s a cold start
takes, and a client whose stream landed in that window saw a failed fetch. With **socket
activation** systemd owns the loopback listening socket and hands it to every gateway process, so
those connects queue in the kernel backlog and the new process serves them: a pause of a few
seconds instead of a refusal, and no onion descriptor is republished because Tor never restarts.

Measured on staging node-06 on 2026-10-01 (`systemctl restart shade-tree-gateway`, a local
connect probe on the gateway port at 4/s for 40 s, restart at t=10 s):

| | process absent | refused connects | client stream in the window |
|---|---|---|---|
| before (self-binding) | 4 to 5 s | 16 to 20 of 160 samples per restart | refused |
| after (socket activation) | 4 to 5 s (unchanged) | 0 of 141, 0 of 160 (two restarts) | queued, served by the new process (a session init sent during the absence opened its book 1.7 s after "gateway up") |

The process absence itself (Node start plus the on-chain root replay) is unchanged; what
changed is that nobody is turned away during it.

Turn it on when you bootstrap (or re-run bootstrap on an existing box; the first enablement stops
the self-binding gateway once so the socket can take the port, after that restarts are warm):

```bash
SHADE_TREE_SOCKET_ACTIVATION=1 ... bootstrap.sh            # renders shade-tree-gateway.socket
systemctl status shade-tree-gateway.socket                  # active (listening) 127.0.0.1:8443
journalctl -u shade-tree-gateway -g socketActivation        # "gateway up ... socketActivation:true"
```

Then a code roll or a config change is just `systemctl restart shade-tree-gateway`. The Ansible
role (`deploy/v4`) sets `shade_tree_socket_activation: true` for the fleet. The in-flight tunnels
of the old process still drain for `SHADE_TREE_SHUTDOWN_TIMEOUT_MS` (10 s) before it exits.

### Drain for maintenance

For anything longer than a restart (kernel upgrade, moving the box), announce it first so clients
route around the node instead of timing out on it:

```bash
shade-tree-node drain on --wait      # flag file -> heartbeat announces `draining: true` in its
                                     # signed caps within 2 s; /readyz turns 503; --wait returns
                                     # after the announce plus one directory refresh (60 s)
systemctl stop shade-tree-gateway    # or whatever the maintenance is
...
systemctl start shade-tree-gateway
shade-tree-node drain off            # announced on the next poll; clients pick it again
shade-tree-node drain status         # exit 0 while draining
```

The flag is a file (`SHADE_TREE_DRAIN_FILE`, default `/opt/shade-tree/deploy-state/draining`);
create it as root, the service user only reads it. A draining node stays listed and keeps serving
whoever still picks it (both SDKs treat it like health `down`: last resort only), so a client is
never stranded. The heartbeat's `shade_tree_heartbeat_draining` gauge and an info alert show it.

### Alerts without Prometheus

The node evaluates the conditions from `monitoring/alerts.yml` in-process and POSTs one JSON
document per transition to a webhook, repeating a still-firing alert every 4 h:

```bash
# in the gateway and heartbeat units (bootstrap renders both when set):
SHADE_TREE_ALERT_WEBHOOK=https://hooks.slack.com/services/...   # or a Discord / Matrix hookshot URL
SHADE_TREE_ALERT_WEBHOOK_FORMAT=slack                            # generic (default) | slack | discord | matrix
```

Heartbeat: `HeartbeatStale` (no Elder accepted an announce for 3 intervals), `HeartbeatNeverAccepted`,
`EgressDown`, `ElderPartial` (some Elders refuse), `Draining`. Gateway: `RootSourceDegraded`,
`RpcEndpointFailing` (3+ failovers in 15 min), `HighDropRate` (>50 % drops over 20+ tunnels in
15 min), `Draining`, plus `GatewayStarted` / `GatewayStopping` lifecycle notices. Delivery is
counted in `shade_tree_alert_webhook_total{result}`; a dead webhook is logged once a minute and
never blocks the node. Payload shapes and a hookshot template are in `monitoring/README.md`.

For dashboards, `monitoring/compose/` runs Prometheus + Grafana on the host network with the
rules and the node dashboard preloaded: `cd monitoring/compose && docker compose --profile monitoring up -d`,
then http://127.0.0.1:3000.

### Operator SLO

What a single node promises the canopy, and what the alerts above watch: a heartbeat accepted by
at least one Elder Tree every 5 min (so the node never ages out of the 15 min directory TTL);
`/readyz` 200 except while draining; a planned restart invisible to clients (socket activation) and
a planned stop announced at least one directory refresh ahead (drain). The public canopy page
stays aggregate on purpose (no per-node identity leaves the canopy), so check your own node against
this with `/readyz`, `shade_tree_heartbeat_last_success_timestamp_seconds` and
`shade_tree_heartbeat_draining` on the loopback metrics listeners, the webhook alerts, or the
Grafana dashboard in `monitoring/compose/`.


### Health

```bash
systemctl status shade-tree-bootnode shade-tree-gateway shade-tree-heartbeat

# over Tor (droplet SOCKS = 9050):
curl --socks5-hostname 127.0.0.1:9050 http://<bootnode-onion>/health      # liveness + count + admission
curl --socks5-hostname 127.0.0.1:9050 http://<bootnode-onion>/directory   # current signed directory

# local sanity (node, tor, deps, keys):
shade-tree-node doctor
```

`shade-tree-node doctor` is read-only; it flags a missing Tor daemon, missing deps, missing onion
identity, and whether on-chain mode is configured.

### Operator output

```bash
journalctl -u shade-tree-gateway   -f -o cat
journalctl -u shade-tree-bootnode  -f -o cat
journalctl -u shade-tree-heartbeat -f -o cat
```

The bootstrap writes newline-delimited JSON and disables decorative output for
systemd. Each record has `ts`, `level`, `component`, and `msg`, plus bounded
fields relevant to the event. Send those records directly to journald, Loki, or
another JSON-aware collector.

Direct terminal runs default to compact, colored output. Once a role is ready,
it grows one small ASCII Shade Tree and prints its local listen and metrics
details. The tree appears only on an interactive TTY. It never appears in JSON,
CI, a pipe, or a service log.

```bash
# Interactive operator view with the startup tree.
shade-tree-node node --log-level debug --log-format pretty --banner --metrics-port 9101

# One JSON object per line, with no tree.
shade-tree-node node --log-format json --no-banner

# Warnings and errors only.
shade-tree-node node --quiet
```

Levels have a narrow purpose:

- `debug` covers bounded tunnel outcomes, selection, and routing details.
- `info` covers startup, readiness, configuration state, and state changes.
- `warn` covers recoverable degradation that needs operator attention.
- `error` covers a failed role or operation.

Per-tunnel and payment logs do not include destinations, selected onion
addresses, nullifiers, external nullifiers, member secrets, or payment
authorizations. Debug logs keep the same traffic-metadata boundary. Service
configuration can still name public contract addresses or the role's own onion.
Known secret fields and credentials in URLs are redacted as a second line of
defense. Do not add raw request objects to log fields.

Configure this with `SHADE_TREE_LOG_LEVEL=debug|info|warn|error|off`,
`SHADE_TREE_LOG_FORMAT=auto|pretty|text|json`, and
`SHADE_TREE_BANNER=auto|always|never`. `auto` uses pretty logs and the tree on a
TTY, then JSON everywhere else. `--banner` forces the tree for non-JSON output;
`--no-banner` suppresses it. The tree follows the `info` threshold, so
`--quiet` suppresses it too.

### Local metrics

The bootstrap gives each role a separate loopback-only Prometheus listener:

| Role | Local endpoint |
|---|---|
| Elder Tree | `http://127.0.0.1:9100/metrics` |
| Shade Tree node | `http://127.0.0.1:9101/metrics` |
| Registrar, when enabled | `http://127.0.0.1:9102/metrics` |
| Heartbeat | `http://127.0.0.1:9103/metrics` |

```bash
curl --fail http://127.0.0.1:9101/readyz
curl --fail http://127.0.0.1:9101/metrics
```

Direct invocations leave metrics off unless a port is set. Use
`--metrics-port` for the Elder Tree, node, registrar, or Proxy. The heartbeat
uses `--heartbeat-metrics-port`. Every listener is hard-bound to loopback and is
separate from the onion-mapped protocol port. Never publish or Tor-map it.

The metrics expose process health, bounded outcomes, and latency without
destination, onion, nullifier, operator, contract-address, or request-ID
labels. They stay on the operator machine and are never sent to the Elder Tree
or public canopy. See [monitoring/README.md](../monitoring/README.md) for the full
series list, scrape config, dashboard, alerts, and retention guidance.

---

## 4. Key management

### One operator key (opt-in)

The three on-chain role keys (`SHADE_TREE_SLASH_KEY`, `SHADE_TREE_GW_OPERATOR_KEY`,
`SHADE_TREE_REGISTRAR_KEY`) can derive from ONE 32-byte seed with HKDF-SHA256, so a new operator
backs up and rotates a single secret (`scripts/operator-keys.mjs`):

```bash
node scripts/operator-keys.mjs generate --out ~/operator.seed          # 0600, refuses overwrite
node scripts/operator-keys.mjs show --seed ~/operator.seed             # the three addresses to fund / stake
node scripts/operator-keys.mjs derive --seed ~/operator.seed --out-dir /root/creds
SHADE_TREE_CREDENTIALS_FROM=/root/creds ... bootstrap.sh               # installs them into /etc/credstore
```

Derivation is one-way (a leaked role key does not reveal the seed or the other roles) and
deterministic (restoring the seed restores the same addresses). Rotating means a new seed, a new
`derive`, re-staking the operator and re-funding the slasher, same as with three separate keys.
Independently managed keys keep working unchanged.

Three secrets. All are gitignored (`identity.local.json`, `hs_ed25519_secret_key`,
`bootnode-signer.key`) and never leave the box on their own.

| secret | where (droplet) | what it is |
|---|---|---|
| gateway onion seed | `deploy-state/gateway-hs/identity.local.json` (+ Tor's copy in `/var/lib/tor/shade-tree-gateway/`) | the 32-byte seed behind the onion; signs announces. Losing it loses the onion address. |
| bootnode onion seed | `deploy-state/bootnode-hs/identity.local.json` (+ `/var/lib/tor/shade-tree-bootnode/`) | same, for the bootnode onion. |
| bootnode signer key | `deploy-state/bootnode-signer.key` | the `{pub,priv}` that signs the directory. The `pub` is what clients pin as `--dir-signer`. |
| operator EOA key | operator's wallet (env `SHADE_TREE_GW_OPERATOR_KEY` / `SHADE_TREE_REGISTER_KEY`, `SHADE_TREE_SLASH_KEY`) | funds the stake and pays slash gas. Keep it off the box where possible. |

Locally (non-bootstrapped) the same files live under `tor/hs*/identity.local.json` and
`bootnode/bootnode-signer.key`.

### Backup

`shade-tree-node backup` / `shade-tree-node restore` (`scripts/backup.mjs`, full guide in
[BACKUP.md](BACKUP.md)) encrypt the onion seeds (`identity.local.json`,
`hs_ed25519_secret_key`) and the bootnode signer key into one tamper-evident file
(scrypt + AES-256-GCM, Node crypto only, no `gpg` needed). The passphrase is read
**only** from `SHADE_TREE_BACKUP_PASSPHRASE`, never from argv, never logged.

```bash
export SHADE_TREE_BACKUP_PASSPHRASE='…a long, unique passphrase…'
sudo -E node /opt/shade-tree/packages/node/bin/shade-tree.mjs backup /opt/shade-tree/deploy-state shade-tree-keys-$(date +%F).shade-tree-backup
# then move the .shade-tree-backup file to an off-box, encrypted-at-rest location.

# on a fresh box, before starting the units:
sudo -E node /opt/shade-tree/packages/node/bin/shade-tree.mjs restore shade-tree-keys-<date>.shade-tree-backup /opt/shade-tree/deploy-state   # --force to overwrite
```

Restore lays the files back with `0600`/`0700` perms; the onion address and pinned
signer are preserved, so clients keep working. To prove the restored key really is the
same onion before cutting over, use `scripts/onion-identity.mjs`
([ONION-IDENTITY.md](ONION-IDENTITY.md)). The operator EOA key is backed up with your
normal wallet backups, not here.

---

## 5. Respond to a member over-spend / slash

An over-spend is a member reusing a per-epoch rate slot: two RLN signals under the same
nullifier with distinct evaluation points. The gateway detects it cryptographically and
slashes automatically. No operator action is required for the slash itself; your job is
to confirm it landed.

What the node logs for the slash lifecycle:

```
SLASH tx 0x<hash> commitment=0x0123456789abcd.. (waiting)
SLASH mined block <n> commitment=0x0123456789abcd..
```

At `debug`, the rejected tunnel has the bounded reason
`over-spend-slashed`. Subsequent attempts use `rate-slashed`. The node does not
log the nullifier or destination.

If slashing is not configured you instead see a dry-run and **no on-chain tx**:

```
slash: DRY-RUN (set SHADE_TREE_SLASH_KEY + deployed.local.json/SHADE_TREE_GROUP_CONTRACT to submit on chain)
SLASH (dry-run) commitment=0x0123456789abcd..
```

To slash for real, the gateway needs `SHADE_TREE_SLASH_KEY` (a hot key, separate from any
member secret) and a slash contract (`SHADE_TREE_SLASH_CONTRACT`, or `contracts/deployed.local.json`);
`ethers` must be installed. Optional `SHADE_TREE_SLASH_RECEIVER` sets who receives the bond
(defaults to the slasher wallet).

Verify:

```bash
journalctl -u shade-tree-gateway | grep SLASH          # find the tx hash
# then confirm on chain with your explorer or:
cast tx 0x<hash> --rpc-url https://<rpc-endpoint>   # foundry; check it was mined and reverted=false
```

Confirm the member's stake in `StakedReputationSet` moved to the receiver, and that the
over-spending member can no longer egress (repeated `DROP rate-slashed`).

### Cross-fleet replay defense (shared nonce tally — T-FEAT-20)

Each gateway defends itself against an exact-envelope replay with a per-gateway
seen-envelope cache (T-FEAT-12): a captured envelope resent to the **same** gateway
outside the honest-retry window (`SHADE_TREE_REPLAY_WINDOW_MS`, default 5s) is dropped
`replayed-envelope`. That cache is local, so a non-colluding fleet had no shared
spent-set — a malicious relay could fan one captured envelope to **peer** gateways and
each would serve it once.

The optional **shared nonce tally** (`packages/node/gateway/fleet-tally.mjs`) reduces that replay
window on a best-effort basis. Gateways share a per-epoch spent-**nullifier** tally.
Gateway A publishes only after the destination TCP connection succeeds, then gateway B
rejects the same envelope `replayed-envelope` once it receives the tally. DNS and
pre-connect failures remain eligible for cross-node failover. A tally-based rejection
logs `scope=fleet`.

- **What crosses the wire, and why it is safe.** Only the pair `(nullifier, epoch)` is
  shared — never member identity/commitment, never `share.y` (the secret a slash
  reconstructs from), never the egress `target`, never `share.x` or the nonce. An RLN
  nullifier is per-epoch, per-tunnel, and pseudorandom (unlinkable to the member — the
  same property that already lets one gateway dedup on it without learning who the member
  is), so sharing it adds no linkability beyond what the admitting gateway already had. A
  peer learns only "some request with nullifier N happened in epoch E." Because `share.y`
  never leaves a gateway, the tally is **not** a slashing/deanonymization side channel.
- **Slashing stays local.** A slash needs two shares under one nullifier; since `share.y`
  is not shared, a peer that has received the first gateway's tally rejects a distributed
  over-spend, but concurrent attempts or a failed push can still pass at different
  gateways. Slashing occurs only where both shares land. That is the intended privacy
  trade: gossiping shares would leak the bytes that reconstruct an identity.
- **Fail-open.** A gateway that cannot reach the tally degrades to the per-gateway
  T-FEAT-12 defense and keeps serving — the tally is defense-in-depth, never an admission
  authority, so a partition or a broken peer cannot deny legitimate members.
- **Off by default.** No shared transport is wired unless one is configured. With no
  `SHADE_TREE_FLEET_TALLY_PEERS` set the gateway runs **exactly** the per-gateway behavior
  (byte-identical to T-FEAT-12). When the tally is active the gateway logs `fleet tally: ON`
  at startup. A client can reuse the same envelope across nodes until one destination
  connection succeeds. That success triggers an asynchronous announcement; peers reject
  later replays after receiving it. This is not an atomic fleet spent-set: concurrent
  attempts, dropped pushes, and partitions remain fail-open.

#### Real cross-host transport (T-FEAT-20b — HTTP push)

The tally speaks to the fleet through an injectable `{ publish(nullifier, epoch),
subscribe(cb) }` seam. The bundled real transport (`makeHttpTallyTransport` in
`packages/node/gateway/fleet-tally.mjs`) is a tiny **HTTP push**: each gateway exposes an inbound
announcement endpoint and POSTs `{"nullifier":…,"epoch":…}` to each **configured peer**
gateway. It is a direct **1-hop** push to a fixed peer set — not a forwarding flood — so a
nullifier crosses the wire at most once per peer per established egress (no gossip storm, no loops: the
inbound handler only records locally, it never re-publishes).

- **Enable it** with `SHADE_TREE_FLEET_TALLY_PEERS` (comma-separated peer gateways) and the same
  randomly generated `SHADE_TREE_FLEET_TALLY_TOKEN` on every tally peer. The token must be 32 to
  256 printable non-space characters. Missing or invalid authentication leaves the optional tally
  off, so a half-configured mesh cannot expose an unauthenticated intake endpoint. A peer that is
  an `.onion:port` is reached **over Tor** (reusing the bootnode fetch path — no exit node, the
  peer never learns this gateway's IP); a bare `host:port` peer is reached with a plain HTTP
  POST and sends the bearer token in cleartext. Use that form only on localhost or a trusted,
  encrypted private link. Set `SHADE_TREE_FLEET_TALLY_LISTEN` (`host:port` or
  `port`, default `127.0.0.1:0`) for this gateway's inbound endpoint — behind Tor, map the
  gateway's onion to that local port. The bundled bootstrap does this on virtual port `8879` when
  `SHADE_TREE_FLEET_TALLY_PEERS` and `SHADE_TREE_FLEET_TALLY_TOKEN` are set. It accepts onion peers
  only and keeps the shared token in a root-only environment file.
  `SHADE_TREE_FLEET_TALLY_PATH` overrides the endpoint path
  (default `/fleet-tally`). For a full mesh, list the other gateways as each gateway's peers
  (federation, T-FEAT-1, already discovers them).
- **Trust model — peers are semi-trusted.** Peers are fleet gateways the operator configured,
  not the open internet, but the transport assumes any peer can be down, slow, or malicious
  and bounds the damage:
  - **Fail-open, both directions.** Outbound POSTs are fire-and-forget with a per-peer timeout
    (`SHADE_TREE_FLEET_TALLY_TIMEOUT_MS`, default 4s); a refused / 401 / 500 / slow / partitioned peer is
    swallowed and **never** blocks admission — `publish()` returns synchronously and the
    gateway proceeds on its local defense. Missing/wrong bearer credentials are rejected with
    401 and logged by the sender; inbound malformed / oversized bodies are dropped (400/413),
    never crash the endpoint. The listener has fixed header, request, keep-alive, header-size,
    and 256-connection limits. Outbound work is capped at four in-flight pushes per peer and 128
    total; excess announcements drop fail-open instead of accumulating sockets.
  - **Only two fields ever read.** The inbound handler reads **only** `nullifier` and `epoch`;
    any extra key a peer stuffs into the body is ignored, never stored, never acted on — the
    same privacy invariant as above, now enforced at the wire boundary.
  - **Bounded blast radius.** Both public fields must be canonical decimal BN254 field elements.
    State is capped per epoch (50,000 entries by default), across epoch buckets (4), and in total
    (100,000). Expired buckets are pruned before new state allocates. Past any cap recording simply
    stops: lose dedup, never deny. A malicious authenticated peer therefore cannot grow memory
    without bound. It cannot cause a fleet-wide
    outage. A live nullifier is `H(identitySecret, externalNullifier)`, per-tunnel
    pseudorandom and unpredictable, so a flooder cannot pre-image a **future** honest member's
    nullifier to get it pre-rejected — its garbage collides with nothing real, and the only
    harm stays on the flooder. Response reads are byte-capped against an unbounded reply.

---

## 6. Rotate or retire a gateway

Retiring a **staked** gateway is a two-step on-chain exit plus stopping the units. The
`shade-tree` wrappers (`group/exit-gateway.mjs`) drive `GatewayRegistry`
(`contracts/GatewayRegistry.sol`); the equivalent raw `cast` calls are shown for reference.
All three read the on-chain state first and refuse a call the contract would revert
(`NotStaked` / `AlreadyExiting` / `NotExiting` / `StillBonded`), and every sending
command takes `--dry-run` (prints target + calldata + an `eth_call` simulation, broadcasts
nothing). Set `SHADE_TREE_RPC_URL` / `SHADE_TREE_GATEWAY_REGISTRY` (or `--rpc-url` / `--gateway-registry`).
The operator key is the one that called `register()`; hand it over via `--account <name>`
(Foundry encrypted keystore, `cast wallet import <name> --interactive`; password from
`SHADE_TREE_KEYSTORE_PASSWORD` or a no-echo prompt), `--keystore <json>`, `--key-file <0600 file>`,
or `SHADE_TREE_REGISTER_KEY` in the environment — never on the command line.

0. Look before you leap (read-only, no key needed):

   ```bash
   shade-tree-node gateway-status --operator 0x<operator> --rpc-url https://<rpc-endpoint> --gateway-registry 0x<GatewayRegistry>
   ```

1. Start the unbonding clock (operator-only). You stay slashable for the whole
   `UNBONDING` window, so you cannot exit-then-dodge a slash:

   ```bash
   shade-tree-node exit-gateway --account shade-tree-operator --rpc-url https://<rpc-endpoint> --gateway-registry 0x<GatewayRegistry> --dry-run
   shade-tree-node exit-gateway --account shade-tree-operator --rpc-url https://<rpc-endpoint> --gateway-registry 0x<GatewayRegistry>
   # raw equivalent: cast send 0x<GatewayRegistry> "initiateExit()" --account shade-tree-operator --rpc-url https://<rpc-endpoint>
   ```

   The command prints `withdrawable at <unix> (<ISO>)`; `shade-tree-node gateway-status` shows the same
   (raw: `cast call 0x<GatewayRegistry> "withdrawableAt(address)(uint256)" 0x<operator>`).
   A stake-admission bootnode stops admitting this operator on its next refresh
   (`SHADE_TREE_STAKE_CACHE_MS`), so do step 2 right away.

2. Stop the units so the gateway stops announcing:

   ```bash
   systemctl disable --now shade-tree-heartbeat shade-tree-gateway
   # keep shade-tree-bootnode running if this box is also the bootnode
   ```

3. The bootnode holds soft state with a TTL (`--ttl`, default 900s). Once the heartbeat
   stops, the entry ages out and clients stop selecting it. Clients cache the
   last-known-good directory, so the fleet degrades gracefully.

4. After the `UNBONDING` window, reclaim the bond (`--recipient` defaults to the operator
   address; point it at a cold address if you like). Before the window elapses the
   command refuses with `StillBonded until <ISO> — N s to go` and sends nothing:

   ```bash
   shade-tree-node withdraw-gateway --recipient 0x<recipient> --account shade-tree-operator --rpc-url https://<rpc-endpoint> --gateway-registry 0x<GatewayRegistry> --dry-run
   shade-tree-node withdraw-gateway --recipient 0x<recipient> --account shade-tree-operator --rpc-url https://<rpc-endpoint> --gateway-registry 0x<GatewayRegistry>
   # raw equivalent: cast send 0x<GatewayRegistry> "withdraw(address)" 0x<recipient> --account shade-tree-operator --rpc-url https://<rpc-endpoint>
   ```

**Rotating** an onion (new address, same operator/stake): mint a new identity
(`shade-tree-node keygen ...`), point Tor and the heartbeat at it, and let the old entry TTL out.
No re-staking needed; the stake is keyed to the operator address, not the onion.

An **unstaked** (`--admission open`) gateway is just steps 2-3: stop the units, let the
TTL expire.

---

## 7. Config reference

Full surface: [CONFIG.md](CONFIG.md). The knobs an operator actually changes:

| Env var | Flag | What it does |
|---|---|---|
| `SHADE_TREE_BOOTNODE_ADMISSION` | `--admission` | `open` (onion-control only) or `stake` (require live operator bond). |
| `SHADE_TREE_BOOTNODE_TTL` | `--ttl` | Seconds a gateway stays live without re-announcing (default 900). |
| `SHADE_TREE_BOOTNODE_HEARTBEAT` | `--interval` | Re-announce interval (default 300). |
| `SHADE_TREE_GW_WEIGHT` | `--weight` | Selection weight advertised for this gateway (default 100). |
| `SHADE_TREE_STAKE_MODE` | `--stake-mode` | `onchain` (eth_call `isStaked`) or `mock` (chainless dev). |
| `SHADE_TREE_GATEWAY_REGISTRY` | `--gateway-registry` | `GatewayRegistry` address (required for onchain stake + `register-gateway`). |
| `SHADE_TREE_ADMIT` | `--admit` | Admission policy (T-FEAT-9): `invited[,staked][,paid]`, default `invited` (max-anon) — the ONLY root sources + slash targets; a named path without its contract refuses to start. Set the same on the heartbeat (advertised as signed `caps.admits`). `SHADE_TREE_ROOTS` = deprecated alias. See "Choose what you admit and what you sell" below. |
| `SHADE_TREE_GROUP_CONTRACT` | `--group-contract` | `StakedReputationSet` address (comma list allowed); read ONLY when `SHADE_TREE_ADMIT` includes `staked`. |
| `SHADE_TREE_PAY_PROTOCOLS` | `--pay-protocols` | Registrar rails served + advertised: `x402,mpp` (default) / `x402` / `mpp` (T-FEAT-9). |
| `SHADE_TREE_SLASH_KEY` | `--slash-key` | Hot key that submits `slash()` txs; unset = dry-run. |
| `SHADE_TREE_SLASH_CONTRACT` | `--slash-contract` | Slash contract address (independent of the root source). |
| `SHADE_TREE_SLOTS` | (none) | Default-tier per-epoch rate cap `K` (nullifiers before over-spend). Must match the limit members' leaves were enrolled with. |
| `SHADE_TREE_SLOT_STATE_DIR` | (none) | Proxy/SDK/Rust client state root for atomic RLN slot allocation. Defaults to the OS user-state directory and is namespaced by public member leaf. Empty/`off` is rejected; state corruption, unavailability, or a stale lock fails closed. |
| `SHADE_TREE_TIERS` | (none) | Reputation-tier limits this gateway knows, e.g. `8,32` (T-FEAT-8). Only used to name the right leaf when slashing an over-spender (`resolveSlashLeaf`); proofs carry no tier. Default = `SHADE_TREE_SLOTS`. See "Reputation tiers" below. |
| `SHADE_TREE_EPOCH_SECONDS` | `--epoch-seconds` | Epoch length (default 120). Must match client and gateway. |
| `SHADE_TREE_RPC_URL` | `--rpc-url` | JSON-RPC endpoint for all on-chain reads/writes. For `SHADE_TREE_ROOT_PROVIDER=light` it must serve `eth_getProof` at the finalized block (own node / archive-capable provider; public RPCs' proof windows are ~32 blocks, shorter than finality). |
| `SHADE_TREE_ROOT_PROVIDER` | `--root-provider` | `node` (trusted node, event reconstruction; default) or `light` (EIP-1186 storage proof of the on-chain `currentRoot`). |
| `SHADE_TREE_HELIOS_RPC_URL` | (none) | `light` only: local Helios verifying RPC (`http://127.0.0.1:8546` from `bootstrap.sh SHADE_TREE_HELIOS=1`). Set ⇒ the proof's block `stateRoot` is sync-committee verified and the RPC cannot lie about the root (only withhold); startup logs `stateRootSource: helios (sync-committee verified)`. Unset ⇒ `stateRootSource: rpc header (TRUSTED, …)`. See "Anchor the admission root to the sync committee" below and `docs/LIGHT-CLIENT.md`. |
| `SHADE_TREE_HELIOS_CHAIN_ID` | (none) | Decimal chain id Helios must report; unset = must equal the RPC's `eth_chainId`. Mismatch ⇒ refuses to start reading roots. |
| `SHADE_TREE_FROM_BLOCK` / `SHADE_TREE_FROM_BLOCKS` / `SHADE_TREE_LOGS_CHUNK` | (none) | `node` root provider + client leaf discovery: where the `eth_getLogs` event scan starts (one block for all sets / `<0xaddr>=<block>,…` per set; default = each set's deploy block from the network record) and how many blocks per call (default 10000, halved automatically when the RPC refuses a window). See "Public RPC log-range caps" below. |
| `SHADE_TREE_TOR_HOST` / `SHADE_TREE_TOR_PORT` | `--tor-host` / `--tor-port` | Local Tor SOCKS (droplet 9050, local dev 9250). |
| `SHADE_TREE_LOG_LEVEL` / `SHADE_TREE_LOG_FORMAT` | `--log-level` / `--log-format` | Operator output level and format. Defaults to `info` / `auto`; bootstrap uses `info` / `json`. |
| `SHADE_TREE_BANNER` | `--banner` / `--no-banner` | Show the one-time ASCII tree. `auto` shows it only on an interactive, non-JSON terminal. |
| `SHADE_TREE_METRICS_PORT` | `--metrics-port` | Separate loopback metrics listener for the Elder Tree, node, registrar, or Proxy. Unset or `0` is off for direct runs. |
| `SHADE_TREE_HEARTBEAT_METRICS_PORT` | `--heartbeat-metrics-port` | Separate loopback heartbeat metrics listener. Unset or `0` is off for direct runs. |
| `SHADE_TREE_FLEET_TALLY_PEERS` | (none) | Comma-separated peer gateways for the cross-fleet shared nonce tally (T-FEAT-20b). `.onion:port` peers use Tor; `host:port` uses plain HTTP. **Unset = off** (per-gateway behavior, byte-identical). The bootstrap accepts onion peers only and maps port 8879 by default. |
| `SHADE_TREE_FLEET_TALLY_TOKEN` | (none) | Required shared bearer secret for tally peers, 32..256 printable non-space characters. Generate independently of node/operator keys. Missing or invalid = tally stays off. Never log or put it in a URL. |
| `SHADE_TREE_FLEET_TALLY_LISTEN` | (none) | Inbound tally endpoint `host:port` (or bare `port`); default `127.0.0.1:0`. Behind Tor, map the gateway onion to this local port. |
| `SHADE_TREE_FLEET_TALLY_PATH` | (none) | Inbound tally endpoint path (default `/fleet-tally`). |
| `SHADE_TREE_FLEET_TALLY_TIMEOUT_MS` | (none) | Per-peer push timeout (default 4000). A slow/down peer is swallowed (fail-open), never blocks admission. |
| `SHADE_TREE_FLEET_TALLY_MAX_PER_EPOCH` | (none) | In-memory entries per external-nullifier bucket (default 50000, hard max 200000). Past the cap evidence is dropped fail-open. |
| `SHADE_TREE_FLEET_TALLY_MAX_EPOCHS` | (none) | In-memory external-nullifier buckets (default 4, hard max 16). |
| `SHADE_TREE_FLEET_TALLY_MAX_TOTAL` | (none) | Aggregate in-memory tally entries across buckets (default 100000, hard max 500000). |
| `SHADE_TREE_FLEET_TALLY` | (none) | Legacy flag; with no `SHADE_TREE_FLEET_TALLY_PEERS` it only logs a note and stays off (fail-open). |
| `SHADE_TREE_EGRESS_ALLOW` / `SHADE_TREE_EGRESS_DENY` | (none) | Egress policy (see §2). When `SHADE_TREE_EGRESS_ALLOW` is **set**, the heartbeat also advertises its concrete allowed ports as SIGNED capabilities (T-FEAT-10b) so clients can route by port. Unset = default `*:443` and **no** caps advertised. |
| `SHADE_TREE_DNS_TIMEOUT_MS` | (none) | Target DNS deadline in milliseconds (default 5000). Resolution checks every answer, rejects the hostname if any answer is non-public, then pins at most eight validated numeric results. Those candidates share one upstream-connect deadline and are tried in resolver order. `0` disables the DNS deadline. |
| `SHADE_TREE_ALLOW_PRIVATE_TARGETS` | (none) | Unsafe local-test escape hatch. Only exact value `1` permits private and special-purpose destination addresses; startup emits a warning. Never use on a network-connected node. |
| `SHADE_TREE_GATEWAY_REGION` | (none) | Coarse self-declared region bucket advertised in signed caps: one of `na sa eu af as oc aq unknown`. Continent-scale only (too coarse to fingerprint). Unset/invalid = omitted. |
| `SHADE_TREE_ZK_ARTIFACTS` | (none) | The ZK artifact sets (verification keys) this gateway ACCEPTS, as `<id>=<vkey path>[,<id>=<vkey path>...]` (T-HARD-8, `docs/CEREMONY.md` §6). `<id>` is content-derived (`rln-<sha256(vkey)[0:16]>`, = `testdata/zk-artifacts.lock.json` `circuits.rln.artifactId`) and MUST match the file, else the gateway refuses to start. Unset = the built-in `circuits/rln/verification_key.json` under its own id (byte-equivalent to a single-VK gateway) and **no** artifact caps advertised. When set, the accepted ids are advertised as SIGNED caps (`artifacts`). |
| `SHADE_TREE_ZK_ARTIFACT_LEGACY` | (none) | Which artifact id an envelope WITHOUT an `artifact` field (an un-upgraded client) means. Unset = the lock's `circuits.rln.previousArtifactId` if a ceremony has rotated the set, else the built-in id. If this id is not in `SHADE_TREE_ZK_ARTIFACTS`, such envelopes are rejected `artifact-retired:<id>` (precise, never `invalid-proof`). |
| `SHADE_TREE_ENVELOPE_TIMEOUT_MS` / `SHADE_TREE_TUNNEL_IDLE_TIMEOUT_MS` | (none) | Gateway slow-client limits: envelope deadline (default 30 s) and relay idle timeout (default 5 min). See "Endpoint hardening" below. |
| `SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES` | (none) | Combined payload ceiling per RLN epoch slot (default `41943040` = 40 MiB). Same-node retries share it; `0` disables. |
| `SHADE_TREE_MAX_CONNS` / `SHADE_TREE_MAX_CONNS_PER_NULLIFIER` | (none) | Gateway concurrent-connection caps: total (default 1024) and per nullifier (default 8). `0` = unlimited. |
| `SHADE_TREE_BOOTNODE_ANNOUNCE_RATE` / `SHADE_TREE_BOOTNODE_ANNOUNCE_BURST` | (none) | Bootnode GLOBAL announce token bucket (default 66.7/s, burst 1000 — sized from `SHADE_TREE_BOOTNODE_MAX_ENTRIES` and `SHADE_TREE_BOOTNODE_HEARTBEAT`; `docs/BOOTNODE.md`). |
| `SHADE_TREE_BOOTNODE_HEADERS_TIMEOUT_MS` / `_REQUEST_TIMEOUT_MS` / `_KEEPALIVE_TIMEOUT_MS` / `_MAX_HEADER_BYTES` | (none) | Bootnode HTTP slow-client limits (defaults 10 s / 30 s / 5 s / 8 KiB). |

### Public RPC log-range caps (eth_getLogs)

The `node` root provider (and the client's leaf discovery, `shade-tree leaves`) rebuilds a set's tree
from its event log with `eth_getLogs`. Every public / hosted RPC caps ONE such call — by block
range and/or result count — and answers with an error, not a partial result: publicnode
`exceed maximum block range: 50000`, Infura `query returned more than 10000 results` (and a
10k-block range), QuickNode `limited to a 10,000 blocks range`, Alchemy `Log response size
exceeded` (2k blocks on the free tier). Scanning "from block 0" against one of them fails on
the very first call — which is how both fleet gateways crash-looped at startup on 2026-08-17
after `SHADE_TREE_PAID_ACCESS_CONTRACT` was enabled (`docs/history/GO-LIVE-LOG-2026-08-17.md`,
`docs/INCIDENT.md` §5).

Since that night the gateway does three things on its own (`packages/node/lib/root-provider.mjs`):

- **Pages the scan.** `[from, head]` is split into `SHADE_TREE_LOGS_CHUNK` windows (default 10000,
  under every cap above; `head` is resolved to a number once so every page sees the same block); a
  window the RPC refuses is halved and retried (down to 8 blocks); pieces are concatenated in
  order. Finalized reads then continue incrementally (only the new blocks each refresh), so a
  long-lived gateway costs one small call per poll, not a re-scan of the history.
- **Starts at the deploy block.** Each contract's scan starts at its own deploy block from a
  committed network record's `deployBlocks`, including when the box pins
  `SHADE_TREE_GROUP_CONTRACT` / `SHADE_TREE_PAID_ACCESS_CONTRACT` by hand. Historical records
  can still supply this provenance without becoming runtime presets. Only a contract no record
  knows starts at 0 (still correct, just slower). Override per box with
  `SHADE_TREE_FROM_BLOCK=<block>` (all sets) or `SHADE_TREE_FROM_BLOCKS=0xSet=<block>,0xPaid=<block>`
  (`bootstrap.sh` passes both into the gateway unit when given).
- **Fails soft at startup.** If every chain source is unreadable at boot but `members.json` gives
  a root, the gateway STARTS with that root, logs `root source UNAVAILABLE at startup …` (with the
  fix hint), gauges `shade_tree_gateway_root_source_degraded{source="staked"} 1` or
  `shade_tree_gateway_root_source_degraded{source="paid"} 1`, and picks the chain roots up on the
  next successful poll (no restart). With no root at all it still refuses to start (an
  empty admission set is not a gateway; systemd's restart is the retry). Alert on the gauge.

If you see the error anyway: check `SHADE_TREE_RPC_URL` is the RPC you think, lower `SHADE_TREE_LOGS_CHUNK`
(some providers cap at 2k), or pin the start blocks. Your own node has no such cap.

### Anchor the admission root to the sync committee (optional, T-DEV-9b)

By default an on-chain gateway (`SHADE_TREE_GROUP_CONTRACT` set) trusts its RPC for the admission
root — fine when `SHADE_TREE_RPC_URL` is your own node. If it is a third-party RPC, run the Helios
light-client sidecar so the root is verified against Ethereum consensus instead:

```bash
SHADE_TREE_HELIOS=1 \
SHADE_TREE_HELIOS_CONSENSUS_RPC=https://lodestar-sepolia.chainsafe.io \   # a beacon API with the light-client endpoints
SHADE_TREE_RPC_URL=<execution RPC that serves eth_getProof at finalized> \
SHADE_TREE_GROUP_CONTRACT=0xFe48De8b9aCA4386DC31C845d579ae62f04f9d25 \   # rln-v4-tiers (on-chain root; network/sepolia/contracts.json)
  sudo bash packages/node/bootnode/deploy/bootstrap.sh          # composes with SHADE_TREE_BOOTNODE_ONION (gateway-only)
journalctl -u shade-tree-helios -f                       # 'consensus client in sync with checkpoint', then 'finalized block number=…'
journalctl -u shade-tree-gateway | grep stateRootSource  # expect: helios (sync-committee verified)
```

That installs the sha256-pinned `helios 0.11.1` release binary, a hardened `shade-tree-helios`
unit (loopback `:8546`), and sets `SHADE_TREE_ROOT_PROVIDER=light` + `SHADE_TREE_HELIOS_RPC_URL` on the
gateway unit, ordered after the sidecar. Optional: `SHADE_TREE_HELIOS_CHECKPOINT=0x<recent finalized
beacon block root>` to pin the weak-subjectivity checkpoint yourself (else Helios fetches one
from public checkpoint services), `SHADE_TREE_HELIOS_NETWORK` (`sepolia` default), `SHADE_TREE_HELIOS_PORT`.
Trust after this: the sync committee + that checkpoint; the RPC can withhold but not lie
(`docs/THREAT-MODEL.md`). If Helios is down or on the wrong chain the gateway refuses to
start reading roots (fail closed) and restarts until it is up. Full how-to, flags and the live
Sepolia receipt: `docs/LIGHT-CLIENT.md`; tunables: `packages/node/bootnode/deploy/README.md`.

### Reputation tiers (T-FEAT-8)

A member's per-epoch budget is the `userMessageLimit` baked into its leaf
(`docs/adr/0006-reputation-tiers.md`): `Poseidon2(Poseidon1(identitySecret), limit)`. One tree
holds every tier; the proof opens the leaf and range-checks the slot under its limit, so the
gateway needs NO per-tier config to enforce it — a leaf carrying limit 8 has no valid proof
for slot 8, and a member cannot forge a bigger limit (a different leaf, not in your set:
`wrong-group-root`). What you as operator decide is admission: which limit you admit for whom.

```bash
# member side (they run this; only the commitment reaches you):
shade-tree enroll --limit 32 --commitment-only        # -> leaf that commits to 32; they run SHADE_TREE_LIMIT=32
# operator side: admit the leaf exactly like a default one (members.json / register-onchain)
# gateway: tell the slash path which limits exist, so an over-spender's leaf resolves to its tier
export SHADE_TREE_TIERS=8,32
```

Limits are 1..65535 (the circuit's 16-bit range check; never admit more). With
`SHADE_TREE_TIERS` unset a tiered over-spender is still slashed, but the log names the default-tier
leaf (`slash: tier of the over-spent leaf not resolvable locally`). The current rln-v4
`StakedReputationSet` admits `register(commitment, limit)`, prices tiers with `bondFor(limit)`,
and resolves the enrolled limit during slashing. The retired rln-v3 contract remains tier-8 only.

### Choose what you admit and what you sell (T-FEAT-9, ADR [0008](adr/0008-per-gateway-admission-and-payment-choice.md))

Every gateway PROVIDER decides two things; the defaults are the maximum-anonymity mode.

**1. What you admit — `SHADE_TREE_ADMIT`.** The three admission paths, in ANONYMITY ORDER (most → least):

| path | root source | what a member's membership reveals |
|---|---|---|
| `invited` | `group/members.json` (`SHADE_TREE_MEMBERS_FILE`) — leaves you enrolled by hand | nothing on chain |
| `staked` | every `StakedReputationSet` in `SHADE_TREE_GROUP_CONTRACT` (comma list) | the staking wallet ↔ commitment (+ tier bond), public and permanent |
| `paid` | the `PaidAccessSet` in `SHADE_TREE_PAID_ACCESS_CONTRACT` | the buyer address → your address transfer (amount = tier price) + the `Inserted(commitment, limit)` |

```bash
# the default: invited ONLY -- even when env supplies contract addresses (opt in explicitly)
SHADE_TREE_ADMIT=invited shade-tree-node gateway
# admit staked members too
SHADE_TREE_ADMIT=invited,staked shade-tree-node gateway \
  --group-contract <v4-staked-set-address> --rpc-url <operator-rpc-url>
# admit everyone you can (what the pre-T-FEAT-9 union heuristic silently did)
SHADE_TREE_ADMIT=invited,staked,paid shade-tree-node gateway \
  --group-contract <v4-staked-set-address> --paid-access-contract <v4-paid-set-address> \
  --rpc-url <operator-rpc-url>
# on-chain only, no members.json at all
SHADE_TREE_ADMIT=staked shade-tree-node gateway \
  --group-contract <v4-staked-set-address> --rpc-url <operator-rpc-url>
```

Use a named network only when you maintain a current v4 runtime record for it. The legacy
`sepolia` contracts, bootnode, and signed directories are retired pre-v4 history and intentionally
are not a gateway configuration preset. Its separate `deployment.json` is a current research
receipt, not a complete runtime preset.

- The named paths are the ONLY root sources and the ONLY slash routing targets; a configured but
  un-admitted contract is never read. Startup prints the policy, then the sources: `admits:
  invited+staked+paid` / `roots: members.json + staked(0x…) + paid(0x…)` — read both.
- Fail closed: `SHADE_TREE_ADMIT=invited,staked` without a `StakedReputationSet` configured (or `paid`
  without a `PaidAccessSet`) refuses to start — never a silently smaller set. `SHADE_TREE_ADMIT` unset
  with contracts configured WARNs `SHADE_TREE_ADMIT is unset: admitting invited ONLY … set
  SHADE_TREE_ADMIT=invited,staked,paid` and runs invited-only.
- `SHADE_TREE_ROOTS=static,onchain` (T-FEAT-7) still works as a DEPRECATED alias (static→invited,
  onchain→staked+paid over what is configured) with a warning; move to `SHADE_TREE_ADMIT`.
- **Set the SAME value on the heartbeat unit.** The heartbeat advertises it as signed `caps.admits`
  so clients route only to gateways that admit their leaf source (a paid buyer never dials your
  invited-only gateway; an invited member with `--max-anon` dials ONLY invited-only gateways).
  `bootstrap.sh SHADE_TREE_ADMIT=…` renders both units; by hand, add `Environment=SHADE_TREE_ADMIT=…` to
  `shade-tree-gateway.service.d/` AND `shade-tree-heartbeat.service.d/` drop-ins and restart both. A heartbeat
  without `SHADE_TREE_ADMIT` advertises no policy: clients then assume you may admit anything and a
  mismatch costs them one `wrong-group-root` reject + failover (rollout compat, `docs/CLIENTS.md`).
- The demo fleet is heterogeneous on purpose (`network/sepolia/README.md`): gateway-1
  `invited,staked,paid` + registrar, gateway-2 `invited,staked` — so a paid buyer lands on
  gateway-1 only, and `--max-anon` refuses both (neither is invited-only).

**2. What you sell — `SHADE_TREE_PAY_PROTOCOLS`, your own registrar, your own `PaidAccessSet`.**
Selling is opt-in (`SHADE_TREE_REGISTRAR=1`, next section) and requires `paid` in `SHADE_TREE_ADMIT` (admit
what you sell; `bootstrap.sh` refuses otherwise). `SHADE_TREE_PAY_PROTOCOLS=x402,mpp` (default both) is
the rail subset THIS registrar serves — `x402` or `mpp` alone: a disabled rail gets no challenge,
is absent from `pay.protocols`, and its payload is refused `400 protocol-disabled` (the rails are
equal on the anonymity axis; pick by fees/tooling). A GATEWAY-ONLY box may run its own registrar
on its own gateway onion (`bootstrap.sh SHADE_TREE_REGISTRAR=1` with `SHADE_TREE_BOOTNODE_ONION` set:
`HiddenServicePort 8878` in the gateway HS block, `SHADE_TREE_REGISTRAR_ONION` = the gateway onion) and
its own `PaidAccessSet` (deploy one, `docs/ONCHAIN-DEPLOY.md`; `SHADE_TREE_PAID_ACCESS_CONTRACT` on both
the registrar and the gateway unit): you sell access on your own terms, no bootnode required. The
offer is advertised in your gateway's signed caps (`caps.pay`; heartbeat `SHADE_TREE_REGISTRAR_ADVERTISE=1`
+ `SHADE_TREE_PAY_*`, rendered by bootstrap) — and, on a bootnode box, in the bootnode's `/health` as before.

### Selling access via 402 (T-FEAT-7)

Members can *buy* a leaf instead of being enrolled by hand: `docs/PAYMENTS.md` "Shipped
2026-08-17". You run a **registrar** (`packages/node/payments/registrar.mjs`) next to the bootnode; it speaks
both HTTP-402 rails (x402 v2 and MPP), takes a stablecoin (EIP-3009: the buyer signs, *you*
submit and pay gas), and inserts the buyer's commitment into the on-chain `PaidAccessSet`
(`contracts/PaidAccessSet.sol`, operator-insert-only). Your gateways trust that set's root next
to the staked set's (`SHADE_TREE_PAID_ACCESS_CONTRACT` on the gateway unit; the multi-root gateway,
T-FEAT-7 2/3), so a buyer egresses with the ordinary RLN proof.

**You are the facilitator.** Nothing is outsourced: the registrar verifies the typed-data
signature and submits the transfer from your key. It needs ETH for gas (one settle tx ≈ 60k gas +
one insert ≈ 1.26M gas per sale on Sepolia), the stablecoin arrives at `SHADE_TREE_PAY_TO`
(default: the operator address).

Deploy (bootnode box shown; a gateway-only box works the same with `SHADE_TREE_BOOTNODE_ONION` set — the
registrar then rides the GATEWAY onion; `bootstrap.sh` is idempotent, re-run it with the tunables):

```bash
SHADE_TREE_REGISTRAR=1 \
SHADE_TREE_ADMIT=invited,paid                \   # T-FEAT-9: admit what you sell (add staked if you trust the staked set too)
SHADE_TREE_PAY_PROTOCOLS=x402,mpp            \   # T-FEAT-9: the rails you serve (default both; x402 or mpp alone is fine)
SHADE_TREE_PAID_ACCESS_CONTRACT=0x4e8C2Bf5d3c5454A04837401095fce2646484111 \   # network/sepolia/contracts.json contracts.paidAccessSet
SHADE_TREE_PAY_ASSET=<stablecoin>            \   # Sepolia USDC 0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238, or contracts.json payAsset (tUSD)
SHADE_TREE_PAY_PRICES=8=100000,32=400000     \   # atomic units per tier (0.10 / 0.40 with 6 decimals)
SHADE_TREE_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com \
  sudo -E bash packages/node/bootnode/deploy/bootstrap.sh
# the operator key is a SECRET: 0600 drop-in via stdin, never argv / unit file / log
sudo install -d -m 0755 /etc/systemd/system/shade-tree-registrar.service.d
printf '[Service]\nEnvironment=SHADE_TREE_REGISTRAR_KEY=%s\n' "$(cat /path/to/operator.key)" \
  | sudo install -m 0600 /dev/stdin /etc/systemd/system/shade-tree-registrar.service.d/operator.conf
sudo systemctl daemon-reload && sudo systemctl restart shade-tree-registrar
journalctl -u shade-tree-registrar -n 5   # "registrar up on 127.0.0.1:8878 operator=0x… asset=… tiers=…"
curl -sS -D - --socks5-hostname 127.0.0.1:9050 "http://<bootnode-onion>:8878/pay/quote?limit=8" -o /dev/null | grep -i "^HTTP\|payment-required\|www-authenticate"
```

What bootstrap did: `HiddenServicePort 8878 127.0.0.1:8878` inside the bootnode's HS block (the
registrar rides the bootnode onion; no new identity — on a gateway-only box, inside the GATEWAY's
HS block instead), `shade-tree-registrar.service` (same sandbox as the other units; store at
`deploy-state/registrar-state.json`; `SHADE_TREE_PAY_PROTOCOLS` in its env),
`SHADE_TREE_REGISTRAR_ADVERTISE=1` on `shade-tree-bootnode.service` so `GET /health` carries `pay:{port,
protocols, asset, chain, tiers}` (how a client discovers "this fleet sells access, here"), and the
same advert on `shade-tree-heartbeat.service` so your gateway's SIGNED caps carry `pay` (+ `admits`) in
the directory (T-FEAT-9: how a client discovers "THIS gateway sells, and admits paid leaves").
The registrar refuses to start if the token's on-chain `DOMAIN_SEPARATOR()` does not match its
computed EIP-712 domain or if `PaidAccessSet.allowedLimits()` lacks a sold tier.

Day 2:

- `GET /health` on `:8878` = the public offer + `leafCount` + `root`. Local
  `127.0.0.1:9102/metrics` =
  `shade_tree_registrar_payments_total{protocol,result,reason}`, `shade_tree_registrar_txs_total{kind,result}`,
  `shade_tree_registrar_orders`, `shade_tree_registrar_inflight`.
  The payment counter records each completed `POST /pay` once. `protocol` is
  `unknown`, `x402`, or `mpp`; early rejects use `unknown`. `result` is
  `challenged`, `inserted`, `replayed`, `rejected`, or `failed`. Reasons are a
  fixed vocabulary, with unexpected values folded into `other`.
- At `debug`, settlement and insertion events include only bounded protocol and
  tier fields. They omit the payer, authorization, commitment, nonce, and
  transaction identifier.
- A crash between settle and insert is repaired on the next boot (`registrar: recovery
  resumed=1`) or by the buyer re-POSTing the same authorization (idempotent, no second charge).
  `GET /pay/status/<nonce>` shows any order's public state.
- Change prices / asset / payTo: edit the unit env (or re-run bootstrap) and restart; every
  outstanding MPP challenge is retired automatically (its HMAC no longer matches the offer) and
  x402 payments for the old amount are refused (`value_mismatch`).
- Rate limits: `SHADE_TREE_REGISTRAR_PAY_RATE/_BURST` (default 1/s, 10) in front of paid POSTs,
  `SHADE_TREE_REGISTRAR_QUOTE_RATE/_BURST` (20/s, 100) for quotes, `SHADE_TREE_REGISTRAR_MAX_INFLIGHT` (8)
  concurrent settlements; the same slow-client HTTP limits as the bootnode.
- Rotate the operator: `PaidAccessSet.setOperator(new)` + `acceptOperator()` from the new key,
  then swap the drop-in and restart. Real USDC instead of the test token: change
  `SHADE_TREE_PAY_ASSET` (one env), restart.

Buyer side: `docs/JOIN.md` "Buy access" / `shade-tree-node pay --help`.

### Selling access: the paid set (T-FEAT-7)

Access can be BOUGHT as well as staked or granted (`docs/PAYMENTS.md`, `docs/adr/0007-paid-access.md`).
The buyer pays OFF chain over HTTP 402 rails (x402 / MPP; the registrar service — a separate
component — handles the payment) and the operator/registrar key inserts the buyer's
rateCommitment into the `PaidAccessSet` (`insert(commitment, limit)`, `insertBatch`; operator
only, nothing payable on chain, no refunds, no exit). From then on the buyer proves membership
of the PAID tree exactly like everyone else; the gateway learns nothing about which leaf.

What the gateway does with it — three knobs, all documented in `docs/CONFIG.md`:

```bash
# trust the paid set NEXT TO the staked set and members.json (union; nothing is replaced)
export SHADE_TREE_GROUP_CONTRACT=0xStaked          # may be a comma list of sets
export SHADE_TREE_PAID_ACCESS_CONTRACT=0xPaid      # appends the paid set as one more root source
export SHADE_TREE_PAID_MIN_LEAVES=8               # anonymity-set floor K: WARN below it, never refuse
export SHADE_TREE_TIERS=8,32                       # the tiers you sell, so a paid over-spender's leaf resolves
```

- **Roots.** `SHADE_TREE_ADMIT` names them (T-FEAT-9, "Choose what you admit" above): the DEFAULT is
  `invited` alone, so set `SHADE_TREE_ADMIT=invited,paid` (or `invited,staked,paid`) for the paid set to
  become a root source at all — configuring `SHADE_TREE_PAID_ACCESS_CONTRACT` is not enough. Startup prints
  `admits: invited+paid` then `roots: members.json + paid(0x…)` — read both. (`SHADE_TREE_ROOTS` is the
  deprecated alias.)
- **Floor.** `paid-access anonymity set: N leaves (floor K=SHADE_TREE_PAID_MIN_LEAVES)`: with few paid
  leaves a paid member is thinly hidden among the OTHER paid members (the gateway still cannot
  tell which one; but "one of 3 buyers" is a small crowd). The gateway WARNs and keeps serving;
  raise the floor for your own reporting, hold inserts to batch them (dwell time), or seed the set.
  Metric: `shade_tree_gateway_paid_access_leaves`; roots per source: `shade_tree_gateway_trusted_roots`.
- **Slashing.** A paid over-spender is slashed on the PAID contract: the gateway resolves which
  configured set holds the reconstructed secret's leaf (`limitOf`) and calls THAT contract's
  `slash(commitment, secret, limit, receiver)` (`slash: routed to paid(0x…)`). There is no bond
  to burn — the leaf is zeroed, the buyer's access ends, the root changes on the next refresh. Your
  `SHADE_TREE_SLASH_KEY` needs gas on the same chain; `SHADE_TREE_SLASH_CONTRACT` stays the primary (a
  superseded set you still slash on) and is tried first.
- **Sweep / prices.** Not on this contract any more: the money moves over the 402 rails
  (registrar); the contract only records leaves. Prices and tiers are the registrar's config; the
  contract's `allowedLimits()` is the admitted tier table.
- **Rust clients.** They read a static `--members` file: `shade-tree leaves --contract 0xPaid --out
  members.json` exports the paid tree in that shape (zeros preserved), re-run after inserts/slashes.

### Endpoint hardening (T-HARD-4)

Both listeners bound every lever an *unauthenticated* peer can pull. Defaults are on; you
should not need to touch them unless you run an unusually large or slow fleet.

**Gateway** (`packages/node/gateway/gateway.mjs`):

- **Envelope deadline** — the newline-terminated envelope must arrive within
  `SHADE_TREE_ENVELOPE_TIMEOUT_MS` (30 s) *of connect*. The deadline is absolute (dribbling one byte
  at a time does not extend it). Cut connections show as `drop reason=envelope-timeout` in the
  metrics (`shade_tree_gateway_tunnels_total{result="drop",reason="envelope-timeout"}`).
- **Relay idle timeout** — an established tunnel with no bytes in either direction for
  `SHADE_TREE_TUNNEL_IDLE_TIMEOUT_MS` (5 min) is closed at both ends
  (`shade_tree_gateway_tunnel_closes_total{reason="idle-timeout"}`). Long-lived idle TLS sessions
  simply reconnect; raise it if members legitimately hold idle connections longer.
- **Combined payload ceiling** — both opaque TLS directions spend from one
  `(externalNullifier, nullifier)` budget. At `SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES` bytes (40 MiB by
  default), the final chunk is truncated to the exact boundary and both sockets close with
  `reason="payload-limit"`. A same-node retry gets only the slot's remainder. Higher tiers receive
  one allowance per private slot; asynchronous cross-node replays can still race the fleet tally.
- **Connection caps** — `SHADE_TREE_MAX_CONNS` (1024) concurrent sockets total, refused at accept
  before any read (`too-many-connections`); `SHADE_TREE_MAX_CONNS_PER_NULLIFIER` (8) concurrent
  tunnels per nullifier (`nullifier-conn-limit`), so one proof replayed inside the honest-retry
  window cannot pin an unbounded number of idle tunnels. Both slots are released on close.
- **Half-close crash fixed** — a client that sent a partial envelope and then FIN'd used to
  crash the whole gateway process (uncaught `EPIPE` on the error reply). Fixed in the same
  slice; `test/adversarial.selftest.mjs` scenario 6 exercises it.

If a *legitimate* member trips `too-many-connections` (metric climbing under normal load), raise
`SHADE_TREE_MAX_CONNS`; the per-nullifier cap should never be hit by an honest client (one request per
nullifier, one tunnel each; a retry replaces a dead tunnel).

**Bootnode** (`packages/node/bootnode/server.mjs`):

- **HTTP slow-client limits** — headers within 10 s, whole request within 30 s (`408`), keep-alive
  idle 5 s, headers <= 8 KiB (`431`), enforced every second (Node's own defaults are 60 s / 300 s
  / 16 KiB / checked every 30 s).
- **Global announce bucket** — in front of the per-onion throttle's blind spot: an attacker
  minting *fresh* onions could force one ed25519 verify per onion until the registry filled. Now
  at most `SHADE_TREE_BOOTNODE_ANNOUNCE_BURST` (1000) reach verification in one instant, then
  `SHADE_TREE_BOOTNODE_ANNOUNCE_RATE` (66.7/s). Overflow gets `429` + `Retry-After` and the heartbeat
  simply retries at its next beat. Legit fleets never hit it at default cadence — the math is in
  `docs/BOOTNODE.md` "Endpoint hardening". If your bootnode logs many `global-rate-limited`
  rejects while the fleet is healthy, you are under an announce flood, not misconfigured.

### Capability advertisement (T-FEAT-10b)

By default a gateway advertises **no** capabilities and its announce is byte-identical to a
legacy gateway — an unconfigured gateway is indistinguishable on the wire. When you set an
egress policy (`SHADE_TREE_EGRESS_ALLOW`) and/or a region (`SHADE_TREE_GATEWAY_REGION`), the heartbeat
attaches a **signed** capability set to every announce:

- `ports` — the coarse allowed egress port set derived from `SHADE_TREE_EGRESS_ALLOW`
  (`*:443` → `[443]`; `*:443,*:8443` → `[443,8443]`; a wildcard `*` port is dropped).
- `region` — your `SHADE_TREE_GATEWAY_REGION` bucket, if valid.
- `proto` — the envelope version range this build speaks (from the gateway's negotiated range).
- `artifacts` — the ZK artifact ids the gateway verifies proofs under, ONLY when
  `SHADE_TREE_ZK_ARTIFACTS` is set (the dual-VK rollout window, `docs/CEREMONY.md` §6). Loaded through
  the same fail-closed loader the gateway verifies with, so a heartbeat can never advertise an id
  the gateway does not hold.

The caps are signed by the gateway's onion key (not the bootnode), so a bootnode or directory
signer cannot forge or alter them. Clients that opt into capability-aware selection then route a
port-`X` request only to gateways advertising `X`. The heartbeat logs the exact caps it advertises
on startup (`capabilities advertised (signed): …`), or `capabilities: none` when unconfigured.

On the systemd deploy, set these as `Environment=` lines in the relevant unit
(`/etc/systemd/system/shade-tree-*.service`), then `systemctl daemon-reload && systemctl
restart <unit>`.
