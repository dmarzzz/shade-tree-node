# External uptime checks (T-MON-4)

`scripts/uptime-probe.mjs` is a standalone, dependency-light prober an **external** monitor runs
to check fleet health from OUTSIDE, over Tor. It is not a server and arms nothing: a cron job or a
hosted uptime service (with a tor-capable runner) invokes it on an interval and reads its exit code.

Unlike the loopback `/health` on the bootnode (`packages/node/bootnode/server.mjs`, reachable only on 127.0.0.1
or through the onion), this prober reaches the bootnode the way a client does — a SOCKS dial
through the local Tor daemon, no exit node, the bootnode never learns the monitor's IP — then
verifies the served directory against the **pinned** signer and rejects issue times outside a
bounded freshness window. So a green check means more than "the box answers": it means the
fleet is serving a fresh, authentic, signer-pinned directory. A swapped, replayed, or MITM'd
directory fails closed.

## Run it

```
# Production: over Tor to the bootnode onion
SHADE_TREE_BOOTNODE_ONION=<bootnode>.onion \
SHADE_TREE_DIR_SIGNER=<pinned signer pubkey hex> \
  node scripts/uptime-probe.mjs

# Dev: plain HTTP straight to a local bootnode (bypasses Tor)
SHADE_TREE_BOOTNODE_URL=http://127.0.0.1:8877 \
SHADE_TREE_DIR_SIGNER=<pinned signer pubkey hex> \
  node scripts/uptime-probe.mjs
```

`SHADE_TREE_DIR_SIGNER` is the pinned directory-signer pubkey the bootnode prints on boot
("pinned signer pubkey (clients set SHADE_TREE_DIR_SIGNER to this)").

## Config (all `SHADE_TREE_*`)

| var | meaning | default |
| --- | --- | --- |
| `SHADE_TREE_BOOTNODE_ONION` | bootnode v3 `.onion` (fetched over Tor) | — |
| `SHADE_TREE_TOR_HOST` / `SHADE_TREE_TOR_PORT` | local Tor SOCKS proxy | `127.0.0.1` / `9250` |
| `SHADE_TREE_BOOTNODE_URL` | plain-http base, dev only (bypasses Tor) | — |
| `SHADE_TREE_DIR_SIGNER` | pinned directory-signer pubkey (hex), **required** | — |
| `SHADE_TREE_DIR_MAX_AGE_SEC` | maximum accepted age of the signed directory issue time | `300` |
| `SHADE_TREE_DIR_FUTURE_SEC` | maximum accepted future clock skew for the issue time | `300` |
| `SHADE_TREE_PROBE_ACCEPT_PRE_V4_CAPS` | set to `1` only for read-only observation of an explicitly identified pre-v4 fleet; accepts its old capability-signature domain without enabling legacy client/node protocol behavior | off |
| `SHADE_TREE_NETWORK` | `<name>`: default `SHADE_TREE_BOOTNODE_ONION` + `SHADE_TREE_DIR_SIGNER` from `network/<name>/bootnode.json` (explicit env wins; a `pending` record supplies nothing → misconfig) | — |
| `SHADE_TREE_PROBE_TIMEOUT_MS` | per-request timeout | `20000` |

Provide `SHADE_TREE_BOOTNODE_ONION` **or** `SHADE_TREE_BOOTNODE_URL` (or `SHADE_TREE_NETWORK` naming a live record). Reads are bounded
(`SHADE_TREE_BOOTNODE_MAX_RESP`, 2 MB) and time out; the prober never hangs and **fails closed** —
any error (unreachable, bad signature, timeout, misconfig) reports UNHEALTHY.

## Check formats

**Default (JSON).** One line to stdout; exit `0` healthy, nonzero unhealthy:

```json
{"ok":true,"bootnodeReachable":true,"signerOk":true,"directoryFresh":true,"fleetSize":3,"ts":1786675086}
```

(An optional `reason` field is appended when unhealthy.)

**Nagios** (`--format nagios`), for uptime services that consume a status line + code — exit `0`
OK / `2` CRITICAL:

```
OK: bootnode reachable, signed directory fresh
CRITICAL: bootnode unreachable
```

## Privacy posture

The JSON format includes a **count** (`fleetSize`) for private operator monitoring, never gateway
onions, onion prefixes, or operator addresses, and reduces directory errors to fixed classes.
The Nagios format used by
the hosted workflow, systemd unit, and example cron deliberately omits the count so public Actions
logs and long-lived journals do not create another exact-count history.

## Scheduling it (T-DEPLOY-5 / GAP-8)

The probe is the SLI source for `docs/SLO.md` 2.2/2.3 (GO-LIVE row 6.3), so it needs a
scheduler on a tor-capable runner **outside** the fleet. Three shipped options, all in
`monitoring/uptime/`; pick one per vantage point (two vantages are better than one):

| runner | files | cadence | notes |
|---|---|---|---|
| systemd (any Linux box with tor) | `shade-tree-uptime-probe.service` + `shade-tree-uptime-probe.timer` | 5 min | sandboxed oneshot; exit code in the journal |
| GitHub Actions (hosted) | `.github/workflows/uptime-probe.yml` | 15 min | installs tor on the runner; **no-ops green** until repo variables are set |
| plain cron | `crontab.example` | 5 min | one line, appends nagios lines to `/var/log/shade-tree-uptime.log` |

All three read the same inputs: `SHADE_TREE_BOOTNODE_ONION` + `SHADE_TREE_DIR_SIGNER`, **or**
`SHADE_TREE_NETWORK=<name>` (resolved from `network/<name>/bootnode.json`, `packages/node/lib/network-record.mjs`).
Neither input is secret (an onion and a public key). `uptime-probe.env.example` is the
`/etc/shade-tree/uptime-probe.env` template the systemd unit and cron line source.

### systemd timer

```bash
# on the prober box: repo at /opt/shade-tree (npm ci done), tor running with SocksPort 9050, user `shade-tree`
sudo install -m 0644 monitoring/uptime/shade-tree-uptime-probe.{service,timer} /etc/systemd/system/
sudo install -d -m 0755 /etc/shade-tree
sudo install -m 0644 monitoring/uptime/uptime-probe.env.example /etc/shade-tree/uptime-probe.env   # edit: onion+signer or SHADE_TREE_NETWORK
sudo systemctl daemon-reload
sudo systemctl enable --now shade-tree-uptime-probe.timer
systemctl list-timers shade-tree-uptime-probe.timer            # next fire
journalctl -u shade-tree-uptime-probe.service -n 20            # last probe lines (OK: … / CRITICAL: …)
```

The service uses `SuccessExitStatus=1 2` so a CRITICAL probe is a **journal line, not a failed
unit** — the timer keeps firing and the SLI is `grep CRITICAL` over the journal (or ship the
journal to your log stack). Adjust `User=`, `WorkingDirectory=`, `SHADE_TREE_TOR_PORT` for your box.

### GitHub Actions

`.github/workflows/uptime-probe.yml` runs `*/15 * * * *` (+ `workflow_dispatch`). Set repository
**variables** (Settings → Secrets and variables → Actions → Variables): `SHADE_TREE_BOOTNODE_ONION` +
`SHADE_TREE_DIR_SIGNER`, or `SHADE_TREE_NETWORK` naming a current v4 deployment to read them from its committed record.
Secrets of the same names are read as a fallback. Until one of those is set the job emits a
`::notice::` and exits green (it does not even check out the repo), so an unconfigured repo or
fork never red-flags. A `pending` network record likewise skips green. Once configured, a
CRITICAL probe fails the run with an `::error::` (which is the alert). GitHub's schedule floor is
5 minutes but scheduled runs are best-effort and often late, so this is the coarse hosted signal;
the systemd timer is the 5-minute SLI source.

Hosted Tor bootstrap is occasionally sensitive to a runner's first guard path. The workflow
makes two bounded attempts with separate data directories before failing the observation; it
never probes or publishes from a partial bootstrap.

The hosted Sepolia observer targets the current Protocol v4 research Grove and keeps
`SHADE_TREE_PROBE_ACCEPT_PRE_V4_CAPS=0`. Set that compatibility switch to `1` only for a deliberately
isolated observer of a named legacy fleet; it is never inferred from `SHADE_TREE_NETWORK` and must
not be enabled for the current Grove.

The public Grove also requires `SHADE_TREE_NETWORK=sepolia` and the
`SHADE_TREE_GROVE_SIGNING_KEY` Actions **secret**. Other network selectors can
still run the uptime probe, but they do not replace the snapshot behind the
versioned Sepolia Data API. The key's public half is pinned in
`network/grove-signing-public.pem`. The read-only probe job signs only the
allowlisted aggregate; a separate minimal publisher job receives temporary
`contents: write`, checks out no code, and force-updates a one-file, parentless
`network-state` commit. See [`specs/data-api.md`](../specs/data-api.md).

After the publisher succeeds, a separate read-only job checks the production `/grove/` page and
both signed API heads. This makes a green scheduled run evidence that the public consumer caught
up too, rather than evidence only that the Tor observer and Git publisher worked.

### cron

```
*/5 * * * * set -a; . /etc/shade-tree/uptime-probe.env; set +a; SHADE_TREE_TOR_PORT=9050 /usr/bin/node /opt/shade-tree/scripts/uptime-probe.mjs --format nagios >> /var/log/shade-tree-uptime.log 2>&1
```

(`monitoring/uptime/crontab.example`, verbatim.)

Tests: `node scripts/uptime-probe.selftest.mjs` (probe) and
`node monitoring/uptime/uptime-scheduler.selftest.mjs` (units / cron / workflow well-formed and
wired to the probe), both auto-discovered by `scripts/test-all.mjs`.

## Outcomes and second vantage point (OPS-7)

- **OK / CRITICAL / UNKNOWN.** The probe exits 3 (`UNKNOWN`) when its own Tor SOCKS port is
  down, and the hosted workflow reports a runner Tor bootstrap failure the same way. Neither
  counts against the canopy. Each attempt waits up to 60 s (`SHADE_TREE_PROBE_TIMEOUT_MS`), because a
  cold onion descriptor fetch plus rendezvous often exceeds the old 20 s.
- **Pin check.** With `SHADE_TREE_NETWORK` set, the probe compares the Elder's `/health` commit with
  the record's `services.elder.commit` and reports `pinMatch`; drift is a warning, not downtime.
- **Second vantage point.** `--prom-file <path>` writes `shade_tree_probe_*` gauges for the
  node_exporter textfile collector. The operator deployment runs it every 5 minutes on the Lab
  runner, and the canopy monitor alerts when the Elder is unreachable from there for 15 minutes.
- **Cadence.** GitHub throttles scheduled workflows (about every 2.5 h in practice), so the
  operator deployment also dispatches the hosted probe every 15 minutes.
