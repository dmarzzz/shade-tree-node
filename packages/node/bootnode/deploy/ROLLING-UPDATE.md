# Rolling update (zero downtime)

Update a deployed shade-tree box to a new git ref with minimal disruption. One box is
handled by [`rolling-update.sh`](rolling-update.sh); a multi-box fleet is
sequenced one gateway at a time (below) so healthy gateways keep serving
throughout.

This complements [`bootstrap.sh`](bootstrap.sh) (first bring-up) and the
[operator runbook](../../../../docs/OPERATOR.md). It touches only code and services --
never `deploy-state` (onion seeds, signer key, persistence store are reused).

## Why a brief restart is safe

The gateway and bootnode sit behind Tor v3 onions. Clients do **weighted
rotation + failover** and cache a **last-known-good directory**, so a gateway
that blips for a few seconds is routed around (see
[BOOTNODE.md → Liveness](../../../../docs/BOOTNODE.md#liveness)). The bootnode reloads
its **persisted live-set** on boot (`SHADE_TREE_BOOTNODE_STORE`, T-DEV-4), so its
directory survives a restart instead of blanking. A single box bouncing is
absorbed by client cache + failover.

## One box

```bash
# on the box (repo at /opt/shade-tree):
sudo bash /opt/shade-tree/packages/node/bootnode/deploy/rolling-update.sh <branch|tag|sha>

# or over ssh:
ssh root@<droplet> 'sudo bash /opt/shade-tree/packages/node/bootnode/deploy/rolling-update.sh <ref>'
```

What it does, in order:

1. **Capture + pin the current ref** (`git rev-parse HEAD`, pinned as a
   `shade-tree-rollback-*` tag) *before* any change, so rollback is a one-liner and the
   old commit can't be pruned from a shallow clone.
2. **Update**: `git fetch` + checkout the new ref, `npm install --omit=dev`, then the ref's
   `binaries.sh` installs its sha256-pinned `shadenet-node` + `shadenet-elder` release binaries.
3. **Staged restart, health-gated between each** — safe order:
   `shade-tree-bootnode` → `shade-tree-gateway`.
   - bootnode first (reloads persisted fleet state; a broken build is caught on
     its `/health` before anything else is touched),
   - gateway second (confirmed active + accepting on its loopback port; it re-announces
     itself to the healthy bootnode from inside the process).
   A failed health wait aborts the run before the next service is bounced.
4. **Verify**: both units active, bootnode `/health` ok on loopback **and**
   over the local Tor SOCKS onion (the onion is reused and Tor is not restarted,
   so it should answer quickly).
5. **On any failure**, print the exact rollback command:
   `git checkout <previous-sha> && npm install --omit=dev && <reinstall its binaries> && systemctl restart …`.

Tunables (env, defaults match `bootstrap.sh`): `SHADE_TREE_DIR` (`/opt/shade-tree`),
`SHADE_TREE_BOOTNODE_PORT` (8877), `SHADE_TREE_GATEWAY_PORT` (8443), `SHADE_TREE_TOR_PORT` (9050),
`SHADE_TREE_HEALTH_TIMEOUT` (60s), `SHADE_TREE_ONION_TIMEOUT` (120s). The ref may be passed
as `$1` or `SHADE_TREE_REF`.

## Rolling a multi-box fleet — one gateway at a time

The invariant: **at least one healthy gateway stays in the signed directory at
all times**, so clients always have a live route. Never restart two gateways at
once, and never let the whole fleet drop out of `/directory` together.

Given gateways `gw-1 … gw-N` (each a box running `shade-tree-gateway`, which announces
itself to the bootnode), update them **serially**:

For each `gw-i`:

1. **Drain** — stop the node's heartbeat so the gateway stops re-announcing while its open
   tunnels finish (SIGUSR1 is the node's retire signal, ADR 0014):

   ```bash
   ssh root@gw-i 'systemctl kill -s SIGUSR1 shade-tree-gateway'
   ```

   Leave `shade-tree-gateway` running for now so in-flight circuits finish.

2. **Wait for the TTL to drop it from the directory.** The bootnode holds each
   gateway as soft state for `SHADE_TREE_BOOTNODE_TTL` (default **900s**). Once the
   heartbeat stops, the entry ages out and clients stop selecting `gw-i` while
   still selecting the others. Confirm it's gone:

   ```bash
   curl --socks5-hostname 127.0.0.1:9050 http://<bootnode-onion>/directory \
     | grep -c '<gw-i-onion>'      # expect 0 before proceeding
   ```

   (To drain faster than 900s, run the fleet with a shorter `SHADE_TREE_BOOTNODE_TTL` /
   `SHADE_TREE_BOOTNODE_HEARTBEAT` so aged-out is quick — a deliberate rollout knob.)

3. **Update the box.** `rolling-update.sh` bounces `shade-tree-gateway` (drop any lingering
   circuits; clients fail over to the still-announced peers); the restarted node
   **re-announces** `gw-i` back into the directory:

   ```bash
   ssh root@gw-i 'sudo bash /opt/shade-tree/packages/node/bootnode/deploy/rolling-update.sh <ref>'
   ```

4. **Confirm `gw-i` rejoined and is healthy** before moving to `gw-(i+1)`:

   ```bash
   curl --socks5-hostname 127.0.0.1:9050 http://<bootnode-onion>/directory \
     | grep -c '<gw-i-onion>'      # expect 1 (re-announced)
   ssh root@gw-i 'systemctl is-active shade-tree-gateway'
   ```

Only then drain the next gateway. Because at every step `N-1` gateways remain
announced and healthy, clients always have a route and the rollout is
zero-downtime for the fleet.

### The bootnode box

If a box runs the bootnode too, update it like any other box with
`rolling-update.sh`. The bootnode restart is covered by persistence (reloads the
live-set) + client last-known-good caching, so the momentary blip is safe. If
you run **multiple bootnodes**, update them one at a time as well, confirming
`/health` on each before the next.

### Rollback

If a gateway fails to rejoin or misbehaves after update, run the rollback line
the script printed for that box (checkout the previous pinned ref + reinstall +
restart), confirm it re-announces, then investigate before resuming the rollout.
The rest of the fleet was never touched, so it stayed up the whole time.
