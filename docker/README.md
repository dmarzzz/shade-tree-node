# Docker

## Shade Tree node, from the record

`docker/shadenet-node.Dockerfile` is the operator front door: Tor + the node + its heartbeat, run
from a deployment record alone. Published by the release workflow as
`ghcr.io/dmarzzz/shadenet-node:<version>` (multi-arch). See docs/OPERATOR.md section 2.

```sh
docker run -d --name shadenet-node --restart unless-stopped \
  -e SHADENET_RECORD=https://raw.githubusercontent.com/dmarzzz/shade-tree-node/main/network/sepolia/deployment.json \
  -v shadenet-node:/state ghcr.io/dmarzzz/shadenet-node:0.7.1
docker run --rm -e SHADENET_RECORD=... ghcr.io/dmarzzz/shadenet-node:0.7.1 check --probe   # validate, start nothing
```

Build it locally: `docker build -f docker/shadenet-node.Dockerfile --build-arg COMMIT=$(git rev-parse HEAD) -t shadenet-node:dev .`

## Everything else

Two ways to run: a **single-image** for one-off roles, and a **compose fleet**
that stands up tor + bootnode + gateway + client locally.

## Image

One image, every role. The entrypoint is the unified `shade-tree` CLI; the role is the
subcommand, and every `--flag` maps to an `SHADE_TREE_*` env var.

```sh
docker build -t shade-tree-node .

docker run --rm shade-tree-node                       # prints the command list
docker run --rm shade-tree-node bootnode --help       # a role's flags
docker run --rm shade-tree-node doctor                # local setup check
docker run --rm -p 8877:8877 shade-tree-node \
  bootnode --port 8877 --admission open --stake-mode mock
```

Notes
- Runs as the non-root `node` user. Anything the code mints at runtime (e.g. the
  bootnode signer key) must land in a writable path — use `/data` (a declared
  volume), e.g. `--signer-key /data/bootnode-signer.key`.
- The bootnode/gateway/client all bind `127.0.0.1`. Run bare like this and only
  the same container can reach them; the compose fleet solves that by sharing
  tor's network namespace (below).

## Fleet (docker compose)

The full local path: one `tor` service publishing two onion services (bootnode
and gateway) plus a SOCKS port, with `bootnode`, `gateway`, and `client` sharing
tor's loopback via `network_mode: service:tor`.

```sh
docker compose -p shade-tree up --build
```

### Running beside a validator or local AI stack

Keep Shade Tree in its own Compose project; do not paste these services into the
validator's Compose file. The shipped fleet drops capabilities, enables
`no-new-privileges`, uses a read-only root filesystem, rotates logs, caps CPU,
memory and processes, and publishes Tor SOCKS on host loopback only. It never
needs the Docker socket, host networking, validator keys, fee-recipient keys,
engine JWTs, model credentials, or GPU devices. Do not add any of those mounts.

The client role is the low-risk co-location path. A public gateway also consumes
outbound bandwidth and shares the host's public-IP reputation; sustained proof
verification can contend with a validator or inference job. Keep the shipped
limits for the research preview, watch host headroom, and move the gateway to a
separate machine if validator duties or local workloads show pressure. Docker
access can reveal container environment variables, so use this fleet only where
Docker administration is already trusted and never reuse a validator secret as
a Shade Tree member secret.

### Onion addresses appear on first boot

The onion hostnames are generated the first time tor boots, and their
descriptors take **~10-30s** to publish to the network before circuits work.
tor mirrors the hostnames to a shared volume; read them with:

```sh
docker compose -p shade-tree exec tor cat /shared/bootnode.onion
docker compose -p shade-tree exec tor cat /shared/gateway.onion
```

(or `docker volume inspect <project>_onions` for the host path). The `client`
service already reads `bootnode.onion` from that volume automatically and exports
it as `SHADE_TREE_BOOTNODE_ONION` before starting the shim.

### Driving the client

The shim binds `127.0.0.1:8888` inside tor's namespace, so a published port
can't reach it — drive it from inside the container:

```sh
docker compose -p shade-tree exec client \
  curl -x http://127.0.0.1:8888 https://api.ipify.org?format=json
```

The shim needs a member secret and the bootnode's signer pubkey. Provide them
before `up` (the compose passes them through):

```sh
export SHADE_TREE_SECRET="$(docker run --rm shade-tree-node enroll | ...)"   # a member secret
export SHADE_TREE_DIR_SIGNER="<pinned signer pubkey printed in the bootnode log>"
docker compose -p shade-tree up --build
```

Without `SHADE_TREE_SECRET` the shim prints a helpful error and exits — set it and
re-up. The bootnode prints its pinned signer pubkey at startup
(`docker compose -p shade-tree logs bootnode`); that value is `SHADE_TREE_DIR_SIGNER`.

### Proof-of-work defense

`HiddenServicePoWDefensesEnabled` is left **commented** in `docker/torrc.services`
on purpose: stock tor (including the Debian package used here) hard-fails config
validation without the `pow` module compiled in. Enable it only on a tor build
that ships the module. This mirrors the repo's `tor/torrc` convention.
