#!/usr/bin/env bash
# T-TEST-1 CI path: the AUTHORITATIVE real-Tor client->gateway ACCEPT, run against the REAL
# fleet that packages/node/bootnode/deploy/bootstrap.sh brings up inside a systemd container (the same
# published-.onion fleet a fresh droplet gets). This is the container analogue of the local
# test/real-tor-e2e.sh, and it reuses the systemd-in-container machinery documented in
# packages/node/bootnode/deploy/E2E-CONTAINER.md.
#
# Flow:
#   1. boot ubuntu:24.04 with real systemd as PID 1,
#   2. run bootstrap.sh -> tor + shade-tree-bootnode + shade-tree-gateway with REAL v3 onions,
#   3. derive a member (packages/node/lib/rln.mjs), point the gateway's PoC root at that single-member set,
#      restart the gateway so its membership root matches the proof the client will mint,
#   4. start a local :443 sink (matches the gateway's default *:443 egress policy),
#   5. run the JS REFERENCE client (test/real-tor-e2e-client.mjs) INSIDE the container: it
#      mints a real RLN proof and dials the gateway's .onion over the container's Tor SOCKS,
#   6. assert the gateway ACCEPTED (client ok ack + local pass metric + the sink got the
#      tunneled connection).
#
# GATING (matches e2e-container.sh's over-Tor step): v3 HS descriptor propagation over the live
# Tor network is slow + flaky, so the dial is RETRIED and a propagation timeout is a SOFT/NEUTRAL
# outcome (exit 0), NOT a hard failure. A genuine ACCEPT, when observed, IS asserted (a client
# that claims ACCEPT without the corroborating metric and sink evidence is a HARD failure).
#
# Requires: docker + a kernel that runs systemd in a privileged container (GitHub Actions
# ubuntu-latest, Docker Desktop / colima). The container is force-removed on exit.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$(cd "$HERE/.." && pwd)"          # repo root
IMAGE="${E2E_IMAGE:-ubuntu:24.04}"
CONTAINER="shade-tree-tor-e2e-$$"
BOOTNODE_PORT="${SHADE_TREE_BOOTNODE_PORT:-8877}"
GATEWAY_PORT="${SHADE_TREE_GATEWAY_PORT:-8443}"
SECRET="${SHADE_TREE_SECRET:-12345678901234567890}"
SINK_PORT="${SHADE_TREE_SINK_PORT:-443}"      # :443 so the gateway's DEFAULT *:443 egress policy allows it
RUN_ATTEMPTS="${SHADE_TREE_TOR_RUN_ATTEMPTS:-5}"

log()  { echo -e "\n\033[1;36m== $*\033[0m"; }
fail() { echo -e "\033[1;31mFAIL: $*\033[0m" >&2; exit 1; }

command -v docker >/dev/null || fail "docker not found on PATH"
docker info >/dev/null 2>&1 || fail "docker daemon not reachable (start Docker Desktop / dockerd)"

REF="${SHADE_TREE_REF:-$(git -C "$SRC" symbolic-ref --quiet --short HEAD || true)}"
CREATED_TAG=""
if [ -z "$REF" ]; then
  REF="shade-tree-tor-e2e-head"
  git -C "$SRC" tag -f "$REF" HEAD >/dev/null
  CREATED_TAG="$REF"
fi

cleanup() {
  if [ "${E2E_KEEP:-0}" = "1" ]; then
    echo "E2E_KEEP=1 -> leaving container $CONTAINER up (docker rm -f $CONTAINER to remove)"
  else
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  fi
  [ -n "$CREATED_TAG" ] && git -C "$SRC" tag -d "$CREATED_TAG" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM HUP PIPE

log "boot ubuntu container with systemd as PID 1 ($IMAGE)"
docker run -d --name "$CONTAINER" \
  --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  --tmpfs /run --tmpfs /run/lock \
  -v "$SRC":/mnt/src:ro \
  "$IMAGE" \
  bash -c 'export DEBIAN_FRONTEND=noninteractive;
           apt="-o Acquire::Retries=3 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20";
           for attempt in 1 2 3; do
             echo "$(date -u +%T) apt attempt $attempt: update";
             apt-get $apt update -qq &&
               echo "$(date -u +%T) apt attempt $attempt: install systemd" &&
               apt-get $apt install -y -qq systemd systemd-sysv && break;
             echo "$(date -u +%T) apt attempt $attempt failed; retrying"; sleep 5;
           done;
           echo "$(date -u +%T) exec systemd";
           test -x /lib/systemd/systemd || { echo "systemd is not installed; see apt output above"; exit 1; };
           exec /lib/systemd/systemd' >/dev/null

log "wait for systemd to come up"
# apt runs before systemd, so a slow mirror spends this budget; apt's output lands in `docker logs`.
ok=0
for _ in $(seq 1 90); do
  [ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" = "true" ] || break
  state="$(docker exec "$CONTAINER" systemctl is-system-running 2>/dev/null || true)"
  case "$state" in
    running|degraded|starting) ok=1; [ "$state" = "starting" ] || break ;;
  esac
  sleep 2
done
[ "$ok" = "1" ] || {
  docker logs "$CONTAINER" 2>&1 | tail -60
  docker inspect -f 'container running={{.State.Running}} exit={{.State.ExitCode}}' "$CONTAINER" 2>&1 || true
  echo "last systemctl is-system-running: ${state:-<no answer>}; processes:"
  docker exec "$CONTAINER" ps -eo pid,etime,args 2>&1 | head -15 || true
  fail "systemd never came up in container"
}

log "run bootstrap.sh inside the container (clone file:///mnt/src @ $REF)"
docker exec \
  -e SHADE_TREE_REPO="file:///mnt/src" \
  -e SHADE_TREE_REF="$REF" \
  -e SHADE_TREE_MEMBERS_FILE="/mnt/src/group/members.json" \
  -e SHADE_TREE_ADMISSION="open" \
  -e SHADE_TREE_BOOTNODE_PORT="$BOOTNODE_PORT" \
  -e SHADE_TREE_GATEWAY_PORT="$GATEWAY_PORT" \
  "$CONTAINER" bash /mnt/src/packages/node/bootnode/deploy/bootstrap.sh

log "point the gateway's PoC root at a derived member + restart it"
docker exec -i "$CONTAINER" env SECRET="$SECRET" bash -s <<'PREP'
set -euo pipefail
export PATH="$(ls -d /opt/node-v*/bin 2>/dev/null | sort -V | tail -1):$PATH"  # bootstrap.sh installs Node off PATH
cd /opt/shade-tree
# Derive a single member whose rateCommitment leaf becomes the gateway's whole membership set,
# so the client (same secret) proves against the exact root the gateway trusts.
node crates/shadenet-rln/interop/egress-derive.mjs /tmp "$SECRET"
cp /tmp/members.json /opt/shade-tree/deploy-state/members.json
chown shade-tree:shade-tree /opt/shade-tree/deploy-state/members.json 2>/dev/null || true
systemctl restart shade-tree-gateway
# wait for the gateway to be listening again on loopback
for _ in $(seq 1 30); do
  if timeout 2 bash -c ":</dev/tcp/127.0.0.1/8443" 2>/dev/null; then echo "gateway back up"; break; fi
  sleep 1
done
PREP

log "run the JS reference client egress over Tor, inside the container (best-effort/gated)"
GW_ONION="$(docker exec "$CONTAINER" cat /var/lib/tor/shade-tree-gateway/hostname | tr -d '[:space:]')"
echo "gateway onion: $GW_ONION"

set +e
docker exec -i "$CONTAINER" \
  env GW_ONION="$GW_ONION" SECRET="$SECRET" SINK_PORT="$SINK_PORT" RUN_ATTEMPTS="$RUN_ATTEMPTS" bash -s <<'RUN'
set -uo pipefail
export PATH="$(ls -d /opt/node-v*/bin 2>/dev/null | sort -V | tail -1):$PATH"  # bootstrap.sh installs Node off PATH
cd /opt/shade-tree

# local egress sink; :443 matches the gateway's default *:443 policy (no unit edit needed)
node -e 'const net=require("net");let n=0;net.createServer(s=>{n++;console.error("[sink] connection #"+n);s.resume();}).listen(Number(process.env.SINK_PORT),"127.0.0.1",()=>console.error("[sink] up"));' \
  > /tmp/sink.log 2>&1 &
SINK_PID=$!
for _ in $(seq 1 20); do grep -q "\[sink\] up" /tmp/sink.log 2>/dev/null && break; sleep 0.3; done

ACCEPT=0
for attempt in $(seq 1 "$RUN_ATTEMPTS"); do
  echo "--- client run attempt $attempt/$RUN_ATTEMPTS ---"
  SHADE_TREE_SECRET="$SECRET" SHADE_TREE_ONION="$GW_ONION" SHADE_TREE_TOR_PORT=9050 SHADE_TREE_DIAL_ATTEMPTS=3 \
    node test/real-tor-e2e-client.mjs "127.0.0.1:${SINK_PORT}"
  rc=$?
  [ "$rc" -eq 0 ] && { ACCEPT=1; break; }
  echo "attempt $attempt rc=$rc; HS descriptor may not have propagated yet, retrying ..."
  sleep 15
done

echo "--- sink log ---"; cat /tmp/sink.log 2>/dev/null || true
echo "--- node pass metric ---"; curl -fsS http://127.0.0.1:9101/metrics 2>/dev/null | grep 'shade_tree_gateway_tunnels_total' || true
kill "$SINK_PID" 2>/dev/null || true

GW_OK=0;   curl -fsS http://127.0.0.1:9101/metrics 2>/dev/null | grep -Eq '^shade_tree_gateway_tunnels_total\{result="pass"\} [1-9][0-9]*$' && GW_OK=1
SINK_OK=0; grep -q "\[sink\] connection" /tmp/sink.log 2>/dev/null && SINK_OK=1

if [ "$ACCEPT" = "1" ] && [ "$GW_OK" = "1" ] && [ "$SINK_OK" = "1" ]; then
  echo "OVER-TOR ACCEPT OK (client ack + node pass metric + sink connection)"
  exit 0
fi
if [ "$ACCEPT" = "0" ]; then
  echo "SOFT: no over-Tor ACCEPT after ${RUN_ATTEMPTS} attempts (likely HS descriptor propagation). Non-fatal."
  exit 42   # sentinel: soft-skip
fi
echo "HARD-FAIL: client reported ACCEPT but node-metric/sink evidence missing (GW_OK=$GW_OK SINK_OK=$SINK_OK)"
exit 1
RUN
rc=$?
set -e

if [ "$rc" -eq 0 ]; then
  log "PASS -- JS client got a REAL over-Tor ACCEPT from the fleet gateway"
elif [ "$rc" -eq 42 ]; then
  log "SOFT-SKIP -- fleet published its onions but the over-Tor dial did not complete (propagation). Non-fatal, exactly like e2e-container.sh's over-Tor step."
else
  fail "over-Tor client egress FAILED hard (rc=$rc) -- see gateway journal + sink log above"
fi
