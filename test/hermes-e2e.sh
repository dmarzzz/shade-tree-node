#!/usr/bin/env bash
# Real Hermes -> Shade Tree integration (gated, operator-run).
#
# This is intentionally not a *.selftest.mjs: it needs a configured Hermes model, live Tor
# network access, and one public HTTPS request. It proves more than the offline runner test:
#
#   Hermes terminal tool -> shade-tree run -> Rust CONNECT Proxy -> embedded Arti
#   -> .onion node -> HTTPS
#
# The Grove is ephemeral. A deterministic test member is written only under mktemp, the node
# accepts only that member, and cleanup stops every process and removes the onion keys. System
# Tor is used only to publish the temporary server-side onion; the agent-side Proxy dials it
# with Arti embedded in the Rust binary, with no Tor daemon or SOCKS dependency. The
# Hermes model endpoint may be placed in NO_PROXY (loopback is already included); the public
# curl performed by Hermes must cross the Grove. A passing run requires BOTH the Hermes marker
# and a real `result="pass"` node metric.
#
# Local Hermes:
#   SHADE_TREE_HERMES_E2E=1 bash test/hermes-e2e.sh
#
# Hermes on another host (the SSH login must be able to run the configured account):
#   SHADE_TREE_HERMES_E2E=1 \
#   HERMES_E2E_SSH_TARGET=orbital-one \
#   HERMES_E2E_REMOTE_USER=mindagent \
#   HERMES_E2E_REMOTE_HOME=/home/mindagent \
#   bash test/hermes-e2e.sh
#
# Useful overrides: HERMES_E2E_HERMES_BIN, HERMES_E2E_TOR_BIN,
# HERMES_E2E_RUST_BIN, HERMES_E2E_{GATEWAY,PROXY,METRICS}_PORT,
# HERMES_E2E_REMOTE_PROXY_PORT,
# HERMES_E2E_MODEL_FORWARD_PORT, HERMES_E2E_BOOTSTRAP_TIMEOUT_MS,
# HERMES_E2E_REQUEST_URL, HERMES_E2E_NO_PROXY.
set -euo pipefail

if [ "${1:-}" = "--hermes-child" ]; then
  # This branch is entered only as the child of `shade-tree run`. It therefore sees the
  # process-scoped proxy variables and none of the member/operator SHADE_TREE_* credentials.
  prompt="${HERMES_E2E_PROMPT:?HERMES_E2E_PROMPT is required}"
  hermes_bin="${HERMES_E2E_HERMES_BIN:-hermes}"
  hermes_args=(--ignore-rules --toolsets terminal)
  [ "${HERMES_E2E_IGNORE_USER_CONFIG:-0}" = "1" ] && hermes_args+=(--ignore-user-config)
  [ -n "${HERMES_E2E_MODEL:-}" ] && hermes_args+=(--model "$HERMES_E2E_MODEL")
  [ -n "${HERMES_E2E_PROVIDER:-}" ] && hermes_args+=(--provider "$HERMES_E2E_PROVIDER")
  if [ -z "${HERMES_E2E_SSH_TARGET:-}" ]; then
    exec "$hermes_bin" "${hermes_args[@]}" --oneshot "$prompt"
  fi

  remote_port="${HERMES_E2E_REMOTE_PROXY_PORT:-18888}"
  local_port="${HERMES_E2E_LOCAL_PROXY_PORT:?HERMES_E2E_LOCAL_PROXY_PORT is required}"
  remote_user="${HERMES_E2E_REMOTE_USER:-}"
  remote_home="${HERMES_E2E_REMOTE_HOME:-}"
  remote_path="${HERMES_E2E_REMOTE_PATH:-}"
  local_proxy="${HTTPS_PROXY:?authenticated HTTPS_PROXY is required}"
  proxy_authority="${local_proxy#http://}"
  case "$proxy_authority" in
    *@* ) proxy_userinfo="${proxy_authority%@*}" ;;
    * ) echo "Hermes child received a proxy URL without credentials" >&2; exit 2 ;;
  esac
  remote_proxy="http://${proxy_userinfo}@127.0.0.1:${remote_port}"
  remote_no_proxy="${NO_PROXY:-127.0.0.1,localhost,::1}"

  # Build one quoted bash command. The values are operator configuration or this file's fixed
  # prompt; %q prevents any of them from becoming remote shell syntax.
  printf -v q_prompt '%q' "$prompt"
  printf -v q_bin '%q' "$hermes_bin"
  printf -v q_proxy '%q' "$remote_proxy"
  printf -v q_no_proxy '%q' "$remote_no_proxy"
  hermes_command="$q_bin"
  for arg in "${hermes_args[@]}"; do
    printf -v q_arg '%q' "$arg"
    hermes_command+=" ${q_arg}"
  done
  remote_command="exec env HTTP_PROXY=${q_proxy} http_proxy=${q_proxy} HTTPS_PROXY=${q_proxy} https_proxy=${q_proxy} WSS_PROXY=${q_proxy} wss_proxy=${q_proxy} NO_PROXY=${q_no_proxy} no_proxy=${q_no_proxy} NODE_USE_ENV_PROXY=1 SHADE_TREE_ACTIVE=1 SHADE_TREE_PROXY_URL=${q_proxy} ${hermes_command} --oneshot ${q_prompt}"
  for env_name in CUSTOM_BASE_URL CUSTOM_API_KEY; do
    if [ -n "${!env_name:-}" ]; then
      printf -v q_env_value '%q' "${!env_name}"
      remote_command="export ${env_name}=${q_env_value} && ${remote_command}"
    fi
  done

  if [ -n "$remote_home" ]; then
    printf -v q_home '%q' "$remote_home"
    remote_command="cd ${q_home} && ${remote_command}"
  fi
  if [ -n "$remote_path" ]; then
    printf -v q_path '%q' "$remote_path"
    remote_command="export PATH=${q_path} && ${remote_command}"
  fi

  printf -v q_remote_command '%q' "$remote_command"
  remote_launch="bash -c ${q_remote_command}"
  if [ -n "$remote_user" ]; then
    printf -v q_remote_user '%q' "$remote_user"
    remote_launch="sudo -u ${q_remote_user} env"
    if [ -n "$remote_home" ]; then
      printf -v q_remote_home '%q' "$remote_home"
      remote_launch+=" HOME=${q_remote_home}"
    fi
    if [ -n "$remote_path" ]; then
      printf -v q_remote_path '%q' "$remote_path"
      remote_launch+=" PATH=${q_remote_path}"
    fi
    remote_launch+=" bash -c ${q_remote_command}"
  fi

  ssh_forwards=(-R "127.0.0.1:${remote_port}:127.0.0.1:${local_port}")
  if [ -n "${HERMES_E2E_MODEL_FORWARD_PORT:-}" ]; then
    model_port="$HERMES_E2E_MODEL_FORWARD_PORT"
    remote_model_port="${HERMES_E2E_REMOTE_MODEL_PORT:-$model_port}"
    ssh_forwards+=(-R "127.0.0.1:${remote_model_port}:127.0.0.1:${model_port}")
  fi

  exec ssh -T \
    -o BatchMode=yes \
    -o ConnectTimeout="${HERMES_E2E_SSH_CONNECT_TIMEOUT:-10}" \
    -o ExitOnForwardFailure=yes \
    "${ssh_forwards[@]}" \
    "$HERMES_E2E_SSH_TARGET" "$remote_launch"
fi

if [ "${SHADE_TREE_HERMES_E2E:-0}" != "1" ]; then
  echo "SKIP Hermes e2e: set SHADE_TREE_HERMES_E2E=1 to run."
  echo "  (needs a configured Hermes model, Rust, server-side Tor, and live network access)"
  exit 0
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
INTEROP="$REPO/crates/shadenet-rln/interop"
RUST_MANIFEST="$REPO/Cargo.toml"
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
WORK="$(mktemp -d)"

TOR_BIN="${HERMES_E2E_TOR_BIN:-tor}"
SECRET="${HERMES_E2E_SECRET:-12345678901234567890}"
GW_PORT="${HERMES_E2E_GATEWAY_PORT:-18443}"
PROXY_PORT="${HERMES_E2E_PROXY_PORT:-18888}"
METRICS_PORT="${HERMES_E2E_METRICS_PORT:-19101}"
BOOTSTRAP_TIMEOUT_MS="${HERMES_E2E_BOOTSTRAP_TIMEOUT_MS:-180000}"
REQUEST_URL="${HERMES_E2E_REQUEST_URL:-https://api.ipify.org?format=json}"
EXTRA_NO_PROXY="${HERMES_E2E_NO_PROXY:-}"
PROXY_TOKEN="${HERMES_E2E_PROXY_TOKEN:-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef}"
RUN_ATTEMPTS="${HERMES_E2E_RUN_ATTEMPTS:-3}"
export SHADE_TREE_PROXY_TOKEN="$PROXY_TOKEN"

GW_PID=""
TOR_PID=""
PROXY_PID=""
PIDFILE="$WORK/pids"
: > "$PIDFILE"

track() { printf '%s\n' "$1" >> "$PIDFILE"; }
fail() { echo "FAIL Hermes e2e: $*" >&2; exit 1; }
case "$REQUEST_URL" in
  https://* ) ;;
  * ) fail "HERMES_E2E_REQUEST_URL must be an https:// URL" ;;
esac
case "$RUN_ATTEMPTS" in
  ''|*[!0-9]*|0 ) fail "HERMES_E2E_RUN_ATTEMPTS must be a positive integer" ;;
esac
[ "$RUN_ATTEMPTS" -le 4 ] || fail "HERMES_E2E_RUN_ATTEMPTS must be between 1 and 4"
gateway_pass_count() {
  curl --fail --silent --show-error --max-time 5 \
    "http://127.0.0.1:${METRICS_PORT}/metrics" 2>/dev/null \
    | sed -n 's/^shade_tree_gateway_tunnels_total{result="pass"} \([0-9][0-9]*\)$/\1/p' \
    | tail -n 1 || true
}
cleanup() {
  local p
  for p in "$PROXY_PID" "$TOR_PID" "$GW_PID"; do
    [ -n "$p" ] && kill "$p" 2>/dev/null || true
  done
  while read -r p; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done < "$PIDFILE"
  sleep 1
  while read -r p; do [ -n "$p" ] && kill -0 "$p" 2>/dev/null && kill -9 "$p" 2>/dev/null || true; done < "$PIDFILE"
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM HUP PIPE

command -v node >/dev/null 2>&1 || fail "node not found"
command -v "$TOR_BIN" >/dev/null 2>&1 || fail "Tor not found ($TOR_BIN)"
if [ -n "${HERMES_E2E_RUST_BIN:-}" ]; then
  RUST_SHADE_TREE="$HERMES_E2E_RUST_BIN"
  [ -x "$RUST_SHADE_TREE" ] || fail "Rust shade-tree binary is not executable: $RUST_SHADE_TREE"
else
  command -v cargo >/dev/null 2>&1 || fail "cargo not found; set HERMES_E2E_RUST_BIN to a live shade-tree binary"
  echo "== build the Rust Proxy with embedded Arti and RLN artifacts =="
  cargo build --locked --manifest-path "$RUST_MANIFEST" \
    -p shadenet-cli --features live
  RUST_SHADE_TREE="$REPO/target/debug/shade-tree"
fi
if [ -z "${HERMES_E2E_SSH_TARGET:-}" ]; then
  command -v "${HERMES_E2E_HERMES_BIN:-hermes}" >/dev/null 2>&1 || fail "Hermes not found; set HERMES_E2E_HERMES_BIN or HERMES_E2E_SSH_TARGET"
else
  command -v ssh >/dev/null 2>&1 || fail "ssh not found"
fi

echo "== derive an ephemeral invited member =="
node "$INTEROP/egress-derive.mjs" "$WORK" "$SECRET"
IDENTITY="$WORK/identity.json"
MEMBERS="$WORK/members.json"

echo "== start the proof-gated node on 127.0.0.1:${GW_PORT} =="
SHADE_TREE_MEMBERS_FILE="$MEMBERS" \
SHADE_TREE_GATEWAY_PORT="$GW_PORT" \
SHADE_TREE_METRICS_PORT="$METRICS_PORT" \
SHADE_TREE_LOG_LEVEL=info \
SHADE_TREE_BANNER=never \
  node "$REPO/gateway/gateway.mjs" > "$WORK/gateway.log" 2>&1 &
GW_PID=$!
track "$GW_PID"
node "$INTEROP/wait-log.mjs" "$WORK/gateway.log" "gateway up on" 30000 || {
  cat "$WORK/gateway.log" >&2
  fail "node did not become ready"
}

echo "== publish the node as an ephemeral Tor v3 onion =="
mkdir -p "$WORK/hs" "$WORK/tor-data"
chmod 700 "$WORK/hs" "$WORK/tor-data"
"$TOR_BIN" \
  --DataDirectory "$WORK/tor-data" \
  --SocksPort 0 \
  --HiddenServiceDir "$WORK/hs" \
  --HiddenServiceVersion 3 \
  --HiddenServicePort "80 127.0.0.1:${GW_PORT}" \
  --Log "notice file $WORK/tor.log" \
  > "$WORK/tor-bootstrap.log" 2>&1 &
TOR_PID=$!
track "$TOR_PID"
node "$INTEROP/wait-log.mjs" "$WORK/tor.log" "Bootstrapped 100%" "$BOOTSTRAP_TIMEOUT_MS" || {
  cat "$WORK/tor.log" >&2 || true
  fail "Tor did not bootstrap"
}

for _ in $(seq 1 60); do [ -s "$WORK/hs/hostname" ] && break; sleep 1; done
[ -s "$WORK/hs/hostname" ] || fail "Tor did not write the onion hostname"
ONION="$(tr -d '[:space:]' < "$WORK/hs/hostname")"
echo "onion ready: ${ONION:0:16}..onion"
node "$INTEROP/wait-log.mjs" "$WORK/tor.log" "Success uploading" 120000 >/dev/null 2>&1 || sleep 20

echo "== start the Rust Shade Tree CONNECT Proxy on 127.0.0.1:${PROXY_PORT} =="
SHADE_TREE_SLOT_STATE_DIR="$WORK/slots" \
SHADE_TREE_TOR_TIMEOUT_SECS="${HERMES_E2E_ARTI_TIMEOUT_SECS:-300}" \
  "$RUST_SHADE_TREE" proxy \
    --listen "127.0.0.1:${PROXY_PORT}" \
    --onion "${ONION}:80" \
    --identity "$IDENTITY" \
    --members "$MEMBERS" \
    > "$WORK/proxy.log" 2>&1 &
PROXY_PID=$!
track "$PROXY_PID"
node "$INTEROP/wait-log.mjs" "$WORK/proxy.log" "shade-tree proxy listening" 30000 || {
  cat "$WORK/proxy.log" >&2
  fail "Proxy did not become ready"
}

PROMPT="You are running a network integration test. Use the terminal tool exactly once to run: curl --fail --silent --show-error --max-time 90 '${REQUEST_URL}'. If and only if it returns JSON containing an ip field, reply with HERMES_SHADE_TREE_OK followed by one space and that JSON. Do not use any other tools."

echo "== launch Hermes through shade-tree run =="
mkdir -p "$WORK/hermes-cwd"
export HERMES_E2E_PROMPT="$PROMPT"
export HERMES_E2E_LOCAL_PROXY_PORT="$PROXY_PORT"
hermes_ok=0
for attempt in $(seq 1 "$RUN_ATTEMPTS"); do
  echo "--- Hermes tunnel attempt ${attempt}/${RUN_ATTEMPTS} ---"
  passes_before="$(gateway_pass_count)"; passes_before="${passes_before:-0}"
  set +e
  response="$({
    cd "$WORK/hermes-cwd"
    run_args=(run --proxy "http://127.0.0.1:${PROXY_PORT}")
    [ -n "$EXTRA_NO_PROXY" ] && run_args+=(--no-proxy "$EXTRA_NO_PROXY")
    run_args+=(-- "$SELF" --hermes-child)
    "$RUST_SHADE_TREE" "${run_args[@]}"
  } 2> >(tee "$WORK/hermes.stderr" >&2))"
  rc=$?
  set -e
  printf '%s\n' "$response"
  passes_after="$(gateway_pass_count)"; passes_after="${passes_after:-0}"
  if [ "$rc" -eq 0 ] && grep -q 'HERMES_SHADE_TREE_OK' <<< "$response" \
    && [ "$passes_after" -gt "$passes_before" ]; then
    hermes_ok=1
    break
  fi
  echo "Hermes attempt ${attempt} did not produce both its marker and a new node pass"
  [ "$attempt" -lt "$RUN_ATTEMPTS" ] && sleep 15
done
[ "$hermes_ok" = "1" ] || {
  cat "$WORK/proxy.log" >&2 || true
  cat "$WORK/gateway.log" >&2 || true
  fail "Hermes did not produce both its success marker and a corroborating node pass"
}

echo "== open a second CONNECT through the same Rust Proxy/Arti client =="
second_ok=0
for attempt in $(seq 1 "$RUN_ATTEMPTS"); do
  echo "--- second tunnel attempt ${attempt}/${RUN_ATTEMPTS} ---"
  passes_before_second="$(gateway_pass_count)"; passes_before_second="${passes_before_second:-0}"
  set +e
  second_response="$({
    cd "$WORK/hermes-cwd"
    "$RUST_SHADE_TREE" run \
      --proxy "http://127.0.0.1:${PROXY_PORT}" \
      -- curl --fail --silent --show-error --max-time 90 "$REQUEST_URL"
  } 2> >(tee "$WORK/second.stderr" >&2))"
  rc=$?
  set -e
  passes_after_second="$(gateway_pass_count)"; passes_after_second="${passes_after_second:-0}"
  if [ "$rc" -eq 0 ] && grep -q '"ip"' <<< "$second_response" \
    && [ "$passes_after_second" -gt "$passes_before_second" ]; then
    second_ok=1
    break
  fi
  echo "Second tunnel attempt ${attempt} did not produce both an IP response and a new node pass"
  [ "$attempt" -lt "$RUN_ATTEMPTS" ] && sleep 15
done
[ "$second_ok" = "1" ] || {
  cat "$WORK/proxy.log" >&2 || true
  cat "$WORK/gateway.log" >&2 || true
  fail "second process-scoped request failed"
}

metrics="$(curl --fail --silent --show-error --max-time 5 "http://127.0.0.1:${METRICS_PORT}/metrics")"
grep -Eq '^shade_tree_gateway_tunnels_total\{result="pass"\} ([2-9]|[1-9][0-9]+)$' <<< "$metrics" || {
  cat "$WORK/gateway.log" >&2 || true
  fail "the two requests were not corroborated by two passed node tunnels"
}
bootstrap_count="$(grep -c 'embedded Arti bootstrap complete' "$WORK/proxy.log" || true)"
[ "$bootstrap_count" = "1" ] || {
  cat "$WORK/proxy.log" >&2 || true
  fail "expected one embedded Arti bootstrap across two CONNECT tunnels, saw $bootstrap_count"
}

echo "PASS Hermes e2e: two Rust-run CONNECT tunnels crossed one embedded-Arti client"
