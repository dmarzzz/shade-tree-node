#!/usr/bin/env bash
# Bring a FRESH Ubuntu 24.04 droplet up as a Shade Tree bootnode +
# gateway, in one idempotent command. You rent the box; this does the rest.
#
#   ssh root@<droplet>            # or a sudo user
#   curl -fsSL https://raw.githubusercontent.com/dmarzzz/shade-tree-node/main/bootnode/deploy/bootstrap.sh \
#     | sudo env SHADE_TREE_MEMBERS_FILE=/root/operator-members.json bash
#   # or, if you already cloned the repo on the box:
#   sudo bash bootnode/deploy/bootstrap.sh
#
# It installs Node + Tor (from the official Tor Project repo, so `pow: yes` is available),
# mints the bootnode and gateway onion identities, writes systemd units, starts everything,
# and prints the bootnode onion + pinned signer + gateway onion + the exact client command.
# Re-running it is safe: existing keys/units are reused, not regenerated.
#
# Tunables (env):
#   SHADE_TREE_REPO        git URL            (default: the public repo)
#   SHADE_TREE_REF         branch/tag/sha     (default: main)
#   SHADE_TREE_DIR         install dir        (default: /opt/shade-tree)
#   SHADE_TREE_ADMISSION   open | stake       (default: open)
#   SHADE_TREE_BOOTNODE_PORT / SHADE_TREE_GATEWAY_PORT   loopback backends (default 8877 / 8443)
#   SHADE_TREE_ELDER_METRICS_PORT / SHADE_TREE_NODE_METRICS_PORT   local Prometheus endpoints
#                    (default 9100 / 9101). Registrar and heartbeat use 9102 / 9103. All four
#                    stay on loopback and must be distinct from each other and active service ports.
#   SHADE_TREE_LOG_LEVEL   debug | info | warn | error | off   (default: info)
#   SHADE_TREE_LOG_FORMAT  auto | pretty | text | json          (default: json under systemd)
#   SHADE_TREE_BANNER      auto | always | never                 (default: never under systemd)
#   SHADE_TREE_ENABLE_POW  1 | 0              (default: 0) onion PoW DoS defense
#                    (HiddenServicePoWDefensesEnabled) on every HS block this box publishes.
#                    Default OFF: a client tor built without the pow module (e.g. the Homebrew
#                    bottle, `tor --list-modules` -> `pow: no`) could NOT reach a PoW-enabled
#                    onion (docs/DEPLOYMENT.md "PoW capability mismatch"); the agent-devops
#                    fleet role defaults `shade_tree_enable_pow: false` for the same reason. Turn it
#                    on (=1) once every client you serve runs a pow-capable tor. Toggling
#                    later = edit /etc/tor/torrc.d-shade-tree + `systemctl reload tor` (keys/onions
#                    are unchanged either way).
#   SHADE_TREE_BOOTNODE_ONION   <56-char>.onion   (default: unset = this box runs its OWN bootnode)
#                    GATEWAY-ONLY mode: when set, this box installs ONLY tor + shade-tree-gateway +
#                    shade-tree-heartbeat (no shade-tree-bootnode unit, no bootnode HS block, no bootnode
#                    identity) and the heartbeat announces the gateway to THAT remote bootnode.
#                    Use it to add a second/third gateway to an existing bootnode (docs/OPERATOR.md
#                    section 2). Optional companions, only read in this mode:
#     SHADE_TREE_BOOTNODE_SIGNER   the remote bootnode's pinned signer pubkey -- printed into the
#                            client command at the end (the heartbeat does not need it).
#   SHADE_TREE_ELDER_ONLY     1 | 0              (default: 0) DEDICATED-ELDER mode. Publishes only
#                    the Elder onion and runs only shade-tree-bootnode (no gateway onion, gateway,
#                    or heartbeat). Mutually exclusive with SHADE_TREE_BOOTNODE_ONION.
#   SHADE_TREE_GATEWAY_REGION  na|sa|eu|af|as|oc|aq|unknown  (default: unset = not advertised)
#                    coarse region bucket the heartbeat advertises in signed caps (docs/CONFIG.md).
#   SHADE_TREE_HELIOS      1 | 0              (default: 0) OPT-IN Helios light-client sidecar (T-DEV-9b,
#                    docs/LIGHT-CLIENT.md). =1 installs the pinned a16z/helios release binary
#                    (sha256-verified, SHADE_TREE_HELIOS_VERSION below), renders + starts a hardened
#                    shade-tree-helios.service (local verifying JSON-RPC on 127.0.0.1:SHADE_TREE_HELIOS_PORT),
#                    and points the gateway at it: the gateway unit gets SHADE_TREE_ROOT_PROVIDER=light,
#                    SHADE_TREE_HELIOS_RPC_URL, SHADE_TREE_RPC_URL, SHADE_TREE_GROUP_CONTRACT and is ordered after
#                    the sidecar. The admission root is then anchored to the beacon sync committee
#                    (no RPC trust). Default OFF: the default render is byte-identical to before.
#                    Companions, read only when SHADE_TREE_HELIOS=1:
#     SHADE_TREE_HELIOS_CONSENSUS_RPC  beacon API URL that serves the light-client endpoints  (REQUIRED)
#     SHADE_TREE_RPC_URL               execution JSON-RPC; MUST serve eth_getProof at the finalized
#                                block (own node / archive-capable provider)               (REQUIRED)
#     SHADE_TREE_GROUP_CONTRACT        StakedReputationSet address the gateway reads roots from (REQUIRED)
#     SHADE_TREE_HELIOS_NETWORK        mainnet | sepolia | holesky   (default: sepolia)
#     SHADE_TREE_HELIOS_PORT           sidecar loopback RPC port     (default: 8546; 8545 is left for a local node)
#     SHADE_TREE_HELIOS_CHECKPOINT     weak-subjectivity checkpoint = a recent FINALIZED beacon block
#                                root, 0x + 64 hex (default: unset -> helios --load-external-fallback,
#                                i.e. it fetches one from public checkpoint services; pinning your
#                                own is the more trust-minimized choice, docs/LIGHT-CLIENT.md)
#     SHADE_TREE_HELIOS_VERSION        release tag to install         (default: 0.11.1, sha256-pinned below;
#                                another version needs SHADE_TREE_HELIOS_SHA256=<sha256 of the tarball>)
#   SHADE_TREE_ADMIT       invited[,staked][,paid]  (default: invited) the gateway's ADMISSION POLICY
#                    (T-FEAT-9, docs/adr/0008): which membership roots this PROVIDER honours, in
#                    anonymity order invited (members.json, no on-chain footprint) > staked
#                    (StakedReputationSet) > paid (PaidAccessSet). The default `invited` is the
#                    MAXIMUM-ANONYMITY mode; opt into the others explicitly. Rendered into BOTH the
#                    gateway unit (gateway/gateway.mjs enforces it; a named path whose contract is
#                    missing fails closed at startup) and the heartbeat unit (advertised as signed
#                    `caps.admits`, so clients route only to gateways that admit their leaf).
#     SHADE_TREE_MEMBERS_FILE  absolute path to an operator-owned members.json (REQUIRED when
#                            `invited` is admitted in LIVE mode). The bootstrap validates and copies
#                            it to root-owned /etc/shade-tree/members.json; it never serves the
#                            repository demo set or a member set writable by the node service.
#                    Companions, required when named:
#     SHADE_TREE_GROUP_CONTRACT        StakedReputationSet address (`staked`)                       (REQUIRED with staked)
#     SHADE_TREE_PAID_ACCESS_CONTRACT  PaidAccessSet address (`paid`)                                (REQUIRED with paid)
#     SHADE_TREE_RPC_URL               execution JSON-RPC the gateway reads those roots through   (REQUIRED with staked/paid)
#                    all three land in the gateway unit verbatim.
#   SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES  non-negative integer (default: 41943040 = 40 MiB)
#                    combined opaque payload relayed in both directions per RLN epoch slot.
#                    Same-node retries share the allowance; 0 explicitly disables the ceiling.
#   SHADE_TREE_EPOCH_SECONDS positive integer (default: 120) fixed RLN epoch; clients must match.
#   SHADE_TREE_TIERS comma-separated ascending limits (default: 8) admitted proof tiers.
#   SHADE_TREE_ROOT_FRESHNESS_SECONDS positive integer (default: epoch length) hard wall-clock
#                    lifetime for superseded roots and cached RPC snapshots.
#   SHADE_TREE_ZK_ARTIFACTS <id>=<verification-key-path>[,...]  explicit verification-key set
#                    accepted by the gateway and advertised by the heartbeat. Paths are absolute
#                    or relative to SHADE_TREE_DIR. Production automation should always set this;
#                    an empty value preserves the built-in development artifact behavior.
#   SHADE_TREE_ZK_ARTIFACT_LEGACY <id>  artifact implied by envelopes that omit `artifact` during
#                    a dual-key rollout. When set it must use the same bounded artifact-id grammar.
#   SHADE_TREE_REGISTRAR   1 | 0              (default: 0) OPT-IN 402 registrar (T-FEAT-7, docs/PAYMENTS.md
#                    "Shipped 2026-08-17"): sell membership leaves for a stablecoin over x402 / MPP.
#                    =1 renders + starts a hardened shade-tree-registrar.service (payments/registrar.mjs on
#                    127.0.0.1:SHADE_TREE_REGISTRAR_PORT) and publishes it as an EXTRA PORT of an onion this
#                    box already runs (HiddenServicePort <port> 127.0.0.1:<port> inside that HS block):
#                    the BOOTNODE onion on a bootnode+gateway box (buyers reach it at
#                    http://<bootnode-onion>:<port>/, and the bootnode advertises it in GET /health
#                    `pay: {...}`), or -- T-FEAT-9 -- the GATEWAY onion on a gateway-only box
#                    (SHADE_TREE_BOOTNODE_ONION set; buyers reach it at http://<gateway-onion>:<port>/).
#                    Either way the heartbeat advertises the offer in the gateway's signed caps
#                    (`caps.pay`), so a provider sells access on its own terms with its own
#                    PaidAccessSet. The OPERATOR KEY is a secret and deliberately NOT a
#                    tunable: after bootstrap, add it as a 0600 drop-in
#                    /etc/systemd/system/shade-tree-registrar.service.d/operator.conf
#                    (Environment=SHADE_TREE_REGISTRAR_KEY=0x…; docs/OPERATOR.md "Selling access via 402").
#                    Default OFF: the default render is byte-identical to before.
#                    Companions, read only when SHADE_TREE_REGISTRAR=1:
#     SHADE_TREE_PAID_ACCESS_CONTRACT  PaidAccessSet address the registrar inserts into            (REQUIRED)
#     SHADE_TREE_PAY_ASSET             EIP-3009 stablecoin address (Sepolia USDC 0x1c7D…7238, or the
#                                test tUSD from network/sepolia/contracts.json payAsset)      (REQUIRED)
#     SHADE_TREE_PAY_PRICES            per-tier price in atomic units, "8=100000,32=400000"       (REQUIRED)
#     SHADE_TREE_RPC_URL               execution JSON-RPC the registrar settles/inserts through   (REQUIRED)
#     SHADE_TREE_PAY_PROTOCOLS         rails to serve + advertise: x402,mpp | x402 | mpp   (default: x402,mpp)
#     SHADE_TREE_PAY_TO                stablecoin recipient        (default: unset = the operator key's address)
#     SHADE_TREE_REGISTRAR_PORT        loopback + onion port       (default: 8878)
#     SHADE_TREE_PAY_CHAIN_ID          chain id advertised (bootnode /health + gateway caps.pay) (default: 11155111 Sepolia)
#                    Selling access without ADMITTING paid leaves is a config error: SHADE_TREE_REGISTRAR=1
#                    requires `paid` in SHADE_TREE_ADMIT (this gateway must honour what it sells).
#   SHADE_TREE_FROM_BLOCK  <block>            (default: unset = not rendered) eth_getLogs START block for
#                    the gateway's on-chain root scans (0x-hex or decimal), passed into the gateway
#                    unit verbatim. Public RPCs cap one eth_getLogs call (publicnode: 50k blocks;
#                    docs/OPERATOR.md "public RPC log-range caps"); the gateway pages the scan
#                    itself and derives each contract's deploy block from the committed network
#                    record, so this is only needed for a contract the records do not know.
#     SHADE_TREE_FROM_BLOCKS <addr>=<block>,…  per-contract start blocks (same passthrough; wins over
#                    SHADE_TREE_FROM_BLOCK for the named contract). Both unset = default render, byte-identical.
#   SHADE_TREE_RENDER_ONLY <dir>   (default: unset) RENDER mode for tests/review: write the torrc
#                    include + systemd units under <dir>/etc/... and exit WITHOUT touching the
#                    host (no root, no apt, no tor/node install, no clone, no systemctl). Onions
#                    are fixed placeholders so the output is deterministic (golden-testable).
#                    `bootstrap.sh --render <dir>` is the same thing.
set -euo pipefail

if [ "${1:-}" = "--render" ]; then SHADE_TREE_RENDER_ONLY="${2:?--render needs a directory}"; shift 2; fi

die() { echo "bootstrap.sh: $*" >&2; exit 1; }
# --- network preset (OPS-11): join a published canopy with one command -----------------------
#   SHADENET_NETWORK=sepolia bash bootstrap.sh
# reads network/<name>/deployment.json (from SHADENET_NETWORK_RECORD=<file>, else from the repo
# at SHADENET_RECORD_REF, default main) and fills every UNSET tunable a joining node needs: the
# Elder onion and signer, the staked-root contract, RPC, deploy block, tiers, epoch, freshness,
# payload budget and accepted artifacts. SHADE_TREE_REF defaults to the record's immutable node
# commit, never a branch. Explicit env always wins. SHADE_TREE_NETWORK is accepted as an alias.
SHADENET_NETWORK="${SHADENET_NETWORK:-${SHADE_TREE_NETWORK:-}}"
SHADENET_NETWORK_RECORD="${SHADENET_NETWORK_RECORD:-}"
SHADENET_RECORD_REF="${SHADENET_RECORD_REF:-main}"
if [ -n "$SHADENET_NETWORK" ]; then
  [[ "$SHADENET_NETWORK" =~ ^[a-z0-9][a-z0-9-]{0,31}$ ]] || die "SHADENET_NETWORK must be a record name like sepolia"
  if [ -z "$SHADENET_NETWORK_RECORD" ]; then
    [[ "$SHADENET_RECORD_REF" =~ ^[A-Za-z0-9._/-]{1,100}$ ]] || die "SHADENET_RECORD_REF is not a git ref"
    command -v curl >/dev/null || die "SHADENET_NETWORK needs curl to fetch the deployment record"
    SHADENET_NETWORK_RECORD="$(mktemp)"
    repo="${SHADE_TREE_REPO:-https://github.com/dmarzzz/shade-tree-node}"
    raw="${repo/https:\/\/github.com\//https://raw.githubusercontent.com/}"
    curl -fsSL --proto '=https' "$raw/$SHADENET_RECORD_REF/network/$SHADENET_NETWORK/deployment.json" -o "$SHADENET_NETWORK_RECORD" \
      || die "could not fetch network/$SHADENET_NETWORK/deployment.json at $SHADENET_RECORD_REF"
  fi
  [ -f "$SHADENET_NETWORK_RECORD" ] || die "SHADENET_NETWORK_RECORD not found: $SHADENET_NETWORK_RECORD"
  command -v python3 >/dev/null || die "SHADENET_NETWORK needs python3 to read the deployment record"
  preset="$(python3 - "$SHADENET_NETWORK_RECORD" "${SHADE_TREE_ELDER_ONLY:-0}" <<'PY'
import json, re, shlex, sys
r = json.load(open(sys.argv[1], encoding="utf-8"))
if r.get("status") not in ("live", "staging"):
    sys.exit(f"record status is {r.get('status')!r}; only live or staging records can be joined")
elder, adm, rate = r["elder"], r["admission"], r["ratePolicy"]
staked = (adm.get("roots") or {}).get("staked") or {}
elder_only = sys.argv[2] in ("1", "true", "yes", "on")
out = {
    # A joining node announces to the Elder in the record; a joining Elder federates with it instead.
    ("SHADE_TREE_BOOTNODE_PEERS" if elder_only else "SHADE_TREE_BOOTNODE_ONION"): elder["onion"],
    "SHADE_TREE_BOOTNODE_SIGNER": elder["canopySigner"],
    "SHADE_TREE_EPOCH_SECONDS": rate["epochSeconds"],
    "SHADE_TREE_ROOT_FRESHNESS_SECONDS": rate["rootFreshnessSeconds"],
    "SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES": rate["payloadBytesPerSlot"],
    "SHADE_TREE_REF": r["services"]["node"]["commit"],
    "SHADE_TREE_ADMIT": "staked",
}
if staked:
    rpc = staked.get("rpcUrls") or [staked["rpcUrl"]]
    out.update({
        "SHADE_TREE_GROUP_CONTRACT": staked["contract"],
        "SHADE_TREE_RPC_URL": ",".join(rpc),
        "SHADE_TREE_FROM_BLOCK": staked["deployBlock"],
        "SHADE_TREE_TIERS": ",".join(str(t["limit"]) for t in staked["tiers"]),
    })
arts = [f'{a["id"]}={a["verificationKeyPath"]}' for a in (r.get("artifacts") or {}).get("accepted", [])]
if arts:
    out["SHADE_TREE_ZK_ARTIFACTS"] = ",".join(arts)
if elder.get("admission"):
    out["SHADE_TREE_ADMISSION"] = elder["admission"]
if elder.get("gatewayRegistry"):
    out["SHADE_TREE_GATEWAY_REGISTRY"] = elder["gatewayRegistry"]
for k, v in out.items():
    v = str(v)
    if not re.fullmatch(r"[A-Za-z0-9._:/,=@%+-]{1,512}", v):
        sys.exit(f"record value for {k} has unexpected characters")
    print(f"{k}={shlex.quote(v)}")
PY
)" || die "network/$SHADENET_NETWORK deployment record is not joinable"
  while IFS='=' read -r key value; do
    [ -n "$key" ] || continue
    value="${value#\'}"; value="${value%\'}"
    [ -z "${!key:-}" ] || continue            # explicit env wins
    printf -v "$key" '%s' "$value"
    export "$key"
  done <<< "$preset"
  # A node joining a published canopy admits staked members only; invited needs the operator's
  # private members file, so it is added only when one is supplied.
  [ -n "${SHADE_TREE_MEMBERS_FILE:-}" ] && [ "${SHADE_TREE_ADMIT:-}" = "staked" ] && SHADE_TREE_ADMIT="invited,staked"
  SHADENET_PRESET_APPLIED=1
fi
SHADENET_PRESET_APPLIED="${SHADENET_PRESET_APPLIED:-0}"


SHADE_TREE_REPO="${SHADE_TREE_REPO:-https://github.com/dmarzzz/shade-tree-node}"
# Default ref: the preset's immutable commit, else main (a self-contained test canopy). For a
# public canopy always pass a tag or 40-hex commit; a branch prints a warning below.
SHADE_TREE_REF="${SHADE_TREE_REF:-main}"
SHADE_TREE_DIR="${SHADE_TREE_DIR:-/opt/shade-tree}"
SHADE_TREE_ADMISSION="${SHADE_TREE_ADMISSION:-open}"
SHADE_TREE_BOOTNODE_PORT="${SHADE_TREE_BOOTNODE_PORT:-8877}"
SHADE_TREE_GATEWAY_PORT="${SHADE_TREE_GATEWAY_PORT:-8443}"
SHADE_TREE_ENABLE_POW="${SHADE_TREE_ENABLE_POW:-0}"
SHADE_TREE_BOOTNODE_ONION="${SHADE_TREE_BOOTNODE_ONION:-}"
SHADE_TREE_BOOTNODE_SIGNER="${SHADE_TREE_BOOTNODE_SIGNER:-}"
SHADE_TREE_ELDER_ONLY="${SHADE_TREE_ELDER_ONLY:-0}"
SHADE_TREE_BOOTNODE_PEERS="${SHADE_TREE_BOOTNODE_PEERS:-}"
SHADE_TREE_GATEWAY_REGISTRY="${SHADE_TREE_GATEWAY_REGISTRY:-}"
SHADE_TREE_GATEWAY_REGION="${SHADE_TREE_GATEWAY_REGION:-}"
SHADE_TREE_RENDER_ONLY="${SHADE_TREE_RENDER_ONLY:-}"
RUN_USER="${SHADE_TREE_USER:-shade-tree}"
SHADE_TREE_HELIOS="${SHADE_TREE_HELIOS:-0}"
SHADE_TREE_HELIOS_CONSENSUS_RPC="${SHADE_TREE_HELIOS_CONSENSUS_RPC:-}"
SHADE_TREE_RPC_URL="${SHADE_TREE_RPC_URL:-}"
SHADE_TREE_GROUP_CONTRACT="${SHADE_TREE_GROUP_CONTRACT:-}"
SHADE_TREE_HELIOS_NETWORK="${SHADE_TREE_HELIOS_NETWORK:-sepolia}"
SHADE_TREE_HELIOS_PORT="${SHADE_TREE_HELIOS_PORT:-8546}"
SHADE_TREE_HELIOS_CHECKPOINT="${SHADE_TREE_HELIOS_CHECKPOINT:-}"
SHADE_TREE_HELIOS_VERSION="${SHADE_TREE_HELIOS_VERSION:-0.11.1}"
SHADE_TREE_HELIOS_SHA256="${SHADE_TREE_HELIOS_SHA256:-}"
HELIOS_BIN=/usr/local/bin/helios
SHADE_TREE_ADMIT="${SHADE_TREE_ADMIT:-invited}"
SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES="${SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES:-41943040}"
SHADE_TREE_EPOCH_SECONDS="${SHADE_TREE_EPOCH_SECONDS:-120}"
SHADE_TREE_TIERS="${SHADE_TREE_TIERS:-8}"
SHADE_TREE_ROOT_FRESHNESS_SECONDS="${SHADE_TREE_ROOT_FRESHNESS_SECONDS:-$SHADE_TREE_EPOCH_SECONDS}"
SHADE_TREE_MEMBERS_FILE="${SHADE_TREE_MEMBERS_FILE:-}"
SHADE_TREE_REGISTRAR="${SHADE_TREE_REGISTRAR:-0}"
SHADE_TREE_PAY_PROTOCOLS="${SHADE_TREE_PAY_PROTOCOLS:-x402,mpp}"
SHADE_TREE_PAID_ACCESS_CONTRACT="${SHADE_TREE_PAID_ACCESS_CONTRACT:-}"
SHADE_TREE_PAY_ASSET="${SHADE_TREE_PAY_ASSET:-}"
SHADE_TREE_PAY_PRICES="${SHADE_TREE_PAY_PRICES:-}"
SHADE_TREE_PAY_TO="${SHADE_TREE_PAY_TO:-}"
SHADE_TREE_REGISTRAR_PORT="${SHADE_TREE_REGISTRAR_PORT:-8878}"
SHADE_TREE_PAY_CHAIN_ID="${SHADE_TREE_PAY_CHAIN_ID:-11155111}"
SHADE_TREE_FROM_BLOCK="${SHADE_TREE_FROM_BLOCK:-}"
SHADE_TREE_FROM_BLOCKS="${SHADE_TREE_FROM_BLOCKS:-}"
SHADE_TREE_ZK_ARTIFACTS="${SHADE_TREE_ZK_ARTIFACTS:-}"
SHADE_TREE_ZK_ARTIFACT_LEGACY="${SHADE_TREE_ZK_ARTIFACT_LEGACY:-}"
SHADE_TREE_LOG_LEVEL="${SHADE_TREE_LOG_LEVEL:-info}"
SHADE_TREE_LOG_FORMAT="${SHADE_TREE_LOG_FORMAT:-json}"
SHADE_TREE_BANNER="${SHADE_TREE_BANNER:-never}"
SHADE_TREE_ELDER_METRICS_PORT="${SHADE_TREE_ELDER_METRICS_PORT:-9100}"
SHADE_TREE_NODE_METRICS_PORT="${SHADE_TREE_NODE_METRICS_PORT:-9101}"
SHADE_TREE_REGISTRAR_METRICS_PORT="${SHADE_TREE_REGISTRAR_METRICS_PORT:-9102}"
SHADE_TREE_HEARTBEAT_METRICS_PORT="${SHADE_TREE_HEARTBEAT_METRICS_PORT:-9103}"
SHADE_TREE_FLEET_TALLY_PEERS="${SHADE_TREE_FLEET_TALLY_PEERS:-}"
SHADE_TREE_FLEET_TALLY_TOKEN="${SHADE_TREE_FLEET_TALLY_TOKEN:-}"
SHADE_TREE_FLEET_TALLY_PORT="${SHADE_TREE_FLEET_TALLY_PORT:-8879}"
# Pinned sha256 of the a16z/helios 0.11.1 release tarballs (github.com/a16z/helios/releases/tag/0.11.1),
# computed 2026-08-17 from the downloaded assets. Another SHADE_TREE_HELIOS_VERSION must bring its own
# SHADE_TREE_HELIOS_SHA256 (no unpinned download, ever).
helios_pinned_sha256() {  # $1 = version, $2 = amd64|arm64 -> echoes sha256 or nothing
  case "$1:$2" in
    0.11.1:amd64) echo 339bf4ce73073c53790e41e3217b6d91f0e5d8571132b9e88689997613162ddb ;;
    0.11.1:arm64) echo 20132e1f772af246eac3885bcba3b54c21a98ac24027a5853eca2fb0edc5dab6 ;;
    *) ;;
  esac
}

SHADE_TREE_NODE_VERSION="${SHADE_TREE_NODE_VERSION:-24.20.0}"
# sha256 of the nodejs.org linux tarballs, checked against SHASUMS256.txt 2026-09-28.
node_pinned_sha256() {  # $1 = version, $2 = x64|arm64
  case "$1:$2" in
    24.20.0:x64)   echo 2f2c0da162318f0de47665410c7c8c2ed3d36c8f3105de4bbc61176c70a7cbf2 ;;
    24.20.0:arm64) echo 5f4ddab610c1ab2016b3c227cebdbf6d9495161487e4739c7b90090595f465f7 ;;
    *) ;;
  esac
}
SHADE_TREE_CREDENTIALS_FROM="${SHADE_TREE_CREDENTIALS_FROM:-}"
SHADE_TREE_JOURNAL_MAX_USE="${SHADE_TREE_JOURNAL_MAX_USE:-500M}"
SHADE_TREE_JOURNAL_RETENTION="${SHADE_TREE_JOURNAL_RETENTION:-14day}"

log() { echo -e "\n\033[1;36m== $*\033[0m"; }
die() { echo "bootstrap.sh: $*" >&2; exit 1; }


# --- validate the tunables up front (fail fast, before anything is installed) ---
case "$SHADE_TREE_ENABLE_POW" in
  1|true|yes|on)   SHADE_TREE_ENABLE_POW=1 ;;
  0|false|no|off)  SHADE_TREE_ENABLE_POW=0 ;;
  *) die "SHADE_TREE_ENABLE_POW must be 1 or 0 (got '$SHADE_TREE_ENABLE_POW')" ;;
esac
case "$SHADE_TREE_ELDER_ONLY" in
  1|true|yes|on)   SHADE_TREE_ELDER_ONLY=1 ;;
  0|false|no|off)  SHADE_TREE_ELDER_ONLY=0 ;;
  *) die "SHADE_TREE_ELDER_ONLY must be 1 or 0 (got '$SHADE_TREE_ELDER_ONLY')" ;;
esac
case "$SHADE_TREE_ADMISSION" in open|stake) ;; *) die "SHADE_TREE_ADMISSION must be open or stake (got '$SHADE_TREE_ADMISSION')" ;; esac
case "$SHADE_TREE_LOG_LEVEL" in debug|info|warn|error|off) ;; *) die "SHADE_TREE_LOG_LEVEL must be debug, info, warn, error, or off" ;; esac
case "$SHADE_TREE_LOG_FORMAT" in auto|pretty|text|json) ;; *) die "SHADE_TREE_LOG_FORMAT must be auto, pretty, text, or json" ;; esac
case "$SHADE_TREE_BANNER" in auto|always|never|on|off|true|false|1|0) ;; *) die "SHADE_TREE_BANNER must be auto, always, or never" ;; esac
for service_port in "$SHADE_TREE_BOOTNODE_PORT" "$SHADE_TREE_GATEWAY_PORT"; do
  { [[ "$service_port" =~ ^[0-9]{4,5}$ ]] && [ "$service_port" -ge 1024 ] && [ "$service_port" -le 65535 ]; } \
    || die "bootnode and gateway ports must be in 1024..65535 (got '$service_port')"
done
metrics_ports_seen=""
for metrics_port in "$SHADE_TREE_ELDER_METRICS_PORT" "$SHADE_TREE_NODE_METRICS_PORT" "$SHADE_TREE_REGISTRAR_METRICS_PORT" "$SHADE_TREE_HEARTBEAT_METRICS_PORT"; do
  { [[ "$metrics_port" =~ ^[0-9]{4,5}$ ]] && [ "$metrics_port" -ge 1024 ] && [ "$metrics_port" -le 65535 ]; } \
    || die "operator metrics ports must be in 1024..65535 (got '$metrics_port')"
  case " $metrics_ports_seen " in *" $metrics_port "*) die "operator metrics ports must be distinct (duplicate '$metrics_port')" ;; esac
  metrics_ports_seen="$metrics_ports_seen $metrics_port"
done
# Mode: default is bootnode + gateway; SHADE_TREE_BOOTNODE_ONION selects gateway-only;
#       SHADE_TREE_ELDER_ONLY=1 selects a dedicated Elder with no gateway or heartbeat.
WITH_BOOTNODE=1
WITH_GATEWAY=1
if [ "$SHADE_TREE_ELDER_ONLY" = "1" ] && [ -n "$SHADE_TREE_BOOTNODE_ONION" ]; then
  die "SHADE_TREE_ELDER_ONLY is mutually exclusive with SHADE_TREE_BOOTNODE_ONION"
fi
if [ -n "$SHADE_TREE_BOOTNODE_ONION" ]; then
  SHADE_TREE_BOOTNODE_ONION="${SHADE_TREE_BOOTNODE_ONION%.onion}.onion"
  [[ "$SHADE_TREE_BOOTNODE_ONION" =~ ^[a-z2-7]{56}\.onion$ ]] \
    || die "SHADE_TREE_BOOTNODE_ONION must be a v3 onion address (56 base32 chars, optional .onion suffix)"
  WITH_BOOTNODE=0
fi
if [ "$SHADE_TREE_ELDER_ONLY" = "1" ]; then WITH_GATEWAY=0; fi
if [ -n "$SHADE_TREE_GATEWAY_REGION" ]; then
  case "$SHADE_TREE_GATEWAY_REGION" in na|sa|eu|af|as|oc|aq|unknown) ;;
    *) die "SHADE_TREE_GATEWAY_REGION must be one of na sa eu af as oc aq unknown (got '$SHADE_TREE_GATEWAY_REGION')" ;; esac
fi
if [ "$WITH_GATEWAY" = "0" ] && [ -n "$SHADE_TREE_GATEWAY_REGION" ]; then
  die "SHADE_TREE_GATEWAY_REGION is not valid in Elder-only mode"
fi
case "$SHADE_TREE_HELIOS" in
  1|true|yes|on)   SHADE_TREE_HELIOS=1 ;;
  0|false|no|off)  SHADE_TREE_HELIOS=0 ;;
  *) die "SHADE_TREE_HELIOS must be 1 or 0 (got '$SHADE_TREE_HELIOS')" ;;
esac
if [ "$SHADE_TREE_HELIOS" = "1" ]; then
  [ "$WITH_GATEWAY" = "1" ] || die "SHADE_TREE_HELIOS=1 requires a gateway; it is not valid in Elder-only mode"
  # URLs: http(s) (ws(s) too for the execution RPC), no whitespace/quotes/semicolons (they land in unit files).
  [[ "$SHADE_TREE_HELIOS_CONSENSUS_RPC" =~ ^https?://[A-Za-z0-9._~:/?#@!$\&*+,=%-]+$ ]] \
    || die "SHADE_TREE_HELIOS=1 needs SHADE_TREE_HELIOS_CONSENSUS_RPC=<http(s) beacon API URL serving the light-client endpoints>"
  [[ "$SHADE_TREE_RPC_URL" =~ ^(https?|wss?)://[A-Za-z0-9._~:/?#@!$\&*+,=%-]+$ ]] \
    || die "SHADE_TREE_HELIOS=1 needs SHADE_TREE_RPC_URL=<execution JSON-RPC URL that serves eth_getProof at finalized>"
  [[ "$SHADE_TREE_GROUP_CONTRACT" =~ ^0x[0-9a-fA-F]{40}$ ]] \
    || die "SHADE_TREE_HELIOS=1 needs SHADE_TREE_GROUP_CONTRACT=<0x StakedReputationSet address> (the gateway reads its roots from it)"
  case "$SHADE_TREE_HELIOS_NETWORK" in mainnet|sepolia|holesky) ;;
    *) die "SHADE_TREE_HELIOS_NETWORK must be mainnet, sepolia or holesky (got '$SHADE_TREE_HELIOS_NETWORK')" ;; esac
  { [[ "$SHADE_TREE_HELIOS_PORT" =~ ^[0-9]{4,5}$ ]] && [ "$SHADE_TREE_HELIOS_PORT" -ge 1024 ] && [ "$SHADE_TREE_HELIOS_PORT" -le 65535 ]; } \
    || die "SHADE_TREE_HELIOS_PORT must be a port in 1024..65535 (got '$SHADE_TREE_HELIOS_PORT')"
  { [ -z "$SHADE_TREE_HELIOS_CHECKPOINT" ] || [[ "$SHADE_TREE_HELIOS_CHECKPOINT" =~ ^0x[0-9a-fA-F]{64}$ ]]; } \
    || die "SHADE_TREE_HELIOS_CHECKPOINT must be a 0x-prefixed 32-byte beacon block root (got '$SHADE_TREE_HELIOS_CHECKPOINT')"
  [[ "$SHADE_TREE_HELIOS_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "SHADE_TREE_HELIOS_VERSION must look like 0.11.1 (got '$SHADE_TREE_HELIOS_VERSION')"
  { [ -z "$SHADE_TREE_HELIOS_SHA256" ] || [[ "$SHADE_TREE_HELIOS_SHA256" =~ ^[0-9a-fA-F]{64}$ ]]; } || die "SHADE_TREE_HELIOS_SHA256 must be 64 hex chars"
fi

# Admission policy (T-FEAT-9): a comma list drawn from invited|staked|paid, normalized to the
# canonical anonymity order (invited,staked,paid) so the rendered unit is deterministic. Each named
# on-chain path needs its contract + an RPC here (the gateway fails closed at startup otherwise).
SHADE_TREE_ADMIT="$(echo "$SHADE_TREE_ADMIT" | tr 'A-Z' 'a-z' | tr -d ' ')"
[[ "$SHADE_TREE_ADMIT" =~ ^(invited|staked|paid)(,(invited|staked|paid))*$ ]] \
  || die "SHADE_TREE_ADMIT must be a comma list drawn from invited, staked, paid (got '$SHADE_TREE_ADMIT')"
ADMIT_INVITED=0; ADMIT_STAKED=0; ADMIT_PAID=0
case ",$SHADE_TREE_ADMIT," in *,invited,*) ADMIT_INVITED=1 ;; esac
case ",$SHADE_TREE_ADMIT," in *,staked,*)  ADMIT_STAKED=1 ;;  esac
case ",$SHADE_TREE_ADMIT," in *,paid,*)    ADMIT_PAID=1 ;;    esac
SHADE_TREE_ADMIT=""
[ "$ADMIT_INVITED" = "1" ] && SHADE_TREE_ADMIT="invited"
[ "$ADMIT_STAKED" = "1" ]  && SHADE_TREE_ADMIT="${SHADE_TREE_ADMIT:+$SHADE_TREE_ADMIT,}staked"
[ "$ADMIT_PAID" = "1" ]    && SHADE_TREE_ADMIT="${SHADE_TREE_ADMIT:+$SHADE_TREE_ADMIT,}paid"
if [ "$ADMIT_STAKED" = "1" ]; then
  [[ "$SHADE_TREE_GROUP_CONTRACT" =~ ^0x[0-9a-fA-F]{40}(,0x[0-9a-fA-F]{40})*$ ]] \
    || die "SHADE_TREE_ADMIT names staked: needs SHADE_TREE_GROUP_CONTRACT=<0x StakedReputationSet address[,...]>"
fi
if [ "$WITH_GATEWAY" = "1" ] && [ "$ADMIT_INVITED" = "1" ] && [ -z "$SHADE_TREE_RENDER_ONLY" ]; then
  [ -n "$SHADE_TREE_MEMBERS_FILE" ] \
    || die "SHADE_TREE_ADMIT includes invited: pass SHADE_TREE_MEMBERS_FILE=/absolute/path/to/operator-members.json (the committed group/members.json is demo data and is never trusted by the live bootstrap)"
  [[ "$SHADE_TREE_MEMBERS_FILE" = /* ]] \
    || die "SHADE_TREE_MEMBERS_FILE must be an absolute path (got '$SHADE_TREE_MEMBERS_FILE')"
  [ -r "$SHADE_TREE_MEMBERS_FILE" ] && [ -s "$SHADE_TREE_MEMBERS_FILE" ] \
    || die "SHADE_TREE_MEMBERS_FILE must name a readable, non-empty file (got '$SHADE_TREE_MEMBERS_FILE')"
fi
[ -z "$SHADE_TREE_MEMBERS_FILE" ] || [[ "$SHADE_TREE_MEMBERS_FILE" =~ ^/[A-Za-z0-9._/+:-]+$ ]] \
  || die "SHADE_TREE_MEMBERS_FILE contains unsupported path characters (use an absolute path without spaces)"
SHADE_TREE_MEMBERS_RUNTIME_FILE="$SHADE_TREE_MEMBERS_FILE"
if [ "$WITH_GATEWAY" = "1" ] && [ "$ADMIT_INVITED" = "1" ] && [ -n "$SHADE_TREE_MEMBERS_FILE" ]; then
  SHADE_TREE_MEMBERS_RUNTIME_FILE="/etc/shade-tree/members.json"
fi
if [ "$ADMIT_PAID" = "1" ]; then
  [[ "$SHADE_TREE_PAID_ACCESS_CONTRACT" =~ ^0x[0-9a-fA-F]{40}$ ]] \
    || die "SHADE_TREE_ADMIT names paid: needs SHADE_TREE_PAID_ACCESS_CONTRACT=<0x PaidAccessSet address>"
fi
if [ "$ADMIT_STAKED" = "1" ] || [ "$ADMIT_PAID" = "1" ]; then
  [[ "$SHADE_TREE_RPC_URL" =~ ^(https?|wss?)://[A-Za-z0-9._~:/?#@!$\&*+,=%-]+$ ]] \
    || die "SHADE_TREE_ADMIT names ${SHADE_TREE_ADMIT}: needs SHADE_TREE_RPC_URL=<execution JSON-RPC URL> (the gateway reads on-chain roots through it)"
fi
{ [[ "$SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES" =~ ^(0|[1-9][0-9]{0,15})$ ]] && [ "$SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES" -le 9007199254740991 ]; } \
  || die "SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES must be an integer in 0..9007199254740991 (got '$SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES')"
[[ "$SHADE_TREE_EPOCH_SECONDS" =~ ^[1-9][0-9]{0,8}$ ]] \
  || die "SHADE_TREE_EPOCH_SECONDS must be a positive integer (got '$SHADE_TREE_EPOCH_SECONDS')"
[[ "$SHADE_TREE_ROOT_FRESHNESS_SECONDS" =~ ^[1-9][0-9]{0,8}$ ]] \
  || die "SHADE_TREE_ROOT_FRESHNESS_SECONDS must be a positive integer (got '$SHADE_TREE_ROOT_FRESHNESS_SECONDS')"
[[ "$SHADE_TREE_TIERS" =~ ^[1-9][0-9]{0,4}(,[1-9][0-9]{0,4})*$ ]] \
  || die "SHADE_TREE_TIERS must be a comma-separated tier list (got '$SHADE_TREE_TIERS')"
if [ "$SHADE_TREE_HELIOS" = "1" ] && [ "$ADMIT_STAKED" != "1" ]; then
  die "SHADE_TREE_HELIOS=1 anchors the ON-CHAIN (staked) admission root, but SHADE_TREE_ADMIT=${SHADE_TREE_ADMIT} does not admit staked leaves; set SHADE_TREE_ADMIT=invited,staked (or staked)"
fi

case "$SHADE_TREE_REGISTRAR" in
  1|true|yes|on)   SHADE_TREE_REGISTRAR=1 ;;
  0|false|no|off)  SHADE_TREE_REGISTRAR=0 ;;
  *) die "SHADE_TREE_REGISTRAR must be 1 or 0 (got '$SHADE_TREE_REGISTRAR')" ;;
esac
# Payment rails (T-FEAT-9): a non-empty subset of x402,mpp, normalized to the canonical order.
SHADE_TREE_PAY_PROTOCOLS="$(echo "$SHADE_TREE_PAY_PROTOCOLS" | tr 'A-Z' 'a-z' | tr -d ' ')"
[[ "$SHADE_TREE_PAY_PROTOCOLS" =~ ^(x402|mpp)(,(x402|mpp))*$ ]] \
  || die "SHADE_TREE_PAY_PROTOCOLS must be a comma list drawn from x402, mpp (got '$SHADE_TREE_PAY_PROTOCOLS')"
PAY_X402=0; PAY_MPP=0
case ",$SHADE_TREE_PAY_PROTOCOLS," in *,x402,*) PAY_X402=1 ;; esac
case ",$SHADE_TREE_PAY_PROTOCOLS," in *,mpp,*)  PAY_MPP=1 ;;  esac
SHADE_TREE_PAY_PROTOCOLS=""
[ "$PAY_X402" = "1" ] && SHADE_TREE_PAY_PROTOCOLS="x402"
[ "$PAY_MPP" = "1" ]  && SHADE_TREE_PAY_PROTOCOLS="${SHADE_TREE_PAY_PROTOCOLS:+$SHADE_TREE_PAY_PROTOCOLS,}mpp"
if [ "$SHADE_TREE_REGISTRAR" = "1" ]; then
  [ "$WITH_GATEWAY" = "1" ] || die "SHADE_TREE_REGISTRAR=1 requires a gateway; it is not valid in Elder-only mode"
  [ "$ADMIT_PAID" = "1" ] || die "SHADE_TREE_REGISTRAR=1 sells paid leaves but SHADE_TREE_ADMIT=${SHADE_TREE_ADMIT} does not admit them; set SHADE_TREE_ADMIT=${SHADE_TREE_ADMIT},paid (a gateway must honour what it sells)"
  [[ "$SHADE_TREE_PAID_ACCESS_CONTRACT" =~ ^0x[0-9a-fA-F]{40}$ ]] \
    || die "SHADE_TREE_REGISTRAR=1 needs SHADE_TREE_PAID_ACCESS_CONTRACT=<0x PaidAccessSet address>"
  [[ "$SHADE_TREE_PAY_ASSET" =~ ^0x[0-9a-fA-F]{40}$ ]] \
    || die "SHADE_TREE_REGISTRAR=1 needs SHADE_TREE_PAY_ASSET=<0x EIP-3009 stablecoin address>"
  [[ "$SHADE_TREE_PAY_PRICES" =~ ^[1-9][0-9]{0,4}=[1-9][0-9]*(,[1-9][0-9]{0,4}=[1-9][0-9]*)*$ ]] \
    || die "SHADE_TREE_REGISTRAR=1 needs SHADE_TREE_PAY_PRICES=<limit>=<atomic-amount>[,...] (e.g. 8=100000,32=400000)"
  [[ "$SHADE_TREE_RPC_URL" =~ ^(https?|wss?)://[A-Za-z0-9._~:/?#@!$\&*+,=%-]+$ ]] \
    || die "SHADE_TREE_REGISTRAR=1 needs SHADE_TREE_RPC_URL=<execution JSON-RPC URL>"
  { [ -z "$SHADE_TREE_PAY_TO" ] || [[ "$SHADE_TREE_PAY_TO" =~ ^0x[0-9a-fA-F]{40}$ ]]; } || die "SHADE_TREE_PAY_TO must be a 0x address"
  { [[ "$SHADE_TREE_REGISTRAR_PORT" =~ ^[0-9]{4,5}$ ]] && [ "$SHADE_TREE_REGISTRAR_PORT" -ge 1024 ] && [ "$SHADE_TREE_REGISTRAR_PORT" -le 65535 ]; } \
    || die "SHADE_TREE_REGISTRAR_PORT must be a port in 1024..65535 (got '$SHADE_TREE_REGISTRAR_PORT')"
  [[ "$SHADE_TREE_PAY_CHAIN_ID" =~ ^[1-9][0-9]{0,15}$ ]] || die "SHADE_TREE_PAY_CHAIN_ID must be a positive integer"
fi

FLEET_TALLY_ENABLED=0
if [ -n "$SHADE_TREE_FLEET_TALLY_PEERS" ]; then
  [ "$WITH_GATEWAY" = "1" ] || die "SHADE_TREE_FLEET_TALLY_PEERS requires a gateway; it is not valid in Elder-only mode"
  FLEET_TALLY_ENABLED=1
  { [[ "$SHADE_TREE_FLEET_TALLY_PORT" =~ ^[0-9]{4,5}$ ]] && [ "$SHADE_TREE_FLEET_TALLY_PORT" -ge 1024 ] && [ "$SHADE_TREE_FLEET_TALLY_PORT" -le 65535 ]; } \
    || die "SHADE_TREE_FLEET_TALLY_PORT must be a port in 1024..65535 (got '$SHADE_TREE_FLEET_TALLY_PORT')"
  [ "${#SHADE_TREE_FLEET_TALLY_TOKEN}" -ge 32 ] && [ "${#SHADE_TREE_FLEET_TALLY_TOKEN}" -le 128 ] && [[ "$SHADE_TREE_FLEET_TALLY_TOKEN" =~ ^[-A-Za-z0-9._~]+$ ]] \
    || die "SHADE_TREE_FLEET_TALLY_PEERS needs SHADE_TREE_FLEET_TALLY_TOKEN (32..128 URL-safe characters)"
  IFS=',' read -r -a TALLY_PEERS <<< "$SHADE_TREE_FLEET_TALLY_PEERS"
  for peer in "${TALLY_PEERS[@]}"; do
    [[ "$peer" =~ ^[a-z2-7]{56}\.onion:[0-9]{1,5}$ ]] \
      || die "bootstrap tally peers must be <56-char-v3-onion>.onion:<port> (got '$peer')"
    peer_port="${peer##*:}"
    [ "$peer_port" -ge 1 ] && [ "$peer_port" -le 65535 ] \
      || die "bootstrap tally peer port must be in 1..65535 (got '$peer_port')"
  done
fi

# Every active local listener must have its own port. A metrics listener sharing a Tor-mapped
# backend can otherwise win the bind race, accidentally putting /metrics behind an onion while
# the intended service crash-loops. Tor's local SOCKS port is reserved here for the same reason.
runtime_ports_seen=""
reserve_runtime_port() { # $1 = label, $2 = port
  case " $runtime_ports_seen " in
    *" $2 "*) die "active local service ports must be distinct; $1 reuses port $2" ;;
  esac
  runtime_ports_seen="$runtime_ports_seen $2"
}
reserve_runtime_port "Tor SOCKS" "9050"
if [ "$WITH_GATEWAY" = "1" ]; then
  reserve_runtime_port "gateway backend" "$SHADE_TREE_GATEWAY_PORT"
  reserve_runtime_port "node metrics" "$SHADE_TREE_NODE_METRICS_PORT"
  reserve_runtime_port "heartbeat metrics" "$SHADE_TREE_HEARTBEAT_METRICS_PORT"
fi
if [ "$WITH_BOOTNODE" = "1" ]; then
  reserve_runtime_port "bootnode backend" "$SHADE_TREE_BOOTNODE_PORT"
  reserve_runtime_port "Elder metrics" "$SHADE_TREE_ELDER_METRICS_PORT"
fi
if [ "$SHADE_TREE_REGISTRAR" = "1" ]; then
  reserve_runtime_port "registrar backend" "$SHADE_TREE_REGISTRAR_PORT"
  reserve_runtime_port "registrar metrics" "$SHADE_TREE_REGISTRAR_METRICS_PORT"
fi
if [ "$SHADE_TREE_HELIOS" = "1" ]; then
  reserve_runtime_port "Helios RPC" "$SHADE_TREE_HELIOS_PORT"
fi
[ "$FLEET_TALLY_ENABLED" = "1" ] && reserve_runtime_port "fleet tally backend" "$SHADE_TREE_FLEET_TALLY_PORT"

# eth_getLogs start blocks (gateway on-chain roots): a bare block, or <0xaddr>=<block> pairs. Both
# land verbatim in a unit file, so the shape is pinned here (no spaces/quotes/semicolons).
{ [ -z "$SHADE_TREE_FROM_BLOCK" ] || [[ "$SHADE_TREE_FROM_BLOCK" =~ ^(0x[0-9a-fA-F]{1,16}|[0-9]{1,16})$ ]]; } \
  || die "SHADE_TREE_FROM_BLOCK must be a block number (0x-hex or decimal; got '$SHADE_TREE_FROM_BLOCK')"
{ [ -z "$SHADE_TREE_FROM_BLOCKS" ] || [[ "$SHADE_TREE_FROM_BLOCKS" =~ ^0x[0-9a-fA-F]{40}=(0x[0-9a-fA-F]{1,16}|[0-9]{1,16})(,0x[0-9a-fA-F]{40}=(0x[0-9a-fA-F]{1,16}|[0-9]{1,16}))*$ ]]; } \
  || die "SHADE_TREE_FROM_BLOCKS must be <0xaddress>=<block>[,...] (got '$SHADE_TREE_FROM_BLOCKS')"

# Explicit proof artifacts are part of the signed capability surface. Keep this shell-side guard
# deliberately narrower than lib/zk-artifacts.mjs: only bounded ids and plain file paths may enter
# a systemd Environment= line. Runtime startup then verifies each id against the vkey bytes.
if [ -n "$SHADE_TREE_ZK_ARTIFACTS" ]; then
  [[ "$SHADE_TREE_ZK_ARTIFACTS" =~ ^[a-z0-9][a-z0-9._-]{0,63}=[A-Za-z0-9._/+:-]+(,[a-z0-9][a-z0-9._-]{0,63}=[A-Za-z0-9._/+:-]+)*$ ]] \
    || die "SHADE_TREE_ZK_ARTIFACTS must be <artifact-id>=<verification-key-path>[,...]"
  case "/$SHADE_TREE_ZK_ARTIFACTS/" in *"/../"*|*"/./"*) die "SHADE_TREE_ZK_ARTIFACTS paths must not contain . or .. segments" ;; esac
fi
{ [ -z "$SHADE_TREE_ZK_ARTIFACT_LEGACY" ] || [[ "$SHADE_TREE_ZK_ARTIFACT_LEGACY" =~ ^[a-z0-9][a-z0-9._-]{0,63}$ ]]; } \
  || die "SHADE_TREE_ZK_ARTIFACT_LEGACY must be a bounded lowercase artifact id"
[ -z "$SHADE_TREE_ZK_ARTIFACT_LEGACY" ] || [ -n "$SHADE_TREE_ZK_ARTIFACTS" ] \
  || die "SHADE_TREE_ZK_ARTIFACT_LEGACY requires an explicit SHADE_TREE_ZK_ARTIFACTS set"

[[ "$SHADE_TREE_JOURNAL_MAX_USE" =~ ^[0-9]{1,6}[KMG]$ ]] || die "SHADE_TREE_JOURNAL_MAX_USE must look like 500M"
[[ "$SHADE_TREE_JOURNAL_RETENTION" =~ ^[0-9]{1,4}(day|week|month|h)$ ]] || die "SHADE_TREE_JOURNAL_RETENTION must look like 14day"
[[ "$SHADE_TREE_NODE_VERSION" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || die "SHADE_TREE_NODE_VERSION must be x.y.z"
[ -z "$SHADE_TREE_CREDENTIALS_FROM" ] || [ -d "$SHADE_TREE_CREDENTIALS_FROM" ] || die "SHADE_TREE_CREDENTIALS_FROM must be a directory"

for peer in ${SHADE_TREE_BOOTNODE_PEERS//,/ }; do
  [[ "${peer%.onion}" =~ ^[a-z2-7]{56}$ ]] || die "SHADE_TREE_BOOTNODE_PEERS must be comma-separated v3 onions"
done
if [ -n "$SHADE_TREE_GATEWAY_REGISTRY" ]; then
  [[ "$SHADE_TREE_GATEWAY_REGISTRY" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "SHADE_TREE_GATEWAY_REGISTRY must be 0x<40 hex>"
  [ -n "$SHADE_TREE_RPC_URL" ] || die "SHADE_TREE_GATEWAY_REGISTRY needs SHADE_TREE_RPC_URL"
fi

# --- renderers: the ONLY places torrc / unit text is produced (live + render mode share them) ---
# torrc include: one HiddenServiceDir block per onion this box publishes. The PoW line is a
# per-service option, so it sits INSIDE each block right after its HiddenServicePort.
render_torrc() {  # $1 = output file
  {
    if [ "$WITH_BOOTNODE" = "1" ]; then
      if [ "$WITH_GATEWAY" = "1" ]; then
        echo "# shade-tree: two onion services (bootnode + gateway). PoW defense: SHADE_TREE_ENABLE_POW=${SHADE_TREE_ENABLE_POW}."
      else
        echo "# shade-tree: dedicated Elder onion service. PoW defense: SHADE_TREE_ENABLE_POW=${SHADE_TREE_ENABLE_POW}."
      fi
      echo "HiddenServiceDir /var/lib/tor/shade-tree-bootnode"
      echo "HiddenServicePort 80 127.0.0.1:${SHADE_TREE_BOOTNODE_PORT}"
      # The 402 registrar rides the SAME onion on an extra virtual port (SHADE_TREE_REGISTRAR=1).
      [ "$SHADE_TREE_REGISTRAR" = "1" ] && echo "HiddenServicePort ${SHADE_TREE_REGISTRAR_PORT} 127.0.0.1:${SHADE_TREE_REGISTRAR_PORT}"
      echo "HiddenServicePoWDefensesEnabled ${SHADE_TREE_ENABLE_POW}"
    else
      echo "# shade-tree: gateway-only box (bootnode is remote: ${SHADE_TREE_BOOTNODE_ONION}). PoW defense: SHADE_TREE_ENABLE_POW=${SHADE_TREE_ENABLE_POW}."
    fi
    if [ "$WITH_GATEWAY" = "1" ]; then
      echo "HiddenServiceDir /var/lib/tor/shade-tree-gateway"
      echo "HiddenServicePort 80 127.0.0.1:${SHADE_TREE_GATEWAY_PORT}"
      [ "$FLEET_TALLY_ENABLED" = "1" ] && echo "HiddenServicePort ${SHADE_TREE_FLEET_TALLY_PORT} 127.0.0.1:${SHADE_TREE_FLEET_TALLY_PORT}"
      # Gateway-only box: the 402 registrar rides the GATEWAY onion on an extra virtual port (T-FEAT-9).
      [ "$SHADE_TREE_REGISTRAR" = "1" ] && [ "$WITH_BOOTNODE" = "0" ] && echo "HiddenServicePort ${SHADE_TREE_REGISTRAR_PORT} 127.0.0.1:${SHADE_TREE_REGISTRAR_PORT}"
      echo "HiddenServicePoWDefensesEnabled ${SHADE_TREE_ENABLE_POW}"
    fi
  } > "$1"
}

# Sandbox rationale (applied identically to every unit below). Each is a plain Node
# process that needs: outbound network (bootnode/heartbeat over Tor SOCKS on loopback, Node
# fetch), read access to the repo, and write access ONLY to ${SHADE_TREE_DIR}/deploy-state (the
# bootnode mints its signer key there at runtime; the gateway/heartbeat read the minted onion
# identities from there; persistence writes there too) plus a private /tmp.
#   NoNewPrivileges       no setuid/capability escalation ever
#   ProtectSystem=strict  whole FS read-only; ReadWritePaths re-opens deploy-state (see above)
#   ProtectHome           /home,/root,/run/user hidden (service user is --system, no $HOME use)
#   PrivateTmp            private /tmp,/var/tmp, unshared from the host
#   ProtectKernel*/CGroups block /proc/sys, /sys, kmod, and cgroup writes (none needed)
#   RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX  IPv4/IPv6 + AF_UNIX for the Tor SOCKS
#                          path/DNS resolver sockets; everything exotic (AF_PACKET, AF_NETLINK…) denied
#   RestrictNamespaces/LockPersonality  no new namespaces, no persona (ASLR) downgrades
#   SystemCallFilter=@system-service  vetted allowlist for normal services; implicitly EXCLUDES
#                          @privileged/@mount/@reboot/@swap/@module etc. (~=EPERM below)
#   CapabilityBoundingSet= (empty) drop ALL capabilities — the services bind only loopback high
#                          ports (>1024), so no CAP_NET_BIND_SERVICE or anything else is required
#   CPUQuota/CPUWeight/Nice keep Shade Tree subordinate to deadline-sensitive validator or AI work
#   MemoryMax/MemorySwapMax/TasksMax contain runaway RSS, swap pressure, and fork storms
# MemoryDenyWriteExecute is deliberately NOT set: V8's JIT maps writable-then-executable pages,
# so W^X enforcement would crash the Node runtime. Left off on purpose.
render_sandbox() {
  local cpu_quota="${1:-50%}" memory_max="${2:-512M}" tasks_max="${3:-128}"
  cat <<EOF
# --- secrets: systemd credentials (OPS-12). Files named SHADE_TREE_<SECRET> in /etc/credstore
# (root, 0600) reach the service via \$CREDENTIALS_DIRECTORY, never Environment= or systemctl show.
ImportCredential=SHADE_TREE_*
# --- sandbox (see rationale in bootstrap.sh) ---
NoNewPrivileges=true
UMask=0077
ProtectSystem=strict
ReadWritePaths=${SHADE_TREE_DIR}/deploy-state
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectClock=true
ProtectHostname=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectProc=invisible
ProcSubset=pid
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
RemoveIPC=true
SystemCallFilter=@system-service
SystemCallArchitectures=native
CapabilityBoundingSet=
Nice=5
CPUAccounting=true
CPUQuota=${cpu_quota}
CPUWeight=25
MemoryAccounting=true
MemoryMax=${memory_max}
MemorySwapMax=0
TasksAccounting=true
TasksMax=${tasks_max}
[Install]
WantedBy=multi-user.target
EOF
}

render_bootnode_unit() {  # $1 = output file
  {
    cat <<EOF
[Unit]
Description=shade-tree bootnode (gateway discovery)
After=network-online.target tor.service
Wants=network-online.target
[Service]
User=${RUN_USER}
WorkingDirectory=${SHADE_TREE_DIR}
Environment=SHADE_TREE_BOOTNODE_PORT=${SHADE_TREE_BOOTNODE_PORT}
Environment=SHADE_TREE_BOOTNODE_ADMISSION=${SHADE_TREE_ADMISSION}
Environment=SHADE_TREE_BOOTNODE_SIGNER_KEY=${SHADE_TREE_DIR}/deploy-state/bootnode-signer.key
Environment=SHADE_TREE_BOOTNODE_STORE=${SHADE_TREE_DIR}/deploy-state/bootnode-state.json
Environment=SHADE_TREE_METRICS_PORT=${SHADE_TREE_ELDER_METRICS_PORT}
Environment=SHADE_TREE_LOG_LEVEL=${SHADE_TREE_LOG_LEVEL}
Environment=SHADE_TREE_LOG_FORMAT=${SHADE_TREE_LOG_FORMAT}
Environment=SHADE_TREE_BANNER=${SHADE_TREE_BANNER}
SyslogIdentifier=shade-tree-elder
EOF
    if [ "$SHADE_TREE_ADMISSION" = "stake" ] && [ -n "$SHADE_TREE_GATEWAY_REGISTRY" ]; then
      # Stake admission: the Elder checks each announcing operator in GatewayRegistry.
      echo "Environment=SHADE_TREE_STAKE_MODE=onchain"
      echo "Environment=SHADE_TREE_GATEWAY_REGISTRY=${SHADE_TREE_GATEWAY_REGISTRY}"
      echo "Environment=SHADE_TREE_RPC_URL=${SHADE_TREE_RPC_URL}"
    fi
    # Federation (T-FEAT-1, OPS-9): pull and re-verify peers' announces.
    [ -z "$SHADE_TREE_BOOTNODE_PEERS" ] || echo "Environment=SHADE_TREE_BOOTNODE_PEERS=${SHADE_TREE_BOOTNODE_PEERS}"
    if [ "$SHADE_TREE_REGISTRAR" = "1" ]; then
      # Advertise the registrar in GET /health (`pay: {port, protocols, asset, chain, tiers}`).
      echo "Environment=SHADE_TREE_REGISTRAR_ADVERTISE=1"
      echo "Environment=SHADE_TREE_REGISTRAR_PORT=${SHADE_TREE_REGISTRAR_PORT}"
      echo "Environment=SHADE_TREE_PAY_ASSET=${SHADE_TREE_PAY_ASSET}"
      echo "Environment=SHADE_TREE_PAY_PRICES=${SHADE_TREE_PAY_PRICES}"
      echo "Environment=SHADE_TREE_PAY_CHAIN_ID=${SHADE_TREE_PAY_CHAIN_ID}"
      echo "Environment=SHADE_TREE_PAY_PROTOCOLS=${SHADE_TREE_PAY_PROTOCOLS}"
    fi
    cat <<EOF
ExecStart=${NODE_BIN} ${SHADE_TREE_DIR}/bootnode/server.mjs
Restart=always
RestartSec=3
EOF
    render_sandbox "25%" "256M" "96"
  } > "$1"
}

# The 402 registrar (T-FEAT-7): a loopback Node service that sells membership leaves over x402 /
# MPP (SHADE_TREE_PAY_PROTOCOLS) and inserts them into the PaidAccessSet from the operator key. Same
# sandbox as the other units; its order store lives under deploy-state (the one writable path).
# REG_ONION is the onion it rides (bootnode's, or the gateway's on a gateway-only box, T-FEAT-9).
# SHADE_TREE_REGISTRAR_KEY is a SECRET and is NOT rendered here: add it as a 0600 drop-in after bootstrap.
render_registrar_unit() {  # $1 = output file
  {
    cat <<EOF
[Unit]
Description=shade-tree 402 registrar (sell membership leaves: x402 + MPP -> PaidAccessSet)
After=network-online.target tor.service
Wants=network-online.target
[Service]
User=${RUN_USER}
WorkingDirectory=${SHADE_TREE_DIR}
Environment=SHADE_TREE_REGISTRAR_PORT=${SHADE_TREE_REGISTRAR_PORT}
Environment=SHADE_TREE_REGISTRAR_ONION=${REG_ONION}
Environment=SHADE_TREE_REGISTRAR_STORE=${SHADE_TREE_DIR}/deploy-state/registrar-state.json
Environment=SHADE_TREE_PAID_ACCESS_CONTRACT=${SHADE_TREE_PAID_ACCESS_CONTRACT}
Environment=SHADE_TREE_PAY_ASSET=${SHADE_TREE_PAY_ASSET}
Environment=SHADE_TREE_PAY_PRICES=${SHADE_TREE_PAY_PRICES}
Environment=SHADE_TREE_PAY_PROTOCOLS=${SHADE_TREE_PAY_PROTOCOLS}
Environment=SHADE_TREE_RPC_URL=${SHADE_TREE_RPC_URL}
Environment=SHADE_TREE_METRICS_PORT=${SHADE_TREE_REGISTRAR_METRICS_PORT}
Environment=SHADE_TREE_LOG_LEVEL=${SHADE_TREE_LOG_LEVEL}
Environment=SHADE_TREE_LOG_FORMAT=${SHADE_TREE_LOG_FORMAT}
Environment=SHADE_TREE_BANNER=${SHADE_TREE_BANNER}
SyslogIdentifier=shade-tree-registrar
EOF
    [ -z "$SHADE_TREE_PAY_TO" ] || echo "Environment=SHADE_TREE_PAY_TO=${SHADE_TREE_PAY_TO}"
    cat <<EOF
ExecStart=${NODE_BIN} ${SHADE_TREE_DIR}/payments/registrar.mjs
Restart=always
RestartSec=5
EOF
    render_sandbox "40%" "384M" "96"
  } > "$1"
}

# With SHADE_TREE_HELIOS=1 the gateway is ordered after the sidecar and told to read on-chain roots
# through the light provider anchored to it (SHADE_TREE_ROOT_PROVIDER=light + SHADE_TREE_HELIOS_RPC_URL);
# lib/root-provider.mjs fails closed if the sidecar is down/mismatched, so the gateway simply
# restarts until Helios is synced. Default (SHADE_TREE_HELIOS=0): byte-identical to before.
render_gateway_unit() {  # $1 = output file
  {
    echo "[Unit]"
    echo "Description=Shade Tree tunnel gateway"
    if [ "$SHADE_TREE_HELIOS" = "1" ]; then
      echo "After=network-online.target tor.service shade-tree-helios.service"
      echo "Wants=network-online.target shade-tree-helios.service"
    else
      echo "After=network-online.target tor.service"
      echo "Wants=network-online.target"
    fi
    cat <<EOF
[Service]
User=${RUN_USER}
WorkingDirectory=${SHADE_TREE_DIR}
Environment=SHADE_TREE_ADMIT=${SHADE_TREE_ADMIT}
Environment=SHADE_TREE_GATEWAY_PORT=${SHADE_TREE_GATEWAY_PORT}
Environment=SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES=${SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES}
Environment=SHADE_TREE_EPOCH_SECONDS=${SHADE_TREE_EPOCH_SECONDS}
Environment=SHADE_TREE_TIERS=${SHADE_TREE_TIERS}
Environment=SHADE_TREE_ROOT_FRESHNESS_SECONDS=${SHADE_TREE_ROOT_FRESHNESS_SECONDS}
Environment=SHADE_TREE_METRICS_PORT=${SHADE_TREE_NODE_METRICS_PORT}
Environment=SHADE_TREE_LOG_LEVEL=${SHADE_TREE_LOG_LEVEL}
Environment=SHADE_TREE_LOG_FORMAT=${SHADE_TREE_LOG_FORMAT}
Environment=SHADE_TREE_BANNER=${SHADE_TREE_BANNER}
SyslogIdentifier=shade-tree-node
EOF
    if [ "$FLEET_TALLY_ENABLED" = "1" ]; then
      echo "Environment=SHADE_TREE_FLEET_TALLY_PEERS=${SHADE_TREE_FLEET_TALLY_PEERS}"
      echo "Environment=SHADE_TREE_FLEET_TALLY_LISTEN=127.0.0.1:${SHADE_TREE_FLEET_TALLY_PORT}"
      echo "Environment=SHADE_TREE_TOR_HOST=127.0.0.1"
      echo "Environment=SHADE_TREE_TOR_PORT=9050"
      echo "EnvironmentFile=-/etc/shade-tree/fleet-tally.env"
    fi
    [ "$ADMIT_INVITED" = "1" ] && [ -n "$SHADE_TREE_MEMBERS_RUNTIME_FILE" ] && echo "Environment=SHADE_TREE_MEMBERS_FILE=${SHADE_TREE_MEMBERS_RUNTIME_FILE}"
    # Admission policy companions (T-FEAT-9): the contracts + RPC behind each admitted on-chain
    # path (SHADE_TREE_HELIOS=1 implies staked). Only rendered when the policy needs them.
    if [ "$ADMIT_STAKED" = "1" ] || [ "$SHADE_TREE_HELIOS" = "1" ]; then echo "Environment=SHADE_TREE_GROUP_CONTRACT=${SHADE_TREE_GROUP_CONTRACT}"; fi
    if [ "$ADMIT_PAID" = "1" ]; then echo "Environment=SHADE_TREE_PAID_ACCESS_CONTRACT=${SHADE_TREE_PAID_ACCESS_CONTRACT}"; fi
    if [ "$ADMIT_STAKED" = "1" ] || [ "$ADMIT_PAID" = "1" ] || [ "$SHADE_TREE_HELIOS" = "1" ]; then echo "Environment=SHADE_TREE_RPC_URL=${SHADE_TREE_RPC_URL}"; fi
    if [ "$SHADE_TREE_HELIOS" = "1" ]; then
      echo "Environment=SHADE_TREE_ROOT_PROVIDER=light"
      echo "Environment=SHADE_TREE_HELIOS_RPC_URL=http://127.0.0.1:${SHADE_TREE_HELIOS_PORT}"
    fi
    # eth_getLogs start block(s) for the on-chain root scan (only when given; unset = no line).
    [ -z "$SHADE_TREE_FROM_BLOCK" ]  || echo "Environment=SHADE_TREE_FROM_BLOCK=${SHADE_TREE_FROM_BLOCK}"
    [ -z "$SHADE_TREE_FROM_BLOCKS" ] || echo "Environment=SHADE_TREE_FROM_BLOCKS=${SHADE_TREE_FROM_BLOCKS}"
    [ -z "$SHADE_TREE_ZK_ARTIFACTS" ] || echo "Environment=SHADE_TREE_ZK_ARTIFACTS=${SHADE_TREE_ZK_ARTIFACTS}"
    [ -z "$SHADE_TREE_ZK_ARTIFACT_LEGACY" ] || echo "Environment=SHADE_TREE_ZK_ARTIFACT_LEGACY=${SHADE_TREE_ZK_ARTIFACT_LEGACY}"
    cat <<EOF
ExecStart=${NODE_BIN} ${SHADE_TREE_DIR}/gateway/gateway.mjs
Restart=always
RestartSec=3
EOF
    render_sandbox "75%" "512M" "128"
  } > "$1"
}

# The Helios sidecar (T-DEV-9b, docs/LIGHT-CLIENT.md option A): a local JSON-RPC that only
# answers with sync-committee-verified headers/state. Endpoints go in via helios' own env vars
# (EXECUTION_RPC / CONSENSUS_RPC / CHECKPOINT) rather than argv so an API key in a URL is not
# in `ps`. Binds loopback only. Same sandbox as the other units; helios is a Rust binary (no
# JIT), so W^X (MemoryDenyWriteExecute) is ON here even though the Node units must leave it off.
# The checkpoint cache lives under deploy-state (already the one writable path).
render_helios_unit() {  # $1 = output file
  {
    cat <<EOF
[Unit]
Description=shade-tree helios light client (sync-committee verified stateRoot anchor, ${SHADE_TREE_HELIOS_NETWORK})
After=network-online.target
Wants=network-online.target
[Service]
User=${RUN_USER}
WorkingDirectory=${SHADE_TREE_DIR}
Environment=RUST_LOG=info
Environment=EXECUTION_RPC=${SHADE_TREE_RPC_URL}
Environment=CONSENSUS_RPC=${SHADE_TREE_HELIOS_CONSENSUS_RPC}
EOF
    if [ -n "$SHADE_TREE_HELIOS_CHECKPOINT" ]; then
      echo "Environment=CHECKPOINT=${SHADE_TREE_HELIOS_CHECKPOINT}"
      echo "ExecStart=${HELIOS_BIN} ethereum --network ${SHADE_TREE_HELIOS_NETWORK} --rpc-bind-ip 127.0.0.1 --rpc-port ${SHADE_TREE_HELIOS_PORT} --data-dir ${SHADE_TREE_DIR}/deploy-state/helios"
    else
      echo "ExecStart=${HELIOS_BIN} ethereum --network ${SHADE_TREE_HELIOS_NETWORK} --rpc-bind-ip 127.0.0.1 --rpc-port ${SHADE_TREE_HELIOS_PORT} --data-dir ${SHADE_TREE_DIR}/deploy-state/helios --load-external-fallback"
    fi
    cat <<EOF
Restart=always
RestartSec=5
MemoryDenyWriteExecute=true
EOF
    render_sandbox "40%" "384M" "96"
  } > "$1"
}

# The gateway announces itself to the bootnode (local one by default, SHADE_TREE_BOOTNODE_ONION in
# gateway-only mode). It uses the gateway onion identity and the local Tor SOCKS. (For
# admission=stake, add Environment=SHADE_TREE_GW_OPERATOR_KEY=... here after staking -- a secret,
# so it is deliberately NOT a bootstrap.sh tunable; see bootnode/deploy/README.md.)
render_heartbeat_unit() {  # $1 = output file
  {
    if [ "$WITH_BOOTNODE" = "1" ]; then
      echo "[Unit]"
      echo "Description=shade-tree gateway heartbeat to bootnode"
      echo "After=shade-tree-bootnode.service tor.service"
    else
      echo "[Unit]"
      echo "Description=shade-tree gateway heartbeat to remote bootnode ${SHADE_TREE_BOOTNODE_ONION}"
      echo "After=network-online.target tor.service"
      echo "Wants=network-online.target"
    fi
    cat <<EOF
[Service]
User=${RUN_USER}
WorkingDirectory=${SHADE_TREE_DIR}
Environment=SHADE_TREE_BOOTNODE_ONION=${BN_ONION}
Environment=SHADE_TREE_GW_IDENTITY=${GW_HS}/identity.local.json
Environment=SHADE_TREE_TOR_PORT=9050
Environment=SHADE_TREE_ADMIT=${SHADE_TREE_ADMIT}
Environment=SHADE_TREE_EPOCH_SECONDS=${SHADE_TREE_EPOCH_SECONDS}
Environment=SHADE_TREE_TIERS=${SHADE_TREE_TIERS}
Environment=SHADE_TREE_ROOT_FRESHNESS_SECONDS=${SHADE_TREE_ROOT_FRESHNESS_SECONDS}
Environment=SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES=${SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES}
Environment=SHADE_TREE_HEARTBEAT_METRICS_PORT=${SHADE_TREE_HEARTBEAT_METRICS_PORT}
Environment=SHADE_TREE_LOG_LEVEL=${SHADE_TREE_LOG_LEVEL}
Environment=SHADE_TREE_LOG_FORMAT=${SHADE_TREE_LOG_FORMAT}
Environment=SHADE_TREE_BANNER=${SHADE_TREE_BANNER}
SyslogIdentifier=shade-tree-heartbeat
EOF
    [ -z "$SHADE_TREE_GATEWAY_REGION" ] || echo "Environment=SHADE_TREE_GATEWAY_REGION=${SHADE_TREE_GATEWAY_REGION}"
    # Heartbeat loads the same vkeys and advertises their content-derived ids in signed caps.
    [ -z "$SHADE_TREE_ZK_ARTIFACTS" ] || echo "Environment=SHADE_TREE_ZK_ARTIFACTS=${SHADE_TREE_ZK_ARTIFACTS}"
    if [ "$SHADE_TREE_REGISTRAR" = "1" ]; then
      # Advertise the offer in the gateway's SIGNED caps (`caps.pay`, T-FEAT-9) -- the same
      # advert the bootnode puts in /health; SHADE_TREE_REGISTRAR_ONION names the onion it rides.
      echo "Environment=SHADE_TREE_REGISTRAR_ADVERTISE=1"
      echo "Environment=SHADE_TREE_REGISTRAR_PORT=${SHADE_TREE_REGISTRAR_PORT}"
      echo "Environment=SHADE_TREE_REGISTRAR_ONION=${REG_ONION}"
      echo "Environment=SHADE_TREE_PAY_ASSET=${SHADE_TREE_PAY_ASSET}"
      echo "Environment=SHADE_TREE_PAY_PRICES=${SHADE_TREE_PAY_PRICES}"
      echo "Environment=SHADE_TREE_PAY_CHAIN_ID=${SHADE_TREE_PAY_CHAIN_ID}"
      echo "Environment=SHADE_TREE_PAY_PROTOCOLS=${SHADE_TREE_PAY_PROTOCOLS}"
    fi
    cat <<EOF
ExecStart=${NODE_BIN} ${SHADE_TREE_DIR}/bootnode/heartbeat.mjs
Restart=always
RestartSec=10
EOF
    render_sandbox "20%" "256M" "96"
  } > "$1"
}

BN_HS="$SHADE_TREE_DIR/deploy-state/bootnode-hs"
GW_HS="$SHADE_TREE_DIR/deploy-state/gateway-hs"

# --- RENDER mode: emit the files and stop -------------------------------------------------
if [ -n "$SHADE_TREE_RENDER_ONLY" ]; then
  NODE_BIN="${SHADE_TREE_NODE_BIN:-/usr/bin/node}"
  if [ "$WITH_GATEWAY" = "1" ]; then GW_ONION="gatewayplaceholderplaceholderplaceholderplaceholderplace.onion"; else GW_ONION=""; fi
  if [ "$WITH_BOOTNODE" = "1" ]; then BN_ONION="bootnodeplaceholderplaceholderplaceholderplaceholderplac.onion"; else BN_ONION="$SHADE_TREE_BOOTNODE_ONION"; fi
  if [ "$WITH_BOOTNODE" = "1" ]; then REG_ONION="$BN_ONION"; else REG_ONION="$GW_ONION"; fi
  out="$SHADE_TREE_RENDER_ONLY"
  mkdir -p "$out/etc/tor" "$out/etc/systemd/system"
  render_torrc "$out/etc/tor/torrc.d-shade-tree"
  [ "$WITH_BOOTNODE" = "1" ] && render_bootnode_unit "$out/etc/systemd/system/shade-tree-bootnode.service"
  [ "$WITH_GATEWAY" = "1" ] && render_gateway_unit "$out/etc/systemd/system/shade-tree-gateway.service"
  [ "$WITH_GATEWAY" = "1" ] && render_heartbeat_unit "$out/etc/systemd/system/shade-tree-heartbeat.service"
  [ "$SHADE_TREE_HELIOS" = "1" ] && render_helios_unit "$out/etc/systemd/system/shade-tree-helios.service"
  [ "$SHADE_TREE_REGISTRAR" = "1" ] && render_registrar_unit "$out/etc/systemd/system/shade-tree-registrar.service"
  if [ "$WITH_GATEWAY" = "0" ]; then render_mode="elder-only"; elif [ "$WITH_BOOTNODE" = "1" ]; then render_mode="bootnode+gateway"; else render_mode="gateway-only"; fi
  echo "rendered to $out (mode: ${render_mode}, pow=${SHADE_TREE_ENABLE_POW}, helios=${SHADE_TREE_HELIOS}, registrar=${SHADE_TREE_REGISTRAR}, admit=${SHADE_TREE_ADMIT}$([ "$SHADE_TREE_REGISTRAR" = "1" ] && echo ", pay=${SHADE_TREE_PAY_PROTOCOLS}"))"
  exit 0
fi

# --- LIVE mode --------------------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || { echo "run as root or with sudo"; exit 1; }

[[ "$SHADE_TREE_REF" =~ ^([0-9a-f]{40}|v[0-9]+\.[0-9]+\.[0-9]+.*)$ ]] \
  || echo "bootstrap.sh: WARNING: SHADE_TREE_REF=$SHADE_TREE_REF is a branch; pin a release tag or commit for a public canopy" >&2

log "packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl gnupg ca-certificates git apt-transport-https xz-utils >/dev/null

log "node 24"
# Node < 24 is upgraded, not tolerated: the units below run under
# SystemCallFilter=@system-service, and Node 20's V8 calls pkey_alloc (syscall 330) at
# startup, which that allowlist does not include -> every unit dies with SIGSYS
# (status=31/SYS) in a restart loop. Observed on the 2026-08-17 go-live box (pre-installed
# NodeSource 20.20.2); Node 24 starts clean under the same filter. See
# docs/GO-LIVE-LOG-2026-08-17.md (Phase 1.3).
# The runtime is a pinned, checksum-verified nodejs.org release (OPS-11), not an unpinned
# `curl | bash` of a third-party apt setup script. Another version must bring its own sha256.
case "$(uname -m)" in x86_64) NODE_ARCH=x64 ;; aarch64|arm64) NODE_ARCH=arm64 ;; *) die "unsupported CPU $(uname -m)" ;; esac
NODE_SHA256="${SHADE_TREE_NODE_SHA256:-$(node_pinned_sha256 "$SHADE_TREE_NODE_VERSION" "$NODE_ARCH")}"
# Installed privately under /opt/node-v<version>; the units and npm use it by absolute path, so a
# system node that other software on the host depends on is left alone.
node_dir="/opt/node-v${SHADE_TREE_NODE_VERSION}"
if [ -z "${SHADE_TREE_NODE_BIN:-}" ] && [ "$("$node_dir/bin/node" -p process.versions.node 2>/dev/null)" != "$SHADE_TREE_NODE_VERSION" ]; then
  [ -n "$NODE_SHA256" ] || die "no pinned sha256 for node $SHADE_TREE_NODE_VERSION ($NODE_ARCH); set SHADE_TREE_NODE_SHA256"
  node_tar="$(mktemp)"
  curl -fsSL --proto '=https' "https://nodejs.org/dist/v${SHADE_TREE_NODE_VERSION}/node-v${SHADE_TREE_NODE_VERSION}-linux-${NODE_ARCH}.tar.xz" -o "$node_tar"
  echo "${NODE_SHA256}  ${node_tar}" | sha256sum -c --quiet - || die "node tarball checksum mismatch"
  rm -rf "$node_dir" && mkdir -p "$node_dir"
  tar -xJf "$node_tar" -C "$node_dir" --strip-components=1 || die "could not unpack node $SHADE_TREE_NODE_VERSION"
  rm -f "$node_tar"
fi
NODE_BIN="${SHADE_TREE_NODE_BIN:-$node_dir/bin/node}"
"$NODE_BIN" --version

log "tor (official repo, for pow: yes)"
if ! command -v tor >/dev/null; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc \
    | gpg --dearmor -o /etc/apt/keyrings/tor.gpg
  . /etc/os-release
  echo "deb [signed-by=/etc/apt/keyrings/tor.gpg] https://deb.torproject.org/torproject.org ${VERSION_CODENAME} main" \
    > /etc/apt/sources.list.d/tor.list
  apt-get update -qq
  apt-get install -y -qq tor deb.torproject.org-keyring >/dev/null
fi
tor --version | head -1

log "service user + repo"
id -u "$RUN_USER" >/dev/null 2>&1 || useradd --system --create-home --shell /usr/sbin/nologin "$RUN_USER"
# A file:// source (the e2e containers bind-mount the checkout) is usually owned by a
# different uid than root; git >= 2.35.2 refuses to read it ("dubious ownership") until
# the path is marked safe. Scoped to that one path; a URL source is unaffected.
case "$SHADE_TREE_REPO" in
  file://*)
    _src="${SHADE_TREE_REPO#file://}"
    # git resolves a file:// clone source to its .git dir and checks THAT path.
    git config --global --add safe.directory "$_src"
    git config --global --add safe.directory "$_src/.git"
    ;;
esac
if [ -d "$SHADE_TREE_DIR/.git" ]; then
  git -C "$SHADE_TREE_DIR" fetch --depth 1 origin "$SHADE_TREE_REF" -q && git -C "$SHADE_TREE_DIR" checkout -q FETCH_HEAD
else
  # init + fetch works for a branch, a tag and a bare commit SHA alike (a shallow
  # `clone --branch` cannot take a SHA, which is what SHADENET_NETWORK pins).
  # Never delete an existing install: its deploy-state holds the onion identities.
  if [ -e "$SHADE_TREE_DIR" ] && [ -n "$(ls -A "$SHADE_TREE_DIR" 2>/dev/null)" ]; then
    die "$SHADE_TREE_DIR exists, is not a git checkout and is not empty; move it aside first"
  fi
  git init -q "$SHADE_TREE_DIR"
  git -C "$SHADE_TREE_DIR" remote add origin "$SHADE_TREE_REPO"
  git -C "$SHADE_TREE_DIR" fetch --depth 1 -q origin "$SHADE_TREE_REF" && git -C "$SHADE_TREE_DIR" checkout -q FETCH_HEAD
fi
( cd "$SHADE_TREE_DIR" && PATH="$(dirname "$NODE_BIN"):$PATH" npm install --omit=dev --no-audit --no-fund >/dev/null 2>&1 )

# A live invited gateway must trust an operator-supplied set, never the repository's demo
# members. Validate the document with the runtime we just installed, then copy it outside every
# service-writable directory. The root-owned file is group-readable by the node, but the node
# cannot rewrite its own admission root. This also keeps a later bootstrap invocation idempotent:
# the source remains explicit, while the unit always reads the canonical protected copy.
if [ "$WITH_GATEWAY" = "1" ] && [ "$ADMIT_INVITED" = "1" ]; then
  MEMBERS_SOURCE="$SHADE_TREE_MEMBERS_FILE"
  "$NODE_BIN" - "$MEMBERS_SOURCE" <<'NODE'
const { readFileSync } = require("node:fs");
const path = process.argv[2];
let doc;
try { doc = JSON.parse(readFileSync(path, "utf8")); }
catch (error) { console.error(`bootstrap.sh: invalid SHADE_TREE_MEMBERS_FILE ${path}: ${error.message}`); process.exit(1); }
const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
if (doc?.version !== 2 || !Array.isArray(doc.members) || doc.members.length === 0 || doc.members.length > 2 ** 20 ||
    doc.members.some((leaf) => typeof leaf !== "string" || !/^(0|[1-9][0-9]*)$/.test(leaf) || BigInt(leaf) >= FIELD)) {
  console.error("bootstrap.sh: SHADE_TREE_MEMBERS_FILE must contain 1..1048576 canonical decimal-string BN254 field elements");
  process.exit(1);
}
NODE
  install -d -o root -g "$RUN_USER" -m 0750 /etc/shade-tree
  MEMBERS_DEST="/etc/shade-tree/members.json"
  if [ -e "$MEMBERS_DEST" ] && [ "$MEMBERS_SOURCE" -ef "$MEMBERS_DEST" ]; then
    chown "root:$RUN_USER" "$MEMBERS_DEST"
    chmod 0640 "$MEMBERS_DEST"
  else
    install -o root -g "$RUN_USER" -m 0640 "$MEMBERS_SOURCE" "$MEMBERS_DEST"
  fi
fi

log "onion identities (reused if present)"
if [ "$WITH_BOOTNODE" = "1" ]; then
  [ -f "$BN_HS/hostname" ] || "$NODE_BIN" "$SHADE_TREE_DIR/bootnode/keygen.mjs" "$BN_HS" --label bootnode >/dev/null
  BN_ONION="$(cat "$BN_HS/hostname")"
else
  BN_ONION="$SHADE_TREE_BOOTNODE_ONION"   # remote; nothing minted here
fi
if [ "$WITH_GATEWAY" = "1" ]; then
  [ -f "$GW_HS/hostname" ] || "$NODE_BIN" "$SHADE_TREE_DIR/bootnode/keygen.mjs" "$GW_HS" --label gateway  >/dev/null
  GW_ONION="$(cat "$GW_HS/hostname")"
else
  GW_ONION=""
fi
if [ "$WITH_BOOTNODE" = "1" ]; then REG_ONION="$BN_ONION"; else REG_ONION="$GW_ONION"; fi   # the onion the 402 registrar rides

if [ "$WITH_GATEWAY" = "0" ]; then log "tor config (dedicated Elder hidden service only, pow=${SHADE_TREE_ENABLE_POW})"; elif [ "$WITH_BOOTNODE" = "1" ]; then log "tor config (two hidden services, pow=${SHADE_TREE_ENABLE_POW})"; else log "tor config (gateway hidden service only, pow=${SHADE_TREE_ENABLE_POW})"; fi
# Tor owns the HS dirs; copy the minted keys into tor's own dirs (Tor is strict about perms).
HS_PAIRS=()
[ "$WITH_BOOTNODE" = "1" ] && HS_PAIRS+=("$BN_HS:/var/lib/tor/shade-tree-bootnode")
[ "$WITH_GATEWAY" = "1" ] && HS_PAIRS+=("$GW_HS:/var/lib/tor/shade-tree-gateway")
for pair in "${HS_PAIRS[@]}"; do
  src="${pair%%:*}"; dst="${pair##*:}"
  install -d -o debian-tor -g debian-tor -m 0700 "$dst"
  install -o debian-tor -g debian-tor -m 0600 "$src/hs_ed25519_secret_key" "$dst/"
  install -o debian-tor -g debian-tor -m 0600 "$src/hs_ed25519_public_key" "$dst/"
  install -o debian-tor -g debian-tor -m 0600 "$src/hostname" "$dst/"
done
render_torrc /etc/tor/torrc.d-shade-tree
grep -q "torrc.d-shade-tree" /etc/tor/torrc || echo "%include /etc/tor/torrc.d-shade-tree" >> /etc/tor/torrc
systemctl enable tor >/dev/null 2>&1 || true
systemctl restart tor

if [ "$SHADE_TREE_HELIOS" = "1" ]; then
  log "helios ${SHADE_TREE_HELIOS_VERSION} light-client sidecar (sha256-pinned release binary)"
  # Release layout (checked 2026-08-17): helios_linux_{amd64,arm64,armv7,riscv64gc}.tar.gz, each
  # a tarball containing the single `helios` binary at its root. Anything else -> manual install
  # (docs/LIGHT-CLIENT.md "Sidecar"): put a `helios` on ${HELIOS_BIN} and re-run.
  case "$(dpkg --print-architecture 2>/dev/null || uname -m)" in
    amd64|x86_64) HELIOS_ARCH=amd64 ;;
    arm64|aarch64) HELIOS_ARCH=arm64 ;;
    *) die "no pinned helios build for this arch; install helios ${SHADE_TREE_HELIOS_VERSION} manually at ${HELIOS_BIN} (docs/LIGHT-CLIENT.md)" ;;
  esac
  WANT_SHA="${SHADE_TREE_HELIOS_SHA256:-$(helios_pinned_sha256 "$SHADE_TREE_HELIOS_VERSION" "$HELIOS_ARCH")}"
  [ -n "$WANT_SHA" ] || die "no pinned sha256 for helios ${SHADE_TREE_HELIOS_VERSION}/${HELIOS_ARCH}; pass SHADE_TREE_HELIOS_SHA256=<sha256 of helios_linux_${HELIOS_ARCH}.tar.gz>"
  if [ -x "$HELIOS_BIN" ] && "$HELIOS_BIN" --version 2>/dev/null | grep -q " ${SHADE_TREE_HELIOS_VERSION}\$"; then
    echo "helios ${SHADE_TREE_HELIOS_VERSION} already installed at ${HELIOS_BIN}"
  else
    tmpd="$(mktemp -d)"
    curl -fsSL -o "$tmpd/helios.tar.gz" \
      "https://github.com/a16z/helios/releases/download/${SHADE_TREE_HELIOS_VERSION}/helios_linux_${HELIOS_ARCH}.tar.gz"
    echo "${WANT_SHA}  $tmpd/helios.tar.gz" | sha256sum -c - >/dev/null \
      || die "helios tarball sha256 mismatch (want ${WANT_SHA}); refusing to install"
    tar -xzf "$tmpd/helios.tar.gz" -C "$tmpd" helios
    install -o root -g root -m 0755 "$tmpd/helios" "$HELIOS_BIN"
    rm -rf "$tmpd"
  fi
  "$HELIOS_BIN" --version
  install -d -o "$RUN_USER" -g "$RUN_USER" -m 0700 "$SHADE_TREE_DIR/deploy-state/helios"
  render_helios_unit /etc/systemd/system/shade-tree-helios.service
  systemctl daemon-reload
  systemctl enable --now shade-tree-helios >/dev/null 2>&1 || systemctl restart shade-tree-helios
elif [ -f /etc/systemd/system/shade-tree-helios.service ]; then
  # A previous run had the sidecar on; SHADE_TREE_HELIOS=0 (default) means it must go, and the gateway
  # unit rendered below no longer points at it.
  systemctl disable --now shade-tree-helios >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/shade-tree-helios.service
fi

log "systemd units"
FLEET_TALLY_ENV_FILE=/etc/shade-tree/fleet-tally.env
if [ "$FLEET_TALLY_ENABLED" = "1" ]; then
  # Keep the directory traversable by the node's primary group when invited admission also
  # installs members.json here. The tally token itself remains root-only below.
  install -d -o root -g "$RUN_USER" -m 0750 /etc/shade-tree
  FLEET_TALLY_ENV_TMP="$(mktemp /etc/shade-tree/.fleet-tally.env.XXXXXX)"
  ( umask 077; printf 'SHADE_TREE_FLEET_TALLY_TOKEN=%s\n' "$SHADE_TREE_FLEET_TALLY_TOKEN" > "$FLEET_TALLY_ENV_TMP" )
  chown root:root "$FLEET_TALLY_ENV_TMP"
  chmod 0600 "$FLEET_TALLY_ENV_TMP"
  mv -f "$FLEET_TALLY_ENV_TMP" "$FLEET_TALLY_ENV_FILE"
else
  # An omitted peer list is the off switch. Do not leave the previous shared bearer token
  # behind after disabling the listener on an idempotent re-run.
  rm -f "$FLEET_TALLY_ENV_FILE"
fi

# `enable --now` starts an inactive unit but deliberately does not reload an active one. Remember
# the pre-run state so a live re-run applies new peer/token configuration (or stops a disabled
# tally listener) without needlessly double-starting the gateway on its first install.
if [ "$WITH_GATEWAY" = "1" ] && systemctl is-active --quiet shade-tree-gateway; then
  GATEWAY_WAS_ACTIVE=1
else
  GATEWAY_WAS_ACTIVE=0
fi
UNITS=""
log "journald caps + credentials"
install -d -m 0755 /etc/systemd/journald.conf.d
printf '[Journal]\nSystemMaxUse=%s\nMaxRetentionSec=%s\n' "$SHADE_TREE_JOURNAL_MAX_USE" "$SHADE_TREE_JOURNAL_RETENTION" \
  > /etc/systemd/journald.conf.d/shade-tree.conf
systemctl restart systemd-journald || true
install -d -m 0700 /etc/credstore
if [ -n "$SHADE_TREE_CREDENTIALS_FROM" ]; then
  # Copy SHADE_TREE_* secret files (e.g. SHADE_TREE_GW_OPERATOR_KEY) into the credential store.
  for f in "$SHADE_TREE_CREDENTIALS_FROM"/SHADE_TREE_*; do
    [ -f "$f" ] || continue
    install -m 0600 -o root -g root "$f" "/etc/credstore/$(basename "$f")"
  done
fi

if [ "$WITH_BOOTNODE" = "1" ]; then
  render_bootnode_unit /etc/systemd/system/shade-tree-bootnode.service
  UNITS="shade-tree-bootnode"
elif [ -f /etc/systemd/system/shade-tree-bootnode.service ]; then
  # A previous run of this box was bootnode+gateway; gateway-only means that unit must go.
  systemctl disable --now shade-tree-bootnode >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/shade-tree-bootnode.service
fi
if [ "$WITH_GATEWAY" = "1" ]; then
  render_gateway_unit /etc/systemd/system/shade-tree-gateway.service
  UNITS="${UNITS:+$UNITS }shade-tree-gateway"
elif [ -f /etc/systemd/system/shade-tree-gateway.service ]; then
  systemctl disable --now shade-tree-gateway >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/shade-tree-gateway.service
fi
# the deploy-state dir must be writable by the service user (signer key is minted at runtime)
chown -R "$RUN_USER":"$RUN_USER" "$SHADE_TREE_DIR/deploy-state"
systemctl daemon-reload
# shellcheck disable=SC2086
if ! systemctl enable --now $UNITS >/dev/null 2>&1; then
  systemctl restart $UNITS
elif [ "$WITH_GATEWAY" = "1" ] && [ "$GATEWAY_WAS_ACTIVE" = "1" ]; then
  systemctl restart shade-tree-gateway
fi

if [ "$WITH_GATEWAY" = "1" ]; then
  log "gateway heartbeat -> bootnode ${BN_ONION}"
  render_heartbeat_unit /etc/systemd/system/shade-tree-heartbeat.service
  systemctl daemon-reload
  systemctl enable --now shade-tree-heartbeat >/dev/null 2>&1 || systemctl restart shade-tree-heartbeat
elif [ -f /etc/systemd/system/shade-tree-heartbeat.service ]; then
  systemctl disable --now shade-tree-heartbeat >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/shade-tree-heartbeat.service
  systemctl daemon-reload
fi

if [ "$SHADE_TREE_REGISTRAR" = "1" ]; then
  log "402 registrar on ${REG_ONION}:${SHADE_TREE_REGISTRAR_PORT} (rails: ${SHADE_TREE_PAY_PROTOCOLS}; onion: $([ "$WITH_BOOTNODE" = "1" ] && echo bootnode || echo gateway))"
  render_registrar_unit /etc/systemd/system/shade-tree-registrar.service
  systemctl daemon-reload
  if [ -f /etc/systemd/system/shade-tree-registrar.service.d/operator.conf ]; then
    systemctl enable --now shade-tree-registrar >/dev/null 2>&1 || systemctl restart shade-tree-registrar
  else
    systemctl enable shade-tree-registrar >/dev/null 2>&1 || true
    echo "shade-tree-registrar: NOT started — add the operator key drop-in first (see the summary below), then: systemctl start shade-tree-registrar"
  fi
elif [ -f /etc/systemd/system/shade-tree-registrar.service ]; then
  systemctl disable --now shade-tree-registrar >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/shade-tree-registrar.service
fi

print_client_setup() {
  local bootnode="$1"
  local signer="$2"
  cat <<EOF
Client setup (the member loads their secret; the operator supplies the exact tier and profile):
  read -s SHADE_TREE_SECRET && export SHADE_TREE_SECRET
  read -r SHADE_TREE_LIMIT && export SHADE_TREE_LIMIT
EOF
  if [ "$ADMIT_INVITED" = "1" ]; then
    cat <<'EOF'
  SHADE_TREE_MEMBERS_FILE=/path/from-operator/members.json \
EOF
  fi
  cat <<EOF
  shade-tree proxy \\
    --bootnode "$bootnode" \\
    --dir-signer "$signer" \\
    --limit "\$SHADE_TREE_LIMIT"
EOF
  if [ "$ADMIT_STAKED" = "1" ] || [ "$ADMIT_PAID" = "1" ]; then
    cat <<'EOF'
  Add the operator-supplied leaf source, contract, and RPC values for on-chain access.
EOF
  fi
}

if [ "$WITH_GATEWAY" = "0" ]; then
  log "waiting for the Elder signer + onion descriptor (~15s)…"
  sleep 15
  SIGNER="$("$NODE_BIN" -e "console.log(JSON.parse(require('fs').readFileSync('${SHADE_TREE_DIR}/deploy-state/bootnode-signer.key')).pub)" 2>/dev/null || echo '<check: journalctl -u shade-tree-bootnode>')"
  cat <<EOF

========================================================================
Shade Tree Elder is up (dedicated control-plane host).

  Elder onion : ${BN_ONION}
  Canopy signer: ${SIGNER}
  admission    : ${SHADE_TREE_ADMISSION}
  onion PoW    : ${SHADE_TREE_ENABLE_POW}

Check it:
  systemctl status shade-tree-bootnode
  curl --socks5-hostname 127.0.0.1:9050 http://${BN_ONION}/health
========================================================================
EOF
elif [ "$WITH_BOOTNODE" = "1" ]; then
  log "waiting for the bootnode signer + onion descriptors (~15s)…"
  sleep 15
  SIGNER="$("$NODE_BIN" -e "console.log(JSON.parse(require('fs').readFileSync('${SHADE_TREE_DIR}/deploy-state/bootnode-signer.key')).pub)" 2>/dev/null || echo '<check: journalctl -u shade-tree-bootnode>')"
  cat <<EOF

========================================================================
shade-tree fleet is up.

  bootnode onion : ${BN_ONION}
  bootnode signer: ${SIGNER}
  gateway onion  : ${GW_ONION}
  admission      : ${SHADE_TREE_ADMISSION}
  gateway admits : ${SHADE_TREE_ADMIT}   (SHADE_TREE_ADMIT; invited = max-anon default; docs/adr/0008)
  onion PoW      : ${SHADE_TREE_ENABLE_POW}   (SHADE_TREE_ENABLE_POW; 0 = off)
  helios sidecar : ${SHADE_TREE_HELIOS}   (SHADE_TREE_HELIOS; 1 = admission root anchored to the sync committee, journalctl -u shade-tree-helios)
  402 registrar  : ${SHADE_TREE_REGISTRAR}   (SHADE_TREE_REGISTRAR; 1 = http://${REG_ONION}:${SHADE_TREE_REGISTRAR_PORT}/pay/quote sells leaves via ${SHADE_TREE_PAY_PROTOCOLS})
$([ "$SHADE_TREE_REGISTRAR" = "1" ] && cat <<REG

Registrar operator key (settles EIP-3009 transfers + inserts leaves; pays gas) — a SECRET, so it is
NOT a bootstrap tunable. Install it as a 0600 drop-in via stdin (never in argv/log), then start:
  install -d -m 0755 /etc/systemd/system/shade-tree-registrar.service.d
  printf '[Service]\\nEnvironment=SHADE_TREE_REGISTRAR_KEY=%s\\n' "\$(cat /path/to/key)" \\
    | install -m 0600 /dev/stdin /etc/systemd/system/shade-tree-registrar.service.d/operator.conf
  systemctl daemon-reload && systemctl restart shade-tree-registrar
  curl --socks5-hostname 127.0.0.1:9050 "http://${REG_ONION}:${SHADE_TREE_REGISTRAR_PORT}/pay/quote?limit=8"   # expect 402 + the enabled rails' challenges (PAYMENT-REQUIRED / WWW-Authenticate: Payment)
REG
)
$(print_client_setup "$BN_ONION" "$SIGNER")

Check it:
  systemctl status shade-tree-bootnode shade-tree-gateway shade-tree-heartbeat$([ "$SHADE_TREE_HELIOS" = "1" ] && echo " shade-tree-helios")$([ "$SHADE_TREE_REGISTRAR" = "1" ] && echo " shade-tree-registrar")
  curl --socks5-hostname 127.0.0.1:9050 http://${BN_ONION}/health   # after ~30s of descriptor propagation
========================================================================
EOF
else
  SIGNER="${SHADE_TREE_BOOTNODE_SIGNER:-<pinned signer of the remote bootnode; ask its operator>}"
  cat <<EOF

========================================================================
shade-tree gateway is up (gateway-only box; bootnode is remote).

  bootnode onion : ${BN_ONION}   (remote, SHADE_TREE_BOOTNODE_ONION)
  bootnode signer: ${SIGNER}
  gateway onion  : ${GW_ONION}
  gateway admits : ${SHADE_TREE_ADMIT}   (SHADE_TREE_ADMIT; invited = max-anon default; docs/adr/0008)
  onion PoW      : ${SHADE_TREE_ENABLE_POW}   (SHADE_TREE_ENABLE_POW; 0 = off)
  402 registrar  : ${SHADE_TREE_REGISTRAR}   (SHADE_TREE_REGISTRAR; 1 = http://${GW_ONION}:${SHADE_TREE_REGISTRAR_PORT}/pay/quote on THIS gateway's onion, rails ${SHADE_TREE_PAY_PROTOCOLS}; operator key = 0600 drop-in shade-tree-registrar.service.d/operator.conf, then systemctl start shade-tree-registrar)

The heartbeat announces this gateway to the remote bootnode over Tor. For an
admission=stake bootnode, stake the operator first (shade-tree register-gateway), then add
  Environment=SHADE_TREE_GW_OPERATOR_KEY=<operator-key>
to /etc/systemd/system/shade-tree-heartbeat.service and \`systemctl daemon-reload && systemctl restart shade-tree-heartbeat\`.

$(print_client_setup "$BN_ONION" "$SIGNER")

Check it:
  systemctl status shade-tree-gateway shade-tree-heartbeat
  journalctl -u shade-tree-heartbeat -f      # expect 'announced (...)' once the descriptors propagate
  curl --socks5-hostname 127.0.0.1:9050 http://${BN_ONION}/directory | grep -o "${GW_ONION%.onion}" | head -1
========================================================================
EOF
fi
