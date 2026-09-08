# shade-tree configuration

Every configuration value is an `SHADE_TREE_*` environment variable. Most also have a `--flag` on the `shade-tree` CLI (see `docs/CLI.md`); the flag just sets the same env var and overrides it. Tables below give the default, what the variable controls, which component reads it, and the `--flag` alias where one exists.

## Bootnode

Read by `bootnode/server.mjs` (discovery service) and `bootnode/heartbeat.mjs` (gateway announcer).

| Env var | Default | Controls | Component | Flag |
|---|---|---|---|---|
| `SHADE_TREE_BOOTNODE_PORT` | `8877` | Loopback port Tor maps the bootnode onion to (listens on `127.0.0.1`). | bootnode server | `--port` |
| `SHADE_TREE_BOOTNODE_ADMISSION` | `open` | Admission policy: `open` (onion-control only) or `stake` (require live operator stake). | bootnode server | `--admission` |
| `SHADE_TREE_BOOTNODE_TTL` | `900` | Seconds a gateway stays live without re-announcing before it ages out. | bootnode server | `--ttl` |
| `SHADE_TREE_BOOTNODE_SIGNER_KEY` | `bootnode/bootnode-signer.key` | Path to the pinned `{pub,priv}` JSON signer; minted and persisted if absent. | bootnode server | `--signer-key` |
| `SHADE_TREE_BOOTNODE_STORE` | (off) | Optional JSON state file for write-through persistence. When set, each accepted announce is mirrored to disk and reloaded on boot so a restart does not blank the fleet until every gateway re-announces. Reload re-verifies each record (onion control + operator stake) and drops any past its TTL, so a stale or tampered store can never admit anything a live announce would reject. | bootnode server | — |
| `SHADE_TREE_BOOTNODE_ONION` | (required for heartbeat / bootnode discovery) | The bootnode onion to announce to (heartbeat) / to fetch the live directory from (client). | heartbeat, client selection | `--bootnode` |
| `SHADE_TREE_BOOTNODE_HEARTBEAT` | `300` | Re-announce interval in seconds. | heartbeat | `--interval` |
| `SHADE_TREE_GW_IDENTITY` | `tor/hs/identity.local.json` | Path to the onion identity `{onion, seed}` (from `keygen`) the heartbeat announces. | heartbeat | `--identity` |
| `SHADE_TREE_GW_WEIGHT` | `100` | Selection weight advertised for this gateway. | heartbeat | `--weight` |
| `SHADE_TREE_GW_OPERATOR_KEY` | (unset) | Operator EOA private key; signs the durable onion↔operator authorization (stake mode). Must be 64 hex (0x optional); a malformed value fails the heartbeat at startup with a message that never echoes the key. | heartbeat | `--operator-key` |
| `SHADE_TREE_GW_OPERATOR` | (unset) | Pre-computed operator address (used with `SHADE_TREE_GW_OPERATOR_SIG` instead of the key; the pair takes precedence over `SHADE_TREE_GW_OPERATOR_KEY`). Setting one without the other is a startup error, not a silent onion-only downgrade. | heartbeat | `--operator` |
| `SHADE_TREE_GW_OPERATOR_SIG` | (unset) | Pre-computed operator signature over `operatorAuthMessage(onion, operator)`. Verified locally at startup (same check the bootnode runs); a sig that does not recover `SHADE_TREE_GW_OPERATOR` for this onion fails fast. | heartbeat | `--operator-sig` |
| `SHADE_TREE_RELAY_TELEMETRY` | (unset → off) | `1` opts the gateway into local payload counters and the heartbeat into the separate signed Elder report path. Set it on both services. It never changes `/announce`. | gateway, heartbeat | (none) |
| `SHADE_TREE_RELAY_TELEMETRY_STATE` | `tor/hs/relay-telemetry.local.json` | Shared 0600 node-local counter state. The gateway writes; the heartbeat reads. | gateway, heartbeat | (none) |
| `SHADE_TREE_RELAY_REPORT_STATE` | `tor/hs/relay-report.local.json` | 0600 heartbeat sequence/baseline state, advanced only after Elder acceptance. | heartbeat | (none) |
| `SHADE_TREE_RELAY_ELDER_STATE` | `bootnode/relay-telemetry-state.local.json` | Private 0600 replay checkpoint (node identity, last sequence/boot/counters only). Raw interval contributions remain memory-only and become unavailable across Elder restart. | bootnode server | (none) |
| `SHADE_TREE_RELAY_MIN_COHORT` | `5` | Elder aggregate publication floor. Values below five refuse startup. | bootnode server | (none) |
| `SHADE_TREE_RELAY_DELAY_HOURS` | `6` | Elder fixed-window publication delay. Values below six refuse startup. | bootnode server | (none) |
| `SHADE_TREE_BOOTNODE_MAX_ENTRIES` | `10000` | Registry size cap: a NEW onion is refused `registry-full` when full; resident onions still refresh. | bootnode server | (none) |
| `SHADE_TREE_BOOTNODE_MIN_REANNOUNCE` | `5` | Per-onion re-announce throttle in seconds (`rate-limited`, before verify). | bootnode server | (none) |
| `SHADE_TREE_BOOTNODE_ANNOUNCE_RATE` | `2 * maxEntries / SHADE_TREE_BOOTNODE_HEARTBEAT` (= `66.7`/s) | GLOBAL announce token-bucket refill (announces/second that may reach ed25519 verification, whoever sends them). Sized so a fleet at the registry cap heartbeating at the default cadence (`maxEntries/heartbeat` = 33.3/s) draws half the refill; see `docs/BOOTNODE.md` "Endpoint hardening". Overflow is `429 global-rate-limited` + `Retry-After`. `0` with burst `0` disables. | bootnode server | (none) |
| `SHADE_TREE_BOOTNODE_ANNOUNCE_BURST` | `max(100, maxEntries / 10)` (= `1000`) | The bucket's capacity: how many announces may reach verify in one instant. Covers a lockstep re-announce of a fleet up to this size; an attacker minting fresh onions gets at most this many verifies up front, then `RATE`/s. | bootnode server | (none) |
| `SHADE_TREE_BOOTNODE_HEADERS_TIMEOUT_MS` | `10000` | HTTP: complete request headers must arrive within this (slow-loris headers => `408` + close). `0` disables. | bootnode server | (none) |
| `SHADE_TREE_BOOTNODE_REQUEST_TIMEOUT_MS` | `30000` | HTTP: the whole request (headers + body) must complete within this (a dribbled body => `408` + close). Must be >= headers timeout (clamped). `0` disables. | bootnode server | (none) |
| `SHADE_TREE_BOOTNODE_KEEPALIVE_TIMEOUT_MS` | `5000` | HTTP: an idle keep-alive connection is closed after this. | bootnode server | (none) |
| `SHADE_TREE_BOOTNODE_MAX_HEADER_BYTES` | `8192` | HTTP: max total request-header bytes; over => `431`. | bootnode server | (none) |
| `SHADE_TREE_BOOTNODE_CONN_CHECK_MS` | `1000` | HTTP: how often the timeouts above are enforced (Node's default 30 s would let a slow client linger that long past the deadline). | bootnode server | (none) |

## Gateway

Read by `gateway/gateway.mjs` (egress proxy). See also On-chain and Common groups.

| Env var | Default | Controls | Component | Flag |
|---|---|---|---|---|
| `SHADE_TREE_GATEWAY_PORT` | `8443` | Loopback port Tor maps the node onion to. | gateway | `--gateway-port` |
| `SHADE_TREE_ADMIT` | `invited` | Admission paths this gateway trusts: `invited[,staked][,paid]`, normalized to that order. Only named paths become proof roots or routed slash targets. `staked` requires `SHADE_TREE_GROUP_CONTRACT`; `paid` requires `SHADE_TREE_PAID_ACCESS_CONTRACT`; a missing required contract is a startup error. Configuring a contract does not admit it by itself. | gateway root source + slasher | `--admit` |
| `SHADE_TREE_GROUP_CONTRACT` | (unset; or `network/<SHADE_TREE_NETWORK>/contracts.json`) | Comma-separated `StakedReputationSet` addresses available to the `staked` admission path. Each admitted set is read through its own RootProvider (`node` or `light`) and their roots are unioned by `CompositeRootProvider`. The gateway does not read or route slashing to these contracts unless `SHADE_TREE_ADMIT` includes `staked`. | gateway root source, root-provider | `--group-contract` |
| `SHADE_TREE_PAID_ACCESS_CONTRACT` | (unset; or `network/<SHADE_TREE_NETWORK>/contracts.json` `contracts.paidAccessSet`) | `PaidAccessSet` address available to the `paid` admission path. Its leaves are inserted after an off-chain HTTP 402 payment. The gateway reads the root, reports its anonymity-set floor, and includes it in slash routing only when `SHADE_TREE_ADMIT` includes `paid`. | gateway root source + slasher, `shade-tree leaves` default | `--paid-access-contract` |
| `SHADE_TREE_ROOTS` | (unset; `SHADE_TREE_ADMIT` governs) | Deprecated admission alias: `static` maps to `invited`; `onchain` maps to the configured `staked` and/or `paid` paths. `SHADE_TREE_ADMIT` wins when both are set. `onchain` without a configured contract is a startup error. | gateway root source | `--roots` |
| `SHADE_TREE_MEMBERS_FILE` | `group/members.json` | Path of the static members list (`{ version, members: [leaf, …] }`) the `static` root source reads and watches. | gateway (static root), lib/rln `loadGroup`, client leaf discovery | (none) |
| `SHADE_TREE_PAID_MIN_LEAVES` | `8` | The paid set's anonymity-set floor K (`docs/PAYMENTS.md` open item 3): at startup and on every refresh that crosses it the gateway WARNs `paid-access anonymity set: N leaves (floor K=8) — BELOW the floor` when `leafCount() < K`. It NEVER refuses proofs over it: the floor is a logged deployment parameter, not a gate. Metrics: `shade_tree_gateway_paid_access_leaves`. | gateway startup / refresh | (none) |
| `SHADE_TREE_ROOT_PROVIDER` | `node` | Root source mode: `node` (trusted local node, event reconstruction) or `light` (EIP-1186 storage proof of `currentRoot` against the block header, `LightClientRootProvider`; the header's `stateRoot` is RPC-trusted unless `SHADE_TREE_HELIOS_RPC_URL` anchors it to the beacon sync committee, T-DEV-9b). | root-provider factory | `--root-provider` |
| `SHADE_TREE_HELIOS_RPC_URL` | (unset = stateRoot RPC-trusted) | `light` provider only: URL of a LOCAL [Helios](https://github.com/a16z/helios) verifying JSON-RPC (sidecar, `bootnode/deploy/bootstrap.sh SHADE_TREE_HELIOS=1`, default `http://127.0.0.1:8546`). When set, the block `stateRoot` the storage proof is verified against comes from Helios (sync-committee verified) and the RPC's header is only cross-checked (mismatch ⇒ rejected, precise reason); Helios unreachable / wrong chain ⇒ fail closed. Startup log says `stateRootSource: helios (sync-committee verified)` vs `rpc header (TRUSTED, …)`. Refused with `SHADE_TREE_ROOT_PROVIDER=node`. `docs/LIGHT-CLIENT.md`. | root-provider (`lib/helios-root.mjs`) | (none) |
| `SHADE_TREE_HELIOS_CHAIN_ID` | (unset = must equal the RPC's `eth_chainId`) | Decimal chain id Helios must report (`11155111` Sepolia, `1` mainnet); mismatch ⇒ the provider refuses to anchor. Unset: Helios and `SHADE_TREE_RPC_URL` must agree on `eth_chainId`. | root-provider (`lib/helios-root.mjs`) | (none) |
| `SHADE_TREE_SLASH_KEY` | (unset → dry-run) | Operational hot key that submits on-chain `slash()` txs. Without it (or without a slash contract) slashing logs a dry-run. | gateway slasher | `--slash-key` |
| `SHADE_TREE_SLASH_CONTRACT` | (unset; falls back to `deployed.local.json`) | The PRIMARY slash contract. Independent of the membership root source, so a gateway can slash on-chain while membership stays on `members.json`, or keep slashing a superseded set (the fleet's rln-v3) it no longer reads roots from. T-FEAT-7 ROUTING: every configured root contract (`SHADE_TREE_GROUP_CONTRACT` list + `SHADE_TREE_PAID_ACCESS_CONTRACT`) is appended as a further target, and an over-spender is slashed on WHICHEVER holds a live leaf of the reconstructed secret (`limitOf(leaf) != 0`, or `isActive` on rln-v3), primary first; held by none → the primary gets the default-tier claim (revert on record), as before. Startup logs `slash: routing over primary(0x…) + staked(0x…) + paid(0x…)`; a slash logs `slash: routed to paid(0x…)` and `SLASH tx … via=0x…`. One target = the plain single-contract slasher, unchanged. | gateway slasher | `--slash-contract` |
| `SHADE_TREE_SLASH_RECEIVER` | (unset → the slasher wallet's own address) | Address that receives the slashed bond. | gateway slasher | (none) |
| `SHADE_TREE_ENVELOPE_TIMEOUT_MS` | `30000` | Absolute deadline (from connect, NOT re-armed by activity) for the newline-terminated envelope; a slow-loris client that never sends the newline or dribbles bytes is cut at the deadline (reply `bad-envelope:envelope timeout`, drop reason `envelope-timeout`). `0` disables. | gateway | (none) |
| `SHADE_TREE_TUNNEL_IDLE_TIMEOUT_MS` | `300000` (5 min) | Inactivity timeout on the ESTABLISHED relay: no bytes in either direction for this long => both ends closed (`shade_tree_gateway_tunnel_closes_total{reason="idle-timeout"}`). It is also the one aggregate deadline shared by every pinned upstream address during connect (`upstream-timeout`). `0` disables. | gateway | (none) |
| `SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES` | `41943040` (40 MiB) | Combined opaque application payload allowed in both directions per `(externalNullifier, nullifier)` RLN epoch slot. Same-node retries share the allowance; the boundary chunk is truncated and both sockets close (`shade_tree_gateway_tunnel_closes_total{reason="payload-limit"}`). `0` disables. | gateway | (none) |
| `SHADE_TREE_DNS_TIMEOUT_MS` | `5000` | Deadline for resolving an admitted target. The gateway checks every DNS answer, refuses the hostname if any answer is non-public, then pins at most eight validated numeric results in resolver order. `0` disables the DNS deadline, not address validation. | gateway | (none) |
| `SHADE_TREE_ALLOW_PRIVATE_TARGETS` | (unset) | Unsafe local-development escape hatch. Only `1` permits private or special-purpose destination addresses; the gateway warns at startup. Never set on a network-connected node. | gateway | (none) |
| `SHADE_TREE_MAX_CONNS` | `1024` | Max concurrent client connections, decided at accept BEFORE any byte is read; over => reply `too-many-connections` + close. `0` = unlimited. | gateway | (none) |
| `SHADE_TREE_MAX_CONNS_PER_NULLIFIER` | `8` | Max concurrent tunnels ONE nullifier may hold open (the RLN budget counts requests, not open tunnels; an in-window honest retry is admitted idempotently, so without this one proof could pin N idle tunnels). Over => `nullifier-conn-limit`. `0` = unlimited. | gateway | (none) |
| `SHADE_TREE_TIERS` | `SHADE_TREE_SLOTS` (i.e. `8`) | Comma-separated tier limits this gateway KNOWS (T-FEAT-8), e.g. `8,32`; ascending, distinct, 1..65535; `K` is always included. Used ONLY after an over-spend to name which tier's leaf the reconstructed `identitySecret` sits behind (`resolveSlashLeaf`); verification never consults it (the tier is private to the proof). Against an rln-v4 (tiered) slash contract the on-chain slasher unions this with the contract's `allowedLimits()` and resolves the tier via `limitOf` on chain, then calls `slash(commitment, secret, limit, receiver)`; against rln-v3 it calls the 3-arg default-tier slash (auto-detected at startup, logged as `slash: on-chain … abi=`). Bad value = startup error. | gateway slash path | (none) |
| `SHADE_TREE_REPLAY_WINDOW_MS` | `5000` | Honest-retry window of the per-gateway seen-envelope cache; an exact replay later than this is dropped `replayed-envelope`. | gateway | (none) |
| `SHADE_TREE_FLEET_TALLY_PEERS` | (off) | Comma-separated tally peers. `.onion` peers use Tor. Bare `host:port` peers use cleartext HTTP and are safe only on localhost or a trusted encrypted private link. No peers leaves the optional fleet tally off. | gateway fleet tally | (none) |
| `SHADE_TREE_FLEET_TALLY_TOKEN` | (required with peers) | Shared 32 to 256 character bearer token for tally pushes. Missing or invalid authentication leaves the tally off. Never log or place it in a public unit file. | gateway fleet tally | (none) |
| `SHADE_TREE_FLEET_TALLY_LISTEN` | `127.0.0.1:0` | Inbound tally listener as `host:port` or `port`. Keep it loopback unless an authenticated, firewalled private link is intentional. | gateway fleet tally | (none) |
| `SHADE_TREE_FLEET_TALLY_PATH` | `/fleet-tally` | HTTP path for authenticated tally announcements. | gateway fleet tally | (none) |
| `SHADE_TREE_FLEET_TALLY_TIMEOUT_MS` | `4000` | Per-peer push timeout. Non-2xx, timeout, and network failures log and drop fail-open. Outbound work is also capped at four in-flight pushes per peer and 128 total. | gateway fleet tally | (none) |
| `SHADE_TREE_FLEET_TALLY_MAX_PER_EPOCH` | `50000` | Maximum recorded nullifiers in one epoch bucket. Past the cap, evidence drops fail-open. Hard maximum 200000. | gateway fleet tally | (none) |
| `SHADE_TREE_FLEET_TALLY_MAX_EPOCHS` | `4` | Maximum live epoch buckets. Hard maximum 16. | gateway fleet tally | (none) |
| `SHADE_TREE_FLEET_TALLY_MAX_TOTAL` | `100000` | Maximum recorded entries across all epoch buckets. Hard maximum 500000. | gateway fleet tally | (none) |
| `SHADE_TREE_SHUTDOWN_TIMEOUT_MS` | `10000` | Drain grace on SIGTERM/SIGINT before in-flight tunnels are force-closed. | gateway, bootnode | (none) |

## Client

Read by `client/shim.mjs` / `client/shade-tree-client.mjs` (proxy + library) and `client/selection.mjs` (fleet selection).

| Env var | Default | Controls | Component | Flag |
|---|---|---|---|---|
| `SHADE_TREE_SECRET` | (required) | Member secret (bearer credential from `enroll`); used to mint per-tunnel RLN proofs. | client | `--secret` |
| `SHADE_TREE_ONION` | (unset) | Pin a single gateway onion (skips directory selection). `.onion` suffix optional. | client | `--onion` |
| `SHADE_TREE_DIRECTORY` | (unset) | Path to a static signed directory JSON (offline discovery). | client selection | `--directory` |
| `SHADE_TREE_DIR_SIGNER` | current v4 Sepolia Canopy signer when no source is explicit | Pinned ed25519 public key of the directory signer. Explicit Elder/static-directory overrides must supply their matching signer; no TOFU fallback. | client selection | `--dir-signer` |
| `SHADE_TREE_BOOTNODE_ONION` | current v4 Sepolia Elder when no source is explicit | Elder onion to fetch the live signed directory from over Tor. Wins over `SHADE_TREE_DIRECTORY` if both are explicitly set. | client selection | `--bootnode` |
| `SHADE_TREE_DIRECTORY_CACHE` | `cache/bootnode-directory.lkg` (bootnode) or `<SHADE_TREE_DIRECTORY>.lkg` (file), else none | Last-known-good directory cache path. | client selection | (none) |
| `SHADE_TREE_DIRECTORY_REFRESH_MS` | `300000` (5 min) | Base interval for lazy and active live-Canopy refresh. Background polls are jittered ±20%; `0` disables the timer in direct/test use. | client selection | `--directory-refresh-ms` |
| `SHADE_TREE_SHIM_PORT` | `8888` | Local HTTP-CONNECT proxy listen port (on `127.0.0.1`). | shim | `--shim-port` |
| `SHADE_TREE_SOCKS_ISOLATION` | enabled | Set `0` to disable per-tunnel SOCKS credentials. With Tor `IsolateSOCKSAuth`, the default gives separate CONNECT tunnels separate Tor streams; without that Tor option the credentials are harmless. | client / Proxy | `ShadeTreeClient({ socksIsolation })` |
| `SHADE_TREE_SLOTS` | `8` | `K_SLOTS`: the DEFAULT tier's per-epoch rate cap (`userMessageLimit` baked into a leaf enrolled without `--limit`; number of per-slot nullifiers before over-spend). | lib/rln (client + gateway) | (none) |
| `SHADE_TREE_LIMIT` | bundled client network's `defaultLimit` (current Sepolia: `1`); otherwise `SHADE_TREE_SLOTS` (`8`) | THIS member's reputation-tier limit (T-FEAT-8, `docs/adr/0006-reputation-tiers.md`): the `userMessageLimit` its leaf was enrolled with (`shade-tree enroll --limit N`), staked at, or bought at. The Proxy wraps slots at it and proves with it; a value the leaf does not carry fails at discovery/prove time (`your leaf … is in none of …` / `not in group`). 1..65535. Enrollment and `shade-tree identity` bake it into the leaf, registration and payment submit that same tier, and the Proxy must use it afterward. | Proxy, enroll, join, identity, register-member, pay | `ShadeTreeClient({ limit })`, `--limit` |
| `SHADE_TREE_GROUP_CONTRACT` / `SHADE_TREE_PAID_ACCESS_CONTRACT` / `SHADE_TREE_RPC_URL` (client) | (unset → members.json only) | Leaf-source DISCOVERY (T-FEAT-7): the client looks for its own leaf in `members.json` first, then in each configured contract in order (the group list, then the paid set), rebuilding that set's tree from its event log (`lib/root-provider.mjs` `loadGroupFromContract`) and proving against it. With no contract configured behavior is unchanged (members.json). A leaf found nowhere is a precise error naming every source tried. `SHADE_TREE_NETWORK` fills these from the record. | client (`makeLeafSourceLoader`) | `--group-contract`, `--paid-access-contract`, `--rpc-url` |
| `SHADE_TREE_LEAF_SOURCE` | `auto` | Which set to prove from (T-FEAT-9): `auto` = whichever set holds the leaf (members.json first, then the staked sets, then the paid set — as before); `invited` / `staked` / `paid` PINS the search to that set (a member with a leaf in several sets chooses which one — and therefore which gateways admit it). The discovered/pinned source is the client's **leaf source** for admission filtering: only gateways whose signed `caps.admits` include it are dialed (a gateway advertising no policy is assumed to admit any path during the rollout, logged once); none ⇒ a fail-closed error naming every gateway's policy. | client (`makeLeafSourceLoader`, `selectCandidates`) | `--leaf-source` |
| `SHADE_TREE_MAX_ANON` | (unset = off) | `1`/`true`: **maximum-anonymity mode** (T-FEAT-9). Route ONLY to gateways whose signed `admits` is exactly `["invited"]` (their whole population is invited; a policy-less gateway cannot prove it and is excluded), and REFUSE to run with a staked/paid leaf (an invited-only gateway would reject it `wrong-group-root`; the client says why before any dial). No invited-only gateway in the directory ⇒ fail closed with the fleet's policies. | client | `--max-anon` (bare flag) |
| `SHADE_TREE_RLN_IDENTIFIER` | `1` | RLN identifier bound into the circuit / external nullifier. Must match across client and gateway. | lib/rln (client + gateway) | (none) |

## On-chain

Read by `lib/gateway-registry.mjs` (StakeVerifier), `lib/root-provider.mjs` (RootProvider), and the `register-*` scripts.

| Env var | Default | Controls | Component | Flag |
|---|---|---|---|---|
| `SHADE_TREE_STAKE_MODE` | auto: `onchain` if `SHADE_TREE_GATEWAY_REGISTRY` set, else `mock` | StakeVerifier source: `onchain` (eth_call `isStaked`) or `mock` (chainless dev). | gateway-registry | `--stake-mode` |
| `SHADE_TREE_GATEWAY_REGISTRY` | (unset; falls back to `network/<SHADE_TREE_NETWORK>/contracts.json` `contracts.gatewayRegistry`, then `deployed.local.json`) | `GatewayRegistry` contract address (required for `onchain` stake mode and `register-gateway`). | gateway-registry, register-gateway | `--gateway-registry` |
| `SHADE_TREE_STAKE_ALLOWLIST` | (unset → everyone staked) | Comma-separated operator addresses treated as staked in `mock` mode; empty means open dev (all staked). | gateway-registry (mock) | `--stake-allowlist` |
| `SHADE_TREE_STAKE_CACHE_MS` | `15000` | TTL of the on-chain `isStaked` result cache (keeps heartbeat storms cheap). | gateway-registry (onchain) | (none) |
| `SHADE_TREE_CHAIN_ID` | bundled staked profile chain | Expected chain for `register-member`. The CLI refuses to sign if the RPC's `eth_chainId` differs; set explicitly with a custom contract/RPC. | member registration | (none) |
| `SHADE_TREE_STAKE_PROFILE` | bundled public profile or unset | Selects protocol-specific client safety defaults. `public-stake-v1` pins on-chain leaf discovery to `finalized`; generic `shade-tree leaves` retains its explicit-tooling `latest` default. | client, member registration | (none) |
| `SHADE_TREE_FRESHNESS_ROOTS` | unset | Optional legacy cap on accepted roots inside the freshness window, including current. Unset retains every root the provider observes for the full wall-clock window; setting a finite cap can evict a still-fresh proof during rapid churn. | root-provider | (none) |
| `SHADE_TREE_ROOT_FRESHNESS_SECONDS` | `SHADE_TREE_EPOCH_SECONDS` | Hard wall-clock lifetime for superseded roots and last-known-good RPC snapshots. Expiry progresses even when the set is otherwise idle. Must fit inside the deployed set's unbonding safety margin. | root-provider | (none) |
| `SHADE_TREE_FROM_BLOCK` | record deploy block, else `0x0` | Start block for the `eth_getLogs` scan that reconstructs a member tree, for EVERY contract (0x-hex or decimal). Unset: each contract starts at its own deploy block from the committed network record (`network/<SHADE_TREE_NETWORK>/contracts.json` `deployBlocks.<slot>`; without `SHADE_TREE_NETWORK`, any record naming the address — `lib/network-record.mjs` `deployBlockForContract`), else `0x0`. `SHADE_TREE_NETWORK` also fills this (the MIN deploy block of the record's sets) unless it or `SHADE_TREE_FROM_BLOCKS` is set explicitly. Explicit env always wins. | root-provider (node), client leaf discovery, `shade-tree leaves` | (none) |
| `SHADE_TREE_FROM_BLOCKS` | (from the record, see above) | Per-contract start blocks `<0xaddr>=<block>[,...]` (block 0x-hex or decimal; address case-insensitive). Wins over `SHADE_TREE_FROM_BLOCK` for the named contract; others fall through. A malformed entry is a startup error (never a silent scan from 0). | root-provider (node), client, `shade-tree leaves` | (none) |
| `SHADE_TREE_LOGS_CHUNK` | `10000` | Blocks per `eth_getLogs` call. The scan is PAGED: `[from, to]` is split into windows of this size (`to` resolved to a number once), a window the RPC refuses as too wide / too many results (`exceed maximum block range`, `Log response size exceeded`, `query returned more than 10000 results`, `limited to a 10,000 blocks range`, … — `lib/root-provider.mjs` `LOG_RANGE_ERROR_PATTERNS`) is halved and retried down to a floor of 8; a range that fits one window is one call. Public Sepolia RPCs cap at 50k (publicnode) / 10k (Infura, QuickNode) / 2k (Alchemy free), so 10k is safe by default; a local node can take `1000000`. Finalized reads then continue INCREMENTALLY (only new blocks per refresh). | root-provider (node), client, `shade-tree leaves` | (none) |
| `SHADE_TREE_CONFIRMATIONS` | `0` | Confirmation depth. `0` reads `latest` for gateway-stake checks and `finalized` for membership roots; JavaScript and Rust client leaf discovery also default to `finalized`. `>0` makes the JavaScript root provider and leaf discovery read `head - N`; a Rust custom Grove must pass its matching `--block-tag`. | gateway-registry, root-provider, client leaf discovery | `--block-tag` (Rust leaf discovery) |
| `SHADE_TREE_REGISTER_KEY` | anvil account #0 (member) / #1 (gateway), **loopback RPC only** | Funding / operator private key used to submit the stake tx. A non-loopback RPC without an explicit key fails before any request; public Anvil keys are never selected remotely. `exit-gateway` / `withdraw-gateway` reuse it as the operator signer (falling back to `SHADE_TREE_GW_OPERATOR_KEY`). Prefer `--key-file` / `--account` where supported on a real chain. | register-onchain, register-gateway, exit-gateway, withdraw-gateway | `--register-key` |
| `SHADE_TREE_KEYSTORE_PASSWORD` | (unset → interactive prompt on a TTY) | Password for the Foundry-style encrypted keystore selected with `--account <name>` (`~/.foundry/keystores/<name>`, dir overridable via `FOUNDRY_KEYSTORES`) or `--keystore <path>`. Env only, never argv. | exit-gateway, withdraw-gateway, gateway-status | (none) |
| `SHADE_TREE_BOND` | on-chain `BOND()` (member also tries `deployed.bond`) | Bond amount in wei to stake. | register-onchain, register-gateway | `--bond` |

## Registrar (402 payments, T-FEAT-7)

Read by `payments/registrar.mjs` (the operator's HTTP-402 service that sells membership leaves over x402 / MPP and inserts them into `PaidAccessSet`; `docs/PAYMENTS.md` "Shipped 2026-08-17") and by `shade-tree pay` (`group/pay.mjs`, the buyer). Published as an extra port of an onion the box already runs (`bootstrap.sh` `SHADE_TREE_REGISTRAR=1`): the bootnode onion on a bootnode+gateway box, or — T-FEAT-9 — the GATEWAY onion on a gateway-only box (every provider may run its own registrar + its own `PaidAccessSet`; `docs/adr/0008`).

| Env var | Default | Controls | Component | Flag |
|---|---|---|---|---|
| `SHADE_TREE_REGISTRAR_KEY` | (required) | Operator hot key: submits `transferWithAuthorization` (the buyer's signed EIP-3009 authorization) and `PaidAccessSet.insert`; pays all gas. Secret: unit drop-in / env only, never argv. | registrar | (none) |
| `SHADE_TREE_PAID_ACCESS_CONTRACT` | `network/<SHADE_TREE_NETWORK>/contracts.json` `contracts.paidAccessSet` | The `PaidAccessSet` the registrar inserts into (must list every sold tier in `allowedLimits()`; checked at boot). | registrar, gateway | (none) |
| `SHADE_TREE_PAY_ASSET` | `network/<SHADE_TREE_NETWORK>/contracts.json` `payAsset.address` | The EIP-3009 stablecoin buyers pay in (Sepolia USDC `0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238`, or the test tUSD). Probed at boot: `name()`/`version()`/`decimals()`, and the computed EIP-712 domain MUST equal on-chain `DOMAIN_SEPARATOR()` (fail-closed). | registrar | (none) |
| `SHADE_TREE_PAY_ASSET_NAME` / `SHADE_TREE_PAY_ASSET_VERSION` | token `name()` / `version()` | EIP-712 domain overrides for a token whose `version()` is missing or differs from its domain. | registrar | (none) |
| `SHADE_TREE_PAY_PRICES` | (required) | Price per tier in the asset's atomic units: `8=100000,32=400000` (= 0.10 / 0.40 with 6 decimals). Limits 1..65535, one price per tier; the price IS the tier's public fingerprint, so keep it fixed. | registrar; bootnode advert | (none) |
| `SHADE_TREE_PAY_TO` | the operator key's address | Recipient of the stablecoin (`payTo` in x402, `recipient` in MPP). | registrar | (none) |
| `SHADE_TREE_PAY_PROTOCOLS` | `x402,mpp` | **Which rails this provider serves** (T-FEAT-9): any non-empty subset of `x402`, `mpp` (canonical order `x402,mpp`; unknown ⇒ startup error). A disabled rail gets NO challenge in any 402 (`GET /pay/quote`, the bodied `POST /pay`), is absent from the 402 body / `/health` `pay.protocols`, and a `POST /pay` carrying its header (`PAYMENT-SIGNATURE` for x402, `Authorization: Payment` for MPP) is refused `400 {err:"protocol-disabled", protocol, protocols:[enabled]}` before any parsing. Also read by the **bootnode** (`/health` `pay.protocols`, with `SHADE_TREE_REGISTRAR_ADVERTISE`) and the **heartbeat** (signed `caps.pay.protocols`). `shade-tree pay` turns a missing challenge into "this registrar does not serve <rail>; retry with --protocol <enabled>". | registrar; bootnode + heartbeat adverts | `--pay-protocols` |
| `SHADE_TREE_REGISTRAR_PORT` | `8878` (or `contracts.json` `registrar.port`) | Loopback listen port == the onion virtual port. | registrar, `shade-tree pay` (`--registrar-port`) | (none) |
| `SHADE_TREE_REGISTRAR_ONION` | (unset → `127.0.0.1`) | This registrar's onion: becomes the x402 `resource.url` host and the MPP `realm` (`SHADE_TREE_REGISTRAR_REALM` overrides the realm alone). | registrar | (none) |
| `SHADE_TREE_REGISTRAR_STORE` | `payments/registrar-state.local.json` | JSON order store (idempotency by `(asset, from, nonce)`, settle→insert crash recovery, the MPP challenge-binding secret). Atomic writes, mode 0600. | registrar | (none) |
| `SHADE_TREE_PAY_TIMEOUT` | `600` | Challenge validity in seconds: x402 `maxTimeoutSeconds`, MPP `expires`; the client sets `validBefore = now + this`. | registrar | (none) |
| `SHADE_TREE_PAY_SETTLE_BUFFER` | `20` | Seconds of `validBefore` headroom a payment must still have when it arrives (so the settle tx can mine); less → `402 expired`. | registrar | (none) |
| `SHADE_TREE_PAY_CONFIRMATIONS` | `1` | Confirmations to wait after the settle tx and after the insert tx. | registrar | (none) |
| `SHADE_TREE_REGISTRAR_PAY_RATE` / `SHADE_TREE_REGISTRAR_PAY_BURST` | `1` / `10` | Token bucket in front of `POST /pay` *with* a payment header (signature verify + RPC reads); over → `429` + `Retry-After`. Same bucket code as the bootnode's announce bucket. | registrar | (none) |
| `SHADE_TREE_REGISTRAR_QUOTE_RATE` / `SHADE_TREE_REGISTRAR_QUOTE_BURST` | `20` / `100` | Token bucket in front of quotes (`GET /pay/quote`). | registrar | (none) |
| `SHADE_TREE_REGISTRAR_MAX_INFLIGHT` | `8` | Concurrent settlements; over → `503` + `Retry-After`. Operator txs are serialized regardless (one key, one nonce sequence). | registrar | (none) |
| `SHADE_TREE_REGISTRAR_HEADERS_TIMEOUT_MS` / `_REQUEST_TIMEOUT_MS` / `_KEEPALIVE_TIMEOUT_MS` / `_MAX_HEADER_BYTES` / `_CONN_CHECK_MS` | `10000` / `30000` / `5000` / `8192` / `1000` | HTTP slow-client limits, same semantics and defaults as the bootnode's (`SHADE_TREE_BOOTNODE_*`). Body cap is fixed at 4 KiB. | registrar | (none) |
| `SHADE_TREE_REGISTRAR_ADVERTISE` | (unset) | On the **bootnode**: `1` = add `pay: {port, protocols, asset, chain, tiers}` to `GET /health`, composed from `SHADE_TREE_REGISTRAR_PORT` + `SHADE_TREE_PAY_ASSET` + `SHADE_TREE_PAY_PRICES` + `SHADE_TREE_PAY_CHAIN_ID` (`11155111`) + `SHADE_TREE_PAY_PROTOCOLS`; or a JSON object literal passed through. Unset = `/health` unchanged. On the **heartbeat** (T-FEAT-9): the SAME advert rides in the gateway's signed caps as `caps.pay` (plus `onion` = `SHADE_TREE_REGISTRAR_ONION` when the registrar rides another onion than the gateway's, e.g. the bootnode's), so a gateway-only provider's offer is discoverable from `/directory`. Both adverts may coexist. | bootnode `/health`; heartbeat `caps.pay` | (none) |
| `SHADE_TREE_PAY_KEY` | (unset) | **Buyer** wallet key for `shade-tree pay` (holds the stablecoin; needs no ETH). Alternatives: `--key-file <path>` (raw hex) or `--account <keystore.json>` + `SHADE_TREE_PAY_PASSPHRASE`. Never argv. | `shade-tree pay` | `--key-file` / `--account` |
| `SHADE_TREE_PAY_PROTOCOL` | `x402` | `shade-tree pay` rail: `x402` or `mpp`. | `shade-tree pay` | `--protocol` |
| `SHADE_TREE_REGISTRAR_URL` | (unset) | `shade-tree pay` direct URL (no Tor; tests / a local registrar). Production goes through Tor to `SHADE_TREE_BOOTNODE_ONION:SHADE_TREE_REGISTRAR_PORT`. | `shade-tree pay` | `--registrar-url` |
| `SHADE_TREE_PAY_HTTP_TIMEOUT_MS` | `240000` | Per-attempt deadline for the paying `POST /pay`, which may span settlement and insertion receipts over Tor. The buyer retries once with the same idempotent order. This is separate from the operator's per-transaction `SHADE_TREE_TX_RECEIPT_TIMEOUT_MS`. | `shade-tree pay` | (none) |

## Common

| Env var | Default | Controls | Component | Flag |
|---|---|---|---|---|
| `SHADE_TREE_NETWORK` | (unset) | Name of a committed network record under `network/<name>/`. Fills any UNSET discovery / contract var from `bootnode.json` (`SHADE_TREE_BOOTNODE_ONION`, `SHADE_TREE_DIR_SIGNER`, `SHADE_TREE_BOOTNODE_ADMISSION`, or the static `SHADE_TREE_DIRECTORY` fallback) and `contracts.json` (`SHADE_TREE_GATEWAY_REGISTRY`, `SHADE_TREE_GROUP_CONTRACT`, `SHADE_TREE_PAID_ACCESS_CONTRACT` from `contracts.paidAccessSet`, `SHADE_TREE_PAY_ASSET` from `payAsset.address`, `SHADE_TREE_REGISTRAR_PORT` from `registrar.port`, `SHADE_TREE_RPC_URL`). Explicit env/flags always win. See `network/README.md`. | `shade-tree` (all commands), client selection, heartbeat, gateway-registry, register-gateway, uptime probe | `--network` |
| `SHADE_TREE_RPC_URL` | `http://127.0.0.1:8545` (register scripts try `deployed.rpcUrl` first) | JSON-RPC endpoint for all on-chain reads/writes. | gateway-registry, root-provider, gateway slasher, register-* | `--rpc-url` |
| `SHADE_TREE_RPC_TIMEOUT_MS` | `15000` | Deadline for each execution JSON-RPC request, including root refreshes, stake checks, slashing, registration, and registrar settlement. Invalid or zero values fall back to the default rather than disabling the guard. | root-provider, gateway-registry, gateway slasher, register-*, registrar | (none) |
| `SHADE_TREE_TX_RECEIPT_TIMEOUT_MS` | `180000` | Wall-clock deadline after broadcasting a transaction while waiting for its receipt and requested confirmations. A timeout is reported as unresolved, with the transaction hash; it does not mean the transaction failed and must be checked before retrying. Invalid or zero values fall back to the default. | gateway slasher, register-*, exit-gateway, registrar | (none) |
| `SHADE_TREE_TOR_HOST` | `127.0.0.1` | Local Tor SOCKS host. | heartbeat, client, selection | `--tor-host` |
| `SHADE_TREE_TOR_PORT` | `9250` | Local Tor SOCKS port. | heartbeat, client, selection | `--tor-port` |
| `SHADE_TREE_EPOCH_SECONDS` | bundled client network's policy (current Sepolia: `60`); otherwise `120` | Epoch length in seconds (the fixed nullifier/rate window). Must match on client and gateway; public-profile clients require the same value in onion-signed node capabilities. | lib/rln (client + gateway) | `--epoch-seconds` |
| `SHADE_TREE_LOG_LEVEL` | `info` | Minimum operator log level: `debug`, `info`, `warn`, `error`, or `off`. `--quiet` is shorthand for `warn` unless `--log-level` is also set. | long-running roles | `--log-level` |
| `SHADE_TREE_LOG_FORMAT` | `auto` | `auto`, `pretty`, `text`, or `json`. `auto` uses compact colored output on an interactive TTY and one JSON object per line elsewhere. | long-running roles | `--log-format` |
| `SHADE_TREE_BANNER` | `auto` | One-time ASCII tree after the role is ready: `auto`, `always`, or `never` (boolean spellings also accepted). `auto` requires an interactive TTY. JSON output always suppresses it. | long-running roles | `--banner` / `--no-banner` |
| `SHADE_TREE_METRICS_PORT` | `0` (off) | Separate Prometheus listener for the Elder Tree, node, registrar, or Proxy. It is hard-bound to loopback and serves only `/metrics`, `/livez`, and `/readyz`. Choose a free port for each process on the host. | bootnode, gateway, registrar, client proxy | `--metrics-port` |
| `SHADE_TREE_HEARTBEAT_METRICS_PORT` | `0` (off) | Separate loopback Prometheus listener for the heartbeat. | heartbeat | `--heartbeat-metrics-port` |

## Scoped agent runner (`shade-tree run`)

| Env var | Default | Controls | Component | Flag |
|---|---|---|---|---|
| `SHADE_TREE_PROXY_URL` | `http://127.0.0.1:<SHADE_TREE_SHIM_PORT>` | HTTP CONNECT Proxy URL installed only into the child process. Only `http://` URLs containing a host and port are accepted. | `shade-tree run` | `--proxy` |
| `SHADE_TREE_NO_PROXY` | (unset) | Extra comma-separated agent-local hosts appended to the fixed loopback bypass list. `*` is rejected because it would bypass Shade Tree. | `shade-tree run` | `--no-proxy` |
| `SHADE_TREE_PROXY_CHECK_TIMEOUT_MS` | `2000` | TCP preflight deadline before the child is started; integer 1..30000 milliseconds. | `shade-tree run` | `--check-timeout-ms` |

## Binary installer (`scripts/install.sh`)

These variables are read only by the POSIX one-line installer, not by a running
`shade-tree` process. Network release bases must use HTTPS; `file://` and
loopback HTTP support exists only for its offline selftest.

| Env var | Default | Controls |
|---|---|---|
| `SHADE_TREE_VERSION` | latest release | Pin a release tag, for example `v0.6.0` or `0.6.0`. |
| `SHADE_TREE_LIVE` | `auto` | `auto` probes the selected release for `-live` and falls back only when its checksum or binary is absent; `1` requires live; `0` requests verifier-only. |
| `SHADE_TREE_INSTALL_DIR` | `$HOME/.local/bin` | User-writable destination; the installer creates it without sudo. |
| `SHADE_TREE_FORCE` | `0` | `1` permits replacing a destination symlink to a file; unsafe types and directory symlinks remain refused. |
| `SHADE_TREE_TARGET` | detected | Exact published Rust target triple override. |
| `SHADE_TREE_LIBC` | detected | Linux-only `gnu` or `musl` override when libc cannot be identified. |
| `SHADE_TREE_RELEASE_BASE` | GitHub Releases | Alternate HTTPS release root; local schemes are test-only. |

On macOS, the installer checks `sysctl.proc_translated` so an Apple Silicon
machine running an x86_64 shell under Rosetta receives the native arm64 asset.

## Deploy (`bootnode/deploy/bootstrap.sh`)

Read only by the one-command droplet bring-up (not by any `shade-tree` process). They shape the torrc include + systemd units the script writes; the units then carry the runtime `SHADE_TREE_*` values above as `Environment=` lines. Full table + rationale: `bootnode/deploy/README.md` "Tunables".

| Env var | Default | Controls |
|---|---|---|
| `SHADE_TREE_ENABLE_POW` | `0` | `HiddenServicePoWDefensesEnabled` on every onion this box publishes (per-HS line, right after `HiddenServicePort`). Off by default: a client tor without the `pow` module (Homebrew, `pow: no`) could not connect to a PoW onion; matches the agent-devops role default. |
| `SHADE_TREE_BOOTNODE_ONION` | (unset = this box runs its own bootnode) | Gateway-only mode: install tor + gateway + heartbeat only, heartbeat announces to this remote bootnode. |
| `SHADE_TREE_BOOTNODE_SIGNER` | (unset) | Gateway-only: remote bootnode's pinned signer, echoed into the printed client command. |
| `SHADE_TREE_GATEWAY_REGION` | (unset) | Written into the heartbeat unit (see Bootnode/heartbeat rows above). |
| `SHADE_TREE_ADMISSION` | `open` | Becomes `SHADE_TREE_BOOTNODE_ADMISSION` on the bootnode unit. |
| `SHADE_TREE_LOG_LEVEL` / `SHADE_TREE_LOG_FORMAT` / `SHADE_TREE_BANNER` | `info` / `json` / `never` | Operator output written into every rendered service. JSON and no banner keep journald machine-readable. |
| `SHADE_TREE_ELDER_METRICS_PORT` / `SHADE_TREE_NODE_METRICS_PORT` / `SHADE_TREE_REGISTRAR_METRICS_PORT` / `SHADE_TREE_HEARTBEAT_METRICS_PORT` | `9100` / `9101` / `9102` / `9103` | Loopback metrics ports written into the Elder Tree, node, optional registrar, and heartbeat units. All four must be distinct and cannot reuse an active service or Tor port. |
| `SHADE_TREE_REPO` / `SHADE_TREE_REF` / `SHADE_TREE_DIR` / `SHADE_TREE_BOOTNODE_PORT` / `SHADE_TREE_GATEWAY_PORT` | see script header | Clone source, install dir, loopback backend ports. |
| `SHADE_TREE_ADMIT` | `invited` | The gateway's admission policy (T-FEAT-9), rendered into BOTH the gateway unit (enforced) and the heartbeat unit (advertised as signed `caps.admits`); normalized to the canonical order `invited,staked,paid`. `staked` requires `SHADE_TREE_GROUP_CONTRACT`, `paid` requires `SHADE_TREE_PAID_ACCESS_CONTRACT`, either requires `SHADE_TREE_RPC_URL` (validated up front; rendered into the gateway unit). `SHADE_TREE_HELIOS=1` requires `staked` (it anchors the on-chain root); `SHADE_TREE_REGISTRAR=1` requires `paid` (admit what you sell). The default render's units gained `Environment=SHADE_TREE_ADMIT=invited` (golden regenerated). |
| `SHADE_TREE_FLEET_TALLY_PEERS` / `SHADE_TREE_FLEET_TALLY_TOKEN` | *(unset = off)* | Optional bootstrap-managed tally mesh. Peers must be v3 `.onion:port` addresses and share one independently generated 32 to 128 character URL-safe token. The token is written to a root-only environment file, not the unit. |
| `SHADE_TREE_FLEET_TALLY_PORT` | `8879` | Loopback tally backend and gateway-onion virtual port. Must not collide with a service, Tor, or metrics port. |
| `SHADE_TREE_REGISTRAR` | `0` | `1` = render + start `shade-tree-registrar.service` (the 402 registrar), publish it as an extra `HiddenServicePort SHADE_TREE_REGISTRAR_PORT` of an onion this box runs — the BOOTNODE onion (bootnode+gateway box; the bootnode advertises it in `/health`) or, T-FEAT-9, the GATEWAY onion (gateway-only box, `SHADE_TREE_BOOTNODE_ONION` set) — and make the heartbeat advertise it as signed `caps.pay`. Companions (all required with `1`): `SHADE_TREE_PAID_ACCESS_CONTRACT`, `SHADE_TREE_PAY_ASSET`, `SHADE_TREE_PAY_PRICES`, `SHADE_TREE_RPC_URL`, `paid` in `SHADE_TREE_ADMIT`; optional `SHADE_TREE_PAY_PROTOCOLS` (default `x402,mpp`; rendered into the registrar unit + both adverts), `SHADE_TREE_PAY_TO`, `SHADE_TREE_REGISTRAR_PORT`, `SHADE_TREE_PAY_CHAIN_ID`. The operator key is a secret → a 0600 drop-in, never a tunable (`docs/OPERATOR.md` "Selling access via 402"). |
| `SHADE_TREE_RENDER_ONLY` | (unset) | `<dir>`: render the torrc + units under `<dir>/etc/…` and exit (no root, nothing installed); `--render <dir>` is the same. |

## Demo / test only

Not part of the core protocol; set only when running the demo page or the Sepolia integration script.

| Env var | Default | Controls | Component |
|---|---|---|---|
| `SHADE_TREE_DEMO_INDEX` | `0` | Which `keys.local.json` member index the demo uses as `SHADE_TREE_SECRET`. | `demo/server.mjs` |
| `SHADE_TREE_DEMO_PORT` | `8790` | Demo HTTP port. | `demo/server.mjs` |
| `SHADE_TREE_DEMO_WALLET` | (unset) | Address shown as the funder (display only). | `demo/server.mjs` |
| `SHADE_TREE_SCRATCH` | a session scratchpad path | Scratch directory the Sepolia integration script writes to. | `scripts/integration-sepolia.mjs` |

## Profiles

### (a) Local dev, no chain

Chainless: mock stake (everyone counts as staked), members root from the local `members.json`, discovery either pinned or via a static signed directory / local bootnode. No `SHADE_TREE_GROUP_CONTRACT`, so the gateway uses the `members.json` fallback and never touches an RPC.

```bash
# gateway (members.json root, dry-run slashing, mock stake)
export SHADE_TREE_STAKE_MODE=mock
# shade-tree gateway

# bootnode (open admission; no stake checks)
export SHADE_TREE_BOOTNODE_PORT=8877
export SHADE_TREE_BOOTNODE_ADMISSION=open
# shade-tree bootnode

# client — pinned single onion (simplest), OR static directory
read -s SHADE_TREE_SECRET && export SHADE_TREE_SECRET
read -r SHADE_TREE_LIMIT && export SHADE_TREE_LIMIT   # exact enrolled tier
export SHADE_TREE_ONION=<gateway-onion>            # pin one gateway
#   or, fleet rotation over a signed directory / local bootnode:
# export SHADE_TREE_DIRECTORY=group/directory.example.json
# export SHADE_TREE_DIR_SIGNER=<ed25519-pubkey>
# export SHADE_TREE_BOOTNODE_ONION=<bootnode-onion>   # live discovery instead of a file
export SHADE_TREE_TOR_HOST=127.0.0.1
export SHADE_TREE_TOR_PORT=9250
# shade-tree client
```

### (b) Staked bootnode on a public chain

On-chain everything: bootnode requires operator stake, gateway reads the membership root on-chain and slashes for real. Point every component at the same RPC and contract addresses.

```bash
# shared
export SHADE_TREE_RPC_URL=https://<your-rpc-endpoint>
export SHADE_TREE_CONFIRMATIONS=6            # read head-N for reorg safety on a public chain
export SHADE_TREE_ADMIT=staked               # enforced by the node; advertised by the heartbeat

# bootnode — require live operator stake
export SHADE_TREE_BOOTNODE_ADMISSION=stake
export SHADE_TREE_STAKE_MODE=onchain
export SHADE_TREE_GATEWAY_REGISTRY=0x<GatewayRegistry>
# shade-tree elder

# gateway operator heartbeat (durably authorizes this onion for the staked operator)
export SHADE_TREE_BOOTNODE_ONION=<bootnode-onion>
export SHADE_TREE_GW_IDENTITY=tor/hs/identity.local.json
read -s SHADE_TREE_GW_OPERATOR_KEY && export SHADE_TREE_GW_OPERATOR_KEY
# shade-tree heartbeat

# gateway — on-chain root + real slashing
export SHADE_TREE_GROUP_CONTRACT=0x<StakedReputationSet>
export SHADE_TREE_ROOT_PROVIDER=node
read -s SHADE_TREE_SLASH_KEY && export SHADE_TREE_SLASH_KEY
export SHADE_TREE_SLASH_CONTRACT=0x<StakedReputationSet>
# export SHADE_TREE_SLASH_RECEIVER=0x<receiver>    # optional; defaults to the slasher address
# shade-tree node

# client — bundled current-v4 Elder+signer by default
read -s SHADE_TREE_SECRET && export SHADE_TREE_SECRET
read -r SHADE_TREE_LIMIT && export SHADE_TREE_LIMIT   # exact enrolled tier
# Optional override pair:
# export SHADE_TREE_BOOTNODE_ONION=<elder-onion>
# export SHADE_TREE_DIR_SIGNER=<matching-canopy-signer-pubkey>
# shade-tree proxy
```

## Client directory freshness bound (T-FEAT-21)

Read by `client/selection.mjs`. OPTIONAL, OFF by default — leave unset and directory loading behaves
exactly as before (legitimate long-lived static-file directories are unaffected).

The monotonic issued FLOOR (loop-15) refuses a directory whose `issued` moves BACKWARD within a
session, but on a COLD start a fresh client accepts whatever `issued` the bootnode first serves — so a
bootnode replaying a months-old (but validly signed) directory to a new client is undetectable. Arming
the max-age bound rejects a FRESH directory (not the last-known-good cache) whose `issued` is older
than `now - SHADE_TREE_DIRECTORY_MAX_AGE_MS`, failing closed to the last-good in-memory fleet / cache.

| Env var | Default | Controls | Component | Flag |
|---|---|---|---|---|
| `SHADE_TREE_DIRECTORY_MAX_AGE_MS` | (unset → no bound) | Max age (ms) a FRESH directory's `issued` may be before it is rejected as stale. Unset / non-positive => check disabled. | client selection | (none) |
| `SHADE_TREE_DIRECTORY_MAX_AGE_SKEW_MS` | `300000` (5 min) | Clock-skew grace added on top of the bound so a lagging client clock doesn't spuriously reject a just-issued directory. Only consulted when the bound is armed. | client selection | (none) |

Note: directory `issued` is in SECONDS (the bootnode signs `Math.floor(Date.now()/1000)`); the bound is
in MILLISECONDS. `client/selection.mjs` scales `issued` by 1000 before comparing, matching the unit the
rollback floor uses.

## Client receipt reputation → quality-aware selection (T-FEAT-22)

Read by `client/selection.mjs`. OPTIONAL, OFF by default — leave `SHADE_TREE_RECEIPT_SCORING` unset and
selection is byte-for-byte today's weight-only behavior (no tally file is written, `reportReceipt` is a
no-op). Even with the flag armed, a fleet with no receipt evidence yet produces an identity adjustment,
so arming it alone changes nothing until real receipts arrive.

T-FEAT-13 gives the client a verifiable per-epoch egress-success receipt from each gateway. With scoring
armed, the client folds each verified-or-bogus receipt outcome into a SMALL, LOCAL, per-gateway quality
tally sitting next to the gateway-health cache: a gateway that keeps returning VALID receipts earns a
modest weight bonus; one that returns BAD receipts (present but bogus — the gate-then-drop signal) is
deprioritized. A gateway simply running with receipts OFF sends none and is never entered into the tally
or penalized (fully additive).

Privacy: the tally stores ONLY the gateway `.onion` (already learned from the SIGNED directory) plus
three locally-computed numbers — a decaying quality EWMA in `[0,1]`, a bounded sample count, and a
`lastSeen` wall-clock. It NEVER stores receipt bytes, the receipt's epoch, or anything tied to a specific
request, and is never transmitted anywhere — the same never-sent, local-only discipline as the health
cache. Schema: `onion -> { score, samples, lastSeen }`.

| Env var | Default | Controls |
|---|---|---|
| `SHADE_TREE_RECEIPT_SCORING` | (unset → OFF) | Arm the feature: `1`/`on`/`true`/`yes` enables it; anything else (or unset) is OFF. |
| `SHADE_TREE_RECEIPT_CACHE` | `cache/gateway-receipts.json` (gitignored) | Tally file path. `""`/`off`/`0` disables persistence (in-memory only). |
| `SHADE_TREE_RECEIPT_MAX` | `512` | Max distinct gateways retained; oldest-`lastSeen` evicted first (bounded). |
| `SHADE_TREE_RECEIPT_DECAY_MS` | `1209600000` (14 days) | A tally not updated for this long is treated as decayed → neutral (no bonus, no penalty): a gateway is never punished forever. |
| `SHADE_TREE_RECEIPT_ALPHA` | `0.3` | EWMA weight on the newest outcome (mirrors the health latency EWMA). |
| `SHADE_TREE_RECEIPT_BONUS` | `0.5` | Max fractional weight swing at full confidence + extreme score (±50%). |
| `SHADE_TREE_RECEIPT_CONFIDENCE_N` | `4` | Samples needed for full confidence, so one good receipt is not decisive. |

Integration seam: `client/selection.mjs` exposes `reportReceipt(onion, { valid })` (mirroring
`reportResult(onion, { ok, latencyMs })`). The one-line call site — added later in
`client/shade-tree-client.mjs`, immediately after `_verifyReceipt` — is
`if (receipt.present) reportReceipt(usedOnion, { valid: receipt.valid === true });`.

## Client rotation / load spread (T-FEAT-4)

Read by `client/selection.mjs` and the Rust live client. Smooth spread is ON by default, so successive
CONNECT tunnels advance the weighted schedule instead of independently re-rolling the first gateway.

With spread disabled, each CONNECT re-rolls slot-0 (the gateway the shim actually dials) as a fresh
weighted-random draw: memoryless, so the top-weight gateway can win back-to-back and equal-weight peers
see bursty, clumped load. By default, slot-0 is chosen by a smooth weighted round-robin (SWRR) over the SAME
healthy, weight-clamped, receipt-adjusted pool the failover order already selects from. SWRR keeps a
per-gateway in-memory "current deficit" that advances every CONNECT, giving two properties: (1) the
just-used gateway drops below its peers and is not re-picked until they have had their proportional turn
— load spreads evenly across the healthy fleet, no back-to-back hammering (equal weights => strict
round-robin, zero immediate repeats); and (2) over each full cycle a gateway is selected exactly in
proportion to its effective weight, so the long-run weighted (and receipt-adjusted) share is preserved —
spread changes the ORDER, never the marginal distribution. Deficits are seeded with a small rng jitter so
two clients loading the same fleet don't emit an identical, cross-linkable sequence.

No new persistence store: the SWRR deficits are in-memory session state (like the live health signal),
and the failover TAIL (only consulted on a dial timeout) stays weighted-random via the existing
selection order. Reuses the health (`"down"`) + receipt-adjusted weight signals already in the module.

| Env var | Default | Controls | Component | Flag |
|---|---|---|---|---|
| `SHADE_TREE_ROTATION_SPREAD` | (unset → ON) | Smooth weighted round-robin for the first gateway on each new tunnel. Set `0`/`off`/`false`/`no` to restore weighted-random selection. | JS/Rust client selection | `--rotation-spread`, `--no-rotation-spread` |
