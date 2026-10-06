# Changelog

ShadeNet was formerly Shade Tree Grove; entries below keep the names they shipped with.

## Unreleased

### Dependencies

- @noble/hashes 1.3.2 → 2.4.0, the browser crypto backend's sha256 and sha3-256
  (`packages/node/lib/crypto-browser.mjs`; Dependabot #260, merged as #330). v2 exports explicit `.js`
  subpaths, so the imports are `@noble/hashes/sha3.js` and `@noble/hashes/sha2.js`.
  - New `test/crypto-backends.selftest.mjs` (32 checks) pins the browser and Node (OpenSSL)
    backends to each other: FIPS known answers, the RFC 8032 ed25519 vector, cross-verification,
    and refusal of a corrupted or non-canonical-S signature.
  - The stake page bundle is byte-identical.
- chacha20poly1305 0.10 → 0.11, the XChaCha20-Poly1305 seal on passphrase-protected
  `identity.json` (Dependabot #262, merged as #329). It moves to `hybrid-array` (the key from the
  32-byte array, `XNonce::try_from` / `from`).
  - Checked in both directions: every pre-bump fixture opens, and a file locked by the new build
    opens with the v0.7.4 CLI and the JS reader.
  - New fixture `rust-init-locked-chacha011.json` (`vectors.json` `lockedChacha011`).
- scrypt 0.11 → 0.12, which derives the key for passphrase-protected `identity.json` (Dependabot
  #266). `Params::new` no longer takes the output length; the 32-byte key buffer sets it, so the
  key is identical.
  - Checked in both directions:
    - the existing Rust- and SDK-locked fixtures open under the new code;
    - a file locked by the new build opens with the v0.7.4 (scrypt 0.11) CLI and with the JS
      reader, to the same secret.
  - New fixture `testdata/identity/rust-init-locked-scrypt012.json` (`vectors.json`
    `lockedScrypt012`), read by both test suites.

### Record RPCs: publicnode out, tenderly in (task 19)

- The Sepolia record's second member-set RPC was publicnode, which intermittently answers the
  member-set `eth_getLogs` replay with `code 4444, pruned history unavailable`. That made
  `doctor` fail, and SearXNG's proxy refused every CONNECT. It is replaced by
  `https://sepolia.gateway.tenderly.co`; the list is now ethpandaops, tenderly.
- Checked 2026-10-06:
  - tenderly returns the full log from the set's deploy block and takes a burst of 20 calls
    without throttling;
  - the Rust client's `doctor --rpc` reports "member log complete (7 live / 11 slots)";
  - both v4 preflights pass;
  - the JS root provider resolves `finalized` to a block number before `eth_getLogs` (tenderly
    rejects the tag itself).
- Rejected: 1rpc.io (HTTP 429/400 under the preflight), drpc and onfinality (range limits), and
  Blast (shut down).
- `scripts/deploy-contracts.mjs` defaults to the same pair for future records.
- The stake page bundle is rebuilt; its only change is this URL.

### `shadenet proxy --preopen`: a session book ready before the first request

- A cold first request spent most of its time proving and opening a session book: 8 s or more
  through a nearby node from a running proxy, and 68 s through Singapore from New York (task 71).
- `--preopen` (`SHADENET_PREOPEN=1`, `preopen_books = true` in `config.toml`) opens a book ahead
  of requests: one at start, then again after a book idles out or runs dry, but only while
  requests came in within the last 10 minutes. An idle proxy stops spending proofs.
- Each book costs one proof of the epoch's budget. A pre-open needs at least two proofs left, so
  one stays for a request, and it never opens a second book while one still has tickets.
- No wire change: a session initialization already carries no target (its signal binds the node,
  class, nonce and book digest). The node accepts it as today.
- Measured on the live canopy (2026-10-06, via gcc-shade-1): the book was pre-opened at start; the
  first request then spent ticket 0 directly and returned in 9.9 s.
- Off by default.

### CLI output names the budget, not a tier

- The public record has one tier, so `init`, `doctor`, `status` and `plan` no longer print
  "tier 8", "(tier 8)" or "1 tier(s), default tier 8". They state the budget instead:
  "8 sessions per 60s epoch" (with session tickets) or "N tunnels per epoch".
  - `doctor` names the tier count only for a record that lists several.
  - `--json` keeps `tier` and `limit`; the `--limit` flag is unchanged.
- `status`: the epoch line said `tunnels used 0, left 8` next to `48 tunnel(s) per epoch`. It now
  says `sessions (6 tunnels each) used 0 of 8, left 8`, so the two numbers agree.
- `status`: the node line silently stopped at six nodes. It now adds `, +N more`; `--json` lists
  every node.
- `plan` advice no longer suggests "tier N would do it in one epoch"; the plan's
  `one_epoch_tier` field is unchanged.

## 0.7.4 — forward-compatible capability verification

Clients verify a signed directory over the bytes as signed and tolerate capability fields they do not recognize, instead of rejecting the directory. A future `caps.*` field no longer bricks an installed client the way `caps.sets` did to v0.7.0; interpretation still ignores unknown fields. Symmetric in the Rust client and the JS node, with a previous-release conformance vector. No new signed capability field ships until this release is the floor.

## 0.7.3 — first-run polish

The one-tier launch set plus: init shortens the leaf it prints so it cannot be pasted where the identity commitment belongs, and doctor reports a pruned backup RPC as a note for clients instead of a failure.

Nothing yet.

## 0.7.2 — one tier, more bandwidth

Signed and hashed v4 wire strings are unchanged (`test/wire-freeze.selftest.mjs`); `research-v2`
is a new session class next to `research-v1`.

### Client first run (fresh-install trial of main, 2026-10-05)

- `shadenet init` shortens the leaf (`leaf 103528278813.. (tier 1), derived from it; not for
  staking`) when it prints the identity commitment. The two were full numbers of similar length on
  adjacent lines, the stake page cannot tell them apart, and staking the leaf locks a bond nobody
  can withdraw.
- `shadenet doctor` no longer exits with a `fail` on a healthy fresh install because one fallback
  RPC in the record has pruned history (publicnode: `pruned history unavailable`). For a client,
  when another endpoint returned the complete member set, a failing endpoint is a `warn` saying
  there is nothing to do on this machine. `shadenet doctor --rpc` (operators) still fails it.

### Node operators: the first hour (orbital-one join, 2026-10-05)

- An Elder's refusal is logged as one: `heartbeat rejected` with the Elder's `err` and, for
  `not-staked` and `bad-operator-sig`, a `fix` field. It used to read `heartbeat transport failed`
  with `reason: transport-error`, and the reason was dropped. A 4xx reply other than 408 and 429 is
  no longer retried four times by the Tor HTTP helper; the error carries `status` and `reply`.
- `shadenet-node check --probe` reaches each Elder again (it failed on every Elder with
  `Cannot read properties of undefined`) and prints its node count, admission and commit.
- `shadenet-node status` adds `listed`: how many Elder Trees accepted the last announce, and when.
- A running node checks its record source every 15 minutes. When the set, the Elder Trees, the
  proof artifacts, the epoch or the status moved on, it logs a warning naming the change and
  `status` shows `recordDrift`; it keeps serving what it started with until restarted.
- `shadenet doctor` judges the state-directory path with fs-mistrust, the library embedded Tor
  uses, so a group-writable directory of the user's own self-named group (Ubuntu's `user:user`
  with umask 002) no longer reads `fail` while Tor starts fine.
- The Operators page and `docs/OPERATOR.md` stake and sign before the node runs, through the node
  image (no npm package needed), and the run line carries the compose file's hardening flags.

### The proxy is a scheduler (ADR 0013, #229)

- Budget queue: with the epoch budget spent, `shadenet proxy`, `mcp` and `fetch` hold a request
  for the next epoch instead of answering `429 budget_exhausted`, up to `--max-wait` (default two
  epochs; `SHADENET_QUEUE_MAX_WAIT_SECS`, `queue_max_wait_secs`). A queued `200` carries
  `X-ShadeNet-Queued`; a refusal carries `X-ShadeNet-ETA`. `--no-queue` restores the old contract.
  The Rust SDK queues only when asked (`Config::queue_max_wait`, `Client::wait_for_budget`,
  `connect_queued`); the JS SDK keeps the 429 contract (dogfood #235).
- `shadenet plan --url …|--count N [--json]`, the MCP tool `shadenet_plan` and
  `GET /_shadenet/plan?count=N` say what a batch costs: tunnels available now, epochs needed,
  seconds until the last tunnel, and the tier that fits it in one epoch. `status` gains `queue`,
  `plan` and `nodes`.
- Session class `research-v2`: `research-v1` with a 60 s idle limit instead of 15 s, so a client
  that opens one connection at a time keeps its book. Nodes advertise every class they serve and
  clients prefer v2. A client opens one book per node at a time; concurrent tunnels share the
  first proof's book (dogfood #231).
- Same-envelope failover: a root refusal (`wrong-group-root`, `gate:*`) on a plain tunnel envelope
  moves the same bytes to the next node; an onion dial is retried once at the same node; a session
  init that fails in transport or with `upstream:*` is retried once at another node with a new
  slot (dogfood #232, #233).
- `shadenet run` keeps the caller's `NO_PROXY` and bypasses a default list of model-API and
  telemetry hosts (`--no-default-bypass` turns it off); `shadenet proxy --targets` is an
  allow-list that refuses other hosts with `403 target_not_allowed` before anything is spent
  (dogfood #230).
- `status`, `plan` and `fetch` use a proxy that is already listening; `--direct` starts an own
  client (dogfood #236).
- Warm circuits to the two best nodes (`--warm N`, `--no-warm`, `SHADENET_WARM_NODES`); metrics
  `shadenet_queue_depth`, `shadenet_queue_next_slot_seconds`, `shadenet_queued_total` and
  `shadenet_queue_wait_seconds_total`.

### CLI

- `shadenet init` prints the bond in ether with the tier and the network name ("tier 1 (1 session
  per 60s epoch) for a bond of 0.01 Sepolia ETH on Sepolia") instead of wei and a chain id
  (dogfood #239, #246).
- `shadenet doctor`: the umask probe file is unique per call, so concurrent callers no longer
  collide (#247).

### Node and operations

- Bootstrap renders the admitted contract list into the heartbeat unit as well as the gateway
  unit, so a node advertises its sets (`caps.sets`); the v4 role's postflight expects the earliest
  deploy block across the record set and `shade_tree_extra_sets` (#252).
- `node-image.yml` is a reusable workflow: `release.yml` calls it for every tag, and it can be
  dispatched for an existing tag. Its smoke test no longer dies on a closed pipe, which had kept
  the 0.7.1 release run from pushing the image (#248).
- Fleet records: both deployment records are pinned to `190d643` and every node admits the
  production set and the staging set; `package-lock.json` carries the `shadenet-node` bin entry;
  `docs/STAGING-REHEARSAL.md` section 12 records the two-set roll (#255).

### Docs

- Dogfood report (`docs/DOGFOOD-2026-10-01.md`): six tasks timed on the staging canopy and eleven
  ranked findings, filed as #230 to #240. The agent docs, `llms.txt` and the README install line
  moved from v0.7.0-rc.1 to v0.7.0 (#241).

## 0.7.1 — the node container

- `ghcr.io/dmarzzz/shadenet-node:<version>`: Tor + the JS node + its heartbeat in one image, run from a deployment record alone (`SHADENET_RECORD`). `shadenet-node run | check [--probe] | identity | authorize | status | retire`; ten knobs as `SHADENET_*` or `/state/node.toml`, including `sets` (one node admitting several staked sets); any explicit `SHADE_TREE_*` still wins. Published multi-arch and attested by the release workflow.
- `bootstrap.sh` and the v4 role take `SHADENET_SETS` / `shade_tree_extra_sets` for the same thing.
- The operator page, OPERATOR.md, JOIN.md, CONFIG.md and docker/README.md lead with the container; the stale "blocked by #6" note is gone.

## 0.7.0 — ShadeNet research preview on Sepolia

The launch release. The fleet, the site, both SDKs and the `shadenet` binary read one
production record, `network/sepolia/deployment.json`, deployed 2026-09-30 from the final
economics (H2) with the PSE trusted-setup verifier (H3). Signed and hashed v4 wire strings are
unchanged (`test/wire-freeze.selftest.mjs`). `docs/LAUNCH-REPORT.md` is the launch gate line by
line with evidence.

### Launch

- Production contracts on Sepolia: `StakedReputationSet` `0xDEB294E6e9ad6A3FcBDeFfD1F67aC9678AC94bBC`
  with the ceremony `WithdrawVerifier`, all four contracts Sourcify `exact_match`; the earlier set
  `0xEB67…4275` is retired (CHAIN-1). The record lists the RPC failover order (ADR 0012).
- Economics final (H2, #212, `docs/ECONOMICS.md`): tier 1 = 0.01 ETH, tier 8 = 0.08 ETH, 24 h
  unbonding, slash bounty 1/10, 24 sponsor seats, session tickets on.
- Trusted setup: PSE's finalized RLN ceremony adopted for both circuits after an independent
  re-verification from public inputs (H3, #214, `docs/ceremony/PSE-VERIFICATION.md`, two archive
  mirrors). The dual-VK window closed with the production record: only
  `rln-ae43614cd02ebe95` is accepted, `security.proofArtifacts` is `trusted-ceremony`,
  `circuits/rln/previous/` is gone, and `deploy/v4/preflight.mjs` reads the lock's `CEREMONY`
  trust value.
- The Get access page and its status API build from the production record; install lines pin
  v0.7.0 (#216, #218, #222).

### Protocol and SDKs

- Session tickets (#103, ADR 0011, #205): with the record's `sessionTickets` switch on, one RLN
  proof per epoch buys a gateway-bound ticket good for several tunnels inside the epoch's payload
  budget; shared vectors, Rust client, JS node and `@shadenet/sdk` all agree. Off by default in
  code; on in the launch record. Units render the switch (#221, #225).
- Every Elder hears every node and the Lab reads the record's `elders[]` (ADR 0012, #213, #224).
- Member-set replay verified against the contract's counters, fail closed on an RPC that returns
  an empty log page (#207); v4 preflight retries a missing receipt (#209) and checks fallback RPCs
  for current state (#217).

### Ops and release

- The JS node lives in `packages/node/` (#202) and the compatibility shims are gone (#208).
- Staging rehearsal report (M7, `docs/STAGING-REHEARSAL.md`, #209, #219, #223, #224): every
  launch-gate line run on the staging canopy, including a browser stake, Hermes and SearXNG
  through the canopy, Elder failover, an RPC outage, an alert round trip and a release from a tag.
- Release: Intel macOS live binary (#198), `--version` names the commit (#199), packageable crates
  and a tag gate (#191), prerelease handling and a Homebrew tap step with a deploy key (#194, #211),
  the publish dry-run passes a dist-tag for prereleases (#206); `install.sh` glibc and aarch64
  loader fixes (#220).

### Dependencies

- brace-expansion 2.1.7 / 5.0.12 (GHSA-q2hr-2g5m-vwhr and related, #201, #203, #204); routine
  npm, cargo and Actions bumps.

## 0.7.0-rc.1 — ShadeNet research preview, release candidate

First release cut from a tag under the ShadeNet name; a prerelease, so it never becomes "Latest"
and the fleet rolls to it on staging only. Work toward the ShadeNet research preview on Sepolia.
Signed and hashed v4 wire strings are unchanged (`test/wire-freeze.selftest.mjs`). The contracts
change and take effect with a fresh deployment: staging is live (`network/sepolia-staging/`);
production waits for the economics and the trusted setup.

### Contracts

- Burn 90% of each slashed member bond instead of paying it all to the slasher (#115, audit 2.1.1).
- The set derives each leaf from the identity commitment and the tier it proves; zero and
  non-canonical commitments are rejected; exit and withdraw proofs bind chain, contract and leaf
  index (#136, audit 2.1.2 to 2.2.1).
- The paid set burns a slashed identity at every tier and refuses to re-insert it; the registrar
  refuses before charging (#181, audit 2.3.3). The audit's reproductions are regression tests.
- Economics as config: `network/<net>/economics.json` in, a read-back-verified deployment record
  out; production refuses placeholder economics (#177). Staging deployed and source-verified on
  Sourcify's v2 API (#187).
- The internal audit report and a finding-by-finding index (#151).

### SDKs and clients

- Session tickets behind the `sessionTickets` switch (#103, ADR 0011): one RLN proof buys a
  `research-v1` book of six single-use tunnel tickets at one node, spent with proof-less
  envelopes on the v4 port; shared byte ceiling, shaping, lifetime and idle limits per book; the
  onion-signed `session` capability; the same vectors in the node, the JS client, `@shadenet/sdk`
  and the Rust SDK. Off by default; H2 turns it on in `economics.json`.
- `shadenet`, the Rust SDK crate, with an async proxy and the `shadenet` CLI (#155): concurrent
  CONNECTs, structured errors, a status endpoint, `shadenet mcp` for agents.
- `@shadenet/sdk`, the JavaScript SDK for browsers and Node (#135).
- Passphrase-protected identity files (#171); no panics on untrusted input (#164); Ethereum
  primitives in `shadenet::eth` replace ethers-core (#174).
- Several Elder Trees: deployment record schemaVersion 2 with `elders[]`; both SDKs use every
  Elder (#182).
- Agent docs, examples, `llms.txt`, a local API spec and an installer (#161).
- Rust CLI copy says ShadeNet and canopy (#184). The JS CLI binary is `shade-tree-node` (#134).

### Node and operations

- One-command join from the deployment record; secrets as systemd credentials; pinned Node;
  journald caps (#165). Bootstrap fixes (#167).
- RPC failover across up to five endpoints (#156); the spent-nullifier set persists across
  restarts (#159); the running commit is in `build_info` and `/health` (#158).
- Onion DoS defenses: a per-circuit stream cap and Arti proof-of-work support (#162).
- Federation dials the configured Tor SOCKS port (#168); alert rules load in Prometheus (#150);
  uptime probe hardening (#160).
- `npm run dev:offline` runs a real node and Proxy on loopback without Tor (#175).
- Every server environment variable is documented and checked (#172); SLOs, on-call and key
  backup (#166); fleet hot key rotated and split by role (#148).

### Site and docs

- ShadeNet and canopy across the site and current docs; Grove and Canopy merged into canopy.
  `/canopy` serves the network page; `/grove` and the v1/v2 Data API paths keep working (#132, #152).
- Get access page built from the deployment record: stake, status, exit and withdraw with proofs
  made in the tab (#147, #169). `/pricing` redirects to `/stake/`.
- Docs reorganized into use, run, reference, security, design and history, with a link check (#170).
- The launch runbook for the owner's gates (#185); ADR-0010, two SDKs and one spec (#130).
- Ceremony kit (#128); PSE's RLN setup passes the adoption check for both circuits (#163); the
  launch circuit set is frozen (#186).

### Build, CI and release

- Rust workspace moved to `crates/` with `shadenet-*` crates (#131).
- The JS node moved to `packages/node/` with shims at the old paths for one minor release (#202).
- Required checks: real-Tor e2e, bootstrap e2e, `cargo deny`, `cargo audit`; one Node lane per PR
  and the full matrix nightly (#153, #179); main CI is never cancelled (#183).
- Release assets for `shadenet`, Intel Mac live build, signing, Homebrew formula, GHCR image and
  publish dry-runs (#157).
- The Smithers harness is removed (#154).

### Dependencies

- arti-client and tor-rtcompat 0.46 (#127); rustls 0.23.45 (RUSTSEC-2026-0285); underscore
  1.13.8 in the ceremony kit (#133); arkworks bumps grouped (#149); routine npm, cargo and
  Actions bumps.

## 0.6.0 — Private staking and recovery

**Official Sepolia research preview.** This release still uses unaudited,
untrusted-testnet proof artifacts and testnet ETH. It is not a production anonymity
or security boundary and must not be used with real funds or sensitive traffic.

The public tier-1 Grove now has a friendly local-first staking page for humans and a
complete Node-free identity, staking, status, exit, and withdrawal path for agents.
The on-chain profile is unchanged: 0.1 Sepolia ETH admits one CONNECT tunnel per
fixed 60-second epoch with a 40 MiB combined payload ceiling.

### Added

- Added a static privacy-first staking page that creates a Semaphore-v3-compatible
  identity locally, validates imports, requires a recovery download, supports
  injected-wallet registration, and offers a public-leaf-only sponsor mode.
- Added `register-member --identity` so the Rust client recomputes and validates the
  secret, leaf, and exact tier before its first wallet or RPC interaction.
- Added native Rust `member-status`, `exit-member`, and `withdraw-member` commands.
  Exit and recipient-bound withdrawal proofs are built and self-verified locally,
  then the exact EIP-1559 call is simulated and signed locally with a separable gas
  wallet.
- Embedded the deployed withdrawal circuit artifacts in the live Rust binary and
  verified Rust-generated proof calldata against the live Sepolia verifier.

### Hardened

- Pin the browser flow to the current Sepolia chain, contract bytecode, tier, and
  exact bond; reject active leaves, insufficient balances, changed parameters, and
  reverted simulations before requesting a staking transaction.
- Reject malformed, oversized, mismatched, extra-field, wrong-tier, and duplicate
  identity/CLI inputs without printing bearer material.
- Document the precise privacy ledger: the static host can see a page load, the
  wallet/RPC sees the public registration, and the public commitment necessarily
  links the pseudonymous register/exit/withdraw lifecycle.

## 0.5.0 — Public Sepolia staking

**Official research preview.** This release uses unaudited, untrusted-testnet
proof artifacts and Sepolia ETH. It is not a production anonymity or security
boundary and must not be used with real funds or sensitive traffic.

The bundled Grove now admits any member who registers a tier-1 commitment with
exactly 0.1 Sepolia ETH. Tier 1 permits one CONNECT tunnel per fixed 60-second
epoch and caps that tunnel at 40 MiB of combined payload. Cross-gateway replay
suppression is authenticated but best-effort and fail-open, not an atomic global
reservation system.

### Added

- Added a fresh immutable public staking profile with tier 1 at 0.1 Sepolia ETH,
  compatibility tier 8 at 0.8 Sepolia ETH, a 24-hour unbonding window, and the
  real in-repo testnet exit verifier.
- Added native Rust member registration with owner-only key-file or environment
  key input, local EIP-1559 signing, exact on-chain bond discovery, receipt
  confirmation, and duplicate protection.
- Added bundled zero-configuration JS and Rust defaults for the live Elder,
  Canopy signer, staking contract, RPC, deployment block, tier, and rate policy.
- Added onion-signed node rate capabilities and fail-closed client matching for
  the 60-second epoch, 60-second root lifetime, and 40 MiB payload ceiling.
- Added a pinned runtime-bytecode manifest for the staking set, commitment
  hasher, exit wrapper, Groth16 verifier, and linked Poseidon libraries; both
  local release tests and live deployment preflight reject executable drift.

### Fixed

- Expire superseded membership roots and last-known-good RPC snapshots by wall
  clock even when no later membership event occurs.
- Reset node and light-client root history after a stale observation gap, and
  retain only the current root during RPC fallback, so recovery cannot make an
  old withdrawn-member root fresh again.
- Keep identity enrollment, registration, and egress on the same explicit tier
  in both implementations, including RPC-only overrides.
- Sort contract tier tables globally so the new limit-1 tier precedes limit 8.

## 0.4.1 — Accepted-tunnel close handling

**Official research preview.** This patch supersedes v0.4.0 for agents, but it
still uses the unaudited, untrusted-testnet proving setup and is not a production
anonymity or security boundary. Grove access remains invite-only.

Install the matching checksummed Rust `-live` binary with:

```sh
curl -q -fsSL --proto '=https' --proto-redir '=https' \
  https://raw.githubusercontent.com/dmarzzz/shade-tree-node/v0.4.1/scripts/install.sh \
  | SHADE_TREE_VERSION=v0.4.1 sh
```

### Added

- Added a hardened POSIX installer that detects the supported target, downloads
  the pinned binary and checksum over HTTPS, verifies the digest and filename,
  and installs without `sudo`.

### Fixed

- Fixed Rust CONNECT Proxy completion after proof acceptance: once the Proxy has
  sent `200 Connection Established`, a later peer-close relay error is logged as
  the end of that accepted tunnel instead of being treated as a pre-accept setup
  failure. Errors before the 200 response remain fail-closed and nonzero.
- Hardened the real-Hermes/embedded-Arti E2E so each successful agent request is
  corroborated by a new gateway acceptance while bounded retries remain within
  the eight-slot research epoch budget.

## 0.4.0 — Node-free Rust agent path

**Official research preview.** These artifacts use the unaudited,
untrusted-testnet proving setup and are not production-ready. Grove access is
invite-only: an operator must provide the signed directory, membership set, and
matching identity inputs.

For agents, download the matching checksummed `-live` asset from the release's
Assets list. It embeds Arti and the research proving artifacts, so it requires
neither Node.js nor a system Tor daemon. Live binaries cover Linux
x86_64/aarch64 (GNU and musl), macOS Apple Silicon, and Windows x86_64. Each
binary is accompanied by a SHA-256 file, an SPDX SBOM, and GitHub
provenance/SBOM attestations. For example, on x86_64 GNU/Linux:

```sh
ASSET=shade-tree-0.4.0-x86_64-unknown-linux-gnu-live
curl -q -fLO --proto '=https' --proto-redir '=https' \
  "https://github.com/dmarzzz/shade-tree-node/releases/download/v0.4.0/$ASSET"
curl -q -fLO --proto '=https' --proto-redir '=https' \
  "https://github.com/dmarzzz/shade-tree-node/releases/download/v0.4.0/$ASSET.sha256"
sha256sum -c "$ASSET.sha256"
chmod +x "$ASSET"
./"$ASSET" --version
```

Follow the [agent install and enrollment guide](https://github.com/dmarzzz/shade-tree-node/blob/v0.4.0/docs/AGENT.md),
including checksum and attestation verification, before running the binary.
macOS binaries are not notarized; source/package registries remain intentionally
unpublished for this binary-first preview.

### Added

- Added a Node-free Rust member enrollment command that writes an owner-only
  identity file, emits only the public commitment for operator admission, and
  can opt into a local version-2 membership set for demos.
- Added a native `shade-tree run -- <command>` wrapper for process-scoped,
  fail-closed authenticated proxy routing without exposing the member identity
  or operator configuration to the child process.
- Added `shade-tree proxy-token` and mandatory loopback Proxy authentication so
  another local OS account cannot spend the member's RLN slots.
- Added the reusable `shade-tree-egress` Rust crate and a long-lived Proxy
  lifecycle that shares one bootstrapped Arti base while giving each CONNECT
  tunnel a separate circuit-isolation view.

### Changed

- Made the checksummed Rust `-live` binary the primary agent distribution; the
  JavaScript package remains the operator and contributor path.
- Expanded the native live-release matrix and kept every binary paired with a
  checksum, provenance attestation, and SBOM.

## 0.3.0 — Shade Tree research preview

### Changed

- Renamed the project, package, CLI, services, metrics, paths, Rust crates,
  JavaScript API, and configuration surface to Shade Tree.
- Introduced the `shade-tree run -- <command>` process wrapper for proxy-aware
  agents and local tools.
- Moved the protocol to explicit v4 and rotated every name-bearing signature
  domain.
- Reworked operator defaults for safer service isolation and clearer
  co-location guidance.
- Replaced the public README and research-note presentation with the minimal
  Shade Tree identity and banner.

### Compatibility

- v3 and unversioned envelopes are rejected.
- Old configuration names have no compatibility alias.
- Capability, operator, and receipt records must be re-signed.
- Exit and withdrawal paths require contracts deployed with the new contexts.
- The checked-in Sepolia records describe the earlier research deployment.

See [`docs/history/MIGRATING-TO-SHADE-TREE.md`](docs/history/MIGRATING-TO-SHADE-TREE.md) for
the rollout sequence.
