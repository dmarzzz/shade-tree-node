# Protocol v4 deployment plan

**Status:** disposable v4 research canopy live · production blocked on trusted setup · 2026-08-26

This is the current rollout boundary. The older `DEPLOYMENT.md`, `GO-LIVE.md`, and legacy
Sepolia contract/directory files describe the retired pre-v4 fleet. The current disposable v4
research deployment is recorded separately in
[`network/sepolia/deployment.json`](../network/sepolia/deployment.json) and
[`GO-LIVE-LOG-2026-08-25-v4.md`](history/GO-LIVE-LOG-2026-08-25-v4.md).

## Topology

```text
discovery

Shade Tree node -- signed heartbeat --> Elder Tree -- signed canopy directory --> Proxy

traffic

agent --> Proxy --> Tor --> Shade Tree node --> destination
```

The Elder Tree (`bootnode` in source) is a separate control-plane service. It
signs the canopy directory and never carries agent traffic. The Shade Tree node (`gateway`
in source) verifies the v4 proof before it opens destination egress.

## Current inventory

- The Vercel site, canopy page, and signed v1/v2 Data API are deployed from `docs/post`.
- A dedicated Protocol v4 Elder Tree and three dedicated Shade Tree nodes run on Ubuntu 24.04
  across DigitalOcean New York, San Francisco, and Amsterdam. The provider-visible addresses,
  SSH inventory, OpenTofu state, and private identity backups remain outside this repository.
- The v4 canopy admits invited members and public Sepolia stakers (`admission.paths` in the
  record) and accepts only the artifact ids pinned in its record. Its `security.proofArtifacts`
  stays `untrusted-testnet` while the dev set `rln-0b25f824a04da3a8` is still accepted alongside
  the ceremony set `rln-ae43614cd02ebe95` (adopted from PSE's RLN ceremony on 2026-09-30,
  `docs/ceremony/PSE-ADOPTION.md`); it flips to `trusted-ceremony` when the dual-VK window
  closes. Until then this is disposable research infrastructure, not production and not
  suitable for real funds or sensitive traffic. Production deploys were blocked on trusted setup
  until that adoption and stay blocked on final economics (H2) and the M8 deploy.
- The Elder's signed canopy directory has three fresh Protocol v4 announcements. Signer-pinned probes over
  Tor and real HTTPS CONNECT tunnels through all three nodes passed at go-live.
- The isolated `agent-devops/tofu/environments/shade-tree-v4` state and `deploy/v4` Ansible role
  own reconciliation and teardown. Do not operate the older shared fleet environment.

## Gates before infrastructure changes

1. **Complete:** [#73](https://github.com/dmarzzz/shade-tree-node/issues/73). Nodes reject
   private, loopback, link-local, carrier-grade NAT, metadata, multicast, and
   reserved destinations after resolving every answer, then dial the checked
   numeric address. The local-test override is explicit and warns at startup.
2. **Complete:** [#75](https://github.com/dmarzzz/shade-tree-node/issues/75). Proxy slot
   allocation is persisted and atomically coordinated across restarts and processes.
3. **Research exception recorded; production still blocked.** The operator explicitly scoped the
   live fleet to disposable testnet research with no real funds or sensitive traffic and recorded
   the artifact hash. The v4 preflight continues to reject `production` while the pinned artifact
   lock says `UNTRUSTED-TESTNET` or lacks a completed trusted ceremony.
4. **Complete for the research fleet.** Targets, provider account, regions, sizes, admin CIDR,
   SSH keys, and rollback path were reviewed before deployment. The live inventory is isolated
   from the older fleet state.
5. **Complete.** The v4 network record contains the Elder onion, pinned canopy signer,
   admitted roots, accepted artifact identifiers, and protocol range. Pin an immutable git commit for every
   service. [`deploy/v4/preflight.mjs`](../deploy/v4/preflight.mjs) validates this
   record and recomputes verification-key hashes/content ids before any target is
   changed; its null-filled example cannot deploy.
6. **Complete and exercised.** The
   [`deploy/v4` Ansible role](../deploy/v4/README.md) reconciles the Elder Tree,
   Shade Tree node, Tor, heartbeat, firewall, JSON logs, and loopback-only metrics
   through the current pinned checkout and shared hardened bootstrap. It verifies
   restored identities, active services, source commit, artifact configuration,
   and listener scope before writing its idempotence marker. Target inventory and
   provider state remain operator-controlled and uncommitted.
7. **Complete for invited and staked research.** The role defaults to invited-only; the live
   record adds the public staked path.
   Staked or paid admission cannot run unless the reviewed
   contract roots, non-secret authorization reference, explicit operator approval,
   RPC, and required slashing/operator keys are all present. Missing configuration
   stops before the first remote mutation.

Production still requires the trusted-setup decision in issue #6 and an explicit
production review. Any additional provider target needs the same ownership, firewall,
identity-backup, rollback, and preflight evidence; none is safe to infer from the legacy fleet.

## Repeatable rollout order

1. Provision or adopt the Elder Tree target. Generate or restore its onion and
   canopy-signing keys, expose only its onion service, and keep health and metrics
   on loopback.
2. Provision one isolated Shade Tree node with a dedicated public IP. Keep GPU,
   validator, wallet, metadata, and authenticated RPC surfaces unreachable from
   egress.
3. Start the proof gate and heartbeat. Confirm the Elder Tree accepts the signed
   announcement and returns a v4 canopy directory containing exactly that node.
4. Publish the Elder onion and signer pin out of band to the test Proxy. Do not
   publish node IPs or a raw per-node observer feed.
5. Add the actual Elder and node hosts to Ansible inventory in the same change
   that provisions them. Never add placeholder or absent hosts.
6. Expand beyond one node only after the single-node checks pass and the rollback
   has been exercised.

## Verification

- Elder `/health` and signed canopy directory are reachable over Tor and reject tampering.
- The node is reachable only through its onion and advertises protocol v4.
- An authorized proof opens one CONNECT tunnel; malformed, stale, wrong-root,
  wrong-artifact, replayed, and unauthorized proofs fail closed.
- Nullifier accounting enforces the node's configured per-epoch view. If a
  cross-node tally is enabled, its fail-open behavior is tested and documented.
- Private and reserved destinations fail before any outbound connection.
- A permitted HTTPS request returns the node IP, not the Proxy IP, while TLS
  still terminates at the destination.
- Metrics remain loopback-only, logs contain no target, onion, nullifier, member
  secret, or payment authorization, and each service has a working rollback.

Record the final hosts, immutable refs, onions, signer pin, artifact IDs, health
evidence, and rollback result without committing secret keys.
