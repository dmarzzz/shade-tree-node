# ShadeNet launch report (M8)

Date: 2026-09-30. Production network: Sepolia, record `network/sepolia/deployment.json`.
This is the launch gate of the ShadeNet roadmap (the `Launch gate` list in `~/shadenet-launch/ROADMAP.md`, mirrored by [LAUNCH-RUNBOOK.md](LAUNCH-RUNBOOK.md)) line by line, with the
evidence for each, written by the M8 launch agent. Lines marked *pending* name the one thing
that unblocks them.

## Summary

| Gate line | State |
|---|---|
| Keys rotated, split by role, recorded; private vulnerability reporting on; SECURITY.md current | pass (M4, `docs/KEY-ROTATIONS.md`; SECURITY.md updated here) |
| Audit findings 2.1.1 through 2.2.1 fixed; Slither clean; contracts source-verified | pass (#136, #181, #190; four launch contracts Sourcify `exact_match`) |
| Ceremony complete, independently verified, archived; the canopy accepts only the new key | pass for the ceremony (#214, `docs/ceremony/PSE-VERIFICATION.md`, two mirrors); "only the new key" proven in §CHAIN-7 below after the fleet roll |
| Production deploy smoke-tested through a real 24 h withdraw and a slash | fork rehearsal pass (12/12, same bytecode, real Sepolia state); on-chain smoke *pending* deployer ETH (0.02 ETH + gas), then `scripts/smoke-staking.mjs` and `--resume` after 24 h |
| Rust SDK, CLI and JS SDK released from one tag, passing shared vectors and real-Tor e2e | pass: `v0.7.0`, 19/19 jobs, Latest (§Release) |
| Proxy serves concurrent CONNECTs with structured errors and a status endpoint | pass (M2/M3, `docs/STAGING-REHEARSAL.md`) |
| `shadenet mcp`, Hermes role, SearXNG recipe and llms.txt run end to end | pass on staging (`docs/STAGING-REHEARSAL.md` §2, §3); Hermes's client is on v0.7.0 and the production canopy, its seat *pending* ETH |
| Fleet on a release tag with the commit in `/health`; alerts reaching Matrix; 2 RPC sources or Helios; 2 Elders on 2 providers | pass: both Elders and all nodes on `56ae0a6` = `v0.7.0` (§Fleet); alerts to Matrix and the RPC failover list unchanged from M7 |
| Site, docs and repo say ShadeNet and canopy; wire-string freeze test green | pass (#132, #184, #218; `test/wire-freeze.selftest.mjs` in CI) |
| "Get access" page reviewed (H1) and built from the production record | built from the production record in this PR; Dan's H1 read-through still his |
| Economics set (H2); launch cohort seeded | economics final (#212, `docs/ECONOMICS.md`); cohort and 24 sponsor seats *pending* ETH |

## Contracts

Deployed 2026-09-30 by `0x62c448057273fceE5785dd5b57e40d0ff19554b1` from
`network/sepolia/economics.json` (H2 final: tier 1 = 0.01 ETH, tier 8 = 0.08 ETH, 24 h unbonding,
slash bounty 1/10, 24 sponsor seats, session tickets on) with the PSE ceremony verifier (H3).

| Contract | Address | Tx |
|---|---|---|
| RateCommitmentHasher | `0x7fcb0e768ea138129fec90c10e95fb6a5534980c` | `0xfb1cee371a…` |
| WithdrawGroth16Verifier | `0x5bb469863f23d871062558892acc234407577e0d` | `0x733ba40635…` |
| WithdrawVerifier | `0x76d88a50803565496a5acc0c5fc85ef43e4f66ff` | `0x1ea30d51bc…` |
| StakedReputationSet | `0xDEB294E6e9ad6A3FcBDeFfD1F67aC9678AC94bBC` (block 11817836) | `0x56c572442f96714b71c393fc4e35b07bd36ef11928c580f0f5835e26f008f21f` |

- `deploy-contracts.mjs --network sepolia --fork` first: register → exit → withdraw → slash 12/12
  on an anvil fork of Sepolia with these exact numbers and keys.
- `--broadcast` ran out of deployer gas after the first three CREATEs (Sepolia gas spiked to
  2 gwei against a 0.007 ETH balance). The set was deployed by `forge create` with the identical
  constructor arguments and the record rebuilt by the same code path (`buildRecord`,
  `validatePublicStakeOnchain`: bytecode matches the pinned manifest). `contracts-deploy.json`
  carries the note.
- Source verification: all four `exact_match` on Sourcify. Etherscan skipped (no API key).
- The earlier set `0xEB67…4275` is retired in `network/sepolia/contracts.json` (CHAIN-1).
- Dual-VK window closed: the production and staging records accept only
  `rln-ae43614cd02ebe95`, `security.proofArtifacts` is `trusted-ceremony`, and
  `circuits/rln/previous/` is gone.

## Release

Tag `v0.7.0` on `56ae0a6` (PR #226, merged 2026-10-01 00:1xZ; the roll pin in #227).
`scripts/release-check.mjs` passed on the tagged commit (4 crates, package.json, CHANGELOG).
Release run 36795435173: **success, 19/19 jobs** after one re-run (the x86_64 musl live job had
failed on a transient zig toolchain download). GitHub Release `v0.7.0` is **Latest** (rc.1 stays a
prerelease), 86 assets (`shadenet-*` and `shade-tree-*` aliases, `.sha256`, `.spdx.json`,
`shadenet.rb`). Checked on a downloaded `shadenet-0.7.0-aarch64-apple-darwin-live`: sha256 OK,
 exit 0 (quiet), `--version` prints `shadenet 0.7.0 (commit 56ae0a65c24d)`.
`ghcr.io/dmarzzz/shadenet:0.7.0` and `:latest` exist for amd64 and arm64. Apple notarization and
the Homebrew tap push degrade to notices until their secrets exist (Dan asks).

## Fleet

Record `network/sepolia/deployment.json` at `56ae0a6`, written into agent-devops by
`scripts/shade-tree-v4-record.sh sepolia main` (agent-devops #30), rolled with
`scripts/shade-tree-v4-deploy.sh` (elder-v4-02 + Lab first, then nodes 04/05/06, every play
`failed=0`); the orbital-one Elder (installed by hand with `bootstrap.sh`) checked out `56ae0a6`
and restarted.

| Host | Evidence |
|---|---|
| shade-elder-v4-02 | `/health` `{"ok":true,"count":3,"admission":"stake","commit":"56ae0a65…"}` |
| orbital-one Elder | `/health` `{"ok":true,"count":3,"admission":"stake","commit":"56ae0a65…"}` |
| orbital-one client (Hermes) | `shadenet 0.7.0 (commit 56ae0a65c24d)` from the checksummed installer, bundled `sepolia` network: `status` sees set `0xDEB294E6…4bBC`, canopy 3 nodes, `not_admitted` until its seat is staked (leaf `11575066…062900`, printed by the role) |
| shade-node-v4-04/05/06 | `shade_tree_build_info{commit="56ae0a65…",role="node",version="0.7.0"}`; units carry `SHADE_TREE_SESSION_TICKETS=1`, `SHADE_TREE_FROM_BLOCK=11817836` (the launch set's deploy block), `SHADE_TREE_TIERS=1,8`, RPC failover `ethpandaops,publicnode` |

The fleet e2e (`scripts/shade-tree-v4-e2e.sh`, 2026-10-01 00:5xZ, second run after the onion
descriptors re-published): the Lab verifies the canopy (`verified: true, count: 3`) and the
**invited** path is accepted by every node with `artifact: rln-ae43614cd02ebe95`, `gate: accepted`,
HTTP 200 (so proofs under the ceremony key are what the fleet now accepts); the **staked** path
stops at `staked(0xDEB294E6…4bBC) (0 leaves)`: the launch set has no member yet, which is the
seats item below, not a fleet fault.

## CHAIN-7: the fleet accepts only the ceremony key

- Every node's gateway starts with `SHADE_TREE_ZK_ARTIFACTS=rln-ae43614cd02ebe95=/opt/shade-tree/circuits/rln/verification_key.json`
  and logs `zk artifacts accepted:["rln-ae43614cd02ebe95"] legacy:"rln-0b25f824a04da3a8"
  legacyStatus:"RETIRED (field-less / explicit-legacy envelopes => artifact-retired)"`
  (node-04 journal 2026-10-01 00:35:47Z; 05 and 06 identical).
- The record lists one accepted artifact and `legacy: null`; `circuits/rln/previous/` is gone from
  the tree, so no build of `56ae0a6` can even load the dev key.
- A client built with the dev artifacts (`shadenet 0.7.0-rc.1`, run against the launch canopy)
  verifies the canopy (3 nodes, 3 eligible) and stops at admission: the launch set has 0 live
  leaves, so no dev-key proof can be produced for it. The node-side refusal of a dev-id envelope is
  the T-HARD-8 negotiation path (`artifact-retired` / `artifact-unsupported`), covered by
  `packages/node/lib/zk-artifacts.selftest.mjs` and `test/zk-artifact-window.selftest.mjs`.
  A live negative probe needs one staked member (see Seats).

## Seats and cohort

Nothing seeded: the deployer `0x62c448057273fceE5785dd5b57e40d0ff19554b1` held 0.0024 Sepolia ETH
after the contract deploy (the H2 staging redeploy and its smoke spent the rest earlier the same
day). One funding transaction to that address unblocks, in this order, each run by the agent with
the commands already proven on staging:

| ETH | What it buys |
|---|---|
| 0.025 | the on-chain smoke (`scripts/smoke-staking.mjs`: two 0.01 bonds, slash refunds one tenth, `--resume` after 24 h) and the Lab's staked seat (0.01), which turns the e2e's staked line green |
| 0.03 | Hermes on orbital-one, the SearXNG stack and one spare agent seat (3 × 0.01) |
| 0.24 | the 24 sponsor seats of `economics.json` |
| 0.01 × N | a launch cohort of N invited members |

About 0.5 ETH covers all of it with gas to spare.

## Left for Dan

- Fund the deployer (`0x62c448057273fceE5785dd5b57e40d0ff19554b1`) for the on-chain smoke,
  the 24 sponsor seats and the launch cohort; then announce.
- Accounts and secrets: `@shadenet` npm scope + `NPM_TOKEN`, Apple Developer ID + notary key,
  `HOMEBREW_TAP_TOKEN` (tap repo exists), Etherscan API key, Hetzner/Vultr token, DO token
  rotation, GitHub Actions billing, the domain.
- H1: read the Get access page, the site, the agent docs and llms.txt as a first-time reader.
- An outside verifier's signed statement for the ceremony (`ceremony.independentVerifierStatement`).
