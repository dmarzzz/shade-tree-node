# ShadeNet launch report (M8)

Date: 2026-09-30. Production network: Sepolia, record `network/sepolia/deployment.json`.
This is the [roadmap's launch gate](../../shadenet-launch/ROADMAP.md) line by line, with the
evidence for each, written by the M8 launch agent. Lines marked *pending* name the one thing
that unblocks them.

## Summary

| Gate line | State |
|---|---|
| Keys rotated, split by role, recorded; private vulnerability reporting on; SECURITY.md current | pass (M4, `docs/KEY-ROTATIONS.md`; SECURITY.md updated here) |
| Audit findings 2.1.1 through 2.2.1 fixed; Slither clean; contracts source-verified | pass (#136, #181, #190; four launch contracts Sourcify `exact_match`) |
| Ceremony complete, independently verified, archived; the canopy accepts only the new key | pass for the ceremony (#214, `docs/ceremony/PSE-VERIFICATION.md`, two mirrors); "only the new key" proven in §CHAIN-7 below after the fleet roll |
| Production deploy smoke-tested through a real 24 h withdraw and a slash | fork rehearsal pass (12/12, same bytecode, real Sepolia state); on-chain smoke *pending* deployer ETH (0.02 ETH + gas), then `scripts/smoke-staking.mjs` and `--resume` after 24 h |
| Rust SDK, CLI and JS SDK released from one tag, passing shared vectors and real-Tor e2e | v0.7.0-rc.1 proved the path (19/19); v0.7.0 in §Release |
| Proxy serves concurrent CONNECTs with structured errors and a status endpoint | pass (M2/M3, `docs/STAGING-REHEARSAL.md`) |
| `shadenet mcp`, Hermes role, SearXNG recipe and llms.txt run end to end | pass on staging (`docs/STAGING-REHEARSAL.md` §2, §3); production seats *pending* ETH |
| Fleet on a release tag with the commit in `/health`; alerts reaching Matrix; 2 RPC sources or Helios; 2 Elders on 2 providers | rc.1 roll pass (§7 of the rehearsal); v0.7.0 roll in §Fleet |
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

*filled in when the tag run completes*

## Fleet

*filled in after the roll: `/health` commit per host, `task shade-tree:e2e`, alert path*

## CHAIN-7: the fleet refuses the dev key

*filled in after the roll: a client built with the dev artifacts (v0.7.0-rc.1) against a
production node*

## Seats and cohort

*pending deployer ETH; what was seeded and what one funding transaction unblocks*

## Left for Dan

- Fund the deployer (`0x62c448057273fceE5785dd5b57e40d0ff19554b1`) for the on-chain smoke,
  the 24 sponsor seats and the launch cohort; then announce.
- Accounts and secrets: `@shadenet` npm scope + `NPM_TOKEN`, Apple Developer ID + notary key,
  `HOMEBREW_TAP_TOKEN` (tap repo exists), Etherscan API key, Hetzner/Vultr token, DO token
  rotation, GitHub Actions billing, the domain.
- H1: read the Get access page, the site, the agent docs and llms.txt as a first-time reader.
- An outside verifier's signed statement for the ceremony (`ceremony.independentVerifierStatement`).
