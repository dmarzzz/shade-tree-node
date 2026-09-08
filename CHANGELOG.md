# Changelog

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

See [`docs/MIGRATING-TO-SHADE-TREE.md`](docs/MIGRATING-TO-SHADE-TREE.md) for
the rollout sequence.
