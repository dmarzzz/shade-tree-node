# ADR 0010: Two SDKs, one spec

- Status: Accepted
- Date: 2026-09-28
- Task: HYG-6 (ShadeNet launch roadmap, M0; decision D11)
- Supersedes: the "JS source wins" rule in [ADR 0001](0001-client-language.md)

## Context

ADR 0001 made the JavaScript client the reference implementation and the Rust client
the distributable: where a port disagreed with the JS source, the JS source won. Since
then the Rust client has become the path agents actually run (`shade-tree proxy`,
embedded Arti, no Node), while the JS client still backs the browser staking page, the
Lab runner and the demo. The ShadeNet relaunch needs both as supported libraries:

- a **Rust SDK** for the CLI, the local proxy that agents and SearXNG sit behind, and the
  `mcp` server that Hermes uses;
- a **JavaScript SDK** for browsers (staking, sponsoring, exit and withdraw with an
  in-browser prover, canopy verification) and for Node programs.

Two SDKs cannot each be "the reference". If one of them wins every disagreement, the
other is a port and its users inherit whatever the winner happens to do.

## Decision

The protocol spec is the reference; neither SDK is.

- **Normative:** `specs/protocol.md`, `docs/WIRE-SPEC.md` and the byte-pinned fixtures
  in `testdata/vectors.json`. Where an SDK disagrees with them, the SDK is wrong. Where
  the spec is silent, the change goes into the spec and a vector first, then into both
  SDKs.
- **Rust SDK** (`shadenet` crate, over `shadenet-proto` and `shadenet-rln`): the
  reference for the CLI, the local proxy and the MCP server. The `shadenet` binary is a
  thin shell over the crate.
- **JS SDK** (`@shadenet/sdk`): today's JS client refactored into one isomorphic package
  with a stable API, for browsers and Node. It keeps the gateway's wire code as the one
  JS implementation of the trust-critical checks, so the node and the JS SDK cannot drift
  from each other.
- **One monorepo.** Both SDKs, the node, the contracts, the circuits and the spec live in
  this repository and release from one tag. The Rust workspace moves to `crates/`, the
  npm workspaces to `packages/`.
- **Matching surfaces.** Both SDKs expose the same operations and the same error codes
  (`NotAdmitted`, `NotFinalized`, `BudgetExhausted`, `PortNotAllowed`, `NoEligibleNode`,
  `NodeRefused`, `Transport`, `Canopy`, `Rpc`), so docs and agents describe one API.

The gateway, the Elder Tree and the registrar stay JavaScript for the research preview
(decision D7). ADR 0001's criteria for moving the servers to Rust still apply.

## Consequences

- Both SDKs run `testdata/vectors.json` in CI. A change to a signed, hashed or proved
  value lands as a spec change plus a vector before either SDK changes;
  `test/wire-freeze.selftest.mjs` pins the values that must not move before v5.
- CI cross-tests the Rust SDK against the JS node over real Tor as a required check,
  which covers the part the vectors can't: the two implementations talking to each
  other.
- The trust-critical checks exist in two languages, as they already did under ADR 0001.
  The guard is the same (vectors plus conformance), but the tie-break moves from "JS
  wins" to "the spec wins".
- A browser cannot open raw TCP or Tor. The JS SDK in a browser does identity, staking,
  proofs and verification itself and reaches the network through a local `shadenet`
  daemon on loopback.
- If maintaining two implementations drifts in practice, a WASM build of
  `shadenet-proto` can replace the JS wire code later without changing this decision.

## Alternatives considered

- **Keep JS as the reference (ADR 0001 as is).** Rejected: the Rust client is what
  agents run, and a Rust SDK that loses every disagreement to a JS client it doesn't
  ship with is a port, not an SDK.
- **Make Rust the reference and freeze JS as a test harness.** This was the launch
  audit's recommendation. Rejected: the staking page and browser users need a supported
  JS library, and a frozen harness would be rebuilt as an SDK anyway.
- **One Rust core compiled to WASM for JS now.** Deferred: it removes the second
  implementation, but snarkjs proving, Arti and the bundle size make it a larger change
  than the preview needs.
- **Separate repositories per SDK.** Rejected: one spec and one vector file are easier
  to keep honest when every change to them runs both SDKs' tests in the same PR.

## References

- docs/adr/0001-client-language.md (the decision this revises)
- specs/protocol.md, docs/WIRE-SPEC.md, testdata/vectors.json (normative contract)
- rust/shade-tree-proto/tests/conformance.rs (Rust vector harness)
- test/wire-freeze.selftest.mjs (frozen v4 wire strings)
- ShadeNet launch roadmap: decisions D7 and D11, "SDK and monorepo shape"
