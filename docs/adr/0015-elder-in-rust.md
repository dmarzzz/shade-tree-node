# ADR 0015: The Elder Tree is a Rust binary

- Status: Accepted
- Date: 2026-11-16
- Task: the second step of deleting the JavaScript node (ADR 0014, "the Elder Tree and the
  registrar stay JavaScript. They are the next candidates"); supersedes that bullet for the
  Elder Tree

## Context

ADR 0014 moved the node to Rust and left the Elder Tree (`packages/node/bootnode/server.mjs`)
and the registrar in JavaScript, as the next candidates "with the same crate shape". With the
node ported, the Elder is the only service every fleet runs that still needs Node.js, `npm ci`
of the monorepo and the JavaScript SDK on the box. The deploy path cannot drop the JavaScript
runtime while the Elder needs it, and the JavaScript node cannot be deleted while the Elder's
tests and deploy units share its package.

The Elder's trust-critical work already exists in Rust. `shadenet-proto` verifies an announce
(onion control, the operator authorization, signed capabilities), builds the canonical
directory bytes and signs and verifies a directory; `shadenet` verifies the incident feed; the
node reports relay telemetry. What is left is a registry with a TTL, an HTTP server, three
periodic loops and the on-chain stake check.

## Decision

The Elder Tree is a Rust binary, `shadenet-elder`, in `crates/shadenet-elder`. It replaces
`packages/node/bootnode/server.mjs`, `federation.mjs`, `incidents.mjs`, `keygen.mjs` and the
Elder half of `packages/node/lib/relay-telemetry.mjs`.

- **One entrypoint, private modules.** `main.rs` resolves a `Config` and runs `Elder`; the
  library exports `Config`, `Elder` and `Error` and nothing else, like the node. The commands
  are `run`, `check`, `identity` (the Elder's own onion, replacing `keygen.mjs`) and `help`.
- **A shared crate for what both binaries need.** `crates/shadenet-service` holds the Tor
  HTTP client, the JSON-RPC client with failover, the Prometheus registry and its loopback
  listener, the onion identity, the clock, atomic files, the build commit and logging. It is
  where `pub` items live; a binary crate keeps everything crate-private and never depends on
  another binary crate, so the Elder does not link the node's Groth16 verifier and the
  registrar can follow with the same shape.
- **Wire and operator contracts are unchanged.** The routes (`/health`, `/announce`,
  `/directory`, `/directory/delta`, `/gateway/<onion>`, `/incidents`,
  `/incidents/alertmanager`, `/telemetry/relay`, `/telemetry/aggregate`), the reply bodies and
  status codes, the `x-shade-tree-role` and `x-shade-tree-view` headers, the ETag and gzip
  behaviour, every `SHADE_TREE_BOOTNODE_*`, `SHADE_TREE_STAKE_*` and `SHADE_TREE_RELAY_*` knob,
  the signer, store, incidents and relay checkpoint files, the Prometheus series and the
  `bootnode up on 127.0.0.1:<port>` readiness line. An existing Elder keeps its signer and its
  onion.
- **HTTP on hyper.** The slow-client limits, keep-alive and the 408 and 431 answers are where
  a hand-rolled server goes wrong; hyper is already in the dependency tree through reqwest.
- **The stake verifier is an enum**, on-chain `isStaked(address)` or the chainless mock, chosen
  by `SHADE_TREE_STAKE_MODE` as before.
- **Two behaviours change, recorded in the changelog.** File defaults that pointed inside the
  npm checkout (`bootnode/bootnode-signer.key`, `incidents.local.json`,
  `relay-telemetry-state.local.json`) move under the Elder's state directory; the deploy sets
  them explicitly already. `SHADE_TREE_NETWORK`, which read `network/<name>/` from a checkout,
  is replaced by `SHADENET_RECORD`, the same record reader the node uses, because a binary has
  no checkout.
- **The port lands in phases**, each gated by the existing conformance guard run against the
  Rust Elder: the registry and the four discovery routes with the node's heartbeat and the
  JavaScript client; persistence, deltas, transport features and stake mode; federation and
  probing; incidents, the relay aggregate and the registrar advert; then the deploy wiring.
  New vectors in `testdata/vectors.json` pin the Elder's signed documents.

## Consequences

- The JavaScript Elder stays one release, as the node did, and is deleted with the JavaScript
  node. Its consumers (the clients' selection, the uptime probe, the status page, the fleet
  tally, the grove snapshot) keep working because the wire does not move.
- The deploy renders the Elder unit from the binary; the release workflow packages a third
  binary; the node image gains it.
- `shadenet-node` loses its own copies of the shared modules and its build script; its
  `--version` commit comes from `shadenet-service`.
- The registrar is the last JavaScript service and is not covered by this decision.

## Alternatives considered

- **A second binary inside `shadenet-node`.** Rejected: it would link the node's proof
  verifier into the Elder and make the node crate the home of everything shared, which is the
  wrong shape once the registrar follows.
- **Making the node's modules `pub` and depending on the node crate.** Rejected for the same
  reason, and because a binary crate should have one entrypoint.
- **A hand-rolled HTTP server like the metrics listener.** Rejected: the Elder faces the Tor
  network and its slow-client limits are part of the hardening the JavaScript Elder ships.
- **Porting the Elder and the registrar together.** Rejected: the registrar needs EIP-712 typed
  data that nothing in the workspace has yet, and the Elder is what every fleet runs.

## References

- `docs/adr/0014-node-in-rust.md`
- `docs/adr/0003-bootnode-is-a-cache-not-a-trust-root.md`
- `docs/BOOTNODE.md`, `docs/WIRE-SPEC.md` sections 3 to 5
- `packages/node/bootnode/server.mjs`, `federation.mjs`, `incidents.mjs`
- `crates/shadenet-proto/src/lib.rs`, `crates/shadenet-service/src/lib.rs`
