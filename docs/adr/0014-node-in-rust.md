# ADR 0014: The node is a Rust binary

- Status: Accepted
- Date: 2026-10-26
- Task: roadmap #369 M3 (network growth: low hundreds of residential nodes); supersedes the
  "gateway and bootnode stay JavaScript" half of [ADR 0001](0001-client-language.md) and
  decision D7 in [ADR 0010](0010-two-sdks-one-spec.md) for the node only

## Context

ADR 0001 kept the gateway and the bootnode in JavaScript because one party ran them, in a
controlled environment, and a rewrite would duplicate the trust-critical checks a second time.
It listed a second operator as the first reason to revisit that. ADR 0010 confirmed the split
for the research preview.

Three things changed:

- Roadmap #369 M3 plans low hundreds of residential nodes on Linux containers, Mac minis and
  Android phones, run by people who are not the project. `shadenet-node` today needs Node.js,
  `npm ci` of the whole monorepo, and a system `tor`. The client went through the same
  transition in ADR 0001 for the same reason.
- The trust-critical checks already exist twice. `shadenet-proto` reimplements the onion
  binding, canonical bytes, signature verification, the request signal and the artifact id, and
  is pinned to `testdata/vectors.json`. `shadenet-rln` has the Poseidon tree and a Groth16
  verifier. A Rust node adds no third implementation of those checks.
- The session-ticket design (ADR 0011) and the response-timing work (#369 M2) put a pacer and
  shaped tunnels on the node, which the JavaScript stream model makes hard to get right.

## Decision

The node is a Rust binary, `shadenet-node`, in `crates/shadenet-node`. It replaces
`packages/node/gateway/`, `bin/shadenet-node.mjs`, the heartbeat and the node supervisor.

- One entrypoint: `main.rs` resolves a `Config` and calls `ShadeNode::new(config)` then `run()`.
  The library exports `Config`, `ShadeNode` and `Error`; everything else is private.
- Wire and operator contracts are unchanged: the v4 envelope and ack lines, every refusal
  reason, the session-ticket exchange, the announce and caps bytes, the receipt bytes, the
  `SHADE_TREE_*` variables, `node.toml`, the `hs-gateway/` key files and `identity.local.json`,
  `status.json`, the spent-set file, the Prometheus series. An existing node keeps its onion.
- The Tor backend is an enum. C Tor as a child process ships first, with the same `torrc` the
  JavaScript supervisor writes. Embedded Arti hosting is added once the node can launch it from
  the same ed25519 seed; whether it becomes the default is a later decision.
- The port lands in phases, each gated by the existing interop harness in
  `crates/shadenet-rln/interop/` run against the Rust node: v4 egress on a static member set,
  on-chain roots and slashing, session tickets, the operator process, then optional subsystems
  (alerts, fleet tally, relay telemetry, light-client roots).
- The Elder Tree and the registrar stay JavaScript. They are the next candidates, with the
  same crate shape, and are not covered by this decision.

## Consequences

- `shadenet-rln` grows a `verify` module and a `prove` feature, so a node links Groth16
  verification without the witness calculator and wasmer.
- The JavaScript node is deleted at the end of the port. The JavaScript SDK keeps
  `lib/directory.mjs`, the verify path of `lib/rln.mjs` and `bootnode/announce.mjs` for the
  Elder and the browser. The conformance guard stays: vectors plus the harness, with the Rust
  client and the JavaScript client both talking to the Rust node until the latter is retired.
- Known JavaScript behaviours that are bugs are fixed in the port and recorded in the
  changelog rather than copied: bytes sent between the envelope and the relay are buffered,
  session-path refusals carry the same `gate:` prefix as v4, the over-spend reply no longer
  waits for the slash transaction, and each refusal reason gets its own bounded metric label.
- The release workflow builds and packages a second binary; the node image is built from it.

## Alternatives considered

- **Keep the node in JavaScript and ship a container.** Rejected: M3 targets phones and home
  boxes where a 300 MB image with a Node runtime is the wrong shape, and the container still
  needs the monorepo's `node_modules`.
- **Port the Elder first.** Rejected: the node is what every operator runs; the Elder is run by
  a handful of parties.
- **Embedded Arti hosting from day one.** Rejected for the first phase: server-side proof of
  work is still behind Arti's experimental flag, and an onion-availability regression on the
  live fleet would be hard to tell apart from port bugs. The enum keeps the door open.

## References

- `docs/adr/0001-client-language.md`, section "Criteria to move the servers to Rust too"
- `docs/adr/0010-two-sdks-one-spec.md`, decision D7
- `docs/WIRE-SPEC.md` section 6, `docs/design/SESSION-TICKETS.md` sections 12 to 17
- `crates/shadenet-proto/src/lib.rs`, `crates/shadenet-rln/src/verify.rs`
- https://github.com/dmarzzz/shade-tree-node/issues/369
