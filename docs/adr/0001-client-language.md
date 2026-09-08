# ADR 0001: Client implementation language — JS reference, Rust distributable

- Status: Accepted
- Date: 2026-08-13
- Task: T-RUST-0 (docs/SHIP-PLAN.md section 7b)

## Context

Shade Tree has three programs sharing one wire protocol: the bootnode, the gateway, and
the client. The security-critical checks (v3 onion to ed25519 binding, canonical
directory/announce byte encodings, `verifyDirectory`, `verifyAnnounce`, the
envelope format and target binding) currently live once, in JavaScript
(`lib/directory.mjs`, `bootnode/announce.mjs`, `lib/rln.mjs`), and are shared by
all three. That single definition is the reason there is exactly one source of
truth for those checks today.

The client is the program end users actually run, and its current UX carries the
worst warts: install Node, `npm install`, run a separate system `tor` daemon,
configure SOCKS and a `torrc`. We want to go live with something people can run
without that.

## Decision

Keep the **JavaScript client as the reference implementation**. It defines the
wire protocol and shares the trust-critical checks with the gateway and bootnode.
The wire spec `docs/WIRE-SPEC.md` and the byte-pinned fixtures
`testdata/vectors.json` are the neutral contract; where any port disagrees with
the JS source, the JS source wins.

Build a **Rust client as the distributable** for going live. Not for raw speed
(RLN proving already runs native/wasm), but for two things JS cannot match:

1. **Single static binary.** No "install Node + npm install" for people running
   the client. One downloadable file, no runtime.
2. **Embedded Tor via `arti`.** The client becomes its own Tor client, removing
   the system-`tor` daemon plus SOCKS plus `torrc` friction. This is also a
   security win: no separate process to configure or trust.

Stack: `arti` (Tor), `zerokit` (PSE's canonical Rust RLN), `alloy` (chain reads),
`tokio`/`hyper`.

## Boundary

- **Rust:** the client (`rust/shade-tree-client`), plus a `rust/shade-tree-proto` lib holding
  the trust-critical checks reimplemented from the JS reference and gated by the
  conformance vectors.
- **JavaScript (stays):** the gateway and the bootnode. They are operator
  controlled, run in a controlled environment, and there is little upside to a
  rewrite and real risk in duplicating the trust-critical checks a second time.
- **Neutral contract:** `docs/WIRE-SPEC.md` + `testdata/vectors.json`. Both
  implementations must reproduce every byte-pinned value; the conformance harness
  (T-RUST-1) enforces it on both sides so a Rust port cannot silently drift.

## Criteria to move the servers to Rust too

Revisit the "gateway + bootnode stay JS" half of this decision if any of these
becomes true:

- **A second operator.** More than one party running gateways/bootnodes raises
  the value of a single, auditable, dependency-light binary for the servers too.
- **An embedded or mobile target.** A deployment where shipping a Node runtime is
  impractical (bundled appliance, mobile, constrained device).
- **A security review demanding one language.** A review that concludes the
  trust-critical checks must not exist in two languages at all, and picks Rust as
  the surviving one.

Absent those, the servers stay JS and the Rust surface is the client plus
`shade-tree-proto`.

## Consequences

- One reference (JS), one distributable (Rust); the checks now exist in two
  languages, and the conformance harness is the guard that keeps them identical.
- Users get a single binary with embedded Tor; the Node/tor/SOCKS/torrc setup goes
  away for the client.
- New work: keep `shade-tree-proto` in lockstep with the JS checks, and keep both
  passing `testdata/vectors.json`.

## References

- docs/SHIP-PLAN.md section 7b (decision + T-RUST-0..4)
- docs/WIRE-SPEC.md (wire contract, conformance map)
- testdata/vectors.json (byte-pinned fixtures)
- arti: https://gitlab.torproject.org/tpo/core/arti
- zerokit: https://github.com/vacp2p/zerokit
