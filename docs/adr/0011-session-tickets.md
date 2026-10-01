# ADR 0011: Session tickets ride the v4 port

- Status: Accepted (implementation behind the `sessionTickets` switch; the switch itself is Dan's H2 decision)
- Date: 2026-09-30
- Task: #103 (ShadeNet launch roadmap, M2 "session tickets behind a flag"); locks ST-SESSION-0 of [`docs/design/SESSION-TICKETS.md`](../design/SESSION-TICKETS.md)

## Context

ADR 0009 sized one RLN slot as one 40 MiB tunnel per 60-second epoch. A research session (one
search plus a handful of result origins) needs several tunnels, and today each costs a Groth16
proof and a fresh onion dial. The design document proposes gateway-bound ticket books: one proof
buys a small book of single-use tickets at one node, each ticket opens one tunnel cheaply. Its
section 6 puts the book on a dedicated onion port speaking HTTP/2 with prior knowledge, so the
HTTP/2 connection is the session handle and its streams are the tunnels.

The launch roadmap deferred "what a slot buys" to H2 and asked for session tickets to be built
behind a flag so H2 can turn them on. The flag existed (`economics.json` `sessionTickets`, the
Rust `session_tickets` config field) with nothing behind it.

## Decision

`session-v1` is implemented as **two new envelope kinds on the existing v4 onion port**, not as an
HTTP/2 side port:

1. **Initialization** is a v4 envelope whose proof binds the session signal
   `shade-tree:session:v1\n<onion>\n<class>\n<nonce>\n<ticketBookDigest>` and carries the book's
   commitments instead of a target. The node answers with the policy echo and closes.
2. **Spend** is a proof-less v4 envelope `{ ticket: { book, i, t, n }, target }` on a new onion
   stream; the node reserves the ticket synchronously, dials, marks it spent inside the successful
   connect, acks `{"ok":true}` and relays exactly as a v4 tunnel.

The **ticket-book digest is the session handle**, not a connection. Ticket cryptography, the
policy class (`research-v1`), the state machines, the shared limits and the privacy stance are
implemented as the design document writes them (sections 8 to 10 and 13 to 17). The capability
advertises `{ version, classes }` without a port.

Sections of the design that this supersedes: 6 (transport), 11's `port`, 12 (the HTTP/2
initialization exchange, replaced by the envelope above) and 13.1's `authorization` header
(replaced by the `ticket` object). Everything else stands.

The switch: `economics.json` `sessionTickets` is written into the deployment record by the deploy
script; the node role starts every node and heartbeat with `SHADE_TREE_SESSION_TICKETS=1` from
it; the heartbeat then advertises the onion-signed `session` capability; both SDKs read the
record for their default and honour `SHADENET_SESSION_TICKETS` / `SHADE_TREE_SESSION_TICKETS` as
an override. With the record saying `false`, every path is byte-identical to v4 and a
session envelope is refused `session-unsupported`. A client whose record says `true` treats that
refusal as "this node has no tickets": it remembers the onion and opens the same tunnel on the
v4 path in the same call, so a canopy mid-roll or a pinned onion still serves.

## Why not the HTTP/2 side port

- **Tor already multiplexes.** Streams of one circuit share the onion connection; a ticket
  spend on a new stream costs one `RELAY_BEGIN`, no new circuit and no proof. The client keeps
  one SOCKS isolation credential per book, so all its tunnels ride one circuit. HTTP/2 would add
  a second multiplexer on top of the one Tor provides, plus a new listener, a second hidden
  service port in every torrc and role, an `h2` dependency in the Rust client and `node:http2`
  hardening (HPACK bounds, settings, GOAWAY) on the node.
- **The node's hardened path is reused whole.** The extracted `establishTunnel` (DNS revalidation,
  candidate deadlines, the exact payload boundary, idle timers, metrics, cleanup) serves both v4
  and tickets; only hooks differ. The HTTP/2 design would have needed a parallel relay
  implementation with its own adversarial history.
- **The byte ceiling is the proof's slot budget.** `makePayloadBudget` is keyed by
  `(externalNullifier, nullifier)`; every stream of a book shares that key, so a book can never
  relay more than the one slot it was bought with, and a same-slot v4 retry and a book share the
  same accounting. A separate per-connection counter would have been a second source of truth.
- **Two SDKs, one spec.** The envelope shape is one JSON line in both SDKs today; the shared
  vectors pin the digests, the signal and the wire ticket. An HTTP/2 client in Rust and Node
  would have doubled the conformance surface for the launch.

What the side port would have bought and this does not: a single TCP-level connection as an
unforgeable session boundary, and a clean way to refuse Protocol v4 on the session port. Here
the boundary is the book digest carried in every spend; a captured spend envelope is useless
without the 32-byte secret, and a captured secret is single-use, index-bound and gateway-bound.

## Consequences

- One proof, six tunnels, at one node. Per-tunnel node rotation is gone for the life of a book
  (90 s); the six tunnels are linkable to the serving node as one session. The proof still
  hides the member. The client's `sessionTickets` flag is the explicit policy choice and stays
  off unless the record or the operator says otherwise.
- A slot burns on an unreachable node: the Rust and JS clients prove before dialing the chosen
  node (the design's dial-before-proof is not possible with a proof-first transport). Health
  seeding keeps unreachable nodes out of the first position; the loss is one slot.
- Exact in-flight duplicates and reuse for another target are distinguished by the node-local
  spend digest; a definite pre-connect failure refunds the ticket, a timeout burns it.
- Shaping is per book and direction (token buckets in the relay transform), so opening six
  streams never multiplies the rate; the idle clock moves only on relayed payload.
- Entitlement is multiplicative by tier: a tier-8 member may open 8 books (48 tunnels, 320 MiB)
  per epoch instead of 8 tunnels. H2 decides whether that is the intended product.
- Nothing changes in circuits, contracts, the directory schema or any signed v4 string
  (`test/wire-freeze.selftest.mjs` pins the four new domain strings).
- Deferred: exact book recovery after a lost initialization ack (design section 15.3), HTTP/2
  if measurements ever show Tor stream setup dominating, and blind (unlinkable) tickets
  (section 28).

## Alternatives considered

- **HTTP/2 on a dedicated onion port** (the design's section 6): rejected for the launch for
  the reasons above; the design stays the reference for a later transport if one is needed.
- **A full RLN proof per child stream**: the status quo; too slow for a research session and
  the reason for #103.
- **Server-issued session cookie**: a stable tracking handle with no cryptographic binding to
  the proof; rejected by the design (section 15.3) and here.
- **Ticket books on the same stream as the initialization** (one long-lived stream carrying
  many CONNECTs): would have needed a custom multiplexer inside a Tor stream, exactly what
  Tor streams already are.

## References

- `docs/design/SESSION-TICKETS.md` (the design; sections 8 to 10, 13 to 17 implemented)
- `packages/node/lib/session-tickets.mjs`, `crates/shadenet-proto/src/session.rs` (ticket cryptography, vectors
  `testdata/vectors.json` `sessionTickets`)
- `packages/node/gateway/session.mjs`, `packages/node/gateway/gateway.mjs` (`handleSessionInit`, `handleTicketSpend`,
  `establishTunnel`), `packages/node/lib/rln.mjs` (`verifySessionEnvelope`)
- `packages/node/client/shade-tree-client.mjs` (`_sessionInit`, `_sessionSpend`), `packages/sdk/src/session.mjs`
- `crates/shadenet/src/session.rs`, `crates/shadenet/src/client.rs` (`session_init`,
  `session_spend`), `crates/shadenet/src/transport.rs` (`SessionInit`, `spend_ticket`)
- `packages/node/lib/directory.mjs` `canonicalSession`, `packages/node/bootnode/heartbeat.mjs` `advertisedSession`
- `scripts/deploy-contracts.mjs` `withEconomicsFlags`, `packages/node/lib/network-record.mjs`,
  `deploy/v4/ansible/roles/shade_tree_v4/tasks/main.yml` (`SHADE_TREE_SESSION_TICKETS`)
- `specs/protocol.md` "Session tickets", `docs/LAUNCH-RUNBOOK.md` H2
