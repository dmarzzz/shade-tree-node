# ADR 0003: The bootnode is a cache and a discovery trust boundary

- Status: Amended
- Date: 2026-08-13
- Amended: 2026-08-23
- Task: milestone 4 (docs/history/ROADMAP-v1.md #4)

## Context

Milestone 3 shipped fleet discovery as a signed static file. Milestone 4 makes it
live: gateways announce themselves, and a bootnode (`bootnode/server.mjs`, its own v3
onion service) holds live ones for a TTL and serves the union as a signed directory
that `lib/directory.mjs` already knows how to verify.

Making discovery live introduces a new always-on party. A hostile or compromised
directory signer can steer a member onto a node it controls. The trust boundary must
be explicit even though the service remains outside the traffic path.

## Decision

The bootnode verifies announcements before admitting them to its registry:

- **Onion control.** The announce is ed25519-signed by the onion's own identity key.
  The service verifies that signature before accepting a direct or gossiped record.
- **Operator stake (optional, on chain).** In stake-admission mode a durable ECDSA
  authorization binds operator to onion. The bootnode recovers it and reads
  `GatewayRegistry.isStaked(operator)` on chain.

The directory does not carry the announcement's `onionSig`. A Proxy pins the directory
signer (`SHADE_TREE_DIR_SIGNER`) and trusts it to choose the candidate list.
`verifyDirectory` authenticates that list, checks each onion/public-key binding, and
verifies onion-signed capabilities when present. It does not prove live onion control.
`GET /gateway/<onion>` returns the raw stored announce. Optional stake re-verification
uses that record, but it is off by default and does not cover onion-only entries.

## Consequences

- A compromised pinned signer can omit, reorder, or add an internally consistent entry,
  including a malicious onion it controls. It cannot make an existing onion terminate
  at a different key. Capabilities remain independently verifiable when their signed
  advertisement is present.
- The pinned signer must be distributed to clients out of band; there is intentionally
  no default, because an unpinned directory is trust-on-first-use, which is the exact
  poisoning surface the pin closes (docs/AUDIT.md).
- Clients cache the last-known-good directory (`loadDirectory`), re-verified against the
  same pinned signer, so an unavailable service can degrade to the previous signed view.
  A compromised signer remains a selection risk.
- Persistence on restart is not blind trust: each stored announce is re-run through the
  same verification (onion control, and in stake mode a live `isStaked` re-check) and
  any entry past its TTL is dropped (docs/BOOTNODE.md, "Surviving a restart").

## Alternatives considered

- **Require every client to verify each raw announcement.** This would narrow signer
  trust by proving onion control at selection time. The current protocol does not do
  this for every entry because it adds one fetch and verification per candidate. A
  future directory schema can include the signed announcement fields directly.

## References

- docs/BOOTNODE.md ("What it verifies and what clients trust")
- lib/directory.mjs `verifyDirectory`, `onionToPubkey`, `verifyOnionControl`,
  `loadDirectory`
- bootnode/server.mjs (`GET /gateway/<onion>` zero-trust re-verification; `MAX_WEIGHT`)
- bootnode/announce.mjs, bootnode/selftest.mjs (adversarial cases rejected)
- docs/AUDIT.md (discovery trust boundary)
- docs/history/ROADMAP-v1.md #4
