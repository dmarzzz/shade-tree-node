# ADR 0012: Every Elder hears every node; the record carries the RPC failover list

- Status: Accepted
- Date: 2026-09-30
- Task: ShadeNet launch roadmap M7 "Left for M8" (`docs/STAGING-REHEARSAL.md`): Elder failover
  ages out after the TTL; the record's RPC dropped history

## Context

ADR 0003 made the Elder Tree a cache, not a trust root, and #182 let a record list several
Elders (`elders[]`, schemaVersion 2) with both SDKs verifying and merging every Elder's canopy.
The M7 rehearsal showed the other half was missing: a node announced to ONE Elder (the record's
`elder`), and the Lab runner and the JS client fetched from that one Elder. Stopping the primary
Elder left the second Elder's directory to age out after its 900 s TTL, because nothing
re-announced to it; the failover only worked for as long as the last announces lived.

The same rehearsal found the record's execution RPC (a pooled public endpoint) answering
`eth_getLogs`, a deploy receipt and archive reads with nothing. #207 made the member-set replay
verify itself against the contract's counters and fail closed, but a client with one endpoint
then has nowhere to go. The fleet already ran a comma-separated failover list in
`SHADE_TREE_RPC_URL` (OPS-8), assembled by the deploy wrapper from the record's `rpcUrl` plus a
wrapper-side default; the SDKs and the site only saw `rpcUrl`.

## Decision

1. **Nodes announce to every Elder.** `SHADE_TREE_BOOTNODE_ONIONS` lists every Elder Tree of
   the canopy (primary first). `SHADE_TREE_NETWORK` and the bootstrap preset fill it from the
   record's `elders[]`; the v4 role writes it into the heartbeat unit. The heartbeat runs one
   egress check, then one signed announce per Elder in parallel, each classified and logged as
   before, tagged with the Elder's prefix. The cycle is accepted when at least one Elder
   accepted; `shade_tree_heartbeat_elders_total` and `_elders_accepted` expose the rest, so one
   unreachable Elder is visible without failing the node. A single-Elder configuration is
   byte-identical to before: same announce bytes, same logs, same metrics.
2. **The JS client falls back through the Elders.** `packages/node/client/selection.mjs` tries
   the Elders in record order and takes the first directory that verifies against the pinned
   signer set; only when every Elder fails does it use the last-known-good cache. The pinned
   signer set (`SHADE_TREE_DIR_SIGNER`) becomes the union of the Elders' canopy signers, primary
   first. This covers the Lab runner and `@shadenet/sdk/node`, which wrap this client. The Rust
   SDK and the browser SDK already did this (#182).
3. **The record carries the RPC list.** `admission.roots.staked.rpcUrls` is the failover order
   (one to five HTTPS endpoints, no duplicates); `rpcUrl` stays and must equal `rpcUrls[0]`.
   Every reader takes the list: `SHADE_TREE_NETWORK` fills `SHADE_TREE_RPC_URL` with it, the v4
   role and the bootstrap preset default the runtime RPC to it, the Rust client tries each
   endpoint until one returns complete history, `@shadenet/sdk` moves to the next endpoint on a
   transport failure, and the v4 preflight checks every endpoint on chain when no `--rpc-url`
   is given. `scripts/deploy-contracts.mjs` writes the list. A full-history endpoint goes first;
   the pooled endpoint stays as fallback.

## Consequences

- With the primary Elder down, the second Elder keeps receiving announces, so its canopy stays
  fresh for as long as the outage lasts, and clients that fall back to it find every node.
- Each node makes one extra Tor POST per Elder per interval (300 s); with two Elders that is
  one more request every five minutes.
- Records validated before this change (no `rpcUrls`) keep working: the list defaults to
  `[rpcUrl]` everywhere.
- The announce bytes, the directory format and every signed string are unchanged; the wire
  freeze test is untouched.
- The Elder-side federation (`SHADE_TREE_BOOTNODE_PEERS`) is unchanged and still lists the
  primary only for a joining Elder; making it symmetric is separate work.

## Alternatives considered

- **Elder-to-Elder replication of announces.** The Elders already federate their directories,
  but a replicated announce is a second-hand liveness claim: the Elder that lists a node should
  have heard from it. Announcing to each Elder keeps every listing first-hand and needs no new
  trust between Elders.
- **Keep the RPC list in the deploy wrapper.** That is where it lived; the site, the SDKs and
  the preflight then disagreed with the fleet about which endpoints exist. One list in the
  record, read by everyone, removes the drift.
- **An RPC list at the top level of the record.** The endpoint belongs to the staked root (it
  is that contract's chain); other roots may live on other chains later.

## References

- `docs/STAGING-REHEARSAL.md` sections 4 and "Left for M8" (the two findings).
- #182 (`elders[]`, both SDKs use every Elder), #195 (preflight checks every failover
  endpoint), #207 (member-set replay verified against the contract counters).
- ADR 0003 (the Elder is a cache, not a trust root); OPS-8 (RPC failover list in
  `SHADE_TREE_RPC_URL`).
