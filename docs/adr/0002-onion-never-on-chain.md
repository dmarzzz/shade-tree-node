# ADR 0002: The onion address is never stored on chain

- Status: Accepted
- Date: 2026-08-13
- Task: milestone 4 (docs/history/ROADMAP-v1.md #4), invariant I6 (docs/CONTRACTS-AUDIT.md)

## Context

A v3 `.onion` address *is* an ed25519 public key. `onionToPubkey` in
`lib/directory.mjs` recovers the 32-byte identity key straight out of the 56-char
address (`base32(PUBKEY[32] || CHECKSUM[2] || VERSION[1])`), which is the whole
reason a directory entry can be self-authenticating. That same property is why the
address must not go on chain.

Tor stores v3 onion descriptors on the HSDir hashring under a *blinded* key,
specifically so the set of running hidden services cannot be enumerated. Writing the
onion into a public contract would hand back exactly what the blinded HSDir design
throws away: the full fleet becomes publicly enumerable, and each onion is bound
forever to the address that paid to stake it. The paying address links the operator's
funding graph to a specific egress node, permanently, on an immutable ledger.

The on-chain contract that backs a gateway is `contracts/GatewayRegistry.sol`. It
needs to answer one question for the bootnode and clients: is this operator's bond
live (`isStaked(operator)`)? That question is about an operator, not about an onion.

## Decision

`GatewayRegistry` keys the stake by operator **address** and stores only
`struct Stake { bond, index, exitInitiatedAt }`. There is no field, event, argument,
or view anywhere in the contract that carries an onion address (docs/CONTRACTS-AUDIT.md
invariant I6). Keying by `msg.sender` is honest here because a gateway operator is not
anonymous: it serves a public egress IP anyone using it can observe, so an ordinary key
managing an ordinary bond leaks nothing new.

The onion lives only in the signed announce the operator hands the bootnode
(`bootnode/announce.mjs`). The binding "this onion is backed by this stake" is an
off-chain ECDSA operator signature over `{onion, operator}`, verified at announce time
and re-checkable by any client from `GET /gateway/<onion>`.

## Consequences

- One stake can rotate across many onions over time. The operator re-signs a new
  announce for a new onion under the same bond; nothing on chain changes.
- The fleet is never enumerable on chain. An observer reading `GatewayRegistry` sees a
  count of bonded operator addresses, never the set of running onions.
- The onion to operator link exists in exactly one place: the signed announce. A client
  that wants the pairing fetches the raw announce and re-verifies the operator signature
  itself; it is not forced to trust the bootnode for the pairing (docs/AUDIT.md, "known
  unaudited surfaces").
- Onion control and stake liveness are checked independently: onion control is
  cryptographic (ed25519 by the onion's own key, re-derived by the client); stake is an
  on-chain `isStaked` read. Neither depends on the onion being on chain.

## Alternatives considered

- **Key the stake by onion address.** Rejected: puts the onion on chain directly,
  making the fleet enumerable and binding onion to funding address forever. Defeats the
  blinded-HSDir property the whole design leans on.
- **Key by `keccak256(onion)` (a hash, not the raw address).** Rejected: the onion set
  is small and its members are public strings, so the preimage is trivially derivable by
  hashing candidate addresses. A hash of a low-entropy public identifier is not a hiding
  commitment; the fleet stays enumerable and the permanent funding-address binding
  remains.

## References

- contracts/GatewayRegistry.sol (keyed by operator address; header comment "WHAT THIS
  CONTRACT DOES NOT DO")
- docs/CONTRACTS-AUDIT.md invariant I6 ("The onion is NEVER stored on chain")
- lib/directory.mjs `onionToPubkey` / `pubkeyToOnion` (a v3 onion IS an ed25519 key)
- bootnode/announce.mjs (the off-chain onion to operator signature)
- docs/BOOTNODE.md ("The onion is never on chain")
- docs/history/ROADMAP-v1.md #4
