# Architecture decision records

Terse records of the load-bearing decisions in Shade Tree: the
context, the decision, its consequences, and the alternatives that were rejected. Each
claim is traceable to a source file, contract, or existing doc.

| ADR | Title | One-line summary |
|---|---|---|
| [0001](0001-client-language.md) | Client implementation language | JS stays the reference implementation and single source of truth for the trust-critical checks; a Rust client (`arti` + `zerokit`) is the distributable, kept honest by the conformance vectors. |
| [0002](0002-onion-never-on-chain.md) | The onion address is never stored on chain | `GatewayRegistry` keys the stake by operator address, never the onion, so the fleet stays un-enumerable and one stake can rotate across many onions; the onion↔operator link lives only in the signed announce. |
| [0003](0003-bootnode-is-a-cache-not-a-trust-root.md) | The bootnode is a cache and a discovery trust boundary | The pinned signer controls the candidate list; onion/key binding and signed capabilities narrow, but do not remove, that trust. |
| [0004](0004-rln-over-slot-scheme.md) | Real RLN over the public-slot scheme | Chose real circom-rln Groth16 (fresh per-tunnel share, over-spend reconstructs the secret and slashes) over the ROADMAP-v1 #1 public-slot scheme, which was simpler but leaked the slot histogram and had no slashing. |
| [0005](0005-governed-gateway-slash.md) | Gateway slashing governed, member slashing permissionless | Member over-spend is a cryptographic proof, so its slash is permissionless; gateway misbehavior is subjective, so its slash is owner-governed (swappable for a DAO / fraud-proof). |
| [0006](0006-reputation-tiers.md) | Reputation tiers are per-leaf `userMessageLimit`s in one tree | The tier IS the leaf's private `userMessageLimit` (circom-rln already hashes it into the leaf and range-checks `messageId` under it), so two tiers with different `K` are proven in ZK, enforced by the root + nullifier set, and unclaimable — with no circuit change, no wire change, and no tier leak; on-chain tier admission/slash is a flagged follow-up. |
| [0007](0007-paid-access.md) | Paid access is an operator-inserted leaf in a second on-chain tree, redeemed with the same RLN proof | Access is bought off chain (HTTP 402 rails, registrar) and the operator inserts the buyer's rateCommitment into `PaidAccessSet` (sibling tree, slot-3 root, no exit/refund); the gateway trusts the UNION of members.json + staked + paid roots, routes a slash to whichever contract holds the leaf, and only WARNs below the anonymity floor; supersedes PAYMENTS.md's native-ETH deposit/sweep rail. |
| [0008](0008-per-gateway-admission-and-payment-choice.md) | Each gateway provider chooses what it admits and what it sells; the default is maximum anonymity | `SHADE_TREE_ADMIT=invited[,staked][,paid]` (default `invited`, the max-anon mode; anonymity order invited > staked > paid; fail-closed on a missing contract; `SHADE_TREE_ROOTS` deprecated alias) names the ONLY root sources + slash targets; the registrar serves a chosen rail subset (`SHADE_TREE_PAY_PROTOCOLS`) and may run on a gateway-only box; both are advertised as signed caps (`admits`, `pay`) so a client routes only to gateways admitting its leaf source, and `--max-anon` insists on invited-only gateways. |
| [0009](0009-epoch-bandwidth-envelope.md) | Size a public RLN epoch as a bounded research session | Enforce `10 ×` the 4 MiB workload estimate (40 MiB combined) per local RLN epoch slot; rate shaping, signed advertisement, a multi-target session, and atomic Grove-wide accounting remain follow-ups. |
| [0011](0011-session-tickets.md) | Session tickets ride the v4 port | `session-v1` is two new v4 envelope kinds on the existing onion port (an initialization that binds a ticket-book digest, and proof-less ticket spends), not the HTTP/2 side port of the design doc; Tor already multiplexes streams on one circuit, the book digest is the session handle, the byte ceiling is the proof's own slot budget; off unless the record's `sessionTickets` says so. |
| [0010](0010-two-sdks-one-spec.md) | Two SDKs, one spec | The spec and `testdata/vectors.json` are normative; a Rust SDK (CLI, proxy, MCP) and a JS SDK (browser and Node) live in one monorepo, pass the same vectors and expose the same errors; replaces ADR 0001's "JS source wins". |

## Format

Each ADR carries Status / Date / Task, then Context, Decision, Consequences, and
Alternatives considered, plus a References list pinning every claim to a source. Numbered
sequentially; a superseded decision is marked in its own Status line rather than deleted.
