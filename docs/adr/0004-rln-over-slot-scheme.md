# ADR 0004: Real RLN over the public-slot scheme

- Status: Accepted
- Date: 2026-08-13
- Task: milestone 1 (docs/history/ROADMAP-v1.md #1)

## Context

The goal is per-tunnel unlinkable rate limiting: a member should get a fixed budget of
requests per epoch, each request should carry a distinct nullifier so even the gateway
cannot tie a member's requests together, and an over-spender should be punished.

ROADMAP-v1 #1 sketched this in two tiers. Tier 1 ("public slots, stock Semaphore") needs no
custom circuit: publish `K` scope slots per epoch, `scope_i = H(epoch, i)`, and have the
client generate one ordinary Semaphore proof per slot, the gateway accepting a proof only
if its scope is in the published slot set. Tier 2 hides the slot with a custom circuit but
explicitly drops slashing, because a Semaphore proof travels inside the single Tor tunnel
to one verifier, so there is no public Shamir share to reconstruct from.

That framing left the rate-limit budget enforced only by "refuse a nullifier once its
budget is spent" and, in tier 1, leaked which slot index each request used.

## Decision

Ship real RLN instead of the slot scheme: `rlnjs@3.3.0` against the locally-built
`circom-rln` v1.0.0 Groth16 artifacts (`lib/rln.mjs`, `circuits/rln/`). One Groth16 proof
per tunnel proves, in a single circuit:

- ownership of the `identitySecret` behind some `rateCommitment` leaf in the depth-20
  tree,
- at a private `messageId = slot i`, range-checked `0 <= i < K` inside the circuit,
- for `externalNullifier = Poseidon(epoch, rlnIdentifier)` (per-epoch, not per-slot),
- evaluating the degree-1 line `y = identitySecret + a1*x` at `x = H(message)`.

`K` distinct `messageId`s per epoch yield `K` distinct nullifiers, so the rate stays
capped. Reusing a `messageId` in the same epoch on a *different* message produces two
`(x, y)` points on the same line, from which anyone can Shamir-reconstruct the
`identitySecret` (`reconstructSecret`) and slash the leaf.

The share-to-membership binding is proven *inside* the one Groth16 circuit, replacing the
v2 proof-of-concept that layered a hand-rolled Shamir share over a separate Semaphore
membership proof and asserted the binding with a cheap `signal == share.x` check.

## Consequences

- One leaf is the `rateCommitment` (`deriveCommitment` / `RateCommitmentHasher`), which is
  exactly the on-chain membership leaf in `StakedReputationSet`. The crypto side and the
  contract share one commitment (docs/CONTRACTS-AUDIT.md invariant I8).
- The slot is a **private** witness (`messageId`); there is no public slot any more. The
  gateway keys its spent-set on `nullifier`, and a repeated nullifier with a *different*
  public `x` is the over-spend signal (`verifyEnvelope`). No slot-usage histogram leaks.
- Slashing is cryptographic: an over-spend reveals the secret, and possession of a
  `(commitment, secret)` pair is the sole authorization for the permissionless
  `StakedReputationSet.slash`. Honest members never expose their secret, so they are never
  slashable.
- Cost is a custom circuit to build, audit, and ship artifacts for. The current
  `circuits/rln/` artifacts came from an untrusted testnet phase-2 ceremony, so they are
  testnet-only until a proper multi-party ceremony (docs/AUDIT.md; task T-HARD-1).

## Alternatives considered

- **The slot scheme (ROADMAP-v1 #1 tier 1/2).** Simpler: tier 1 needs no custom circuit at
  all, just a scope-set check on stock Semaphore. Rejected as the endpoint because tier 1
  leaks the slot-usage histogram (the gateway learns which slot index each request used),
  and both tiers give up slashing entirely (no public share to reconstruct in the
  single-verifier tunnel), leaving over-spend punished only by refusal, not by loss of
  bond. Real RLN hides the slot as a private witness *and* keeps a cryptographic slash.

## References

- lib/rln.mjs (header "REAL Rate-Limiting-Nullifier ... replaces the v2 PoC";
  `proveForSlot`, `verifyEnvelope`, `reconstructSecret`, `deriveCommitment`)
- lib/MIGRATION-NOTES.md (v2 to v3 semantic changes)
- circuits/rln/ARTIFACTS.md (artifact provenance, untrusted ceremony)
- contracts/StakedReputationSet.sol `slash` (cryptographic, permissionless)
- docs/CONTRACTS-AUDIT.md invariant I8 (membership leaf == rate commitment)
- docs/history/ROADMAP-v1.md #1 (the slot scheme, superseded)
