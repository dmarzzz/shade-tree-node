# ADR 0005: Gateway slashing is governed, member slashing is permissionless

- Status: Accepted
- Date: 2026-08-13
- Task: milestone 4 (docs/history/ROADMAP-v1.md #4), invariant I4 (docs/CONTRACTS-AUDIT.md)

## Context

Two contracts hold slashable bonds. `StakedReputationSet` stakes *members* (anonymous
RLN leaves); `GatewayRegistry` stakes *gateway operators* (public egress nodes). Both
need a slash path, but the two kinds of misbehavior are not the same kind of fact.

A member over-spend is **cryptographically provable**: reconstructing the identity secret
from L+1 RLN shares yields exactly the `(commitment, secret)` pair such that
`hasher.commitmentOf(secret) == commitment`, and that pair only ever exists after a
genuine rate violation. An honest member's secret is never exposed.

Gateway misbehavior (censoring, tampering, downtime) is a **subjective off-chain
judgment**. There is no on-chain predicate that proves a gateway dropped a request or
served a bad response. Whoever decides a gateway misbehaved is exercising judgment, not
checking a proof.

## Decision

Make each slash's authorization match the nature of its evidence:

- **`StakedReputationSet.slash` is permissionless**, gated only by
  `hasher.commitmentOf(secret) == commitment`. No `owner`, no admin. Authorization *is*
  possession of the reconstructed secret. This keeps the member anonymous: the caller
  acts by cryptographic proof, never by `msg.sender` identity.
- **`GatewayRegistry.slash` is owner-gated** (`if (msg.sender != owner) revert
  NotOwner()`). Slashing authority is a governance role because the underlying judgment
  is subjective. `owner` is a single key today; the header comment states the intent that
  swapping it for a DAO, timelock, or fraud-proof verifier is a drop-in change, since the
  stake/exit logic does not depend on who holds `owner`.

This is the one deliberate asymmetry between the member stake and the gateway stake; the
rest of both contracts (register / initiateExit / withdraw, the unbonding window, the
delete-before-payout CEI ordering) is parallel.

## Consequences

- The member slash needs no trusted party: anyone holding a valid over-spend proof can
  execute it, and honest members are structurally unslashable.
- The gateway slash concentrates authority in `owner`, which is a governance surface, not
  a cryptographic one. A DAO or fraud-proof verifier can replace `owner` later without
  touching the bond mechanics.
- `owner` being a single key is a known limitation: `transferOwnership` is a plain
  single-step transfer with no zero-address check, so a fat-fingered `to` could brick
  slashing (docs/CONTRACTS-AUDIT.md section 3). Hardening (two-step accept, timelock,
  DAO) is future work.
- Both slashes work whether the stake is active or mid-unbonding (no `exitInitiatedAt`
  gate), which is what closes the "exit to dodge slash" escape for members and operators
  alike (docs/CONTRACTS-AUDIT.md invariant I4).

## Alternatives considered

- **Permissionless gateway slash.** Anyone can slash an operator on presentation of some
  evidence. Rejected: there is no on-chain proof of gateway misbehavior to gate it on, so
  a permissionless slash would be authorized by an unprovable claim, making it a grief
  vector (any party could burn any operator's bond). Absent a cryptographic predicate,
  the honest form of subjective authority is an explicit, swappable governance role.

## References

- contracts/GatewayRegistry.sol `slash` (owner-gated; header "Semantics: slash owner-only
  (governance)")
- contracts/StakedReputationSet.sol `slash` (permissionless, `commitmentOf` gate)
- docs/CONTRACTS-AUDIT.md section 1 ("the honest asymmetry"), invariant I4, section 3
  ("`owner` is a single key")
- docs/AUDIT.md ("Governed, not permissionless (by design)")
- docs/BOOTNODE.md ("Admission policy"), docs/history/ROADMAP-v1.md #4
