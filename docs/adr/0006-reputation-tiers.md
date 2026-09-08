# ADR 0006: Reputation tiers are per-leaf `userMessageLimit`s in one tree

- Status: Accepted and fully shipped — JS + Rust clients and gateway (T-FEAT-8, PR #39) AND
  on-chain tier admission / tiered slash (T-FEAT-8b, live on Sepolia as `rln-v4-tiers`,
  `0xFe48De8b9aCA4386DC31C845d579ae62f04f9d25`, 2026-08-17; `docs/ONCHAIN.md` "Tiers on chain")
- Date: 2026-08-17 (on-chain follow-up landed the same day)
- Task: T-FEAT-8 / T-FEAT-8b (docs/SHIP-PLAN.md) — reputation-weighted rate budget

## Context

Membership was binary: every member proved against the same leaf formula and got the
same per-epoch budget `K` (`K_SLOTS = 8`, `SHADE_TREE_SLOTS`). T-FEAT-8 asks for a spectrum:
"a member with higher on-chain stake (or accrued good behavior) proves, in zero knowledge,
a budget tier and gets a larger `K`, without revealing which member" — two tiers with
different `K`, each proven in ZK, the gateway enforcing the proven tier, and no member able
to claim a tier it lacks. The task text assumed a circuit change ("the RLN circuit taking a
tier as a range-checked public input").

Reading the circuit we ship (`circuits/rln/ARTIFACTS.md`, circom-rln v1.0.0 `RLN(20,16)`)
shows the tier is ALREADY a circuit input — it is just private:

```
identityCommitment = Poseidon(1)([ identitySecret ])
rateCommitment     = Poseidon(2)([ identityCommitment, userMessageLimit ])   // the tree leaf
messageId < userMessageLimit                                                 // RangeCheck(16), asserted
public signals: [ y, root, nullifier, x, externalNullifier ]                 // no limit on the wire
```

`userMessageLimit` is a PRIVATE witness that is (a) hashed into the leaf the Merkle path
opens and (b) the upper bound of the in-circuit range check on the private `messageId`. Every
side of the repo simply hard-wired it to 8: `lib/rln.mjs` (`K_BIG` in the leaf and in
`proveForSlot`), the JS client's slot pool (`makeSlotPool` wraps at `K_SLOTS`), the Rust
client (`slotcursor::K_SLOTS`, `--k`), the identity file, `group/enroll.mjs`, and on chain
`RateCommitmentHasher.K = 8` (`network/sepolia/contracts.json` `userMessageLimit: 8`).

## Decision

**A tier IS the leaf's `userMessageLimit`.** One tree holds every tier; a member enrols a leaf
`Poseidon2(Poseidon1(identitySecret), limit)` at its tier's limit and proves with that same
limit. Nothing else changes:

- **Proven in ZK, without revealing which member — or which tier.** The proof opens a leaf
  that commits to `limit` and asserts `messageId < limit`; both are private. The public
  signals, the envelope (`docs/WIRE-SPEC.md`), and `verifyEnvelope`'s result are
  byte-identical across tiers. The gateway learns nothing about a proof's tier — strictly
  more private than the task's "public tier input", and than the separate-root alternative
  below.
- **The gateway enforces the proven tier** the only way a private input can be enforced:
  the Groth16 verify against a TRUSTED ROOT (`wrong-group-root` before any SNARK work), and
  the per-nullifier spent-set. A tier-1 member (limit 8) has no valid proof for
  `messageId >= 8` (client pre-check `slot i >= limit`, and bypassing it the circuit's
  RangeCheck asserts), so its 9th distinct request in an epoch must reuse a messageId =>
  the same nullifier with a distinct `x` => `over-spend-slashed`. A tier-2 member (limit 32)
  gets 32 distinct nullifiers from the same tree.
- **A member cannot claim a tier it lacks.** A different limit is a different Poseidon
  output, i.e. a leaf that is NOT in the tree: `proveForSlot(.., { limit: 32 })` for a
  tier-8 member fails at the Merkle lookup ("not in group"), and a real proof over a
  forged tree containing the wished-for leaf is rejected `wrong-group-root`. Tier
  admission is therefore exactly leaf admission: whoever admits leaves (the operator's
  `members.json`, or the contract) decides who may hold which limit.
- **Slashing names the right leaf.** After an over-spend the gateway holds the
  reconstructed `identitySecret` but not the tier. `resolveSlashLeaf(secret, { tiers,
  hasLeaf })` derives one candidate per known tier (`SHADE_TREE_TIERS`, always containing `K`)
  and picks the one present in the local set; with no leaves (on-chain root mode) it falls
  back to the default tier's leaf (`resolved:false`, a warn) — the pre-tier behaviour and the
  only leaf today's on-chain hasher can slash (see Consequences).
- **Bounds.** `MAX_LIMIT = 65535`: the circuit compares with `LessThan(16)`, which is NOT
  sound for a limit >= 2^16 (a leaf with such a limit is not rejected by the circuit), so
  `normLimit` refuses it everywhere a leaf is derived, and admission MUST never accept one.

Surface (all default to `K_SLOTS`, so pre-tier files, leaves, and wire bytes are unchanged):
`rateCommitmentOf(identity, limit)`, `deriveCommitment(identitySecret, limit)`,
`proveForSlot(.., { limit })`, `groupFromIdentities([{ identity, limit }])`,
`ShadeTreeClient({ limit })` / `SHADE_TREE_LIMIT`, `shade-tree enroll --limit N`, `shade-tree identity --limit N`
(writes `limit` into the Rust identity file only when non-default), Rust `--k` (defaults to
the identity file's `limit`, else 8), gateway `SHADE_TREE_TIERS`.

## Consequences

- No circuit change, no new trusted setup, no artifact rotation, no wire version bump, no
  Rust conformance-vector change: the envelope shape and public signals are unchanged.
- The tier is a per-leaf, admission-time fact. Changing a member's tier = removing its
  leaf and admitting a new one (the member re-enrols at the new limit; the identity secret
  can stay). There is no "upgrade in place".
- A member must run its client with the limit its leaf was enrolled with (`SHADE_TREE_LIMIT`,
  identity-file `limit`, `--k`); a mismatch fails at prove time, never on the wire.
- **On chain, tiers are admitted since rln-v4-tiers (T-FEAT-8b).** The redeployed
  `StakedReputationSet` records the tier at `register(commitment, limit)` and requires that
  tier's fixed bond (`bondFor(limit)`, an immutable constructor table — no owner), the
  `RateCommitmentHasher` is tiered (`commitmentOf(secret, limit)`), and
  `slash(commitment, secret, limit, receiver)` recomputes the leaf at the CLAIMED limit and
  burns that tier's bond; the exit-auth verifier receives the recorded limit. The rln-v3 set
  (hasher pinned K=8, unslashable tiered leaves) is superseded and only remains the live
  fleet's slash target until its units are flipped. Tier changes are still re-enrolment
  (a new leaf, a new stake); the table on Sepolia is {8, 32}.
- The gateway's `SHADE_TREE_TIERS` is bookkeeping for the slash path, not a policy: proof
  verification does not consult it. Against rln-v4 the on-chain slasher unions it with the
  contract's `allowedLimits()` and resolves the tier of a reconstructed secret via
  `limitOf(candidateLeaf)` (`gateway/gateway.mjs makeOnchainSlasher`), so an over-spend at
  ANY admitted tier slashes the right leaf even from a gateway that holds only roots; against
  rln-v3 an unknown-tier over-spend still slashes the default leaf (with a warn).

## Alternatives considered

- **Tier as a new PUBLIC circuit input** (the task's original framing). Needs a circuit
  change + a new ceremony (`docs/CEREMONY.md`), a wire bump, and it publishes the tier on
  every request — a linkability channel across the fleet's logs (`docs/THREAT-MODEL.md`
  §4.13 spirit). Rejected: strictly more work and strictly less private than what the
  shipped circuit already gives.
- **One tree per tier, gateway maps root -> K.** Also zero circuit work and simple, but
  the root IS a public signal, so every proof reveals its tier to the gateway and to any
  observer of the accepted-root set; it also splits the anonymity set per tier and doubles
  the root plumbing (on-chain contract, root providers, freshness windows). Rejected: the
  per-leaf limit gives the same enforcement with one tree, one root, and no tier leak.
- **Gateway-side counting (`K` per nullifier family).** Impossible: nullifiers are
  unlinkable by design, so the gateway cannot count a member's requests; the only counter
  is the circuit's messageId range, which is what per-leaf limits use.

## References

- `circuits/rln/ARTIFACTS.md` — leaf formula, `RLN(20,16)`, public-signal order.
- `lib/rln.mjs` — `K_SLOTS`, `MAX_LIMIT`, `normLimit`, `parseTiers`/`TIERS`,
  `rateCommitmentOf`, `deriveCommitment(s)`, `resolveSlashLeaf`, `proveForSlot({ limit })`.
- `gateway/gateway.mjs` — `deriveSlashLeaf`, `SHADE_TREE_TIERS` startup line.
- `client/shade-tree-client.mjs` — `makeSlotPool({ K })`, `ShadeTreeClient({ limit })`, `buildEnvelope`.
- `lib/identity-file.mjs`, `group/identity.mjs`, `group/enroll.mjs` — `--limit`.
- `rust/shade-tree-client/src/main.rs` (`IdentityFile.limit`, `--k`), `rust/shade-tree-client/src/slotcursor.rs`
  (`MAX_LIMIT`), `rust/shade-tree-rln/src/tree.rs` (`rate_commitment`), `rust/shade-tree-rln/tests/tree_parity.rs`.
- Tests: `lib/tiers.selftest.mjs` (fast), `test/reputation-tiers.selftest.mjs` (real proofs).
- `docs/ONCHAIN.md` "Tiers on chain" — the contract side (shipped: `contracts/StakedReputationSet.sol`,
  `contracts/RateCommitmentHasher.sol`, `contracts/WithdrawVerifier.sol`,
  `test/StakedReputationSet.tiers.t.sol`, `test/onchain-tiers.selftest.mjs`,
  `network/sepolia/integration-report-rln-v4.md`).
