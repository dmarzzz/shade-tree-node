# Plan: close the three PoC seams by adopting RLN

> Historical record. This plan produced the legacy v3 envelope and was later
> superseded by the v4 tiers deployment. Shade Tree now uses wire v4; see
> [`protocol.md`](../../specs/protocol.md) and
> [`MIGRATING-TO-SHADE-TREE.md`](MIGRATING-TO-SHADE-TREE.md).

**Status: P0–P4 BUILT + VERIFIED (2026-07-15; P4 fleet + live Tor confirmed, see progress list below). Historical migration plan; the result was the `rln-v3` release, superseded 2026-08-17 by **`rln-v4-tiers`** (P5 below) in `network/sepolia/contracts.json`.**
Seams 1–3 from `network/sepolia/E2E-REPORT.md` §9 (membership-from-chain, real RLN circuit,
real verifier/hasher) are closed by adopting the real Rate-Limiting-Nullifier circuit in
place of the two-view Semaphore+JS-Shamir crypto.

Progress:
- **P0 artifact gate** — circom-rln v1.0.0 Groth16 artifacts built + `rlnjs@3.3.0` round-trip
  green on Node 24. `circuits/rln/ARTIFACTS.md`. ✓
- **P1 crypto core** — `lib/rln.mjs` real RLN; `lib/rln.selftest.mjs` 21/21. ✓
- **P3-onchain** — rateCommitment hasher + JS↔Solidity vectors; `forge test` 24/24. ✓
- **P2 gateway/shim/e2e** — envelope v3, nullifier-keyed spent-set; anvil `demo-e2e` 23/23. ✓
- **P3-live** — fresh Sepolia deploy (`0xdAE242AE…20FC`) + live integration PASS: stake →
  normal use → over-spend → on-chain slash (`0xc0f99e96…39efb`). `network/sepolia/
  integration-report-rln.md`. ✓
- **P4 fleet + live Tor** — all 3 DO gateways (egress-01, egress-02, shade-tree-03) re-provisioned
  onto the RLN branch (rlnjs installed, wired to `0xdAE242AE…20FC`); live round-trip over Tor
  confirmed, rotating across all three, laptop IP absent from every gateway log. ✓

- **P5 rln-v4-tiers (2026-08-17, T-DEV-9c + T-FEAT-8b)** — the member set redeployed at
  `0xFe48De8b…9d25` with the T-DEV-9 ON-CHAIN incremental tree (`currentRoot` at slot 3, so
  `LightClientRootProvider` reads a real root; the rln-v3 set predated it and proved slot 3 = 0)
  and ON-CHAIN reputation tiers (`register(commitment, limit)` at `bondFor(limit)`, tiered
  `RateCommitmentHasher.commitmentOf(secret, limit)`, `slash(commitment, secret, limit, receiver)`,
  real Groth16 exit-auth taking the recorded limit; table {8: 0.001 ETH, 32: 0.004 ETH}).
  Live integration PASS at two tiers: stake tier 8 + tier 32 → on-chain root == JS root →
  gateway in on-chain root mode → tier-32 over-spend → `slash(.., 32, ..)` burns the tier-32
  bond (`0xfff760a6…494c`, block 11510548). `network/sepolia/integration-report-rln-v4.md`.
  Members from rln-v3 do NOT migrate (the set is a fresh contract; re-stake, at a tier). The
  fleet units still point their slashing at rln-v3 until flipped (`docs/ONCHAIN-DEPLOY.md` §8).
  `lib/root-provider.mjs` reads both event generations, `group/register-onchain.mjs` /
  `gateway/gateway.mjs` detect the contract generation, so one codebase serves either. ✓

Two live-only bugs were found + fixed during P3-live (both slipped past every offline gate):
a shared-snarkjs reentrancy race (serialized behind a mutex in `lib/rln.mjs`) and a stale
`lib/semaphore.mjs` `loadGroup` that built a depth-3 Semaphore-v4 tree instead of the
depth-20 RLN tree (now delegates to the RLN loader).

## Why one circuit closes all three

Today: membership leaf = `Poseidon(EdDSA-pubkey(secret))` (Semaphore identity), slash
leaf = `Poseidon(secret)` (on-chain). Different functions → the two-view seam. RLN
collapses membership + slashable identity into **one Groth16 proof** that emits the Shamir
share, so all three seams close together — the client, the gateway, AND the on-chain hasher
adopt the same leaf.

**Correction (primary source, circom-rln v1.0.0 `rln.circom`).** The real RLN leaf is
**NOT** `Poseidon(secret)`. It is:

```
identityCommitment = Poseidon(1)([ identitySecret ])
rateCommitment     = Poseidon(2)([ identityCommitment, userMessageLimit ])   ← the Merkle leaf
a1                 = Poseidon(3)([ identitySecret, externalNullifier, messageId ])
y                  = identitySecret + a1 * x        ← the SSS share; slash reveals identitySecret
```

Tree DEPTH=20, LIMIT_BIT_SIZE=16 (max `userMessageLimit` = 2^16 - 1; T-FEAT-8 uses this
per-leaf limit AS the reputation tier, `docs/adr/0006-reputation-tiers.md`). The slashable value is
`identitySecret` (= `Poseidon(nullifier, trapdoor)` of the RLN identity), not the raw secret.

So the earlier "the on-chain side is already RLN-shaped / hasher already `Poseidon(secret)`"
claim was **wrong** and is retracted. What's actually true:

- **Seam 2 (real circuit):** the circom-rln circuit *is* the real circuit. ✓
- **Seam 3 (real verifier/hasher):** its exported Groth16 `Verifier.sol` replaces
  `MockWithdrawVerifier`; **`MockCommitmentHasher` must change** from `Poseidon(secret)` to
  `rateCommitment = Poseidon(Poseidon(secret), limit)` (still real Poseidon, one more level).
- **Seam 1 (membership-from-chain):** once `StakedReputationSet` stores **rateCommitment**
  leaves and `loadGroupOnchain` rebuilds that tree, RLN membership proofs verify against the
  on-chain root and "stake → member" is automatic. ✓

The real unlock: **RLN's proof also carries the slashing share**, so one circuit binds
membership and slashability to the *same* secret — which the current two-view design can't.
The cost is a coordinated leaf change on **both** sides (hasher + client) plus adopting a real
circuit; it is not the "on-chain is already done" freebie the first draft claimed.

RLN replaces the Semaphore-v4 proof path entirely (its Groth16 proof *is* the membership
proof), so there is no v3/v4 conflict — enrollment simply moves to RLN identities, as planned.
`rlnjs@3.3.0` is frozen (last publish 2023-10) but coherent and complete; we own its frozen
dep graph (`ffjavascript@0.2.55` pinned) and must build the artifacts ourselves (Phase 0).

## What changes vs. what stays

| Stays unchanged | Changes |
|---|---|
| Tor transport, fleet, onion directory | `lib/rln.mjs` crypto core (Semaphore proof → RLN proof) |
| Shim rotation (gateway + slot) | `lib/semaphore.mjs` `proveForSlot`/`verifyEnvelope` internals |
| `StakedReputationSet` stake/slash/exit logic | Gateway: verify RLN proof; source root from chain (drop members.json default) |
| Envelope v2 shape (proof/nullifier/share) | Enrollment: RLN identity, register `Poseidon(secret)` on-chain |
| On-chain hasher (`Poseidon(secret)`) | New: Groth16 verifier contract for withdraw/exit ZK-auth |

## Decision points — background (all resolved above under "Decisions")

_Kept for the reasoning; the choices are settled in the "Decisions (resolved for this build)"
section below._

1. **Library: `rlnjs` (JS) vs `zerokit` (Rust).** `rlnjs` keeps the current Node stack and
   is the fast path. `zerokit` is the Rust path (pairs with the LIGHT-CLIENT.md /
   embedded-Helios direction). **Lean `rlnjs` now**, revisit zerokit with the Rust rewrite.
2. **Circuit artifacts.** Adopt upstream `rate-limiting-nullifier` circom `rln` + its
   Groth16 wasm/zkey/vkey. Do **not** hand-roll or re-trust a ceremony — use their
   published artifacts; pin hashes. This is the audit surface.
3. **Rate model.** RLN's `userMessageLimit` per epoch maps directly to our K slots. Confirm
   the mapping (K = messageLimit) and that the nullifier/share match our spent-set.
4. **Withdraw/exit ZK-auth.** RLN.sol's withdraw differs from our time-locked exit. Either
   graft our `initiateExit`/`withdraw` (with `U ≥ F+E+C`) onto RLN's registry, or add a
   real Groth16 withdraw verifier (replaces the mock's revealed-secret shortcut). Pick one.
5. **Migration.** `members.json` (identity leaves) is abandoned; members re-enroll with RLN
   identities and re-register `Poseidon(secret)` on-chain. Fresh testnet deploy; no
   in-place migration of the current 8 demo members.

## Decisions (resolved for this build)

1. **Library:** `rlnjs@3.3.0` (JS) now. zerokit stays with the Rust rewrite.
2. **Artifacts:** build locally — no published bundle exists. circom-rln **v1.0.0** (commit
   `17f0fed`), dev Groth16 setup, artifacts hash-pinned under `circuits/rln/`. **Testnet-only**
   (untrusted ceremony). Mainnet needs a real ceremony + audit.
3. **Rate model:** `userMessageLimit = K_SLOTS = 8` by default; since T-FEAT-8 the per-leaf
   limit IS the reputation tier (`docs/adr/0006-reputation-tiers.md`) and since rln-v4 the
   contract records/prices/slashes it (`docs/ONCHAIN.md` "Tiers on chain"). The RLN
   nullifier/messageId maps onto our spent-set the same way the earlier slot nullifier did.
4. **Withdraw/exit:** **graft** our time-locked exit (`initiateExit`/`withdraw`, `U ≥ F+E+C`)
   onto the new leaf, keeping the working economic layer; adopt the real Groth16 `Verifier.sol`
   only for the membership/slash proof. Do NOT swap in RLN.sol wholesale (loses our timelock).
5. **Migration:** fresh testnet deploy, members re-enroll with RLN identities; no in-place
   migration of the current 8 demo members.

## Phased build (each phase independently testable)

- **P0 — artifact gate (prerequisite).** Install circom, build `rln.wasm` / `rln_final.zkey` /
  `verification_key.json` from circom-rln v1.0.0, export `Verifier.sol` from that exact zkey,
  and prove `rlnjs` round-trips against them on this machine (register → prove → verify →
  double-signal → BREACH → recover secret). Hash-pin artifacts in `circuits/rln/ARTIFACTS.md`.
  *Gate: rlnjs BREACH-recovers the identity secret against our own artifacts.* **If this fails
  on Node 24 / the ceremony, the rlnjs path stalls and zerokit is reconsidered — nothing
  downstream is safe to build until P0 is green.**
- **P1 — crypto swap (offline).** `lib/rln.mjs`: RLN identity, `proveForSlot` → RLN proof
  (real circuit), `verifyEnvelope` → RLN verify, keep `reconstructSecret`/share logic
  (RLN gives it natively). Unit test: prove→verify, 2-share reconstruct, K-limit. No chain,
  no Tor. *Gate: rln.selftest green.*
- **P2 — on-chain group + membership-from-chain.** Point the gateway at
  `SHADE_TREE_GROUP_CONTRACT` (on-chain root mode already exists); verify an RLN proof built
  against the on-chain-reconstructed root passes. Register a member, watch the gateway
  accept them with **no members.json**. *Gate: stake → recognized, on anvil.*
- **P3 — real slashing + exit.** Wire the Groth16 withdraw verifier (or graft the timelock);
  redo the integration test (`scripts/integration-sepolia.mjs`) with RLN proofs end-to-end
  on a fresh Sepolia deploy. *Gate: integration test green with the real circuit.*
- **P4 — fleet + live Tor.** Re-provision with RLN artifacts (add a role task to fetch +
  hash-pin the zkey/wasm — also fixes the corrupt-artifact issue seen this run). Live
  round-trip. *Gate: live fleet round-trip on RLN.*

## Cost / risk (honest)

- **The circuit is the audit surface.** Unaudited circuit + real bonds = testnet-only until
  reviewed. Biggest single risk.
- **Artifact size/latency.** RLN proving is heavier than Semaphore; re-check the hot path
  (still one prove per slot at request time until the precompute split, ROADMAP-v1 #1).
- **No mainnet until:** audited circuit, real (not mock) withdraw verifier, and the
  members-only directory (seam 4, separate — FLEET.md).

## Not in this plan (deliberately)

Seam 4 (public directory → members-only / on-chain gateway registry with service staking)
is independent and lives in FLEET.md. The Rust rewrite (zerokit + embedded Helios) is a
separate track (LIGHT-CLIENT.md). Sequence: **RLN first**, then those.
