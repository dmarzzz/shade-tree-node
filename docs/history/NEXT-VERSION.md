# Next version: combined build spec (A + B + C)

> **History.** Kept as written for the record; it describes an earlier version and is not a current runbook. Current docs: [docs index](../README.md).

**Status: build spec for the next version.** This is the integration contract three
parallel tracks build against, then combine. It bundles the increments discussed in
ONCHAIN.md / FLEET.md / LIGHT-CLIENT.md into one coherent demo:

- **A — honesty fixes:** self-enrollment, request-bound signal, deterministic-retry,
  cheap-check reorder.
- **B — correlation mitigations:** per-tunnel gateway rotation (already scaffolded) +
  per-tunnel slot nullifiers (ROADMAP-v1 #1 Tier 1, public slots, no custom circuit).
- **C — on-chain staked set + slashing:** `StakedReputationSet` on a local `anvil`,
  trusted **node** root provider, RLN-style share slashing at PoC fidelity.

## Demo parameters (chosen; production values noted)

| Param | Demo | Production | Env |
|---|---|---|---|
| Epoch length | 120 s | 3600 s | `SHADE_TREE_EPOCH_SECONDS` |
| Slots per member per epoch `K` | 8 | 30 | `SHADE_TREE_SLOTS` |
| RLN degree `L` per slot | 1 (2nd use of a slot ⇒ slashable) | 1 | — |
| Bond | 0.01 ETH | policy | contract ctor |
| Unbonding `U` (≥ F+E+C) | 300 s | 24 h | contract ctor |
| Freshness window `F` | 1 epoch | 1 epoch | `SHADE_TREE_FRESHNESS_ROOTS` |
| Slash-confirm margin `C` | 30 s (anvil ~instant) | ~13 min (L1 finality) | — |

Short epoch + short unbonding are deliberate so the time-locked withdraw is demonstrable
in a few minutes on `anvil`; the constraint `U ≥ F + E + C` still holds (120+120+30=270 ≤
300).

## Slot nullifiers (B)

- Scope per slot: `scope(epoch, i) = H(epoch, i)` for `i ∈ [0, K)`.
- The shim precomputes the epoch's `K` proofs in the background at rollover and rotates
  through them **one slot per tunnel**, so the hot path just picks the next unused proof
  (near-zero latency; proving is never on the request path).
- Each slot yields a distinct nullifier `H(secret, scope_i)`, mutually unlinkable to the
  gateway. A member has exactly `K` valid scopes per epoch ⇒ rate capped at `K`.
- Combine with rotation: the shim picks a slot **and** a gateway per tunnel.

## Request-bound signal + deterministic retry (A)

- The RLN signal (message) is `signal = H(target_host:port, requestNonce)` where
  `requestNonce` is stable for one logical request.
- **Reuse the same signal on every retry of that request.** A retry reproduces the same
  share (same evaluation point), so an induced-retry storm cannot manufacture a distinct
  over-spend and slash an honest member. Load-bearing; see ONCHAIN.md.

## RLN share + slashing at PoC fidelity (C)

Full RLN needs a Groth16 circuit (adopt `rate-limiting-nullifier` upstream in production).
The demo carries the share in JS at PoC fidelity, and **documents the seam honestly**:

- Per (secret, scope_i): nullifier `N = Poseidon(secret, scope_i)`; a degree-`L` line with
  the identity secret as constant term; share `y = a0 + a1·x` at `x = signal`.
- One signal per slot reveals one point (`y`) — reveals nothing. A **second distinct
  signal under the same (scope_i, N)** reveals a second point ⇒ interpolate the secret ⇒
  `deriveCommitment(secret)` ⇒ `slash(commitment, secret, receiver)` on chain.
- **Fidelity note (must be in code + docs):** the demo does not ZK-prove the share is
  well-formed relative to the membership proof; a production RLN circuit binds share ↔
  membership. The demo trusts the envelope's share format. State this; do not hide it.

## Envelope v2 (the wire format between shim and gateway)

```json
{ "v": 2, "target": "host:443", "slot": 3,
  "proof": { ...semaphore membership proof against the on-chain root... },
  "nullifier": "…", "scope": "…H(epoch,slot)…",
  "share": { "x": "…H(signal)…", "y": "…" } }
```

Gateway order of checks (cheap first, per adversarial-review #4):
1. `scope` is a valid slot for the current/previous epoch (cheap),
2. `proof.merkleTreeRoot` ∈ recent-roots (cheap),
3. membership `verifyProof` (expensive SNARK),
4. slot-nullifier dedup + share collection; on 2nd distinct signal ⇒ reconstruct + slash,
5. egress `:443` tunnel.

## Library API (Track 2 provides; Track 3 consumes)

`lib/semaphore.mjs` (extended) + `lib/rln.mjs` (new) export:

```
currentEpoch(nowMs?) -> bigint
EPOCH_SECONDS, K_SLOTS
slotScope(epoch, i) -> scope
requestSignal(target, nonce) -> x
proveForSlot(secret, epoch, i, signal) -> { proof, nullifier, scope, slot, share }
verifyEnvelope(env, recentRoots, nowMs?) -> { ok, reason, nullifier, scope, slot, share }
reconstructSecret(shareA, shareB) -> secret        // 2 points on the degree-1 line
deriveCommitment(secret) -> commitment             // Poseidon; must match the on-chain hasher
loadGroupOnchain(rootProvider) -> { recentRoots }   // via lib/root-provider.mjs (node mode)
```

`deriveCommitment` and the on-chain `ICommitmentHasher` MUST agree (same Poseidon) so a
reconstructed secret slashes the right leaf.

## Track file ownership (no overlap ⇒ safe parallel edits)

- **Track 1 — contracts.** `contracts/` (finalize `StakedReputationSet.sol`, add mock
  `IWithdrawVerifier` + `ICommitmentHasher` using `poseidon-solidity`), `foundry.toml`,
  `script/` deploy, `test/` (register / exit / time-locked withdraw / slash / re-register).
  Provide an anvil deploy that prints addresses to a JSON the gateway reads.
- **Track 2 — crypto lib.** `lib/semaphore.mjs`, `lib/rln.mjs`, `lib/root-provider.mjs`
  (finish `NodeRootProvider` in event-reconstruction mode against the contract's
  `MemberRegistered` / `MemberExiting` / `MemberSlashed` events).
- **Track 3 — gateway + shim + enroll.** `gateway/gateway.mjs`, `client/shim.mjs`,
  `group/enroll.mjs` (self-enrollment; on-chain `register` sibling), build to the lib API
  above (mock the lib in unit tests since the real lib lands at combine time).

Do **not** edit `package.json`; report any new npm dep in your final message and it will
be added at combine. Do not edit another track's files.

## Combine + e2e (owner: integrator, not the tracks)

After the tracks land: add deps, reconcile the lib API against Track 3's expectations,
then a single `scripts/demo-e2e.sh` that on `anvil`: deploys, self-enrolls + stakes two
members, runs a rotating-gateway + rotating-slot egress, forces a slot over-spend and
shows the on-chain slash + a blocked withdraw, and shows a clean member's time-locked
`initiateExit → wait U → withdraw`.
