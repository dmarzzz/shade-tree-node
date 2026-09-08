# RLN migration (P1 crypto core) — what the gateway + shim must change

`lib/rln.mjs` now produces **real** Rate-Limiting-Nullifier Groth16 proofs (rlnjs@3.3.0
against `circuits/rln/` circom-rln v1.0.0 artifacts). The v2 PoC layered a hand-rolled
Shamir share over a Semaphore membership proof and bound them only by a cheap
`signal == share.x` check. That seam is **gone**: the share↔membership binding is now
proven inside one circuit. This changes the envelope and several gateway assumptions.

## Envelope v4 shape (the wire object)

`proveForSlot(secret, epoch, i, signal, { group })` returns:

```js
{
  proof: {                              // RLNFullProof, JSON-safe (bigints stringified)
    snarkProof: {
      proof: { pi_a, pi_b, pi_c, protocol, curve },   // groth16 proof (strings)
      publicSignals: {                  // ORDER on-chain: [y, root, nullifier, x, externalNullifier]
        y, root, nullifier, x, externalNullifier      // all decimal strings
      }
    },
    epoch: "<decimal string>",
    rlnIdentifier: "<decimal string>"   // = RLN_IDENTIFIER (default 1)
  },
  nullifier:         "<decimal string>",   // == publicSignals.nullifier (spent-set key)
  externalNullifier: "<decimal string>",   // == publicSignals.externalNullifier (per-EPOCH)
  slot: <number i>,                        // LOCAL bookkeeping only — NOT verified, NOT public
  share: { x: "<string>", y: "<string>" }  // == publicSignals.x / publicSignals.y
}
```

The **envelope the shim sends** should carry `{ v: 4, target, proof, nullifier,
externalNullifier, share }`. Do **not** send `slot`/`scope` — the slot (messageId) is a
private circuit witness; there is no public slot any more. `verifyEnvelope` ignores any
`slot` field.

## `verifyEnvelope(env, recentRoots, nowMs)` — new contract

Returns `{ ok, reason, nullifier, externalNullifier, share:{x,y} }` (no `slot`, no
`scope`). The returned `nullifier` and `share` are read from the proof's **public
signals** (authoritative), never from the envelope's copies — a lying envelope can't
desync the spent-set. Reasons, in cheap→expensive order:

1. `stale-external-nullifier` — `externalNullifier` must equal
   `externalNullifierFor(epoch)` for the **current or previous** epoch (one-epoch skew).
2. `signal-mismatch` — `share.x` must equal the proof's public `x`.
3. `wrong-group-root` — the proof's public `root` must be in `recentRoots`
   (accepts a `Set` or `Array`; `Array.from` normalizes both — unchanged).
3b. `bad-artifact:*` / `artifact-retired:<id>` / `artifact-unknown:<id>` — (T-HARD-8) the
   envelope's optional `artifact` id must resolve to a vkey in the gateway's accepted set
   (`SHADE_TREE_ZK_ARTIFACTS`; absent field ⇒ the legacy id). Cheap map lookup; see
   `docs/VERSIONING.md` "Artifact-version negotiation".
4. `invalid-proof` / `verify-threw:*` — the RLN Groth16 verify under THAT vkey (last, expensive).

## Semantic changes the gateway MUST make

- **Spent-set keys on `nullifier`.** There is no public slot. A member's K messageIds in
  an epoch yield **K distinct nullifiers**; the gateway counts distinct nullifiers per
  root/epoch for the rate cap. (Previously keyed on `(scope, nullifier)`/slot.)
- **Breach detection = repeated `nullifier` with a DIFFERENT public `x`.** Same nullifier
  + same `x` is a duplicate/retry (no new info). Same nullifier + different `x` is an
  over-spend: collect the two `share`s and call `reconstructSecret(shareA, shareB)`.
- **`reconstructSecret` returns the `identitySecret`** (Semaphore v3
  `Poseidon2(nullifier, trapdoor)`), **not** the app's seed `secret`. Feed it to
  `deriveCommitment(identitySecret)` to get the rateCommitment leaf to slash. That leaf
  equals rlnjs `calculateRateCommitment(identityCommitment, K)` and the on-chain
  `hasher.commitmentOf(identitySecret)`.
- **Scope → externalNullifier.** The per-epoch value is `externalNullifier =
  Poseidon(epoch, rlnIdentifier)`. There is no per-slot scope. Use `externalNullifierFor(epoch)`.
- **The message is a STRING.** `requestSignal(target, nonce)` now returns a deterministic
  string; the circuit's public `x = calculateSignalHash(message)`. The shim must reuse the
  same `(target, nonce)` on every retry so `x` (hence share + nullifier) is reproduced.
- **Merkle leaves are rateCommitments.** `group/members.json` is now `version: 2` and its
  members are rateCommitment leaves (was Semaphore commitments). `loadGroup()` builds the
  RLN v3 depth-20 Poseidon tree (rlnjs's own Group) so the JS root == the circuit root.
- **`loadGroupOnchain` / root-provider.** `lib/root-provider.mjs` now rebuilds the tree
  with `newGroup()` (RLN v3), and treats event `topics[1]` as the rateCommitment leaf.
  **On-chain coordination (contracts agent):** the contract MUST maintain the identical
  circom-rln depth-20 Poseidon tree of rateCommitments and emit the rateCommitment as the
  indexed `MemberRegistered` topic, or reconstructed roots won't match proof roots.
  Removed-leaf handling rebuilds a fresh tree of survivors (index renumbering) — fine for
  the append-only demo; a slash that zeroes a leaf in place is a TODO for removals.

## Removed / renamed exports

Gone (v2 PoC): `slotScope`, `shareFor`, `slotNullifier`, `validSlotFor`,
`COMMITMENT_SCHEME`, and `deriveCommitment`'s scheme argument / `SHADE_TREE_COMMITMENT_SCHEME`
(there is now exactly one coherent leaf; no scheme flag).

New helpers: `RLN_IDENTIFIER`, `externalNullifierFor(epoch)`, `identitySecretOf(identity)`,
`rateCommitmentOf(identity)`, `newGroup(leaves)`, `groupFromIdentities(ids)`, `cleanUp()`.

Kept (adapted semantics): `FIELD`, `EPOCH_SECONDS`, `K_SLOTS`, `currentEpoch`, `toField`,
`requestSignal`, `identityFor`, `deriveCommitment`, `proveForSlot`, `verifyEnvelope`,
`reconstructSecret`, `loadGroup`, `loadGroupOnchain`.

## Gotchas

- `deriveCommitment(x)` now takes an **identitySecret**, not the app seed secret. Compute
  a member's leaf as `rateCommitmentOf(identityFor(seed))` or
  `deriveCommitment(identitySecretOf(identityFor(seed)))`.
- rlnjs nests Semaphore **v3** identity/group; `lib/rln.mjs` imports them by explicit
  `dist/index.mjs` path. Do **not** substitute the app's top-level `@semaphore-protocol/*`
  v4 — its LeanIMT tree won't match the circuit.
- Call `cleanUp()` (→ `RLN.cleanUp()`) once at process end so snarkjs worker threads exit;
  otherwise the process hangs. It's a no-op-safe if no proof was ever generated.
- Groth16 proof **bytes** are randomized per call. Only the **public signals** (share x/y,
  nullifier, externalNullifier, root) are deterministic given the inputs. Never dedupe on
  proof bytes; dedupe on `nullifier` (+ compare `x`).
- Proving is ~0.4s/proof (full witness + groth16). Budget accordingly on the gateway; the
  cheap checks (1–3) gate before the expensive verify.
