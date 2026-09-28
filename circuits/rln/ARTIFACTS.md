# RLN circuit artifacts (Phase 0 gate)

Real Groth16 artifacts for `Rate-Limiting-Nullifier/circom-rln`, built locally on
this machine, plus a matching Solidity verifier. Produced by the Phase-0 gate that
proves `rlnjs@3.3.0` round-trips against them. **Testnet-only** (dev/untrusted
Groth16 setup — see Trust below).

## GATE: PASSED

`node circuits/rln/smoke.mjs` is green on **Node v24.6.0** (the repo's Node — no
downgrade needed). It creates an RLN member, registers at `userMessageLimit = 8`
(app `K_SLOTS`), verifies a valid proof, detects a same-epoch messageId reuse as a
**BREACH**, and recovers the member's `identitySecret` — which equals the
identity's secret exactly.

## Toolchain / provenance

| Item | Value |
|---|---|
| circom | `circom compiler 2.2.2` (built from source, iden3/circom tag `v2.2.2`) |
| circom-rln | tag `v1.0.0`, commit `17f0fed7d8d19e8b127fd0b3e5295a4831193a0d` |
| snarkjs (build) | `0.7.x` (circom-rln devDep; used for setup + export) |
| circomlib | `2.x` (circom-rln devDep; poseidon/mux/comparators/bitify) |
| Powers of Tau | `powersOfTau28_hez_final_14.ptau` (2^14), sha256 `489be9e5ac65d524f7b1685baac8a183c6e77924fdb73d2b8105e335f277895d` |
| Groth16 phase-2 | circom-rln `scripts/build-circuits.sh`: 2 dummy contributions + `zkey beacon` (untrusted) |

### Why ptau_14 (and not smaller)

RLN(20,16) compiles to **12,390 constraints** (12,413 wires, 5 public signals).
That exceeds 2^13 = 8,192, so **ptau_13 is too small**; 2^14 = 16,384 is the
minimum standard hermez ptau that fits. This is exactly the file upstream's build
script downloads.

## Circuit parameters (confirmed against source)

- `component main = RLN(20, 16)` → **DEPTH = 20**, **LIMIT_BIT_SIZE = 16**.
- Public signals (order in `_pubSignals[5]`, outputs first then public inputs):
  `[ y, root, nullifier, x, externalNullifier ]`.

### Confirmed Merkle leaf formula (from `circuits/rln.circom`)

```
identityCommitment = Poseidon(1)([ identitySecret ])
rateCommitment     = Poseidon(2)([ identityCommitment, userMessageLimit ])   // <-- the tree leaf
```

`rlnjs` computes `identitySecret = Poseidon(2)([ identity.getNullifier(), identity.getTrapdoor() ])`
(Semaphore v3 identity), and `identityCommitment = Poseidon(1)([ identitySecret ])`.
On a BREACH the recovered secret is that `identitySecret`, so
`Poseidon(1)([secret])` reproduces the leaf's inner commitment. Verified in the gate.

## Artifacts (this directory) + sha256

| File | sha256 |
|---|---|
| `rln.wasm` | `d06035923ab4c7fefedf92e05c9903d059af583b8a92a95ce72466a389ac6ab0` |
| `rln_final.zkey` | `3f87e9a1f30933587ccdbe45a602329a499b9cf011e7378eae7f78b2ec22e685` |
| `verification_key.json` | `0b25f824a04da3a85f128baa6fdaa33d10baa7dd18c5e6f5935089661c68622c` |
| `withdraw.wasm` | `d0b6425f026a75a52fd2f324fac663b6f8986b8e4439b86a9e6d73ee03eef2bb` |
| `withdraw_final.zkey` | `bd4750e62a753738d02cb1d3f04d959e9b01c60df1961c77f783072120a10d43` |
| `withdraw_verification_key.json` | `dd6bfa937405972fdf2080ab82a0f11c80748a4b82c44e572502be6d1eb26fa7` |
| `Verifier.sol` | `6c18de80c770babe2f1fe0db25ed88cbd1766275efcd98d3f9c5bfa62b18419d` |

### Artifact ids (T-HARD-8 artifact-version negotiation)

Each circuit's artifact SET is named on the wire by a content-derived id,
`<circuit>-<sha256(verification_key.json)[0:16]>` — the vkey row above, first 16 hex chars
(`lib/zk-artifacts.mjs` `artifactIdOf`; `testdata/zk-artifacts.lock.json` `circuits.<c>.artifactId`;
Rust `shadenet_proto::artifact_id_of`). Envelopes carry the rln id in `artifact`; gateways accept a set
of ids (`SHADE_TREE_ZK_ARTIFACTS`) so a ceremony swap runs as a dual-VK window (`docs/CEREMONY.md` §6).

| Circuit | Artifact id | Previous id |
|---|---|---|
| `rln` | `rln-0b25f824a04da3a8` | (none — no ceremony has rotated the set) |
| `withdraw` | `withdraw-dd6bfa937405972f` | (none) |

`Verifier.sol` is `contract Groth16Verifier`, `pragma solidity >=0.7.0 <0.9.0`,
`verifyProof(uint[2] _pA, uint[2][2] _pB, uint[2] _pC, uint[5] _pubSignals)`.
Its embedded VK is derived from **this exact** `rln_final.zkey`; the on-chain side
MUST adopt these artifacts as a set (swap the zkey → re-export the verifier).

> The `withdraw` circuit is `RLN slash`-side (`Poseidon(1)([identitySecret])`,
> public `address`); the `RLN` circuit above is the message/rate-limit proof.

## Trust / honesty note

This is a **local, untrusted** phase-2 ceremony (two hard-coded "Random entropy"
contributions + a fixed beacon, exactly as circom-rln's `build-circuits.sh` does
it). Fine for testnet. For any real deployment, run a proper multi-party phase-2
and regenerate `rln_final.zkey` + `Verifier.sol` + `verification_key.json`
together.

## Exact working rlnjs@3.3.0 API (copy verbatim)

Key facts the next agent must know:
- `RLN.create({ ... })` is **async** (returns `Promise<RLN>`).
- `verificationKey` is the **parsed JSON object**, not a path.
- `wasmFilePath` / `finalZkeyPath` are string paths (or `Uint8Array`).
- `register(limit, counter)` and `createProof`/`verifyProof`/`saveProof` are all async; `epoch` and `userMessageLimit` are **bigint**.
- `RLN.create` builds its own `Identity` unless you pass `identity:`.
- **Gotcha:** `createProof` auto-saves to the caller's *own* cache and **throws**
  (`'Proof will spam'`) if a reuse would breach. So a single instance cannot
  observe its own breach — a separate receiver must collect proofs via
  `saveProof`, and the second spammer must be a *distinct instance sharing the
  same identity* with a reset `MemoryMessageIDCounter`.
- `Status` enum: `VALID=0, DUPLICATE=1, BREACH=2`. `EvaluatedProof` = `{ status, nullifier?, secret?, msg? }`; `secret` (bigint) is populated only on BREACH.

```js
import { RLN, MemoryRLNRegistry, MemoryMessageIDCounter, Status,
         calculateIdentityCommitment } from "rlnjs";

const registry = new MemoryRLNRegistry(rlnIdentifier /*bigint*/, 20 /*treeDepth*/);

const rln = await RLN.create({
  rlnIdentifier, registry, treeDepth: 20,
  wasmFilePath, finalZkeyPath,          // string paths to rln.wasm / rln_final.zkey
  verificationKey,                      // parsed verification_key.json object
});

await rln.register(8n, new MemoryMessageIDCounter(8n));   // userMessageLimit = K_SLOTS

const proofA = await rln.createProof(42n, "message-A");   // epoch bigint, messageId 0 (auto-saved to rln.cache)
await receiver.verifyProof(42n, "message-A", proofA);     // => true

// BREACH: same identity, fresh counter, same epoch, reused messageId, different msg
const spam = await RLN.create({ rlnIdentifier, registry, identity: rln.identity,
                                treeDepth: 20, wasmFilePath, finalZkeyPath, verificationKey });
await spam.setMessageIDCounter(new MemoryMessageIDCounter(8n));
const proofB = await spam.createProof(42n, "message-B");  // messageId 0 again

await receiver.saveProof(proofA);        // { status: Status.VALID }
const b = await receiver.saveProof(proofB);
// b.status === Status.BREACH; b.secret === Poseidon(2)([identity.getNullifier(), identity.getTrapdoor()])
RLN.cleanUp();                           // terminate snarkjs worker threads
```

## Dependency notes (repo tree)

- `rlnjs@3.3.0` installed with the **default** npm resolver — **no `--legacy-peer-deps` needed**.
  It nests its own `@semaphore-protocol/identity`/`group` **v3.15.2** and
  `ffjavascript@0.2.55`; the app's top-level `@semaphore-protocol/*` **v4.14.2**
  deps are untouched and still resolve. `npm ls ffjavascript` shows
  `rlnjs → ffjavascript@0.2.55` as required.

## Circuit freeze (ShadeNet launch, 2026-09-28)

The launch circuit set is frozen at **{`rln` = RLN(20,16), `withdraw`}** from
`Rate-Limiting-Nullifier/circom-rln` at `17f0fed7d8d19e8b127fd0b3e5295a4831193a0d`. The M1 contract
fixes (proven tier, canonical leaves, bound proof contexts) needed no circuit change: the tier is
derived on chain and the proof context is an opaque public input. No circuit, circuit parameter
or public-signal order changes before the trusted-setup adoption (H3).

- Adoption path (D3): PSE's finalized ceremony over this exact source, compiled with circom 2.1.5
  `--O2`; the WASM and zkeys are swapped together (`docs/ceremony/PSE-ADOPTION.md`).
- Fallback path: a community phase 2 over the current circom 2.2.2 `--O1` build, whose R1CS/WASM
  hashes are pinned in `scripts/ceremony/toolchain.json` and were reproduced on 2026-09-28.

A change to either circuit after this point voids both paths and needs a new setup.

