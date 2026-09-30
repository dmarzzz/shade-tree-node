# RLN circuit artifacts (ceremony set, adopted from PSE)

Groth16 artifacts for `Rate-Limiting-Nullifier/circom-rln` at commit
`17f0fed7d8d19e8b127fd0b3e5295a4831193a0d`, taken **verbatim from PSE's RLN Trusted Setup
Ceremony** (p0tion, July–September 2023) under launch decision D3, plus the verification keys,
Solidity verifiers and the withdraw fixture derived from them. Adopted 2026-09-30; see
[docs/ceremony/PSE-ADOPTION.md](../../docs/ceremony/PSE-ADOPTION.md) for the decision and
[docs/ceremony/PSE-VERIFICATION.md](../../docs/ceremony/PSE-VERIFICATION.md) for the
verification run, and the `ceremony` block of
[testdata/zk-artifacts.lock.json](../../testdata/zk-artifacts.lock.json) for every pin.

## GATE: PASSED

`node circuits/rln/smoke.mjs` is green on Node v24. It creates an RLN member, registers at
`userMessageLimit = 8` (app `K_SLOTS`), verifies a valid proof, detects a same-epoch messageId
reuse as a **BREACH**, and recovers the member's `identitySecret`. The JS gateway and the Rust
prover interoperate under these keys (`crates/shadenet-rln/interop/run.sh`).

## Toolchain / provenance

| Item | Value |
|---|---|
| circom | `2.1.5` (commit `127414e9088cc017a357233f30f3fd7d91a8906c`), `--O2`; rebuilt from source 2026-09-30, R1CS and WASM byte-identical to PSE's published files |
| circom-rln | commit `17f0fed7d8d19e8b127fd0b3e5295a4831193a0d` (tag `v1.0.0`) |
| snarkjs (ceremony) | `0.5.0` (p0tion, commit `6660254b`) for contributions and finalization; `0.7.5` here for the exports and the independent `verifyFromInit` |
| Powers of Tau | `powersOfTau28_hez_final_13.ptau` (2^13), sha256 `95751b5207f20aa822f01109902315c01c15250303feacea2b8aa7dc9fdfeefd` |
| Groth16 phase-2 | PSE ceremony: `rln-20` 60 contributions + beacon, `rln-withdraw` 62 contributions + beacon; beacon `sha256(0xa894a3f9…bb9d)`, 2^10 iterations |

### Why ptau_13 and circom 2.1.5

PSE compiled the circuits with circom 2.1.5 at `--O2`: `RLN(20,16)` is **5,820 constraints**
(5,844 wires) and `Withdraw` is 214, so the RLN key fits the power-13 Hermez file. The repo
previously compiled the same source with circom 2.2.2 at `--O1` (12,390 / 416 constraints). The
statements are the same; only the optimisation differs. A zkey only works with the WASM it was
set up for, so the WASM and the zkey were swapped together. PSE set up `rln-withdraw` from the
power-8 prefix of the same transcript; a power-13 rebuild is byte-identical in every key section.

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
`Poseidon(1)([secret])` reproduces the leaf's inner commitment.

## Artifacts (this directory) + sha256

| File | sha256 |
|---|---|
| `rln.wasm` | `fa9586db68a9566fd9b3af6e8d7c66f5567b35647aa63a426f220375e9fa8c04` |
| `rln_final.zkey` | `ae30d3d4b29d9dab8c65ff181644a3eb57c2c0fa9f687ea3baf8c7f711d7946a` |
| `verification_key.json` | `ae43614cd02ebe951f44465924eff9882d1321b20f0cc129406bc5fa2547fe11` |
| `withdraw.wasm` | `239bd578deea5eebf3cde5a9aeba22ba799d23d0aff6b9a8b153afd8d2cc191e` |
| `withdraw_final.zkey` | `c8c778bc0123b43071ae2d218d88f343d7be05d6b1a843c695289c6c3d7cf8e5` |
| `withdraw_verification_key.json` | `4e7e70a99310989afa2df1848f996944cf3ee1496e45fc1d8d9e3c3b7efdb101` |
| `Verifier.sol` | `383dd8bb22cd2f1e02cb8c9d7df631fe05bf2e26d39106467db96aee25a6659f` |

`rln.wasm` is PSE's `RLN-20.wasm`, `rln_final.zkey` is `rln-20_final.zkey`, `withdraw.wasm` is
`RLN-Withdraw.wasm` and `withdraw_final.zkey` is `rln-withdraw_final.zkey`, byte for byte. The
two verification keys parse equal to PSE's published `*_vkey.json`.

### Artifact ids (T-HARD-8 artifact-version negotiation)

Each circuit's artifact SET is named on the wire by a content-derived id,
`<circuit>-<sha256(verification_key.json)[0:16]>` — the vkey row above, first 16 hex chars
(`packages/node/lib/zk-artifacts.mjs` `artifactIdOf`; `testdata/zk-artifacts.lock.json` `circuits.<c>.artifactId`;
Rust `shadenet_proto::artifact_id_of`). Envelopes carry the rln id in `artifact`; gateways accept a set
of ids (`SHADE_TREE_ZK_ARTIFACTS`) so a ceremony swap runs as a dual-VK window (`docs/CEREMONY.md` §6).

| Circuit | Artifact id | Previous id |
|---|---|---|
| `rln` | `rln-ae43614cd02ebe95` | `rln-0b25f824a04da3a8` (the dev set; retire it after the fleet rolls) |
| `withdraw` | `withdraw-4e7e70a99310989a` | `withdraw-dd6bfa937405972f` (the dev set) |

`Verifier.sol` is `contract Groth16Verifier`, `pragma solidity >=0.7.0 <0.9.0`,
`verifyProof(uint[2] _pA, uint[2][2] _pB, uint[2] _pC, uint[5] _pubSignals)`.
Its embedded VK is derived from **this exact** `rln_final.zkey`; the on-chain side
MUST adopt these artifacts as a set (swap the zkey → re-export the verifier).

> The `withdraw` circuit is `RLN slash`-side (`Poseidon(1)([identitySecret])`,
> public `address`); the `RLN` circuit above is the message/rate-limit proof.

## Trust / honesty note

These keys come from a public multi-party phase-2 ceremony run by PSE, whose contribution chains
verify from the initial zkeys and end in a published beacon. That is evidence that the toxic waste
is gone **if at least one contributor per chain was honest** and the phase-1 (Hermez) and
implementation assumptions hold. It is not an audit of the circuits, the contracts or this
software, and ShadeNet remains a research preview. The dev set that preceded it
(`rln-0b25f824a04da3a8` / `withdraw-dd6bfa937405972f`, circom 2.2.2, circom-rln's two hard-coded
contributions) must not be trusted with anything of value; it stays accepted only for the
dual-VK window described in `docs/CEREMONY.md` §6.

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

