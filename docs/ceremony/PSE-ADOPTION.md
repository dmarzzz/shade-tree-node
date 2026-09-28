# Adopting PSE's RLN ceremony (decision D3)

Status: test passed 2026-09-28 · adoption not yet applied · decision owner: Dan (H3)

Launch decision D3 was: adopt PSE's finalized RLN trusted setup if an interop swap passes, and
run our own phase 2 only where it does not. The swap passes for **both** circuits, the RLN
circuit and the withdraw circuit, so the fallback ceremony event is not needed for either.

## What PSE ran

PSE's [RLN Trusted Setup Ceremony](https://ceremony.pse.dev/projects/RLN%20Trusted%20Setup%20Ceremony)
(p0tion) over `Rate-Limiting-Nullifier/circom-rln` at commit `17f0fed`, the same source this
repo builds. It covers `rln-20` (RLN(20,16)) with 60 contributions and `rln-withdraw` with 62,
each closed by a beacon. The artifacts are public in
`rln-trusted-setup-ceremony-pse-p0tion-production` (S3, eu-central-1).

## What was checked, and how to re-run it

`scripts/ceremony/pse-check.mjs` reproduces every step below from public inputs:

```sh
npm ci --prefix scripts/ceremony --ignore-scripts
git clone https://github.com/iden3/circom && (cd circom && git checkout v2.1.5 && cargo build --release)
git clone https://github.com/Rate-Limiting-Nullifier/circom-rln && (cd circom-rln && git checkout 17f0fed && npm ci --omit=dev)
node scripts/ceremony/pse-check.mjs --work /tmp/pse --circom circom/target/release/circom --circom-rln circom-rln
```

| Check | RLN (`rln-20`) | Withdraw (`rln-withdraw`) |
|---|---|---|
| PSE initial and final zkeys match pinned SHA-256 | pass | pass |
| Initial zkey key material byte-identical to a local build (circom v2.1.5 `--O2`, Hermez `powersOfTau28_hez_final_13`) | pass, sections 1–9 | pass, sections 1–9 |
| Contribution chain verifies from the initial zkey (`snarkjs zkey verifyFromInit`) | 60 + beacon | 62 + beacon |
| JS prover (`lib/rln.mjs` via `SHADE_TREE_ZK_PROVER_ARTIFACTS`) proves, gateway `verifyEnvelope` accepts | pass | n/a |
| Rust prover (`shadenet-rln-probe`) proves at tier 8 and tier 32 slot 20, JS gateway accepts | pass | n/a |
| Cross-implementation over-spend reconstructs the identity secret | pass | n/a |
| Local WASM witness proves under PSE's final zkey and verifies under its key | pass | pass |
| Negative control: an envelope under PSE's id is refused by a gateway holding only the dev key | refused (`artifact-unknown`) | n/a |

Findings worth knowing:

- **Why earlier attempts said "not byte-identical".** The repo's circuits are compiled with
  circom 2.2.2 at `--O1` (12,390 RLN constraints). PSE compiled with circom 2.1.5 at `--O2`
  (5,820). The circuits are the same source; only the compiler optimisation differs. Adoption
  therefore replaces **the WASM and the zkey together**; a PSE zkey never runs with our WASM.
- **`snarkjs zkey verify` against the R1CS reports "Circuit does not match".** That check
  compares section 10's `csHash`, which snarkjs computes differently across versions. Every key
  section (1–9) is byte-identical to our reproduction, and the chain verifies from PSE's own
  initial zkey, so this is bookkeeping, not a key mismatch.
- **Phase 1 is Hermez power 13** for both circuits (the `alpha1`/`beta` elements match it; PSE's
  own perpetual powers of tau `ppot_0080` does not).
- **Beacon.** The chains end in a beacon with generator `003089a0…0203`, 2^10 iterations. PSE's
  site lists the finalization beacon value `0xa894a3f9…bb9d`. Relating the two (the generator is
  derived from the published value) is a remaining independent-verifier step.

## Pinned inputs

| File | SHA-256 |
|---|---|
| `rln-20_00000.zkey` | `3b5499f002173787a6d931e0cb8a4a09091c66cb47d4324150154e6fabd66ee2` |
| `rln-20_final.zkey` | `ae30d3d4b29d9dab8c65ff181644a3eb57c2c0fa9f687ea3baf8c7f711d7946a` |
| `rln-withdraw_00000.zkey` | `def04ae8e7ed939105e4dce98e0bcf2b946060e2ecdd45694e9500448b6db158` |
| `rln-withdraw_final.zkey` | `c8c778bc0123b43071ae2d218d88f343d7be05d6b1a843c695289c6c3d7cf8e5` |
| `powersOfTau28_hez_final_13.ptau` | `95751b5207f20aa822f01109902315c01c15250303feacea2b8aa7dc9fdfeefd` |
| local `rln.wasm` (circom 2.1.5 `--O2`) | `fa9586db68a9566fd9b3af6e8d7c66f5567b35647aa63a426f220375e9fa8c04` |
| local `withdraw.wasm` (circom 2.1.5 `--O2`) | `239bd578deea5eebf3cde5a9aeba22ba799d23d0aff6b9a8b153afd8d2cc191e` |

## What H3 becomes

Instead of recruiting contributors and running an event, H3 is:

1. Dan confirms adopting PSE's setup for both circuits.
2. One independent verifier (outside the core team) reruns `pse-check.mjs` and relates the
   beacon generator to PSE's published beacon value, then publishes a signed statement.
3. The adoption PR: replace `circuits/rln/{rln.wasm, rln_final.zkey, verification_key.json,
   withdraw.wasm, withdraw_final.zkey, withdraw_verification_key.json}`, regenerate
   `contracts/RlnGroth16Verifier.sol` and `contracts/WithdrawGroth16Verifier.sol`, the withdraw
   fixture, the pinned bytecode manifest and `testdata/zk-artifacts.lock.json` (`trust`,
   `ceremony.status: "complete"`, one `ceremony` entry per circuit naming PSE's ceremony,
   contribution counts, the beacon and the pinned hashes above), `circuits/rln/ARTIFACTS.md`,
   and the Rust embedded artifacts. Run the JS and Rust interop and `forge test`.
4. M8's production deploy then runs `scripts/deploy-contracts.mjs --network sepolia`, which
   refuses to broadcast until the lock records a completed ceremony.

The community ceremony kit (`scripts/ceremony/`, `EVENT.md`) stays as the fallback if Dan
prefers a ShadeNet-specific setup or a later circuit change needs one.
