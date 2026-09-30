# Reproduce the circuit inputs

> **Scope note (2026-09-30).** These are the build pins of the *fallback* kit: circom 2.2.2 `--O1`
> and `powersOfTau28_hez_final_14.ptau`. The keys the repo ships were adopted from PSE's ceremony
> and were built with circom 2.1.5 `--O2` and `powersOfTau28_hez_final_13.ptau`; their rebuild is
> reproduced by `scripts/ceremony/pse-check.mjs` and recorded in `PSE-VERIFICATION.md`. The hash
> table below no longer matches `circuits/rln/*.wasm`.

This builds the public inputs for a community phase-2 ceremony over the **existing**
Shade Tree RLN and withdrawal circuits. It does not generate a circuit-specific
proving key, contribute entropy, apply a beacon, publish artifacts, or activate a
new verifier. The community ceremony and its independent verification come later.

The implementation is [`build-inputs.mjs`](../../scripts/ceremony/build-inputs.mjs).
All identity-defining pins are in
[`toolchain.json`](../../scripts/ceremony/toolchain.json). Output belongs in a
dedicated directory outside the project; active files under `circuits/rln/` and
the artifact lock remain unchanged.

## Prerequisites and command

Use Git, Node 22 or later, npm, and rustup. The build tested here used Node
24.6.0, npm 11.5.1, Rust/Cargo 1.98.0, and macOS arm64. Rust is pinned by the
builder; install that toolchain if it is not already present:

```sh
rustup toolchain install 1.98.0 --profile minimal
npm ci --prefix scripts/ceremony --ignore-scripts
node scripts/ceremony/build-inputs.mjs --out /tmp/shade-tree-ceremony-inputs
```

The last command fetches the pinned source commits, checks both dependency-lock
hashes, installs only the circuit's locked production dependency without lifecycle
scripts, builds Circom, and compiles both circuits. It checks the exact R1CS and
WASM hashes, checks the WASM hashes against the unchanged repository copies, runs
`snarkjs r1cs info`, obtains the pinned public phase-1 file, checks its SHA-256 and
BLAKE2b-512, and runs `snarkjs powersoftau verify`. Only after every check succeeds
does it write `build-inputs.json`.

With an existing public phase-1 file, use:

```sh
node scripts/ceremony/build-inputs.mjs \
  --out /tmp/shade-tree-ceremony-inputs \
  --ptau-file /absolute/path/powersOfTau28_hez_final_14.ptau
```

The supplied file must match the same hashes and size. There is no option to skip
these checks or substitute a freshly generated phase-1 transcript. The directory
can be reused after a successful or failed build if it has the builder's ownership
marker. An arbitrary nonempty folder is refused. Concurrent builds in one output
directory are refused; if a process was killed, first establish that it has stopped
before removing the stale `.build-inputs.lock`. A fresh output directory avoids
both stale state and accidental reuse.

Network downloads and compiler/package caches are public build material. Neither
the builder nor these logs require private member keys, contributor entropy,
operator wallets, RPC credentials, or production environment files.

## Exact source and dependencies

| Component | Pin |
| --- | --- |
| Circom | `iden3/circom`, commit `e410b0d5cd2948a15931df0bc50d79ce56fa8c32`, tag `v2.2.2` |
| Compiler command | `cargo +1.98.0 build --release --locked` (builder uses equivalent `rustup run 1.98.0 cargo …`) |
| Circom Cargo.lock SHA-256 | `5f54c3cce2a5f6dbddc525515b08889deea2ebb03d6a176e34c27532291c6a2e` |
| Circuit source | `Rate-Limiting-Nullifier/circom-rln`, commit `17f0fed7d8d19e8b127fd0b3e5295a4831193a0d`, tag `v1.0.0` |
| Circuit package-lock.json SHA-256 | `830729d4905bc5c6882a43b6dc0c0d95b8e85ac787e76ebdd7f0d4ffd494707f` |
| Circuit library | `circomlib@2.0.5`, installed by the upstream lockfile with `npm ci --omit=dev --ignore-scripts --no-audit --no-fund` |
| Ceremony inspection/runtime | `snarkjs@0.7.5`, exact version in `scripts/ceremony/package-lock.json` |
| Field | BN254 scalar field (`--prime bn128`) |
| Optimization | `--O1` |
| Outputs | `--r1cs --wasm --sym` |

The circuit source's historical developer lock contains `snarkjs@0.7.0`. It is
not installed or used by this builder: only `circomlib` is required to compile.
Inspection and phase-1 verification use the separately pinned ceremony tool
runtime. The root project's mutable dependency resolver is not used to select a
Circom library or snarkjs version.

The explicit compilation commands, relative to the pinned circuit checkout, are:

```sh
circom circuits/rln.circom --r1cs --wasm --sym --O1 --prime bn128 -o /absolute/build/rln
circom circuits/withdraw.circom --r1cs --wasm --sym --O1 --prime bn128 -o /absolute/build/withdraw
```

The historical upstream build script is **not** a compilation-only script: it also
runs setup, hard-coded contributions, and a fixed beacon. Do not run it for this
preparation. The builder invokes the compiler directly and never invokes an
upstream package script.

## Reproduced artifacts

The following outputs were reconstructed on 2026-09-08 from the pins above. Both
WASM files match the checked-in files byte for byte. R1CS hashes now pin the actual
constraint systems as well; a matching witness calculator alone is insufficient
to establish which constraints a ceremony uses.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `build/rln/rln.r1cs` | 1,655,120 | `452cd7f8830ef82244c481639bc44b354d9e72ec2504694ce4814b961a2f22a2` |
| `build/rln/rln_js/rln.wasm` | 2,448,462 | `d06035923ab4c7fefedf92e05c9903d059af583b8a92a95ce72466a389ac6ab0` |
| `build/withdraw/withdraw.r1cs` | 53,348 | `52dd6134d2223e585b4782f2f033fc882eb7fac567570bffdb9a763f3be88788` |
| `build/withdraw/withdraw_js/withdraw.wasm` | 1,633,988 | `d0b6425f026a75a52fd2f324fac663b6f8986b8e4439b86a9e6d73ee03eef2bb` |

| Circuit | Constraints | Nonlinear / linear | Wires | Private inputs | Public inputs / outputs | Public-signal order |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `RLN(20,16)` | 12,390 | 5,893 / 6,497 | 12,413 | 43 | 2 / 3 | `y, root, nullifier, x, externalNullifier` |
| `Withdraw` | 416 | 217 / 199 | 419 | 1 | 1 / 1 | `identityCommitment, address` |

These numbers were checked using the pinned compiler and `snarkjs r1cs info`.
They identify the current circuits; this preparation does not change their
statements or fix application-level issuance/accounting concerns. The existing
public/development setup is still active until a separate, reviewed activation.

Compiler executable hashes are recorded in each build manifest as observations.
They are platform-specific and are not claimed to be reproducible across operating
systems. The required portable equality checks are the resulting R1CS and WASM
hashes. Dependency sources, flags, tool versions, and per-command logs are retained
so another builder can reproduce and inspect the work independently.

## Reused phase 1 and mirror policy

The power-14 transcript is **18,957,464 bytes (about 18.1 MiB)**, not the roughly
300 MB associated with power 18. Its pins are:

```text
SHA-256:
489be9e5ac65d524f7b1685baac8a183c6e77924fdb73d2b8105e335f277895d

BLAKE2b-512:
eeefbcf7c3803b523c94112023c7ff89558f9b8e0cf5d6cdcba3ade60f168af4a181c9c21774b94fbae6c90411995f7d854d02ebd93fb66043dbb06f17a831c1
```

SHA-256 already appears in the repository's artifact lock. BLAKE2b-512 is the
power-14 entry in the [snarkjs 0.7.5 public transcript table](https://github.com/iden3/snarkjs/blob/v0.7.5/README.md#7-prepare-phase-2).
The builder checks both plus the byte length, regardless of which mirror supplies
the download.

On the preparation date, the historical Google zkevm and Hermez S3 URLs returned
HTTP 403. An accessible copy was obtained from the FastFourier DigitalOcean CDN
URL documented in [0xPARC/zkrepl's pinned source](https://github.com/0xPARC/zkrepl/blob/10e655a825e5d060621513e91f4b5d2884c6e790/src/worker/worker.ts#L540).
It matched both pinned hashes and passed full `snarkjs powersoftau verify`, ending
in `Powers of Tau Ok!`. This is a byte-identical mirror, not a replacement setup or
an additional trust assumption about its operator. The builder retains HTTPS
certificate validation and rejects error documents, truncated downloads, and
mismatched artifacts.

## Output record and handoff

The output tree is:

```text
build-inputs.json
src/circom/                 pinned compiler source and release build
src/circom-rln/             pinned circuits and locked circomlib
build/rln/                 R1CS, symbols, witness WASM and generated helper JS
build/withdraw/            R1CS, symbols, witness WASM and generated helper JS
ptau/powersOfTau28_hez_final_14.ptau
logs/                      commands, compiler statistics, and phase-1 verification
```

`build-inputs.json` has schema version 1 and kind `shade-tree-ceremony-inputs`.
It records absolute file paths, hashes and sizes under `circuits.rln.r1cs`,
`circuits.rln.wasm`, `circuits.withdraw.r1cs`, `circuits.withdraw.wasm`, and `ptau`;
constraint/public-input counts; compiler/source pins; observed platform and tool
versions; the toolchain and ceremony-runtime lock hashes; and verification logs.
Its status is `verified-inputs-only`. No contribution or setup trust is implied.

The coordinator must rehash the actual input files against the checked-in
`toolchain.json`, rather than trusting a participant-supplied manifest's claimed
hashes. Use a frozen, reviewed copy of the toolchain pins when beginning a real
ceremony. A changed R1CS hash is a different circuit and requires a new review,
even if public signal names, constraint counts, or WASM bytes happen to match.
