# `shadenet-rln`

Rust RLN proving, verification, and Merkle-tree parity for Shade Tree.

This crate consumes the repository's Circom artifacts directly and produces
proofs that the JavaScript reference accepts. It is excluded from the Rust
workspace's `default-members` because its `ark-circom` and Wasmer dependency
tree is heavy. It is included when the distributable client is built with the
`live` feature:

```sh
cargo build -p shadenet-cli --features live
```

That live client combines this crate's prover and native tree with embedded
Arti Tor transport. The default client build keeps only deterministic
directory, selection, and receipt functions.

## Interoperability guarantees

The test harnesses establish that:

- Rust and JavaScript derive the same v4 request signal.
- Public signals use the same `[y, root, nullifier, x, externalNullifier]`
  order and values.
- Rust proofs verify with the checked-in `verification_key.json` and are
  accepted by `packages/node/lib/rln.mjs:verifyEnvelope`.
- Two Rust shares for one reused slot reconstruct the same `identitySecret`
  in JavaScript.
- The native depth-20 Poseidon tree produces the same roots and paths as the
  nested Semaphore-v3 group used by `rlnjs`.

Run the complete cross-language suite from the repository root:

```sh
bash crates/shadenet-rln/interop/run.sh
bash crates/shadenet-rln/interop/tree-run.sh
```

The harness requires the root npm dependencies and a Rust toolchain.

## Why `ark-circom`

The upstream Zerokit `rln` crate consumes its own `arkzkey` resources and does
not read this repository's snarkjs `.zkey` directly. `ark-circom` reads the
checked-in `rln_final.zkey` and `rln.wasm`, calculates the matching witness,
and lets `ark-groth16` emit a proof in the shape expected by the JavaScript
verifier. This avoids mixing a proving key and witness graph from different
artifact sets.

## Layout

- `src/lib.rs` — public crate surface.
- `src/prover.rs` — witness calculation and Groth16 proving.
- `src/tree.rs` — native depth-20 Poseidon membership tree.
- `src/artifacts.rs` — embedded artifact lock and identifiers.
- `src/main.rs` — interoperability probe.
- `src/bin/tree.rs` — root/path helper used by the harness.
- `interop/` — JavaScript/Rust fixtures and end-to-end checks.

## Artifact warning

The bundled artifacts came from an untrusted testnet ceremony. Embedding and
hash-locking them prevents accidental drift; it does not establish production
provenance. Review [`../../circuits/rln/ARTIFACTS.md`](../../circuits/rln/ARTIFACTS.md)
and [`../../SECURITY.md`](../../SECURITY.md) before operating the live client.
