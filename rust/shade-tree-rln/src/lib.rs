//! `shade-tree-rln` library surface (T-RUST-2c).
//!
//! Exposes the native depth-20 Poseidon (BN254) incremental Merkle tree that
//! matches the rlnjs Semaphore-v3 group (`@semaphore-protocol/group@3.15.2` ->
//! `@zk-kit/incremental-merkle-tree@1.1.0`), so the Rust client can compute its
//! OWN membership root + path instead of taking them from a JS fixture. See
//! `tree` for the exact convention (hash, arity, depth, zero value, order).

pub mod artifacts;
pub mod identity;
pub mod prover;
pub mod tree;
pub mod withdraw;
