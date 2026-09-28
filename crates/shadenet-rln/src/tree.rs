//! Native depth-20 Poseidon (BN254) incremental Merkle tree — rlnjs parity (T-RUST-2c).
//!
//! This is a byte-for-byte port of the tree the JS reference proves against. The
//! chain, verified by READING the pinned deps (not guessed), is:
//!
//!   `lib/rln.mjs` `newGroup` -> `rlnjs`'s nested **Semaphore v3**
//!   `@semaphore-protocol/group@3.15.2` -> `@zk-kit/incremental-merkle-tree@1.1.0`.
//!
//! The exact convention this module matches:
//!   - **Hash:** `poseidon2` (BN254, arity 2) as shipped by `poseidon-lite` /
//!     circomlib. Nodes are `poseidon2([left, right])`. Reproduced here with
//!     `light-poseidon`'s circom-compatible parameters.
//!   - **Arity:** 2 (binary tree).
//!   - **Depth:** 20 (circom-rln `RLN(20,16)`), fixed depth (NOT a LeanIMT — the
//!     app's top-level Semaphore **v4** LeanIMT does NOT match; that is exactly
//!     why `lib/rln.mjs` reaches into rlnjs's nested v3 group).
//!   - **Zero value:** `zeroes[0] = hash(id)` where `id` is the group id
//!     (`RLN_IDENTIFIER`, `1` here) and `hash(m) = keccak256(be32(m)) >> 8`
//!     (the Semaphore group's keccak-into-field hash — NOT `0`, NOT Poseidon).
//!     Higher zeroes: `zeroes[l+1] = poseidon2([zeroes[l], zeroes[l]])`.
//!   - **Insertion order:** members appended left-to-right at increasing leaf
//!     index; internal nodes fill missing right-children with `zeroes[level]`.
//!
//! Membership proof (`create_proof`) returns `(siblings, path_indices)` in the
//! same shape the circom witness consumes (`pathElements[20]`,
//! `identityPathIndex[20]`), matching `Group.generateMerkleProof` (which flattens
//! each arity-2 sibling list to its single element).

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::BigUint;
use sha3::{Digest, Keccak256};

/// circom-rln tree depth (`RLN(20,16)`).
pub const TREE_DEPTH: usize = 20;

/// `poseidon2([a, b])` over BN254 — circomlib / poseidon-lite compatible.
pub fn poseidon2(a: Fr, b: Fr) -> Fr {
    // `new_circom(2)` selects circomlib's t=3 (2-input) round constants + MDS,
    // the exact parameter set poseidon-lite ships, so digests match byte-for-byte.
    let mut hasher = Poseidon::<Fr>::new_circom(2).expect("poseidon2 circom params");
    hasher.hash(&[a, b]).expect("poseidon2 hash")
}

/// `poseidon1([a])` over BN254 — circomlib / poseidon-lite compatible (t=2 params).
pub fn poseidon1(a: Fr) -> Fr {
    let mut hasher = Poseidon::<Fr>::new_circom(1).expect("poseidon1 circom params");
    hasher.hash(&[a]).expect("poseidon1 hash")
}

/// The RLN `rateCommitment` leaf for an `identitySecret` at a tier `limit`
/// (`userMessageLimit`, T-FEAT-8): `Poseidon2(Poseidon1(identitySecret), limit)` — the exact
/// leaf `lib/rln.mjs deriveCommitment(identitySecret, limit)` publishes and the circuit opens.
/// The limit is PART of the leaf, so a member's tier is what its leaf commits to.
pub fn rate_commitment(identity_secret: Fr, limit: u64) -> Fr {
    poseidon2(poseidon1(identity_secret), Fr::from(limit))
}

/// The Semaphore group hash used for the tree's zero value:
/// `hash(m) = keccak256( be32(m mod 2^256) ) >> 8`.
///
/// `be32` is the 32-byte big-endian encoding (`@ethersproject` `zeroPad(..., 32)`
/// of `BigNumber(m).toTwos(256)`), matching the group's `hash(id)` exactly.
pub fn keccak_hash_to_field(m: &BigUint) -> Fr {
    let modulus = BigUint::from(1u8) << 256u32;
    let reduced = m % &modulus;
    let be = reduced.to_bytes_be();
    let mut buf = [0u8; 32];
    buf[32 - be.len()..].copy_from_slice(&be); // left-pad to 32 bytes big-endian
    let digest = Keccak256::digest(buf); // 32-byte keccak256
    let shifted = BigUint::from_bytes_be(&digest) >> 8u32; // >> 8, always < field
    Fr::from(shifted)
}

/// `externalNullifier = poseidon2(epoch, rlnIdentifier)` — the per-EPOCH binding the
/// gateway checks cheap (`lib/rln.mjs` `externalNullifierFor` /
/// rlnjs `calculateExternalNullifier`). `epoch` is `< field` for any realistic value,
/// so it maps straight to `Fr`; `rln_identifier` is the group id.
pub fn external_nullifier(epoch: u64, rln_identifier: &BigUint) -> Fr {
    poseidon2(Fr::from(epoch), Fr::from(rln_identifier.clone()))
}

/// Render a field element as its canonical base-10 string (big-endian), matching
/// how the JS side stringifies `group.root` / sibling elements.
pub fn fr_to_dec(f: &Fr) -> String {
    let bytes = f.into_bigint().to_bytes_be();
    BigUint::from_bytes_be(&bytes).to_str_radix(10)
}

/// Parse a decimal (or `0x`-prefixed) big-integer string into `Fr` (mod field).
pub fn dec_to_fr(s: &str) -> Fr {
    let s = s.trim();
    let big = if let Some(hex) = s.strip_prefix("0x") {
        BigUint::parse_bytes(hex.as_bytes(), 16).expect("hex field element")
    } else {
        BigUint::parse_bytes(s.as_bytes(), 10).expect("decimal field element")
    };
    Fr::from(big)
}

/// A fixed-depth, arity-2 incremental Merkle tree matching
/// `@zk-kit/incremental-merkle-tree` (Semaphore v3).
pub struct MerkleTree {
    depth: usize,
    zeroes: Vec<Fr>, // len == depth; zeroes[l] is the empty-subtree root at level l
    nodes: Vec<Vec<Fr>>, // len == depth + 1; nodes[0] == leaves, nodes[depth] == [root]
}

impl MerkleTree {
    /// Build the tree from a group `id` (its keccak-hash seeds the zeroes), the
    /// tree `depth`, and the ordered `leaves` (rate commitments). Mirrors the
    /// `IncrementalMerkleTree` constructor's leaf-based build precisely.
    pub fn new(id: &BigUint, depth: usize, leaves: &[Fr]) -> Self {
        assert!(depth >= 1, "tree depth must be >= 1");

        // zeroes[0] = hash(id); zeroes[l+1] = poseidon2(zeroes[l], zeroes[l]).
        let mut zeroes = Vec::with_capacity(depth);
        let mut z = keccak_hash_to_field(id);
        for _ in 0..depth {
            zeroes.push(z);
            z = poseidon2(z, z);
        }
        // After the loop, `z` == the level-`depth` zero (the empty-tree root).
        let empty_root = z;

        let mut nodes: Vec<Vec<Fr>> = vec![Vec::new(); depth + 1];
        nodes[0] = leaves.to_vec();

        if leaves.is_empty() {
            // Match JS: an empty tree's root is the final zero value.
            nodes[depth].push(empty_root);
            return MerkleTree {
                depth,
                zeroes,
                nodes,
            };
        }

        for level in 0..depth {
            let len = nodes[level].len();
            let count = len.div_ceil(2); // ceil(len / arity), arity == 2
            for index in 0..count {
                let left = nodes[level]
                    .get(2 * index)
                    .copied()
                    .unwrap_or(zeroes[level]);
                let right = nodes[level]
                    .get(2 * index + 1)
                    .copied()
                    .unwrap_or(zeroes[level]);
                let parent = poseidon2(left, right);
                nodes[level + 1].push(parent);
            }
        }

        MerkleTree {
            depth,
            zeroes,
            nodes,
        }
    }

    /// The tree depth.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// The zeroes chain (`zeroes[l]` = empty-subtree root at level `l`).
    pub fn zeroes(&self) -> &[Fr] {
        &self.zeroes
    }

    /// The Merkle root (`nodes[depth][0]`).
    pub fn root(&self) -> Fr {
        self.nodes[self.depth][0]
    }

    /// The leaf index of `leaf`, or `None` if absent (mirrors `Group.indexOf`).
    pub fn index_of(&self, leaf: &Fr) -> Option<usize> {
        self.nodes[0].iter().position(|l| l == leaf)
    }

    /// The leaf value at `index` (mirrors `Group.members[index]`). After a
    /// [`remove`](Self::remove) the vacated slot reads back as the tree zero
    /// value (`zeroes[0]`).
    pub fn leaf(&self, index: usize) -> Fr {
        self.nodes[0][index]
    }

    /// The tree zero value (`zeroes[0]` = `hash(id)`), i.e. the value a removed
    /// leaf takes. Exposed so callers can assert the zero-in-place convention.
    pub fn zero_value(&self) -> Fr {
        self.zeroes[0]
    }

    /// Remove the leaf at its ORIGINAL `index` using the ZERO-IN-PLACE convention
    /// — the on-chain contract's immutable append-only indices and the loop-26 JS
    /// `reconstructRoot` (`lib/root-provider.mjs`) both use it, and this matches
    /// `@zk-kit/incremental-merkle-tree`'s `delete(index)` (which is
    /// `update(index, zeroes[0])`) as reached through Semaphore-v3 `Group.delete`.
    ///
    /// The leaf becomes the tree zero value (`zeroes[0]` — the keccak-seeded
    /// `hash(id)`, NOT `0` and NOT a Poseidon zero), every other leaf keeps its
    /// index and Merkle path, and the root is recomputed over the zeroed leaf.
    /// The leaf count is unchanged, so higher-level node lengths are unchanged;
    /// the tree never collapses to the empty-tree special case (a fully-emptied
    /// tree still has `len` zero-valued leaves, matching the JS group).
    pub fn remove(&mut self, index: usize) {
        assert!(
            index < self.nodes[0].len(),
            "leaf index {index} out of range"
        );
        // Zero-in-place: set the leaf to the tree's zero value, then recompute.
        self.nodes[0][index] = self.zeroes[0];
        self.recompute();
    }

    /// Recompute `nodes[1..=depth]` from the current `nodes[0]`, filling missing
    /// right-children with `zeroes[level]` — the identical fold `new` performs, so
    /// a zero-in-place `remove` yields exactly the root a fresh build over the same
    /// (post-removal) leaf array would.
    fn recompute(&mut self) {
        for level in 0..self.depth {
            let len = self.nodes[level].len();
            let count = len.div_ceil(2); // ceil(len / arity), arity == 2
            let mut parents = Vec::with_capacity(count);
            for index in 0..count {
                let left = self.nodes[level]
                    .get(2 * index)
                    .copied()
                    .unwrap_or(self.zeroes[level]);
                let right = self.nodes[level]
                    .get(2 * index + 1)
                    .copied()
                    .unwrap_or(self.zeroes[level]);
                parents.push(poseidon2(left, right));
            }
            self.nodes[level + 1] = parents;
        }
    }

    /// A membership proof for the leaf at `index`: `(siblings, path_indices)`,
    /// each of length `depth`. `siblings[l]` is the sibling node at level `l`
    /// (an actual node, or `zeroes[l]` for an empty subtree); `path_indices[l]`
    /// is the proof leaf's position (`0` = left, `1` = right) at level `l`.
    /// Matches `IncrementalMerkleTree.createProof` for arity 2 (one sibling per
    /// level, as flattened by `Group.generateMerkleProof`).
    pub fn create_proof(&self, index: usize) -> (Vec<Fr>, Vec<u8>) {
        assert!(
            index < self.nodes[0].len(),
            "leaf index {index} out of range"
        );
        let mut siblings = Vec::with_capacity(self.depth);
        let mut path_indices = Vec::with_capacity(self.depth);
        let mut idx = index;
        for level in 0..self.depth {
            let position = idx % 2;
            path_indices.push(position as u8);
            // The sibling is the other member of the arity-2 pair.
            let sib_i = if position == 0 { idx + 1 } else { idx - 1 };
            let sib = self
                .nodes
                .get(level)
                .and_then(|row| row.get(sib_i))
                .copied()
                .unwrap_or(self.zeroes[level]);
            siblings.push(sib);
            idx /= 2;
        }
        (siblings, path_indices)
    }
}
