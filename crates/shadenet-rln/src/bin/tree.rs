//! `shadenet-rln-tree` — native Rust merkle root/path emitter (T-RUST-2c).
//!
//! Computes the depth-20 Poseidon (BN254) membership root + path in Rust, matching
//! the rlnjs Semaphore-v3 group (`lib/rln.mjs` `newGroup`). Lets the interop harness
//! feed a RUST-computed root + path into the prover instead of the JS fixture's.
//!
//! Usage:
//!   shadenet-rln-tree root  [--id ID] <leaf...>
//!       -> prints the tree root (decimal) for the ordered member list.
//!   shadenet-rln-tree proof [--id ID] <index> <leaf...>
//!       -> prints JSON { root, pathElements[20], identityPathIndex[20] } for the
//!          member at <index> (drop-in for a fixture's root/pathElements/identityPathIndex).
//!
//! `--id` is the group id / RLN identifier (default 1, matching SHADE_TREE_RLN_IDENTIFIER=1).

use num_bigint::BigUint;
use shadenet_rln::tree::{dec_to_fr, fr_to_dec, MerkleTree, TREE_DEPTH};

fn parse_id(args: &mut Vec<String>) -> BigUint {
    if let Some(pos) = args.iter().position(|a| a == "--id") {
        let val = args
            .get(pos + 1)
            .expect("--id needs a value")
            .parse::<BigUint>()
            .expect("--id must be a decimal integer");
        args.drain(pos..pos + 2);
        val
    } else {
        BigUint::from(1u8)
    }
}

fn main() {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: shadenet-rln-tree <root|proof> [--id ID] ...");
        std::process::exit(2);
    }
    let mode = args.remove(0);
    let id = parse_id(&mut args);

    match mode.as_str() {
        "root" => {
            if args.is_empty() {
                eprintln!("usage: shadenet-rln-tree root [--id ID] <leaf...>");
                std::process::exit(2);
            }
            let leaves: Vec<_> = args.iter().map(|s| dec_to_fr(s)).collect();
            let tree = MerkleTree::new(&id, TREE_DEPTH, &leaves);
            println!("{}", fr_to_dec(&tree.root()));
        }
        "proof" => {
            if args.len() < 2 {
                eprintln!("usage: shadenet-rln-tree proof [--id ID] <index> <leaf...>");
                std::process::exit(2);
            }
            let index: usize = args.remove(0).parse().expect("index must be an integer");
            let leaves: Vec<_> = args.iter().map(|s| dec_to_fr(s)).collect();
            let tree = MerkleTree::new(&id, TREE_DEPTH, &leaves);
            let (siblings, path_indices) = tree.create_proof(index);
            let path_elements: Vec<String> = siblings.iter().map(fr_to_dec).collect();
            let identity_path_index: Vec<u8> = path_indices;
            let out = serde_json::json!({
                "root": fr_to_dec(&tree.root()),
                "pathElements": path_elements,
                "identityPathIndex": identity_path_index,
            });
            println!("{}", serde_json::to_string(&out).unwrap());
        }
        other => {
            eprintln!("unknown mode '{other}' (expected root|proof)");
            std::process::exit(2);
        }
    }
}
