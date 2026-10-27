//! An EIP-1186 Merkle-Patricia proof verifier (`packages/node/lib/root-provider.mjs`
//! `verifyMptProof`): given a trusted root, the value under a key in a secure trie, or its
//! absence, from the node list `eth_getProof` returns. A tampered or missing node no longer
//! hashes to what its parent commits to, so a lying RPC cannot pass a false value.

use std::collections::HashMap;

use sha3::{Digest as _, Keccak256};

/// A decoded RLP item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Rlp {
    Bytes(Vec<u8>),
    List(Vec<Rlp>),
}

impl Rlp {
    fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(b) => Some(b),
            Self::List(_) => None,
        }
    }
}

pub(crate) fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

fn length(input: &[u8], offset: usize, len_of_len: usize) -> Result<usize, String> {
    let bytes = input
        .get(offset..offset + len_of_len)
        .ok_or("rlp: truncated length")?;
    if bytes.first() == Some(&0) {
        return Err("rlp: leading zero in length".into());
    }
    if len_of_len > 8 {
        return Err("rlp: length too long".into());
    }
    let mut out = 0_usize;
    for b in bytes {
        out = out
            .checked_mul(256)
            .and_then(|v| v.checked_add(usize::from(*b)))
            .ok_or("rlp: length overflow")?;
    }
    Ok(out)
}

/// Decode one item and return it with how many bytes it took.
fn decode_at(input: &[u8]) -> Result<(Rlp, usize), String> {
    let first = *input.first().ok_or("rlp: empty input")?;
    match first {
        0x00..=0x7f => Ok((Rlp::Bytes(vec![first]), 1)),
        0x80..=0xb7 => {
            let len = usize::from(first - 0x80);
            let data = input.get(1..1 + len).ok_or("rlp: truncated bytes")?;
            if len == 1 && data[0] < 0x80 {
                return Err("rlp: non-canonical single byte".into());
            }
            Ok((Rlp::Bytes(data.to_vec()), 1 + len))
        }
        0xb8..=0xbf => {
            let len_of_len = usize::from(first - 0xb7);
            let len = length(input, 1, len_of_len)?;
            if len < 56 {
                return Err("rlp: non-canonical long bytes".into());
            }
            let start = 1 + len_of_len;
            let data = input
                .get(start..start + len)
                .ok_or("rlp: truncated bytes")?;
            Ok((Rlp::Bytes(data.to_vec()), start + len))
        }
        0xc0..=0xf7 => {
            let len = usize::from(first - 0xc0);
            let items = decode_list(input.get(1..1 + len).ok_or("rlp: truncated list")?)?;
            Ok((Rlp::List(items), 1 + len))
        }
        0xf8..=0xff => {
            let len_of_len = usize::from(first - 0xf7);
            let len = length(input, 1, len_of_len)?;
            if len < 56 {
                return Err("rlp: non-canonical long list".into());
            }
            let start = 1 + len_of_len;
            let items = decode_list(input.get(start..start + len).ok_or("rlp: truncated list")?)?;
            Ok((Rlp::List(items), start + len))
        }
    }
}

fn decode_list(mut input: &[u8]) -> Result<Vec<Rlp>, String> {
    let mut items = Vec::new();
    while !input.is_empty() {
        let (item, used) = decode_at(input)?;
        items.push(item);
        input = &input[used..];
    }
    Ok(items)
}

/// Decode exactly one RLP item from `input`.
pub(crate) fn decode(input: &[u8]) -> Result<Rlp, String> {
    let (item, used) = decode_at(input)?;
    if used != input.len() {
        return Err("rlp: trailing bytes".into());
    }
    Ok(item)
}

fn nibbles(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().flat_map(|b| [b >> 4, b & 0x0f]).collect()
}

/// Decode a hex-prefix (compact) encoded path into its nibbles and the leaf flag.
fn decode_compact_path(bytes: &[u8]) -> (Vec<u8>, bool) {
    let Some(first) = bytes.first() else {
        return (Vec::new(), false);
    };
    let flag = first >> 4;
    let leaf = flag & 2 != 0;
    let odd = flag & 1 != 0;
    let mut path = Vec::new();
    if odd {
        path.push(first & 0x0f);
    }
    path.extend(nibbles(&bytes[1..]));
    (path, leaf)
}

/// What a child slot of a branch or extension refers to.
enum Child<'a> {
    Empty,
    Hash([u8; 32]),
    Embedded(&'a Rlp),
}

fn child(item: &Rlp) -> Result<Child<'_>, String> {
    match item {
        Rlp::Bytes(b) if b.is_empty() => Ok(Child::Empty),
        Rlp::Bytes(b) if b.len() == 32 => {
            let mut hash = [0_u8; 32];
            hash.copy_from_slice(b);
            Ok(Child::Hash(hash))
        }
        Rlp::Bytes(_) => Err("mpt: malformed node".into()),
        list @ Rlp::List(_) => Ok(Child::Embedded(list)),
    }
}

/// Walk the proof for `raw_key` (hashed here to the secure-trie key) from `root`. The value
/// item's bytes when the key is present, `None` when the proof shows it absent, an error when
/// the proof is malformed, incomplete or tampered.
pub(crate) fn verify_proof(
    root: &[u8; 32],
    raw_key: &[u8],
    nodes: &[Vec<u8>],
) -> Result<Option<Vec<u8>>, String> {
    let mut by_hash: HashMap<[u8; 32], Rlp> = HashMap::new();
    for node in nodes {
        by_hash.insert(keccak256(node), decode(node)?);
    }
    let key = nibbles(&keccak256(raw_key));
    let mut expected: Child<'_> = Child::Hash(*root);
    let mut i = 0;
    for _ in 0..key.len() + 4 {
        let node = match expected {
            Child::Empty => return Ok(None),
            Child::Hash(hash) => by_hash
                .get(&hash)
                .ok_or("mpt: proof node missing for referenced hash")?,
            Child::Embedded(node) => node,
        };
        let Rlp::List(items) = node else {
            return Err("mpt: malformed node".into());
        };
        match items.len() {
            17 => {
                if i == key.len() {
                    return Ok(items[16].bytes().map(<[u8]>::to_vec));
                }
                expected = child(&items[usize::from(key[i])])?;
                i += 1;
            }
            2 => {
                let encoded = items[0].bytes().ok_or("mpt: malformed node")?;
                let (path, leaf) = decode_compact_path(encoded);
                if key.get(i..i + path.len()) != Some(path.as_slice()) {
                    return Ok(None);
                }
                i += path.len();
                if leaf {
                    return Ok(if i == key.len() {
                        items[1].bytes().map(<[u8]>::to_vec)
                    } else {
                        None
                    });
                }
                expected = child(&items[1])?;
            }
            _ => return Err("mpt: malformed node".into()),
        }
    }
    Err("mpt: proof did not terminate".into())
}

pub(crate) fn parse_hex_bytes(text: &str) -> Result<Vec<u8>, String> {
    let hex = text.trim().trim_start_matches("0x");
    let padded = if hex.len() % 2 == 1 {
        format!("0{hex}")
    } else {
        hex.to_string()
    };
    hex::decode(padded).map_err(|e| format!("bad hex: {e}"))
}

pub(crate) fn parse_hash(text: &str) -> Result<[u8; 32], String> {
    let bytes = parse_hex_bytes(text)?;
    <[u8; 32]>::try_from(bytes).map_err(|_| "expected 32 bytes".to_string())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use num_bigint::BigUint;

    /// The real proof of the Sepolia staked set's root slot (`testdata/light-root-proof.json`).
    pub(crate) const FIXTURE: &str = include_str!("../../../testdata/light-root-proof.json");

    // a tiny rlp encoder for hand-built tries
    pub(crate) fn encode_bytes(data: &[u8]) -> Vec<u8> {
        if data.len() == 1 && data[0] < 0x80 {
            return data.to_vec();
        }
        let mut out = encode_length(data.len(), 0x80);
        out.extend_from_slice(data);
        out
    }

    pub(crate) fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
        let body: Vec<u8> = items.concat();
        let mut out = encode_length(body.len(), 0xc0);
        out.extend(body);
        out
    }

    fn encode_length(len: usize, offset: u8) -> Vec<u8> {
        if len < 56 {
            return vec![offset + len as u8];
        }
        let be: Vec<u8> = len
            .to_be_bytes()
            .iter()
            .copied()
            .skip_while(|b| *b == 0)
            .collect();
        let mut out = vec![offset + 55 + be.len() as u8];
        out.extend(be);
        out
    }

    pub(crate) fn compact(path: &[u8], leaf: bool) -> Vec<u8> {
        let flag = if leaf { 2 } else { 0 };
        let odd = path.len() % 2 == 1;
        let mut out = Vec::new();
        let mut rest = path;
        if odd {
            out.push(((flag | 1) << 4) | path[0]);
            rest = &path[1..];
        } else {
            out.push(flag << 4);
        }
        for pair in rest.chunks(2) {
            out.push((pair[0] << 4) | pair[1]);
        }
        out
    }

    fn fixture_nodes(value: &serde_json::Value) -> Vec<Vec<u8>> {
        value
            .as_array()
            .unwrap()
            .iter()
            .map(|n| parse_hex_bytes(n.as_str().unwrap()).unwrap())
            .collect()
    }

    #[test]
    fn rlp_decodes_canonically() {
        assert_eq!(decode(&[0x80]).unwrap(), Rlp::Bytes(Vec::new()));
        assert_eq!(decode(&[0x7f]).unwrap(), Rlp::Bytes(vec![0x7f]));
        assert_eq!(decode(&[0x82, 1, 2]).unwrap(), Rlp::Bytes(vec![1, 2]));
        assert_eq!(
            decode(&[0xc2, 0x01, 0x80]).unwrap(),
            Rlp::List(vec![Rlp::Bytes(vec![1]), Rlp::Bytes(Vec::new())])
        );
        assert!(decode(&[0x81, 0x05]).is_err(), "non-canonical single byte");
        assert!(decode(&[0x82, 1]).is_err(), "truncated");
        assert!(decode(&[0x01, 0x02]).is_err(), "trailing bytes");
        let long = vec![7_u8; 60];
        assert_eq!(decode(&encode_bytes(&long)).unwrap(), Rlp::Bytes(long));
    }

    #[test]
    fn the_real_sepolia_proof_verifies_and_tampering_is_caught() {
        let fixture: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
        let state_root = parse_hash(fixture["block"]["stateRoot"].as_str().unwrap()).unwrap();
        let contract = parse_hex_bytes(fixture["contract"].as_str().unwrap()).unwrap();
        let account_nodes = fixture_nodes(&fixture["proof"]["accountProof"]);
        let account = verify_proof(&state_root, &contract, &account_nodes)
            .unwrap()
            .expect("the contract exists");
        let Rlp::List(fields) = decode(&account).unwrap() else {
            panic!("account is a list")
        };
        assert_eq!(fields.len(), 4);
        let storage_hash: [u8; 32] = fields[2].bytes().unwrap().try_into().unwrap();
        assert_eq!(
            hex::encode(storage_hash),
            fixture["proof"]["storageHash"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x")
        );
        let slot = parse_hex_bytes(fixture["slot"].as_str().unwrap()).unwrap();
        let storage_nodes = fixture_nodes(&fixture["proof"]["storageProof"][0]["proof"]);
        let value = verify_proof(&storage_hash, &slot, &storage_nodes)
            .unwrap()
            .expect("the root slot is set");
        let value = decode(&value).unwrap();
        let root = BigUint::from_bytes_be(value.bytes().unwrap());
        assert_eq!(root.to_string(), fixture["root"].as_str().unwrap());

        // a different slot walks off the supplied path: the proof is incomplete for it, which
        // is an error, never a silent absence (absence needs an empty child or a diverging leaf)
        let mut other_slot = slot.clone();
        other_slot[31] = 0x42;
        assert!(verify_proof(&storage_hash, &other_slot, &storage_nodes).is_err());

        // a flipped byte in a leaf breaks the hash its parent commits to
        let mut tampered = storage_nodes.clone();
        let last = tampered.last_mut().unwrap();
        let end = last.len() - 1;
        last[end] ^= 1;
        assert!(verify_proof(&storage_hash, &slot, &tampered).is_err());
        // a missing node is caught too
        assert!(verify_proof(
            &storage_hash,
            &slot,
            &storage_nodes[..storage_nodes.len() - 1]
        )
        .is_err());
        // a wrong state root never resolves
        assert!(verify_proof(&[0_u8; 32], &contract, &account_nodes).is_err());
    }

    #[test]
    fn a_hand_built_single_leaf_trie_round_trips() {
        let raw_key = [0xab_u8; 20];
        let value = encode_bytes(&[0x12, 0x34]);
        let path = nibbles(&keccak256(&raw_key));
        let leaf = encode_list(&[encode_bytes(&compact(&path, true)), encode_bytes(&value)]);
        let root = keccak256(&leaf);
        assert_eq!(
            verify_proof(&root, &raw_key, std::slice::from_ref(&leaf)).unwrap(),
            Some(value)
        );
        assert_eq!(verify_proof(&root, &[0xac_u8; 20], &[leaf]).unwrap(), None);
    }
}
