//! Membership-set replay shared by every reader: the StakedReputationSet / PaidAccessSet
//! events in append order with zero-in-place removals, matching `lib/root-provider.mjs`.

use std::collections::HashMap;

use num_bigint::BigUint;
use serde::Serialize;
use serde_json::Value;

use crate::tree::{fr_to_dec, parse_fr, MerkleTree, TREE_DEPTH};

pub const REGISTERED: &[&str] = &[
    "0x0dbb6a3ed41d8f3d21e481b86d0e8bbf65a630b7dc4c5ee6c2c1a74561841e6d",
    "0x509c8735bf3647b16c92625a43b5459d0b51845aa0f3ec846f9d24594e7b824b",
    "0x829b3fd9a2105b78eea5138f4d692eb507be107a9b265a9456ea94fb2db9f992",
    "0x9b776d199f09c774f5b205c9bc2ac6f40d508c347aaea919867eeaf06ebef0e9",
];
pub const REMOVED: &[&str] = &[
    "0x971e754215411b0ec07054d759063d876d53872b7d4b37294744e5a776604f37",
    "0x8f2d81dd61a3f7ff90ea7265e45192f03f643615dd2458e287d84aaac222ffe9",
    "0x707cd9719d0c14265b9e456f7add99095401f907e570e5cdd65a92920947c450",
    "0x0a39eb0fcb6a37e10a529e106ae887cbd1721626fa57900170ed0c2437af3797",
    "0xac0c8be2061774c705c517af2a774ab5cb33a2d7fe7054dd4a2728433026029c",
];
// `nextIndex()` and `activeCount()` of StakedReputationSet: the contract's own slot and live
// counters. A reconstruction that disagrees with them was built from an incomplete log
// scan (M7 rehearsal 2026-09-30: a public RPC pool answered a 10 000-block eth_getLogs with an
// EMPTY array from a pruned backend, so the client built a 3-slot tree, presented a root no
// node knew, and every tunnel was refused `gate:wrong-group-root`). PaidAccessSet has no such
// views; the check is skipped when the calls do not return a word.
pub const NEXT_INDEX_SELECTOR: &str = "0xfc7e9c6f";
pub const ACTIVE_COUNT_SELECTOR: &str = "0x4331ed1f";

/// Every membership event topic a reader filters on.
pub const ALL_TOPICS: &[&str] = &[
    REGISTERED[0],
    REGISTERED[1],
    REMOVED[0],
    REMOVED[1],
    REMOVED[2],
    REMOVED[3],
    REGISTERED[2],
    REGISTERED[3],
    REMOVED[4],
];

#[derive(Debug, Clone, Serialize)]
pub struct MembersDocument {
    pub version: u64,
    pub members: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DiscoveredMembers {
    pub document: MembersDocument,
    pub live_count: usize,
    pub root: String,
}

fn hex_number(value: &str) -> Option<BigUint> {
    let hex = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    BigUint::parse_bytes(hex.as_bytes(), 16)
}

fn log_order(log: &Value) -> (BigUint, BigUint) {
    let zero = || BigUint::from(0u8);
    (
        log.get("blockNumber")
            .and_then(Value::as_str)
            .and_then(hex_number)
            .unwrap_or_else(zero),
        log.get("logIndex")
            .and_then(Value::as_str)
            .and_then(hex_number)
            .unwrap_or_else(zero),
    )
}

/// An error whose cause is a partial log scan (a gap in the contract's append-only indices or a
/// disagreement with its counters). The fetcher retries such a scan with smaller pages.
pub fn is_incomplete(error: &str) -> bool {
    error.starts_with("incomplete member log:")
}

pub fn reconstruct(logs: &[Value], rln_identifier: u64) -> Result<DiscoveredMembers, String> {
    let id = BigUint::from(rln_identifier);
    let empty = MerkleTree::new(&id, TREE_DEPTH, &[]);
    let zero = fr_to_dec(&empty.zero_value());
    let mut ordered = logs.to_vec();
    ordered.sort_by_key(log_order);
    let mut members: Vec<String> = Vec::new();
    let mut live: HashMap<String, usize> = HashMap::new();
    for log in &ordered {
        let topics = log
            .get("topics")
            .and_then(Value::as_array)
            .ok_or_else(|| "membership log missing topics".to_string())?;
        let topic0 = topics
            .first()
            .and_then(Value::as_str)
            .ok_or_else(|| "membership log missing topic0".to_string())?
            .to_ascii_lowercase();
        let commitment_hex = topics
            .get(1)
            .and_then(Value::as_str)
            .ok_or_else(|| "membership log missing indexed commitment".to_string())?;
        let commitment = hex_number(commitment_hex)
            .ok_or_else(|| "membership log has invalid commitment".to_string())?
            .to_str_radix(10);
        if REGISTERED.contains(&topic0.as_str()) {
            if live.contains_key(&commitment) {
                continue;
            }
            // MemberRegistered(uint256 indexed commitment, uint64 indexed index, uint256 limit):
            // the contract's slot for this leaf. A register that lands past the next free slot
            // means the scan skipped earlier registrations; appending it would build a tree no
            // node shares.
            if let Some(index) = topics.get(2).and_then(Value::as_str).and_then(hex_number) {
                let expected = BigUint::from(members.len());
                if index > expected {
                    return Err(format!(
                        "incomplete member log: registration of slot {index} arrived with only {expected} slots replayed (the RPC dropped earlier logs)"
                    ));
                }
            }
            live.insert(commitment.clone(), members.len());
            members.push(commitment);
        } else if REMOVED.contains(&topic0.as_str()) {
            if let Some(index) = live.remove(&commitment) {
                members[index] = zero.clone();
            }
        }
    }
    // Commitments come from an RPC we do not trust: a malformed or out-of-field value is an error
    // for this fetch, never a panic that would take the proxy down.
    let fields = members
        .iter()
        .map(|m| parse_fr(m).map_err(|e| format!("member set from RPC: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    let tree = MerkleTree::new(&id, TREE_DEPTH, &fields);
    Ok(DiscoveredMembers {
        document: MembersDocument {
            version: 2,
            members,
        },
        live_count: live.len(),
        root: fr_to_dec(&tree.root()),
    })
}

/// True when an RPC refused an `eth_getLogs` window for its size; the caller halves the page.
pub fn range_error(error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    [
        "block range",
        "range is too",
        "range too",
        "too many results",
        "response size",
        "limit exceeded",
        "query timeout",
        "exceed maximum",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn log(topic: &str, commitment: u64, block: u64, index: u64) -> Value {
        json!({
            "blockNumber": format!("0x{block:x}"),
            "logIndex": format!("0x{index:x}"),
            "topics": [topic, format!("0x{commitment:064x}")],
        })
    }

    fn log_v4(commitment: u64, index: u64, block: u64) -> Value {
        json!({
            "blockNumber": format!("0x{block:x}"),
            "logIndex": "0x0",
            "topics": [REGISTERED[1], format!("0x{commitment:064x}"), format!("0x{index:064x}")],
        })
    }

    #[test]
    fn a_register_past_the_next_slot_is_an_incomplete_scan() {
        // Slots 0..4 dropped by the RPC: the first log seen claims slot 5.
        let err = reconstruct(&[log_v4(555, 5, 10)], 1).unwrap_err();
        assert!(is_incomplete(&err), "{err}");
        assert!(err.contains("slot 5"), "{err}");
        // A complete scan replays the contract's indices exactly.
        let ok = reconstruct(&[log_v4(111, 0, 1), log_v4(222, 1, 2)], 1).unwrap();
        assert_eq!(
            ok.document.members,
            vec!["111".to_string(), "222".to_string()]
        );
        // A reorg echo (an index already replayed) is tolerated, as before.
        let echo = reconstruct(&[log_v4(111, 0, 1), log_v4(111, 0, 1)], 1).unwrap();
        assert_eq!(echo.document.members.len(), 1);
    }

    #[test]
    fn replay_preserves_append_order_and_zeroes_removals() {
        let logs = vec![
            log(REGISTERED[0], 111, 1, 0),
            log(REMOVED[2], 111, 3, 0),
            log(REGISTERED[1], 222, 2, 0),
            log(REGISTERED[0], 111, 4, 0),
        ];
        let out = reconstruct(&logs, 1).unwrap();
        assert_eq!(out.live_count, 2);
        assert_eq!(out.document.version, 2);
        assert_eq!(out.document.members.len(), 3);
        assert_ne!(out.document.members[0], "0");
        assert_eq!(out.document.members[1], "222");
        assert_eq!(out.document.members[2], "111");
    }
}
