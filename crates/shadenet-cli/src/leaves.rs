//! Native membership-set discovery for the Rust client.
//!
//! Replays the same StakedReputationSet/PaidAccessSet events as
//! `lib/root-provider.mjs`, preserving append order and zero-in-place removals.

use std::collections::HashMap;

use num_bigint::BigUint;
use serde::Serialize;
use serde_json::{json, Value};
use shadenet_rln::tree::{dec_to_fr, fr_to_dec, MerkleTree, TREE_DEPTH};

const REGISTERED: &[&str] = &[
    "0x0dbb6a3ed41d8f3d21e481b86d0e8bbf65a630b7dc4c5ee6c2c1a74561841e6d",
    "0x509c8735bf3647b16c92625a43b5459d0b51845aa0f3ec846f9d24594e7b824b",
    "0x829b3fd9a2105b78eea5138f4d692eb507be107a9b265a9456ea94fb2db9f992",
    "0x9b776d199f09c774f5b205c9bc2ac6f40d508c347aaea919867eeaf06ebef0e9",
];
const REMOVED: &[&str] = &[
    "0x971e754215411b0ec07054d759063d876d53872b7d4b37294744e5a776604f37",
    "0x8f2d81dd61a3f7ff90ea7265e45192f03f643615dd2458e287d84aaac222ffe9",
    "0x707cd9719d0c14265b9e456f7add99095401f907e570e5cdd65a92920947c450",
    "0x0a39eb0fcb6a37e10a529e106ae887cbd1721626fa57900170ed0c2437af3797",
    "0xac0c8be2061774c705c517af2a774ab5cb33a2d7fe7054dd4a2728433026029c",
];
const ALL_TOPICS: &[&str] = &[
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
            live.insert(commitment.clone(), members.len());
            members.push(commitment);
        } else if REMOVED.contains(&topic0.as_str()) {
            if let Some(index) = live.remove(&commitment) {
                members[index] = zero.clone();
            }
        }
    }
    let fields = members.iter().map(|m| dec_to_fr(m)).collect::<Vec<_>>();
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

struct Rpc {
    client: reqwest::blocking::Client,
    url: String,
    id: u64,
}

impl Rpc {
    fn new(url: &str) -> Result<Self, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|e| format!("build RPC client: {e}"))?;
        Ok(Self {
            client,
            url: url.to_string(),
            id: 0,
        })
    }

    fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        self.id += 1;
        let response = self
            .client
            .post(&self.url)
            .json(&json!({"jsonrpc":"2.0","id":self.id,"method":method,"params":params}))
            .send()
            .map_err(|e| format!("{method}: RPC transport failed: {e}"))?;
        if !response.status().is_success() {
            return Err(format!("{method}: RPC HTTP {}", response.status()));
        }
        let body: Value = response
            .json()
            .map_err(|e| format!("{method}: invalid RPC JSON: {e}"))?;
        if let Some(error) = body.get("error") {
            return Err(format!("{method}: RPC error {error}"));
        }
        body.get("result")
            .cloned()
            .ok_or_else(|| format!("{method}: RPC response missing result"))
    }
}

fn range_error(error: &str) -> bool {
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

pub fn fetch_members(
    rpc_url: &str,
    contract: &str,
    from_block: u64,
    block_tag: &str,
    rln_identifier: u64,
) -> Result<DiscoveredMembers, String> {
    let address = contract.to_ascii_lowercase();
    if address.len() != 42 || !address.starts_with("0x") || hex::decode(&address[2..]).is_err() {
        return Err(format!("not an Ethereum address: {contract}"));
    }
    let mut rpc = Rpc::new(rpc_url)?;
    let block = rpc.call("eth_getBlockByNumber", json!([block_tag, false]))?;
    let to_hex = block
        .get("number")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("eth_getBlockByNumber({block_tag}) returned no block"))?;
    let to = u64::from_str_radix(to_hex.trim_start_matches("0x"), 16)
        .map_err(|_| format!("bad block number: {to_hex}"))?;
    if from_block > to {
        return reconstruct(&[], rln_identifier);
    }

    let mut cursor = from_block;
    let mut chunk = 10_000u64;
    let mut logs = Vec::new();
    while cursor <= to {
        let end = to.min(cursor.saturating_add(chunk - 1));
        let filter = json!({
            "address": address,
            "topics": [ALL_TOPICS],
            "fromBlock": format!("0x{cursor:x}"),
            "toBlock": format!("0x{end:x}"),
        });
        match rpc.call("eth_getLogs", json!([filter])) {
            Ok(Value::Array(mut page)) => {
                logs.append(&mut page);
                cursor = end.saturating_add(1);
            }
            Ok(_) => return Err("eth_getLogs returned a non-array result".into()),
            Err(e) if range_error(&e) && chunk > 8 => {
                chunk = (chunk / 2).max(8);
            }
            Err(e) => return Err(e),
        }
    }
    reconstruct(&logs, rln_identifier)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log(topic: &str, commitment: u64, block: u64, index: u64) -> Value {
        json!({
            "blockNumber": format!("0x{block:x}"),
            "logIndex": format!("0x{index:x}"),
            "topics": [topic, format!("0x{commitment:064x}")],
        })
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
