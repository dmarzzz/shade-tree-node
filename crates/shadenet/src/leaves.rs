//! Native membership-set discovery for the Rust client.
//!
//! Replays the same StakedReputationSet/PaidAccessSet events as
//! `lib/root-provider.mjs`, preserving append order and zero-in-place removals.

use num_bigint::BigUint;
use serde_json::{json, Value};
use shadenet_rln::replay::range_error;
pub use shadenet_rln::replay::{
    is_incomplete, reconstruct, DiscoveredMembers, MembersDocument, ACTIVE_COUNT_SELECTOR,
    ALL_TOPICS, NEXT_INDEX_SELECTOR,
};

const MIN_CHUNK: u64 = 64;

/// A minimal blocking JSON-RPC client (public within the crate for `doctor`).
pub(crate) struct Rpc {
    client: reqwest::blocking::Client,
    url: String,
    id: u64,
}

impl Rpc {
    pub(crate) fn new(url: &str) -> Result<Self, String> {
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

    pub(crate) fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
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

/// The contract's `(nextIndex, activeCount)` at `block`, or `None` for a set without those views.
fn contract_counters(
    rpc: &mut Rpc,
    address: &str,
    block: &str,
) -> Result<Option<(u64, u64)>, String> {
    let mut counters = [0u64; 2];
    for (slot, selector) in [NEXT_INDEX_SELECTOR, ACTIVE_COUNT_SELECTOR]
        .iter()
        .enumerate()
    {
        let word = match rpc.call(
            "eth_call",
            json!([{ "to": address, "data": selector }, block]),
        ) {
            Ok(Value::String(word)) => word,
            Ok(_) => return Ok(None),
            Err(error) if error.to_ascii_lowercase().contains("revert") => return Ok(None),
            Err(error) => return Err(error),
        };
        let raw = word.trim_start_matches("0x");
        if raw.len() != 64 {
            return Ok(None);
        }
        let value = BigUint::parse_bytes(raw.as_bytes(), 16)
            .ok_or_else(|| format!("contract counter is not a number: {word}"))?;
        let digits = value.to_u64_digits();
        counters[slot] = match digits.len() {
            0 => 0,
            1 => digits[0],
            _ => return Err(format!("contract counter out of range: {word}")),
        };
    }
    Ok(Some((counters[0], counters[1])))
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

    let counters = contract_counters(&mut rpc, &address, to_hex)?;
    let mut chunk = 10_000u64;
    loop {
        let logs = scan_logs(&mut rpc, &address, from_block, to, &mut chunk)?;
        let outcome = reconstruct(&logs, rln_identifier).and_then(|set| match counters {
            Some((next_index, active))
                if set.document.members.len() as u64 != next_index || set.live_count as u64 != active =>
            {
                Err(format!(
                    "incomplete member log: {} slots and {} live members replayed from logs, but the contract reports nextIndex {next_index} and activeCount {active} at block {to} (the RPC dropped logs)",
                    set.document.members.len(),
                    set.live_count
                ))
            }
            _ => Ok(set),
        });
        match outcome {
            Ok(set) => return Ok(set),
            // A public RPC pool can answer a wide eth_getLogs with a silently empty page: smaller
            // pages reach a backend that has the history. Give up only at the floor.
            Err(error) if is_incomplete(&error) && chunk > MIN_CHUNK => {
                chunk = (chunk / 2).max(MIN_CHUNK);
            }
            Err(error) if is_incomplete(&error) => {
                return Err(format!("{error}; {rpc_url} returned partial history even in {chunk}-block pages, use another RPC"));
            }
            Err(error) => return Err(error),
        }
    }
}

fn scan_logs(
    rpc: &mut Rpc,
    address: &str,
    from_block: u64,
    to: u64,
    chunk: &mut u64,
) -> Result<Vec<Value>, String> {
    let mut cursor = from_block;
    let mut logs = Vec::new();
    while cursor <= to {
        let end = to.min(cursor.saturating_add(*chunk - 1));
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
            Err(e) if range_error(&e) && *chunk > 8 => {
                *chunk = (*chunk / 2).max(8);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(logs)
}
