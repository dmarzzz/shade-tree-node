//! On-chain admission roots (`packages/node/lib/root-provider.mjs` `NodeRootProvider`,
//! `makeFreshRootRing`, `withCache`, `replayVerified`): every contract's membership events are
//! replayed into the tree, checked against the contract's own counters, and kept as a
//! time-bounded set of recent roots so a proof against a just-superseded root still verifies.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use shadenet_rln::replay::{
    is_incomplete, range_error, reconstruct, ACTIVE_COUNT_SELECTOR, ALL_TOPICS, NEXT_INDEX_SELECTOR,
};

use crate::metrics::Registry;
use crate::rpc::{Rpc, RpcError};

const POLL_INTERVAL: Duration = Duration::from_secs(12);
const MIN_CHUNK: u64 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Staked,
    Paid,
}

impl Kind {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Staked => "staked",
            Self::Paid => "paid",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Contract {
    pub(crate) address: String,
    pub(crate) kind: Kind,
    pub(crate) from_block: u64,
}

/// The current root plus the roots it superseded within the freshness window.
struct Ring {
    initialized: bool,
    current: Option<String>,
    retired: Vec<(String, Instant)>,
}

impl Ring {
    fn new() -> Self {
        Self {
            initialized: false,
            current: None,
            retired: Vec::new(),
        }
    }

    fn push(&mut self, root: Option<String>, freshness: Duration, now: Instant) -> Vec<String> {
        if !self.initialized {
            self.initialized = true;
            self.current = root;
        } else if root != self.current {
            if let Some(previous) = self.current.take() {
                self.retired.insert(0, (previous, now));
            }
            self.current = root;
        }
        self.retired
            .retain(|(_, retired_at)| now.duration_since(*retired_at) <= freshness);
        let mut roots: Vec<String> = self.current.iter().cloned().collect();
        for (root, _) in &self.retired {
            if !roots.contains(root) {
                roots.push(root.clone());
            }
        }
        roots
    }
}

struct Snapshot {
    roots: Vec<String>,
    block: u64,
    leaves: usize,
}

struct Source {
    contract: Contract,
    ring: Ring,
    scanned: Option<(u64, Vec<Value>)>,
    last_success: Option<Instant>,
    snapshot: Option<Snapshot>,
    stale: bool,
}

/// What a `wrong-group-root` refusal advertises about the primary source.
pub(crate) struct Advert {
    pub(crate) block: Option<u64>,
    pub(crate) leaves: Option<usize>,
}

pub(crate) struct ChainSource {
    rpc: Arc<Rpc>,
    freshness: Duration,
    confirmations: u64,
    chunk: u64,
    rln_identifier: u64,
    sources: Mutex<Vec<Source>>,
    registry: Option<Arc<Registry>>,
}

fn hex_block(value: u64) -> String {
    format!("0x{value:x}")
}

fn parse_hex(value: &Value) -> Option<u64> {
    let text = value.as_str()?;
    u64::from_str_radix(text.trim_start_matches("0x"), 16).ok()
}

impl ChainSource {
    pub(crate) fn new(
        rpc: Arc<Rpc>,
        contracts: Vec<Contract>,
        freshness: Duration,
        confirmations: u64,
        chunk: u64,
        rln_identifier: u64,
        registry: Option<Arc<Registry>>,
    ) -> Self {
        Self {
            rpc,
            freshness,
            confirmations,
            chunk: chunk.max(MIN_CHUNK),
            rln_identifier,
            registry,
            sources: Mutex::new(
                contracts
                    .into_iter()
                    .map(|contract| Source {
                        contract,
                        ring: Ring::new(),
                        scanned: None,
                        last_success: None,
                        snapshot: None,
                        stale: false,
                    })
                    .collect(),
            ),
        }
    }

    /// The per-source gauges: distinct trusted roots and the degraded flag per kind, and the
    /// paid set's live leaf count (its anonymity set).
    fn publish(&self, sources: &[Source]) {
        let Some(registry) = &self.registry else {
            return;
        };
        let now = Instant::now();
        for kind in [Kind::Staked, Kind::Paid] {
            let of_kind: Vec<&Source> =
                sources.iter().filter(|s| s.contract.kind == kind).collect();
            if of_kind.is_empty() {
                continue;
            }
            let roots: HashSet<&String> = of_kind
                .iter()
                .filter(|s| {
                    s.last_success
                        .is_some_and(|at| now.duration_since(at) <= self.freshness)
                })
                .filter_map(|s| s.snapshot.as_ref())
                .flat_map(|snapshot| snapshot.roots.iter())
                .collect();
            registry.gauge(
                "shade_tree_gateway_trusted_roots",
                &[("source", kind.label())],
                roots.len() as f64,
            );
            registry.gauge(
                "shade_tree_gateway_root_source_degraded",
                &[("source", kind.label())],
                if of_kind.iter().any(|s| s.stale) {
                    1.0
                } else {
                    0.0
                },
            );
            if kind == Kind::Paid {
                if let Some(leaves) = of_kind
                    .iter()
                    .filter_map(|s| s.snapshot.as_ref())
                    .map(|s| s.leaves)
                    .next()
                {
                    registry.gauge("shade_tree_gateway_paid_access_leaves", &[], leaves as f64);
                }
            }
        }
    }

    pub(crate) fn contracts(&self) -> Vec<Contract> {
        self.sources
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|s| s.contract.clone())
            .collect()
    }

    /// The roots every source currently vouches for. A source past the freshness window
    /// contributes nothing: on-chain admission fails closed rather than serving stale roots.
    pub(crate) fn roots(&self) -> HashSet<String> {
        let now = Instant::now();
        self.sources
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|s| {
                s.last_success
                    .is_some_and(|at| now.duration_since(at) <= self.freshness)
            })
            .filter_map(|s| s.snapshot.as_ref())
            .flat_map(|snapshot| snapshot.roots.iter().cloned())
            .collect()
    }

    pub(crate) fn advert(&self) -> Advert {
        let sources = self.sources.lock().unwrap_or_else(|e| e.into_inner());
        match sources.first().and_then(|s| s.snapshot.as_ref()) {
            Some(snapshot) => Advert {
                block: Some(snapshot.block),
                leaves: Some(snapshot.leaves),
            },
            None => Advert {
                block: None,
                leaves: None,
            },
        }
    }

    /// Refresh every source once. Returns how many answered.
    pub(crate) async fn refresh(&self) -> usize {
        let contracts = self.contracts();
        let mut healthy = 0;
        for (index, contract) in contracts.iter().enumerate() {
            let started = Instant::now();
            let scanned = {
                let mut sources = self.sources.lock().unwrap_or_else(|e| e.into_inner());
                sources[index].scanned.take()
            };
            match self.read(contract, scanned).await {
                Ok(read) => {
                    healthy += 1;
                    self.record(index, read, started);
                }
                Err(e) => self.fail(index, &e, started),
            }
        }
        healthy
    }

    pub(crate) async fn poll(self: Arc<Self>) {
        loop {
            tokio::time::sleep(POLL_INTERVAL).await;
            self.refresh().await;
        }
    }

    fn record(&self, index: usize, read: Read, started: Instant) {
        let mut sources = self.sources.lock().unwrap_or_else(|e| e.into_inner());
        let source = &mut sources[index];
        let now = Instant::now();
        let stale_gap = source
            .last_success
            .is_some_and(|at| started.duration_since(at) > self.freshness);
        let invalidated = source.last_success.is_some() && read.finalized && !read.incremental;
        if stale_gap || invalidated {
            source.ring = Ring::new();
        }
        let mut roots = None;
        if !(stale_gap || invalidated) {
            for transition in &read.transitions {
                roots = Some(source.ring.push(transition.clone(), self.freshness, now));
            }
        }
        let roots =
            roots.unwrap_or_else(|| source.ring.push(read.root.clone(), self.freshness, now));
        let changed = source
            .snapshot
            .as_ref()
            .is_none_or(|s| s.roots != roots || s.block != read.block);
        if changed {
            tracing::info!(
                source = source.contract.kind.label(),
                block = read.block,
                leaves = read.leaves,
                roots = roots.len(),
                "admission roots refreshed"
            );
        }
        source.snapshot = Some(Snapshot {
            roots,
            block: read.block,
            leaves: read.leaves,
        });
        source.scanned = read.scanned;
        source.last_success = Some(now);
        if source.stale {
            tracing::info!(
                source = source.contract.kind.label(),
                "root source recovered"
            );
        }
        source.stale = false;
        self.publish(&sources);
    }

    fn fail(&self, index: usize, error: &RpcError, started: Instant) {
        let mut sources = self.sources.lock().unwrap_or_else(|e| e.into_inner());
        let source = &mut sources[index];
        source.scanned = None;
        let within = source
            .last_success
            .is_some_and(|at| started.duration_since(at) <= self.freshness);
        if within {
            if let Some(snapshot) = source.snapshot.as_mut() {
                snapshot.roots.truncate(1);
            }
            if !source.stale {
                tracing::warn!(
                    source = source.contract.kind.label(),
                    "root source degraded; serving its last-known-good root: {error}"
                );
            }
        } else {
            tracing::warn!(
                source = source.contract.kind.label(),
                "root freshness window expired; rejecting on-chain admission from this source until it reads again: {error}"
            );
        }
        source.stale = true;
        self.publish(&sources);
    }

    async fn block_tag(&self) -> Result<String, RpcError> {
        if self.confirmations == 0 {
            return Ok("finalized".into());
        }
        let head = self
            .rpc
            .call("eth_getBlockByNumber", json!(["latest", false]))
            .await?;
        Ok(parse_hex(&head["number"])
            .map(|n| hex_block(n.saturating_sub(self.confirmations)))
            .unwrap_or_else(|| "latest".into()))
    }

    async fn read(
        &self,
        contract: &Contract,
        scanned: Option<(u64, Vec<Value>)>,
    ) -> Result<Read, RpcError> {
        let tag = self.block_tag().await?;
        let finalized = tag == "finalized";
        let block = self
            .rpc
            .call("eth_getBlockByNumber", json!([tag, false]))
            .await?;
        let observed = parse_hex(&block["number"]).ok_or_else(|| RpcError::Transport {
            method: "eth_getBlockByNumber".into(),
            message: format!("{tag} returned no block number"),
        })?;
        let to_hex = hex_block(observed);
        let counters = self.counters(&contract.address, &to_hex).await?;
        let incremental = finalized && scanned.as_ref().is_some_and(|(to, _)| observed >= *to);
        let mut chunk = self.chunk;
        let mut previous: Option<(u64, Vec<Value>)> = if incremental { scanned } else { None };
        loop {
            let (logs, old_count) = match previous.take() {
                Some((to, mut old)) => {
                    let old_count = old.len();
                    if observed > to {
                        let mut fresh = self
                            .scan(&contract.address, to + 1, observed, &mut chunk)
                            .await?;
                        old.append(&mut fresh);
                    }
                    (old, old_count)
                }
                None => (
                    self.scan(&contract.address, contract.from_block, observed, &mut chunk)
                        .await?,
                    usize::MAX,
                ),
            };
            let outcome = reconstruct(&logs, self.rln_identifier).and_then(|set| match counters {
                Some((next_index, active))
                    if set.document.members.len() as u64 != next_index
                        || set.live_count as u64 != active =>
                {
                    Err(format!(
                        "incomplete member log: {} slots and {} live members replayed, but the contract reports nextIndex {next_index} and activeCount {active} at block {observed} (the RPC dropped logs)",
                        set.document.members.len(),
                        set.live_count
                    ))
                }
                _ => Ok(set),
            });
            match outcome {
                Ok(set) => {
                    let root = (set.live_count > 0).then(|| set.root.clone());
                    let mut transitions = Vec::new();
                    if old_count < logs.len() {
                        for end in old_count + 1..=logs.len() {
                            let step =
                                reconstruct(&logs[..end], self.rln_identifier).map_err(|e| {
                                    RpcError::Transport {
                                        method: "eth_getLogs".into(),
                                        message: e,
                                    }
                                })?;
                            transitions.push((step.live_count > 0).then_some(step.root));
                        }
                    }
                    return Ok(Read {
                        root,
                        transitions,
                        block: observed,
                        leaves: set.live_count,
                        finalized,
                        incremental: old_count != usize::MAX,
                        scanned: finalized.then_some((observed, logs)),
                    });
                }
                Err(e) if is_incomplete(&e) && chunk > MIN_CHUNK => {
                    chunk = (chunk / 2).max(MIN_CHUNK);
                }
                Err(e) => {
                    return Err(RpcError::Transport {
                        method: "eth_getLogs".into(),
                        message: if is_incomplete(&e) {
                            format!("{e}; partial history even in {chunk}-block pages")
                        } else {
                            e
                        },
                    })
                }
            }
        }
    }

    /// `(nextIndex, activeCount)` at `block`, or `None` for a set without those views.
    async fn counters(&self, address: &str, block: &str) -> Result<Option<(u64, u64)>, RpcError> {
        let mut out = [0_u64; 2];
        for (slot, selector) in [NEXT_INDEX_SELECTOR, ACTIVE_COUNT_SELECTOR]
            .iter()
            .enumerate()
        {
            let word = match self
                .rpc
                .call(
                    "eth_call",
                    json!([{"to": address, "data": selector}, block]),
                )
                .await
            {
                Ok(Value::String(word)) => word,
                Ok(_) => return Ok(None),
                Err(e) if e.is_revert() => return Ok(None),
                Err(e) => return Err(e),
            };
            let raw = word.trim_start_matches("0x");
            if raw.len() != 64 {
                return Ok(None);
            }
            match u64::from_str_radix(raw.trim_start_matches('0'), 16) {
                Ok(value) => out[slot] = value,
                Err(_) if raw.bytes().all(|b| b == b'0') => out[slot] = 0,
                Err(_) => return Ok(None),
            }
        }
        Ok(Some((out[0], out[1])))
    }

    async fn scan(
        &self,
        address: &str,
        from: u64,
        to: u64,
        chunk: &mut u64,
    ) -> Result<Vec<Value>, RpcError> {
        let mut cursor = from;
        let mut logs = Vec::new();
        while cursor <= to {
            let end = to.min(cursor.saturating_add(*chunk - 1));
            let filter = json!({
                "address": address,
                "topics": [ALL_TOPICS],
                "fromBlock": hex_block(cursor),
                "toBlock": hex_block(end),
            });
            match self.rpc.call("eth_getLogs", json!([filter])).await {
                Ok(Value::Array(mut page)) => {
                    logs.append(&mut page);
                    cursor = end.saturating_add(1);
                }
                Ok(_) => {
                    return Err(RpcError::Transport {
                        method: "eth_getLogs".into(),
                        message: "returned a non-array result".into(),
                    })
                }
                Err(e) if range_error(&e.to_string()) && *chunk > MIN_CHUNK => {
                    *chunk = (*chunk / 2).max(MIN_CHUNK);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(logs)
    }
}

struct Read {
    root: Option<String>,
    transitions: Vec<Option<String>>,
    block: u64,
    leaves: usize,
    finalized: bool,
    incremental: bool,
    scanned: Option<(u64, Vec<Value>)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ring_keeps_superseded_roots_for_the_freshness_window() {
        let mut ring = Ring::new();
        let fresh = Duration::from_millis(50);
        let t0 = Instant::now();
        assert_eq!(ring.push(Some("a".into()), fresh, t0), ["a"]);
        assert_eq!(ring.push(Some("a".into()), fresh, t0), ["a"]);
        assert_eq!(
            ring.push(Some("b".into()), fresh, t0 + Duration::from_millis(10)),
            ["b", "a"]
        );
        assert_eq!(
            ring.push(Some("c".into()), fresh, t0 + Duration::from_millis(20)),
            ["c", "b", "a"]
        );
        assert_eq!(
            ring.push(Some("c".into()), fresh, t0 + Duration::from_millis(61)),
            ["c", "b"],
            "a retired at t0+10 is older than the window"
        );
        assert_eq!(
            ring.push(None, fresh, t0 + Duration::from_millis(62)),
            ["c", "b"],
            "an empty set retires the current root but names no new one"
        );
    }
}
