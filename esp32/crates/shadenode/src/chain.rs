//! The node's view of the chain: the staking contract's current root, and the one
//! transaction a node ever sends, a slash.
//!
//! The platform supplies HTTPS (`Http`); everything here is blocking code meant for a helper
//! thread, plus the tasks that run it without stalling the event loop.

use std::future::poll_fn;
use std::sync::mpsc::{channel, TryRecvError};
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};

use ark_bn254::Fr;
use k256::ecdsa::SigningKey;
use microtor::rt::{sleep, spawn};
use num_bigint::BigUint;
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};

use crate::node::{Node, OverSpend};
use crate::rln::{fr_to_dec, rate_commitment, recover_secret};

/// Stack for the thread that builds and signs a slash (field arithmetic plus ECDSA, on top of
/// the HTTPS client's own needs).
const SLASH_STACK: usize = 32 * 1024;
/// Tries per over-spend before giving up on the transaction.
const SLASH_ATTEMPTS: u32 = 4;

/// Storage slot of `currentRoot` in the staking contract.
const ROOT_SLOT: &str = "0x3";

/// A blocking HTTP client. Implementations verify TLS certificates.
pub trait Http: Send + Sync + 'static {
    /// POST a JSON body, return the response body.
    fn post_json(&self, url: &str, body: &str) -> Result<String, String>;
    /// GET a page; return the status and whether a `cf-mitigated` header was present.
    fn get_status(&self, url: &str) -> Result<(u16, bool), String>;
}

/// Run blocking work on its own thread and wait for it from a task.
pub async fn in_thread<T: Send + 'static>(
    stack: usize,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, String> {
    let (tx, rx) = channel();
    std::thread::Builder::new()
        .name("chain".into())
        .stack_size(stack)
        .spawn(move || {
            let _ = tx.send(work());
        })
        .map_err(|e| format!("could not start a thread: {e}"))?;
    poll_fn(|_| match rx.try_recv() {
        Ok(value) => Poll::Ready(Ok(value)),
        Err(TryRecvError::Empty) => Poll::Pending,
        Err(TryRecvError::Disconnected) => Poll::Ready(Err("worker thread died".to_string())),
    })
    .await
}

/// JSON-RPC over a list of endpoints, tried in order from the last one that worked.
#[derive(Clone)]
pub struct Rpc {
    http: Arc<dyn Http>,
    urls: Arc<Vec<String>>,
}

impl Rpc {
    pub fn new(http: Arc<dyn Http>, urls: Vec<String>) -> Self {
        Self {
            http,
            urls: Arc::new(urls),
        }
    }

    pub fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let body =
            json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
        let mut last = "no RPC endpoint configured".to_string();
        for url in self.urls.iter() {
            let reply = match self.http.post_json(url, &body) {
                Ok(reply) => reply,
                Err(e) => {
                    last = format!("{method}: {e}");
                    continue;
                }
            };
            let parsed: Value = match serde_json::from_str(&reply) {
                Ok(v) => v,
                Err(_) => {
                    last = format!("{method}: reply is not JSON");
                    continue;
                }
            };
            if let Some(error) = parsed.get("error").filter(|e| !e.is_null()) {
                // The endpoint answered: a JSON-RPC error is the answer, not a reason to ask
                // another one.
                let message = error["message"].as_str().unwrap_or("error");
                return Err(format!(
                    "{method}: {}",
                    message.chars().take(120).collect::<String>()
                ));
            }
            return Ok(parsed["result"].clone());
        }
        Err(last)
    }

    fn quantity(&self, method: &str, params: Value) -> Result<BigUint, String> {
        let value = self.call(method, params)?;
        value
            .as_str()
            .and_then(from_quantity)
            .ok_or_else(|| format!("{method}: not a quantity"))
    }
}

fn from_quantity(text: &str) -> Option<BigUint> {
    let hex = text.strip_prefix("0x")?;
    if hex.is_empty() {
        return Some(BigUint::default());
    }
    BigUint::parse_bytes(hex.as_bytes(), 16)
}

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

fn hex(data: &[u8]) -> String {
    format!("0x{}", microtor::util::hex_encode(data))
}

fn selector(signature: &str) -> [u8; 4] {
    keccak256(signature.as_bytes())[..4].try_into().unwrap()
}

fn word(value: &BigUint) -> [u8; 32] {
    let bytes = value.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len().min(32)..].copy_from_slice(&bytes[bytes.len().saturating_sub(32)..]);
    out
}

fn fr_word(value: &Fr) -> [u8; 32] {
    word(&BigUint::parse_bytes(fr_to_dec(value).as_bytes(), 10).unwrap_or_default())
}

/// Read the staking contract's current root at a block tag. `None` means the set is empty.
pub fn read_root(rpc: &Rpc, contract: &str, tag: &str) -> Result<Option<String>, String> {
    let value = rpc.quantity("eth_getStorageAt", json!([contract, ROOT_SLOT, tag]))?;
    Ok((value != BigUint::default()).then(|| value.to_str_radix(10)))
}

/// The roots a node accepts from one on-chain set: the current one, plus each root it
/// superseded for one freshness window, so a client proving against the previous root just
/// as a registration lands is not refused.
pub struct RootRing {
    current: Option<String>,
    retired: Vec<(String, Instant)>,
    last_ok: Option<Instant>,
    window: Duration,
}

impl RootRing {
    pub fn new(window: Duration) -> Self {
        Self {
            current: None,
            retired: Vec::new(),
            last_ok: None,
            window,
        }
    }

    pub fn observe(&mut self, root: Option<String>, now: Instant) {
        // A gap longer than the window means roots may have come and gone unseen.
        if self
            .last_ok
            .is_some_and(|t| now.duration_since(t) > self.window * 3)
        {
            self.retired.clear();
        }
        if root != self.current {
            if let Some(old) = self.current.take() {
                self.retired.push((old, now));
            }
            self.current = root;
        }
        self.last_ok = Some(now);
    }

    /// Accepted roots right now. A source that has not answered for three windows contributes
    /// nothing: better to refuse than to admit against a set that may have changed.
    pub fn roots(&mut self, now: Instant) -> Vec<String> {
        let window = self.window;
        self.retired
            .retain(|(_, at)| now.duration_since(*at) <= window);
        match self.last_ok {
            Some(t) if now.duration_since(t) <= window * 3 => self
                .current
                .iter()
                .cloned()
                .chain(self.retired.iter().map(|(r, _)| r.clone()))
                .collect(),
            _ => Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Transactions

fn rlp_bytes(data: &[u8], out: &mut Vec<u8>) {
    if data.len() == 1 && data[0] < 0x80 {
        out.push(data[0]);
    } else {
        rlp_length(data.len(), 0x80, out);
        out.extend_from_slice(data);
    }
}

fn rlp_length(len: usize, offset: u8, out: &mut Vec<u8>) {
    if len < 56 {
        out.push(offset + len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        out.push(offset + 55 + (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
}

fn rlp_uint(value: &BigUint, out: &mut Vec<u8>) {
    if *value == BigUint::default() {
        out.push(0x80);
    } else {
        rlp_bytes(&value.to_bytes_be(), out);
    }
}

fn rlp_list(items: &[u8], out: &mut Vec<u8>) {
    rlp_length(items.len(), 0xc0, out);
    out.extend_from_slice(items);
}

/// A secp256k1 key that signs EIP-1559 transactions.
pub struct Wallet {
    key: SigningKey,
    pub address: [u8; 20],
}

impl Wallet {
    pub fn from_secret(secret: &[u8; 32]) -> Result<Self, String> {
        let key =
            SigningKey::from_slice(secret).map_err(|_| "not a valid secp256k1 key".to_string())?;
        let public = key.verifying_key().to_encoded_point(false);
        let address: [u8; 20] = keccak256(&public.as_bytes()[1..])[12..].try_into().unwrap();
        Ok(Self { key, address })
    }

    pub fn address_hex(&self) -> String {
        hex(&self.address)
    }

    /// The raw signed type-2 transaction.
    #[allow(clippy::too_many_arguments)]
    fn sign(
        &self,
        chain_id: &BigUint,
        nonce: &BigUint,
        max_priority_fee: &BigUint,
        max_fee: &BigUint,
        gas: &BigUint,
        to: &[u8; 20],
        data: &[u8],
    ) -> Result<Vec<u8>, String> {
        let mut fields = Vec::with_capacity(160 + data.len());
        rlp_uint(chain_id, &mut fields);
        rlp_uint(nonce, &mut fields);
        rlp_uint(max_priority_fee, &mut fields);
        rlp_uint(max_fee, &mut fields);
        rlp_uint(gas, &mut fields);
        rlp_bytes(to, &mut fields);
        rlp_uint(&BigUint::default(), &mut fields); // value
        rlp_bytes(data, &mut fields);
        rlp_list(&[], &mut fields); // access list
        let mut unsigned = vec![0x02];
        rlp_list(&fields, &mut unsigned);
        let (signature, recovery) = self
            .key
            .sign_prehash_recoverable(&keccak256(&unsigned))
            .map_err(|_| "signing failed".to_string())?;
        let bytes = signature.to_bytes();
        rlp_uint(&BigUint::from(recovery.to_byte()), &mut fields);
        rlp_uint(&BigUint::from_bytes_be(&bytes[..32]), &mut fields);
        rlp_uint(&BigUint::from_bytes_be(&bytes[32..]), &mut fields);
        let mut raw = vec![0x02];
        rlp_list(&fields, &mut raw);
        Ok(raw)
    }
}

fn parse_address(text: &str) -> Result<[u8; 20], String> {
    text.strip_prefix("0x")
        .and_then(|h| microtor::util::hex_fixed::<20>(h).ok())
        .ok_or_else(|| "not a 0x address".to_string())
}

/// Estimate, price, sign and broadcast a call to `to`. Returns the transaction hash. Errors
/// never carry the calldata.
fn send_transaction(rpc: &Rpc, wallet: &Wallet, to: &str, data: &[u8]) -> Result<String, String> {
    let from = wallet.address_hex();
    let chain_id = rpc.quantity("eth_chainId", json!([]))?;
    let estimated = rpc.quantity(
        "eth_estimateGas",
        json!([{"from": from, "to": to, "data": hex(data)}]),
    )?;
    let gas = estimated * 120u32 / 100u32;
    let nonce = rpc.quantity("eth_getTransactionCount", json!([from, "pending"]))?;
    let gas_price = rpc.quantity("eth_gasPrice", json!([]))?;
    // The next block's base fee. `eth_feeHistory` answers in a few hundred bytes, where a
    // whole block (which also carries the field) can run to tens of kilobytes.
    let history = rpc.call("eth_feeHistory", json!(["0x1", "latest", []]))?;
    let base_fee = history["baseFeePerGas"]
        .as_array()
        .and_then(|fees| fees.last())
        .and_then(Value::as_str)
        .and_then(from_quantity)
        .ok_or("eth_feeHistory returned no base fee")?;
    let priority = rpc
        .quantity("eth_maxPriorityFeePerGas", json!([]))
        .ok()
        .or_else(|| (gas_price > base_fee).then(|| &gas_price - &base_fee))
        .unwrap_or_else(|| gas_price.clone().min(BigUint::from(1_000_000_000u64)));
    let max_fee = (&base_fee * 2u32 + &priority).max(gas_price);
    let raw = wallet.sign(
        &chain_id,
        &nonce,
        &priority,
        &max_fee,
        &gas,
        &parse_address(to)?,
        data,
    )?;
    let hash = hex(&keccak256(&raw));
    rpc.call("eth_sendRawTransaction", json!([hex(&raw)]))?;
    Ok(hash)
}

/// Slash the member behind an over-spend: recover the secret, find which tier's leaf is
/// bonded, and send `slash(commitment, secret, limit, receiver)`. Without a wallet this is a
/// dry run that only reports the leaf. Returns a line for the log; the secret is never in it.
pub fn slash(
    rpc: &Rpc,
    contract: &str,
    wallet: Option<&Wallet>,
    tiers: &[u64],
    over_spend: &OverSpend,
) -> Result<String, String> {
    let secret = recover_secret(
        (&over_spend.first.0, &over_spend.first.1),
        (&over_spend.second.0, &over_spend.second.1),
    )?;
    let limit_of = selector("limitOf(uint256)");
    let mut found = None;
    for &limit in tiers {
        let leaf = rate_commitment(secret, limit);
        let mut data = limit_of.to_vec();
        data.extend_from_slice(&fr_word(&leaf));
        let bonded = rpc.quantity(
            "eth_call",
            json!([{"to": contract, "data": hex(&data)}, "latest"]),
        )?;
        if bonded == BigUint::from(limit) {
            found = Some((leaf, limit));
            break;
        }
    }
    let Some((leaf, limit)) = found else {
        return Ok(
            "over-spend by a member with no live bond in this set (nothing to slash)".into(),
        );
    };
    let Some(wallet) = wallet else {
        return Ok(format!(
            "SLASH (dry-run) leaf={} limit={limit}: no slash key configured",
            fr_to_dec(&leaf)
        ));
    };
    let mut data = selector("slash(uint256,uint256,uint256,address)").to_vec();
    data.extend_from_slice(&fr_word(&leaf));
    data.extend_from_slice(&fr_word(&secret));
    data.extend_from_slice(&word(&BigUint::from(limit)));
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(&wallet.address);
    let hash = send_transaction(rpc, wallet, contract, &data)?;
    Ok(format!(
        "SLASH sent leaf={} limit={limit} tx={hash}",
        fr_to_dec(&leaf)
    ))
}

// ---------------------------------------------------------------------------------------------
// Tasks

#[derive(Clone)]
pub struct ChainConfig {
    pub http: Arc<dyn Http>,
    pub rpc_urls: Vec<String>,
    /// The staking contract (`0x` address).
    pub contract: String,
    /// Block tag roots are read at. Clients of the public network prove against `finalized`.
    pub block_tag: String,
    pub poll: Duration,
    /// How long a superseded root stays accepted (the record's `rootFreshnessSeconds`).
    pub freshness: Duration,
    /// Key that signs slash transactions and receives the reward; `None` is a dry run.
    pub slash_key: Option<[u8; 32]>,
    /// Tier limits a member's leaf may have been staked at.
    pub tiers: Vec<u64>,
    /// Stack for the HTTPS worker thread.
    pub thread_stack: usize,
    /// Take the heavy-job slot around each request (a TLS handshake is one on a small device).
    pub exclusive: bool,
}

impl Node {
    /// Track the staking contract's root and slash over-spenders, for as long as the node
    /// runs.
    pub fn start_chain(&self, config: ChainConfig) {
        let rpc = Rpc::new(config.http.clone(), config.rpc_urls.clone());

        let node = self.clone();
        let roots_config = config.clone();
        let roots_rpc = rpc.clone();
        spawn(async move {
            let mut ring = RootRing::new(roots_config.freshness);
            let mut failures = 0u32;
            loop {
                let (rpc, contract, tag) = (
                    roots_rpc.clone(),
                    roots_config.contract.clone(),
                    roots_config.block_tag.clone(),
                );
                let read = {
                    let _heavy = if roots_config.exclusive {
                        Some(microtor::rt::heavy().await)
                    } else {
                        None
                    };
                    in_thread(roots_config.thread_stack, move || {
                        read_root(&rpc, &contract, &tag)
                    })
                    .await
                };
                match read.and_then(|r| r) {
                    Ok(root) => {
                        if failures > 0 {
                            log::info!("chain root source is answering again");
                        }
                        failures = 0;
                        ring.observe(root, Instant::now());
                    }
                    Err(e) => {
                        failures += 1;
                        if failures == 1 || failures.is_multiple_of(10) {
                            log::warn!("chain root read failed ({failures}): {e}");
                        }
                    }
                }
                let roots = ring.roots(Instant::now());
                if node.set_chain_roots(roots.clone()) {
                    log::info!("accepted on-chain roots: {}", roots.len());
                }
                sleep(roots_config.poll).await;
            }
        });

        let node = self.clone();
        spawn(async move {
            let wallet = match config.slash_key.as_ref().map(Wallet::from_secret) {
                Some(Ok(wallet)) => Some(Arc::new(wallet)),
                Some(Err(e)) => {
                    log::warn!("slash key unusable ({e}); slashing is a dry run");
                    None
                }
                None => None,
            };
            // Over-spends waiting to be slashed, with the attempts made so far.
            let mut pending: Vec<(OverSpend, u32)> = Vec::new();
            loop {
                sleep(Duration::from_secs(if pending.is_empty() { 1 } else { 20 })).await;
                pending.extend(node.take_over_spends().into_iter().map(|o| (o, 0)));
                let mut retry = Vec::new();
                for (over_spend, attempts) in pending.drain(..) {
                    let (rpc, contract, tiers, wallet, shares) = (
                        rpc.clone(),
                        config.contract.clone(),
                        config.tiers.clone(),
                        wallet.clone(),
                        over_spend.clone(),
                    );
                    let _heavy = if config.exclusive {
                        Some(microtor::rt::heavy().await)
                    } else {
                        None
                    };
                    let outcome = in_thread(config.thread_stack.max(SLASH_STACK), move || {
                        slash(&rpc, &contract, wallet.as_deref(), &tiers, &shares)
                    })
                    .await;
                    match outcome.and_then(|r| r) {
                        Ok(line) => log::warn!("{line}"),
                        Err(e) if attempts < SLASH_ATTEMPTS => {
                            log::warn!("slash attempt {} failed: {e}", attempts + 1);
                            retry.push((over_spend, attempts + 1));
                        }
                        Err(e) => log::warn!("slash abandoned: {e}"),
                    }
                }
                pending = retry;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_and_words() {
        assert_eq!(
            selector("slash(uint256,uint256,uint256,address)"),
            [0xbd, 0xa8, 0x96, 0xf4]
        );
        assert_eq!(selector("limitOf(uint256)"), [0xd5, 0x7b, 0x50, 0xe7]);
        assert_eq!(word(&BigUint::from(8u32))[31], 8);
        assert_eq!(from_quantity("0x"), Some(BigUint::default()));
        assert_eq!(from_quantity("0x1a"), Some(BigUint::from(26u32)));
        assert_eq!(from_quantity("26"), None);
    }

    #[test]
    fn rlp_encodings() {
        let enc = |f: &dyn Fn(&mut Vec<u8>)| {
            let mut out = Vec::new();
            f(&mut out);
            out
        };
        assert_eq!(enc(&|o| rlp_uint(&BigUint::default(), o)), [0x80]);
        assert_eq!(enc(&|o| rlp_uint(&BigUint::from(0x7fu32), o)), [0x7f]);
        assert_eq!(enc(&|o| rlp_uint(&BigUint::from(0x80u32), o)), [0x81, 0x80]);
        assert_eq!(
            enc(&|o| rlp_uint(&BigUint::from(1024u32), o)),
            [0x82, 0x04, 0x00]
        );
        assert_eq!(enc(&|o| rlp_bytes(b"dog", o)), [0x83, b'd', b'o', b'g']);
        assert_eq!(enc(&|o| rlp_list(&[], o)), [0xc0]);
        let long = vec![7u8; 60];
        let encoded = enc(&|o| rlp_bytes(&long, o));
        assert_eq!(&encoded[..2], &[0xb8, 60]);
    }

    /// The well-known test key 0x01: its address, and that a signed transaction recovers to it.
    #[test]
    fn wallet_address_and_signature() {
        let mut secret = [0u8; 32];
        secret[31] = 1;
        let wallet = Wallet::from_secret(&secret).unwrap();
        assert_eq!(
            wallet.address_hex(),
            "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
        );
        let raw = wallet
            .sign(
                &BigUint::from(11_155_111u32),
                &BigUint::from(3u32),
                &BigUint::from(1_000_000_000u64),
                &BigUint::from(2_000_000_000u64),
                &BigUint::from(100_000u32),
                &[0x11; 20],
                &[1, 2, 3],
            )
            .unwrap();
        assert_eq!(raw[0], 0x02);
        // Re-derive the signing hash from the raw transaction's first nine fields and check
        // the signature recovers to the wallet.
        use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
        let body = &raw[3..]; // 0x02, 0xf8, len
        let sig_len = 1 + 33 + 33;
        let fields = &body[..body.len() - sig_len];
        let mut unsigned = vec![0x02];
        rlp_list(fields, &mut unsigned);
        let tail = &body[body.len() - sig_len..];
        let recovery = RecoveryId::from_byte(if tail[0] == 0x80 { 0 } else { tail[0] }).unwrap();
        let signature = Signature::from_slice(&[&tail[2..34], &tail[35..67]].concat()).unwrap();
        let recovered =
            VerifyingKey::recover_from_prehash(&keccak256(&unsigned), &signature, recovery)
                .unwrap();
        assert_eq!(recovered, *wallet.key.verifying_key());
    }

    #[test]
    fn root_ring_keeps_superseded_roots_for_one_window() {
        let t0 = Instant::now();
        let s = Duration::from_secs;
        let mut ring = RootRing::new(s(60));
        assert!(ring.roots(t0).is_empty());
        ring.observe(Some("a".into()), t0);
        assert_eq!(ring.roots(t0), vec!["a"]);
        ring.observe(Some("b".into()), t0 + s(20));
        assert_eq!(ring.roots(t0 + s(30)), vec!["b", "a"]);
        ring.observe(Some("b".into()), t0 + s(70));
        assert_eq!(ring.roots(t0 + s(81)), vec!["b"]);
        // An empty set contributes no root; a silent source contributes nothing at all.
        ring.observe(None, t0 + s(90));
        assert_eq!(ring.roots(t0 + s(91)), vec!["b"]);
        assert!(ring.roots(t0 + s(90 + 181)).is_empty());
    }
}
