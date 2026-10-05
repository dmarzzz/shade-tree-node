//! The staked-member lifecycle on chain: register (stake), read state, exit, withdraw.
//!
//! Everything signs locally with [`eth::Wallet`] and sends raw EIP-1559 transactions; the RPC never
//! sees a key or an identity secret. Exit and withdraw carry a zero-knowledge proof bound to a
//! context the contract recomputes (chain id, set address, leaf, leaf index, and for a withdrawal
//! the recipient), and the local context is checked against the contract's own view before
//! proving.
//!
//! Functions take an [`Rpc`] so tests can script the chain; [`HttpRpc`] is the real one.

use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::eth::{self, Address, Eip1559, Token, Wallet, U256};

const BN254_FIELD: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

/// JSON-RPC transport.
pub trait Rpc {
    fn call(&mut self, method: &str, params: Value) -> Result<Value, String>;
}

/// Blocking JSON-RPC over HTTP(S). Errors name the host, never the path (which often holds an
/// API key).
pub struct HttpRpc {
    client: reqwest::blocking::Client,
    url: String,
    label: String,
    timeout: Duration,
    id: u64,
}

impl HttpRpc {
    pub fn new(url: &str, timeout: Duration) -> Result<Self, String> {
        let parsed = reqwest::Url::parse(url)
            .map_err(|_| "RPC must be an absolute HTTP(S) URL".to_string())?;
        if !matches!(parsed.scheme(), "http" | "https") || parsed.host().is_none() {
            return Err("RPC must be an absolute HTTP(S) URL".into());
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|_| "build bounded RPC client".to_string())?;
        Ok(Self {
            client,
            url: url.to_string(),
            label: rpc_label(url),
            timeout,
            id: 0,
        })
    }
}

impl Rpc for HttpRpc {
    fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        self.id += 1;
        let response = self
            .client
            .post(&self.url)
            .json(&json!({"jsonrpc":"2.0","id":self.id,"method":method,"params":params}))
            .send()
            .map_err(|error| {
                if error.is_timeout() {
                    format!(
                        "{method}: RPC request timed out after {}ms at {}",
                        self.timeout.as_millis(),
                        self.label
                    )
                } else {
                    format!("{method}: RPC request failed at {}", self.label)
                }
            })?;
        if !response.status().is_success() {
            return Err(format!(
                "{method}: RPC HTTP {} at {}",
                response.status(),
                self.label
            ));
        }
        let body: Value = response
            .json()
            .map_err(|_| format!("{method}: malformed RPC JSON from {}", self.label))?;
        if let Some(error) = body.get("error") {
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("JSON-RPC error");
            return Err(format!("{method}: {message}"));
        }
        body.get("result")
            .cloned()
            .ok_or_else(|| format!("{method}: RPC response missing result"))
    }
}

/// `scheme://host[:port]` of an RPC URL, for messages.
pub fn rpc_label(value: &str) -> String {
    reqwest::Url::parse(value)
        .ok()
        .and_then(|url| {
            let host = url.host_str()?;
            Some(match url.port() {
                Some(port) => format!("{}://{host}:{port}", url.scheme()),
                None => format!("{}://{host}", url.scheme()),
            })
        })
        .unwrap_or_else(|| "[configured RPC]".into())
}

/// True for 127.0.0.1, localhost and ::1.
pub fn is_loopback_rpc(value: &str) -> bool {
    reqwest::Url::parse(value).ok().is_some_and(|url| {
        matches!(
            url.host_str()
                .map(|host| host.to_ascii_lowercase())
                .as_deref(),
            Some("127.0.0.1") | Some("localhost") | Some("::1") | Some("[::1]")
        )
    })
}

/// Parse an unsigned integer given in decimal or `0x` hex.
pub fn parse_uint(value: &str, label: &str) -> Result<U256, String> {
    let value = value.trim();
    let parsed = match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hex_part) => U256::from_quantity(&format!("0x{}", hex_part.trim_start_matches('0')))
            .or_else(|| hex_part.bytes().all(|b| b == b'0').then(U256::zero)),
        None => U256::from_dec_str(value),
    };
    parsed.ok_or_else(|| format!("{label} must be an unsigned decimal or 0x-hex integer"))
}

fn quantity(value: Value, what: &str) -> Result<U256, String> {
    let text = value
        .as_str()
        .ok_or_else(|| format!("{what}: expected a hex quantity"))?;
    parse_uint(text, what)
}

fn receipt_field(receipt: &Value, field: &str, hash: &str) -> Result<U256, String> {
    let value = receipt.get(field).cloned().ok_or_else(|| {
        format!("transaction receipt for {hash} has no {field}; check the hash before retrying")
    })?;
    quantity(value, field).map_err(|error| {
        format!(
            "transaction receipt for {hash} has an invalid {field} ({error}); check the hash before retrying"
        )
    })
}

fn field_modulus() -> U256 {
    U256::from_dec_str(BN254_FIELD).unwrap_or_default()
}

/// A staking set on one chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakingSet {
    pub contract: Address,
    pub rpc_url: String,
    /// Refuse to sign on any other chain.
    pub expected_chain_id: Option<u64>,
}

/// Knobs for sending transactions.
#[derive(Debug, Clone, Copy)]
pub struct SendOptions {
    /// How long to wait for one confirmation after broadcasting.
    pub receipt_timeout: Duration,
    /// Poll interval for the receipt.
    pub poll: Duration,
}

impl Default for SendOptions {
    fn default() -> Self {
        Self {
            receipt_timeout: Duration::from_secs(180),
            poll: Duration::from_secs(1),
        }
    }
}

/// Progress reported while a lifecycle call runs, so a CLI or UI can show it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    /// The bond the contract asks for this tier.
    Bond { wei: U256 },
    /// Building the exit or withdraw proof locally.
    Proving,
    /// Broadcast; waiting for one confirmation.
    Broadcast { hash: String },
}

/// A mined transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mined {
    pub hash: String,
    pub block: U256,
}

/// Verify the chain id and that the set has code.
pub fn check_chain<R: Rpc>(rpc: &mut R, set: &StakingSet) -> Result<u64, String> {
    let chain_id = quantity(rpc.call("eth_chainId", json!([]))?, "eth_chainId")?
        .as_u64()
        .filter(|id| *id > 0)
        .ok_or("eth_chainId returned an unsupported value")?;
    if let Some(expected) = set
        .expected_chain_id
        .filter(|expected| *expected != chain_id)
    {
        return Err(format!(
            "RPC chainId {chain_id} does not match configured chainId {expected}; refusing to continue"
        ));
    }
    let code = rpc.call("eth_getCode", json!([set.contract.to_string(), "latest"]))?;
    let has_code = code
        .as_str()
        .and_then(|value| value.strip_prefix("0x"))
        .is_some_and(|value| !value.is_empty() && value.bytes().any(|byte| byte != b'0'));
    if !has_code {
        return Err(format!(
            "no contract bytecode at {} on chainId {chain_id}",
            set.contract
        ));
    }
    Ok(chain_id)
}

fn eth_call<R: Rpc>(rpc: &mut R, to: Address, data: &[u8]) -> Result<Vec<u8>, String> {
    let result = rpc.call(
        "eth_call",
        json!([{"to": to.to_string(), "data": format!("0x{}", hex::encode(data))}, "latest"]),
    )?;
    let raw = result
        .as_str()
        .and_then(|value| value.strip_prefix("0x"))
        .ok_or_else(|| "eth_call: expected 0x-hex data".to_string())?;
    hex::decode(raw).map_err(|_| "eth_call: returned invalid hex data".to_string())
}

fn call_uint<R: Rpc>(rpc: &mut R, to: Address, data: &[u8]) -> Result<U256, String> {
    let raw = eth_call(rpc, to, data)?;
    Ok(eth::decode_uints(&raw, 1)?.remove(0))
}

/// A member's on-chain state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberState {
    pub bond: U256,
    pub index: U256,
    pub exit_initiated_at: U256,
    pub limit: U256,
    pub withdrawable_at: U256,
}

impl MemberState {
    /// `absent`, `active` or `exiting`.
    pub fn phase(&self) -> &'static str {
        if self.bond.is_zero() {
            "absent"
        } else if self.exit_initiated_at.is_zero() {
            "active"
        } else {
            "exiting"
        }
    }
}

/// Read `members(leaf)` and `withdrawableAt(leaf)`.
pub fn member_state<R: Rpc>(
    rpc: &mut R,
    set: &StakingSet,
    leaf: &U256,
) -> Result<MemberState, String> {
    let raw = eth_call(
        rpc,
        set.contract,
        &eth::calldata("members(uint256)", &[Token::Uint(leaf.clone())]),
    )?;
    let words = eth::decode_uints(&raw, 4)
        .map_err(|_| "members(): contract returned malformed state".to_string())?;
    let withdrawable_at = call_uint(
        rpc,
        set.contract,
        &eth::calldata("withdrawableAt(uint256)", &[Token::Uint(leaf.clone())]),
    )
    .map_err(|_| "withdrawableAt(): contract returned malformed state".to_string())?;
    let mut words = words.into_iter();
    Ok(MemberState {
        bond: words.next().unwrap_or_default(),
        index: words.next().unwrap_or_default(),
        exit_initiated_at: words.next().unwrap_or_default(),
        limit: words.next().unwrap_or_default(),
        withdrawable_at,
    })
}

/// Which authorization a proof carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Exit,
    Withdraw,
}

/// The context `StakedReputationSet.exitContext` / `withdrawContext` compute:
/// `keccak256(abi.encodePacked(tag, chainid, set, leaf, index[, recipient]))`.
pub fn action_context(
    action: Action,
    chain_id: u64,
    contract: Address,
    leaf: &U256,
    index: &U256,
    recipient: Option<Address>,
) -> [u8; 32] {
    let mut packed = match action {
        Action::Exit => b"SHADENET_EXIT".to_vec(),
        Action::Withdraw => b"SHADENET_WITHDRAW".to_vec(),
    };
    packed.extend(U256::from(chain_id).to_big_endian());
    packed.extend(contract.0);
    packed.extend(leaf.to_big_endian());
    packed.extend(index.to_big_endian());
    if let Some(recipient) = recipient {
        packed.extend(recipient.0);
    }
    eth::keccak256(&packed)
}

fn onchain_context<R: Rpc>(
    rpc: &mut R,
    set: &StakingSet,
    action: Action,
    leaf: &U256,
    recipient: Option<Address>,
) -> Result<[u8; 32], String> {
    let data = match action {
        Action::Exit => eth::calldata("exitContext(uint256)", &[Token::Uint(leaf.clone())]),
        Action::Withdraw => eth::calldata(
            "withdrawContext(uint256,address)",
            &[
                Token::Uint(leaf.clone()),
                Token::Address(recipient.unwrap_or_default()),
            ],
        ),
    };
    let raw = eth_call(rpc, set.contract, &data).map_err(|error| {
        format!("the staking set has no proof-context view; it predates the ShadeNet contracts ({error})")
    })?;
    <[u8; 32]>::try_from(raw.as_slice())
        .map_err(|_| "proof-context view returned malformed data".to_string())
}

/// `base * 2 + priority`, the usual EIP-1559 fee ceiling.
pub fn checked_fee(base: &U256, priority: &U256) -> Result<U256, String> {
    base.checked_mul(&U256::from(2))
        .and_then(|value| value.checked_add(priority))
        .ok_or_else(|| "RPC returned fees too large to encode".to_string())
}

/// Estimate, price, check balance, sign, broadcast, and wait for one confirmation.
#[allow(clippy::too_many_arguments)]
fn send_transaction<R: Rpc>(
    rpc: &mut R,
    wallet: &Wallet,
    chain_id: u64,
    to: Address,
    value: U256,
    data: Vec<u8>,
    simulate: bool,
    label: &str,
    options: SendOptions,
    progress: &mut dyn FnMut(Progress),
) -> Result<Mined, String> {
    let from = wallet.address.to_string();
    let call = json!({
        "from": from,
        "to": to.to_string(),
        "value": value.to_quantity(),
        "data": format!("0x{}", hex::encode(&data)),
    });
    if simulate {
        // Stale state and bad proofs fail here, before anything is signed.
        rpc.call("eth_call", json!([call.clone(), "latest"]))?;
    }
    let nonce = quantity(
        rpc.call("eth_getTransactionCount", json!([from, "pending"]))?,
        "eth_getTransactionCount",
    )?;
    let estimated = quantity(
        rpc.call("eth_estimateGas", json!([call]))?,
        "eth_estimateGas",
    )?;
    let gas = estimated
        .checked_mul(&U256::from(120))
        .and_then(|value| U256::from_big_endian(&(value.as_biguint() / 100u32).to_bytes_be()))
        .ok_or_else(|| "eth_estimateGas returned an unsupported value".to_string())?;
    let gas_price = quantity(rpc.call("eth_gasPrice", json!([]))?, "eth_gasPrice")?;
    let block = rpc.call("eth_getBlockByNumber", json!(["latest", false]))?;
    let base_fee = quantity(
        block.get("baseFeePerGas").cloned().ok_or_else(|| {
            "latest block has no baseFeePerGas; this signer requires EIP-1559".to_string()
        })?,
        "baseFeePerGas",
    )?;
    let priority = rpc
        .call("eth_maxPriorityFeePerGas", json!([]))
        .ok()
        .and_then(|value| quantity(value, "eth_maxPriorityFeePerGas").ok())
        // eth_gasPrice is normally base + suggested tip; keep that suggestion if the optional
        // method is missing instead of tipping the whole gas price.
        .or_else(|| {
            gas_price
                .checked_sub(&base_fee)
                .filter(|value| !value.is_zero())
        })
        .unwrap_or_else(|| gas_price.clone().min(U256::from(1_000_000_000)));
    let max_fee = checked_fee(&base_fee, &priority)?.max(gas_price);
    let balance = quantity(
        rpc.call("eth_getBalance", json!([from, "latest"]))?,
        "eth_getBalance",
    )?;
    let required = gas
        .checked_mul(&max_fee)
        .and_then(|fee| fee.checked_add(&value))
        .ok_or_else(|| format!("estimated {label} cost is too large to encode"))?;
    if balance < required {
        return Err(format!(
            "wallet {} balance {balance} wei is below the worst-case {label} cost {required} wei",
            wallet.address
        ));
    }
    let raw = wallet.sign(&Eip1559 {
        chain_id,
        nonce,
        max_priority_fee_per_gas: priority,
        max_fee_per_gas: max_fee,
        gas,
        to,
        value,
        data,
    })?;
    let local_hash = format!("0x{}", hex::encode(eth::keccak256(&raw)));
    let remote = rpc
        .call("eth_sendRawTransaction", json!([format!("0x{}", hex::encode(&raw))]))
        .map_err(|error| {
            format!(
                "broadcast result for locally signed {label} transaction {local_hash} is unknown ({error}); check the hash before retrying"
            )
        })?;
    let remote_hash = remote
        .as_str()
        .filter(|value| value.len() == 66 && value.starts_with("0x"))
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| {
            format!(
                "RPC returned an invalid hash; locally signed {label} transaction {local_hash} may have been broadcast, so check it before retrying"
            )
        })?;
    if remote_hash != local_hash {
        return Err(format!(
            "RPC returned {remote_hash}, but the locally signed {label} transaction is {local_hash}; check both before retrying"
        ));
    }
    progress(Progress::Broadcast {
        hash: local_hash.clone(),
    });
    let started = Instant::now();
    loop {
        let receipt = rpc
            .call("eth_getTransactionReceipt", json!([local_hash]))
            .map_err(|error| {
                format!(
                    "{label} transaction {local_hash} was broadcast, but its receipt could not be checked ({error}); check the hash before retrying"
                )
            })?;
        if receipt.is_null() {
            if started.elapsed() >= options.receipt_timeout {
                return Err(format!(
                    "{label} transaction {local_hash} was broadcast but did not reach 1 confirmation within {}ms; it may still confirm, so check the hash before retrying",
                    options.receipt_timeout.as_millis()
                ));
            }
            thread::sleep(options.poll);
            continue;
        }
        let status = receipt_field(&receipt, "status", &local_hash)?;
        let block = receipt_field(&receipt, "blockNumber", &local_hash)?;
        if status != U256::from(1) {
            return Err(format!(
                "{label} transaction {local_hash} reverted in block {block}"
            ));
        }
        return Ok(Mined {
            hash: local_hash,
            block,
        });
    }
}

// ------------------------------------------------------------------ identity

/// An identity checked for internal consistency: its leaf matches its secret and tier.
pub struct VerifiedIdentity {
    pub secret: zeroize::Zeroizing<String>,
    /// `Poseidon1(identitySecret)`, what `registerIdentity` takes.
    pub identity_commitment: U256,
    /// `Poseidon2(identityCommitment, limit)`, the leaf.
    pub leaf: U256,
    pub limit: u64,
}

impl std::fmt::Debug for VerifiedIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedIdentity")
            .field("secret", &"<redacted>")
            .field("leaf", &self.leaf)
            .field("limit", &self.limit)
            .finish_non_exhaustive()
    }
}

/// Check a loaded identity before any network use. `requested_limit` must agree with the file.
pub fn verify_identity(
    material: &crate::identity::IdentityMaterial,
    requested_limit: Option<u64>,
) -> Result<VerifiedIdentity, String> {
    let limit = match (material.limit, requested_limit) {
        (Some(file), Some(requested)) if file != requested => {
            return Err(format!(
                "identity tier {file} does not match requested tier {requested}"
            ));
        }
        (Some(file), _) => file,
        (None, Some(requested)) => requested,
        (None, None) => return Err(
            "identity file has no limit; pass --limit explicitly so a legacy tier is never guessed"
                .into(),
        ),
    };
    if !(1..=u64::from(u16::MAX)).contains(&limit) {
        return Err(format!("identity limit must be in 1..={}", u16::MAX));
    }
    if material.secret.is_empty() {
        return Err("identity is passphrase-protected; unlock it first".into());
    }
    let leaf = parse_uint(&material.leaf, "identity leaf")?;
    if leaf.is_zero() || leaf >= field_modulus() {
        return Err("identity leaf must be a non-zero BN254 field element".into());
    }
    let expected = shadenet_rln::identity::commitment_from_identity_secret(&material.secret, limit)
        .map_err(|error| format!("identity file is invalid ({error}; value not shown)"))?;
    if expected != material.leaf {
        return Err(
            "identity file leaf does not match its identitySecret and tier (secret not shown)"
                .into(),
        );
    }
    let identity_commitment = parse_uint(
        &shadenet_rln::identity::identity_commitment_from_identity_secret(&material.secret)
            .map_err(|error| format!("identity file is invalid ({error}; value not shown)"))?,
        "identity commitment",
    )?;
    Ok(VerifiedIdentity {
        secret: material.secret.clone(),
        identity_commitment,
        leaf,
        limit,
    })
}

/// The leaf the contract derives for an identity commitment at a tier.
pub fn leaf_for(identity_commitment: &U256, limit: u64) -> Result<U256, String> {
    if identity_commitment.is_zero() || *identity_commitment >= field_modulus() {
        return Err("identity commitment must be a non-zero BN254 field element".into());
    }
    parse_uint(
        &shadenet_rln::identity::rate_commitment_from_identity_commitment(
            &identity_commitment.to_string(),
            limit,
        )?,
        "leaf",
    )
}

// ------------------------------------------------------------------ register

/// What to stake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub identity_commitment: U256,
    pub leaf: U256,
    pub limit: u64,
    /// Refuse unless the contract's bond for the tier equals this.
    pub expected_bond: Option<U256>,
}

/// Result of [`register`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterOutcome {
    AlreadyActive,
    Mined(Mined),
}

/// Stake a leaf: `registerIdentity(identityCommitment, limit)` with the tier's bond.
pub fn register<R: Rpc>(
    rpc: &mut R,
    set: &StakingSet,
    registration: &Registration,
    wallet: &Wallet,
    options: SendOptions,
    progress: &mut dyn FnMut(Progress),
) -> Result<RegisterOutcome, String> {
    let chain_id = quantity(rpc.call("eth_chainId", json!([]))?, "eth_chainId")?
        .as_u64()
        .filter(|id| *id > 0)
        .ok_or("eth_chainId returned an unsupported value")?;
    if let Some(expected) = set
        .expected_chain_id
        .filter(|expected| *expected != chain_id)
    {
        return Err(format!(
            "staking RPC chainId {chain_id} does not match configured chainId {expected}; refusing to sign"
        ));
    }
    let bond = call_uint(
        rpc,
        set.contract,
        &eth::calldata(
            "bondFor(uint256)",
            &[Token::Uint(U256::from(registration.limit))],
        ),
    )
    .map_err(|error| {
        format!(
            "contract does not expose bondFor({}); it is not a ShadeNet staking set ({error})",
            registration.limit
        )
    })?;
    if bond.is_zero() {
        return Err(format!(
            "tier {} is not admitted by {} (bondFor returned zero)",
            registration.limit, set.contract
        ));
    }
    if let Some(expected) = registration
        .expected_bond
        .as_ref()
        .filter(|expected| **expected != bond)
    {
        return Err(format!(
            "configured bond {expected} does not equal the contract's tier-{} bond {bond}; refusing a transaction that would revert",
            registration.limit
        ));
    }
    let active = call_uint(
        rpc,
        set.contract,
        &eth::calldata(
            "isActive(uint256)",
            &[Token::Uint(registration.leaf.clone())],
        ),
    )?;
    if !active.is_zero() {
        return Ok(RegisterOutcome::AlreadyActive);
    }
    let existing = call_uint(
        rpc,
        set.contract,
        &eth::calldata(
            "limitOf(uint256)",
            &[Token::Uint(registration.leaf.clone())],
        ),
    )?;
    if !existing.is_zero() {
        return Err(
            "member exists but is exiting; withdraw the old bond before registering this identity commitment again"
                .into(),
        );
    }
    progress(Progress::Bond { wei: bond.clone() });
    let data = eth::calldata(
        "registerIdentity(uint256,uint256)",
        &[
            Token::Uint(registration.identity_commitment.clone()),
            Token::Uint(U256::from(registration.limit)),
        ],
    );
    send_transaction(
        rpc,
        wallet,
        chain_id,
        set.contract,
        bond,
        data,
        false,
        "member registration",
        options,
        progress,
    )
    .map(RegisterOutcome::Mined)
}

// ------------------------------------------------------------ exit / withdraw

/// Result of [`exit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitOutcome {
    /// Exit was already initiated; nothing sent.
    AlreadyExiting {
        withdrawable_at: U256,
    },
    Mined(Mined),
}

fn authorize<R: Rpc>(
    rpc: &mut R,
    set: &StakingSet,
    identity: &VerifiedIdentity,
    action: Action,
    recipient: Option<Address>,
    circuits_dir: Option<String>,
) -> Result<(u64, MemberState, Vec<u8>), String> {
    let chain_id = check_chain(rpc, set)?;
    let state = member_state(rpc, set, &identity.leaf)?;
    if state.bond.is_zero() {
        return Err(
            "leaf is not currently bonded (it may be absent, withdrawn, or slashed)".into(),
        );
    }
    if state.limit != U256::from(identity.limit) {
        return Err(format!(
            "on-chain tier {} does not match identity tier {}; refusing to prove",
            state.limit, identity.limit
        ));
    }
    let context = action_context(
        action,
        chain_id,
        set.contract,
        &identity.leaf,
        &state.index,
        recipient,
    );
    if onchain_context(rpc, set, action, &identity.leaf, recipient)? != context {
        return Err("the set's proof context differs from the local one; refusing to prove".into());
    }
    if circuits_dir.is_none() {
        shadenet_rln::artifacts::verify_withdraw_embedded().map_err(|e| e.to_string())?;
    }
    let proof =
        shadenet_rln::withdraw::build_withdraw_proof(&shadenet_rln::withdraw::WithdrawProofInput {
            identity_secret: identity.secret.to_string(),
            context,
            circuits_dir,
        })
        .map_err(|error| format!("could not build authorization proof: {error}"))?;
    Ok((chain_id, state, proof.proof_bytes))
}

/// Start unbonding: `initiateExit(leaf, proof)`, authorized by a local zero-knowledge proof.
pub fn exit<R: Rpc>(
    rpc: &mut R,
    set: &StakingSet,
    identity: &VerifiedIdentity,
    wallet: &Wallet,
    circuits_dir: Option<String>,
    options: SendOptions,
    progress: &mut dyn FnMut(Progress),
) -> Result<ExitOutcome, String> {
    check_chain(rpc, set)?;
    let state = member_state(rpc, set, &identity.leaf)?;
    if !state.bond.is_zero() && !state.exit_initiated_at.is_zero() {
        return Ok(ExitOutcome::AlreadyExiting {
            withdrawable_at: state.withdrawable_at,
        });
    }
    progress(Progress::Proving);
    let (chain_id, _, proof) = authorize(rpc, set, identity, Action::Exit, None, circuits_dir)?;
    let data = eth::calldata(
        "initiateExit(uint256,bytes)",
        &[Token::Uint(identity.leaf.clone()), Token::Bytes(proof)],
    );
    send_transaction(
        rpc,
        wallet,
        chain_id,
        set.contract,
        U256::zero(),
        data,
        true,
        "exit",
        options,
        progress,
    )
    .map(ExitOutcome::Mined)
}

/// Reclaim the bond after unbonding: `withdraw(leaf, recipient, proof)`. The proof binds the
/// recipient, so a relayer cannot redirect the funds.
#[allow(clippy::too_many_arguments)]
pub fn withdraw<R: Rpc>(
    rpc: &mut R,
    set: &StakingSet,
    identity: &VerifiedIdentity,
    recipient: Address,
    wallet: &Wallet,
    circuits_dir: Option<String>,
    options: SendOptions,
    progress: &mut dyn FnMut(Progress),
) -> Result<Mined, String> {
    if recipient == Address::default() {
        return Err("recipient must be a non-zero address".into());
    }
    check_chain(rpc, set)?;
    let state = member_state(rpc, set, &identity.leaf)?;
    if !state.bond.is_zero() && state.exit_initiated_at.is_zero() {
        return Err("exit has not been initiated; run exit-member first".into());
    }
    let block = rpc.call("eth_getBlockByNumber", json!(["latest", false]))?;
    let now = quantity(
        block
            .get("timestamp")
            .cloned()
            .ok_or_else(|| "latest block has no timestamp".to_string())?,
        "latest block timestamp",
    )?;
    if now < state.withdrawable_at {
        return Err(format!(
            "still bonded; chain time {now}, withdrawable at {}",
            state.withdrawable_at
        ));
    }
    progress(Progress::Proving);
    let (chain_id, _, proof) = authorize(
        rpc,
        set,
        identity,
        Action::Withdraw,
        Some(recipient),
        circuits_dir,
    )?;
    let data = eth::calldata(
        "withdraw(uint256,address,bytes)",
        &[
            Token::Uint(identity.leaf.clone()),
            Token::Address(recipient),
            Token::Bytes(proof),
        ],
    );
    send_transaction(
        rpc,
        wallet,
        chain_id,
        set.contract,
        U256::zero(),
        data,
        true,
        "withdrawal",
        options,
        progress,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};

    const ANVIL_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    fn hexsel(signature: &str) -> String {
        format!("0x{}", hex::encode(eth::selector(signature)))
    }

    struct MockRpc {
        calls: Arc<Mutex<Vec<(String, Value)>>>,
        active: bool,
        send_error: bool,
        chain_id: &'static str,
        sent_raw: Option<String>,
    }

    impl MockRpc {
        fn new(chain_id: &'static str) -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                active: false,
                send_error: false,
                chain_id,
                sent_raw: None,
            }
        }
    }

    impl Rpc for MockRpc {
        fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
            self.calls
                .lock()
                .unwrap()
                .push((method.to_string(), params.clone()));
            Ok(match method {
                "eth_chainId" => Value::String(self.chain_id.into()),
                "eth_getCode" => Value::String("0x6001600055".into()),
                "eth_call" => {
                    let data = params[0]["data"].as_str().unwrap_or_default();
                    let word = |value: u64| format!("{value:064x}");
                    if data.starts_with(&hexsel("bondFor(uint256)")) {
                        Value::String(format!("0x{}", word(100_000_000_000_000_000)))
                    } else if data.starts_with(&hexsel("isActive(uint256)")) {
                        Value::String(format!("0x{}", word(u64::from(self.active))))
                    } else if data.starts_with(&hexsel("limitOf(uint256)")) {
                        Value::String(format!("0x{}", word(0)))
                    } else if data.starts_with(&hexsel("members(uint256)")) {
                        Value::String(format!("0x{}{}{}{}", word(100), word(7), word(55), word(1)))
                    } else if data.starts_with(&hexsel("withdrawableAt(uint256)")) {
                        Value::String(format!("0x{}", word(86_455)))
                    } else {
                        Value::String("0x".into())
                    }
                }
                "eth_getTransactionCount" => Value::String("0x7".into()),
                "eth_estimateGas" => Value::String("0x186a0".into()),
                "eth_gasPrice" => Value::String("0x77359400".into()),
                "eth_maxPriorityFeePerGas" => Value::String("0x3b9aca00".into()),
                "eth_getBalance" => Value::String("0xde0b6b3a7640000".into()),
                "eth_getBlockByNumber" => {
                    json!({"baseFeePerGas":"0x3b9aca00","timestamp":"0x15180"})
                }
                "eth_sendRawTransaction" => {
                    let raw = params[0].as_str().unwrap().to_string();
                    assert!(raw.starts_with("0x02"), "must send an EIP-1559 transaction");
                    let hash = format!(
                        "0x{}",
                        hex::encode(eth::keccak256(&hex::decode(&raw[2..]).unwrap()))
                    );
                    self.sent_raw = Some(raw);
                    if self.send_error {
                        return Err("transport result unavailable".into());
                    }
                    Value::String(hash)
                }
                "eth_getTransactionReceipt" => json!({"status":"0x1","blockNumber":"0x2a"}),
                _ => panic!("unexpected method {method}"),
            })
        }
    }

    fn set() -> StakingSet {
        StakingSet {
            contract: Address::from_str("0x1111111111111111111111111111111111111111").unwrap(),
            rpc_url: "https://rpc.example/secret-api-key".into(),
            expected_chain_id: Some(11_155_111),
        }
    }

    fn registration() -> Registration {
        let identity_commitment = U256::from(123);
        Registration {
            leaf: leaf_for(&identity_commitment, 8).unwrap(),
            identity_commitment,
            limit: 8,
            expected_bond: None,
        }
    }

    fn fast() -> SendOptions {
        SendOptions {
            receipt_timeout: Duration::from_secs(5),
            poll: Duration::from_millis(10),
        }
    }

    #[test]
    fn registration_signs_locally_and_waits_for_success() {
        let mut rpc = MockRpc::new("0xaa36a7");
        let wallet = Wallet::from_hex(ANVIL_KEY).unwrap();
        let mut events = Vec::new();
        let outcome = register(
            &mut rpc,
            &set(),
            &registration(),
            &wallet,
            fast(),
            &mut |p| events.push(p),
        )
        .unwrap();
        assert!(
            matches!(outcome, RegisterOutcome::Mined(Mined { ref block, .. }) if *block == U256::from(42))
        );
        assert_eq!(
            events[0],
            Progress::Bond {
                wei: U256::from(100_000_000_000_000_000)
            }
        );
        assert!(matches!(events[1], Progress::Broadcast { .. }));
        let raw = rpc.sent_raw.clone().unwrap();
        assert!(!raw.contains(ANVIL_KEY.trim_start_matches("0x")));
        let calls = rpc.calls.lock().unwrap();
        let estimate = calls.iter().find(|(m, _)| m == "eth_estimateGas").unwrap();
        assert_eq!(
            &estimate.1[0]["data"].as_str().unwrap()[..10],
            hexsel("registerIdentity(uint256,uint256)")
        );
        assert_eq!(estimate.1[0]["value"], "0x16345785d8a0000");
    }

    #[test]
    fn already_active_never_signs() {
        let mut rpc = MockRpc::new("0xaa36a7");
        rpc.active = true;
        let wallet = Wallet::from_hex(ANVIL_KEY).unwrap();
        assert_eq!(
            register(
                &mut rpc,
                &set(),
                &registration(),
                &wallet,
                fast(),
                &mut |_| {}
            )
            .unwrap(),
            RegisterOutcome::AlreadyActive
        );
        assert!(rpc.sent_raw.is_none());
    }

    #[test]
    fn uncertain_broadcast_keeps_the_local_hash() {
        let mut rpc = MockRpc::new("0xaa36a7");
        rpc.send_error = true;
        let wallet = Wallet::from_hex(ANVIL_KEY).unwrap();
        let error = register(
            &mut rpc,
            &set(),
            &registration(),
            &wallet,
            fast(),
            &mut |_| {},
        )
        .unwrap_err();
        assert!(error.contains("transaction 0x"), "{error}");
        assert!(error.contains("check the hash before retrying"));
    }

    #[test]
    fn wrong_chain_is_refused_before_anything_else() {
        let mut rpc = MockRpc::new("0x1");
        let wallet = Wallet::from_hex(ANVIL_KEY).unwrap();
        let error = register(
            &mut rpc,
            &set(),
            &registration(),
            &wallet,
            fast(),
            &mut |_| {},
        )
        .unwrap_err();
        assert!(error.contains("chainId 1 does not match configured chainId 11155111"));
        assert_eq!(rpc.calls.lock().unwrap().len(), 1);
        let mut rpc = MockRpc::new("0x1");
        assert!(check_chain(&mut rpc, &set())
            .unwrap_err()
            .contains("does not match"));
    }

    #[test]
    fn member_state_is_read_and_phased() {
        let mut rpc = MockRpc::new("0xaa36a7");
        let state = member_state(&mut rpc, &set(), &U256::from(123)).unwrap();
        assert_eq!(state.phase(), "exiting");
        assert_eq!(state.bond, U256::from(100));
        assert_eq!(state.limit, U256::from(1));
        assert_eq!(state.withdrawable_at, U256::from(86_455));
        let absent = MemberState {
            bond: U256::zero(),
            index: U256::zero(),
            exit_initiated_at: U256::zero(),
            limit: U256::zero(),
            withdrawable_at: U256::zero(),
        };
        assert_eq!(absent.phase(), "absent");
    }

    #[test]
    fn lifecycle_sends_simulate_first() {
        let mut rpc = MockRpc::new("0xaa36a7");
        let wallet = Wallet::from_hex(ANVIL_KEY).unwrap();
        let data = eth::calldata(
            "initiateExit(uint256,bytes)",
            &[Token::Uint(U256::from(123)), Token::Bytes(vec![9; 288])],
        );
        let selector = format!("0x{}", hex::encode(&data[..4]));
        let mined = send_transaction(
            &mut rpc,
            &wallet,
            11_155_111,
            set().contract,
            U256::zero(),
            data,
            true,
            "exit",
            fast(),
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(mined.block, U256::from(42));
        let calls = rpc.calls.lock().unwrap();
        let first_call = calls.iter().position(|(m, p)| {
            m == "eth_call"
                && p[0]["data"]
                    .as_str()
                    .is_some_and(|d| d.starts_with(&selector))
        });
        let first_send = calls
            .iter()
            .position(|(m, _)| m == "eth_sendRawTransaction");
        assert!(first_call.unwrap() < first_send.unwrap());
    }

    #[test]
    fn action_context_matches_the_solidity_fixture() {
        let fixture: Value =
            serde_json::from_str(include_str!("../../../testdata/withdraw-proof.json")).unwrap();
        let chain_id = fixture["chainId"].as_u64().unwrap();
        let contract = Address::from_str(fixture["set"].as_str().unwrap()).unwrap();
        let leaf = U256::from_dec_str(fixture["commitment"].as_str().unwrap()).unwrap();
        let index = U256::from(fixture["index"].as_u64().unwrap());
        let recipient = Address::from_str(fixture["recipient"].as_str().unwrap()).unwrap();
        let hex32 = |value: &Value| {
            let bytes = hex::decode(value.as_str().unwrap().trim_start_matches("0x")).unwrap();
            <[u8; 32]>::try_from(bytes.as_slice()).unwrap()
        };
        assert_eq!(
            action_context(Action::Exit, chain_id, contract, &leaf, &index, None),
            hex32(&fixture["exit"]["context"])
        );
        assert_eq!(
            action_context(
                Action::Withdraw,
                chain_id,
                contract,
                &leaf,
                &index,
                Some(recipient)
            ),
            hex32(&fixture["withdraw"]["context"])
        );
        let base = action_context(Action::Exit, chain_id, contract, &leaf, &index, None);
        assert_ne!(
            base,
            action_context(Action::Exit, 1, contract, &leaf, &index, None)
        );
        assert_ne!(
            base,
            action_context(
                Action::Exit,
                chain_id,
                contract,
                &leaf,
                &U256::from(1),
                None
            )
        );
    }

    #[test]
    fn identities_are_verified_before_network_use() {
        let material =
            shadenet_rln::identity::derive_identity(&format!("0x{}", "5a".repeat(32)), 1).unwrap();
        let loaded = crate::identity::IdentityMaterial {
            secret: zeroize::Zeroizing::new(material.identity_secret.clone()),
            leaf: material.leaf.clone(),
            limit: Some(1),
        };
        let verified = verify_identity(&loaded, None).unwrap();
        assert_eq!(verified.leaf.to_string(), material.leaf);
        assert_eq!(
            leaf_for(&verified.identity_commitment, 1).unwrap(),
            verified.leaf
        );
        assert!(verify_identity(&loaded, Some(8))
            .unwrap_err()
            .contains("does not match"));
        let wrong = crate::identity::IdentityMaterial {
            leaf: "1".into(),
            ..loaded
        };
        assert!(verify_identity(&wrong, None)
            .unwrap_err()
            .contains("does not match"));
    }

    #[test]
    fn rpc_labels_hide_paths_and_loopback_is_recognized() {
        assert_eq!(
            rpc_label("https://rpc.example/secret-key?x=1"),
            "https://rpc.example"
        );
        assert!(is_loopback_rpc("http://[::1]:8545"));
        assert!(!is_loopback_rpc("https://rpc.example"));
        assert_eq!(parse_uint("0x10", "x").unwrap(), U256::from(16));
        assert_eq!(parse_uint("0x0", "x").unwrap(), U256::zero());
        assert!(parse_uint("-1", "x").is_err());
    }
}
