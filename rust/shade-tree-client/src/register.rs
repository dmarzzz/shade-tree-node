//! Native, Node-free member staking for the Rust client.
//!
//! The funding key is loaded from an owner-only file or an environment variable,
//! signs an EIP-1559 transaction locally, and is never sent to the RPC. The public
//! Sepolia contract and RPC come from the same bundled deployment record as default
//! Elder discovery; explicit CLI/environment values always win.

use ethers_core::abi::{encode, Token};
use ethers_core::k256::ecdsa::{
    signature::hazmat::PrehashSigner, RecoveryId, Signature as RecoverableSignature, SigningKey,
};
use ethers_core::k256::elliptic_curve::zeroize::Zeroize;
use ethers_core::types::{
    transaction::eip2718::TypedTransaction, Address, Bytes, Eip1559TransactionRequest,
    NameOrAddress, Signature, U256, U64,
};
use ethers_core::utils::{id, keccak256, secret_key_to_address};
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs;
use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

const DEFAULT_LIMIT: u64 = 8;
const DEFAULT_RPC_TIMEOUT_MS: u64 = 15_000;
const DEFAULT_RECEIPT_TIMEOUT_MS: u64 = 180_000;
const BN254_FIELD: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";
const ANVIL_KEY_0: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const HELP: &str = r#"shade-tree register-member — stake a public member leaf

usage: shade-tree register-member <commitment> [--limit N]
       shade-tree register-member --identity identity.json
       [--contract 0xaddress] [--rpc-url https://...]
       [--key-file <owner-only-file>]

--identity reads the public leaf and exact tier from a Rust-compatible identity
file, verifies that they match its private identitySecret, and never logs the
secret. It cannot be combined with a positional commitment. The funding key is
read from --key-file or SHADE_TREE_REGISTER_KEY and signs
locally; it is never accepted as an argument or sent to the RPC. Without an
explicit contract/RPC, the bundled live Sepolia Grove staking profile is used.
SHADE_TREE_GROUP_CONTRACT, SHADE_TREE_RPC_URL, SHADE_TREE_LIMIT, and
SHADE_TREE_BOND are the environment equivalents. SHADE_TREE_CHAIN_ID overrides
the expected chain; the bundled public contract is pinned to Sepolia. A public Anvil development key
is selected only for a loopback RPC. The default tier is the bundled staked
root's defaultLimit (1 for the public Grove)."#;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CliOptions {
    commitment: Option<String>,
    limit: Option<String>,
    contract: Option<String>,
    rpc_url: Option<String>,
    key_file: Option<PathBuf>,
    identity: Option<PathBuf>,
    bond: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityInput {
    #[serde(rename = "identitySecret")]
    identity_secret: String,
    leaf: String,
    limit: Option<u64>,
}

#[derive(Debug, Clone)]
struct Registration {
    commitment: U256,
    limit: u64,
    contract: Address,
    rpc_url: String,
    expected_chain_id: Option<u64>,
    bond_override: Option<U256>,
}

pub(crate) struct FundingWallet {
    signer: SigningKey,
    pub(crate) address: Address,
}

impl FundingWallet {
    pub(crate) fn from_key(value: &str) -> Result<Self, String> {
        let normalized = value.trim().strip_prefix("0x").unwrap_or(value.trim());
        if normalized.len() != 64 || hex::decode(normalized).map_or(true, |bytes| bytes.len() != 32)
        {
            return Err("funding key is not a 32-byte hex private key (value not shown)".into());
        }
        let mut bytes = [0_u8; 32];
        if hex::decode_to_slice(normalized, &mut bytes).is_err() {
            bytes.zeroize();
            return Err("funding key is not valid hex (value not shown)".into());
        }
        let signer_result = SigningKey::from_slice(&bytes).map_err(|_| {
            "funding key is not a valid secp256k1 private key (value not shown)".to_string()
        });
        bytes.zeroize();
        let signer = signer_result?;
        let address = secret_key_to_address(&signer);
        Ok(Self { signer, address })
    }

    pub(crate) fn sign(&self, transaction: &TypedTransaction) -> Result<Signature, String> {
        let (signature, recovery): (RecoverableSignature, RecoveryId) = self
            .signer
            .sign_prehash(transaction.sighash().as_bytes())
            .map_err(|_| "could not sign member transaction".to_string())?;
        let bytes = signature.to_bytes();
        Ok(Signature {
            r: U256::from_big_endian(&bytes[..32]),
            s: U256::from_big_endian(&bytes[32..]),
            // EIP-1559 serializes yParity as 0/1; TypedTransaction::rlp_signed
            // accepts that normalized form directly.
            v: u64::from(u8::from(recovery)),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SendOutcome {
    AlreadyActive,
    Mined { hash: String, block: U256 },
}

fn value_for(args: &[String], index: &mut usize, name: &str) -> Result<String, String> {
    if let Some(value) = args[*index].strip_prefix(&format!("{name}=")) {
        if value.is_empty() {
            return Err(format!("{name} needs a value"));
        }
        return Ok(value.to_string());
    }
    *index += 1;
    args.get(*index)
        .filter(|value| !value.starts_with("--"))
        .cloned()
        .ok_or_else(|| format!("{name} needs a value"))
}

fn parse_args(args: &[String]) -> Result<Option<CliOptions>, String> {
    let mut out = CliOptions::default();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--help" || arg == "-h" {
            return Ok(None);
        }
        let matched = [
            "--limit",
            "--contract",
            "--group-contract",
            "--rpc-url",
            "--key-file",
            "--identity",
            "--bond",
        ]
        .iter()
        .find(|name| arg == **name || arg.starts_with(&format!("{name}=")))
        .copied();
        if let Some(name) = matched {
            let value = value_for(args, &mut index, name)?;
            match name {
                "--limit" => {
                    if out.limit.replace(value).is_some() {
                        return Err("pass --limit only once".into());
                    }
                }
                "--contract" | "--group-contract" => {
                    if out.contract.replace(value).is_some() {
                        return Err("pass only one of --contract/--group-contract".into());
                    }
                }
                "--rpc-url" => {
                    if out.rpc_url.replace(value).is_some() {
                        return Err("pass --rpc-url only once".into());
                    }
                }
                "--key-file" => {
                    if out.key_file.replace(PathBuf::from(value)).is_some() {
                        return Err("pass --key-file only once".into());
                    }
                }
                "--identity" => {
                    if out.identity.replace(PathBuf::from(value)).is_some() {
                        return Err("pass --identity only once".into());
                    }
                }
                "--bond" => {
                    if out.bond.replace(value).is_some() {
                        return Err("pass --bond only once".into());
                    }
                }
                _ => unreachable!(),
            }
        } else if arg.starts_with("--") {
            return Err(format!("unexpected argument {arg}"));
        } else if out.commitment.replace(arg.clone()).is_some() {
            return Err("register-member accepts exactly one commitment".into());
        }
        index += 1;
    }
    if out.identity.is_some() && out.commitment.is_some() {
        return Err("pass either a positional commitment or --identity, not both".into());
    }
    Ok(Some(out))
}

#[cfg(test)]
pub(crate) fn registration_defaults_from(
    deployment: crate::BundledDeployment,
) -> Result<(String, String, u64, Option<u64>), String> {
    let default_limit = crate::staked_default_limit_from(&deployment)?;
    let staked = deployment
        .staked
        .ok_or_else(|| "bundled deployment has no live staked admission root".to_string())?;
    Ok((
        staked.contract,
        staked.rpc_url,
        default_limit,
        staked.chain_id,
    ))
}

pub(crate) fn bundled_defaults() -> Result<(String, String, u64, Option<u64>), String> {
    let profile = crate::default_public_profile()?;
    Ok((
        profile.contract,
        profile.rpc_url,
        profile.default_limit,
        Some(profile.chain_id),
    ))
}

fn parse_u256(value: &str, label: &str) -> Result<U256, String> {
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        U256::from_str_radix(hex, 16)
            .map_err(|_| format!("{label} must be an unsigned decimal or 0x-hex integer"))
    } else {
        U256::from_dec_str(value)
            .map_err(|_| format!("{label} must be an unsigned decimal or 0x-hex integer"))
    }
}

fn first_contract(value: &str) -> &str {
    value.split(',').next().unwrap_or_default().trim()
}

fn read_commitment(cli: &CliOptions) -> Result<String, String> {
    if let Some(value) = &cli.commitment {
        return Ok(value.clone());
    }
    if io::stdin().is_terminal() {
        return Err("missing commitment (or pipe one on stdin)".into());
    }
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(|e| format!("read commitment from stdin: {e}"))?;
    input
        .split_whitespace()
        .next()
        .map(str::to_string)
        .ok_or_else(|| "missing commitment (stdin was empty)".to_string())
}

fn read_identity(path: &Path) -> Result<IdentityInput, String> {
    let metadata =
        fs::metadata(path).map_err(|e| format!("read identity {}: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("identity {} is not a file", path.display()));
    }
    if metadata.len() > 16 * 1024 {
        return Err(format!("identity {} exceeds 16 KiB", path.display()));
    }
    let bytes =
        fs::read_to_string(path).map_err(|e| format!("read identity {}: {e}", path.display()))?;
    serde_json::from_str(&bytes).map_err(|_| {
        format!(
            "identity {} is not valid Shade Tree identity JSON",
            path.display()
        )
    })
}

pub(crate) struct VerifiedIdentity {
    pub(crate) identity_secret: String,
    pub(crate) commitment: U256,
    pub(crate) limit: u64,
}

pub(crate) fn verified_identity(
    path: &Path,
    requested_limit: Option<u64>,
) -> Result<VerifiedIdentity, String> {
    let identity = read_identity(path)?;
    let limit = match (identity.limit, requested_limit) {
        (Some(file), Some(requested)) if file != requested => {
            return Err(format!(
                "identity tier {file} does not match requested tier {requested}"
            ));
        }
        (Some(file), _) => file,
        (None, Some(requested)) => requested,
        (None, None) => {
            return Err(
                "identity file has no limit; pass --limit explicitly so a legacy tier is never guessed"
                    .into(),
            );
        }
    };
    if !(1..=u16::MAX as u64).contains(&limit) {
        return Err(format!("identity limit must be in 1..={}", u16::MAX));
    }
    let commitment = parse_u256(&identity.leaf, "identity leaf")?;
    let field = U256::from_dec_str(BN254_FIELD).expect("BN254 field constant");
    if commitment.is_zero() || commitment >= field {
        return Err("identity leaf must be a non-zero BN254 field element".into());
    }
    let expected =
        shade_tree_rln::identity::commitment_from_identity_secret(&identity.identity_secret, limit)
            .map_err(|error| format!("identity file is invalid ({error}; value not shown)"))?;
    if expected != identity.leaf {
        return Err(
            "identity file leaf does not match its identitySecret and tier (secret not shown)"
                .into(),
        );
    }
    Ok(VerifiedIdentity {
        identity_secret: identity.identity_secret,
        commitment,
        limit,
    })
}

fn resolve_registration(cli: &CliOptions) -> Result<Registration, String> {
    let (bundled_contract, bundled_rpc, bundled_limit, bundled_chain_id) = bundled_defaults()?;
    let requested_limit = cli
        .limit
        .clone()
        .or_else(|| std::env::var("SHADE_TREE_LIMIT").ok())
        .map(|value| {
            value
                .parse::<u64>()
                .ok()
                .filter(|limit| (1..=u16::MAX as u64).contains(limit))
                .ok_or_else(|| format!("--limit must be in 1..={}", u16::MAX))
        })
        .transpose()?;
    let verified = cli
        .identity
        .as_deref()
        .map(|path| verified_identity(path, requested_limit))
        .transpose()?;
    let commitment_raw = verified
        .as_ref()
        .map(|identity| identity.commitment.to_string())
        .map(Ok)
        .unwrap_or_else(|| read_commitment(cli))?;
    let commitment = parse_u256(&commitment_raw, "commitment")?;
    let field = U256::from_dec_str(BN254_FIELD).expect("BN254 field constant");
    if commitment.is_zero() || commitment >= field {
        return Err("commitment must be a non-zero BN254 field element".into());
    }
    let limit = verified
        .as_ref()
        .map(|identity| identity.limit)
        .or(requested_limit)
        .unwrap_or(bundled_limit);
    let bundled_address = Address::from_str(first_contract(&bundled_contract)).ok();
    let contract_raw = cli
        .contract
        .clone()
        .or_else(|| std::env::var("SHADE_TREE_GROUP_CONTRACT").ok())
        .unwrap_or(bundled_contract);
    let contract = Address::from_str(first_contract(&contract_raw))
        .map_err(|_| "staking contract is not a 20-byte Ethereum address".to_string())?;
    let rpc_url = cli
        .rpc_url
        .clone()
        .or_else(|| std::env::var("SHADE_TREE_RPC_URL").ok())
        .unwrap_or(bundled_rpc);
    let parsed_url = reqwest::Url::parse(&rpc_url)
        .map_err(|_| "staking RPC must be an absolute HTTP(S) URL".to_string())?;
    if !matches!(parsed_url.scheme(), "http" | "https") || parsed_url.host().is_none() {
        return Err("staking RPC must be an absolute HTTP(S) URL".into());
    }
    let bond_override = cli
        .bond
        .clone()
        .or_else(|| std::env::var("SHADE_TREE_BOND").ok())
        .map(|value| parse_u256(&value, "bond"))
        .transpose()?;
    let expected_chain_id = match std::env::var("SHADE_TREE_CHAIN_ID").ok() {
        Some(value) if !value.trim().is_empty() => Some(
            value
                .parse::<u64>()
                .ok()
                .filter(|chain_id| *chain_id > 0)
                .ok_or_else(|| "SHADE_TREE_CHAIN_ID must be a positive integer".to_string())?,
        ),
        _ if bundled_address == Some(contract) => bundled_chain_id,
        _ => None,
    };
    Ok(Registration {
        commitment,
        limit,
        contract,
        rpc_url,
        expected_chain_id,
        bond_override,
    })
}

fn loopback_rpc(value: &str) -> bool {
    reqwest::Url::parse(value).ok().is_some_and(|url| {
        matches!(
            url.host_str()
                .map(|host| host.to_ascii_lowercase())
                .as_deref(),
            Some("127.0.0.1") | Some("localhost") | Some("::1") | Some("[::1]")
        )
    })
}

pub(crate) fn key_file(path: &Path) -> Result<String, String> {
    let metadata =
        fs::metadata(path).map_err(|e| format!("read funding key {}: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("funding key {} is not a file", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "funding key {} must be owner-only (chmod 600; current mode {mode:o})",
                path.display()
            ));
        }
    }
    fs::read_to_string(path)
        .map(|value| value.trim().to_string())
        .map_err(|e| format!("read funding key {}: {e}", path.display()))
}

fn wallet_for(cli: &CliOptions, rpc_url: &str) -> Result<FundingWallet, String> {
    let mut key = if let Some(path) = &cli.key_file {
        key_file(path)?
    } else if let Ok(key) = std::env::var("SHADE_TREE_REGISTER_KEY") {
        if key.trim().is_empty() {
            return Err("SHADE_TREE_REGISTER_KEY is empty".into());
        }
        key
    } else if loopback_rpc(rpc_url) {
        ANVIL_KEY_0.to_string()
    } else {
        return Err(
            "member registration on a non-loopback RPC needs --key-file or SHADE_TREE_REGISTER_KEY; the public Anvil key is never used remotely"
                .into(),
        );
    };
    let wallet = FundingWallet::from_key(&key);
    key.zeroize();
    wallet
}

pub(crate) fn rpc_timeout_ms() -> u64 {
    std::env::var("SHADE_TREE_RPC_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_RPC_TIMEOUT_MS)
}

pub(crate) fn receipt_timeout_ms() -> u64 {
    std::env::var("SHADE_TREE_TX_RECEIPT_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_RECEIPT_TIMEOUT_MS)
}

pub(crate) fn rpc_label(value: &str) -> String {
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

pub(crate) trait RpcCall {
    fn call(&mut self, method: &str, params: Value) -> Result<Value, String>;
}

pub(crate) struct HttpRpc {
    client: reqwest::blocking::Client,
    url: String,
    label: String,
    id: u64,
}

impl HttpRpc {
    pub(crate) fn new(url: &str) -> Result<Self, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(rpc_timeout_ms()))
            .build()
            .map_err(|_| "build bounded staking RPC client".to_string())?;
        Ok(Self {
            client,
            url: url.to_string(),
            label: rpc_label(url),
            id: 0,
        })
    }
}

impl RpcCall for HttpRpc {
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
                        rpc_timeout_ms(),
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

fn calldata(signature: &str, tokens: Vec<Token>) -> Bytes {
    let mut bytes = id(signature)[..4].to_vec();
    bytes.extend(encode(&tokens));
    bytes.into()
}

pub(crate) fn hex_quantity(value: U256) -> String {
    format!("{value:#x}")
}

pub(crate) fn result_quantity(value: Value, method: &str) -> Result<U256, String> {
    let value = value
        .as_str()
        .ok_or_else(|| format!("{method}: expected a hex quantity"))?;
    parse_u256(value, method)
}

pub(crate) fn receipt_quantity(receipt: &Value, field: &str, hash: &str) -> Result<U256, String> {
    let value = receipt.get(field).cloned().ok_or_else(|| {
        format!("transaction receipt for {hash} has no {field}; check the hash before retrying")
    })?;
    result_quantity(value, field).map_err(|error| {
        format!(
            "transaction receipt for {hash} has an invalid {field} ({error}); check the hash before retrying"
        )
    })
}

fn eth_call<R: RpcCall>(rpc: &mut R, contract: Address, data: &Bytes) -> Result<U256, String> {
    let result = rpc.call(
        "eth_call",
        json!([{"to": format!("{contract:#x}"), "data": format!("0x{}", hex::encode(data))}, "latest"]),
    )?;
    result_quantity(result, "eth_call result")
}

fn tier_bond<R: RpcCall>(rpc: &mut R, registration: &Registration) -> Result<(U256, bool), String> {
    let tier_call = calldata(
        "bondFor(uint256)",
        vec![Token::Uint(registration.limit.into())],
    );
    match eth_call(rpc, registration.contract, &tier_call) {
        Ok(bond) if bond.is_zero() => Err(format!(
            "tier {} is not admitted by {:#x} (bondFor returned zero)",
            registration.limit, registration.contract
        )),
        Ok(bond) => Ok((bond, true)),
        Err(tier_error) if registration.limit == DEFAULT_LIMIT => {
            let legacy = calldata("BOND()", vec![]);
            eth_call(rpc, registration.contract, &legacy)
                .map(|bond| (bond, false))
                .map_err(|legacy_error| {
                    format!("could not read tier bond ({tier_error}); legacy BOND() also failed ({legacy_error})")
                })
        }
        Err(error) => Err(format!(
            "contract does not expose bondFor({}); only tier {} is compatible with a legacy set ({error})",
            registration.limit, DEFAULT_LIMIT
        )),
    }
}

fn is_active<R: RpcCall>(rpc: &mut R, registration: &Registration) -> Result<bool, String> {
    let call = calldata(
        "isActive(uint256)",
        vec![Token::Uint(registration.commitment)],
    );
    eth_call(rpc, registration.contract, &call).map(|value| !value.is_zero())
}

fn existing_limit<R: RpcCall>(rpc: &mut R, registration: &Registration) -> Result<U256, String> {
    let call = calldata(
        "limitOf(uint256)",
        vec![Token::Uint(registration.commitment)],
    );
    eth_call(rpc, registration.contract, &call)
}

pub(crate) fn checked_fee(base: U256, priority: U256) -> Result<U256, String> {
    base.checked_mul(U256::from(2))
        .and_then(|value| value.checked_add(priority))
        .ok_or_else(|| "RPC returned fees too large to encode".to_string())
}

fn send<R, B, S>(
    rpc: &mut R,
    registration: &Registration,
    wallet: &FundingWallet,
    mut before_send: B,
    mut broadcast: S,
) -> Result<SendOutcome, String>
where
    R: RpcCall,
    B: FnMut(U256, bool),
    S: FnMut(&str),
{
    let chain_id = result_quantity(rpc.call("eth_chainId", json!([]))?, "eth_chainId")?;
    if chain_id.is_zero() || chain_id > U256::from(u64::MAX) {
        return Err("eth_chainId returned an unsupported value".into());
    }
    if registration
        .expected_chain_id
        .is_some_and(|expected| chain_id.as_u64() != expected)
    {
        return Err(format!(
            "staking RPC chainId {} does not match configured chainId {}; refusing to sign",
            chain_id,
            registration.expected_chain_id.unwrap()
        ));
    }
    let (contract_bond, tiered) = tier_bond(rpc, registration)?;
    let bond = registration.bond_override.unwrap_or(contract_bond);
    if bond != contract_bond {
        return Err(format!(
            "configured bond {bond} does not equal the contract's tier-{} bond {contract_bond}; refusing a transaction that would revert",
            registration.limit
        ));
    }
    if is_active(rpc, registration)? {
        return Ok(SendOutcome::AlreadyActive);
    }
    if tiered && !existing_limit(rpc, registration)?.is_zero() {
        return Err(
            "member exists but is exiting; withdraw the old bond before registering this leaf again"
                .into(),
        );
    }
    let data = if tiered {
        calldata(
            "register(uint256,uint256)",
            vec![
                Token::Uint(registration.commitment),
                Token::Uint(registration.limit.into()),
            ],
        )
    } else {
        calldata(
            "register(uint256)",
            vec![Token::Uint(registration.commitment)],
        )
    };
    before_send(bond, tiered);

    let from = wallet.address;
    let call = json!({
        "from": format!("{from:#x}"),
        "to": format!("{:#x}", registration.contract),
        "value": hex_quantity(bond),
        "data": format!("0x{}", hex::encode(&data)),
    });
    let nonce = result_quantity(
        rpc.call(
            "eth_getTransactionCount",
            json!([format!("{from:#x}"), "pending"]),
        )?,
        "eth_getTransactionCount",
    )?;
    let estimated = result_quantity(
        rpc.call("eth_estimateGas", json!([call]))?,
        "eth_estimateGas",
    )?;
    let gas = estimated
        .checked_mul(U256::from(120))
        .map(|value| value / U256::from(100))
        .ok_or_else(|| "eth_estimateGas returned an unsupported value".to_string())?;
    let gas_price = result_quantity(rpc.call("eth_gasPrice", json!([]))?, "eth_gasPrice")?;
    let block = rpc.call("eth_getBlockByNumber", json!(["latest", false]))?;
    let base_fee = block
        .get("baseFeePerGas")
        .cloned()
        .ok_or_else(|| {
            "latest block has no baseFeePerGas; this signer requires EIP-1559".to_string()
        })
        .and_then(|value| result_quantity(value, "baseFeePerGas"))?;
    let priority = rpc
        .call("eth_maxPriorityFeePerGas", json!([]))
        .ok()
        .and_then(|value| result_quantity(value, "eth_maxPriorityFeePerGas").ok())
        // EIP-1559 eth_gasPrice is normally base + suggested priority. If the
        // optional priority method is unavailable, preserve that suggestion
        // instead of accidentally using the whole gas price as a tip.
        .or_else(|| {
            gas_price
                .checked_sub(base_fee)
                .filter(|value| !value.is_zero())
        })
        .unwrap_or_else(|| gas_price.min(U256::from(1_000_000_000_u64)));
    let max_fee = checked_fee(base_fee, priority)?.max(gas_price);
    let balance = result_quantity(
        rpc.call("eth_getBalance", json!([format!("{from:#x}"), "latest"]))?,
        "eth_getBalance",
    )?;
    let required = gas
        .checked_mul(max_fee)
        .and_then(|fee| fee.checked_add(bond))
        .ok_or_else(|| "estimated registration cost is too large to encode".to_string())?;
    if balance < required {
        return Err(format!(
            "funding wallet balance {balance} wei is below the worst-case bond + gas estimate {required} wei"
        ));
    }

    let request = Eip1559TransactionRequest {
        from: Some(from),
        to: Some(NameOrAddress::Address(registration.contract)),
        gas: Some(gas),
        value: Some(bond),
        data: Some(data),
        nonce: Some(nonce),
        access_list: Default::default(),
        max_priority_fee_per_gas: Some(priority),
        max_fee_per_gas: Some(max_fee),
        chain_id: Some(U64::from(chain_id.as_u64())),
    };
    let transaction = TypedTransaction::Eip1559(request);
    let signature = wallet.sign(&transaction)?;
    let raw = transaction.rlp_signed(&signature);
    let local_hash = format!("0x{}", hex::encode(keccak256(&raw)));
    let remote_hash_value = rpc
        .call(
            "eth_sendRawTransaction",
            json!([format!("0x{}", hex::encode(&raw))]),
        )
        .map_err(|error| {
            format!(
                "broadcast result for locally signed transaction {local_hash} is unknown ({error}); check the hash before retrying"
            )
        })?;
    let remote_hash = remote_hash_value
        .as_str()
        .filter(|value| value.len() == 66 && value.starts_with("0x"))
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| {
            format!(
                "eth_sendRawTransaction returned an invalid hash; locally signed transaction {local_hash} may have been broadcast, so check it before retrying"
            )
        })?;
    if remote_hash != local_hash {
        return Err(format!(
            "RPC returned transaction hash {remote_hash}, but the locally signed transaction is {local_hash}; check both before retrying"
        ));
    }
    broadcast(&local_hash);

    let started = Instant::now();
    let timeout = Duration::from_millis(receipt_timeout_ms());
    loop {
        let receipt = rpc
            .call("eth_getTransactionReceipt", json!([local_hash]))
            .map_err(|error| {
                format!(
                    "member registration transaction {local_hash} was broadcast, but its receipt could not be checked ({error}); check the hash before retrying"
                )
            })?;
        if receipt.is_null() {
            if started.elapsed() >= timeout {
                return Err(format!(
                    "member registration transaction {local_hash} was broadcast but did not reach 1 confirmation within {}ms; it may still confirm, so check the hash before retrying",
                    timeout.as_millis()
                ));
            }
            thread::sleep(Duration::from_secs(1));
            continue;
        }
        let status = receipt_quantity(&receipt, "status", &local_hash)?;
        let block = receipt_quantity(&receipt, "blockNumber", &local_hash)?;
        if status != U256::one() {
            return Err(format!(
                "member registration transaction {local_hash} reverted in block {block}"
            ));
        }
        return Ok(SendOutcome::Mined {
            hash: local_hash,
            block,
        });
    }
}

pub fn cmd_register_member(args: &[String]) -> ExitCode {
    let cli = match parse_args(args) {
        Ok(Some(options)) => options,
        Ok(None) => {
            println!("{HELP}");
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("register-member: {error}\n\n{HELP}");
            return ExitCode::from(2);
        }
    };
    let registration = match resolve_registration(&cli) {
        Ok(registration) => registration,
        Err(error) => {
            eprintln!("register-member: {error}");
            return ExitCode::from(2);
        }
    };
    // Resolve and validate the key before the first network request. This keeps a
    // missing/malformed key from leaking any membership intent to a public RPC.
    let wallet = match wallet_for(&cli, &registration.rpc_url) {
        Ok(wallet) => wallet,
        Err(error) => {
            eprintln!("register-member: {error}");
            return ExitCode::from(2);
        }
    };
    let mut rpc = match HttpRpc::new(&registration.rpc_url) {
        Ok(rpc) => rpc,
        Err(error) => {
            eprintln!("register-member: {error}");
            return ExitCode::from(1);
        }
    };
    println!(
        "register({}, {})",
        registration.commitment, registration.limit
    );
    println!("  contract: {:#x}", registration.contract);
    println!("  rpc:      {}", rpc_label(&registration.rpc_url));
    println!("  from:     {:#x}", wallet.address);
    let result = send(
        &mut rpc,
        &registration,
        &wallet,
        |bond, tiered| {
            println!("  limit:    {}", registration.limit);
            println!("  bond:     {bond} wei");
            if !tiered {
                println!("  set:      legacy (default tier only)");
            }
        },
        |hash| println!("  tx:       {hash}  (waiting for confirmation...)"),
    );
    match result {
        Ok(SendOutcome::AlreadyActive) => {
            println!("member is already staked; nothing to do.");
            ExitCode::SUCCESS
        }
        Ok(SendOutcome::Mined { hash, block }) => {
            println!("  mined:    {hash} in block {block}; member staked. Public admission begins after this block reaches finality.");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("register-member failed: {error}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct MockRpc {
        calls: Arc<Mutex<Vec<(String, Value)>>>,
        active: bool,
        send_error: bool,
        sent_raw: Option<String>,
        chain_id: &'static str,
    }

    impl RpcCall for MockRpc {
        fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
            self.calls
                .lock()
                .unwrap()
                .push((method.to_string(), params.clone()));
            Ok(match method {
                "eth_call" => {
                    let data = params[0]["data"].as_str().unwrap();
                    if data.starts_with("0xe0b91f92") {
                        Value::String(format!(
                            "0x{:x}",
                            U256::from_dec_str("100000000000000000").unwrap()
                        ))
                    } else if data.starts_with("0x82afd23b") {
                        Value::String(if self.active { "0x1" } else { "0x0" }.into())
                    } else if data.starts_with("0xd57b50e7") {
                        Value::String("0x0".into())
                    } else {
                        panic!("unexpected eth_call {data}");
                    }
                }
                "eth_chainId" => Value::String(self.chain_id.into()),
                "eth_getTransactionCount" => Value::String("0x7".into()),
                "eth_estimateGas" => Value::String("0x186a0".into()),
                "eth_gasPrice" => Value::String("0x77359400".into()),
                "eth_maxPriorityFeePerGas" => Value::String("0x3b9aca00".into()),
                "eth_getBalance" => Value::String("0xde0b6b3a7640000".into()),
                "eth_getBlockByNumber" => json!({"baseFeePerGas":"0x3b9aca00"}),
                "eth_sendRawTransaction" => {
                    let raw = params[0].as_str().unwrap().to_string();
                    assert!(raw.starts_with("0x02"), "must send an EIP-1559 transaction");
                    let bytes = hex::decode(raw.trim_start_matches("0x")).unwrap();
                    let hash = format!("0x{}", hex::encode(keccak256(bytes)));
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

    fn registration() -> Registration {
        Registration {
            commitment: U256::from(123),
            limit: 8,
            contract: Address::from_str("0x1111111111111111111111111111111111111111").unwrap(),
            rpc_url: "https://rpc.example/secret-api-key".into(),
            expected_chain_id: Some(11_155_111),
            bond_override: None,
        }
    }

    #[test]
    fn parser_accepts_safe_key_file_and_both_contract_spellings() {
        let one = parse_args(&[
            "123".into(),
            "--limit=32".into(),
            "--contract".into(),
            "0x1111111111111111111111111111111111111111".into(),
            "--key-file=wallet.key".into(),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(one.commitment.as_deref(), Some("123"));
        assert_eq!(one.limit.as_deref(), Some("32"));
        assert_eq!(one.key_file, Some(PathBuf::from("wallet.key")));
        let two = parse_args(&[
            "123".into(),
            "--group-contract=0x2222222222222222222222222222222222222222".into(),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(
            two.contract.as_deref(),
            Some("0x2222222222222222222222222222222222222222")
        );
        assert!(parse_args(&["123".into(), "456".into()]).is_err());
        assert!(parse_args(&["123".into(), "--register-key=secret".into()]).is_err());
        let identity = parse_args(&[
            "--identity".into(),
            "identity.json".into(),
            "--key-file".into(),
            "wallet.key".into(),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(identity.identity, Some(PathBuf::from("identity.json")));
        assert!(parse_args(&["123".into(), "--identity=identity.json".into()]).is_err());
        assert!(parse_args(&[
            "--identity=identity.json".into(),
            "--identity=other.json".into(),
        ])
        .is_err());
    }

    #[test]
    fn bundled_profile_points_at_live_staked_root() {
        let (contract, rpc, default_limit, chain_id) = bundled_defaults().unwrap();
        assert!(Address::from_str(&contract).is_ok());
        assert!(rpc.starts_with("https://"));
        assert!((1..=u16::MAX as u64).contains(&default_limit));
        assert_eq!(chain_id, Some(11_155_111));
        assert!(!rpc_label(&rpc).contains('?'));
    }

    #[test]
    fn registration_default_limit_comes_from_the_bundled_staked_root() {
        let mut deployment: Value = serde_json::from_str(crate::DEFAULT_DEPLOYMENT).unwrap();
        deployment["admission"]["roots"]["staked"]["defaultLimit"] = json!(1);
        let parsed = crate::parse_bundled_deployment(&deployment.to_string()).unwrap();
        let (_, _, limit, _) = registration_defaults_from(parsed).unwrap();
        assert_eq!(limit, 1);
    }

    #[test]
    fn bad_key_error_never_echoes_secret() {
        let bad = "super-secret-not-a-key";
        let error = FundingWallet::from_key(bad).err().unwrap();
        assert!(!error.contains(bad));
        assert!(error.contains("value not shown"));
        assert!(!loopback_rpc("https://rpc.example"));
        assert!(loopback_rpc("http://[::1]:8545"));
    }

    #[test]
    fn key_files_must_be_owner_only() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "shade-tree-register-key-{}-{nonce}",
            std::process::id()
        ));
        fs::write(&path, ANVIL_KEY_0).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(key_file(&path).unwrap_err().contains("chmod 600"));
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(key_file(&path).unwrap(), ANVIL_KEY_0);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn identity_input_verifies_leaf_and_tier_before_network_use() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "shade-tree-register-identity-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("identity.json");
        let material =
            shade_tree_rln::identity::derive_identity(&format!("0x{}", "5a".repeat(32)), 1)
                .unwrap();
        fs::write(
            &path,
            serde_json::to_vec(&json!({
                "identitySecret": material.identity_secret,
                "leaf": material.leaf,
                "limit": material.limit,
            }))
            .unwrap(),
        )
        .unwrap();
        let cli = CliOptions {
            identity: Some(path.clone()),
            ..CliOptions::default()
        };
        let registration = resolve_registration(&cli).unwrap();
        assert_eq!(registration.limit, 1);
        assert_eq!(registration.commitment.to_string(), material.leaf);

        let mut wrong: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        wrong["leaf"] = json!("1");
        fs::write(&path, serde_json::to_vec(&wrong).unwrap()).unwrap();
        assert!(resolve_registration(&cli)
            .unwrap_err()
            .contains("does not match"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn signs_locally_broadcasts_raw_transaction_and_waits_for_success() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut rpc = MockRpc {
            calls: calls.clone(),
            active: false,
            send_error: false,
            sent_raw: None,
            chain_id: "0xaa36a7",
        };
        let wallet = FundingWallet::from_key(ANVIL_KEY_0).unwrap();
        let mut observed_bond = None;
        let mut observed_hash = None;
        let outcome = send(
            &mut rpc,
            &registration(),
            &wallet,
            |bond, tiered| observed_bond = Some((bond, tiered)),
            |hash| observed_hash = Some(hash.to_string()),
        )
        .unwrap();
        assert!(matches!(outcome, SendOutcome::Mined { block, .. } if block == U256::from(42)));
        assert_eq!(
            observed_bond,
            Some((U256::from_dec_str("100000000000000000").unwrap(), true))
        );
        assert!(observed_hash.unwrap().starts_with("0x"));
        let raw = rpc.sent_raw.unwrap();
        assert!(!raw.contains(ANVIL_KEY_0.trim_start_matches("0x")));
        let raw_bytes = hex::decode(raw.trim_start_matches("0x")).unwrap();
        let (signed, signature) =
            TypedTransaction::decode_signed(&ethers_core::utils::rlp::Rlp::new(&raw_bytes))
                .unwrap();
        assert_eq!(signed.chain_id(), Some(U64::from(11_155_111_u64)));
        assert_eq!(signature.recover(signed.sighash()).unwrap(), wallet.address);
        let calls = calls.lock().unwrap();
        let estimate = calls
            .iter()
            .find(|(method, _)| method == "eth_estimateGas")
            .unwrap();
        assert_eq!(&estimate.1[0]["data"].as_str().unwrap()[..10], "0xd66d6c10");
        assert_eq!(
            estimate.1[0]["value"],
            Value::String("0x16345785d8a0000".into())
        );
        assert_eq!(
            calls.last().map(|(method, _)| method.as_str()),
            Some("eth_getTransactionReceipt")
        );
    }

    #[test]
    fn already_active_member_never_signs_or_broadcasts() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut rpc = MockRpc {
            calls: calls.clone(),
            active: true,
            send_error: false,
            sent_raw: None,
            chain_id: "0xaa36a7",
        };
        let wallet = FundingWallet::from_key(ANVIL_KEY_0).unwrap();
        assert_eq!(
            send(&mut rpc, &registration(), &wallet, |_, _| {}, |_| {}).unwrap(),
            SendOutcome::AlreadyActive
        );
        assert!(rpc.sent_raw.is_none());
        assert_eq!(calls.lock().unwrap().len(), 3);
    }

    #[test]
    fn uncertain_broadcast_error_retains_local_hash_and_retry_warning() {
        let mut rpc = MockRpc {
            calls: Arc::new(Mutex::new(Vec::new())),
            active: false,
            send_error: true,
            sent_raw: None,
            chain_id: "0xaa36a7",
        };
        let wallet = FundingWallet::from_key(ANVIL_KEY_0).unwrap();
        let error = send(&mut rpc, &registration(), &wallet, |_, _| {}, |_| {}).unwrap_err();
        assert!(error.contains("locally signed transaction 0x"));
        assert!(error.contains("check the hash before retrying"));
        assert!(rpc.sent_raw.is_some());
    }

    #[test]
    fn wrong_chain_is_rejected_before_contract_reads_or_signing() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut rpc = MockRpc {
            calls: calls.clone(),
            active: false,
            send_error: false,
            sent_raw: None,
            chain_id: "0x1",
        };
        let wallet = FundingWallet::from_key(ANVIL_KEY_0).unwrap();
        let error = send(&mut rpc, &registration(), &wallet, |_, _| {}, |_| {}).unwrap_err();
        assert!(error.contains("chainId 1 does not match configured chainId 11155111"));
        assert!(rpc.sent_raw.is_none());
        assert_eq!(
            calls.lock().unwrap().as_slice(),
            &[("eth_chainId".into(), json!([]))]
        );
    }
}
