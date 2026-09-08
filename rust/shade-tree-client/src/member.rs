//! ZK-authorized staking membership lifecycle for the live Rust client.
//!
//! The identity secret is validated and used only in-process to build an exit or
//! withdrawal proof. JSON-RPC sees the already-public leaf and a zero-knowledge
//! proof, never the identity secret. Transactions are signed locally.

use ethers_core::abi::{decode, encode, ParamType, Token};
use ethers_core::types::{
    transaction::eip2718::TypedTransaction, Address, Bytes, Eip1559TransactionRequest,
    NameOrAddress, U256, U64,
};
use ethers_core::utils::{id, keccak256};
use serde_json::json;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

use crate::register::{
    bundled_defaults, checked_fee, key_file, receipt_quantity, receipt_timeout_ms, result_quantity,
    rpc_label, verified_identity, FundingWallet, HttpRpc, RpcCall,
};

const HELP: &str = r#"Shade Tree staked-member lifecycle (Sepolia)

usage:
  shade-tree member-status --identity identity.json [--json]
  shade-tree exit-member --identity identity.json [--key-file gas.key]
  shade-tree withdraw-member --identity identity.json --recipient 0x... [--key-file gas.key]

All commands accept --contract, --rpc-url, and --limit. Defaults come from the
bundled public Grove. exit-member and withdraw-member build a fresh Groth16 proof
locally and sign an EIP-1559 gas transaction locally. The identity secret is never
sent to the RPC. The gas key comes from --key-file, SHADE_TREE_MEMBER_KEY, or
SHADE_TREE_REGISTER_KEY; it may be unrelated to the wallet that funded the stake.
withdraw-member requires an explicit recipient because it is cryptographically
bound into the proof. Use --circuits only to override the embedded release artifacts."#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Status,
    Exit,
    Withdraw,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CliOptions {
    identity: Option<PathBuf>,
    limit: Option<u64>,
    contract: Option<String>,
    rpc_url: Option<String>,
    key_file: Option<PathBuf>,
    recipient: Option<String>,
    circuits: Option<String>,
    json: bool,
}

#[derive(Debug, Clone)]
struct Network {
    contract: Address,
    rpc_url: String,
    expected_chain_id: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MemberState {
    bond: U256,
    index: U256,
    exit_initiated_at: U256,
    limit: U256,
    withdrawable_at: U256,
}

impl MemberState {
    fn phase(self) -> &'static str {
        if self.bond.is_zero() {
            "absent"
        } else if self.exit_initiated_at.is_zero() {
            "active"
        } else {
            "exiting"
        }
    }
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

fn set_once<T>(slot: &mut Option<T>, value: T, name: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("pass {name} only once"));
    }
    Ok(())
}

fn parse_args(action: Action, args: &[String]) -> Result<Option<CliOptions>, String> {
    let mut out = CliOptions::default();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--help" || arg == "-h" {
            return Ok(None);
        }
        if arg == "--json" {
            if out.json {
                return Err("pass --json only once".into());
            }
            out.json = true;
            index += 1;
            continue;
        }
        let matched = [
            "--identity",
            "--limit",
            "--contract",
            "--group-contract",
            "--rpc-url",
            "--key-file",
            "--recipient",
            "--circuits",
        ]
        .iter()
        .find(|name| arg == **name || arg.starts_with(&format!("{name}=")))
        .copied();
        let Some(name) = matched else {
            return Err(format!("unexpected argument {arg}"));
        };
        let value = value_for(args, &mut index, name)?;
        match name {
            "--identity" => set_once(&mut out.identity, PathBuf::from(value), name)?,
            "--limit" => {
                let parsed = value
                    .parse::<u64>()
                    .ok()
                    .filter(|limit| (1..=u16::MAX as u64).contains(limit))
                    .ok_or_else(|| format!("--limit must be in 1..={}", u16::MAX))?;
                set_once(&mut out.limit, parsed, name)?;
            }
            "--contract" | "--group-contract" => {
                set_once(&mut out.contract, value, "--contract/--group-contract")?
            }
            "--rpc-url" => set_once(&mut out.rpc_url, value, name)?,
            "--key-file" => set_once(&mut out.key_file, PathBuf::from(value), name)?,
            "--recipient" => set_once(&mut out.recipient, value, name)?,
            "--circuits" => set_once(&mut out.circuits, value, name)?,
            _ => unreachable!(),
        }
        index += 1;
    }
    if out.identity.is_none() {
        return Err("--identity is required".into());
    }
    if action == Action::Withdraw && out.recipient.is_none() {
        return Err("withdraw-member requires --recipient".into());
    }
    if action != Action::Withdraw && out.recipient.is_some() {
        return Err("--recipient is only valid for withdraw-member".into());
    }
    if action != Action::Status && out.json {
        return Err("--json is only valid for member-status".into());
    }
    if action == Action::Status && (out.key_file.is_some() || out.circuits.is_some()) {
        return Err("member-status does not accept --key-file or --circuits".into());
    }
    Ok(Some(out))
}

fn first_contract(value: &str) -> &str {
    value.split(',').next().unwrap_or_default().trim()
}

fn resolve_network(cli: &CliOptions) -> Result<Network, String> {
    let (bundled_contract, bundled_rpc, _, bundled_chain_id) = bundled_defaults()?;
    let bundled_address = Address::from_str(first_contract(&bundled_contract)).ok();
    let env_contract = std::env::var("SHADE_TREE_GROUP_CONTRACT").ok();
    let contract_raw = cli
        .contract
        .as_deref()
        .or(env_contract.as_deref())
        .unwrap_or(&bundled_contract);
    let contract = Address::from_str(first_contract(contract_raw))
        .map_err(|_| "staking contract is not a 20-byte Ethereum address".to_string())?;
    let env_rpc = std::env::var("SHADE_TREE_RPC_URL").ok();
    let rpc_url = cli
        .rpc_url
        .as_deref()
        .or(env_rpc.as_deref())
        .unwrap_or(&bundled_rpc)
        .to_string();
    let parsed = reqwest::Url::parse(&rpc_url)
        .map_err(|_| "staking RPC must be an absolute HTTP(S) URL".to_string())?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host().is_none() {
        return Err("staking RPC must be an absolute HTTP(S) URL".into());
    }
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
    Ok(Network {
        contract,
        rpc_url,
        expected_chain_id,
    })
}

fn calldata(signature: &str, tokens: Vec<Token>) -> Bytes {
    let mut bytes = id(signature)[..4].to_vec();
    bytes.extend(encode(&tokens));
    bytes.into()
}

fn check_chain<R: RpcCall>(rpc: &mut R, network: &Network) -> Result<u64, String> {
    let chain_id = result_quantity(rpc.call("eth_chainId", json!([]))?, "eth_chainId")?;
    if chain_id.is_zero() || chain_id > U256::from(u64::MAX) {
        return Err("eth_chainId returned an unsupported value".into());
    }
    let chain_id = chain_id.as_u64();
    if network
        .expected_chain_id
        .is_some_and(|expected| expected != chain_id)
    {
        return Err(format!(
            "staking RPC chainId {chain_id} does not match configured chainId {}; refusing to continue",
            network.expected_chain_id.unwrap()
        ));
    }
    let code = rpc.call(
        "eth_getCode",
        json!([format!("{:#x}", network.contract), "latest"]),
    )?;
    let has_code = code
        .as_str()
        .and_then(|value| value.strip_prefix("0x"))
        .is_some_and(|value| !value.is_empty() && value.bytes().any(|byte| byte != b'0'));
    if !has_code {
        return Err(format!(
            "no contract bytecode at {:#x} on chainId {chain_id}",
            network.contract
        ));
    }
    Ok(chain_id)
}

fn eth_call<R: RpcCall>(rpc: &mut R, network: &Network, data: &Bytes) -> Result<Vec<u8>, String> {
    let result = rpc.call(
        "eth_call",
        json!([{"to":format!("{:#x}", network.contract),"data":format!("0x{}", hex::encode(data))},"latest"]),
    )?;
    let raw = result
        .as_str()
        .and_then(|value| value.strip_prefix("0x"))
        .ok_or_else(|| "eth_call: expected 0x-hex data".to_string())?;
    hex::decode(raw).map_err(|_| "eth_call: returned invalid hex data".to_string())
}

fn uint_token(token: &Token, label: &str) -> Result<U256, String> {
    token
        .clone()
        .into_uint()
        .ok_or_else(|| format!("members(): invalid {label}"))
}

fn member_state<R: RpcCall>(
    rpc: &mut R,
    network: &Network,
    commitment: U256,
) -> Result<MemberState, String> {
    let member_raw = eth_call(
        rpc,
        network,
        &calldata("members(uint256)", vec![Token::Uint(commitment)]),
    )?;
    let member = decode(
        &[
            ParamType::Uint(256),
            ParamType::Uint(64),
            ParamType::Uint(64),
            ParamType::Uint(32),
        ],
        &member_raw,
    )
    .map_err(|_| "members(): contract returned malformed state".to_string())?;
    let withdraw_raw = eth_call(
        rpc,
        network,
        &calldata("withdrawableAt(uint256)", vec![Token::Uint(commitment)]),
    )?;
    let withdraw = decode(&[ParamType::Uint(256)], &withdraw_raw)
        .map_err(|_| "withdrawableAt(): contract returned malformed state".to_string())?;
    Ok(MemberState {
        bond: uint_token(&member[0], "bond")?,
        index: uint_token(&member[1], "index")?,
        exit_initiated_at: uint_token(&member[2], "exit timestamp")?,
        limit: uint_token(&member[3], "limit")?,
        withdrawable_at: uint_token(&withdraw[0], "withdrawable timestamp")?,
    })
}

fn action_context(action: Action, commitment: U256, recipient: Option<Address>) -> [u8; 32] {
    let mut packed = match action {
        Action::Exit => b"SHADE_TREE_EXIT".to_vec(),
        Action::Withdraw => b"SHADE_TREE_WITHDRAW".to_vec(),
        Action::Status => unreachable!("status has no proof context"),
    };
    let mut word = [0_u8; 32];
    commitment.to_big_endian(&mut word);
    packed.extend(word);
    if let Some(recipient) = recipient {
        packed.extend(recipient.as_bytes());
    }
    keccak256(packed)
}

fn gas_wallet(cli: &CliOptions) -> Result<FundingWallet, String> {
    let mut key = if let Some(path) = &cli.key_file {
        key_file(path)?
    } else if let Ok(value) = std::env::var("SHADE_TREE_MEMBER_KEY") {
        value
    } else if let Ok(value) = std::env::var("SHADE_TREE_REGISTER_KEY") {
        value
    } else {
        return Err(
            "a gas key is required via --key-file, SHADE_TREE_MEMBER_KEY, or SHADE_TREE_REGISTER_KEY"
                .into(),
        );
    };
    if key.trim().is_empty() {
        return Err("configured gas key is empty".into());
    }
    use ethers_core::k256::elliptic_curve::zeroize::Zeroize;
    let wallet = FundingWallet::from_key(&key);
    key.zeroize();
    wallet
}

fn latest_timestamp<R: RpcCall>(rpc: &mut R) -> Result<U256, String> {
    let block = rpc.call("eth_getBlockByNumber", json!(["latest", false]))?;
    result_quantity(
        block
            .get("timestamp")
            .cloned()
            .ok_or_else(|| "latest block has no timestamp".to_string())?,
        "latest block timestamp",
    )
}

fn send_action<R: RpcCall>(
    rpc: &mut R,
    network: &Network,
    wallet: &FundingWallet,
    chain_id: u64,
    data: Bytes,
    label: &str,
) -> Result<(String, U256), String> {
    let from = wallet.address;
    let call = json!({
        "from":format!("{from:#x}"), "to":format!("{:#x}", network.contract),
        "value":"0x0", "data":format!("0x{}", hex::encode(&data)),
    });
    // Simulate the exact call before signing so stale state and bad proofs fail safely.
    rpc.call("eth_call", json!([call.clone(), "latest"]))?;
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
    let base_fee = result_quantity(
        block.get("baseFeePerGas").cloned().ok_or_else(|| {
            "latest block has no baseFeePerGas; this signer requires EIP-1559".to_string()
        })?,
        "baseFeePerGas",
    )?;
    let priority = rpc
        .call("eth_maxPriorityFeePerGas", json!([]))
        .ok()
        .and_then(|value| result_quantity(value, "eth_maxPriorityFeePerGas").ok())
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
        .ok_or_else(|| "estimated lifecycle gas cost is too large to encode".to_string())?;
    if balance < required {
        return Err(format!(
            "gas wallet balance {balance} wei is below the worst-case gas estimate {required} wei"
        ));
    }
    let request = Eip1559TransactionRequest {
        from: Some(from),
        to: Some(NameOrAddress::Address(network.contract)),
        gas: Some(gas),
        value: Some(U256::zero()),
        data: Some(data),
        nonce: Some(nonce),
        access_list: Default::default(),
        max_priority_fee_per_gas: Some(priority),
        max_fee_per_gas: Some(max_fee),
        chain_id: Some(U64::from(chain_id)),
    };
    let transaction = TypedTransaction::Eip1559(request);
    let signature = wallet.sign(&transaction)?;
    let raw = transaction.rlp_signed(&signature);
    let local_hash = format!("0x{}", hex::encode(keccak256(&raw)));
    let remote = rpc
        .call("eth_sendRawTransaction", json!([format!("0x{}", hex::encode(&raw))]))
        .map_err(|error| format!(
            "{label} transaction {local_hash} may have been broadcast ({error}); check the hash before retrying"
        ))?;
    let remote_hash = remote
        .as_str()
        .filter(|value| value.len() == 66 && value.starts_with("0x"))
        .map(str::to_ascii_lowercase)
        .ok_or_else(|| format!(
            "RPC returned an invalid hash; {label} transaction {local_hash} may have been broadcast, so check it before retrying"
        ))?;
    if remote_hash != local_hash {
        return Err(format!(
            "RPC returned {remote_hash}, but locally signed {label} transaction is {local_hash}; check both before retrying"
        ));
    }
    println!("  tx:       {local_hash}  (waiting for confirmation...)");
    let started = Instant::now();
    let timeout = Duration::from_millis(receipt_timeout_ms());
    loop {
        let receipt = rpc
            .call("eth_getTransactionReceipt", json!([local_hash]))
            .map_err(|error| format!(
                "{label} transaction {local_hash} was broadcast but its receipt could not be checked ({error}); check the hash before retrying"
            ))?;
        if receipt.is_null() {
            if started.elapsed() >= timeout {
                return Err(format!(
                    "{label} transaction {local_hash} did not reach 1 confirmation within {}ms; it may still confirm, so check before retrying",
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
                "{label} transaction {local_hash} reverted in block {block}"
            ));
        }
        return Ok((local_hash, block));
    }
}

fn print_status(state: MemberState, commitment: U256, json_output: bool) {
    if json_output {
        println!(
            "{}",
            json!({
                "commitment": commitment.to_string(),
                "status": state.phase(),
                "bondWei": state.bond.to_string(),
                "index": state.index.to_string(),
                "limit": state.limit.to_string(),
                "exitInitiatedAt": state.exit_initiated_at.to_string(),
                "withdrawableAt": state.withdrawable_at.to_string(),
            })
        );
    } else {
        println!("member {}", commitment);
        println!("  status:          {}", state.phase());
        println!("  bond:            {} wei", state.bond);
        if !state.bond.is_zero() {
            println!("  tier:            {}", state.limit);
            println!("  index:           {}", state.index);
        }
        if !state.withdrawable_at.is_zero() {
            println!(
                "  withdrawable-at: {} (Unix seconds)",
                state.withdrawable_at
            );
        }
    }
}

pub fn cmd_member(action: Action, args: &[String]) -> ExitCode {
    let cli = match parse_args(action, args) {
        Ok(Some(cli)) => cli,
        Ok(None) => {
            println!("{HELP}");
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("member: {error}\n\n{HELP}");
            return ExitCode::from(2);
        }
    };
    // Strictly validate secret/leaf/tier consistency before the first network call.
    let identity = match verified_identity(cli.identity.as_ref().unwrap(), cli.limit) {
        Ok(identity) => identity,
        Err(error) => {
            eprintln!("member: {error}");
            return ExitCode::from(2);
        }
    };
    let network = match resolve_network(&cli) {
        Ok(network) => network,
        Err(error) => {
            eprintln!("member: {error}");
            return ExitCode::from(2);
        }
    };
    // Validate the gas key before contacting a public RPC, but status needs no key.
    let wallet = if action == Action::Status {
        None
    } else {
        match gas_wallet(&cli) {
            Ok(wallet) => Some(wallet),
            Err(error) => {
                eprintln!("member: {error}");
                return ExitCode::from(2);
            }
        }
    };
    let mut rpc = match HttpRpc::new(&network.rpc_url) {
        Ok(rpc) => rpc,
        Err(error) => {
            eprintln!("member: {error}");
            return ExitCode::from(1);
        }
    };
    let chain_id = match check_chain(&mut rpc, &network) {
        Ok(chain_id) => chain_id,
        Err(error) => {
            eprintln!("member: {error}");
            return ExitCode::from(1);
        }
    };
    let state = match member_state(&mut rpc, &network, identity.commitment) {
        Ok(state) => state,
        Err(error) => {
            eprintln!("member: {error}");
            return ExitCode::from(1);
        }
    };
    if action == Action::Status {
        print_status(state, identity.commitment, cli.json);
        return ExitCode::SUCCESS;
    }
    if state.bond.is_zero() {
        eprintln!("member: leaf is not currently bonded (it may be absent, withdrawn, or slashed)");
        return ExitCode::from(1);
    }
    if state.limit != U256::from(identity.limit) {
        eprintln!(
            "member: on-chain tier {} does not match identity tier {}; refusing to prove",
            state.limit, identity.limit
        );
        return ExitCode::from(1);
    }
    if action == Action::Exit && !state.exit_initiated_at.is_zero() {
        println!(
            "member is already exiting; withdrawable at {}.",
            state.withdrawable_at
        );
        return ExitCode::SUCCESS;
    }
    if action == Action::Withdraw && state.exit_initiated_at.is_zero() {
        eprintln!("member: exit has not been initiated; run exit-member first");
        return ExitCode::from(1);
    }
    if action == Action::Withdraw {
        let now = match latest_timestamp(&mut rpc) {
            Ok(now) => now,
            Err(error) => {
                eprintln!("member: {error}");
                return ExitCode::from(1);
            }
        };
        if now < state.withdrawable_at {
            eprintln!(
                "member: still bonded; chain time {now}, withdrawable at {}",
                state.withdrawable_at
            );
            return ExitCode::from(1);
        }
    }
    let recipient = match cli.recipient.as_deref() {
        Some(value) => match Address::from_str(value) {
            Ok(address) if address != Address::zero() => Some(address),
            _ => {
                eprintln!("member: --recipient must be a non-zero 20-byte Ethereum address");
                return ExitCode::from(2);
            }
        },
        None => None,
    };
    let context = action_context(action, identity.commitment, recipient);
    if cli.circuits.is_none() {
        if let Err(error) = shade_tree_rln::artifacts::verify_withdraw_embedded() {
            eprintln!("member: {error}");
            return ExitCode::from(1);
        }
    }
    println!("building a local zero-knowledge proof...");
    let proof = match shade_tree_rln::withdraw::build_withdraw_proof(
        &shade_tree_rln::withdraw::WithdrawProofInput {
            identity_secret: identity.identity_secret,
            context,
            circuits_dir: cli.circuits,
        },
    ) {
        Ok(proof) => proof,
        Err(error) => {
            eprintln!("member: could not build authorization proof: {error}");
            return ExitCode::from(1);
        }
    };
    let data = match action {
        Action::Exit => calldata(
            "initiateExit(uint256,bytes)",
            vec![
                Token::Uint(identity.commitment),
                Token::Bytes(proof.proof_bytes),
            ],
        ),
        Action::Withdraw => calldata(
            "withdraw(uint256,address,bytes)",
            vec![
                Token::Uint(identity.commitment),
                Token::Address(recipient.unwrap()),
                Token::Bytes(proof.proof_bytes),
            ],
        ),
        Action::Status => unreachable!(),
    };
    let label = if action == Action::Exit {
        "exit"
    } else {
        "withdrawal"
    };
    println!("{label}({})", identity.commitment);
    println!("  contract: {:#x}", network.contract);
    println!("  rpc:      {}", rpc_label(&network.rpc_url));
    println!("  from:     {:#x}", wallet.as_ref().unwrap().address);
    if let Some(recipient) = recipient {
        println!("  recipient:{recipient:#x}");
    }
    match send_action(
        &mut rpc,
        &network,
        wallet.as_ref().unwrap(),
        chain_id,
        data,
        label,
    ) {
        Ok((hash, block)) => {
            println!("  mined:    {hash} in block {block}; {label} confirmed.");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("member: {error}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::sync::{Arc, Mutex};

    struct MockRpc {
        calls: Arc<Mutex<Vec<(String, Value)>>>,
        wrong_chain: bool,
    }

    impl RpcCall for MockRpc {
        fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
            self.calls
                .lock()
                .unwrap()
                .push((method.to_string(), params.clone()));
            Ok(match method {
                "eth_chainId" => Value::String(if self.wrong_chain {
                    "0x1".into()
                } else {
                    "0xaa36a7".into()
                }),
                "eth_getCode" => Value::String("0x6001600055".into()),
                "eth_call" => {
                    let data = params[0]["data"].as_str().unwrap_or_default();
                    if data.starts_with(&format!("0x{}", hex::encode(&id("members(uint256)")[..4])))
                    {
                        Value::String(format!(
                            "0x{}",
                            hex::encode(encode(&[
                                Token::Uint(U256::from(100_u64)),
                                Token::Uint(U256::from(7_u64)),
                                Token::Uint(U256::from(55_u64)),
                                Token::Uint(U256::one()),
                            ]))
                        ))
                    } else if data.starts_with(&format!(
                        "0x{}",
                        hex::encode(&id("withdrawableAt(uint256)")[..4])
                    )) {
                        Value::String(format!(
                            "0x{}",
                            hex::encode(encode(&[Token::Uint(U256::from(86_455_u64))]))
                        ))
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
                    let raw = params[0].as_str().unwrap();
                    Value::String(format!(
                        "0x{}",
                        hex::encode(keccak256(hex::decode(&raw[2..]).unwrap()))
                    ))
                }
                "eth_getTransactionReceipt" => {
                    json!({"status":"0x1","blockNumber":"0x2a"})
                }
                _ => panic!("unexpected method {method}"),
            })
        }
    }

    fn network() -> Network {
        Network {
            contract: Address::from_str("0x2222222222222222222222222222222222222222").unwrap(),
            rpc_url: "https://rpc.example/private-token".into(),
            expected_chain_id: Some(11_155_111),
        }
    }

    #[test]
    fn parser_enforces_private_identity_and_action_specific_flags() {
        assert!(parse_args(Action::Status, &[]).is_err());
        assert!(parse_args(
            Action::Exit,
            &["--identity=a.json".into(), "--identity=b.json".into()]
        )
        .is_err());
        assert!(parse_args(Action::Withdraw, &["--identity=a.json".into()]).is_err());
        assert!(parse_args(
            Action::Exit,
            &["--identity=a.json".into(), "--recipient=0x00".into()]
        )
        .is_err());
        let parsed = parse_args(
            Action::Withdraw,
            &[
                "--identity=a.json".into(),
                "--recipient=0x1111111111111111111111111111111111111111".into(),
                "--key-file=gas.key".into(),
            ],
        )
        .unwrap()
        .unwrap();
        assert_eq!(parsed.identity, Some(PathBuf::from("a.json")));
        assert_eq!(parsed.key_file, Some(PathBuf::from("gas.key")));
    }

    #[test]
    fn action_context_matches_solidity_packed_layout() {
        let commitment = U256::from(123_u64);
        let recipient = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
        let mut exit = b"SHADE_TREE_EXIT".to_vec();
        let mut word = [0_u8; 32];
        commitment.to_big_endian(&mut word);
        exit.extend(word);
        assert_eq!(
            action_context(Action::Exit, commitment, None),
            keccak256(exit)
        );
        let mut withdrawal = b"SHADE_TREE_WITHDRAW".to_vec();
        withdrawal.extend(word);
        withdrawal.extend(recipient.as_bytes());
        assert_eq!(
            action_context(Action::Withdraw, commitment, Some(recipient)),
            keccak256(withdrawal)
        );
    }

    #[test]
    fn member_phase_is_unambiguous() {
        let state = MemberState {
            bond: U256::zero(),
            index: U256::zero(),
            exit_initiated_at: U256::zero(),
            limit: U256::zero(),
            withdrawable_at: U256::zero(),
        };
        assert_eq!(state.phase(), "absent");
        assert_eq!(
            MemberState {
                bond: U256::one(),
                ..state
            }
            .phase(),
            "active"
        );
        assert_eq!(
            MemberState {
                bond: U256::one(),
                exit_initiated_at: U256::one(),
                ..state
            }
            .phase(),
            "exiting"
        );
    }

    #[test]
    fn reads_typed_member_state_and_rejects_wrong_chain_first() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut rpc = MockRpc {
            calls: calls.clone(),
            wrong_chain: false,
        };
        assert_eq!(check_chain(&mut rpc, &network()).unwrap(), 11_155_111);
        let state = member_state(&mut rpc, &network(), U256::from(123_u64)).unwrap();
        assert_eq!(state.phase(), "exiting");
        assert_eq!(state.bond, U256::from(100_u64));
        assert_eq!(state.limit, U256::one());
        assert_eq!(state.withdrawable_at, U256::from(86_455_u64));

        let mut wrong = MockRpc {
            calls: Arc::new(Mutex::new(Vec::new())),
            wrong_chain: true,
        };
        assert!(check_chain(&mut wrong, &network())
            .unwrap_err()
            .contains("does not match"));
        assert_eq!(wrong.calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn locally_signs_and_simulates_exact_lifecycle_calldata() {
        const KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut rpc = MockRpc {
            calls: calls.clone(),
            wrong_chain: false,
        };
        let wallet = FundingWallet::from_key(KEY).unwrap();
        let data = calldata(
            "initiateExit(uint256,bytes)",
            vec![Token::Uint(U256::from(123_u64)), Token::Bytes(vec![9; 288])],
        );
        let expected_selector = format!("0x{}", hex::encode(&data[..4]));
        let (hash, block) =
            send_action(&mut rpc, &network(), &wallet, 11_155_111, data, "exit").unwrap();
        assert!(hash.starts_with("0x"));
        assert_eq!(block, U256::from(42_u64));
        let calls = calls.lock().unwrap();
        let simulation = calls
            .iter()
            .find(|(method, params)| {
                method == "eth_call"
                    && params[0]["data"]
                        .as_str()
                        .is_some_and(|value| value.starts_with(&expected_selector))
            })
            .expect("exact lifecycle simulation");
        assert_eq!(simulation.1[0]["value"], "0x0");
        let raw = calls
            .iter()
            .find(|(method, _)| method == "eth_sendRawTransaction")
            .unwrap()
            .1[0]
            .as_str()
            .unwrap();
        assert!(raw.starts_with("0x02"));
        assert!(!raw.contains(KEY.trim_start_matches("0x")));
    }
}
