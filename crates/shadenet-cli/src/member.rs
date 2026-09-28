//! ZK-authorized staking membership lifecycle for the live Rust client.
//!
//! The identity secret is validated and used only in-process to build an exit or
//! withdrawal proof. JSON-RPC sees the already-public leaf and a zero-knowledge
//! proof, never the identity secret. Transactions are signed locally.

use serde_json::json;
use shadenet::eth::{Address, Wallet, U256};
use shadenet::member::{self, rpc_label, ExitOutcome, MemberState, Progress, StakingSet};
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use zeroize::Zeroizing;

use crate::register::{bundled_defaults, http_rpc, key_file, send_options, verified_identity};

const HELP: &str = r#"ShadeNet staked-member lifecycle

usage:
  shadenet member-status --identity identity.json [--json]
  shadenet exit-member --identity identity.json [--key-file gas.key]
  shadenet withdraw-member --identity identity.json --recipient 0x... [--key-file gas.key]

All commands accept --contract, --rpc-url, and --limit. Defaults come from the
bundled network. exit-member and withdraw-member build a fresh Groth16 proof
locally and sign an EIP-1559 gas transaction locally. The identity secret is never
sent to the RPC. The gas key comes from --key-file, SHADENET_MEMBER_KEY, or
SHADENET_REGISTER_KEY; it may be unrelated to the wallet that funded the stake.
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

fn resolve_set(cli: &CliOptions) -> Result<StakingSet, String> {
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
    let expected_chain_id = match std::env::var("SHADE_TREE_CHAIN_ID").ok() {
        Some(value) if !value.trim().is_empty() => Some(
            value
                .parse::<u64>()
                .ok()
                .filter(|chain_id| *chain_id > 0)
                .ok_or_else(|| "SHADENET_CHAIN_ID must be a positive integer".to_string())?,
        ),
        _ if bundled_address == Some(contract) => bundled_chain_id,
        _ => None,
    };
    Ok(StakingSet {
        contract,
        rpc_url,
        expected_chain_id,
    })
}

fn gas_wallet(cli: &CliOptions) -> Result<Wallet, String> {
    let key = Zeroizing::new(if let Some(path) = &cli.key_file {
        key_file(path)?
    } else if let Some(value) = shadenet::env::var("MEMBER_KEY")? {
        value
    } else if let Some(value) = shadenet::env::var("REGISTER_KEY")? {
        value
    } else {
        return Err(
            "a gas key is required via --key-file, SHADENET_MEMBER_KEY, or SHADENET_REGISTER_KEY"
                .into(),
        );
    });
    if key.trim().is_empty() {
        return Err("configured gas key is empty".into());
    }
    Wallet::from_hex(&key)
}

fn print_status(state: &MemberState, leaf: &U256, json_output: bool) {
    if json_output {
        println!(
            "{}",
            json!({
                "commitment": leaf.to_string(),
                "status": state.phase(),
                "bondWei": state.bond.to_string(),
                "index": state.index.to_string(),
                "limit": state.limit.to_string(),
                "exitInitiatedAt": state.exit_initiated_at.to_string(),
                "withdrawableAt": state.withdrawable_at.to_string(),
            })
        );
    } else {
        println!("member {leaf}");
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

fn fail(error: impl std::fmt::Display, code: u8) -> ExitCode {
    eprintln!("member: {error}");
    ExitCode::from(code)
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
    // Validate secret/leaf/tier consistency before the first network call.
    let identity = match verified_identity(cli.identity.as_ref().unwrap(), cli.limit) {
        Ok(identity) => identity,
        Err(error) => return fail(error, 2),
    };
    let set = match resolve_set(&cli) {
        Ok(set) => set,
        Err(error) => return fail(error, 2),
    };
    // Validate the gas key before contacting a public RPC; status needs no key.
    let wallet = if action == Action::Status {
        None
    } else {
        match gas_wallet(&cli) {
            Ok(wallet) => Some(wallet),
            Err(error) => return fail(error, 2),
        }
    };
    let recipient = match cli.recipient.as_deref() {
        Some(value) => match Address::from_str(value) {
            Ok(address) if address != Address::default() => Some(address),
            _ => return fail("--recipient must be a non-zero 20-byte Ethereum address", 2),
        },
        None => None,
    };
    let mut rpc = match http_rpc(&set.rpc_url) {
        Ok(rpc) => rpc,
        Err(error) => return fail(error, 1),
    };
    let mut progress = |progress: Progress| match progress {
        Progress::Proving => println!("building a local zero-knowledge proof..."),
        Progress::Broadcast { hash } => {
            println!("  tx:       {hash}  (waiting for confirmation...)")
        }
        Progress::Bond { .. } => {}
    };
    let header = |label: &str, wallet: &Wallet| {
        println!("{label}({})", identity.leaf);
        println!("  contract: {}", set.contract);
        println!("  rpc:      {}", rpc_label(&set.rpc_url));
        println!("  from:     {}", wallet.address);
        if let Some(recipient) = recipient {
            println!("  recipient:{recipient}");
        }
    };
    match action {
        Action::Status => {
            if let Err(error) = member::check_chain(&mut rpc, &set) {
                return fail(error, 1);
            }
            match member::member_state(&mut rpc, &set, &identity.leaf) {
                Ok(state) => {
                    print_status(&state, &identity.leaf, cli.json);
                    ExitCode::SUCCESS
                }
                Err(error) => fail(error, 1),
            }
        }
        Action::Exit => {
            let wallet = wallet.unwrap();
            header("exit", &wallet);
            match member::exit(
                &mut rpc,
                &set,
                &identity,
                &wallet,
                cli.circuits,
                send_options(),
                &mut progress,
            ) {
                Ok(ExitOutcome::AlreadyExiting { withdrawable_at }) => {
                    println!("member is already exiting; withdrawable at {withdrawable_at}.");
                    ExitCode::SUCCESS
                }
                Ok(ExitOutcome::Mined(mined)) => {
                    println!(
                        "  mined:    {} in block {}; exit confirmed.",
                        mined.hash, mined.block
                    );
                    ExitCode::SUCCESS
                }
                Err(error) => fail(error, 1),
            }
        }
        Action::Withdraw => {
            let wallet = wallet.unwrap();
            header("withdrawal", &wallet);
            match member::withdraw(
                &mut rpc,
                &set,
                &identity,
                recipient.unwrap(),
                &wallet,
                cli.circuits,
                send_options(),
                &mut progress,
            ) {
                Ok(mined) => {
                    println!(
                        "  mined:    {} in block {}; withdrawal confirmed.",
                        mined.hash, mined.block
                    );
                    ExitCode::SUCCESS
                }
                Err(error) => fail(error, 1),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
