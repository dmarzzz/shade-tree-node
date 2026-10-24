//! Native, Node-free member staking for the Rust client.
//!
//! The funding key is loaded from an owner-only file or an environment variable,
//! signs an EIP-1559 transaction locally, and is never sent to the RPC. The public
//! Sepolia contract and RPC come from the same bundled deployment record as default
//! Elder discovery; explicit CLI/environment values always win.

use shadenet::eth::{Address, Wallet, U256};
use shadenet::member::{
    self, is_loopback_rpc, parse_uint, rpc_label, Funding, FundingQuote, HttpRpc, Progress,
    RegisterOutcome,
};
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const DEFAULT_RPC_TIMEOUT_MS: u64 = 15_000;
const DEFAULT_RECEIPT_TIMEOUT_MS: u64 = 180_000;
/// How often the funding wallet's balance is read while waiting for ETH.
const DEFAULT_FUNDING_POLL_MS: u64 = 15_000;
/// How long `register-member` waits for the funding wallet to be funded.
const DEFAULT_WAIT_TIMEOUT_SECS: u64 = 3600;
/// Exit code when the funding wallet was not funded within `--wait-timeout`.
const EXIT_NOT_FUNDED: u8 = 4;
/// The file that holds the funding wallet's key, next to the identity.
const FUNDING_KEY_FILE: &str = "funding.key";
/// `0.0001 ETH`: a top-up after a partial payment is rounded up to this so it reads and types
/// well. A first quote is already a round figure (bond plus a reserve rung).
const SEND_GRANULARITY_WEI: u64 = 100_000_000_000_000;
const ANVIL_KEY_0: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const HELP: &str = r#"shadenet register-member — stake a member identity

usage: shadenet register-member --identity identity.json
       shadenet register-member <identity-commitment> [--limit N]
       [--contract 0xaddress] [--rpc-url https://...]
       [--key-file <owner-only-file>]
       [--funding-key <path>] [--wait-timeout <seconds>]

Without --key-file or SHADENET_REGISTER_KEY, register-member pays from a
funding wallet of its own: it creates an owner-only key at --funding-key
(default: funding.key next to the identity file, else in the config directory)
the first time, prints the wallet's address and the amount to send (the tier's
bond plus a gas reserve), waits for the balance to cover it, then stakes. The
same command resumes after Ctrl-C; an existing funding.key is reused, never
replaced. --wait-timeout (default 3600; 0 checks once) bounds the wait; an
unfunded wallet at the deadline exits 4 after printing what is still missing
(SHADENET_FUNDING_POLL_MS sets the poll interval, default 15000). Unspent gas
money stays in the funding wallet. The gas reserve is the smallest of 0.002,
0.004, 0.008 ... ETH that covers 1 800 000 gas at the current fee, so the
amount moves only in coarse steps and does not single out its sender; should
fees climb past it while the ETH is on its way, the signer's own balance check
refuses and the same command, run again, re-quotes the difference.

The funding address, the amount and the stake are public on chain, so whoever
sends the ETH is linked to this membership (not to its use: each request
carries an RLN proof that hides which member sent it). To keep your main
wallet out of it, send from a fresh address funded through a large shared pool
(Railgun, Privacy Pools, a CEX withdrawal), and send exactly the quoted amount.
The leftover gas money is tied to the stake too: send it on to a fresh
address, not back to the wallet that funded it.

The staking contract takes the identity commitment Poseidon1(identitySecret)
and derives the member leaf Poseidon2(identityCommitment, limit) itself, so the
bond always pays for the leaf's real tier. --identity reads the identitySecret,
leaf and tier from a Rust-compatible identity file, checks that they match,
computes the identity commitment locally, and never logs the secret. It cannot
be combined with a positional identity commitment. The funding key is
read from --key-file or SHADENET_REGISTER_KEY and signs
locally; it is never accepted as an argument or sent to the RPC. Without an
explicit contract/RPC, the bundled network's staking profile is used.
SHADENET_GROUP_CONTRACT, SHADENET_RPC_URL, SHADENET_LIMIT, and
SHADENET_BOND are the environment equivalents. SHADENET_CHAIN_ID overrides
the expected chain; the bundled public contract is pinned to Sepolia. A public Anvil development key
is selected only for a loopback RPC. The default tier is the network record's
staked defaultLimit."#;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CliOptions {
    commitment: Option<String>,
    limit: Option<String>,
    contract: Option<String>,
    rpc_url: Option<String>,
    key_file: Option<PathBuf>,
    identity: Option<PathBuf>,
    bond: Option<String>,
    funding_key: Option<PathBuf>,
    wait_timeout: Option<String>,
}

#[derive(Debug, Clone)]
struct Registration {
    registration: member::Registration,
    set: member::StakingSet,
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
            "--funding-key",
            "--wait-timeout",
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
                "--funding-key" => {
                    if out.funding_key.replace(PathBuf::from(value)).is_some() {
                        return Err("pass --funding-key only once".into());
                    }
                }
                "--wait-timeout" => {
                    if out.wait_timeout.replace(value).is_some() {
                        return Err("pass --wait-timeout only once".into());
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
    parse_uint(value, label)
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

/// Load (asking for the passphrase if the file is encrypted) and verify an identity file.
pub(crate) fn verified_identity(
    path: &Path,
    requested_limit: Option<u64>,
) -> Result<member::VerifiedIdentity, String> {
    let material = shadenet::identity::load(path, || {
        crate::passphrase::unlock(path).map_err(shadenet::Error::Config)
    })
    .map_err(|e| e.to_string())?;
    member::verify_identity(&material, requested_limit)
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
    let identity_raw = verified
        .as_ref()
        .map(|identity| identity.identity_commitment.to_string())
        .map(Ok)
        .unwrap_or_else(|| read_commitment(cli))?;
    let identity_commitment = parse_u256(&identity_raw, "identity commitment")?;
    let limit = verified
        .as_ref()
        .map(|identity| identity.limit)
        .or(requested_limit)
        .unwrap_or(bundled_limit);
    // The leaf the contract will derive; used for the already-staked checks and the output.
    let leaf = member::leaf_for(&identity_commitment, limit)?;
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
        registration: member::Registration {
            identity_commitment,
            leaf,
            limit,
            expected_bond: bond_override,
        },
        set: member::StakingSet {
            contract,
            rpc_url,
            expected_chain_id,
        },
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

/// The wallet an explicit key names: `--key-file`, `SHADENET_REGISTER_KEY`, or the public Anvil
/// key on a loopback RPC. `None` means no key was given and the funding wallet pays.
fn wallet_for(cli: &CliOptions, rpc_url: &str) -> Result<Option<Wallet>, String> {
    let key = Zeroizing::new(if let Some(path) = &cli.key_file {
        key_file(path)?
    } else if let Some(key) = shadenet::env::var("REGISTER_KEY")? {
        if key.trim().is_empty() {
            return Err("SHADENET_REGISTER_KEY is empty".into());
        }
        key
    } else if is_loopback_rpc(rpc_url) {
        ANVIL_KEY_0.to_string()
    } else {
        return Ok(None);
    });
    Wallet::from_hex(&key).map(Some)
}

/// Where the funding wallet's key lives: `--funding-key`, else next to the identity file, else
/// the config directory.
fn funding_key_path(cli: &CliOptions) -> Result<PathBuf, String> {
    if let Some(path) = &cli.funding_key {
        return Ok(path.clone());
    }
    if let Some(identity) = &cli.identity {
        let dir = identity
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        return Ok(dir.join(FUNDING_KEY_FILE));
    }
    crate::config_file::default_dir()
        .map(|dir| dir.join(FUNDING_KEY_FILE))
        .ok_or_else(|| "no config directory for the funding wallet; pass --funding-key".into())
}

/// Load the funding wallet at `path`, or create it owner-only. The second value says whether it
/// was created by this call. The key is never printed; only the address is.
fn load_or_create_funding_wallet(path: &Path) -> Result<(Wallet, bool), String> {
    if path.exists() {
        let key = Zeroizing::new(key_file(path)?);
        return Wallet::from_hex(&key)
            .map(|wallet| (wallet, false))
            .map_err(|error| format!("funding wallet {}: {error}", path.display()));
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let (wallet, secret) = Wallet::generate()?;
    let mut file = crate::enroll::private_open(path)?;
    let written = file
        .write_all(secret.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = written {
        let _ = fs::remove_file(path);
        return Err(format!("write {}: {error}", path.display()));
    }
    Ok((wallet, true))
}

fn funding_poll() -> Duration {
    Duration::from_millis(
        shadenet::env::var_lenient("FUNDING_POLL_MS")
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(DEFAULT_FUNDING_POLL_MS),
    )
}

fn wait_timeout(cli: &CliOptions) -> Result<Duration, String> {
    cli.wait_timeout
        .as_deref()
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|_| "--wait-timeout must be a number of seconds".to_string())
        })
        .transpose()
        .map(|secs| Duration::from_secs(secs.unwrap_or(DEFAULT_WAIT_TIMEOUT_SECS)))
}

/// `wei` rounded up to the next multiple of `SEND_GRANULARITY_WEI`, so the figure a person
/// copies into a wallet is short and always covers the quote.
fn round_up_to_send(wei: &U256) -> U256 {
    let unit = U256::from(SEND_GRANULARITY_WEI);
    let unit_big = unit.as_biguint();
    let rounded = ((wei.as_biguint() + unit_big - 1u32) / unit_big) * unit_big;
    U256::from_big_endian(&rounded.to_bytes_be()).unwrap_or_else(|| wei.clone())
}

fn eth(wei: &U256, chain_id: u64) -> String {
    crate::live::format_bond(&wei.to_string(), chain_id)
}

/// Why the funding path stopped without a funded wallet.
enum FundingStop {
    /// The deadline passed; the wallet still holds less than the quote (exit 4).
    NotFunded(String),
    /// The first quote failed, or the RPC kept failing until the deadline (exit 1).
    Rpc(String),
}

/// The funding path: quote the registration for the funding wallet, print the address and the
/// amount, and poll the balance until it covers the quote or the deadline passes. An RPC error
/// after the first quote is retried on the next poll, so a flaky endpoint does not lose the
/// wait; the first quote failing is reported at once.
fn wait_for_funding(
    rpc: &mut HttpRpc,
    registration: &Registration,
    wallet: &Wallet,
    key_path: &Path,
    created: bool,
    timeout: Duration,
) -> Result<Option<FundingQuote>, FundingStop> {
    let set = &registration.set;
    let reg = &registration.registration;
    let started = Instant::now();
    let poll = funding_poll();
    let mut last_report: Option<(U256, U256)> = None;
    loop {
        let quote = match member::funding_quote(rpc, set, reg, wallet.address) {
            Ok(Funding::AlreadyActive) => return Ok(None),
            Ok(Funding::Quote(quote)) => quote,
            Err(error) if last_report.is_some() && started.elapsed() < timeout => {
                eprintln!(
                    "  rpc: {error}; checking again in {} s",
                    poll.as_secs().max(1)
                );
                std::thread::sleep(poll);
                continue;
            }
            Err(error) => return Err(FundingStop::Rpc(error)),
        };
        let chain = quote.chain_id;
        if last_report.is_none() {
            println!(
                "No funded key was given (--key-file / SHADENET_REGISTER_KEY), so this machine's funding wallet pays:"
            );
            println!(
                "  wallet:   {}  ({}; owner-only; keep it, it holds the gas money)",
                key_path.display(),
                if created { "created now" } else { "existing" }
            );
            println!("  address:  {}", wallet.address);
            println!(
                "  bond:     {} (tier {})",
                eth(&quote.bond, chain),
                reg.limit
            );
            println!(
                "  gas:      up to {} reserved ({} gas at the current fee, rounded up to a 0.002 ETH x 2^k step)",
                eth(&quote.gas_reserve, chain),
                member::REGISTER_GAS_CEILING
            );
            println!("  balance:  {}", eth(&quote.balance, chain));
        }
        if quote.is_funded() {
            println!(
                "funded: {} covers the bond and gas reserve; staking.",
                eth(&quote.balance, chain)
            );
            return Ok(Some(quote));
        }
        let shortfall = quote.shortfall();
        let report = (quote.balance.clone(), shortfall.clone());
        if last_report.as_ref() != Some(&report) {
            let send = round_up_to_send(&shortfall);
            println!();
            println!(
                "Send {} to {} ({}).",
                eth(&send, chain),
                wallet.address,
                chain_label(chain)
            );
            if last_report.is_none() {
                println!("{FUNDING_PRIVACY}");
                if timeout.is_zero() {
                    println!("Not waiting (--wait-timeout 0); run the same command again once it has arrived.");
                } else {
                    println!(
                        "Waiting for it: checking every {} s, for up to {} s. Ctrl-C stops; the same command resumes.",
                        poll.as_secs().max(1),
                        timeout.as_secs()
                    );
                }
            } else {
                println!(
                    "  balance {}, {} still needed",
                    eth(&quote.balance, chain),
                    eth(&shortfall, chain)
                );
            }
            let _ = io::stdout().flush();
            last_report = Some(report);
        }
        if started.elapsed() >= timeout {
            return Err(FundingStop::NotFunded(format!(
                "funding wallet {} holds {}, {} short of the {} this registration needs; send the rest and run the same command again",
                wallet.address,
                eth(&quote.balance, chain),
                eth(&shortfall, chain),
                eth(&quote.required, chain)
            )));
        }
        std::thread::sleep(poll);
    }
}

/// Printed once with the first amount to send: the funding hop is the one on-chain link between
/// a wallet and a membership, and only the sender can break it (docs/PAYMENTS.md, Layer 0).
const FUNDING_PRIVACY: &str = "\
Privacy: this address, the amount and the stake are public on chain, so the wallet that sends
it is linked to this membership (not to its use; requests carry an RLN proof that hides which
member sent them). To keep your main wallet out of it, send from a fresh address funded
through a large shared pool (Railgun, Privacy Pools, a CEX withdrawal), and send exactly this
amount.";

/// Printed after a stake from the funding wallet: what is left is the unspent gas reserve.
fn leftover_note(rpc: &mut HttpRpc, wallet: &Wallet, block: &U256, key_path: &Path, chain_id: u64) {
    // Read at the stake's block: on 2026-10-20 `latest` came from a replica one block behind and
    // reported the whole deposit as left over. A replica that lacks the block errors; retry briefly.
    let mut left = None;
    for attempt in 0..5 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_secs(2));
        }
        if let Ok(balance) = member::balance_at(rpc, wallet.address, block) {
            left = Some(balance);
            break;
        }
    }
    let Some(left) = left else {
        return;
    };
    if left.is_zero() {
        return;
    }
    println!(
        "  leftover: {} stays in {} (the unspent gas reserve).",
        eth(&left, chain_id),
        key_path.display()
    );
    println!("            It is tied to this stake on chain: keep it for a later top-up, or send it to a");
    println!("            fresh address, not back to the wallet that funded it.");
}

fn chain_label(chain_id: u64) -> &'static str {
    match chain_id {
        1 => "Ethereum mainnet",
        11_155_111 => "Sepolia",
        17_000 => "Holesky",
        _ => "this chain",
    }
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

pub(crate) fn send_options() -> member::SendOptions {
    member::SendOptions {
        receipt_timeout: Duration::from_millis(receipt_timeout_ms()),
        ..member::SendOptions::default()
    }
}

pub(crate) fn http_rpc(url: &str) -> Result<HttpRpc, String> {
    HttpRpc::new(url, Duration::from_millis(rpc_timeout_ms()))
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
    let explicit = match wallet_for(&cli, &registration.set.rpc_url) {
        Ok(wallet) => wallet,
        Err(error) => {
            eprintln!("register-member: {error}");
            return ExitCode::from(2);
        }
    };
    let timeout = match wait_timeout(&cli) {
        Ok(timeout) => timeout,
        Err(error) => {
            eprintln!("register-member: {error}\n\n{HELP}");
            return ExitCode::from(2);
        }
    };
    // No explicit key: the funding wallet is loaded or created before any network request,
    // for the same reason.
    let funding = match &explicit {
        Some(_) => None,
        None => {
            let path = match funding_key_path(&cli) {
                Ok(path) => path,
                Err(error) => {
                    eprintln!("register-member: {error}");
                    return ExitCode::from(2);
                }
            };
            match load_or_create_funding_wallet(&path) {
                Ok((wallet, created)) => Some((wallet, path, created)),
                Err(error) => {
                    eprintln!("register-member: {error}");
                    return ExitCode::from(2);
                }
            }
        }
    };
    let mut rpc = match http_rpc(&registration.set.rpc_url) {
        Ok(rpc) => rpc,
        Err(error) => {
            eprintln!("register-member: {error}");
            return ExitCode::from(1);
        }
    };
    let mut funded_from: Option<(PathBuf, u64)> = None;
    let wallet = match (explicit, funding) {
        (Some(wallet), _) => wallet,
        (None, Some((wallet, path, created))) => {
            match wait_for_funding(&mut rpc, &registration, &wallet, &path, created, timeout) {
                Ok(Some(quote)) => {
                    funded_from = Some((path, quote.chain_id));
                    wallet
                }
                Ok(None) => {
                    println!("member is already staked; nothing to do.");
                    return ExitCode::SUCCESS;
                }
                Err(FundingStop::NotFunded(error)) => {
                    eprintln!("register-member: {error}");
                    return ExitCode::from(EXIT_NOT_FUNDED);
                }
                Err(FundingStop::Rpc(error)) => {
                    eprintln!("register-member: {error}");
                    return ExitCode::from(1);
                }
            }
        }
        (None, None) => unreachable!("a missing key always resolves to a funding wallet"),
    };
    let reg = &registration.registration;
    println!(
        "registerIdentity({}, {})",
        reg.identity_commitment, reg.limit
    );
    println!("  leaf:     {}", reg.leaf);
    println!("  contract: {}", registration.set.contract);
    println!("  rpc:      {}", rpc_label(&registration.set.rpc_url));
    println!("  from:     {}", wallet.address);
    let result = member::register(
        &mut rpc,
        &registration.set,
        reg,
        &wallet,
        send_options(),
        &mut |progress| match progress {
            Progress::Bond { wei } => {
                println!("  limit:    {}", reg.limit);
                println!("  bond:     {wei} wei");
            }
            Progress::Broadcast { hash } => {
                println!("  tx:       {hash}  (waiting for confirmation...)")
            }
            Progress::Proving => {}
        },
    );
    match result {
        Ok(RegisterOutcome::AlreadyActive) => {
            println!("member is already staked; nothing to do.");
            ExitCode::SUCCESS
        }
        Ok(RegisterOutcome::Mined(mined)) => {
            println!("  mined:    {} in block {}; member staked. Public admission begins after this block reaches finality.", mined.hash, mined.block);
            if let Some((path, chain_id)) = &funded_from {
                leftover_note(&mut rpc, &wallet, &mined.block, path, *chain_id);
            }
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
    use serde_json::{json, Value};
    use std::time::{SystemTime, UNIX_EPOCH};

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
        assert!(parse_args(&["123".into(), "456".into()]).is_err());
        assert!(parse_args(&["123".into(), "--register-key=secret".into()]).is_err());
        assert!(parse_args(&["123".into(), "--identity=identity.json".into()]).is_err());
    }

    #[test]
    fn parser_takes_funding_wallet_flags_once() {
        let parsed = parse_args(&[
            "--identity".into(),
            "identity.json".into(),
            "--funding-key=/tmp/f.key".into(),
            "--wait-timeout".into(),
            "0".into(),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(parsed.funding_key, Some(PathBuf::from("/tmp/f.key")));
        assert_eq!(parsed.wait_timeout.as_deref(), Some("0"));
        assert_eq!(wait_timeout(&parsed).unwrap(), Duration::ZERO);
        assert_eq!(
            wait_timeout(&CliOptions::default()).unwrap(),
            Duration::from_secs(DEFAULT_WAIT_TIMEOUT_SECS)
        );
        assert!(wait_timeout(&CliOptions {
            wait_timeout: Some("soon".into()),
            ..CliOptions::default()
        })
        .is_err());
        assert!(parse_args(&["--funding-key=a".into(), "--funding-key=b".into()]).is_err());
    }

    #[test]
    fn funding_key_sits_next_to_the_identity_unless_told_otherwise() {
        let beside = funding_key_path(&CliOptions {
            identity: Some(PathBuf::from("/srv/agent/identity.json")),
            ..CliOptions::default()
        })
        .unwrap();
        assert_eq!(beside, PathBuf::from("/srv/agent/funding.key"));
        let explicit = funding_key_path(&CliOptions {
            identity: Some(PathBuf::from("/srv/agent/identity.json")),
            funding_key: Some(PathBuf::from("/elsewhere/gas.key")),
            ..CliOptions::default()
        })
        .unwrap();
        assert_eq!(explicit, PathBuf::from("/elsewhere/gas.key"));
        let bare = funding_key_path(&CliOptions {
            identity: Some(PathBuf::from("identity.json")),
            ..CliOptions::default()
        })
        .unwrap();
        assert_eq!(bare, PathBuf::from("./funding.key"));
    }

    #[test]
    fn missing_key_on_a_remote_rpc_means_the_funding_wallet_pays() {
        let cli = CliOptions::default();
        assert!(wallet_for(&cli, "https://rpc.sepolia.example")
            .unwrap()
            .is_none());
        assert!(wallet_for(&cli, "http://127.0.0.1:8545").unwrap().is_some());
    }

    #[test]
    fn funding_wallet_is_created_owner_only_once_and_reused() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "shadenet-funding-wallet-{}-{nonce}",
            std::process::id()
        ));
        let path = dir.join("nested").join(FUNDING_KEY_FILE);
        let (first, created) = load_or_create_funding_wallet(&path).unwrap();
        assert!(created);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let stored = fs::read_to_string(&path).unwrap();
        assert_eq!(
            stored.trim().len(),
            66,
            "0x + 32 bytes of hex, newline-terminated"
        );
        assert_eq!(Wallet::from_hex(&stored).unwrap().address, first.address);
        let (second, created_again) = load_or_create_funding_wallet(&path).unwrap();
        assert!(!created_again);
        assert_eq!(second.address, first.address);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(load_or_create_funding_wallet(&path)
                .unwrap_err()
                .contains("chmod 600"));
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn send_amounts_round_up_to_a_tenth_of_a_milliether() {
        let unit = U256::from(SEND_GRANULARITY_WEI);
        assert_eq!(round_up_to_send(&U256::zero()), U256::zero());
        assert_eq!(round_up_to_send(&U256::from(1)), unit);
        assert_eq!(round_up_to_send(&unit), unit);
        // A sum that already sits on the grid (0.0148 ETH) is unchanged.
        let exact = U256::from(14_800_000_000_000_000);
        assert_eq!(round_up_to_send(&exact), exact);
        assert_eq!(
            round_up_to_send(&U256::from(14_800_000_000_000_001)),
            U256::from(14_900_000_000_000_000)
        );
        assert_eq!(
            eth(
                &round_up_to_send(&U256::from(14_800_000_000_000_001)),
                11_155_111
            ),
            "0.0149 Sepolia ETH"
        );
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
        // 3 is neither the bundled default nor the legacy fallback (8), so only a value read
        // from the record's field can produce it.
        let mut deployment: Value = serde_json::from_str(crate::DEFAULT_DEPLOYMENT).unwrap();
        deployment["admission"]["roots"]["staked"]["defaultLimit"] = json!(3);
        let parsed = crate::parse_bundled_deployment(&deployment.to_string()).unwrap();
        let (_, _, limit, _) = registration_defaults_from(parsed).unwrap();
        assert_eq!(limit, 3);
    }

    #[test]
    fn bad_key_error_never_echoes_secret() {
        let bad = "super-secret-not-a-key";
        let error = Wallet::from_hex(bad).err().unwrap();
        assert!(!error.contains(bad));
        assert!(error.contains("value not shown"));
    }

    #[test]
    fn key_files_must_be_owner_only() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "shadenet-register-key-{}-{nonce}",
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
            "shadenet-register-identity-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("identity.json");
        let material =
            shadenet_rln::identity::derive_identity(&format!("0x{}", "5a".repeat(32)), 1).unwrap();
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
        assert_eq!(registration.registration.limit, 1);
        assert_eq!(registration.registration.leaf.to_string(), material.leaf);
        let mut wrong: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        wrong["leaf"] = json!("1");
        fs::write(&path, serde_json::to_vec(&wrong).unwrap()).unwrap();
        assert!(resolve_registration(&cli)
            .unwrap_err()
            .contains("does not match"));
        fs::remove_dir_all(dir).unwrap();
    }
}
