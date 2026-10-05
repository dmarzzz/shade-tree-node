//! Native, Node-free member staking for the Rust client.
//!
//! The funding key is loaded from an owner-only file or an environment variable,
//! signs an EIP-1559 transaction locally, and is never sent to the RPC. The public
//! Sepolia contract and RPC come from the same bundled deployment record as default
//! Elder discovery; explicit CLI/environment values always win.

use shadenet::eth::{Address, Wallet, U256};
use shadenet::member::{
    self, is_loopback_rpc, parse_uint, rpc_label, HttpRpc, Progress, RegisterOutcome,
};
use std::fs;
use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;
use zeroize::Zeroizing;

const DEFAULT_RPC_TIMEOUT_MS: u64 = 15_000;
const DEFAULT_RECEIPT_TIMEOUT_MS: u64 = 180_000;
const ANVIL_KEY_0: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

const HELP: &str = r#"shadenet register-member — stake a member identity

usage: shadenet register-member --identity identity.json
       shadenet register-member <identity-commitment> [--limit N]
       [--contract 0xaddress] [--rpc-url https://...]
       [--key-file <owner-only-file>]

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

fn wallet_for(cli: &CliOptions, rpc_url: &str) -> Result<Wallet, String> {
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
        return Err(
            "member registration on a non-loopback RPC needs --key-file or SHADENET_REGISTER_KEY; the public Anvil key is never used remotely"
                .into(),
        );
    });
    Wallet::from_hex(&key)
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
    let wallet = match wallet_for(&cli, &registration.set.rpc_url) {
        Ok(wallet) => wallet,
        Err(error) => {
            eprintln!("register-member: {error}");
            return ExitCode::from(2);
        }
    };
    let mut rpc = match http_rpc(&registration.set.rpc_url) {
        Ok(rpc) => rpc,
        Err(error) => {
            eprintln!("register-member: {error}");
            return ExitCode::from(1);
        }
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
