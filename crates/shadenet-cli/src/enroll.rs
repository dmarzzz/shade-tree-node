//! Native, Node-free member enrollment for the Rust client.
//!
//! Enrollment has two deliberately separate outputs:
//! - the private identity file, written owner-only and consumed by `shade-tree egress`;
//! - the public RLN rate commitment (`leaf`), printed on stdout for an operator or
//!   optionally inserted into a local version-2 `members.json` demo set.
//!
//! The random application seed is intentionally not persisted. The derived
//! `identitySecret` in the identity file is the bearer material the Rust prover
//! needs, and keeping an additional equivalent secret would only widen exposure.

use serde::Serialize;
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const DEFAULT_IDENTITY_PATH: &str = "identity.json";
const BN254_FIELD: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

#[cfg(any(windows, test))]
fn windows_path_has_alternate_stream(path_units: &[u16]) -> bool {
    path_units.iter().enumerate().any(|(index, unit)| {
        if *unit != b':' as u16 {
            return false;
        }
        let drive_prefix = index == 1
            && path_units.first().is_some_and(|first| {
                (b'A' as u16..=b'Z' as u16).contains(first)
                    || (b'a' as u16..=b'z' as u16).contains(first)
            });
        !drive_prefix
    })
}

const HELP: &str = r#"shade-tree enroll — generate a private Rust identity and public enrollment leaf

usage: shade-tree enroll [--limit N] [--out identity.json]
                         [--members members.json]

The identity file is secret bearer material and is created owner-only (mode
0600 on Unix; a protected owner DACL on Windows). Its public leaf is printed
alone on stdout so it can be sent to a Grove operator.
Pass --members only for a local/demo version-2 membership set. Existing identity
files are never overwritten; choose a new path or remove the old credential first.
The tier defaults to the bundled staked root's defaultLimit (1 for the public
Grove); --limit or SHADE_TREE_LIMIT overrides it."#;

#[derive(Debug, Clone, PartialEq, Eq)]
struct EnrollOptions {
    limit: u64,
    out: PathBuf,
    members: Option<PathBuf>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IdentityOutput<'a> {
    identity_secret: &'a str,
    leaf: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<u64>,
}

fn flag_value(args: &[String], index: &mut usize, name: &str) -> Result<String, String> {
    let arg = &args[*index];
    if let Some(value) = arg.strip_prefix(&format!("{name}=")) {
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

fn parse_args_with_defaults(
    args: &[String],
    env_limit: Option<&str>,
    bundled_limit: u64,
) -> Result<Option<EnrollOptions>, String> {
    let mut options = EnrollOptions {
        limit: bundled_limit,
        out: PathBuf::from(DEFAULT_IDENTITY_PATH),
        members: None,
    };
    let mut cli_limit = false;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "--help" | "-h" => return Ok(None),
            "--commitment-only" | "--no-local" => {
                // Compatibility with the JavaScript enrollment vocabulary. The
                // Rust command is commitment-only unless --members is explicit.
            }
            "--limit" | "--out" | "--members" => {
                let name = arg.clone();
                let value = flag_value(args, &mut index, &name)?;
                match name.as_str() {
                    "--limit" => {
                        options.limit = value
                            .parse::<u64>()
                            .map_err(|_| "--limit must be an integer".to_string())?;
                        cli_limit = true;
                    }
                    "--out" => options.out = PathBuf::from(value),
                    "--members" => options.members = Some(PathBuf::from(value)),
                    _ => unreachable!(),
                }
            }
            _ if arg.starts_with("--limit=") => {
                options.limit = flag_value(args, &mut index, "--limit")?
                    .parse::<u64>()
                    .map_err(|_| "--limit must be an integer".to_string())?;
                cli_limit = true;
            }
            _ if arg.starts_with("--out=") => {
                options.out = PathBuf::from(flag_value(args, &mut index, "--out")?);
            }
            _ if arg.starts_with("--members=") => {
                options.members = Some(PathBuf::from(flag_value(args, &mut index, "--members")?));
            }
            _ => return Err(format!("unexpected argument {arg}")),
        }
        index += 1;
    }
    if !cli_limit {
        options.limit = crate::identity_creation_limit_setting(None, env_limit, options.limit)
            .map_err(|error| format!("SHADE_TREE_LIMIT: {error}"))?;
    }
    if options.limit == 0 || options.limit > u16::MAX as u64 {
        return Err(format!("--limit must be in 1..={}", u16::MAX));
    }
    if options.out.as_os_str().is_empty() {
        return Err("--out cannot be empty".to_string());
    }
    Ok(Some(options))
}

fn parse_args(args: &[String]) -> Result<Option<EnrollOptions>, String> {
    let env_limit = std::env::var("SHADE_TREE_LIMIT").ok();
    parse_args_with_defaults(args, env_limit.as_deref(), crate::default_staked_limit()?)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn private_open(path: &Path) -> Result<std::fs::File, String> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    let file = options
        .open(path)
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    if let Err(error) = file.set_permissions(fs::Permissions::from_mode(0o600)) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(format!("secure {}: {error}", path.display()));
    }
    let actual = match file.metadata() {
        Ok(metadata) => metadata.permissions().mode() & 0o777,
        Err(error) => {
            drop(file);
            let _ = fs::remove_file(path);
            return Err(format!("inspect {}: {error}", path.display()));
        }
    };
    if actual & 0o077 != 0 {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(format!(
            "{} did not enforce owner-only permissions (actual mode {actual:o}); refusing to write bearer material",
            path.display()
        ));
    }
    Ok(file)
}

#[cfg(target_os = "macos")]
fn private_open(path: &Path) -> Result<std::fs::File, String> {
    use std::ffi::{c_void, CString};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::ptr::null_mut;

    type FileSec = *mut c_void;
    type Acl = *mut c_void;
    type AclFlagSet = *mut c_void;
    const FILESEC_MODE: i32 = 4;
    const FILESEC_ACL: i32 = 5;
    const ACL_TYPE_EXTENDED: i32 = 0x0000_0100;
    const ACL_FLAG_NO_INHERIT: i32 = 1 << 17;

    unsafe extern "C" {
        fn filesec_init() -> FileSec;
        fn filesec_free(value: FileSec);
        fn filesec_set_property(value: FileSec, property: i32, data: *const c_void) -> i32;
        fn acl_init(count: i32) -> Acl;
        fn acl_free(value: *mut c_void) -> i32;
        fn acl_get_flagset_np(value: *mut c_void, flags: *mut AclFlagSet) -> i32;
        fn acl_add_flag_np(flags: AclFlagSet, flag: i32) -> i32;
        fn acl_get_fd_np(fd: i32, acl_type: i32) -> Acl;
        fn acl_get_entry(acl: Acl, entry_id: i32, entry: *mut *mut c_void) -> i32;
        fn openx_np(path: *const i8, flags: i32, security: FileSec) -> i32;
    }

    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("{} contains a NUL byte", path.display()))?;
    let security = unsafe { filesec_init() };
    if security.is_null() {
        return Err(format!(
            "prepare atomic macOS file security for {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    let acl = unsafe { acl_init(0) };
    if acl.is_null() {
        unsafe { filesec_free(security) };
        return Err(format!(
            "prepare empty macOS ACL for {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    let mode: libc::mode_t = 0o600;
    let mut acl_flags = null_mut();
    let set_no_inherit = unsafe {
        acl_get_flagset_np(acl, &mut acl_flags) == 0
            && acl_add_flag_np(acl_flags, ACL_FLAG_NO_INHERIT) == 0
    };
    let set_mode = unsafe {
        filesec_set_property(
            security,
            FILESEC_MODE,
            (&mode as *const libc::mode_t).cast(),
        )
    };
    let acl_pointer = acl;
    let set_acl =
        unsafe { filesec_set_property(security, FILESEC_ACL, (&acl_pointer as *const Acl).cast()) };
    if !set_no_inherit || set_mode != 0 || set_acl != 0 {
        let error = std::io::Error::last_os_error();
        unsafe {
            acl_free(acl);
            filesec_free(security);
        }
        return Err(format!(
            "configure atomic macOS file security for {}: {error}",
            path.display()
        ));
    }
    let fd = unsafe {
        openx_np(
            c_path.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
            security,
        )
    };
    unsafe {
        acl_free(acl);
        filesec_free(security);
    }
    if fd < 0 {
        return Err(format!(
            "write {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let verification = (|| {
        let mode = file
            .metadata()
            .map_err(|e| format!("inspect {}: {e}", path.display()))?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "{} did not atomically enforce mode 0600 (actual {mode:o})",
                path.display()
            ));
        }
        unsafe { *libc::__error() = 0 };
        let actual_acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
        if actual_acl.is_null() {
            let error = std::io::Error::last_os_error();
            // Darwin reports a file with no extended ACL as NULL + ENOENT.
            // Every other NULL result is an inspection failure and stays fatal.
            if error.raw_os_error() == Some(libc::ENOENT) {
                return Ok(());
            }
            return Err(format!(
                "inspect extended ACL on {}: {error}",
                path.display()
            ));
        }
        let mut entry = null_mut();
        unsafe { *libc::__error() = 0 };
        let entry_result = unsafe { acl_get_entry(actual_acl, 0, &mut entry) };
        let entry_error = std::io::Error::last_os_error();
        unsafe { acl_free(actual_acl) };
        if entry_result == 0 {
            return Err(format!("{} retained an extended ACL entry", path.display()));
        }
        if entry_error.raw_os_error() != Some(libc::EINVAL) {
            return Err(format!(
                "inspect extended ACL entries on {}: {entry_error}",
                path.display()
            ));
        }
        Ok::<(), String>(())
    })();
    if let Err(error) = verification {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(format!("{error}; refusing to write bearer material"));
    }
    Ok(file)
}

#[cfg(windows)]
fn private_open(path: &Path) -> Result<std::fs::File, String> {
    windows_private::create_owner_only(path)
}

#[cfg(not(any(unix, windows)))]
fn private_open(path: &Path) -> Result<std::fs::File, String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("write {}: {e}", path.display()))
}

fn write_identity(
    path: &Path,
    material: &shadenet_rln::identity::IdentityMaterial,
) -> Result<(), String> {
    let output = IdentityOutput {
        identity_secret: &material.identity_secret,
        leaf: &material.leaf,
        // Persist the exact tier so moving this identity between the public
        // profile and a custom Grove never silently changes its committed K.
        limit: Some(material.limit),
    };
    let mut body = serde_json::to_string_pretty(&output).expect("serialize identity");
    body.push('\n');
    let mut file = private_open(path)?;
    file.write_all(body.as_bytes())
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    file.sync_all()
        .map_err(|e| format!("sync {}: {e}", path.display()))?;
    Ok(())
}

fn validate_member(member: &Value, path: &Path) -> Result<(), String> {
    let value = member
        .as_str()
        .ok_or_else(|| format!("{}: every member must be a decimal string", path.display()))?;
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(format!(
            "{}: member values must be canonical unsigned decimal strings",
            path.display()
        ));
    }
    let parsed = num_bigint::BigUint::parse_bytes(value.as_bytes(), 10)
        .ok_or_else(|| format!("{}: invalid decimal member", path.display()))?;
    let field =
        num_bigint::BigUint::parse_bytes(BN254_FIELD.as_bytes(), 10).expect("BN254 field constant");
    if parsed >= field {
        return Err(format!(
            "{}: member is outside the canonical BN254 field",
            path.display()
        ));
    }
    Ok(())
}

fn atomic_replace(temporary: &Path, destination: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        return windows_private::replace_file(temporary, destination)
            .map_err(|e| format!("replace {}: {e}", destination.display()));
    }
    #[cfg(not(windows))]
    {
        fs::rename(temporary, destination)
            .map_err(|e| format!("replace {}: {e}", destination.display()))
    }
}

fn write_public_atomic(path: &Path, body: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("members.json");
    for _ in 0..8 {
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce)
            .map_err(|e| format!("operating-system randomness unavailable: {e}"))?;
        let temporary = parent.join(format!(".{file_name}.{}.tmp", hex::encode(nonce)));
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(format!("write {}: {error}", temporary.display())),
        };
        let result = (|| {
            file.write_all(body)
                .map_err(|e| format!("write {}: {e}", temporary.display()))?;
            file.sync_all()
                .map_err(|e| format!("sync {}: {e}", temporary.display()))?;
            drop(file);
            atomic_replace(&temporary, path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        return result;
    }
    Err(format!(
        "could not allocate a temporary file beside {}",
        path.display()
    ))
}

fn update_members(path: &Path, leaf: &str) -> Result<usize, String> {
    let mut document = if path.exists() {
        let bytes =
            fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        serde_json::from_str::<Value>(&bytes)
            .map_err(|e| format!("parse {}: {e}", path.display()))?
    } else {
        json!({ "version": 2, "members": [] })
    };
    let object = document
        .as_object_mut()
        .ok_or_else(|| format!("{}: expected a JSON object", path.display()))?;
    if object.get("version").and_then(Value::as_u64) != Some(2) {
        return Err(format!("{}: expected members version 2", path.display()));
    }
    let members = object
        .get_mut("members")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| format!("{}: expected a members array", path.display()))?;
    for member in members.iter() {
        validate_member(member, path)?;
    }
    if members.iter().any(|member| member.as_str() == Some(leaf)) {
        return Ok(members.len());
    }
    members.push(Value::String(leaf.to_string()));
    let count = members.len();
    let mut body = serde_json::to_string_pretty(&document).expect("serialize members");
    body.push('\n');
    write_public_atomic(path, body.as_bytes())?;
    Ok(count)
}

fn enroll_with_secret(
    options: &EnrollOptions,
    secret: &str,
) -> Result<(String, Option<usize>), String> {
    let material = shadenet_rln::identity::derive_identity(secret, options.limit)?;
    write_identity(&options.out, &material)?;
    let count = options
        .members
        .as_deref()
        .map(|path| update_members(path, &material.leaf))
        .transpose()?;
    Ok((material.leaf, count))
}

pub fn cmd_enroll(args: &[String]) -> ExitCode {
    let options = match parse_args(args) {
        Ok(Some(options)) => options,
        Ok(None) => {
            println!("{HELP}");
            return ExitCode::SUCCESS;
        }
        Err(error) => {
            eprintln!("enroll: {error}\n\n{HELP}");
            return ExitCode::from(2);
        }
    };
    let mut seed = [0u8; 32];
    if let Err(error) = getrandom::fill(&mut seed) {
        eprintln!("enroll: operating-system randomness unavailable: {error}");
        return ExitCode::from(1);
    }
    let secret = format!("0x{}", hex::encode(seed));
    match enroll_with_secret(&options, &secret) {
        Ok((leaf, count)) => {
            println!("{leaf}");
            eprintln!(
                "shade-tree enroll — wrote owner-only private identity {} (tier {})",
                options.out.display(),
                options.limit
            );
            if let (Some(path), Some(count)) = (&options.members, count) {
                eprintln!(
                    "  public leaf added to {} ({} member{})",
                    path.display(),
                    count,
                    if count == 1 { "" } else { "s" }
                );
            } else {
                eprintln!(
                    "  stake it with `shade-tree register-member --identity {}`, or submit the stdout leaf to your Grove operator; no local member set was changed",
                    options.out.display()
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("enroll: {error}");
            ExitCode::from(1)
        }
    }
}

pub fn cmd_proxy_token(args: &[String]) -> ExitCode {
    if matches!(args, [arg] if arg == "--help" || arg == "-h") {
        println!(
            "shade-tree proxy-token — print a fresh URL-safe proxy authentication token\n\nusage: shade-tree proxy-token"
        );
        return ExitCode::SUCCESS;
    }
    if !args.is_empty() {
        eprintln!("proxy-token: this command takes no arguments");
        return ExitCode::from(2);
    }
    let mut token = [0_u8; 32];
    if let Err(error) = getrandom::fill(&mut token) {
        eprintln!("proxy-token: operating-system randomness unavailable: {error}");
        return ExitCode::from(1);
    }
    println!("{}", hex::encode(token));
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "shade-tree-enroll-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn enrollment_writes_compatible_identity_and_public_member_only() {
        let dir = test_dir("compatible");
        let out = dir.join("identity.json");
        let members = dir.join("members.json");
        let options = EnrollOptions {
            limit: 32,
            out: out.clone(),
            members: Some(members.clone()),
        };
        let secret = format!("0x{}", "5a".repeat(32));
        let (leaf, count) = enroll_with_secret(&options, &secret).unwrap();
        assert_eq!(count, Some(1));
        assert_eq!(
            leaf,
            "8531432642199005327621956115945513784566419842920753480654713473814300694991"
        );
        let identity: Value = serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(identity["leaf"], leaf);
        assert_eq!(identity["limit"], 32);
        let set: Value = serde_json::from_str(&fs::read_to_string(&members).unwrap()).unwrap();
        assert_eq!(set, json!({ "version": 2, "members": [leaf] }));
        assert!(!fs::read_to_string(&members).unwrap().contains(&secret));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&out).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn enrollment_refuses_identity_overwrite_and_deduplicates_members() {
        let dir = test_dir("overwrite");
        let out = dir.join("identity.json");
        let members = dir.join("members.json");
        let options = EnrollOptions {
            limit: 8,
            out: out.clone(),
            members: Some(members.clone()),
        };
        let secret = format!("0x{}", "5a".repeat(32));
        let (leaf, _) = enroll_with_secret(&options, &secret).unwrap();
        assert!(enroll_with_secret(&options, &secret)
            .unwrap_err()
            .contains("write"));
        assert_eq!(update_members(&members, &leaf).unwrap(), 1);
        let set: Value = serde_json::from_str(&fs::read_to_string(&members).unwrap()).unwrap();
        assert_eq!(set["members"].as_array().unwrap().len(), 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn argument_parser_keeps_local_members_opt_in() {
        let parsed = parse_args(&["--limit=32".into(), "--out".into(), "member.json".into()])
            .unwrap()
            .unwrap();
        assert_eq!(parsed.limit, 32);
        assert_eq!(parsed.out, PathBuf::from("member.json"));
        assert_eq!(parsed.members, None);
        assert!(parse_args(&["--limit=0".into()]).is_err());
        assert!(parse_args(&["surprise".into()]).is_err());
    }

    #[test]
    fn public_default_and_explicit_limit_precedence_are_unambiguous() {
        assert_eq!(
            parse_args_with_defaults(&[], None, 1)
                .unwrap()
                .unwrap()
                .limit,
            1
        );
        assert_eq!(
            parse_args_with_defaults(&[], Some("32"), 1)
                .unwrap()
                .unwrap()
                .limit,
            32
        );
        assert_eq!(
            parse_args_with_defaults(&["--limit=8".into()], Some("32"), 1)
                .unwrap()
                .unwrap()
                .limit,
            8
        );
    }

    #[test]
    fn enroll_and_register_defaults_commit_to_the_same_public_limit() {
        let mut deployment: Value = serde_json::from_str(crate::DEFAULT_DEPLOYMENT).unwrap();
        deployment["admission"]["roots"]["staked"]["defaultLimit"] = json!(1);
        let parsed = crate::parse_bundled_deployment(&deployment.to_string()).unwrap();
        let (_, _, registration_limit, _) =
            crate::register::registration_defaults_from(parsed).unwrap();

        let dir = test_dir("public-default");
        let mut options = parse_args_with_defaults(&[], None, registration_limit)
            .unwrap()
            .unwrap();
        options.out = dir.join("identity.json");
        let secret = format!("0x{}", "5a".repeat(32));
        let (enrolled_leaf, _) = enroll_with_secret(&options, &secret).unwrap();
        let registered_tier_leaf =
            shadenet_rln::identity::derive_identity(&secret, registration_limit)
                .unwrap()
                .leaf;
        assert_eq!(options.limit, 1);
        assert_eq!(registration_limit, 1);
        assert_eq!(enrolled_leaf, registered_tier_leaf);
        let identity: Value =
            serde_json::from_str(&fs::read_to_string(&options.out).unwrap()).unwrap();
        assert_eq!(identity["limit"], 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn members_validation_runs_before_duplicate_shortcut() {
        let dir = test_dir("malformed");
        let members = dir.join("members.json");
        let leaf = "1";
        for malformed in [
            json!({ "version": 2, "members": [leaf, 123] }),
            json!({ "version": 2, "members": [leaf, "not-decimal"] }),
            json!({ "version": 2, "members": [leaf, "01"] }),
            json!({ "version": 2, "members": [leaf, BN254_FIELD] }),
        ] {
            fs::write(&members, serde_json::to_vec(&malformed).unwrap()).unwrap();
            assert!(
                update_members(&members, leaf).is_err(),
                "accepted {malformed}"
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn windows_ads_guard_only_exempts_ascii_drive_letters() {
        let units = |value: &str| value.encode_utf16().collect::<Vec<_>>();
        assert!(!windows_path_has_alternate_stream(&units(
            "C:\\identity.json"
        )));
        assert!(!windows_path_has_alternate_stream(&units(
            "a:identity.json"
        )));
        assert!(windows_path_has_alternate_stream(&units("1:s")));
        assert!(windows_path_has_alternate_stream(&units("Ł:secret")));
        assert!(windows_path_has_alternate_stream(&units(
            "identity.json:secret"
        )));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn enrollment_strips_inherited_macos_acl_before_writing_secret() {
        let dir = test_dir("macos-acl");
        let acl = std::process::Command::new("/bin/chmod")
            .arg("+a")
            .arg("everyone allow read,file_inherit")
            .arg(&dir)
            .status()
            .unwrap();
        assert!(acl.success(), "could not install inherited ACL fixture");
        let out = dir.join("identity.json");
        let options = EnrollOptions {
            limit: 8,
            out: out.clone(),
            members: None,
        };
        let secret = format!("0x{}", "5a".repeat(32));
        enroll_with_secret(&options, &secret).unwrap();
        let listing = std::process::Command::new("/bin/ls")
            .arg("-lde")
            .arg(&out)
            .output()
            .unwrap();
        let permissions = String::from_utf8_lossy(&listing.stdout)
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_string();
        assert!(!permissions.ends_with('+'), "ACL survived: {permissions}");
        fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(windows)]
mod windows_private {
    use std::ffi::{c_void, OsStr};
    use std::fs::File;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use std::path::Path;
    use std::ptr::null_mut;

    const GENERIC_WRITE: u32 = 0x4000_0000;
    const CREATE_NEW: u32 = 1;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    const SDDL_REVISION_1: u32 = 1;
    const FILE_PERSISTENT_ACLS: u32 = 0x8;
    const INVALID_HANDLE_VALUE: *mut c_void = -1_isize as *mut c_void;

    #[repr(C)]
    struct SecurityAttributes {
        length: u32,
        security_descriptor: *mut c_void,
        inherit_handle: i32,
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string: *const u16,
            revision: u32,
            descriptor: *mut *mut c_void,
            size: *mut u32,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share_mode: u32,
            security: *mut SecurityAttributes,
            creation: u32,
            flags: u32,
            template: *mut c_void,
        ) -> *mut c_void;
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
        fn MoveFileExW(existing: *const u16, replacement: *const u16, flags: u32) -> i32;
        fn GetVolumeInformationByHandleW(
            handle: *mut c_void,
            volume_name: *mut u16,
            volume_name_size: u32,
            serial_number: *mut u32,
            maximum_component_length: *mut u32,
            filesystem_flags: *mut u32,
            filesystem_name: *mut u16,
            filesystem_name_size: u32,
        ) -> i32;
    }

    fn wide(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(Some(0)).collect()
    }

    pub(super) fn create_owner_only(path: &Path) -> Result<File, String> {
        let path_units: Vec<u16> = path.as_os_str().encode_wide().collect();
        if super::windows_path_has_alternate_stream(&path_units) {
            return Err(format!(
                "{}: NTFS alternate data streams are not valid identity paths",
                path.display()
            ));
        }
        // Protected DACL: File All Access is granted only through the Windows
        // OWNER RIGHTS SID. CreateFile assigns the current token as owner.
        let sddl = wide(OsStr::new("D:P(A;;FA;;;OW)"));
        let mut descriptor = null_mut();
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        };
        if converted == 0 {
            return Err(format!(
                "build owner-only Windows ACL: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut security = SecurityAttributes {
            length: std::mem::size_of::<SecurityAttributes>() as u32,
            security_descriptor: descriptor,
            inherit_handle: 0,
        };
        let name = wide(path.as_os_str());
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_WRITE,
                0,
                &mut security,
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        let error = (handle == INVALID_HANDLE_VALUE).then(std::io::Error::last_os_error);
        unsafe {
            LocalFree(descriptor);
        }
        if let Some(error) = error {
            return Err(format!("write {}: {error}", path.display()));
        }
        // Verify the filesystem associated with the actual opened handle, not
        // a path checked before open (which could cross a swapped junction).
        // No secret bytes have been written yet, so failure is safe to delete.
        let mut filesystem_flags = 0_u32;
        let volume_ok = unsafe {
            GetVolumeInformationByHandleW(
                handle,
                null_mut(),
                0,
                null_mut(),
                null_mut(),
                &mut filesystem_flags,
                null_mut(),
                0,
            )
        };
        if volume_ok == 0 || filesystem_flags & FILE_PERSISTENT_ACLS == 0 {
            let volume_error = (volume_ok == 0).then(std::io::Error::last_os_error);
            drop(unsafe { File::from_raw_handle(handle) });
            let _ = std::fs::remove_file(path);
            return Err(match volume_error {
                Some(error) => format!(
                    "inspect Windows volume security for {}: {error}",
                    path.display()
                ),
                None => format!(
                    "{} is on a filesystem without persistent ACLs; refusing to write bearer material",
                    path.display()
                ),
            });
        }
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    pub(super) fn replace_file(temporary: &Path, destination: &Path) -> Result<(), String> {
        let from = wide(temporary.as_os_str());
        let to = wide(destination.as_os_str());
        let ok = unsafe {
            MoveFileExW(
                from.as_ptr(),
                to.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok == 0 {
            Err(std::io::Error::last_os_error().to_string())
        } else {
            Ok(())
        }
    }
}
