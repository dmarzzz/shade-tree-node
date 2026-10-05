//! Canopy-side diagnosis for `shadenet doctor`.
//!
//! The M7 rehearsal (docs/STAGING-REHEARSAL.md) showed that every real failure was
//! environmental and surfaced as something else: a public RPC pool returning an empty
//! `eth_getLogs` page became `gate:wrong-group-root`; a group-writable state directory became
//! "Arti refuses to start"; an identity staked in the staging set looked `not_admitted` on the
//! production record. Each check here answers one of those with a cause and the exact fix.
//!
//! Everything is blocking and self-contained so the CLI can run the checks one by one and print
//! as it goes; the Elder checks need the live client (Tor) and take it by reference.

use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::Serialize;
use serde_json::{json, Value};

use crate::leaves;
use crate::profile::{Network, PublicProfile};

/// The Elder Tree directory TTL (seconds): an entry older than this has aged out, and a
/// directory older than this means the Elder stopped refreshing it.
pub const DIRECTORY_TTL_SECS: u64 = 900;

/// `ok`, `warn` or `fail`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

/// One line of `shadenet doctor`: what was checked, what was found, and when something is
/// wrong, why and what to do.
#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: String,
    pub level: Level,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cause: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

impl Check {
    pub fn ok(name: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            level: Level::Ok,
            detail: detail.into(),
            cause: None,
            fix: None,
        }
    }

    pub fn warn(
        name: impl Into<String>,
        detail: impl Into<String>,
        cause: impl Into<String>,
        fix: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            level: Level::Warn,
            detail: detail.into(),
            cause: Some(cause.into()),
            fix: Some(fix.into()),
        }
    }

    pub fn fail(
        name: impl Into<String>,
        detail: impl Into<String>,
        cause: impl Into<String>,
        fix: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            level: Level::Fail,
            detail: detail.into(),
            cause: Some(cause.into()),
            fix: Some(fix.into()),
        }
    }
}

// ------------------------------------------------------------------- RPC

/// What one RPC endpoint in the record is good for.
#[derive(Debug, Clone, Serialize)]
pub struct RpcVerdict {
    pub url: String,
    pub reachable: bool,
    pub latency_ms: Option<u128>,
    pub head: Option<u64>,
    /// `ok`, `null` (the receipt of the deploy transaction is missing: a pruned backend),
    /// `error`, or `skipped` when the record has no deploy tx.
    pub receipt: String,
    /// `complete`, `partial` (dropped logs), `rate_limited`, `error`.
    pub members: String,
    pub live: Option<usize>,
    pub slots: Option<usize>,
    pub root: Option<String>,
    pub error: Option<String>,
}

/// Who reads the RPC lines. A client needs a complete member log and nothing else. An operator
/// (`shadenet doctor --rpc`, deploys and preflights) also reads receipts from the endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcAudience {
    Client,
    Operator,
}

/// Probe every RPC in the record (or the override list) for the three things the member-set
/// replay needs: a head block, the deploy receipt, and a complete log history. Then compare the
/// roots the good endpoints produced. A complete member log with a null deploy receipt is a
/// warning for an operator and an `ok` line with a note for a client.
pub fn check_rpcs(
    profile: &PublicProfile,
    deploy_tx: Option<&str>,
    rpc_override: Option<&[String]>,
    rln_identifier: u64,
    audience: RpcAudience,
) -> (Vec<Check>, Vec<RpcVerdict>) {
    let urls: Vec<String> = match rpc_override {
        Some(list) if !list.is_empty() => list.to_vec(),
        _ => profile.rpc_urls.clone(),
    };
    let mut checks = Vec::new();
    let mut verdicts = Vec::new();
    for url in &urls {
        let verdict = probe_rpc(url, profile, deploy_tx, rln_identifier);
        checks.push(rpc_check(&verdict, audience));
        verdicts.push(verdict);
    }
    let complete: Vec<&RpcVerdict> = verdicts
        .iter()
        .filter(|v| v.members == "complete")
        .collect();
    soften_covered_rpc_failures(&mut checks, &verdicts, audience);
    if urls.is_empty() {
        checks.push(Check::fail(
            "rpc",
            "no RPC endpoint configured",
            "the record names no rpcUrls and none was passed",
            "set SHADENET_RPC_URL to a Sepolia JSON-RPC endpoint",
        ));
    } else if complete.is_empty() {
        checks.push(Check::fail(
            "member set",
            "no endpoint returned a complete member log",
            "every RPC either dropped logs, rate-limited this client or was unreachable; the client would build a tree no node shares and be refused `gate:wrong-group-root`",
            "set SHADENET_RPC_URL to an endpoint with full Sepolia history (an archive node or a paid endpoint), or wait a minute if the only problem was a 429",
        ));
    } else {
        let roots: Vec<&str> = complete.iter().filter_map(|v| v.root.as_deref()).collect();
        let first = roots[0];
        if roots.iter().all(|r| *r == first) {
            let v = complete[0];
            checks.push(Check::ok(
                "member set",
                format!(
                    "{} live leaves in {} slots, root {}… (agreed by {} endpoint{})",
                    v.live.unwrap_or_default(),
                    v.slots.unwrap_or_default(),
                    &first[..first.len().min(12)],
                    complete.len(),
                    if complete.len() == 1 { "" } else { "s" }
                ),
            ));
        } else {
            let detail = complete
                .iter()
                .map(|v| {
                    format!(
                        "{} -> {}…",
                        crate::member::rpc_label(&v.url),
                        v.root
                            .as_deref()
                            .unwrap_or("?")
                            .chars()
                            .take(12)
                            .collect::<String>()
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            checks.push(Check::warn(
                "member set",
                detail,
                "complete endpoints disagree on the finalized root; one of them is behind the chain head",
                "prefer the endpoint whose head block is highest; the client already takes the first complete one in record order",
            ));
        }
    }
    (checks, verdicts)
}

fn probe_rpc(
    url: &str,
    profile: &PublicProfile,
    deploy_tx: Option<&str>,
    rln_identifier: u64,
) -> RpcVerdict {
    let mut verdict = RpcVerdict {
        url: url.to_string(),
        reachable: false,
        latency_ms: None,
        head: None,
        receipt: "skipped".into(),
        members: "error".into(),
        live: None,
        slots: None,
        root: None,
        error: None,
    };
    let mut rpc = match leaves::Rpc::new(url) {
        Ok(rpc) => rpc,
        Err(e) => {
            verdict.error = Some(e);
            return verdict;
        }
    };
    let started = Instant::now();
    match rpc.call("eth_blockNumber", json!([])) {
        Ok(Value::String(hex)) => {
            verdict.reachable = true;
            verdict.latency_ms = Some(started.elapsed().as_millis());
            verdict.head = u64::from_str_radix(hex.trim_start_matches("0x"), 16).ok();
        }
        Ok(_) => verdict.error = Some("eth_blockNumber returned a non-string".into()),
        Err(e) => {
            verdict.error = Some(e);
            return verdict;
        }
    }
    if let Some(tx) = deploy_tx.filter(|tx| tx.starts_with("0x") && tx.len() == 66) {
        verdict.receipt = match rpc.call("eth_getTransactionReceipt", json!([tx])) {
            Ok(Value::Null) => "null".into(),
            Ok(_) => "ok".into(),
            Err(e) => {
                verdict.error = Some(e);
                "error".into()
            }
        };
    }
    match leaves::fetch_members(
        url,
        &profile.contract,
        profile.deploy_block,
        "finalized",
        rln_identifier,
    ) {
        Ok(set) => {
            verdict.members = "complete".into();
            verdict.live = Some(set.live_count);
            verdict.slots = Some(set.document.members.len());
            verdict.root = Some(set.root);
        }
        Err(e) => {
            let lower = e.to_ascii_lowercase();
            verdict.members = if leaves::is_incomplete(&e) {
                "partial".into()
            } else if lower.contains("429") || lower.contains("too many") {
                "rate_limited".into()
            } else {
                "error".into()
            };
            verdict.error = Some(e);
        }
    }
    verdict
}

/// A client takes the first endpoint that returns a complete member log, so a broken fallback
/// is nothing a fresh install can or needs to fix: a warning, not a `fail`. Operators keep the
/// `fail`, since deploys and preflights read every endpoint.
fn soften_covered_rpc_failures(
    checks: &mut [Check],
    verdicts: &[RpcVerdict],
    audience: RpcAudience,
) {
    if audience != RpcAudience::Client {
        return;
    }
    let Some(good) = verdicts.iter().find(|v| v.members == "complete") else {
        return;
    };
    let good = crate::member::rpc_label(&good.url);
    for check in checks.iter_mut().filter(|c| c.level == Level::Fail) {
        check.level = Level::Warn;
        check.fix = Some(format!(
            "nothing to do on this machine: the client used {good}, which returned the full member set; report this endpoint so the record can drop it"
        ));
    }
}

fn rpc_check(v: &RpcVerdict, audience: RpcAudience) -> Check {
    let name = format!("rpc {}", crate::member::rpc_label(&v.url));
    if !v.reachable {
        return Check::fail(
            name,
            v.error.clone().unwrap_or_else(|| "unreachable".into()),
            "the endpoint did not answer eth_blockNumber",
            "if every endpoint fails, this machine has no HTTPS egress; otherwise the client already falls back to the next rpcUrls entry",
        );
    }
    let head = v.head.map(|h| format!("head {h}, ")).unwrap_or_default();
    let ms = v.latency_ms.unwrap_or_default();
    match v.members.as_str() {
        "complete" => {
            let complete = format!(
                "{head}{ms} ms, member log complete ({} live / {} slots)",
                v.live.unwrap_or_default(),
                v.slots.unwrap_or_default()
            );
            match (v.receipt.as_str(), audience) {
                ("null", RpcAudience::Operator) => Check::warn(
                    name,
                    format!("{head}{ms} ms, member log complete, but the deploy receipt came back null"),
                    "a pruned backend behind this pool answers some reads with nothing and no error; member-set replay was complete this time, receipts were not",
                    "fine for the client (it verifies the replay against the contract counters); for deploys and preflights put a full-history endpoint first in the record",
                ),
                // The client verifies the replay against the contract counters and never reads
                // a receipt: nothing for it to fix, so no warning on a fresh install.
                ("null", RpcAudience::Client) => Check::ok(
                    name,
                    format!("{complete}; deploy receipt null, which a client does not need (`shadenet doctor --rpc` has the detail)"),
                ),
                _ => Check::ok(name, complete),
            }
        }
        "partial" => Check::fail(
            name,
            format!("{head}{ms} ms, member log INCOMPLETE"),
            format!(
                "this endpoint returned an empty or short eth_getLogs page for the set's history ({}); a client that trusted it would present a root no node knows and be refused `gate:wrong-group-root`",
                v.error.as_deref().unwrap_or("dropped logs")
            ),
            "the client now fails closed on this and tries the next rpcUrls entry; move a full-history endpoint first with SHADENET_RPC_URL=<url>,<fallback>",
        ),
        "rate_limited" => Check::warn(
            name,
            format!("{head}{ms} ms, rate-limited while replaying the member log"),
            "the endpoint answered 429 Too Many Requests",
            "wait a minute, or put another rpcUrls entry first",
        ),
        _ => Check::fail(
            name,
            format!(
                "{head}{ms} ms, member log failed: {}",
                v.error.as_deref().unwrap_or("unknown")
            ),
            "the endpoint answered eth_blockNumber but not the log replay",
            "the client falls back to the next rpcUrls entry; report the endpoint if it is the record's first",
        ),
    }
}

// --------------------------------------------------------- state directories

/// Arti refuses a state directory that it, or any parent, lets the group or the world write
/// (`Incorrect permissions: … must be g-w`). Check the directories the client will use and
/// every existing ancestor up to the filesystem root, and the umask that will create the
/// missing ones.
pub fn check_state_dirs(
    tor_directories: Option<&(PathBuf, PathBuf)>,
    cache_dir: Option<&Path>,
) -> Vec<Check> {
    let mut checks = Vec::new();
    let mut dirs: Vec<(&str, &Path)> = Vec::new();
    if let Some((state, cache)) = tor_directories {
        dirs.push(("tor state dir", state.as_path()));
        dirs.push(("tor cache dir", cache.as_path()));
    }
    if let Some(cache) = cache_dir {
        dirs.push(("cache dir", cache));
    }
    for (name, dir) in dirs {
        match refused_by_arti(dir) {
            Some((offender, mode)) => checks.push(Check::fail(
                name,
                format!("{} is mode {mode:o}", offender.display()),
                format!(
                    "{} is group- or world-writable, and embedded Tor (Arti) refuses to start with a state directory whose path has one (the SearXNG example hit this with umask 002)",
                    offender.display()
                ),
                format!("chmod g-w,o-w {}", offender.display()),
            )),
            None => checks.push(Check::ok(
                name,
                format!(
                    "{}{}",
                    dir.display(),
                    if dir.exists() { "" } else { " (will be created)" }
                ),
            )),
        }
    }
    if let Some(check) = umask_check() {
        checks.push(check);
    }
    checks
}

/// The first directory on `dir`'s path that embedded Tor would refuse, with its mode. With the
/// `live` feature this asks fs-mistrust, the library Arti itself uses, so a group-writable
/// directory owned by the user's own self-named group (Ubuntu's default `user:user` with umask
/// 002) passes here exactly when it passes there. Without it, any group- or world-writable
/// directory outside the trusted prefixes counts, which can only over-warn.
fn refused_by_arti(dir: &Path) -> Option<(PathBuf, u32)> {
    let offender = first_group_writable(dir)?;
    #[cfg(all(unix, feature = "live"))]
    {
        let existing = dir.ancestors().find(|p| p.exists())?;
        // permit_readable: Arti creates its own state directory 0700; what it checks on the
        // way there is that no ancestor is writable by anyone untrusted, which is this rule.
        // Checked on Ubuntu: `dmarz:dmarz` 0775 accepted, 0777 refused.
        if fs_mistrust::Mistrust::new()
            .verifier()
            .permit_readable()
            .require_directory()
            .check(existing)
            .is_ok()
        {
            return None;
        }
    }
    Some(offender)
}

#[cfg(unix)]
fn first_group_writable(dir: &Path) -> Option<(PathBuf, u32)> {
    use std::os::unix::fs::PermissionsExt;
    let mut current = Some(dir);
    while let Some(path) = current {
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            // Arti's rule: nothing in the path may be writable by group or others. The root
            // directory and system prefixes are exempt in Arti (trusted); mirror that.
            if mode & 0o022 != 0 && !is_trusted_prefix(path) {
                return Some((path.to_path_buf(), mode));
            }
        }
        current = path.parent();
    }
    None
}

#[cfg(not(unix))]
fn first_group_writable(_dir: &Path) -> Option<(PathBuf, u32)> {
    None
}

fn is_trusted_prefix(path: &Path) -> bool {
    matches!(
        path.to_str(),
        Some("/")
            | Some("/Users")
            | Some("/home")
            | Some("/var")
            | Some("/tmp")
            | Some("/private")
            | Some("/private/var")
            | Some("/private/tmp")
            | Some("/opt")
            | Some("/srv")
    )
}

/// The process umask, read without touching the real one: create a scratch file requesting
/// 0666 and see what the kernel kept.
#[cfg(unix)]
pub fn current_umask() -> Option<u32> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    // Unique per call: parallel callers in one process (the doctor's tests run concurrently)
    // must not race on one probe file, or `create_new` fails and the check reads as "unknown".
    static PROBE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nonce = PROBE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        ".shadenet-umask-{}-{:?}-{}",
        std::process::id(),
        std::thread::current().id(),
        nonce
    ));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o666)
        .open(&path)
        .ok()?;
    let mode = file.metadata().ok()?.permissions().mode() & 0o777;
    drop(file);
    let _ = std::fs::remove_file(&path);
    Some(0o666 & !mode)
}

#[cfg(not(unix))]
pub fn current_umask() -> Option<u32> {
    None
}

fn umask_check() -> Option<Check> {
    let umask = current_umask()?;
    Some(if umask & 0o022 == 0o022 {
        Check::ok("umask", format!("{umask:03o}"))
    } else {
        Check::warn(
            "umask",
            format!("{umask:03o}"),
            "new directories will be group- or world-writable, and embedded Tor refuses such a state directory the first time it is created",
            "run the proxy with `umask 022` (in the shell, or `UMask=0022` in the systemd unit)",
        )
    })
}

// ----------------------------------------------------------------- version

/// The binary against the record. A release is cut at a tag, and the record that ships inside
/// that tagged binary names the fleet commit the canopy runs — always an EARLIER commit than the
/// tag — so comparing commits made every release binary warn against its own record. When the
/// record carries `services.node.version` we compare that against the binary's version instead:
/// a fresh install of the release the record expects is clean, and only a genuinely different
/// release (a real wire or artifact drift) warns. Records that predate the version field fall
/// back to the commit comparison, which still catches an off-release build.
pub fn check_version(
    binary_version: &str,
    binary_commit: Option<&str>,
    network: &Network,
) -> Check {
    let record_commit = network.deployment.node_commit.as_deref();
    let record_version = network.deployment.node_version.as_deref();
    let record_pin = match (record_version, record_commit) {
        (Some(v), Some(c)) => format!("version {v} (commit {})", &c[..c.len().min(7)]),
        (Some(v), None) => format!("version {v}"),
        (None, Some(c)) => format!("commit {}", &c[..c.len().min(7)]),
        (None, None) => "unknown".to_string(),
    };
    let detail = format!(
        "shadenet {binary_version} (commit {}); record {} pins node {record_pin}",
        binary_commit.unwrap_or("unknown"),
        network.name,
    );
    // The version comparison is the precise one: it holds across the release window the commit
    // comparison could not. Only when the record has no version do we fall back to the commit.
    if let Some(rec_version) = record_version {
        return if rec_version == binary_version {
            Check::ok("version", detail)
        } else {
            Check::warn(
                "version",
                detail,
                "this binary is a different release than the one the record's nodes run; across a wire or artifact change nodes refuse with `bad-version` or `bad-artifact`",
                "install the release the record pins: `curl … install.sh | SHADENET_VERSION=<tag> sh`, or `brew upgrade shadenet`",
            )
        };
    }
    match (binary_commit, record_commit) {
        (Some(bin), Some(rec)) if bin != "unknown" && !rec.starts_with(bin) && !bin.starts_with(&rec[..rec.len().min(bin.len())]) => Check::warn(
            "version",
            detail,
            "this binary was built from a different commit than the one the record's nodes run; inside a release window that is fine, across a wire or artifact change nodes refuse with `bad-version` or `bad-artifact`",
            "install the release the record pins: `curl … install.sh | SHADENET_VERSION=<tag> sh`, or `brew upgrade shadenet`",
        ),
        _ => Check::ok("version", detail),
    }
}

// ------------------------------------------------------------- identity set

/// Where a leaf is admitted, across the records the doctor knows (the active one and any
/// others it was handed). Answers "this identity is in the staging set but you are on the
/// production record".
pub fn check_identity_elsewhere(
    leaf: &str,
    active: &Network,
    others: &[Network],
    rln_identifier: u64,
) -> Vec<Check> {
    let mut checks = Vec::new();
    for network in others {
        if network.name == active.name {
            continue;
        }
        let Ok(profile) = network.public_profile() else {
            continue;
        };
        if active
            .public_profile()
            .map(|p| p.contract.eq_ignore_ascii_case(&profile.contract))
            .unwrap_or(false)
        {
            continue;
        }
        let mut found = None;
        let mut last_error = None;
        for url in &profile.rpc_urls {
            match leaves::fetch_members(
                url,
                &profile.contract,
                profile.deploy_block,
                "latest",
                rln_identifier,
            ) {
                Ok(set) => {
                    found = Some(set.document.members.iter().any(|m| m == leaf));
                    break;
                }
                Err(e) => last_error = Some(e),
            }
        }
        match found {
            Some(true) => checks.push(Check::warn(
                format!("identity in {}", network.name),
                format!("leaf is registered in {} ({})", network.name, profile.contract),
                format!(
                    "this identity was staked in the {} set, but the client runs on the {} record ({}); nodes of this canopy read the other set, so every proof is `not_admitted` here",
                    network.name,
                    active.name,
                    active.public_profile().map(|p| p.contract).unwrap_or_default()
                ),
                format!(
                    "either run against that network (`--network {}` or SHADENET_NETWORK=<path to its deployment.json>) or register this identity commitment here: `shadenet register-member --identity <file> --key-file <funded key>`",
                    network.name
                ),
            )),
            Some(false) => checks.push(Check::ok(
                format!("identity in {}", network.name),
                "not registered there either",
            )),
            None => checks.push(Check::warn(
                format!("identity in {}", network.name),
                last_error.unwrap_or_else(|| "no RPC".into()),
                "that record's RPCs could not be read, so the doctor cannot tell whether the leaf lives there",
                "retry, or check on the Get access page with the identity's commitment",
            )),
        }
    }
    checks
}

// ------------------------------------------------------------------ Elders

/// One Elder Tree as seen over Tor.
#[derive(Debug, Clone, Serialize)]
pub struct ElderVerdict {
    pub onion: String,
    pub reachable: bool,
    pub issued: Option<u64>,
    pub age_seconds: Option<u64>,
    pub gateways: Option<usize>,
    pub incidents: Vec<crate::incidents::Incident>,
    pub error: Option<String>,
    pub sets: SetsVerdict,
}

/// Judge one Elder from its fetched directory body (and incident feed body, when any).
pub fn judge_elder(
    onion: &str,
    signers: &str,
    directory: Result<String, String>,
    incidents: Option<Result<String, String>>,
    now: u64,
) -> (Check, ElderVerdict) {
    judge_elder_for_set(onion, signers, directory, incidents, now, None)
}

/// Which admission sets the listed nodes advertise (`caps.sets`), against ours.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SetsVerdict {
    /// Nodes that advertise any set.
    pub advertising: usize,
    /// Of those, nodes whose sets include ours.
    pub admitting: usize,
    /// Every set advertised by any node (lowercase addresses).
    pub advertised: Vec<String>,
}

/// [`judge_elder`], also judging the directory's nodes against our admission set when known.
pub fn judge_elder_for_set(
    onion: &str,
    signers: &str,
    directory: Result<String, String>,
    incidents: Option<Result<String, String>>,
    now: u64,
    our_set: Option<&str>,
) -> (Check, ElderVerdict) {
    let mut verdict = ElderVerdict {
        onion: onion.to_string(),
        reachable: false,
        issued: None,
        age_seconds: None,
        gateways: None,
        incidents: Vec::new(),
        error: None,
        sets: SetsVerdict::default(),
    };
    let label = format!("elder {}", &onion[..onion.len().min(12)]);
    let raw = match directory {
        Ok(raw) => raw,
        Err(e) => {
            verdict.error = Some(e.clone());
            return (
                Check::warn(
                    label,
                    e,
                    "this Elder Tree did not answer over Tor (down, restarting, or its onion descriptor is republishing after a restart)",
                    "nothing to do while another Elder answers; the client merges every Elder's canopy. If every Elder fails, check Tor with the `tor` line above",
                ),
                verdict,
            );
        }
    };
    verdict.reachable = true;
    let doc = match crate::dircache::parse_and_verify_document(&raw, signers) {
        Ok(doc) => doc,
        Err(e) => {
            verdict.error = Some(e.clone());
            return (
                Check::fail(
                    label,
                    e,
                    "the directory this Elder served does not verify under the pinned canopy signer",
                    "the record's canopySigner and the Elder's key disagree: update the record (or the binary) to the current release",
                ),
                verdict,
            );
        }
    };
    let dir = doc.dir;
    verdict.issued = Some(dir.issued);
    verdict.gateways = Some(dir.gateways.len());
    let age = now.saturating_sub(dir.issued);
    verdict.age_seconds = Some(age);
    if let Some(Ok(raw)) = incidents {
        if let Ok(feed) = crate::incidents::parse_and_verify(&raw, signers, now) {
            verdict.incidents = feed.active(now).into_iter().cloned().collect();
        }
    }
    let ours = our_set.map(str::to_ascii_lowercase);
    let mut advertised = std::collections::BTreeSet::new();
    for g in &dir.gateways {
        if let Some(sets) = g
            .caps
            .as_ref()
            .and_then(|c| shadenet_proto::canonical_caps(c).sets)
        {
            verdict.sets.advertising += 1;
            if ours.as_deref().is_some_and(|o| sets.iter().any(|s| s == o)) {
                verdict.sets.admitting += 1;
            }
            advertised.extend(sets);
        }
    }
    verdict.sets.advertised = advertised.into_iter().collect();
    let incident_note = if verdict.incidents.is_empty() {
        String::new()
    } else {
        format!(
            ", {} open incident(s): {}",
            verdict.incidents.len(),
            verdict
                .incidents
                .iter()
                .map(|i| format!("{} ({})", i.id, i.summary))
                .collect::<Vec<_>>()
                .join("; ")
        )
    };
    let check = if age > DIRECTORY_TTL_SECS {
        Check::warn(
            label,
            format!("directory issued {age}s ago, {} node(s){incident_note}", dir.gateways.len()),
            format!("this Elder's directory is older than the {DIRECTORY_TTL_SECS}s TTL: it stopped refreshing (its process is wedged or no node has announced to it)"),
            "the client prefers the fresher Elder automatically; operators: restart the Elder and check the heartbeat fan-out gauge",
        )
    } else if dir.gateways.is_empty() {
        Check::warn(
            label,
            format!("directory fresh ({age}s) but lists no nodes{incident_note}"),
            "no node has announced to this Elder within the TTL",
            "if the other Elder lists nodes, this one's heartbeat fan-out is broken (ADR 0012); operators check `shade_tree_heartbeat_elders_accepted`",
        )
    } else {
        Check::ok(
            label,
            format!(
                "directory {age}s old, {} node(s){incident_note}",
                dir.gateways.len()
            ),
        )
    };
    (check, verdict)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict(url: &str, members: &str) -> RpcVerdict {
        RpcVerdict {
            url: url.into(),
            reachable: true,
            latency_ms: Some(100),
            head: Some(1),
            receipt: "ok".into(),
            members: members.into(),
            live: Some(1),
            slots: Some(1),
            root: Some("1".into()),
            error: (members != "complete").then(|| "pruned history unavailable".into()),
        }
    }

    #[test]
    fn a_broken_fallback_rpc_is_a_warning_for_a_client_when_another_is_complete() {
        let verdicts = [
            verdict("https://good.example", "complete"),
            verdict("https://pruned.example", "error"),
        ];
        let checks = |audience| {
            let mut c: Vec<Check> = verdicts.iter().map(|v| rpc_check(v, audience)).collect();
            soften_covered_rpc_failures(&mut c, &verdicts, audience);
            c
        };
        let client = checks(RpcAudience::Client);
        assert_eq!(client[1].level, Level::Warn, "{client:?}");
        assert!(client[1]
            .fix
            .as_deref()
            .unwrap()
            .contains("nothing to do on this machine"));
        // Operators still see the fail: deploys read every endpoint.
        assert_eq!(checks(RpcAudience::Operator)[1].level, Level::Fail);
        // With no complete endpoint, the client's fail stays.
        let only_bad = [verdict("https://pruned.example", "error")];
        let mut c = vec![rpc_check(&only_bad[0], RpcAudience::Client)];
        soften_covered_rpc_failures(&mut c, &only_bad, RpcAudience::Client);
        assert_eq!(c[0].level, Level::Fail);
    }

    #[test]
    fn umask_is_readable_and_checks_022() {
        // Read the umask from several threads at once: the probe must not collide with itself.
        let reads: Vec<Option<u32>> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..8).map(|_| s.spawn(current_umask)).collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        let umask = reads[0].expect("umask");
        assert!(umask <= 0o777);
        assert!(reads.iter().all(|r| *r == Some(umask)), "{reads:?}");
        let check = umask_check().unwrap();
        assert_eq!(check.level == Level::Ok, umask & 0o022 == 0o022);
    }

    #[test]
    fn group_writable_ancestor_is_named_with_a_chmod() {
        let base = std::env::temp_dir().join(format!("shadenet-doctor-{}", std::process::id()));
        let loose = base.join("loose");
        let state = loose.join("state").join("arti");
        std::fs::create_dir_all(&state).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
            // World-writable: refused whatever the group (a self-named group may own `loose` on Linux).
            std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o777)).unwrap();
            std::fs::set_permissions(loose.join("state"), std::fs::Permissions::from_mode(0o755))
                .unwrap();
            std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
            let checks = check_state_dirs(Some(&(state.clone(), state.clone())), None);
            let tor = &checks[0];
            assert_eq!(tor.level, Level::Fail, "{tor:?}");
            assert!(tor.fix.as_deref().unwrap().contains("chmod g-w,o-w"));
            assert!(tor.detail.contains("loose"), "{}", tor.detail);
            std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).unwrap();
            let checks = check_state_dirs(Some(&(state.clone(), state.clone())), Some(&state));
            assert!(
                checks.iter().take(3).all(|c| c.level == Level::Ok),
                "{checks:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn version_mismatch_is_a_warning_with_an_install_line() {
        // Legacy records (no services.node.version): fall back to the commit comparison.
        let mut net = Network::bundled("sepolia").unwrap();
        net.deployment.node_commit = Some("abcdef1234567890".into());
        net.deployment.node_version = None;
        let same = check_version("0.7.0", Some("abcdef123456"), &net);
        assert_eq!(same.level, Level::Ok);
        let other = check_version("0.7.0", Some("000000000000"), &net);
        assert_eq!(other.level, Level::Warn);
        assert!(other.fix.unwrap().contains("install.sh"));
        let unknown = check_version("0.7.0", None, &net);
        assert_eq!(unknown.level, Level::Ok);
    }

    #[test]
    fn same_release_is_clean_even_when_the_record_names_an_earlier_fleet_commit() {
        // A tagged release ships a record that pins an EARLIER fleet commit but the SAME version.
        // The fresh install must not warn: version wins over the commit.
        let mut net = Network::bundled("sepolia").unwrap();
        net.deployment.node_version = Some("0.7.2".into());
        // Record's fleet commit is deliberately different from the build commit (the real case).
        net.deployment.node_commit = Some("1111111111111111111111111111111111111111".into());
        let fresh = check_version(
            "0.7.2",
            Some("2222222222222222222222222222222222222222"),
            &net,
        );
        assert_eq!(fresh.level, Level::Ok, "{fresh:?}");
        assert!(fresh.detail.contains("version 0.7.2"));

        // A genuinely older record (different version) still warns, even if the commit matched.
        net.deployment.node_version = Some("0.7.1".into());
        let older = check_version(
            "0.7.2",
            Some("2222222222222222222222222222222222222222"),
            &net,
        );
        assert_eq!(older.level, Level::Warn, "{older:?}");
        assert!(older.fix.unwrap().contains("install.sh"));

        // A newer record than the binary also warns.
        net.deployment.node_version = Some("0.8.0".into());
        let newer = check_version(
            "0.7.2",
            Some("2222222222222222222222222222222222222222"),
            &net,
        );
        assert_eq!(newer.level, Level::Warn, "{newer:?}");
    }

    #[test]
    fn elder_verdicts_cover_down_stale_empty_and_fresh() {
        let signer = "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29";
        let (down, v) = judge_elder("abc", signer, Err("connect: timed out".into()), None, 1000);
        assert_eq!(down.level, Level::Warn);
        assert!(!v.reachable);
        assert!(down.cause.unwrap().contains("descriptor"));
        let (bad, _) = judge_elder(
            "abc",
            signer,
            Ok("{\"version\":1,\"issued\":1,\"gateways\":[]}".into()),
            None,
            1000,
        );
        assert_eq!(bad.level, Level::Fail);
    }

    /// A fake JSON-RPC endpoint on loopback that answers each method with a canned response,
    /// so the RPC verdicts for the rehearsal's three failure modes are pinned.
    fn fake_rpc(script: Vec<(&'static str, Value)>, status: u16) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buf = vec![0u8; 65536];
                let mut total = 0;
                loop {
                    let n = stream.read(&mut buf[total..]).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    total += n;
                    let text = String::from_utf8_lossy(&buf[..total]);
                    if let Some(idx) = text.find("\r\n\r\n") {
                        let len: usize = text
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        if total >= idx + 4 + len {
                            break;
                        }
                    }
                }
                let text = String::from_utf8_lossy(&buf[..total]).to_string();
                let body_start = text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(text.len());
                let request: Value =
                    serde_json::from_str(&text[body_start..]).unwrap_or(Value::Null);
                let method = request["method"].as_str().unwrap_or("");
                let result = script
                    .iter()
                    .find(|(m, _)| *m == method)
                    .map(|(_, r)| r.clone())
                    .unwrap_or(Value::Null);
                let body = json!({"jsonrpc":"2.0","id":request["id"],"result":result}).to_string();
                let reason = if status == 200 {
                    "OK"
                } else {
                    "Too Many Requests"
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        url
    }

    const TX: &str = "0xabababababababababababababababababababababababababababababababab";

    fn profile_for(url: &str) -> PublicProfile {
        let mut net = Network::bundled("sepolia").unwrap();
        let mut profile = net.public_profile().unwrap();
        profile.rpc_urls = vec![url.to_string()];
        profile.rpc_url = url.to_string();
        profile.deploy_block = 10;
        net.name.clear();
        profile
    }

    #[test]
    fn empty_log_page_is_reported_as_partial_history() {
        // nextIndex() = 2 and activeCount() = 2 but eth_getLogs returns nothing: the exact M7 shape.
        let word2 = format!("0x{:064x}", 2);
        let url = fake_rpc(
            vec![
                ("eth_blockNumber", json!("0x64")),
                ("eth_getBlockByNumber", json!({"number":"0x64"})),
                ("eth_getTransactionReceipt", Value::Null),
                ("eth_call", json!(word2)),
                ("eth_getLogs", json!([])),
            ],
            200,
        );
        let (checks, verdicts) =
            check_rpcs(&profile_for(&url), Some(TX), None, 1, RpcAudience::Client);
        assert_eq!(verdicts[0].members, "partial", "{verdicts:?}");
        assert_eq!(verdicts[0].receipt, "null");
        assert_eq!(checks[0].level, Level::Fail);
        assert!(checks[0]
            .cause
            .as_deref()
            .unwrap()
            .contains("wrong-group-root"));
        assert!(checks[0]
            .fix
            .as_deref()
            .unwrap()
            .contains("SHADENET_RPC_URL"));
        assert_eq!(checks.last().unwrap().name, "member set");
        assert_eq!(checks.last().unwrap().level, Level::Fail);
    }

    #[test]
    fn rate_limited_endpoint_is_a_warning() {
        let url = fake_rpc(vec![], 429);
        let (checks, verdicts) =
            check_rpcs(&profile_for(&url), Some(TX), None, 1, RpcAudience::Client);
        // eth_blockNumber itself 429s here, so the endpoint reads as unreachable with the reason.
        assert!(!verdicts[0].reachable);
        assert_eq!(checks[0].level, Level::Fail);
        assert!(checks[0].detail.contains("429"), "{}", checks[0].detail);
    }

    fn null_receipt_rpc() -> String {
        let word0 = format!("0x{:064x}", 0);
        fake_rpc(
            vec![
                ("eth_blockNumber", json!("0x64")),
                ("eth_getBlockByNumber", json!({"number":"0x64"})),
                ("eth_getTransactionReceipt", Value::Null),
                ("eth_call", json!(word0)),
                ("eth_getLogs", json!([])),
            ],
            200,
        )
    }

    #[test]
    fn complete_history_with_null_receipt_is_ok_with_a_note_for_a_client() {
        // A fresh install against a pool with a pruned backend: nothing for the client to fix,
        // so the line is `ok` and carries the note; the verdict still records the null receipt.
        let url = null_receipt_rpc();
        let (checks, verdicts) =
            check_rpcs(&profile_for(&url), Some(TX), None, 1, RpcAudience::Client);
        assert_eq!(verdicts[0].members, "complete");
        assert_eq!(verdicts[0].receipt, "null");
        assert_eq!(checks[0].level, Level::Ok);
        assert!(
            checks[0]
                .detail
                .contains("member log complete (0 live / 0 slots); deploy receipt null"),
            "{}",
            checks[0].detail
        );
        assert!(checks[0].detail.contains("doctor --rpc"));
        assert!(checks[0].cause.is_none() && checks[0].fix.is_none());
        assert_eq!(checks[1].level, Level::Ok);
        assert!(checks.iter().all(|check| check.level == Level::Ok));
    }

    #[test]
    fn complete_history_with_null_receipt_stays_a_warning_for_an_operator() {
        // `shadenet doctor --rpc` rates endpoints for deploys and preflights, which read receipts.
        let url = null_receipt_rpc();
        let (checks, verdicts) =
            check_rpcs(&profile_for(&url), Some(TX), None, 1, RpcAudience::Operator);
        assert_eq!(verdicts[0].members, "complete");
        assert_eq!(checks[0].level, Level::Warn);
        assert!(checks[0].detail.contains("deploy receipt came back null"));
        assert!(checks[0].cause.as_deref().unwrap().contains("pruned"));
        assert!(checks[0].fix.as_deref().unwrap().contains("full-history"));
        assert_eq!(checks[1].level, Level::Ok);
    }
}
