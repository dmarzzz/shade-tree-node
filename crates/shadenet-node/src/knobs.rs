//! The operator front door's knobs (`packages/node/lib/node-config.mjs`): the few settings of
//! `shadenet-node`, read from `SHADENET_*` or `<state>/node.toml`, validated together so an
//! operator sees every mistake at once. Everything else comes from the deployment record.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub(crate) const GATEWAY_PORT: u16 = 8443;
pub(crate) const TOR_SOCKS_PORT: u16 = 9050;
const DEFAULT_WEIGHT: &str = "100";
const DEFAULT_LOG: &str = "json:info";
const DEFAULT_ADMIT: &str = "staked";
const DEFAULT_ALLOW: &str = "*:443";
const DEFAULT_PROFILE: &str = "default";
// what `profile = "home"` sets for the knobs the operator left at their default
const HOME_WEIGHT: &str = "10";
const HOME_CONNS: &str = "32";
const HOME_SESSIONS: &str = "4";
const HOME_BANDWIDTH: &str = "2m";
const HOME_CANARY: &str = "on";

/// One knob: its environment name, its `node.toml` key and what it sets.
pub(crate) struct Knob {
    pub(crate) key: &'static str,
    pub(crate) env: &'static str,
    pub(crate) what: &'static str,
    pub(crate) default: Option<&'static str>,
}

pub(crate) const KNOBS: &[Knob] = &[
    Knob { key: "record", env: "SHADENET_RECORD", what: "deployment record: https URL or file path (required)", default: None },
    Knob { key: "state", env: "SHADENET_STATE", what: "state directory: onion identity, Tor state, spent set, logs", default: Some("") },
    Knob { key: "admit", env: "SHADENET_ADMIT", what: "who this node admits: staked | invited,staked | staked,paid (ADR 0008)", default: Some(DEFAULT_ADMIT) },
    Knob { key: "sets", env: "SHADENET_SETS", what: "extra staked sets to admit besides the record's: 0xcontract@deployBlock, comma-separated (one node, several canopies)", default: Some("") },
    Knob { key: "members_file", env: "SHADENET_MEMBERS_FILE", what: "operator-owned members.json for the invited path", default: None },
    Knob { key: "allow", env: "SHADENET_ALLOW", what: "egress allow list, host:port patterns", default: Some(DEFAULT_ALLOW) },
    Knob { key: "deny", env: "SHADENET_DENY", what: "egress deny list; deny wins", default: Some("") },
    Knob { key: "deny_file", env: "SHADENET_DENY_FILE", what: "hosts-format or domain-list blocklist on the deny side (absolute path); re-read when it changes", default: None },
    Knob { key: "profile", env: "SHADENET_PROFILE", what: "preset: default | home (a node on a home connection: weight 10, conns 32, sessions 4, bandwidth 2m, canary on unless set)", default: Some(DEFAULT_PROFILE) },
    Knob { key: "weight", env: "SHADENET_WEIGHT", what: "selection weight 1..1000 (lower = less traffic lands here)", default: Some(DEFAULT_WEIGHT) },
    Knob { key: "conns", env: "SHADENET_CONNS", what: "max concurrent tunnels; the node's own default is 1024, 0 = unlimited", default: Some("") },
    Knob { key: "sessions", env: "SHADENET_SESSIONS", what: "max live session-ticket books; the node's own default is 256, 0 = unlimited", default: Some("") },
    Knob { key: "bandwidth", env: "SHADENET_BANDWIDTH", what: "bytes per second this node relays in total, both directions (k or m suffix); unset or 0 = unlimited", default: Some("") },
    Knob { key: "canary", env: "SHADENET_CANARY", what: "reputation canary: on | off (drains the node while probes from its address are challenged)", default: Some("off") },
    Knob { key: "region", env: "SHADENET_REGION", what: "coarse region bucket advertised: na sa eu af as oc aq unknown", default: Some("") },
    Knob { key: "metrics", env: "SHADENET_METRICS", what: "Prometheus port on loopback, or off", default: Some("9101") },
    Knob { key: "log", env: "SHADENET_LOG", what: "log format json | pretty | text, with an optional :level", default: Some(DEFAULT_LOG) },
    Knob { key: "operator_key_file", env: "SHADENET_OPERATOR_KEY_FILE", what: "file holding the staked operator key (stake-admission canopies)", default: None },
    Knob { key: "operator", env: "SHADENET_OPERATOR", what: "operator address, with operator_sig instead of a key on the box", default: None },
    Knob { key: "operator_sig", env: "SHADENET_OPERATOR_SIG", what: "operator signature over operatorAuthMessage(onion, operator)", default: None },
    Knob { key: "pow", env: "SHADENET_POW", what: "onion proof-of-work defense (needs a Tor built with the pow module)", default: Some("false") },
];

/// `/state` when it exists on Linux (the image), else `./shadenet-node`.
pub(crate) fn default_state_dir() -> PathBuf {
    if cfg!(target_os = "linux") && Path::new("/state").is_dir() {
        PathBuf::from("/state")
    } else {
        PathBuf::from("./shadenet-node")
    }
}

/// The resolved knobs. Values keep their text form; `pow` is the one boolean.
#[derive(Debug, Clone, Default)]
pub(crate) struct Knobs {
    pub(crate) record: Option<String>,
    pub(crate) state: PathBuf,
    pub(crate) admit: String,
    pub(crate) sets: String,
    pub(crate) members_file: Option<String>,
    pub(crate) allow: String,
    pub(crate) deny: String,
    pub(crate) deny_file: Option<String>,
    pub(crate) profile: String,
    pub(crate) weight: String,
    pub(crate) conns: String,
    pub(crate) sessions: String,
    pub(crate) bandwidth: String,
    pub(crate) canary: String,
    pub(crate) region: String,
    pub(crate) metrics: String,
    pub(crate) log: String,
    pub(crate) operator_key_file: Option<String>,
    pub(crate) operator: Option<String>,
    pub(crate) operator_sig: Option<String>,
    pub(crate) pow: bool,
}

impl Knobs {
    pub(crate) fn hs_dir(&self) -> PathBuf {
        self.state.join("hs-gateway")
    }

    /// The metrics port, `None` for `off`.
    pub(crate) fn metrics_port(&self) -> Option<u16> {
        match self.metrics.as_str() {
            "off" | "0" => None,
            text => text.parse().ok(),
        }
    }

    /// `(format, level)` from `json:info`.
    pub(crate) fn log_parts(&self) -> (String, String) {
        let (format, level) = self.log.split_once(':').unwrap_or((&self.log, "info"));
        (format.to_string(), level.to_string())
    }

    /// Every knob as `(key, value)` for printing; the signature is shortened to `…`.
    pub(crate) fn display_rows(&self) -> Vec<(&'static str, String)> {
        let mut rows = Vec::new();
        let mut push = |key: &'static str, value: Option<String>| {
            if let Some(value) = value.filter(|v| !v.is_empty()) {
                rows.push((key, value));
            }
        };
        push("record", self.record.clone());
        push("state", Some(self.state.display().to_string()));
        push("admit", Some(self.admit.clone()));
        push("sets", Some(self.sets.clone()));
        push("members_file", self.members_file.clone());
        push("allow", Some(self.allow.clone()));
        push("deny", Some(self.deny.clone()));
        push("deny_file", self.deny_file.clone());
        push("profile", Some(self.profile.clone()));
        push("weight", Some(self.weight.clone()));
        push("conns", Some(self.conns.clone()));
        push("sessions", Some(self.sessions.clone()));
        push("bandwidth", Some(self.bandwidth.clone()));
        push("canary", Some(self.canary.clone()));
        push("region", Some(self.region.clone()));
        push("metrics", Some(self.metrics.clone()));
        push("log", Some(self.log.clone()));
        push("operator_key_file", self.operator_key_file.clone());
        push("operator", self.operator.clone());
        push(
            "operator_sig",
            self.operator_sig.as_ref().map(|_| "…".to_string()),
        );
        push("pow", Some(self.pow.to_string()));
        rows
    }
}

/// Knobs plus where each came from and every problem found.
pub(crate) struct Resolved {
    pub(crate) knobs: Knobs,
    pub(crate) sources: BTreeMap<&'static str, String>,
    pub(crate) errors: Vec<String>,
    pub(crate) toml_path: Option<PathBuf>,
}

/// The TOML subset `node.toml` may use: `key = value` lines, an optional `[node]` table, `#`
/// comments, double-quoted strings, integers, `true`/`false` and arrays of double-quoted
/// strings (joined with commas). Anything else names its line, so a typo never becomes a
/// default.
pub(crate) fn parse_node_toml(text: &str) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    for (index, raw) in text.lines().enumerate() {
        let line = strip_comment(raw).trim().to_string();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let number = index + 1;
        if line.starts_with('[') && line.ends_with(']') {
            if line != "[node]" {
                return Err(format!(
                    "node.toml line {number}: only the [node] table is understood"
                ));
            }
            continue;
        }
        let Some((key, rhs)) = line.split_once('=') else {
            return Err(format!("node.toml line {number}: expected key = value"));
        };
        let key = key.trim();
        let rhs = rhs.trim();
        let valid_key = !key.is_empty()
            && key
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
            && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
        if !valid_key || rhs.is_empty() {
            return Err(format!("node.toml line {number}: expected key = value"));
        }
        let value = if rhs.starts_with('"') {
            match serde_json::from_str::<String>(rhs) {
                Ok(s) => s,
                Err(_) => {
                    return Err(format!(
                        "node.toml line {number}: value must be a \"string\", integer, true/false or [\"array\"]"
                    ))
                }
            }
        } else if rhs.starts_with('[') {
            match serde_json::from_str::<Vec<serde_json::Value>>(rhs) {
                Ok(items) if items.iter().all(serde_json::Value::is_string) => items
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .collect::<Vec<_>>()
                    .join(","),
                _ => {
                    return Err(format!(
                        "node.toml line {number}: arrays hold double-quoted strings only"
                    ))
                }
            }
        } else if rhs == "true"
            || rhs == "false"
            || rhs
                .strip_prefix('-')
                .unwrap_or(rhs)
                .bytes()
                .all(|b| b.is_ascii_digit())
        {
            // booleans and integers keep their text; every knob is read as text anyway
            rhs.to_string()
        } else {
            return Err(format!(
                "node.toml line {number}: value must be a \"string\", integer, true/false or [\"array\"]"
            ));
        };
        out.insert(key.to_string(), value);
    }
    Ok(out)
}

fn strip_comment(line: &str) -> &str {
    // a `#` after whitespace starts a comment, as the javascript parser's regex has it
    let mut in_string = false;
    let bytes = line.as_bytes();
    for i in 0..bytes.len() {
        match bytes[i] {
            b'"' if i == 0 || bytes[i - 1] != b'\\' => in_string = !in_string,
            b'#' if !in_string && i > 0 && bytes[i - 1].is_ascii_whitespace() => {
                return &line[..i];
            }
            _ => {}
        }
    }
    line
}

pub(crate) fn is_eth_address(value: &str) -> bool {
    let value = value.trim();
    value.len() == 42
        && value.starts_with("0x")
        && value[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

/// A 32-byte hex private key, `0x` optional.
pub(crate) fn is_private_hex(value: &str) -> bool {
    let hex = value.trim();
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_signature_hex(value: &str) -> bool {
    let value = value.trim();
    value.len() == 132
        && value.starts_with("0x")
        && value[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

/// `sets`: `0xContract@block,...`; the deploy block is required (a scan from 0 against a
/// public RPC is the empty-page failure the rehearsal hit).
pub(crate) fn parse_sets(spec: &str) -> (Vec<(String, u64)>, Vec<String>) {
    let mut sets: Vec<(String, u64)> = Vec::new();
    let mut errors = Vec::new();
    for raw in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (contract, block) = raw
            .split_once('@')
            .map_or((raw, None), |(c, b)| (c, Some(b)));
        if !is_eth_address(contract) {
            errors.push(format!("{raw}: expected 0x<contract>@<deployBlock>"));
            continue;
        }
        let block = match block {
            Some(b) if !b.is_empty() && b.bytes().all(|c| c.is_ascii_digit()) => {
                b.parse::<u64>().ok()
            }
            Some(_) => {
                errors.push(format!("{raw}: expected 0x<contract>@<deployBlock>"));
                continue;
            }
            None => None,
        };
        let Some(block) = block else {
            errors.push(format!(
                "{raw}: add @<deployBlock> (the block the set was deployed at; it is in that canopy's record)"
            ));
            continue;
        };
        if sets.iter().any(|(c, _)| c.eq_ignore_ascii_case(contract)) {
            errors.push(format!("{raw}: listed twice"));
            continue;
        }
        sets.push((contract.to_string(), block));
    }
    (sets, errors)
}

/// Resolve every knob from the environment, then `node.toml`, then the default.
pub(crate) fn resolve(
    env: &dyn Fn(&str) -> Option<String>,
    toml: &BTreeMap<String, String>,
) -> Resolved {
    let mut values: BTreeMap<&'static str, String> = BTreeMap::new();
    let mut sources = BTreeMap::new();
    for knob in KNOBS {
        if let Some(value) = env(knob.env).filter(|v| !v.trim().is_empty()) {
            values.insert(knob.key, value.trim().to_string());
            sources.insert(knob.key, format!("env {}", knob.env));
        } else if let Some(value) = toml.get(knob.key) {
            values.insert(knob.key, value.clone());
            sources.insert(knob.key, format!("node.toml {}", knob.key));
        } else if let Some(default) = knob.default {
            values.insert(knob.key, default.to_string());
            sources.insert(knob.key, "default".to_string());
        }
    }
    // a profile only fills in what the operator left at the default
    let profile = values.get("profile").cloned().unwrap_or_default();
    if profile == "home" {
        for (key, preset) in [
            ("weight", HOME_WEIGHT),
            ("conns", HOME_CONNS),
            ("sessions", HOME_SESSIONS),
            ("bandwidth", HOME_BANDWIDTH),
            ("canary", HOME_CANARY),
        ] {
            if sources.get(key).is_some_and(|source| source == "default") {
                values.insert(key, preset.to_string());
                sources.insert(key, "profile home".to_string());
            }
        }
    }
    let get = |key: &str| values.get(key).cloned().unwrap_or_default();
    let optional = |key: &str| values.get(key).cloned().filter(|v| !v.is_empty());
    let mut errors = Vec::new();
    if !matches!(profile.as_str(), "default" | "home") {
        errors.push(format!("profile: default or home (got {profile})"));
    }
    let record = optional("record");
    match &record {
        None => errors.push(
            "record: set SHADENET_RECORD (the deployment record URL or path); nothing else is required"
                .to_string(),
        ),
        Some(record)
            if !record.starts_with("https://")
                && !(record.starts_with('/') || record.starts_with('.') || record.starts_with('~')) =>
        {
            errors.push(format!(
                "record: must be an https:// URL or a file path (got {record})"
            ))
        }
        Some(_) => {}
    }
    let admit = get("admit");
    let paths: Vec<&str> = admit
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if paths.is_empty()
        || !paths
            .iter()
            .all(|p| matches!(*p, "invited" | "staked" | "paid"))
    {
        errors.push(format!(
            "admit: must be a comma list of invited, staked, paid (got {admit})"
        ));
    }
    let members_file = optional("members_file");
    if paths.contains(&"invited") && members_file.is_none() {
        errors.push("admit: the invited path needs members_file (your own members.json)".into());
    }
    if let Some(file) = &members_file {
        if !Path::new(file).is_absolute() {
            errors.push(format!(
                "members_file: must be an absolute path (got {file})"
            ));
        }
    }
    let sets = get("sets");
    for problem in parse_sets(&sets).1 {
        errors.push(format!("sets: {problem}"));
    }
    let weight = get("weight");
    match weight.parse::<u64>() {
        Ok(w) if (1..=1000).contains(&w) => {}
        _ => errors.push(format!("weight: integer 1..1000 (got {weight})")),
    }
    let conns = get("conns");
    if !conns.is_empty() && conns.parse::<u64>().is_err() {
        errors.push(format!(
            "conns: a whole number, 0 = unlimited (got {conns})"
        ));
    }
    let sessions = get("sessions");
    if !sessions.is_empty() && sessions.parse::<u64>().is_err() {
        errors.push(format!(
            "sessions: a whole number, 0 = unlimited (got {sessions})"
        ));
    }
    let bandwidth = get("bandwidth");
    if !bandwidth.is_empty() && parse_bandwidth(&bandwidth).is_none() {
        errors.push(format!(
            "bandwidth: bytes per second with an optional k or m suffix, 0 = unlimited (got {bandwidth})"
        ));
    }
    let canary = get("canary");
    if !matches!(canary.as_str(), "on" | "off") {
        errors.push(format!("canary: on or off (got {canary})"));
    }
    let deny_file = optional("deny_file");
    if deny_file
        .as_deref()
        .is_some_and(|f| !Path::new(f).is_absolute())
    {
        errors.push("deny_file: must be an absolute path".into());
    }
    let region = get("region");
    if !region.is_empty() && !shadenet_proto::is_region_bucket(&region) {
        errors.push(format!(
            "region: one of na sa eu af as oc aq unknown (got {region})"
        ));
    }
    let metrics = get("metrics");
    let metrics_ok = metrics == "off"
        || metrics == "0"
        || (metrics.bytes().all(|b| b.is_ascii_digit())
            && metrics
                .parse::<u64>()
                .is_ok_and(|p| (1..=65535).contains(&p)));
    if !metrics_ok {
        errors.push(format!("metrics: a port 1..65535 or off (got {metrics})"));
    }
    let log = get("log");
    let (format, level) = log.split_once(':').unwrap_or((&log, "info"));
    if !matches!(format, "json" | "pretty" | "text") {
        errors.push(format!(
            "log: json | pretty | text, optionally :debug|info|warn|error (got {log})"
        ));
    }
    if !matches!(level, "debug" | "info" | "warn" | "error") {
        errors.push(format!(
            "log: level must be debug, info, warn or error (got {level})"
        ));
    }
    let operator = optional("operator");
    let operator_sig = optional("operator_sig");
    if operator.as_deref().is_some_and(|o| !is_eth_address(o)) {
        errors.push("operator: not a 0x-prefixed 20-byte address".into());
    }
    if operator_sig
        .as_deref()
        .is_some_and(|s| !is_signature_hex(s))
    {
        errors.push("operator_sig: not a 65-byte 0x-hex signature".into());
    }
    if operator.is_some() != operator_sig.is_some() {
        errors.push("operator and operator_sig go together (or use operator_key_file)".into());
    }
    let operator_key_file = optional("operator_key_file");
    if operator_key_file
        .as_deref()
        .is_some_and(|f| !Path::new(f).is_absolute())
    {
        errors.push("operator_key_file: must be an absolute path".into());
    }
    let pow = matches!(
        get("pow").to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    );
    let state = optional("state").map_or_else(default_state_dir, PathBuf::from);
    Resolved {
        knobs: Knobs {
            record,
            state,
            admit,
            sets,
            members_file,
            allow: get("allow"),
            deny: get("deny"),
            deny_file,
            profile,
            weight,
            conns,
            sessions,
            bandwidth,
            canary,
            region,
            metrics,
            log,
            operator_key_file,
            operator,
            operator_sig: operator_sig.map(|s| s.trim().to_string()),
            pow,
        },
        sources,
        errors,
        toml_path: None,
    }
}

/// `bandwidth`: a whole number of bytes per second, or one with a `k` or `m` suffix (KiB, MiB).
pub(crate) fn parse_bandwidth(text: &str) -> Option<u64> {
    let text = text.trim().to_ascii_lowercase();
    let (digits, unit) = match text.strip_suffix('k') {
        Some(d) => (d, 1024_u64),
        None => match text.strip_suffix('m') {
            Some(d) => (d, 1024 * 1024),
            None => (text.as_str(), 1),
        },
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u64>().ok()?.checked_mul(unit)
}

/// Read `node.toml` from the state directory (when present) and resolve. Fails only on an
/// unreadable or malformed `node.toml`.
pub(crate) fn load(env: &dyn Fn(&str) -> Option<String>) -> Result<Resolved, String> {
    let state = env("SHADENET_STATE")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map_or_else(default_state_dir, PathBuf::from);
    let toml_path = state.join("node.toml");
    let toml = if toml_path.exists() {
        let text = std::fs::read_to_string(&toml_path)
            .map_err(|e| format!("{}: {e}", toml_path.display()))?;
        parse_node_toml(&text)?
    } else {
        BTreeMap::new()
    };
    let mut resolved = resolve(env, &toml);
    resolved.knobs.state = absolute(&resolved.knobs.state);
    resolved.toml_path = toml_path.exists().then_some(toml_path);
    Ok(resolved)
}

/// `path` made absolute against the working directory (no symlink resolution).
pub(crate) fn absolute(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    std::env::current_dir()
        .map(|cwd| cwd.join(path))
        .unwrap_or_else(|_| path.to_path_buf())
}

/// The operator key file: one line, 64 hex (`0x` optional), readable by its owner only.
/// The value is never logged.
pub(crate) fn read_operator_key_file(path: &Path) -> Result<String, String> {
    let metadata = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "{}: must be readable by the owner only (chmod 600)",
                path.display()
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = metadata;
    let key = std::fs::read_to_string(path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .trim()
        .to_string();
    if !is_private_hex(&key) {
        return Err(format!(
            "{}: not a 32-byte hex private key (64 hex, 0x optional)",
            path.display()
        ));
    }
    Ok(key)
}

/// The `Knobs (...)` block of `shadenet-node help`.
pub(crate) fn usage_lines() -> String {
    let mut out = String::new();
    for knob in KNOBS {
        let default = match knob.default {
            Some(d) if !d.is_empty() => format!(" [{d}]"),
            _ => String::new(),
        };
        out.push_str(&format!("  {:<28} {}{default}\n", knob.env, knob.what));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_string())
        }
    }

    #[test]
    fn node_toml_subset_parses_and_rejects_with_line_numbers() {
        let parsed = parse_node_toml(
            "# comment\n[node]\nweight = 42\nregion = \"eu\" # trailing\npow = true\nallow = [\"*:443\", \"*:8443\"]\n",
        )
        .unwrap();
        assert_eq!(parsed["weight"], "42");
        assert_eq!(parsed["region"], "eu");
        assert_eq!(parsed["pow"], "true");
        assert_eq!(parsed["allow"], "*:443,*:8443");
        assert_eq!(
            parse_node_toml("[other]\n").unwrap_err(),
            "node.toml line 1: only the [node] table is understood"
        );
        assert_eq!(
            parse_node_toml("\nweight\n").unwrap_err(),
            "node.toml line 2: expected key = value"
        );
        assert_eq!(
            parse_node_toml("weight = 1.5\n").unwrap_err(),
            "node.toml line 1: value must be a \"string\", integer, true/false or [\"array\"]"
        );
        assert_eq!(
            parse_node_toml("allow = [1]\n").unwrap_err(),
            "node.toml line 1: arrays hold double-quoted strings only"
        );
    }

    #[test]
    fn knobs_resolve_with_precedence_and_collect_every_error() {
        let toml = BTreeMap::from([
            ("weight".to_string(), "42".to_string()),
            ("region".to_string(), "eu".to_string()),
        ]);
        let resolved = resolve(
            &env_of(&[
                ("SHADENET_RECORD", "/tmp/record.json"),
                ("SHADENET_WEIGHT", "7"),
            ]),
            &toml,
        );
        assert!(resolved.errors.is_empty(), "{:?}", resolved.errors);
        assert_eq!(resolved.knobs.weight, "7");
        assert_eq!(resolved.knobs.region, "eu");
        assert_eq!(resolved.sources["weight"], "env SHADENET_WEIGHT");
        assert_eq!(resolved.sources["region"], "node.toml region");
        assert_eq!(resolved.sources["admit"], "default");
        assert_eq!(resolved.knobs.metrics_port(), Some(9101));
        assert_eq!(
            resolved.knobs.log_parts(),
            ("json".to_string(), "info".to_string())
        );

        let bad = resolve(
            &env_of(&[
                ("SHADENET_RECORD", "ftp://x"),
                ("SHADENET_ADMIT", "invited"),
                ("SHADENET_WEIGHT", "0"),
                ("SHADENET_REGION", "mars"),
                ("SHADENET_METRICS", "70000"),
                ("SHADENET_LOG", "xml:loud"),
                ("SHADENET_OPERATOR", "0x1"),
                ("SHADENET_SETS", "0xabc"),
                ("SHADENET_PROFILE", "office"),
                ("SHADENET_CONNS", "many"),
                ("SHADENET_SESSIONS", "-1"),
                ("SHADENET_BANDWIDTH", "fast"),
                ("SHADENET_CANARY", "maybe"),
                ("SHADENET_DENY_FILE", "blocklist.txt"),
            ]),
            &BTreeMap::new(),
        );
        let text = bad.errors.join("\n");
        for needle in [
            "record: must be an https:// URL or a file path",
            "admit: the invited path needs members_file",
            "weight: integer 1..1000",
            "region: one of",
            "metrics: a port 1..65535 or off",
            "log: json | pretty | text",
            "log: level must be",
            "operator: not a 0x-prefixed",
            "operator and operator_sig go together",
            "sets: 0xabc: expected 0x<contract>@<deployBlock>",
            "profile: default or home (got office)",
            "conns: a whole number, 0 = unlimited (got many)",
            "sessions: a whole number, 0 = unlimited (got -1)",
            "bandwidth: bytes per second with an optional k or m suffix, 0 = unlimited (got fast)",
            "canary: on or off (got maybe)",
            "deny_file: must be an absolute path",
        ] {
            assert!(text.contains(needle), "missing {needle:?} in {text}");
        }
        let missing = resolve(&env_of(&[]), &BTreeMap::new());
        assert!(missing.errors[0].starts_with("record: set SHADENET_RECORD"));
        assert_eq!(missing.knobs.metrics, "9101");
    }

    #[test]
    fn the_home_profile_fills_in_only_what_the_operator_left_alone() {
        let toml = BTreeMap::from([("sessions".to_string(), "4".to_string())]);
        let home = resolve(
            &env_of(&[
                ("SHADENET_RECORD", "/tmp/record.json"),
                ("SHADENET_PROFILE", "home"),
                ("SHADENET_WEIGHT", "25"),
            ]),
            &toml,
        );
        assert!(home.errors.is_empty(), "{:?}", home.errors);
        assert_eq!(home.knobs.profile, "home");
        assert_eq!(home.knobs.weight, "25");
        assert_eq!(home.sources["weight"], "env SHADENET_WEIGHT");
        assert_eq!(home.knobs.sessions, "4");
        assert_eq!(home.sources["sessions"], "node.toml sessions");
        assert_eq!(home.knobs.conns, "32");
        assert_eq!(home.sources["conns"], "profile home");
        assert_eq!(home.knobs.bandwidth, "2m");
        assert_eq!(home.knobs.canary, "on");
        assert_eq!(home.sources["canary"], "profile home");
        assert!(home
            .knobs
            .display_rows()
            .contains(&("conns", "32".to_string())));

        let plain = resolve(
            &env_of(&[("SHADENET_RECORD", "/tmp/record.json")]),
            &BTreeMap::new(),
        );
        assert_eq!(plain.knobs.profile, "default");
        assert_eq!(plain.knobs.weight, "100");
        assert_eq!(plain.knobs.conns, "");
        assert_eq!(plain.knobs.sessions, "");
        assert_eq!(plain.knobs.bandwidth, "");
        assert_eq!(plain.knobs.canary, "off");
        assert_eq!(plain.knobs.deny_file, None);
        assert_eq!(plain.sources["conns"], "default");
        assert!(!plain
            .knobs
            .display_rows()
            .iter()
            .any(|(key, _)| *key == "conns"));
    }

    #[test]
    fn bandwidth_takes_bytes_with_a_k_or_m_suffix() {
        assert_eq!(parse_bandwidth("0"), Some(0));
        assert_eq!(parse_bandwidth("1500"), Some(1500));
        assert_eq!(parse_bandwidth("512k"), Some(512 * 1024));
        assert_eq!(parse_bandwidth(" 2M "), Some(2 * 1024 * 1024));
        for bad in ["", "k", "2g", "2.5m", "-1", "fast"] {
            assert_eq!(parse_bandwidth(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn sets_need_a_deploy_block_each() {
        let contract = format!("0x{}", "ab".repeat(20));
        let (sets, errors) = parse_sets(&format!("{contract}@123, {contract}@5"));
        assert_eq!(sets, vec![(contract.clone(), 123)]);
        assert_eq!(errors, vec![format!("{contract}@5: listed twice")]);
        let (_, errors) = parse_sets(&contract);
        assert!(errors[0].contains("add @<deployBlock>"));
        assert!(is_private_hex(
            "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
        ));
        assert!(!is_private_hex("0x1234"));
    }

    #[test]
    fn usage_names_every_knob() {
        let usage = usage_lines();
        for knob in KNOBS {
            assert!(usage.contains(knob.env));
        }
        assert!(usage.contains("[9101]"));
    }
}
