//! Environment variables under both prefixes.
//!
//! `SHADENET_*` is the name going forward; `SHADE_TREE_*` keeps working for one minor release.
//! When both are set to different values the read fails instead of guessing, because several of
//! these settings are safety-critical (the RLN slot-state directory decides whether a nullifier can
//! be reused). Anything under either prefix is treated as a credential when building a child
//! environment or printing configuration.

use std::sync::Mutex;

/// Current prefix.
pub const PREFIX: &str = "SHADENET_";
/// Deprecated prefix, still read for one minor release.
pub const LEGACY_PREFIX: &str = "SHADE_TREE_";
/// Both prefixes, current first.
pub const PREFIXES: [&str; 2] = [PREFIX, LEGACY_PREFIX];

static WARNED: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn warn_legacy(name: &str) {
    let mut warned = WARNED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !warned.iter().any(|seen| seen == name) {
        warned.push(name.to_string());
        tracing::warn!(
            "{LEGACY_PREFIX}{name} is deprecated; use {PREFIX}{name} (the old name is read for one more minor release)"
        );
    }
}

fn read(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

/// Read `SHADENET_<name>`, else `SHADE_TREE_<name>`. Conflicting values are an error.
pub fn var(name: &str) -> Result<Option<String>, String> {
    resolve(
        name,
        read(&format!("{PREFIX}{name}")),
        read(&format!("{LEGACY_PREFIX}{name}")),
    )
}

/// Like [`var`] but a conflict or absence both yield `None`, for non-critical tuning knobs.
/// Conflicts are still logged.
pub fn var_lenient(name: &str) -> Option<String> {
    match var(name) {
        Ok(value) => value,
        Err(message) => {
            tracing::warn!("{message}; ignoring both");
            None
        }
    }
}

/// Parse a numeric knob, ignoring unparsable values.
pub fn parse<T: std::str::FromStr>(name: &str) -> Option<T> {
    var_lenient(name).and_then(|value| value.trim().parse().ok())
}

/// A boolean knob (`1/true/yes/on`, `0/false/no/off`).
pub fn flag(name: &str) -> Option<bool> {
    var_lenient(name).and_then(|value| match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    })
}

/// Pure resolution rule, separated for tests.
pub fn resolve(
    name: &str,
    current: Option<String>,
    legacy: Option<String>,
) -> Result<Option<String>, String> {
    match (current, legacy) {
        (Some(current), Some(legacy)) if current != legacy => Err(format!(
            "{PREFIX}{name} and {LEGACY_PREFIX}{name} are both set to different values; unset one"
        )),
        (Some(current), _) => Ok(Some(current)),
        (None, Some(legacy)) => {
            warn_legacy(name);
            Ok(Some(legacy))
        }
        (None, None) => Ok(None),
    }
}

/// True when `key` belongs to either prefix. Case-insensitive, because Windows environment keys are.
pub fn is_protected(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    PREFIXES.iter().any(|prefix| upper.starts_with(prefix))
}

/// Name fragments that mark a value as secret in logs and `doctor` output.
const SECRET_MARKERS: [&str; 6] = [
    "SECRET",
    "TOKEN",
    "KEY",
    "PASSWORD",
    "PASSPHRASE",
    "MNEMONIC",
];

/// True when an environment key's value must never be printed.
pub fn is_secret(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    is_protected(&upper) && SECRET_MARKERS.iter().any(|marker| upper.contains(marker))
}

/// Render a value for display: secrets become `<redacted>`.
pub fn redact(key: &str, value: &str) -> String {
    if is_secret(key) {
        "<redacted>".into()
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_prefix_wins_and_conflicts_fail_closed() {
        assert_eq!(resolve("X", Some("a".into()), None), Ok(Some("a".into())));
        assert_eq!(resolve("X", None, Some("b".into())), Ok(Some("b".into())));
        assert_eq!(
            resolve("X", Some("a".into()), Some("a".into())),
            Ok(Some("a".into()))
        );
        assert!(resolve("X", Some("a".into()), Some("b".into())).is_err());
        assert_eq!(resolve("X", None, None), Ok(None));
    }

    #[test]
    fn both_prefixes_are_protected_and_secrets_redacted() {
        for key in [
            "SHADENET_SECRET",
            "SHADE_TREE_SECRET",
            "shadenet_proxy_token",
            "Shade_Tree_Register_Key",
        ] {
            assert!(is_protected(key), "{key}");
            assert!(is_secret(key), "{key}");
            assert_eq!(redact(key, "hunter2"), "<redacted>");
        }
        assert!(is_protected("SHADENET_RPC_URL"));
        assert!(!is_secret("SHADENET_RPC_URL"));
        assert!(!is_protected("HTTPS_PROXY"));
        assert_eq!(redact("SHADENET_RPC_URL", "https://x"), "https://x");
    }
}
