//! `config.toml`: defaults for flags, below flags and environment variables in precedence.
//!
//! ```toml
//! network = "sepolia"                     # or a path to a deployment.json record
//! identity = "~/.config/shadenet/identity.json"
//! proxy_token_file = "~/.config/shadenet/proxy-token"
//! listen = "127.0.0.1:8118"
//! rpc_url = "https://rpc.sepolia.example"
//! searxng_url = "http://127.0.0.1:8080"
//! ```

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Every supported key. Unknown keys are an error so a typo never silently falls back.
#[derive(Debug, Default, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    pub network: Option<String>,
    pub identity: Option<PathBuf>,
    pub proxy_token_file: Option<PathBuf>,
    pub listen: Option<String>,
    pub rpc_url: Option<String>,
    pub cache_dir: Option<PathBuf>,
    pub leaf_source: Option<String>,
    pub members: Option<PathBuf>,
    pub contract: Option<String>,
    pub prover_workers: Option<usize>,
    pub max_tunnels: Option<usize>,
    pub max_setups: Option<usize>,
    pub allow_non_loopback: Option<bool>,
    pub searxng_url: Option<String>,
    /// Where this file was read from, for relative paths and `doctor`.
    #[serde(skip)]
    pub path: Option<PathBuf>,
}

/// `$XDG_CONFIG_HOME/shadenet` or `~/.config/shadenet` (`%APPDATA%\shadenet` on Windows).
pub fn default_dir() -> Option<PathBuf> {
    if let Some(value) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(value).join("shadenet"));
    }
    if cfg!(windows) {
        return std::env::var_os("APPDATA").map(|base| PathBuf::from(base).join("shadenet"));
    }
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config").join("shadenet"))
}

fn expand(path: PathBuf, base: Option<&Path>) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    match base {
        Some(base) if path.is_relative() => base.join(path),
        _ => path,
    }
}

/// Parse a config file's text. Relative paths resolve against `base`.
pub fn parse(raw: &str, base: Option<&Path>) -> Result<ConfigFile, String> {
    let mut file: ConfigFile = toml::from_str(raw).map_err(|e| e.to_string())?;
    let fix = |value: Option<PathBuf>| value.map(|path| expand(path, base));
    file.identity = fix(file.identity);
    file.proxy_token_file = fix(file.proxy_token_file);
    file.cache_dir = fix(file.cache_dir);
    file.members = fix(file.members);
    if let Some(network) = &file.network {
        // A network value that looks like a path is a deployment record.
        if network.contains('/') || network.ends_with(".json") {
            file.network = Some(expand(PathBuf::from(network), base).display().to_string());
        }
    }
    Ok(file)
}

/// Load `explicit`, else `SHADENET_CONFIG`, else the default file when it exists.
pub fn load(explicit: Option<&Path>) -> Result<ConfigFile, String> {
    let from_env = shadenet::env::var("CONFIG")?.map(PathBuf::from);
    let (path, required) = match explicit.map(Path::to_path_buf).or(from_env) {
        Some(path) => (path, true),
        None => match default_dir() {
            Some(dir) => (dir.join("config.toml"), false),
            None => return Ok(ConfigFile::default()),
        },
    };
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) if !required && error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ConfigFile::default())
        }
        Err(error) => return Err(format!("read config {}: {error}", path.display())),
    };
    let mut file =
        parse(&raw, path.parent()).map_err(|e| format!("config {}: {e}", path.display()))?;
    file.path = Some(path);
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_keys_and_rejects_typos() {
        let file = parse(
            "network = \"sepolia\"\nidentity = \"id.json\"\nlisten = \"127.0.0.1:9000\"\nmax_tunnels = 8\n",
            Some(Path::new("/etc/shadenet")),
        )
        .unwrap();
        assert_eq!(file.network.as_deref(), Some("sepolia"));
        assert_eq!(file.identity, Some(PathBuf::from("/etc/shadenet/id.json")));
        assert_eq!(file.max_tunnels, Some(8));
        assert!(parse("listn = \"x\"\n", None).is_err());
        let staging = parse(
            "network = \"staging/deployment.json\"\n",
            Some(Path::new("/c")),
        )
        .unwrap();
        assert_eq!(
            staging.network.as_deref(),
            Some("/c/staging/deployment.json")
        );
    }

    #[test]
    fn a_missing_default_file_is_fine_but_an_explicit_one_is_not() {
        assert!(load(Some(Path::new("/definitely/not/here.toml"))).is_err());
    }
}
