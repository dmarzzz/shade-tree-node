//! `config.toml`: defaults for flags, below flags and environment variables in precedence.
//!
//! ```toml
//! network = "sepolia"                     # or a path to a deployment.json record
//! identity = "~/.config/shadenet/identity.json"
//! proxy_token_file = "~/.config/shadenet/proxy-token"
//! listen = "127.0.0.1:8118"
//! rpc_url = "https://rpc.sepolia.example"
//! searxng_url = "http://127.0.0.1:8080"
//! queue_max_wait_secs = 120              # budget queue (ADR 0013); 0 refuses at once
//! warm_nodes = 2                         # circuits kept warm by `shadenet proxy`
//! preopen_books = true                   # `shadenet proxy --preopen`: a session book ready ahead
//! targets = [".wikipedia.org", "api.ipify.org"]   # proxy allow-list; omit for any host
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
    /// Budget queue: longest wait in seconds; 0 refuses at once (ADR 0013).
    pub queue_max_wait_secs: Option<u64>,
    /// Nodes to keep warm circuits to (0 disables).
    pub warm_nodes: Option<usize>,
    /// `shadenet proxy --preopen`: keep a session-ticket book open ahead of requests.
    pub preopen_books: Option<bool>,
    /// Destination allow-list for the proxy (names or `.suffix`); empty allows every host.
    pub targets: Option<Vec<String>>,
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

    /// The configs people have, pinned field by field, so a TOML parser change (toml 0.8 -> 1.x,
    /// Dependabot #263) that read any of them differently fails here: what `shadenet init`
    /// writes, what agent-devops renders for Hermes, every key at once in the styles TOML allows,
    /// and the errors that must stay errors.
    #[test]
    fn the_config_corpus_parses_the_same_across_toml_versions() {
        let base = Some(Path::new("/home/u/.config/shadenet"));
        // `shadenet init` (v0.7.3).
        let init = parse(
            "# ShadeNet client configuration. Flags and SHADENET_* variables override these.\n\
             network = \"sepolia\"\n\
             identity = \"/home/u/.config/shadenet/identity.json\"\n\
             proxy_token_file = \"/home/u/.config/shadenet/proxy-token\"\n\
             listen = \"127.0.0.1:8118\"\n",
            base,
        )
        .unwrap();
        assert_eq!(
            init,
            ConfigFile {
                network: Some("sepolia".into()),
                identity: Some("/home/u/.config/shadenet/identity.json".into()),
                proxy_token_file: Some("/home/u/.config/shadenet/proxy-token".into()),
                listen: Some("127.0.0.1:8118".into()),
                ..ConfigFile::default()
            }
        );
        // agent-devops roles/shadenet_client (Hermes on orbital-one, 2026-10-06).
        let hermes = parse(
            "# Managed by agent-devops (roles/shadenet_client).\n\
             network = \"sepolia\"\n\
             identity = \"/home/mindagent/.config/shadenet/identity.json\"\n\
             proxy_token_file = \"/home/mindagent/.config/shadenet/proxy-token\"\n\
             listen = \"127.0.0.1:8118\"\n\
             rpc_url = \"https://rpc.sepolia.ethpandaops.io,https://sepolia.gateway.tenderly.co\"\n\
             searxng_url = \"http://127.0.0.1:8090\"\n",
            base,
        )
        .unwrap();
        assert_eq!(
            hermes.rpc_url.as_deref(),
            Some("https://rpc.sepolia.ethpandaops.io,https://sepolia.gateway.tenderly.co")
        );
        assert_eq!(hermes.searxng_url.as_deref(), Some("http://127.0.0.1:8090"));
        // Every key, with inline comments, a literal string, a multi-line array with a trailing
        // comma, and CRLF line endings.
        let every = parse(
            "network = 'staging/deployment.json'   # a record path\r\n\
             identity = \"id.json\"\r\n\
             proxy_token_file = \"~/token\"\r\n\
             listen = \"127.0.0.1:9000\"\r\n\
             rpc_url = \"https://a.example,https://b.example\"\r\n\
             cache_dir = \"cache\"\r\n\
             leaf_source = \"rpc\"\r\n\
             members = \"members.json\"\r\n\
             contract = \"0x789967F0bDD7f3a96fb60F6D315e93F103b5680b\"\r\n\
             prover_workers = 2\r\n\
             max_tunnels = 64\r\n\
             max_setups = 16\r\n\
             allow_non_loopback = false\r\n\
             searxng_url = \"http://127.0.0.1:8080\"\r\n\
             queue_max_wait_secs = 120\r\n\
             warm_nodes = 0\r\n\
             preopen_books = true\r\n\
             targets = [\r\n  \".wikipedia.org\",\r\n  \"api.ipify.org\", # trailing comma next\r\n]\r\n",
            base,
        )
        .unwrap();
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_default();
        assert_eq!(
            every,
            ConfigFile {
                network: Some("/home/u/.config/shadenet/staging/deployment.json".into()),
                identity: Some("/home/u/.config/shadenet/id.json".into()),
                proxy_token_file: Some(if home.as_os_str().is_empty() {
                    "/home/u/.config/shadenet/~/token".into()
                } else {
                    home.join("token")
                }),
                listen: Some("127.0.0.1:9000".into()),
                rpc_url: Some("https://a.example,https://b.example".into()),
                cache_dir: Some("/home/u/.config/shadenet/cache".into()),
                leaf_source: Some("rpc".into()),
                members: Some("/home/u/.config/shadenet/members.json".into()),
                contract: Some("0x789967F0bDD7f3a96fb60F6D315e93F103b5680b".into()),
                prover_workers: Some(2),
                max_tunnels: Some(64),
                max_setups: Some(16),
                allow_non_loopback: Some(false),
                searxng_url: Some("http://127.0.0.1:8080".into()),
                queue_max_wait_secs: Some(120),
                warm_nodes: Some(0),
                preopen_books: Some(true),
                targets: Some(vec![".wikipedia.org".into(), "api.ipify.org".into()]),
                path: None,
            }
        );
        // Errors stay errors: an unknown key (named in the message), a wrong type, a duplicate
        // key, and broken syntax.
        let unknown = parse("listn = \"x\"\n", None).unwrap_err();
        assert!(unknown.contains("listn"), "{unknown}");
        assert!(parse("max_tunnels = \"8\"\n", None).is_err());
        assert!(parse("listen = \"a\"\nlisten = \"b\"\n", None).is_err());
        assert!(parse("network = \"sepolia\n", None).is_err());
        assert!(parse("targets = [1, 2]\n", None).is_err());
    }

    #[test]
    fn a_missing_default_file_is_fine_but_an_explicit_one_is_not() {
        assert!(load(Some(Path::new("/definitely/not/here.toml"))).is_err());
    }
}
