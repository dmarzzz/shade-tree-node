//! Own-node exclusion (roadmap #369 M0): canopy selection never offers a node that this machine
//! runs, or that the user says shares this machine's internet connection.
//!
//! A node exits from its own public IP. When that IP is the client's own (the user's own node, or
//! a node on the same home connection), the destination sees the user's address and the tunnel
//! hides nothing. Canopy records carry no egress IP (on purpose: ROADMAP §3.1), and the client
//! must not ask a clear-net IP-echo service for its own address, so the rule is keyed by onion,
//! from local sources only:
//!
//! 1. [`Config::avoid_nodes`](crate::Config::avoid_nodes) (`--avoid-nodes`, `avoid_nodes` in
//!    config.toml);
//! 2. `SHADENET_AVOID_NODES` (or `SHADE_TREE_AVOID_NODES`; both are read);
//! 3. the avoid-nodes file, `$XDG_CONFIG_HOME/shadenet/avoid-nodes` or
//!    `~/.config/shadenet/avoid-nodes` (`%APPDATA%\shadenet\avoid-nodes` on Windows), which
//!    `shadenet-node run` appends its own onion to;
//! 4. `$SHADENET_STATE/hs-gateway/hostname` when `SHADENET_STATE` is set.
//!
//! Sources 2–4 are re-read at most once a minute, so a node started after the client is picked up
//! without a restart. A node on the same connection that none of these names is not detected; that
//! needs egress IPs the protocol does not publish (see `docs/THREAT-MODEL.md`). An explicitly
//! pinned onion (`--onion`) is the caller's choice and is not filtered.
//!
//! The normalization and the rule live in `shadenet_proto` (`normalize_own_node`,
//! `exclude_own_nodes`) and are pinned with the JS client in `testdata/vectors.json` `ownNodes`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// File name of the avoid list inside the shadenet config directory.
pub const AVOID_NODES_FILE: &str = "avoid-nodes";

const REFRESH: Duration = Duration::from_secs(60);

/// The avoid-nodes file: `$XDG_CONFIG_HOME/shadenet/avoid-nodes`, else
/// `~/.config/shadenet/avoid-nodes` (`%APPDATA%\shadenet\avoid-nodes` on Windows).
pub fn avoid_nodes_path() -> Option<PathBuf> {
    let dir = if let Some(value) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        PathBuf::from(value)
    } else if cfg!(windows) {
        PathBuf::from(std::env::var_os("APPDATA")?)
    } else {
        PathBuf::from(std::env::var_os("HOME")?).join(".config")
    };
    Some(dir.join("shadenet").join(AVOID_NODES_FILE))
}

/// What the local sources name.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Found {
    /// Normalized onions (`<56>.onion`).
    pub nodes: BTreeSet<String>,
    /// Entries that are not v3 onions (ignored).
    pub junk: Vec<String>,
}

impl Found {
    fn add(&mut self, text: &str) {
        let (nodes, junk) = shadenet_proto::parse_own_node_list(text);
        self.nodes.extend(nodes);
        self.junk.extend(junk);
    }
}

/// Read the environment and file sources (2–4 above) through injected readers.
pub fn discover_with(
    env: &dyn Fn(&str) -> Option<String>,
    read: &dyn Fn(&Path) -> Option<String>,
    avoid_file: Option<&Path>,
) -> Found {
    let mut found = Found::default();
    for name in ["SHADENET_AVOID_NODES", "SHADE_TREE_AVOID_NODES"] {
        if let Some(value) = env(name) {
            found.add(&value);
        }
    }
    if let Some(text) = avoid_file.and_then(read) {
        found.add(&text);
    }
    if let Some(state) = env("SHADENET_STATE").filter(|s| !s.trim().is_empty()) {
        let hostname = Path::new(state.trim()).join("hs-gateway").join("hostname");
        if let Some(text) = read(&hostname) {
            found.add(&text);
        }
    }
    found
}

/// Read the environment and file sources of this process.
pub fn discover() -> Found {
    discover_with(
        &|name| std::env::var(name).ok(),
        &|path| std::fs::read_to_string(path).ok(),
        avoid_nodes_path().as_deref(),
    )
}

/// The own-node set a client filters with: explicit entries plus (unless disabled) the local
/// sources, refreshed at most once a minute.
#[derive(Debug)]
pub struct OwnNodes {
    explicit: BTreeSet<String>,
    discover: bool,
    cache: Mutex<Option<(Instant, BTreeSet<String>)>>,
    logged: Mutex<String>,
}

impl OwnNodes {
    /// `explicit` entries are already validated by [`crate::ConfigBuilder::build`]; invalid ones
    /// are skipped here.
    pub fn new(explicit: &[String], discover: bool) -> Self {
        Self {
            explicit: explicit
                .iter()
                .filter_map(|e| shadenet_proto::normalize_own_node(e))
                .collect(),
            discover,
            cache: Mutex::new(None),
            logged: Mutex::new(String::new()),
        }
    }

    /// The current own-node set.
    pub fn current(&self) -> BTreeSet<String> {
        if !self.discover {
            return self.explicit.clone();
        }
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some((at, nodes)) = &*cache {
            if at.elapsed() < REFRESH {
                return nodes.clone();
            }
        }
        let found = discover();
        if !found.junk.is_empty() {
            tracing::warn!(
                count = found.junk.len(),
                "ignoring avoid-nodes entries that are not v3 onions"
            );
        }
        let mut nodes = found.nodes;
        nodes.extend(self.explicit.iter().cloned());
        *cache = Some((Instant::now(), nodes.clone()));
        nodes
    }

    /// Apply the rule to a canopy's gateways. Fails closed (`Err` with the refusal detail) when
    /// every offered node is an own node.
    pub fn filter(&self, gateways: &mut Vec<shadenet_proto::GatewayEntry>) -> Result<(), String> {
        let own = self.current();
        let offered = gateways.len();
        let excluded = shadenet_proto::exclude_own_nodes(gateways, &own);
        if excluded.is_empty() {
            return Ok(());
        }
        let key = excluded.join(",");
        let mut logged = self
            .logged
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *logged != key {
            tracing::info!(
                count = excluded.len(),
                "skipping own node(s): they exit from this connection's IP"
            );
            *logged = key;
        }
        if gateways.is_empty() {
            return Err(only_own_nodes_message(offered));
        }
        Ok(())
    }
}

/// The fail-closed refusal; starts with [`shadenet_proto::REASON_ONLY_OWN_NODES`].
pub fn only_own_nodes_message(offered: usize) -> String {
    format!(
        "{}: every node the canopy offers ({offered}) is one this machine or its connection runs, and exiting through it would show destinations your own IP",
        shadenet_proto::REASON_ONLY_OWN_NODES
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn onion(byte: u8) -> String {
        shadenet_proto::pubkey_to_onion(&[byte; 32])
    }

    fn entry(onion: &str) -> shadenet_proto::GatewayEntry {
        shadenet_proto::GatewayEntry {
            onion: onion.to_string(),
            pubkey: hex::encode(shadenet_proto::onion_to_pubkey(onion).unwrap()),
            weight: 100,
            health: "up".into(),
            operator: None,
            staked: None,
            caps: None,
            caps_sig: None,
        }
    }

    #[test]
    fn every_local_source_is_merged() {
        let (a, b, c, d) = (onion(0x33), onion(0x44), onion(0x55), onion(0x66));
        let env: HashMap<&str, String> = HashMap::from([
            (
                "SHADENET_AVOID_NODES",
                format!("{}, junk", a.to_uppercase()),
            ),
            ("SHADE_TREE_AVOID_NODES", d.clone()),
            ("SHADENET_STATE", "/state".to_string()),
        ]);
        let files: HashMap<PathBuf, String> = HashMap::from([
            (PathBuf::from("/cfg/avoid-nodes"), format!("# home\n{b}\n")),
            (
                Path::new("/state").join("hs-gateway").join("hostname"),
                format!("{c}\n"),
            ),
        ]);
        let found = discover_with(
            &|name| env.get(name).cloned(),
            &|path| files.get(path).cloned(),
            Some(Path::new("/cfg/avoid-nodes")),
        );
        assert_eq!(found.nodes, BTreeSet::from([a, b, c, d]));
        assert_eq!(found.junk, vec!["junk".to_string()]);
    }

    #[test]
    fn missing_sources_find_nothing() {
        let found = discover_with(&|_| None, &|_| None, None);
        assert!(found.nodes.is_empty() && found.junk.is_empty());
    }

    #[test]
    fn explicit_nodes_are_filtered_and_all_own_fails_closed() {
        let (a, b) = (onion(0x33), onion(0x44));
        let own = OwnNodes::new(&[a.trim_end_matches(".onion").to_uppercase()], false);
        let mut gateways = vec![entry(&a), entry(&b)];
        own.filter(&mut gateways).unwrap();
        assert_eq!(
            gateways
                .iter()
                .map(|g| g.onion.as_str())
                .collect::<Vec<_>>(),
            [b.as_str()]
        );

        let both = OwnNodes::new(&[a.clone(), format!("{b}:80")], false);
        let mut gateways = vec![entry(&a), entry(&b)];
        let refusal = both.filter(&mut gateways).unwrap_err();
        assert!(refusal.starts_with("only-own-nodes: "), "{refusal}");
        assert!(gateways.is_empty());

        let none = OwnNodes::new(&[], false);
        let mut gateways = vec![entry(&a)];
        none.filter(&mut gateways).unwrap();
        assert_eq!(gateways.len(), 1);
    }
}
