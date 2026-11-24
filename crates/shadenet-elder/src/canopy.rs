//! The signed directory (`registry.directory`, `directoryWithEtag`, `delta`): the live set as
//! the shape every client verifies against the pinned signer, its strong ETag, and the delta
//! protocol that ships only what changed since a client's last view. A delta carries the
//! current signer, signature and gateway order, so the client reconstructs the directory from
//! its cached base plus `added` and verifies it as usual; a lie anywhere changes the bytes the
//! pinned signer signed (ADR 0003).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use serde_json::value::RawValue;
use sha2::{Digest as _, Sha256};
use shadenet_proto::{
    canonical_caps_json_text, canonical_directory_bytes, Directory, GatewayEntry,
};

use crate::registry::{Entry, Registry};
use crate::signer::Signer;

const DIRECTORY_VERSION: u64 = 1;

/// A served directory: its bytes, its ETag and what the delta protocol needs to remember.
pub(crate) struct Served {
    pub(crate) body: Vec<u8>,
    pub(crate) etag: String,
    issued: u64,
    signature: String,
    entries: Vec<(String, Box<RawValue>)>,
}

#[derive(Serialize)]
struct EntryJson<'a> {
    onion: &'a str,
    pubkey: &'a str,
    weight: u64,
    health: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    operator: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    staked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    caps: Option<Box<RawValue>>,
    #[serde(rename = "capsSig", skip_serializing_if = "Option::is_none")]
    caps_sig: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    announce: Option<&'a RawValue>,
}

#[derive(Serialize)]
struct Meta<'a> {
    version: u64,
    issued: u64,
    signer: &'a str,
    signature: &'a str,
    order: Vec<&'a str>,
}

#[derive(Serialize)]
struct DeltaJson<'a> {
    base: &'a str,
    since: &'a str,
    added: Vec<&'a RawValue>,
    removed: Vec<&'a str>,
    unchanged: usize,
    directory: Meta<'a>,
}

#[derive(Serialize)]
struct FullJson<'a> {
    full: bool,
    base: &'a str,
}

pub(crate) struct Canopy {
    signer: Arc<Signer>,
    registry: Arc<Registry>,
    /// Recent versions by ETag, each the entries it listed, newest last.
    history: Mutex<VecDeque<(String, HashMap<String, String>)>>,
    history_max: usize,
    /// Onions the prober found unreachable, demoted to `down` in the listing.
    down: Mutex<HashSet<String>>,
}

fn etag_key(etag: &str) -> String {
    etag.trim().trim_matches('"').to_ascii_lowercase()
}

impl Canopy {
    pub(crate) fn new(signer: Arc<Signer>, registry: Arc<Registry>, history_max: usize) -> Self {
        Self {
            signer,
            registry,
            history: Mutex::new(VecDeque::new()),
            history_max,
            down: Mutex::new(HashSet::new()),
        }
    }

    /// Replace the set of onions listed as `down`.
    pub(crate) fn set_down(&self, onions: HashSet<String>) {
        *self.down.lock().unwrap_or_else(|e| e.into_inner()) = onions;
    }

    /// The signed directory over the live set at `now`, recorded into the delta history.
    pub(crate) fn directory(&self, now: u64) -> Served {
        let down = self.down.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let (entries, signed) = self.registry.with_live(now, |live| {
            let mut entries = Vec::with_capacity(live.len());
            let mut signed = Vec::with_capacity(live.len());
            for (onion, entry) in live {
                entries.push((onion.clone(), entry_json(onion, entry, &down)));
                signed.push(gateway_entry(onion, entry, &down));
            }
            (entries, signed)
        });
        let directory = Directory {
            version: DIRECTORY_VERSION,
            issued: now,
            gateways: signed,
            signer: None,
            signature: None,
            signers: None,
            signatures: None,
            threshold: None,
        };
        let signature = self.signer.sign(&canonical_directory_bytes(&directory));
        let mut body = format!("{{\"version\":{DIRECTORY_VERSION},\"issued\":{now},\"gateways\":[");
        for (i, (_, entry)) in entries.iter().enumerate() {
            if i > 0 {
                body.push(',');
            }
            body.push_str(entry.get());
        }
        body.push_str(&format!(
            "],\"signer\":\"{}\",\"signature\":\"{signature}\"}}",
            self.signer.public_hex()
        ));
        let body = body.into_bytes();
        let etag = format!("\"{}\"", hex::encode(Sha256::digest(&body)));
        self.record_version(&etag, &entries);
        Served {
            body,
            etag,
            issued: now,
            signature,
            entries,
        }
    }

    fn record_version(&self, etag: &str, entries: &[(String, Box<RawValue>)]) {
        let key = etag_key(etag);
        let mut history = self.history.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(position) = history.iter().position(|(k, _)| *k == key) {
            history.remove(position);
        }
        history.push_back((
            key,
            entries
                .iter()
                .map(|(onion, entry)| (onion.clone(), entry.get().to_string()))
                .collect(),
        ));
        while history.len() > self.history_max {
            history.pop_front();
        }
    }

    /// What changed since the client's `since` ETag, or `full: true` when that version is
    /// unknown or aged out. Returns the JSON and whether it was a delta.
    pub(crate) fn delta(&self, now: u64, since: Option<&str>) -> (Vec<u8>, bool) {
        let served = self.directory(now);
        let full = || {
            (
                serde_json::to_vec(&FullJson {
                    full: true,
                    base: &served.etag,
                })
                .unwrap_or_default(),
                false,
            )
        };
        let Some(since) = since.filter(|s| !etag_key(s).is_empty()) else {
            return full();
        };
        let previous = {
            let history = self.history.lock().unwrap_or_else(|e| e.into_inner());
            let key = etag_key(since);
            history
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, m)| m.clone())
        };
        let Some(previous) = previous else {
            return full();
        };
        let current: HashSet<&str> = served.entries.iter().map(|(o, _)| o.as_str()).collect();
        let added: Vec<&RawValue> = served
            .entries
            .iter()
            .filter(|(onion, entry)| previous.get(onion) != Some(&entry.get().to_string()))
            .map(|(_, entry)| &**entry)
            .collect();
        let removed: Vec<&str> = previous
            .keys()
            .map(String::as_str)
            .filter(|onion| !current.contains(onion))
            .collect();
        let delta = DeltaJson {
            base: &served.etag,
            since,
            unchanged: current.len() - added.len(),
            added,
            removed,
            directory: Meta {
                version: DIRECTORY_VERSION,
                issued: served.issued,
                signer: self.signer.public_hex(),
                signature: &served.signature,
                order: served.entries.iter().map(|(o, _)| o.as_str()).collect(),
            },
        };
        (serde_json::to_vec(&delta).unwrap_or_default(), true)
    }
}

fn health(onion: &str, down: &HashSet<String>) -> &'static str {
    if down.contains(onion) {
        "down"
    } else {
        "up"
    }
}

fn entry_json(onion: &str, entry: &Entry, down: &HashSet<String>) -> Box<RawValue> {
    let json = EntryJson {
        onion,
        pubkey: &entry.pubkey,
        weight: entry.weight,
        health: health(onion, down),
        operator: entry.operator.as_deref(),
        staked: entry.operator.as_ref().map(|_| entry.staked),
        caps: entry
            .caps
            .as_ref()
            .and_then(|(caps, _)| RawValue::from_string(canonical_caps_json_text(caps)).ok()),
        caps_sig: entry.caps.as_ref().map(|(_, sig)| sig.as_str()),
        announce: entry.listed(),
    };
    // the fields above are strings, numbers and valid json fragments, so this cannot fail
    RawValue::from_string(serde_json::to_string(&json).unwrap_or_default()).unwrap_or_else(|_| {
        RawValue::from_string("{}".into()).expect("a literal object is valid json")
    })
}

fn gateway_entry(onion: &str, entry: &Entry, down: &HashSet<String>) -> GatewayEntry {
    GatewayEntry {
        onion: onion.to_string(),
        pubkey: entry.pubkey.clone(),
        weight: entry.weight,
        health: health(onion, down).to_string(),
        operator: entry.operator.clone(),
        staked: entry.operator.as_ref().map(|_| entry.staked),
        caps: entry.caps.as_ref().map(|(caps, _)| caps.clone()),
        caps_sig: entry.caps.as_ref().map(|(_, sig)| sig.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::tests::{make, mock, raw, Node};
    use crate::registry::Outcome;
    use serde_json::Value;
    use shadenet::dircache::parse_and_verify_document;
    use shadenet_proto::{Caps, ProtoCaps};

    fn signer(dir: &str) -> Arc<Signer> {
        let path =
            std::env::temp_dir().join(format!("shadenet-elder-{dir}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        Arc::new(Signer::load_or_mint(&path.join("signer.key")).unwrap())
    }

    async fn accept(registry: &Registry, node: &Node, now: u64, nonce: &str) {
        match registry
            .announce(&raw(&node.announce(100, now, nonce, None, None)), now)
            .await
        {
            Outcome::Accepted { .. } => {}
            Outcome::Rejected { reason, .. } => panic!("{reason}"),
        }
    }

    #[tokio::test]
    async fn the_served_directory_verifies_and_the_delta_reconstructs_it() {
        let now = 1_000_000;
        let registry = Arc::new(make(mock(None), false, 900, 10_000, 0, now));
        let signer = signer("canopy");
        let canopy = Canopy::new(Arc::clone(&signer), Arc::clone(&registry), 64);
        let (g1, g2, g3) = (Node::new(1), Node::new(2), Node::new(3));
        accept(&registry, &g1, now, "e1").await;
        accept(&registry, &g2, now, "e1").await;
        let e1 = canopy.directory(now);
        let text = String::from_utf8(e1.body.clone()).unwrap();
        let verified = parse_and_verify_document(&text, signer.public_hex()).unwrap();
        assert_eq!(verified.dir.gateways.len(), 2);
        assert!(parse_and_verify_document(&text, &"00".repeat(32)).is_err());
        let value: Value = serde_json::from_str(&text).unwrap();
        let listed = value["gateways"]
            .as_array()
            .unwrap()
            .iter()
            .find(|g| g["onion"] == g1.onion)
            .unwrap();
        assert_eq!(listed["announce"]["onion"], g1.onion);
        assert_eq!(listed["health"], "up");
        assert!(listed.get("operator").is_none());

        let (empty, is_delta) = canopy.delta(now, Some(&e1.etag));
        let empty: Value = serde_json::from_slice(&empty).unwrap();
        assert!(
            is_delta
                && empty["added"].as_array().unwrap().is_empty()
                && empty["removed"].as_array().unwrap().is_empty()
        );
        assert_eq!(empty["unchanged"], 2);
        assert_eq!(empty["base"], e1.etag);

        let later = now + 901;
        accept(&registry, &g1, later, "e2").await;
        accept(&registry, &g3, later, "e2").await;
        let (delta, is_delta) = canopy.delta(later, Some(&e1.etag));
        assert!(is_delta);
        let delta: Value = serde_json::from_slice(&delta).unwrap();
        let added = delta["added"].as_array().unwrap();
        assert_eq!(
            added.len(),
            2,
            "g3 joined and g1's listed announce moved on"
        );
        assert!(added.iter().any(|g| g["onion"] == g3.onion));
        assert!(added
            .iter()
            .any(|g| g["onion"] == g1.onion && g["announce"]["ts"] == later));
        assert_eq!(delta["removed"], serde_json::json!([g2.onion]));
        assert_eq!(delta["unchanged"], 0);

        // an honest client rebuilds the directory from its cached base plus the delta
        let mut by_onion: HashMap<String, Value> = value["gateways"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| (g["onion"].as_str().unwrap().to_string(), g.clone()))
            .collect();
        for g in added {
            by_onion.insert(g["onion"].as_str().unwrap().to_string(), g.clone());
        }
        let order = delta["directory"]["order"].as_array().unwrap();
        let rebuilt = serde_json::json!({
            "version": delta["directory"]["version"],
            "issued": delta["directory"]["issued"],
            "gateways": order.iter().map(|o| by_onion[o.as_str().unwrap()].clone()).collect::<Vec<_>>(),
            "signer": delta["directory"]["signer"],
            "signature": delta["directory"]["signature"],
        });
        assert!(parse_and_verify_document(&rebuilt.to_string(), signer.public_hex()).is_ok());
        let full = canopy.directory(later);
        assert_eq!(
            serde_json::from_slice::<Value>(&full.body).unwrap(),
            rebuilt,
            "the delta path and the full path agree"
        );

        // a forged entry fails the client's own onion-key binding
        let mut forged = rebuilt.clone();
        forged["gateways"].as_array_mut().unwrap().push(serde_json::json!({"onion": g2.onion, "pubkey": "00".repeat(32), "weight": 1000, "health": "up"}));
        assert!(parse_and_verify_document(&forged.to_string(), signer.public_hex()).is_err());

        let (unknown, is_delta) = canopy.delta(later, Some(&format!("\"{}\"", "de".repeat(32))));
        assert!(!is_delta);
        let unknown: Value = serde_json::from_slice(&unknown).unwrap();
        assert_eq!(unknown["full"], true);
        assert!(unknown["base"].is_string());
        assert!(!canopy.delta(later, None).1);
    }

    #[tokio::test]
    async fn caps_and_operator_labels_are_listed_as_the_javascript_elder_lists_them() {
        let now = 1_000_000;
        let registry = Arc::new(make(mock(None), false, 900, 10_000, 0, now));
        let signer = signer("canopy-caps");
        let canopy = Canopy::new(Arc::clone(&signer), Arc::clone(&registry), 64);
        let (operator, operator_sig, node) = crate::registry::tests::operator_vector();
        let caps = Caps {
            ports: Some(vec![80, 443]),
            region: Some("eu".into()),
            proto: Some(ProtoCaps { min: 4, max: 4 }),
            ..Caps::default()
        };
        match registry
            .announce(
                &raw(&node.announce(
                    5000,
                    now,
                    "cap",
                    Some(&caps),
                    Some((&operator, &operator_sig)),
                )),
                now,
            )
            .await
        {
            Outcome::Accepted { .. } => {}
            Outcome::Rejected { reason, .. } => panic!("{reason}"),
        }
        let served = canopy.directory(now);
        let text = String::from_utf8(served.body).unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        let entry = &value["gateways"][0];
        assert_eq!(entry["weight"], 1000);
        assert_eq!(entry["operator"], operator.to_ascii_lowercase());
        assert_eq!(entry["staked"], true);
        assert_eq!(
            entry["caps"],
            serde_json::json!({"ports": [80, 443], "region": "eu", "proto": {"min": 4, "max": 4}})
        );
        assert!(entry["capsSig"].is_string());
        let verified = parse_and_verify_document(&text, signer.public_hex()).unwrap();
        assert_eq!(
            verified.dir.gateways[0].operator.as_deref(),
            Some(operator.to_ascii_lowercase().as_str())
        );
        canopy.set_down(HashSet::from([node.onion.clone()]));
        let demoted: Value = serde_json::from_slice(&canopy.directory(now).body).unwrap();
        assert_eq!(demoted["gateways"][0]["health"], "down");
    }

    #[test]
    fn the_signed_bytes_match_the_vectors() {
        let vectors: Value =
            serde_json::from_str(include_str!("../../../testdata/vectors.json")).unwrap();
        let entry = &vectors["capabilities"];
        let caps = Caps {
            ports: Some(vec![80, 443]),
            region: Some("eu".into()),
            proto: Some(ProtoCaps { min: 4, max: 4 }),
            ..Caps::default()
        };
        let directory = Directory {
            version: 1,
            issued: 1_000_000,
            gateways: vec![GatewayEntry {
                onion: vectors["onion"].as_str().unwrap().into(),
                pubkey: vectors["onionPub"].as_str().unwrap().into(),
                weight: 100,
                health: "up".into(),
                operator: None,
                staked: None,
                caps: Some(caps),
                caps_sig: Some(entry["capsSig"].as_str().unwrap().into()),
            }],
            signer: None,
            signature: None,
            signers: None,
            signatures: None,
            threshold: None,
        };
        assert_eq!(
            hex::encode(canonical_directory_bytes(&directory)),
            entry["directoryWithCaps"]["canonicalBytesHex"]
                .as_str()
                .unwrap()
        );
    }
}
