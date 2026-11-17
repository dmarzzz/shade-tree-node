//! `<state>/status.json`: what a running node is doing, written by `run` and read by
//! `shadenet-node status` (`packages/node/lib/node-supervisor.mjs` `writeStatus`,
//! `heartbeatListing`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::{json, Value};

use crate::clock;

pub(crate) const FILE: &str = "status.json";

pub(crate) struct Status {
    path: PathBuf,
    fields: Mutex<Value>,
}

/// What `run` records before the node serves.
pub(crate) struct Start {
    pub(crate) state_dir: PathBuf,
    pub(crate) onion: String,
    pub(crate) network: String,
    pub(crate) set: String,
    pub(crate) elders: Vec<String>,
    pub(crate) commit: String,
    pub(crate) record_pin: Option<String>,
    pub(crate) metrics_port: u16,
}

impl Status {
    pub(crate) fn new(start: Start) -> Self {
        let fields = json!({
            "stateDir": start.state_dir.display().to_string(),
            "onion": start.onion,
            "network": start.network,
            "set": start.set,
            "elders": start.elders,
            "commit": start.commit,
            "recordPin": start.record_pin,
            "metricsPort": start.metrics_port,
            // one process serves both the node's and the heartbeat's series
            "heartbeatMetricsPort": start.metrics_port,
            "startedAt": clock::iso(clock::now_ms()),
            "pids": {},
        });
        Self {
            path: start.state_dir.join(FILE),
            fields: Mutex::new(fields),
        }
    }

    fn update(&self, apply: impl FnOnce(&mut serde_json::Map<String, Value>)) {
        let mut fields = self.fields.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(object) = fields.as_object_mut() {
            apply(object);
            object.insert(
                "updatedAt".into(),
                Value::String(clock::iso(clock::now_ms())),
            );
        }
        let text = serde_json::to_string_pretty(&*fields).unwrap_or_default();
        if let Err(e) = std::fs::write(&self.path, format!("{text}\n")) {
            tracing::debug!("status.json not written: {e}");
        }
    }

    pub(crate) fn set_pid(&self, name: &str, pid: Option<u32>) {
        self.update(|fields| {
            let pids = fields.entry("pids").or_insert_with(|| json!({}));
            if let Some(pids) = pids.as_object_mut() {
                match pid {
                    Some(pid) => {
                        pids.insert(name.into(), json!(pid));
                    }
                    None => {
                        pids.remove(name);
                    }
                }
            }
        });
    }

    pub(crate) fn set_drift(&self, changes: &[String]) {
        self.update(|fields| {
            if changes.is_empty() {
                fields.remove("recordDrift");
            } else {
                fields.insert(
                    "recordDrift".into(),
                    json!({ "changes": changes, "seenAt": clock::iso(clock::now_ms()) }),
                );
            }
        });
    }

    pub(crate) fn stopped(&self) {
        self.update(|fields| {
            fields.insert(
                "stoppedAt".into(),
                Value::String(clock::iso(clock::now_ms())),
            );
        });
    }
}

/// The last written status, if any.
pub(crate) fn read(state_dir: &Path) -> Option<Value> {
    serde_json::from_slice(&std::fs::read(state_dir.join(FILE)).ok()?).ok()
}

/// How many Elder Trees list this node, from the heartbeat's own Prometheus text.
pub(crate) fn heartbeat_listing(metrics: &str) -> Option<BTreeMap<&'static str, Value>> {
    let read = |name: &str| -> Option<f64> {
        metrics.lines().find_map(|line| {
            let rest = line.strip_prefix(name)?;
            let rest = match rest.strip_prefix('{') {
                Some(labels) => labels.split_once('}')?.1,
                None => rest,
            };
            let value = rest.strip_prefix(' ')?.trim();
            value.parse().ok()
        })
    };
    let accepted = read("shade_tree_heartbeat_elders_accepted")?;
    let total = read("shade_tree_heartbeat_elders_total")?;
    let last = read("shade_tree_heartbeat_last_success_timestamp_seconds").filter(|v| *v > 0.0);
    Some(BTreeMap::from([
        ("eldersAccepted", json!(accepted)),
        ("eldersTotal", json!(total)),
        (
            "lastAcceptedAt",
            last.map_or(Value::Null, |secs| {
                Value::String(clock::iso((secs * 1000.0) as u64))
            }),
        ),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listing_reads_the_heartbeat_series() {
        let listing = heartbeat_listing("# HELP x\nshade_tree_heartbeat_elders_accepted 0\nshade_tree_heartbeat_elders_total 2\nshade_tree_heartbeat_last_success_timestamp_seconds 0\n").unwrap();
        assert_eq!(listing["eldersAccepted"], 0.0);
        assert_eq!(listing["eldersTotal"], 2.0);
        assert_eq!(listing["lastAcceptedAt"], Value::Null);
        let listing = heartbeat_listing("shade_tree_heartbeat_elders_accepted 2\nshade_tree_heartbeat_elders_total 2\nshade_tree_heartbeat_last_success_timestamp_seconds 1791191700.779\n").unwrap();
        assert_eq!(listing["lastAcceptedAt"], "2026-10-05T09:15:00.779Z");
        assert!(heartbeat_listing("nothing here").is_none());
    }

    #[test]
    fn the_file_tracks_pids_drift_and_the_stop() {
        let dir = std::env::temp_dir().join(format!("shadenet-status-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let status = Status::new(Start {
            state_dir: dir.clone(),
            onion: "x.onion".into(),
            network: "sepolia".into(),
            set: "0xabc".into(),
            elders: vec!["e.onion".into()],
            commit: "abc".into(),
            record_pin: None,
            metrics_port: 9101,
        });
        status.set_pid("tor", Some(42));
        let value = read(&dir).unwrap();
        assert_eq!(value["pids"]["tor"], 42);
        assert_eq!(value["heartbeatMetricsPort"], 9101);
        assert!(value["updatedAt"].is_string());
        status.set_drift(&["set a -> b".into()]);
        assert_eq!(
            read(&dir).unwrap()["recordDrift"]["changes"][0],
            "set a -> b"
        );
        status.set_drift(&[]);
        assert!(read(&dir).unwrap().get("recordDrift").is_none());
        status.set_pid("tor", None);
        status.stopped();
        let value = read(&dir).unwrap();
        assert!(value["pids"].get("tor").is_none());
        assert!(value["stoppedAt"].is_string());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
