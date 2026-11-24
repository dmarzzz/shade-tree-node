//! The canopy incident feed (`packages/node/bootnode/incidents.mjs`): a small signed list of
//! operator-declared incidents at `GET /incidents`, so a client can tell its agent the real
//! cause instead of a bare transport timeout. Fed by the Alertmanager webhook (firing alerts
//! are upserted, resolved ones get `until`) or by hand in the file, re-read on every fetch.
//! Signed by the canopy signer over the bytes `shadenet::incidents::canonical_bytes` builds.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;
use serde_json::Value;
use shadenet::incidents::{canonical_bytes, Incident, MAX_INCIDENTS};
use shadenet_service::clock;
use shadenet_service::files::atomic_write;

use crate::signer::Signer;

const MAX_FIELD: usize = 256;
const COMPONENTS: [&str; 6] = ["elder", "node", "heartbeat", "rpc", "canopy", "other"];
const SEVERITIES: [&str; 3] = ["critical", "warning", "info"];
/// A resolved incident stays listed this long after `until`.
const RESOLVED_GRACE_SECS: u64 = 60 * 60;

#[derive(Serialize)]
struct Feed<'a> {
    version: u64,
    issued: u64,
    incidents: &'a [Incident],
    signer: &'a str,
    signature: String,
}

#[derive(Serialize)]
struct File<'a> {
    incidents: &'a [Incident],
}

/// What the webhook answers.
pub(crate) struct Applied {
    pub(crate) firing: usize,
    pub(crate) resolved: usize,
    pub(crate) open: usize,
}

fn clip(value: Option<&Value>) -> String {
    let text = value.and_then(Value::as_str).unwrap_or("");
    text.chars().take(MAX_FIELD).collect()
}

/// A unix time from a number or an ISO 8601 string.
fn unix(value: Option<&Value>) -> Option<u64> {
    match value? {
        Value::Number(n) => n
            .as_f64()
            .filter(|f| f.is_finite())
            .map(|f| f.floor() as u64),
        Value::String(s) => clock::parse_timestamp(s)
            .filter(|ms| *ms > 0)
            .map(|ms| ms / 1000),
        _ => None,
    }
}

/// One incident in the exact field set the signature covers; `None` when unusable.
pub(crate) fn normalize(raw: &Value) -> Option<Incident> {
    if !raw.is_object() {
        return None;
    }
    let id = clip(raw.get("id"));
    if id.is_empty() {
        return None;
    }
    let pick = |key: &str, allowed: &[&str], fallback: &str| -> String {
        raw.get(key)
            .and_then(Value::as_str)
            .filter(|v| allowed.contains(v))
            .unwrap_or(fallback)
            .to_string()
    };
    let since = unix(raw.get("since"))?;
    let until = match raw.get("until") {
        None | Some(Value::Null) => None,
        other => unix(other),
    };
    let instance = clip(raw.get("instance"));
    let summary = clip(raw.get("summary"));
    Some(Incident {
        id: id.clone(),
        component: pick("component", &COMPONENTS, "other"),
        instance: if instance.is_empty() {
            "canopy".into()
        } else {
            instance
        },
        severity: pick("severity", &SEVERITIES, "warning"),
        summary: if summary.is_empty() { id } else { summary },
        since,
        until,
    })
}

/// Drop resolved incidents past their grace and bound the list, newest first.
pub(crate) fn prune(incidents: Vec<Incident>, now: u64) -> Vec<Incident> {
    let mut kept: Vec<Incident> = incidents
        .into_iter()
        .filter(|i| {
            i.until
                .is_none_or(|until| until + RESOLVED_GRACE_SECS > now)
        })
        .collect();
    kept.sort_by_key(|i| std::cmp::Reverse(i.since));
    kept.truncate(MAX_INCIDENTS);
    kept
}

/// Map one Alertmanager webhook payload onto the list. Returns the merged list and how many
/// alerts were firing and resolved.
pub(crate) fn apply_payload(
    existing: Vec<Incident>,
    payload: &Value,
    now: u64,
) -> (Vec<Incident>, usize, usize) {
    let mut by_id: Vec<Incident> = existing;
    let (mut firing, mut resolved) = (0, 0);
    for alert in payload["alerts"].as_array().into_iter().flatten() {
        let labels = &alert["labels"];
        let name = {
            let n = clip(labels.get("alertname"));
            if n.is_empty() {
                "alert".to_string()
            } else {
                n
            }
        };
        let instance = {
            let i = clip(
                labels
                    .get("instance")
                    .or(labels.get("host"))
                    .or(labels.get("job")),
            );
            if i.is_empty() {
                "canopy".to_string()
            } else {
                i
            }
        };
        let id = format!("{name}:{instance}");
        let job = labels["job"].as_str().unwrap_or("").to_ascii_lowercase();
        let component = labels["component"]
            .as_str()
            .filter(|c| COMPONENTS.contains(c))
            .map(str::to_string)
            .unwrap_or_else(|| {
                if job.contains("bootnode") || job.contains("elder") {
                    "elder"
                } else if job.contains("gateway") || job.contains("node") {
                    "node"
                } else if job.contains("heartbeat") {
                    "heartbeat"
                } else {
                    "other"
                }
                .to_string()
            });
        let severity = labels["severity"]
            .as_str()
            .filter(|s| SEVERITIES.contains(s))
            .unwrap_or("warning")
            .to_string();
        let summary = {
            let s = clip(alert["annotations"].get("summary"));
            if s.is_empty() {
                name.clone()
            } else {
                s
            }
        };
        let since = unix(alert.get("startsAt")).unwrap_or(now);
        let previous = by_id.iter().position(|i| i.id == id);
        if alert["status"].as_str() == Some("resolved") {
            let until = unix(alert.get("endsAt")).filter(|t| *t > 0).unwrap_or(now);
            let mut incident = previous.map(|at| by_id.remove(at)).unwrap_or(Incident {
                id: id.clone(),
                component: component.clone(),
                instance: instance.clone(),
                severity: severity.clone(),
                summary: summary.clone(),
                since,
                until: None,
            });
            incident.until = Some(until);
            by_id.push(incident);
            resolved += 1;
        } else {
            if let Some(at) = previous {
                by_id.remove(at);
            }
            by_id.push(Incident {
                id,
                component,
                instance,
                severity,
                summary,
                since,
                until: None,
            });
            firing += 1;
        }
    }
    (by_id, firing, resolved)
}

pub(crate) struct Incidents {
    path: PathBuf,
    signer: Arc<Signer>,
}

impl Incidents {
    pub(crate) fn new(path: PathBuf, signer: Arc<Signer>) -> Self {
        Self { path, signer }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// The file's list, pruned; an absent or unreadable file is an empty feed.
    pub(crate) fn load(&self, now: u64) -> Vec<Incident> {
        if !self.path.exists() {
            return Vec::new();
        }
        let parsed = match std::fs::read_to_string(&self.path)
            .map_err(|e| e.to_string())
            .and_then(|text| serde_json::from_str::<Value>(&text).map_err(|e| e.to_string()))
        {
            Ok(parsed) => parsed,
            Err(e) => {
                tracing::warn!(path = %self.path.display(), "incidents file unreadable; serving an empty feed: {e}");
                return Vec::new();
            }
        };
        let list = match &parsed {
            Value::Array(list) => list.clone(),
            Value::Object(_) => parsed["incidents"].as_array().cloned().unwrap_or_default(),
            _ => Vec::new(),
        };
        prune(list.iter().filter_map(normalize).collect(), now)
    }

    fn save(&self, incidents: &[Incident]) -> Result<(), String> {
        let text = serde_json::to_string_pretty(&File { incidents }).map_err(|e| e.to_string())?;
        atomic_write(&self.path, format!("{text}\n").as_bytes()).map_err(|e| e.to_string())
    }

    /// The signed document for `GET /incidents`, built from the file on every call.
    pub(crate) fn feed(&self, now: u64) -> Vec<u8> {
        let incidents = self.load(now);
        let signature = self.signer.sign(&canonical_bytes(now, &incidents));
        serde_json::to_vec(&Feed {
            version: 1,
            issued: now,
            incidents: &incidents,
            signer: self.signer.public_hex(),
            signature,
        })
        .unwrap_or_default()
    }

    /// `POST /incidents/alertmanager`: merge the payload into the file.
    pub(crate) fn apply_alertmanager(&self, payload: &Value, now: u64) -> Result<Applied, String> {
        let (merged, firing, resolved) = apply_payload(self.load(now), payload, now);
        let open = merged.iter().filter(|i| i.until.is_none()).count();
        self.save(&prune(merged, now))?;
        Ok(Applied {
            firing,
            resolved,
            open,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn at(iso: &str) -> u64 {
        clock::parse_timestamp(iso).unwrap() / 1000
    }

    fn firing() -> Value {
        json!({
            "version": "4", "status": "firing",
            "alerts": [
                { "status": "firing", "labels": { "alertname": "BootnodeDown", "instance": "shade-elder-v4-02", "job": "shade-tree-bootnode", "severity": "critical" },
                  "annotations": { "summary": "Bootnode shade-elder-v4-02 is down / unscrapable" }, "startsAt": "2026-10-01T06:50:00Z", "endsAt": "0001-01-01T00:00:00Z" },
                { "status": "firing", "labels": { "alertname": "GatewayRootDegraded", "instance": "node-06", "job": "shade-tree-gateway" }, "annotations": {}, "startsAt": "2026-10-01T06:52:00Z" }
            ]
        })
    }

    #[test]
    fn incidents_normalize_like_the_javascript_elder() {
        assert!(normalize(&json!({"id": "x"})).is_none(), "no since");
        let n = normalize(&json!({"id": "x", "since": "2026-09-30T22:11:20Z", "component": "weird", "severity": "loud"})).unwrap();
        assert_eq!(n.since, at("2026-09-30T22:11:20Z"));
        assert_eq!(
            (
                n.component.as_str(),
                n.severity.as_str(),
                n.instance.as_str(),
                n.summary.as_str()
            ),
            ("other", "warning", "canopy", "x")
        );
    }

    #[test]
    fn the_alertmanager_mapping_and_the_prune_match() {
        let now = at("2026-10-01T06:55:00Z");
        let (list, firing_count, _) = apply_payload(Vec::new(), &firing(), now);
        assert_eq!((firing_count, list.len()), (2, 2));
        let elder = list
            .iter()
            .find(|i| i.id == "BootnodeDown:shade-elder-v4-02")
            .unwrap();
        assert_eq!(
            (
                elder.component.as_str(),
                elder.severity.as_str(),
                elder.until,
                elder.since
            ),
            ("elder", "critical", None, at("2026-10-01T06:50:00Z"))
        );
        let node = list
            .iter()
            .find(|i| i.id == "GatewayRootDegraded:node-06")
            .unwrap();
        assert_eq!(
            (
                node.component.as_str(),
                node.severity.as_str(),
                node.summary.as_str()
            ),
            ("node", "warning", "GatewayRootDegraded")
        );
        let resolved = json!({ "alerts": [{ "status": "resolved", "labels": { "alertname": "BootnodeDown", "instance": "shade-elder-v4-02", "job": "shade-tree-bootnode" }, "startsAt": "2026-10-01T06:50:00Z", "endsAt": "2026-10-01T07:12:00Z" }] });
        let (list, _, resolved_count) = apply_payload(list, &resolved, at("2026-10-01T07:12:30Z"));
        let closed = list
            .iter()
            .find(|i| i.id == "BootnodeDown:shade-elder-v4-02")
            .unwrap();
        assert_eq!(
            (resolved_count, closed.until, closed.since),
            (
                1,
                Some(at("2026-10-01T07:12:00Z")),
                at("2026-10-01T06:50:00Z")
            )
        );
        assert_eq!(
            prune(list.clone(), at("2026-10-01T07:12:00Z") + 3601).len(),
            1,
            "pruned an hour after until"
        );
        assert_eq!(
            prune(list, at("2026-10-01T07:12:00Z") + 10).len(),
            2,
            "listed inside the grace"
        );
        let many = json!({ "alerts": (0..100).map(|i| json!({ "status": "firing", "labels": { "alertname": "A", "instance": format!("h{i}") }, "startsAt": "2026-10-01T06:50:00Z" })).collect::<Vec<_>>() });
        assert_eq!(
            prune(apply_payload(Vec::new(), &many, now).0, now).len(),
            64
        );
    }

    #[test]
    fn the_feed_is_signed_over_the_shared_canonical_bytes_and_round_trips_the_file() {
        let dir =
            std::env::temp_dir().join(format!("shadenet-elder-incidents-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let signer = Arc::new(Signer::load_or_mint(&dir.join("signer.key")).unwrap());
        let incidents = Incidents::new(dir.join("incidents.json"), Arc::clone(&signer));
        let now = at("2026-10-01T06:55:00Z");
        let empty = String::from_utf8(incidents.feed(now)).unwrap();
        let verified =
            shadenet::incidents::parse_and_verify(&empty, signer.public_hex(), now).unwrap();
        assert!(verified.incidents.is_empty());
        std::fs::write(incidents.path(), json!({"incidents": [{"id": "ByHand:node-05", "component": "node", "instance": "node-05", "severity": "info", "summary": "planned restart", "since": now - 60}]}).to_string()).unwrap();
        assert_eq!(incidents.load(now)[0].id, "ByHand:node-05");
        let applied = incidents.apply_alertmanager(&firing(), now).unwrap();
        assert_eq!((applied.firing, applied.open), (2, 3));
        let on_disk: Value =
            serde_json::from_str(&std::fs::read_to_string(incidents.path()).unwrap()).unwrap();
        assert_eq!(on_disk["incidents"].as_array().unwrap().len(), 3);
        let feed = String::from_utf8(incidents.feed(now)).unwrap();
        let verified =
            shadenet::incidents::parse_and_verify(&feed, signer.public_hex(), now).unwrap();
        assert_eq!(verified.incidents.len(), 3);
        assert!(shadenet::incidents::parse_and_verify(&feed, &"ab".repeat(32), now).is_err());
        std::fs::write(incidents.path(), "{not json").unwrap();
        assert!(
            incidents.load(now).is_empty(),
            "an unreadable file serves an empty feed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_sample_vector_bytes_are_the_javascript_ones() {
        let sample = vec![Incident {
            id: "BootnodeDown:shade-elder-v4-02".into(),
            component: "elder".into(),
            instance: "shade-elder-v4-02".into(),
            severity: "critical".into(),
            summary: "Bootnode \"shade-elder-v4-02\" is down".into(),
            since: 1_759_299_000,
            until: None,
        }];
        let bytes = String::from_utf8(canonical_bytes(1_759_300_000, &sample)).unwrap();
        assert_eq!(bytes, "Shade Tree incidents v1\n{\"version\":1,\"issued\":1759300000,\"incidents\":[{\"id\":\"BootnodeDown:shade-elder-v4-02\",\"component\":\"elder\",\"instance\":\"shade-elder-v4-02\",\"severity\":\"critical\",\"summary\":\"Bootnode \\\"shade-elder-v4-02\\\" is down\",\"since\":1759299000,\"until\":null}]}");
    }
}
