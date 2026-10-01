//! The canopy incident feed: a small signed document an Elder Tree serves at `GET /incidents`,
//! written by the operator's alerting (Alertmanager webhook) or by hand, so a client can tell an
//! agent "node-06 has been restarting since 22:11Z" instead of "transport timed out".
//!
//! Wire shape (mirrors `packages/node/bootnode/incidents.mjs`):
//!
//! ```json
//! { "version": 1, "issued": 1759300000,
//!   "incidents": [ { "id": "BootnodeDown:shade-elder-v4-02", "component": "elder",
//!                    "instance": "shade-elder-v4-02", "severity": "critical",
//!                    "summary": "Bootnode shade-elder-v4-02 is down", "since": 1759299000, "until": null } ],
//!   "signer": "<hex ed25519>", "signature": "<hex ed25519 over the canonical bytes>" }
//! ```
//!
//! The signature covers [`INCIDENTS_DOMAIN`] followed by the canonical JSON of
//! `{version, issued, incidents}` with fixed key order, exactly as `JSON.stringify` writes it, so
//! both implementations build byte-identical input. The signer is the Elder's canopy signer, the
//! key the client already pins for the directory; the feed carries no authority beyond "this Elder
//! says so" and is only ever surfaced as advice.

use serde::{Deserialize, Serialize};

/// Domain separator for the incident feed signature.
pub const INCIDENTS_DOMAIN: &str = "Shade Tree incidents v1\n";
/// A feed older than this is ignored (an Elder that stopped refreshing it says nothing useful).
pub const MAX_FEED_AGE_SECS: u64 = 24 * 60 * 60;
/// Clock skew tolerated on `issued`.
pub const MAX_SKEW_SECS: u64 = 5 * 60;
/// Upper bound on incidents accepted from one feed.
pub const MAX_INCIDENTS: usize = 64;
const MAX_FIELD: usize = 256;

/// One operator-declared incident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Incident {
    pub id: String,
    pub component: String,
    pub instance: String,
    pub severity: String,
    pub summary: String,
    pub since: u64,
    #[serde(default)]
    pub until: Option<u64>,
}

impl Incident {
    /// Still open at `now`.
    pub fn active_at(&self, now: u64) -> bool {
        self.until.is_none_or(|until| until > now)
    }
}

/// A verified feed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IncidentFeed {
    pub issued: u64,
    pub signer: String,
    pub incidents: Vec<Incident>,
}

impl IncidentFeed {
    /// Incidents still open at `now`.
    pub fn active(&self, now: u64) -> Vec<&Incident> {
        self.incidents.iter().filter(|i| i.active_at(now)).collect()
    }
}

#[derive(Deserialize)]
struct FeedDto {
    version: u64,
    issued: u64,
    #[serde(default)]
    incidents: Vec<Incident>,
    #[serde(default)]
    signer: Option<String>,
    #[serde(default)]
    signature: Option<String>,
}

/// JSON string escaping as `JSON.stringify` does it (the subset that matters: `"`, `\`, the
/// C0 controls, and the two short escapes JS emits for `\b` `\f` `\n` `\r` `\t`).
fn push_js_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The exact bytes the Elder signs.
pub fn canonical_bytes(issued: u64, incidents: &[Incident]) -> Vec<u8> {
    let mut s = String::from(INCIDENTS_DOMAIN);
    s.push_str("{\"version\":1,\"issued\":");
    s.push_str(&issued.to_string());
    s.push_str(",\"incidents\":[");
    for (i, inc) in incidents.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str("{\"id\":");
        push_js_string(&mut s, &inc.id);
        s.push_str(",\"component\":");
        push_js_string(&mut s, &inc.component);
        s.push_str(",\"instance\":");
        push_js_string(&mut s, &inc.instance);
        s.push_str(",\"severity\":");
        push_js_string(&mut s, &inc.severity);
        s.push_str(",\"summary\":");
        push_js_string(&mut s, &inc.summary);
        s.push_str(",\"since\":");
        s.push_str(&inc.since.to_string());
        s.push_str(",\"until\":");
        match inc.until {
            Some(u) => s.push_str(&u.to_string()),
            None => s.push_str("null"),
        }
        s.push('}');
    }
    s.push_str("]}");
    s.into_bytes()
}

/// Parse an untrusted feed body and verify it against the pinned canopy signer(s)
/// (`;`-separated hex, as the client pins them). Rejects an unsigned, forged, oversized, future
/// or day-old feed.
pub fn parse_and_verify(raw: &str, pinned_signers: &str, now: u64) -> Result<IncidentFeed, String> {
    if raw.len() > 256 * 1024 {
        return Err("incident feed exceeds 256 KiB".into());
    }
    let dto: FeedDto =
        serde_json::from_str(raw).map_err(|e| format!("incident feed is not JSON: {e}"))?;
    if dto.version != 1 {
        return Err(format!("incident feed version {} is not 1", dto.version));
    }
    if dto.incidents.len() > MAX_INCIDENTS {
        return Err(format!(
            "incident feed lists {} incidents (max {MAX_INCIDENTS})",
            dto.incidents.len()
        ));
    }
    for inc in &dto.incidents {
        for (name, value) in [
            ("id", &inc.id),
            ("component", &inc.component),
            ("instance", &inc.instance),
            ("severity", &inc.severity),
            ("summary", &inc.summary),
        ] {
            if value.is_empty() || value.len() > MAX_FIELD {
                return Err(format!(
                    "incident {name} is empty or over {MAX_FIELD} bytes"
                ));
            }
        }
    }
    if dto.issued > now.saturating_add(MAX_SKEW_SECS) {
        return Err(format!(
            "incident feed issued {} is in the future",
            dto.issued
        ));
    }
    if now.saturating_sub(dto.issued) > MAX_FEED_AGE_SECS {
        return Err(format!(
            "incident feed issued {} is more than a day old",
            dto.issued
        ));
    }
    let signer = dto
        .signer
        .ok_or("incident feed is unsigned")?
        .to_ascii_lowercase();
    let signature = dto.signature.ok_or("incident feed is unsigned")?;
    let pinned = pinned_signers
        .split(';')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .any(|s| s == signer);
    if !pinned {
        return Err("incident feed signer is not a pinned canopy signer".into());
    }
    let ok = (|| -> Option<bool> {
        let pk: [u8; 32] = hex::decode(&signer).ok()?.try_into().ok()?;
        let sig: [u8; 64] = hex::decode(&signature).ok()?.try_into().ok()?;
        Some(shadenet_proto::ed25519_verify(
            &canonical_bytes(dto.issued, &dto.incidents),
            &sig,
            &pk,
        ))
    })()
    .unwrap_or(false);
    if !ok {
        return Err("incident feed signature does not verify".into());
    }
    Ok(IncidentFeed {
        issued: dto.issued,
        signer,
        incidents: dto.incidents,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Signed by packages/node/bootnode/incidents.selftest.mjs ("vector" section) with the seed
    // 00..01; the selftest prints these exact bytes so both implementations agree.
    const SIGNER: &str = "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29";
    const SIGNATURE: &str = "10379a42403b717a9149d3c9c170bb43c7049188294bd9c370c387828bc57ad8eb7cff7c5055c0a940c27c673a2dc258a38e0bd3bd03d95e6a7f04ce2bba9402";

    fn sample() -> (u64, Vec<Incident>) {
        (
            1_759_300_000,
            vec![Incident {
                id: "BootnodeDown:shade-elder-v4-02".into(),
                component: "elder".into(),
                instance: "shade-elder-v4-02".into(),
                severity: "critical".into(),
                summary: "Bootnode \"shade-elder-v4-02\" is down".into(),
                since: 1_759_299_000,
                until: None,
            }],
        )
    }

    #[test]
    fn canonical_bytes_match_json_stringify() {
        let (issued, incidents) = sample();
        let bytes = String::from_utf8(canonical_bytes(issued, &incidents)).unwrap();
        assert_eq!(
            bytes,
            "Shade Tree incidents v1\n{\"version\":1,\"issued\":1759300000,\"incidents\":[{\"id\":\"BootnodeDown:shade-elder-v4-02\",\"component\":\"elder\",\"instance\":\"shade-elder-v4-02\",\"severity\":\"critical\",\"summary\":\"Bootnode \\\"shade-elder-v4-02\\\" is down\",\"since\":1759299000,\"until\":null}]}"
        );
    }

    #[test]
    fn js_escaping_rules() {
        let mut s = String::new();
        push_js_string(&mut s, "a\"b\\c\n\t\u{1}é");
        assert_eq!(s, "\"a\\\"b\\\\c\\n\\t\\u0001é\"");
    }

    #[test]
    fn rejects_unsigned_future_stale_and_unpinned() {
        let (issued, incidents) = sample();
        let body = serde_json::json!({
            "version": 1, "issued": issued, "incidents": incidents,
            "signer": SIGNER, "signature": SIGNATURE,
        });
        let now = issued + 10;
        assert!(parse_and_verify(&body.to_string(), "deadbeef", now)
            .unwrap_err()
            .contains("not a pinned"));
        let mut unsigned = body.clone();
        unsigned["signature"] = serde_json::Value::Null;
        assert!(parse_and_verify(&unsigned.to_string(), SIGNER, now)
            .unwrap_err()
            .contains("unsigned"));
        assert!(
            parse_and_verify(&body.to_string(), SIGNER, issued - MAX_SKEW_SECS - 1)
                .unwrap_err()
                .contains("future")
        );
        assert!(
            parse_and_verify(&body.to_string(), SIGNER, issued + MAX_FEED_AGE_SECS + 1)
                .unwrap_err()
                .contains("day old")
        );
        let mut forged = body.clone();
        forged["incidents"][0]["summary"] = "tampered".into();
        assert!(parse_and_verify(&forged.to_string(), SIGNER, now)
            .unwrap_err()
            .contains("signature"));
    }

    #[test]
    fn verifies_the_js_vector() {
        let (issued, incidents) = sample();
        let body = serde_json::json!({
            "version": 1, "issued": issued, "incidents": incidents,
            "signer": SIGNER, "signature": SIGNATURE,
        });
        let feed = parse_and_verify(
            &body.to_string(),
            &format!("deadbeef;{SIGNER}"),
            issued + 10,
        )
        .unwrap();
        assert_eq!(feed.signer, SIGNER);
        assert_eq!(feed.incidents, incidents);
        assert_eq!(feed.active(issued + 10).len(), 1);
    }

    #[test]
    fn active_filters_on_until() {
        let feed = IncidentFeed {
            issued: 100,
            signer: SIGNER.into(),
            incidents: vec![
                Incident {
                    id: "a".into(),
                    component: "node".into(),
                    instance: "n".into(),
                    severity: "warning".into(),
                    summary: "s".into(),
                    since: 1,
                    until: Some(50),
                },
                Incident {
                    id: "b".into(),
                    component: "node".into(),
                    instance: "n".into(),
                    severity: "warning".into(),
                    summary: "s".into(),
                    since: 1,
                    until: None,
                },
            ],
        };
        let active: Vec<_> = feed.active(60).iter().map(|i| i.id.clone()).collect();
        assert_eq!(active, vec!["b"]);
    }
}
