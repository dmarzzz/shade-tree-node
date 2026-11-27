//! Wire-format helpers shared with the reference implementation (docs/WIRE-SPEC.md):
//! the request signal, artifact ids, and the canonical bytes a node signs when it announces.

use sha2::Sha256;
use sha3::{Digest, Keccak256};

use num_bigint::BigUint;

pub const PROTO_MIN: u64 = 4;
pub const PROTO_MAX: u64 = 4;
/// Combined payload bytes one proof slot may carry (40 MiB).
pub const DEFAULT_PAYLOAD_BYTES_PER_SLOT: u64 = 41_943_040;
/// What an envelope with no `artifact` field means to the reference node: the retired
/// pre-ceremony key.
pub const LEGACY_ARTIFACT_ID: &str = "rln-0b25f824a04da3a8";
pub const CAPS_DOMAIN: &str = "Shade Tree gateway capabilities v1\n";

/// The signal a v4 tunnel proof commits to.
pub fn request_signal(target: &str, nonce: &str) -> String {
    format!("shade-tree:v4\n{target}\n{nonce}")
}

/// The circuit's public `x` for a signal: `keccak256(utf8(message)) >> 8`, in decimal.
pub fn calculate_signal_hash(message: &str) -> String {
    let digest = Keccak256::digest(message.as_bytes());
    (BigUint::from_bytes_be(&digest) >> 8u32).to_str_radix(10)
}

/// A signal field must be non-empty, bounded, and free of the delimiter.
pub fn signal_field_safe(s: &str, max_len: usize) -> bool {
    !s.is_empty() && s.chars().count() <= max_len && !s.contains(['\n', '\r'])
}

/// `<circuit>-<first 16 hex of sha256(verification_key.json)>`.
pub fn artifact_id_of(circuit: &str, vkey_bytes: &[u8]) -> String {
    let digest = Sha256::digest(vkey_bytes);
    let mut id = String::with_capacity(circuit.len() + 17);
    id.push_str(circuit);
    id.push('-');
    for b in &digest[..8] {
        id.push_str(&format!("{b:02x}"));
    }
    id
}

/// `^[a-z0-9][a-z0-9._-]{0,63}$`
pub fn is_artifact_id(s: &str) -> bool {
    let bytes = s.as_bytes();
    let head = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    !bytes.is_empty()
        && bytes.len() <= 64
        && head(bytes[0])
        && bytes[1..]
            .iter()
            .all(|&b| head(b) || matches!(b, b'.' | b'_' | b'-'))
}

/// JSON string literal for `s` (the escaping `JSON.stringify` applies).
pub fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The rate policy a node advertises; clients on the public network only pick nodes whose
/// policy equals the deployment record's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RatePolicy {
    pub epoch_seconds: u64,
    pub root_freshness_seconds: u64,
    pub payload_bytes_per_slot: u64,
}

/// A node's signed capabilities, restricted to the fields this node can truthfully claim.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Caps {
    pub ports: Vec<u16>,
    pub region: Option<String>,
    pub artifacts: Vec<String>,
    /// Subset of `invited`, `staked`, `paid`.
    pub admits: Vec<String>,
    pub rate: Option<RatePolicy>,
    /// Session-ticket classes served (`research-v1`, `research-v2`); empty when none.
    pub session: Vec<String>,
    pub draining: bool,
    /// Lowercase `0x` contract addresses of the on-chain sets this node reads.
    pub sets: Vec<String>,
    /// Leave out the `proto` range. A node always advertises it; the flag exists so the
    /// canonical form of caps that came without one can be reproduced.
    pub omit_proto: bool,
}

impl Caps {
    /// Canonical JSON: fixed key order `ports, region, proto, artifacts, admits, pay, rate,
    /// session, draining, sets`, each present only when set; `proto` whenever anything is
    /// (unless `omit_proto`).
    pub fn canonical_json(&self) -> Option<String> {
        let mut parts: Vec<String> = Vec::new();
        let mut ports = self.ports.clone();
        ports.sort_unstable();
        ports.dedup();
        ports.retain(|p| *p != 0);
        if !ports.is_empty() {
            let list: Vec<String> = ports.iter().map(u16::to_string).collect();
            parts.push(format!("\"ports\":[{}]", list.join(",")));
        }
        if let Some(region) = &self.region {
            if matches!(
                region.as_str(),
                "na" | "sa" | "eu" | "af" | "as" | "oc" | "aq" | "unknown"
            ) {
                parts.push(format!("\"region\":{}", json_string(region)));
            }
        }
        let mut tail: Vec<String> = Vec::new();
        let mut artifacts: Vec<&String> = self
            .artifacts
            .iter()
            .filter(|a| is_artifact_id(a))
            .collect();
        artifacts.sort();
        artifacts.dedup();
        artifacts.truncate(8);
        if !artifacts.is_empty() {
            let list: Vec<String> = artifacts.iter().map(|a| json_string(a)).collect();
            tail.push(format!("\"artifacts\":[{}]", list.join(",")));
        }
        let admits: Vec<String> = ["invited", "staked", "paid"]
            .iter()
            .filter(|path| self.admits.iter().any(|a| a.eq_ignore_ascii_case(path)))
            .map(|path| json_string(path))
            .collect();
        if !admits.is_empty() {
            tail.push(format!("\"admits\":[{}]", admits.join(",")));
        }
        if let Some(rate) = &self.rate {
            tail.push(format!(
                "\"rate\":{{\"scope\":\"grove-v4\",\"window\":\"fixed\",\"epochSeconds\":{},\"previousEpochsAccepted\":1,\"rootFreshnessSeconds\":{},\"payloadBytesPerSlot\":{}}}",
                rate.epoch_seconds, rate.root_freshness_seconds, rate.payload_bytes_per_slot
            ));
        }
        if !self.session.is_empty() {
            let classes: Vec<String> = self.session.iter().map(|c| json_string(c)).collect();
            tail.push(format!(
                "\"session\":{{\"version\":1,\"classes\":[{}]}}",
                classes.join(",")
            ));
        }
        if self.draining {
            tail.push("\"draining\":true".to_string());
        }
        let mut sets: Vec<String> = self
            .sets
            .iter()
            .map(|s| s.to_ascii_lowercase())
            .filter(|s| {
                s.len() == 42
                    && s.starts_with("0x")
                    && s[2..].bytes().all(|b| b.is_ascii_hexdigit())
            })
            .collect();
        sets.sort();
        sets.dedup();
        sets.truncate(8);
        if !sets.is_empty() {
            let list: Vec<String> = sets.iter().map(|s| json_string(s)).collect();
            tail.push(format!("\"sets\":[{}]", list.join(",")));
        }
        if parts.is_empty() && tail.is_empty() {
            return None;
        }
        if !self.omit_proto {
            parts.push(format!(
                "\"proto\":{{\"min\":{PROTO_MIN},\"max\":{PROTO_MAX}}}"
            ));
        }
        parts.extend(tail);
        Some(format!("{{{}}}", parts.join(",")))
    }
}

/// The bytes `capsSig` covers.
pub fn canonical_caps_bytes(onion: &str, caps_json: &str) -> Vec<u8> {
    format!(
        "{CAPS_DOMAIN}{{\"onion\":{},\"caps\":{caps_json}}}",
        json_string(onion)
    )
    .into_bytes()
}

/// The bytes `onionSig` covers: `{v, onion, weight, ts, nonce[, caps]}` in that order.
pub fn canonical_announce_bytes(
    onion: &str,
    weight: u64,
    ts: u64,
    nonce: &str,
    caps_json: Option<&str>,
) -> Vec<u8> {
    let mut out = format!(
        "{{\"v\":1,\"onion\":{},\"weight\":{weight},\"ts\":{ts},\"nonce\":{}",
        json_string(onion),
        json_string(nonce)
    );
    if let Some(caps) = caps_json {
        out.push_str(",\"caps\":");
        out.push_str(caps);
    }
    out.push('}');
    out.into_bytes()
}

fn hex(bytes: &[u8]) -> String {
    microtor::util::hex_encode(bytes)
}

/// The bytes a liveness receipt's signature covers. A receipt names only the node and a
/// coarse epoch: no target, no nullifier, no fine timestamp.
pub fn canonical_receipt_bytes(onion: &str, epoch: u64) -> Vec<u8> {
    format!(
        "Shade Tree egress success receipt v1\n{{\"v\":1,\"onion\":{},\"epoch\":\"{epoch}\",\"ok\":true}}",
        json_string(onion)
    )
    .into_bytes()
}

/// The `receipt` object attached to a tunnel acknowledgement.
pub fn build_receipt(identity: &microtor::crypto::EdExpanded, onion: &str, epoch: u64) -> String {
    let sig = identity.sign(&canonical_receipt_bytes(onion, epoch));
    format!(
        "{{\"v\":1,\"onion\":{},\"epoch\":\"{epoch}\",\"ok\":true,\"sig\":\"{}\"}}",
        json_string(onion),
        hex(&sig)
    )
}

/// A complete announce record, signed with the node's onion identity.
pub fn build_announce(
    identity: &microtor::crypto::EdExpanded,
    onion: &str,
    weight: u64,
    ts: u64,
    nonce: &str,
    caps: &Caps,
    operator: Option<(&str, &str)>,
) -> String {
    let caps_json = caps.canonical_json();
    let onion_sig = identity.sign(&canonical_announce_bytes(
        onion,
        weight,
        ts,
        nonce,
        caps_json.as_deref(),
    ));
    let mut out = format!(
        "{{\"v\":1,\"onion\":{},\"weight\":{weight},\"ts\":{ts},\"nonce\":{}",
        json_string(onion),
        json_string(nonce)
    );
    if let Some(caps_json) = &caps_json {
        let caps_sig = identity.sign(&canonical_caps_bytes(onion, caps_json));
        out.push_str(&format!(
            ",\"caps\":{caps_json},\"capsSig\":\"{}\"",
            hex(&caps_sig)
        ));
    }
    out.push_str(&format!(",\"onionSig\":\"{}\"", hex(&onion_sig)));
    if let Some((address, signature)) = operator {
        out.push_str(&format!(
            ",\"operator\":{},\"operatorSig\":{}",
            json_string(&address.to_ascii_lowercase()),
            json_string(signature)
        ));
    }
    out.push('}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use microtor::crypto::{ed_verify, EdExpanded};
    use microtor::util::hex_decode;

    /// The onion seed used throughout testdata/vectors.json.
    const ONION_SEED: &str = "0202020202020202020202020202020202020202020202020202020202020202";

    #[test]
    fn artifact_ids_match_the_pinned_vector() {
        assert_eq!(artifact_id_of("rln", b"hello"), "rln-2cf24dba5fb0a30e");
        assert_eq!(
            artifact_id_of("rln", crate::rln::BUILTIN_VKEY),
            "rln-ae43614cd02ebe95"
        );
        assert!(is_artifact_id("rln-ae43614cd02ebe95"));
        assert!(!is_artifact_id("-rln"));
        assert!(!is_artifact_id("RLN"));
        assert!(!is_artifact_id(""));
    }

    #[test]
    fn signal_fields() {
        assert_eq!(
            request_signal("example.com:443", "aa"),
            "shade-tree:v4\nexample.com:443\naa"
        );
        assert!(signal_field_safe("example.com:443", 256));
        assert!(!signal_field_safe("a\nb", 256));
        assert!(!signal_field_safe("", 256));
        assert!(!signal_field_safe(&"x".repeat(257), 256));
        // keccak256("") >> 8
        assert_eq!(
            calculate_signal_hash(""),
            (BigUint::parse_bytes(
                b"c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                16
            )
            .unwrap()
                >> 8u32)
                .to_str_radix(10)
        );
    }

    #[test]
    fn announce_bytes_and_signatures() {
        let seed: [u8; 32] = hex_decode(ONION_SEED).unwrap().try_into().unwrap();
        let identity = EdExpanded::from_seed(&seed);
        let onion = microtor::hsdesc::onion_address(&identity.public);
        let bytes = canonical_announce_bytes(
            &onion,
            100,
            1_000_000,
            "abcdef0123456789abcdef0123456789",
            None,
        );
        assert_eq!(
            String::from_utf8(bytes.clone()).unwrap(),
            format!("{{\"v\":1,\"onion\":\"{onion}\",\"weight\":100,\"ts\":1000000,\"nonce\":\"abcdef0123456789abcdef0123456789\"}}")
        );
        let caps = Caps {
            ports: vec![443, 443],
            artifacts: vec!["rln-ae43614cd02ebe95".into()],
            admits: vec!["staked".into(), "invited".into()],
            rate: Some(RatePolicy {
                epoch_seconds: 60,
                root_freshness_seconds: 60,
                payload_bytes_per_slot: 41_943_040,
            }),
            sets: vec!["0x789967F0bDD7f3a96fb60F6D315e93F103b5680b".into()],
            ..Default::default()
        };
        let caps_json = caps.canonical_json().unwrap();
        assert_eq!(
            caps_json,
            "{\"ports\":[443],\"proto\":{\"min\":4,\"max\":4},\"artifacts\":[\"rln-ae43614cd02ebe95\"],\"admits\":[\"invited\",\"staked\"],\"rate\":{\"scope\":\"grove-v4\",\"window\":\"fixed\",\"epochSeconds\":60,\"previousEpochsAccepted\":1,\"rootFreshnessSeconds\":60,\"payloadBytesPerSlot\":41943040},\"sets\":[\"0x789967f0bdd7f3a96fb60f6d315e93f103b5680b\"]}"
        );
        let record = build_announce(
            &identity,
            &onion,
            100,
            1_000_000,
            "abcdef0123456789abcdef0123456789",
            &caps,
            None,
        );
        let parsed: serde_json::Value = serde_json::from_str(&record).unwrap();
        let sig = hex_decode(parsed["onionSig"].as_str().unwrap()).unwrap();
        let signed = canonical_announce_bytes(
            &onion,
            100,
            1_000_000,
            "abcdef0123456789abcdef0123456789",
            Some(&caps_json),
        );
        assert!(ed_verify(&identity.public, &signed, &sig));
        let caps_sig = hex_decode(parsed["capsSig"].as_str().unwrap()).unwrap();
        assert!(ed_verify(
            &identity.public,
            &canonical_caps_bytes(&onion, &caps_json),
            &caps_sig
        ));
        assert_eq!(Caps::default().canonical_json(), None);
    }
}
