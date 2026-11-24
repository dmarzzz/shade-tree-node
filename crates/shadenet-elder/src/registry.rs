//! The live set (`makeRegistry`): every onion that proved control of itself recently, with
//! its weight, operator and signed capabilities, aged out by a TTL. Admission runs the real
//! announce verification whether the record arrived over HTTP, from a federation peer or
//! from the Elder's own store on restart; nothing on disk or from a peer grants trust the
//! signature and stake checks would not.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use serde_json::Value;
use shadenet::dircache::CapsDto;
use shadenet_proto::{
    has_caps, onion_to_pubkey, verify_announce, Announce, Caps, ANNOUNCE_VERSION,
};
use shadenet_service::files::atomic_write;

use crate::bucket::Bucket;
use crate::stake::Verifier;

/// The self-attested selection weight is clamped so one node cannot capture every client.
pub(crate) const MAX_WEIGHT: u64 = 1000;
/// An announce larger than this is listed without its copy (WIRE-SPEC 4.5), so a few padded
/// announces cannot push `/directory` past every client's response cap.
const MAX_LISTED_ANNOUNCE_BYTES: usize = 4096;
/// Seconds a live announce's `ts` may lead or lag the Elder's clock.
const LIVE_SKEW: u64 = 120;
const STORE_VERSION: u64 = 1;

/// One live node.
pub(crate) struct Entry {
    pub(crate) pubkey: String,
    pub(crate) weight: u64,
    pub(crate) operator: Option<String>,
    pub(crate) staked: bool,
    /// The signed capabilities and their durable onion signature, both or neither.
    pub(crate) caps: Option<(Caps, String)>,
    /// The announce exactly as received.
    pub(crate) announce: Box<RawValue>,
    pub(crate) expires_at: u64,
    last_at: u64,
}

impl Entry {
    /// The announce a directory entry carries, when it is small enough to list.
    pub(crate) fn listed(&self) -> Option<&RawValue> {
        (self.announce.get().len() <= MAX_LISTED_ANNOUNCE_BYTES).then_some(&*self.announce)
    }
}

/// What `/announce` answers.
pub(crate) enum Outcome {
    Accepted {
        onion: String,
        staked: bool,
    },
    Rejected {
        reason: String,
        retry_after_secs: Option<u64>,
    },
}

/// What a gossiped announce came to.
pub(crate) enum Gossip {
    Merged,
    /// Already held at least this fresh; nothing to do.
    FreshExisting,
    Rejected(String),
}

/// How a record reached the registry, which decides its freshness rule and its expiry.
#[derive(Clone, Copy)]
enum Source {
    /// A live announce: `ts` within the skew, expiry `now + ttl`.
    Live,
    /// The Elder's own store on restart: expiry as stored; exempt from the bucket.
    Store { expires_at: u64 },
    /// A peer's copy: expiry `ts + ttl` of the origin announce, never refreshed by gossip.
    Gossip { expires_at: u64 },
}

/// The DoS controls and the store, as configured.
pub(crate) struct Settings {
    pub(crate) require_stake: bool,
    pub(crate) ttl_secs: u64,
    pub(crate) max_entries: usize,
    pub(crate) min_reannounce_secs: u64,
    pub(crate) announce_rate: f64,
    pub(crate) announce_burst: f64,
    pub(crate) store: Option<PathBuf>,
}

struct Inner {
    live: BTreeMap<String, Entry>,
    nonces: HashMap<String, u64>,
    bucket: Bucket,
    reloading: bool,
}

pub(crate) struct Registry {
    inner: Mutex<Inner>,
    stake: Arc<Verifier>,
    require_stake: bool,
    ttl_secs: u64,
    max_entries: usize,
    min_reannounce_secs: u64,
    store: Option<PathBuf>,
}

/// An announce parsed leniently, with the reason the JavaScript verifier would give for a
/// missing or mistyped field.
struct Parsed {
    announce: Announce,
    raw: Box<RawValue>,
}

#[derive(Serialize)]
struct StoreEntry<'a> {
    rec: &'a RawValue,
    #[serde(rename = "expiresAt")]
    expires_at: u64,
}

#[derive(Serialize)]
struct StoreFile<'a> {
    version: u64,
    entries: Vec<StoreEntry<'a>>,
}

#[derive(Deserialize)]
struct StoredEntry {
    rec: Box<RawValue>,
    #[serde(rename = "expiresAt", default)]
    expires_at: Value,
}

#[derive(Deserialize)]
struct StoredFile {
    #[serde(default)]
    entries: Vec<StoredEntry>,
}

/// `verifyAnnounce`'s field checks, in its order: version, onion, timestamp.
fn parse(raw: &RawValue) -> Result<Parsed, String> {
    let value: Value = serde_json::from_str(raw.get()).map_err(|e| format!("bad-json:{e}"))?;
    let Some(object) = value.as_object() else {
        return Err("no-announce".into());
    };
    let v = object.get("v").cloned().unwrap_or(Value::Null);
    if v.as_u64() != Some(ANNOUNCE_VERSION) {
        return Err(format!("bad-version:{}", display(&v)));
    }
    let Some(onion) = object.get("onion").and_then(Value::as_str) else {
        return Err("no-onion".into());
    };
    onion_to_pubkey(onion).map_err(|e| format!("bad-onion:{e}"))?;
    let ts_value = object.get("ts").cloned().unwrap_or(Value::Null);
    let Some(ts) = ts_value.as_u64() else {
        return Err(format!("stale-ts:{}", display(&ts_value)));
    };
    // a weight or nonce the canonical bytes cannot carry leaves the signature unverifiable
    let weight = object
        .get("weight")
        .and_then(Value::as_u64)
        .ok_or("bad-onion-sig")?;
    let nonce = object
        .get("nonce")
        .and_then(Value::as_str)
        .ok_or("bad-onion-sig")?;
    let text = |key: &str| object.get(key).and_then(Value::as_str).map(str::to_string);
    let caps = match object.get("caps") {
        Some(Value::Object(_)) => serde_json::from_value::<CapsDto>(object["caps"].clone())
            .ok()
            .map(CapsDto::into_proto),
        _ => None,
    };
    // a caps signature that is present but not a string fails exactly like a wrong one
    let caps_sig = object
        .get("capsSig")
        .map(|v| v.as_str().unwrap_or("").to_string());
    let (operator, operator_sig) = match (object.get("operator"), object.get("operatorSig")) {
        (Some(op), Some(sig)) if truthy(op) && truthy(sig) => (
            Some(op.as_str().unwrap_or("").to_string()),
            Some(sig.as_str().unwrap_or("").to_string()),
        ),
        _ => (None, None),
    };
    Ok(Parsed {
        announce: Announce {
            v: ANNOUNCE_VERSION,
            onion: onion.to_string(),
            weight,
            ts,
            nonce: nonce.to_string(),
            onion_sig: text("onionSig"),
            operator,
            operator_sig,
            caps,
            caps_sig,
        },
        raw: raw.to_owned(),
    })
}

/// JavaScript truthiness for the optional operator pair.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// How JavaScript prints the field in a reason code.
fn display(value: &Value) -> String {
    match value {
        Value::Null => "undefined".into(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

impl Registry {
    pub(crate) fn new(stake: Arc<Verifier>, settings: Settings, now: u64) -> Self {
        Self {
            inner: Mutex::new(Inner {
                live: BTreeMap::new(),
                nonces: HashMap::new(),
                bucket: Bucket::new(settings.announce_rate, settings.announce_burst, now),
                reloading: false,
            }),
            stake,
            require_stake: settings.require_stake,
            ttl_secs: settings.ttl_secs,
            max_entries: settings.max_entries,
            min_reannounce_secs: settings.min_reannounce_secs,
            store: settings.store,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn ttl_secs(&self) -> u64 {
        self.ttl_secs
    }

    pub(crate) fn size(&self) -> usize {
        self.lock().live.len()
    }

    pub(crate) fn has(&self, onion: &str) -> bool {
        self.lock().live.contains_key(&with_suffix(onion))
    }

    /// The bucket's sizing, for the startup log.
    pub(crate) fn bucket(&self) -> (f64, f64) {
        let inner = self.lock();
        (inner.bucket.rate(), inner.bucket.burst())
    }

    /// Spend one token of the shared peer-write bucket, for routes that share it with
    /// `/announce`; the retry hint when there is none.
    pub(crate) fn take_token(&self, now: u64) -> Result<(), u64> {
        let mut inner = self.lock();
        if inner.bucket.take(now) {
            Ok(())
        } else {
            Err(inner.bucket.retry_after_secs())
        }
    }

    /// A live announce over HTTP.
    pub(crate) async fn announce(&self, raw: &RawValue, now: u64) -> Outcome {
        self.admit(raw, now, Source::Live).await
    }

    async fn admit(&self, raw: &RawValue, now: u64, source: Source) -> Outcome {
        let reject = |reason: String| Outcome::Rejected {
            reason,
            retry_after_secs: None,
        };
        // cheap checks before the signature, so a flood is refused early
        let onion_key = serde_json::from_str::<Value>(raw.get())
            .ok()
            .and_then(|v| v.get("onion").and_then(Value::as_str).map(str::to_string));
        {
            let mut inner = self.lock();
            let existing = onion_key.as_ref().and_then(|k| inner.live.get(k));
            if existing.is_some_and(|e| now.saturating_sub(e.last_at) < self.min_reannounce_secs) {
                return reject("rate-limited".into());
            }
            if existing.is_none() && inner.live.len() >= self.max_entries {
                self.sweep_inner(&mut inner, now);
                if inner.live.len() >= self.max_entries {
                    return reject("registry-full".into());
                }
            }
            // the global cap is the last gate before verification; replaying the Elder's own
            // store is local work and exempt
            if !matches!(source, Source::Store { .. }) && !inner.bucket.take(now) {
                return Outcome::Rejected {
                    reason: "global-rate-limited".into(),
                    retry_after_secs: Some(inner.bucket.retry_after_secs()),
                };
            }
        }
        let parsed = match parse(raw) {
            Ok(parsed) => parsed,
            Err(reason) => return reject(reason),
        };
        let announce = parsed.announce;
        if matches!(source, Source::Live) && now.abs_diff(announce.ts) > LIVE_SKEW {
            return reject(format!("stale-ts:{}", announce.ts));
        }
        let replay_key = format!("{}:{}", announce.onion, announce.nonce);
        if self.lock().nonces.contains_key(&replay_key) {
            return reject("replayed-nonce".into());
        }
        // freshness was decided above by the source's own rule
        if let Err(e) = verify_announce(&announce, announce.ts, u64::MAX, None) {
            return reject(e.to_string());
        }
        let pubkey = match onion_to_pubkey(&announce.onion) {
            Ok(key) => hex::encode(key),
            Err(e) => return reject(format!("bad-onion:{e}")),
        };
        let operator = announce
            .operator
            .as_ref()
            .filter(|_| announce.operator_sig.is_some())
            .map(|op| op.to_ascii_lowercase());
        let mut staked = false;
        if let Some(operator) = &operator {
            match self.stake.is_staked(operator).await {
                Ok(value) => staked = value,
                Err(e) if self.require_stake => {
                    return reject(format!("stake-check-failed:{e}"));
                }
                Err(_) => {}
            }
        }
        if self.require_stake && !staked {
            return reject("not-staked".into());
        }
        let caps = announce
            .caps
            .clone()
            .filter(has_caps)
            .zip(announce.caps_sig.clone());
        let entry = Entry {
            pubkey,
            weight: announce.weight.min(MAX_WEIGHT),
            operator,
            staked,
            caps,
            announce: parsed.raw,
            expires_at: match source {
                Source::Live => now + self.ttl_secs,
                Source::Store { expires_at } | Source::Gossip { expires_at } => expires_at,
            },
            last_at: now,
        };
        let onion = announce.onion.clone();
        {
            let mut inner = self.lock();
            if !matches!(source, Source::Gossip { .. }) {
                inner.nonces.insert(replay_key, now);
            }
            inner.live.insert(onion.clone(), entry);
            if !inner.reloading {
                self.persist(&inner);
            }
        }
        Outcome::Accepted { onion, staked }
    }

    /// A record pulled from a peer Elder (`admitGossip`): the peer's own signature carries no
    /// authority; the announce is re-verified as if the node had sent it here. It lives no
    /// longer than `ts + ttl` of the announce the origin signed, and never shortens or churns a
    /// fresher entry already held.
    pub(crate) async fn admit_gossip(&self, raw: &RawValue, now: u64) -> Gossip {
        let value: Value = serde_json::from_str(raw.get()).unwrap_or(Value::Null);
        let Some(onion) = value.get("onion").and_then(Value::as_str) else {
            return Gossip::Rejected("no-onion".into());
        };
        let Some(ts) = value.get("ts").and_then(Value::as_u64) else {
            return Gossip::Rejected("stale-ts".into());
        };
        let expires_at = ts + self.ttl_secs;
        if expires_at <= now {
            return Gossip::Rejected("stale-gossip".into());
        }
        {
            let inner = self.lock();
            if inner
                .live
                .get(onion)
                .is_some_and(|e| e.expires_at >= expires_at)
            {
                return Gossip::FreshExisting;
            }
        }
        match self.admit(raw, now, Source::Gossip { expires_at }).await {
            Outcome::Accepted { .. } => Gossip::Merged,
            Outcome::Rejected { reason, .. } => Gossip::Rejected(reason),
        }
    }

    /// Drop every entry past its expiry and every nonce older than the TTL.
    pub(crate) fn sweep(&self, now: u64) {
        let mut inner = self.lock();
        self.sweep_inner(&mut inner, now);
    }

    fn sweep_inner(&self, inner: &mut Inner, now: u64) {
        let before = inner.live.len();
        inner.live.retain(|_, e| e.expires_at > now);
        let cut = now.saturating_sub(self.ttl_secs);
        inner.nonces.retain(|_, at| *at >= cut);
        if inner.live.len() != before && !inner.reloading {
            self.persist(inner);
        }
    }

    /// Every live entry after a sweep, in onion order.
    pub(crate) fn with_live<T>(
        &self,
        now: u64,
        f: impl FnOnce(&BTreeMap<String, Entry>) -> T,
    ) -> T {
        let mut inner = self.lock();
        self.sweep_inner(&mut inner, now);
        f(&inner.live)
    }

    pub(crate) fn live_onions(&self) -> Vec<String> {
        self.lock().live.keys().cloned().collect()
    }

    /// The stored announce of one onion, for zero-trust re-verification.
    pub(crate) fn record(&self, onion: &str) -> Option<Box<RawValue>> {
        self.lock()
            .live
            .get(&with_suffix(onion))
            .map(|e| e.announce.clone())
    }

    /// Mirror the live set to the store: the raw signed records and their expiry, never a
    /// derived verdict. A write failure is logged, never fatal to an accepted announce.
    fn persist(&self, inner: &Inner) {
        let Some(path) = &self.store else {
            return;
        };
        let file = StoreFile {
            version: STORE_VERSION,
            entries: inner
                .live
                .values()
                .map(|e| StoreEntry {
                    rec: &e.announce,
                    expires_at: e.expires_at,
                })
                .collect(),
        };
        let result = serde_json::to_vec(&file)
            .map_err(|e| e.to_string())
            .and_then(|bytes| atomic_write(path, &bytes).map_err(|e| e.to_string()));
        if let Err(e) = result {
            tracing::error!("persist write failed (continuing): {e}");
        }
    }

    /// Re-admit the store on boot through the real announce path; an entry past its stored
    /// expiry, or one whose signature or stake no longer verifies, is dropped. Returns
    /// `(loaded, dropped)`.
    pub(crate) async fn load_persisted(&self, now: u64) -> (usize, usize) {
        let Some(path) = &self.store else {
            return (0, 0);
        };
        if !path.exists() {
            return (0, 0);
        }
        let stored = match std::fs::read(path)
            .map_err(|e| e.to_string())
            .and_then(|bytes| {
                serde_json::from_slice::<StoredFile>(&bytes).map_err(|e| e.to_string())
            }) {
            Ok(stored) => stored,
            Err(e) => {
                tracing::error!("persist read failed, ignoring store: {e}");
                return (0, 0);
            }
        };
        self.lock().reloading = true;
        let (mut loaded, mut dropped) = (0, 0);
        for entry in stored.entries {
            let Some(expires_at) = entry.expires_at.as_u64().filter(|at| *at > now) else {
                dropped += 1;
                continue;
            };
            match self
                .admit(&entry.rec, now, Source::Store { expires_at })
                .await
            {
                Outcome::Accepted { .. } => loaded += 1,
                Outcome::Rejected { .. } => dropped += 1,
            }
        }
        let mut inner = self.lock();
        inner.reloading = false;
        self.persist(&inner);
        (loaded, dropped)
    }
}

fn with_suffix(onion: &str) -> String {
    if onion.ends_with(".onion") {
        onion.to_string()
    } else {
        format!("{onion}.onion")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::config::StakeSource;
    use crate::stake::Verifier;
    use shadenet_proto::{
        canonical_announce_bytes, canonical_caps_bytes, canonical_caps_json_text,
        ed25519_public_key, ed25519_sign, operator_auth_message, pubkey_to_onion, ProtoCaps,
    };
    use shadenet_service::metrics::Registry as Metrics;

    /// A node with its onion seed, able to sign announces the way the Rust node does.
    pub(crate) struct Node {
        pub(crate) seed: [u8; 32],
        pub(crate) onion: String,
    }

    impl Node {
        pub(crate) fn new(tag: u8) -> Self {
            let seed = [tag; 32];
            Self {
                onion: pubkey_to_onion(&ed25519_public_key(&seed)),
                seed,
            }
        }

        /// `buildAnnounce`: the caps and their durable signature ride before the onion
        /// signature that covers them; the operator pair comes last.
        pub(crate) fn announce(
            &self,
            weight: u64,
            ts: u64,
            nonce: &str,
            caps: Option<&Caps>,
            operator: Option<(&str, &str)>,
        ) -> String {
            let caps = caps.filter(|c| has_caps(c));
            let announce = Announce {
                v: ANNOUNCE_VERSION,
                onion: self.onion.clone(),
                weight,
                ts,
                nonce: nonce.to_string(),
                onion_sig: None,
                operator: None,
                operator_sig: None,
                caps: caps.cloned(),
                caps_sig: None,
            };
            let onion_sig = hex::encode(ed25519_sign(
                &canonical_announce_bytes(&announce),
                &self.seed,
            ));
            let mut body = format!(
                "{{\"v\":1,\"onion\":\"{}\",\"weight\":{weight},\"ts\":{ts},\"nonce\":\"{nonce}\"",
                self.onion
            );
            if let Some(caps) = caps {
                let caps_sig = hex::encode(ed25519_sign(
                    &canonical_caps_bytes(&self.onion, caps),
                    &self.seed,
                ));
                body.push_str(&format!(
                    ",\"caps\":{},\"capsSig\":\"{caps_sig}\"",
                    canonical_caps_json_text(caps)
                ));
            }
            body.push_str(&format!(",\"onionSig\":\"{onion_sig}\""));
            if let Some((operator, sig)) = operator {
                body.push_str(&format!(
                    ",\"operator\":\"{}\",\"operatorSig\":\"{sig}\"",
                    operator.to_ascii_lowercase()
                ));
            }
            body.push('}');
            body
        }
    }

    /// The announce with the last character of its onion signature flipped.
    pub(crate) fn flip_last_sig_char(body: &str) -> String {
        let at = body.rfind("\"}").expect("the body ends with the signature");
        let flipped = if body.as_bytes()[at - 1] == b'0' {
            "1"
        } else {
            "0"
        };
        format!("{}{flipped}{}", &body[..at - 1], &body[at..])
    }

    pub(crate) fn raw(text: &str) -> Box<RawValue> {
        RawValue::from_string(text.to_string()).unwrap()
    }

    pub(crate) fn mock(allowlist: Option<Vec<String>>) -> Arc<Verifier> {
        let metrics = Arc::new(Metrics::new("elder", "0", "0", crate::metrics::DEFINITIONS));
        Arc::new(Verifier::new(&StakeSource::Mock { allowlist }, metrics).unwrap())
    }

    pub(crate) fn make(
        stake: Arc<Verifier>,
        require_stake: bool,
        ttl: u64,
        max_entries: usize,
        min_reannounce: u64,
        now: u64,
    ) -> Registry {
        Registry::new(
            stake,
            Settings {
                require_stake,
                ttl_secs: ttl,
                max_entries,
                min_reannounce_secs: min_reannounce,
                announce_rate: 1000.0,
                announce_burst: 1000.0,
                store: None,
            },
            now,
        )
    }

    fn bucket_settings(max_entries: usize, min_reannounce: u64, rate: f64, burst: f64) -> Settings {
        Settings {
            require_stake: false,
            ttl_secs: 900,
            max_entries,
            min_reannounce_secs: min_reannounce,
            announce_rate: rate,
            announce_burst: burst,
            store: None,
        }
    }

    fn reason(outcome: Outcome) -> String {
        match outcome {
            Outcome::Accepted { .. } => "accepted".into(),
            Outcome::Rejected { reason, .. } => reason,
        }
    }

    /// The operator vector: a fixed key whose personal_sign over the auth message is pinned.
    pub(crate) fn operator_vector() -> (String, String, Node) {
        let vectors: Value =
            serde_json::from_str(include_str!("../../../testdata/vectors.json")).unwrap();
        let op = &vectors["operatorAnnounce"];
        let seed: [u8; 32] = hex::decode(vectors["onionSeed"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let node = Node {
            onion: vectors["onion"].as_str().unwrap().to_string(),
            seed,
        };
        assert_eq!(node.onion, pubkey_to_onion(&ed25519_public_key(&seed)));
        assert_eq!(
            op["operatorAuthMessage"].as_str().unwrap(),
            operator_auth_message(&node.onion, op["operator"].as_str().unwrap())
        );
        (
            op["operator"].as_str().unwrap().to_string(),
            op["operatorSig"].as_str().unwrap().to_string(),
            node,
        )
    }

    #[tokio::test]
    async fn announces_are_verified_the_way_the_javascript_elder_verifies_them() {
        let now = 1_000_000;
        let registry = make(mock(None), false, 900, 10_000, 0, now);
        let (g1, g2, g3) = (Node::new(1), Node::new(2), Node::new(3));
        assert_eq!(
            reason(
                registry
                    .announce(&raw(&g1.announce(100, now, "aa", None, None)), now)
                    .await
            ),
            "accepted"
        );
        assert_eq!(
            reason(
                registry
                    .announce(
                        &raw(&flip_last_sig_char(
                            &g2.announce(100, now, "ab", None, None)
                        )),
                        now
                    )
                    .await
            ),
            "bad-onion-sig"
        );
        let wrong_key = Node {
            seed: g3.seed,
            onion: g2.onion.clone(),
        }
        .announce(100, now, "ac", None, None);
        assert_eq!(
            reason(registry.announce(&raw(&wrong_key), now).await),
            "bad-onion-sig"
        );
        assert_eq!(
            reason(
                registry
                    .announce(&raw(&g3.announce(100, now - 9999, "ad", None, None)), now)
                    .await
            ),
            "stale-ts:990001"
        );
        let replayed = g3.announce(100, now, "ae", None, None);
        assert_eq!(
            reason(registry.announce(&raw(&replayed), now).await),
            "accepted"
        );
        assert_eq!(
            reason(registry.announce(&raw(&replayed), now).await),
            "replayed-nonce"
        );
        assert_eq!(
            reason(registry.announce(&raw("[1,2]"), now).await),
            "no-announce"
        );
        assert_eq!(
            reason(registry.announce(&raw("{\"v\":2}"), now).await),
            "bad-version:2"
        );
        assert_eq!(
            reason(registry.announce(&raw("{\"v\":1}"), now).await),
            "no-onion"
        );
        assert_eq!(
            reason(
                registry
                    .announce(&raw("{\"v\":1,\"onion\":\"nope.onion\"}"), now)
                    .await
            ),
            "bad-onion:not a v3 onion (expected 56 chars)"
        );
        assert_eq!(
            reason(
                registry
                    .announce(
                        &raw(&format!(
                            "{{\"v\":1,\"onion\":\"{}\",\"ts\":\"x\"}}",
                            g1.onion
                        )),
                        now
                    )
                    .await
            ),
            "stale-ts:x"
        );
        let onions = registry.live_onions();
        assert_eq!(
            onions,
            vec![g1.onion.clone(), g3.onion.clone()]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
        );
        assert!(
            registry.record(&g1.onion[..56]).is_some(),
            "the suffix is optional"
        );
        assert!(registry.record(&g2.onion).is_none());
    }

    #[tokio::test]
    async fn stake_mode_requires_a_live_authorized_bond() {
        let now = 1_000_000;
        let (operator, operator_sig, node) = operator_vector();
        let listed = make(
            mock(Some(vec![operator.to_ascii_lowercase()])),
            true,
            900,
            10_000,
            0,
            now,
        );
        match listed
            .announce(
                &raw(&node.announce(100, now, "a1", None, Some((&operator, &operator_sig)))),
                now,
            )
            .await
        {
            Outcome::Accepted { staked, .. } => assert!(staked),
            Outcome::Rejected { reason, .. } => panic!("{reason}"),
        }
        let other = Node::new(7);
        assert_eq!(
            reason(
                listed
                    .announce(&raw(&other.announce(100, now, "a2", None, None)), now)
                    .await
            ),
            "not-staked"
        );
        // the operator signature is bound to the vector's onion, so another onion cannot reuse it
        assert_eq!(
            reason(
                listed
                    .announce(
                        &raw(&other.announce(
                            100,
                            now,
                            "a3",
                            None,
                            Some((&operator, &operator_sig))
                        )),
                        now
                    )
                    .await
            ),
            "bad-operator-sig"
        );
        let unstaked = make(
            mock(Some(vec![
                "0x0000000000000000000000000000000000000000".into()
            ])),
            true,
            900,
            10_000,
            0,
            now,
        );
        assert_eq!(
            reason(
                unstaked
                    .announce(
                        &raw(&node.announce(
                            100,
                            now,
                            "a4",
                            None,
                            Some((&operator, &operator_sig))
                        )),
                        now
                    )
                    .await
            ),
            "not-staked"
        );
        // open admission still labels a verified, staked operator
        let open = make(mock(None), false, 900, 10_000, 0, now);
        match open
            .announce(
                &raw(&node.announce(100, now, "a5", None, Some((&operator, &operator_sig)))),
                now,
            )
            .await
        {
            Outcome::Accepted { staked, .. } => assert!(staked),
            Outcome::Rejected { reason, .. } => panic!("{reason}"),
        }
    }

    #[tokio::test]
    async fn the_ttl_the_throttle_the_cap_and_the_weight_clamp_bound_the_set() {
        let mut now = 2_000_000;
        let registry = make(mock(None), false, 100, 10_000, 0, now);
        let g1 = Node::new(1);
        assert_eq!(
            reason(
                registry
                    .announce(
                        &raw(&g1.announce(1_000_000_000_000, now, "t1", None, None)),
                        now
                    )
                    .await
            ),
            "accepted"
        );
        registry.with_live(now, |live| {
            assert_eq!(
                live[&g1.onion].weight, MAX_WEIGHT,
                "self-attested weight clamped"
            )
        });
        now += 101;
        registry.with_live(now, |live| {
            assert!(live.is_empty(), "expired without a re-announce")
        });

        let now = 3_000_000;
        let throttled = make(mock(None), false, 900, 10_000, 5, now);
        assert_eq!(
            reason(
                throttled
                    .announce(&raw(&g1.announce(100, now, "r1", None, None)), now)
                    .await
            ),
            "accepted"
        );
        assert_eq!(
            reason(
                throttled
                    .announce(&raw(&g1.announce(100, now, "r2", None, None)), now)
                    .await
            ),
            "rate-limited"
        );
        assert_eq!(
            reason(
                throttled
                    .announce(&raw(&g1.announce(100, now + 6, "r3", None, None)), now + 6)
                    .await
            ),
            "accepted"
        );

        let now = 4_000_000;
        let full = make(mock(None), false, 900, 1, 0, now);
        let g2 = Node::new(2);
        assert_eq!(
            reason(
                full.announce(&raw(&g1.announce(100, now, "f1", None, None)), now)
                    .await
            ),
            "accepted"
        );
        assert_eq!(
            reason(
                full.announce(&raw(&g2.announce(100, now, "f2", None, None)), now)
                    .await
            ),
            "registry-full"
        );
        assert_eq!(
            reason(
                full.announce(&raw(&g1.announce(100, now, "f3", None, None)), now)
                    .await
            ),
            "accepted",
            "a listed onion still refreshes when full"
        );
    }

    #[tokio::test]
    async fn the_bucket_bounds_fresh_onions_and_cheap_rejects_cost_nothing() {
        let now = 5_000_000;
        let registry = Registry::new(mock(None), bucket_settings(1000, 0, 1.0, 4.0), now);
        let (mut accepted, mut throttled) = (0, 0);
        for tag in 10..20 {
            match registry
                .announce(
                    &raw(&Node::new(tag).announce(100, now, "b", None, None)),
                    now,
                )
                .await
            {
                Outcome::Accepted { .. } => accepted += 1,
                Outcome::Rejected {
                    reason,
                    retry_after_secs,
                } if reason == "global-rate-limited" => {
                    assert!(retry_after_secs.is_some_and(|s| s >= 1));
                    throttled += 1;
                }
                Outcome::Rejected { reason, .. } => panic!("{reason}"),
            }
        }
        assert_eq!((accepted, throttled), (4, 6));
        let mut late = 0;
        for tag in 14..20 {
            if matches!(
                registry
                    .announce(
                        &raw(&Node::new(tag).announce(100, now + 3, "c", None, None)),
                        now + 3
                    )
                    .await,
                Outcome::Accepted { .. }
            ) {
                late += 1;
            }
        }
        assert_eq!(late, 3, "three tokens refilled after three seconds");

        let now = 6_000_000;
        let ordered = Registry::new(mock(None), bucket_settings(1, 5, 0.001, 2.0), now);
        let (a, b) = (Node::new(1), Node::new(2));
        assert_eq!(
            reason(
                ordered
                    .announce(&raw(&a.announce(100, now, "o1", None, None)), now)
                    .await
            ),
            "accepted"
        );
        for _ in 0..20 {
            assert_eq!(
                reason(
                    ordered
                        .announce(&raw(&a.announce(100, now, "o2", None, None)), now)
                        .await
                ),
                "rate-limited"
            );
            assert_eq!(
                reason(
                    ordered
                        .announce(&raw(&b.announce(100, now, "o3", None, None)), now)
                        .await
                ),
                "registry-full"
            );
        }
        assert_eq!(
            ordered.lock().bucket.tokens(now),
            1.0,
            "forty cheap rejects consumed no token"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_store_is_reloaded_through_the_real_checks() {
        let dir = std::env::temp_dir().join(format!("shadenet-elder-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = dir.join("state.json");
        let now = 2_000_000;
        let make = |now: u64, stake: Arc<Verifier>, require: bool| {
            Registry::new(
                stake,
                Settings {
                    require_stake: require,
                    ttl_secs: 900,
                    max_entries: 10_000,
                    min_reannounce_secs: 0,
                    announce_rate: 100.0,
                    announce_burst: 100.0,
                    store: Some(store.clone()),
                },
                now,
            )
        };
        let first = make(now, mock(None), false);
        let nodes: Vec<Node> = (1..=3).map(Node::new).collect();
        for node in &nodes {
            assert_eq!(
                reason(
                    first
                        .announce(&raw(&node.announce(100, now, "s", None, None)), now)
                        .await
                ),
                "accepted"
            );
        }
        let stored: Value = serde_json::from_slice(&std::fs::read(&store).unwrap()).unwrap();
        assert_eq!(stored["entries"].as_array().unwrap().len(), 3);
        assert!(
            stored["entries"][0]["rec"]["onionSig"].is_string()
                && stored["entries"][0]["expiresAt"].is_u64()
        );
        assert!(
            stored["entries"][0]["rec"].get("pubkey").is_none(),
            "no derived verdict is stored"
        );

        let restarted = make(now + 300, mock(None), false);
        assert_eq!(
            restarted.load_persisted(now + 300).await,
            (3, 0),
            "a restart past the skew but inside the ttl keeps the fleet"
        );
        assert_eq!(restarted.size(), 3);
        let late = make(now + 901, mock(None), false);
        assert_eq!(
            late.load_persisted(now + 901).await,
            (0, 3),
            "a restart past the ttl resurrects nothing"
        );

        // a tampered record fails verification and is dropped
        let fresh = make(now, mock(None), false);
        for node in &nodes {
            fresh
                .announce(&raw(&node.announce(100, now, "p", None, None)), now)
                .await;
        }
        let mut poisoned: Value = serde_json::from_slice(&std::fs::read(&store).unwrap()).unwrap();
        let sig = poisoned["entries"][0]["rec"]["onionSig"]
            .as_str()
            .unwrap()
            .to_string();
        let flipped = format!(
            "{}{}",
            &sig[..sig.len() - 1],
            if sig.ends_with('0') { "1" } else { "0" }
        );
        poisoned["entries"][0]["rec"]["onionSig"] = Value::String(flipped);
        std::fs::write(&store, poisoned.to_string()).unwrap();
        let reloaded = make(now, mock(None), false);
        assert_eq!(reloaded.load_persisted(now).await, (2, 1));

        // stake is re-read on reload, fail-closed
        let (operator, operator_sig, node) = operator_vector();
        let staked = make(now, mock(Some(vec![operator.to_ascii_lowercase()])), true);
        assert_eq!(
            reason(
                staked
                    .announce(
                        &raw(&node.announce(100, now, "k", None, Some((&operator, &operator_sig)))),
                        now
                    )
                    .await
            ),
            "accepted"
        );
        let still = make(
            now + 300,
            mock(Some(vec![operator.to_ascii_lowercase()])),
            true,
        );
        assert_eq!(still.load_persisted(now + 300).await, (1, 0));
        still.with_live(now + 300, |live| assert!(live[&node.onion].staked));
        let gone = make(
            now + 300,
            mock(Some(vec![
                "0x0000000000000000000000000000000000000000".into()
            ])),
            true,
        );
        assert_eq!(gone.load_persisted(now + 300).await, (0, 1));

        std::fs::write(&store, "{ this is not valid json").unwrap();
        assert_eq!(
            make(now, mock(None), false).load_persisted(now).await,
            (0, 0)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn gossip_is_re_verified_bounded_by_the_origin_ttl_and_never_shortens() {
        let now = 7_000_000;
        let registry = make(mock(None), false, 900, 10_000, 0, now);
        let node = Node::new(4);
        let old = node.announce(100, now - 500, "g1", None, None);
        assert!(matches!(
            registry.admit_gossip(&raw(&old), now).await,
            Gossip::Merged
        ));
        registry.with_live(now, |live| {
            assert_eq!(
                live[&node.onion].expires_at,
                now - 500 + 900,
                "expiry is the origin's ts plus the ttl"
            )
        });
        assert!(
            matches!(
                registry.admit_gossip(&raw(&old), now).await,
                Gossip::FreshExisting
            ),
            "re-pulling the same record is idempotent"
        );
        let stale = node.announce(100, now - 901, "g2", None, None);
        assert!(
            matches!(registry.admit_gossip(&raw(&stale), now).await, Gossip::Rejected(r) if r == "stale-gossip")
        );
        let forged = old.replace(
            &format!("\"ts\":{}", now - 500),
            &format!("\"ts\":{}", now - 400),
        );
        assert!(
            matches!(registry.admit_gossip(&raw(&forged), now).await, Gossip::Rejected(r) if r == "bad-onion-sig")
        );
        // a direct heartbeat is fresher than any gossip of an older announce
        assert_eq!(
            reason(
                registry
                    .announce(&raw(&node.announce(100, now, "g3", None, None)), now)
                    .await
            ),
            "accepted"
        );
        assert!(matches!(
            registry.admit_gossip(&raw(&old), now).await,
            Gossip::FreshExisting
        ));
    }

    #[tokio::test]
    async fn caps_are_listed_only_with_their_durable_signature() {
        let now = 8_000_000;
        let registry = make(mock(None), false, 900, 10_000, 0, now);
        let node = Node::new(5);
        let caps = Caps {
            ports: Some(vec![443, 80, 80]),
            region: Some("eu".into()),
            proto: Some(ProtoCaps { min: 4, max: 4 }),
            ..Caps::default()
        };
        assert_eq!(
            reason(
                registry
                    .announce(&raw(&node.announce(100, now, "c1", Some(&caps), None)), now)
                    .await
            ),
            "accepted"
        );
        registry.with_live(now, |live| {
            let (listed, _) = live[&node.onion].caps.as_ref().unwrap();
            assert_eq!(
                canonical_caps_json_text(listed),
                "{\"ports\":[80,443],\"region\":\"eu\",\"proto\":{\"min\":4,\"max\":4}}"
            );
            assert!(live[&node.onion].listed().is_some());
        });
        let bad_sig = node
            .announce(100, now, "c2", Some(&caps), None)
            .replace("\"capsSig\":\"", "\"capsSig\":\"ff");
        assert_eq!(
            reason(registry.announce(&raw(&bad_sig), now).await),
            "bad-caps-sig"
        );
        let padded = format!(
            "{{\"pad\":\"{}\",{}",
            "x".repeat(5000),
            &node.announce(100, now, "c3", None, None)[1..]
        );
        assert_eq!(
            reason(registry.announce(&raw(&padded), now).await),
            "accepted"
        );
        registry.with_live(now, |live| {
            assert!(
                live[&node.onion].listed().is_none(),
                "an oversized announce is listed without its copy"
            )
        });
    }
}
