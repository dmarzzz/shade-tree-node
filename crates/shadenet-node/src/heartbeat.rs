//! The heartbeat (`packages/node/bootnode/heartbeat.mjs`): a fresh signed announce to every
//! Elder Tree of the canopy each interval, gated on a local egress check, carrying the node's
//! real configuration as signed capabilities. An Elder's entry is soft state with a TTL, so a
//! node that stops announcing ages out on its own; that is what `retire` relies on.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use shadenet_proto::{
    canonical_announce_bytes, canonical_caps_bytes, canonical_caps_json_text, ed25519_sign,
    has_caps, operator_auth_message, verify_operator_sig, Announce, Caps, PayCaps, ProtoCaps,
    RateCaps, SessionCaps, ANNOUNCE_VERSION, PROTO_MAX, PROTO_MIN,
};
use tokio::net::TcpStream;
use tokio::sync::watch;

use crate::clock;
use crate::drain;
use crate::knobs;
use crate::metrics::Registry;
use crate::receipt::Signer;
use crate::telemetry;
use crate::torhttp::{self, Request, Socks};

pub(crate) const DEFAULT_INTERVAL_SECS: u64 = 300;
pub(crate) const DEFAULT_EGRESS_CHECK_TARGET: &str = "1.1.1.1:443";
pub(crate) const DEFAULT_EGRESS_CHECK_TIMEOUT_MS: u64 = 5_000;
const ELDER_PORT: u16 = 80;

/// How the operator stake authorization is configured.
#[derive(Clone)]
pub(crate) enum OperatorAuth {
    /// Onion-only announces.
    None,
    /// A pre-computed address and signature (the key never reaches the node).
    Pair { operator: String, sig: String },
    /// The operator key itself; the signature is made once at startup.
    Key(String),
}

/// Resolve the operator authorization once; every misconfiguration fails here, at startup.
pub(crate) fn resolve_operator(
    onion: &str,
    auth: &OperatorAuth,
) -> Result<Option<(String, String)>, String> {
    match auth {
        OperatorAuth::None => Ok(None),
        OperatorAuth::Pair { operator, sig } => {
            if !knobs::is_eth_address(operator) {
                return Err("SHADE_TREE_GW_OPERATOR is not a 0x-prefixed 20-byte address".into());
            }
            let sig = sig.trim();
            if sig.len() != 132
                || !sig.starts_with("0x")
                || !sig[2..].bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(
                    "SHADE_TREE_GW_OPERATOR_SIG is not a 65-byte 0x-hex personal_sign signature"
                        .into(),
                );
            }
            if !verify_operator_sig(onion, operator, sig) {
                return Err(format!(
                    "SHADE_TREE_GW_OPERATOR_SIG does not recover SHADE_TREE_GW_OPERATOR for onion {onion} (re-sign operatorAuthMessage with the operator key)"
                ));
            }
            Ok(Some((operator.clone(), sig.to_string())))
        }
        OperatorAuth::Key(key) => {
            if !knobs::is_private_hex(key) {
                return Err("SHADE_TREE_GW_OPERATOR_KEY is not a 32-byte hex private key (64 hex, 0x optional)".into());
            }
            let wallet = shadenet::eth::Wallet::from_hex(key).map_err(|_| {
                "SHADE_TREE_GW_OPERATOR_KEY is not a valid secp256k1 private key".to_string()
            })?;
            let operator = wallet.address.to_string();
            let sig = wallet.sign_message(&operator_auth_message(onion, &operator));
            Ok(Some((operator, sig)))
        }
    }
}

/// What the node advertises, taken from what it actually runs. A field is advertised only
/// when the operator configured it, so an unconfigured node announces byte for byte like a
/// legacy one.
#[derive(Clone, Default)]
pub(crate) struct CapsInputs {
    /// `SHADE_TREE_EGRESS_ALLOW` when set explicitly.
    pub(crate) egress_allow: Option<String>,
    pub(crate) region: Option<String>,
    /// The accepted artifact ids when `SHADE_TREE_ZK_ARTIFACTS` was set explicitly.
    pub(crate) artifacts: Option<Vec<String>>,
    /// The admission paths when `SHADE_TREE_ADMIT` (or its alias) was set.
    pub(crate) admits: Option<Vec<String>>,
    pub(crate) pay: Option<PayCaps>,
    pub(crate) rate: Option<RateCaps>,
    pub(crate) session: bool,
    pub(crate) sets: Option<Vec<String>>,
}

/// The concrete ports of an allow list: `*:443` gives `[443]`; a wildcard port is dropped.
pub(crate) fn advertised_ports(allow: &str) -> Vec<i64> {
    let mut ports: Vec<i64> = allow
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|spec| {
            let i = spec.rfind(':')?;
            if i == 0 || i == spec.len() - 1 {
                return None;
            }
            let port = &spec[i + 1..];
            if port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            port.parse::<i64>().ok().filter(|p| (1..=65535).contains(p))
        })
        .collect();
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// The raw caps for an announce, or `None` when nothing is configured.
pub(crate) fn build_caps(inputs: &CapsInputs, draining: bool) -> Option<Caps> {
    let mut caps = Caps::default();
    if let Some(allow) = &inputs.egress_allow {
        let ports = advertised_ports(allow);
        if !ports.is_empty() {
            caps.ports = Some(ports);
        }
    }
    if let Some(region) = &inputs.region {
        if shadenet_proto::is_region_bucket(region) {
            caps.region = Some(region.clone());
        }
    }
    if let Some(ids) = &inputs.artifacts {
        if !ids.is_empty() {
            caps.artifacts = Some(ids.clone());
        }
    }
    caps.admits = inputs.admits.clone();
    caps.pay = inputs.pay.clone();
    caps.rate = inputs.rate.clone();
    if inputs.session {
        caps.session = Some(SessionCaps {
            version: 1,
            classes: shadenet_proto::session::CLASSES
                .iter()
                .map(|c| c.class.to_string())
                .collect(),
        });
    }
    if draining {
        caps.draining = Some(true);
    }
    caps.sets = inputs.sets.clone();
    if !has_caps(&caps) {
        return None;
    }
    caps.proto = Some(ProtoCaps {
        min: PROTO_MIN as i64,
        max: PROTO_MAX as i64,
    });
    Some(caps)
}

fn nonce() -> String {
    let mut bytes = [0_u8; 16];
    let _ = getrandom::fill(&mut bytes);
    hex::encode(bytes)
}

/// The signed announce body (`buildAnnounce`): the caps and their durable signature ride
/// before the onion signature that covers them, and the operator pair comes last.
pub(crate) fn announce_body(
    signer: &Signer,
    weight: u64,
    ts: u64,
    nonce: &str,
    caps: Option<&Caps>,
    operator: Option<&(String, String)>,
) -> String {
    let onion = signer.onion();
    let caps = caps.filter(|c| has_caps(c));
    let announce = Announce {
        v: ANNOUNCE_VERSION,
        onion: onion.clone(),
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
        signer.seed(),
    ));
    let mut body = format!(
        "{{\"v\":{ANNOUNCE_VERSION},\"onion\":{},\"weight\":{weight},\"ts\":{ts},\"nonce\":{}",
        serde_json::to_string(&onion).unwrap_or_default(),
        serde_json::to_string(nonce).unwrap_or_default()
    );
    if let Some(caps) = caps {
        let caps_sig = hex::encode(ed25519_sign(
            &canonical_caps_bytes(&onion, caps),
            signer.seed(),
        ));
        body.push_str(&format!(
            ",\"caps\":{},\"capsSig\":\"{caps_sig}\"",
            canonical_caps_json_text(caps)
        ));
    }
    body.push_str(&format!(",\"onionSig\":\"{onion_sig}\""));
    if let Some((operator, sig)) = operator {
        body.push_str(&format!(
            ",\"operator\":{},\"operatorSig\":{}",
            serde_json::to_string(&operator.to_ascii_lowercase()).unwrap_or_default(),
            serde_json::to_string(sig).unwrap_or_default()
        ));
    }
    body.push('}');
    body
}

/// A metadata-only liveness probe of this host's clearnet egress: connect to a well-known
/// `:443` host, write nothing, close.
#[derive(Clone)]
pub(crate) struct EgressCheck {
    pub(crate) target: String,
    pub(crate) timeout: Duration,
}

impl EgressCheck {
    /// `(healthy, reason)`; the reason is `connected`, `timeout` or `connect-error:<kind>`.
    pub(crate) async fn run(&self) -> (bool, String) {
        let (host, port) = match self.target.rsplit_once(':') {
            Some((host, port)) if !host.is_empty() => {
                (host.to_string(), port.parse().unwrap_or(443))
            }
            _ => (self.target.clone(), 443),
        };
        match tokio::time::timeout(self.timeout, TcpStream::connect((host.as_str(), port))).await {
            Ok(Ok(_)) => (true, "connected".into()),
            Ok(Err(e)) => (
                false,
                format!(
                    "connect-error:{}",
                    crate::egress::upstream_reason(&e).trim_start_matches("upstream:")
                ),
            ),
            Err(_) => (false, "timeout".into()),
        }
    }
}

pub(crate) struct Settings {
    pub(crate) bootnodes: Vec<String>,
    pub(crate) interval: Duration,
    pub(crate) weight: u64,
    pub(crate) socks: Socks,
    pub(crate) egress_check: Option<EgressCheck>,
    pub(crate) auth: OperatorAuth,
    pub(crate) caps: CapsInputs,
    pub(crate) relay_telemetry: Option<telemetry::Paths>,
    pub(crate) drain_poll: Duration,
}

/// One Elder's answer to one announce.
enum Outcome {
    Accepted { staked: bool, ttl: u64 },
    Rejected { err: String },
    Failed { err: String },
}

fn elder_tag(onion: &str) -> String {
    format!("{}..onion", onion.chars().take(16).collect::<String>())
}

/// What an operator does about the refusals they can fix themselves.
pub(crate) fn rejection_fix(err: &str) -> Option<&'static str> {
    match err {
        "not-staked" => Some("this Elder admits staked operators only: stake the operator bond (shade-tree register-gateway), then give the node SHADENET_OPERATOR + SHADENET_OPERATOR_SIG from `shadenet-node authorize`, or SHADENET_OPERATOR_KEY_FILE"),
        "bad-operator-sig" => Some("SHADENET_OPERATOR_SIG does not sign this onion for SHADENET_OPERATOR; run `shadenet-node authorize --onion <this onion>` again"),
        _ => None,
    }
}

pub(crate) struct Heartbeat {
    settings: Settings,
    signer: Arc<Signer>,
    operator: Option<(String, String)>,
    registry: Arc<Registry>,
    drain: Arc<drain::Flag>,
}

impl Heartbeat {
    /// Resolve the operator authorization and announce the configuration.
    pub(crate) fn new(
        settings: Settings,
        signer: Arc<Signer>,
        registry: Arc<Registry>,
        drain: Arc<drain::Flag>,
    ) -> Result<Self, String> {
        let operator = resolve_operator(&signer.onion(), &settings.auth)?;
        let bootnodes = &settings.bootnodes;
        tracing::info!(
            interval_sec = settings.interval.as_secs(),
            auth_mode = if operator.is_some() {
                "staked-operator"
            } else {
                "onion-only"
            },
            "heartbeat: {} -> {} every {}s{}",
            elder_tag(&signer.onion()),
            elder_tag(bootnodes.first().map_or("", String::as_str)),
            settings.interval.as_secs(),
            operator
                .as_ref()
                .map_or(" (onion-only)".to_string(), |(o, _)| format!(
                    " (operator {}..)",
                    o.chars().take(10).collect::<String>()
                ))
        );
        if bootnodes.len() > 1 {
            tracing::info!(
                elders = bootnodes.len(),
                "heartbeat: announcing to {} Elder Trees ({})",
                bootnodes.len(),
                bootnodes
                    .iter()
                    .map(|b| elder_tag(b))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        registry.gauge(
            "shade_tree_heartbeat_elders_total",
            &[],
            bootnodes.len() as f64,
        );
        registry.gauge("shade_tree_heartbeat_elders_accepted", &[], 0.0);
        registry.gauge(
            "shade_tree_heartbeat_last_success_timestamp_seconds",
            &[],
            0.0,
        );
        match &settings.egress_check {
            Some(check) => tracing::info!(
                enabled = true,
                target = check.target,
                "egress self-check: ON (metadata-only TCP connect to {} before each announce; SKIP announce if DOWN). Disable with SHADE_TREE_EGRESS_CHECK=0",
                check.target
            ),
            None => tracing::info!(
                enabled = false,
                "egress self-check: OFF (SHADE_TREE_EGRESS_CHECK=0) -- announcing unconditionally"
            ),
        }
        let caps = build_caps(&settings.caps, drain.is_set());
        match &caps {
            Some(caps) => tracing::debug!(
                "capabilities advertised (signed): {}",
                canonical_caps_json_text(caps)
            ),
            None => tracing::debug!(
                "capabilities: none (unconfigured -- announce is byte-identical to a legacy gateway; set SHADE_TREE_EGRESS_ALLOW, SHADE_TREE_GATEWAY_REGION, SHADE_TREE_ZK_ARTIFACTS, SHADE_TREE_ADMIT and/or SHADE_TREE_REGISTRAR_ADVERTISE to advertise)"
            ),
        }
        match &settings.caps.admits {
            Some(admits) => tracing::debug!(
                "admission policy advertised: admits={} (SHADE_TREE_ADMIT; must match the gateway unit's)",
                admits.join(",")
            ),
            None => tracing::warn!(
                reason = "SHADE_TREE_ADMIT-unset",
                "admission policy: NOT advertised (SHADE_TREE_ADMIT unset here); clients assume this gateway may admit any leaf source; set SHADE_TREE_ADMIT to the gateway's policy"
            ),
        }
        if let Some(pay) = &settings.caps.pay {
            tracing::debug!(
                "payment advert: protocols={} port={}{}",
                pay.protocols.clone().unwrap_or_default().join(","),
                pay.port.unwrap_or(0),
                pay.onion
                    .as_ref()
                    .map_or(" (this onion)".to_string(), |o| format!(
                        " onion={}..",
                        o.chars().take(16).collect::<String>()
                    ))
            );
        }
        Ok(Self {
            settings,
            signer,
            operator,
            registry,
            drain,
        })
    }

    pub(crate) fn bootnodes(&self) -> usize {
        self.settings.bootnodes.len()
    }

    /// Announce until `retire` turns true. A drain transition announces at once.
    pub(crate) async fn run(self: Arc<Self>, mut retire: watch::Receiver<bool>) {
        let mut draining = self.drain.watch(self.settings.drain_poll);
        self.registry.gauge(
            "shade_tree_heartbeat_draining",
            &[],
            if *draining.borrow() { 1.0 } else { 0.0 },
        );
        if *draining.borrow() {
            tracing::info!(
                draining = true,
                path = %self.drain.path().display(),
                "drain flag set; announcing draining"
            );
        }
        let first = self.beat().await;
        tracing::info!(
            first = match first {
                Beat::Accepted => "accepted",
                Beat::Skipped => "skipped",
                Beat::Failed => "retrying",
            },
            "heartbeat ready"
        );
        loop {
            tokio::select! {
                () = tokio::time::sleep(self.settings.interval) => {
                    self.beat().await;
                }
                changed = draining.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    let on = *draining.borrow();
                    self.registry.gauge("shade_tree_heartbeat_draining", &[], if on { 1.0 } else { 0.0 });
                    if on {
                        tracing::info!(draining = true, path = %self.drain.path().display(), "drain flag set; announcing draining");
                    } else {
                        tracing::info!(draining = false, "drain flag cleared; announcing normal");
                    }
                    self.beat().await;
                }
                changed = retire.changed() => {
                    if changed.is_err() || *retire.borrow() {
                        tracing::info!("heartbeat stopped; this node leaves every Elder Tree's directory within the TTL");
                        return;
                    }
                }
            }
        }
    }

    async fn beat(self: &Arc<Self>) -> Beat {
        let registry = &self.registry;
        if let Some(check) = &self.settings.egress_check {
            let (healthy, reason) = check.run().await;
            registry.gauge(
                "shade_tree_heartbeat_egress_check_up",
                &[],
                if healthy { 1.0 } else { 0.0 },
            );
            if !healthy {
                registry.gauge("shade_tree_heartbeat_elders_accepted", &[], 0.0);
                registry.counter(
                    "shade_tree_heartbeat_attempts_total",
                    &[("outcome", "egress-unhealthy")],
                );
                tracing::warn!(
                    reason = "egress-unhealthy",
                    "egress DOWN ({} {reason}); SKIP announce; gateway ages out of the bootnode via TTL",
                    check.target
                );
                return Beat::Skipped;
            }
        }
        let caps = build_caps(&self.settings.caps, self.drain.is_set());
        // one announce per elder tree, in parallel, each classified and logged on its own
        let mut announces = tokio::task::JoinSet::new();
        for elder in &self.settings.bootnodes {
            let this = Arc::clone(self);
            let elder = elder.clone();
            let caps = caps.clone();
            announces.spawn(async move {
                let outcome = this.announce(&elder, caps.as_ref()).await;
                this.log_outcome(&elder, &outcome);
                outcome
            });
        }
        let mut accepted = 0;
        while let Some(joined) = announces.join_next().await {
            if matches!(joined, Ok(Outcome::Accepted { .. })) {
                accepted += 1;
            }
        }
        registry.gauge("shade_tree_heartbeat_elders_accepted", &[], accepted as f64);
        let total = self.settings.bootnodes.len();
        if accepted == 0 {
            return Beat::Failed;
        }
        if accepted < total {
            tracing::warn!(
                accepted,
                total,
                "announced to {accepted} of {total} Elder Trees (the rest will be retried next interval)"
            );
        }
        if let Some(paths) = &self.settings.relay_telemetry {
            match telemetry::report(
                &self.settings.socks,
                &self.settings.bootnodes[0],
                &self.signer,
                paths,
            )
            .await
            {
                Ok(()) => tracing::debug!(
                    published = "aggregate-input",
                    "private relay telemetry accepted"
                ),
                Err(e) => tracing::warn!(
                    reason = "telemetry-unavailable",
                    "private relay telemetry unavailable; will retry next interval: {e}"
                ),
            }
        }
        Beat::Accepted
    }

    async fn announce(&self, elder: &str, caps: Option<&Caps>) -> Outcome {
        let body = announce_body(
            &self.signer,
            self.settings.weight,
            clock::now_secs(),
            &nonce(),
            caps,
            self.operator.as_ref(),
        );
        let request = Request::post("/announce", body.as_bytes());
        match torhttp::request_over_tor(
            &self.settings.socks,
            elder,
            ELDER_PORT,
            &request,
            torhttp::DEFAULT_ATTEMPTS,
        )
        .await
        {
            Ok(reply) => classify(&reply),
            Err(torhttp::Error::Refusal {
                reply: Some(reply), ..
            }) if reply.get("ok") == Some(&Value::Bool(false)) => classify(&reply),
            Err(e) => Outcome::Failed { err: e.to_string() },
        }
    }

    fn log_outcome(&self, elder: &str, outcome: &Outcome) {
        let registry = &self.registry;
        let tag = elder_tag(elder);
        match outcome {
            Outcome::Accepted { staked, ttl } => {
                registry.counter(
                    "shade_tree_heartbeat_attempts_total",
                    &[("outcome", "accepted")],
                );
                registry.gauge(
                    "shade_tree_heartbeat_last_success_timestamp_seconds",
                    &[],
                    clock::now_ms() as f64 / 1000.0,
                );
                tracing::info!(elder = tag, staked, ttl_sec = ttl, "heartbeat accepted");
            }
            Outcome::Rejected { err } => {
                registry.counter(
                    "shade_tree_heartbeat_attempts_total",
                    &[("outcome", "rejected")],
                );
                match rejection_fix(err) {
                    Some(fix) => tracing::warn!(
                        elder = tag,
                        reason = "elder-rejected",
                        err,
                        fix,
                        "heartbeat rejected"
                    ),
                    None => tracing::warn!(
                        elder = tag,
                        reason = "elder-rejected",
                        err,
                        "heartbeat rejected"
                    ),
                }
            }
            Outcome::Failed { err } => {
                registry.counter(
                    "shade_tree_heartbeat_attempts_total",
                    &[("outcome", "transport-error")],
                );
                tracing::warn!(
                    elder = tag,
                    reason = "transport-error",
                    "heartbeat transport failed; will retry: {err}"
                );
            }
        }
    }
}

enum Beat {
    Accepted,
    Skipped,
    Failed,
}

/// An Elder's reply is untrusted input: anything but a plain object with `ok` is a rejection.
fn classify(reply: &Value) -> Outcome {
    let Some(object) = reply.as_object() else {
        return Outcome::Rejected {
            err: "malformed response".into(),
        };
    };
    if object.get("ok") == Some(&Value::Bool(true)) {
        return Outcome::Accepted {
            staked: object.get("staked") == Some(&Value::Bool(true)),
            ttl: object.get("ttl").and_then(Value::as_u64).unwrap_or(0),
        };
    }
    Outcome::Rejected {
        err: match object.get("err") {
            Some(Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
            None => String::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadenet_proto::{ed25519_public_key, pubkey_to_onion, verify_announce};

    // testdata/vectors.json `onionSeed`: 32 bytes of 0x22
    fn signer() -> Signer {
        Signer::from_seed([0x22_u8; 32])
    }

    #[test]
    fn an_announce_without_caps_is_the_legacy_announce_and_verifies() {
        let signer = signer();
        let body = announce_body(
            &signer,
            100,
            1_000_000,
            "abcdef0123456789abcdef0123456789",
            None,
            None,
        );
        let onion = pubkey_to_onion(&ed25519_public_key(&[0x22_u8; 32]));
        assert_eq!(
            onion,
            "ucnkl5d2m5myal7zkx4nyljkcss4thjdx2l7qzasp74tqncvutypp3ad.onion"
        );
        // testdata/vectors.json `announce` + `announceOnionSig`
        assert_eq!(
            body,
            format!("{{\"v\":1,\"onion\":\"{onion}\",\"weight\":100,\"ts\":1000000,\"nonce\":\"abcdef0123456789abcdef0123456789\",\"onionSig\":\"b1169a85129aabed237b1623efd9074652ee2c12abb52499c6de343836dd43f392a7ef242deaa72814c353570b70edfd4b4b32690b27c20e103e1bff52465101\"}}")
        );
    }

    #[test]
    fn caps_ride_signed_inside_the_announce_and_the_elder_accepts_them() {
        let signer = signer();
        let inputs = CapsInputs {
            egress_allow: Some("*:443, *:80, *:*".into()),
            region: Some("eu".into()),
            artifacts: Some(vec!["rln-ae43614cd02ebe95".into()]),
            admits: Some(vec!["staked".into()]),
            session: true,
            sets: Some(vec![format!("0x{}", "ab".repeat(20))]),
            ..CapsInputs::default()
        };
        let caps = build_caps(&inputs, true).unwrap();
        assert_eq!(caps.ports, Some(vec![80, 443]));
        assert_eq!(caps.proto, Some(ProtoCaps { min: 4, max: 4 }));
        let body = announce_body(
            &signer,
            7,
            clock::now_secs(),
            &nonce(),
            Some(&caps),
            Some(&(
                "0xAbC0000000000000000000000000000000000000".into(),
                "0xsig".into(),
            )),
        );
        let parsed: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["caps"]["draining"], true);
        assert_eq!(
            parsed["caps"]["session"]["classes"],
            serde_json::json!(["research-v1", "research-v2"])
        );
        assert_eq!(
            parsed["operator"],
            "0xabc0000000000000000000000000000000000000"
        );
        // the key order is the javascript builder's: caps and capsSig before the onion
        // signature that covers them, the operator pair last
        let positions: Vec<usize> = [
            "\"v\":",
            "\"onion\":",
            "\"weight\":",
            "\"ts\":",
            "\"nonce\":",
            "\"caps\":",
            "\"capsSig\":",
            "\"onionSig\":",
            "\"operator\":",
            "\"operatorSig\":",
        ]
        .iter()
        .map(|key| {
            body.find(key)
                .unwrap_or_else(|| panic!("{key} missing in {body}"))
        })
        .collect();
        assert!(positions.windows(2).all(|w| w[0] < w[1]), "{positions:?}");
        // the announce verifies exactly as the elder checks it, caps and capsSig included
        let announce = Announce {
            v: 1,
            onion: parsed["onion"].as_str().unwrap().into(),
            weight: 7,
            ts: parsed["ts"].as_u64().unwrap(),
            nonce: parsed["nonce"].as_str().unwrap().into(),
            onion_sig: parsed["onionSig"].as_str().map(str::to_string),
            operator: None,
            operator_sig: None,
            caps: Some(caps.clone()),
            caps_sig: parsed["capsSig"].as_str().map(str::to_string),
        };
        verify_announce(&announce, parsed["ts"].as_u64().unwrap(), 120, None).expect("verifies");
        assert!(
            build_caps(&CapsInputs::default(), false).is_none(),
            "nothing configured, nothing advertised"
        );
        assert!(
            build_caps(
                &CapsInputs {
                    egress_allow: Some("*:*".into()),
                    ..CapsInputs::default()
                },
                false
            )
            .is_none(),
            "a wildcard port is not a cap"
        );
    }

    #[test]
    fn operator_resolution_fails_fast_on_every_misconfiguration() {
        let onion = "ucnkl5d2m5myal7zkx4nyljkcss4thjdx2l7qzasp74tqncvutypp3ad.onion";
        assert!(resolve_operator(onion, &OperatorAuth::None)
            .unwrap()
            .is_none());
        let pair = resolve_operator(onion, &OperatorAuth::Pair {
            operator: "0x7564105E977516C53bE337314c7E53838967bDaC".into(),
            sig: "0x9e50686e4a58a1566a9fce04a78c9ab0071ac03dc0f93de15026107ec88ffad810b350a14b181f8697882bd79c556c50a619141f741391df1ed6e1fb7940b1851b".into(),
        }).unwrap().unwrap();
        assert_eq!(pair.0, "0x7564105E977516C53bE337314c7E53838967bDaC");
        let from_key = resolve_operator(
            onion,
            &OperatorAuth::Key(
                "0x4444444444444444444444444444444444444444444444444444444444444444".into(),
            ),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            from_key.1, pair.1,
            "the key signs the same durable authorization"
        );
        assert!(resolve_operator(
            onion,
            &OperatorAuth::Pair {
                operator: "0x7564105E977516C53bE337314c7E53838967bDaC".into(),
                sig: format!("0x{}", "11".repeat(65))
            }
        )
        .unwrap_err()
        .contains("does not recover"));
        assert!(resolve_operator(
            onion,
            &OperatorAuth::Pair {
                operator: "nope".into(),
                sig: String::new()
            }
        )
        .unwrap_err()
        .contains("not a 0x-prefixed"));
        assert!(resolve_operator(onion, &OperatorAuth::Key("0x12".into()))
            .unwrap_err()
            .contains("not a 32-byte"));
    }

    #[test]
    fn replies_are_classified_as_untrusted_input() {
        assert!(matches!(
            classify(&serde_json::json!({"ok": true, "staked": true, "ttl": 900})),
            Outcome::Accepted {
                staked: true,
                ttl: 900
            }
        ));
        assert!(
            matches!(classify(&serde_json::json!({"ok": false, "err": "not-staked"})), Outcome::Rejected { err } if err == "not-staked")
        );
        assert!(
            matches!(classify(&serde_json::json!([1])), Outcome::Rejected { err } if err == "malformed response")
        );
        assert!(rejection_fix("not-staked").is_some());
        assert!(rejection_fix("weird").is_none());
    }
}
