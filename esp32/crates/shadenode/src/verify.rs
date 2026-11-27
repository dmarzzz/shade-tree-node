//! Envelope verification in the reference node's order: cheap checks first, the pairing last,
//! first failure returned. Field elements are compared as the strings the client sent.

use std::sync::Arc;

use serde_json::Value;

use crate::proto::{
    calculate_signal_hash, is_artifact_id, request_signal, signal_field_safe, LEGACY_ARTIFACT_ID,
};
use crate::rln::{external_nullifier, fr_to_dec, parse_fr, parse_proof, verify, VerifyingKey};

const TARGET_MAX_LEN: usize = 256;
const NONCE_MAX_LEN: usize = 128;

/// Why an envelope was refused, with the extras the reply line carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    Reason(String),
    WrongRoot,
    Artifact(String),
}

impl Refusal {
    fn reason(text: &str) -> Self {
        Refusal::Reason(text.to_string())
    }
}

/// The values the node acts on, read from the proof's public signals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub nullifier: String,
    pub external_nullifier: String,
    pub share_x: String,
    pub share_y: String,
}

/// What the proof's public `x` must be the hash of.
pub enum Binding<'a> {
    /// A v4 tunnel: `requestSignal(target, nonce)` from the envelope.
    Target,
    /// A session initialization: the signal rebuilt from the validated `session` object.
    Signal(&'a str),
}

/// JavaScript truthiness, which the reference check was written against.
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// `String(value)` for scalars, as JavaScript would render them.
pub fn js_string(v: Option<&Value>) -> String {
    match v {
        None => "undefined".into(),
        Some(Value::Null) => "null".into(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Array(_)) => String::new(),
        Some(Value::Object(_)) => "[object Object]".into(),
    }
}

/// Everything the pairing needs, detached from the envelope so it can run on another thread.
pub struct PairingJob {
    key: Arc<VerifyingKey>,
    proof: Value,
    signals: [String; 5],
}

impl PairingJob {
    /// Parse the proof and public inputs and run the Groth16 check. `Err` is the text after
    /// `verify-threw:`.
    pub fn run(self) -> Result<bool, String> {
        let proof = parse_proof(&self.proof)?;
        let names = ["y", "root", "nullifier", "x", "externalNullifier"];
        let mut inputs = Vec::with_capacity(5);
        for (name, value) in names.iter().zip(self.signals.iter()) {
            inputs.push(parse_fr(value).map_err(|e| format!("public signal {name}: {e}"))?);
        }
        verify(&self.key, &proof, &inputs)
    }
}

pub struct Verifier {
    key: Arc<VerifyingKey>,
    artifact_id: String,
    pub epoch_seconds: u64,
    pub rln_identifier: u64,
    /// Proofs for epochs before this one are refused as stale (see
    /// `NodeConfig::quarantine_boot_epoch`).
    pub min_epoch: u64,
    /// External nullifiers already computed: `(epoch, decimal)`. Two Poseidon hashes a minute
    /// are cheap, but every envelope asks.
    cache: Vec<(u64, String)>,
}

impl Verifier {
    pub fn new(
        key: Arc<VerifyingKey>,
        artifact_id: String,
        epoch_seconds: u64,
        rln_identifier: u64,
    ) -> Self {
        Self {
            key,
            artifact_id,
            epoch_seconds: epoch_seconds.max(1),
            rln_identifier,
            min_epoch: 0,
            cache: Vec::new(),
        }
    }

    pub fn artifact_ids(&self) -> Vec<String> {
        vec![self.artifact_id.clone()]
    }

    pub fn current_epoch(&self, now_unix: u64) -> u64 {
        now_unix / self.epoch_seconds
    }

    fn external_nullifier_for(&mut self, epoch: u64) -> String {
        if let Some((_, value)) = self.cache.iter().find(|(e, _)| *e == epoch) {
            return value.clone();
        }
        let value = fr_to_dec(&external_nullifier(epoch, self.rln_identifier));
        if self.cache.len() >= 4 {
            self.cache.remove(0);
        }
        self.cache.push((epoch, value.clone()));
        value
    }

    /// Run every check short of the pairing. On success returns the verified values (not yet
    /// authoritative) and the job that makes them so.
    pub fn precheck(
        &mut self,
        envelope: &Value,
        roots: &[String],
        binding: Binding<'_>,
        now_unix: u64,
    ) -> Result<(Verified, PairingJob), Refusal> {
        let proof = &envelope["proof"];
        let snark = &proof["snarkProof"];
        let signals = &snark["publicSignals"];
        if !truthy(proof) || !truthy(snark) || !truthy(signals) {
            return Err(Refusal::reason("no-proof"));
        }
        let signal = |name: &str| js_string(signals.get(name));

        let now = self.current_epoch(now_unix);
        let external = signal("externalNullifier");
        let min_epoch = self.min_epoch;
        let fresh = [now, now.saturating_sub(1)]
            .into_iter()
            .filter(|epoch| *epoch >= min_epoch)
            .any(|epoch| self.external_nullifier_for(epoch) == external);
        if !fresh {
            return Err(Refusal::reason("stale-external-nullifier"));
        }

        let x = signal("x");
        let share_x = match envelope.get("share").filter(|s| truthy(s)) {
            Some(share) => js_string(share.get("x")),
            None => x.clone(),
        };
        if share_x != x {
            return Err(Refusal::reason("signal-mismatch"));
        }

        match binding {
            Binding::Target => {
                let (Some(target), Some(nonce)) = (
                    envelope.get("target").filter(|v| !v.is_null()),
                    envelope.get("nonce").filter(|v| !v.is_null()),
                ) else {
                    return Err(Refusal::reason("unbound-target"));
                };
                let (Some(target), Some(nonce)) = (target.as_str(), nonce.as_str()) else {
                    return Err(Refusal::reason("bad-signal-field"));
                };
                if !signal_field_safe(target, TARGET_MAX_LEN)
                    || !signal_field_safe(nonce, NONCE_MAX_LEN)
                {
                    return Err(Refusal::reason("bad-signal-field"));
                }
                if calculate_signal_hash(&request_signal(target, nonce)) != x {
                    return Err(Refusal::reason("target-not-bound"));
                }
            }
            Binding::Signal(signal) => {
                if calculate_signal_hash(signal) != x {
                    return Err(Refusal::reason("session-not-bound"));
                }
            }
        }

        let root = signal("root");
        if !roots.contains(&root) {
            return Err(Refusal::WrongRoot);
        }

        // Artifact: a missing field means the retired legacy key upstream, so it is refused the
        // same way here; only the ceremony key compiled into this node is accepted.
        let artifact = match envelope.get("artifact") {
            None | Some(Value::Null) => LEGACY_ARTIFACT_ID.to_string(),
            Some(Value::String(s)) if is_artifact_id(s) => s.clone(),
            Some(other) => {
                return Err(Refusal::Artifact(format!(
                    "bad-artifact:{}",
                    artifact_repr(other)
                )));
            }
        };
        if artifact != self.artifact_id {
            let kind = if artifact == LEGACY_ARTIFACT_ID {
                "artifact-retired"
            } else {
                "artifact-unknown"
            };
            return Err(Refusal::Artifact(format!("{kind}:{artifact}")));
        }

        // The proof names its own epoch and identifier; they must reproduce the external
        // nullifier the freshness check accepted.
        let epoch: u64 = js_string(proof.get("epoch"))
            .parse()
            .map_err(|_| Refusal::reason("verify-threw:proof.epoch is not an integer"))?;
        let identifier: u64 = match proof.get("rlnIdentifier") {
            None | Some(Value::Null) => 1,
            other => js_string(other).parse().map_err(|_| {
                Refusal::reason("verify-threw:proof.rlnIdentifier is not an integer")
            })?,
        };
        if identifier != self.rln_identifier || self.external_nullifier_for(epoch) != external {
            return Err(Refusal::reason("invalid-proof"));
        }

        let verified = Verified {
            nullifier: signal("nullifier"),
            external_nullifier: external.clone(),
            share_x: x.clone(),
            share_y: signal("y"),
        };
        let job = PairingJob {
            key: self.key.clone(),
            proof: snark["proof"].clone(),
            signals: [signal("y"), root, signal("nullifier"), x, external],
        };
        Ok((verified, job))
    }
}

fn artifact_repr(value: &Value) -> String {
    match value {
        Value::String(s) => crate::proto::json_string(&s.chars().take(16).collect::<String>()),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => "object".into(),
    }
}

/// Turn the pairing result into the reference refusal.
pub fn pairing_refusal(result: Result<bool, String>) -> Option<Refusal> {
    match result {
        Ok(true) => None,
        Ok(false) => Some(Refusal::reason("invalid-proof")),
        Err(message) => Some(Refusal::Reason(format!("verify-threw:{message}"))),
    }
}
