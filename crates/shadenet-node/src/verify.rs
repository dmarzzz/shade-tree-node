//! `verifyEnvelope` (`docs/WIRE-SPEC.md` section 6.4, `packages/node/lib/rln.mjs`): cheap
//! checks first, the Groth16 pairing last, first failure returned. The accepted artifact set
//! (`packages/node/lib/zk-artifacts.mjs`) decides which verification key a proof is checked
//! under.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ark_bn254::Fr;
use num_bigint::BigUint;
use serde_json::Value;
use shadenet_proto::{
    artifact_id_of, calculate_signal_hash, is_artifact_id, request_signal, signal_field_safe,
};
use shadenet_rln::tree::{external_nullifier, fr_to_dec, parse_fr};
use shadenet_rln::verify::{parse_proof, verify, VerifyingKey};
use tokio::sync::Semaphore;

use crate::error::Error;

const BUILTIN_VKEY: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../circuits/rln/verification_key.json"
));
const LOCK: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/zk-artifacts.lock.json"
));
const CIRCUIT: &str = "rln";
/// The path spelling that names the verification key compiled into this binary, so a
/// deployment record's artifact can be selected without a checkout on disk.
pub(crate) const BUILTIN_PATH: &str = "builtin";
const TARGET_MAX_LEN: usize = 256;

/// The artifact id of the verification key compiled into this binary.
pub(crate) fn builtin_artifact_id() -> String {
    artifact_id_of(CIRCUIT, BUILTIN_VKEY)
}
const NONCE_MAX_LEN: usize = 128;

/// The verification keys this node accepts, by artifact id.
pub struct ArtifactSet {
    accepted: HashMap<String, Arc<VerifyingKey>>,
    ids: Vec<String>,
    legacy_id: String,
}

impl ArtifactSet {
    /// `SHADE_TREE_ZK_ARTIFACTS="id=path,path,..."` names the keys; unset means the built-in
    /// key under its own id. `SHADE_TREE_ZK_ARTIFACT_LEGACY` names what an envelope with no
    /// `artifact` field means; its default is the lock's previous id, else the built-in id.
    pub(crate) fn load(spec: Option<&str>, legacy: Option<&str>) -> Result<Self, Error> {
        let name = "SHADE_TREE_ZK_ARTIFACTS";
        let builtin_id = artifact_id_of(CIRCUIT, BUILTIN_VKEY);
        let mut accepted = HashMap::new();
        match spec.map(str::trim).filter(|s| !s.is_empty()) {
            None => {
                let key = parse_key(BUILTIN_VKEY, Path::new("<built-in verification key>"))?;
                accepted.insert(builtin_id.clone(), Arc::new(key));
            }
            Some(spec) => {
                for item in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    let (declared, path) = match item.split_once('=') {
                        Some((id, path)) => (Some(id.trim()), path.trim()),
                        None => (None, item),
                    };
                    if let Some(id) = declared {
                        if !is_artifact_id(id) {
                            return Err(Error::Setting {
                                name,
                                message: format!(
                                    "bad artifact id {:?} in {:?}",
                                    id.chars().take(32).collect::<String>(),
                                    item.chars().take(80).collect::<String>()
                                ),
                            });
                        }
                        if path.is_empty() {
                            return Err(Error::Setting {
                                name,
                                message: format!("missing vkey path for {id}"),
                            });
                        }
                    }
                    let path = PathBuf::from(path);
                    let bytes = if path == Path::new(BUILTIN_PATH) {
                        BUILTIN_VKEY.to_vec()
                    } else {
                        std::fs::read(&path).map_err(|source| Error::ReadFile {
                            path: path.clone(),
                            source,
                        })?
                    };
                    let key = parse_key(&bytes, &path)?;
                    let derived = artifact_id_of(CIRCUIT, &bytes);
                    if declared.is_some_and(|id| id != derived) {
                        return Err(Error::FileContent {
                            path,
                            message: format!(
                                "declared {} but the file's content id is {derived} (refusing to verify under a mislabeled key)",
                                declared.unwrap_or_default()
                            ),
                        });
                    }
                    if accepted.insert(derived.clone(), Arc::new(key)).is_some() {
                        return Err(Error::Setting {
                            name,
                            message: format!("duplicate artifact id {derived}"),
                        });
                    }
                }
            }
        }
        let mut ids: Vec<String> = accepted.keys().cloned().collect();
        ids.sort();
        let legacy_id = match legacy.map(str::trim).filter(|s| !s.is_empty()) {
            Some(id) if is_artifact_id(id) => id.to_string(),
            Some(id) => {
                return Err(Error::Setting {
                    name: "SHADE_TREE_ZK_ARTIFACT_LEGACY",
                    message: format!(
                        "bad artifact id {:?}",
                        id.chars().take(32).collect::<String>()
                    ),
                })
            }
            None => lock_previous_id().unwrap_or(builtin_id),
        };
        Ok(Self {
            accepted,
            ids,
            legacy_id,
        })
    }

    pub(crate) fn ids(&self) -> &[String] {
        &self.ids
    }

    fn resolve(&self, field: Option<&Value>) -> Result<(String, Arc<VerifyingKey>), Refusal> {
        let id = match field {
            None | Some(Value::Null) => self.legacy_id.clone(),
            Some(Value::String(s)) if is_artifact_id(s) => s.clone(),
            Some(other) => {
                return Err(Refusal::artifact(
                    format!("bad-artifact:{}", artifact_repr(other)),
                    self.ids.clone(),
                ))
            }
        };
        if let Some(key) = self.accepted.get(&id) {
            return Ok((id, Arc::clone(key)));
        }
        let reason = if id == self.legacy_id {
            format!("artifact-retired:{id}")
        } else {
            format!("artifact-unknown:{id}")
        };
        Err(Refusal::artifact(reason, self.ids.clone()))
    }
}

fn parse_key(bytes: &[u8], path: &Path) -> Result<VerifyingKey, Error> {
    let json: Value = serde_json::from_slice(bytes).map_err(|source| Error::ParseJson {
        path: path.to_path_buf(),
        source,
    })?;
    if !json["IC"].is_array() {
        return Err(Error::FileContent {
            path: path.to_path_buf(),
            message: "does not look like a snarkjs verification key (no IC)".into(),
        });
    }
    VerifyingKey::parse(&json).map_err(|e| Error::FileContent {
        path: path.to_path_buf(),
        message: e.to_string(),
    })
}

fn lock_previous_id() -> Option<String> {
    let lock: Value = serde_json::from_str(LOCK).ok()?;
    lock["circuits"][CIRCUIT]["previousArtifactId"]
        .as_str()
        .filter(|id| is_artifact_id(id))
        .map(str::to_string)
}

fn artifact_repr(value: &Value) -> String {
    match value {
        Value::String(s) => {
            serde_json::to_string(&s.chars().take(16).collect::<String>()).unwrap_or_default()
        }
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "object".into(),
        Value::Array(_) | Value::Object(_) => "object".into(),
    }
}

/// A verified envelope: the values the node acts on, read from the proof's public signals.
pub(crate) struct Verified {
    pub(crate) nullifier: String,
    pub(crate) external_nullifier: String,
    pub(crate) share_x: String,
    pub(crate) share_y: String,
}

/// Why an envelope was refused, with the extras the reply carries.
pub(crate) enum Refusal {
    Reason(String),
    WrongRoot,
    Artifact { reason: String, ids: Vec<String> },
}

impl Refusal {
    fn reason(reason: &str) -> Self {
        Self::Reason(reason.to_string())
    }

    fn artifact(reason: String, ids: Vec<String>) -> Self {
        Self::Artifact { reason, ids }
    }
}

/// What the proof's public `x` must be the hash of.
pub(crate) enum Binding {
    /// A v4 tunnel: `requestSignal(target, nonce)` from the envelope's own fields.
    Target,
    /// A session initialization: the signal rebuilt from the validated `session` fields.
    Signal(String),
}

pub(crate) struct Verifier {
    artifacts: Arc<ArtifactSet>,
    epoch_seconds: u64,
    rln_identifier: BigUint,
    parallel: Semaphore,
}

impl Verifier {
    pub(crate) fn new(
        artifacts: Arc<ArtifactSet>,
        epoch_seconds: u64,
        rln_identifier: BigUint,
    ) -> Self {
        let parallel = std::thread::available_parallelism().map_or(1, usize::from);
        Self {
            artifacts,
            epoch_seconds,
            rln_identifier,
            parallel: Semaphore::new(parallel),
        }
    }

    pub(crate) fn artifacts(&self) -> &ArtifactSet {
        &self.artifacts
    }

    pub(crate) fn current_epoch(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        now / self.epoch_seconds
    }

    fn external_nullifier_for(&self, epoch: u64) -> String {
        fr_to_dec(&external_nullifier(epoch, &self.rln_identifier))
    }

    pub(crate) async fn verify(
        &self,
        envelope: &Value,
        roots: &HashSet<String>,
        binding: Binding,
    ) -> Result<Verified, Refusal> {
        let proof = &envelope["proof"];
        let snark = &proof["snarkProof"];
        let signals = &snark["publicSignals"];
        if !truthy(proof) || !truthy(snark) || !truthy(signals) {
            return Err(Refusal::reason("no-proof"));
        }
        let signal = |name: &str| js_string(signals.get(name));

        let now = self.current_epoch();
        let external = signal("externalNullifier");
        let fresh = [now, now.saturating_sub(1)]
            .iter()
            .any(|epoch| self.external_nullifier_for(*epoch) == external);
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
                if calculate_signal_hash(&signal) != x {
                    return Err(Refusal::reason("session-not-bound"));
                }
            }
        }

        let root = signal("root");
        if !roots.contains(&root) {
            return Err(Refusal::WrongRoot);
        }

        let (_, key) = self.artifacts.resolve(envelope.get("artifact"))?;

        let threw = |message: String| Refusal::Reason(format!("verify-threw:{message}"));
        let parsed = parse_proof(&snark["proof"]).map_err(|e| threw(e.to_string()))?;
        let field = |name: &str, value: &str| {
            parse_fr(value).map_err(|e| threw(format!("public signal {name}: {e}")))
        };
        let nullifier = signal("nullifier");
        let inputs = [
            field("y", &signal("y"))?,
            field("root", &root)?,
            field("nullifier", &nullifier)?,
            field("x", &x)?,
            field("externalNullifier", &external)?,
        ];
        let epoch: u64 = js_string(proof.get("epoch"))
            .parse()
            .map_err(|_| threw("proof.epoch is not an integer".into()))?;
        let identifier = match proof.get("rlnIdentifier") {
            None | Some(Value::Null) => BigUint::from(1_u8),
            Some(value) => BigUint::parse_bytes(js_string(Some(value)).as_bytes(), 10)
                .ok_or_else(|| threw("proof.rlnIdentifier is not an integer".into()))?,
        };
        if identifier != self.rln_identifier || self.external_nullifier_for(epoch) != external {
            return Err(Refusal::reason("invalid-proof"));
        }

        let _slot = self
            .parallel
            .acquire()
            .await
            .map_err(|_| threw("verifier closed".into()))?;
        let valid = tokio::task::spawn_blocking(move || verify(&key, &parsed, &inputs))
            .await
            .map_err(|e| threw(format!("verifier task: {e}")))?
            .map_err(|e| threw(e.to_string()))?;
        if !valid {
            return Err(Refusal::reason("invalid-proof"));
        }
        Ok(Verified {
            nullifier,
            external_nullifier: external,
            share_x: x,
            share_y: signal("y"),
        })
    }
}

/// JavaScript truthiness for the `!proof || !proof.snarkProof` style checks.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

/// `String(v)` for the scalar shapes a public signal can take.
fn js_string(value: Option<&Value>) -> String {
    match value {
        None => "undefined".into(),
        Some(Value::Null) => "null".into(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Array(_)) => String::new(),
        Some(Value::Object(_)) => "[object Object]".into(),
    }
}

pub(crate) fn parse_field(value: &str) -> Result<Fr, String> {
    parse_fr(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_builtin_key_is_accepted_under_its_lock_id() {
        let set = ArtifactSet::load(None, None).unwrap();
        let lock: Value = serde_json::from_str(LOCK).unwrap();
        let id = lock["circuits"]["rln"]["artifactId"].as_str().unwrap();
        assert_eq!(set.ids(), [id.to_string()]);
        assert!(set.resolve(Some(&Value::String(id.into()))).is_ok());
        let previous = lock["circuits"]["rln"]["previousArtifactId"]
            .as_str()
            .unwrap();
        assert_eq!(set.legacy_id, previous);
        match set.resolve(None) {
            Err(Refusal::Artifact { reason, ids }) => {
                assert_eq!(reason, format!("artifact-retired:{previous}"));
                assert_eq!(ids, set.ids());
            }
            _ => panic!("an absent field resolves to the retired legacy id"),
        }
        match set.resolve(Some(&Value::String("rln-0000000000000000".into()))) {
            Err(Refusal::Artifact { reason, .. }) => {
                assert_eq!(reason, "artifact-unknown:rln-0000000000000000");
            }
            _ => panic!("an unknown id is named"),
        }
        match set.resolve(Some(&Value::String("Not An Id".into()))) {
            Err(Refusal::Artifact { reason, .. }) => {
                assert_eq!(reason, "bad-artifact:\"Not An Id\"")
            }
            _ => panic!("garbage is a bad artifact"),
        }
        match set.resolve(Some(&Value::Number(7.into()))) {
            Err(Refusal::Artifact { reason, .. }) => assert_eq!(reason, "bad-artifact:7"),
            _ => panic!("a number is a bad artifact"),
        }
    }

    #[test]
    fn an_explicit_legacy_id_keeps_old_clients_working() {
        let set = ArtifactSet::load(None, Some("rln-abc")).unwrap();
        match set.resolve(None) {
            Err(Refusal::Artifact { reason, .. }) => assert_eq!(reason, "artifact-retired:rln-abc"),
            _ => panic!(),
        }
        assert!(ArtifactSet::load(None, Some("BAD ID")).is_err());
    }

    #[test]
    fn a_mislabeled_key_file_is_refused() {
        let dir = std::env::temp_dir().join(format!("shadenet-node-vkey-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("verification_key.json");
        std::fs::write(&path, BUILTIN_VKEY).unwrap();
        let spec = format!("rln-0000000000000000={}", path.display());
        assert!(matches!(
            ArtifactSet::load(Some(&spec), None),
            Err(Error::FileContent { .. })
        ));
        let spec = format!("{0},{0}", path.display());
        assert!(matches!(
            ArtifactSet::load(Some(&spec), None),
            Err(Error::Setting { .. })
        ));
        let set = ArtifactSet::load(Some(&spec[..spec.len() / 2]), None).unwrap();
        assert_eq!(set.ids().len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
