//! The verifier against a real envelope made by the `shadenet-rln` prover (identity secret 111,
//! tier 8, a one-member tree, epoch 7, target example.com:443).

use std::sync::Arc;

use serde_json::Value;
use shadenode::proto::artifact_id_of;
use shadenode::rln::{VerifyingKey, BUILTIN_VKEY};
use shadenode::verify::{pairing_refusal, Binding, Refusal, Verifier};

const EPOCH_SECONDS: u64 = 60;
const NOW: u64 = 7 * EPOCH_SECONDS + 5;

fn envelope() -> Value {
    serde_json::from_str(include_str!("../../../firmware/fixtures/envelope.json")).unwrap()
}

fn verifier() -> Verifier {
    let key = Arc::new(VerifyingKey::builtin().unwrap());
    Verifier::new(key, artifact_id_of("rln", BUILTIN_VKEY), EPOCH_SECONDS, 1)
}

fn root(envelope: &Value) -> Vec<String> {
    vec![envelope["proof"]["snarkProof"]["publicSignals"]["root"]
        .as_str()
        .unwrap()
        .to_string()]
}

fn reason(result: Result<impl Sized, Refusal>) -> String {
    match result {
        Ok(_) => "ok".into(),
        Err(Refusal::Reason(r)) => r,
        Err(Refusal::WrongRoot) => "wrong-group-root".into(),
        Err(Refusal::Artifact(r)) => r,
    }
}

#[test]
fn a_real_envelope_is_admitted() {
    let env = envelope();
    let mut v = verifier();
    let (verified, job) = v
        .precheck(&env, &root(&env), Binding::Target, NOW)
        .ok()
        .unwrap();
    assert_eq!(verified.nullifier, env["nullifier"].as_str().unwrap());
    assert_eq!(verified.share_x, env["share"]["x"].as_str().unwrap());
    assert_eq!(pairing_refusal(job.run()), None);
    // The previous epoch is still accepted; two epochs later it is not.
    assert!(v
        .precheck(&env, &root(&env), Binding::Target, NOW + EPOCH_SECONDS)
        .is_ok());
    assert_eq!(
        reason(v.precheck(&env, &root(&env), Binding::Target, NOW + 2 * EPOCH_SECONDS)),
        "stale-external-nullifier"
    );
    // A node on another epoch length disagrees about what "now" is.
    let key = Arc::new(VerifyingKey::builtin().unwrap());
    let mut other = Verifier::new(key, artifact_id_of("rln", BUILTIN_VKEY), 120, 1);
    assert_eq!(
        reason(other.precheck(&env, &root(&env), Binding::Target, NOW)),
        "stale-external-nullifier"
    );
}

#[test]
fn cheap_checks_refuse_in_the_reference_order() {
    let env = envelope();
    let roots = root(&env);
    let mut v = verifier();
    let mut check = |edit: &dyn Fn(&mut Value), roots: &[String]| {
        let mut e = env.clone();
        edit(&mut e);
        reason(v.precheck(&e, roots, Binding::Target, NOW))
    };
    assert_eq!(check(&|e| e["proof"] = Value::Null, &roots), "no-proof");
    assert_eq!(
        check(&|e| e["share"]["x"] = "1".into(), &roots),
        "signal-mismatch"
    );
    assert_eq!(
        check(&|e| e["target"] = Value::Null, &roots),
        "unbound-target"
    );
    assert_eq!(
        check(&|e| e["nonce"] = 5.into(), &roots),
        "bad-signal-field"
    );
    assert_eq!(
        check(&|e| e["target"] = "evil.example:443".into(), &roots),
        "target-not-bound"
    );
    assert_eq!(
        check(&|e| e["nonce"] = "ff".into(), &roots),
        "target-not-bound"
    );
    assert_eq!(check(&|_| {}, &["1".to_string()]), "wrong-group-root");
    assert_eq!(
        check(
            &|e| {
                e.as_object_mut().unwrap().remove("artifact");
            },
            &roots
        ),
        "artifact-retired:rln-0b25f824a04da3a8"
    );
    assert_eq!(
        check(&|e| e["artifact"] = "rln-0000000000000000".into(), &roots),
        "artifact-unknown:rln-0000000000000000"
    );
    assert_eq!(
        check(&|e| e["artifact"] = "NOPE".into(), &roots),
        "bad-artifact:\"NOPE\""
    );
    assert_eq!(
        check(&|e| e["proof"]["epoch"] = "8".into(), &roots),
        "invalid-proof"
    );
    assert_eq!(
        check(&|e| e["proof"]["epoch"] = "x".into(), &roots),
        "verify-threw:proof.epoch is not an integer"
    );
    assert_eq!(
        check(&|e| e["proof"]["rlnIdentifier"] = "2".into(), &roots),
        "invalid-proof"
    );
    // The share is optional; without it the public signal stands in.
    assert_eq!(
        check(
            &|e| {
                e.as_object_mut().unwrap().remove("share");
            },
            &roots
        ),
        "ok"
    );
}

#[test]
fn the_pairing_catches_what_the_cheap_checks_cannot() {
    let env = envelope();
    let roots = root(&env);
    let mut v = verifier();
    // A different y passes every string check and fails the proof.
    let mut forged = env.clone();
    forged["proof"]["snarkProof"]["publicSignals"]["y"] = "12345".into();
    let (_, job) = v
        .precheck(&forged, &roots, Binding::Target, NOW)
        .ok()
        .unwrap();
    assert_eq!(
        pairing_refusal(job.run()),
        Some(Refusal::Reason("invalid-proof".into()))
    );
    // A proof point off the curve is a parse failure, reported as verify-threw.
    let mut broken = env.clone();
    broken["proof"]["snarkProof"]["proof"]["pi_a"][0] = "1".into();
    let (_, job) = v
        .precheck(&broken, &roots, Binding::Target, NOW)
        .ok()
        .unwrap();
    assert_eq!(
        pairing_refusal(job.run()),
        Some(Refusal::Reason(
            "verify-threw:proof pi_a is not a G1 point".into()
        ))
    );
}
