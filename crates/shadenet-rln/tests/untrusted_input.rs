//! Malformed input from files or an RPC must be an error, never a panic: release builds abort on
//! panic, which would take a long-running proxy down with it.

use shadenet_rln::prover::{build_envelope, EnvelopeInput};
use shadenet_rln::tree::parse_fr;

const MODULUS: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

#[test]
fn field_elements_parse_strictly() {
    assert_eq!(parse_fr("16").unwrap(), parse_fr("0x10").unwrap());
    assert!(parse_fr(" 16 ").is_ok());
    for bad in ["", "0x", "-1", "1e3", "12a", "0xzz", "not a number"] {
        assert!(parse_fr(bad).is_err(), "{bad:?} must be rejected");
    }
    assert!(
        parse_fr(MODULUS).is_err(),
        "the modulus itself is out of field"
    );
    let below = "21888242871839275222246405745257275088548364400416034343698204186575808495616";
    assert!(parse_fr(below).is_ok());
}

fn input(members: Vec<String>, leaf: &str, secret: &str) -> EnvelopeInput {
    EnvelopeInput {
        identity_secret: secret.into(),
        member_leaf: leaf.into(),
        members,
        target: "example.com:443".into(),
        nonce: "00112233445566778899aabbccddeeff".into(),
        epoch: 1,
        rln_identifier: "1".into(),
        user_message_limit: 1,
        message_id: 0,
        circuits_dir: None,
    }
}

#[test]
fn the_prover_refuses_malformed_members_and_secrets_without_panicking() {
    let error = build_envelope(&input(vec!["garbage".into()], "1", "1"))
        .err()
        .unwrap();
    assert!(error.contains("members[0]"), "{error}");
    let error = build_envelope(&input(vec!["1".into(), MODULUS.into()], "1", "1"))
        .err()
        .unwrap();
    assert!(error.contains("members[1]"), "{error}");
    let error = build_envelope(&input(vec!["1".into()], "0xnope", "1"))
        .err()
        .unwrap();
    assert!(error.contains("member_leaf"), "{error}");
}
