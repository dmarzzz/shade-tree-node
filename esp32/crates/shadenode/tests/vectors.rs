//! Byte-for-byte conformance with the golden wire-format vectors (`testdata/vectors.json`).

use microtor::crypto::EdExpanded;
use microtor::hsdesc::onion_address;
use microtor::util::{hex_decode, hex_encode};
use serde_json::Value;
use shadenode::heartbeat::operator_auth_message;
use shadenode::proto::{
    artifact_id_of, calculate_signal_hash, canonical_announce_bytes, canonical_caps_bytes,
    request_signal, Caps,
};

fn vectors() -> Value {
    serde_json::from_str(include_str!("../../../../testdata/vectors.json")).unwrap()
}

fn text(v: &Value) -> &str {
    v.as_str().unwrap()
}

fn identity(v: &Value) -> EdExpanded {
    let seed: [u8; 32] = hex_decode(text(&v["onionSeed"]))
        .unwrap()
        .try_into()
        .unwrap();
    EdExpanded::from_seed(&seed)
}

fn caps_from(json: &Value) -> Caps {
    let strings = |key: &str| -> Vec<String> {
        json[key]
            .as_array()
            .map(|a| a.iter().map(|s| text(s).to_string()).collect())
            .unwrap_or_default()
    };
    Caps {
        ports: json["ports"]
            .as_array()
            .map(|a| a.iter().map(|p| p.as_u64().unwrap() as u16).collect())
            .unwrap_or_default(),
        region: json["region"].as_str().map(str::to_string),
        artifacts: strings("artifacts"),
        admits: strings("admits"),
        rate: json.get("rate").map(|r| shadenode::proto::RatePolicy {
            epoch_seconds: r["epochSeconds"].as_u64().unwrap(),
            root_freshness_seconds: r["rootFreshnessSeconds"].as_u64().unwrap(),
            payload_bytes_per_slot: r["payloadBytesPerSlot"].as_u64().unwrap(),
        }),
        session: json["session"]["classes"]
            .as_array()
            .map(|a| a.iter().map(|s| text(s).to_string()).collect())
            .unwrap_or_default(),
        draining: json["draining"] == Value::Bool(true),
        sets: strings("sets"),
        omit_proto: json.get("proto").is_none(),
    }
}

#[test]
fn onion_address_and_announce() {
    let v = vectors();
    let id = identity(&v);
    assert_eq!(hex_encode(&id.public), text(&v["onionPub"]));
    assert_eq!(onion_address(&id.public), text(&v["onion"]));
    let a = &v["announce"];
    let bytes = canonical_announce_bytes(
        text(&a["onion"]),
        a["weight"].as_u64().unwrap(),
        a["ts"].as_u64().unwrap(),
        text(&a["nonce"]),
        None,
    );
    assert_eq!(hex_encode(&bytes), text(&v["canonicalAnnounceBytesHex"]));
    assert_eq!(hex_encode(&id.sign(&bytes)), text(&v["announceOnionSig"]));
    assert_eq!(
        operator_auth_message(text(&v["onion"]), text(&v["operator"])),
        text(&v["operatorAuthMessage"])
    );
}

#[test]
fn capabilities_bytes_and_signatures() {
    let v = vectors();
    let id = identity(&v);
    let onion = text(&v["onion"]);
    let cases = [
        &v["capabilities"],
        &v["capabilitiesDraining"],
        &v["capabilitiesSets"],
        &v["artifacts"]["capsWithArtifacts"],
        &v["sessionTickets"]["capsWithSession"],
    ];
    for case in cases {
        let caps_json = caps_from(&case["caps"]).canonical_json().unwrap();
        let bytes = canonical_caps_bytes(onion, &caps_json);
        assert_eq!(
            hex_encode(&bytes),
            text(&case["canonicalCapsBytesHex"]),
            "{caps_json}"
        );
        assert_eq!(hex_encode(&id.sign(&bytes)), text(&case["capsSig"]));
    }
    // An announce that carries caps signs them after the nonce.
    let a = &v["announce"];
    let caps_json = caps_from(&v["capabilities"]["caps"])
        .canonical_json()
        .unwrap();
    let bytes = canonical_announce_bytes(
        onion,
        a["weight"].as_u64().unwrap(),
        a["ts"].as_u64().unwrap(),
        text(&a["nonce"]),
        Some(&caps_json),
    );
    let pinned = &v["capabilities"]["announceWithCaps"];
    assert_eq!(hex_encode(&bytes), text(&pinned["canonicalBytesHex"]));
    assert_eq!(hex_encode(&id.sign(&bytes)), text(&pinned["onionSig"]));
}

#[test]
fn receipt_bytes_and_signature() {
    let v = vectors();
    let id = identity(&v);
    let r = &v["receipt"];
    let epoch: u64 = text(&r["epoch"]).parse().unwrap();
    let bytes = shadenode::proto::canonical_receipt_bytes(text(&r["onion"]), epoch);
    assert_eq!(hex_encode(&bytes), text(&r["canonicalReceiptBytesHex"]));
    let receipt: Value = serde_json::from_str(&shadenode::proto::build_receipt(
        &id,
        text(&r["onion"]),
        epoch,
    ))
    .unwrap();
    assert_eq!(receipt["sig"], r["receiptOnionSig"]);
    assert_eq!(receipt["epoch"], r["epoch"]);
}

#[test]
fn signal_hash_and_artifact_id() {
    let v = vectors();
    let s = &v["signalHash"];
    let message = request_signal(text(&s["target"]), text(&s["nonce"]));
    assert_eq!(message, text(&s["message"]));
    assert_eq!(
        calculate_signal_hash(&message),
        text(&s["signalHashDecimal"])
    );
    let sample = &v["artifacts"]["sample"];
    assert_eq!(
        artifact_id_of(
            text(&sample["circuit"]),
            text(&sample["inputUtf8"]).as_bytes()
        ),
        text(&sample["artifactId"])
    );
}
