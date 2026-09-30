//! Wire-format conformance harness (T-RUST-1).
//!
//! Reads the byte-pinned golden fixtures in `testdata/vectors.json` (the same file
//! the JS reference produced) and asserts the Rust deterministic primitives in
//! `shadenet-proto` reproduce every pinned value exactly. Where a value is byte-pinned
//! the assertion is byte/hex equality; ed25519 verify additionally checks a flipped
//! bit is rejected.
//!
//! Only the functions with a vector in the fixture are exercised here.
//! `calculate_signal_hash` is now conformance-checked against the `signalHash` vector
//! (T-RUST-1b). Announcement verification is covered across onion control,
//! EIP-191 operator recovery, freshness, and replay state.

use serde_json::Value;
use shadenet_proto::{
    accept_envelope_version, calculate_signal_hash, canonical_announce_bytes, canonical_caps_bytes,
    canonical_directory_bytes, canonical_receipt_bytes, ed25519_public_key, ed25519_sign,
    ed25519_verify, onion_to_pubkey, operator_auth_message, pubkey_to_onion, request_signal,
    select_proto_version, sign_receipt, verify_announce, verify_caps_sig, verify_directory,
    verify_directory_threshold, verify_operator_sig, verify_receipt, Announce, Caps, Directory,
    EnvelopeVersion, GatewayEntry, PayCaps, ProtoCaps, RateCaps, Receipt, REASON_BAD_VERSION,
    REASON_NO_MUTUAL_VERSION, REASON_UNSUPPORTED_VERSION,
};

/// Load `testdata/vectors.json` relative to this crate's manifest dir.
fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../testdata/vectors.json");
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    serde_json::from_str(&raw).expect("vectors.json is valid JSON")
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("vector field {k} missing or not a string"))
}

fn seed32(hexstr: &str) -> [u8; 32] {
    hex::decode(hexstr).unwrap().try_into().unwrap()
}

fn pub32(hexstr: &str) -> [u8; 32] {
    hex::decode(hexstr).unwrap().try_into().unwrap()
}

/// Build the exact directory the fixture's `canonicalDirectoryBytesHex` /
/// `directorySignature` were produced over (spec 9 table): version 1, issued
/// 1000000, one gateway { onion, pubkey: onionPub, weight: 100, health: "up" }.
fn vector_directory(v: &Value) -> Directory {
    Directory {
        version: 1,
        issued: 1_000_000,
        gateways: vec![GatewayEntry {
            onion: s(v, "onion").to_string(),
            pubkey: s(v, "onionPub").to_string(),
            weight: 100,
            health: "up".to_string(),
            operator: None,
            staked: None,
            caps: None,
            caps_sig: None,
        }],
        signer: Some(s(v, "signerPub").to_string()),
        signature: Some(s(v, "directorySignature").to_string()),
        signers: None,
        signatures: None,
        threshold: None,
    }
}

/// Build the announce record from the fixture's `announce` object.
fn vector_announce(v: &Value) -> Announce {
    let a = &v["announce"];
    Announce {
        v: a["v"].as_u64().unwrap(),
        onion: a["onion"].as_str().unwrap().to_string(),
        weight: a["weight"].as_u64().unwrap(),
        ts: a["ts"].as_u64().unwrap(),
        nonce: a["nonce"].as_str().unwrap().to_string(),
        onion_sig: Some(s(v, "announceOnionSig").to_string()),
        operator: None,
        operator_sig: None,
        caps: None,
        caps_sig: None,
    }
}

#[test]
fn verify_announce_checks_eip191_freshness_and_replay() {
    let v = vectors();
    let mut ann = vector_announce(&v);
    ann.operator = Some(
        v["operatorAnnounce"]["operator"]
            .as_str()
            .unwrap()
            .to_string(),
    );
    ann.operator_sig = Some(
        v["operatorAnnounce"]["operatorSig"]
            .as_str()
            .unwrap()
            .to_string(),
    );
    assert!(verify_operator_sig(
        &ann.onion,
        ann.operator.as_deref().unwrap(),
        ann.operator_sig.as_deref().unwrap()
    ));

    let mut seen = std::collections::HashSet::new();
    verify_announce(&ann, ann.ts, 120, Some(&mut seen)).expect("valid announce");
    assert_eq!(
        verify_announce(&ann, ann.ts, 120, Some(&mut seen))
            .unwrap_err()
            .to_string(),
        "replayed-nonce"
    );

    let mut fresh_seen = std::collections::HashSet::new();
    assert_eq!(
        verify_announce(&ann, ann.ts + 121, 120, Some(&mut fresh_seen))
            .unwrap_err()
            .to_string(),
        format!("stale-ts:{}", ann.ts)
    );
    assert!(
        fresh_seen.is_empty(),
        "a rejected announce must not burn its nonce"
    );

    let mut bad_operator = ann.clone();
    bad_operator.operator = Some("0x000000000000000000000000000000000000dead".into());
    assert_eq!(
        verify_announce(&bad_operator, bad_operator.ts, 120, None)
            .unwrap_err()
            .to_string(),
        "bad-operator-sig"
    );
}

// -- 1. onion <-> pubkey (spec 2) ------------------------------------------

#[test]
fn onion_to_pubkey_matches_vector() {
    let v = vectors();
    let derived = onion_to_pubkey(s(&v, "onion")).expect("valid v3 onion");
    assert_eq!(hex::encode(derived), s(&v, "onionPub"));
}

#[test]
fn pubkey_to_onion_matches_vector() {
    let v = vectors();
    let onion = pubkey_to_onion(&pub32(s(&v, "onionPub")));
    assert_eq!(onion, s(&v, "onion"));
}

#[test]
fn onion_roundtrip_and_checksum_rejects_tamper() {
    let v = vectors();
    let pk = pub32(s(&v, "onionPub"));
    // round trip pubkey -> onion -> pubkey
    assert_eq!(onion_to_pubkey(&pubkey_to_onion(&pk)).unwrap(), pk);
    // flip one base32 char in the address body => checksum mismatch (or version).
    let onion = s(&v, "onion");
    let mut chars: Vec<char> = onion.strip_suffix(".onion").unwrap().chars().collect();
    chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
    let tampered: String = chars.into_iter().collect::<String>() + ".onion";
    assert!(
        onion_to_pubkey(&tampered).is_err(),
        "tampered onion must fail"
    );
    // wrong length.
    assert!(onion_to_pubkey("abc.onion").is_err());
}

// -- 2. canonical byte encodings (spec 1) ----------------------------------

#[test]
fn canonical_directory_bytes_matches_vector() {
    let v = vectors();
    let bytes = canonical_directory_bytes(&vector_directory(&v));
    assert_eq!(hex::encode(&bytes), s(&v, "canonicalDirectoryBytesHex"));
}

#[test]
fn canonical_announce_bytes_matches_vector() {
    let v = vectors();
    let bytes = canonical_announce_bytes(&vector_announce(&v));
    assert_eq!(hex::encode(&bytes), s(&v, "canonicalAnnounceBytesHex"));
}

// -- 3. ed25519 key derivation + sign/verify (spec 6.5) --------------------

#[test]
fn ed25519_public_key_matches_vectors() {
    let v = vectors();
    assert_eq!(
        hex::encode(ed25519_public_key(&seed32(s(&v, "signerSeed")))),
        s(&v, "signerPub")
    );
    assert_eq!(
        hex::encode(ed25519_public_key(&seed32(s(&v, "onionSeed")))),
        s(&v, "onionPub")
    );
}

#[test]
fn ed25519_sign_matches_pinned_signatures() {
    let v = vectors();
    let dir_bytes = canonical_directory_bytes(&vector_directory(&v));
    assert_eq!(
        hex::encode(ed25519_sign(&dir_bytes, &seed32(s(&v, "signerSeed")))),
        s(&v, "directorySignature")
    );
    let ann_bytes = canonical_announce_bytes(&vector_announce(&v));
    assert_eq!(
        hex::encode(ed25519_sign(&ann_bytes, &seed32(s(&v, "onionSeed")))),
        s(&v, "announceOnionSig")
    );
}

#[test]
fn ed25519_verify_accepts_pinned_and_rejects_flipped_bit() {
    let v = vectors();

    // directory signature verifies under signerPub
    let dir_bytes = canonical_directory_bytes(&vector_directory(&v));
    let dir_sig: [u8; 64] = hex::decode(s(&v, "directorySignature"))
        .unwrap()
        .try_into()
        .unwrap();
    assert!(ed25519_verify(
        &dir_bytes,
        &dir_sig,
        &pub32(s(&v, "signerPub"))
    ));

    // announce onion signature verifies under onionPub
    let ann_bytes = canonical_announce_bytes(&vector_announce(&v));
    let ann_sig: [u8; 64] = hex::decode(s(&v, "announceOnionSig"))
        .unwrap()
        .try_into()
        .unwrap();
    assert!(ed25519_verify(
        &ann_bytes,
        &ann_sig,
        &pub32(s(&v, "onionPub"))
    ));

    // a flipped signature bit must be rejected
    let mut bad_sig = dir_sig;
    bad_sig[0] ^= 0x01;
    assert!(!ed25519_verify(
        &dir_bytes,
        &bad_sig,
        &pub32(s(&v, "signerPub"))
    ));

    // a flipped message bit must be rejected
    let mut bad_msg = dir_bytes.clone();
    bad_msg[0] ^= 0x01;
    assert!(!ed25519_verify(
        &bad_msg,
        &dir_sig,
        &pub32(s(&v, "signerPub"))
    ));
}

// -- 4. verify_directory (spec 4.3) ----------------------------------------

#[test]
fn verify_directory_accepts_pinned_signer() {
    let v = vectors();
    verify_directory(&vector_directory(&v), s(&v, "signerPub"))
        .expect("vector directory must verify under its pinned signer");
}

#[test]
fn verify_directory_rejects_wrong_signer() {
    let v = vectors();
    // Verify under a different valid ed25519 pubkey (the onion key, not the signer).
    let err = verify_directory(&vector_directory(&v), s(&v, "onionPub")).unwrap_err();
    // signer field is signerPub, pinned is onionPub => signer-not-pinned fires first.
    assert_eq!(err.to_string(), "signer-not-pinned");

    // Strip the signer label so the check falls through to the crypto verify.
    let mut dir = vector_directory(&v);
    dir.signer = None;
    let err = verify_directory(&dir, s(&v, "onionPub")).unwrap_err();
    assert_eq!(err.to_string(), "bad-signature");
}

#[test]
fn verify_directory_rejects_grafted_onion() {
    let v = vectors();
    // Graft a different onion under the (still signed) pubkey: the onion<->pubkey
    // binding must reject it. Re-sign so we get PAST bad-signature to the binding check.
    let mut dir = vector_directory(&v);
    // A valid but DIFFERENT onion (derived from the signer key) grafted onto the entry.
    dir.gateways[0].onion = pubkey_to_onion(&pub32(s(&v, "signerPub")));
    let signed_bytes = canonical_directory_bytes(&dir);
    let resig = ed25519_sign(&signed_bytes, &seed32(s(&v, "signerSeed")));
    dir.signature = Some(hex::encode(resig));
    let err = verify_directory(&dir, s(&v, "signerPub")).unwrap_err();
    assert!(
        err.to_string().starts_with("pubkey-onion-mismatch:"),
        "expected pubkey-onion-mismatch, got {err}"
    );

    // Also reject an unsigned directory.
    let mut unsigned = vector_directory(&v);
    unsigned.signature = None;
    assert_eq!(
        verify_directory(&unsigned, s(&v, "signerPub"))
            .unwrap_err()
            .to_string(),
        "unsigned"
    );
}

// -- 5. operator auth message + request signal (deterministic, no crypto) --

#[test]
fn operator_auth_message_matches_vector() {
    let v = vectors();
    let got = operator_auth_message(s(&v, "onion"), s(&v, "operator"));
    assert_eq!(got, s(&v, "operatorAuthMessage"));
}

#[test]
fn request_signal_shape() {
    // No fixture value; assert the documented spec-6.2 shape (literal newlines).
    assert_eq!(request_signal("t", "n"), "shade-tree:v4\nt\nn");
}

// -- 6. calculate_signal_hash (spec 6.2, keccak256 >> 8) -------------------

#[test]
fn calculate_signal_hash_matches_vector() {
    let v = vectors();
    let sh = &v["signalHash"];
    let target = sh["target"].as_str().unwrap();
    let nonce = sh["nonce"].as_str().unwrap();
    let want = sh["signalHashDecimal"].as_str().unwrap();
    // request_signal(target, nonce) -> calculate_signal_hash must equal the pinned decimal.
    let got = calculate_signal_hash(&request_signal(target, nonce));
    assert_eq!(
        got, want,
        "signal hash decimal must match the pinned vector"
    );
    // The fixture also pins the exact message the hash is taken over; hashing it directly
    // must give the same value (guards request_signal + the hash jointly).
    assert_eq!(calculate_signal_hash(sh["message"].as_str().unwrap()), want);
}

// -- 7. receipt (spec T-FEAT-13, lib/receipt.mjs) --------------------------

/// Build the `Receipt` pinned in the fixture's `receipt` block.
fn vector_receipt(v: &Value) -> Receipt {
    let r = &v["receipt"];
    Receipt {
        v: r["v"].as_u64().unwrap(),
        onion: r["onion"].as_str().unwrap().to_string(),
        epoch: r["epoch"].as_str().unwrap().to_string(),
        ok: r["ok"].as_bool().unwrap(),
        sig: Some(r["receiptOnionSig"].as_str().unwrap().to_string()),
    }
}

#[test]
fn receipt_domain_matches_vector() {
    let v = vectors();
    assert_eq!(
        shadenet_proto::RECEIPT_DOMAIN,
        s(&v["receipt"], "receiptDomain")
    );
}

#[test]
fn canonical_receipt_bytes_matches_vector() {
    let v = vectors();
    let r = &v["receipt"];
    let bytes = canonical_receipt_bytes(
        r["v"].as_u64().unwrap(),
        r["onion"].as_str().unwrap(),
        r["epoch"].as_str().unwrap(),
        r["ok"].as_bool().unwrap(),
    );
    assert_eq!(hex::encode(&bytes), s(r, "canonicalReceiptBytesHex"));
}

#[test]
fn receipt_signature_matches_pinned() {
    let v = vectors();
    let r = &v["receipt"];
    // Re-sign the canonical bytes with the SAME onion seed the fixture used (onionSeed);
    // ed25519 is RFC 8032 deterministic, so the signature must byte-match receiptOnionSig.
    let onion_seed = seed32(s(&v, "onionSeed"));
    let sig = sign_receipt(
        r["v"].as_u64().unwrap(),
        r["onion"].as_str().unwrap(),
        r["epoch"].as_str().unwrap(),
        r["ok"].as_bool().unwrap(),
        &onion_seed,
    );
    assert_eq!(hex::encode(sig), s(r, "receiptOnionSig"));
}

#[test]
fn verify_receipt_accepts_pinned() {
    let v = vectors();
    let rec = vector_receipt(&v);
    // Signature-only + onion binding (epoch skew skipped: the pinned epoch is a fixed old
    // bucket, deliberately not "now"). Binds to the receipt's own onion.
    let ok = verify_receipt(&rec, Some(rec.onion.as_str()), None, 1)
        .expect("pinned receipt must verify under its own onion");
    assert_eq!(ok.onion, rec.onion);
    assert_eq!(ok.epoch, rec.epoch);
    // The recovered pubkey is exactly onionPub.
    assert_eq!(hex::encode(ok.pubkey), s(&v, "onionPub"));
    // And it also verifies with no onion binding at all.
    verify_receipt(&rec, None, None, 1).expect("verifies with no onion binding");
    // Freshness: within skew of the pinned epoch is accepted.
    verify_receipt(&rec, None, Some(&rec.epoch), 1).expect("same-epoch is fresh");
}

#[test]
fn verify_receipt_rejects_tamper_and_wrong_onion() {
    let v = vectors();
    let rec = vector_receipt(&v);

    // wrong onion binding -> onion-mismatch (a DIFFERENT valid onion, the signer key's).
    let other = pubkey_to_onion(&pub32(s(&v, "signerPub")));
    assert_eq!(
        verify_receipt(&rec, Some(&other), None, 1)
            .unwrap_err()
            .to_string(),
        "onion-mismatch"
    );

    // flipped signature bit -> bad-sig.
    let mut bad = rec.clone();
    let mut sig = hex::decode(rec.sig.as_ref().unwrap()).unwrap();
    sig[0] ^= 0x01;
    bad.sig = Some(hex::encode(sig));
    assert_eq!(
        verify_receipt(&bad, None, None, 1).unwrap_err().to_string(),
        "bad-sig"
    );

    // ok=false -> not-success.
    let mut notok = rec.clone();
    notok.ok = false;
    assert_eq!(
        verify_receipt(&notok, None, None, 1)
            .unwrap_err()
            .to_string(),
        "not-success"
    );

    // wrong version -> bad-version:<v>.
    let mut badv = rec.clone();
    badv.v = 2;
    assert_eq!(
        verify_receipt(&badv, None, None, 1)
            .unwrap_err()
            .to_string(),
        "bad-version:2"
    );

    // non-canonical epoch -> bad-epoch (signed bytes would differ; guard fires first).
    let mut bade = rec.clone();
    bade.epoch = "08333".to_string(); // leading zero
    assert_eq!(
        verify_receipt(&bade, None, None, 1)
            .unwrap_err()
            .to_string(),
        "bad-epoch"
    );

    // stale epoch (skew exceeded) -> stale-epoch:<epoch>.
    let far: u64 = rec.epoch.parse::<u64>().unwrap() + 100;
    assert_eq!(
        verify_receipt(&rec, None, Some(&far.to_string()), 1)
            .unwrap_err()
            .to_string(),
        format!("stale-epoch:{}", rec.epoch)
    );

    // missing signature -> bad-sig.
    let mut unsigned = rec.clone();
    unsigned.sig = None;
    assert_eq!(
        verify_receipt(&unsigned, None, None, 1)
            .unwrap_err()
            .to_string(),
        "bad-sig"
    );
}

// -- 8. version-negotiation reason labels (protoReasons vector) ------------

#[test]
fn proto_reason_labels_match_vector() {
    let v = vectors();
    let p = &v["protoReasons"];
    // The bounded reason LABELS/prefixes the Rust client emits must match the pinned literals.
    assert_eq!(REASON_BAD_VERSION, s(p, "badVersion"));
    assert_eq!(REASON_UNSUPPORTED_VERSION, s(p, "unsupportedVersion"));
    assert_eq!(REASON_NO_MUTUAL_VERSION, s(p, "noMutualVersion"));

    // And the runtime reasons carry those exact prefixes.
    let range = (shadenet_proto::PROTO_MIN, shadenet_proto::PROTO_MAX);
    let bad = accept_envelope_version(&EnvelopeVersion::Garbage("\"x\"".into()), range)
        .unwrap_err()
        .to_string();
    assert!(
        bad.starts_with(&format!("{}:", s(p, "badVersion"))),
        "got {bad}"
    );

    let unsup = accept_envelope_version(&EnvelopeVersion::Int(9), range)
        .unwrap_err()
        .to_string();
    assert_eq!(unsup, format!("{}:9", s(p, "unsupportedVersion")));

    let nomut = select_proto_version(Some((5, 6)), (1, 2))
        .unwrap_err()
        .to_string();
    assert!(
        nomut.starts_with(&format!("{}:", s(p, "noMutualVersion"))),
        "got {nomut}"
    );
}

// -- 9. threshold (M-of-N) directory (T-FEAT-9b, lib/directory.mjs) ---------
//
// Consumes the `thresholdDirectory` vector: a 2-of-3 directory whose 3 signatures
// (fixed test seeds, RFC 8032 deterministic) are byte-pinned. Every check byte-matches
// the JS `verifyDirectoryThreshold` behavior.

/// String array field of an object as `Vec<String>`.
fn strvec(v: &Value, k: &str) -> Vec<String> {
    v.get(k)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("vector field {k} missing or not an array"))
        .iter()
        .map(|x| x.as_str().expect("array element is a string").to_string())
        .collect()
}

/// Build the threshold `Directory` pinned in the fixture's `thresholdDirectory` block.
/// Its single gateway matches the single-sig `onion`/`onionPub` (weight 100, health "up"),
/// so its `canonical_directory_bytes` are byte-IDENTICAL to `canonicalDirectoryBytesHex`.
fn threshold_directory(v: &Value) -> Directory {
    let td = &v["thresholdDirectory"];
    Directory {
        version: td["version"].as_u64().unwrap(),
        issued: td["issued"].as_u64().unwrap(),
        gateways: vec![GatewayEntry {
            onion: td["onion"].as_str().unwrap().to_string(),
            pubkey: td["onionPub"].as_str().unwrap().to_string(),
            weight: 100,
            health: "up".to_string(),
            operator: None,
            staked: None,
            caps: None,
            caps_sig: None,
        }],
        signer: None,
        signature: None,
        signers: Some(strvec(td, "signers")),
        signatures: Some(strvec(td, "signatures")),
        threshold: Some(td["threshold"].as_i64().unwrap()),
    }
}

/// The three pinned signer pubkeys from the vector.
fn threshold_pins(v: &Value) -> Vec<String> {
    strvec(&v["thresholdDirectory"], "signers")
}

#[test]
fn threshold_canonical_bytes_are_identical_to_single_sig() {
    // The whole additive-extension claim: the threshold fields are EXCLUDED from the
    // canonical bytes, so a threshold directory over the same {version,issued,gateways}
    // hashes byte-for-byte the same as the single-sig `canonicalDirectoryBytesHex`.
    let v = vectors();
    let bytes = canonical_directory_bytes(&threshold_directory(&v));
    assert_eq!(hex::encode(&bytes), s(&v, "canonicalDirectoryBytesHex"));
}

#[test]
fn threshold_directory_accepts_valid_2_of_3() {
    let v = vectors();
    let dir = threshold_directory(&v);
    let pins = threshold_pins(&v);
    let pin_refs: Vec<&str> = pins.iter().map(String::as_str).collect();
    // All three signatures are valid; threshold is 2 => verifies, and every distinct
    // pinned signer is counted (3 >= 2).
    let matched = verify_directory_threshold(&dir, &pin_refs)
        .expect("valid 2-of-3 must verify under the pinned set");
    assert_eq!(matched.len(), 3, "all three pinned signers verify");
    for p in &pins {
        assert!(matched.contains(p), "matched set includes {p}");
    }
    // A pinned 2-subset (drop one signer) still meets the 2-of-3 threshold.
    let two: Vec<&str> = pin_refs.iter().take(2).copied().collect();
    let m2 = verify_directory_threshold(&dir, &two).expect("2 pinned signers meet threshold 2");
    assert_eq!(m2.len(), 2);
}

#[test]
fn threshold_directory_one_pinned_signer_not_met() {
    let v = vectors();
    let dir = threshold_directory(&v);
    let pins = threshold_pins(&v);
    // Only ONE signer pinned => at most one distinct valid sig => below threshold 2.
    let err = verify_directory_threshold(&dir, &[pins[0].as_str()])
        .unwrap_err()
        .to_string();
    assert_eq!(err, "threshold-not-met:1/2");

    // The single-sig `verify_directory` entry point DELEGATES to the threshold rule
    // (it must NOT treat a threshold directory as `unsigned` — the T-FEAT-9b bug).
    // With one pinned signer it reaches the same threshold-not-met, not "unsigned".
    let err2 = verify_directory(&dir, pins[0].as_str())
        .unwrap_err()
        .to_string();
    assert_eq!(err2, "threshold-not-met:1/2");
}

#[test]
fn threshold_directory_rejects_duplicate_unpinned_and_bad_shapes() {
    let v = vectors();
    let pins = threshold_pins(&v);
    let sigs = strvec(&v["thresholdDirectory"], "signatures");
    let pin_refs: Vec<&str> = pins.iter().map(String::as_str).collect();

    // DUPLICATE: the same pinned signer listed 3x with its own valid sig is counted ONCE,
    // so a 2-of-N cannot be self-satisfied by one key => threshold-not-met:1/2.
    let mut dup = threshold_directory(&v);
    dup.signers = Some(vec![pins[0].clone(), pins[0].clone(), pins[0].clone()]);
    dup.signatures = Some(vec![sigs[0].clone(), sigs[0].clone(), sigs[0].clone()]);
    assert_eq!(
        verify_directory_threshold(&dup, &pin_refs)
            .unwrap_err()
            .to_string(),
        "threshold-not-met:1/2"
    );

    // UNPINNED: pin only signer[2]; signers[0]/[1] are ignored though their sigs are valid
    // => one distinct pinned+valid => threshold-not-met:1/2.
    let dir = threshold_directory(&v);
    assert_eq!(
        verify_directory_threshold(&dir, &[pins[2].as_str()])
            .unwrap_err()
            .to_string(),
        "threshold-not-met:1/2"
    );

    // TAMPERED: flip a bit in two of the three sigs => only one distinct valid => not met.
    let mut tam = threshold_directory(&v);
    let mut s0 = hex::decode(&sigs[0]).unwrap();
    s0[0] ^= 0x01;
    let mut s1 = hex::decode(&sigs[1]).unwrap();
    s1[0] ^= 0x01;
    tam.signatures = Some(vec![hex::encode(s0), hex::encode(s1), sigs[2].clone()]);
    assert_eq!(
        verify_directory_threshold(&tam, &pin_refs)
            .unwrap_err()
            .to_string(),
        "threshold-not-met:1/2"
    );

    // bad-threshold: absent, zero, and negative all reject (mirrors JS `!isInteger || < 1`).
    for bad in [None, Some(0), Some(-1)] {
        let mut d = threshold_directory(&v);
        d.threshold = bad;
        assert_eq!(
            verify_directory_threshold(&d, &pin_refs)
                .unwrap_err()
                .to_string(),
            "bad-threshold"
        );
    }

    // bad-signatures: missing signatures array, or unequal lengths.
    let mut nosig = threshold_directory(&v);
    nosig.signatures = None;
    assert_eq!(
        verify_directory_threshold(&nosig, &pin_refs)
            .unwrap_err()
            .to_string(),
        "bad-signatures"
    );
    let mut mismatch = threshold_directory(&v);
    mismatch.signatures = Some(vec![sigs[0].clone()]); // 3 signers, 1 signature
    assert_eq!(
        verify_directory_threshold(&mismatch, &pin_refs)
            .unwrap_err()
            .to_string(),
        "bad-signatures"
    );

    // threshold-exceeds-signers: an unsatisfiable threshold > N.
    let mut over = threshold_directory(&v);
    over.threshold = Some(5); // only 3 signers provided
    assert_eq!(
        verify_directory_threshold(&over, &pin_refs)
            .unwrap_err()
            .to_string(),
        "threshold-exceeds-signers"
    );

    // TOTAL on garbage signer/signature hex: non-hex entries simply do not verify
    // (never panic) => below threshold, not a crash.
    let mut garbage = threshold_directory(&v);
    garbage.signers = Some(vec!["zz".into(), pins[1].clone(), pins[2].clone()]);
    garbage.signatures = Some(vec!["nothex".into(), sigs[1].clone(), sigs[2].clone()]);
    // signers[1] and signers[2] are still valid+pinned => 2 distinct => meets threshold 2.
    let ok = verify_directory_threshold(&garbage, &pin_refs)
        .expect("two valid pinned sigs still meet the threshold despite one garbage entry");
    assert_eq!(ok.len(), 2);
}

#[test]
fn threshold_directory_rejects_grafted_onion() {
    // Once the threshold is met, the gateway onion<->pubkey binding is still enforced
    // (shared with the single-sig path). Graft a different onion under the entry and it
    // must reject `pubkey-onion-mismatch:` — the signatures still verify (bytes exclude
    // gateways? no: gateways ARE signed) so we must NOT resign; instead assert the binding
    // fails AFTER threshold. Here we keep the signed onion but swap only `pubkey`.
    let v = vectors();
    let pins = threshold_pins(&v);
    let pin_refs: Vec<&str> = pins.iter().map(String::as_str).collect();
    let mut dir = threshold_directory(&v);
    // Swap the pubkey to the signer key's (a valid but WRONG key for this onion). This
    // changes the canonical bytes, so re-sign all three over the tampered bytes so we get
    // PAST threshold-not-met to the binding check (mirrors the single-sig grafted test).
    dir.gateways[0].pubkey = s(&v, "signerPub").to_string();
    let tampered_bytes = canonical_directory_bytes(&dir);
    let seeds = strvec(&v["thresholdDirectory"], "signerSeeds");
    let resigs: Vec<String> = seeds
        .iter()
        .map(|seed| {
            let sk: [u8; 32] = hex::decode(seed).unwrap().try_into().unwrap();
            hex::encode(ed25519_sign(&tampered_bytes, &sk))
        })
        .collect();
    dir.signatures = Some(resigs);
    let err = verify_directory_threshold(&dir, &pin_refs)
        .unwrap_err()
        .to_string();
    assert!(
        err.starts_with("pubkey-onion-mismatch:"),
        "expected pubkey-onion-mismatch, got {err}"
    );
}

// -- 10. gateway capability advertisement (T-FEAT-10c, lib/directory.mjs) ----
//
// Consumes the `capabilities` vector: caps normalized to fixed {ports,region,proto},
// an onion-bound `capsSig`, and both caps-carrying canonical byte hexes (announce +
// directory). Every value here is byte-pinned (RFC 8032 deterministic capsSig).

/// The caps object pinned in the fixture's `capabilities.caps` block.
fn vector_caps(v: &Value) -> Caps {
    let c = &v["capabilities"]["caps"];
    Caps {
        ports: Some(
            c["ports"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_i64().unwrap())
                .collect(),
        ),
        region: Some(c["region"].as_str().unwrap().to_string()),
        proto: Some(ProtoCaps {
            min: c["proto"]["min"].as_i64().unwrap(),
            max: c["proto"]["max"].as_i64().unwrap(),
        }),
        ..Default::default()
    }
}

/// The caps-carrying directory pinned in `capabilities.directoryWithCaps`: the single-sig
/// gateway plus `caps` + the onion-bound `capsSig`, signed by the bootnode signer key.
fn directory_with_caps(v: &Value) -> Directory {
    Directory {
        version: 1,
        issued: 1_000_000,
        gateways: vec![GatewayEntry {
            onion: s(v, "onion").to_string(),
            pubkey: s(v, "onionPub").to_string(),
            weight: 100,
            health: "up".to_string(),
            operator: None,
            staked: None,
            caps: Some(vector_caps(v)),
            caps_sig: Some(s(&v["capabilities"], "capsSig").to_string()),
        }],
        signer: Some(s(v, "signerPub").to_string()),
        signature: Some(
            v["capabilities"]["directoryWithCaps"]["signature"]
                .as_str()
                .unwrap()
                .to_string(),
        ),
        signers: None,
        signatures: None,
        threshold: None,
    }
}

#[test]
fn caps_domain_matches_vector() {
    let v = vectors();
    assert_eq!(
        shadenet_proto::CAPS_DOMAIN,
        s(&v["capabilities"], "capsDomain")
    );
}

#[test]
fn canonical_caps_bytes_matches_vector() {
    let v = vectors();
    let bytes = canonical_caps_bytes(s(&v, "onion"), &vector_caps(&v));
    assert_eq!(
        hex::encode(&bytes),
        s(&v["capabilities"], "canonicalCapsBytesHex")
    );
}

#[test]
fn caps_sig_signs_and_verifies() {
    let v = vectors();
    let onion = s(&v, "onion");
    let caps = vector_caps(&v);
    // RFC 8032 deterministic: signing the canonical caps bytes with onionSeed byte-matches
    // the pinned capsSig.
    let sig = ed25519_sign(
        &canonical_caps_bytes(onion, &caps),
        &seed32(s(&v, "onionSeed")),
    );
    assert_eq!(hex::encode(sig), s(&v["capabilities"], "capsSig"));
    // verify_caps_sig accepts the pinned capsSig under the key the onion address commits to.
    assert!(verify_caps_sig(
        onion,
        &caps,
        Some(s(&v["capabilities"], "capsSig"))
    ));
    // TOTAL: absent / empty / garbage signature -> false, never panics.
    assert!(!verify_caps_sig(onion, &caps, None));
    assert!(!verify_caps_sig(onion, &caps, Some("")));
    assert!(!verify_caps_sig(onion, &caps, Some("nothex")));
    // A tampered cap (drop a port) breaks the onion-bound signature.
    let tampered = Caps {
        ports: Some(vec![443]),
        ..caps.clone()
    };
    assert!(!verify_caps_sig(
        onion,
        &tampered,
        Some(s(&v["capabilities"], "capsSig"))
    ));
}

#[test]
fn fixed_public_rate_caps_follow_pay_and_have_a_pinned_signature() {
    let v = vectors();
    let onion = s(&v, "onion");
    let caps = Caps {
        admits: Some(vec!["staked".into()]),
        pay: Some(PayCaps {
            protocols: Some(vec!["x402".into()]),
            port: Some(8878),
            asset: Some("0x1111111111111111111111111111111111111111".into()),
            chain: Some("eip155:11155111".into()),
            tiers: Some(vec![("1".into(), "100000".into())]),
            ..Default::default()
        }),
        rate: Some(RateCaps {
            scope: "grove-v4".into(),
            window: "fixed".into(),
            epoch_seconds: 60,
            previous_epochs_accepted: 1,
            root_freshness_seconds: 60,
            payload_bytes_per_slot: 41_943_040,
        }),
        ..Default::default()
    };
    let expected = format!(
        "Shade Tree gateway capabilities v1\n{{\"onion\":\"{onion}\",\"caps\":{{\"admits\":[\"staked\"],\"pay\":{{\"protocols\":[\"x402\"],\"port\":8878,\"asset\":\"0x1111111111111111111111111111111111111111\",\"chain\":\"eip155:11155111\",\"tiers\":{{\"1\":\"100000\"}}}},\"rate\":{{\"scope\":\"grove-v4\",\"window\":\"fixed\",\"epochSeconds\":60,\"previousEpochsAccepted\":1,\"rootFreshnessSeconds\":60,\"payloadBytesPerSlot\":41943040}}}}}}"
    );
    assert_eq!(canonical_caps_bytes(onion, &caps), expected.as_bytes());

    // Independently pinned with Node's Ed25519 implementation from the vector onionSeed.
    const SIGNATURE: &str = "ded3e2aa769c1dd7c002511417d1c79d599dab991db29c8aaa3b32a969629ce79761c0bc4851f59b1cee02e8ebf719f8e3a400ccec27f0210ad9aaa5476c740e";
    assert_eq!(
        hex::encode(ed25519_sign(
            &canonical_caps_bytes(onion, &caps),
            &seed32(s(&v, "onionSeed"))
        )),
        SIGNATURE
    );
    assert!(verify_caps_sig(onion, &caps, Some(SIGNATURE)));

    let mut changed = caps.clone();
    changed.rate.as_mut().unwrap().epoch_seconds = 120;
    assert!(!verify_caps_sig(onion, &changed, Some(SIGNATURE)));
}

#[test]
fn invalid_rate_caps_are_omitted_but_valid_rate_only_caps_are_present() {
    let invalid = Caps {
        rate: Some(RateCaps {
            scope: "grove-v4".into(),
            window: "sliding".into(),
            epoch_seconds: 60,
            previous_epochs_accepted: 1,
            root_freshness_seconds: 60,
            payload_bytes_per_slot: 41_943_040,
        }),
        ..Default::default()
    };
    assert_eq!(shadenet_proto::canonical_caps(&invalid).rate, None);
    assert!(!shadenet_proto::has_caps(&invalid));

    let valid = Caps {
        rate: Some(RateCaps {
            window: "fixed".into(),
            ..invalid.rate.unwrap()
        }),
        ..Default::default()
    };
    assert!(shadenet_proto::has_caps(&valid));
}

#[test]
fn announce_with_caps_matches_vector() {
    let v = vectors();
    let a = &v["announce"];
    let aw = &v["capabilities"]["announceWithCaps"];
    let ann = Announce {
        v: a["v"].as_u64().unwrap(),
        onion: a["onion"].as_str().unwrap().to_string(),
        weight: a["weight"].as_u64().unwrap(),
        ts: a["ts"].as_u64().unwrap(),
        nonce: a["nonce"].as_str().unwrap().to_string(),
        onion_sig: None,
        operator: None,
        operator_sig: None,
        caps: Some(vector_caps(&v)),
        caps_sig: None,
    };
    let bytes = canonical_announce_bytes(&ann);
    // caps appended after nonce; byte-identical to the pinned caps-carrying announce.
    assert_eq!(
        hex::encode(&bytes),
        aw["canonicalBytesHex"].as_str().unwrap()
    );
    // the pinned onionSig verifies over those bytes, and re-signing is deterministic.
    let sig: [u8; 64] = hex::decode(aw["onionSig"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert!(ed25519_verify(&bytes, &sig, &pub32(s(&v, "onionPub"))));
    assert_eq!(
        hex::encode(ed25519_sign(&bytes, &seed32(s(&v, "onionSeed")))),
        aw["onionSig"].as_str().unwrap()
    );
}

#[test]
fn directory_with_caps_matches_and_verifies() {
    let v = vectors();
    let dir = directory_with_caps(&v);
    // canonical bytes carry caps + capsSig after health, byte-identical to the pinned hex.
    assert_eq!(
        hex::encode(canonical_directory_bytes(&dir)),
        s(&v["capabilities"]["directoryWithCaps"], "canonicalBytesHex")
    );
    // Full verify: pinned bootnode signature + onion<->pubkey binding + capsSig all pass.
    verify_directory(&dir, s(&v, "signerPub")).expect("caps-carrying directory must verify");
}

#[test]
fn directory_with_tampered_caps_is_rejected_bad_caps_sig() {
    let v = vectors();
    let mut dir = directory_with_caps(&v);
    // Alter a cap (drop port 80) WITHOUT re-signing capsSig: the onion-bound signature no
    // longer covers these caps. The directory bytes change too, so re-sign the DIRECTORY
    // (bootnode key) to get PAST bad-signature down to the per-entry caps check.
    dir.gateways[0].caps = Some(Caps {
        ports: Some(vec![443]),
        region: Some("eu".to_string()),
        proto: Some(ProtoCaps { min: 4, max: 4 }),
        ..Default::default()
    });
    let resig = ed25519_sign(
        &canonical_directory_bytes(&dir),
        &seed32(s(&v, "signerSeed")),
    );
    dir.signature = Some(hex::encode(resig));
    let err = verify_directory(&dir, s(&v, "signerPub"))
        .unwrap_err()
        .to_string();
    assert!(
        err.starts_with("bad-caps-sig:"),
        "expected bad-caps-sig, got {err}"
    );
}

#[test]
fn absent_caps_is_byte_identical_to_no_caps_vector() {
    let v = vectors();
    // The single-sig gateway with caps:None / caps_sig:None serializes to the pinned
    // NO-caps directory bytes — the additive omit-when-absent guarantee.
    let dir = vector_directory(&v);
    assert_eq!(
        hex::encode(canonical_directory_bytes(&dir)),
        s(&v, "canonicalDirectoryBytesHex")
    );
    // Caps that canonicalize EMPTY (all junk: no valid ports, unknown region, max<min) are
    // ALSO omitted (has_caps=false), so the bytes are still byte-identical even with a
    // capsSig present — nothing to sign over, nothing to append.
    let mut dir2 = vector_directory(&v);
    dir2.gateways[0].caps = Some(Caps {
        ports: Some(vec![]),
        region: Some("zzz".to_string()),
        proto: Some(ProtoCaps { min: 9, max: 1 }),
        artifacts: Some(vec!["Not An Id".to_string(), String::new()]),
        ..Default::default()
    });
    dir2.gateways[0].caps_sig = Some("deadbeef".to_string());
    assert_eq!(
        hex::encode(canonical_directory_bytes(&dir2)),
        s(&v, "canonicalDirectoryBytesHex")
    );
    // And such an entry still verifies (no caps to check -> capsSig ignored).
    verify_directory(&dir2, s(&v, "signerPub")).expect("empty-canonicalizing caps are ignored");
}

// -- 10. ZK artifact-version negotiation (artifacts vector, T-HARD-8) --------------------
// Consumes the `artifacts` vector: the content-derived id, the client's pick + its
// byte-pinned disjoint reason, the bounded reason labels, and caps that CARRY an
// `artifacts` list (canonical form, bytes, onion sig) — while the pre-existing
// `capabilities` vectors above stay byte-identical (artifacts absent => omitted).

fn str_vec(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect()
}

#[test]
fn artifact_id_matches_vector() {
    let v = vectors();
    let smp = &v["artifacts"]["sample"];
    assert_eq!(
        shadenet_proto::artifact_id_of(s(smp, "circuit"), s(smp, "inputUtf8").as_bytes()),
        s(smp, "artifactId")
    );
    assert!(shadenet_proto::is_artifact_id(s(smp, "artifactId")));
    assert!(!shadenet_proto::is_artifact_id("Not An Id"));
    assert!(!shadenet_proto::is_artifact_id(""));
    assert!(!shadenet_proto::is_artifact_id(&"a".repeat(65)));
    assert!(shadenet_proto::is_artifact_id(&"a".repeat(64)));
}

#[test]
fn artifact_reason_labels_match_vector() {
    let v = vectors();
    let r = &v["artifacts"]["reasons"];
    assert_eq!(shadenet_proto::REASON_BAD_ARTIFACT, s(r, "badArtifact"));
    assert_eq!(
        shadenet_proto::REASON_ARTIFACT_RETIRED,
        s(r, "artifactRetired")
    );
    assert_eq!(
        shadenet_proto::REASON_ARTIFACT_UNKNOWN,
        s(r, "artifactUnknown")
    );
    assert_eq!(
        shadenet_proto::REASON_NO_MUTUAL_ARTIFACT,
        s(r, "noMutualArtifact")
    );
    assert_eq!(
        shadenet_proto::REASON_NO_CLIENT_ARTIFACT,
        s(r, "noClientArtifact")
    );
}

#[test]
fn select_artifact_matches_vector() {
    let v = vectors();
    let sel = &v["artifacts"]["selection"];
    let mine = str_vec(&sel["clientNewestFirst"]);
    let ad = str_vec(&sel["gatewayAd"]);
    assert_eq!(
        shadenet_proto::select_artifact(Some(&ad), &mine).unwrap(),
        s(sel, "picked")
    );
    assert_eq!(
        shadenet_proto::select_artifact(None, &mine).unwrap(),
        s(sel, "noAdPicked")
    );
    assert_eq!(
        shadenet_proto::select_artifact(Some(&[]), &mine).unwrap(),
        s(sel, "noAdPicked"),
        "an empty ad is treated as no ad"
    );
    let disjoint = vec![
        "rln-ffffffffffffffff".to_string(),
        "rln-aaaaaaaaaaaaaaaa".to_string(),
    ];
    let err = shadenet_proto::select_artifact(Some(&disjoint), &mine).unwrap_err();
    assert_eq!(err.to_string(), s(sel, "disjointReason"));
    let err = shadenet_proto::select_artifact(None, &[]).unwrap_err();
    assert_eq!(
        err.to_string(),
        s(&v["artifacts"]["reasons"], "noClientArtifact")
    );
    // junk client ids are ignored, not selected
    let err = shadenet_proto::select_artifact(None, &["Not An Id".to_string()]).unwrap_err();
    assert_eq!(err.to_string(), shadenet_proto::REASON_NO_CLIENT_ARTIFACT);
}

#[test]
fn caps_with_artifacts_match_vector() {
    let v = vectors();
    let cwa = &v["artifacts"]["capsWithArtifacts"];
    let onion = s(&v, "onion");
    let caps = Caps {
        ports: Some(str_ports(&cwa["caps"]["ports"])),
        region: None,
        proto: Some(ProtoCaps {
            min: cwa["caps"]["proto"]["min"].as_i64().unwrap(),
            max: cwa["caps"]["proto"]["max"].as_i64().unwrap(),
        }),
        artifacts: Some(str_vec(&cwa["caps"]["artifacts"])),
        ..Default::default()
    };
    // canonical form: artifacts deduped + sorted, appended after proto
    let cc = shadenet_proto::canonical_caps(&caps);
    assert_eq!(
        cc.artifacts.as_deref().unwrap(),
        str_vec(&cwa["canonical"]["artifacts"])
    );
    assert!(
        shadenet_proto::has_caps(&Caps {
            artifacts: Some(vec![s(&v["artifacts"]["sample"], "artifactId").to_string()]),
            ..Default::default()
        }),
        "artifacts alone make caps non-empty"
    );
    // bytes + sig byte-pinned
    assert_eq!(
        hex::encode(canonical_caps_bytes(onion, &caps)),
        s(cwa, "canonicalCapsBytesHex")
    );
    let sig = ed25519_sign(
        &canonical_caps_bytes(onion, &caps),
        &seed32(s(&v, "onionSeed")),
    );
    assert_eq!(hex::encode(sig), s(cwa, "capsSig"));
    assert!(verify_caps_sig(onion, &caps, Some(s(cwa, "capsSig"))));
    // Grafting an extra artifact id breaks the onion-bound signature (ids are unforgeable).
    let mut grafted = caps.clone();
    grafted
        .artifacts
        .as_mut()
        .unwrap()
        .push("rln-ffffffffffffffff".to_string());
    assert!(!verify_caps_sig(onion, &grafted, Some(s(cwa, "capsSig"))));
    // Junk / oversize lists canonicalize to NO artifacts (TOTAL, never fails).
    let junk = Caps {
        artifacts: Some(vec!["Not An Id".to_string(), String::new()]),
        ..Default::default()
    };
    assert_eq!(shadenet_proto::canonical_caps(&junk).artifacts, None);
    let too_many: Vec<String> = (0..=shadenet_proto::MAX_CAPS_ARTIFACTS)
        .map(|i| format!("rln-{i:016x}"))
        .collect();
    assert_eq!(
        shadenet_proto::canonical_caps(&Caps {
            artifacts: Some(too_many),
            ..Default::default()
        })
        .artifacts,
        None
    );
    // And the pre-existing no-artifacts caps still byte-match their (unchanged) vector.
    assert_eq!(
        hex::encode(canonical_caps_bytes(onion, &vector_caps(&v))),
        s(&v["capabilities"], "canonicalCapsBytesHex")
    );
}

fn str_ports(v: &Value) -> Vec<i64> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_i64().unwrap())
        .collect()
}

// ---------------------------------------------------------------------------
// T-FEAT-9 per-gateway admission policy + payment advert (`admission` vector)
// ---------------------------------------------------------------------------
// Consumes `admission.capsWithAdmission`: caps carrying `admits` + `pay` normalize to the
// pinned canonical form (admits deduped in ANONYMITY order, pay with fixed protocol order,
// lowercased onion/asset, numeric-ascending tiers), serialize to the pinned canonical bytes,
// and re-produce the pinned onion capsSig. Junk/oversized admits/pay canonicalize to ABSENT.

fn vector_pay(p: &Value) -> shadenet_proto::PayCaps {
    let tiers = p["tiers"].as_object().map(|m| {
        m.iter()
            .map(|(k, v)| {
                let price = match v {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    _ => String::new(),
                };
                (k.clone(), price)
            })
            .collect::<Vec<_>>()
    });
    shadenet_proto::PayCaps {
        protocols: p["protocols"].as_array().map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        }),
        onion: p["onion"].as_str().map(String::from),
        port: p["port"].as_i64(),
        asset: p["asset"].as_str().map(String::from),
        chain: p["chain"].as_str().map(String::from),
        tiers,
    }
}

#[test]
fn caps_with_admission_match_vector() {
    let v = vectors();
    let ad = &v["admission"];
    let cwa = &ad["capsWithAdmission"];
    let onion = s(&v, "onion");
    assert_eq!(
        str_vec(&ad["admitPaths"]),
        shadenet_proto::ADMIT_PATHS
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        str_vec(&ad["payProtocols"]),
        shadenet_proto::PAY_PROTOCOLS
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        ad["maxPayTiers"].as_u64().unwrap() as usize,
        shadenet_proto::MAX_CAPS_PAY_TIERS
    );
    let caps = Caps {
        ports: Some(str_ports(&cwa["caps"]["ports"])),
        proto: Some(ProtoCaps {
            min: cwa["caps"]["proto"]["min"].as_i64().unwrap(),
            max: cwa["caps"]["proto"]["max"].as_i64().unwrap(),
        }),
        admits: Some(str_vec(&cwa["caps"]["admits"])),
        pay: Some(vector_pay(&cwa["caps"]["pay"])),
        ..Default::default()
    };
    let cc = shadenet_proto::canonical_caps(&caps);
    assert_eq!(
        cc.admits.as_deref().unwrap(),
        str_vec(&cwa["canonical"]["admits"]),
        "admits deduped, anonymity order"
    );
    let pay = cc.pay.as_ref().expect("pay canonicalizes");
    assert_eq!(
        pay.protocols,
        str_vec(&cwa["canonical"]["pay"]["protocols"])
    );
    assert_eq!(
        pay.onion.as_deref(),
        cwa["canonical"]["pay"]["onion"].as_str()
    );
    assert_eq!(pay.asset, s(&cwa["canonical"]["pay"], "asset"));
    assert_eq!(pay.chain, s(&cwa["canonical"]["pay"], "chain"));
    assert_eq!(pay.port, cwa["canonical"]["pay"]["port"].as_u64().unwrap());
    let want_tiers: Vec<(u64, String)> = cwa["canonical"]["pay"]["tiers"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.parse::<u64>().unwrap(), v.as_str().unwrap().to_string()))
        .collect::<Vec<_>>();
    let mut want_sorted = want_tiers.clone();
    want_sorted.sort_by_key(|(l, _)| *l);
    assert_eq!(pay.tiers, want_sorted, "tiers sorted by numeric limit");
    // bytes + sig byte-pinned
    assert_eq!(
        hex::encode(canonical_caps_bytes(onion, &caps)),
        s(cwa, "canonicalCapsBytesHex")
    );
    let sig = ed25519_sign(
        &canonical_caps_bytes(onion, &caps),
        &seed32(s(&v, "onionSeed")),
    );
    assert_eq!(hex::encode(sig), s(cwa, "capsSig"));
    assert!(verify_caps_sig(onion, &caps, Some(s(cwa, "capsSig"))));
    // Widening the policy (grafting `staked`) breaks the onion-bound signature.
    let mut grafted = caps.clone();
    grafted.admits.as_mut().unwrap().push("staked".to_string());
    assert!(!verify_caps_sig(onion, &grafted, Some(s(cwa, "capsSig"))));
    // admits alone make caps non-empty; junk admits canonicalize to none.
    assert!(shadenet_proto::has_caps(&Caps {
        admits: Some(vec!["invited".to_string()]),
        ..Default::default()
    }));
    for j in ad["junk"]["admits"].as_array().unwrap() {
        let list: Vec<String> = j
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap_or("").to_string())
            .collect();
        assert_eq!(
            shadenet_proto::canonical_caps(&Caps {
                admits: Some(list),
                ..Default::default()
            })
            .admits,
            None
        );
    }
    for j in ad["junk"]["pay"].as_array().unwrap() {
        assert_eq!(
            shadenet_proto::canonical_caps(&Caps {
                pay: Some(vector_pay(j)),
                ..Default::default()
            })
            .pay,
            None,
            "junk pay: {j}"
        );
    }
    // Pre-existing caps vectors are byte-UNCHANGED (admits/pay absent => omitted).
    let cap = vector_caps(&v);
    assert_eq!(
        hex::encode(canonical_caps_bytes(onion, &cap)),
        s(&v["capabilities"], "canonicalCapsBytesHex")
    );
}

// --------------------------------------------------------------------------
// Session tickets (session-v1, ADR 0011): `sessionTickets` vector
// --------------------------------------------------------------------------

#[test]
fn session_ticket_book_matches_vector() {
    use shadenet_proto::session as st;
    let v = vectors();
    let t = &v["sessionTickets"];
    assert_eq!(s(t, "signalPrefix"), st::SESSION_SIGNAL_PREFIX);
    assert_eq!(s(t, "ticketDomain"), st::TICKET_DOMAIN);
    assert_eq!(s(t, "ticketBookDomain"), st::TICKET_BOOK_DOMAIN);
    assert_eq!(s(t, "ticketSpendDomain"), st::TICKET_SPEND_DOMAIN);

    let secrets: Vec<[u8; 32]> = str_vec(&t["secretsHex"])
        .iter()
        .map(|h| seed32(h))
        .collect();
    let book = st::build_ticket_book(&secrets).unwrap();
    assert_eq!(book.commitments, str_vec(&t["commitments"]));
    assert_eq!(book.ticket_book_digest, s(t, "ticketBookDigest"));

    let signal = st::session_signal(
        s(t, "onion"),
        s(t, "classId"),
        s(t, "sessionNonce"),
        &book.ticket_book_digest,
    )
    .unwrap();
    assert_eq!(signal, s(t, "signal"));
    assert_eq!(calculate_signal_hash(&signal), s(t, "signalHashDecimal"));

    let spend = &t["spend"];
    let index = spend["index"].as_u64().unwrap() as u16;
    assert_eq!(
        st::spend_digest(
            &book.ticket_book_digest,
            index,
            s(spend, "target"),
            s(spend, "requestNonce")
        )
        .unwrap(),
        s(spend, "spendDigest")
    );
    let ticket = &spend["ticket"];
    assert_eq!(ticket["v"].as_u64().unwrap(), st::SESSION_VERSION);
    assert_eq!(s(ticket, "book"), book.ticket_book_digest);
    assert_eq!(ticket["i"].as_u64().unwrap() as u16, index);
    assert_eq!(
        st::encode_ticket_secret(&secrets[index as usize]),
        s(ticket, "t")
    );
    assert_eq!(
        st::decode_ticket_secret(s(ticket, "t")),
        Some(secrets[index as usize])
    );
    assert_eq!(s(ticket, "n"), s(spend, "requestNonce"));

    let policy = &t["policy"];
    let class = st::class_policy(s(t, "classId")).expect("research-v1 is known");
    assert_eq!(s(policy, "class"), class.class);
    assert_eq!(policy["tickets"].as_u64().unwrap(), class.tickets);
    assert_eq!(
        policy["maxPayloadBytes"].as_u64().unwrap(),
        class.max_payload_bytes
    );
    assert_eq!(policy["lifetimeMs"].as_u64().unwrap(), class.lifetime_ms);
    assert_eq!(
        policy["idleTimeoutMs"].as_u64().unwrap(),
        class.idle_timeout_ms
    );
    assert_eq!(
        policy["maxConcurrentStreams"].as_u64().unwrap(),
        class.max_concurrent_streams
    );
    assert_eq!(class.tickets as usize, secrets.len());
}

#[test]
fn caps_with_session_match_vector_and_are_onion_signed() {
    let v = vectors();
    let cws = &v["sessionTickets"]["capsWithSession"];
    let onion = s(&v, "onion");
    let rate = &cws["caps"]["rate"];
    let caps = Caps {
        admits: Some(str_vec(&cws["caps"]["admits"])),
        rate: Some(RateCaps {
            scope: s(rate, "scope").into(),
            window: s(rate, "window").into(),
            epoch_seconds: rate["epochSeconds"].as_i64().unwrap(),
            previous_epochs_accepted: rate["previousEpochsAccepted"].as_i64().unwrap(),
            root_freshness_seconds: rate["rootFreshnessSeconds"].as_i64().unwrap(),
            payload_bytes_per_slot: rate["payloadBytesPerSlot"].as_i64().unwrap(),
        }),
        session: Some(shadenet_proto::SessionCaps {
            version: cws["caps"]["session"]["version"].as_i64().unwrap(),
            classes: str_vec(&cws["caps"]["session"]["classes"]),
        }),
        ..Default::default()
    };
    assert_eq!(
        hex::encode(canonical_caps_bytes(onion, &caps)),
        s(cws, "canonicalCapsBytesHex")
    );
    assert_eq!(
        hex::encode(ed25519_sign(
            &canonical_caps_bytes(onion, &caps),
            &seed32(s(&v, "onionSeed"))
        )),
        s(cws, "capsSig")
    );
    assert!(verify_caps_sig(onion, &caps, Some(s(cws, "capsSig"))));

    // A signer without the onion key cannot add or widen session support.
    let mut widened = caps.clone();
    widened
        .session
        .as_mut()
        .unwrap()
        .classes
        .push("bulk-v1".into());
    assert!(!verify_caps_sig(onion, &widened, Some(s(cws, "capsSig"))));
    let mut removed = caps.clone();
    removed.session = None;
    assert!(!verify_caps_sig(onion, &removed, Some(s(cws, "capsSig"))));

    // Junk session adverts are dropped whole, never thrown; absent stays byte-identical.
    let junk = Caps {
        session: Some(shadenet_proto::SessionCaps {
            version: 0,
            classes: vec!["research-v1".into()],
        }),
        ..Default::default()
    };
    assert_eq!(shadenet_proto::canonical_caps(&junk).session, None);
    assert!(!shadenet_proto::has_caps(&junk));
    let unsorted = Caps {
        session: Some(shadenet_proto::SessionCaps {
            version: 1,
            classes: vec!["zeta".into(), "alpha".into(), "zeta".into(), "Bad".into()],
        }),
        ..Default::default()
    };
    assert_eq!(
        shadenet_proto::canonical_caps(&unsorted)
            .session
            .unwrap()
            .classes,
        vec!["alpha".to_string(), "zeta".to_string()]
    );
}
