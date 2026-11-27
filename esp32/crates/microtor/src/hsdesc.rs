//! v3 onion-service identities and descriptors (rend-spec-v3 sections 1 and 2).

use crate::circuit::RelayInfo;
use crate::crypto::{
    aes256_ctr_apply, ct_eq, curve_to_ed_public, ed_verify, rand_array, sha3_256, shake256,
    EdExpanded,
};
use crate::util::{b32_decode, b32_encode, b64_decode, b64_encode, b64_fixed, b64_lines};
use crate::{Error, Result};

const CERT_LIFETIME_HOURS: u64 = 54;
const SUPERENCRYPTED_PAD: usize = 10_000;
const SIG_PREFIX: &[u8] = b"Tor onion service descriptor sig v3";

pub mod cert_type {
    /// Blinded key certifies the descriptor signing key.
    pub const HS_DESC_SIGNING: u8 = 0x08;
    /// Descriptor signing key certifies an introduction point authentication key.
    pub const HS_IP_AUTH: u8 = 0x09;
    /// Descriptor signing key certifies the ed25519 form of an introduction point
    /// encryption key.
    pub const HS_IP_ENC: u8 = 0x0b;
}

/// `<56 base32 chars>.onion` for an identity key.
pub fn onion_address(public: &[u8; 32]) -> String {
    let checksum = sha3_256(&[b".onion checksum", public, &[3]]);
    let mut raw = [0u8; 35];
    raw[..32].copy_from_slice(public);
    raw[32..34].copy_from_slice(&checksum[..2]);
    raw[34] = 3;
    format!("{}.onion", b32_encode(&raw))
}

/// The identity key inside an onion address (with or without the `.onion` suffix).
pub fn parse_onion(address: &str) -> Result<[u8; 32]> {
    let label = address.strip_suffix(".onion").unwrap_or(address);
    if label.len() != 56 {
        return Err(Error::Parse("onion address length"));
    }
    let raw = b32_decode(label)?;
    if raw.len() != 35 || raw[34] != 3 {
        return Err(Error::Parse("onion address version"));
    }
    let public: [u8; 32] = raw[..32].try_into().unwrap();
    let checksum = sha3_256(&[b".onion checksum", &public, &[3]]);
    if raw[32..34] != checksum[..2] {
        return Err(Error::Parse("onion address checksum"));
    }
    Ok(public)
}

/// `N_hs_subcred = H("subcredential" | H("credential" | identity) | blinded)`.
pub fn subcredential(identity: &[u8; 32], blinded: &[u8; 32]) -> [u8; 32] {
    let credential = sha3_256(&[b"credential", identity]);
    sha3_256(&[b"subcredential", &credential, blinded])
}

/// An ed25519 certificate (cert-spec 2.1) with the signing key included as an extension.
pub fn make_cert(kind: u8, certified: &[u8; 32], signer: &EdExpanded, now: u64) -> Vec<u8> {
    let expires_hours = (now / 3600 + CERT_LIFETIME_HOURS) as u32;
    let mut cert = Vec::with_capacity(140);
    cert.push(1);
    cert.push(kind);
    cert.extend_from_slice(&expires_hours.to_be_bytes());
    cert.push(1); // certified key type: ed25519
    cert.extend_from_slice(certified);
    cert.push(1); // one extension
    cert.extend_from_slice(&[0, 32, 4, 0]); // length, type "signed-with-ed25519-key", flags
    cert.extend_from_slice(&signer.public);
    let sig = signer.sign(&cert);
    cert.extend_from_slice(&sig);
    cert
}

/// Check a certificate's type, expiry and signature. Returns the certified key and the
/// signing key it names. `expected_signer`, when given, must match.
pub fn check_cert(
    cert: &[u8],
    kind: u8,
    expected_signer: Option<&[u8; 32]>,
    now: u64,
) -> Result<([u8; 32], [u8; 32])> {
    let bad = Error::Proto("bad certificate");
    if cert.len() < 40 + 64 || cert[0] != 1 || cert[1] != kind || cert[6] != 1 {
        return Err(bad);
    }
    let expires = u64::from(u32::from_be_bytes(cert[2..6].try_into().unwrap())) * 3600;
    if expires < now {
        return Err(Error::Proto("certificate expired"));
    }
    let certified: [u8; 32] = cert[7..39].try_into().unwrap();
    let body_len = cert.len() - 64;
    let mut at = 40;
    let mut signer: Option<[u8; 32]> = None;
    for _ in 0..cert[39] {
        let header = cert.get(at..at + 4).ok_or(bad.clone())?;
        let len = u16::from_be_bytes([header[0], header[1]]) as usize;
        let data = cert.get(at + 4..at + 4 + len).ok_or(bad.clone())?;
        if at + 4 + len > body_len {
            return Err(bad);
        }
        if header[2] == 4 && len == 32 {
            signer = Some(data.try_into().unwrap());
        }
        at += 4 + len;
    }
    let signer = match (signer, expected_signer) {
        (Some(s), Some(e)) if s != *e => return Err(bad),
        (Some(s), _) => s,
        (None, Some(e)) => *e,
        (None, None) => return Err(bad),
    };
    if !ed_verify(&signer, &cert[..body_len], &cert[body_len..]) {
        return Err(Error::Proto("certificate signature"));
    }
    Ok((certified, signer))
}

fn push_cert(out: &mut String, cert: &[u8]) {
    out.push_str("-----BEGIN ED25519 CERT-----\n");
    b64_lines(cert, out);
    out.push_str("-----END ED25519 CERT-----\n");
}

fn layer_keys(
    blinded: &[u8; 32],
    subcred: &[u8; 32],
    revision: u64,
    salt: &[u8],
    constant: &[u8],
) -> ([u8; 32], [u8; 16], [u8; 32]) {
    let mut keys = [0u8; 80];
    shake256(
        &[blinded, subcred, &revision.to_be_bytes(), salt, constant],
        &mut keys,
    );
    (
        keys[..32].try_into().unwrap(),
        keys[32..48].try_into().unwrap(),
        keys[48..].try_into().unwrap(),
    )
}

fn layer_mac(mac_key: &[u8; 32], salt: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    sha3_256(&[
        &32u64.to_be_bytes(),
        mac_key,
        &(salt.len() as u64).to_be_bytes(),
        salt,
        ciphertext,
    ])
}

/// `salt | AES-256-CTR(plaintext) | MAC` for one descriptor layer; consumes the plaintext
/// buffer to avoid a second copy.
fn seal_layer(
    mut plaintext: Vec<u8>,
    blinded: &[u8; 32],
    subcred: &[u8; 32],
    revision: u64,
    constant: &[u8],
) -> Vec<u8> {
    let salt: [u8; 16] = rand_array();
    let (key, iv, mac_key) = layer_keys(blinded, subcred, revision, &salt, constant);
    aes256_ctr_apply(&key, &iv, &mut plaintext);
    let mac = layer_mac(&mac_key, &salt, &plaintext);
    let mut out = Vec::with_capacity(16 + plaintext.len() + 32);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&plaintext);
    out.extend_from_slice(&mac);
    out
}

fn open_layer(
    blob: &[u8],
    blinded: &[u8; 32],
    subcred: &[u8; 32],
    revision: u64,
    constant: &[u8],
) -> Result<Vec<u8>> {
    if blob.len() < 16 + 32 {
        return Err(Error::Proto("descriptor layer too short"));
    }
    let (salt, rest) = blob.split_at(16);
    let (ciphertext, mac) = rest.split_at(rest.len() - 32);
    let (key, iv, mac_key) = layer_keys(blinded, subcred, revision, salt, constant);
    if !ct_eq(&layer_mac(&mac_key, salt, ciphertext), mac) {
        return Err(Error::Proto("descriptor layer mac"));
    }
    let mut plaintext = ciphertext.to_vec();
    aes256_ctr_apply(&key, &iv, &mut plaintext);
    Ok(plaintext)
}

/// The public half of an introduction point, as it appears in a descriptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntroInfo {
    pub relay: RelayInfo,
    /// `KP_hs_ipt_sid`: the ed25519 key the service authenticates to this point with.
    pub auth_key: [u8; 32],
    /// `KP_hss_ntor`: the curve25519 key clients encrypt their introduction to.
    pub enc_key: [u8; 32],
}

/// Build and sign a descriptor for one time period.
///
/// `blinded` is the identity key blinded for that period; `revision` must grow with every
/// upload under the same blinded key.
pub fn build_descriptor(
    identity: &[u8; 32],
    blinded: &EdExpanded,
    intros: &[IntroInfo],
    revision: u64,
    now: u64,
) -> Result<String> {
    let subcred = subcredential(identity, &blinded.public);
    let signing = EdExpanded::generate();

    // Inner layer: what a client needs to introduce itself.
    let mut inner = String::with_capacity(64 + intros.len() * 720);
    inner.push_str("create2-formats 2\n");
    for intro in intros {
        inner.push_str("introduction-point ");
        inner.push_str(&b64_encode(&intro.relay.link_specifiers(), true));
        inner.push_str("\nonion-key ntor ");
        inner.push_str(&b64_encode(&intro.relay.ntor_key, true));
        inner.push_str("\nauth-key\n");
        push_cert(
            &mut inner,
            &make_cert(cert_type::HS_IP_AUTH, &intro.auth_key, &signing, now),
        );
        inner.push_str("enc-key ntor ");
        inner.push_str(&b64_encode(&intro.enc_key, true));
        inner.push_str("\nenc-key-cert\n");
        let enc_as_ed = curve_to_ed_public(&intro.enc_key)?;
        push_cert(
            &mut inner,
            &make_cert(cert_type::HS_IP_ENC, &enc_as_ed, &signing, now),
        );
    }
    let inner_blob = seal_layer(
        inner.into_bytes(),
        &blinded.public,
        &subcred,
        revision,
        b"hsdir-encrypted-data",
    );

    // Middle layer: client authorization (unused, so sixteen decoy entries) around the inner
    // blob, padded so its size says nothing about the number of introduction points.
    let mut middle = String::with_capacity(SUPERENCRYPTED_PAD);
    middle.push_str("desc-auth-type x25519\ndesc-auth-ephemeral-key ");
    middle.push_str(&b64_encode(&rand_array::<32>(), true));
    middle.push('\n');
    for _ in 0..16 {
        middle.push_str("auth-client ");
        middle.push_str(&b64_encode(&rand_array::<8>(), false));
        middle.push(' ');
        middle.push_str(&b64_encode(&rand_array::<16>(), false));
        middle.push(' ');
        middle.push_str(&b64_encode(&rand_array::<16>(), false));
        middle.push('\n');
    }
    middle.push_str("encrypted\n-----BEGIN MESSAGE-----\n");
    b64_lines(&inner_blob, &mut middle);
    drop(inner_blob);
    middle.push_str("-----END MESSAGE-----");
    let mut middle = middle.into_bytes();
    let padded = middle.len().div_ceil(SUPERENCRYPTED_PAD) * SUPERENCRYPTED_PAD;
    middle.resize(padded, 0);
    let outer_blob = seal_layer(
        middle,
        &blinded.public,
        &subcred,
        revision,
        b"hsdir-superencrypted-data",
    );

    let mut desc = String::with_capacity(outer_blob.len() * 4 / 3 + 1024);
    desc.push_str("hs-descriptor 3\ndescriptor-lifetime 180\ndescriptor-signing-key-cert\n");
    push_cert(
        &mut desc,
        &make_cert(cert_type::HS_DESC_SIGNING, &signing.public, blinded, now),
    );
    desc.push_str(&format!(
        "revision-counter {revision}\nsuperencrypted\n-----BEGIN MESSAGE-----\n"
    ));
    b64_lines(&outer_blob, &mut desc);
    drop(outer_blob);
    desc.push_str("-----END MESSAGE-----\n");
    let mut signed = Vec::with_capacity(SIG_PREFIX.len() + desc.len());
    signed.extend_from_slice(SIG_PREFIX);
    signed.extend_from_slice(desc.as_bytes());
    let signature = signing.sign(&signed);
    drop(signed);
    desc.push_str("signature ");
    desc.push_str(&b64_encode(&signature, false));
    desc.push('\n');
    Ok(desc)
}

/// The base64 body of the object that follows the line `keyword`, joined into one string.
fn object_after<'a>(lines: &mut impl Iterator<Item = &'a str>) -> Result<String> {
    let mut body = String::new();
    match lines.next() {
        Some(l) if l.starts_with("-----BEGIN ") => {}
        _ => return Err(Error::Parse("descriptor object")),
    }
    for line in lines {
        if line.starts_with("-----END ") {
            return Ok(body);
        }
        body.push_str(line);
    }
    Err(Error::Parse("descriptor object unterminated"))
}

/// Verify and decrypt a descriptor fetched for `blinded` (no client authorization), returning
/// its introduction points.
pub fn parse_descriptor(
    text: &str,
    identity: &[u8; 32],
    blinded: &[u8; 32],
    now: u64,
) -> Result<Vec<IntroInfo>> {
    let subcred = subcredential(identity, blinded);
    let sig_at = text
        .rfind("\nsignature ")
        .ok_or(Error::Parse("descriptor signature"))?
        + 1;
    let signature = b64_decode(text[sig_at + 10..].trim())?;

    let mut signing_key = None;
    let mut revision = None;
    let mut outer_blob = None;
    let mut lines = text[..sig_at].lines();
    while let Some(line) = lines.next() {
        match line.split(' ').next() {
            Some("hs-descriptor") if line != "hs-descriptor 3" => {
                return Err(Error::Parse("descriptor version"));
            }
            Some("descriptor-signing-key-cert") => {
                let cert = b64_decode(&object_after(&mut lines)?)?;
                let (key, _) = check_cert(&cert, cert_type::HS_DESC_SIGNING, Some(blinded), now)?;
                signing_key = Some(key);
            }
            Some("revision-counter") => {
                revision = line.split(' ').nth(1).and_then(|v| v.parse::<u64>().ok());
            }
            Some("superencrypted") => outer_blob = Some(b64_decode(&object_after(&mut lines)?)?),
            _ => {}
        }
    }
    let signing_key = signing_key.ok_or(Error::Parse("descriptor has no signing key"))?;
    let revision = revision.ok_or(Error::Parse("descriptor has no revision"))?;
    let outer_blob = outer_blob.ok_or(Error::Parse("descriptor has no body"))?;
    let mut signed = Vec::with_capacity(SIG_PREFIX.len() + sig_at);
    signed.extend_from_slice(SIG_PREFIX);
    signed.extend_from_slice(&text.as_bytes()[..sig_at]);
    if !ed_verify(&signing_key, &signed, &signature) {
        return Err(Error::Proto("descriptor signature"));
    }
    drop(signed);

    let middle = open_layer(
        &outer_blob,
        blinded,
        &subcred,
        revision,
        b"hsdir-superencrypted-data",
    )?;
    drop(outer_blob);
    let end = middle.iter().position(|&b| b == 0).unwrap_or(middle.len());
    let middle =
        core::str::from_utf8(&middle[..end]).map_err(|_| Error::Parse("descriptor utf8"))?;
    let mut lines = middle.lines();
    let mut inner_blob = None;
    while let Some(line) = lines.next() {
        if line == "encrypted" {
            inner_blob = Some(b64_decode(&object_after(&mut lines)?)?);
        }
    }
    let inner_blob = inner_blob.ok_or(Error::Parse("descriptor has no inner layer"))?;
    let inner = open_layer(
        &inner_blob,
        blinded,
        &subcred,
        revision,
        b"hsdir-encrypted-data",
    )?;
    let inner = core::str::from_utf8(&inner).map_err(|_| Error::Parse("descriptor utf8"))?;

    struct Partial {
        specifiers: Vec<u8>,
        ntor_key: Option<[u8; 32]>,
        auth_key: Option<[u8; 32]>,
        enc_key: Option<[u8; 32]>,
    }
    fn finish(p: Option<Partial>, out: &mut Vec<IntroInfo>) {
        let Some(p) = p else { return };
        let (Some(ntor_key), Some(auth_key), Some(enc_key)) = (p.ntor_key, p.auth_key, p.enc_key)
        else {
            return;
        };
        if let Ok((relay, _)) = RelayInfo::from_link_specifiers(&p.specifiers, ntor_key) {
            out.push(IntroInfo {
                relay,
                auth_key,
                enc_key,
            });
        }
    }

    let mut intros = Vec::new();
    let mut current: Option<Partial> = None;
    let mut lines = inner.lines();
    while let Some(line) = lines.next() {
        let mut words = line.split(' ');
        match (words.next(), words.next(), words.next()) {
            (Some("introduction-point"), Some(spec), _) => {
                finish(current.take(), &mut intros);
                current = Some(Partial {
                    specifiers: b64_decode(spec)?,
                    ntor_key: None,
                    auth_key: None,
                    enc_key: None,
                });
            }
            (Some("onion-key"), Some("ntor"), Some(key)) => {
                if let Some(p) = current.as_mut() {
                    p.ntor_key = b64_fixed::<32>(key).ok();
                }
            }
            (Some("enc-key"), Some("ntor"), Some(key)) => {
                if let Some(p) = current.as_mut() {
                    p.enc_key = b64_fixed::<32>(key).ok();
                }
            }
            (Some("auth-key"), None, _) => {
                let cert = b64_decode(&object_after(&mut lines)?)?;
                let (key, _) = check_cert(&cert, cert_type::HS_IP_AUTH, Some(&signing_key), now)?;
                if let Some(p) = current.as_mut() {
                    p.auth_key = Some(key);
                }
            }
            _ => {}
        }
    }
    finish(current, &mut intros);
    if intros.is_empty() {
        return Err(Error::Proto(
            "descriptor lists no usable introduction point",
        ));
    }
    Ok(intros)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::x25519_keypair;

    #[test]
    fn onion_addresses_round_trip() {
        // docs/WIRE-SPEC.md fixture seeds produce valid addresses; check our own encoding.
        let key = EdExpanded::from_seed(&[1u8; 32]).public;
        let address = onion_address(&key);
        assert_eq!(address.len(), 62);
        assert_eq!(parse_onion(&address).unwrap(), key);
        let mut wrong = address.clone();
        wrong.replace_range(0..1, if address.starts_with('a') { "b" } else { "a" });
        assert!(parse_onion(&wrong).is_err());
        // A well-known address (the Tor Project's site) must pass the checksum.
        assert!(
            parse_onion("2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion").is_ok()
        );
    }

    #[test]
    fn descriptor_round_trips_through_both_layers() {
        let now = 1_795_791_600;
        let identity = EdExpanded::from_seed(&[9u8; 32]);
        let blinded = identity.blind(20_784, 1440).unwrap();
        let intros: Vec<IntroInfo> = (1..=3u8)
            .map(|n| IntroInfo {
                relay: RelayInfo {
                    rsa_id: [n; 20],
                    ed_id: Some([n + 10; 32]),
                    ntor_key: [n + 20; 32],
                    addr: format!("10.0.0.{n}:9001").parse().unwrap(),
                },
                auth_key: EdExpanded::from_seed(&[n; 32]).public,
                enc_key: x25519_keypair().1,
            })
            .collect();
        let text = build_descriptor(&identity.public, &blinded, &intros, 77, now).unwrap();
        assert!(text.starts_with("hs-descriptor 3\n"));
        assert!(text.len() > 13_000 && text.len() < 20_000, "{}", text.len());
        let parsed = parse_descriptor(&text, &identity.public, &blinded.public, now).unwrap();
        assert_eq!(parsed, intros);

        // Wrong period key, expired certificates and tampering are all refused.
        let other = identity.blind(20_785, 1440).unwrap();
        assert!(parse_descriptor(&text, &identity.public, &other.public, now).is_err());
        assert!(
            parse_descriptor(&text, &identity.public, &blinded.public, now + 60 * 3600).is_err()
        );
        let tampered = text.replacen("revision-counter 77", "revision-counter 78", 1);
        assert!(parse_descriptor(&tampered, &identity.public, &blinded.public, now).is_err());
    }
}
