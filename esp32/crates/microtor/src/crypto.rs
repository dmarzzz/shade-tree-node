//! Tor's cryptographic building blocks: hashes and MACs, the two circuit KDFs, the ntor and
//! hs-ntor handshakes, ed25519 key blinding, and RSA signature opening for directory documents.

use aes::cipher::{KeyIvInit, StreamCipher};
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::hazmat::ExpandedSecretKey;
use ed25519_dalek::{Signature, VerifyingKey};
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Sha3_256, Shake256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::Error;

pub type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;
pub type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

/// Operating-system randomness.
pub fn rand_bytes(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("system randomness is available");
}

pub fn rand_array<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand_bytes(&mut out);
    out
}

pub fn rand_u32() -> u32 {
    u32::from_le_bytes(rand_array())
}

pub fn rand_u64() -> u64 {
    u64::from_le_bytes(rand_array())
}

/// A uniform float in `(0, 1]`.
pub fn rand_unit() -> f64 {
    ((rand_u64() >> 11) as f64 + 1.0) / (1u64 << 53) as f64
}

/// `rand_core` adapter over the system source, for crates that want an RNG object.
pub struct SysRng;

impl rand_core::RngCore for SysRng {
    fn next_u32(&mut self) -> u32 {
        rand_u32()
    }
    fn next_u64(&mut self) -> u64 {
        rand_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand_bytes(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        rand_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for SysRng {}

pub fn sha1(parts: &[&[u8]]) -> [u8; 20] {
    let mut h = Sha1::new();
    for p in parts {
        Digest::update(&mut h, p);
    }
    h.finalize().into()
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        Digest::update(&mut h, p);
    }
    h.finalize().into()
}

pub fn sha512(parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha512::new();
    for p in parts {
        Digest::update(&mut h, p);
    }
    h.finalize().into()
}

pub fn sha3_256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    for p in parts {
        Digest::update(&mut h, p);
    }
    h.finalize().into()
}

/// rend-spec-v3 `MAC(k, m) = SHA3-256(INT_8(len(k)) | k | m)`.
pub fn hs_mac(key: &[u8], msg: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, (key.len() as u64).to_be_bytes());
    Digest::update(&mut h, key);
    for p in msg {
        Digest::update(&mut h, p);
    }
    h.finalize().into()
}

/// rend-spec-v3 `KDF(m, n) = SHAKE-256(m, n)`.
pub fn shake256(parts: &[&[u8]], out: &mut [u8]) {
    let mut h = Shake256::default();
    for p in parts {
        h.update(p);
    }
    h.finalize_xof().read(out);
}

pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac takes any key length");
    for p in parts {
        Mac::update(&mut mac, p);
    }
    mac.finalize().into_bytes().into()
}

/// tor-spec KDF-TOR, used by CREATE_FAST: `K = H(K0 | [00]) | H(K0 | [01]) | ...`.
pub fn kdf_tor(k0: &[u8], out: &mut [u8]) {
    for (i, chunk) in out.chunks_mut(20).enumerate() {
        let block = sha1(&[k0, &[i as u8]]);
        chunk.copy_from_slice(&block[..chunk.len()]);
    }
}

/// tor-spec KDF-RFC5869 expansion: `K(i) = HMAC(KEY_SEED, K(i-1) | m_expand | INT8(i))`.
pub fn hkdf_expand(key_seed: &[u8; 32], info: &[u8], out: &mut [u8]) {
    let hk = hkdf::Hkdf::<Sha256>::from_prk(key_seed).expect("32-byte PRK");
    hk.expand(info, out).expect("output fits HKDF bounds");
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn aes128_ctr(key: &[u8; 16]) -> Aes128Ctr {
    Aes128Ctr::new(key.into(), &[0u8; 16].into())
}

pub fn aes256_ctr(key: &[u8; 32], iv: &[u8; 16]) -> Aes256Ctr {
    Aes256Ctr::new(key.into(), iv.into())
}

pub fn aes256_ctr_apply(key: &[u8; 32], iv: &[u8; 16], data: &mut [u8]) {
    aes256_ctr(key, iv).apply_keystream(data);
}

// ---------------------------------------------------------------------------------------------
// ntor (tor-spec 5.1.4)

const NTOR_PROTOID: &[u8] = b"ntor-curve25519-sha256-1";
const NTOR_MAC: &[u8] = b"ntor-curve25519-sha256-1:mac";
const NTOR_KEY: &[u8] = b"ntor-curve25519-sha256-1:key_extract";
const NTOR_VERIFY: &[u8] = b"ntor-curve25519-sha256-1:verify";
const NTOR_EXPAND: &[u8] = b"ntor-curve25519-sha256-1:key_expand";

/// Key material from a circuit handshake: `Df | Db | Kf | Kb | KH`.
pub const CIRC_KEYS_LEN: usize = 20 + 20 + 16 + 16 + 20;

pub struct NtorClient {
    secret: StaticSecret,
    public: [u8; 32],
    relay_id: [u8; 20],
    relay_key: [u8; 32],
}

impl NtorClient {
    /// Start a handshake with the relay whose RSA identity digest is `relay_id` and whose ntor
    /// onion key is `relay_key`. Returns the state and the 84-byte client handshake.
    pub fn start(relay_id: [u8; 20], relay_key: [u8; 32]) -> (Self, [u8; 84]) {
        let secret = StaticSecret::from(rand_array::<32>());
        let public = PublicKey::from(&secret).to_bytes();
        let mut skin = [0u8; 84];
        skin[..20].copy_from_slice(&relay_id);
        skin[20..52].copy_from_slice(&relay_key);
        skin[52..].copy_from_slice(&public);
        (
            Self {
                secret,
                public,
                relay_id,
                relay_key,
            },
            skin,
        )
    }

    /// Check the relay's `Y | AUTH` reply and derive the hop's key material.
    pub fn finish(&self, reply: &[u8]) -> Result<[u8; CIRC_KEYS_LEN], Error> {
        if reply.len() < 64 {
            return Err(Error::Proto("short ntor reply"));
        }
        let y: [u8; 32] = reply[..32].try_into().unwrap();
        let auth = &reply[32..64];
        let xy = self.secret.diffie_hellman(&PublicKey::from(y));
        let xb = self.secret.diffie_hellman(&PublicKey::from(self.relay_key));
        if !xy.was_contributory() || !xb.was_contributory() {
            return Err(Error::Proto("ntor: degenerate key"));
        }
        let secret_input: [&[u8]; 7] = [
            xy.as_bytes(),
            xb.as_bytes(),
            &self.relay_id,
            &self.relay_key,
            &self.public,
            &y,
            NTOR_PROTOID,
        ];
        let key_seed = hmac_sha256(NTOR_KEY, &secret_input);
        let verify = hmac_sha256(NTOR_VERIFY, &secret_input);
        let expected = hmac_sha256(
            NTOR_MAC,
            &[
                &verify,
                &self.relay_id,
                &self.relay_key,
                &y,
                &self.public,
                NTOR_PROTOID,
                b"Server",
            ],
        );
        if !ct_eq(&expected, auth) {
            return Err(Error::Proto("ntor: bad auth"));
        }
        let mut keys = [0u8; CIRC_KEYS_LEN];
        hkdf_expand(&key_seed, NTOR_EXPAND, &mut keys);
        Ok(keys)
    }
}

// ---------------------------------------------------------------------------------------------
// hs-ntor (rend-spec-v3 3.3.2, NTOR-WITH-EXTRA-DATA)

const HS_PROTOID: &[u8] = b"tor-hs-ntor-curve25519-sha3-256-1";
const HS_ENC: &[u8] = b"tor-hs-ntor-curve25519-sha3-256-1:hs_key_extract";
const HS_VERIFY: &[u8] = b"tor-hs-ntor-curve25519-sha3-256-1:hs_verify";
const HS_MAC: &[u8] = b"tor-hs-ntor-curve25519-sha3-256-1:hs_mac";
const HS_EXPAND: &[u8] = b"tor-hs-ntor-curve25519-sha3-256-1:hs_key_expand";

/// The 128 bytes of end-to-end key material: `Df | Db | Kf | Kb` (SHA3-256 seeds, AES-256 keys).
pub const HS_KEYS_LEN: usize = 128;

fn hs_intro_keys(
    dh: &[u8; 32],
    auth_key: &[u8; 32],
    x: &[u8; 32],
    b: &[u8; 32],
    subcred: &[u8; 32],
) -> ([u8; 32], [u8; 32]) {
    let mut keys = [0u8; 64];
    shake256(
        &[dh, auth_key, x, b, HS_PROTOID, HS_ENC, HS_EXPAND, subcred],
        &mut keys,
    );
    (
        keys[..32].try_into().unwrap(),
        keys[32..].try_into().unwrap(),
    )
}

fn hs_rend_keys(
    xy: &[u8; 32],
    xb: &[u8; 32],
    auth_key: &[u8; 32],
    b: &[u8; 32],
    x: &[u8; 32],
    y: &[u8; 32],
) -> ([u8; 32], [u8; HS_KEYS_LEN]) {
    let mut input = Vec::with_capacity(32 * 6 + HS_PROTOID.len());
    for part in [&xy[..], xb, auth_key, b, x, y, HS_PROTOID] {
        input.extend_from_slice(part);
    }
    let key_seed = hs_mac(&input, &[HS_ENC]);
    let verify = hs_mac(&input, &[HS_VERIFY]);
    let mut auth_input = Vec::with_capacity(32 * 5 + HS_PROTOID.len() + 6);
    for part in [&verify[..], auth_key, b, y, x, HS_PROTOID, b"Server"] {
        auth_input.extend_from_slice(part);
    }
    let auth = hs_mac(&auth_input, &[HS_MAC]);
    let mut keys = [0u8; HS_KEYS_LEN];
    shake256(&[&key_seed, HS_EXPAND], &mut keys);
    (auth, keys)
}

/// What the service learns from a valid INTRODUCE2 body.
pub struct IntroOpened {
    pub plaintext: Vec<u8>,
    pub client_pk: [u8; 32],
    dh_xb: [u8; 32],
}

/// Service side, step 1: authenticate and decrypt the `ENCRYPTED` part of an INTRODUCE2 body.
///
/// `header` is everything before `CLIENT_PK`; `rest` is `CLIENT_PK | ENCRYPTED_DATA | MAC`.
pub fn hs_service_open_intro(
    enc_secret: &StaticSecret,
    enc_public: &[u8; 32],
    auth_key: &[u8; 32],
    subcred: &[u8; 32],
    header: &[u8],
    rest: &[u8],
) -> Result<IntroOpened, Error> {
    if rest.len() < 32 + 32 {
        return Err(Error::Proto("short introduce2"));
    }
    let client_pk: [u8; 32] = rest[..32].try_into().unwrap();
    let (ciphertext, mac) = rest[32..].split_at(rest.len() - 64);
    let dh = enc_secret.diffie_hellman(&PublicKey::from(client_pk));
    if !dh.was_contributory() {
        return Err(Error::Proto("introduce2: degenerate key"));
    }
    let (enc_key, mac_key) =
        hs_intro_keys(dh.as_bytes(), auth_key, &client_pk, enc_public, subcred);
    let expected = hs_mac(&mac_key, &[header, &client_pk, ciphertext]);
    if !ct_eq(&expected, mac) {
        return Err(Error::Proto("introduce2: bad mac"));
    }
    let mut plaintext = ciphertext.to_vec();
    aes256_ctr_apply(&enc_key, &[0u8; 16], &mut plaintext);
    Ok(IntroOpened {
        plaintext,
        client_pk,
        dh_xb: dh.to_bytes(),
    })
}

/// Service side, step 2: the `SERVER_PK | AUTH` body for RENDEZVOUS1 and the end-to-end keys.
pub fn hs_service_rendezvous(
    opened: &IntroOpened,
    enc_public: &[u8; 32],
    auth_key: &[u8; 32],
) -> Result<([u8; 64], [u8; HS_KEYS_LEN]), Error> {
    let y = StaticSecret::from(rand_array::<32>());
    hs_service_rendezvous_with(opened, enc_public, auth_key, &y)
}

fn hs_service_rendezvous_with(
    opened: &IntroOpened,
    enc_public: &[u8; 32],
    auth_key: &[u8; 32],
    y: &StaticSecret,
) -> Result<([u8; 64], [u8; HS_KEYS_LEN]), Error> {
    let y_pub = PublicKey::from(y).to_bytes();
    let xy = y.diffie_hellman(&PublicKey::from(opened.client_pk));
    if !xy.was_contributory() {
        return Err(Error::Proto("rendezvous: degenerate key"));
    }
    let (auth, keys) = hs_rend_keys(
        xy.as_bytes(),
        &opened.dh_xb,
        auth_key,
        enc_public,
        &opened.client_pk,
        &y_pub,
    );
    let mut body = [0u8; 64];
    body[..32].copy_from_slice(&y_pub);
    body[32..].copy_from_slice(&auth);
    Ok((body, keys))
}

/// Client side of hs-ntor, for reaching another onion service.
pub struct HsNtorClient {
    secret: StaticSecret,
    pub public: [u8; 32],
    enc_key: [u8; 32],
    auth_key: [u8; 32],
    dh_xb: [u8; 32],
}

impl HsNtorClient {
    /// Returns the client state plus the INTRODUCE1 encryption and MAC keys.
    pub fn start(
        enc_key: [u8; 32],
        auth_key: [u8; 32],
        subcred: &[u8; 32],
    ) -> Result<(Self, [u8; 32], [u8; 32]), Error> {
        let secret = StaticSecret::from(rand_array::<32>());
        let public = PublicKey::from(&secret).to_bytes();
        let dh = secret.diffie_hellman(&PublicKey::from(enc_key));
        if !dh.was_contributory() {
            return Err(Error::Proto("introduce1: degenerate key"));
        }
        let (enc, mac) = hs_intro_keys(dh.as_bytes(), &auth_key, &public, &enc_key, subcred);
        Ok((
            Self {
                secret,
                public,
                enc_key,
                auth_key,
                dh_xb: dh.to_bytes(),
            },
            enc,
            mac,
        ))
    }

    /// Check a RENDEZVOUS2 body (`SERVER_PK | AUTH`) and derive the end-to-end keys.
    pub fn finish(&self, body: &[u8]) -> Result<[u8; HS_KEYS_LEN], Error> {
        if body.len() < 64 {
            return Err(Error::Proto("short rendezvous2"));
        }
        let y: [u8; 32] = body[..32].try_into().unwrap();
        let xy = self.secret.diffie_hellman(&PublicKey::from(y));
        if !xy.was_contributory() {
            return Err(Error::Proto("rendezvous2: degenerate key"));
        }
        let (auth, keys) = hs_rend_keys(
            xy.as_bytes(),
            &self.dh_xb,
            &self.auth_key,
            &self.enc_key,
            &self.public,
            &y,
        );
        if !ct_eq(&auth, &body[32..64]) {
            return Err(Error::Proto("rendezvous2: bad auth"));
        }
        Ok(keys)
    }
}

// ---------------------------------------------------------------------------------------------
// ed25519: identity keys, blinding, signing with an expanded key

/// The ed25519 basepoint as the ASCII string rend-spec-v3 hashes into the blinding factor.
const ED_BASEPOINT_STR: &[u8] = b"(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)";

/// An ed25519 key in expanded form: the secret scalar and the nonce prefix. Tor needs this
/// form because a blinded key has no seed.
#[derive(Clone)]
pub struct EdExpanded {
    scalar: Scalar,
    prefix: [u8; 32],
    pub public: [u8; 32],
}

impl EdExpanded {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let h = sha512(&[seed]);
        let mut lower: [u8; 32] = h[..32].try_into().unwrap();
        lower[0] &= 248;
        lower[31] &= 63;
        lower[31] |= 64;
        let scalar = Scalar::from_bytes_mod_order(lower);
        let public = EdwardsPoint::mul_base(&scalar).compress().to_bytes();
        Self {
            scalar,
            prefix: h[32..].try_into().unwrap(),
            public,
        }
    }

    pub fn generate() -> Self {
        Self::from_seed(&rand_array())
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let esk = ExpandedSecretKey {
            scalar: self.scalar,
            hash_prefix: self.prefix,
        };
        let vk = VerifyingKey::from_bytes(&self.public).expect("own public key is a valid point");
        ed25519_dalek::hazmat::raw_sign::<Sha512>(&esk, msg, &vk).to_bytes()
    }

    /// The blinded keypair for one time period (rend-spec-v3 appendix A.2).
    pub fn blind(&self, period_num: u64, period_length: u64) -> Result<Self, Error> {
        let h = blinding_factor(&self.public, period_num, period_length);
        let point = CompressedEdwardsY(self.public)
            .decompress()
            .ok_or(Error::Proto("bad ed25519 key"))?;
        let public = (h * point).compress().to_bytes();
        let hash = sha512(&[b"Derive temporary signing key hash input", &self.prefix]);
        Ok(Self {
            scalar: h * self.scalar,
            prefix: hash[..32].try_into().unwrap(),
            public,
        })
    }
}

fn blinding_factor(public: &[u8; 32], period_num: u64, period_length: u64) -> Scalar {
    let mut h = sha3_256(&[
        b"Derive temporary signing key\0",
        public,
        ED_BASEPOINT_STR,
        b"key-blind",
        &period_num.to_be_bytes(),
        &period_length.to_be_bytes(),
    ]);
    h[0] &= 248;
    h[31] &= 63;
    h[31] |= 64;
    Scalar::from_bytes_mod_order(h)
}

/// Blind someone else's public identity key (what a client does to find a descriptor).
pub fn ed_blind_public(
    public: &[u8; 32],
    period_num: u64,
    period_length: u64,
) -> Result<[u8; 32], Error> {
    let h = blinding_factor(public, period_num, period_length);
    let point = CompressedEdwardsY(*public)
        .decompress()
        .ok_or(Error::Proto("bad ed25519 key"))?;
    Ok((h * point).compress().to_bytes())
}

pub fn ed_verify(public: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(sig) = Signature::from_slice(sig) else {
        return false;
    };
    VerifyingKey::from_bytes(public)
        .map(|vk| vk.verify_strict(msg, &sig).is_ok())
        .unwrap_or(false)
}

/// The ed25519 key Tor certifies in place of a curve25519 key (sign bit 0).
pub fn curve_to_ed_public(curve: &[u8; 32]) -> Result<[u8; 32], Error> {
    MontgomeryPoint(*curve)
        .to_edwards(0)
        .map(|p| p.compress().to_bytes())
        .ok_or(Error::Proto("curve25519 key has no ed25519 form"))
}

pub fn x25519_keypair() -> (StaticSecret, [u8; 32]) {
    let secret = StaticSecret::from(rand_array::<32>());
    let public = PublicKey::from(&secret).to_bytes();
    (secret, public)
}

// ---------------------------------------------------------------------------------------------
// RSA signature opening for directory documents

/// An RSA public key from a PKCS#1 `RSAPublicKey` DER structure.
pub struct RsaPublic {
    n: BigUint,
    e: BigUint,
    len: usize,
}

impl RsaPublic {
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let (seq, _) = der_take(der, 0x30)?;
        let (n, rest) = der_take(seq, 0x02)?;
        let (e, _) = der_take(rest, 0x02)?;
        let n = strip_zeros(n);
        if n.len() < 128 || n.len() > 1024 {
            return Err(Error::Parse("rsa modulus size"));
        }
        Ok(Self {
            n: BigUint::from_bytes_be(n),
            e: BigUint::from_bytes_be(e),
            len: n.len(),
        })
    }

    /// Open a PKCS#1 v1.5 type-1 signature and return the signed payload. Tor signs the raw
    /// digest with no DigestInfo wrapper.
    pub fn open(&self, sig: &[u8]) -> Result<Vec<u8>, Error> {
        let s = BigUint::from_bytes_be(sig);
        if s >= self.n {
            return Err(Error::Proto("rsa signature out of range"));
        }
        let m = s.modpow(&self.e, &self.n).to_bytes_be();
        // Left-pad to the modulus length: 00 01 FF.. 00 payload.
        if m.len() + 1 != self.len || m[0] != 0x01 {
            return Err(Error::Proto("rsa padding"));
        }
        let mut i = 1;
        while i < m.len() && m[i] == 0xff {
            i += 1;
        }
        if i < 9 || i >= m.len() || m[i] != 0x00 {
            return Err(Error::Proto("rsa padding"));
        }
        Ok(m[i + 1..].to_vec())
    }
}

fn strip_zeros(mut bytes: &[u8]) -> &[u8] {
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes = &bytes[1..];
    }
    bytes
}

/// Read one DER TLV with the expected tag; returns `(contents, remainder)`.
fn der_take(data: &[u8], tag: u8) -> Result<(&[u8], &[u8]), Error> {
    let bad = Error::Parse("der");
    if data.len() < 2 || data[0] != tag {
        return Err(bad);
    }
    let (len, header) = match data[1] {
        n if n < 0x80 => (n as usize, 2),
        0x81 if data.len() >= 3 => (data[2] as usize, 3),
        0x82 if data.len() >= 4 => (((data[2] as usize) << 8) | data[3] as usize, 4),
        _ => return Err(bad),
    };
    if data.len() < header + len {
        return Err(bad);
    }
    Ok((&data[header..header + len], &data[header + len..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::hex_decode;

    fn h32(s: &str) -> [u8; 32] {
        hex_decode(s).unwrap().try_into().unwrap()
    }

    /// rend-spec-v3 appendix G.1.
    #[test]
    fn hs_ntor_matches_the_spec_vectors() {
        let auth_key = h32("34E171E4358E501BFF21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F");
        let enc_public = h32("8E5127A40E83AABF6493E41F142B6EE3604B85A3961CD7E38D247239AFF71979");
        let enc_secret = StaticSecret::from(h32(
            "A0ED5DBF94EEB2EDB3B514E4CF6ABFF6022051CC5F103391F1970A3FCD15296A",
        ));
        let subcred = h32("0085D26A9DEBA252263BF0231AEAC59B17CA11BAD8A218238AD6487CBAD68B57");
        let body = hex_decode(
            "000000000000000000000000000000000000000002002034E171E4358E501BFF\
             21ED907E96AC6BFEF697C779D040BBAF49ACC30FC5D21F00BF04348B46D09AED\
             726F1D66C618FDEA1DE58E8CB8B89738D7356A0C59111D5DADBECCCB38E37830\
             4DCC179D3D9E437B452AF5702CED2CCFEC085BC02C4C175FA446525C1B9D5530\
             563C362FDFFB802DAB8CD9EBC7A5EE17DA62E37DEEB0EB187FBB48C63298B0E8\
             3F391B7566F42ADC97C46BA7588278273A44CE96BC68FFDAE31EF5F0913B9A9C\
             7E0F173DBC0BDDCD4ACB4C4600980A7DDD9EAEC6E7F3FA3FC37CD95E5B8BFB3E\
             35717012B78B4930569F895CB349A07538E42309C993223AEA77EF8AEA64F25D\
             DEE97DA623F1AEC0A47F150002150455845C385E5606E41A9A199E7111D54EF2\
             D1A51B7554D8B3692D85AC587FB9E69DF990EFB776D8",
        )
        .unwrap();
        // Header: legacy key id (20) + auth key type (1) + len (2) + key (32) + n_ext (1).
        let (header, rest) = body.split_at(56);
        let opened =
            hs_service_open_intro(&enc_secret, &enc_public, &auth_key, &subcred, header, rest)
                .unwrap();
        assert_eq!(
            &opened.plaintext[..20],
            &hex_decode("6BD364C12638DD5C3BE23D76ACA05B04E6CE932C").unwrap()[..]
        );
        let y = StaticSecret::from(h32(
            "68CB5188CA0CD7924250404FAB54EE1392D3D2B9C049A2E446513875952F8F55",
        ));
        let (reply, keys) =
            hs_service_rendezvous_with(&opened, &enc_public, &auth_key, &y).unwrap();
        assert_eq!(
            &reply[..32],
            &h32("8FBE0DB4D4A9C7FF46701E3E0EE7FD05CD28BE4F302460ADDEEC9E93354EE700")
        );
        assert_eq!(
            &reply[32..],
            &h32("4A92E8437B8424D5E5EC279245D5C72B25A0327ACF6DAF902079FCB643D8B208")
        );
        // A tampered MAC is refused.
        let mut bad = rest.to_vec();
        *bad.last_mut().unwrap() ^= 1;
        assert!(
            hs_service_open_intro(&enc_secret, &enc_public, &auth_key, &subcred, header, &bad)
                .is_err()
        );
        assert_eq!(keys.len(), 128);
    }

    #[test]
    fn hs_ntor_client_and_service_agree() {
        let (enc_secret, enc_public) = x25519_keypair();
        let auth_key = [7u8; 32];
        let subcred = [9u8; 32];
        let (client, enc, mac) = HsNtorClient::start(enc_public, auth_key, &subcred).unwrap();
        let header = b"header";
        let mut body = b"rendezvous cookie and friends".to_vec();
        aes256_ctr_apply(&enc, &[0u8; 16], &mut body);
        let tag = hs_mac(&mac, &[header, &client.public, &body]);
        let mut rest = client.public.to_vec();
        rest.extend_from_slice(&body);
        rest.extend_from_slice(&tag);
        let opened =
            hs_service_open_intro(&enc_secret, &enc_public, &auth_key, &subcred, header, &rest)
                .unwrap();
        assert_eq!(opened.plaintext, b"rendezvous cookie and friends");
        let (reply, service_keys) = hs_service_rendezvous(&opened, &enc_public, &auth_key).unwrap();
        assert_eq!(client.finish(&reply).unwrap(), service_keys);
    }

    #[test]
    fn blinded_signatures_verify_under_the_blinded_key() {
        let id = EdExpanded::from_seed(&[42u8; 32]);
        assert!(ed_verify(&id.public, b"m", &id.sign(b"m")));
        let blinded = id.blind(20_000, 1440).unwrap();
        assert_ne!(blinded.public, id.public);
        assert_eq!(
            ed_blind_public(&id.public, 20_000, 1440).unwrap(),
            blinded.public
        );
        let sig = blinded.sign(b"descriptor");
        assert!(ed_verify(&blinded.public, b"descriptor", &sig));
        assert!(!ed_verify(&blinded.public, b"other", &sig));
    }

    #[test]
    fn seed_expansion_matches_ed25519_dalek() {
        let seed = [3u8; 32];
        let ours = EdExpanded::from_seed(&seed);
        let theirs = ed25519_dalek::SigningKey::from_bytes(&seed);
        assert_eq!(ours.public, theirs.verifying_key().to_bytes());
        use ed25519_dalek::Signer;
        assert_eq!(ours.sign(b"x"), theirs.sign(b"x").to_bytes());
    }

    #[test]
    fn kdf_tor_blocks() {
        let mut out = [0u8; 45];
        kdf_tor(b"k0", &mut out);
        assert_eq!(&out[..20], &sha1(&[b"k0", &[0]]));
        assert_eq!(&out[40..], &sha1(&[b"k0", &[2]])[..5]);
    }
}
