//! # shade-tree-proto
//!
//! Trust-critical wire-format primitives for the Shade Tree protocol. This crate is a
//! Rust port of the security-critical checks in
//! the JavaScript reference client, and it is the reimplementation target for the
//! conformance harness (T-RUST-1).
//!
//! ## Source of truth
//!
//! The JavaScript client is the reference implementation. Where this crate and the
//! JS source disagree, the JS source wins and the drift is a bug here. Every item
//! below cites the reference `file:symbol` and the section of the wire spec it
//! implements:
//!
//! - Wire spec: `docs/WIRE-SPEC.md`
//! - Golden fixtures (byte-pinned): `testdata/vectors.json`
//!
//! ## Determinism contract (spec 6.5)
//!
//! Everything in this crate is deterministic and MUST be conformance-tested by
//! byte- or value-equality against `testdata/vectors.json`:
//!
//! - onion address, checksum, canonical announce/directory bytes,
//! - ed25519 sign/verify (RFC 8032, deterministic),
//! - `request_signal` and the `calculate_signal_hash` target binding.
//!
//! RLN Groth16 proof BYTES are non-deterministic and are therefore NOT in this
//! crate's byte-pinned surface; they are verified for validity/equivalence in the
//! client (T-RUST-2), not by byte-equality.
//!
//! ## Version tags (spec 0 — do not conflate)
//!
//! - `ANNOUNCE_VERSION` = 1 (announce record `v`)
//! - directory `version` = 1
//! - egress envelope `v` = 4 (an omitted `v` remains legacy v3 and is rejected)
//! - request-signal prefix = `shade-tree:v4`
//! - onion address version byte = `0x03`

use std::collections::{HashMap, HashSet};
use std::fmt;

use data_encoding::Specification;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use k256::ecdsa::{RecoveryId, Signature as Secp256k1Signature, VerifyingKey as Secp256k1Key};
use num_bigint::BigUint;
use sha3::{Digest, Keccak256, Sha3_256};

// --------------------------------------------------------------------------
// Internal helpers (not part of the public wire surface)
// --------------------------------------------------------------------------

/// Base32, lowercase, NO padding, alphabet `abcdefghijklmnopqrstuvwxyz234567`.
/// Mirrors `lib/directory.mjs:63 B32` exactly (Tor v3 onion alphabet).
fn base32() -> data_encoding::Encoding {
    let mut spec = Specification::new();
    spec.symbols.push_str("abcdefghijklmnopqrstuvwxyz234567");
    // padding stays None => no `=` padding, matching JS base32Encode/Decode.
    spec.encoding().expect("valid base32 spec")
}

/// Two-byte v3 onion checksum: `SHA3-256(".onion checksum" || pubkey || 0x03)[:2]`.
/// Reference: `lib/directory.mjs:105`/`:117`.
fn onion_checksum(pubkey: &[u8; 32]) -> [u8; 2] {
    let mut h = Sha3_256::new();
    h.update(b".onion checksum");
    h.update(pubkey);
    h.update([0x03u8]);
    let digest = h.finalize();
    [digest[0], digest[1]]
}

/// Append a JSON string literal to `out` with the exact escaping `JSON.stringify`
/// emits: `"` `\` and the C0 controls (`\b \t \n \f \r`, else `\u00XX`). The onion
/// alphabet and hex fields never need escaping, but this keeps the encoders faithful
/// to `JSON.stringify` for any field value.
fn push_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0a}' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\u{0d}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

// --------------------------------------------------------------------------
// Errors
// --------------------------------------------------------------------------

/// Error type carrying the exact reason strings the JS reference emits, so the
/// Rust checks can reproduce spec reason codes verbatim (spec 2, 3.4, 4.3, 6.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// An `onionToPubkey` failure message from spec section 2, verbatim, e.g.
    /// `"onion checksum mismatch"`.
    Onion(&'static str),
    /// A `verify*` reason code, e.g. `"bad-signature"` or `"replayed-nonce"`.
    Reason(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Onion(m) => write!(f, "{m}"),
            Error::Reason(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {}

/// Crate result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Bootnode announce record version (`bootnode/announce.mjs`).
pub const ANNOUNCE_VERSION: u64 = 1;

// --------------------------------------------------------------------------
// Record types (spec 3 announce, spec 4.1 directory)
// --------------------------------------------------------------------------

/// One gateway entry inside a signed directory (spec 4.1). Only the first four
/// fields (`onion`, `pubkey`, `weight`, `health`) are covered by the directory
/// signature (spec 1.2); `operator`/`staked` are labels and MUST be excluded from
/// [`canonical_directory_bytes`].
#[derive(Debug, Clone)]
pub struct GatewayEntry {
    /// v3 `.onion` address (with suffix).
    pub onion: String,
    /// lowercase hex ed25519 pubkey; MUST equal `onion_to_pubkey(onion)`.
    pub pubkey: String,
    /// selection weight.
    pub weight: u64,
    /// health label, `"up"` for every entry the bootnode emits.
    pub health: String,
    /// operator address label (NOT signed). Present only when the entry had one.
    pub operator: Option<String>,
    /// stake label (NOT signed). Present only when the entry had an operator.
    pub staked: Option<bool>,
    /// T-FEAT-10 self-declared coarse capabilities. OPTIONAL and additive: `None`
    /// (or a value that canonicalizes empty) OMITS the `caps`/`capsSig` fields from
    /// [`canonical_directory_bytes`], so a no-caps entry is byte-identical to before.
    /// Mirrors `g.caps` on a JS directory entry (`lib/directory.mjs`).
    pub caps: Option<Caps>,
    /// T-FEAT-10 onion-bound signature over exactly these caps ([`canonical_caps_bytes`]),
    /// signed by the gateway's OWN onion key. When `caps` is present this MUST verify
    /// (`check_gateway_bindings` -> `bad-caps-sig`), so a bootnode/directory signer that
    /// lacks the onion key cannot forge or alter caps. Mirrors `g.capsSig`.
    pub caps_sig: Option<String>,
}

/// A signed directory (spec 4.1). `signer`/`signature` are top-level and excluded
/// from the canonical signed bytes (spec 1.2).
///
/// The `signers`/`signatures`/`threshold` fields are the OPTIONAL M-of-N threshold
/// extension (T-FEAT-9 / T-FEAT-9b). Like `signer`/`signature`, they are top-level and
/// EXCLUDED from [`canonical_directory_bytes`] — every threshold signer signs the SAME
/// canonical bytes as the single-sig path. A directory carrying ANY of the three is in
/// threshold mode (see [`verify_directory_threshold`]); a directory carrying none takes
/// the unchanged single-`signer` path, so an existing directory is byte-for-byte the old
/// behavior. Reference: `lib/directory.mjs` (`isThresholdDirectory`, `signDirectoryThreshold`,
/// `verifyDirectoryThreshold`).
#[derive(Debug, Clone)]
pub struct Directory {
    /// directory format version (== 1).
    pub version: u64,
    /// issuance time, unix seconds.
    pub issued: u64,
    /// live gateway entries, order-significant.
    pub gateways: Vec<GatewayEntry>,
    /// hex ed25519 pubkey of the pinned signer (label; not self-signed).
    pub signer: Option<String>,
    /// hex ed25519 signature over `canonical_directory_bytes(dir)`.
    pub signature: Option<String>,
    /// M-of-N: hex ed25519 pubkeys of the N signers (NOT signed; positional with
    /// `signatures`). `None` == single-sig directory.
    pub signers: Option<Vec<String>>,
    /// M-of-N: hex ed25519 signatures over `canonical_directory_bytes(dir)`, positional
    /// with `signers`. `None` == single-sig directory.
    pub signatures: Option<Vec<String>>,
    /// M-of-N: how many DISTINCT pinned signers must produce a valid signature. Typed
    /// `i64` so a non-positive threshold is representable and rejected `bad-threshold`
    /// (mirrors the JS `Number.isInteger && >= 1` guard). `None` == single-sig directory.
    pub threshold: Option<i64>,
}

/// An announce record (spec 3). Built by `bootnode/announce.mjs:51 buildAnnounce`,
/// verified by `:80 verifyAnnounce`.
#[derive(Debug, Clone)]
pub struct Announce {
    /// `== ANNOUNCE_VERSION` (1).
    pub v: u64,
    /// v3 `.onion` (with suffix).
    pub onion: String,
    /// selection weight (default 100).
    pub weight: u64,
    /// unix seconds; freshness-checked.
    pub ts: u64,
    /// 16 random bytes hex (32 hex chars); replay key.
    pub nonce: String,
    /// ed25519 hex over `canonical_announce_bytes(rec)`, signed by the onion key.
    pub onion_sig: Option<String>,
    /// Ethereum address, lowercased (optional).
    pub operator: Option<String>,
    /// EIP-191 `personal_sign` over `operator_auth_message` (optional).
    pub operator_sig: Option<String>,
    /// T-FEAT-10 self-declared caps that ride INSIDE the main onion-signed announce bytes
    /// (appended after `nonce`), OPTIONAL/additive: `None`/empty omits the field so a
    /// no-caps announce is byte-identical to before. Unlike the directory entry there is
    /// NO separate `capsSig` on the announce — the caps are covered by `onion_sig`.
    pub caps: Option<Caps>,
    /// Optional durable onion-key signature over [`canonical_caps_bytes`].  The
    /// main `onion_sig` already covers caps in this announce; when this standalone
    /// signature is present it is also checked because it is the signature copied
    /// into directory entries.
    pub caps_sig: Option<String>,
}

// --------------------------------------------------------------------------
// 2. v3 onion <-> ed25519 identity key
// --------------------------------------------------------------------------

/// Recover the 32-byte ed25519 public key that a v3 `.onion` address IS.
///
/// Reference: `lib/directory.mjs:96 onionToPubkey` (spec 2).
///
/// The 56-char base32 address (with or without the `.onion` suffix) decodes to 35
/// bytes: `pubkey[32] || checksum[2] || version[1]`, where
/// `checksum = SHA3-256(b".onion checksum" || pubkey || 0x03)[:2]` and
/// `version == 0x03`.
///
/// Returns the verbatim spec-2 message on failure (`Error::Onion`):
/// `bad base32 char in onion`, `not a v3 onion (expected 56 chars)`,
/// `v3 onion decodes to 35 bytes`, `not onion version 3`, `onion checksum mismatch`.
pub fn onion_to_pubkey(onion: &str) -> Result<[u8; 32]> {
    // Strip a trailing ".onion" suffix (case-insensitive) and lowercase, mirroring
    // `addr = onion.replace(/\.onion$/, "").toLowerCase()` (lib/directory.mjs:97).
    let lower = onion.to_lowercase();
    let addr = lower.strip_suffix(".onion").unwrap_or(&lower);
    if addr.len() != 56 {
        return Err(Error::Onion("not a v3 onion (expected 56 chars)"));
    }
    let decoded = base32()
        .decode(addr.as_bytes())
        .map_err(|_| Error::Onion("bad base32 char in onion"))?;
    if decoded.len() != 35 {
        return Err(Error::Onion("v3 onion decodes to 35 bytes"));
    }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&decoded[0..32]);
    let checksum = &decoded[32..34];
    let version = decoded[34];
    if version != 0x03 {
        return Err(Error::Onion("not onion version 3"));
    }
    if checksum != onion_checksum(&pubkey) {
        return Err(Error::Onion("onion checksum mismatch"));
    }
    Ok(pubkey)
}

/// Encode a 32-byte ed25519 public key as a v3 `.onion` address (with suffix).
///
/// Reference: `lib/directory.mjs:114 pubkeyToOnion` (spec 2). Inverse of
/// [`onion_to_pubkey`]. The address string is 56 base32 no-pad lowercase chars.
pub fn pubkey_to_onion(pubkey: &[u8; 32]) -> String {
    let checksum = onion_checksum(pubkey);
    let mut buf = Vec::with_capacity(35);
    buf.extend_from_slice(pubkey);
    buf.extend_from_slice(&checksum);
    buf.push(0x03);
    format!("{}.onion", base32().encode(&buf))
}

// --------------------------------------------------------------------------
// T-FEAT-10 gateway capability advertisement (caps)
// --------------------------------------------------------------------------
//
// Reference: `lib/directory.mjs` (`CAPS_DOMAIN`, `REGION_BUCKETS`, `canonicalCaps`,
// `hasCaps`, `canonicalCapsBytes`, `verifyCapsSig`). A gateway self-declares COARSE,
// BUCKETED capabilities (allowed egress ports, a coarse region bucket, the supported
// proto envelope range) so a client can route to a CAPABLE gateway. Three rules mirror
// the JS exactly:
//   1. ADDITIVE / OMIT-WHEN-ABSENT: caps are optional; a no-caps entry serializes
//      byte-IDENTICALLY (the canonical-bytes builders append caps ONLY when `has_caps`).
//   2. SIGNED UNDER THE ONION KEY: a directory entry carries a durable, onion-bound
//      `capsSig` ([`canonical_caps_bytes`]) so the caps are unforgeable by a bootnode /
//      directory signer that lacks the gateway's onion key.
//   3. BUCKETED, NOT FINGERPRINTABLE + TOTAL: [`canonical_caps`] dedups/sorts ports,
//      range-checks the proto range, and drops any junk/unknown field — it never fails.

/// Domain tag the onion key signs its caps under (`lib/directory.mjs:143 CAPS_DOMAIN`).
/// The trailing `\n` is a literal newline byte.
pub const CAPS_DOMAIN: &str = "Shade Tree gateway capabilities v1\n";
/// A gateway advertising NO caps is assumed to allow only this egress port
/// (`lib/directory.mjs:150 DEFAULT_EGRESS_PORT`), the conservative floor used by the
/// capability-aware selection filter.
pub const DEFAULT_EGRESS_PORT: u64 = 443;
/// A gateway advertising NO caps is assumed to speak only this proto version
/// (`lib/directory.mjs:151 DEFAULT_PROTO_VERSION`).
pub const DEFAULT_PROTO_VERSION: u64 = 4;

/// True iff `r` is one of the coarse continent/AS region buckets
/// (`lib/directory.mjs:146 REGION_BUCKETS`). Anything else is dropped by
/// [`canonical_caps`] — deliberately too coarse to fingerprint a member.
pub fn is_region_bucket(r: &str) -> bool {
    matches!(
        r,
        "na" | "sa" | "eu" | "af" | "as" | "oc" | "aq" | "unknown"
    )
}

/// The proto version range a gateway supports (`caps.proto = { min, max }`). Typed `i64`
/// so an out-of-range/garbage range parses and is dropped by [`canonical_caps`] rather
/// than aborting (mirrors the JS `Number.isInteger` guard being total over junk).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtoCaps {
    pub min: i64,
    pub max: i64,
}

/// RAW, untrusted gateway capabilities as carried on a directory entry / announce, before
/// [`canonical_caps`] normalization. `ports` are `i64` (out-of-range/dupe values are
/// dropped/deduped at canonicalization, not here); `region`/`proto` are validated there
/// too. Mirrors the shape `g.caps` takes on the JS wire (`lib/directory.mjs`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Caps {
    pub ports: Option<Vec<i64>>,
    pub region: Option<String>,
    pub proto: Option<ProtoCaps>,
    /// T-HARD-8: the ZK artifact ids the gateway verifies proofs under (raw; validated,
    /// deduped + sorted by [`canonical_caps`]). Mirrors `caps.artifacts`.
    pub artifacts: Option<Vec<String>>,
    /// T-FEAT-9: the ADMISSION PATHS the gateway honours (raw; validated against
    /// [`ADMIT_PATHS`], deduped, put in anonymity order by [`canonical_caps`]).
    /// Mirrors `caps.admits`. Absent = a legacy gateway (may admit any path).
    pub admits: Option<Vec<String>>,
    /// T-FEAT-9: the provider's payment advert when it SELLS access (raw; a half/oversized
    /// advert is dropped whole by [`canonical_caps`]). Mirrors `caps.pay`.
    pub pay: Option<PayCaps>,
    /// Epoch and per-slot payload policy enforced by this gateway. This is signed
    /// with every other capability and canonicalizes after `pay` so all older
    /// caps byte strings remain unchanged when it is absent.
    pub rate: Option<RateCaps>,
}

/// RAW, untrusted `caps.pay` (T-FEAT-9): `{ protocols, onion?, port, asset, chain, tiers }`.
/// `tiers` is `(limit, price)` pairs as carried on the wire (object keys/values as strings;
/// an integer price parses to its decimal string upstream). Validated + normalized only by
/// [`canonical_pay`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PayCaps {
    pub protocols: Option<Vec<String>>,
    pub onion: Option<String>,
    pub port: Option<i64>,
    pub asset: Option<String>,
    pub chain: Option<String>,
    pub tiers: Option<Vec<(String, String)>>,
}

/// Canonical `caps.pay`: protocols in the fixed order [`PAY_PROTOCOLS`], onion lowercased
/// (present only when valid), asset lowercased, tiers sorted by numeric limit. Mirrors the
/// object `canonicalPay` returns (`lib/directory.mjs`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CanonicalPay {
    pub protocols: Vec<String>,
    pub onion: Option<String>,
    pub port: u64,
    pub asset: String,
    pub chain: String,
    pub tiers: Vec<(u64, String)>,
}

/// RAW, untrusted fixed-window Grove rate policy (`caps.rate`). Signed gateways
/// use this to bind the client's epoch calculation and per-slot payload budget
/// to the gateway's actual enforcement settings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RateCaps {
    pub scope: String,
    pub window: String,
    pub epoch_seconds: i64,
    pub previous_epochs_accepted: i64,
    pub root_freshness_seconds: i64,
    pub payload_bytes_per_slot: i64,
}

/// Valid canonical `caps.rate`, serialized in the field order shown here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CanonicalRate {
    pub scope: String,
    pub window: String,
    pub epoch_seconds: u64,
    pub previous_epochs_accepted: u64,
    pub root_freshness_seconds: u64,
    pub payload_bytes_per_slot: u64,
}

/// Canonicalized caps: fixed field order (ports, region, proto, artifacts, admits, pay, rate),
/// ports deduped + sorted ascending, artifacts deduped + sorted, admits deduped in anonymity
/// order, payment/rate policies normalized, only valid fields retained. The value
/// [`canonical_caps_json`] serializes and [`has_caps`] tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CanonicalCaps {
    pub ports: Option<Vec<u64>>,
    pub region: Option<String>,
    pub proto: Option<(u64, u64)>,
    pub artifacts: Option<Vec<String>>,
    pub admits: Option<Vec<String>>,
    pub pay: Option<CanonicalPay>,
    pub rate: Option<CanonicalRate>,
}

/// Upper bound on advertised artifact ids (`lib/directory.mjs MAX_CAPS_ARTIFACTS`); a longer
/// list is dropped entirely by [`canonical_caps`] (an ad can't balloon).
pub const MAX_CAPS_ARTIFACTS: usize = 8;

/// T-FEAT-9 (docs/adr/0008): the admission paths in ANONYMITY ORDER (most anonymous first) —
/// `lib/directory.mjs ADMIT_PATHS` / `lib/admission.mjs ADMIT_ORDER`. This order is canonical.
pub const ADMIT_PATHS: [&str; 3] = ["invited", "staked", "paid"];
/// T-FEAT-9: the payment rails, fixed order (`lib/directory.mjs PAY_PROTOCOLS`).
pub const PAY_PROTOCOLS: [&str; 2] = ["x402", "mpp"];
/// Upper bound on advertised price tiers (`lib/directory.mjs MAX_CAPS_PAY_TIERS`); more (or none)
/// drops the whole `pay` advert.
pub const MAX_CAPS_PAY_TIERS: usize = 8;

/// The `admits` field alone (`lib/directory.mjs canonicalAdmits`): valid names, deduped, in
/// [`ADMIT_PATHS`] order; empty when nothing valid (the caller omits it). TOTAL.
pub fn canonical_admits(list: &[String]) -> Vec<String> {
    let lowered: Vec<String> = list.iter().map(|a| a.to_ascii_lowercase()).collect();
    ADMIT_PATHS
        .iter()
        .filter(|p| lowered.iter().any(|a| a == *p))
        .map(|p| p.to_string())
        .collect()
}

fn is_hex_str(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}
fn is_canonical_uint(s: &str, max_len: usize) -> bool {
    !s.is_empty()
        && s.len() <= max_len
        && s.bytes().all(|b| b.is_ascii_digit())
        && !s.starts_with('0')
}
/// A v3 onion address shape: 56 base32 chars + `.onion` (lowercased by the caller).
fn is_v3_onion_shape(o: &str) -> bool {
    o.len() == 62
        && o.ends_with(".onion")
        && o[..56]
            .bytes()
            .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
}

/// The `pay` field alone (`lib/directory.mjs canonicalPay`): `None` unless it forms a complete,
/// bounded advert (protocols ⊆ PAY_PROTOCOLS non-empty; port 1..=65535; asset 0x-hex-40; chain
/// `eip155:<1..16 digits, no leading zero>`; 1..=MAX_CAPS_PAY_TIERS tiers with canonical integer
/// limits 1..=65535 and canonical decimal prices ≤ 40 digits). `onion` kept only when it is a
/// v3 onion shape (lowercased). TOTAL.
pub fn canonical_pay(pay: &PayCaps) -> Option<CanonicalPay> {
    let protos: Vec<String> = pay
        .protocols
        .as_ref()
        .map(|l| l.iter().map(|p| p.to_ascii_lowercase()).collect())
        .unwrap_or_default();
    let protocols: Vec<String> = PAY_PROTOCOLS
        .iter()
        .filter(|p| protos.iter().any(|a| a == *p))
        .map(|p| p.to_string())
        .collect();
    if protocols.is_empty() {
        return None;
    }
    let onion = pay
        .onion
        .as_ref()
        .map(|o| o.to_ascii_lowercase())
        .filter(|o| is_v3_onion_shape(o));
    let port = match pay.port {
        Some(p) if (1..=65535).contains(&p) => p as u64,
        _ => return None,
    };
    let asset = match &pay.asset {
        Some(a) if a.len() == 42 && a.starts_with("0x") && is_hex_str(&a[2..]) => {
            a.to_ascii_lowercase()
        }
        _ => return None,
    };
    let chain = match &pay.chain {
        Some(c) if c.starts_with("eip155:") && is_canonical_uint(&c[7..], 16) => c.clone(),
        _ => return None,
    };
    let mut tiers: Vec<(u64, String)> = Vec::new();
    for (k, v) in pay.tiers.as_deref().unwrap_or(&[]) {
        if !is_canonical_uint(k, 5) {
            continue;
        }
        let limit: u64 = match k.parse() {
            Ok(n) if (1..=65535).contains(&n) => n,
            _ => continue,
        };
        if !is_canonical_uint(v, 40) {
            continue;
        }
        if tiers.iter().any(|(l, _)| *l == limit) {
            continue; // first occurrence wins (a JS object cannot carry a duplicate key anyway)
        }
        tiers.push((limit, v.clone()));
    }
    tiers.sort_by_key(|(l, _)| *l);
    if tiers.is_empty() || tiers.len() > MAX_CAPS_PAY_TIERS {
        return None;
    }
    Some(CanonicalPay {
        protocols,
        onion,
        port,
        asset,
        chain,
        tiers,
    })
}

/// Canonicalize the signed fixed-window rate policy. Unknown policy families or
/// nonsensical/unbounded integer values are omitted, just like the other optional
/// capability families. Valid policies remain visible even when their values differ
/// from a client's expected deployment policy, allowing the client to fail closed on
/// a precise signed mismatch.
pub fn canonical_rate(rate: &RateCaps) -> Option<CanonicalRate> {
    if rate.scope != "grove-v4"
        || rate.window != "fixed"
        || !(1..=86_400).contains(&rate.epoch_seconds)
        || !(0..=16).contains(&rate.previous_epochs_accepted)
        || !(1..=86_400).contains(&rate.root_freshness_seconds)
        || rate.payload_bytes_per_slot <= 0
    {
        return None;
    }
    Some(CanonicalRate {
        scope: rate.scope.clone(),
        window: rate.window.clone(),
        epoch_seconds: rate.epoch_seconds as u64,
        previous_epochs_accepted: rate.previous_epochs_accepted as u64,
        root_freshness_seconds: rate.root_freshness_seconds as u64,
        payload_bytes_per_slot: rate.payload_bytes_per_slot as u64,
    })
}

/// Normalize raw caps into canonical bucketed form (`lib/directory.mjs:156 canonicalCaps`).
/// TOTAL: never fails; unknown/invalid fields are dropped; a fully-empty result is returned
/// when nothing valid remains (which every canonical-bytes builder treats as absent).
///   - ports: keep integers in `[1, 65535]`, dedup, sort ascending; drop when empty.
///   - region: keep iff a known coarse bucket ([`is_region_bucket`]).
///   - proto: keep `{min,max}` iff `min >= 1 && max >= min`.
pub fn canonical_caps(caps: &Caps) -> CanonicalCaps {
    let mut out = CanonicalCaps::default();
    if let Some(ports) = &caps.ports {
        let mut v: Vec<u64> = ports
            .iter()
            .copied()
            .filter(|p| (1..=65535).contains(p))
            .map(|p| p as u64)
            .collect();
        v.sort_unstable();
        v.dedup();
        if !v.is_empty() {
            out.ports = Some(v);
        }
    }
    if let Some(r) = &caps.region {
        if is_region_bucket(r) {
            out.region = Some(r.clone());
        }
    }
    if let Some(p) = &caps.proto {
        if p.min >= 1 && p.max >= p.min {
            out.proto = Some((p.min as u64, p.max as u64));
        }
    }
    // T-HARD-8: artifact ids — grammar-checked, deduped, sorted (JS default sort == byte
    // order for this ASCII grammar), count-bounded; appended LAST so pre-existing caps
    // canonicalize to byte-identical JSON.
    if let Some(list) = &caps.artifacts {
        let mut v: Vec<String> = list.iter().filter(|a| is_artifact_id(a)).cloned().collect();
        v.sort_unstable();
        v.dedup();
        if !v.is_empty() && v.len() <= MAX_CAPS_ARTIFACTS {
            out.artifacts = Some(v);
        }
    }
    // T-FEAT-9: admission policy + payment advert. The rate policy is appended after pay so
    // every caps byte string from before rate negotiation remains byte-identical when absent.
    if let Some(list) = &caps.admits {
        let v = canonical_admits(list);
        if !v.is_empty() {
            out.admits = Some(v);
        }
    }
    if let Some(p) = &caps.pay {
        out.pay = canonical_pay(p);
    }
    if let Some(rate) = &caps.rate {
        out.rate = canonical_rate(rate);
    }
    out
}

/// True iff caps carry at least one valid bucketed field after canonicalization
/// (`lib/directory.mjs:173 hasCaps`). Used to OMIT the `caps` field from canonical bytes
/// when empty, keeping absent/empty-caps records byte-identical to before.
pub fn has_caps(caps: &Caps) -> bool {
    let c = canonical_caps(caps);
    c.ports.is_some()
        || c.region.is_some()
        || c.proto.is_some()
        || c.artifacts.is_some()
        || c.admits.is_some()
        || c.pay.is_some()
        || c.rate.is_some()
}

/// Serialize canonical caps as the exact `JSON.stringify(canonicalCaps(caps))` bytes:
/// `{"ports":[..],"region":"..","proto":{"min":..,"max":..}}` in that fixed order, each
/// field present only when set. Hand-built (no serializer) to match byte-for-byte.
fn canonical_caps_json(cc: &CanonicalCaps) -> String {
    let mut s = String::from("{");
    let mut first = true;
    if let Some(ports) = &cc.ports {
        s.push_str("\"ports\":[");
        for (i, p) in ports.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&p.to_string());
        }
        s.push(']');
        first = false;
    }
    if let Some(r) = &cc.region {
        if !first {
            s.push(',');
        }
        s.push_str("\"region\":");
        push_json_string(&mut s, r);
        first = false;
    }
    if let Some((min, max)) = &cc.proto {
        if !first {
            s.push(',');
        }
        s.push_str("\"proto\":{\"min\":");
        s.push_str(&min.to_string());
        s.push_str(",\"max\":");
        s.push_str(&max.to_string());
        s.push('}');
        first = false;
    }
    if let Some(arts) = &cc.artifacts {
        if !first {
            s.push(',');
        }
        s.push_str("\"artifacts\":[");
        for (i, a) in arts.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            push_json_string(&mut s, a);
        }
        s.push(']');
        first = false;
    }
    // T-FEAT-9: `admits` then `pay`, exactly as JSON.stringify(canonicalCaps(..)) emits them.
    if let Some(adm) = &cc.admits {
        if !first {
            s.push(',');
        }
        s.push_str("\"admits\":[");
        for (i, a) in adm.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            push_json_string(&mut s, a);
        }
        s.push(']');
        first = false;
    }
    if let Some(p) = &cc.pay {
        if !first {
            s.push(',');
        }
        s.push_str("\"pay\":{\"protocols\":[");
        for (i, a) in p.protocols.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            push_json_string(&mut s, a);
        }
        s.push(']');
        if let Some(o) = &p.onion {
            s.push_str(",\"onion\":");
            push_json_string(&mut s, o);
        }
        s.push_str(",\"port\":");
        s.push_str(&p.port.to_string());
        s.push_str(",\"asset\":");
        push_json_string(&mut s, &p.asset);
        s.push_str(",\"chain\":");
        push_json_string(&mut s, &p.chain);
        // tiers: JS orders integer-like keys ascending, so `{"8":"..","32":".."}` — same here.
        s.push_str(",\"tiers\":{");
        for (i, (l, price)) in p.tiers.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            push_json_string(&mut s, &l.to_string());
            s.push(':');
            push_json_string(&mut s, price);
        }
        s.push_str("}}");
        first = false;
    }
    if let Some(rate) = &cc.rate {
        if !first {
            s.push(',');
        }
        s.push_str("\"rate\":{\"scope\":");
        push_json_string(&mut s, &rate.scope);
        s.push_str(",\"window\":");
        push_json_string(&mut s, &rate.window);
        s.push_str(",\"epochSeconds\":");
        s.push_str(&rate.epoch_seconds.to_string());
        s.push_str(",\"previousEpochsAccepted\":");
        s.push_str(&rate.previous_epochs_accepted.to_string());
        s.push_str(",\"rootFreshnessSeconds\":");
        s.push_str(&rate.root_freshness_seconds.to_string());
        s.push_str(",\"payloadBytesPerSlot\":");
        s.push_str(&rate.payload_bytes_per_slot.to_string());
        s.push('}');
    }
    s.push('}');
    s
}

/// Domain-separated, onion-bound canonical bytes the ONION key signs to attest its caps
/// (`lib/directory.mjs:183 canonicalCapsBytes`):
/// `utf8(CAPS_DOMAIN) || utf8(JSON.stringify({ onion, caps: canonicalCaps(caps) }))`.
/// DURABLE (no timestamp) so it is reusable across heartbeats and re-verifiable from a
/// directory entry. Runs caps through [`canonical_caps`] so key order/junk can't shift bytes.
/// Conformance target: `testdata/vectors.json` `capabilities.canonicalCapsBytesHex`.
pub fn canonical_caps_bytes(onion: &str, caps: &Caps) -> Vec<u8> {
    let cc = canonical_caps(caps);
    let mut s = String::from(CAPS_DOMAIN);
    s.push_str("{\"onion\":");
    push_json_string(&mut s, onion);
    s.push_str(",\"caps\":");
    s.push_str(&canonical_caps_json(&cc));
    s.push('}');
    s.into_bytes()
}

/// Verify a caps attestation against the ed25519 key encoded in the onion address
/// (`lib/directory.mjs:194 verifyCapsSig` -> `verifyOnionControl`). TOTAL: an
/// absent/empty/garbage signature or a malformed onion returns `false`, never panics.
/// This is the check that makes caps unforgeable by a bootnode/directory signer that
/// lacks the gateway's onion key.
pub fn verify_caps_sig(onion: &str, caps: &Caps, caps_sig: Option<&str>) -> bool {
    let Some(sig_hex) = caps_sig else {
        return false;
    };
    if sig_hex.is_empty() {
        return false;
    }
    let pubkey = match onion_to_pubkey(onion) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    (|| -> Option<bool> {
        let sig: [u8; 64] = hex::decode(sig_hex).ok()?.try_into().ok()?;
        Some(ed25519_verify(
            &canonical_caps_bytes(onion, caps),
            &sig,
            &pubkey,
        ))
    })()
    .unwrap_or(false)
}

// --------------------------------------------------------------------------
// 1. Canonical byte encodings
// --------------------------------------------------------------------------

/// Canonical signed bytes of an announce record (spec 1.1).
///
/// Reference: `bootnode/announce.mjs:38 canonicalAnnounceBytes`.
///
/// `utf8(JSON.stringify({ v, onion, weight, ts, nonce }))` in exactly that key
/// order, no whitespace. `onionSig`/`operator`/`operatorSig` are EXCLUDED.
///
/// This MUST be produced by hand-building the byte string in fixed key order, NOT
/// by a general JSON serializer (key order and number formatting must match the JS
/// `JSON.stringify` output byte-for-byte; see `testdata/vectors.json`
/// `canonicalAnnounceBytesHex`).
pub fn canonical_announce_bytes(ann: &Announce) -> Vec<u8> {
    // Hand-built in fixed key order { v, onion, weight, ts, nonce }, no whitespace,
    // matching `JSON.stringify` byte-for-byte (bootnode/announce.mjs:38).
    let mut s = String::new();
    s.push_str("{\"v\":");
    s.push_str(&ann.v.to_string());
    s.push_str(",\"onion\":");
    push_json_string(&mut s, &ann.onion);
    s.push_str(",\"weight\":");
    s.push_str(&ann.weight.to_string());
    s.push_str(",\"ts\":");
    s.push_str(&ann.ts.to_string());
    s.push_str(",\"nonce\":");
    push_json_string(&mut s, &ann.nonce);
    // T-FEAT-10: caps ride inside the onion-signed announce bytes ONLY when present,
    // appended AFTER `nonce` (mirrors bootnode/announce.mjs appending caps when hasCaps).
    // A no-caps announce is byte-identical to before. Conformance: `announceWithCaps`.
    if let Some(caps) = &ann.caps {
        if has_caps(caps) {
            s.push_str(",\"caps\":");
            s.push_str(&canonical_caps_json(&canonical_caps(caps)));
        }
    }
    s.push('}');
    s.into_bytes()
}

/// Canonical signed bytes of a directory (spec 1.2).
///
/// Reference: `lib/directory.mjs:129 canonicalDirectoryBytes`.
///
/// `utf8(JSON.stringify({ version, issued, gateways: [{ onion, pubkey, weight,
/// health }, ...] }))`. Only those four gateway fields, in that order, are covered;
/// top-level `signer`/`signature` and per-gateway `operator`/`staked` are EXCLUDED.
/// Hand-build the bytes in fixed key order (see [`canonical_announce_bytes`]).
pub fn canonical_directory_bytes(dir: &Directory) -> Vec<u8> {
    // Fixed key order { version, issued, gateways:[{ onion, pubkey, weight, health }] },
    // no whitespace, matching `JSON.stringify` (lib/directory.mjs:129). Top-level
    // signer/signature and per-gateway operator/staked are EXCLUDED.
    let mut s = String::new();
    s.push_str("{\"version\":");
    s.push_str(&dir.version.to_string());
    s.push_str(",\"issued\":");
    s.push_str(&dir.issued.to_string());
    s.push_str(",\"gateways\":[");
    for (i, g) in dir.gateways.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str("{\"onion\":");
        push_json_string(&mut s, &g.onion);
        s.push_str(",\"pubkey\":");
        push_json_string(&mut s, &g.pubkey);
        s.push_str(",\"weight\":");
        s.push_str(&g.weight.to_string());
        s.push_str(",\"health\":");
        push_json_string(&mut s, &g.health);
        // T-FEAT-10: caps + their onion-control signature ride in the signed bytes ONLY
        // when present, appended AFTER the four legacy fields (mirrors
        // lib/directory.mjs:218: `if (hasCaps(g.caps)) { e.caps = ...; if capsSig ... }`).
        // An entry WITHOUT caps serializes byte-identically to before. capsSig is appended
        // only when it is a string (`Some`), exactly like the JS `typeof g.capsSig ===
        // "string"` guard. Conformance: `directoryWithCaps.canonicalBytesHex`.
        if let Some(caps) = &g.caps {
            if has_caps(caps) {
                s.push_str(",\"caps\":");
                s.push_str(&canonical_caps_json(&canonical_caps(caps)));
                if let Some(sig) = &g.caps_sig {
                    s.push_str(",\"capsSig\":");
                    push_json_string(&mut s, sig);
                }
            }
        }
        s.push('}');
    }
    s.push_str("]}");
    s.into_bytes()
}

// --------------------------------------------------------------------------
// 3. ed25519 primitives (RFC 8032, null digest, raw 32-byte seed/pubkey)
// --------------------------------------------------------------------------

/// Derive the raw 32-byte ed25519 public key from a 32-byte seed.
///
/// Reference: `lib/directory.mjs ed25519PublicKey`. Deterministic (RFC 8032).
/// Conformance: `testdata/vectors.json` `signerSeed -> signerPub`,
/// `onionSeed -> onionPub`.
pub fn ed25519_public_key(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// ed25519 sign `msg` with a raw 32-byte seed (RFC 8032, deterministic).
///
/// Reference: `lib/directory.mjs:46 ed25519Sign` = `crypto.sign(null, msg, key)`.
/// Returns the 64-byte signature. Conformance targets: `directorySignature`,
/// `announceOnionSig` in `testdata/vectors.json`.
pub fn ed25519_sign(msg: &[u8], seed: &[u8; 32]) -> [u8; 64] {
    SigningKey::from_bytes(seed).sign(msg).to_bytes()
}

/// Verify a 64-byte ed25519 signature over `msg` against a raw 32-byte pubkey.
///
/// Reference: `lib/directory.mjs ed25519Verify`. Used by [`verify_directory`] and
/// the announce onion-control check.
pub fn ed25519_verify(msg: &[u8], sig: &[u8; 64], pubkey: &[u8; 32]) -> bool {
    // `verify` (not `verify_strict`) matches node's `crypto.verify(null, ...)` /
    // RFC 8032 cofactored equation used by the JS reference (lib/directory.mjs:50).
    let vk = match VerifyingKey::from_bytes(pubkey) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    vk.verify(msg, &Signature::from_bytes(sig)).is_ok()
}

// --------------------------------------------------------------------------
// 4.3 verifyDirectory / 3.4 verifyAnnounce
// --------------------------------------------------------------------------

/// True iff a directory is in M-of-N threshold mode — it carries ANY of the optional
/// `threshold`/`signers`/`signatures` fields (`lib/directory.mjs:217 isThresholdDirectory`).
/// When none are present, [`verify_directory`] takes the unchanged single-`signer` path,
/// so an existing directory can never be silently reinterpreted as threshold.
fn is_threshold_directory(dir: &Directory) -> bool {
    dir.threshold.is_some() || dir.signers.is_some() || dir.signatures.is_some()
}

/// Shared gateway onion<->pubkey binding check (spec 4, `lib/directory.mjs:224
/// checkGatewayBindings`): each entry's `pubkey` MUST equal the ed25519 key encoded in its
/// own v3 `.onion`. Returns the FIRST bad entry's reason. Used by BOTH the single-sig and
/// threshold verify paths so they never drift; the reason strings are byte-identical to the
/// loop the single-sig path used before it was factored out here.
fn check_gateway_bindings(dir: &Directory) -> Result<()> {
    for g in &dir.gateways {
        let onion12: String = g.onion.chars().take(12).collect();
        let derived = match onion_to_pubkey(&g.onion) {
            Ok(pk) => pk,
            Err(e) => return Err(Error::Reason(format!("bad-onion:{onion12}..:{e}"))),
        };
        if hex::encode(derived) != g.pubkey.to_lowercase() {
            return Err(Error::Reason(format!("pubkey-onion-mismatch:{onion12}..")));
        }
        // T-FEAT-10 (lib/directory.mjs:325): an entry that advertises caps MUST carry a
        // valid onion-control signature over exactly those caps. This is what makes the
        // capabilities unforgeable by the bootnode / directory signer (they lack the
        // gateway's onion key): altering a cap, or grafting caps onto an entry, breaks
        // capsSig -> the whole directory is rejected. Absent caps => nothing to check
        // (additive; legacy entries are unaffected).
        if let Some(caps) = &g.caps {
            if has_caps(caps) && !verify_caps_sig(&g.onion, caps, g.caps_sig.as_deref()) {
                return Err(Error::Reason(format!("bad-caps-sig:{onion12}..")));
            }
        }
    }
    Ok(())
}

/// Normalize the pinned-signer allowlist to lowercase hex with any leading `0x` stripped,
/// dropping empty entries (`lib/directory.mjs:190 normalizePinnedSigners`). A one-element
/// slice models the single-string pin; the single-sig path stays byte-for-byte the old
/// behavior. Lowercasing precedes the `0x` strip, matching `p.toLowerCase().replace(/^0x/, "")`.
fn normalize_pinned_signers(pinned: &[&str]) -> Vec<String> {
    pinned
        .iter()
        .filter(|p| !p.is_empty()) // drop empty BEFORE norm, as JS drops falsy members
        .map(|p| {
            let lower = p.to_lowercase();
            lower.strip_prefix("0x").unwrap_or(&lower).to_string()
        })
        .collect()
}

/// Verify an M-of-N threshold directory (T-FEAT-9 / T-FEAT-9b).
///
/// Reference: `lib/directory.mjs:253 verifyDirectoryThreshold`.
///
/// Accepts iff at least `threshold` DISTINCT signers from the client's PINNED allowlist
/// each produced a valid ed25519 signature over the SAME `canonical_directory_bytes(dir)`
/// the single-sig path checks (threshold fields are excluded from the canonical bytes,
/// exactly like `signer`/`signature`). On success returns the matched distinct signer
/// pubkeys (normalized, in first-seen order — mirrors the JS `[...counted]`).
///
/// TOTAL — never panics on adversarial input. Checks run in the JS order, returning the
/// FIRST failure's reason code verbatim:
/// - non-integer / `< 1` threshold (here: absent or `<= 0`) -> `bad-threshold`
/// - `signers`/`signatures` absent or unequal length -> `bad-signatures`
/// - `threshold` greater than N provided -> `threshold-exceeds-signers`
/// - a signer appearing twice is counted ONCE (one key cannot self-satisfy M-of-N)
/// - an unpinned signer is ignored (never counts)
/// - a signer/signature whose hex fails to decode simply does not verify (not fatal)
/// - fewer than `threshold` distinct valid pinned sigs -> `threshold-not-met:<got>/<want>`
/// - then the gateway onion<->pubkey bindings (`bad-onion:..` / `pubkey-onion-mismatch:..`)
///
/// (The JS `no-directory` guard and the per-entry non-string skip are unrepresentable in
/// the typed Rust struct — `signers`/`signatures` are `Vec<String>` — and are elided,
/// exactly as [`verify_directory`] elides `no-directory`.)
pub fn verify_directory_threshold(dir: &Directory, pinned_signers: &[&str]) -> Result<Vec<String>> {
    let pinned: HashSet<String> = normalize_pinned_signers(pinned_signers)
        .into_iter()
        .collect();

    let threshold = match dir.threshold {
        Some(t) if t >= 1 => t,
        _ => return Err(Error::Reason("bad-threshold".into())),
    };
    let (signers, signatures) = match (&dir.signers, &dir.signatures) {
        (Some(s), Some(sig)) if s.len() == sig.len() => (s, sig),
        _ => return Err(Error::Reason("bad-signatures".into())),
    };
    if threshold > signers.len() as i64 {
        return Err(Error::Reason("threshold-exceeds-signers".into()));
    }

    let bytes = canonical_directory_bytes(dir);
    let mut counted: HashSet<String> = HashSet::new(); // DISTINCT pinned signers that verified
    let mut order: Vec<String> = Vec::new(); // first-seen order, mirrors JS [...counted]
    for i in 0..signers.len() {
        let lower = signers[i].to_lowercase();
        let norm = lower.strip_prefix("0x").unwrap_or(&lower).to_string();
        if !pinned.contains(&norm) {
            continue; // unpinned -> ignored
        }
        if counted.contains(&norm) {
            continue; // already-counted distinct signer -> counted once
        }
        // Decode pubkey + signature hex; any malformed hex simply does not verify (the JS
        // ed25519Verify swallows decode errors and returns false), so this signer is skipped.
        let verified = (|| -> Option<bool> {
            let pk: [u8; 32] = hex::decode(&norm).ok()?.try_into().ok()?;
            let sig: [u8; 64] = hex::decode(&signatures[i]).ok()?.try_into().ok()?;
            Some(ed25519_verify(&bytes, &sig, &pk))
        })()
        .unwrap_or(false);
        if verified {
            counted.insert(norm.clone());
            order.push(norm);
        }
    }
    if (order.len() as i64) < threshold {
        return Err(Error::Reason(format!(
            "threshold-not-met:{}/{}",
            order.len(),
            threshold
        )));
    }
    check_gateway_bindings(dir)?;
    Ok(order)
}

/// Verify a signed directory against a pinned signer pubkey (spec 4.2/4.3).
///
/// Reference: `lib/directory.mjs:284 verifyDirectory`.
///
/// A threshold directory (any of `signers`/`signatures`/`threshold` present) verifies
/// under the M-of-N rule ([`verify_directory_threshold`], with the single pinned signer
/// as a one-element allowlist); everything else takes the unchanged single-signer path.
///
/// Single-sig checks, in order, returning the FIRST failure's reason code:
/// `no-directory`, `unsigned`, `signer-not-pinned`, `bad-signature`,
/// `bad-onion:<onion[:12]>..:<msg>`, `pubkey-onion-mismatch:<onion[:12]>..`.
/// On success returns `Ok(())`.
pub fn verify_directory(dir: &Directory, pinned_signer_hex: &str) -> Result<()> {
    // Threshold directories delegate to the M-of-N rule (before the single-sig `unsigned`
    // check, mirroring lib/directory.mjs:288). The single pinned signer becomes a
    // one-element allowlist, so a 1-of-1 threshold directory is the natural generalization.
    if is_threshold_directory(dir) {
        return verify_directory_threshold(dir, &[pinned_signer_hex]).map(|_| ());
    }
    // Order mirrors lib/directory.mjs verifyDirectory. (`no-directory` — dir not
    // an object — is unrepresentable in the typed Rust struct, so it is elided.)
    let signature_hex = match &dir.signature {
        Some(s) => s,
        None => return Err(Error::Reason("unsigned".into())),
    };
    if let Some(signer) = &dir.signer {
        if !pinned_signer_hex.is_empty()
            && signer.to_lowercase() != pinned_signer_hex.to_lowercase()
        {
            return Err(Error::Reason("signer-not-pinned".into()));
        }
    }

    // Decode pinned signer + signature; any malformed input fails as `bad-signature`
    // (the JS ed25519Verify swallows decode/parse errors and returns false).
    let sig_ok = (|| -> Option<bool> {
        let pk_bytes: [u8; 32] = hex::decode(pinned_signer_hex).ok()?.try_into().ok()?;
        let sig_bytes: [u8; 64] = hex::decode(signature_hex).ok()?.try_into().ok()?;
        Some(ed25519_verify(
            &canonical_directory_bytes(dir),
            &sig_bytes,
            &pk_bytes,
        ))
    })()
    .unwrap_or(false);
    if !sig_ok {
        return Err(Error::Reason("bad-signature".into()));
    }

    // Same onion<->pubkey binding check the threshold path uses (byte-identical reasons).
    check_gateway_bindings(dir)
}

/// Verify a directory against an allowlist of pinned signers.  This is the CLI-
/// facing generalization of [`verify_directory`]: threshold directories can meet
/// M-of-N with several pins, while a legacy single-signature directory must name
/// (or verify under) one member of the same allowlist.
pub fn verify_directory_with_signers(
    dir: &Directory,
    pinned_signers: &[&str],
) -> Result<Vec<String>> {
    let pins = normalize_pinned_signers(pinned_signers);
    if pins.is_empty() {
        return Err(Error::Reason("signer-not-pinned".into()));
    }
    if is_threshold_directory(dir) {
        let refs: Vec<&str> = pins.iter().map(String::as_str).collect();
        return verify_directory_threshold(dir, &refs);
    }

    if let Some(declared) = dir.signer.as_deref() {
        let declared = declared
            .strip_prefix("0x")
            .or_else(|| declared.strip_prefix("0X"))
            .unwrap_or(declared)
            .to_ascii_lowercase();
        if !pins.iter().any(|pin| pin == &declared) {
            return Err(Error::Reason("signer-not-pinned".into()));
        }
        verify_directory(dir, &declared)?;
        return Ok(vec![declared]);
    }

    // A historical directory may omit its signer label.  Try every explicit pin
    // against the signature, but do not weaken the final error into TOFU.
    for pin in &pins {
        if verify_directory(dir, pin).is_ok() {
            return Ok(vec![pin.clone()]);
        }
    }
    Err(Error::Reason("bad-signature".into()))
}

/// Verify an announce record (spec 3.4).
///
/// Reference: `bootnode/announce.mjs:80 verifyAnnounce`.
///
/// Checks run in the spec-3.4 order; the FIRST failure's reason code is returned
/// (`bad-version:<v>`, `no-onion`, `bad-onion:<msg>`, `stale-ts:<ts>`,
/// `replayed-nonce`, `bad-onion-sig`, `bad-operator-sig`, `not-staked`, ...).
///
/// `now` is unix seconds; `skew` is the freshness window (spec 3.3 default 120).
/// `seen_nonce`, when supplied, is the caller's replay window.  A nonce is added
/// only after every cryptographic check succeeds, so a forged record cannot burn
/// a legitimate nonce.  Live stake lookup remains an I/O concern for the caller;
/// this function authenticates the optional operator-to-onion authorization that
/// a stake lookup relies on.
pub fn verify_announce(
    ann: &Announce,
    now: u64,
    skew: u64,
    seen_nonce: Option<&mut HashSet<String>>,
) -> Result<()> {
    if ann.v != ANNOUNCE_VERSION {
        return Err(Error::Reason(format!("bad-version:{}", ann.v)));
    }

    let pubkey =
        onion_to_pubkey(&ann.onion).map_err(|e| Error::Reason(format!("bad-onion:{e}")))?;

    if now.abs_diff(ann.ts) > skew {
        return Err(Error::Reason(format!("stale-ts:{}", ann.ts)));
    }
    let replay_key = format!("{}:{}", ann.onion, ann.nonce);
    if seen_nonce
        .as_deref()
        .is_some_and(|seen| seen.contains(&replay_key))
    {
        return Err(Error::Reason("replayed-nonce".into()));
    }

    let onion_sig_ok = (|| -> Option<bool> {
        let sig: [u8; 64] = hex::decode(ann.onion_sig.as_ref()?).ok()?.try_into().ok()?;
        Some(ed25519_verify(
            &canonical_announce_bytes(ann),
            &sig,
            &pubkey,
        ))
    })()
    .unwrap_or(false);
    if !onion_sig_ok {
        return Err(Error::Reason("bad-onion-sig".into()));
    }

    // The standalone caps signature is optional on announcements, but a supplied
    // value must verify exactly as the JavaScript verifier requires.
    if let (Some(caps), Some(caps_sig)) = (&ann.caps, &ann.caps_sig) {
        if !verify_caps_sig(&ann.onion, caps, Some(caps_sig)) {
            return Err(Error::Reason("bad-caps-sig".into()));
        }
    }

    // JavaScript treats operator authorization as present only when both fields
    // exist.  A half-present optional pair is ignored here as well; stake-required
    // policy is enforced by the caller after this signature-only verification.
    if let (Some(operator), Some(operator_sig)) = (&ann.operator, &ann.operator_sig) {
        if !verify_operator_sig(&ann.onion, operator, operator_sig) {
            return Err(Error::Reason("bad-operator-sig".into()));
        }
    }

    if let Some(seen) = seen_nonce {
        seen.insert(replay_key);
    }
    Ok(())
}

// --------------------------------------------------------------------------
// 3.2 operator authorization message (EIP-191 personal_sign target)
// --------------------------------------------------------------------------

/// Build the operator-authorization message string (spec 3.2).
///
/// Reference: `bootnode/announce.mjs:45 operatorAuthMessage`. Durable (no
/// timestamp). `\n` are literal newline bytes; `operator` is lowercased.
///
/// ```text
/// Shade Tree gateway operator authorization\nonion=<onion>\noperator=<operator-lowercased>
/// ```
///
/// This IS implemented (deterministic, no crypto deps) and is conformance-checked
/// against `testdata/vectors.json` `operatorAuthMessage` in [`tests`].
pub fn operator_auth_message(onion: &str, operator: &str) -> String {
    format!(
        "Shade Tree gateway operator authorization\nonion={onion}\noperator={}",
        operator.to_lowercase()
    )
}

/// Recover the Ethereum address that made an EIP-191 `personal_sign` signature
/// over [`operator_auth_message`] and compare it to the claimed operator.
///
/// Signatures are the standard 65-byte `r || s || v` form.  `v` accepts the
/// common 0/1 and 27/28 encodings (and the EIP-155 parity form accepted by
/// ethers).  Addresses are compared case-insensitively because checksum casing
/// is not part of the authorization message's identity semantics.
pub fn verify_operator_sig(onion: &str, operator: &str, operator_sig: &str) -> bool {
    let claimed = operator.to_ascii_lowercase();
    let Some(address_hex) = claimed.strip_prefix("0x") else {
        return false;
    };
    if address_hex.len() != 40 || hex::decode(address_hex).is_err() {
        return false;
    }

    let sig_hex = operator_sig
        .strip_prefix("0x")
        .or_else(|| operator_sig.strip_prefix("0X"))
        .unwrap_or(operator_sig);
    let Ok(raw) = hex::decode(sig_hex) else {
        return false;
    };
    if raw.len() != 65 {
        return false;
    }
    let Ok(sig) = Secp256k1Signature::from_slice(&raw[..64]) else {
        return false;
    };
    let parity = match raw[64] {
        0 | 1 => raw[64],
        27 | 28 => raw[64] - 27,
        v if v >= 35 => (v - 35) & 1,
        _ => return false,
    };
    let Some(recovery_id) = RecoveryId::from_byte(parity) else {
        return false;
    };

    let message = operator_auth_message(onion, operator);
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut hasher = Keccak256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(message.as_bytes());
    let digest = hasher.finalize();

    let Ok(key) = Secp256k1Key::recover_from_prehash(&digest, &sig, recovery_id) else {
        return false;
    };
    let encoded = key.to_sec1_point(false);
    let pubkey = encoded.as_bytes();
    if pubkey.len() != 65 {
        return false;
    }
    let recovered = Keccak256::digest(&pubkey[1..]);
    hex::encode(&recovered[12..]) == address_hex
}

// --------------------------------------------------------------------------
// 6.2 request signal + target binding
// --------------------------------------------------------------------------

/// Build the RLN request signal that binds a proof to `(target, nonce)` (spec 6.2).
///
/// Reference: `lib/rln.mjs:124 requestSignal`.
///
/// ```text
/// request_signal(target, nonce) = "shade-tree:v4\n{target}\n{nonce}"
/// ```
///
/// The circuit public `x` is `calculate_signal_hash(request_signal(target, nonce))`,
/// so a captured proof cannot be redirected to a different target/nonce. This IS
/// implemented (deterministic, no crypto deps) and is conformance-checked in
/// [`tests`].
pub fn request_signal(target: &str, nonce: &str) -> String {
    format!("shade-tree:v4\n{target}\n{nonce}")
}

/// `keccak256(utf8(message)) >> 8`, the circuit signal hash (spec 6.2).
///
/// Reference: `lib/rln.mjs:122,:253 calculateSignalHash` (rlnjs `calculateSignalHash`,
/// `BigInt(keccak256(utf8(signal))) >> 8n`). Deterministic. Returned as the decimal-string
/// field element `x`, the value `verifyEnvelope`'s target-binding check compares against
/// `ps.x` (`target-not-bound`, spec 6.4 row 2b).
///
/// Semantics (verified against `testdata/vectors.json` `signalHash.signalHashDecimal`):
/// take the 32-byte Keccak-256 digest of the UTF-8 message as a BIG-ENDIAN unsigned
/// integer, shift right by 8 bits (drop the least-significant byte), render decimal.
/// `Keccak256` here is Ethereum/rlnjs keccak (the original padding), NOT NIST `Sha3_256`.
pub fn calculate_signal_hash(message: &str) -> String {
    let digest = Keccak256::digest(message.as_bytes()); // 32 bytes, big-endian
    let x = BigUint::from_bytes_be(&digest) >> 8u32; // drop least-significant byte
    x.to_str_radix(10)
}

/// Bounds check for a signal field before hashing (spec 6.3).
///
/// Reference: `lib/rln.mjs:132 signalFieldSafe`. True iff `s` is non-empty, at most
/// `max_len` chars, and contains no `\n` or `\r`. In `verifyEnvelope` the client
/// calls this with `max_len = 256` for `target` and `128` for `nonce` BEFORE
/// hashing, so no crafted delimiter or oversized field can collide two distinct
/// `(target, nonce)` pairs to one signal.
pub fn signal_field_safe(s: &str, max_len: usize) -> bool {
    !s.is_empty() && s.chars().count() <= max_len && !s.contains(['\n', '\r'])
}

// --------------------------------------------------------------------------
// Signed egress success receipt (T-FEAT-13)
// --------------------------------------------------------------------------
//
// Reference: `lib/receipt.mjs`. After a gateway SUCCESSFULLY proxies a request it
// returns a small receipt signed by its onion-control key attesting "I (this onion)
// served a request at epoch E". A client holding the gateway's directory pubkey can
// verify it offline (the onion IS the ed25519 pubkey, so it is self-authenticating).
// The signed bytes are prefixed with a receipt-only domain tag so a receipt signature
// can never be confused with an announce/directory signature by the same onion key.
// Conformance targets (byte-pinned): `testdata/vectors.json` `receipt` block —
// `receiptDomain`, `canonicalReceiptBytesHex`, `receiptOnionSig`.

/// Receipt schema version (`lib/receipt.mjs:50 RECEIPT_VERSION`).
pub const RECEIPT_VERSION: u64 = 1;

/// Receipt-only domain tag prepended to the signed bytes
/// (`lib/receipt.mjs:55 RECEIPT_DOMAIN`). The trailing `\n` is a literal newline byte.
pub const RECEIPT_DOMAIN: &str = "Shade Tree egress success receipt v1\n";

/// A signed egress-success receipt (`lib/receipt.mjs`).
///
/// `epoch` is a canonical non-negative decimal string (the coarse RLN epoch bucket,
/// normalized via `String(epoch)` in the JS reference); `sig` is the lowercase-hex
/// 64-byte ed25519 signature by the onion key over [`canonical_receipt_bytes`].
#[derive(Debug, Clone)]
pub struct Receipt {
    /// `== RECEIPT_VERSION` (1).
    pub v: u64,
    /// the GATEWAY's own v3 `.onion` address (with suffix); self-authenticating.
    pub onion: String,
    /// coarse epoch bucket, canonical decimal string (e.g. `"8333"`).
    pub epoch: String,
    /// success flag; a valid receipt has `ok == true`.
    pub ok: bool,
    /// lowercase-hex 64-byte ed25519 signature by the onion key. `None` == unsigned.
    pub sig: Option<String>,
}

/// A verified receipt: the gateway onion, its recovered ed25519 pubkey, and the epoch.
#[derive(Debug, Clone)]
pub struct VerifiedReceipt {
    /// the receipt's `.onion` (as presented).
    pub onion: String,
    /// the ed25519 pubkey recovered from `onion` (the key that signed it).
    pub pubkey: [u8; 32],
    /// the receipt's epoch decimal string.
    pub epoch: String,
}

/// Canonical signed bytes of a receipt (`lib/receipt.mjs:61 canonicalReceiptBytes`).
///
/// `utf8(RECEIPT_DOMAIN) || utf8(JSON.stringify({ v, onion, epoch, ok }))` in exactly
/// that fixed key order, no whitespace. `epoch` is a decimal string; `ok` is the literal
/// boolean. Hand-built in fixed key order (NOT via a serializer), matching
/// `JSON.stringify` byte-for-byte — see `testdata/vectors.json` `canonicalReceiptBytesHex`.
pub fn canonical_receipt_bytes(v: u64, onion: &str, epoch: &str, ok: bool) -> Vec<u8> {
    let mut s = String::from(RECEIPT_DOMAIN);
    s.push_str("{\"v\":");
    s.push_str(&v.to_string());
    s.push_str(",\"onion\":");
    push_json_string(&mut s, onion);
    s.push_str(",\"epoch\":");
    push_json_string(&mut s, epoch);
    s.push_str(",\"ok\":");
    s.push_str(if ok { "true" } else { "false" });
    s.push('}');
    s.into_bytes()
}

/// True iff `s` is a canonical non-negative decimal (`^(0|[1-9][0-9]*)$`), matching the
/// epoch guard in `lib/receipt.mjs:109` (no float / hex / leading-zero ambiguity).
fn is_canonical_decimal(s: &str) -> bool {
    match s.as_bytes() {
        [] => false,
        [b'0'] => true,
        [first, rest @ ..] => {
            first.is_ascii_digit() && *first != b'0' && rest.iter().all(u8::is_ascii_digit)
        }
    }
}

/// Strip a trailing lowercase `.onion` then lowercase — matches the JS
/// `String(o).replace(/\.onion$/, "").toLowerCase()` used for the onion-match compare
/// (`lib/receipt.mjs:94`; the suffix strip is case-sensitive, the lowercasing follows).
fn strip_onion(o: &str) -> String {
    o.strip_suffix(".onion").unwrap_or(o).to_lowercase()
}

/// Verify a receipt (`lib/receipt.mjs:88 verifyReceipt`).
///
/// Checks run in the JS order, returning the FIRST failure's reason code verbatim:
/// `bad-version:<v>`, `not-success`, `onion-mismatch`, `bad-onion:<msg>`, `bad-epoch`,
/// `stale-epoch:<epoch>`, `bad-sig`. On success returns the recovered pubkey/onion/epoch.
///
/// - `onion`: if `Some`, the receipt's onion MUST equal it (bind the receipt to the
///   gateway the client dialed) — compared after suffix-strip + lowercase.
/// - `epoch`: if `Some`, the receipt's epoch must be within `epoch_skew` of it, so a
///   stale receipt is not counted as fresh liveness. `None` skips the freshness check.
/// - `epoch_skew`: max `|epoch - rec.epoch|` accepted (JS default 1).
///
/// (The JS `no-receipt` / `no-onion` type guards are unrepresentable in the typed Rust
/// struct — `rec` is always a `Receipt` with a `String` onion — and are elided, exactly
/// as [`verify_directory`] elides `no-directory`.)
pub fn verify_receipt(
    rec: &Receipt,
    onion: Option<&str>,
    epoch: Option<&str>,
    epoch_skew: u64,
) -> Result<VerifiedReceipt> {
    if rec.v != RECEIPT_VERSION {
        return Err(Error::Reason(format!("bad-version:{}", rec.v)));
    }
    if !rec.ok {
        return Err(Error::Reason("not-success".into()));
    }
    if let Some(want) = onion {
        if strip_onion(&rec.onion) != strip_onion(want) {
            return Err(Error::Reason("onion-mismatch".into()));
        }
    }
    // Recover the ed25519 key the (checksummed) v3 address commits to; malformed => bad-onion.
    let pubkey = match onion_to_pubkey(&rec.onion) {
        Ok(pk) => pk,
        Err(e) => return Err(Error::Reason(format!("bad-onion:{e}"))),
    };
    // epoch must be a canonical non-negative decimal string (signed-bytes stability).
    if !is_canonical_decimal(&rec.epoch) {
        return Err(Error::Reason("bad-epoch".into()));
    }
    if let Some(cur) = epoch {
        match (
            BigUint::parse_bytes(rec.epoch.as_bytes(), 10),
            BigUint::parse_bytes(cur.as_bytes(), 10),
        ) {
            (Some(rec_ep), Some(cur_ep)) => {
                let diff = if rec_ep > cur_ep {
                    &rec_ep - &cur_ep
                } else {
                    &cur_ep - &rec_ep
                };
                if diff > BigUint::from(epoch_skew) {
                    return Err(Error::Reason(format!("stale-epoch:{}", rec.epoch)));
                }
            }
            // JS BigInt(String(epoch)) throw path => bad-epoch (e.g. a non-numeric `epoch` arg).
            _ => return Err(Error::Reason("bad-epoch".into())),
        }
    }
    // The signature must verify under the key the onion address commits to.
    let sig_hex = match &rec.sig {
        Some(s) => s,
        None => return Err(Error::Reason("bad-sig".into())),
    };
    let sig_ok = (|| -> Option<bool> {
        let sig: [u8; 64] = hex::decode(sig_hex).ok()?.try_into().ok()?;
        Some(ed25519_verify(
            &canonical_receipt_bytes(rec.v, &rec.onion, &rec.epoch, rec.ok),
            &sig,
            &pubkey,
        ))
    })()
    .unwrap_or(false);
    if !sig_ok {
        return Err(Error::Reason("bad-sig".into()));
    }
    Ok(VerifiedReceipt {
        onion: rec.onion.clone(),
        pubkey,
        epoch: rec.epoch.clone(),
    })
}

/// Sign a receipt with the onion seed (`lib/receipt.mjs:72 buildReceipt`). Convenience for
/// tests / a gateway port: returns the 64-byte ed25519 signature over the canonical bytes.
pub fn sign_receipt(v: u64, onion: &str, epoch: &str, ok: bool, onion_seed: &[u8; 32]) -> [u8; 64] {
    ed25519_sign(&canonical_receipt_bytes(v, onion, epoch, ok), onion_seed)
}

// --------------------------------------------------------------------------
// Protocol / envelope version negotiation (T-FEAT-11)
// --------------------------------------------------------------------------
//
// Reference: `gateway/gateway.mjs` (`PROTO_MIN`/`PROTO_MAX`/`acceptEnvelopeVersion`/
// `versionRepr`) + `client/shade-tree-client.mjs` (`CLIENT_PROTO_*`/`selectProtoVersion`).
// See docs/VERSIONING.md. The bounded reason LABELS are byte-pinned in
// `testdata/vectors.json` `protoReasons`; the full runtime reason strings additionally
// carry the offending version/ranges, which are context-dependent and NOT pinned.

/// Lowest envelope version this build can emit/parse (`PROTO_MIN`/`CLIENT_PROTO_MIN` = 4).
pub const PROTO_MIN: u64 = 4;
/// Highest envelope version this build can emit/parse (`PROTO_MAX`/`CLIENT_PROTO_MAX` = 4).
pub const PROTO_MAX: u64 = 4;

/// Provisional default combined application-payload allowance for one RLN epoch slot.
/// Gateways remain authoritative and may override or disable it operationally; clients use
/// this value for display/documentation only, never as proof that more service is available.
pub const DEFAULT_TUNNEL_MAX_PAYLOAD_BYTES: u64 = 40 * 1024 * 1024;

/// Exact bounded refusal reason returned before tunnel establishment when this gateway has
/// already exhausted the `(externalNullifier, nullifier)` payload allowance.
pub const REASON_PAYLOAD_LIMIT: &str = "payload-limit";

/// The pre-negotiation wire version an envelope with NO `v` field is treated as
/// (`gateway/gateway.mjs:269 LEGACY_ENVELOPE_VERSION` = 3).
pub const LEGACY_ENVELOPE_VERSION: u64 = 3;

/// Bounded reason label for a non-integer / garbage version (`protoReasons.badVersion`).
pub const REASON_BAD_VERSION: &str = "bad-version";
/// Bounded reason label for a well-formed integer version out of range
/// (`protoReasons.unsupportedVersion`).
pub const REASON_UNSUPPORTED_VERSION: &str = "unsupported-version";
/// Bounded reason prefix for disjoint client/gateway ranges (`protoReasons.noMutualVersion`).
pub const REASON_NO_MUTUAL_VERSION: &str = "no-mutual-version";

/// The `v` field of an envelope, classified WITHOUT reading any other field, mirroring
/// how JS treats a dynamically-typed value in `acceptEnvelopeVersion` (`gateway/gateway.mjs:278`).
///
/// A serde-free enum so `shade-tree-proto` stays off serde: the untrusted-JSON → enum mapping
/// (and the `versionRepr` string) lives in the client, which owns serde.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeVersion {
    /// no `v` field (or JSON `null`): the pre-negotiation v3 wire, rejected by a
    /// v4-only range.
    Absent,
    /// a well-formed integer version.
    Int(i64),
    /// a non-integer `v` (string, float, bool, object): garbage. Carries a short, safe
    /// repr for the reason string (the JS `versionRepr` output).
    Garbage(String),
}

/// Decide whether an envelope of version `v` can be parsed, reading only `v`
/// (`gateway/gateway.mjs:278 acceptEnvelopeVersion`). Returns the accepted version, or the
/// FIRST failure's reason code: `unsupported-version:<v>` (integer out of range) or
/// `bad-version:<repr>` (non-integer). `range` is the gateway's `(min, max)`; the reason
/// LABEL for metrics is [`REASON_UNSUPPORTED_VERSION`] / [`REASON_BAD_VERSION`].
pub fn accept_envelope_version(v: &EnvelopeVersion, range: (u64, u64)) -> Result<u64> {
    let (min, max) = range;
    match v {
        // Absent == legacy v3, then range-checked like any other. A v4-only build
        // deliberately rejects it rather than silently treating old bytes as v4.
        EnvelopeVersion::Absent => {
            if LEGACY_ENVELOPE_VERSION < min || LEGACY_ENVELOPE_VERSION > max {
                return Err(Error::Reason(format!(
                    "{REASON_UNSUPPORTED_VERSION}:{LEGACY_ENVELOPE_VERSION}"
                )));
            }
            Ok(LEGACY_ENVELOPE_VERSION)
        }
        EnvelopeVersion::Int(n) => {
            if *n < min as i64 || *n > max as i64 {
                return Err(Error::Reason(format!("{REASON_UNSUPPORTED_VERSION}:{n}")));
            }
            Ok(*n as u64)
        }
        EnvelopeVersion::Garbage(repr) => {
            Err(Error::Reason(format!("{REASON_BAD_VERSION}:{repr}")))
        }
    }
}

/// Pick the HIGHEST version both sides support (`client/shade-tree-client.mjs:95
/// selectProtoVersion`). `gateway_range` is `Some((min,max))` once learned (from a
/// version-reject advertisement), else `None`.
///
/// - gateway range unknown (`None`): optimistically emit the client's own max.
/// - ranges overlap: `min(client_max, gateway_max)` — the highest both accept.
/// - ranges disjoint: `Err("no-mutual-version:client=<lo>-<hi>,gateway=<lo>-<hi>")`
///   (the caller fails closed BEFORE proving or dialing).
pub fn select_proto_version(
    gateway_range: Option<(u64, u64)>,
    client_range: (u64, u64),
) -> Result<u64> {
    let (c_min, c_max) = client_range;
    let (g_min, g_max) = match gateway_range {
        None => return Ok(c_max), // no advertisement yet: emit our best supported version
        Some(r) => r,
    };
    let hi = c_max.min(g_max); // highest either side will go
    let lo = c_min.max(g_min); // lowest both sides still accept
    if hi < lo {
        return Err(Error::Reason(format!(
            "{REASON_NO_MUTUAL_VERSION}:client={c_min}-{c_max},gateway={g_min}-{g_max}"
        )));
    }
    Ok(hi) // highest mutually supported
}

// --------------------------------------------------------------------------
// ZK artifact-version negotiation (T-HARD-8)
// --------------------------------------------------------------------------
//
// Reference: `lib/zk-artifacts.mjs` (`ARTIFACT_ID_RE`, `artifactIdOf`, `selectArtifact`,
// `resolveArtifact` reason strings). An artifact SET (wasm + zkey + vkey from one phase-2
// output) is named by a CONTENT-DERIVED id, `<circuit>-<sha256(verification_key.json)[0:16]>`
// — literally the vkey's hash prefix in `testdata/zk-artifacts.lock.json` — so the lock, the
// JS gateway/client and this Rust client agree on the name with no registry. The gateway
// advertises its accepted ids in its signed caps (`caps.artifacts`) and verifies under the
// vkey the envelope's `artifact` field names; the client sends the NEWEST of its own sets the
// gateway accepts. Bounded reason labels are byte-pinned in `testdata/vectors.json`
// `artifacts`; runtime reasons additionally carry ids (context-dependent, not pinned).

/// Hex chars of the sha256 kept in an artifact id (`lib/zk-artifacts.mjs ARTIFACT_ID_HASH_CHARS`).
pub const ARTIFACT_ID_HASH_CHARS: usize = 16;
/// Gateway reason label: the envelope's `artifact` field is present but not an id.
pub const REASON_BAD_ARTIFACT: &str = "bad-artifact";
/// Gateway reason label: the (legacy) id is known but no longer accepted (window closed).
pub const REASON_ARTIFACT_RETIRED: &str = "artifact-retired";
/// Gateway reason label: an id this gateway holds no vkey for.
pub const REASON_ARTIFACT_UNKNOWN: &str = "artifact-unknown";
/// Client-side reason prefix: no artifact set is accepted by both sides (fail closed).
pub const REASON_NO_MUTUAL_ARTIFACT: &str = "no-mutual-artifact";
/// Client-side reason: this client has no prover artifact set at all.
pub const REASON_NO_CLIENT_ARTIFACT: &str = "no-client-artifact";

/// The artifact-id grammar (`lib/zk-artifacts.mjs ARTIFACT_ID_RE` =
/// `/^[a-z0-9][a-z0-9._-]{0,63}$/`): lowercase alnum start, then up to 63 of `[a-z0-9._-]`.
pub fn is_artifact_id(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 64 {
        return false;
    }
    if !(b[0].is_ascii_lowercase() || b[0].is_ascii_digit()) {
        return false;
    }
    b[1..]
        .iter()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-'))
}

/// `artifact_id_of(circuit, vkey_bytes)` = `<circuit>-<sha256(bytes) hex[0:16]>`
/// (`lib/zk-artifacts.mjs artifactIdOf`). `vkey_bytes` are the `verification_key.json`
/// FILE bytes exactly as the lock hashes them. Conformance target:
/// `testdata/vectors.json` `artifacts.sample`.
pub fn artifact_id_of(circuit: &str, vkey_bytes: &[u8]) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(vkey_bytes);
    let hex = hex::encode(digest);
    format!("{circuit}-{}", &hex[..ARTIFACT_ID_HASH_CHARS])
}

/// The client's pick (`lib/zk-artifacts.mjs selectArtifact`). `client_ids` is the ORDERED
/// list of sets this client can prove with, NEWEST FIRST; `gateway_ids` is the gateway's
/// advertised accepted set (`caps.artifacts`) or `None` when unknown.
///
/// - no valid client id: `Err("no-client-artifact")`.
/// - gateway unknown / empty ad: optimistically the client's newest.
/// - otherwise the FIRST (newest) client id the gateway lists.
/// - disjoint: `Err("no-mutual-artifact:client=a|b,gateway=c|d")` (gateway ids sorted).
pub fn select_artifact(gateway_ids: Option<&[String]>, client_ids: &[String]) -> Result<String> {
    let mine: Vec<&String> = client_ids.iter().filter(|s| is_artifact_id(s)).collect();
    if mine.is_empty() {
        return Err(Error::Reason(REASON_NO_CLIENT_ARTIFACT.to_string()));
    }
    let theirs: Vec<&String> = match gateway_ids {
        Some(g) if !g.is_empty() => g.iter().filter(|s| is_artifact_id(s)).collect(),
        _ => return Ok(mine[0].clone()),
    };
    for id in &mine {
        if theirs.contains(id) {
            return Ok((*id).clone());
        }
    }
    let mut sorted: Vec<&str> = theirs.iter().map(|s| s.as_str()).collect();
    sorted.sort_unstable();
    sorted.dedup();
    let mine_s: Vec<&str> = mine.iter().map(|s| s.as_str()).collect();
    Err(Error::Reason(format!(
        "{REASON_NO_MUTUAL_ARTIFACT}:client={},gateway={}",
        mine_s.join("|"),
        sorted.join("|")
    )))
}

// --------------------------------------------------------------------------
// Gateway selection (weighted, deterministic under an injected rng)
// --------------------------------------------------------------------------
//
// Reference: `lib/directory.mjs:273 MAX_WEIGHT` / `:274 clampWeight` / `:279 pickGateway`
// / `:296 selectionOrder`. The client bounds gateway-attested weight itself (not just the
// bootnode) so no directory source — including a static or compromised-signer one — can
// concentrate a member's traffic on one gateway (a deanonymization lever).

/// Max selection weight the client will honor (`lib/directory.mjs:273 MAX_WEIGHT`).
pub const MAX_WEIGHT: f64 = 1000.0;

/// Clamp a gateway's attested weight (`lib/directory.mjs:274 clampWeight`).
///
/// `weight = Number(g.weight)`: absent/`NaN`/non-finite => `1`; negative => floored at `0`;
/// anything huge => capped at [`MAX_WEIGHT`]. `None` models the JS `undefined` (absent field).
pub fn clamp_weight(weight: Option<f64>) -> f64 {
    match weight {
        // w is guarded finite and 0.0 < MAX_WEIGHT, so clamp is total here (mirrors the JS
        // `Math.max(0, Math.min(MAX_WEIGHT, w))`).
        Some(w) if w.is_finite() => w.clamp(0.0, MAX_WEIGHT),
        _ => 1.0,
    }
}

/// The (clamped) weights of the pool `pick_gateway`/`selection_order` draw from, in the
/// same order and with the same healthy/down fallback. Shared by both so the two never drift.
fn selection_pool<'a>(dir: &'a Directory, exclude: &HashSet<String>) -> Vec<&'a GatewayEntry> {
    let all: Vec<&GatewayEntry> = dir
        .gateways
        .iter()
        .filter(|g| !exclude.contains(&g.onion))
        .collect();
    if all.is_empty() {
        return all;
    }
    let healthy: Vec<&GatewayEntry> = all.iter().copied().filter(|g| g.health != "down").collect();
    // last resort: if every remaining gateway is "down", still try one.
    if healthy.is_empty() {
        all
    } else {
        healthy
    }
}

/// Weighted-random pick of one gateway (`lib/directory.mjs:279 pickGateway`).
///
/// `exclude` is a set of already-tried onions; `rng` yields a value in `[0, 1)` (injectable
/// so selection is deterministic in tests, mirroring the JS `{ rng }` option). Returns `None`
/// only when every gateway is excluded. When the total clamped weight is `0`, falls back to a
/// uniform pick over the pool (matching the JS `total <= 0` branch).
pub fn pick_gateway<'a>(
    dir: &'a Directory,
    exclude: &HashSet<String>,
    rng: &mut dyn FnMut() -> f64,
) -> Option<&'a GatewayEntry> {
    let pool = selection_pool(dir, exclude);
    if pool.is_empty() {
        return None;
    }
    let total: f64 = pool
        .iter()
        .map(|g| clamp_weight(Some(g.weight as f64)))
        .sum();
    if total <= 0.0 {
        let idx = (rng() * pool.len() as f64).floor() as usize;
        return Some(pool[idx.min(pool.len() - 1)]);
    }
    let mut r = rng() * total;
    for g in &pool {
        r -= clamp_weight(Some(g.weight as f64));
        if r < 0.0 {
            return Some(g);
        }
    }
    Some(pool[pool.len() - 1])
}

/// Full weighted failover order (`lib/directory.mjs:296 selectionOrder`): the weighted pick
/// first, then the rest of the fleet in weighted order, so the client can walk the list on
/// dial timeout. `rng` is injected (deterministic in tests).
pub fn selection_order<'a>(
    dir: &'a Directory,
    rng: &mut dyn FnMut() -> f64,
) -> Vec<&'a GatewayEntry> {
    let mut order = Vec::new();
    let mut exclude: HashSet<String> = HashSet::new();
    while let Some(g) = pick_gateway(dir, &exclude, rng) {
        order.push(g);
        exclude.insert(g.onion.clone());
    }
    order
}

/// In-memory smooth-weighted-round-robin deficits for successive tunnel selections.
/// The map is pruned against every new directory, so address churn cannot grow it without bound.
#[derive(Debug, Default)]
pub struct SmoothWeightedState {
    current: HashMap<String, f64>,
}

/// Choose the first healthy gateway with smooth weighted round-robin, then fill the failover tail
/// with the existing weighted-random order. Equal weights rotate without immediate repetition;
/// unequal weights retain their exact long-run share. New gateways receive a small random phase so
/// independent clients do not emit the same deterministic sequence.
pub fn spread_selection_order<'a>(
    dir: &'a Directory,
    state: &mut SmoothWeightedState,
    rng: &mut dyn FnMut() -> f64,
) -> Vec<&'a GatewayEntry> {
    let all: Vec<&GatewayEntry> = dir.gateways.iter().collect();
    let healthy: Vec<&GatewayEntry> = all
        .iter()
        .copied()
        .filter(|gateway| gateway.health != "down")
        .collect();
    let pool = if healthy.is_empty() { &all } else { &healthy };
    let positive: Vec<&GatewayEntry> = pool
        .iter()
        .copied()
        .filter(|gateway| clamp_weight(Some(gateway.weight as f64)) > 0.0)
        .collect();
    let spread_pool = if positive.is_empty() { pool } else { &positive };
    if spread_pool.len() < 2 {
        return selection_order(dir, rng);
    }

    let live: HashSet<&str> = all.iter().map(|gateway| gateway.onion.as_str()).collect();
    state
        .current
        .retain(|onion, _| live.contains(onion.as_str()));

    let total: f64 = spread_pool
        .iter()
        .map(|gateway| clamp_weight(Some(gateway.weight as f64)))
        .sum();
    if total <= 0.0 {
        return selection_order(dir, rng);
    }

    let mut winner: Option<&GatewayEntry> = None;
    let mut winner_current = f64::NEG_INFINITY;
    for gateway in spread_pool {
        let weight = clamp_weight(Some(gateway.weight as f64));
        let current = state
            .current
            .entry(gateway.onion.clone())
            .or_insert_with(|| rng() * weight);
        *current += weight;
        if *current > winner_current {
            winner = Some(*gateway);
            winner_current = *current;
        }
    }
    let Some(winner) = winner else {
        return selection_order(dir, rng);
    };
    if let Some(current) = state.current.get_mut(&winner.onion) {
        *current -= total;
    }

    let mut order = vec![winner];
    let mut exclude = HashSet::from([winner.onion.clone()]);
    while let Some(gateway) = pick_gateway(dir, &exclude, rng) {
        order.push(gateway);
        exclude.insert(gateway.onion.clone());
    }
    order
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Conformance: `request_signal` must match spec 6.2 exactly.
    /// (Full fixture-file conformance runner lands in T-RUST-1.)
    #[test]
    fn request_signal_matches_spec() {
        let target = "example.com:443";
        let nonce = "abcdef0123456789abcdef0123456789";
        assert_eq!(
            request_signal(target, nonce),
            "shade-tree:v4\nexample.com:443\nabcdef0123456789abcdef0123456789"
        );
        // Delimiters are literal newlines (0x0a), not escaped.
        assert_eq!(request_signal("t", "n"), "shade-tree:v4\nt\nn");
    }

    /// Conformance: `operator_auth_message` against testdata/vectors.json.
    #[test]
    fn operator_auth_message_lowercases_operator() {
        // From testdata/vectors.json (mixed-case operator input -> lowercased).
        let onion = "ucnkl5d2m5myal7zkx4nyljkcss4thjdx2l7qzasp74tqncvutypp3ad.onion";
        let got = operator_auth_message(onion, "0x000000000000000000000000000000000000dEaD");
        let want = "Shade Tree gateway operator authorization\n\
                    onion=ucnkl5d2m5myal7zkx4nyljkcss4thjdx2l7qzasp74tqncvutypp3ad.onion\n\
                    operator=0x000000000000000000000000000000000000dead";
        assert_eq!(got, want);
    }

    /// `signal_field_safe` bounds (spec 6.3).
    #[test]
    fn signal_field_safe_bounds() {
        assert!(signal_field_safe("ok", 256));
        assert!(!signal_field_safe("", 256)); // empty
        assert!(!signal_field_safe("abc", 2)); // too long
        assert!(!signal_field_safe("a\nb", 256)); // newline
        assert!(!signal_field_safe("a\rb", 256)); // carriage return
    }

    // -- clamp_weight (lib/directory.mjs:274) ------------------------------

    #[test]
    fn clamp_weight_matches_js_semantics() {
        assert_eq!(clamp_weight(Some(100.0)), 100.0); // in range unchanged
        assert_eq!(clamp_weight(None), 1.0); // absent/undefined -> 1
        assert_eq!(clamp_weight(Some(f64::NAN)), 1.0); // NaN -> 1
        assert_eq!(clamp_weight(Some(f64::INFINITY)), 1.0); // non-finite -> 1
        assert_eq!(clamp_weight(Some(-5.0)), 0.0); // negative floors at 0
        assert_eq!(clamp_weight(Some(50_000.0)), MAX_WEIGHT); // huge caps at MAX_WEIGHT
        assert_eq!(clamp_weight(Some(MAX_WEIGHT)), MAX_WEIGHT); // exactly the cap
    }

    // -- weighted selection distribution (seeded rng) ----------------------

    /// mulberry32 — the same tiny seedable PRNG the JS test suite uses, so selection is
    /// deterministic here with zero extra dependency (no `rand`). Yields `f64` in `[0,1)`.
    fn mulberry32(seed: u32) -> impl FnMut() -> f64 {
        let mut a = seed;
        move || {
            a = a.wrapping_add(0x6D2B_79F5);
            let mut t = a;
            t = (t ^ (t >> 15)).wrapping_mul(t | 1);
            t ^= t.wrapping_add((t ^ (t >> 7)).wrapping_mul(t | 61));
            (((t ^ (t >> 14)) as f64) / 4_294_967_296.0).fract()
        }
    }

    fn gw(onion: &str, weight: u64, health: &str) -> GatewayEntry {
        GatewayEntry {
            onion: onion.to_string(),
            pubkey: String::new(),
            weight,
            health: health.to_string(),
            operator: None,
            staked: None,
            caps: None,
            caps_sig: None,
        }
    }

    #[test]
    fn pick_gateway_long_run_matches_weight_ratios() {
        // Weights 100 / 200 / 700 (sum 1000) => expected selection shares 0.1 / 0.2 / 0.7.
        let dir = Directory {
            version: 1,
            issued: 0,
            gateways: vec![gw("a", 100, "up"), gw("b", 200, "up"), gw("c", 700, "up")],
            signer: None,
            signature: None,
            signers: None,
            signatures: None,
            threshold: None,
        };
        let mut rng = mulberry32(12345);
        let empty = HashSet::new();
        let n = 60_000;
        let mut counts = [0usize; 3];
        for _ in 0..n {
            let g = pick_gateway(&dir, &empty, &mut rng).unwrap();
            let i = match g.onion.as_str() {
                "a" => 0,
                "b" => 1,
                _ => 2,
            };
            counts[i] += 1;
        }
        let share = |c: usize| c as f64 / n as f64;
        // Long-run frequencies match the weight ratios within a loose tolerance.
        assert!(
            (share(counts[0]) - 0.1).abs() < 0.02,
            "a share {}",
            share(counts[0])
        );
        assert!(
            (share(counts[1]) - 0.2).abs() < 0.02,
            "b share {}",
            share(counts[1])
        );
        assert!(
            (share(counts[2]) - 0.7).abs() < 0.02,
            "c share {}",
            share(counts[2])
        );
    }

    #[test]
    fn pick_gateway_clamps_runaway_weight() {
        // A directory that tries to concentrate all traffic on `b` with weight 1e9 is
        // clamped to MAX_WEIGHT, so `a` (weight 1000) still gets ~half the picks.
        let dir = Directory {
            version: 1,
            issued: 0,
            gateways: vec![gw("a", 1000, "up"), gw("b", 1_000_000_000, "up")],
            signer: None,
            signature: None,
            signers: None,
            signatures: None,
            threshold: None,
        };
        let mut rng = mulberry32(999);
        let empty = HashSet::new();
        let mut a = 0usize;
        let n = 40_000;
        for _ in 0..n {
            if pick_gateway(&dir, &empty, &mut rng).unwrap().onion == "a" {
                a += 1;
            }
        }
        let share = a as f64 / n as f64;
        assert!((share - 0.5).abs() < 0.03, "clamped share {share}");
    }

    #[test]
    fn selection_order_prefers_healthy_and_covers_all() {
        let dir = Directory {
            version: 1,
            issued: 0,
            gateways: vec![
                gw("up1", 100, "up"),
                gw("down1", 100, "down"),
                gw("up2", 100, "up"),
            ],
            signer: None,
            signature: None,
            signers: None,
            signatures: None,
            threshold: None,
        };
        let mut rng = mulberry32(7);
        let order = selection_order(&dir, &mut rng);
        // every gateway appears exactly once.
        assert_eq!(order.len(), 3);
        // the two healthy gateways are ordered before the "down" one (down is last resort).
        assert_eq!(order[2].onion, "down1");
        assert!(order[0].onion.starts_with("up"));
        assert!(order[1].onion.starts_with("up"));
    }

    #[test]
    fn smooth_spread_rotates_frequently_and_preserves_weights() {
        let equal = Directory {
            version: 1,
            issued: 0,
            gateways: vec![
                gw("a", 100, "up"),
                gw("b", 100, "up"),
                gw("c", 100, "up"),
                gw("d", 100, "up"),
            ],
            signer: None,
            signature: None,
            signers: None,
            signatures: None,
            threshold: None,
        };
        let mut state = SmoothWeightedState::default();
        let mut rng = mulberry32(0x44ef);
        let mut previous = "";
        let mut counts = HashMap::<String, usize>::new();
        for _ in 0..8_000 {
            let order = spread_selection_order(&equal, &mut state, &mut rng);
            assert_eq!(order.len(), 4);
            assert_ne!(order[0].onion, previous);
            previous = &order[0].onion;
            *counts.entry(order[0].onion.clone()).or_default() += 1;
        }
        assert!(counts.values().all(|count| *count == 2_000));

        let weighted = Directory {
            version: 1,
            issued: 0,
            gateways: vec![gw("heavy", 300, "up"), gw("light", 100, "up")],
            signer: None,
            signature: None,
            signers: None,
            signatures: None,
            threshold: None,
        };
        let mut state = SmoothWeightedState::default();
        let mut rng = mulberry32(0x51ed);
        let mut heavy = 0usize;
        for _ in 0..8_000 {
            if spread_selection_order(&weighted, &mut state, &mut rng)[0].onion == "heavy" {
                heavy += 1;
            }
        }
        assert_eq!(heavy, 6_000);
    }

    // -- version negotiation (gateway.mjs / shade-tree-client.mjs) ---------------

    #[test]
    fn accept_envelope_version_branches() {
        let range = (PROTO_MIN, PROTO_MAX); // {4}
                                            // absent -> legacy v3, rejected by the v4-only range.
        assert_eq!(
            accept_envelope_version(&EnvelopeVersion::Absent, range)
                .unwrap_err()
                .to_string(),
            "unsupported-version:3"
        );
        // in-range integer accepted.
        assert_eq!(
            accept_envelope_version(&EnvelopeVersion::Int(4), range).unwrap(),
            4
        );
        // out-of-range integer -> unsupported-version:<v>.
        assert_eq!(
            accept_envelope_version(&EnvelopeVersion::Int(3), range)
                .unwrap_err()
                .to_string(),
            "unsupported-version:3"
        );
        // non-integer -> bad-version:<repr>.
        assert_eq!(
            accept_envelope_version(&EnvelopeVersion::Garbage("\"3\"".into()), range)
                .unwrap_err()
                .to_string(),
            "bad-version:\"3\""
        );
    }

    #[test]
    fn select_proto_version_branches() {
        let client = (PROTO_MIN, PROTO_MAX); // {4}
                                             // unknown gateway range -> client max.
        assert_eq!(select_proto_version(None, client).unwrap(), 4);
        // overlap -> highest mutual.
        assert_eq!(select_proto_version(Some((1, 3)), (1, 3)).unwrap(), 3);
        assert_eq!(select_proto_version(Some((2, 5)), (1, 3)).unwrap(), 3);
        // disjoint -> fail closed.
        let err = select_proto_version(Some((5, 6)), (1, 2))
            .unwrap_err()
            .to_string();
        assert_eq!(err, "no-mutual-version:client=1-2,gateway=5-6");
    }
}
