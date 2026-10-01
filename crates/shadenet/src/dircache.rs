//! Directory loading with last-known-good caching + rollback / max-age guards —
//! the Rust port of `client/selection.mjs`'s `ensureLoaded` / `loadFromBootnode`
//! discipline (T-RUST-3, slice 2). Default-build (serde_json + shadenet-proto only).
//!
//! A verified directory is cached to disk; if a fresh fetch fails or is
//! unverifiable, the client falls back to the last-known-good cache. It NEVER
//! serves an unverified directory (both the fresh and the cached path run
//! `verify_directory`, which enforces the pinned signer + the onion<->key binding).
//! Two guards from `selection.mjs` are ported here because they are client-side
//! session state, not stateless proto checks:
//!
//!   - ROLLBACK FLOOR (audit loop-15 F2): a FRESH directory whose `issued` predates
//!     the last-known-good cache's `issued` is refused (a hostile/replaying source
//!     re-serving an old, validly-signed directory to resurrect a dropped gateway).
//!     For a one-shot CLI the persisted cache IS the high-water mark, so the cached
//!     `issued` is the floor. A same-or-newer `issued` is accepted (idempotent
//!     refetch is fine) and overwrites the cache, raising the floor.
//!   - ABSOLUTE MAX-AGE (T-FEAT-21): OPTIONAL. A FRESH directory whose `issued` is
//!     older than `now - max_age - skew` is refused (a far-behind or replaying
//!     source serving a months-old-but-validly-signed directory to a cold client).
//!
//! The last-known-good CACHE is EXEMPT from both guards: a stale-but-verified cache
//! is still better than going dark, exactly as `selection.mjs` treats it.

use std::path::Path;

use serde::Deserialize;
use shadenet_proto::{
    verify_directory_with_signers, Caps, Directory, GatewayEntry, ProtoCaps, RateCaps,
};

// --------------------------------------------------------------------------
// Untrusted-JSON DTOs (serde) -> shadenet-proto Directory (trust-critical checks)
// --------------------------------------------------------------------------
//
// Mirrors the on-the-wire signed-directory JSON (lib/directory.mjs). UNTRUSTED
// input: we deserialize it, map it into shadenet-proto's Directory, and let
// verify_directory make every security-critical decision.

#[derive(Deserialize)]
pub struct DirEntryDto {
    pub onion: String,
    pub pubkey: String,
    pub weight: u64,
    pub health: String,
    #[serde(default)]
    pub operator: Option<String>,
    #[serde(default)]
    pub staked: Option<bool>,
    // T-FEAT-10c: carry the self-declared caps + their onion-bound signature through so
    // verify_directory can enforce capsSig (bad-caps-sig) and the client can filter on
    // capability. OPTIONAL/additive: absent on a legacy entry (verify + selection unchanged).
    #[serde(default)]
    pub caps: Option<CapsDto>,
    #[serde(rename = "capsSig", default)]
    pub caps_sig: Option<String>,
}

/// Untrusted caps object on a directory entry (`g.caps`). Deserialized leniently, then
/// mapped to shadenet_proto's `Caps` and CANONICALIZED (dedup/sort/range-check) by the proto
/// crate — this DTO does no validation itself.
#[derive(Deserialize)]
pub struct CapsDto {
    #[serde(default)]
    pub ports: Option<Vec<i64>>,
    #[serde(default)]
    pub region: Option<String>,
    #[serde(default)]
    pub proto: Option<ProtoCapsDto>,
    // T-HARD-8: accepted ZK artifact ids (canonicalized by shadenet-proto; junk dropped there).
    #[serde(default)]
    pub artifacts: Option<Vec<String>>,
    // T-FEAT-9: admission policy + payment advert (canonicalized by shadenet-proto; junk dropped).
    #[serde(default)]
    pub admits: Option<Vec<String>>,
    #[serde(default)]
    pub pay: Option<PayCapsDto>,
    #[serde(default)]
    pub rate: Option<RateCapsDto>,
    // Session tickets (ADR 0011): `{ version, classes }`, canonicalized by shadenet-proto.
    #[serde(default)]
    pub session: Option<SessionCapsDto>,
    // Operator drain flag (day-two ops): `true` while the node announces a planned stop.
    #[serde(default)]
    pub draining: Option<bool>,
    // Admission sets this node reads (dogfood #234); canonicalized by shadenet-proto.
    #[serde(default)]
    pub sets: Option<Vec<String>>,
}

/// Untrusted `caps.session`; validation lives in `shadenet_proto::canonical_session`.
#[derive(Deserialize)]
pub struct SessionCapsDto {
    #[serde(default)]
    pub version: i64,
    #[serde(default)]
    pub classes: Vec<String>,
}

/// Untrusted signed fixed-window rate policy. Structural/range validation stays
/// in shadenet-proto so parsing and canonical signature bytes share one rule.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RateCapsDto {
    pub scope: String,
    pub window: String,
    pub epoch_seconds: i64,
    pub previous_epochs_accepted: i64,
    pub root_freshness_seconds: i64,
    pub payload_bytes_per_slot: i64,
}

/// Untrusted `caps.pay` (T-FEAT-9). Lenient: tiers may carry string or integer prices; the
/// proto crate validates/normalizes (`canonical_pay`).
#[derive(Deserialize)]
pub struct PayCapsDto {
    #[serde(default)]
    pub protocols: Option<Vec<String>>,
    #[serde(default)]
    pub onion: Option<String>,
    #[serde(default)]
    pub port: Option<i64>,
    #[serde(default)]
    pub asset: Option<String>,
    #[serde(default)]
    pub chain: Option<String>,
    #[serde(default)]
    pub tiers: Option<std::collections::BTreeMap<String, serde_json::Value>>,
}

impl PayCapsDto {
    fn into_proto(self) -> shadenet_proto::PayCaps {
        shadenet_proto::PayCaps {
            protocols: self.protocols,
            onion: self.onion,
            port: self.port,
            asset: self.asset,
            chain: self.chain,
            tiers: self.tiers.map(|m| {
                m.into_iter()
                    .map(|(k, v)| {
                        let price = match v {
                            serde_json::Value::String(s) => s,
                            serde_json::Value::Number(n) => n.to_string(),
                            _ => String::new(),
                        };
                        (k, price)
                    })
                    .collect()
            }),
        }
    }
}

#[derive(Deserialize)]
pub struct ProtoCapsDto {
    pub min: i64,
    pub max: i64,
}

#[derive(Deserialize)]
pub struct DirectoryDto {
    pub version: u64,
    pub issued: u64,
    #[serde(default)]
    pub gateways: Vec<DirEntryDto>,
    #[serde(default)]
    pub signer: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
    // T-FEAT-9c: carry the M-of-N threshold fields through so the client consumes
    // threshold-signed directories (verify_directory auto-delegates when present).
    #[serde(default)]
    pub signers: Option<Vec<String>>,
    #[serde(default)]
    pub signatures: Option<Vec<String>>,
    #[serde(default)]
    pub threshold: Option<i64>,
    /// Issue #67: unsigned demo routing advert.  Keep it as a raw value so a
    /// malformed optional advert is ignored without making the signed directory
    /// itself unparsable.
    #[serde(default)]
    pub demo: Option<serde_json::Value>,
}

/// Validated, unsigned demo advert from the bootnode directory.  It is never
/// included in canonical directory bytes and never treated as an admission
/// signature; it only narrows `--leaf-source demo` routing candidates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemoAdvert {
    pub port: u16,
    pub pow_bits: u32,
    pub limit: u64,
    pub contract: String,
    pub chain: String,
    pub gateways: Vec<String>,
    pub onion: Option<String>,
}

fn normalize_onion(value: &str) -> Option<String> {
    let full = if value.to_ascii_lowercase().ends_with(".onion") {
        value.to_ascii_lowercase()
    } else {
        format!("{}.onion", value.to_ascii_lowercase())
    };
    shadenet_proto::onion_to_pubkey(&full).ok()?;
    Some(full)
}

/// Parse the issue-#67 demo block leniently: any malformed field drops the
/// whole unsigned advert while leaving the signed directory usable.
fn parse_demo(value: Option<&serde_json::Value>) -> Option<DemoAdvert> {
    let obj = value?.as_object()?;
    let port = u16::try_from(obj.get("port")?.as_u64()?)
        .ok()
        .filter(|p| *p > 0)?;
    let pow_bits = u32::try_from(obj.get("powBits")?.as_u64()?).ok()?;
    let limit = obj.get("limit")?.as_u64().filter(|n| *n > 0)?;
    let contract = obj.get("contract")?.as_str()?.to_ascii_lowercase();
    if contract.len() != 42 || !contract.starts_with("0x") || hex::decode(&contract[2..]).is_err() {
        return None;
    }
    let chain = obj.get("chain")?.as_str()?.to_ascii_lowercase();
    let chain_id = chain.strip_prefix("eip155:")?;
    if chain_id.is_empty() || !chain_id.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let raw_gateways = obj.get("gateways")?.as_array()?;
    let mut gateways = Vec::with_capacity(raw_gateways.len());
    for item in raw_gateways {
        let normalized = normalize_onion(item.as_str()?)?;
        if !gateways.contains(&normalized) {
            gateways.push(normalized);
        }
    }
    let onion = match obj.get("onion") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => Some(normalize_onion(v.as_str()?)?),
    };
    Some(DemoAdvert {
        port,
        pow_bits,
        limit,
        contract,
        chain,
        gateways,
        onion,
    })
}

impl DirectoryDto {
    pub fn into_proto(self) -> Directory {
        Directory {
            version: self.version,
            issued: self.issued,
            gateways: self
                .gateways
                .into_iter()
                .map(|g| GatewayEntry {
                    onion: g.onion,
                    pubkey: g.pubkey,
                    weight: g.weight,
                    health: g.health,
                    operator: g.operator,
                    staked: g.staked,
                    caps: g.caps.map(|c| Caps {
                        ports: c.ports,
                        region: c.region,
                        proto: c.proto.map(|p| ProtoCaps {
                            min: p.min,
                            max: p.max,
                        }),
                        artifacts: c.artifacts,
                        admits: c.admits,
                        pay: c.pay.map(|p| p.into_proto()),
                        rate: c.rate.map(|rate| RateCaps {
                            scope: rate.scope,
                            window: rate.window,
                            epoch_seconds: rate.epoch_seconds,
                            previous_epochs_accepted: rate.previous_epochs_accepted,
                            root_freshness_seconds: rate.root_freshness_seconds,
                            payload_bytes_per_slot: rate.payload_bytes_per_slot,
                        }),
                        session: c.session.map(|session| shadenet_proto::SessionCaps {
                            version: session.version,
                            classes: session.classes,
                        }),
                        draining: c.draining,
                        sets: c.sets,
                    }),
                    caps_sig: g.caps_sig,
                })
                .collect(),
            signer: self.signer,
            signature: self.signature,
            signers: self.signers,
            signatures: self.signatures,
            threshold: self.threshold,
        }
    }

    fn into_document(self) -> DirectoryDocument {
        let demo = parse_demo(self.demo.as_ref());
        DirectoryDocument {
            dir: self.into_proto(),
            demo,
        }
    }
}

#[derive(Debug)]
pub struct DirectoryDocument {
    pub dir: Directory,
    pub demo: Option<DemoAdvert>,
}

pub fn parse_document(raw: &str) -> Result<DirectoryDocument, String> {
    let dto: DirectoryDto =
        serde_json::from_str(raw).map_err(|e| format!("directory parse: {e}"))?;
    Ok(dto.into_document())
}

pub fn parse_and_verify_document(raw: &str, signers: &str) -> Result<DirectoryDocument, String> {
    let document = parse_document(raw)?;
    let pins: Vec<&str> = signers
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    verify_directory_with_signers(&document.dir, &pins)
        .map_err(|e| format!("directory rejected: {e}"))?;
    Ok(document)
}

/// Where the accepted directory came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A freshly fetched/read directory that verified and passed the guards.
    Fresh,
    /// The last-known-good on-disk cache (the fresh path failed or was refused).
    Cache,
}

/// The accepted directory + provenance.
#[derive(Debug)]
pub struct LoadOutcome {
    pub dir: Directory,
    pub demo: Option<DemoAdvert>,
    pub source: Source,
    /// Why the fresh path was not used, when `source == Cache`.
    pub fresh_error: Option<String>,
}

/// Optional absolute-freshness bound (T-FEAT-21). Both in milliseconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MaxAge {
    pub max_age_ms: Option<u64>,
    pub skew_ms: u64,
}

/// Read + verify the on-disk cache. Best-effort: any error (missing/corrupt/
/// unverifiable) yields `None`, so a broken cache never serves an unverified
/// directory (verify runs here too).
fn read_verified_cache(cache_path: Option<&Path>, signer: &str) -> Option<DirectoryDocument> {
    let raw = std::fs::read_to_string(cache_path?).ok()?;
    parse_and_verify_document(&raw, signer).ok()
}

/// Best-effort write-through of an accepted fresh directory to the LKG cache.
fn write_cache(cache_path: Option<&Path>, raw: &str) {
    let Some(path) = cache_path else { return };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let body = if raw.ends_with('\n') {
        raw.to_string()
    } else {
        format!("{raw}\n")
    };
    let _ = std::fs::write(path, body);
}

/// Resolve the directory to use from a (maybe-failed) FRESH fetch + the LKG cache.
///
/// `fresh` is the result of reading a file / fetching over the network; an `Err`
/// models a dead or unreachable source. `signer` is the pinned ed25519 signer hex.
/// `now_ms` is the current wall clock in ms (for the max-age guard).
///
/// Returns the accepted directory + provenance, or an error only when BOTH the
/// fresh path and the cache are unusable (fail-closed: never an unverified list).
pub fn resolve_directory(
    fresh: Result<String, String>,
    cache_path: Option<&Path>,
    signer: &str,
    max_age: MaxAge,
    now_ms: u64,
) -> Result<LoadOutcome, String> {
    // The LKG cache doubles as the monotonic `issued` floor for the rollback guard.
    let cached = read_verified_cache(cache_path, signer);
    let floor = cached.as_ref().map(|d| d.dir.issued).unwrap_or(0);

    // Reason the fresh path was rejected (drives the cache-fallback message).
    let fresh_reject: String = match fresh {
        Ok(raw) => match parse_and_verify_document(&raw, signer) {
            Ok(document) => {
                let dir = document.dir;
                // Rollback guard: a fresh directory must not move `issued` BACKWARD
                // relative to the last-known-good we already accepted.
                if dir.issued < floor {
                    format!(
                        "directory rollback rejected: issued {} < cached {floor}",
                        dir.issued
                    )
                } else if let Some(max) = max_age.max_age_ms {
                    // Absolute max-age guard (fresh only; cache is exempt).
                    let age_ms = now_ms.saturating_sub(dir.issued.saturating_mul(1000));
                    if age_ms > max + max_age.skew_ms {
                        format!(
                            "directory too stale: issued {}s is {}s old > max-age {}s (bound+skew)",
                            dir.issued,
                            age_ms / 1000,
                            (max + max_age.skew_ms) / 1000
                        )
                    } else {
                        // Accept: overwrite the LKG cache (raising the floor).
                        write_cache(cache_path, &raw);
                        return Ok(LoadOutcome {
                            dir,
                            demo: document.demo,
                            source: Source::Fresh,
                            fresh_error: None,
                        });
                    }
                } else {
                    write_cache(cache_path, &raw);
                    return Ok(LoadOutcome {
                        dir,
                        demo: document.demo,
                        source: Source::Fresh,
                        fresh_error: None,
                    });
                }
            }
            Err(e) => e,
        },
        Err(e) => e,
    };

    // Fresh path unusable -> fall back to the last-known-good cache (verified above).
    match cached {
        Some(document) => Ok(LoadOutcome {
            dir: document.dir,
            demo: document.demo,
            source: Source::Cache,
            fresh_error: Some(fresh_reject),
        }),
        None => Err(format!(
            "no verifiable directory (fresh: {fresh_reject}; no valid cache)"
        )),
    }
}

// --------------------------------------------------------------------------
// Minimal HTTP/1.1 over a byte stream (bootnode discovery). Ports bootnode/
// fetch.mjs: the bootnode always sends a Content-Length body over a
// Connection: close socket, so header/body split on the first CRLFCRLF is
// enough. Used over plain TCP here (default build) and over an arti Tor stream
// in the `live` egress module.
// --------------------------------------------------------------------------

/// Generous cap on a bootnode response so a hostile/misbehaving source gets a
/// bounded read, not an OOM (`bootnode/fetch.mjs` `MAX_RESP`, 2 MiB).
pub const MAX_HTTP_RESP: usize = 2 * 1024 * 1024;

/// Build a `GET <path> HTTP/1.1` request for the bootnode onion (Connection:
/// close so the body ends at EOF).
pub fn http_get_request(host: &str, path: &str) -> String {
    format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept: application/json\r\n\r\n"
    )
}

/// Parse a full HTTP/1.1 response, returning the body iff the status is 200.
/// Mirrors `bootnode/fetch.mjs` `parseHttp` (no chunked support needed).
pub fn parse_http_body(buf: &[u8]) -> Result<String, String> {
    let sep = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "no HTTP header terminator".to_string())?;
    let head = String::from_utf8_lossy(&buf[..sep]);
    let status_line = head.lines().next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("bad HTTP status line: {status_line:?}"))?;
    let body = String::from_utf8_lossy(&buf[sep + 4..]).to_string();
    if status != 200 {
        return Err(format!(
            "bootnode HTTP {status}: {}",
            body.chars().take(200).collect::<String>()
        ));
    }
    Ok(body)
}

/// Fetch `path` from a plain-TCP HTTP endpoint (the `--bootnode-tcp` escape hatch,
/// analogous to `--plain-tcp` for egress). Reads to EOF, capped at [`MAX_HTTP_RESP`].
pub fn fetch_http_plain(dial: &str, host: &str, path: &str) -> Result<String, String> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    let mut stream = TcpStream::connect(dial).map_err(|e| format!("connect {dial}: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(20))).ok();
    stream
        .write_all(http_get_request(host, path).as_bytes())
        .map_err(|e| format!("write request: {e}"))?;
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream
            .read(&mut chunk)
            .map_err(|e| format!("read response: {e}"))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_HTTP_RESP {
            return Err(format!("bootnode response exceeded {MAX_HTTP_RESP} bytes"));
        }
    }
    parse_http_body(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A tiny valid signed directory + its pinned signer, generated once with the
    // JS reference (group/sign-directory.mjs) so verify_directory accepts it. Kept
    // inline so these tests need no fixtures or network.
    const SIGNER: &str = include_str!("testdata/lkg_signer.txt");
    fn signed_dir(issued: u64) -> String {
        // The signature only covers {version,issued,gateways}; we hold gateways +
        // version fixed and vary issued, so each issued value needs its own
        // signature. The fixtures below are pre-signed for the two issued values
        // the tests use (100 and 200).
        match issued {
            100 => include_str!("testdata/lkg_dir_100.json").to_string(),
            200 => include_str!("testdata/lkg_dir_200.json").to_string(),
            _ => panic!("no fixture for issued={issued}"),
        }
    }

    fn workdir(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("shade-tree-dircache-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn directory_parser_carries_the_signed_rate_policy_into_proto() {
        let raw = r#"{
          "version": 1,
          "issued": 100,
          "gateways": [{
            "onion": "abcdefghijklmnopqrstuvwxabcdefghijklmnopqrstuvwxabcd.onion",
            "pubkey": "00",
            "weight": 100,
            "health": "up",
            "caps": {"rate": {
              "scope": "grove-v4",
              "window": "fixed",
              "epochSeconds": 60,
              "previousEpochsAccepted": 1,
              "rootFreshnessSeconds": 60,
              "payloadBytesPerSlot": 41943040
            }}
          }]
        }"#;
        let document = parse_document(raw).unwrap();
        let rate = shadenet_proto::canonical_caps(document.dir.gateways[0].caps.as_ref().unwrap())
            .rate
            .unwrap();
        assert_eq!(rate.scope, "grove-v4");
        assert_eq!(rate.window, "fixed");
        assert_eq!(rate.epoch_seconds, 60);
        assert_eq!(rate.previous_epochs_accepted, 1);
        assert_eq!(rate.root_freshness_seconds, 60);
        assert_eq!(rate.payload_bytes_per_slot, 41_943_040);
    }

    #[test]
    fn fresh_verifies_and_writes_cache() {
        let d = workdir("fresh");
        let cache = d.join("dir.lkg");
        let signer = SIGNER.trim();
        let out = resolve_directory(
            Ok(signed_dir(100)),
            Some(&cache),
            signer,
            MaxAge::default(),
            0,
        )
        .unwrap();
        assert_eq!(out.source, Source::Fresh);
        assert_eq!(out.dir.issued, 100);
        assert!(cache.exists(), "LKG cache written");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn fresh_failure_falls_back_to_verified_cache() {
        let d = workdir("lkg");
        let cache = d.join("dir.lkg");
        let signer = SIGNER.trim();
        // Seed a good cache.
        resolve_directory(
            Ok(signed_dir(100)),
            Some(&cache),
            signer,
            MaxAge::default(),
            0,
        )
        .unwrap();
        // Fresh fetch fails -> LKG cache is used (never nothing).
        let out = resolve_directory(
            Err("bootnode unreachable".into()),
            Some(&cache),
            signer,
            MaxAge::default(),
            0,
        )
        .unwrap();
        assert_eq!(out.source, Source::Cache);
        assert_eq!(out.dir.issued, 100);
        assert!(out.fresh_error.unwrap().contains("unreachable"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn unverifiable_fresh_falls_back_never_served() {
        let d = workdir("badfresh");
        let cache = d.join("dir.lkg");
        let signer = SIGNER.trim();
        resolve_directory(
            Ok(signed_dir(100)),
            Some(&cache),
            signer,
            MaxAge::default(),
            0,
        )
        .unwrap();
        // A tampered fresh directory (bad signature) must NOT be served.
        let tampered = signed_dir(100).replace("\"issued\":100", "\"issued\":999");
        let out =
            resolve_directory(Ok(tampered), Some(&cache), signer, MaxAge::default(), 0).unwrap();
        assert_eq!(out.source, Source::Cache);
        assert_eq!(out.dir.issued, 100); // the verified cache, not the tampered 999
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn rollback_fresh_is_refused_cache_kept() {
        let d = workdir("rollback");
        let cache = d.join("dir.lkg");
        let signer = SIGNER.trim();
        // Accept the newer directory first (raises the floor to 200).
        resolve_directory(
            Ok(signed_dir(200)),
            Some(&cache),
            signer,
            MaxAge::default(),
            0,
        )
        .unwrap();
        // A validly-signed OLDER directory (issued 100 < 200) is a rollback: refused.
        let out = resolve_directory(
            Ok(signed_dir(100)),
            Some(&cache),
            signer,
            MaxAge::default(),
            0,
        )
        .unwrap();
        assert_eq!(out.source, Source::Cache);
        assert_eq!(out.dir.issued, 200);
        assert!(out.fresh_error.unwrap().contains("rollback"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn max_age_rejects_stale_fresh() {
        let d = workdir("maxage");
        let cache = d.join("dir.lkg");
        let signer = SIGNER.trim();
        resolve_directory(
            Ok(signed_dir(200)),
            Some(&cache),
            signer,
            MaxAge::default(),
            200_000,
        )
        .unwrap();
        // issued=100s => 100_000ms; now=10_000_000ms => age ~9990s. max-age 60s => reject fresh.
        let ma = MaxAge {
            max_age_ms: Some(60_000),
            skew_ms: 0,
        };
        // Use a distinct cache so the 100-directory is not blocked by the 200 floor.
        let cache2 = d.join("dir2.lkg");
        resolve_directory(
            Ok(signed_dir(100)),
            Some(&cache2),
            signer,
            MaxAge::default(),
            0,
        )
        .unwrap();
        let out =
            resolve_directory(Ok(signed_dir(100)), Some(&cache2), signer, ma, 10_000_000).unwrap();
        assert_eq!(out.source, Source::Cache); // stale fresh refused, cache kept
        assert!(out.fresh_error.unwrap().contains("too stale"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn no_fresh_no_cache_is_fatal() {
        let d = workdir("fatal");
        let cache = d.join("dir.lkg");
        let signer = SIGNER.trim();
        let err = resolve_directory(
            Err("dead".into()),
            Some(&cache),
            signer,
            MaxAge::default(),
            0,
        )
        .unwrap_err();
        assert!(err.contains("no verifiable directory"));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn parse_http_body_extracts_200_and_rejects_non_200() {
        let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(parse_http_body(ok).unwrap(), "{}");
        let notfound = b"HTTP/1.1 404 Not Found\r\n\r\nnope";
        assert!(parse_http_body(notfound).is_err());
    }

    #[test]
    fn demo_advert_is_parsed_outside_signed_bytes_and_malformed_is_ignored() {
        let raw = signed_dir(100);
        let demo = "\"demo\":{\"port\":8878,\"powBits\":18,\"limit\":8,\"contract\":\"0x1111111111111111111111111111111111111111\",\"chain\":\"eip155:11155111\",\"gateways\":[\"ucnkl5d2m5myal7zkx4nyljkcss4thjdx2l7qzasp74tqncvutypp3ad\"]},\"signer\"";
        let with_demo = raw.replace("\"signer\"", demo);
        let parsed = parse_and_verify_document(&with_demo, SIGNER.trim()).unwrap();
        let advert = parsed.demo.expect("valid unsigned demo advert");
        assert_eq!(advert.port, 8878);
        assert_eq!(advert.gateways.len(), 1);
        assert!(advert.gateways[0].ends_with(".onion"));

        let malformed = with_demo.replace("\"powBits\":18", "\"powBits\":\"eighteen\"");
        let parsed = parse_and_verify_document(&malformed, SIGNER.trim()).unwrap();
        assert!(
            parsed.demo.is_none(),
            "bad optional advert does not poison directory"
        );
    }
}
