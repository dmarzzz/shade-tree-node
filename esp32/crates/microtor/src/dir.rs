//! Directory documents (dir-spec): authority key certificates, the microdescriptor consensus,
//! microdescriptors, and the HTTP exchange that fetches them over a BEGIN_DIR stream.
//!
//! Every parser here is streaming. The consensus is a few megabytes; a device with 200 KB of
//! heap never sees more than one line of it at a time.

use std::net::{Ipv4Addr, SocketAddrV4};

use miniz_oxide::inflate::stream::{inflate, InflateState};
use miniz_oxide::{DataFormat, MZFlush, MZStatus};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::bootstrap_data::AUTHORITIES;
use crate::circuit::Circuit;
use crate::crypto::{ct_eq, sha1, RsaPublic};
use crate::util::{
    b64_decode, b64_decode_into, b64_fixed, hex_fixed, parse_datetime, LineSplitter,
};
use crate::{Error, Result};

pub mod flag {
    pub const EXIT: u16 = 1 << 0;
    pub const FAST: u16 = 1 << 1;
    pub const GUARD: u16 = 1 << 2;
    pub const HSDIR: u16 = 1 << 3;
    pub const RUNNING: u16 = 1 << 4;
    pub const STABLE: u16 = 1 << 5;
    pub const V2DIR: u16 = 1 << 6;
    pub const VALID: u16 = 1 << 7;
    pub const BAD_EXIT: u16 = 1 << 8;
    pub const AUTHORITY: u16 = 1 << 9;
    pub const MIDDLE_ONLY: u16 = 1 << 10;
}

fn flag_bit(name: &str) -> u16 {
    match name {
        "Exit" => flag::EXIT,
        "Fast" => flag::FAST,
        "Guard" => flag::GUARD,
        "HSDir" => flag::HSDIR,
        "Running" => flag::RUNNING,
        "Stable" => flag::STABLE,
        "V2Dir" => flag::V2DIR,
        "Valid" => flag::VALID,
        "BadExit" => flag::BAD_EXIT,
        "Authority" => flag::AUTHORITY,
        "MiddleOnly" => flag::MIDDLE_ONLY,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------------------------
// Authority key certificates

/// A directory authority's signing key, certified by its long-term identity key.
pub struct AuthCert {
    pub v3ident: [u8; 20],
    pub signing_key_digest: [u8; 20],
    pub signing_key: RsaPublic,
    pub expires: u64,
}

fn pem_body(lines: &[String]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for line in lines {
        b64_decode_into(line.as_bytes(), &mut out)?;
    }
    Ok(out)
}

/// Parse and verify a concatenation of `dir-key-certificate-version 3` documents. Certificates
/// from unknown authorities, expired ones and ones whose signature fails are skipped.
pub struct AuthCertParser {
    lines: LineSplitter,
    hasher: Option<Sha1>,
    fingerprint: Option<[u8; 20]>,
    expires: u64,
    block: Option<&'static str>,
    block_lines: Vec<String>,
    identity_der: Vec<u8>,
    signing_der: Vec<u8>,
    now: u64,
    pub certs: Vec<AuthCert>,
}

impl AuthCertParser {
    pub fn new(now: u64) -> Self {
        Self {
            lines: LineSplitter::new(256),
            hasher: None,
            fingerprint: None,
            expires: 0,
            block: None,
            block_lines: Vec::new(),
            identity_der: Vec::new(),
            signing_der: Vec::new(),
            now,
            certs: Vec::new(),
        }
    }

    pub fn feed(&mut self, data: &[u8]) -> Result<()> {
        let mut lines = core::mem::replace(&mut self.lines, LineSplitter::new(0));
        let result = lines.feed(data, |line| self.line(line));
        self.lines = lines;
        result
    }

    fn line(&mut self, raw: &[u8]) -> Result<()> {
        let line = core::str::from_utf8(raw).map_err(|_| Error::Parse("cert utf8"))?;
        if line == "dir-key-certificate-version 3" {
            self.hasher = Some(Sha1::new());
            self.fingerprint = None;
            self.expires = 0;
            self.identity_der.clear();
            self.signing_der.clear();
            self.block = None;
        }
        // The signed text runs from the first line through `dir-key-certification\n`.
        let in_signature = self.block == Some("certification");
        if let Some(h) = self.hasher.as_mut() {
            if !in_signature {
                h.update(raw);
                h.update(b"\n");
            }
        } else {
            return Ok(());
        }

        if line.starts_with("-----BEGIN ") {
            self.block_lines.clear();
            return Ok(());
        }
        if line.starts_with("-----END ") {
            let body = pem_body(&self.block_lines)?;
            self.block_lines.clear();
            match self.block.take() {
                Some("identity") => self.identity_der = body,
                Some("signing") => self.signing_der = body,
                Some("certification") => self.finish_cert(&body),
                _ => {}
            }
            return Ok(());
        }
        if self.block.is_some()
            && !line.contains(' ')
            && !line.is_empty()
            && !line.starts_with("dir-")
        {
            self.block_lines.push(line.to_string());
            return Ok(());
        }
        let mut words = line.split(' ');
        match words.next() {
            Some("fingerprint") => {
                self.fingerprint = words.next().and_then(|w| hex_fixed::<20>(w).ok());
            }
            Some("dir-key-expires") => {
                if let (Some(d), Some(t)) = (words.next(), words.next()) {
                    self.expires = parse_datetime(d, t).unwrap_or(0);
                }
            }
            Some("dir-identity-key") => self.block = Some("identity"),
            Some("dir-signing-key") => self.block = Some("signing"),
            Some("dir-key-crosscert") => self.block = Some("crosscert"),
            Some("dir-key-certification") => self.block = Some("certification"),
            _ => {}
        }
        Ok(())
    }

    fn finish_cert(&mut self, signature: &[u8]) {
        let Some(hasher) = self.hasher.take() else {
            return;
        };
        let digest: [u8; 20] = hasher.finalize().into();
        let Some(fingerprint) = self.fingerprint else {
            return;
        };
        if !AUTHORITIES.iter().any(|a| a.v3ident == fingerprint) {
            return;
        }
        if sha1(&[&self.identity_der]) != fingerprint || self.expires <= self.now {
            return;
        }
        let Ok(identity) = RsaPublic::from_der(&self.identity_der) else {
            return;
        };
        match identity.open(signature) {
            Ok(signed) if ct_eq(&signed, &digest) => {}
            _ => {
                log::warn!("authority certificate signature did not verify");
                return;
            }
        }
        let Ok(signing_key) = RsaPublic::from_der(&self.signing_der) else {
            return;
        };
        let signing_key_digest = sha1(&[&self.signing_der]);
        // Keep the newest certificate per authority.
        self.certs
            .retain(|c| c.v3ident != fingerprint || c.expires > self.expires);
        if !self.certs.iter().any(|c| c.v3ident == fingerprint) {
            self.certs.push(AuthCert {
                v3ident: fingerprint,
                signing_key_digest,
                signing_key,
                expires: self.expires,
            });
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Consensus

#[derive(Clone, Debug, Default)]
pub struct ConsensusMeta {
    pub valid_after: u64,
    pub fresh_until: u64,
    pub valid_until: u64,
    pub srv_current: Option<[u8; 32]>,
    pub srv_previous: Option<[u8; 32]>,
    /// Onion-service time period length in minutes (`hsdir_interval`).
    pub hsdir_interval: u64,
    pub hsdir_n_replicas: u8,
    pub hsdir_spread_store: u8,
    pub hsdir_spread_fetch: u8,
    pub relays: u32,
}

/// One relay's entry in the microdescriptor consensus.
#[derive(Clone, Debug)]
pub struct RouterEntry {
    pub rsa_id: [u8; 20],
    pub addr: SocketAddrV4,
    pub md_digest: [u8; 32],
    pub flags: u16,
    /// Consensus bandwidth weight (kilobytes per second, unitless in practice).
    pub bandwidth: u32,
}

/// Bytes of one relay in scratch storage.
pub const ROUTER_RECORD_LEN: usize = 64;

impl RouterEntry {
    pub fn to_record(&self) -> [u8; ROUTER_RECORD_LEN] {
        let mut out = [0u8; ROUTER_RECORD_LEN];
        out[..20].copy_from_slice(&self.rsa_id);
        out[20..24].copy_from_slice(&self.addr.ip().octets());
        out[24..26].copy_from_slice(&self.addr.port().to_be_bytes());
        out[26..28].copy_from_slice(&self.flags.to_be_bytes());
        out[28..32].copy_from_slice(&self.bandwidth.to_be_bytes());
        out[32..].copy_from_slice(&self.md_digest);
        out
    }

    pub fn from_record(r: &[u8; ROUTER_RECORD_LEN]) -> Self {
        Self {
            rsa_id: r[..20].try_into().unwrap(),
            addr: SocketAddrV4::new(
                Ipv4Addr::new(r[20], r[21], r[22], r[23]),
                u16::from_be_bytes([r[24], r[25]]),
            ),
            flags: u16::from_be_bytes([r[26], r[27]]),
            bandwidth: u32::from_be_bytes(r[28..32].try_into().unwrap()),
            md_digest: r[32..].try_into().unwrap(),
        }
    }
}

pub struct ConsensusSignature {
    pub v3ident: [u8; 20],
    pub signing_key_digest: [u8; 20],
    pub sha256: bool,
    pub signature: Vec<u8>,
}

const SIGNATURE_NEEDLE: &[u8] = b"directory-signature ";

/// Streaming parser for `consensus-microdesc`. It hashes the signed portion as it goes and
/// collects the signatures; nothing it reports is trustworthy until [`verify_consensus`]
/// accepts the result.
pub struct ConsensusParser {
    lines: LineSplitter,
    hasher: Option<Sha256>,
    /// How much of `SIGNATURE_NEEDLE` the current line has matched; `None` once it cannot.
    needle: Option<usize>,
    current: Option<RouterEntry>,
    in_signature: bool,
    sig_lines: Vec<u8>,
    pub meta: ConsensusMeta,
    pub signatures: Vec<ConsensusSignature>,
    digest: Option<[u8; 32]>,
}

impl Default for ConsensusParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsensusParser {
    pub fn new() -> Self {
        Self {
            lines: LineSplitter::new(4096),
            hasher: Some(Sha256::new()),
            needle: Some(0),
            current: None,
            in_signature: false,
            sig_lines: Vec::new(),
            meta: ConsensusMeta {
                hsdir_interval: 1440,
                hsdir_n_replicas: 2,
                hsdir_spread_store: 4,
                hsdir_spread_fetch: 3,
                ..Default::default()
            },
            signatures: Vec::new(),
            digest: None,
        }
    }

    /// Hash the signed part: everything through the space after the first
    /// `directory-signature` that starts a line.
    fn hash(&mut self, data: &[u8]) {
        let Some(hasher) = self.hasher.as_mut() else {
            return;
        };
        let mut i = 0;
        while i < data.len() {
            match self.needle {
                None => match data[i..].iter().position(|&b| b == b'\n') {
                    Some(pos) => {
                        i += pos + 1;
                        self.needle = Some(0);
                    }
                    None => i = data.len(),
                },
                Some(matched) if data[i] == SIGNATURE_NEEDLE[matched] => {
                    i += 1;
                    if matched + 1 == SIGNATURE_NEEDLE.len() {
                        hasher.update(&data[..i]);
                        self.digest = self.hasher.take().map(|h| h.finalize().into());
                        return;
                    }
                    self.needle = Some(matched + 1);
                }
                Some(_) => {
                    self.needle = (data[i] == b'\n').then_some(0);
                    i += 1;
                }
            }
        }
        hasher.update(data);
    }

    pub fn feed(&mut self, data: &[u8], on_router: &mut dyn FnMut(&RouterEntry)) -> Result<()> {
        self.hash(data);
        let mut lines = core::mem::replace(&mut self.lines, LineSplitter::new(0));
        let result = lines.feed(data, |line| self.line(line, on_router));
        self.lines = lines;
        result
    }

    fn flush_router(&mut self, on_router: &mut dyn FnMut(&RouterEntry)) {
        if let Some(entry) = self.current.take() {
            self.meta.relays += 1;
            on_router(&entry);
        }
    }

    fn line(&mut self, raw: &[u8], on_router: &mut dyn FnMut(&RouterEntry)) -> Result<()> {
        let Ok(line) = core::str::from_utf8(raw) else {
            return Ok(());
        };
        if self.in_signature {
            if line.starts_with("-----END") {
                self.in_signature = false;
                let mut signature = Vec::new();
                b64_decode_into(&self.sig_lines, &mut signature)?;
                self.sig_lines.clear();
                if let Some(last) = self.signatures.last_mut() {
                    last.signature = signature;
                }
            } else if !line.starts_with("-----BEGIN") {
                self.sig_lines.extend_from_slice(raw);
            }
            return Ok(());
        }
        let (keyword, rest) = line.split_once(' ').unwrap_or((line, ""));
        match keyword {
            "r" => {
                self.flush_router(on_router);
                // r nickname identity published-date published-time IP ORPort DirPort
                let mut f = rest.split(' ');
                let (_nick, id, _date, _time, ip, port) =
                    (f.next(), f.next(), f.next(), f.next(), f.next(), f.next());
                let parsed = (|| {
                    Some(RouterEntry {
                        rsa_id: b64_fixed::<20>(id?).ok()?,
                        addr: SocketAddrV4::new(ip?.parse().ok()?, port?.parse().ok()?),
                        md_digest: [0u8; 32],
                        flags: 0,
                        bandwidth: 0,
                    })
                })();
                self.current = parsed;
            }
            "m" => {
                if let Some(entry) = self.current.as_mut() {
                    match b64_fixed::<32>(rest.split(' ').next().unwrap_or("")) {
                        Ok(d) => entry.md_digest = d,
                        Err(_) => self.current = None,
                    }
                }
            }
            "s" => {
                if let Some(entry) = self.current.as_mut() {
                    entry.flags = rest.split(' ').fold(0, |acc, name| acc | flag_bit(name));
                }
            }
            "w" => {
                if let Some(entry) = self.current.as_mut() {
                    entry.bandwidth = rest
                        .split(' ')
                        .find_map(|kv| kv.strip_prefix("Bandwidth="))
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                }
            }
            "valid-after" | "fresh-until" | "valid-until" => {
                let (date, time) = rest.split_once(' ').ok_or(Error::Parse("consensus date"))?;
                let t = parse_datetime(date, time)?;
                match keyword {
                    "valid-after" => self.meta.valid_after = t,
                    "fresh-until" => self.meta.fresh_until = t,
                    _ => self.meta.valid_until = t,
                }
            }
            "shared-rand-current-value" | "shared-rand-previous-value" => {
                // shared-rand-*-value NumReveals Value
                let value = rest.split(' ').nth(1).and_then(|v| b64_fixed::<32>(v).ok());
                if keyword == "shared-rand-current-value" {
                    self.meta.srv_current = value;
                } else {
                    self.meta.srv_previous = value;
                }
            }
            "params" => {
                for kv in rest.split(' ') {
                    let Some((k, v)) = kv.split_once('=') else {
                        continue;
                    };
                    let Ok(v) = v.parse::<i64>() else { continue };
                    match k {
                        "hsdir_interval" if (30..=14400).contains(&v) => {
                            self.meta.hsdir_interval = v as u64;
                        }
                        "hsdir_n_replicas" if (1..=16).contains(&v) => {
                            self.meta.hsdir_n_replicas = v as u8;
                        }
                        "hsdir_spread_store" if (1..=128).contains(&v) => {
                            self.meta.hsdir_spread_store = v as u8;
                        }
                        "hsdir_spread_fetch" if (1..=128).contains(&v) => {
                            self.meta.hsdir_spread_fetch = v as u8;
                        }
                        _ => {}
                    }
                }
            }
            "directory-footer" => self.flush_router(on_router),
            "directory-signature" => {
                self.flush_router(on_router);
                // directory-signature [Algorithm] identity signing-key-digest
                let words: Vec<&str> = rest.split(' ').collect();
                let (sha256, ident, key) = match words.as_slice() {
                    [algo, ident, key] => (*algo == "sha256", *ident, *key),
                    [ident, key] => (false, *ident, *key),
                    _ => return Err(Error::Parse("directory-signature")),
                };
                self.signatures.push(ConsensusSignature {
                    v3ident: hex_fixed(ident)?,
                    signing_key_digest: hex_fixed(key)?,
                    sha256,
                    signature: Vec::new(),
                });
                self.in_signature = true;
            }
            _ => {}
        }
        Ok(())
    }

    /// The SHA-256 of the signed portion, once the first signature has been reached.
    pub fn signed_digest(&self) -> Option<[u8; 32]> {
        self.digest
    }
}

/// Accept a consensus when more than half of the known authorities signed its digest with a
/// certified key, and it is not expired (a day of slack past `valid-until`, as Tor clients
/// allow) or from the future.
pub fn verify_consensus(parser: &ConsensusParser, certs: &[AuthCert], now: u64) -> Result<()> {
    let digest = parser
        .signed_digest()
        .ok_or(Error::Proto("consensus has no signatures"))?;
    let meta = &parser.meta;
    if meta.valid_after == 0 || meta.valid_until < meta.valid_after {
        return Err(Error::Proto("consensus has no validity interval"));
    }
    if now + 3600 < meta.valid_after || now > meta.valid_until + 86_400 {
        return Err(Error::Proto("consensus is not valid at this time"));
    }
    let mut signers: Vec<[u8; 20]> = Vec::new();
    for sig in parser.signatures.iter().filter(|s| s.sha256) {
        let Some(cert) = certs
            .iter()
            .find(|c| c.v3ident == sig.v3ident && c.signing_key_digest == sig.signing_key_digest)
        else {
            continue;
        };
        if signers.contains(&sig.v3ident) {
            continue;
        }
        match cert.signing_key.open(&sig.signature) {
            Ok(signed) if ct_eq(&signed, &digest) => signers.push(sig.v3ident),
            _ => log::warn!("a consensus signature did not verify"),
        }
    }
    let needed = AUTHORITIES.len() / 2 + 1;
    log::info!(
        "consensus signed by {} of {} authorities ({} needed)",
        signers.len(),
        AUTHORITIES.len(),
        needed
    );
    if signers.len() < needed {
        return Err(Error::Proto("too few authority signatures on consensus"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Microdescriptors

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Microdesc {
    /// SHA-256 of the microdescriptor text; matches the consensus `m` line.
    pub digest: [u8; 32],
    pub ntor_key: Option<[u8; 32]>,
    pub ed_id: Option<[u8; 32]>,
}

const MD_START: &[u8] = b"onion-key\n";

/// Splits a concatenation of microdescriptors, hashing each one exactly as served.
pub struct MicrodescParser {
    hasher: Option<Sha256>,
    /// Bytes at the start of a line that may still turn out to be `onion-key\n`.
    pending: Vec<u8>,
    deciding: bool,
    head: Vec<u8>,
    ntor_key: Option<[u8; 32]>,
    ed_id: Option<[u8; 32]>,
}

impl Default for MicrodescParser {
    fn default() -> Self {
        Self::new()
    }
}

impl MicrodescParser {
    pub fn new() -> Self {
        Self {
            hasher: None,
            pending: Vec::with_capacity(MD_START.len()),
            deciding: true,
            head: Vec::with_capacity(96),
            ntor_key: None,
            ed_id: None,
        }
    }

    fn emit(&mut self, on_md: &mut dyn FnMut(Microdesc)) {
        if let Some(hasher) = self.hasher.take() {
            on_md(Microdesc {
                digest: hasher.finalize().into(),
                ntor_key: self.ntor_key.take(),
                ed_id: self.ed_id.take(),
            });
        }
    }

    fn hash(&mut self, data: &[u8]) {
        if let Some(h) = self.hasher.as_mut() {
            h.update(data);
        }
    }

    pub fn feed(&mut self, mut data: &[u8], on_md: &mut dyn FnMut(Microdesc)) {
        while !data.is_empty() {
            let (part, ended) = match data.iter().position(|&b| b == b'\n') {
                Some(pos) => (&data[..=pos], true),
                None => (data, false),
            };
            data = &data[part.len()..];

            let room = 96usize.saturating_sub(self.head.len());
            self.head.extend_from_slice(&part[..part.len().min(room)]);

            let mut rest = part;
            if self.deciding {
                let take = (MD_START.len() - self.pending.len()).min(rest.len());
                self.pending.extend_from_slice(&rest[..take]);
                rest = &rest[take..];
                if self.pending == MD_START {
                    self.emit(on_md);
                    self.hasher = Some(Sha256::new());
                    let pending = core::mem::take(&mut self.pending);
                    self.hash(&pending);
                } else if !MD_START.starts_with(&self.pending) || ended {
                    self.deciding = false;
                    let pending = core::mem::take(&mut self.pending);
                    self.hash(&pending);
                }
            }
            if !self.deciding || ended {
                self.hash(rest);
            }
            if ended {
                self.end_line();
            }
        }
    }

    fn end_line(&mut self) {
        if let Ok(line) = core::str::from_utf8(&self.head) {
            let line = line.trim_end();
            if let Some(key) = line.strip_prefix("ntor-onion-key ") {
                self.ntor_key = b64_fixed::<32>(key.split(' ').next().unwrap_or("")).ok();
            } else if let Some(key) = line.strip_prefix("id ed25519 ") {
                self.ed_id = b64_fixed::<32>(key).ok();
            }
        }
        self.head.clear();
        self.deciding = true;
        self.pending.clear();
    }

    pub fn finish(&mut self, on_md: &mut dyn FnMut(Microdesc)) {
        let pending = core::mem::take(&mut self.pending);
        self.hash(&pending);
        self.emit(on_md);
    }
}

// ---------------------------------------------------------------------------------------------
// HTTP over a directory stream

enum Body {
    Identity,
    Deflate(Box<InflateState>),
}

/// Incremental HTTP/1.0 response reader: status line, headers, then a body that is either
/// passed through or inflated.
struct HttpResponse {
    head: Vec<u8>,
    body: Option<Body>,
    status: u16,
    out: Vec<u8>,
}

impl HttpResponse {
    fn new() -> Self {
        Self {
            head: Vec::new(),
            body: None,
            status: 0,
            out: Vec::new(),
        }
    }

    fn feed(&mut self, mut data: &[u8], sink: &mut dyn FnMut(&[u8]) -> Result<()>) -> Result<()> {
        if self.body.is_none() {
            self.head.extend_from_slice(data);
            if self.head.len() > 4096 {
                return Err(Error::Parse("http header too long"));
            }
            let Some(end) = self.head.windows(4).position(|w| w == b"\r\n\r\n") else {
                return Ok(());
            };
            let head = core::mem::take(&mut self.head);
            let text =
                core::str::from_utf8(&head[..end]).map_err(|_| Error::Parse("http header"))?;
            let mut lines = text.split("\r\n");
            self.status = lines
                .next()
                .and_then(|l| l.split(' ').nth(1))
                .and_then(|s| s.parse().ok())
                .ok_or(Error::Parse("http status"))?;
            if self.status != 200 {
                return Err(Error::Http(self.status));
            }
            let mut deflate = false;
            for line in lines {
                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("content-encoding") {
                        match value.trim() {
                            "identity" => {}
                            "deflate" | "x-deflate" => deflate = true,
                            _ => return Err(Error::Parse("http content-encoding")),
                        }
                    }
                }
            }
            self.body = Some(if deflate {
                self.out = vec![0u8; 2048];
                Body::Deflate(InflateState::new_boxed(DataFormat::Zlib))
            } else {
                Body::Identity
            });
            let rest = head[end + 4..].to_vec();
            return self.feed(&rest, sink);
        }
        match self.body.as_mut().unwrap() {
            Body::Identity => {
                if !data.is_empty() {
                    sink(data)?;
                }
            }
            Body::Deflate(state) => loop {
                let r = inflate(state, data, &mut self.out, MZFlush::None);
                data = &data[r.bytes_consumed..];
                if r.bytes_written > 0 {
                    sink(&self.out[..r.bytes_written])?;
                }
                match r.status {
                    Ok(MZStatus::StreamEnd) => break,
                    Ok(_) => {}
                    // Nothing more can happen until there is more input.
                    Err(miniz_oxide::MZError::Buf) => break,
                    Err(_) => return Err(Error::Parse("deflate")),
                }
                if data.is_empty() && r.bytes_written < self.out.len() {
                    break;
                }
            },
        }
        Ok(())
    }
}

/// `GET path` over a fresh BEGIN_DIR stream on `circ`, feeding the decoded body to `sink`.
/// Returns the number of bytes received on the wire.
pub async fn dir_get(
    circ: &Circuit,
    path: &str,
    sink: &mut dyn FnMut(&[u8]) -> Result<()>,
) -> Result<usize> {
    let stream = circ.begin_dir().await?;
    let encoding = if crate::rt::limits().dir_compression {
        "deflate, identity"
    } else {
        "identity"
    };
    let request = format!("GET {path} HTTP/1.0\r\nAccept-Encoding: {encoding}\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;
    let mut response = HttpResponse::new();
    let mut buf = vec![0u8; 2048];
    let mut total = 0;
    loop {
        let n = crate::rt::timeout(
            core::time::Duration::from_secs(45),
            "directory response",
            stream.read(&mut buf),
        )
        .await?;
        if n == 0 {
            break;
        }
        total += n;
        response.feed(&buf[..n], sink)?;
    }
    if response.body.is_none() {
        return Err(Error::Parse("http response ended in headers"));
    }
    Ok(total)
}

/// `POST path` with `body`; succeeds on a 200.
pub async fn dir_post(circ: &Circuit, path: &str, body: &[u8]) -> Result<()> {
    let stream = circ.begin_dir().await?;
    let head = format!(
        "POST {path} HTTP/1.0\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    let mut response = HttpResponse::new();
    let mut buf = [0u8; 512];
    loop {
        let n = crate::rt::timeout(
            core::time::Duration::from_secs(45),
            "directory response",
            stream.read(&mut buf),
        )
        .await?;
        if n == 0 {
            break;
        }
        response.feed(&buf[..n], &mut |_| Ok(()))?;
    }
    match response.status {
        200 => Ok(()),
        0 => Err(Error::Parse("no http status")),
        other => Err(Error::Http(other)),
    }
}

/// Decode the base64 body of a PEM-like block given as one string.
pub fn decode_block(text: &str) -> Result<Vec<u8>> {
    b64_decode(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sha256;

    #[test]
    fn microdescs_split_and_hash_at_any_chunking() {
        let md1 = "onion-key\nntor-onion-key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nfamily $ABC $DEF onion-key-lookalike\nid ed25519 AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE\n";
        let md2 = "onion-key\nonion-keyX not a start\nntor-onion-key AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI\n";
        let text = format!("{md1}{md2}");
        for chunk in [1usize, 2, 5, 9, 10, 11, 64, 1000] {
            let mut parser = MicrodescParser::new();
            let mut out = Vec::new();
            for piece in text.as_bytes().chunks(chunk) {
                parser.feed(piece, &mut |md| out.push(md));
            }
            parser.finish(&mut |md| out.push(md));
            assert_eq!(out.len(), 2, "chunk {chunk}");
            assert_eq!(out[0].digest, sha256(&[md1.as_bytes()]), "chunk {chunk}");
            assert_eq!(out[1].digest, sha256(&[md2.as_bytes()]), "chunk {chunk}");
            assert_eq!(out[0].ntor_key, Some([0u8; 32]));
            assert_eq!(out[0].ed_id, Some([1u8; 32]));
            assert_eq!(out[1].ntor_key, Some([2u8; 32]));
            assert_eq!(out[1].ed_id, None);
        }
    }

    #[test]
    fn consensus_parser_hashes_the_signed_part_and_reads_routers() {
        let signed = "network-status-version 3 microdesc\n\
valid-after 2026-11-27 15:00:00\n\
fresh-until 2026-11-27 16:00:00\n\
valid-until 2026-11-27 18:00:00\n\
params hsdir_interval=1440 other=3\n\
shared-rand-previous-value 9 AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\n\
shared-rand-current-value 9 AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\n\
r relayA AAAAAAAAAAAAAAAAAAAAAAAAAAA 2026-11-27 01:02:03 10.1.2.3 9001 0\n\
m AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM\n\
s Fast Guard HSDir Running Stable V2Dir Valid\n\
w Bandwidth=1234\n\
r relayB AQEBAQEBAQEBAQEBAQEBAQEBAQE 2026-11-27 01:02:03 10.9.8.7 443 0\n\
m BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ\n\
s Exit Running Valid\n\
w Bandwidth=7 Unmeasured=1\n\
directory-footer\n\
bandwidth-weights Wbd=0\n\
directory-signature ";
        let tail = "sha256 0232AF901C31A04EE9848595AF9BB7620D4C5B2E 1111111111111111111111111111111111111111\n\
-----BEGIN SIGNATURE-----\nAAEC\n-----END SIGNATURE-----\n\
directory-signature sha256 23D15D965BC35114467363C165C4F724B64B4F66 2222222222222222222222222222222222222222\n\
-----BEGIN SIGNATURE-----\nAwQF\n-----END SIGNATURE-----\n";
        let text = format!("{signed}{tail}");
        for chunk in [1usize, 3, 17, 4096] {
            let mut parser = ConsensusParser::new();
            let mut routers = Vec::new();
            for piece in text.as_bytes().chunks(chunk) {
                parser
                    .feed(piece, &mut |r| routers.push(r.clone()))
                    .unwrap();
            }
            assert_eq!(
                parser.signed_digest(),
                Some(sha256(&[signed.as_bytes()])),
                "chunk {chunk}"
            );
            assert_eq!(routers.len(), 2);
            assert_eq!(routers[0].addr, "10.1.2.3:9001".parse().unwrap());
            assert_eq!(routers[0].md_digest, [3u8; 32]);
            assert_eq!(routers[0].bandwidth, 1234);
            assert!(routers[0].flags & flag::HSDIR != 0 && routers[0].flags & flag::EXIT == 0);
            assert_eq!(routers[1].rsa_id, [1u8; 20]);
            assert_eq!(routers[1].flags, flag::EXIT | flag::RUNNING | flag::VALID);
            assert_eq!(parser.meta.valid_after, 1_795_791_600);
            assert_eq!(parser.meta.srv_current, Some([2u8; 32]));
            assert_eq!(parser.meta.srv_previous, Some([1u8; 32]));
            assert_eq!(parser.signatures.len(), 2);
            assert_eq!(parser.signatures[0].signature, vec![0, 1, 2]);
            assert_eq!(parser.signatures[1].signature, vec![3, 4, 5]);
            let record = routers[0].to_record();
            assert_eq!(
                RouterEntry::from_record(&record).md_digest,
                routers[0].md_digest
            );
        }
    }
}
