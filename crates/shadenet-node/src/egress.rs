//! The destination side (`gateway.mjs` `validTarget`, `makeEgressPolicy`,
//! `isPublicEgressAddress`, `resolveEgressTarget`, `dialNext`): the target grammar and the
//! operator's allow/deny policy are checked before any proof work; DNS runs only after
//! admission, every answer must be public, and the pinned addresses are dialled in order under
//! one deadline.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use serde_json::Value;
use tokio::net::TcpStream;

pub(crate) const REASON_BAD_TARGET: &str = "bad-target";
pub(crate) const REASON_BAD_TARGET_POLICY: &str = "bad-target-policy";
pub(crate) const REASON_BAD_TARGET_DNS: &str = "bad-target-dns";
pub(crate) const REASON_BAD_TARGET_ADDRESS: &str = "bad-target-address";
const MAX_ADDRESSES: usize = 8;
/// How often the node looks at the blocklist file for a change.
pub(crate) const BLOCKLIST_POLL: Duration = Duration::from_secs(60);

enum HostPattern {
    Any,
    Suffix(String),
    Exact(String),
}

struct Pattern {
    host: HostPattern,
    port: Option<u16>,
}

impl Pattern {
    fn parse(spec: &str) -> Option<Self> {
        let (host, port) = spec.rsplit_once(':')?;
        if host.is_empty() || port.is_empty() {
            return None;
        }
        let host = host.to_ascii_lowercase();
        let host = if host == "*" {
            HostPattern::Any
        } else if let Some(suffix) = host.strip_prefix('*') {
            if suffix.starts_with('.') {
                HostPattern::Suffix(suffix.to_string())
            } else {
                HostPattern::Exact(host)
            }
        } else {
            HostPattern::Exact(host)
        };
        let port = if port == "*" {
            None
        } else {
            Some(parse_port(port)?)
        };
        Some(Self { host, port })
    }

    fn matches(&self, host: &str, port: u16) -> bool {
        if self.port.is_some_and(|p| p != port) {
            return false;
        }
        match &self.host {
            HostPattern::Any => true,
            HostPattern::Suffix(suffix) => host.ends_with(suffix.as_str()),
            HostPattern::Exact(exact) => exact == host,
        }
    }
}

/// A hosts-format or domain-list file on the deny side (`SHADE_TREE_EGRESS_DENY_FILE`): one
/// host per line as `0.0.0.0 host`, `127.0.0.1 host`, `:: host` or `host`, `#` comments. A listed
/// host is refused on every port, and so are its subdomains. Single-label names (the `localhost`
/// lines of a hosts file) are skipped: they are never public destinations.
pub(crate) struct Blocklist {
    path: PathBuf,
    hosts: RwLock<Arc<HashSet<String>>>,
    modified: Mutex<Option<SystemTime>>,
}

/// The hosts named in blocklist text.
fn parse_blocklist(text: &str) -> HashSet<String> {
    let mut hosts = HashSet::new();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        let mut fields = line.split_whitespace();
        let Some(first) = fields.next() else {
            continue;
        };
        let name = match fields.next() {
            Some(second) if first.parse::<IpAddr>().is_ok() => second,
            _ => first,
        };
        let name = name.rsplit_once(':').map_or(name, |(host, port)| {
            if parse_port(port).is_some() {
                host
            } else {
                name
            }
        });
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let plausible = name.contains('.')
            && !name.starts_with('.')
            && !name.contains("..")
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
        if plausible {
            hosts.insert(name);
        }
    }
    hosts
}

impl Blocklist {
    fn load(path: &Path) -> Result<(HashSet<String>, Option<SystemTime>), String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let modified = std::fs::metadata(path).and_then(|m| m.modified()).ok();
        Ok((parse_blocklist(&text), modified))
    }

    /// Read the file once; an unreadable file is a startup error.
    pub(crate) fn open(path: PathBuf) -> Result<Self, String> {
        let (hosts, modified) = Self::load(&path)?;
        Ok(Self {
            path,
            hosts: RwLock::new(Arc::new(hosts)),
            modified: Mutex::new(modified),
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.hosts.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// Re-read the file when its modification time moved. `Some(count)` after a reload; an
    /// unreadable file keeps the last good list.
    pub(crate) fn reload(&self) -> Option<usize> {
        let modified = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok();
        {
            let last = self.modified.lock().unwrap_or_else(|e| e.into_inner());
            if *last == modified {
                return None;
            }
        }
        match Self::load(&self.path) {
            Ok((hosts, modified)) => {
                let count = hosts.len();
                *self.hosts.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(hosts);
                *self.modified.lock().unwrap_or_else(|e| e.into_inner()) = modified;
                tracing::info!(path = %self.path.display(), hosts = count, "egress blocklist re-read");
                Some(count)
            }
            Err(error) => {
                tracing::warn!(%error, "egress blocklist could not be re-read; keeping the last good list");
                None
            }
        }
    }

    /// The host itself or any parent domain is listed.
    fn blocks(&self, host: &str) -> bool {
        let hosts = Arc::clone(&self.hosts.read().unwrap_or_else(|e| e.into_inner()));
        let mut suffix = host;
        loop {
            if hosts.contains(suffix) {
                return true;
            }
            match suffix.split_once('.') {
                Some((_, rest)) if !rest.is_empty() => suffix = rest,
                _ => return false,
            }
        }
    }
}

pub(crate) struct Policy {
    allows: Vec<Pattern>,
    denies: Vec<Pattern>,
    blocklist: Option<Blocklist>,
}

/// A target that passed the grammar and the policy.
pub(crate) struct Target {
    pub(crate) host: String,
    pub(crate) port: u16,
}

impl Policy {
    /// Comma-separated `host:port` patterns; malformed entries are dropped.
    pub(crate) fn parse(allow: &str, deny: &str) -> Self {
        let list = |spec: &str| {
            spec.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .filter_map(Pattern::parse)
                .collect()
        };
        Self {
            allows: list(allow),
            denies: list(deny),
            blocklist: None,
        }
    }

    /// Add a blocklist file to the deny side.
    pub(crate) fn with_blocklist(mut self, path: PathBuf) -> Result<Self, String> {
        self.blocklist = Some(Blocklist::open(path)?);
        Ok(self)
    }

    /// How many hosts the blocklist holds, when there is one.
    pub(crate) fn blocklist_hosts(&self) -> Option<usize> {
        self.blocklist.as_ref().map(Blocklist::len)
    }

    /// Re-read a changed blocklist file; `Some(count)` after a reload.
    pub(crate) fn reload_blocklist(&self) -> Option<usize> {
        self.blocklist.as_ref().and_then(Blocklist::reload)
    }

    fn allows(&self, host: &str, port: u16) -> bool {
        let host = host.to_ascii_lowercase();
        let host = host.strip_suffix('.').unwrap_or(&host);
        if host.is_empty() || host.starts_with('.') || host.contains("..") {
            return false;
        }
        if self.denies.iter().any(|p| p.matches(host, port)) {
            return false;
        }
        if self
            .blocklist
            .as_ref()
            .is_some_and(|list| list.blocks(host))
        {
            return false;
        }
        self.allows.iter().any(|p| p.matches(host, port))
    }

    /// Check an envelope's `target` field: the `host:port` grammar first, then this policy.
    pub(crate) fn check_target(&self, target: Option<&Value>) -> Result<Target, &'static str> {
        let target = target.and_then(Value::as_str).ok_or(REASON_BAD_TARGET)?;
        let (host, port) = target.rsplit_once(':').ok_or(REASON_BAD_TARGET)?;
        let host_ok = !host.is_empty()
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
        if !host_ok {
            return Err(REASON_BAD_TARGET);
        }
        let port = parse_port(port).ok_or(REASON_BAD_TARGET)?;
        if !self.allows(host, port) {
            return Err(REASON_BAD_TARGET_POLICY);
        }
        Ok(Target {
            host: host.to_string(),
            port,
        })
    }
}

fn parse_port(digits: &str) -> Option<u16> {
    if digits.is_empty() || digits.len() > 5 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits
        .parse::<u32>()
        .ok()
        .filter(|p| (1..=65535).contains(p))
        .and_then(|p| u16::try_from(p).ok())
}

const IPV4_NON_PUBLIC: [(Ipv4Addr, u32); 18] = [
    (Ipv4Addr::new(0, 0, 0, 0), 8),
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(100, 64, 0, 0), 10),
    (Ipv4Addr::new(127, 0, 0, 0), 8),
    (Ipv4Addr::new(169, 254, 0, 0), 16),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 0, 0, 0), 24),
    (Ipv4Addr::new(192, 0, 2, 0), 24),
    (Ipv4Addr::new(192, 31, 196, 0), 24),
    (Ipv4Addr::new(192, 52, 193, 0), 24),
    (Ipv4Addr::new(192, 88, 99, 0), 24),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(192, 175, 48, 0), 24),
    (Ipv4Addr::new(198, 18, 0, 0), 15),
    (Ipv4Addr::new(198, 51, 100, 0), 24),
    (Ipv4Addr::new(203, 0, 113, 0), 24),
    (Ipv4Addr::new(224, 0, 0, 0), 4),
    (Ipv4Addr::new(240, 0, 0, 0), 4),
];

const IPV6_SPECIAL: [(Ipv6Addr, u32); 5] = [
    (Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23),
    (Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16),
    (Ipv6Addr::new(0x2620, 0x4f, 0x8000, 0, 0, 0, 0, 0), 48),
    (Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20),
];

fn in_v4(value: Ipv4Addr, base: Ipv4Addr, prefix: u32) -> bool {
    let shift = 32 - prefix;
    (u32::from(value) >> shift) == (u32::from(base) >> shift)
}

fn in_v6(value: Ipv6Addr, base: Ipv6Addr, prefix: u32) -> bool {
    let shift = 128 - prefix;
    (u128::from(value) >> shift) == (u128::from(base) >> shift)
}

/// A destination a node may egress to: global unicast, none of the special-purpose ranges.
pub(crate) fn is_public(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => !IPV4_NON_PUBLIC
            .iter()
            .any(|(base, prefix)| in_v4(v4, *base, *prefix)),
        IpAddr::V6(v6) => {
            in_v6(v6, Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3)
                && !IPV6_SPECIAL
                    .iter()
                    .any(|(base, prefix)| in_v6(v6, *base, *prefix))
        }
    }
}

/// Resolve once, validate every answer, pin at most eight addresses.
pub(crate) async fn resolve(
    target: &Target,
    allow_private: bool,
    timeout: Option<Duration>,
) -> Result<Vec<SocketAddr>, &'static str> {
    if let Ok(literal) = target.host.parse::<IpAddr>() {
        if !allow_private && !is_public(literal) {
            return Err(REASON_BAD_TARGET_ADDRESS);
        }
        return Ok(vec![SocketAddr::new(literal, target.port)]);
    }
    let lookup = tokio::net::lookup_host((target.host.as_str(), target.port));
    let answers = match timeout {
        Some(limit) => tokio::time::timeout(limit, lookup)
            .await
            .map_err(|_| REASON_BAD_TARGET_DNS)?,
        None => lookup.await,
    }
    .map_err(|_| REASON_BAD_TARGET_DNS)?
    .collect::<Vec<SocketAddr>>();
    if answers.is_empty() {
        return Err(REASON_BAD_TARGET_DNS);
    }
    if !allow_private && answers.iter().any(|a| !is_public(a.ip())) {
        return Err(REASON_BAD_TARGET_ADDRESS);
    }
    let mut pinned: Vec<SocketAddr> = Vec::new();
    for answer in answers {
        if !pinned.contains(&answer) {
            pinned.push(answer);
        }
        if pinned.len() == MAX_ADDRESSES {
            break;
        }
    }
    Ok(pinned)
}

/// The wire reason for a failed dial: `upstream:<errno name>`.
pub(crate) fn upstream_reason(error: &std::io::Error) -> String {
    use std::io::ErrorKind;
    let code = match error.kind() {
        ErrorKind::ConnectionRefused => "ECONNREFUSED",
        ErrorKind::ConnectionReset => "ECONNRESET",
        ErrorKind::ConnectionAborted => "ECONNABORTED",
        ErrorKind::TimedOut => "ETIMEDOUT",
        ErrorKind::NetworkUnreachable => "ENETUNREACH",
        ErrorKind::HostUnreachable => "EHOSTUNREACH",
        ErrorKind::NetworkDown => "ENETDOWN",
        ErrorKind::AddrNotAvailable => "EADDRNOTAVAIL",
        ErrorKind::PermissionDenied => "EACCES",
        _ => "EIO",
    };
    format!("upstream:{code}")
}

/// Dial the pinned addresses in order. Every candidate shares one deadline; each gets a fair
/// slice of what remains so one black hole cannot starve the rest.
pub(crate) async fn dial(
    candidates: &[SocketAddr],
    deadline: Option<Duration>,
) -> Result<TcpStream, String> {
    let started = Instant::now();
    let mut last = String::from("upstream:ETIMEDOUT");
    for (index, candidate) in candidates.iter().enumerate() {
        let later = candidates.len() - index - 1;
        let attempt = match deadline {
            Some(total) => {
                let remaining = total.saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    return Err("upstream:ETIMEDOUT".into());
                }
                Some(remaining / u32::try_from(later + 1).unwrap_or(u32::MAX))
            }
            None => None,
        };
        let connect = TcpStream::connect(candidate);
        let outcome = match attempt {
            Some(limit) => tokio::time::timeout(limit, connect)
                .await
                .unwrap_or_else(|_| Err(std::io::Error::from(std::io::ErrorKind::TimedOut))),
            None => connect.await,
        };
        match outcome {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Err(e) => last = upstream_reason(&e),
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(policy: &Policy, target: &str) -> Result<(String, u16), &'static str> {
        policy
            .check_target(Some(&Value::String(target.into())))
            .map(|t| (t.host, t.port))
    }

    #[test]
    fn the_default_policy_allows_only_port_443() {
        let policy = Policy::parse("*:443", "");
        assert_eq!(
            check(&policy, "example.com:443"),
            Ok(("example.com".into(), 443))
        );
        assert_eq!(
            check(&policy, "example.com:80"),
            Err(REASON_BAD_TARGET_POLICY)
        );
        assert_eq!(
            check(&policy, "EXAMPLE.com.:0443"),
            Ok(("EXAMPLE.com.".into(), 443))
        );
    }

    #[test]
    fn target_grammar_is_host_colon_port() {
        let policy = Policy::parse("*:*", "");
        for bad in [
            "example.com",
            ":443",
            "example.com:",
            "example.com:0",
            "example.com:65536",
            "example.com:443443",
            "[::1]:443",
            "exa mple.com:443",
            "example.com:44a",
        ] {
            assert_eq!(check(&policy, bad), Err(REASON_BAD_TARGET), "{bad}");
        }
        assert!(policy.check_target(None).is_err());
        assert!(policy
            .check_target(Some(&Value::Number(443.into())))
            .is_err());
    }

    #[test]
    fn deny_wins_and_suffixes_exclude_the_apex() {
        let policy = Policy::parse("*.example.com:443, api.other.org:*", "evil.example.com:443");
        assert!(check(&policy, "a.example.com:443").is_ok());
        assert_eq!(
            check(&policy, "example.com:443"),
            Err(REASON_BAD_TARGET_POLICY)
        );
        assert_eq!(
            check(&policy, "evil.example.com:443"),
            Err(REASON_BAD_TARGET_POLICY)
        );
        assert_eq!(
            check(&policy, "evil.example.com.:443"),
            Err(REASON_BAD_TARGET_POLICY)
        );
        assert!(check(&policy, "api.other.org:8443").is_ok());
        assert_eq!(
            check(&policy, "..example.com:443"),
            Err(REASON_BAD_TARGET_POLICY)
        );
    }

    #[test]
    fn malformed_patterns_are_dropped() {
        let policy = Policy::parse("nocolon, :443, host:, host:99999, host:x, *:443", "");
        assert!(check(&policy, "host:443").is_ok());
        assert_eq!(check(&policy, "host:80"), Err(REASON_BAD_TARGET_POLICY));
        let empty = Policy::parse("", "");
        assert_eq!(check(&empty, "host:443"), Err(REASON_BAD_TARGET_POLICY));
    }

    #[test]
    fn a_blocklist_file_reads_hosts_lines_and_covers_subdomains() {
        let parsed = parse_blocklist(
            "# comment\n0.0.0.0 ads.example.com # trailing\n127.0.0.1 localhost\n:: Tracker.Example.NET.\nbad.example.org:443\nnot a host\n\n..broken.com\nbare\n",
        );
        let mut hosts: Vec<&str> = parsed.iter().map(String::as_str).collect();
        hosts.sort_unstable();
        assert_eq!(
            hosts,
            ["ads.example.com", "bad.example.org", "tracker.example.net"]
        );

        let dir = std::env::temp_dir().join(format!("shadenet-blocklist-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("blocklist.txt");
        std::fs::write(&file, "0.0.0.0 ads.example.com\n").unwrap();
        let policy = Policy::parse("*:443", "")
            .with_blocklist(file.clone())
            .unwrap();
        assert_eq!(policy.blocklist_hosts(), Some(1));
        assert_eq!(
            check(&policy, "ads.example.com:443"),
            Err(REASON_BAD_TARGET_POLICY)
        );
        assert_eq!(
            check(&policy, "cdn.ads.example.com:443"),
            Err(REASON_BAD_TARGET_POLICY),
            "subdomains are covered"
        );
        assert_eq!(
            check(&policy, "ADS.example.com.:443"),
            Err(REASON_BAD_TARGET_POLICY)
        );
        assert!(
            check(&policy, "example.com:443").is_ok(),
            "the parent is not"
        );
        assert!(check(&policy, "notads.example.com:443").is_ok());

        assert_eq!(policy.reload_blocklist(), None, "unchanged file: no reload");
        std::thread::sleep(Duration::from_millis(1100));
        std::fs::write(
            &file,
            "0.0.0.0 other.example.com\n0.0.0.0 ads.example.com\n",
        )
        .unwrap();
        assert_eq!(policy.reload_blocklist(), Some(2));
        assert_eq!(
            check(&policy, "other.example.com:443"),
            Err(REASON_BAD_TARGET_POLICY)
        );
        std::fs::remove_file(&file).unwrap();
        assert_eq!(
            policy.reload_blocklist(),
            None,
            "a vanished file keeps the last list"
        );
        assert_eq!(policy.blocklist_hosts(), Some(2));
        assert!(Policy::parse("*:443", "")
            .with_blocklist(dir.join("missing.txt"))
            .is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn public_addresses_exclude_every_special_range() {
        for private in [
            "0.0.0.0",
            "10.1.2.3",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.1",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.255",
            "203.0.113.9",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "fe80::1",
            "fc00::1",
            "2001:db8::1",
            "2002::1",
            "2001:0:1::1",
            "2620:4f:8000::1",
            "3fff::1",
        ] {
            assert!(!is_public(private.parse().unwrap()), "{private}");
        }
        for public in [
            "1.1.1.1",
            "8.8.8.8",
            "172.32.0.1",
            "2606:4700::1111",
            "2a00::1",
        ] {
            assert!(is_public(public.parse().unwrap()), "{public}");
        }
    }

    #[tokio::test]
    async fn literals_skip_dns_and_private_ones_need_the_opt_in() {
        let target = Target {
            host: "127.0.0.1".into(),
            port: 443,
        };
        assert_eq!(
            resolve(&target, false, None).await,
            Err(REASON_BAD_TARGET_ADDRESS)
        );
        assert_eq!(
            resolve(&target, true, None).await,
            Ok(vec!["127.0.0.1:443".parse().unwrap()])
        );
        let localhost = Target {
            host: "localhost".into(),
            port: 443,
        };
        assert_eq!(
            resolve(&localhost, false, Some(Duration::from_secs(5))).await,
            Err(REASON_BAD_TARGET_ADDRESS)
        );
        let nowhere = Target {
            host: "nonexistent.invalid".into(),
            port: 443,
        };
        assert_eq!(
            resolve(&nowhere, true, Some(Duration::from_secs(5))).await,
            Err(REASON_BAD_TARGET_DNS)
        );
    }

    #[tokio::test]
    async fn a_refused_dial_names_the_errno_and_falls_through() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open = listener.local_addr().unwrap();
        let closed = {
            let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            probe.local_addr().unwrap()
        };
        assert_eq!(
            dial(&[closed], Some(Duration::from_secs(2))).await.err(),
            Some("upstream:ECONNREFUSED".into())
        );
        assert!(dial(&[closed, open], Some(Duration::from_secs(2)))
            .await
            .is_ok());
    }
}
