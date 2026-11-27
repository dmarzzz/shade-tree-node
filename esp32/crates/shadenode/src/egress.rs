//! Where a tunnel may go: the target grammar, the operator's allow and deny lists, and the
//! address filter that keeps the node from being a way into its own network.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{channel, Receiver, TryRecvError};
use std::time::{Duration, Instant};

/// At most this many resolved addresses are tried.
const MAX_ADDRESSES: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Exactly as sent (DNS sees this spelling).
    pub host: String,
    pub port: u16,
}

/// `host:port`, split at the last colon. Hosts are letters, digits, dots and hyphens, so IPv6
/// literals are refused. Leading zeros in the port are accepted, as the reference node does.
pub fn parse_target(target: &str) -> Option<Target> {
    let (host, port) = target.rsplit_once(':')?;
    if host.is_empty()
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return None;
    }
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let port: u32 = port.parse().ok()?;
    if !(1..=65535).contains(&port) {
        return None;
    }
    Some(Target {
        host: host.to_string(),
        port: port as u16,
    })
}

#[derive(Debug, Clone)]
struct Pattern {
    host: HostPattern,
    /// `None` matches any port.
    port: Option<u16>,
}

#[derive(Debug, Clone)]
enum HostPattern {
    Any,
    /// Matches hosts ending in this (it starts with a dot).
    Suffix(String),
    Exact(String),
}

fn parse_patterns(list: &str) -> Vec<Pattern> {
    list.split(',')
        .filter_map(|item| {
            let (host, port) = item.trim().rsplit_once(':')?;
            let port = match port {
                "*" => None,
                p => Some(p.parse::<u16>().ok().filter(|p| *p != 0)?),
            };
            let host = host.to_ascii_lowercase();
            let host = match host.as_str() {
                "" => return None,
                "*" => HostPattern::Any,
                h => match h.strip_prefix('*') {
                    Some(suffix) if suffix.starts_with('.') => {
                        HostPattern::Suffix(suffix.to_string())
                    }
                    _ => HostPattern::Exact(host),
                },
            };
            Some(Pattern { host, port })
        })
        .collect()
}

impl Pattern {
    fn matches(&self, host: &str, port: u16) -> bool {
        if self.port.is_some_and(|p| p != port) {
            return false;
        }
        match &self.host {
            HostPattern::Any => true,
            HostPattern::Suffix(suffix) => host.ends_with(suffix.as_str()),
            HostPattern::Exact(exact) => host == exact,
        }
    }
}

/// The operator's policy. Deny wins over allow.
#[derive(Debug, Clone)]
pub struct Policy {
    allow: Vec<Pattern>,
    deny: Vec<Pattern>,
}

impl Policy {
    /// Comma-separated `host:port` patterns: `*`, `*.suffix` or an exact name; `*` or a number
    /// for the port. The reference default is `*:443` with nothing denied.
    pub fn new(allow: &str, deny: &str) -> Self {
        Self {
            allow: parse_patterns(allow),
            deny: parse_patterns(deny),
        }
    }

    pub fn permits(&self, target: &Target) -> bool {
        let lower = target.host.to_ascii_lowercase();
        let host = lower.strip_suffix('.').unwrap_or(&lower);
        if host.is_empty() || host.starts_with('.') || host.contains("..") {
            return false;
        }
        if self.deny.iter().any(|p| p.matches(host, target.port)) {
            return false;
        }
        self.allow.iter().any(|p| p.matches(host, target.port))
    }

    /// The concrete ports the allow list names, for the `ports` capability.
    pub fn ports(&self) -> Vec<u16> {
        let mut ports: Vec<u16> = self.allow.iter().filter_map(|p| p.port).collect();
        ports.sort_unstable();
        ports.dedup();
        ports
    }
}

fn v4_in(addr: Ipv4Addr, base: [u8; 4], prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    (u32::from(addr) & mask) == (u32::from(Ipv4Addr::from(base)) & mask)
}

fn v6_in(addr: Ipv6Addr, base: [u16; 8], prefix: u32) -> bool {
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    };
    (u128::from(addr) & mask) == (u128::from(Ipv6Addr::from(base)) & mask)
}

/// Whether `addr` is a public, routable address. Loopback, private, link-local, carrier-grade
/// NAT, documentation, multicast and every other special-purpose range are refused.
pub fn is_public(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => {
            const BLOCKED: [([u8; 4], u32); 18] = [
                ([0, 0, 0, 0], 8),
                ([10, 0, 0, 0], 8),
                ([100, 64, 0, 0], 10),
                ([127, 0, 0, 0], 8),
                ([169, 254, 0, 0], 16),
                ([172, 16, 0, 0], 12),
                ([192, 0, 0, 0], 24),
                ([192, 0, 2, 0], 24),
                ([192, 31, 196, 0], 24),
                ([192, 52, 193, 0], 24),
                ([192, 88, 99, 0], 24),
                ([192, 168, 0, 0], 16),
                ([192, 175, 48, 0], 24),
                ([198, 18, 0, 0], 15),
                ([198, 51, 100, 0], 24),
                ([203, 0, 113, 0], 24),
                ([224, 0, 0, 0], 4),
                ([240, 0, 0, 0], 4),
            ];
            !BLOCKED
                .iter()
                .any(|(base, prefix)| v4_in(a, *base, *prefix))
        }
        IpAddr::V6(a) => {
            const BLOCKED: [([u16; 8], u32); 5] = [
                ([0x2001, 0, 0, 0, 0, 0, 0, 0], 23),
                ([0x2001, 0x0db8, 0, 0, 0, 0, 0, 0], 32),
                ([0x2002, 0, 0, 0, 0, 0, 0, 0], 16),
                ([0x2620, 0x004f, 0x8000, 0, 0, 0, 0, 0], 48),
                ([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20),
            ];
            v6_in(a, [0x2000, 0, 0, 0, 0, 0, 0, 0], 3)
                && !BLOCKED
                    .iter()
                    .any(|(base, prefix)| v6_in(a, *base, *prefix))
        }
    }
}

fn error_code(e: &std::io::Error) -> &'static str {
    use std::io::ErrorKind as K;
    match e.kind() {
        K::ConnectionRefused => "ECONNREFUSED",
        K::ConnectionReset => "ECONNRESET",
        K::ConnectionAborted => "ECONNABORTED",
        K::TimedOut | K::WouldBlock => "ETIMEDOUT",
        K::NetworkUnreachable => "ENETUNREACH",
        K::HostUnreachable => "EHOSTUNREACH",
        K::NetworkDown => "ENETDOWN",
        K::AddrNotAvailable => "EADDRNOTAVAIL",
        K::PermissionDenied => "EACCES",
        _ => "EIO",
    }
}

#[derive(Clone)]
pub struct DialConfig {
    pub allow_private: bool,
    pub dns_timeout: Duration,
    /// One deadline shared by every address tried.
    pub connect_timeout: Duration,
    /// Stack for the resolver thread (the device has little to spare).
    pub thread_stack: usize,
    /// Skip IPv6 answers (a network with no IPv6 route would only time out on them).
    pub ipv4_only: bool,
}

/// Resolve the name once, refuse if any answer is non-public, then connect to the answers in
/// order. Blocking; meant for a helper thread.
fn resolve_and_connect(target: &Target, config: &DialConfig) -> Result<TcpStream, String> {
    let addresses: Vec<SocketAddr> = match target.host.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, target.port)],
        Err(_) => (target.host.as_str(), target.port)
            .to_socket_addrs()
            .map_err(|_| "bad-target-dns".to_string())?
            .collect(),
    };
    if addresses.is_empty() {
        return Err("bad-target-dns".into());
    }
    if !config.allow_private && addresses.iter().any(|a| !is_public(a.ip())) {
        return Err("bad-target-address".into());
    }
    let mut pinned: Vec<SocketAddr> = Vec::new();
    for address in addresses {
        if config.ipv4_only && address.is_ipv6() {
            continue;
        }
        if !pinned.contains(&address) && pinned.len() < MAX_ADDRESSES {
            pinned.push(address);
        }
    }
    if pinned.is_empty() {
        return Err("upstream:ENETUNREACH".into());
    }
    let deadline = Instant::now() + config.connect_timeout;
    let mut last = "ETIMEDOUT";
    for (i, address) in pinned.iter().enumerate() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            last = "ETIMEDOUT";
            break;
        }
        let share = remaining / (pinned.len() - i) as u32;
        match TcpStream::connect_timeout(address, share.max(Duration::from_millis(1))) {
            Ok(stream) => {
                stream.set_nodelay(true).ok();
                return Ok(stream);
            }
            Err(e) => last = error_code(&e),
        }
    }
    Err(format!("upstream:{last}"))
}

/// A dial in progress on a helper thread, so the event loop never waits on DNS or a connect.
pub struct Dial {
    result: Receiver<Result<TcpStream, String>>,
    started: Instant,
    limit: Duration,
}

impl Dial {
    pub fn start(target: Target, config: DialConfig) -> Result<Self, String> {
        let (tx, rx) = channel();
        let limit = config.dns_timeout + config.connect_timeout;
        std::thread::Builder::new()
            .name("dial".into())
            .stack_size(config.thread_stack)
            .spawn(move || {
                let _ = tx.send(resolve_and_connect(&target, &config));
            })
            .map_err(|_| "upstream:EIO".to_string())?;
        Ok(Self {
            result: rx,
            started: Instant::now(),
            limit,
        })
    }

    /// `None` while the dial is still running.
    pub fn poll(&self) -> Option<Result<TcpStream, String>> {
        match self.result.try_recv() {
            Ok(result) => Some(result),
            Err(TryRecvError::Disconnected) => Some(Err("upstream:EIO".into())),
            // The resolver has no deadline of its own; stop waiting for it.
            Err(TryRecvError::Empty) if self.started.elapsed() > self.limit => {
                Some(Err("bad-target-dns".into()))
            }
            Err(TryRecvError::Empty) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_grammar() {
        assert_eq!(
            parse_target("example.com:443"),
            Some(Target {
                host: "example.com".into(),
                port: 443
            })
        );
        assert_eq!(parse_target("Example.COM.:0443").unwrap().port, 443);
        for bad in [
            "example.com",
            ":443",
            "example.com:",
            "example.com:0",
            "example.com:65536",
            "[::1]:443",
            "exa_mple.com:443",
            "example.com:44a",
            "example.com:123456",
            "a b:1",
        ] {
            assert_eq!(parse_target(bad), None, "{bad}");
        }
    }

    #[test]
    fn policy_matching() {
        let policy = Policy::new("*:443, *.example.org:8443", "bank.com:443,*.bank.com:443");
        let t = |s: &str| parse_target(s).unwrap();
        assert!(policy.permits(&t("example.com:443")));
        assert!(policy.permits(&t("EXAMPLE.com.:443")));
        assert!(!policy.permits(&t("example.com:80")));
        assert!(policy.permits(&t("a.example.org:8443")));
        assert!(!policy.permits(&t("example.org:8443")));
        assert!(!policy.permits(&t("bank.com:443")));
        assert!(!policy.permits(&t("www.bank.com:443")));
        assert!(policy.permits(&t("notbank.com:443")));
        assert!(!policy.permits(&t("a..b:443")));
        assert_eq!(policy.ports(), vec![443, 8443]);
    }

    #[test]
    fn address_filter() {
        let public = ["1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"];
        let private = [
            "0.1.2.3",
            "10.0.0.1",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.1",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.7",
            "203.0.113.9",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "ff02::1",
            "::ffff:10.0.0.1",
            "2001:db8::1",
            "2002::1",
            "64:ff9b::1",
            "2001::1",
        ];
        for a in public {
            assert!(is_public(a.parse().unwrap()), "{a}");
        }
        for a in private {
            assert!(!is_public(a.parse().unwrap()), "{a}");
        }
        assert!(is_public("100.128.0.1".parse().unwrap()));
        assert!(is_public("172.32.0.1".parse().unwrap()));
    }
}
