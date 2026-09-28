//! Process-scoped agent launcher for `shade-tree run`.
//!
//! The wrapper deliberately does not mutate this process's environment and does
//! not start an agent until the configured loopback CONNECT proxy accepts a TCP
//! connection.  It is kept independent of the live egress implementation: the
//! CLI only needs `mod run;` and a `"run" => run::run(rest)` match arm.

use std::env;
use std::ffi::OsString;
use std::fmt;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::process::{Command, ExitCode, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const DEFAULT_PROXY_URL: &str = "http://127.0.0.1:8118";
const DEFAULT_CHECK_TIMEOUT_MS: u64 = 2_000;
const MAX_CHECK_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_NO_PROXY: [&str; 4] = ["127.0.0.1", "localhost", "::1", "host.docker.internal"];

pub const HELP: &str = "\
shade-tree run: start one command with scoped HTTP(S) proxy settings

USAGE:
    shade-tree run [--proxy URL] [--no-proxy HOSTS]
                   [--check-timeout-ms N] -- <command> [args]

The local proxy and its credentials are checked before launch. Provide the same
unpredictable token used by `shade-tree proxy`, preferably in
SHADE_TREE_PROXY_TOKEN. Only the child receives authenticated proxy URLs; the
current shell is unchanged. Other inherited SHADE_TREE_* settings and ALL_PROXY
escape hatches are stripped. Loopback services bypass the proxy; add other
agent-local hosts with --no-proxy.
";

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedRun {
    proxy: Option<String>,
    no_proxy: Option<String>,
    check_timeout_ms: Option<String>,
    command: String,
    args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProxyUrl {
    normalized: String,
    host: String,
    port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RunConfig {
    proxy: ProxyUrl,
    auth_token: String,
    no_proxy: String,
    timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RunError(String);

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Run a child command with routing scoped to that child.
///
/// `args` is everything after the `run` subcommand, including the required
/// `--` separator. Wrapper/configuration errors use status 2, an unavailable
/// proxy uses status 1, and a missing child executable uses status 127. A
/// started child's exit status is propagated.
pub fn run(args: &[String]) -> ExitCode {
    if matches!(args, [arg] if arg == "--help" || arg == "-h") {
        println!("{HELP}");
        return ExitCode::SUCCESS;
    }

    let parsed = match parse_run_args(args) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("shade-tree run: {error}\n\n{HELP}");
            return ExitCode::from(2);
        }
    };
    let config = match resolve_config(&parsed) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("shade-tree run: {error}");
            return ExitCode::from(2);
        }
    };

    if let Err(error) = check_proxy(&config.proxy, &config.auth_token, config.timeout) {
        eprintln!("shade-tree run: local proxy unavailable; command not started ({error})");
        return ExitCode::from(1);
    }

    let mut command = Command::new(&parsed.command);
    command
        .args(&parsed.args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    apply_child_environment(&mut command, &config);

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            eprintln!("shade-tree run: could not start child: {error}");
            return ExitCode::from(127);
        }
    };

    // A terminal sends SIGINT/SIGTERM to the foreground process group, which
    // already includes both wrapper and child. This guard additionally covers
    // supervisors that signal only the wrapper PID on Unix.
    #[cfg(unix)]
    let _signals = unix_signals::ForwardingGuard::install(child.id());

    match child.wait() {
        Ok(status) => {
            // `ExitCode` only accepts u8, but Windows preserves a native 32-bit
            // process status. Exit directly rather than silently mapping values
            // above 255 to 1. Unix shells already define statuses modulo 256.
            #[cfg(windows)]
            if let Some(code) = status.code() {
                std::process::exit(code);
            }
            exit_code_for_status(status)
        }
        Err(error) => {
            eprintln!("shade-tree run: could not wait for child: {error}");
            ExitCode::from(1)
        }
    }
}

fn parse_run_args(args: &[String]) -> Result<ParsedRun, RunError> {
    let separator = args
        .iter()
        .position(|arg| arg == "--")
        .ok_or_else(|| RunError("missing `--` before the command".into()))?;

    let mut proxy = None;
    let mut no_proxy = None;
    let mut check_timeout_ms = None;
    let mut index = 0;
    while index < separator {
        let arg = &args[index];
        let (name, inline) = match arg.strip_prefix("--") {
            Some(flag) => match flag.split_once('=') {
                Some((name, value)) => (name, Some(value.to_string())),
                None => (flag, None),
            },
            None => return Err(RunError(format!("unexpected argument before `--`: {arg}"))),
        };
        let value = match inline {
            Some(value) if !value.is_empty() => value,
            Some(_) => return Err(RunError(format!("--{name} requires a value"))),
            None => {
                index += 1;
                if index >= separator || args[index].starts_with("--") {
                    return Err(RunError(format!("--{name} requires a value")));
                }
                args[index].clone()
            }
        };
        let target = match name {
            "proxy" => &mut proxy,
            "no-proxy" => &mut no_proxy,
            "check-timeout-ms" => &mut check_timeout_ms,
            _ => return Err(RunError(format!("unknown run flag: --{name}"))),
        };
        if target.replace(value).is_some() {
            return Err(RunError(format!("--{name} may be specified only once")));
        }
        index += 1;
    }

    let command = args
        .get(separator + 1)
        .filter(|command| !command.is_empty())
        .ok_or_else(|| RunError("missing command after `--`".into()))?
        .clone();
    Ok(ParsedRun {
        proxy,
        no_proxy,
        check_timeout_ms,
        command,
        args: args[separator + 2..].to_vec(),
    })
}

fn resolve_config(parsed: &ParsedRun) -> Result<RunConfig, RunError> {
    let proxy_raw = match &parsed.proxy {
        Some(value) => value.clone(),
        None => match env::var("SHADE_TREE_PROXY_URL") {
            Ok(value) if !value.trim().is_empty() => value,
            _ => match env::var("SHADE_TREE_SHIM_PORT") {
                Ok(port) if !port.trim().is_empty() => format!("http://127.0.0.1:{port}"),
                _ => DEFAULT_PROXY_URL.to_string(),
            },
        },
    };
    let proxy = parse_proxy_url(&proxy_raw)?;
    let auth_token = env::var("SHADE_TREE_PROXY_TOKEN")
        .map_err(|_| RunError("missing proxy authentication; set SHADE_TREE_PROXY_TOKEN".into()))?;
    validate_auth_token(&auth_token).map_err(RunError)?;

    let no_proxy_extra = parsed
        .no_proxy
        .clone()
        .or_else(|| env::var("SHADE_TREE_NO_PROXY").ok())
        .unwrap_or_default();
    let no_proxy = build_no_proxy(&no_proxy_extra)?;

    let timeout_raw = parsed
        .check_timeout_ms
        .clone()
        .or_else(|| env::var("SHADE_TREE_PROXY_CHECK_TIMEOUT_MS").ok());
    let timeout_ms = match timeout_raw {
        Some(value) => value
            .parse::<u64>()
            .ok()
            .filter(|n| (1..=MAX_CHECK_TIMEOUT_MS).contains(n)),
        None => Some(DEFAULT_CHECK_TIMEOUT_MS),
    }
    .ok_or_else(|| {
        RunError(format!(
            "--check-timeout-ms must be an integer from 1 to {MAX_CHECK_TIMEOUT_MS}"
        ))
    })?;

    Ok(RunConfig {
        proxy,
        auth_token,
        no_proxy,
        timeout: Duration::from_millis(timeout_ms),
    })
}

pub(crate) fn validate_auth_token(token: &str) -> Result<(), String> {
    if !(32..=256).contains(&token.len())
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte))
    {
        return Err(
            "proxy auth token must be 32..=256 URL-safe characters (A-Z, a-z, 0-9, -, ., _, ~)"
                .into(),
        );
    }
    Ok(())
}

fn parse_proxy_url(raw: &str) -> Result<ProxyUrl, RunError> {
    let authority = raw
        .strip_prefix("http://")
        .ok_or_else(|| RunError("the preview supports an http:// CONNECT proxy URL only".into()))?;
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    if authority.is_empty()
        || authority.contains(['/', '?', '#', '@'])
        || authority.chars().any(char::is_whitespace)
    {
        return Err(RunError(format!(
            "proxy URL must contain only a host and port: {raw}"
        )));
    }

    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let close = bracketed
            .find(']')
            .ok_or_else(|| RunError(format!("invalid bracketed IPv6 proxy address: {raw}")))?;
        let host = &bracketed[..close];
        let suffix = &bracketed[close + 1..];
        let port = if suffix.is_empty() {
            80
        } else {
            suffix
                .strip_prefix(':')
                .ok_or_else(|| RunError(format!("invalid proxy URL: {raw}")))?
                .parse::<u16>()
                .ok()
                .filter(|port| *port > 0)
                .ok_or_else(|| RunError(format!("invalid proxy port in URL: {raw}")))?
        };
        if host.is_empty() || bracketed[close + 1..].contains(']') {
            return Err(RunError(format!("invalid proxy URL: {raw}")));
        }
        (host.to_string(), port)
    } else {
        if authority.matches(':').count() > 1 {
            return Err(RunError(format!(
                "IPv6 proxy addresses must be enclosed in brackets: {raw}"
            )));
        }
        match authority.rsplit_once(':') {
            Some((host, port)) => {
                let port = port
                    .parse::<u16>()
                    .ok()
                    .filter(|port| *port > 0)
                    .ok_or_else(|| RunError(format!("invalid proxy port in URL: {raw}")))?;
                (host.to_string(), port)
            }
            None => (authority.to_string(), 80),
        }
    };
    if host.is_empty() {
        return Err(RunError(format!("proxy URL is missing a host: {raw}")));
    }

    Ok(ProxyUrl {
        normalized: format!("http://{authority}"),
        host,
        port,
    })
}

fn build_no_proxy(extra: &str) -> Result<String, RunError> {
    let mut values: Vec<String> = DEFAULT_NO_PROXY
        .iter()
        .map(|value| value.to_string())
        .collect();
    for value in extra
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if value == "*" {
            return Err(RunError(
                "a wildcard `*` in --no-proxy would bypass Shade Tree".into(),
            ));
        }
        if !values.iter().any(|existing| existing == value) {
            values.push(value.to_string());
        }
    }
    Ok(values.join(","))
}

fn check_proxy(proxy: &ProxyUrl, auth_token: &str, timeout: Duration) -> Result<(), String> {
    let host = proxy.host.clone();
    let port = proxy.port;
    let auth_token = auth_token.to_string();
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = connect_any(&host, port, &auth_token, timeout);
        let _ = sender.send(result);
    });
    receiver
        .recv_timeout(timeout)
        .map_err(|error| match error {
            mpsc::RecvTimeoutError::Timeout => {
                format!("proxy check timed out after {}ms", timeout.as_millis())
            }
            mpsc::RecvTimeoutError::Disconnected => {
                "proxy check worker stopped unexpectedly".into()
            }
        })?
}

fn connect_any(host: &str, port: u16, auth_token: &str, timeout: Duration) -> Result<(), String> {
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("resolve proxy {host}:{port}: {error}"))?;
    let start = Instant::now();
    let mut last_error = None;
    let mut found = false;
    for address in addresses {
        found = true;
        let remaining = timeout.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(&address, remaining) {
            Ok(mut stream) => {
                let remaining = timeout.saturating_sub(start.elapsed());
                stream.set_read_timeout(Some(remaining)).ok();
                stream.set_write_timeout(Some(remaining)).ok();
                use base64::Engine as _;
                let credential = base64::engine::general_purpose::STANDARD
                    .encode(format!("shade-tree:{auth_token}"));
                let request = format!(
                    "GET /_shade_tree/health HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Authorization: Basic {credential}\r\nConnection: close\r\n\r\n"
                );
                stream
                    .write_all(request.as_bytes())
                    .map_err(|error| format!("write authenticated proxy health check: {error}"))?;
                let mut response = [0_u8; 256];
                let read = stream
                    .read(&mut response)
                    .map_err(|error| format!("read authenticated proxy health check: {error}"))?;
                let response = String::from_utf8_lossy(&response[..read]);
                if response.starts_with("HTTP/1.1 204 ") {
                    return Ok(());
                }
                if response.starts_with("HTTP/1.1 407 ") {
                    return Err("proxy rejected SHADE_TREE_PROXY_TOKEN".into());
                }
                return Err(format!(
                    "proxy health check returned an unexpected response: {}",
                    response.lines().next().unwrap_or("(empty)")
                ));
            }
            Err(error) => last_error = Some(error),
        }
    }
    if !found {
        Err(format!("proxy host {host} resolved to no addresses"))
    } else if start.elapsed() >= timeout {
        Err(format!(
            "proxy check timed out after {}ms",
            timeout.as_millis()
        ))
    } else {
        Err(format!(
            "connect to proxy {host}:{port}: {}",
            last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "connection failed".into())
        ))
    }
}

fn apply_child_environment(command: &mut Command, config: &RunConfig) {
    for key in child_environment_removals(env::vars_os().map(|(key, _)| key)) {
        command.env_remove(key);
    }
    for (key, value) in child_environment_values(config) {
        command.env(key, value);
    }
}

fn child_environment_removals(keys: impl IntoIterator<Item = OsString>) -> Vec<OsString> {
    keys.into_iter()
        .filter(|key| {
            // Windows environment names are case-insensitive but case-preserving.
            // Normalize on every platform so a mixed-case credential cannot survive
            // scrubbing and then alias one of the child markers installed below.
            let normalized = key.to_string_lossy().to_ascii_uppercase();
            normalized.starts_with("SHADE_TREE_") || normalized == "ALL_PROXY"
        })
        .collect()
}

fn child_environment_values(config: &RunConfig) -> Vec<(&'static str, String)> {
    let proxy = format!(
        "http://shade-tree:{}@{}",
        config.auth_token,
        config
            .proxy
            .normalized
            .strip_prefix("http://")
            .expect("normalized proxy URL")
    );
    let no_proxy = &config.no_proxy;
    vec![
        ("HTTPS_PROXY", proxy.clone()),
        ("https_proxy", proxy.clone()),
        ("HTTP_PROXY", proxy.clone()),
        ("http_proxy", proxy.clone()),
        ("WSS_PROXY", proxy.clone()),
        ("wss_proxy", proxy.clone()),
        ("NO_PROXY", no_proxy.clone()),
        ("no_proxy", no_proxy.clone()),
        ("NODE_USE_ENV_PROXY", "1".into()),
        ("SHADE_TREE_ACTIVE", "1".into()),
        ("SHADE_TREE_PROXY_URL", proxy),
        ("SHADE_TREE_NO_PROXY", no_proxy.clone()),
    ]
}

fn exit_code_for_status(status: ExitStatus) -> ExitCode {
    if let Some(code) = status.code() {
        return ExitCode::from(u8::try_from(code).unwrap_or(1));
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return ExitCode::from(u8::try_from(128 + signal).unwrap_or(1));
        }
    }
    ExitCode::from(1)
}

#[cfg(unix)]
mod unix_signals {
    use std::os::raw::c_int;
    use std::sync::atomic::{AtomicI32, Ordering};

    const SIGINT: c_int = 2;
    const SIGTERM: c_int = 15;
    static CHILD_PID: AtomicI32 = AtomicI32::new(0);

    unsafe extern "C" {
        fn kill(pid: c_int, signal: c_int) -> c_int;
        // Using an integer for the handler also represents SIG_DFL (null) without
        // manufacturing an invalid Rust function pointer.
        fn signal(signal: c_int, handler: usize) -> usize;
    }

    extern "C" fn forward(signal_number: c_int) {
        let pid = CHILD_PID.load(Ordering::Relaxed);
        if pid > 0 {
            // POSIX kill is async-signal-safe.
            unsafe {
                kill(pid, signal_number);
            }
        }
    }

    pub(super) struct ForwardingGuard {
        old_int: usize,
        old_term: usize,
    }

    impl ForwardingGuard {
        pub(super) fn install(pid: u32) -> Self {
            CHILD_PID.store(pid as c_int, Ordering::Relaxed);
            unsafe {
                Self {
                    old_int: signal(SIGINT, forward as *const () as usize),
                    old_term: signal(SIGTERM, forward as *const () as usize),
                }
            }
        }
    }

    impl Drop for ForwardingGuard {
        fn drop(&mut self) {
            CHILD_PID.store(0, Ordering::Relaxed);
            unsafe {
                signal(SIGINT, self.old_int);
                signal(SIGTERM, self.old_term);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn parser_requires_separator_and_command() {
        assert!(parse_run_args(&strings(&["agent"]))
            .unwrap_err()
            .0
            .contains("missing `--`"));
        assert!(parse_run_args(&strings(&["--"]))
            .unwrap_err()
            .0
            .contains("missing command"));
    }

    #[test]
    fn parser_preserves_child_argv() {
        let parsed = parse_run_args(&strings(&[
            "--proxy=http://127.0.0.1:9000",
            "--check-timeout-ms",
            "25",
            "--",
            "agent",
            "--flag",
            "value with spaces",
        ]))
        .unwrap();
        assert_eq!(parsed.proxy.as_deref(), Some("http://127.0.0.1:9000"));
        assert_eq!(parsed.check_timeout_ms.as_deref(), Some("25"));
        assert_eq!(parsed.command, "agent");
        assert_eq!(parsed.args, strings(&["--flag", "value with spaces"]));
    }

    #[test]
    fn parser_rejects_unknown_duplicate_and_bare_flags() {
        assert!(parse_run_args(&strings(&["--wat", "x", "--", "agent"])).is_err());
        assert!(parse_run_args(&strings(&["--proxy", "--", "agent"])).is_err());
        assert!(parse_run_args(&strings(&[
            "--proxy", "http://a", "--proxy", "http://b", "--", "agent"
        ]))
        .is_err());
    }

    #[test]
    fn proxy_url_accepts_http_host_port_and_ipv6() {
        assert_eq!(
            parse_proxy_url("http://localhost:8118/").unwrap(),
            ProxyUrl {
                normalized: "http://localhost:8118".into(),
                host: "localhost".into(),
                port: 8118,
            }
        );
        assert_eq!(parse_proxy_url("http://[::1]:99").unwrap().host, "::1");
        assert_eq!(parse_proxy_url("http://proxy.local").unwrap().port, 80);
    }

    #[test]
    fn proxy_url_rejects_non_http_credentials_paths_and_bad_ports() {
        for raw in [
            "https://localhost:8118",
            "http://user@localhost:8118",
            "http://localhost:8118/path",
            "http://localhost:0",
            "http://localhost:nope",
            "http://::1:8118",
        ] {
            assert!(parse_proxy_url(raw).is_err(), "accepted {raw}");
        }
    }

    #[test]
    fn no_proxy_has_loopback_defaults_deduplicates_and_refuses_wildcard() {
        assert_eq!(
            build_no_proxy("ollama.local,127.0.0.1, ollama.local").unwrap(),
            "127.0.0.1,localhost,::1,host.docker.internal,ollama.local"
        );
        assert!(build_no_proxy("localhost,*")
            .unwrap_err()
            .0
            .contains("bypass"));
    }

    #[test]
    fn child_environment_strips_operator_state_and_escape_hatches() {
        let removed = child_environment_removals(
            strings(&[
                "PATH",
                "SHADE_TREE_SECRET",
                "shade_tree_register_key",
                "ShAdE_TrEe_DiReCtOrY",
                "SHADE_TREE_DIRECTORY",
                "ALL_PROXY",
                "all_proxy",
                "AGENT_TOKEN",
            ])
            .into_iter()
            .map(OsString::from),
        )
        .into_iter()
        .map(|value| value.into_string().unwrap())
        .collect::<Vec<_>>();
        assert_eq!(
            removed,
            strings(&[
                "SHADE_TREE_SECRET",
                "shade_tree_register_key",
                "ShAdE_TrEe_DiReCtOrY",
                "SHADE_TREE_DIRECTORY",
                "ALL_PROXY",
                "all_proxy"
            ])
        );
    }

    #[test]
    fn child_environment_installs_every_scoped_proxy_marker() {
        let config = RunConfig {
            proxy: parse_proxy_url("http://127.0.0.1:8118").unwrap(),
            auth_token: TOKEN.into(),
            no_proxy: build_no_proxy("ollama.local").unwrap(),
            timeout: Duration::from_secs(1),
        };
        let values = child_environment_values(&config);
        assert!(values.iter().any(|(key, value)| {
            *key == "HTTPS_PROXY" && value.contains(&format!("shade-tree:{TOKEN}@"))
        }));
        for key in [
            "HTTPS_PROXY",
            "https_proxy",
            "HTTP_PROXY",
            "http_proxy",
            "WSS_PROXY",
            "wss_proxy",
            "NO_PROXY",
            "no_proxy",
            "NODE_USE_ENV_PROXY",
            "SHADE_TREE_ACTIVE",
            "SHADE_TREE_PROXY_URL",
            "SHADE_TREE_NO_PROXY",
        ] {
            assert!(
                values.iter().any(|(actual, _)| *actual == key),
                "missing {key}"
            );
        }
    }

    #[test]
    fn preflight_accepts_an_active_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let read = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..read]);
            assert!(request.contains("Proxy-Authorization: Basic "));
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .unwrap();
        });
        let proxy = parse_proxy_url(&format!("http://{address}")).unwrap();
        check_proxy(&proxy, TOKEN, Duration::from_secs(1)).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn preflight_refuses_a_closed_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let proxy = parse_proxy_url(&format!("http://{address}")).unwrap();
        assert!(check_proxy(&proxy, TOKEN, Duration::from_millis(250)).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn run_scopes_the_real_child_environment_argv_and_exit_status() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .unwrap();
        });
        let authenticated_proxy =
            proxy.replacen("http://", &format!("http://shade-tree:{TOKEN}@"), 1);
        let expected_no_proxy = "127.0.0.1,localhost,::1,host.docker.internal,ollama.local";
        let script = r#"
            test "$HTTPS_PROXY" = "$2" || exit 10
            test "$https_proxy" = "$2" || exit 11
            test "$HTTP_PROXY" = "$2" || exit 12
            test "$http_proxy" = "$2" || exit 13
            test "$WSS_PROXY" = "$2" || exit 14
            test "$wss_proxy" = "$2" || exit 15
            test "$NO_PROXY" = "$3" || exit 16
            test "$no_proxy" = "$3" || exit 17
            test "$NODE_USE_ENV_PROXY" = 1 || exit 18
            test "$SHADE_TREE_ACTIVE" = 1 || exit 19
            test "$1" = 'child arg' || exit 20
            test -z "$SHADE_TREE_PROXY_TOKEN" || exit 21
            exit 23
        "#;
        let previous_token = env::var_os("SHADE_TREE_PROXY_TOKEN");
        env::set_var("SHADE_TREE_PROXY_TOKEN", TOKEN);
        let result = run(&[
            "--proxy".into(),
            proxy.clone(),
            "--no-proxy".into(),
            "ollama.local".into(),
            "--".into(),
            "/bin/sh".into(),
            "-c".into(),
            script.into(),
            "probe".into(),
            "child arg".into(),
            authenticated_proxy,
            expected_no_proxy.into(),
        ]);
        match previous_token {
            Some(value) => env::set_var("SHADE_TREE_PROXY_TOKEN", value),
            None => env::remove_var("SHADE_TREE_PROXY_TOKEN"),
        }
        assert_eq!(result, ExitCode::from(23));
        server.join().unwrap();
    }
}
