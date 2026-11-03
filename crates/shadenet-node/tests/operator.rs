//! The operator subsystems around a running node: the loopback metrics listener with
//! `/readyz` and the drain flag, the heartbeat announcing through a fake Tor SOCKS port to two
//! fake Elder Trees with signed capabilities, and `retire` through SIGUSR1.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use shadenet_proto::{ed25519_public_key, pubkey_to_onion, verify_announce, Announce, Caps};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Node {
    child: Child,
    port: u16,
    dir: PathBuf,
    log: Arc<Mutex<String>>,
}

impl Node {
    fn spawn(env: &[(&str, &str)]) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "shadenet-node-operator-{}-{}",
            std::process::id(),
            free_port()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let members = dir.join("members.json");
        std::fs::write(&members, json!({"members": ["1"]}).to_string()).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_shadenet-node"));
        command
            .env_remove("SHADENET_LOG")
            .env("SHADE_TREE_GATEWAY_PORT", "0")
            .env("SHADE_TREE_LOG_FORMAT", "text")
            .env("SHADE_TREE_MEMBERS_FILE", &members)
            .env("SHADE_TREE_ADMIT", "invited")
            .env("SHADE_TREE_EGRESS_ALLOW", "*:443")
            .env("SHADE_TREE_DRAIN_FILE", dir.join("draining"))
            .envs(env.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("spawn shadenet-node");
        let stderr = child.stderr.take().expect("stderr is piped");
        let mut lines = BufReader::new(stderr).lines();
        let log = Arc::new(Mutex::new(String::new()));
        let port = loop {
            let line = lines
                .next()
                .expect("node exited before announcing its port")
                .expect("read stderr");
            log.lock().unwrap().push_str(&format!("{line}\n"));
            if let Some(rest) = line.split("gateway up on 127.0.0.1:").nth(1) {
                break rest.trim().parse().expect("port");
            }
        };
        let sink = Arc::clone(&log);
        std::thread::spawn(move || {
            for line in lines.map_while(Result::ok) {
                eprintln!("[node:{port}] {line}");
                sink.lock().unwrap().push_str(&format!("{line}\n"));
            }
        });
        Self {
            child,
            port,
            dir,
            log,
        }
    }

    fn wait_for_log(&self, needle: &str, timeout: Duration) -> bool {
        let started = Instant::now();
        while started.elapsed() < timeout {
            if self.log.lock().unwrap().contains(needle) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }

    fn signal(&self, name: &str) {
        let status = Command::new("kill")
            .args([name, &self.child.id().to_string()])
            .status()
            .expect("kill");
        assert!(status.success());
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Systemd socket activation: the test binds the socket, hands it to the node as fd 3 with
/// `LISTEN_FDS=1` addressed to the node's pid (the shell's `$$` survives `exec`), and the node
/// serves that socket instead of binding its own port.
#[test]
fn the_node_serves_the_listening_socket_systemd_hands_over() {
    use std::os::unix::io::AsRawFd as _;
    use std::os::unix::process::CommandExt as _;

    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    let dir = std::env::temp_dir().join(format!(
        "shadenet-node-activation-{}-{port}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let members = dir.join("members.json");
    std::fs::write(&members, json!({"members": ["1"]}).to_string()).unwrap();
    let fd = socket.as_raw_fd();
    let mut command = Command::new("sh");
    command
        .arg("-c")
        .arg("LISTEN_PID=$$ exec \"$0\" run")
        .arg(env!("CARGO_BIN_EXE_shadenet-node"))
        .env_remove("SHADENET_LOG")
        .env("LISTEN_FDS", "1")
        .env("SHADE_TREE_GATEWAY_PORT", "0")
        .env("SHADE_TREE_LOG_FORMAT", "text")
        .env("SHADE_TREE_MEMBERS_FILE", &members)
        .env("SHADE_TREE_ADMIT", "invited")
        .env("SHADE_TREE_EGRESS_ALLOW", "*:443")
        .env("SHADE_TREE_DRAIN_FILE", dir.join("draining"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // SAFETY: the hook only duplicates one descriptor onto fd 3 (or clears its close-on-exec
    // flag when it already is fd 3), both async-signal-safe calls.
    unsafe {
        command.pre_exec(move || {
            let rc = if fd == 3 {
                libc::fcntl(3, libc::F_SETFD, 0)
            } else {
                libc::dup2(fd, 3)
            };
            if rc < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().expect("spawn shadenet-node through sh");
    drop(socket);
    let stderr = child.stderr.take().expect("stderr is piped");
    let mut log = String::new();
    let mut bound = None;
    for line in BufReader::new(stderr).lines().map_while(Result::ok) {
        log.push_str(&line);
        log.push('\n');
        if let Some(rest) = line.split("gateway up on 127.0.0.1:").nth(1) {
            bound = rest.trim().parse::<u16>().ok();
            break;
        }
    }
    let result = std::panic::catch_unwind(|| {
        assert_eq!(
            bound,
            Some(port),
            "the node reports the inherited socket's port:\n{log}"
        );
        assert!(log.contains("socket activation"), "{log}");
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream.write_all(b"{\"v\":4}\n").unwrap();
        let mut reply = String::new();
        BufReader::new(stream).read_line(&mut reply).unwrap();
        let reply: Value = serde_json::from_str(&reply).expect("a refusal line");
        assert!(reply["err"].is_string(), "{reply}");
    });
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&dir);
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}

/// `GET path` on the loopback metrics port with a chosen Host header.
fn http_get(port: u16, path: &str, host: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).unwrap();
    let status = raw
        .lines()
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = raw.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}

fn metrics(port: u16) -> String {
    let (status, body) = http_get(port, "/metrics", "127.0.0.1");
    assert_eq!(status, 200);
    body
}

#[test]
fn metrics_readiness_and_the_drain_flag() {
    let metrics_port = free_port();
    let node = Node::spawn(&[("SHADE_TREE_METRICS_PORT", &metrics_port.to_string())]);
    assert!(node.wait_for_log("operator metrics ready", Duration::from_secs(10)));
    let text = metrics(metrics_port);
    assert!(
        text.contains("# TYPE shade_tree_build_info gauge\nshade_tree_build_info{commit=\""),
        "{text}"
    );
    assert!(text.contains("role=\"node\""), "{text}");
    assert!(
        text.contains("shade_tree_gateway_trusted_roots{source=\"invited\"} 1\n"),
        "{text}"
    );
    assert!(
        text.contains("# TYPE shade_tree_process_uptime_seconds gauge\n"),
        "{text}"
    );
    assert_eq!(http_get(metrics_port, "/readyz", "127.0.0.1").0, 200);
    assert_eq!(http_get(metrics_port, "/livez", "localhost").0, 200);
    assert_eq!(
        http_get(metrics_port, "/metrics", "evil.example").0,
        421,
        "a non-loopback host is misdirected"
    );
    assert_eq!(http_get(metrics_port, "/nope", "127.0.0.1").0, 404);

    // a refused connection lands in the tunnel counter under its bounded reason
    let mut stream = TcpStream::connect(("127.0.0.1", node.port)).unwrap();
    stream.write_all(b"not json\n").unwrap();
    let mut reply = String::new();
    let _ = stream.read_to_string(&mut reply);
    assert!(
        reply.starts_with("{\"ok\":false,\"err\":\"bad-envelope:"),
        "{reply}"
    );
    let text = metrics(metrics_port);
    assert!(
        text.contains(
            "shade_tree_gateway_tunnels_total{reason=\"bad-envelope\",result=\"drop\"} 1\n"
        ),
        "{text}"
    );
    assert!(
        text.contains("shade_tree_gateway_connections 0\n"),
        "{text}"
    );

    // the drain flag turns readiness off and back on
    std::fs::write(node.dir.join("draining"), "now\n").unwrap();
    assert_eq!(http_get(metrics_port, "/readyz", "127.0.0.1").0, 503);
    assert_eq!(http_get(metrics_port, "/livez", "127.0.0.1").0, 200);
    std::fs::remove_file(node.dir.join("draining")).unwrap();
    assert_eq!(http_get(metrics_port, "/readyz", "127.0.0.1").0, 200);
}

/// What a fake Elder saw and answered.
struct Seen {
    announces: Vec<Value>,
}

/// A fake Tor SOCKS port fronting two fake Elder Trees: the first accepts every announce, the
/// second refuses `not-staked`. Every announce is verified exactly as a real Elder would.
fn fake_tor(accepting: &str, refusing: &str) -> (u16, Arc<Mutex<Seen>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Seen {
        announces: Vec::new(),
    }));
    let accepting = accepting.to_string();
    let refusing = refusing.to_string();
    let record = Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
            let mut greeting = [0_u8; 3];
            if stream.read_exact(&mut greeting).is_err() {
                continue;
            }
            stream.write_all(&[5, 0]).unwrap();
            let mut head = [0_u8; 5];
            stream.read_exact(&mut head).unwrap();
            assert_eq!(head[3], 3, "tor expects a domain name destination");
            let mut name = vec![0_u8; usize::from(head[4]) + 2];
            stream.read_exact(&mut name).unwrap();
            let destination = String::from_utf8_lossy(&name[..name.len() - 2]).to_string();
            stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
            let mut raw = Vec::new();
            let mut chunk = [0_u8; 4096];
            loop {
                let n = match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                raw.extend_from_slice(&chunk[..n]);
                let text = String::from_utf8_lossy(&raw);
                if let Some(head_end) = text.find("\r\n\r\n") {
                    let length: usize = text
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    if raw.len() >= head_end + 4 + length {
                        break;
                    }
                }
            }
            let text = String::from_utf8_lossy(&raw).to_string();
            assert!(text.starts_with("POST /announce HTTP/1.1\r\n"), "{text}");
            let body = text.split("\r\n\r\n").nth(1).unwrap_or("{}");
            let announce: Value = serde_json::from_str(body).expect("announce is JSON");
            let parsed = Announce {
                v: announce["v"].as_u64().unwrap_or(0),
                onion: announce["onion"].as_str().unwrap_or("").to_string(),
                weight: announce["weight"].as_u64().unwrap_or(0),
                ts: announce["ts"].as_u64().unwrap_or(0),
                nonce: announce["nonce"].as_str().unwrap_or("").to_string(),
                onion_sig: announce["onionSig"].as_str().map(str::to_string),
                operator: announce["operator"].as_str().map(str::to_string),
                operator_sig: announce["operatorSig"].as_str().map(str::to_string),
                caps: announce.get("caps").map(|caps| Caps {
                    ports: caps["ports"]
                        .as_array()
                        .map(|p| p.iter().filter_map(Value::as_i64).collect()),
                    region: caps["region"].as_str().map(str::to_string),
                    proto: caps.get("proto").map(|p| shadenet_proto::ProtoCaps {
                        min: p["min"].as_i64().unwrap_or(0),
                        max: p["max"].as_i64().unwrap_or(0),
                    }),
                    artifacts: caps["artifacts"].as_array().map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    }),
                    admits: caps["admits"].as_array().map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    }),
                    draining: caps["draining"].as_bool(),
                    ..Caps::default()
                }),
                caps_sig: announce["capsSig"].as_str().map(str::to_string),
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            verify_announce(&parsed, now, 120, None)
                .expect("the announce verifies like an Elder checks it");
            let mut seen = record.lock().unwrap();
            let mut tagged = announce.clone();
            tagged["_elder"] = Value::String(destination.clone());
            seen.announces.push(tagged);
            let reply = if destination == accepting {
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 36\r\nconnection: close\r\n\r\n{\"ok\":true,\"staked\":false,\"ttl\":900}".to_string()
            } else {
                assert_eq!(destination, refusing);
                "HTTP/1.1 403 Forbidden\r\ncontent-type: application/json\r\ncontent-length: 32\r\nconnection: close\r\n\r\n{\"ok\":false,\"err\":\"not-staked\"}".to_string()
            };
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    (port, seen)
}

#[test]
fn the_heartbeat_announces_to_every_elder_with_signed_caps_and_retires_on_signal() {
    let seed = [9_u8; 32];
    let onion = pubkey_to_onion(&ed25519_public_key(&seed));
    let dir = std::env::temp_dir().join(format!(
        "shadenet-heartbeat-identity-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let identity = dir.join("identity.local.json");
    std::fs::write(
        &identity,
        json!({"onion": onion, "seed": hex::encode(seed)}).to_string(),
    )
    .unwrap();
    let elder_a = pubkey_to_onion(&ed25519_public_key(&[0xa_u8; 32]));
    let elder_b = pubkey_to_onion(&ed25519_public_key(&[0xb_u8; 32]));
    let (socks_port, seen) = fake_tor(&elder_a, &elder_b);
    let metrics_port = free_port();
    let node = Node::spawn(&[
        ("SHADE_TREE_METRICS_PORT", &metrics_port.to_string()),
        ("SHADE_TREE_GW_IDENTITY", &identity.display().to_string()),
        (
            "SHADE_TREE_BOOTNODE_ONIONS",
            &format!("{elder_a},{elder_b}"),
        ),
        ("SHADE_TREE_TOR_HOST", "127.0.0.1"),
        ("SHADE_TREE_TOR_PORT", &socks_port.to_string()),
        ("SHADE_TREE_EGRESS_CHECK", "0"),
        ("SHADE_TREE_BOOTNODE_HEARTBEAT", "1"),
        ("SHADE_TREE_GATEWAY_REGION", "eu"),
        ("SHADE_TREE_GW_WEIGHT", "42"),
    ]);
    assert!(
        node.wait_for_log("heartbeat accepted", Duration::from_secs(30)),
        "{}",
        node.log.lock().unwrap()
    );
    assert!(node.wait_for_log("heartbeat rejected", Duration::from_secs(30)));
    let log = node.log.lock().unwrap().clone();
    assert!(log.contains("not-staked"), "{log}");
    assert!(log.contains("announced to 1 of 2 Elder Trees"), "{log}");
    let text = metrics(metrics_port);
    assert!(
        text.contains("shade_tree_heartbeat_elders_total 2\n"),
        "{text}"
    );
    assert!(
        text.contains("shade_tree_heartbeat_elders_accepted 1\n"),
        "{text}"
    );
    assert!(
        text.contains("shade_tree_heartbeat_attempts_total{outcome=\"accepted\"} "),
        "{text}"
    );
    assert!(
        text.contains("shade_tree_heartbeat_attempts_total{outcome=\"rejected\"} "),
        "{text}"
    );
    assert!(text.contains("shade_tree_heartbeat_draining 0\n"), "{text}");
    {
        let seen = seen.lock().unwrap();
        let first = &seen.announces[0];
        assert_eq!(first["v"], 1);
        assert_eq!(first["onion"], onion);
        assert_eq!(first["weight"], 42);
        assert_eq!(first["caps"]["ports"], json!([443]));
        assert_eq!(first["caps"]["region"], "eu");
        assert_eq!(first["caps"]["admits"], json!(["invited"]));
        assert_eq!(first["caps"]["proto"], json!({"min": 4, "max": 4}));
        assert!(first.get("operator").is_none(), "onion-only");
        assert!(first["capsSig"].is_string());
        assert!(seen.announces.iter().any(|a| a["_elder"] == elder_a));
        assert!(seen.announces.iter().any(|a| a["_elder"] == elder_b));
    }

    // the drain flag is announced at once in the signed caps
    std::fs::write(node.dir.join("draining"), "now\n").unwrap();
    assert!(node.wait_for_log(
        "drain flag set; announcing draining",
        Duration::from_secs(10)
    ));
    let started = Instant::now();
    loop {
        let draining = seen
            .lock()
            .unwrap()
            .announces
            .iter()
            .any(|a| a["caps"]["draining"] == true);
        if draining {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "no draining announce"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(metrics(metrics_port).contains("shade_tree_heartbeat_draining 1\n"));

    // SIGUSR1 is what `shadenet-node retire` sends: the heartbeat stops, the node keeps serving
    node.signal("-USR1");
    assert!(node.wait_for_log("heartbeat stopped", Duration::from_secs(10)));
    let count = seen.lock().unwrap().announces.len();
    std::thread::sleep(Duration::from_millis(2500));
    assert_eq!(
        seen.lock().unwrap().announces.len(),
        count,
        "no announce after retiring"
    );
    assert_eq!(http_get(metrics_port, "/livez", "127.0.0.1").0, 200);
    let _ = std::fs::remove_dir_all(&dir);
}
