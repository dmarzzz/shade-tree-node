//! Black-box checks of the binary over real HTTP: the routes and their replies as the
//! JavaScript Elder's selftests pin them, the transport features, the slow-client limits, the
//! process contract (ready line, signals, exit codes) and the operator commands.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;
use shadenet_proto::{
    canonical_announce_bytes, ed25519_public_key, ed25519_sign, pubkey_to_onion, Announce,
    ANNOUNCE_VERSION,
};

struct Elder {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Elder {
    fn spawn(env: &[(&str, &str)]) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "shadenet-elder-http-{}-{}",
            std::process::id(),
            shadenet_service::clock::now_ms()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let mut command = Command::new(env!("CARGO_BIN_EXE_shadenet-elder"));
        command
            .env_remove("SHADENET_LOG")
            .env("SHADE_TREE_BOOTNODE_PORT", "0")
            .env("SHADE_TREE_LOG_FORMAT", "text")
            .env("SHADE_TREE_LOG_LEVEL", "debug")
            .env("SHADENET_STATE", &dir)
            .env("SHADE_TREE_BOOTNODE_MIN_REANNOUNCE", "0")
            .envs(env.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("spawn shadenet-elder");
        let stderr = child.stderr.take().expect("stderr is piped");
        let mut lines = std::io::BufRead::lines(std::io::BufReader::new(stderr));
        let port = loop {
            let line = lines
                .next()
                .expect("elder exited before announcing its port")
                .expect("read stderr");
            if let Some(rest) = line.split("bootnode up on 127.0.0.1:").nth(1) {
                break rest
                    .split_whitespace()
                    .next()
                    .and_then(|p| p.parse().ok())
                    .expect("port");
            }
        };
        std::thread::spawn(move || for _ in lines {});
        Self { child, port, dir }
    }

    fn connect(&self) -> TcpStream {
        let stream = TcpStream::connect(("127.0.0.1", self.port)).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("read timeout");
        stream
    }

    /// One request on its own connection; the reply split into status, headers and body.
    fn request(&self, method: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Reply {
        let mut stream = self.connect();
        let mut head = format!("{method} {path} HTTP/1.1\r\nHost: elder\r\nConnection: close\r\n");
        for (name, value) in headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        if !body.is_empty() || method == "POST" {
            head.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            ));
        }
        head.push_str("\r\n");
        stream.write_all(head.as_bytes()).expect("write head");
        stream.write_all(body).expect("write body");
        let mut raw = Vec::new();
        let _ = stream.read_to_end(&mut raw);
        Reply::parse(&raw)
    }

    fn get(&self, path: &str) -> Reply {
        self.request("GET", path, &[], &[])
    }

    fn post(&self, path: &str, body: &str) -> Reply {
        self.request("POST", path, &[], body.as_bytes())
    }

    fn terminate(mut self) -> i32 {
        let status = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .expect("kill");
        assert!(status.success());
        let exit = self.child.wait().expect("wait");
        self.child = Command::new("true").spawn().expect("placeholder");
        exit.code().expect("exit code")
    }
}

impl Drop for Elder {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Reply {
    fn parse(raw: &[u8]) -> Self {
        let separator = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("a complete header block");
        let head = String::from_utf8_lossy(&raw[..separator]).to_string();
        let mut lines = head.lines();
        let status = lines
            .next()
            .and_then(|l| l.split(' ').nth(1))
            .and_then(|s| s.parse().ok())
            .expect("status");
        let headers = lines
            .filter_map(|l| l.split_once(':'))
            .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
            .collect();
        Self {
            status,
            headers,
            body: raw[separator + 4..].to_vec(),
        }
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&self.body)))
    }
}

/// A node identity that signs announces the way the Rust node does.
struct Node {
    seed: [u8; 32],
    onion: String,
}

impl Node {
    fn new(tag: u8) -> Self {
        let seed = [tag; 32];
        Self {
            onion: pubkey_to_onion(&ed25519_public_key(&seed)),
            seed,
        }
    }

    fn announce(&self, weight: u64, nonce: &str) -> String {
        let ts = shadenet_service::clock::now_secs();
        let announce = Announce {
            v: ANNOUNCE_VERSION,
            onion: self.onion.clone(),
            weight,
            ts,
            nonce: nonce.to_string(),
            onion_sig: None,
            operator: None,
            operator_sig: None,
            caps: None,
            caps_sig: None,
        };
        let onion_sig = hex::encode(ed25519_sign(
            &canonical_announce_bytes(&announce),
            &self.seed,
        ));
        format!(
            "{{\"v\":1,\"onion\":\"{}\",\"weight\":{weight},\"ts\":{ts},\"nonce\":\"{nonce}\",\"onionSig\":\"{onion_sig}\"}}",
            self.onion
        )
    }
}

fn gunzip(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data)
        .read_to_end(&mut out)
        .expect("gzip body");
    out
}

#[test]
fn the_discovery_routes_answer_like_the_javascript_elder() {
    let elder = Elder::spawn(&[]);
    let health = elder.get("/health");
    assert_eq!(health.status, 200);
    assert_eq!(health.header("x-shade-tree-role"), Some("elder-tree"));
    assert_eq!(health.header("x-shade-tree-view"), None);
    let health = health.json();
    assert_eq!(health["ok"], true);
    assert_eq!(health["count"], 0);
    assert_eq!(health["admission"], "open");
    assert!(health["commit"].is_string());
    assert!(health.get("pay").is_none());
    let signer = health["signer"].as_str().expect("signer").to_string();
    assert_eq!(signer.len(), 64);

    let (g1, g2) = (Node::new(1), Node::new(2));
    let accepted = elder.post("/announce", &g1.announce(100, "a1"));
    assert_eq!(accepted.status, 200);
    assert_eq!(
        accepted.json(),
        serde_json::json!({"ok": true, "onion": g1.onion, "staked": false, "ttl": 900})
    );
    let forged = g2.announce(100, "a2");
    let at = forged.rfind("\"}").unwrap();
    let flipped = if forged.as_bytes()[at - 1] == b'0' {
        "1"
    } else {
        "0"
    };
    let forged = format!("{}{flipped}{}", &forged[..at - 1], &forged[at..]);
    let refused = elder.post("/announce", &forged);
    assert_eq!(refused.status, 400);
    assert_eq!(
        refused.json(),
        serde_json::json!({"ok": false, "err": "bad-onion-sig"})
    );
    let garbage = elder.post("/announce", "{not json");
    assert_eq!(garbage.status, 400);
    assert!(garbage.json()["err"]
        .as_str()
        .unwrap()
        .starts_with("bad-json:"));
    let big = elder.post("/announce", &"x".repeat(200 * 1024));
    assert_eq!(big.status, 400);
    assert_eq!(big.json()["err"], "bad-json:body too large");

    let directory = elder.get("/directory");
    assert_eq!(directory.status, 200);
    assert_eq!(directory.header("x-shade-tree-view"), Some("canopy"));
    let etag = directory.header("etag").expect("etag").to_string();
    assert!(etag.len() == 66 && etag.starts_with('"'));
    let text = String::from_utf8(directory.body.clone()).unwrap();
    let verified = shadenet::dircache::parse_and_verify_document(&text, &signer).expect("verifies");
    assert_eq!(verified.dir.gateways.len(), 1);
    assert_eq!(verified.dir.gateways[0].onion, g1.onion);
    assert!(shadenet::dircache::parse_and_verify_document(&text, &"00".repeat(32)).is_err());

    // the etag is stable while nothing changes; a second boundary between the two requests
    // moves `issued`, so the conditional request is retried once
    let mut conditional = elder.request("GET", "/directory", &[("If-None-Match", &etag)], &[]);
    if conditional.status != 304 {
        let fresh = elder.get("/directory").header("etag").unwrap().to_string();
        conditional = elder.request("GET", "/directory", &[("If-None-Match", &fresh)], &[]);
    }
    assert_eq!(conditional.status, 304);
    assert!(conditional.body.is_empty());
    assert_eq!(conditional.header("x-shade-tree-view"), Some("canopy"));

    let zipped = elder.request("GET", "/directory", &[("Accept-Encoding", "gzip")], &[]);
    assert_eq!(zipped.header("content-encoding"), Some("gzip"));
    let unzipped = String::from_utf8(gunzip(&zipped.body)).unwrap();
    assert!(shadenet::dircache::parse_and_verify_document(&unzipped, &signer).is_ok());
    let plain = elder.request("GET", "/directory", &[("Accept-Encoding", "identity")], &[]);
    assert_eq!(plain.header("content-encoding"), None);

    let stored = elder.get(&format!("/gateway/{}", g1.onion));
    assert_eq!(stored.status, 200);
    assert_eq!(stored.json()["onion"], g1.onion);
    assert_eq!(
        elder.get(&format!("/gateway/{}", &g1.onion[..56])).status,
        200,
        "the suffix is optional"
    );
    let missing = elder.get(&format!("/gateway/{}", g2.onion));
    assert_eq!(missing.status, 404);
    assert_eq!(missing.json()["err"], "not-found");
    let unrouted = elder.get("/nope");
    assert_eq!(unrouted.status, 404);
    assert_eq!(unrouted.json()["err"], "no-route");
    assert_eq!(elder.get("/health").json()["count"], 1);
}

#[test]
fn the_delta_ships_what_changed_since_the_clients_etag() {
    let elder = Elder::spawn(&[]);
    let (g1, g2) = (Node::new(3), Node::new(4));
    assert_eq!(elder.post("/announce", &g1.announce(100, "d1")).status, 200);
    let first = elder.get("/directory");
    let e1 = first.header("etag").unwrap().to_string();
    let base: Value = first.json();
    assert_eq!(elder.post("/announce", &g2.announce(100, "d2")).status, 200);
    let delta = elder.get(&format!(
        "/directory/delta?since={}",
        e1.replace('"', "%22")
    ));
    assert_eq!(delta.status, 200);
    assert_eq!(delta.header("x-shade-tree-view"), Some("canopy"));
    let delta = delta.json();
    assert_eq!(delta.get("full"), None);
    let added = delta["added"].as_array().unwrap();
    assert!(added.iter().any(|g| g["onion"] == g2.onion), "{delta}");
    assert_eq!(delta["removed"], serde_json::json!([]));
    assert_eq!(delta["directory"]["order"].as_array().unwrap().len(), 2);
    let signer = delta["directory"]["signer"].as_str().unwrap();
    // an honest client rebuilds the directory from its base plus the delta
    let mut by_onion: std::collections::HashMap<String, Value> = base["gateways"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| (g["onion"].as_str().unwrap().to_string(), g.clone()))
        .collect();
    for g in added {
        by_onion.insert(g["onion"].as_str().unwrap().to_string(), g.clone());
    }
    let rebuilt = serde_json::json!({
        "version": delta["directory"]["version"],
        "issued": delta["directory"]["issued"],
        "gateways": delta["directory"]["order"].as_array().unwrap().iter().map(|o| by_onion[o.as_str().unwrap()].clone()).collect::<Vec<_>>(),
        "signer": signer,
        "signature": delta["directory"]["signature"],
    });
    assert!(shadenet::dircache::parse_and_verify_document(&rebuilt.to_string(), signer).is_ok());
    let unknown = elder.get("/directory/delta?since=%22deadbeef%22").json();
    assert_eq!(unknown["full"], true);
    assert!(unknown["base"].is_string());
    assert_eq!(elder.get("/directory/delta").json()["full"], true);
}

#[test]
fn a_throttled_announce_is_429_with_retry_after() {
    let elder = Elder::spawn(&[
        ("SHADE_TREE_BOOTNODE_ANNOUNCE_RATE", "1"),
        ("SHADE_TREE_BOOTNODE_ANNOUNCE_BURST", "1"),
    ]);
    let (a, b) = (Node::new(5), Node::new(6));
    assert_eq!(elder.post("/announce", &a.announce(100, "r1")).status, 200);
    let throttled = elder.post("/announce", &b.announce(100, "r2"));
    assert_eq!(throttled.status, 429);
    assert_eq!(throttled.json()["err"], "global-rate-limited");
    assert!(throttled
        .header("retry-after")
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|s| s >= 1));
}

#[test]
fn slow_clients_are_cut_and_honest_ones_are_not() {
    let elder = Elder::spawn(&[
        ("SHADE_TREE_BOOTNODE_HEADERS_TIMEOUT_MS", "400"),
        ("SHADE_TREE_BOOTNODE_REQUEST_TIMEOUT_MS", "800"),
        ("SHADE_TREE_BOOTNODE_KEEPALIVE_TIMEOUT_MS", "300"),
        ("SHADE_TREE_BOOTNODE_MAX_HEADER_BYTES", "2048"),
    ]);
    let closed_within = |stream: &mut TcpStream, limit: Duration| -> (Vec<u8>, Duration) {
        let started = Instant::now();
        stream.set_read_timeout(Some(limit)).unwrap();
        let mut received = Vec::new();
        let _ = stream.read_to_end(&mut received);
        (received, started.elapsed())
    };

    // partial headers, then silence: the connection is cut near the header timeout
    let mut slow = elder.connect();
    slow.write_all(b"GET /health HTTP/1.1\r\nHost: b\r\nX-Slow: ")
        .unwrap();
    let (_, elapsed) = closed_within(&mut slow, Duration::from_secs(5));
    assert!(
        elapsed < Duration::from_millis(2400),
        "cut at {elapsed:?}, not left open"
    );

    // headers complete, the body dribbles then stalls: 408 and close near the request timeout
    let mut dribble = elder.connect();
    dribble
        .write_all(b"POST /announce HTTP/1.1\r\nHost: b\r\nContent-Type: application/json\r\nContent-Length: 500\r\n\r\n{\"onion\":\"")
        .unwrap();
    let (received, elapsed) = closed_within(&mut dribble, Duration::from_secs(6));
    assert!(elapsed < Duration::from_millis(4800), "cut at {elapsed:?}");
    assert!(
        received.starts_with(b"HTTP/1.1 408"),
        "{}",
        String::from_utf8_lossy(&received)
    );

    // oversized headers: 431, never buffered unbounded
    let mut big = elder.connect();
    big.write_all(
        format!(
            "GET /health HTTP/1.1\r\nHost: b\r\nX-Big: {}\r\n\r\n",
            "a".repeat(4096)
        )
        .as_bytes(),
    )
    .unwrap();
    let (received, _) = closed_within(&mut big, Duration::from_secs(5));
    assert!(
        received.starts_with(b"HTTP/1.1 431"),
        "{}",
        String::from_utf8_lossy(&received)
    );

    // an idle keep-alive connection is closed after the keep-alive timeout
    let mut idle = elder.connect();
    idle.write_all(b"GET /health HTTP/1.1\r\nHost: b\r\nConnection: keep-alive\r\n\r\n")
        .unwrap();
    let started = Instant::now();
    let (received, elapsed) = closed_within(&mut idle, Duration::from_secs(5));
    assert!(String::from_utf8_lossy(&received).contains("\"ok\":true"));
    assert!(
        elapsed >= Duration::from_millis(150) && elapsed < Duration::from_millis(2400),
        "closed after {:?}",
        started.elapsed()
    );

    let honest = elder.get("/health");
    assert_eq!(honest.status, 200);
    assert_eq!(honest.json()["ok"], true);
}

#[test]
fn sigterm_drains_and_exits_zero() {
    let elder = Elder::spawn(&[]);
    assert_eq!(elder.terminate(), 0);
}

#[test]
fn a_request_still_open_past_the_grace_exits_one() {
    let elder = Elder::spawn(&[
        ("SHADE_TREE_SHUTDOWN_TIMEOUT_MS", "200"),
        ("SHADE_TREE_BOOTNODE_REQUEST_TIMEOUT_MS", "0"),
    ]);
    let mut held = elder.connect();
    held.write_all(b"POST /announce HTTP/1.1\r\nHost: b\r\nContent-Length: 500\r\n\r\n{\"v\":")
        .unwrap();
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(elder.terminate(), 1);
}

#[test]
fn the_operator_commands_and_the_exit_codes() {
    let dir = std::env::temp_dir().join(format!("shadenet-elder-ops-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let run = |args: &[&str], env: &[(&str, &str)]| {
        Command::new(env!("CARGO_BIN_EXE_shadenet-elder"))
            .args(args)
            .env("SHADENET_STATE", &dir)
            .env("SHADE_TREE_BOOTNODE_PORT", "0")
            .envs(env.iter().copied())
            .output()
            .expect("run")
    };
    let check = run(&["check"], &[]);
    let text = String::from_utf8_lossy(&check.stdout).to_string();
    assert_eq!(check.status.code(), Some(0), "{text}");
    assert!(
        text.lines()
            .any(|l| l.starts_with("admission") && l.ends_with("open")),
        "{text}"
    );
    assert!(
        text.contains("will be minted") && text.ends_with("ready\n"),
        "{text}"
    );

    let bad = run(
        &["check"],
        &[
            ("SHADE_TREE_BOOTNODE_ADMISSION", "weird"),
            ("SHADE_TREE_BOOTNODE_TTL", "soon"),
        ],
    );
    assert_eq!(bad.status.code(), Some(2));
    let err = String::from_utf8_lossy(&bad.stderr).to_string();
    assert!(
        err.contains("config: SHADE_TREE_BOOTNODE_ADMISSION")
            && err.contains("config: SHADE_TREE_BOOTNODE_TTL"),
        "{err}"
    );
    let conflict = run(
        &["check"],
        &[
            ("SHADENET_BOOTNODE_TTL", "1"),
            ("SHADE_TREE_BOOTNODE_TTL", "2"),
        ],
    );
    assert_eq!(conflict.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&conflict.stderr).contains("both set to different values"));

    let hs = dir.join("hs-elder");
    let identity = run(&["identity", hs.to_str().unwrap(), "--label", "elder"], &[]);
    assert_eq!(identity.status.code(), Some(0));
    let text = String::from_utf8_lossy(&identity.stdout).to_string();
    assert!(
        text.contains("minted onion identity (elder)") && text.contains(".onion"),
        "{text}"
    );
    assert!(hs.join("hs_ed25519_secret_key").exists() && hs.join("hostname").exists());
    let again = run(&["identity", hs.to_str().unwrap()], &[]);
    assert_eq!(again.status.code(), Some(2), "refuses to overwrite");

    let help = run(&["help"], &[]);
    assert!(String::from_utf8_lossy(&help.stdout).contains("shadenet-elder run"));
    let unknown = run(&["frobnicate"], &[]);
    assert_eq!(unknown.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("shadenet-elder run"));
    let version = run(&["--version"], &[]);
    assert!(String::from_utf8_lossy(&version.stdout).contains("(commit "));
    let _ = std::fs::remove_dir_all(&dir);
}

/// `buildRelayReport` for a node: the signing payload the node sends, signed by its seed.
fn relay_report(
    node: &Node,
    boot_id: &str,
    sequence: u64,
    interval: (&str, &str),
    counters: (u64, u64),
    reset: bool,
) -> String {
    let (start, end) = interval;
    let (a2d, d2a) = counters;
    let payload = format!(
        "{{\"schema\":\"shade-tree-relay-report-v1\",\"onion\":\"{}\",\"bootId\":\"{boot_id}\",\"sequence\":{sequence},\"intervalStart\":\"{start}\",\"intervalEnd\":\"{end}\",\"counters\":{{\"agentToDestinationBytes\":\"{a2d}\",\"destinationToAgentBytes\":\"{d2a}\"}},\"reset\":{{\"occurred\":{reset},\"reason\":{}}}}}",
        node.onion,
        if reset { "\"process-start\"" } else { "null" }
    );
    let signature = hex::encode(ed25519_sign(payload.as_bytes(), &node.seed));
    format!(
        "{},\"signature\":\"{signature}\"}}",
        &payload[..payload.len() - 1]
    )
}

#[test]
fn relay_reports_are_private_and_the_aggregate_is_signed() {
    let elder = Elder::spawn(&[]);
    let node = Node::new(7);
    let signer = elder.get("/health").json()["signer"]
        .as_str()
        .unwrap()
        .to_string();
    let now_ms = shadenet_service::clock::now_ms();
    let start = shadenet_service::clock::iso(now_ms - 3_600_000);
    let end = shadenet_service::clock::iso(now_ms - 60_000);
    let report = relay_report(
        &node,
        &"ab".repeat(16),
        1,
        (&start, &end),
        (1000, 2000),
        true,
    );
    let unknown = elder.post("/telemetry/relay", &report);
    assert_eq!(unknown.status, 400);
    assert_eq!(unknown.json()["err"], "not-announced");
    assert_eq!(
        elder.post("/announce", &node.announce(100, "t1")).status,
        200
    );
    let accepted = elder.post("/telemetry/relay", &report);
    assert_eq!(
        accepted.status,
        200,
        "{}",
        String::from_utf8_lossy(&accepted.body)
    );
    assert_eq!(accepted.json(), serde_json::json!({"ok": true}));
    let replayed = elder.post("/telemetry/relay", &report);
    assert_eq!(replayed.status, 400);
    assert_eq!(replayed.json()["err"], "sequence-replay");
    let garbage = elder.post("/telemetry/relay", "{\"schema\":1}");
    assert_eq!(garbage.status, 400);
    assert_eq!(garbage.json()["err"], "bad-report");

    let aggregate = elder.get("/telemetry/aggregate");
    assert_eq!(aggregate.status, 200);
    assert_eq!(
        aggregate.header("cache-control"),
        Some("public, max-age=60")
    );
    assert_eq!(aggregate.header("x-shade-tree-role"), Some("elder-tree"));
    let etag = aggregate.header("etag").expect("etag").to_string();
    let doc = aggregate.json();
    assert_eq!(doc["schema"], "shade-tree-relay-aggregate-v1");
    assert_eq!(doc["signer"], signer);
    assert_eq!(doc["windows"]["twentyFourHour"]["status"], "suppressed");
    assert!(doc["windows"]["twentyFourHour"]
        .get("roundedBytes")
        .is_none());
    let text = String::from_utf8(aggregate.body.clone()).unwrap();
    let at = text.rfind(",\"signature\":\"").unwrap();
    let payload = format!("{}}}", &text[..at]);
    let sig: [u8; 64] = hex::decode(doc["signature"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let pubkey: [u8; 32] = hex::decode(&signer).unwrap().try_into().unwrap();
    assert!(
        shadenet_proto::ed25519_verify(payload.as_bytes(), &sig, &pubkey),
        "the aggregate is signed by the canopy signer"
    );
    let conditional = elder.request(
        "GET",
        "/telemetry/aggregate",
        &[("If-None-Match", &etag)],
        &[],
    );
    assert_eq!(conditional.status, 304);
}

#[test]
fn the_incident_feed_is_signed_and_the_webhook_needs_its_token() {
    let elder = Elder::spawn(&[("SHADE_TREE_BOOTNODE_INCIDENTS_TOKEN", "s3cret")]);
    let signer = elder.get("/health").json()["signer"]
        .as_str()
        .unwrap()
        .to_string();
    let now = shadenet_service::clock::now_secs();
    let feed = elder.get("/incidents");
    assert_eq!(feed.status, 200);
    assert_eq!(feed.header("x-shade-tree-view"), Some("canopy"));
    let text = String::from_utf8(feed.body.clone()).unwrap();
    let verified = shadenet::incidents::parse_and_verify(&text, &signer, now).expect("verifies");
    assert!(verified.incidents.is_empty());
    let firing = serde_json::json!({ "alerts": [
        { "status": "firing", "labels": { "alertname": "BootnodeDown", "instance": "shade-elder-v4-02", "job": "shade-tree-bootnode", "severity": "critical" },
          "annotations": { "summary": "Bootnode shade-elder-v4-02 is down" }, "startsAt": "2026-10-01T06:50:00Z" },
        { "status": "firing", "labels": { "alertname": "GatewayRootDegraded", "instance": "node-06", "job": "shade-tree-gateway" }, "startsAt": "2026-10-01T06:52:00Z" }
    ]}).to_string();
    assert_eq!(elder.post("/incidents/alertmanager", &firing).status, 401);
    assert_eq!(
        elder
            .request(
                "POST",
                "/incidents/alertmanager",
                &[("Authorization", "Bearer wrong")],
                firing.as_bytes()
            )
            .status,
        401
    );
    let posted = elder.request(
        "POST",
        "/incidents/alertmanager",
        &[("Authorization", "Bearer s3cret")],
        firing.as_bytes(),
    );
    assert_eq!(posted.status, 200);
    assert_eq!(
        posted.json(),
        serde_json::json!({"ok": true, "firing": 2, "resolved": 0, "open": 2})
    );
    let after = String::from_utf8(elder.get("/incidents").body).unwrap();
    let verified = shadenet::incidents::parse_and_verify(&after, &signer, now).expect("verifies");
    assert_eq!(verified.incidents.len(), 2);
    assert!(verified
        .incidents
        .iter()
        .any(|i| i.component == "elder" && i.severity == "critical"));
    let off = Elder::spawn(&[]);
    let disabled = off.request(
        "POST",
        "/incidents/alertmanager",
        &[("Authorization", "Bearer s3cret")],
        b"{}",
    );
    assert_eq!(disabled.status, 404);
    assert_eq!(disabled.json()["err"], "incidents-webhook-disabled");
}
