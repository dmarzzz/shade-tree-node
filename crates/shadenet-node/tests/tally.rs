//! The fleet tally between two nodes: an envelope admitted and relayed by one node is refused
//! as `replayed-envelope` by its peer once the announcement has crossed, while a nullifier the
//! peer never heard of is admitted as usual.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use shadenet_rln::prover::{build_envelope, BuiltEnvelope, EnvelopeInput};
use shadenet_rln::tree::{fr_to_dec, parse_fr, rate_commitment};

const SECRET: &str = "111";
const LIMIT: u64 = 8;
const EPOCH_SECONDS: u64 = 120;

fn leaf() -> String {
    fr_to_dec(&rate_commitment(parse_fr(SECRET).unwrap(), LIMIT))
}

fn epoch_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / EPOCH_SECONDS
}

fn artifact_id() -> String {
    shadenet_rln::artifacts::verify_embedded()
        .expect("embedded artifacts match the lock")
        .artifact_id
}

fn prove(target: &str, nonce: &str, message_id: u64) -> BuiltEnvelope {
    build_envelope(&EnvelopeInput {
        identity_secret: SECRET.into(),
        member_leaf: leaf(),
        members: vec![leaf()],
        target: target.into(),
        nonce: nonce.into(),
        signal: None,
        epoch: epoch_now(),
        rln_identifier: "1".into(),
        user_message_limit: LIMIT,
        message_id,
        circuits_dir: None,
    })
    .expect("prove")
}

fn envelope(built: &BuiltEnvelope) -> Value {
    json!({
        "v": 4,
        "artifact": artifact_id(),
        "proof": {
            "snarkProof": { "proof": built.proof, "publicSignals": built.public_signals },
            "epoch": built.epoch,
            "rlnIdentifier": built.rln_identifier,
        },
        "nullifier": built.nullifier,
        "externalNullifier": built.external_nullifier,
        "share": { "x": built.share_x, "y": built.share_y },
        "target": built.target,
        "nonce": built.nonce,
    })
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Echo the first chunk back, then close.
fn sink() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut stream = stream;
                let mut buf = [0_u8; 1024];
                if let Ok(n) = stream.read(&mut buf) {
                    let _ = stream.write_all(b"ok:");
                    let _ = stream.write_all(&buf[..n]);
                }
            });
        }
    });
    port
}

struct Node {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Node {
    fn spawn(name: &str, target: &str, listen: u16, peer: u16, token: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("shadenet-node-tally-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let members = dir.join("members.json");
        std::fs::write(&members, json!({"members": [leaf()]}).to_string()).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_shadenet-node"))
            .env_remove("SHADENET_LOG")
            .env("SHADE_TREE_GATEWAY_PORT", "0")
            .env("SHADE_TREE_LOG_FORMAT", "text")
            .env("SHADE_TREE_MEMBERS_FILE", &members)
            .env("SHADE_TREE_EGRESS_ALLOW", target)
            .env("SHADE_TREE_ALLOW_PRIVATE_TARGETS", "1")
            .env("SHADE_TREE_EPOCH_SECONDS", EPOCH_SECONDS.to_string())
            .env(
                "SHADE_TREE_FLEET_TALLY_LISTEN",
                format!("127.0.0.1:{listen}"),
            )
            .env("SHADE_TREE_FLEET_TALLY_PEERS", format!("127.0.0.1:{peer}"))
            .env("SHADE_TREE_FLEET_TALLY_TOKEN", token)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn shadenet-node");
        let stderr = child.stderr.take().expect("stderr is piped");
        let mut lines = BufReader::new(stderr).lines();
        let port = loop {
            let line = lines
                .next()
                .expect("node exited before announcing its port")
                .expect("read stderr");
            if let Some(rest) = line.split("gateway up on 127.0.0.1:").nth(1) {
                break rest.trim().parse().expect("port");
            }
        };
        let tag = name.to_string();
        std::thread::spawn(move || {
            for line in lines.map_while(Result::ok) {
                eprintln!("[node:{tag}] {line}");
            }
        });
        Self { child, port, dir }
    }

    fn open(&self, envelope: &Value, early: &[u8]) -> (String, Vec<u8>) {
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        let mut bytes = serde_json::to_vec(envelope).unwrap();
        bytes.push(b'\n');
        bytes.extend_from_slice(early);
        stream.write_all(&bytes).unwrap();
        let mut reader = BufReader::new(stream);
        let mut ack = String::new();
        reader.read_line(&mut ack).unwrap();
        let mut rest = Vec::new();
        let _ = reader.read_to_end(&mut rest);
        (ack, rest)
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn a_nullifier_established_on_one_node_is_refused_by_its_peer() {
    let sink_port = sink();
    let target = format!("127.0.0.1:{sink_port}");
    let (listen_a, listen_b) = (free_port(), free_port());
    let token = "fleet-tally-shared-secret-of-at-least-32-chars";
    let a = Node::spawn("a", &target, listen_a, listen_b, token);
    let b = Node::spawn("b", &target, listen_b, listen_a, token);

    let first = prove(&target, "00112233445566778899aabbccddeeff", 0);
    let (ack, relayed) = a.open(&envelope(&first), b"ping");
    assert_eq!(ack, "{\"ok\":true}\n");
    assert_eq!(relayed, b"ok:ping");

    // the announcement crosses to the peer, which then treats the same envelope as a replay
    let started = Instant::now();
    loop {
        let (ack, _) = b.open(&envelope(&first), b"");
        if ack == "{\"ok\":false,\"err\":\"replayed-envelope\"}\n" {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the peer never learned the nullifier: {ack}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }

    // another slot is new to both and goes through on the peer
    let second = prove(&target, "0123456789abcdef0123456789abcdef", 1);
    let (ack, relayed) = b.open(&envelope(&second), b"pong");
    assert_eq!(ack, "{\"ok\":true}\n");
    assert_eq!(relayed, b"ok:pong");
}
