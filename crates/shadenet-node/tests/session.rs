//! Session tickets end to end with real proofs (ADR 0011): one initialization proof opens a
//! book bound to this node's onion, each ticket opens a tunnel without a proof, and every
//! refusal carries the bounded reason the JavaScript node gives.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use shadenet_proto::session::{
    build_ticket_book, encode_ticket_secret, session_signal, TicketBook,
};
use shadenet_proto::{ed25519_public_key, pubkey_to_onion};
use shadenet_rln::prover::{build_envelope, BuiltEnvelope, EnvelopeInput};
use shadenet_rln::tree::{fr_to_dec, parse_fr, rate_commitment};

const SECRET: &str = "111";
const LIMIT: u64 = 8;
const EPOCH_SECONDS: u64 = 120;
const SEED: [u8; 32] = [9_u8; 32];

fn leaf() -> String {
    fr_to_dec(&rate_commitment(parse_fr(SECRET).unwrap(), LIMIT))
}

fn onion() -> String {
    pubkey_to_onion(&ed25519_public_key(&SEED))
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

struct Session {
    secrets: Vec<[u8; 32]>,
    book: TicketBook,
    nonce: String,
    class: &'static str,
    proof: BuiltEnvelope,
}

fn open_session(class: &'static str, slot: u64, tag: u8, epoch: u64) -> Session {
    let secrets: Vec<[u8; 32]> = (1..=6_u8).map(|i| [i.wrapping_mul(tag); 32]).collect();
    let book = build_ticket_book(&secrets).unwrap();
    let nonce = format!("{:032x}", u128::from(tag) * 7919);
    let signal = session_signal(&onion(), class, &nonce, &book.ticket_book_digest).unwrap();
    let proof = build_envelope(&EnvelopeInput {
        identity_secret: SECRET.into(),
        member_leaf: leaf(),
        members: vec![leaf()],
        target: "unused:443".into(),
        nonce: nonce.clone(),
        signal: Some(signal),
        epoch,
        rln_identifier: "1".into(),
        user_message_limit: LIMIT,
        message_id: slot,
        circuits_dir: None,
    })
    .expect("prove");
    Session {
        secrets,
        book,
        nonce,
        class,
        proof,
    }
}

fn init_envelope(session: &Session) -> Value {
    let built = &session.proof;
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
        "session": {
            "v": 1,
            "class": session.class,
            "gateway": onion(),
            "nonce": session.nonce,
            "ticketCommitments": session.book.commitments,
            "ticketBookDigest": session.book.ticket_book_digest,
        },
    })
}

fn ticket_envelope(session: &Session, index: usize, target: &str, request_nonce: &str) -> Value {
    json!({
        "v": 4,
        "ticket": {
            "v": 1,
            "book": session.book.ticket_book_digest,
            "i": index,
            "t": encode_ticket_secret(&session.secrets[index]),
            "n": request_nonce,
        },
        "target": target,
    })
}

struct Sink {
    port: u16,
}

impl Sink {
    fn echo() -> Self {
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
        Self { port }
    }

    fn hold() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            for stream in listener.incoming().flatten() {
                held.push(stream);
            }
        });
        Self { port }
    }

    fn target(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }
}

struct Node {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Node {
    fn spawn(sink: &Sink, env: &[(&str, &str)]) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "shadenet-node-session-{}-{}",
            std::process::id(),
            sink.port
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let members = dir.join("members.json");
        std::fs::write(&members, json!({"members": [leaf()]}).to_string()).unwrap();
        let identity = dir.join("identity.local.json");
        std::fs::write(
            &identity,
            json!({
                "label": "test",
                "onion": onion(),
                "pub": hex::encode(ed25519_public_key(&SEED)),
                "seed": hex::encode(SEED),
            })
            .to_string(),
        )
        .unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_shadenet-node"));
        command
            .env_remove("SHADENET_LOG")
            .env("SHADE_TREE_GATEWAY_PORT", "0")
            .env("SHADE_TREE_LOG_FORMAT", "text")
            .env("SHADE_TREE_LOG_LEVEL", "debug")
            .env("SHADE_TREE_MEMBERS_FILE", &members)
            .env("SHADE_TREE_EGRESS_ALLOW", sink.target())
            .env("SHADE_TREE_ALLOW_PRIVATE_TARGETS", "1")
            .env("SHADE_TREE_EPOCH_SECONDS", EPOCH_SECONDS.to_string())
            .env("SHADE_TREE_SESSION_TICKETS", "1")
            .env("SHADE_TREE_GW_IDENTITY", &identity)
            .envs(env.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("spawn shadenet-node");
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
        std::thread::spawn(move || {
            for line in lines.map_while(Result::ok) {
                eprintln!("[node:{port}] {line}");
            }
        });
        Self { child, port, dir }
    }

    fn open(&self, envelope: &Value, early: &[u8]) -> (String, BufReader<TcpStream>) {
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        let mut bytes = serde_json::to_vec(envelope).unwrap();
        bytes.push(b'\n');
        bytes.extend_from_slice(early);
        stream.write_all(&bytes).expect("write");
        let mut reader = BufReader::new(stream);
        let mut ack = String::new();
        reader.read_line(&mut ack).expect("read ack");
        (ack, reader)
    }

    fn ack(&self, envelope: &Value) -> String {
        self.open(envelope, b"").0
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn read_all(mut stream: BufReader<TcpStream>) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = stream.read_to_end(&mut out);
    out
}

static SINK: OnceLock<Sink> = OnceLock::new();

fn sink() -> &'static Sink {
    SINK.get_or_init(Sink::echo)
}

fn policy_echo(class: &str, idle_ms: u64) -> String {
    format!(
        "{{\"class\":\"{class}\",\"tickets\":6,\"maxPayloadBytes\":41943040,\"lifetimeMs\":90000,\"idleTimeoutMs\":{idle_ms},\"maxConcurrentStreams\":4,\"streamMaxMs\":900000}}"
    )
}

#[test]
fn a_book_opens_relays_through_its_tickets_and_refuses_reuse() {
    let node = Node::spawn(sink(), &[]);
    let session = open_session("research-v2", 0, 1, epoch_now());
    let expected = format!(
        "{{\"ok\":true,\"session\":{{\"ticketBookDigest\":\"{}\",\"policy\":{}}}}}\n",
        session.book.ticket_book_digest,
        policy_echo("research-v2", 60_000)
    );
    assert_eq!(node.ack(&init_envelope(&session)), expected);
    assert_eq!(
        node.ack(&init_envelope(&session)),
        expected,
        "an exact replay of a live book is idempotent"
    );

    let target = sink().target();
    let nonce = "0123456789abcdef0123456789abcdef";
    let (ack, stream) = node.open(&ticket_envelope(&session, 0, &target, nonce), b"ping");
    assert_eq!(ack, "{\"ok\":true}\n");
    assert_eq!(read_all(stream), b"ok:ping");
    let (ack, stream) = node.open(&ticket_envelope(&session, 1, &target, nonce), b"pong");
    assert_eq!(ack, "{\"ok\":true}\n");
    assert_eq!(read_all(stream), b"ok:pong");

    assert_eq!(
        node.ack(&ticket_envelope(&session, 0, &target, nonce)),
        "{\"ok\":false,\"err\":\"ticket-spent\"}\n"
    );
    let mut wrong_secret = ticket_envelope(&session, 2, &target, nonce);
    wrong_secret["ticket"]["t"] = json!(encode_ticket_secret(&session.secrets[3]));
    assert_eq!(
        node.ack(&wrong_secret),
        "{\"ok\":false,\"err\":\"ticket-mismatch\"}\n"
    );
    let mut unknown_book = ticket_envelope(&session, 2, &target, nonce);
    unknown_book["ticket"]["book"] = json!("0".repeat(64));
    assert_eq!(
        node.ack(&unknown_book),
        "{\"ok\":false,\"err\":\"session-unknown\"}\n"
    );
    let mut bad_index = ticket_envelope(&session, 2, &target, nonce);
    bad_index["ticket"]["i"] = json!(99);
    assert_eq!(
        node.ack(&bad_index),
        "{\"ok\":false,\"err\":\"ticket-index\"}\n"
    );
    let mut bad_nonce = ticket_envelope(&session, 2, &target, nonce);
    bad_nonce["ticket"]["n"] = json!("xyz");
    assert_eq!(
        node.ack(&bad_nonce),
        "{\"ok\":false,\"err\":\"ticket-nonce\"}\n"
    );
    assert_eq!(
        node.ack(&ticket_envelope(&session, 2, "example.com:80", nonce)),
        "{\"ok\":false,\"err\":\"bad-target-policy\"}\n"
    );
    assert_eq!(
        node.ack(&json!({"v": 4, "ticket": {"v": 2}})),
        "{\"ok\":false,\"err\":\"ticket-version\"}\n"
    );
    let (ack, stream) = node.open(&ticket_envelope(&session, 2, &target, nonce), b"third");
    assert_eq!(
        ack, "{\"ok\":true}\n",
        "the book is unaffected by the refusals"
    );
    assert_eq!(read_all(stream), b"ok:third");
}

#[test]
fn initialization_is_checked_cheap_first() {
    let node = Node::spawn(sink(), &[]);
    let session = open_session("research-v1", 1, 2, epoch_now());
    let good = init_envelope(&session);

    let mut wrong_gateway = good.clone();
    wrong_gateway["session"]["gateway"] = json!(format!("{}.onion", "b".repeat(56)));
    assert_eq!(
        node.ack(&wrong_gateway),
        "{\"ok\":false,\"err\":\"session-wrong-gateway\"}\n"
    );
    let mut bad_class = good.clone();
    bad_class["session"]["class"] = json!("research-v9");
    assert_eq!(
        node.ack(&bad_class),
        "{\"ok\":false,\"err\":\"session-class\"}\n"
    );
    let mut bad_digest = good.clone();
    bad_digest["session"]["ticketBookDigest"] = json!("0".repeat(64));
    assert_eq!(
        node.ack(&bad_digest),
        "{\"ok\":false,\"err\":\"session-digest\"}\n"
    );
    let mut other_nonce = good.clone();
    other_nonce["session"]["nonce"] = json!("00000000000000000000000000000000");
    assert_eq!(
        node.ack(&other_nonce),
        "{\"ok\":false,\"err\":\"gate:session-not-bound\"}\n",
        "the proof is bound to the exact session signal"
    );
    let mut forged = good.clone();
    forged["proof"]["snarkProof"]["publicSignals"]["y"] = json!("2");
    assert_eq!(
        node.ack(&forged),
        "{\"ok\":false,\"err\":\"gate:invalid-proof\"}\n"
    );
    let expected = format!(
        "{{\"ok\":true,\"session\":{{\"ticketBookDigest\":\"{}\",\"policy\":{}}}}}\n",
        session.book.ticket_book_digest,
        policy_echo("research-v1", 15_000)
    );
    assert_eq!(node.ack(&good), expected);
}

#[test]
fn concurrent_streams_are_capped_per_book() {
    let holder = Sink::hold();
    let node = Node::spawn(&holder, &[]);
    let session = open_session("research-v2", 2, 3, epoch_now());
    assert!(node
        .ack(&init_envelope(&session))
        .starts_with("{\"ok\":true"));
    let target = holder.target();
    let mut held = Vec::new();
    for index in 0..4 {
        let (ack, stream) = node.open(
            &ticket_envelope(&session, index, &target, "0123456789abcdef0123456789abcdef"),
            b"",
        );
        assert_eq!(ack, "{\"ok\":true}\n");
        held.push(stream);
    }
    assert_eq!(
        node.ack(&ticket_envelope(
            &session,
            4,
            &target,
            "0123456789abcdef0123456789abcdef"
        )),
        "{\"ok\":false,\"err\":\"session-streams\"}\n"
    );
    drop(held.remove(0));
    std::thread::sleep(Duration::from_millis(300));
    let (ack, _stream) = node.open(
        &ticket_envelope(&session, 4, &target, "0123456789abcdef0123456789abcdef"),
        b"",
    );
    assert_eq!(ack, "{\"ok\":true}\n", "a closed stream frees its slot");
}

#[test]
fn an_idle_book_closes_and_a_session_proof_counts_as_the_slots_share() {
    let node = Node::spawn(sink(), &[]);
    let epoch = epoch_now();
    let session = open_session("research-v1", 3, 4, epoch);
    assert!(node
        .ack(&init_envelope(&session))
        .starts_with("{\"ok\":true"));
    std::thread::sleep(Duration::from_secs(16));
    assert_eq!(
        node.ack(&ticket_envelope(
            &session,
            0,
            &sink().target(),
            "0123456789abcdef0123456789abcdef"
        )),
        "{\"ok\":false,\"err\":\"session-unknown\"}\n",
        "research-v1 books idle out after 15 s"
    );
    let other_book = open_session("research-v1", 3, 5, epoch);
    assert_eq!(
        node.ack(&init_envelope(&other_book)),
        "{\"ok\":false,\"err\":\"over-spend-slashed\"}\n",
        "a second book on the same slot is a second share on the nullifier"
    );
}

#[test]
fn sessions_are_unsupported_without_an_identity() {
    let node = Node::spawn(sink(), &[("SHADE_TREE_SESSION_TICKETS", "0")]);
    let session = open_session("research-v1", 4, 6, epoch_now());
    assert_eq!(
        node.ack(&init_envelope(&session)),
        "{\"ok\":false,\"err\":\"session-unsupported\"}\n"
    );
}
