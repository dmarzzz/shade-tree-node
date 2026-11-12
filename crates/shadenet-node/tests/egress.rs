//! End to end with real Groth16 proofs: the node admits a member of its invited set, relays
//! bytes both ways, and refuses every tampered or over-spent envelope with the reason the
//! JavaScript node gives.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

struct Proof {
    built: BuiltEnvelope,
    epoch: u64,
}

fn prove(target: &str, nonce: &str, message_id: u64, epoch: u64) -> Proof {
    let built = build_envelope(&EnvelopeInput {
        identity_secret: SECRET.into(),
        member_leaf: leaf(),
        members: vec![leaf()],
        target: target.into(),
        nonce: nonce.into(),
        signal: None,
        epoch,
        rln_identifier: "1".into(),
        user_message_limit: LIMIT,
        message_id,
        circuits_dir: None,
    })
    .expect("prove");
    Proof { built, epoch }
}

fn envelope(proof: &Proof) -> Value {
    let built = &proof.built;
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

struct Sink {
    port: u16,
}

impl Sink {
    /// Echo `ok:` plus the first chunk, then close.
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

    /// Accept and hold every connection open.
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
            "shadenet-node-egress-{}-{}",
            std::process::id(),
            sink.port
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let members = dir.join("members.json");
        std::fs::write(&members, json!({"members": [leaf()]}).to_string()).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_shadenet-node"));
        command
            .env_remove("SHADENET_LOG")
            .env("SHADE_TREE_GATEWAY_PORT", "0")
            .env("SHADE_TREE_LOG_FORMAT", "text")
            .env("SHADE_TREE_MEMBERS_FILE", &members)
            .env("SHADE_TREE_EGRESS_ALLOW", sink.target())
            .env("SHADE_TREE_ALLOW_PRIVATE_TARGETS", "1")
            .env("SHADE_TREE_EPOCH_SECONDS", EPOCH_SECONDS.to_string())
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

    fn connect(&self) -> TcpStream {
        let stream = TcpStream::connect(("127.0.0.1", self.port)).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .expect("read timeout");
        stream
    }

    /// Send an envelope plus early bytes; return the ack line and the open stream. The
    /// reader is kept: bytes relayed back may arrive in the same segment as the ack.
    fn open(&self, envelope: &Value, early: &[u8]) -> (String, BufReader<TcpStream>) {
        let mut stream = self.connect();
        let mut bytes = serde_json::to_vec(envelope).unwrap();
        bytes.push(b'\n');
        bytes.extend_from_slice(early);
        stream.write_all(&bytes).expect("write");
        let mut reader = BufReader::new(stream);
        let mut ack = String::new();
        reader.read_line(&mut ack).expect("read ack");
        (ack, reader)
    }

    fn refusal(&self, envelope: &Value) -> String {
        self.open(envelope, b"").0
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
static FIRST: OnceLock<Proof> = OnceLock::new();
static SECOND_SHARE: OnceLock<Proof> = OnceLock::new();
static OTHER_SLOT: OnceLock<Proof> = OnceLock::new();

fn sink() -> &'static Sink {
    SINK.get_or_init(Sink::echo)
}

/// Slot 0 of this epoch.
fn first() -> &'static Proof {
    FIRST.get_or_init(|| {
        prove(
            &sink().target(),
            "00112233445566778899aabbccddeeff",
            0,
            epoch_now(),
        )
    })
}

/// Slot 0 again with another nonce: a second share on the same nullifier.
fn second_share() -> &'static Proof {
    SECOND_SHARE.get_or_init(|| {
        prove(
            &sink().target(),
            "ffeeddccbbaa99887766554433221100",
            0,
            first().epoch,
        )
    })
}

/// Slot 1 of the same epoch.
fn other_slot() -> &'static Proof {
    OTHER_SLOT.get_or_init(|| {
        prove(
            &sink().target(),
            "0123456789abcdef0123456789abcdef",
            1,
            first().epoch,
        )
    })
}

#[test]
fn an_admitted_member_is_relayed_and_may_retry_the_same_envelope() {
    let node = Node::spawn(sink(), &[]);
    let (ack, stream) = node.open(&envelope(first()), b"ping");
    assert_eq!(ack, "{\"ok\":true}\n");
    assert_eq!(read_all(stream), b"ok:ping");
    let (ack, stream) = node.open(&envelope(first()), b"again");
    assert_eq!(
        ack, "{\"ok\":true}\n",
        "an exact replay inside the window is honoured"
    );
    assert_eq!(read_all(stream), b"ok:again");
}

#[test]
fn tampered_envelopes_are_refused_with_the_precise_reason() {
    let node = Node::spawn(sink(), &[]);
    let good = envelope(other_slot());

    let mut stale = good.clone();
    let old = prove(
        &sink().target(),
        "0123456789abcdef0123456789abcdef",
        1,
        first().epoch - 2,
    );
    stale["proof"] = envelope(&old)["proof"].clone();
    stale["nonce"] = json!(old.built.nonce);
    assert_eq!(
        node.refusal(&stale),
        "{\"ok\":false,\"err\":\"gate:stale-external-nullifier\"}\n"
    );

    let mut mismatch = good.clone();
    mismatch["share"]["x"] = json!("1");
    assert_eq!(
        node.refusal(&mismatch),
        "{\"ok\":false,\"err\":\"gate:signal-mismatch\"}\n"
    );

    let mut unbound = good.clone();
    unbound.as_object_mut().unwrap().remove("nonce");
    assert_eq!(
        node.refusal(&unbound),
        "{\"ok\":false,\"err\":\"gate:unbound-target\"}\n"
    );

    let mut other_nonce = good.clone();
    other_nonce["nonce"] = json!("00000000000000000000000000000000");
    assert_eq!(
        node.refusal(&other_nonce),
        "{\"ok\":false,\"err\":\"gate:target-not-bound\"}\n"
    );

    let mut wrong_root = good.clone();
    wrong_root["proof"]["snarkProof"]["publicSignals"]["root"] = json!("1");
    let reply = node.refusal(&wrong_root);
    assert!(
        reply.starts_with("{\"ok\":false,\"err\":\"gate:wrong-group-root\",\"roots\":[\""),
        "{reply}"
    );
    let parsed: Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(
        parsed["roots"][0],
        good["proof"]["snarkProof"]["publicSignals"]["root"]
    );

    let mut unknown = good.clone();
    unknown["artifact"] = json!("rln-0000000000000000");
    assert_eq!(
        node.refusal(&unknown),
        format!(
            "{{\"ok\":false,\"err\":\"gate:artifact-unknown:rln-0000000000000000\",\"artifacts\":[\"{}\"]}}\n",
            artifact_id()
        )
    );

    let mut forged = good.clone();
    forged["proof"]["snarkProof"]["publicSignals"]["y"] = json!("2");
    assert_eq!(
        node.refusal(&forged),
        "{\"ok\":false,\"err\":\"gate:invalid-proof\"}\n"
    );

    let mut bad_proof = good.clone();
    bad_proof["proof"]["snarkProof"]["proof"]["pi_a"] = json!(["1", "1", "1"]);
    let reply = node.refusal(&bad_proof);
    assert!(
        reply.starts_with("{\"ok\":false,\"err\":\"gate:verify-threw:"),
        "{reply}"
    );

    let (ack, stream) = node.open(&good, b"still-fine");
    assert_eq!(ack, "{\"ok\":true}\n");
    assert_eq!(read_all(stream), b"ok:still-fine");
}

#[test]
fn a_second_share_on_one_nullifier_is_an_over_spend() {
    let node = Node::spawn(sink(), &[]);
    let (ack, _stream) = node.open(&envelope(first()), b"x");
    assert_eq!(ack, "{\"ok\":true}\n");
    assert_eq!(
        node.refusal(&envelope(second_share())),
        "{\"ok\":false,\"err\":\"over-spend-slashed\"}\n"
    );
    assert_eq!(
        node.refusal(&envelope(first())),
        "{\"ok\":false,\"err\":\"rate-slashed\"}\n"
    );
}

#[test]
fn the_spent_set_survives_a_restart() {
    let dir = std::env::temp_dir().join(format!("shadenet-node-spent-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let state = dir.join("spent-set.json");
    let env = [("SHADE_TREE_SPENT_STATE_FILE", state.to_str().unwrap())];
    let node = Node::spawn(sink(), &env);
    let (ack, stream) = node.open(&envelope(first()), b"x");
    assert_eq!(ack, "{\"ok\":true}\n");
    assert_eq!(read_all(stream), b"ok:x");
    assert_eq!(node.terminate(), 0);
    assert!(state.exists(), "the snapshot is written at shutdown");

    let node = Node::spawn(sink(), &env);
    assert_eq!(
        node.refusal(&envelope(second_share())),
        "{\"ok\":false,\"err\":\"over-spend-slashed\"}\n",
        "the first share was remembered across the restart"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_payload_allowance_is_shared_by_retries_on_one_slot() {
    let node = Node::spawn(sink(), &[("SHADE_TREE_TUNNEL_MAX_PAYLOAD_BYTES", "8")]);
    let (ack, stream) = node.open(&envelope(other_slot()), b"ping");
    assert_eq!(ack, "{\"ok\":true}\n");
    assert_eq!(
        read_all(stream),
        b"ok:p",
        "4 bytes up and 4 of the 7 back: the boundary chunk is delivered, nothing after it"
    );
    assert_eq!(
        node.refusal(&envelope(other_slot())),
        "{\"ok\":false,\"err\":\"payload-limit\"}\n"
    );
}

#[test]
fn one_nullifier_cannot_pin_more_tunnels_than_the_cap() {
    let holder = Sink::hold();
    let node = Node::spawn(&holder, &[("SHADE_TREE_MAX_CONNS_PER_NULLIFIER", "1")]);
    let proof = prove(
        &holder.target(),
        "abababababababababababababababab",
        2,
        first().epoch,
    );
    let (ack, _held) = node.open(&envelope(&proof), b"");
    assert_eq!(ack, "{\"ok\":true}\n");
    assert_eq!(
        node.refusal(&envelope(&proof)),
        "{\"ok\":false,\"err\":\"nullifier-conn-limit\"}\n"
    );
}

#[test]
fn a_private_destination_needs_the_opt_in() {
    let node = Node::spawn(sink(), &[("SHADE_TREE_ALLOW_PRIVATE_TARGETS", "0")]);
    assert_eq!(
        node.refusal(&envelope(other_slot())),
        "{\"ok\":false,\"err\":\"bad-target-address\"}\n"
    );
}
