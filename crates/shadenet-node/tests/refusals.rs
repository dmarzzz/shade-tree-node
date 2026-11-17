//! Black-box checks of the binary: every refusal a client can receive before proof
//! verification, byte for byte, plus the process contract (log line, signals, exit codes).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Node {
    child: Child,
    port: u16,
}

impl Node {
    fn spawn(env: &[(&str, &str)]) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_shadenet-node"));
        command
            .env_remove("SHADENET_LOG")
            .env("SHADE_TREE_GATEWAY_PORT", "0")
            .env("SHADE_TREE_LOG_FORMAT", "text")
            .env(
                "SHADE_TREE_MEMBERS_FILE",
                concat!(env!("CARGO_MANIFEST_DIR"), "/../../group/members.json"),
            )
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
        std::thread::spawn(move || for _ in lines {});
        Self { child, port }
    }

    fn connect(&self) -> TcpStream {
        let stream = TcpStream::connect(("127.0.0.1", self.port)).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        stream
    }

    fn exchange(&self, bytes: &[u8]) -> String {
        let mut stream = self.connect();
        stream.write_all(bytes).expect("write");
        let mut reply = String::new();
        BufReader::new(stream)
            .read_line(&mut reply)
            .expect("read reply");
        reply
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
    }
}

const PROTO: &str = ",\"proto\":{\"min\":4,\"max\":4}}\n";

#[test]
fn malformed_envelopes_are_named() {
    let node = Node::spawn(&[]);
    assert!(node
        .exchange(b"not json\n")
        .starts_with("{\"ok\":false,\"err\":\"bad-envelope:"));
    assert_eq!(
        node.exchange(b"5\n"),
        "{\"ok\":false,\"err\":\"bad-envelope:envelope is not an object\"}\n"
    );
    let oversized = vec![b'x'; 70_000];
    assert_eq!(
        node.exchange(&oversized),
        "{\"ok\":false,\"err\":\"bad-envelope:envelope too large\"}\n"
    );
}

#[test]
fn a_half_closed_peer_gets_closed_before_envelope() {
    let node = Node::spawn(&[]);
    let mut stream = node.connect();
    stream.write_all(b"{\"v\":4").expect("write");
    stream
        .shutdown(std::net::Shutdown::Write)
        .expect("half close");
    let mut reply = String::new();
    stream.read_to_string(&mut reply).expect("read");
    assert_eq!(
        reply,
        "{\"ok\":false,\"err\":\"bad-envelope:closed before envelope\"}\n"
    );
}

#[test]
fn the_envelope_deadline_is_enforced() {
    let node = Node::spawn(&[("SHADE_TREE_ENVELOPE_TIMEOUT_MS", "200")]);
    let mut stream = node.connect();
    stream.write_all(b"{\"v\":4").expect("write");
    let mut reply = String::new();
    BufReader::new(stream).read_line(&mut reply).expect("read");
    assert_eq!(
        reply,
        "{\"ok\":false,\"err\":\"bad-envelope:envelope timeout\"}\n"
    );
}

#[test]
fn the_version_gate_advertises_the_range() {
    let node = Node::spawn(&[]);
    assert_eq!(
        node.exchange(b"{}\n"),
        format!("{{\"ok\":false,\"err\":\"unsupported-version:3\"{PROTO}")
    );
    assert_eq!(
        node.exchange(b"[]\n"),
        format!("{{\"ok\":false,\"err\":\"unsupported-version:3\"{PROTO}")
    );
    assert_eq!(
        node.exchange(b"{\"v\":5}\n"),
        format!("{{\"ok\":false,\"err\":\"unsupported-version:5\"{PROTO}")
    );
    assert_eq!(
        node.exchange(b"{\"v\":\"4\"}\n"),
        format!("{{\"ok\":false,\"err\":\"bad-version:\\\"4\\\"\"{PROTO}")
    );
    assert_eq!(
        node.exchange(b"{\"v\":4.0}\n"),
        format!("{{\"ok\":false,\"err\":\"bad-version:4.0\"{PROTO}")
    );
}

#[test]
fn sessions_are_refused_until_supported() {
    let node = Node::spawn(&[]);
    assert_eq!(
        node.exchange(b"{\"v\":4,\"session\":{}}\n"),
        "{\"ok\":false,\"err\":\"session-unsupported\"}\n"
    );
    assert_eq!(
        node.exchange(b"{\"v\":4,\"ticket\":{},\"target\":\"example.com:443\"}\n"),
        "{\"ok\":false,\"err\":\"session-unsupported\"}\n"
    );
}

#[test]
fn targets_are_checked_before_any_proof_work() {
    let node = Node::spawn(&[("SHADE_TREE_EGRESS_DENY", "blocked.example:443")]);
    assert_eq!(
        node.exchange(b"{\"v\":4}\n"),
        "{\"ok\":false,\"err\":\"bad-target\"}\n"
    );
    assert_eq!(
        node.exchange(b"{\"v\":4,\"target\":\"example.com\"}\n"),
        "{\"ok\":false,\"err\":\"bad-target\"}\n"
    );
    assert_eq!(
        node.exchange(b"{\"v\":4,\"target\":\"example.com:80\"}\n"),
        "{\"ok\":false,\"err\":\"bad-target-policy\"}\n"
    );
    assert_eq!(
        node.exchange(b"{\"v\":4,\"target\":\"blocked.example:443\"}\n"),
        "{\"ok\":false,\"err\":\"bad-target-policy\"}\n"
    );
    assert_eq!(
        node.exchange(b"{\"v\":4,\"target\":\"example.com:443\"}\n"),
        "{\"ok\":false,\"err\":\"gate:no-proof\"}\n"
    );
}

#[test]
fn the_connection_cap_is_decided_at_accept() {
    let node = Node::spawn(&[("SHADE_TREE_MAX_CONNS", "1")]);
    let _held = node.connect();
    assert_eq!(
        node.exchange(b""),
        "{\"ok\":false,\"err\":\"too-many-connections\"}\n"
    );
}

#[test]
fn sigterm_drains_and_exits_zero() {
    let node = Node::spawn(&[]);
    assert_eq!(node.terminate(), 0);
}

#[test]
fn an_idle_connection_past_the_grace_exits_one() {
    let node = Node::spawn(&[
        ("SHADE_TREE_SHUTDOWN_TIMEOUT_MS", "200"),
        ("SHADE_TREE_ENVELOPE_TIMEOUT_MS", "0"),
    ]);
    let _held = node.connect();
    assert_eq!(node.terminate(), 1);
}

#[test]
fn conflicting_prefixes_are_a_configuration_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_shadenet-node"))
        .env("SHADENET_GATEWAY_PORT", "1")
        .env("SHADE_TREE_GATEWAY_PORT", "2")
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("both set to different values"));
}

#[test]
fn a_missing_member_file_and_an_unsupported_admission_are_configuration_errors() {
    let output = Command::new(env!("CARGO_BIN_EXE_shadenet-node"))
        .env_remove("SHADE_TREE_MEMBERS_FILE")
        .env_remove("SHADENET_MEMBERS_FILE")
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("SHADE_TREE_MEMBERS_FILE"));
    let output = Command::new(env!("CARGO_BIN_EXE_shadenet-node"))
        .env("SHADE_TREE_ADMIT", "invited,staked")
        .output()
        .expect("run");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("SHADE_TREE_ADMIT"));
}

#[test]
fn version_names_the_commit() {
    let output = Command::new(env!("CARGO_BIN_EXE_shadenet-node"))
        .arg("--version")
        .output()
        .expect("run");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.starts_with(&format!(
            "shadenet-node {} (commit ",
            env!("CARGO_PKG_VERSION")
        )),
        "{text}"
    );
}
