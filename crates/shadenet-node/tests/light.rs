//! The light-client root provider end to end: a stub RPC serves a real Sepolia `eth_getProof`
//! of the staked set's root slot, the node proves it against the block's state root and
//! admits on that root; a lying anchor or a tampered proof leaves the node with no root.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use shadenet_rln::prover::{build_envelope, EnvelopeInput};
use shadenet_rln::tree::{fr_to_dec, parse_fr, rate_commitment};

const FIXTURE: &str = include_str!("../../../testdata/light-root-proof.json");

/// A stub JSON-RPC: the fixture's block, proof and storage value. `state_root` overrides what
/// `eth_getBlockByNumber` reports (a lying header), `proof` the proof body.
fn stub_rpc(state_root: Option<String>, proof: Value) -> String {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let proof = Arc::new(proof);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            let mut raw = Vec::new();
            let mut chunk = [0_u8; 8192];
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
            let text = String::from_utf8_lossy(&raw);
            let body = text.split("\r\n\r\n").nth(1).unwrap_or("{}");
            let request: Value = serde_json::from_str(body).unwrap_or(Value::Null);
            let result = match request["method"].as_str() {
                Some("eth_chainId") => json!("0xaa36a7"),
                Some("eth_getBlockByNumber") => json!({
                    "number": fixture["block"]["number"],
                    "hash": fixture["block"]["hash"],
                    "stateRoot": state_root.clone().unwrap_or_else(|| fixture["block"]["stateRoot"].as_str().unwrap().to_string()),
                }),
                Some("eth_getProof") => (*proof).clone(),
                Some("eth_getStorageAt") => fixture["proof"]["storageProof"][0]["value"].clone(),
                _ => Value::Null,
            };
            let reply =
                json!({"jsonrpc": "2.0", "id": request["id"], "result": result}).to_string();
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
                    reply.len()
                )
                .as_bytes(),
            );
        }
    });
    format!("http://127.0.0.1:{port}")
}

struct Started {
    child: std::process::Child,
    port: Option<u16>,
    log: String,
}

impl Drop for Started {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start the node in light mode against `rpc` and wait for its ready line or its exit.
fn start(rpc: &str, extra: &[(&str, &str)]) -> Started {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_shadenet-node"))
        .env_remove("SHADENET_LOG")
        .env("SHADE_TREE_GATEWAY_PORT", "0")
        .env("SHADE_TREE_LOG_FORMAT", "text")
        .env("SHADE_TREE_ADMIT", "staked")
        .env(
            "SHADE_TREE_GROUP_CONTRACT",
            fixture["contract"].as_str().unwrap(),
        )
        .env("SHADE_TREE_RPC_URL", rpc)
        .env("SHADE_TREE_ROOT_PROVIDER", "light")
        .env("SHADE_TREE_EGRESS_ALLOW", "127.0.0.1:1")
        .envs(extra.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn shadenet-node");
    let stderr = child.stderr.take().unwrap();
    let mut log = String::new();
    let mut port = None;
    for line in BufReader::new(stderr).lines().map_while(Result::ok) {
        log.push_str(&line);
        log.push('\n');
        if let Some(rest) = line.split("gateway up on 127.0.0.1:").nth(1) {
            port = rest.trim().parse().ok();
            break;
        }
    }
    Started { child, port, log }
}

fn refusal(port: u16, envelope: &Value) -> Value {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let mut bytes = serde_json::to_vec(envelope).unwrap();
    bytes.push(b'\n');
    stream.write_all(&bytes).unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

/// A real proof against a one-member tree: it passes the epoch, share and target checks and
/// fails on the root, so the refusal advertises the roots the node admits.
fn foreign_root_envelope() -> Value {
    let secret = "111";
    let leaf = fr_to_dec(&rate_commitment(parse_fr(secret).unwrap(), 8));
    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 120;
    let built = build_envelope(&EnvelopeInput {
        identity_secret: secret.into(),
        member_leaf: leaf.clone(),
        members: vec![leaf],
        target: "127.0.0.1:1".into(),
        nonce: "00112233445566778899aabbccddeeff".into(),
        signal: None,
        epoch,
        rln_identifier: "1".into(),
        user_message_limit: 8,
        message_id: 0,
        circuits_dir: None,
    })
    .expect("prove");
    json!({
        "v": 4,
        "artifact": shadenet_rln::artifacts::verify_embedded().unwrap().artifact_id,
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

#[test]
fn a_proven_root_is_admitted_and_a_lying_anchor_or_proof_is_refused() {
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let proof = fixture["proof"].clone();

    // the proven root is what the node admits: a refusal advertises it back
    let honest = start(&stub_rpc(None, proof.clone()), &[]);
    let port = honest.port.unwrap_or_else(|| panic!("{}", honest.log));
    assert!(honest.log.contains("provider=\"light\""), "{}", honest.log);
    assert!(
        honest.log.contains("admission roots refreshed"),
        "{}",
        honest.log
    );
    let envelope = foreign_root_envelope();
    let reply = refusal(port, &envelope);
    assert_eq!(reply["err"], "gate:wrong-group-root", "{reply}");
    assert_eq!(reply["roots"], json!([fixture["root"]]), "{reply}");
    drop(honest);

    // storageat mode trusts the rpc's value, the documented weaker path
    let storage = start(
        &stub_rpc(None, Value::Null),
        &[("SHADE_TREE_LIGHT_MODE", "storageat")],
    );
    let port = storage.port.unwrap_or_else(|| panic!("{}", storage.log));
    assert!(
        storage.log.contains("mode=\"storageat\""),
        "{}",
        storage.log
    );
    assert_eq!(refusal(port, &envelope)["roots"], json!([fixture["root"]]));
    drop(storage);

    // a tampered proof node fails the hash chain: no root, so the node refuses to start
    let mut tampered = proof.clone();
    let nodes = tampered["storageProof"][0]["proof"].as_array_mut().unwrap();
    let last = nodes.last_mut().unwrap();
    let text = last.as_str().unwrap().to_string();
    let flipped = format!(
        "{}{}",
        &text[..text.len() - 2],
        if text.ends_with("00") { "01" } else { "00" }
    );
    *last = Value::String(flipped);
    let broken = start(&stub_rpc(None, tampered), &[]);
    assert!(broken.port.is_none(), "{}", broken.log);
    assert!(
        broken.log.contains("no admission root available"),
        "{}",
        broken.log
    );

    // a helios anchor that attests a different state root than the rpc's header: refused by name
    let anchor = stub_rpc(Some(format!("0x{}", "11".repeat(32))), proof.clone());
    let divergent = start(
        &stub_rpc(None, proof),
        &[("SHADE_TREE_HELIOS_RPC_URL", &anchor)],
    );
    assert!(divergent.port.is_none(), "{}", divergent.log);
    assert!(
        divergent.log.contains("stateRoot mismatch"),
        "{}",
        divergent.log
    );

    // the anchor on another chain is refused before any proof is read
    let other_chain = start(
        &stub_rpc(None, fixture["proof"].clone()),
        &[
            ("SHADE_TREE_HELIOS_RPC_URL", &stub_rpc(None, Value::Null)),
            ("SHADE_TREE_HELIOS_CHAIN_ID", "1"),
        ],
    );
    assert!(other_chain.port.is_none(), "{}", other_chain.log);
    assert!(
        other_chain.log.contains("helios chainId mismatch"),
        "{}",
        other_chain.log
    );

    // helios with the node provider is a configuration error
    let misconfigured = start(
        &stub_rpc(None, Value::Null),
        &[
            ("SHADE_TREE_ROOT_PROVIDER", "node"),
            ("SHADE_TREE_HELIOS_RPC_URL", "http://127.0.0.1:1"),
        ],
    );
    assert!(misconfigured.port.is_none());
    assert!(
        misconfigured
            .log
            .contains("needs SHADE_TREE_ROOT_PROVIDER=light"),
        "{}",
        misconfigured.log
    );
}
