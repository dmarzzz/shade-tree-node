//! On-chain admission and slashing against the real contracts on Anvil: the node rebuilds the
//! member tree from the StakedReputationSet events, admits a staked member with a real proof,
//! and an over-spend lands as a `slash` transaction that burns the bond and pays the bounty.
//!
//! Skipped (with a message) when `anvil`, `forge` or `cast` are not on PATH.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use shadenet_rln::prover::{build_envelope, BuiltEnvelope, EnvelopeInput};
use shadenet_rln::tree::{fr_to_dec, parse_fr, poseidon1, rate_commitment, MerkleTree, TREE_DEPTH};

const LIMIT: u64 = 8;
const EPOCH_SECONDS: u64 = 120;
const BOND_WEI: u64 = 10_000_000_000_000_000;
// Anvil's published development keys (never funded anywhere real).
const DEPLOYER_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const MEMBER_A_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const MEMBER_B_KEY: &str = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
const SLASHER_KEY: &str = "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6";
const RECEIVER: &str = "0x976EA74026E726554dB657fA54763abd0C3a0aa9";

fn repo() -> PathBuf {
    PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
}

fn tools_present() -> bool {
    ["anvil", "forge", "cast"].iter().all(|tool| {
        Command::new(tool)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    })
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Anvil {
    child: Child,
    url: String,
}

impl Anvil {
    fn start() -> Self {
        let port = free_port();
        let child = Command::new("anvil")
            .args(["--port", &port.to_string(), "--silent"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start anvil");
        let url = format!("http://127.0.0.1:{port}");
        let started = Instant::now();
        while cast(&url, &["chain-id"]).is_err() {
            assert!(
                started.elapsed() < Duration::from_secs(30),
                "anvil did not come up"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
        Self { child, url }
    }
}

impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn cast(url: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new("cast")
        .args(args)
        .args(["--rpc-url", url])
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Forge may only write under the repository, so the record lands in `cache/` like the
/// member-lifecycle harness's does.
fn deploy(url: &str, work: &Path) -> String {
    let out = repo().join("cache").join(format!(
        "node-onchain-{}.local.json",
        work.file_name().and_then(|n| n.to_str()).unwrap_or("test")
    ));
    std::fs::create_dir_all(out.parent().unwrap()).unwrap();
    let status = Command::new("forge")
        .current_dir(repo())
        .args([
            "script",
            "contracts/script/DeployRegistry.s.sol:DeployRegistry",
            "--rpc-url",
            url,
            "--broadcast",
            "--private-key",
            DEPLOYER_KEY,
        ])
        .env("SHADE_TREE_BOND_WEI", BOND_WEI.to_string())
        .env("SHADE_TREE_UNBONDING", "300")
        .env("SHADE_TREE_MIN_UNBONDING", "270")
        .env("SHADE_TREE_DEPLOY_OUT", &out)
        .env("SHADE_TREE_RPC_URL", url)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status()
        .expect("run forge");
    assert!(status.success(), "forge script failed");
    let record: Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    let _ = std::fs::remove_file(&out);
    record["stakedReputationSet"]
        .as_str()
        .expect("deploy record names the set")
        .to_string()
}

fn register(url: &str, set: &str, key: &str, secret: &str) -> String {
    let identity_commitment = fr_to_dec(&poseidon1(parse_fr(secret).unwrap()));
    cast(
        url,
        &[
            "send",
            set,
            "registerIdentity(uint256,uint256)",
            &identity_commitment,
            &LIMIT.to_string(),
            "--value",
            &BOND_WEI.to_string(),
            "--private-key",
            key,
        ],
    )
    .expect("registerIdentity");
    fr_to_dec(&rate_commitment(parse_fr(secret).unwrap(), LIMIT))
}

fn is_active(url: &str, set: &str, leaf: &str) -> bool {
    cast(url, &["call", set, "isActive(uint256)(bool)", leaf]).expect("isActive") == "true"
}

fn balance(url: &str, address: &str) -> u128 {
    cast(url, &["balance", address])
        .expect("balance")
        .parse()
        .unwrap()
}

fn epoch_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / EPOCH_SECONDS
}

fn prove(
    secret: &str,
    members: &[String],
    target: &str,
    nonce: &str,
    message_id: u64,
) -> BuiltEnvelope {
    build_envelope(&EnvelopeInput {
        identity_secret: secret.into(),
        member_leaf: fr_to_dec(&rate_commitment(parse_fr(secret).unwrap(), LIMIT)),
        members: members.to_vec(),
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

fn envelope(built: &BuiltEnvelope) -> Vec<u8> {
    let artifact = shadenet_rln::artifacts::verify_embedded()
        .expect("embedded artifacts match the lock")
        .artifact_id;
    let value = json!({
        "v": 4,
        "artifact": artifact,
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
    });
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    bytes
}

struct Node {
    child: Child,
    port: u16,
}

impl Node {
    fn spawn(url: &str, set: &str, sink: &str) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_shadenet-node"))
            .env_remove("SHADENET_LOG")
            .env("SHADE_TREE_GATEWAY_PORT", "0")
            .env("SHADE_TREE_LOG_FORMAT", "text")
            .env("SHADE_TREE_LOG_LEVEL", "debug")
            .env("SHADE_TREE_ADMIT", "staked")
            .env("SHADE_TREE_GROUP_CONTRACT", set)
            .env("SHADE_TREE_RPC_URL", url)
            .env("SHADE_TREE_FROM_BLOCK", "0")
            // Anvil never advances `finalized`; read one block behind the head instead.
            .env("SHADE_TREE_CONFIRMATIONS", "1")
            .env("SHADE_TREE_ROOT_FRESHNESS_SECONDS", "60")
            .env("SHADE_TREE_SLASH_KEY", SLASHER_KEY)
            .env("SHADE_TREE_SLASH_RECEIVER", RECEIVER)
            .env("SHADE_TREE_EGRESS_ALLOW", sink)
            .env("SHADE_TREE_ALLOW_PRIVATE_TARGETS", "1")
            .env("SHADE_TREE_EPOCH_SECONDS", EPOCH_SECONDS.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn shadenet-node");
        let stderr = child.stderr.take().unwrap();
        let mut lines = BufReader::new(stderr).lines();
        let port = loop {
            let line = lines
                .next()
                .expect("node exited before announcing its port")
                .expect("read stderr");
            eprintln!("[node] {line}");
            if let Some(rest) = line.split("gateway up on 127.0.0.1:").nth(1) {
                break rest.trim().parse().expect("port");
            }
        };
        std::thread::spawn(move || {
            for line in lines.map_while(Result::ok) {
                eprintln!("[node] {line}");
            }
        });
        Self { child, port }
    }

    fn open(&self, bytes: &[u8]) -> (String, BufReader<TcpStream>) {
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        stream.write_all(bytes).expect("write");
        let mut reader = BufReader::new(stream);
        let mut ack = String::new();
        reader.read_line(&mut ack).expect("read ack");
        (ack, reader)
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn echo_sink() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
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
    addr.to_string()
}

#[test]
fn staked_members_are_admitted_and_an_over_spender_is_slashed_on_chain() {
    if !tools_present() {
        eprintln!("SKIP: anvil, forge and cast are needed on PATH");
        return;
    }
    let work = std::env::temp_dir().join(format!("shadenet-node-onchain-{}", std::process::id()));
    std::fs::create_dir_all(&work).unwrap();
    let anvil = Anvil::start();
    let url = anvil.url.clone();
    let set = deploy(&url, &work);
    let leaf_a = register(&url, &set, MEMBER_A_KEY, "111");
    let leaf_b = register(&url, &set, MEMBER_B_KEY, "222");
    cast(&url, &["rpc", "evm_mine"]).expect("mine");
    let members = vec![leaf_a.clone(), leaf_b.clone()];
    let sink = echo_sink();
    let node = Node::spawn(&url, &set, &sink);

    let first = prove(
        "222",
        &members,
        &sink,
        "00112233445566778899aabbccddeeff",
        0,
    );
    let (ack, mut stream) = node.open(&envelope(&first));
    assert_eq!(
        ack, "{\"ok\":true}\n",
        "a staked member is admitted from the chain's own events"
    );
    stream.get_mut().write_all(b"ping").unwrap();
    let mut got = Vec::new();
    let _ = stream.read_to_end(&mut got);
    assert_eq!(got, b"ok:ping");

    let second = prove(
        "222",
        &members,
        &sink,
        "ffeeddccbbaa99887766554433221100",
        0,
    );
    let before = balance(&url, RECEIVER);
    let (ack, _) = node.open(&envelope(&second));
    assert_eq!(ack, "{\"ok\":false,\"err\":\"over-spend-slashed\"}\n");

    let started = Instant::now();
    while is_active(&url, &set, &leaf_b) {
        assert!(
            started.elapsed() < Duration::from_secs(90),
            "the slash transaction did not land"
        );
        std::thread::sleep(Duration::from_secs(1));
    }
    assert!(
        is_active(&url, &set, &leaf_a),
        "the other member is untouched"
    );
    cast(&url, &["rpc", "evm_mine"]).expect("mine");
    assert_eq!(
        balance(&url, RECEIVER) - before,
        u128::from(BOND_WEI / 10),
        "the receiver gets the 10% bounty; the rest burned"
    );

    let zero = fr_to_dec(&MerkleTree::new(&1_u8.into(), TREE_DEPTH, &[]).zero_value());
    let after_slash = vec![leaf_a.clone(), zero];
    let old_root = prove(
        "111",
        &members,
        &sink,
        "0123456789abcdef0123456789abcdef",
        1,
    );
    let (ack, _) = node.open(&envelope(&old_root));
    assert_eq!(
        ack, "{\"ok\":true}\n",
        "the superseded root stays accepted inside the freshness window"
    );
    let new_root = prove(
        "111",
        &after_slash,
        &sink,
        "abababababababababababababababab",
        2,
    );
    let started = Instant::now();
    loop {
        let (ack, _) = node.open(&envelope(&new_root));
        if ack == "{\"ok\":true}\n" {
            break;
        }
        assert!(
            ack.starts_with("{\"ok\":false,\"err\":\"gate:wrong-group-root\",\"roots\":[")
                && ack.contains("\"rootBlock\":")
                && ack.contains("\"rootLeaves\":"),
            "{ack}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(40),
            "the node did not pick up the post-slash root"
        );
        std::thread::sleep(Duration::from_secs(2));
    }
    let _ = std::fs::remove_dir_all(&work);
}
