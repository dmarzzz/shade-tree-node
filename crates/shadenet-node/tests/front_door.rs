//! The `shadenet-node` front door, every command short of `run` (which needs a real Tor),
//! driven as a child process against a temp state directory, a file record and a stub JSON-RPC
//! server. Mirrors `packages/node/bin/shadenet-node.selftest.mjs`.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

const STAGING: &str = include_str!("../../../network/sepolia-staging/deployment.json");
const PRODUCTION: &str = include_str!("../../../network/sepolia/deployment.json");

struct Work {
    dir: PathBuf,
    state: PathBuf,
}

impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn work() -> Work {
    let dir = std::env::temp_dir().join(format!("shadenet-front-door-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    Work {
        state: dir.join("state"),
        dir,
    }
}

struct Run {
    code: i32,
    out: String,
    err: String,
}

fn cli(state: &Path, args: &[&str], env: &[(&str, &str)]) -> Run {
    let output = Command::new(env!("CARGO_BIN_EXE_shadenet-node"))
        .args(args)
        .env_remove("SHADENET_LOG")
        .env("SHADENET_STATE", state)
        .env("SHADENET_RECORD", "")
        .env("SHADENET_SETS", "")
        .env("SHADE_TREE_LOG_FORMAT", "text")
        .envs(env.iter().copied())
        .output()
        .expect("run shadenet-node");
    Run {
        code: output.status.code().unwrap_or(-1),
        out: String::from_utf8_lossy(&output.stdout).to_string(),
        err: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

/// A stub Sepolia RPC: chain id 11155111, a fixed head.
fn stub_rpc() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
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
            let text = String::from_utf8_lossy(&raw);
            let body = text.split("\r\n\r\n").nth(1).unwrap_or("{}");
            let request: Value = serde_json::from_str(body).unwrap_or(Value::Null);
            let result = match request["method"].as_str() {
                Some("eth_chainId") => "0xaa36a7",
                Some("eth_blockNumber") => "0xb44f00",
                _ => "null",
            };
            let reply = format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":\"{result}\"}}",
                request["id"]
            );
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

fn findings_text(report: &Value) -> String {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            format!(
                "{} {}",
                f["level"].as_str().unwrap(),
                f["what"].as_str().unwrap()
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn the_front_door_commands_behave_like_the_javascript_ones() {
    let work = work();
    let state = &work.state;
    let rpc_url = stub_rpc();
    let staging: Value = serde_json::from_str(STAGING).unwrap();
    let production: Value = serde_json::from_str(PRODUCTION).unwrap();
    let mut record = staging.clone();
    record["admission"]["roots"]["staked"]["rpcUrls"] = serde_json::json!([rpc_url]);
    record["admission"]["roots"]["staked"]["rpcUrl"] = Value::String(rpc_url.clone());
    let record_path = work.dir.join("record.json");
    std::fs::write(&record_path, record.to_string()).unwrap();
    let mut retired = record.clone();
    retired["status"] = Value::String("retired".into());
    let retired_path = work.dir.join("retired.json");
    std::fs::write(&retired_path, retired.to_string()).unwrap();
    let record_arg = record_path.display().to_string();

    // help lists every knob
    let help = cli(state, &["help"], &[]);
    assert_eq!(help.code, 0);
    for knob in [
        "SHADENET_RECORD",
        "SHADENET_SETS",
        "SHADENET_OPERATOR_SIG",
        "SHADENET_POW",
    ] {
        assert!(help.out.contains(knob), "{knob} missing from help");
    }

    // run without a record refuses with the one-line reason, exit 2
    let run = cli(state, &["run"], &[]);
    assert_eq!(run.code, 2, "{}", run.err);
    assert!(run.err.contains("set SHADENET_RECORD"), "{}", run.err);

    // identity mints once and is stable
    let identity = cli(state, &["identity"], &[]);
    assert_eq!(identity.code, 0, "{}", identity.err);
    let id: Value = serde_json::from_str(&identity.out).unwrap();
    let onion = id["onion"].as_str().unwrap().to_string();
    assert_eq!(onion.len(), 62);
    assert!(onion.ends_with(".onion"));
    assert!(state.join("hs-gateway/identity.local.json").exists());
    let again: Value = serde_json::from_str(&cli(state, &["identity"], &[]).out).unwrap();
    assert_eq!(again["onion"], onion, "identity is reused, never re-minted");

    // authorize signs the onion where the key lives; the signature recovers the operator
    let key_file = work.dir.join("operator.key");
    std::fs::write(
        &key_file,
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d\n",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let authorized = cli(
        state,
        &[
            "authorize",
            "--onion",
            &onion,
            "--key-file",
            &key_file.display().to_string(),
        ],
        &[],
    );
    assert_eq!(authorized.code, 0, "{}", authorized.err);
    let auth: Value = serde_json::from_str(&authorized.out).unwrap();
    let operator = auth["SHADENET_OPERATOR"].as_str().unwrap().to_string();
    let sig = auth["SHADENET_OPERATOR_SIG"].as_str().unwrap().to_string();
    assert_eq!(operator, "0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
    assert!(shadenet_proto::verify_operator_sig(&onion, &operator, &sig));
    assert_eq!(
        cli(state, &["authorize"], &[]).code,
        2,
        "authorize needs --onion and --key-file"
    );

    // check: the operator pair is verified against the minted onion; the stub RPC answers;
    // the derived env is printed with secrets redacted
    let sets = format!(
        "{}@{}",
        production["admission"]["roots"]["staked"]["contract"]
            .as_str()
            .unwrap(),
        production["admission"]["roots"]["staked"]["deployBlock"]
    );
    let check = cli(
        state,
        &["check", "--json"],
        &[
            ("SHADENET_RECORD", &record_arg),
            ("SHADENET_OPERATOR", &operator),
            ("SHADENET_OPERATOR_SIG", &sig),
            ("SHADENET_SETS", &sets),
        ],
    );
    let report: Value = serde_json::from_str(&check.out)
        .unwrap_or_else(|e| panic!("{e}: {} / {}", check.out, check.err));
    let text = findings_text(&report);
    assert!(text.contains("ok record sepolia-staging"), "{text}");
    assert!(
        text.contains(&format!("ok rpc {rpc_url}: chain 11155111, head 11816704")),
        "{text}"
    );
    assert!(text.contains("ok operator 0x7099"), "{text}");
    assert!(text.contains("authorised this onion"), "{text}");
    assert!(text.contains("ok proof artifact rln-"), "{text}");
    assert!(text.contains("GiB free"), "{text}");
    let failed = report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["level"] == "fail");
    assert_eq!(report["ok"], !failed);
    assert_eq!(check.code, if failed { 1 } else { 0 });
    assert_eq!(
        report["env"]["SHADE_TREE_GROUP_CONTRACT"],
        format!(
            "{},{}",
            staging["admission"]["roots"]["staked"]["contract"]
                .as_str()
                .unwrap(),
            production["admission"]["roots"]["staked"]["contract"]
                .as_str()
                .unwrap()
        ),
        "sets: the record's set first, then the extra one"
    );
    assert_eq!(report["env"]["SHADE_TREE_RPC_URL"], rpc_url);
    assert!(
        report["env"]["SHADE_TREE_GW_OPERATOR_SIG"]
            .as_str()
            .unwrap()
            .ends_with('…'),
        "secrets are redacted in the report"
    );
    assert_eq!(report["knobs"]["operator_sig"], "…");
    // a wrong signature is a FAIL finding
    let bad_sig = format!("0x{}", "11".repeat(65));
    let bad = cli(
        state,
        &["check", "--json"],
        &[
            ("SHADENET_RECORD", &record_arg),
            ("SHADENET_OPERATOR", &operator),
            ("SHADENET_OPERATOR_SIG", &bad_sig),
        ],
    );
    let bad: Value = serde_json::from_str(&bad.out).unwrap();
    assert!(findings_text(&bad).contains("fail operator_sig does not recover"));

    // node.toml is read from the state dir; env beats it; the plan prints the mapped knob
    std::fs::write(
        state.join("node.toml"),
        "[node]\nweight = 42\nregion = \"eu\"\n",
    )
    .unwrap();
    let toml = cli(
        state,
        &["check", "--json"],
        &[("SHADENET_RECORD", &record_arg), ("SHADENET_WEIGHT", "7")],
    );
    let toml: Value = serde_json::from_str(&toml.out).unwrap();
    assert_eq!(toml["env"]["SHADE_TREE_GW_WEIGHT"], "7");
    assert_eq!(toml["env"]["SHADE_TREE_GATEWAY_REGION"], "eu");
    assert!(findings_text(&toml).contains("node.toml read from"));
    std::fs::remove_file(state.join("node.toml")).unwrap();

    // the human report names the plan and says ready or not
    let human = cli(state, &["check"], &[("SHADENET_RECORD", &record_arg)]);
    assert!(human.out.contains("would run (cwd"), "{}", human.out);
    assert!(
        human.out.contains("result: ready to run") || human.out.contains("result: not ready"),
        "{}",
        human.out
    );

    // a retired record is refused as not joinable
    let retired = cli(
        state,
        &["check"],
        &[("SHADENET_RECORD", &retired_path.display().to_string())],
    );
    assert_eq!(retired.code, 1);
    assert!(retired.out.contains("not joinable"), "{}", retired.out);
    assert!(
        retired.out.contains("only live or staging"),
        "{}",
        retired.out
    );

    // a bad knob is a FAIL finding, not a crash
    let bad_knob = cli(
        state,
        &["check", "--json"],
        &[("SHADENET_RECORD", &record_arg), ("SHADENET_WEIGHT", "0")],
    );
    assert_eq!(bad_knob.code, 1);
    let bad_knob: Value = serde_json::from_str(&bad_knob.out).unwrap();
    assert!(findings_text(&bad_knob).contains("fail config: weight"));

    // status with nothing running: not running, exit 1 under --quiet
    assert_eq!(cli(state, &["status", "--quiet"], &[]).code, 1);
    let status: Value = serde_json::from_str(&cli(state, &["status"], &[]).out).unwrap();
    assert_eq!(status["running"], false);
    std::fs::write(
        state.join("status.json"),
        serde_json::json!({"stateDir": state, "onion": "x.onion", "pids": {}, "stoppedAt": "2026-10-01T00:00:00Z"}).to_string(),
    )
    .unwrap();
    assert_eq!(
        cli(state, &["status", "--quiet"], &[]).code,
        1,
        "a stopped node is not running"
    );

    // retire with nothing to retire says so
    let retire = cli(state, &["retire"], &[]);
    assert_eq!(retire.code, 1);
    assert!(retire.err.contains("nothing to retire"), "{}", retire.err);

    // unknown command
    let unknown = cli(state, &["frobnicate"], &[]);
    assert_eq!(unknown.code, 2);
    assert!(unknown.err.contains("SHADENET_RECORD"), "{}", unknown.err);
}
