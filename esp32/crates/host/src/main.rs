//! shadenode-host: the device firmware's protocol stack as a desktop process.
//!
//! Same crates, same event loop, same limits if asked (`--small`). Only the platform differs:
//! std sockets and files instead of lwIP and flash.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use std::sync::Arc;

use microtor::circuit::turn;
use microtor::hs::{OnionService, ServiceConfig};
use microtor::hsdesc::parse_onion;
use microtor::netdir::MemScratch;
use microtor::rt::Executor;
use microtor::tor::Tor;
use microtor::util::{hex_encode, hex_fixed};
use shadenode::canary::{CanaryConfig, DEFAULT_URLS};
use shadenode::chain::{ChainConfig, Http};
use shadenode::heartbeat::HeartbeatConfig;
use shadenode::node::{Node, NodeConfig};

struct Stderr(Instant);

impl log::Log for Stderr {
    fn enabled(&self, _: &log::Metadata) -> bool {
        true
    }
    fn log(&self, record: &log::Record) {
        eprintln!(
            "[{:>9.3}] {:<5} {}",
            self.0.elapsed().as_secs_f64(),
            record.level(),
            record.args()
        );
    }
    fn flush(&self) {}
}

/// HTTPS through ureq (rustls, system-independent root store).
struct UreqHttp;

impl Http for UreqHttp {
    fn post_json(&self, url: &str, body: &str) -> Result<String, String> {
        match ureq::post(url)
            .timeout(Duration::from_secs(15))
            .set("Content-Type", "application/json")
            .send_string(body)
        {
            Ok(response) => response.into_string().map_err(|e| e.to_string()),
            Err(ureq::Error::Status(code, _)) => Err(format!("HTTP {code}")),
            Err(e) => Err(e.to_string()),
        }
    }

    fn get_status(&self, url: &str) -> Result<(u16, bool), String> {
        match ureq::get(url).timeout(Duration::from_secs(20)).call() {
            Ok(response) => Ok((response.status(), response.header("cf-mitigated").is_some())),
            Err(ureq::Error::Status(code, response)) => {
                Ok((code, response.header("cf-mitigated").is_some()))
            }
            Err(e) => Err(e.to_string()),
        }
    }
}

const USAGE: &str = "\
shadenode-host: run the ShadeNet ESP32 node's protocol stack on this machine

USAGE:
  shadenode-host --state DIR [options]

OPTIONS:
  --state DIR            where the onion identity seed and guard seed live (created if absent)
  --members FILE         invited member set: JSON {\"members\": [\"<leaf>\", ...]}
  --root DECIMAL         an additional accepted root (repeatable)
  --epoch-seconds N      RLN epoch length (default 60; clients pinned with --members use 120)
  --allow LIST           egress allow list (default *:443)
  --deny LIST            egress deny list
  --allow-private        permit private and loopback targets (testing only)
  --small                use the ESP32's limits (4 tunnels, 8 KiB envelopes, small stacks)
  --intro-points N       introduction points (default 3)
  --contract ADDRESS     staking contract whose root is admitted (with --rpc)
  --rpc URL[,URL]        JSON-RPC endpoints for the contract
  --slash-key-file FILE  hex secp256k1 key that signs slashes (default: dry run)
  --elder ONION          Elder Tree to announce to (repeatable)
  --operator ADDRESS     bonded operator address, with --operator-sig
  --operator-sig HEX     its signature over the authorization message
  --weight N             selection weight to announce (default 10)
  --bandwidth BYTES      bytes per second across all tunnels
  --canary               run the reputation canary
  --receipts             attach signed receipts to acknowledgements
  --no-sessions          do not serve session tickets
  -v                     debug logging
";

/// Load a 32-byte seed from `path`, creating it with fresh randomness on first use.
fn seed_file(path: &Path) -> [u8; 32] {
    if let Ok(text) = std::fs::read_to_string(path) {
        return hex_fixed(text.trim())
            .unwrap_or_else(|_| panic!("{} is not 64 hex chars", path.display()));
    }
    let seed: [u8; 32] = microtor::crypto::rand_array();
    std::fs::write(path, format!("{}\n", hex_encode(&seed))).expect("write seed file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    seed
}

fn main() {
    let mut state: Option<PathBuf> = None;
    let mut config = NodeConfig::default();
    let mut small = false;
    let mut verbose = false;
    let mut intro_points = 3;
    let mut members_file: Option<PathBuf> = None;
    let mut contract: Option<String> = None;
    let mut rpc_urls: Vec<String> = Vec::new();
    let mut slash_key: Option<[u8; 32]> = None;
    let mut elders: Vec<[u8; 32]> = Vec::new();
    let mut operator: Option<String> = None;
    let mut operator_sig: Option<String> = None;
    let mut weight = 10u64;
    let mut canary = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |name: &str| {
            args.next()
                .unwrap_or_else(|| panic!("{name} needs a value"))
        };
        match arg.as_str() {
            "--state" => state = Some(value("--state").into()),
            "--members" => members_file = Some(value("--members").into()),
            "--root" => config.extra_roots.push(value("--root")),
            "--epoch-seconds" => {
                config.epoch_seconds = value("--epoch-seconds").parse().expect("number")
            }
            "--allow" => config.allow = value("--allow"),
            "--deny" => config.deny = value("--deny"),
            "--allow-private" => config.allow_private_targets = true,
            "--small" => small = true,
            "--intro-points" => intro_points = value("--intro-points").parse().expect("number"),
            "--contract" => contract = Some(value("--contract").to_ascii_lowercase()),
            "--rpc" => rpc_urls = value("--rpc").split(',').map(str::to_string).collect(),
            "--slash-key-file" => {
                let text = std::fs::read_to_string(value("--slash-key-file"))
                    .expect("read slash key file");
                slash_key = Some(
                    hex_fixed(text.trim().trim_start_matches("0x"))
                        .expect("slash key is 64 hex chars"),
                );
            }
            "--elder" => {
                elders.push(parse_onion(&value("--elder")).expect("elder is a v3 onion address"))
            }
            "--operator" => operator = Some(value("--operator")),
            "--operator-sig" => operator_sig = Some(value("--operator-sig")),
            "--weight" => weight = value("--weight").parse().expect("number"),
            "--bandwidth" => config.bandwidth = Some(value("--bandwidth").parse().expect("number")),
            "--canary" => canary = true,
            "--receipts" => config.receipts = true,
            "--no-sessions" => config.session_tickets = false,
            "-v" => verbose = true,
            "-h" | "--help" => {
                print!("{USAGE}");
                return;
            }
            other => {
                eprintln!("unknown argument {other}\n\n{USAGE}");
                std::process::exit(2);
            }
        }
    }
    let Some(state) = state else {
        eprintln!("{USAGE}");
        std::process::exit(2);
    };
    let logger: &'static Stderr = Box::leak(Box::new(Stderr(Instant::now())));
    log::set_logger(logger).ok();
    log::set_max_level(if verbose {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    });

    if small {
        microtor::rt::set_limits(microtor::rt::Limits::SMALL);
        let device = NodeConfig::for_small_device();
        config.max_conns = device.max_conns;
        config.max_conns_per_nullifier = device.max_conns_per_nullifier;
        config.max_envelope_bytes = device.max_envelope_bytes;
        config.spent_capacity = device.spent_capacity;
        config.session_max = device.session_max;
    }
    if let Some(path) = &members_file {
        let text = std::fs::read_to_string(path).expect("read members file");
        let json: serde_json::Value = serde_json::from_str(&text).expect("members file is JSON");
        config.members = json["members"]
            .as_array()
            .expect("members file has a `members` array")
            .iter()
            .map(|m| m.as_str().expect("members are strings").to_string())
            .collect();
    }

    std::fs::create_dir_all(&state).expect("create state directory");
    let identity_seed = seed_file(&state.join("identity.seed"));
    let guard_seed = seed_file(&state.join("guard.seed"));

    let tor = Tor::new(Box::<MemScratch>::default(), guard_seed);
    let service = OnionService::new(
        tor.clone(),
        &identity_seed,
        ServiceConfig {
            intro_points,
            peers: elders.clone(),
            ..ServiceConfig::default()
        },
    );
    let node = Node::new(service.clone(), config).expect("node configuration");
    println!("onion: {}", service.onion());
    for root in node.roots() {
        println!("accepted root: {root}");
    }
    println!("artifact: {}", node.artifact_ids().join(","));
    println!("epoch: {} s", node.config().epoch_seconds);
    node.start();

    let http: Arc<dyn Http> = Arc::new(UreqHttp);
    if let Some(contract) = &contract {
        assert!(!rpc_urls.is_empty(), "--contract needs --rpc");
        node.start_chain(ChainConfig {
            http: http.clone(),
            rpc_urls: rpc_urls.clone(),
            contract: contract.clone(),
            block_tag: "finalized".into(),
            poll: Duration::from_secs(12),
            freshness: Duration::from_secs(node.config().epoch_seconds),
            slash_key,
            tiers: vec![8],
            thread_stack: 1024 * 1024,
            exclusive: false,
        });
    }
    if canary {
        node.start_canary(CanaryConfig {
            http: http.clone(),
            urls: DEFAULT_URLS.iter().map(|u| u.to_string()).collect(),
            interval: Duration::from_secs(600),
            thread_stack: 1024 * 1024,
            exclusive: false,
        });
    }
    if !elders.is_empty() {
        node.start_heartbeat(HeartbeatConfig {
            elders,
            interval: Duration::from_secs(300),
            weight,
            operator: operator.zip(operator_sig),
            region: None,
            admits: if contract.is_some() {
                vec!["staked".into()]
            } else {
                vec!["invited".into()]
            },
            sets: contract.iter().cloned().collect(),
            root_freshness_seconds: node.config().epoch_seconds,
        });
    }

    let mut exec = Executor::new();
    let mut announced = false;
    let mut last_report = Instant::now();
    loop {
        turn(tor.core(), &mut exec);
        if service.is_published() && !announced {
            announced = true;
            println!("ready: {}", service.onion());
        }
        if last_report.elapsed() > Duration::from_secs(60) {
            last_report = Instant::now();
            log::info!(
                "intro points {}, circuits {}, node {:?}, service {:?}",
                service.intro_count(),
                tor.core().borrow().circuit_count(),
                node.stats(),
                service.stats()
            );
        }
    }
}
