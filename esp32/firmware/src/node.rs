//! The node on the device: the portable `microtor` + `shadenode` stack on ESP-IDF.
//!
//! Everything protocol-related lives in the portable crates and runs unchanged on a desktop
//! (`../crates/host`). This file supplies what a desktop gets for free: persistent keys in
//! NVS, the raw flash partition as scratch storage for directory refreshes, settings from the
//! serial console, and a status line with the numbers that matter on a device this small.

use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use esp_idf_svc::nvs::{EspDefaultNvsPartition, EspNvs, NvsDefault};
use microtor::circuit::turn;
use microtor::hs::{OnionService, ServiceConfig};
use microtor::hsdesc::parse_onion;
use microtor::netdir::now_unix;
use microtor::rt::{set_limits, Executor, Limits};
use microtor::tor::Tor;
use shadenode::canary::{CanaryConfig, DEFAULT_URLS};
use shadenode::chain::{ChainConfig, Http};
use shadenode::heartbeat::HeartbeatConfig;
use shadenode::node::{Node, NodeConfig};

use crate::platform;

/// Stack for a thread that runs one HTTPS request (the mbedTLS handshake is the deep part).
const HTTP_STACK: usize = 12 * 1024;
/// How often the staking contract's root is read. The `finalized` tag only moves once per
/// beacon epoch (6.4 minutes), so this is frequent enough and keeps TLS handshakes rare.
const ROOT_POLL: Duration = Duration::from_secs(30);

/// Flash sector size: the unit of erase.
const SECTOR: usize = 4096;
const STATUS_EVERY: Duration = Duration::from_secs(30);

/// The `scratch` partition as append-only record storage. Sectors are erased one at a time
/// as the write position reaches them, so a refresh never stalls the event loop on a
/// megabyte-sized erase.
struct FlashScratch {
    partition: platform::Scratch,
    page: Vec<u8>,
    flushed: usize,
}

impl FlashScratch {
    fn new(partition: platform::Scratch) -> Self {
        Self {
            partition,
            page: Vec::with_capacity(SECTOR),
            flushed: 0,
        }
    }

    fn flush(&mut self) -> microtor::Result<()> {
        if self.page.is_empty() {
            return Ok(());
        }
        let full = microtor::Error::Unavailable("scratch partition is full");
        if self.flushed + SECTOR > self.partition.len() {
            return Err(full);
        }
        let failed = |_| microtor::Error::Io(std::io::ErrorKind::Other);
        self.partition
            .erase_range(self.flushed, SECTOR)
            .map_err(failed)?;
        self.partition
            .write(self.flushed, &self.page)
            .map_err(failed)?;
        self.flushed += self.page.len();
        self.page.clear();
        Ok(())
    }
}

impl microtor::netdir::Scratch for FlashScratch {
    fn reset(&mut self) -> microtor::Result<()> {
        self.page.clear();
        self.flushed = 0;
        Ok(())
    }

    fn append(&mut self, record: &[u8]) -> microtor::Result<()> {
        // Records are 64 bytes, so a sector always fills exactly.
        self.page.extend_from_slice(record);
        if self.page.len() >= SECTOR {
            self.flush()?;
        }
        Ok(())
    }

    fn seal(&mut self) -> microtor::Result<()> {
        self.flush()
    }

    fn read(&mut self, offset: usize, buf: &mut [u8]) -> microtor::Result<()> {
        self.partition
            .read(offset, buf)
            .map_err(|_| microtor::Error::Io(std::io::ErrorKind::Other))
    }

    fn len(&self) -> usize {
        self.flushed + self.page.len()
    }
}

/// Settings and keys in the `shadenet` NVS namespace.
struct Store(EspNvs<NvsDefault>);

impl Store {
    fn open(nvs: &EspDefaultNvsPartition) -> Result<Self> {
        Ok(Self(
            EspNvs::new(nvs.clone(), platform::NVS_NAMESPACE, true)
                .context("open NVS namespace")?,
        ))
    }

    /// A 32-byte secret, created from the hardware RNG on first use.
    fn seed(&self, key: &str) -> Result<[u8; 32]> {
        let mut buf = [0u8; 32];
        if let Some(found) = self.0.get_blob(key, &mut buf)? {
            if found.len() == 32 {
                return Ok(buf);
            }
        }
        let seed: [u8; 32] = microtor::crypto::rand_array();
        self.0.set_blob(key, &seed)?;
        Ok(seed)
    }

    fn text(&self, key: &str) -> Option<String> {
        let len = self.0.str_len(key).ok().flatten()?;
        let mut buf = vec![0u8; len + 1];
        self.0
            .get_str(key, &mut buf)
            .ok()
            .flatten()
            .map(str::to_owned)
            .filter(|s| !s.is_empty())
    }

    fn list(&self, key: &str) -> Vec<String> {
        self.text(key)
            .map(|text| {
                text.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn number(&self, key: &str) -> Option<u64> {
        self.text(key)?.trim().parse().ok()
    }
}

pub struct Platform {
    pub wifi: platform::WifiStation,
    pub nvs: EspDefaultNvsPartition,
    pub scratch: platform::Scratch,
}

/// Run the node. Only returns on a configuration error; the caller keeps the radio alive.
pub fn run(mut platform: Platform) -> Result<()> {
    let store = Store::open(&platform.nvs)?;
    set_limits(Limits::SMALL);

    let mut config = NodeConfig::for_small_device();
    if let Some(epoch) = store.number("epoch") {
        config.epoch_seconds = epoch.max(1);
    }
    config.members = store.list("members");
    config.extra_roots = store.list("roots");
    if let Some(allow) = store.text("allow") {
        config.allow = allow;
    }
    if let Some(deny) = store.text("deny") {
        config.deny = deny;
    }
    if let Some(bandwidth) = store.number("bandwidth") {
        config.bandwidth = (bandwidth > 0).then_some(bandwidth);
    }
    if let Some(conns) = store.number("conns") {
        config.max_conns = conns.clamp(1, 8) as usize;
    }
    let off = |key: &str| {
        store
            .text(key)
            .is_some_and(|v| matches!(v.trim(), "0" | "off" | "false"))
    };
    let on = |key: &str| {
        store
            .text(key)
            .is_some_and(|v| matches!(v.trim(), "1" | "on" | "true"))
    };
    config.session_tickets = !off("sessions");
    config.receipts = on("receipts");
    let contract = store
        .text("contract")
        .map(|c| c.trim().to_ascii_lowercase());
    let rpc_urls = store.list("rpc");
    let slash_key = store
        .text("slash_key")
        .and_then(|k| microtor::util::hex_fixed::<32>(k.trim().trim_start_matches("0x")).ok());

    let elders: Vec<[u8; 32]> = store
        .list("elders")
        .iter()
        .filter_map(|onion| parse_onion(onion).ok())
        .collect();

    let identity_seed = store.seed("id_seed")?;
    let guard_seed = store.seed("guard_seed")?;

    let tor = Tor::new(Box::new(FlashScratch::new(platform.scratch)), guard_seed);
    let service = OnionService::new(
        tor.clone(),
        &identity_seed,
        ServiceConfig {
            intro_points: store
                .number("intro_points")
                .map_or(3, |n| n.clamp(1, 6) as usize),
            max_rendezvous: 4,
            accept_backlog: 4,
            peers: elders.clone(),
        },
    );
    let started = Instant::now();
    let node =
        Node::new(service.clone(), config).map_err(|e| anyhow!("node configuration: {e}"))?;
    println!(
        "NODE onion={} epoch_seconds={} roots={} members={} artifact={} key_prepare_ms={}",
        service.onion(),
        node.config().epoch_seconds,
        node.roots().len(),
        node.config().members.len(),
        node.artifact_ids().join(","),
        started.elapsed().as_millis(),
    );
    if node.roots().is_empty() && contract.is_none() {
        println!("NODE warning=\"no accepted roots: every proof will be refused; send: set members <leaf>[,<leaf>...] or set contract/rpc\"");
    }
    platform::log_heap("node_ready");
    node.start();

    let http: std::sync::Arc<dyn Http> = std::sync::Arc::new(crate::http::EspHttp);
    if let Some(contract) = &contract {
        if rpc_urls.is_empty() {
            println!("NODE warning=\"contract is set but rpc is not: on-chain roots are off\"");
        } else {
            println!(
                "NODE chain contract={contract} rpc_endpoints={} slash={}",
                rpc_urls.len(),
                if slash_key.is_some() {
                    "armed"
                } else {
                    "dry-run"
                }
            );
            node.start_chain(ChainConfig {
                http: http.clone(),
                rpc_urls: rpc_urls.clone(),
                contract: contract.clone(),
                block_tag: "finalized".into(),
                poll: ROOT_POLL,
                freshness: Duration::from_secs(node.config().epoch_seconds),
                slash_key,
                tiers: vec![8],
                thread_stack: HTTP_STACK,
                exclusive: true,
            });
        }
    }
    if on("canary") {
        node.start_canary(CanaryConfig {
            http: http.clone(),
            urls: DEFAULT_URLS.iter().map(|u| u.to_string()).collect(),
            interval: Duration::from_secs(600),
            thread_stack: HTTP_STACK,
            exclusive: true,
        });
    }

    if !elders.is_empty() {
        let operator = match (store.text("operator"), store.text("operator_sig")) {
            (Some(address), Some(signature)) => Some((address, signature)),
            _ => None,
        };
        let staked = contract.is_some() && !rpc_urls.is_empty();
        let mut admits = Vec::new();
        if !node.config().members.is_empty() {
            admits.push("invited".to_string());
        }
        if staked {
            admits.push("staked".to_string());
        }
        println!(
            "NODE heartbeat elders={} operator={} admits={}",
            elders.len(),
            operator.as_ref().map_or("none", |(a, _)| a.as_str()),
            admits.join("+")
        );
        node.start_heartbeat(HeartbeatConfig {
            elders,
            interval: Duration::from_secs(300),
            weight: store.number("weight").unwrap_or(10),
            operator,
            region: store.text("region"),
            admits,
            sets: if staked {
                contract.iter().cloned().collect()
            } else {
                Vec::new()
            },
            root_freshness_seconds: node.config().epoch_seconds,
        });
    }

    let mut exec = Executor::new();
    let mut last_status = Instant::now();
    let mut last_wifi_check = Instant::now();
    let mut announced = false;
    loop {
        turn(tor.core(), &mut exec);
        if last_wifi_check.elapsed() >= Duration::from_secs(5) {
            last_wifi_check = Instant::now();
            node.set_draining(platform::DRAIN.load(core::sync::atomic::Ordering::Relaxed));
            if !platform.wifi.is_connected() {
                // The Tor link notices on its own and reconnects once the network is back.
                match platform.wifi.reconnect() {
                    Ok(_) => println!("WIFI state=reconnected"),
                    Err(error) => println!("WIFI state=reconnect_failed msg=\"{error:#}\""),
                }
            }
        }
        if !announced && service.is_published() {
            announced = true;
            println!(
                "NODE state=published onion={} uptime_s={}",
                service.onion(),
                started.elapsed().as_secs()
            );
        }
        if last_status.elapsed() >= STATUS_EVERY {
            last_status = Instant::now();
            let stats = node.stats();
            let svc = service.stats();
            println!(
                "STATUS uptime_s={} unix={} wifi={} intro_points={} circuits={} tunnels={} admitted={} refused={} bytes_up={} bytes_down={} verify_ms={} rendezvous={} publishes={} refreshes={} roots={} sessions={} tickets={} draining={} heap_free={} heap_largest={} heap_min={} stack_free_min={}",
                started.elapsed().as_secs(),
                now_unix(),
                platform.wifi.is_connected() as u8,
                service.intro_count(),
                tor.core().borrow().circuit_count(),
                stats.tunnels_open,
                stats.admitted,
                stats.refused,
                stats.bytes_up,
                stats.bytes_down,
                stats.verify_ms_last,
                svc.rendezvous_ok,
                svc.publishes,
                svc.refreshes,
                node.roots().len(),
                stats.sessions_opened,
                stats.tickets_spent,
                node.is_draining() as u8,
                platform::heap_free(),
                platform::heap_largest(),
                platform::heap_min_free(),
                platform::stack_high_water(),
            );
        }
    }
}
