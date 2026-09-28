//! Commands that need no Tor, prover or chain: canopy verification, cached canopy fetch, node
//! selection and receipt verification. They are in every build.

use std::collections::HashSet;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Args;
use serde::Deserialize;
use shadenet::capability::{self, Admission, Requirement};
use shadenet::{dircache, health};
use shadenet_proto::{pick_gateway, selection_order, Receipt};

use crate::net::Context;

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn read_file(path: &PathBuf) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))
}

#[derive(Args, Debug)]
pub struct VerifyDirectoryArgs {
    /// Signed canopy JSON
    pub file: PathBuf,
    /// Pinned signer(s), comma-separated hex
    #[arg(long, alias = "signers")]
    pub signer: String,
}

pub fn verify_directory(args: VerifyDirectoryArgs) -> ExitCode {
    let raw = match read_file(&args.file) {
        Ok(raw) => raw,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    match dircache::parse_and_verify_document(&raw, &args.signer) {
        Ok(document) => {
            println!("ok");
            if let Some(threshold) = document.dir.threshold {
                println!("threshold: {threshold}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("not-ok: {e}");
            ExitCode::from(1)
        }
    }
}

#[derive(Args, Debug)]
pub struct FetchDirectoryArgs {
    #[arg(long, alias = "signers")]
    pub signer: String,
    /// Last-known-good cache file
    #[arg(long)]
    pub cache: Option<PathBuf>,
    #[arg(long)]
    pub max_age_ms: Option<u64>,
    #[arg(long, default_value_t = 5 * 60 * 1000)]
    pub max_age_skew_ms: u64,
    /// Read the fresh canopy from this file
    #[arg(long, conflicts_with = "bootnode_tcp")]
    pub file: Option<PathBuf>,
    /// Fetch the fresh canopy over plain HTTP from host:port (tests)
    #[arg(long)]
    pub bootnode_tcp: Option<String>,
    #[arg(long, default_value = "/directory")]
    pub path: String,
}

pub fn fetch_directory(args: FetchDirectoryArgs) -> ExitCode {
    let fresh = if let Some(file) = &args.file {
        read_file(file)
    } else if let Some(hp) = &args.bootnode_tcp {
        let host = hp.split(':').next().unwrap_or("127.0.0.1").to_string();
        dircache::fetch_http_plain(hp, &host, &args.path)
    } else {
        eprintln!("fetch-directory: need a source: --file <f> or --bootnode-tcp <host:port>. Over Tor, use `shadenet status`.");
        return ExitCode::from(2);
    };
    let max_age = dircache::MaxAge {
        max_age_ms: args.max_age_ms,
        skew_ms: args.max_age_skew_ms,
    };
    match dircache::resolve_directory(
        fresh,
        args.cache.as_deref(),
        &args.signer,
        max_age,
        now_ms(),
    ) {
        Ok(out) => {
            println!("ok");
            println!(
                "source: {}",
                match out.source {
                    dircache::Source::Fresh => "fresh",
                    dircache::Source::Cache => "cache",
                }
            );
            if let Some(fe) = out.fresh_error {
                println!("fresh-error: {fe}");
            }
            println!("issued: {}", out.dir.issued);
            println!("gateways: {}", out.dir.gateways.len());
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("not-ok: {e}");
            ExitCode::from(1)
        }
    }
}

#[derive(Args, Debug)]
pub struct SelectArgs {
    /// Signed canopy JSON
    pub file: PathBuf,
    #[arg(long, alias = "signers")]
    pub signer: String,
    /// Seed for a reproducible pick
    #[arg(long)]
    pub seed: Option<u32>,
    #[arg(long)]
    pub health_cache: Option<PathBuf>,
    #[arg(long)]
    pub port: Option<u64>,
    #[arg(long)]
    pub proto: Option<u64>,
    #[arg(long)]
    pub region: Option<String>,
    /// invited, staked, paid or demo [env: SHADENET_LEAF_SOURCE]
    #[arg(long)]
    pub leaf_source: Option<String>,
    /// Invited-only nodes [env: SHADENET_MAX_ANON]
    #[arg(long)]
    pub max_anon: bool,
}

fn mulberry32(seed: u32) -> impl FnMut() -> f64 {
    let mut a = seed;
    move || {
        a = a.wrapping_add(0x6D2B_79F5);
        let mut t = a;
        t = (t ^ (t >> 15)).wrapping_mul(t | 1);
        t ^= t.wrapping_add((t ^ (t >> 7)).wrapping_mul(t | 61));
        (((t ^ (t >> 14)) as f64) / 4_294_967_296.0).fract()
    }
}

fn default_seed() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0x1234_5678)
}

pub fn select(args: SelectArgs, _ctx: &Context) -> ExitCode {
    let seed = args.seed.unwrap_or_else(default_seed);
    let raw = match read_file(&args.file) {
        Ok(raw) => raw,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let document = match dircache::parse_and_verify_document(&raw, &args.signer) {
        Ok(d) => d,
        Err(e) => {
            println!("not-ok: {e}");
            return ExitCode::from(1);
        }
    };
    let demo = document.demo;
    let mut dir = document.dir;
    if let Some(path) = &args.health_cache {
        let mut cache = health::load(Some(path));
        health::seed(&mut dir, &mut cache, now_ms());
    }
    let req = Requirement {
        port: args.port,
        proto: args.proto,
        region: args.region.clone(),
    };
    if req.is_active() {
        capability::filter_by_capability(&mut dir.gateways, &req);
        if dir.gateways.is_empty() {
            println!(
                "not-ok: no gateway meets capability requirement: {}",
                req.describe()
            );
            return ExitCode::from(1);
        }
    }
    let env_source = shadenet::env::var_lenient("LEAF_SOURCE")
        .filter(|s| !s.trim().is_empty() && s.trim() != "auto");
    let env_max = shadenet::env::flag("MAX_ANON") == Some(true);
    let adm = Admission {
        leaf_source: args
            .leaf_source
            .clone()
            .or(env_source)
            .map(|s| s.trim().to_ascii_lowercase()),
        max_anon: args.max_anon || env_max,
    };
    if let Err(e) = capability::check_admission(&adm) {
        println!("not-ok: {e}");
        return ExitCode::from(1);
    }
    if adm.is_active() {
        let before = dir.gateways.clone();
        capability::filter_by_admission_with_demo(
            &mut dir.gateways,
            &adm,
            demo.as_ref().map(|d| d.gateways.as_slice()),
        );
        if dir.gateways.is_empty() {
            println!("not-ok: {}", capability::admission_refusal(&adm, &before));
            return ExitCode::from(1);
        }
    }
    let mut rng = mulberry32(seed);
    let empty = HashSet::new();
    let Some(chosen) = pick_gateway(&dir, &empty, &mut rng) else {
        println!("not-ok: no-gateways");
        return ExitCode::from(1);
    };
    println!("ok");
    println!("chosen: {}", chosen.onion);
    let mut rng2 = mulberry32(seed);
    let order = selection_order(&dir, &mut rng2);
    println!("failover-order:");
    for (i, g) in order.iter().enumerate() {
        println!("  {}. {}", i + 1, g.onion);
    }
    ExitCode::SUCCESS
}

#[derive(Args, Debug)]
pub struct VerifyReceiptArgs {
    /// Receipt JSON
    pub file: PathBuf,
    /// Onion the receipt must be bound to
    #[arg(long)]
    pub onion: String,
}

#[derive(Deserialize)]
struct ReceiptDto {
    v: u64,
    onion: String,
    // A canonical decimal string on the wire; a number is a malformed receipt.
    epoch: String,
    ok: bool,
    #[serde(default)]
    sig: Option<String>,
}

pub fn verify_receipt(args: VerifyReceiptArgs) -> ExitCode {
    let raw = match read_file(&args.file) {
        Ok(raw) => raw,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let dto: ReceiptDto = match serde_json::from_str(&raw) {
        Ok(d) => d,
        Err(e) => {
            println!("not-ok: parse: {e}");
            return ExitCode::from(1);
        }
    };
    let receipt = Receipt {
        v: dto.v,
        onion: dto.onion,
        epoch: dto.epoch,
        ok: dto.ok,
        sig: dto.sig,
    };
    // An offline receipt has no live epoch: check the onion binding and signature only.
    match shadenet_proto::verify_receipt(&receipt, Some(&args.onion), None, 1) {
        Ok(v) => {
            println!("ok");
            println!("onion: {}", v.onion);
            println!("pubkey: {}", hex::encode(v.pubkey));
            println!("epoch: {}", v.epoch);
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("not-ok: {e}");
            ExitCode::from(1)
        }
    }
}
