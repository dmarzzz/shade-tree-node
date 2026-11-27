//! The network view: fetch and verify a consensus, pick a guard and a small relay pool, and
//! locate hidden-service directories on the hash ring.
//!
//! A full Tor client keeps every relay in memory. This one keeps about thirty. The consensus is
//! parsed as a stream; relays that carry the HSDir flag are written to scratch storage (flash
//! on the device) so their microdescriptors can be fetched in a second pass, and only the ring
//! positions that matter are remembered.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::circuit::{Circuit, RelayInfo};
use crate::crypto::{rand_unit, sha256, sha3_256};
use crate::dir::{
    dir_get, flag, verify_consensus, AuthCert, AuthCertParser, ConsensusMeta, ConsensusParser,
    Microdesc, MicrodescParser, RouterEntry, ROUTER_RECORD_LEN,
};
use crate::util::b64_encode;
use crate::{Error, Result};

/// Microdescriptors requested per directory fetch (Tor serves up to 92).
const MD_BATCH: usize = 90;
const GUARD_CANDIDATES: usize = 8;
const POOL_SIZE: usize = 24;

// ---------------------------------------------------------------------------------------------
// Clock

static CLOCK_BASE: std::sync::Mutex<Option<(u64, Instant)>> = std::sync::Mutex::new(None);

/// Unix time. Uses the system clock unless [`set_clock`] installed a network-derived time
/// (a device with no RTC and no SNTP learns the time from a relay's NETINFO cell).
pub fn now_unix() -> u64 {
    if let Some((base, at)) = *CLOCK_BASE.lock().unwrap() {
        return base + at.elapsed().as_secs();
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub fn set_clock(unix: u64) {
    *CLOCK_BASE.lock().unwrap() = Some((unix, Instant::now()));
}

/// Whether the system clock looks set at all (after 2025-01-01).
pub fn clock_is_plausible() -> bool {
    now_unix() > 1_735_689_600
}

// ---------------------------------------------------------------------------------------------
// Scratch storage

/// Append-only record storage that survives one directory refresh. RAM on a host, a raw flash
/// partition on the device.
pub trait Scratch {
    /// Discard everything.
    fn reset(&mut self) -> Result<()>;
    fn append(&mut self, record: &[u8]) -> Result<()>;
    /// Make appended records readable (flush any write buffer).
    fn seal(&mut self) -> Result<()>;
    fn read(&mut self, offset: usize, buf: &mut [u8]) -> Result<()>;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Default)]
pub struct MemScratch(Vec<u8>);

impl Scratch for MemScratch {
    fn reset(&mut self) -> Result<()> {
        self.0.clear();
        Ok(())
    }
    fn append(&mut self, record: &[u8]) -> Result<()> {
        self.0.extend_from_slice(record);
        Ok(())
    }
    fn seal(&mut self) -> Result<()> {
        Ok(())
    }
    fn read(&mut self, offset: usize, buf: &mut [u8]) -> Result<()> {
        let src = self
            .0
            .get(offset..offset + buf.len())
            .ok_or(Error::Parse("scratch read out of range"))?;
        buf.copy_from_slice(src);
        Ok(())
    }
    fn len(&self) -> usize {
        self.0.len()
    }
}

// ---------------------------------------------------------------------------------------------
// Onion-service time periods and the HSDir ring

/// The two (time period, shared random value) pairs a service publishes under at any moment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HsPeriods {
    /// Time period length in minutes.
    pub length: u64,
    /// `[first descriptor, second descriptor]`: period number and SRV.
    pub pairs: [(u64, [u8; 32]); 2],
    /// Which pair a client uses to fetch right now.
    pub fetch: usize,
}

fn disaster_srv(length: u64, period: u64) -> [u8; 32] {
    sha3_256(&[
        b"shared-random-disaster",
        &length.to_be_bytes(),
        &period.to_be_bytes(),
    ])
}

impl ConsensusMeta {
    /// rend-spec-v3 2.2.1 and 2.2.4: periods rotate at 12:00 UTC, shared random values at
    /// 00:00 UTC, and which pair is "current" depends on which rotation came last.
    pub fn hs_periods(&self) -> HsPeriods {
        let length = self.hsdir_interval;
        // Time periods are offset by twelve voting rounds (twelve hours).
        let offset_minutes = 12 * 60;
        let period_of = |unix: u64| (unix / 60).saturating_sub(offset_minutes) / length;
        let now_period = period_of(self.valid_after);
        let srv_start = self.valid_after - self.valid_after % 86_400;
        let next_period_start = (period_of(srv_start) + 1) * length * 60 + offset_minutes * 60;
        let between_srv_and_period =
            self.valid_after >= srv_start && self.valid_after < next_period_start;
        let (first, second, fetch) = if between_srv_and_period {
            (now_period, now_period + 1, 0)
        } else {
            (now_period.saturating_sub(1), now_period, 1)
        };
        HsPeriods {
            length,
            pairs: [
                (
                    first,
                    self.srv_previous
                        .unwrap_or_else(|| disaster_srv(length, first)),
                ),
                (
                    second,
                    self.srv_current
                        .unwrap_or_else(|| disaster_srv(length, second)),
                ),
            ],
            fetch,
        }
    }
}

/// Where on the ring a descriptor for `blinded_key` is stored (`replica` counts from 1).
pub fn hs_service_index(blinded_key: &[u8; 32], replica: u8, period: u64, length: u64) -> [u8; 32] {
    sha3_256(&[
        b"store-at-idx",
        blinded_key,
        &u64::from(replica).to_be_bytes(),
        &length.to_be_bytes(),
        &period.to_be_bytes(),
    ])
}

fn hs_relay_index(ed_id: &[u8; 32], srv: &[u8; 32], period: u64, length: u64) -> [u8; 32] {
    sha3_256(&[
        b"node-idx",
        ed_id,
        srv,
        &period.to_be_bytes(),
        &length.to_be_bytes(),
    ])
}

/// `a - b` modulo 2^256, big-endian: how far clockwise `a` is from `b`.
fn ring_distance(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = i16::from(a[i]) - i16::from(b[i]) - borrow;
        out[i] = d.rem_euclid(256) as u8;
        borrow = i16::from(d < 0);
    }
    out
}

/// A question for the ring: which directories follow `target`?
pub struct RingQuery {
    /// Index into [`HsPeriods::pairs`].
    pub pair: usize,
    pub target: [u8; 32],
    pub keep: usize,
    found: Vec<([u8; 32], RelayInfo)>,
}

impl RingQuery {
    pub fn new(pair: usize, target: [u8; 32], keep: usize) -> Self {
        Self {
            pair,
            target,
            keep,
            found: Vec::with_capacity(keep + 1),
        }
    }

    fn offer(&mut self, index: &[u8; 32], relay: &RelayInfo) {
        let distance = ring_distance(index, &self.target);
        if self.found.len() == self.keep && distance >= self.found[self.keep - 1].0 {
            return;
        }
        let pos = self.found.partition_point(|(d, _)| *d < distance);
        self.found.insert(pos, (distance, relay.clone()));
        self.found.truncate(self.keep);
    }

    /// The directories responsible for the target, nearest first.
    pub fn relays(&self) -> impl Iterator<Item = &RelayInfo> {
        self.found.iter().map(|(_, r)| r)
    }
}

// ---------------------------------------------------------------------------------------------
// Relay selection

/// Weighted sampling without replacement (Efraimidis-Spirakis): keep the `k` largest
/// `ln(u) / weight`.
struct Reservoir {
    k: usize,
    items: Vec<(f64, RouterEntry)>,
}

impl Reservoir {
    fn new(k: usize) -> Self {
        Self {
            k,
            items: Vec::with_capacity(k),
        }
    }

    fn offer(&mut self, unit: f64, entry: &RouterEntry) {
        let weight = f64::from(entry.bandwidth.max(1));
        let key = unit.ln() / weight;
        if self.items.len() < self.k {
            self.items.push((key, entry.clone()));
        } else if let Some(min) = self
            .items
            .iter_mut()
            .min_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(core::cmp::Ordering::Equal))
        {
            if key > min.0 {
                *min = (key, entry.clone());
            }
        }
    }

    fn into_sorted(mut self) -> Vec<RouterEntry> {
        self.items
            .sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(core::cmp::Ordering::Equal));
        self.items.into_iter().map(|(_, e)| e).collect()
    }
}

fn has(flags: u16, wanted: u16) -> bool {
    flags & wanted == wanted
}

const GUARD_FLAGS: u16 =
    flag::GUARD | flag::FAST | flag::STABLE | flag::RUNNING | flag::VALID | flag::V2DIR;
const POOL_FLAGS: u16 = flag::FAST | flag::STABLE | flag::RUNNING | flag::VALID;
const HSDIR_FLAGS: u16 = flag::HSDIR | flag::RUNNING | flag::VALID;

#[derive(Clone, Debug)]
pub struct Relay {
    pub info: RelayInfo,
    pub flags: u16,
}

/// What the client remembers of a consensus.
pub struct NetDir {
    pub meta: ConsensusMeta,
    /// Guard candidates in preference order. The order is a keyed function of the relay
    /// identity, so a device keeps choosing the same guard across refreshes.
    pub guards: Vec<RelayInfo>,
    /// A bandwidth-weighted sample of stable, fast relays for middle hops and
    /// introduction points.
    pub pool: Vec<Relay>,
    pub hsdirs: u32,
    pub fetched: Instant,
    pub wire_bytes: usize,
}

impl NetDir {
    /// A random pool relay that is not one of `exclude` and not in the same /16 as any.
    pub fn pick(&self, exclude: &[&RelayInfo]) -> Result<RelayInfo> {
        let ok = |r: &&Relay| {
            exclude.iter().all(|e| {
                e.rsa_id != r.info.rsa_id
                    && e.addr.ip().octets()[..2] != r.info.addr.ip().octets()[..2]
            })
        };
        let candidates: Vec<&Relay> = self.pool.iter().filter(ok).collect();
        if candidates.is_empty() {
            return Err(Error::Unavailable("no usable relay in the pool"));
        }
        let i = (crate::crypto::rand_u32() as usize) % candidates.len();
        Ok(candidates[i].info.clone())
    }

    /// Past `fresh-until`: time to fetch the next consensus.
    pub fn is_stale(&self) -> bool {
        now_unix() > self.meta.fresh_until
    }
}

fn md_path(digests: &[[u8; 32]]) -> String {
    let mut path = String::with_capacity(14 + digests.len() * 44);
    path.push_str("/tor/micro/d/");
    for (i, d) in digests.iter().enumerate() {
        if i > 0 {
            path.push('-');
        }
        path.push_str(&b64_encode(d, false));
    }
    path
}

async fn fetch_microdescs(
    circ: &Circuit,
    digests: &[[u8; 32]],
    on_md: &mut dyn FnMut(Microdesc),
) -> Result<usize> {
    let mut parser = MicrodescParser::new();
    let bytes = dir_get(circ, &md_path(digests), &mut |chunk| {
        parser.feed(chunk, on_md);
        Ok(())
    })
    .await?;
    parser.finish(on_md);
    Ok(bytes)
}

fn complete(entry: &RouterEntry, md: &Microdesc) -> Option<RelayInfo> {
    Some(RelayInfo {
        rsa_id: entry.rsa_id,
        ed_id: Some(md.ed_id?),
        ntor_key: md.ntor_key?,
        addr: entry.addr,
    })
}

/// Fetch authority certificates over `circ`.
pub async fn fetch_certs(circ: &Circuit) -> Result<Vec<AuthCert>> {
    let mut parser = AuthCertParser::new(now_unix());
    dir_get(circ, "/tor/keys/all", &mut |chunk| parser.feed(chunk)).await?;
    if parser.certs.len() <= crate::bootstrap_data::AUTHORITIES.len() / 2 {
        return Err(Error::Proto("too few valid authority certificates"));
    }
    log::info!("{} authority certificates verified", parser.certs.len());
    Ok(parser.certs)
}

/// Download and verify a consensus over the directory circuit `circ`, sample relays, and
/// answer the ring queries that `make_queries` builds once the consensus header is known.
pub async fn fetch_netdir(
    circ: &Circuit,
    certs: &[AuthCert],
    scratch: &mut dyn Scratch,
    guard_seed: &[u8; 32],
    make_queries: &mut dyn FnMut(&ConsensusMeta) -> Vec<RingQuery>,
) -> Result<(NetDir, Vec<RingQuery>)> {
    let _heavy = crate::rt::heavy().await;
    let started = Instant::now();
    scratch.reset()?;
    let mut parser = ConsensusParser::new();
    let mut guards = Reservoir::new(GUARD_CANDIDATES);
    let mut pool = Reservoir::new(POOL_SIZE);
    let mut hsdirs = 0u32;
    let mut scratch_error = None;

    let mut wire_bytes = dir_get(
        circ,
        "/tor/status-vote/current/consensus-microdesc",
        &mut |chunk| {
            parser.feed(chunk, &mut |entry| {
                if has(entry.flags, GUARD_FLAGS) {
                    // A fixed pseudo-random draw per relay keeps the guard choice stable.
                    let h = sha256(&[guard_seed, &entry.rsa_id]);
                    let draw = u64::from_be_bytes(h[..8].try_into().unwrap()) >> 11;
                    guards.offer((draw as f64 + 1.0) / (1u64 << 53) as f64, entry);
                }
                if has(entry.flags, POOL_FLAGS) {
                    pool.offer(rand_unit(), entry);
                }
                if has(entry.flags, HSDIR_FLAGS) {
                    hsdirs += 1;
                    if let Err(e) = scratch.append(&entry.to_record()) {
                        scratch_error.get_or_insert(e);
                    }
                }
            })
        },
    )
    .await?;
    if let Some(e) = scratch_error {
        return Err(e);
    }
    scratch.seal()?;
    verify_consensus(&parser, certs, now_unix())?;
    let meta = parser.meta.clone();
    drop(parser);
    log::info!(
        "consensus valid-after {} with {} relays, {} hsdirs ({} KB on the wire, {:?})",
        meta.valid_after,
        meta.relays,
        hsdirs,
        wire_bytes / 1024,
        started.elapsed()
    );

    // Microdescriptors for the sampled relays: ntor keys and ed25519 identities.
    let guard_entries = guards.into_sorted();
    let pool_entries = pool.into_sorted();
    let mut sampled: Vec<(RouterEntry, Option<RelayInfo>)> = guard_entries
        .iter()
        .chain(pool_entries.iter())
        .map(|e| (e.clone(), None))
        .collect();
    let digests: Vec<[u8; 32]> = sampled.iter().map(|(e, _)| e.md_digest).collect();
    for batch in digests.chunks(MD_BATCH) {
        wire_bytes += fetch_microdescs(circ, batch, &mut |md| {
            for (entry, info) in sampled.iter_mut().filter(|(e, _)| e.md_digest == md.digest) {
                *info = complete(entry, &md);
            }
        })
        .await?;
    }
    let mut sampled = sampled.into_iter();
    let guards: Vec<RelayInfo> = sampled
        .by_ref()
        .take(guard_entries.len())
        .filter_map(|(_, info)| info)
        .collect();
    let pool: Vec<Relay> = sampled
        .filter_map(|(entry, info)| {
            Some(Relay {
                info: info?,
                flags: entry.flags,
            })
        })
        .collect();
    if guards.is_empty() || pool.len() < 3 {
        return Err(Error::Unavailable("consensus sample is too small"));
    }

    // Second pass: every HSDir's ed25519 identity, to place it on the ring.
    let periods = meta.hs_periods();
    let mut queries = make_queries(&meta);
    let mut placed = 0u32;
    if !queries.is_empty() {
        let total = scratch.len() / ROUTER_RECORD_LEN;
        let mut batch: Vec<RouterEntry> = Vec::with_capacity(MD_BATCH);
        let mut at = 0;
        while at < total {
            batch.clear();
            while at < total && batch.len() < MD_BATCH {
                let mut record = [0u8; ROUTER_RECORD_LEN];
                scratch.read(at * ROUTER_RECORD_LEN, &mut record)?;
                batch.push(RouterEntry::from_record(&record));
                at += 1;
            }
            let digests: Vec<[u8; 32]> = batch.iter().map(|e| e.md_digest).collect();
            wire_bytes += fetch_microdescs(circ, &digests, &mut |md| {
                let Some(entry) = batch.iter().find(|e| e.md_digest == md.digest) else {
                    return;
                };
                let Some(info) = complete(entry, &md) else {
                    return;
                };
                let ed_id = info.ed_id.unwrap_or_default();
                placed += 1;
                let index: [[u8; 32]; 2] = [0, 1].map(|i| {
                    hs_relay_index(
                        &ed_id,
                        &periods.pairs[i].1,
                        periods.pairs[i].0,
                        periods.length,
                    )
                });
                for q in queries.iter_mut() {
                    q.offer(&index[q.pair], &info);
                }
            })
            .await?;
        }
    }
    log::info!(
        "network view ready: {} guard candidates, {} pool relays, {} of {} hsdirs placed, {} KB total, {:?}",
        guards.len(),
        pool.len(),
        placed,
        hsdirs,
        wire_bytes / 1024,
        started.elapsed()
    );
    Ok((
        NetDir {
            meta,
            guards,
            pool,
            hsdirs,
            fetched: Instant::now(),
            wire_bytes,
        },
        queries,
    ))
}

/// How long to wait before retrying something that failed `attempt` times.
pub fn backoff(attempt: u32) -> Duration {
    Duration::from_secs((2u64 << attempt.min(6)).min(120))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta_at(valid_after: u64) -> ConsensusMeta {
        ConsensusMeta {
            valid_after,
            hsdir_interval: 1440,
            srv_current: Some([2; 32]),
            srv_previous: Some([1; 32]),
            ..Default::default()
        }
    }

    /// rend-spec-v3 2.2.4: at 13:00 a service publishes for the previous and the current
    /// period; at 01:00 for the current and the next.
    #[test]
    fn periods_follow_the_spec_segments() {
        let day = 20_000u64 * 86_400;
        let afternoon = meta_at(day + 13 * 3600).hs_periods();
        // Minutes since the epoch minus the 12-hour offset, in days.
        let period = (day / 60 + 13 * 60 - 720) / 1440;
        assert_eq!(afternoon.pairs[0], (period - 1, [1; 32]));
        assert_eq!(afternoon.pairs[1], (period, [2; 32]));
        assert_eq!(afternoon.fetch, 1);

        let night = meta_at(day + 3600).hs_periods();
        let period = (day / 60 + 60 - 720) / 1440;
        assert_eq!(night.pairs[0], (period, [1; 32]));
        assert_eq!(night.pairs[1], (period + 1, [2; 32]));
        assert_eq!(night.fetch, 0);
    }

    #[test]
    fn ring_keeps_the_nearest_clockwise() {
        let relay = |n: u8| RelayInfo {
            rsa_id: [n; 20],
            ed_id: Some([n; 32]),
            ntor_key: [n; 32],
            addr: "10.0.0.1:9001".parse().unwrap(),
        };
        let mut q = RingQuery::new(0, [0x80; 32], 2);
        for (n, first) in [(1u8, 0x70u8), (2, 0x81), (3, 0xf0), (4, 0x90), (5, 0x10)] {
            let mut index = [0u8; 32];
            index[0] = first;
            q.offer(&index, &relay(n));
        }
        // Clockwise from 0x8080..: 0x81, 0x90, 0xf0, then wrapping to 0x10 and 0x70.
        let got: Vec<u8> = q.relays().map(|r| r.rsa_id[0]).collect();
        assert_eq!(got, vec![2, 4]);
    }

    #[test]
    fn distance_wraps() {
        let mut a = [0u8; 32];
        a[31] = 1;
        let b = [0xffu8; 32];
        let mut two = [0u8; 32];
        two[31] = 2;
        assert_eq!(ring_distance(&a, &b), two);
    }
}
