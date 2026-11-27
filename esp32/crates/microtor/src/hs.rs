//! Hosting a v3 onion service, and dialing one (rend-spec-v3 section 3).
//!
//! The service keeps a few introduction circuits open, publishes two descriptors (one per
//! overlapping time period), and answers each INTRODUCE2 by meeting the client at the
//! rendezvous point it named. Streams the client opens are handed to the application through
//! [`OnionService::accept`].

use std::cell::RefCell;
use std::collections::VecDeque;
use std::future::poll_fn;
use std::rc::Rc;
use std::task::Poll;
use std::time::{Duration, Instant};

use x25519_dalek::StaticSecret;

use crate::cell::{end_reason, relay};
use crate::circuit::{Circuit, PendingStream, RelayInfo, Stream};
use crate::crypto::{
    aes256_ctr_apply, ed_blind_public, hs_mac, hs_service_open_intro, hs_service_rendezvous,
    rand_array, rand_u32, x25519_keypair, EdExpanded, HsNtorClient,
};
use crate::dir::{dir_get, dir_post, ConsensusMeta};
use crate::hsdesc::{build_descriptor, onion_address, parse_descriptor, subcredential, IntroInfo};
use crate::netdir::{backoff, hs_service_index, now_unix, RingQuery};
use crate::rt::{sleep, spawn, timeout};
use crate::tor::Tor;
use crate::util::b64_encode;
use crate::{Error, Result};

/// Rendezvous circuits torn down after this long with no stream open.
const REND_IDLE: Duration = Duration::from_secs(60);
/// Descriptors are valid for three hours on the directories; refresh well inside that.
const REPUBLISH_EVERY: Duration = Duration::from_secs(75 * 60);
const INTRO_REPLAY_WINDOW: usize = 64;
/// Smallest INTRODUCE1 body a client sends (Tor pads to this).
const INTRODUCE1_MIN: usize = 246;

#[derive(Clone)]
pub struct ServiceConfig {
    pub intro_points: usize,
    /// Rendezvous circuits allowed at once; introductions beyond that are dropped.
    pub max_rendezvous: usize,
    /// Streams waiting in the accept queue before new ones are refused.
    pub accept_backlog: usize,
    /// Other onion services this node dials (their ring positions are resolved on every
    /// consensus refresh so a descriptor fetch needs no extra directory work).
    pub peers: Vec<[u8; 32]>,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            intro_points: 3,
            max_rendezvous: 6,
            accept_backlog: 8,
            peers: Vec::new(),
        }
    }
}

struct IntroSlot {
    info: IntroInfo,
    established: Instant,
}

/// Blinded identity for one time period.
struct PeriodKeys {
    period: u64,
    blinded: EdExpanded,
    subcred: [u8; 32],
}

#[derive(Default, Clone, Debug)]
pub struct ServiceStats {
    pub introductions: u64,
    pub rendezvous_ok: u64,
    pub rendezvous_failed: u64,
    pub streams: u64,
    pub publishes: u64,
    pub uploads_ok: u64,
    pub uploads_failed: u64,
    pub refreshes: u64,
}

struct State {
    intros: Vec<Option<IntroSlot>>,
    /// The relay each slot has chosen, from the moment it is picked (before the circuit is
    /// up), so two slots building at once never land on the same relay.
    intro_relays: Vec<Option<RelayInfo>>,
    periods: Vec<PeriodKeys>,
    period_length: u64,
    /// The introduction set changed since the last publish.
    dirty: bool,
    last_publish: Option<Instant>,
    incoming: VecDeque<PendingStream>,
    rendezvous: usize,
    seen_cookies: VecDeque<[u8; 20]>,
    stats: ServiceStats,
    /// At least one descriptor upload has succeeded since the last change.
    reachable: bool,
}

#[derive(Clone)]
pub struct OnionService {
    tor: Tor,
    identity: Rc<EdExpanded>,
    config: Rc<ServiceConfig>,
    state: Rc<RefCell<State>>,
}

/// A stream opened by a client of the service.
pub struct Incoming {
    pub port: u16,
    pending: PendingStream,
}

impl Incoming {
    pub fn accept(self) -> Result<Stream> {
        self.pending.accept()
    }

    pub fn reject(self) {
        self.pending.reject(end_reason::EXITPOLICY);
    }
}

impl OnionService {
    /// `seed` is the service's ed25519 identity seed; the onion address is a function of it.
    pub fn new(tor: Tor, seed: &[u8; 32], config: ServiceConfig) -> Self {
        let slots = config.intro_points;
        Self {
            tor,
            identity: Rc::new(EdExpanded::from_seed(seed)),
            config: Rc::new(config),
            state: Rc::new(RefCell::new(State {
                intros: (0..slots).map(|_| None).collect(),
                intro_relays: (0..slots).map(|_| None).collect(),
                periods: Vec::new(),
                period_length: 1440,
                dirty: true,
                last_publish: None,
                incoming: VecDeque::new(),
                rendezvous: 0,
                seen_cookies: VecDeque::new(),
                stats: ServiceStats::default(),
                reachable: false,
            })),
        }
    }

    pub fn tor(&self) -> &Tor {
        &self.tor
    }

    pub fn identity(&self) -> &EdExpanded {
        &self.identity
    }

    pub fn onion(&self) -> String {
        onion_address(&self.identity.public)
    }

    pub fn stats(&self) -> ServiceStats {
        self.state.borrow().stats.clone()
    }

    /// True once a descriptor naming live introduction points has been uploaded.
    pub fn is_published(&self) -> bool {
        self.state.borrow().reachable
    }

    pub fn intro_count(&self) -> usize {
        self.state.borrow().intros.iter().flatten().count()
    }

    /// Start the service's tasks. Returns immediately; poll the executor to make progress.
    pub fn start(&self) {
        let svc = self.clone();
        spawn(async move { svc.run().await });
    }

    /// Wait for the next client stream.
    pub async fn accept(&self) -> Incoming {
        poll_fn(|_| match self.state.borrow_mut().incoming.pop_front() {
            Some(pending) => Poll::Ready(Incoming {
                port: pending.port,
                pending,
            }),
            None => Poll::Pending,
        })
        .await
    }

    /// Ring queries for our own descriptors and for every peer we may dial.
    fn ring_queries(&self, meta: &ConsensusMeta) -> Vec<RingQuery> {
        let periods = meta.hs_periods();
        let mut queries = Vec::new();
        let store = usize::from(meta.hsdir_spread_store);
        let fetch = usize::from(meta.hsdir_spread_fetch);
        for (pair, (period, _)) in periods.pairs.iter().enumerate() {
            let Ok(blinded) = ed_blind_public(&self.identity.public, *period, periods.length)
            else {
                continue;
            };
            for replica in 1..=meta.hsdir_n_replicas {
                let target = hs_service_index(&blinded, replica, *period, periods.length);
                queries.push(RingQuery::new(pair, target, store));
            }
        }
        let (period, _) = periods.pairs[periods.fetch];
        for peer in &self.config.peers {
            let Ok(blinded) = ed_blind_public(peer, period, periods.length) else {
                continue;
            };
            for replica in 1..=meta.hsdir_n_replicas {
                let target = hs_service_index(&blinded, replica, period, periods.length);
                queries.push(RingQuery::new(periods.fetch, target, fetch));
            }
        }
        queries
    }

    async fn refresh(&self) -> Result<()> {
        let svc = self.clone();
        self.tor
            .refresh(&mut move |meta| svc.ring_queries(meta))
            .await?;
        let netdir = self.tor.netdir()?;
        let periods = netdir.meta.hs_periods();
        let mut state = self.state.borrow_mut();
        state.stats.refreshes += 1;
        state.period_length = periods.length;
        let wanted: Vec<u64> = periods.pairs.iter().map(|p| p.0).collect();
        if state
            .periods
            .iter()
            .map(|p| p.period)
            .ne(wanted.iter().copied())
        {
            state.periods = wanted
                .iter()
                .filter_map(|&period| {
                    let blinded = self.identity.blind(period, periods.length).ok()?;
                    let subcred = subcredential(&self.identity.public, &blinded.public);
                    Some(PeriodKeys {
                        period,
                        blinded,
                        subcred,
                    })
                })
                .collect();
        }
        // New consensus, possibly new directories: publish again.
        state.dirty = true;
        Ok(())
    }

    async fn run(self) {
        let mut attempt = 0;
        while let Err(e) = self.refresh().await {
            log::warn!("bootstrap failed: {e}");
            sleep(backoff(attempt)).await;
            attempt += 1;
        }
        log::info!("onion service {} starting", self.onion());
        for slot in 0..self.config.intro_points {
            let svc = self.clone();
            spawn(async move { svc.intro_task(slot).await });
        }
        let started = Instant::now();
        let mut failures = 0u32;
        loop {
            sleep(Duration::from_millis(500)).await;
            let stale = self.tor.netdir().map(|n| n.is_stale()).unwrap_or(true);
            let (ready, dirty, last) = {
                let s = self.state.borrow();
                (s.intros.iter().flatten().count(), s.dirty, s.last_publish)
            };
            let due = last.is_none_or(|t| t.elapsed() > REPUBLISH_EVERY);
            if due && stale && last.is_some() {
                if let Err(e) = self.refresh().await {
                    log::warn!("consensus refresh failed: {e}");
                    sleep(backoff(failures)).await;
                    failures += 1;
                    continue;
                }
                failures = 0;
            }
            // Publish when every introduction point is up, or after a grace period with at
            // least one, so a single slow relay cannot keep the service dark.
            let enough = ready == self.config.intro_points
                || (ready > 0 && started.elapsed() > Duration::from_secs(45));
            if enough && (dirty || due) {
                // Give a just-changed set a moment to settle so one upload covers it.
                sleep(Duration::from_secs(2)).await;
                self.publish().await;
            }
        }
    }

    async fn intro_task(self, slot: usize) {
        let mut attempt = 0u32;
        loop {
            match self.intro_once(slot).await {
                Ok(()) => attempt = 0,
                Err(e) => {
                    log::info!("introduction point {slot}: {e}");
                    attempt += 1;
                }
            }
            {
                let mut s = self.state.borrow_mut();
                s.intro_relays[slot] = None;
                if s.intros[slot].take().is_some() {
                    s.dirty = true;
                }
            }
            sleep(backoff(attempt.min(5))).await;
        }
    }

    async fn intro_once(&self, slot: usize) -> Result<()> {
        // Avoid relays other slots already use or are building to.
        let used: Vec<RelayInfo> = self
            .state
            .borrow()
            .intro_relays
            .iter()
            .flatten()
            .cloned()
            .collect();
        let exclude: Vec<&RelayInfo> = used.iter().collect();
        let relay_info = self.tor.pick_relay(&exclude)?;
        self.state.borrow_mut().intro_relays[slot] = Some(relay_info.clone());
        let circ = self.tor.circuit_to(&relay_info).await?;

        let auth = EdExpanded::generate();
        let (enc_secret, enc_public) = x25519_keypair();
        // ESTABLISH_INTRO: key type, length, key, no extensions; then a MAC keyed with the
        // circuit's KH and a signature by the authentication key.
        let mut body = Vec::with_capacity(36 + 32 + 2 + 64);
        body.push(2);
        body.extend_from_slice(&[0, 32]);
        body.extend_from_slice(&auth.public);
        body.push(0);
        let kh = circ.kh(circ.hops() - 1)?;
        let mac = hs_mac(&kh, &[&body]);
        body.extend_from_slice(&mac);
        let mut signed = b"Tor establish-intro cell v1".to_vec();
        signed.extend_from_slice(&body);
        let sig = auth.sign(&signed);
        body.extend_from_slice(&[0, 64]);
        body.extend_from_slice(&sig);
        circ.send(relay::ESTABLISH_INTRO, &body)?;
        circ.recv_ctrl(relay::INTRO_ESTABLISHED, "INTRO_ESTABLISHED")
            .await?;
        log::info!(
            "introduction point {slot} established at {}",
            relay_info.addr
        );

        let info = IntroInfo {
            relay: relay_info,
            auth_key: auth.public,
            enc_key: enc_public,
        };
        {
            let mut s = self.state.borrow_mut();
            s.intros[slot] = Some(IntroSlot {
                info: info.clone(),
                established: Instant::now(),
            });
            s.dirty = true;
        }
        let keys = Rc::new((enc_secret, info));
        loop {
            let msg = circ.next_ctrl().await?;
            if msg.cmd != relay::INTRODUCE2 {
                continue;
            }
            log::info!("introduction received at point {slot}");
            let svc = self.clone();
            let keys = keys.clone();
            spawn(async move {
                if let Err(e) = svc.rendezvous(&keys.0, &keys.1, msg.data).await {
                    log::info!("rendezvous failed: {e}");
                    svc.state.borrow_mut().stats.rendezvous_failed += 1;
                }
            });
        }
    }

    async fn rendezvous(
        &self,
        enc_secret: &StaticSecret,
        intro: &IntroInfo,
        body: Vec<u8>,
    ) -> Result<()> {
        // LEGACY_KEY_ID (20) | AUTH_KEY_TYPE (1) | AUTH_KEY_LEN (2) | AUTH_KEY | N_EXT | exts
        let bad = Error::Proto("malformed introduce2");
        if body.len() < 20 + 3 + 32 + 1 || body[20] != 2 || body[21..23] != [0, 32] {
            return Err(bad);
        }
        if body[23..55] != intro.auth_key {
            return Err(Error::Proto("introduce2 for another key"));
        }
        let mut at = 56;
        for _ in 0..body[55] {
            let len = *body.get(at + 1).ok_or(bad.clone())? as usize;
            at += 2 + len;
        }
        let (header, rest) = body.split_at_checked(at).ok_or(bad.clone())?;

        // The client encrypted to whichever period's subcredential its descriptor carried.
        let subcreds: Vec<[u8; 32]> = self
            .state
            .borrow()
            .periods
            .iter()
            .map(|p| p.subcred)
            .collect();
        let opened = subcreds
            .iter()
            .find_map(|subcred| {
                hs_service_open_intro(
                    enc_secret,
                    &intro.enc_key,
                    &intro.auth_key,
                    subcred,
                    header,
                    rest,
                )
                .ok()
            })
            .ok_or(Error::Proto("introduce2 did not authenticate"))?;

        // RENDEZVOUS_COOKIE (20) | N_EXT | exts | ONION_KEY_TYPE | LEN (2) | KEY | link specifiers
        let p = &opened.plaintext;
        let cookie: [u8; 20] = p.get(..20).ok_or(bad.clone())?.try_into().unwrap();
        let mut at = 21;
        for _ in 0..*p.get(20).ok_or(bad.clone())? {
            let len = *p.get(at + 1).ok_or(bad.clone())? as usize;
            at += 2 + len;
        }
        let key_header = p.get(at..at + 3).ok_or(bad.clone())?;
        if key_header != [1, 0, 32] {
            return Err(Error::Proto("introduce2 onion key type"));
        }
        let ntor_key: [u8; 32] = p
            .get(at + 3..at + 35)
            .ok_or(bad.clone())?
            .try_into()
            .unwrap();
        let (rend_point, _) =
            RelayInfo::from_link_specifiers(p.get(at + 35..).ok_or(bad)?, ntor_key)?;

        {
            let mut s = self.state.borrow_mut();
            s.stats.introductions += 1;
            if s.seen_cookies.contains(&cookie) {
                return Err(Error::Proto("replayed introduction"));
            }
            if s.seen_cookies.len() == INTRO_REPLAY_WINDOW {
                s.seen_cookies.pop_front();
            }
            s.seen_cookies.push_back(cookie);
            if s.rendezvous >= self.config.max_rendezvous {
                return Err(Error::Unavailable("too many rendezvous circuits"));
            }
            s.rendezvous += 1;
        }
        let result = self
            .serve_rendezvous(&opened, intro, cookie, &rend_point)
            .await;
        self.state.borrow_mut().rendezvous -= 1;
        result
    }

    async fn serve_rendezvous(
        &self,
        opened: &crate::crypto::IntroOpened,
        intro: &IntroInfo,
        cookie: [u8; 20],
        rend_point: &RelayInfo,
    ) -> Result<()> {
        let started = Instant::now();
        let (reply, keys) = hs_service_rendezvous(opened, &intro.enc_key, &intro.auth_key)?;
        // One retry through a different middle relay.
        let circ = match self.tor.circuit_to(rend_point).await {
            Ok(circ) => circ,
            Err(e) => {
                log::debug!("rendezvous circuit failed ({e}); retrying");
                self.tor.circuit_to(rend_point).await?
            }
        };
        let mut body = [0u8; 20 + 64];
        body[..20].copy_from_slice(&cookie);
        body[20..].copy_from_slice(&reply);
        circ.send(relay::RENDEZVOUS1, &body)?;
        circ.add_onion_hop(&keys, true)?;
        self.state.borrow_mut().stats.rendezvous_ok += 1;
        log::info!(
            "rendezvous joined at {} in {:?}",
            rend_point.addr,
            started.elapsed()
        );

        let mut idle_since = Instant::now();
        loop {
            let next = timeout(Duration::from_secs(5), "begin", circ.next_begin()).await;
            match next {
                Ok(pending) => {
                    idle_since = Instant::now();
                    let mut s = self.state.borrow_mut();
                    s.stats.streams += 1;
                    if s.incoming.len() >= self.config.accept_backlog {
                        drop(s);
                        pending.reject(end_reason::RESOURCELIMIT);
                    } else {
                        s.incoming.push_back(pending);
                    }
                }
                Err(Error::Timeout(_)) => {
                    if circ.stream_count() > 0 {
                        idle_since = Instant::now();
                    } else if idle_since.elapsed() > REND_IDLE {
                        return Ok(());
                    }
                }
                // The client closed the circuit: the normal way a session ends.
                Err(Error::Closed(_)) => return Ok(()),
                Err(e) => return Err(e),
            }
        }
    }

    /// Upload both descriptors to every responsible directory.
    async fn publish(&self) {
        let now = now_unix();
        let (intros, jobs) = {
            let mut s = self.state.borrow_mut();
            s.dirty = false;
            s.last_publish = Some(Instant::now());
            s.stats.publishes += 1;
            let intros: Vec<IntroInfo> =
                s.intros.iter().flatten().map(|i| i.info.clone()).collect();
            let length = s.period_length;
            let jobs: Vec<(u64, EdExpanded, u64)> = s
                .periods
                .iter()
                .map(|p| (p.period, p.blinded.clone(), length))
                .collect();
            (intros, jobs)
        };
        let jobs_by_period = jobs;
        if intros.is_empty() {
            return;
        }
        let netdir = match self.tor.netdir() {
            Ok(n) => n,
            Err(_) => return,
        };
        let replicas = netdir.meta.hsdir_n_replicas;
        let (mut ok, mut failed) = (0u64, 0u64);
        // One period at a time, so only one 14 KB descriptor exists at once.
        for (period, blinded, length) in jobs_by_period {
            // The revision counter only has to increase per blinded key; unix time does.
            let built = {
                let _heavy = crate::rt::heavy().await;
                build_descriptor(&self.identity.public, &blinded, &intros, now, now)
            };
            let descriptor = match built {
                Ok(d) => Rc::new(d),
                Err(e) => {
                    log::warn!("descriptor build failed: {e}");
                    continue;
                }
            };
            let mut targets: VecDeque<RelayInfo> = VecDeque::new();
            for replica in 1..=replicas {
                let index = hs_service_index(&blinded.public, replica, period, length);
                for dir in self.tor.hsdirs_for(&index) {
                    if !targets.iter().any(|t| t.rsa_id == dir.rsa_id) {
                        targets.push_back(dir);
                    }
                }
            }
            // A few uploads at a time: each is its own three-hop circuit, and one after
            // another they dominate the time from boot to reachable.
            let total = targets.len();
            let targets = Rc::new(RefCell::new(targets));
            let tally = Rc::new(RefCell::new((0u64, 0u64)));
            for _ in 0..crate::rt::limits()
                .upload_concurrency
                .clamp(1, total.max(1))
            {
                let (svc, targets, tally, descriptor) = (
                    self.clone(),
                    targets.clone(),
                    tally.clone(),
                    descriptor.clone(),
                );
                spawn(async move {
                    loop {
                        let Some(dir) = targets.borrow_mut().pop_front() else {
                            return;
                        };
                        let result = svc.upload(&dir, &descriptor).await;
                        let mut t = tally.borrow_mut();
                        match result {
                            Ok(()) => t.0 += 1,
                            Err(e) => {
                                t.1 += 1;
                                log::debug!("descriptor upload to {} failed: {e}", dir.addr);
                            }
                        }
                    }
                });
            }
            poll_fn(|_| {
                let t = tally.borrow();
                if (t.0 + t.1) as usize >= total {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
            ok += tally.borrow().0;
            failed += tally.borrow().1;
        }
        let mut s = self.state.borrow_mut();
        s.stats.uploads_ok += ok;
        s.stats.uploads_failed += failed;
        if ok > 0 {
            s.reachable = true;
        } else {
            // Nothing landed: try again soon.
            s.dirty = true;
        }
        log::info!(
            "descriptor published to {ok} directories ({failed} failed), {} introduction points",
            intros.len()
        );
    }

    async fn upload(&self, dir: &RelayInfo, descriptor: &str) -> Result<()> {
        let circ = self.tor.circuit_to(dir).await?;
        timeout(
            Duration::from_secs(45),
            "descriptor upload",
            dir_post(&circ, "/tor/hs/3/publish", descriptor.as_bytes()),
        )
        .await
    }
}

/// A connection to another onion service: the rendezvous circuit and one stream on it.
pub struct OnionConn {
    pub stream: Stream,
    // Declared after the stream so the stream's END goes out before the circuit closes.
    _circ: Circuit,
}

/// Fetch and decrypt the descriptor of `identity` from the directories found at the last
/// refresh (the service must have been listed in `ServiceConfig::peers`, or the ring queried
/// some other way).
pub async fn fetch_descriptor(
    tor: &Tor,
    identity: &[u8; 32],
) -> Result<(Vec<IntroInfo>, [u8; 32])> {
    let netdir = tor.netdir()?;
    let periods = netdir.meta.hs_periods();
    let (period, _) = periods.pairs[periods.fetch];
    let blinded = ed_blind_public(identity, period, periods.length)?;
    let mut dirs: Vec<RelayInfo> = Vec::new();
    for replica in 1..=netdir.meta.hsdir_n_replicas {
        let index = hs_service_index(&blinded, replica, period, periods.length);
        for dir in tor.hsdirs_for(&index) {
            if !dirs.iter().any(|d| d.rsa_id == dir.rsa_id) {
                dirs.push(dir);
            }
        }
    }
    if dirs.is_empty() {
        return Err(Error::Unavailable(
            "no directories known for this onion service",
        ));
    }
    // Start at a random directory so load and failures spread.
    let start = rand_u32() as usize % dirs.len();
    let path = format!("/tor/hs/3/{}", b64_encode(&blinded, false));
    let mut last = Error::Unavailable("descriptor not found");
    for i in 0..dirs.len() {
        let dir = &dirs[(start + i) % dirs.len()];
        let attempt = async {
            let circ = tor.circuit_to(dir).await?;
            // Fetching and opening a descriptor takes a few tens of kilobytes at once.
            let _heavy = crate::rt::heavy().await;
            let mut text = Vec::new();
            dir_get(&circ, &path, &mut |chunk| {
                if text.len() + chunk.len() > 50_000 {
                    return Err(Error::Parse("descriptor too large"));
                }
                text.extend_from_slice(chunk);
                Ok(())
            })
            .await?;
            let text = String::from_utf8(text).map_err(|_| Error::Parse("descriptor utf8"))?;
            parse_descriptor(&text, identity, &blinded, now_unix())
        };
        match attempt.await {
            Ok(intros) => return Ok((intros, subcredential(identity, &blinded))),
            Err(e) => {
                log::debug!("descriptor fetch from {} failed: {e}", dir.addr);
                last = e;
            }
        }
    }
    Err(last)
}

/// Dial `identity` on `port`: descriptor, rendezvous point, introduction, end-to-end keys.
pub async fn connect_onion(tor: &Tor, identity: &[u8; 32], port: u16) -> Result<OnionConn> {
    let (intros, subcred) = fetch_descriptor(tor, identity).await?;
    connect_with(tor, &intros, &subcred, port).await
}

/// Dial through introduction points already known (from an earlier `fetch_descriptor`).
pub async fn connect_with(
    tor: &Tor,
    intros: &[IntroInfo],
    subcred: &[u8; 32],
    port: u16,
) -> Result<OnionConn> {
    if intros.is_empty() {
        return Err(Error::Unavailable("no introduction points"));
    }
    let mut last = Error::Unavailable("no introduction point worked");
    let start = rand_u32() as usize % intros.len();
    for i in 0..intros.len() {
        let intro = &intros[(start + i) % intros.len()];
        match connect_via(tor, intro, subcred, port).await {
            Ok(conn) => return Ok(conn),
            Err(e) => {
                log::debug!("introduction via {} failed: {e}", intro.relay.addr);
                last = e;
            }
        }
    }
    Err(last)
}

async fn connect_via(
    tor: &Tor,
    intro: &IntroInfo,
    subcred: &[u8; 32],
    port: u16,
) -> Result<OnionConn> {
    // Our end of the meeting: a circuit to a relay of our choosing, holding a cookie.
    let rend_point = tor.pick_relay(&[&intro.relay])?;
    let rend_circ = tor.circuit_to(&rend_point).await?;
    let cookie: [u8; 20] = rand_array();
    rend_circ.send(relay::ESTABLISH_RENDEZVOUS, &cookie)?;
    rend_circ
        .recv_ctrl(relay::RENDEZVOUS_ESTABLISHED, "RENDEZVOUS_ESTABLISHED")
        .await?;

    // INTRODUCE1 through the introduction point.
    let (ntor, enc_key, mac_key) = HsNtorClient::start(intro.enc_key, intro.auth_key, subcred)?;
    let mut header = Vec::with_capacity(56);
    header.extend_from_slice(&[0u8; 20]);
    header.extend_from_slice(&[2, 0, 32]);
    header.extend_from_slice(&intro.auth_key);
    header.push(0);
    let mut plaintext = Vec::with_capacity(INTRODUCE1_MIN);
    plaintext.extend_from_slice(&cookie);
    plaintext.push(0);
    plaintext.extend_from_slice(&[1, 0, 32]);
    plaintext.extend_from_slice(&rend_point.ntor_key);
    plaintext.extend_from_slice(&rend_point.link_specifiers());
    let unpadded = header.len() + 32 + plaintext.len() + 32;
    if unpadded < INTRODUCE1_MIN {
        plaintext.resize(plaintext.len() + INTRODUCE1_MIN - unpadded, 0);
    }
    aes256_ctr_apply(&enc_key, &[0u8; 16], &mut plaintext);
    let mac = hs_mac(&mac_key, &[&header, &ntor.public, &plaintext]);
    let mut body = header;
    body.extend_from_slice(&ntor.public);
    body.extend_from_slice(&plaintext);
    body.extend_from_slice(&mac);

    let intro_circ = tor.circuit_to(&intro.relay).await?;
    intro_circ.send(relay::INTRODUCE1, &body)?;
    let ack = intro_circ
        .recv_ctrl(relay::INTRODUCE_ACK, "INTRODUCE_ACK")
        .await?;
    if ack.data.len() >= 2 && ack.data[..2] != [0, 0] {
        return Err(Error::Proto("introduction refused"));
    }
    drop(intro_circ);

    // The service joins our circuit and proves it holds the introduction keys.
    let joined = timeout(
        Duration::from_secs(60),
        "RENDEZVOUS2",
        rend_circ.next_ctrl(),
    )
    .await?;
    if joined.cmd != relay::RENDEZVOUS2 {
        return Err(Error::Proto("unexpected message instead of RENDEZVOUS2"));
    }
    let keys = ntor.finish(&joined.data)?;
    rend_circ.add_onion_hop(&keys, false)?;
    let stream = rend_circ.begin("", port).await?;
    Ok(OnionConn {
        stream,
        _circ: rend_circ,
    })
}

impl IntroSlot {
    #[allow(dead_code)]
    fn age(&self) -> Duration {
        self.established.elapsed()
    }
}
