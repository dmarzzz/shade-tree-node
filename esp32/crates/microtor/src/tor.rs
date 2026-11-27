//! The client: one guard link, the current network view, and circuits on demand.

use std::cell::RefCell;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::rc::Rc;
use std::time::Duration;

use crate::bootstrap_data::{AUTHORITIES, FALLBACKS};
use crate::circuit::{connect_link, Circuit, Core, RelayInfo, Shared};
use crate::crypto::rand_u32;
use crate::dir::{AuthCert, ConsensusMeta};
use crate::netdir::{
    clock_is_plausible, fetch_certs, fetch_netdir, set_clock, NetDir, RingQuery, Scratch,
};
use crate::rt::timeout;
use crate::{Error, Result};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const BUILD_TIMEOUT: Duration = Duration::from_secs(60);
const BOOTSTRAP_ATTEMPTS: usize = 16;

struct Guard {
    link: usize,
    info: RelayInfo,
}

struct Inner {
    netdir: Option<Rc<NetDir>>,
    certs: Rc<Vec<AuthCert>>,
    guard: Option<Guard>,
    scratch: Option<Box<dyn Scratch>>,
    guard_seed: [u8; 32],
    /// Answers to the ring queries of the last refresh: `(target, directories)`.
    ring: Vec<([u8; 32], Vec<RelayInfo>)>,
    /// Our address as relays report it.
    observed_addr: Option<Ipv4Addr>,
}

/// A handle to the client; cheap to clone, single-threaded.
#[derive(Clone)]
pub struct Tor {
    core: Shared,
    inner: Rc<RefCell<Inner>>,
}

impl Tor {
    /// `guard_seed` should be random and persistent: it keeps the guard choice stable across
    /// restarts. `scratch` holds one refresh worth of relay records (64 bytes per HSDir).
    pub fn new(scratch: Box<dyn Scratch>, guard_seed: [u8; 32]) -> Self {
        Self {
            core: Core::new(),
            inner: Rc::new(RefCell::new(Inner {
                netdir: None,
                certs: Rc::new(Vec::new()),
                guard: None,
                scratch: Some(scratch),
                guard_seed,
                ring: Vec::new(),
                observed_addr: None,
            })),
        }
    }

    pub fn core(&self) -> &Shared {
        &self.core
    }

    pub fn netdir(&self) -> Result<Rc<NetDir>> {
        self.inner
            .borrow()
            .netdir
            .clone()
            .ok_or(Error::Unavailable("no consensus yet"))
    }

    pub fn observed_addr(&self) -> Option<Ipv4Addr> {
        self.inner.borrow().observed_addr
    }

    pub fn guard(&self) -> Option<RelayInfo> {
        self.inner.borrow().guard.as_ref().map(|g| g.info.clone())
    }

    /// The directories found for a ring target at the last refresh.
    pub fn hsdirs_for(&self, target: &[u8; 32]) -> Vec<RelayInfo> {
        self.inner
            .borrow()
            .ring
            .iter()
            .find(|(t, _)| t == target)
            .map(|(_, relays)| relays.clone())
            .unwrap_or_default()
    }

    fn guard_alive(&self) -> Option<(usize, RelayInfo)> {
        let inner = self.inner.borrow();
        let guard = inner.guard.as_ref()?;
        self.core
            .borrow()
            .link_alive(guard.link)
            .then(|| (guard.link, guard.info.clone()))
    }

    /// Connect to some directory mirror for the very first fetch.
    fn bootstrap_link(&self) -> Result<usize> {
        for attempt in 0..BOOTSTRAP_ATTEMPTS {
            // Mirrors first; the authorities only when several mirrors in a row failed.
            let addr = if attempt < BOOTSTRAP_ATTEMPTS - 4 {
                let f = &FALLBACKS[rand_u32() as usize % FALLBACKS.len()];
                SocketAddrV4::new(Ipv4Addr::from(f.ip), f.or_port)
            } else {
                let a = &AUTHORITIES[rand_u32() as usize % AUTHORITIES.len()];
                SocketAddrV4::new(Ipv4Addr::from(a.ip), a.or_port)
            };
            match connect_link(&self.core, addr, CONNECT_TIMEOUT) {
                Ok(link) => {
                    self.note_link(link);
                    log::info!("bootstrapping through {addr}");
                    return Ok(link);
                }
                Err(e) => log::debug!("directory mirror {addr}: {e}"),
            }
        }
        Err(Error::Unavailable("no directory mirror reachable"))
    }

    fn note_link(&self, link: usize) {
        let core = self.core.borrow();
        let Some(l) = core.link(link) else { return };
        if !clock_is_plausible() && l.peer_time > 1_735_689_600 {
            log::info!("no clock; taking the time from the relay ({})", l.peer_time);
            set_clock(u64::from(l.peer_time));
        }
        if let Some(addr) = l.observed_addr {
            self.inner.borrow_mut().observed_addr = Some(addr);
        }
    }

    /// Make sure there is a live link to a guard; connects if needed.
    fn ensure_guard(&self) -> Result<(usize, RelayInfo)> {
        if let Some(alive) = self.guard_alive() {
            return Ok(alive);
        }
        let netdir = self.netdir()?;
        // The previous guard first, then the candidates in their stable order.
        let previous = self.inner.borrow_mut().guard.take().map(|g| g.info);
        let candidates = previous.iter().chain(netdir.guards.iter());
        for info in candidates {
            match connect_link(&self.core, info.addr, CONNECT_TIMEOUT) {
                Ok(link) => {
                    self.note_link(link);
                    log::info!("guard link up: {}", info.addr);
                    self.inner.borrow_mut().guard = Some(Guard {
                        link,
                        info: info.clone(),
                    });
                    return Ok((link, info.clone()));
                }
                Err(e) => log::info!("guard {} unreachable: {e}", info.addr),
            }
        }
        Err(Error::Unavailable("no guard reachable"))
    }

    /// Fetch a fresh consensus and answer ring queries. The first call bootstraps through a
    /// directory mirror; later calls go through the guard.
    pub async fn refresh(
        &self,
        make_queries: &mut dyn FnMut(&ConsensusMeta) -> Vec<RingQuery>,
    ) -> Result<()> {
        let (link, circ, temporary) = match self.guard_alive() {
            Some((link, guard)) => (
                link,
                Circuit::create(&self.core, link, &guard).await?,
                false,
            ),
            None => {
                let link = self.bootstrap_link()?;
                (link, Circuit::create_fast(&self.core, link).await?, true)
            }
        };
        let result = self.refresh_over(&circ, make_queries).await;
        drop(circ);
        if temporary {
            // Let the DESTROY go out, then close the mirror link.
            crate::rt::yield_now().await;
            self.core
                .borrow_mut()
                .drop_link(link, Error::Closed(crate::cell::end_reason::DONE));
        }
        result?;
        self.ensure_guard()?;
        Ok(())
    }

    async fn refresh_over(
        &self,
        circ: &Circuit,
        make_queries: &mut dyn FnMut(&ConsensusMeta) -> Vec<RingQuery>,
    ) -> Result<()> {
        if self.inner.borrow().certs.is_empty() {
            let certs = fetch_certs(circ).await?;
            self.inner.borrow_mut().certs = Rc::new(certs);
        }
        let mut scratch = self
            .inner
            .borrow_mut()
            .scratch
            .take()
            .ok_or(Error::Unavailable("a refresh is already running"))?;
        let seed = self.inner.borrow().guard_seed;
        let mut attempt = 0;
        let result = loop {
            let certs = self.inner.borrow().certs.clone();
            let r = fetch_netdir(circ, &certs, scratch.as_mut(), &seed, make_queries).await;
            match r {
                // An authority rotated its signing key: fetch certificates again, once.
                Err(Error::Proto("too few authority signatures on consensus")) if attempt == 0 => {
                    attempt += 1;
                    match fetch_certs(circ).await {
                        Ok(certs) => self.inner.borrow_mut().certs = Rc::new(certs),
                        Err(e) => break Err(e),
                    }
                }
                other => break other,
            }
        };
        let mut inner = self.inner.borrow_mut();
        inner.scratch = Some(scratch);
        let (netdir, queries) = result?;
        inner.netdir = Some(Rc::new(netdir));
        inner.ring = queries
            .iter()
            .map(|q| (q.target, q.relays().cloned().collect()))
            .collect();
        Ok(())
    }

    /// A one-hop circuit to the guard, for directory requests.
    pub async fn dir_circuit(&self) -> Result<Circuit> {
        let (link, guard) = self.ensure_guard()?;
        timeout(
            BUILD_TIMEOUT,
            "directory circuit",
            Circuit::create(&self.core, link, &guard),
        )
        .await
    }

    /// A three-hop circuit ending at `target`: guard, a random middle, target.
    pub async fn circuit_to(&self, target: &RelayInfo) -> Result<Circuit> {
        let (link, guard) = self.ensure_guard()?;
        let netdir = self.netdir()?;
        let middle = netdir.pick(&[&guard, target])?;
        let path = [guard, middle, target.clone()];
        timeout(
            BUILD_TIMEOUT,
            "circuit build",
            Circuit::build(&self.core, link, &path),
        )
        .await
    }

    /// A random relay from the pool, for an introduction or rendezvous point.
    pub fn pick_relay(&self, exclude: &[&RelayInfo]) -> Result<RelayInfo> {
        let netdir = self.netdir()?;
        let guard = self.guard();
        let mut all: Vec<&RelayInfo> = exclude.to_vec();
        if let Some(g) = guard.as_ref() {
            all.push(g);
        }
        netdir.pick(&all)
    }
}
