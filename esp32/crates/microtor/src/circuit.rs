//! Links, circuits and streams: the cell dispatcher and the async operations built on it.
//!
//! `Core` owns every link and circuit. The loop calls [`pump`] to move cells in, tasks call
//! the async functions here to build circuits and move stream data out. Tasks never hold a
//! borrow of the core across an `.await`.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::future::poll_fn;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::rc::Rc;
use std::task::Poll;
use std::time::{Duration, Instant};

use crate::cell::{
    build_relay, cmd, end_reason, parse_relay, relay, Cell, CircCrypto, HopCrypto, RelayMsg,
    PAYLOAD_LEN, RELAY_DATA_MAX,
};
use crate::crypto::{kdf_tor, rand_array, rand_u32, NtorClient, CIRC_KEYS_LEN};
use crate::link::Link;
use crate::rt::{note_progress, timeout, yield_now};
use crate::{Error, Result};

const CIRC_WINDOW_START: i32 = 1000;
const CIRC_WINDOW_INCREMENT: i32 = 100;
const STREAM_WINDOW_START: i32 = 500;
const STREAM_WINDOW_INCREMENT: i32 = 50;
/// Control messages queued per circuit before new ones are dropped.
const CTRL_QUEUE_MAX: usize = 12;
const PENDING_BEGIN_MAX: usize = 8;
pub const STEP_TIMEOUT: Duration = Duration::from_secs(25);

/// What it takes to extend a circuit to a relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayInfo {
    pub rsa_id: [u8; 20],
    pub ed_id: Option<[u8; 32]>,
    pub ntor_key: [u8; 32],
    pub addr: SocketAddrV4,
}

impl RelayInfo {
    /// The link specifiers for an EXTEND2 cell or an introduction point: IPv4, legacy
    /// identity, ed25519 identity.
    pub fn link_specifiers(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 8 + 22 + 34);
        out.push(if self.ed_id.is_some() { 3 } else { 2 });
        out.extend_from_slice(&[0, 6]);
        out.extend_from_slice(&self.addr.ip().octets());
        out.extend_from_slice(&self.addr.port().to_be_bytes());
        out.extend_from_slice(&[2, 20]);
        out.extend_from_slice(&self.rsa_id);
        if let Some(ed) = &self.ed_id {
            out.extend_from_slice(&[3, 32]);
            out.extend_from_slice(ed);
        }
        out
    }

    /// Rebuild from `NSPEC | specifiers...` plus the ntor key (how INTRODUCE2 names a
    /// rendezvous point). Returns the relay and the number of bytes consumed.
    pub fn from_link_specifiers(data: &[u8], ntor_key: [u8; 32]) -> Result<(Self, usize)> {
        let bad = Error::Proto("link specifiers");
        let n = *data.first().ok_or(bad.clone())? as usize;
        let mut at = 1;
        let mut addr = None;
        let mut rsa_id = None;
        let mut ed_id = None;
        for _ in 0..n {
            let header = data.get(at..at + 2).ok_or(bad.clone())?;
            let (kind, len) = (header[0], header[1] as usize);
            let body = data.get(at + 2..at + 2 + len).ok_or(bad.clone())?;
            match (kind, len) {
                (0, 6) => {
                    addr = Some(SocketAddrV4::new(
                        Ipv4Addr::new(body[0], body[1], body[2], body[3]),
                        u16::from_be_bytes([body[4], body[5]]),
                    ));
                }
                (2, 20) => rsa_id = Some(body.try_into().unwrap()),
                (3, 32) => ed_id = Some(body.try_into().unwrap()),
                _ => {}
            }
            at += 2 + len;
        }
        Ok((
            Self {
                rsa_id: rsa_id.ok_or(bad.clone())?,
                ed_id,
                ntor_key,
                addr: addr.ok_or(bad)?,
            },
            at,
        ))
    }
}

struct StreamState {
    id: u16,
    hop: u8,
    inbuf: VecDeque<u8>,
    connected: bool,
    remote_end: Option<u8>,
    deliver_window: i32,
    package_window: i32,
}

struct Circ {
    id: u32,
    link: usize,
    crypto: CircCrypto,
    ctrl: VecDeque<RelayMsg>,
    streams: Vec<StreamState>,
    /// BEGIN requests waiting for the service to accept them: `(stream id, port)`.
    begins: VecDeque<(u16, u16)>,
    accept_begins: bool,
    deliver_window: i32,
    package_window: i32,
    early_left: u8,
    next_stream_id: u16,
    closed: Option<Error>,
}

pub struct Core {
    links: Vec<Option<Link>>,
    circs: Vec<Circ>,
    /// Circuits and streams whose handles were dropped; torn down on the next pump.
    graveyard: Graveyard,
    pub cells_in: u64,
    pub cells_out: u64,
}

pub type Shared = Rc<RefCell<Core>>;
/// `(circuit id, stream id)`; stream id zero means the whole circuit.
type Graveyard = Rc<RefCell<Vec<(u32, u16)>>>;

impl Core {
    pub fn new() -> Shared {
        Rc::new(RefCell::new(Self {
            links: Vec::new(),
            circs: Vec::new(),
            graveyard: Rc::new(RefCell::new(Vec::new())),
            cells_in: 0,
            cells_out: 0,
        }))
    }

    pub fn add_link(&mut self, link: Link) -> usize {
        if let Some(i) = self.links.iter().position(Option::is_none) {
            self.links[i] = Some(link);
            i
        } else {
            self.links.push(Some(link));
            self.links.len() - 1
        }
    }

    pub fn link(&self, idx: usize) -> Option<&Link> {
        self.links.get(idx).and_then(Option::as_ref)
    }

    pub fn link_alive(&self, idx: usize) -> bool {
        self.link(idx).is_some()
    }

    /// Drop a link and fail every circuit on it.
    pub fn drop_link(&mut self, idx: usize, why: Error) {
        if let Some(slot) = self.links.get_mut(idx) {
            *slot = None;
        }
        for c in self.circs.iter_mut().filter(|c| c.link == idx) {
            c.closed.get_or_insert(why.clone());
        }
        note_progress();
    }

    pub fn circuit_count(&self) -> usize {
        self.circs.len()
    }

    fn circ(&mut self, id: u32) -> Result<&mut Circ> {
        let circ = self
            .circs
            .iter_mut()
            .find(|c| c.id == id)
            .ok_or(Error::Closed(end_reason::DESTROY))?;
        match &circ.closed {
            Some(e) => Err(e.clone()),
            None => Ok(circ),
        }
    }

    fn send_cell(&mut self, link: usize, cell: &Cell) -> Result<()> {
        let result = match self.links.get_mut(link).and_then(Option::as_mut) {
            Some(l) => l.send_cell(cell),
            None => Err(Error::Io(std::io::ErrorKind::NotConnected)),
        };
        if let Err(e) = &result {
            self.drop_link(link, e.clone());
        } else {
            self.cells_out += 1;
        }
        result
    }

    fn new_circ(&mut self, link: usize) -> u32 {
        let id = loop {
            let id = rand_u32() | 0x8000_0000;
            if !self.circs.iter().any(|c| c.id == id) {
                break id;
            }
        };
        self.circs.push(Circ {
            id,
            link,
            crypto: CircCrypto::default(),
            ctrl: VecDeque::new(),
            streams: Vec::new(),
            begins: VecDeque::new(),
            accept_begins: false,
            deliver_window: CIRC_WINDOW_START,
            package_window: CIRC_WINDOW_START,
            early_left: 8,
            next_stream_id: 1,
            closed: None,
        });
        id
    }

    /// Remove a circuit, telling the relay if it is still open.
    fn remove_circ(&mut self, id: u32) {
        if let Some(pos) = self.circs.iter().position(|c| c.id == id) {
            let circ = self.circs.swap_remove(pos);
            if circ.closed.is_none() && self.link_alive(circ.link) {
                let mut cell = Cell::new(id, cmd::DESTROY);
                cell.payload[0] = 0;
                let _ = self.send_cell(circ.link, &cell);
            }
            note_progress();
        }
    }

    /// Encrypt and send one relay cell from the origin to `hop`.
    fn send_relay(
        &mut self,
        id: u32,
        hop: usize,
        command: u8,
        stream_id: u16,
        data: &[u8],
        early: bool,
    ) -> Result<()> {
        let circ = self.circ(id)?;
        if hop >= circ.crypto.len() {
            return Err(Error::Proto("no such hop"));
        }
        let cell_cmd = if early {
            if circ.early_left == 0 {
                return Err(Error::Proto("out of RELAY_EARLY cells"));
            }
            circ.early_left -= 1;
            cmd::RELAY_EARLY
        } else {
            cmd::RELAY
        };
        let mut cell = Cell::new(id, cell_cmd);
        build_relay(&mut cell.payload, command, stream_id, data);
        circ.crypto.encrypt_outbound(hop, &mut cell.payload);
        let link = circ.link;
        self.send_cell(link, &cell)
    }

    fn on_cell(&mut self, link: usize, mut cell: Cell) {
        self.cells_in += 1;
        let Some(pos) = self
            .circs
            .iter()
            .position(|c| c.id == cell.circ_id && c.link == link)
        else {
            return;
        };
        match cell.cmd {
            cmd::RELAY | cmd::RELAY_EARLY => {
                let circ = &mut self.circs[pos];
                if circ.closed.is_some() {
                    return;
                }
                let Some((hop, digest)) = circ.crypto.decrypt_inbound(&mut cell.payload) else {
                    circ.closed = Some(Error::Proto("unrecognized relay cell"));
                    return;
                };
                self.on_relay(pos, hop, digest, &cell.payload);
            }
            cmd::CREATED2 | cmd::CREATED_FAST => {
                let circ = &mut self.circs[pos];
                circ.ctrl.push_back(RelayMsg {
                    cmd: relay::X_CREATED,
                    stream_id: 0,
                    hop: 0,
                    data: cell.payload[..66].to_vec(),
                });
            }
            cmd::DESTROY => {
                let reason = cell.payload[0];
                log::debug!("circuit {:08x}: DESTROY reason {reason}", cell.circ_id);
                self.circs[pos].closed.get_or_insert(Error::Closed(reason));
            }
            _ => {}
        }
    }

    fn on_relay(&mut self, pos: usize, hop: usize, digest: [u8; 20], payload: &[u8; PAYLOAD_LEN]) {
        let Some((command, stream_id, data)) = parse_relay(payload) else {
            self.circs[pos].closed = Some(Error::Proto("bad relay length"));
            return;
        };
        let circ = &mut self.circs[pos];
        let id = circ.id;
        match command {
            relay::DATA => {
                circ.deliver_window -= 1;
                let need_sendme = circ.deliver_window <= CIRC_WINDOW_START - CIRC_WINDOW_INCREMENT;
                if need_sendme {
                    circ.deliver_window += CIRC_WINDOW_INCREMENT;
                }
                if let Some(s) = circ.streams.iter_mut().find(|s| s.id == stream_id) {
                    s.deliver_window -= 1;
                    s.inbuf.extend(data);
                }
                if need_sendme {
                    // Authenticated SENDME (version 1): echo the digest of the cell that
                    // crossed the window boundary.
                    let mut body = [0u8; 23];
                    body[0] = 1;
                    body[2] = 20;
                    body[3..].copy_from_slice(&digest);
                    let _ = self.send_relay(id, hop, relay::SENDME, 0, &body, false);
                }
            }
            relay::SENDME => {
                if stream_id == 0 {
                    circ.package_window += CIRC_WINDOW_INCREMENT;
                } else if let Some(s) = circ.streams.iter_mut().find(|s| s.id == stream_id) {
                    s.package_window += STREAM_WINDOW_INCREMENT;
                }
            }
            relay::END => {
                if let Some(s) = circ.streams.iter_mut().find(|s| s.id == stream_id) {
                    s.remote_end = Some(data.first().copied().unwrap_or(end_reason::MISC));
                }
            }
            relay::CONNECTED => {
                if let Some(s) = circ.streams.iter_mut().find(|s| s.id == stream_id) {
                    s.connected = true;
                }
            }
            relay::BEGIN => {
                let last_hop = hop + 1 == circ.crypto.len();
                let known = circ.streams.iter().any(|s| s.id == stream_id);
                if !circ.accept_begins || !last_hop || known || stream_id == 0 {
                    return;
                }
                match parse_begin_port(data) {
                    Some(port) if circ.begins.len() < PENDING_BEGIN_MAX => {
                        circ.begins.push_back((stream_id, port));
                    }
                    _ => {
                        let _ = self.send_relay(
                            id,
                            hop,
                            relay::END,
                            stream_id,
                            &[end_reason::RESOURCELIMIT],
                            false,
                        );
                    }
                }
            }
            relay::TRUNCATED => {
                log::debug!(
                    "circuit {id:08x}: TRUNCATED by hop {hop} reason {:?}",
                    data.first()
                );
                circ.closed = Some(Error::Closed(data.first().copied().unwrap_or(0)));
            }
            relay::DROP => {}
            _ => {
                if circ.ctrl.len() < CTRL_QUEUE_MAX {
                    circ.ctrl.push_back(RelayMsg {
                        cmd: command,
                        stream_id,
                        hop: hop as u8,
                        data: data.to_vec(),
                    });
                }
            }
        }
        note_progress();
    }

    /// Whether some stream holds so much undelivered data that reading more cells should wait.
    /// The relay side of the link then backs up in TCP, which is the only flow control a
    /// 500-cell window leaves a device with this little memory.
    fn rx_blocked(&self) -> bool {
        let high_water = crate::rt::limits().stream_high_water;
        self.circs
            .iter()
            .flat_map(|c| c.streams.iter())
            .any(|s| s.inbuf.len() > high_water)
    }

    fn bury(&mut self) {
        let graveyard = self.graveyard.clone();
        let dead: Vec<(u32, u16)> = graveyard.borrow_mut().drain(..).collect();
        for (circ_id, stream_id) in dead {
            if stream_id == 0 {
                self.remove_circ(circ_id);
                continue;
            }
            let Some(circ) = self.circs.iter_mut().find(|c| c.id == circ_id) else {
                continue;
            };
            let Some(pos) = circ.streams.iter().position(|s| s.id == stream_id) else {
                continue;
            };
            let stream = circ.streams.swap_remove(pos);
            if stream.remote_end.is_none() && circ.closed.is_none() {
                let _ = self.send_relay(
                    circ_id,
                    stream.hop as usize,
                    relay::END,
                    stream_id,
                    &[end_reason::DONE],
                    false,
                );
            }
        }
    }
}

/// `ADDRPORT` in a BEGIN cell is `host:port\0` (the host is empty for onion streams).
fn parse_begin_port(data: &[u8]) -> Option<u16> {
    let end = data.iter().position(|&b| b == 0)?;
    let text = core::str::from_utf8(&data[..end]).ok()?;
    text.rsplit_once(':')?.1.parse().ok()
}

/// Move cells in from every link and flush what tasks queued. Call once per loop turn.
pub fn pump(core: &Shared) {
    let cells_per_turn = crate::rt::limits().cells_per_turn;
    let mut c = core.borrow_mut();
    c.bury();
    for idx in 0..c.links.len() {
        for _ in 0..cells_per_turn {
            if c.rx_blocked() {
                break;
            }
            let next = match c.links[idx].as_mut() {
                Some(link) => link.next_cell(),
                None => break,
            };
            match next {
                Ok(Some(cell)) => c.on_cell(idx, cell),
                Ok(None) => break,
                Err(e) => {
                    log::warn!("link {idx} failed: {e}");
                    c.drop_link(idx, e);
                    break;
                }
            }
        }
    }
    flush_locked(&mut c);
}

fn flush_locked(c: &mut Core) {
    for idx in 0..c.links.len() {
        let result = match c.links[idx].as_mut() {
            Some(link) => link.flush(),
            None => continue,
        };
        if let Err(e) = result {
            c.drop_link(idx, e);
        }
    }
}

pub fn flush(core: &Shared) {
    flush_locked(&mut core.borrow_mut());
}

/// An open circuit. Dropping the handle tears the circuit down.
pub struct Circuit {
    core: Shared,
    graveyard: Graveyard,
    pub id: u32,
}

impl Drop for Circuit {
    fn drop(&mut self) {
        self.graveyard.borrow_mut().push((self.id, 0));
    }
}

impl Circuit {
    fn new_on(core: &Shared, link: usize) -> Self {
        let (id, graveyard) = {
            let mut c = core.borrow_mut();
            (c.new_circ(link), c.graveyard.clone())
        };
        Self {
            core: core.clone(),
            graveyard,
            id,
        }
    }

    pub fn core(&self) -> &Shared {
        &self.core
    }

    pub fn hops(&self) -> usize {
        self.core
            .borrow_mut()
            .circ(self.id)
            .map(|c| c.crypto.len())
            .unwrap_or(0)
    }

    /// Streams currently open on this circuit.
    pub fn stream_count(&self) -> usize {
        self.core
            .borrow_mut()
            .circ(self.id)
            .map(|c| c.streams.len())
            .unwrap_or(0)
    }

    /// Fails once the circuit has been closed by either side.
    pub fn check(&self) -> Result<()> {
        self.core.borrow_mut().circ(self.id).map(|_| ())
    }

    pub fn kh(&self, hop: usize) -> Result<[u8; 20]> {
        Ok(self.core.borrow_mut().circ(self.id)?.crypto.kh(hop))
    }

    /// A one-hop circuit made with CREATE_FAST: no relay key needed, so it is how the first
    /// directory documents are fetched. Only ever used for directory requests.
    pub async fn create_fast(core: &Shared, link: usize) -> Result<Self> {
        let circ = Self::new_on(core, link);
        let x: [u8; 20] = rand_array();
        let cell = Cell::with_payload(circ.id, cmd::CREATE_FAST, &x);
        core.borrow_mut().send_cell(link, &cell)?;
        let reply = circ.recv_ctrl(relay::X_CREATED, "CREATED_FAST").await?;
        let (y, kh) = reply.data[..40].split_at(20);
        let mut k0 = [0u8; 40];
        k0[..20].copy_from_slice(&x);
        k0[20..].copy_from_slice(y);
        // KDF-TOR output order: KH, Df, Db, Kf, Kb. Rearranged to Df | Db | Kf | Kb | KH.
        let mut k = [0u8; CIRC_KEYS_LEN];
        kdf_tor(&k0, &mut k);
        if k[..20] != *kh {
            return Err(Error::Proto("CREATED_FAST key check"));
        }
        let mut keys = [0u8; CIRC_KEYS_LEN];
        keys[..72].copy_from_slice(&k[20..]);
        keys[72..].copy_from_slice(&k[..20]);
        core.borrow_mut()
            .circ(circ.id)?
            .crypto
            .push(HopCrypto::relay_hop(&keys));
        Ok(circ)
    }

    /// A one-hop circuit to `relay` with the ntor handshake.
    pub async fn create(core: &Shared, link: usize, relay_info: &RelayInfo) -> Result<Self> {
        let circ = Self::new_on(core, link);
        let (ntor, skin) = NtorClient::start(relay_info.rsa_id, relay_info.ntor_key);
        let mut body = [0u8; 4 + 84];
        body[1] = 2; // HTYPE ntor
        body[3] = 84; // HLEN
        body[4..].copy_from_slice(&skin);
        let cell = Cell::with_payload(circ.id, cmd::CREATE2, &body);
        core.borrow_mut().send_cell(link, &cell)?;
        let reply = circ.recv_ctrl(relay::X_CREATED, "CREATED2").await?;
        let keys = ntor.finish(&reply.data[2..66])?;
        core.borrow_mut()
            .circ(circ.id)?
            .crypto
            .push(HopCrypto::relay_hop(&keys));
        Ok(circ)
    }

    /// Extend the circuit by one hop.
    pub async fn extend(&self, relay_info: &RelayInfo) -> Result<()> {
        let (ntor, skin) = NtorClient::start(relay_info.rsa_id, relay_info.ntor_key);
        let mut body = relay_info.link_specifiers();
        body.extend_from_slice(&[0, 2, 0, 84]);
        body.extend_from_slice(&skin);
        let last = self
            .hops()
            .checked_sub(1)
            .ok_or(Error::Proto("empty circuit"))?;
        self.core
            .borrow_mut()
            .send_relay(self.id, last, relay::EXTEND2, 0, &body, true)?;
        let reply = self.recv_ctrl(relay::EXTENDED2, "EXTENDED2").await?;
        if reply.data.len() < 66 {
            return Err(Error::Proto("short EXTENDED2"));
        }
        let keys = ntor.finish(&reply.data[2..66])?;
        self.core
            .borrow_mut()
            .circ(self.id)?
            .crypto
            .push(HopCrypto::relay_hop(&keys));
        Ok(())
    }

    /// Build a circuit through `path` over the link to its first relay.
    pub async fn build(core: &Shared, link: usize, path: &[RelayInfo]) -> Result<Self> {
        let first = path.first().ok_or(Error::Proto("empty path"))?;
        let circ = Self::create(core, link, first).await.inspect_err(|e| {
            log::debug!("circuit: create at {} failed: {e}", first.addr);
        })?;
        for (i, hop) in path[1..].iter().enumerate() {
            circ.extend(hop).await.inspect_err(|e| {
                log::debug!(
                    "circuit {:08x}: extend {} -> {} failed: {e}",
                    circ.id,
                    path[i].addr,
                    hop.addr
                );
            })?;
        }
        Ok(circ)
    }

    /// Add the virtual hop for the far end of a rendezvous circuit.
    pub fn add_onion_hop(
        &self,
        keys: &[u8; crate::crypto::HS_KEYS_LEN],
        we_are_service: bool,
    ) -> Result<()> {
        let mut c = self.core.borrow_mut();
        let circ = c.circ(self.id)?;
        circ.crypto.push(HopCrypto::onion_hop(keys, we_are_service));
        // The far end starts with fresh windows of its own.
        circ.deliver_window = CIRC_WINDOW_START;
        circ.package_window = CIRC_WINDOW_START;
        circ.accept_begins = we_are_service;
        Ok(())
    }

    /// Send a relay message to the last hop.
    pub fn send(&self, command: u8, data: &[u8]) -> Result<()> {
        let last = self
            .hops()
            .checked_sub(1)
            .ok_or(Error::Proto("empty circuit"))?;
        self.core
            .borrow_mut()
            .send_relay(self.id, last, command, 0, data, false)
    }

    /// Wait for the next control message; anything other than `expect` is an error.
    pub async fn recv_ctrl(&self, expect: u8, what: &'static str) -> Result<RelayMsg> {
        let msg = timeout(STEP_TIMEOUT, what, self.next_ctrl()).await?;
        if msg.cmd != expect {
            log::debug!("expected {what}, got relay command {}", msg.cmd);
            return Err(Error::Proto("unexpected relay message"));
        }
        Ok(msg)
    }

    /// Wait (without a deadline) for the next control message on this circuit.
    pub async fn next_ctrl(&self) -> Result<RelayMsg> {
        poll_fn(|_| {
            let mut c = self.core.borrow_mut();
            let Some(circ) = c.circs.iter_mut().find(|c| c.id == self.id) else {
                return Poll::Ready(Err(Error::Closed(end_reason::DESTROY)));
            };
            if let Some(msg) = circ.ctrl.pop_front() {
                return Poll::Ready(Ok(msg));
            }
            match &circ.closed {
                Some(e) => Poll::Ready(Err(e.clone())),
                None => Poll::Pending,
            }
        })
        .await
    }

    /// Open a directory stream to the last hop (BEGIN_DIR).
    pub async fn begin_dir(&self) -> Result<Stream> {
        let (stream_id, hop) = {
            let mut c = self.core.borrow_mut();
            let circ = c.circ(self.id)?;
            let hop = circ
                .crypto
                .len()
                .checked_sub(1)
                .ok_or(Error::Proto("empty circuit"))?;
            let stream_id = circ.next_stream_id;
            circ.next_stream_id = circ.next_stream_id.checked_add(1).unwrap_or(1);
            circ.streams
                .push(StreamState::new(stream_id, hop as u8, false));
            c.send_relay(self.id, hop, relay::BEGIN_DIR, stream_id, &[], false)?;
            (stream_id, hop)
        };
        let stream = Stream {
            core: self.core.clone(),
            graveyard: self.graveyard.clone(),
            circ: self.id,
            id: stream_id,
            hop: hop as u8,
        };
        timeout(STEP_TIMEOUT, "CONNECTED", stream.wait_connected()).await?;
        Ok(stream)
    }

    /// Open a stream to `host:port` through the last hop (an exit or, with an empty host, the
    /// onion service at the far end of a rendezvous circuit).
    pub async fn begin(&self, host: &str, port: u16) -> Result<Stream> {
        let mut body = format!("{host}:{port}").into_bytes();
        body.push(0);
        body.extend_from_slice(&[0, 0, 0, 0]);
        let (stream_id, hop) = {
            let mut c = self.core.borrow_mut();
            let circ = c.circ(self.id)?;
            let hop = circ
                .crypto
                .len()
                .checked_sub(1)
                .ok_or(Error::Proto("empty circuit"))?;
            let stream_id = circ.next_stream_id;
            circ.next_stream_id = circ.next_stream_id.checked_add(1).unwrap_or(1);
            circ.streams
                .push(StreamState::new(stream_id, hop as u8, false));
            c.send_relay(self.id, hop, relay::BEGIN, stream_id, &body, false)?;
            (stream_id, hop)
        };
        let stream = Stream {
            core: self.core.clone(),
            graveyard: self.graveyard.clone(),
            circ: self.id,
            id: stream_id,
            hop: hop as u8,
        };
        timeout(STEP_TIMEOUT, "CONNECTED", stream.wait_connected()).await?;
        Ok(stream)
    }

    /// Wait for the far end to open a stream (service side of a rendezvous circuit). Returns
    /// the requested port and a handle that must be accepted or rejected.
    pub async fn next_begin(&self) -> Result<PendingStream> {
        poll_fn(|_| {
            let mut c = self.core.borrow_mut();
            let Some(circ) = c.circs.iter_mut().find(|c| c.id == self.id) else {
                return Poll::Ready(Err(Error::Closed(end_reason::DESTROY)));
            };
            if let Some((stream_id, port)) = circ.begins.pop_front() {
                let hop = (circ.crypto.len() - 1) as u8;
                circ.streams.push(StreamState::new(stream_id, hop, false));
                return Poll::Ready(Ok(PendingStream {
                    port,
                    stream: Stream {
                        core: self.core.clone(),
                        graveyard: self.graveyard.clone(),
                        circ: self.id,
                        id: stream_id,
                        hop,
                    },
                }));
            }
            match &circ.closed {
                Some(e) => Poll::Ready(Err(e.clone())),
                None => Poll::Pending,
            }
        })
        .await
    }
}

impl StreamState {
    fn new(id: u16, hop: u8, connected: bool) -> Self {
        Self {
            id,
            hop,
            inbuf: VecDeque::new(),
            connected,
            remote_end: None,
            deliver_window: STREAM_WINDOW_START,
            package_window: STREAM_WINDOW_START,
        }
    }
}

/// A stream the other side asked for and we have not answered yet.
pub struct PendingStream {
    pub port: u16,
    stream: Stream,
}

impl PendingStream {
    /// Answer CONNECTED and start carrying data.
    pub fn accept(self) -> Result<Stream> {
        {
            let mut c = self.stream.core.borrow_mut();
            c.send_relay(
                self.stream.circ,
                self.stream.hop as usize,
                relay::CONNECTED,
                self.stream.id,
                &[],
                false,
            )?;
            if let Some(s) = c
                .circ(self.stream.circ)?
                .streams
                .iter_mut()
                .find(|s| s.id == self.stream.id)
            {
                s.connected = true;
            }
        }
        Ok(self.stream)
    }

    /// Refuse with a RELAY_END carrying `reason`.
    pub fn reject(self, reason: u8) {
        self.stream.end(reason);
    }
}

/// One stream on a circuit. Dropping it sends RELAY_END if the stream is still open.
pub struct Stream {
    core: Shared,
    graveyard: Graveyard,
    circ: u32,
    id: u16,
    hop: u8,
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.graveyard.borrow_mut().push((self.circ, self.id));
    }
}

impl Stream {
    async fn wait_connected(&self) -> Result<()> {
        poll_fn(|_| {
            let mut c = self.core.borrow_mut();
            let circ = match c.circ(self.circ) {
                Ok(circ) => circ,
                Err(e) => return Poll::Ready(Err(e)),
            };
            match circ.streams.iter().find(|s| s.id == self.id) {
                Some(s) if s.connected => Poll::Ready(Ok(())),
                Some(s) => match s.remote_end {
                    Some(reason) => Poll::Ready(Err(Error::Closed(reason))),
                    None => Poll::Pending,
                },
                None => Poll::Ready(Err(Error::Closed(end_reason::MISC))),
            }
        })
        .await
    }

    /// Bytes waiting to be read.
    pub fn buffered(&self) -> usize {
        let mut c = self.core.borrow_mut();
        c.circ(self.circ)
            .ok()
            .and_then(|circ| circ.streams.iter().find(|s| s.id == self.id))
            .map_or(0, |s| s.inbuf.len())
    }

    /// Read without waiting: `Ok(Some(0))` is end of stream, `Ok(None)` means nothing yet.
    pub fn try_read(&self, buf: &mut [u8]) -> Result<Option<usize>> {
        let mut c = self.core.borrow_mut();
        let circ = match c.circs.iter_mut().find(|c| c.id == self.circ) {
            Some(circ) => circ,
            None => return Err(Error::Closed(end_reason::DESTROY)),
        };
        let circ_closed = circ.closed.clone();
        let Some(s) = circ.streams.iter_mut().find(|s| s.id == self.id) else {
            return Err(Error::Closed(end_reason::MISC));
        };
        if s.inbuf.is_empty() {
            if s.remote_end.is_some() {
                return Ok(Some(0));
            }
            return match circ_closed {
                Some(e) => Err(e),
                None => Ok(None),
            };
        }
        let n = buf.len().min(s.inbuf.len());
        for (dst, src) in buf.iter_mut().zip(s.inbuf.drain(..n)) {
            *dst = src;
        }
        // Re-open the window once the consumer has caught up.
        let mut sendmes = 0;
        while s.deliver_window <= STREAM_WINDOW_START - STREAM_WINDOW_INCREMENT
            && s.inbuf.len() < crate::rt::limits().stream_high_water / 2
        {
            s.deliver_window += STREAM_WINDOW_INCREMENT;
            sendmes += 1;
        }
        let hop = s.hop as usize;
        if circ_closed.is_none() && s.remote_end.is_none() {
            for _ in 0..sendmes {
                c.send_relay(self.circ, hop, relay::SENDME, self.id, &[], false)?;
            }
        }
        note_progress();
        Ok(Some(n))
    }

    /// Read some bytes; zero means the other side ended the stream.
    pub async fn read(&self, buf: &mut [u8]) -> Result<usize> {
        poll_fn(|_| match self.try_read(buf) {
            Ok(Some(n)) => Poll::Ready(Ok(n)),
            Ok(None) => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        })
        .await
    }

    /// Whether one more DATA cell fits in both flow-control windows right now.
    pub fn can_send(&self) -> Result<bool> {
        let mut c = self.core.borrow_mut();
        let circ = c.circ(self.circ)?;
        let circ_ok = circ.package_window > 0;
        let s = circ
            .streams
            .iter()
            .find(|s| s.id == self.id)
            .ok_or(Error::Closed(end_reason::MISC))?;
        if let Some(reason) = s.remote_end {
            return Err(Error::Closed(reason));
        }
        Ok(circ_ok && s.package_window > 0)
    }

    /// Send up to one cell of data without waiting. Returns how much was taken.
    pub fn try_write(&self, data: &[u8]) -> Result<usize> {
        if data.is_empty() || !self.can_send()? {
            return Ok(0);
        }
        let n = data.len().min(RELAY_DATA_MAX);
        let mut c = self.core.borrow_mut();
        c.send_relay(
            self.circ,
            self.hop as usize,
            relay::DATA,
            self.id,
            &data[..n],
            false,
        )?;
        let circ = c.circ(self.circ)?;
        circ.package_window -= 1;
        if let Some(s) = circ.streams.iter_mut().find(|s| s.id == self.id) {
            s.package_window -= 1;
        }
        Ok(n)
    }

    pub async fn write_all(&self, mut data: &[u8]) -> Result<()> {
        let mut burst = 0;
        while !data.is_empty() {
            let n = self.try_write(data)?;
            data = &data[n..];
            burst += 1;
            if n == 0 || burst % 8 == 0 {
                yield_now().await;
            }
        }
        Ok(())
    }

    /// End the stream with a reason; the handle is consumed.
    pub fn end(self, reason: u8) {
        {
            let mut c = self.core.borrow_mut();
            let open = c
                .circ(self.circ)
                .ok()
                .and_then(|circ| circ.streams.iter_mut().find(|s| s.id == self.id))
                .map(|s| {
                    let open = s.remote_end.is_none();
                    // Mark it so the drop below does not send a second END.
                    s.remote_end.get_or_insert(end_reason::DONE);
                    open
                })
                .unwrap_or(false);
            if open {
                let _ = c.send_relay(
                    self.circ,
                    self.hop as usize,
                    relay::END,
                    self.id,
                    &[reason],
                    false,
                );
            }
        }
        drop(self);
    }
}

/// Connect a link to `addr` and register it. Blocks the loop for the TCP and TLS handshakes.
pub fn connect_link(core: &Shared, addr: SocketAddrV4, connect_timeout: Duration) -> Result<usize> {
    let started = Instant::now();
    let link = Link::connect(addr, connect_timeout)?;
    log::debug!(
        "link to {addr} up in {:?} (v{})",
        started.elapsed(),
        link.link_version
    );
    Ok(core.borrow_mut().add_link(link))
}

/// One turn of the event loop: cells in, every task polled once, cells out. Sleeps briefly
/// when nothing moved. Returns the number of live tasks.
pub fn turn(core: &Shared, exec: &mut crate::rt::Executor) -> usize {
    let before = crate::rt::progress();
    let t0 = Instant::now();
    pump(core);
    let t1 = Instant::now();
    let alive = exec.turn();
    let t2 = Instant::now();
    flush(core);
    let t3 = Instant::now();
    let total = t3 - t0;
    if total > Duration::from_millis(1500) {
        // Everything shares this loop; a turn this long delays every circuit.
        log::warn!(
            "slow loop turn: link read {:?}, tasks {:?}, flush {:?}",
            t1 - t0,
            t2 - t1,
            t3 - t2
        );
    } else if total > Duration::from_millis(250) {
        log::debug!(
            "slow loop turn: link read {:?}, tasks {:?}, flush {:?}",
            t1 - t0,
            t2 - t1,
            t3 - t2
        );
    }
    if crate::rt::progress() == before {
        std::thread::sleep(Duration::from_millis(2));
    }
    alive
}
