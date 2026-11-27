//! A link: one TLS connection to a relay, carrying cells (tor-spec 2 and 4).
//!
//! The relay's TLS certificate is not checked. Tor relays present self-signed certificates and
//! authenticate themselves inside the protocol; this client authenticates every hop with the
//! ntor handshake against a key from the signed consensus instead of verifying the CERTS cell.
//! The one unauthenticated use, CREATE_FAST directory circuits, only ever carries documents
//! that are checked against directory-authority signatures or consensus digests.

use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::rc::Rc;
use std::time::{Duration, Instant};

use embedded_tls::blocking::{
    Aes128GcmSha256, TlsConfig, TlsConnection, TlsContext, UnsecureProvider,
};

use crate::cell::{cmd, Cell, CELL_LEN, PAYLOAD_LEN};
use crate::crypto::SysRng;
use crate::rt::note_progress;
use crate::{Error, Result};

/// The largest TLS record a relay may send, plus header and tag.
const TLS_READ_BUF: usize = 16_640;
/// Room for eight cells per outgoing record.
const TLS_WRITE_BUF: usize = 8 * CELL_LEN + 64;
/// Variable-length cells after the handshake are padding; nothing legitimate is larger.
const MAX_VAR_CELL: usize = 8 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(20);

/// A non-blocking socket presented as a blocking one with a deadline. The loop polls the
/// socket for readability first, so a read here only waits for the rest of a TLS record that
/// is already on its way.
struct Sock {
    stream: Rc<TcpStream>,
}

impl embedded_io::ErrorType for Sock {
    type Error = std::io::Error;
}

impl embedded_io::Read for Sock {
    fn read(&mut self, buf: &mut [u8]) -> core::result::Result<usize, Self::Error> {
        let start = Instant::now();
        loop {
            match (&*self.stream).read(buf) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if start.elapsed() > IO_TIMEOUT {
                        return Err(std::io::ErrorKind::TimedOut.into());
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                other => return other,
            }
        }
    }
}

impl embedded_io::Write for Sock {
    fn write(&mut self, buf: &[u8]) -> core::result::Result<usize, Self::Error> {
        let start = Instant::now();
        loop {
            match (&*self.stream).write(buf) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if start.elapsed() > IO_TIMEOUT {
                        return Err(std::io::ErrorKind::TimedOut.into());
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                other => return other,
            }
        }
    }

    fn flush(&mut self) -> core::result::Result<(), Self::Error> {
        Ok(())
    }
}

/// Reassembles cells from a byte stream that splits them arbitrarily.
struct CellParser {
    carry: Vec<u8>,
    /// 2 until VERSIONS has been negotiated, then 4.
    circ_id_len: usize,
}

/// A cell off the wire. The fixed variant is the hot path and stays inline.
#[allow(clippy::large_enum_variant)]
pub enum Incoming {
    Fixed(Cell),
    Variable { cmd: u8, body: Vec<u8> },
}

impl CellParser {
    fn new() -> Self {
        Self {
            carry: Vec::with_capacity(CELL_LEN),
            circ_id_len: 2,
        }
    }

    /// How many more bytes the cell under assembly needs before the next decision point
    /// (zero means it is complete).
    fn wanted(&self) -> Result<usize> {
        let n = self.circ_id_len;
        let have = self.carry.len();
        if have < n + 1 {
            return Ok(n + 1 - have);
        }
        if !cmd::is_variable(self.carry[n]) {
            return Ok(n + 1 + PAYLOAD_LEN - have);
        }
        if have < n + 3 {
            return Ok(n + 3 - have);
        }
        let len = u16::from_be_bytes([self.carry[n + 1], self.carry[n + 2]]) as usize;
        if len > MAX_VAR_CELL {
            return Err(Error::Proto("oversized variable cell"));
        }
        Ok(n + 3 + len - have)
    }

    fn push(&mut self, data: &[u8]) {
        self.carry.extend_from_slice(data);
    }

    /// Take the completed cell out. Only valid when `wanted()` is zero.
    fn take(&mut self) -> Incoming {
        let n = self.circ_id_len;
        let command = self.carry[n];
        let out = if cmd::is_variable(command) {
            Incoming::Variable {
                cmd: command,
                body: self.carry[n + 3..].to_vec(),
            }
        } else {
            let circ_id = if n == 4 {
                u32::from_be_bytes(self.carry[..4].try_into().unwrap())
            } else {
                u32::from(u16::from_be_bytes([self.carry[0], self.carry[1]]))
            };
            let mut cell = Cell::new(circ_id, command);
            cell.payload
                .copy_from_slice(&self.carry[n + 1..n + 1 + PAYLOAD_LEN]);
            Incoming::Fixed(cell)
        };
        self.carry.clear();
        out
    }
}

pub struct Link {
    // Field order matters: `tls` borrows the two buffers below and must drop first.
    tls: TlsConnection<'static, Sock, Aes128GcmSha256>,
    _read_buf: Box<[u8]>,
    _write_buf: Box<[u8]>,
    stream: Rc<TcpStream>,
    parser: CellParser,
    /// The TLS layer still holds decrypted bytes we have not taken.
    buffered: bool,
    dirty: bool,
    pub peer: SocketAddrV4,
    /// Our address as the relay sees it (from its NETINFO cell).
    pub observed_addr: Option<Ipv4Addr>,
    /// The relay's clock when the link came up.
    pub peer_time: u32,
    pub link_version: u16,
    pub last_rx: Instant,
}

impl Link {
    /// Connect, run the TLS handshake and the link handshake. Blocks for up to `timeout`
    /// on the TCP connect and a few seconds on the handshakes.
    pub fn connect(peer: SocketAddrV4, timeout: Duration) -> Result<Self> {
        let stream = TcpStream::connect_timeout(&SocketAddr::V4(peer), timeout)?;
        stream.set_nodelay(true).ok();
        stream.set_nonblocking(true)?;
        let stream = Rc::new(stream);

        let mut read_buf = vec![0u8; TLS_READ_BUF].into_boxed_slice();
        let mut write_buf = vec![0u8; TLS_WRITE_BUF].into_boxed_slice();
        // SAFETY: the boxes are owned by the returned `Link`, are never moved out of or
        // reallocated, and outlive `tls`, which is declared first and so dropped first.
        let (read_ref, write_ref): (&'static mut [u8], &'static mut [u8]) = unsafe {
            (
                core::slice::from_raw_parts_mut(read_buf.as_mut_ptr(), read_buf.len()),
                core::slice::from_raw_parts_mut(write_buf.as_mut_ptr(), write_buf.len()),
            )
        };
        let sock = Sock {
            stream: stream.clone(),
        };
        let mut tls: TlsConnection<'static, Sock, Aes128GcmSha256> =
            TlsConnection::new(sock, read_ref, write_ref);
        let config = TlsConfig::new();
        tls.open(TlsContext::new(
            &config,
            UnsecureProvider::new::<Aes128GcmSha256>(SysRng),
        ))
        .map_err(|e| {
            log::debug!("tls open to {peer} failed: {e:?}");
            Error::Tls
        })?;

        let mut link = Self {
            tls,
            _read_buf: read_buf,
            _write_buf: write_buf,
            stream,
            parser: CellParser::new(),
            buffered: false,
            dirty: false,
            peer,
            observed_addr: None,
            peer_time: 0,
            link_version: 0,
            last_rx: Instant::now(),
        };
        link.handshake()?;
        Ok(link)
    }

    fn handshake(&mut self) -> Result<()> {
        // VERSIONS: 2-byte circuit id, command, length, then the versions we speak (4 and 5).
        self.write_all(&[0, 0, cmd::VERSIONS, 0, 4, 0, 4, 0, 5])?;
        self.flush()?;

        let deadline = Instant::now() + IO_TIMEOUT;
        let mut version = 0u16;
        loop {
            if Instant::now() > deadline {
                return Err(Error::Timeout("link handshake"));
            }
            match self.read_cell(true)? {
                Some(Incoming::Variable {
                    cmd: cmd::VERSIONS,
                    body,
                }) => {
                    version = body
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|v| u16::from_be_bytes([v[0], v[1]]))
                        .filter(|v| *v == 4 || *v == 5)
                        .max()
                        .ok_or(Error::Proto("no common link version"))?;
                    self.parser.circ_id_len = 4;
                }
                Some(Incoming::Fixed(cell)) if cell.cmd == cmd::NETINFO => {
                    if version == 0 {
                        return Err(Error::Proto("netinfo before versions"));
                    }
                    let p = &cell.payload;
                    self.peer_time = u32::from_be_bytes(p[..4].try_into().unwrap());
                    self.observed_addr =
                        (p[4] == 4 && p[5] == 4).then(|| Ipv4Addr::new(p[6], p[7], p[8], p[9]));
                    break;
                }
                // CERTS, AUTH_CHALLENGE and padding: not used (see the module comment).
                _ => {}
            }
        }
        self.link_version = version;

        // Our NETINFO: no timestamp (clients send zero), the relay's address, none of ours.
        let mut cell = Cell::new(0, cmd::NETINFO);
        cell.payload[4] = 4;
        cell.payload[5] = 4;
        cell.payload[6..10].copy_from_slice(&self.peer.ip().octets());
        self.send_cell(&cell)?;
        self.flush()?;
        Ok(())
    }

    fn write_all(&mut self, mut data: &[u8]) -> Result<()> {
        while !data.is_empty() {
            let n = self.tls.write(data).map_err(|_| Error::Tls)?;
            data = &data[n..];
        }
        self.dirty = true;
        Ok(())
    }

    /// Queue a cell; it reaches the wire when the record fills or on `flush`.
    pub fn send_cell(&mut self, cell: &Cell) -> Result<()> {
        let mut buf = [0u8; CELL_LEN];
        cell.encode(&mut buf);
        note_progress();
        self.write_all(&buf)
    }

    pub fn flush(&mut self) -> Result<()> {
        if self.dirty {
            self.tls.flush().map_err(|_| Error::Tls)?;
            self.dirty = false;
        }
        Ok(())
    }

    fn readable(&self) -> Result<bool> {
        let mut probe = [0u8; 1];
        match self.stream.peek(&mut probe) {
            Ok(0) => Err(Error::Io(std::io::ErrorKind::UnexpectedEof)),
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Assemble the next cell. With `block` false this returns `None` as soon as the socket
    /// has nothing more to give; with `block` true it waits for a whole cell.
    fn read_cell(&mut self, block: bool) -> Result<Option<Incoming>> {
        loop {
            let wanted = self.parser.wanted()?;
            if wanted == 0 {
                return Ok(Some(self.parser.take()));
            }
            if !block && !self.buffered && !self.readable()? {
                return Ok(None);
            }
            let mut buffer = self.tls.read_buffered().map_err(|e| {
                log::debug!("tls read from {} failed: {e:?}", self.peer);
                Error::Tls
            })?;
            let chunk = buffer.pop(wanted);
            self.buffered = !buffer.is_empty();
            self.parser.push(chunk);
            self.last_rx = Instant::now();
        }
    }

    /// The next fixed-length cell that has fully arrived, if any. Never waits for the
    /// network beyond the remainder of a TLS record that is already in flight.
    pub fn next_cell(&mut self) -> Result<Option<Cell>> {
        loop {
            match self.read_cell(false)? {
                Some(Incoming::Fixed(cell)) => {
                    note_progress();
                    return Ok(Some(cell));
                }
                Some(Incoming::Variable { .. }) => {}
                None => return Ok(None),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_reassembles_split_cells() {
        let mut stream = Vec::new();
        // A VERSIONS cell (2-byte circ id), then two fixed cells with 4-byte ids and a
        // variable cell between them.
        stream.extend_from_slice(&[0, 0, cmd::VERSIONS, 0, 2, 0, 4]);
        let mut fixed = [0u8; CELL_LEN];
        Cell::with_payload(0x8000_0001, cmd::RELAY, b"one").encode(&mut fixed);
        stream.extend_from_slice(&fixed);
        stream.extend_from_slice(&[0, 0, 0, 0, cmd::VPADDING, 0, 3, 9, 9, 9]);
        Cell::with_payload(0x8000_0002, cmd::DESTROY, b"two").encode(&mut fixed);
        stream.extend_from_slice(&fixed);

        for chunk in [1usize, 2, 3, 7, 100, 513, 514, 515, 4096] {
            let mut parser = CellParser::new();
            let mut seen = Vec::new();
            for piece in stream.chunks(chunk) {
                let mut piece = piece;
                loop {
                    let wanted = parser.wanted().unwrap();
                    if wanted == 0 {
                        match parser.take() {
                            Incoming::Variable {
                                cmd: cmd::VERSIONS, ..
                            } => {
                                seen.push((0, cmd::VERSIONS));
                                parser.circ_id_len = 4;
                            }
                            Incoming::Variable { cmd, body } => {
                                assert_eq!(body, &[9, 9, 9]);
                                seen.push((0, cmd));
                            }
                            Incoming::Fixed(cell) => seen.push((cell.circ_id, cell.cmd)),
                        }
                        continue;
                    }
                    if piece.is_empty() {
                        break;
                    }
                    let take = wanted.min(piece.len());
                    parser.push(&piece[..take]);
                    piece = &piece[take..];
                }
            }
            assert_eq!(
                seen,
                vec![
                    (0, cmd::VERSIONS),
                    (0x8000_0001, cmd::RELAY),
                    (0, cmd::VPADDING),
                    (0x8000_0002, cmd::DESTROY)
                ],
                "chunk size {chunk}"
            );
        }
    }
}
