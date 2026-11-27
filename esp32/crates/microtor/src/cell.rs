//! Cell and relay-cell formats (tor-spec 3, 6.1) and the per-hop relay cryptography.

use aes::cipher::StreamCipher;
use sha1::Sha1;
use sha2::Digest;
use sha3::Sha3_256;

use crate::crypto::{aes128_ctr, aes256_ctr, Aes128Ctr, Aes256Ctr, CIRC_KEYS_LEN, HS_KEYS_LEN};

pub const PAYLOAD_LEN: usize = 509;
/// A fixed-length cell on link protocol 4 and later: 4-byte circuit id, command, payload.
pub const CELL_LEN: usize = 4 + 1 + PAYLOAD_LEN;
/// Relay header: command, recognized, stream id, digest, length.
pub const RELAY_HEADER_LEN: usize = 11;
pub const RELAY_DATA_MAX: usize = PAYLOAD_LEN - RELAY_HEADER_LEN;

pub mod cmd {
    pub const PADDING: u8 = 0;
    pub const RELAY: u8 = 3;
    pub const DESTROY: u8 = 4;
    pub const CREATE_FAST: u8 = 5;
    pub const CREATED_FAST: u8 = 6;
    pub const VERSIONS: u8 = 7;
    pub const NETINFO: u8 = 8;
    pub const RELAY_EARLY: u8 = 9;
    pub const CREATE2: u8 = 10;
    pub const CREATED2: u8 = 11;
    pub const VPADDING: u8 = 128;
    pub const CERTS: u8 = 129;
    pub const AUTH_CHALLENGE: u8 = 130;

    pub fn is_variable(cmd: u8) -> bool {
        cmd == VERSIONS || cmd >= 128
    }
}

pub mod relay {
    pub const BEGIN: u8 = 1;
    pub const DATA: u8 = 2;
    pub const END: u8 = 3;
    pub const CONNECTED: u8 = 4;
    pub const SENDME: u8 = 5;
    pub const TRUNCATED: u8 = 9;
    pub const DROP: u8 = 10;
    pub const BEGIN_DIR: u8 = 13;
    pub const EXTEND2: u8 = 14;
    pub const EXTENDED2: u8 = 15;
    pub const ESTABLISH_INTRO: u8 = 32;
    pub const ESTABLISH_RENDEZVOUS: u8 = 33;
    pub const INTRODUCE1: u8 = 34;
    pub const INTRODUCE2: u8 = 35;
    pub const RENDEZVOUS1: u8 = 36;
    pub const RENDEZVOUS2: u8 = 37;
    pub const INTRO_ESTABLISHED: u8 = 38;
    pub const RENDEZVOUS_ESTABLISHED: u8 = 39;
    pub const INTRODUCE_ACK: u8 = 40;

    /// Pseudo-commands for non-relay cells delivered through the same per-circuit queue.
    pub const X_CREATED: u8 = 250;
}

pub mod end_reason {
    pub const MISC: u8 = 1;
    pub const RESOLVEFAILED: u8 = 2;
    pub const CONNECTREFUSED: u8 = 3;
    pub const EXITPOLICY: u8 = 4;
    pub const DESTROY: u8 = 5;
    pub const DONE: u8 = 6;
    pub const TIMEOUT: u8 = 7;
    pub const NOROUTE: u8 = 8;
    pub const RESOURCELIMIT: u8 = 11;
}

/// A fixed-length cell.
pub struct Cell {
    pub circ_id: u32,
    pub cmd: u8,
    pub payload: [u8; PAYLOAD_LEN],
}

impl Cell {
    pub fn new(circ_id: u32, cmd: u8) -> Self {
        Self {
            circ_id,
            cmd,
            payload: [0u8; PAYLOAD_LEN],
        }
    }

    pub fn with_payload(circ_id: u32, cmd: u8, data: &[u8]) -> Self {
        let mut cell = Self::new(circ_id, cmd);
        cell.payload[..data.len()].copy_from_slice(data);
        cell
    }

    pub fn encode(&self, out: &mut [u8; CELL_LEN]) {
        out[..4].copy_from_slice(&self.circ_id.to_be_bytes());
        out[4] = self.cmd;
        out[5..].copy_from_slice(&self.payload);
    }
}

/// Fill in a relay cell payload: header plus data, digest left zero for the hop crypto to set.
pub fn build_relay(payload: &mut [u8; PAYLOAD_LEN], command: u8, stream_id: u16, data: &[u8]) {
    debug_assert!(data.len() <= RELAY_DATA_MAX);
    payload.fill(0);
    payload[0] = command;
    payload[3..5].copy_from_slice(&stream_id.to_be_bytes());
    payload[9..11].copy_from_slice(&(data.len() as u16).to_be_bytes());
    payload[RELAY_HEADER_LEN..RELAY_HEADER_LEN + data.len()].copy_from_slice(data);
    // Random padding after the data would go here (tor-spec 6.1 asks for 4 zero bytes, then
    // random). Zeros are valid and keep this path allocation- and RNG-free.
}

/// A decoded relay message.
#[derive(Debug, Clone)]
pub struct RelayMsg {
    pub cmd: u8,
    pub stream_id: u16,
    /// Index of the hop that originated the message.
    pub hop: u8,
    pub data: Vec<u8>,
}

pub fn parse_relay(payload: &[u8; PAYLOAD_LEN]) -> Option<(u8, u16, &[u8])> {
    let len = u16::from_be_bytes([payload[9], payload[10]]) as usize;
    if len > RELAY_DATA_MAX {
        return None;
    }
    let stream_id = u16::from_be_bytes([payload[3], payload[4]]);
    Some((
        payload[0],
        stream_id,
        &payload[RELAY_HEADER_LEN..RELAY_HEADER_LEN + len],
    ))
}

// Inline on purpose: a hop's state is touched for every cell, and boxing the larger variant
// would add a heap allocation per hop on a device that has none to spare.
#[allow(clippy::large_enum_variant)]
enum Cipher {
    Aes128(Aes128Ctr),
    Aes256(Aes256Ctr),
}

impl Cipher {
    fn apply(&mut self, data: &mut [u8]) {
        match self {
            Cipher::Aes128(c) => c.apply_keystream(data),
            Cipher::Aes256(c) => c.apply_keystream(data),
        }
    }
}

// Inline for the same reason as `Cipher`.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
enum Running {
    Sha1(Sha1),
    Sha3(Sha3_256),
}

impl Running {
    fn update(&mut self, data: &[u8]) {
        match self {
            Running::Sha1(h) => h.update(data),
            Running::Sha3(h) => h.update(data),
        }
    }

    /// The digest so far, without disturbing the running state. 20 bytes: the whole SHA-1
    /// output, or the first 20 bytes of SHA3-256 (what authenticated SENDMEs carry).
    fn peek(&self) -> [u8; 20] {
        let mut out = [0u8; 20];
        match self {
            Running::Sha1(h) => out.copy_from_slice(&h.clone().finalize()),
            Running::Sha3(h) => out.copy_from_slice(&h.clone().finalize()[..20]),
        }
        out
    }
}

/// One hop's send and receive state.
pub struct HopCrypto {
    send_cipher: Cipher,
    recv_cipher: Cipher,
    send_digest: Running,
    recv_digest: Running,
    /// `KH` from the circuit handshake; the intro-point handshake MACs with it.
    pub kh: [u8; 20],
}

impl HopCrypto {
    /// A relay hop, from `Df | Db | Kf | Kb | KH` (we send forward, receive backward).
    pub fn relay_hop(keys: &[u8; CIRC_KEYS_LEN]) -> Self {
        let mut send_digest = Sha1::new();
        send_digest.update(&keys[..20]);
        let mut recv_digest = Sha1::new();
        recv_digest.update(&keys[20..40]);
        Self {
            send_cipher: Cipher::Aes128(aes128_ctr(keys[40..56].try_into().unwrap())),
            recv_cipher: Cipher::Aes128(aes128_ctr(keys[56..72].try_into().unwrap())),
            send_digest: Running::Sha1(send_digest),
            recv_digest: Running::Sha1(recv_digest),
            kh: keys[72..92].try_into().unwrap(),
        }
    }

    /// The virtual hop at the far end of a rendezvous circuit, from `Df | Db | Kf | Kb`.
    /// The client is the initiator, so a service sends with the backward keys.
    pub fn onion_hop(keys: &[u8; HS_KEYS_LEN], we_are_service: bool) -> Self {
        let zero_iv = [0u8; 16];
        let mut df = Sha3_256::new();
        df.update(&keys[..32]);
        let mut db = Sha3_256::new();
        db.update(&keys[32..64]);
        let kf = aes256_ctr(keys[64..96].try_into().unwrap(), &zero_iv);
        let kb = aes256_ctr(keys[96..128].try_into().unwrap(), &zero_iv);
        let (send_cipher, recv_cipher, send_digest, recv_digest) = if we_are_service {
            (kb, kf, db, df)
        } else {
            (kf, kb, df, db)
        };
        Self {
            send_cipher: Cipher::Aes256(send_cipher),
            recv_cipher: Cipher::Aes256(recv_cipher),
            send_digest: Running::Sha3(send_digest),
            recv_digest: Running::Sha3(recv_digest),
            kh: [0u8; 20],
        }
    }
}

/// The layered cryptographic state of one circuit.
#[derive(Default)]
pub struct CircCrypto {
    hops: Vec<HopCrypto>,
}

impl CircCrypto {
    pub fn push(&mut self, hop: HopCrypto) {
        self.hops.push(hop);
    }

    pub fn len(&self) -> usize {
        self.hops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }

    pub fn kh(&self, hop: usize) -> [u8; 20] {
        self.hops[hop].kh
    }

    /// Set the digest for `hop` and apply every layer from that hop inward. Returns the
    /// 20-byte running digest after this cell (what a SENDME answering it must echo).
    pub fn encrypt_outbound(&mut self, hop: usize, payload: &mut [u8; PAYLOAD_LEN]) -> [u8; 20] {
        payload[5..9].fill(0);
        let target = &mut self.hops[hop];
        target.send_digest.update(payload);
        let digest = target.send_digest.peek();
        payload[5..9].copy_from_slice(&digest[..4]);
        for h in self.hops[..=hop].iter_mut().rev() {
            h.send_cipher.apply(payload);
        }
        digest
    }

    /// Peel layers until some hop recognizes the cell. Returns that hop's index and its
    /// 20-byte running digest after the cell.
    pub fn decrypt_inbound(
        &mut self,
        payload: &mut [u8; PAYLOAD_LEN],
    ) -> Option<(usize, [u8; 20])> {
        for (i, h) in self.hops.iter_mut().enumerate() {
            h.recv_cipher.apply(payload);
            if payload[1] != 0 || payload[2] != 0 {
                continue;
            }
            let claimed: [u8; 4] = payload[5..9].try_into().unwrap();
            payload[5..9].fill(0);
            let mut candidate = h.recv_digest.clone();
            candidate.update(payload);
            let digest = candidate.peek();
            if digest[..4] == claimed {
                h.recv_digest = candidate;
                return Some((i, digest));
            }
            payload[5..9].copy_from_slice(&claimed);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A relay-side mirror of one hop, to check that both ends of a layer agree.
    fn mirror(keys: &[u8; CIRC_KEYS_LEN]) -> HopCrypto {
        let mut swapped = [0u8; CIRC_KEYS_LEN];
        swapped[..20].copy_from_slice(&keys[20..40]);
        swapped[20..40].copy_from_slice(&keys[..20]);
        swapped[40..56].copy_from_slice(&keys[56..72]);
        swapped[56..72].copy_from_slice(&keys[40..56]);
        HopCrypto::relay_hop(&swapped)
    }

    #[test]
    fn three_hop_round_trip() {
        let keys: Vec<[u8; CIRC_KEYS_LEN]> = (1..=3u8).map(|i| [i; CIRC_KEYS_LEN]).collect();
        let mut client = CircCrypto::default();
        for k in &keys {
            client.push(HopCrypto::relay_hop(k));
        }
        let mut relays: Vec<HopCrypto> = keys.iter().map(mirror).collect();

        for round in 0..3u8 {
            let mut payload = [0u8; PAYLOAD_LEN];
            build_relay(&mut payload, relay::DATA, 7, &[round; 100]);
            client.encrypt_outbound(2, &mut payload);
            // Each relay removes its layer; only the last recognizes the cell.
            for (i, r) in relays.iter_mut().enumerate() {
                r.recv_cipher.apply(&mut payload);
                let recognized = payload[1] == 0 && payload[2] == 0;
                if i < 2 {
                    assert!(!recognized || payload[5..9] != [0, 0, 0, 0]);
                }
            }
            let (cmd, stream, data) = parse_relay(&payload).unwrap();
            assert_eq!((cmd, stream, data), (relay::DATA, 7, &[round; 100][..]));

            // And back: the exit digests and encrypts, the others add layers.
            let mut reply = [0u8; PAYLOAD_LEN];
            build_relay(&mut reply, relay::DATA, 7, &[round ^ 0xff; 50]);
            let exit = &mut relays[2];
            exit.send_digest.update(&reply);
            let d = exit.send_digest.peek();
            reply[5..9].copy_from_slice(&d[..4]);
            for r in relays.iter_mut().rev() {
                r.send_cipher.apply(&mut reply);
            }
            let (hop, _) = client.decrypt_inbound(&mut reply).unwrap();
            assert_eq!(hop, 2);
            assert_eq!(parse_relay(&reply).unwrap().2, &[round ^ 0xff; 50][..]);
        }
    }

    #[test]
    fn onion_hop_pairs_up() {
        let keys = [5u8; HS_KEYS_LEN];
        let mut service = CircCrypto::default();
        service.push(HopCrypto::onion_hop(&keys, true));
        let mut client = CircCrypto::default();
        client.push(HopCrypto::onion_hop(&keys, false));
        let mut payload = [0u8; PAYLOAD_LEN];
        build_relay(&mut payload, relay::BEGIN, 1, b":80\0");
        let sent = client.encrypt_outbound(0, &mut payload);
        let (hop, received) = service.decrypt_inbound(&mut payload).unwrap();
        assert_eq!(hop, 0);
        assert_eq!(sent, received);
        assert_eq!(parse_relay(&payload).unwrap().2, b":80\0");
    }
}
