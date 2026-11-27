//! Small encoders and parsers: base64, base32, hex, dates, a line splitter.

use crate::Error;

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64, with or without `=` padding, ignoring ASCII whitespace.
pub fn b64_decode(input: &str) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4 + 3);
    b64_decode_into(input.as_bytes(), &mut out)?;
    Ok(out)
}

pub fn b64_decode_into(input: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for &c in input {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' | b'\n' | b'\r' | b' ' => continue,
            _ => return Err(Error::Parse("base64")),
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Ok(())
}

/// Decode base64 into a fixed-size array; the decoded length must match exactly.
pub fn b64_fixed<const N: usize>(input: &str) -> Result<[u8; N], Error> {
    let v = b64_decode(input)?;
    v.as_slice()
        .try_into()
        .map_err(|_| Error::Parse("base64 length"))
}

pub fn b64_encode(data: &[u8], pad: bool) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(B64[(n >> 6) as usize & 63] as char);
        } else if pad {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64[n as usize & 63] as char);
        } else if pad {
            out.push('=');
        }
    }
    out
}

/// Base64 broken into 64-character lines, each ending in `\n` (the PEM-like body Tor uses).
pub fn b64_lines(data: &[u8], out: &mut String) {
    let encoded = b64_encode(data, true);
    for line in encoded.as_bytes().chunks(64) {
        out.push_str(core::str::from_utf8(line).unwrap_or(""));
        out.push('\n');
    }
}

const B32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

pub fn b32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 8 / 5 + 1);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &b in data {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[(acc >> bits) as usize & 31] as char);
        }
    }
    if bits > 0 {
        out.push(B32[(acc << (5 - bits)) as usize & 31] as char);
    }
    out
}

pub fn b32_decode(input: &str) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(input.len() * 5 / 8);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in input.bytes() {
        let v = match c {
            b'a'..=b'z' => c - b'a',
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return Err(Error::Parse("base32")),
        };
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

pub fn hex_encode(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 15) as usize] as char);
    }
    out
}

pub fn hex_decode(input: &str) -> Result<Vec<u8>, Error> {
    let bytes: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !bytes.len().is_multiple_of(2) {
        return Err(Error::Parse("hex length"));
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(Error::Parse("hex")),
    };
    bytes
        .chunks(2)
        .map(|p| Ok((nib(p[0])? << 4) | nib(p[1])?))
        .collect()
}

pub fn hex_fixed<const N: usize>(input: &str) -> Result<[u8; N], Error> {
    let v = hex_decode(input)?;
    v.as_slice()
        .try_into()
        .map_err(|_| Error::Parse("hex length"))
}

/// `YYYY-MM-DD` and `HH:MM:SS` (UTC) to unix seconds.
pub fn parse_datetime(date: &str, time: &str) -> Result<u64, Error> {
    let bad = || Error::Parse("date");
    let mut d = date.split('-');
    let year: i64 = d.next().and_then(|v| v.parse().ok()).ok_or_else(bad)?;
    let month: i64 = d.next().and_then(|v| v.parse().ok()).ok_or_else(bad)?;
    let day: i64 = d.next().and_then(|v| v.parse().ok()).ok_or_else(bad)?;
    let mut t = time.split(':');
    let hour: i64 = t.next().and_then(|v| v.parse().ok()).ok_or_else(bad)?;
    let minute: i64 = t.next().and_then(|v| v.parse().ok()).ok_or_else(bad)?;
    let second: i64 = t.next().and_then(|v| v.parse().ok()).ok_or_else(bad)?;
    if !(1970..=2200).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(bad());
    }
    // Days from civil (Howard Hinnant's algorithm).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + hour * 3600 + minute * 60 + second;
    u64::try_from(secs).map_err(|_| bad())
}

/// Splits a byte stream into lines without holding more than one line in memory.
///
/// Lines longer than the cap are truncated (the rest of the line is dropped); callers that
/// need whole lines choose a cap above the longest line they care about.
pub struct LineSplitter {
    buf: Vec<u8>,
    cap: usize,
    overflow: bool,
}

impl LineSplitter {
    pub fn new(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(256),
            cap,
            overflow: false,
        }
    }

    /// Feed bytes; `on_line` gets each complete line without its `\n`.
    pub fn feed<E>(
        &mut self,
        mut data: &[u8],
        mut on_line: impl FnMut(&[u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        while !data.is_empty() {
            match data.iter().position(|&b| b == b'\n') {
                Some(pos) => {
                    self.push(&data[..pos]);
                    let result = on_line(&self.buf);
                    self.buf.clear();
                    self.overflow = false;
                    result?;
                    data = &data[pos + 1..];
                }
                None => {
                    self.push(data);
                    break;
                }
            }
        }
        Ok(())
    }

    /// Flush a final line that had no trailing newline.
    pub fn finish<E>(&mut self, mut on_line: impl FnMut(&[u8]) -> Result<(), E>) -> Result<(), E> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let result = on_line(&self.buf);
        self.buf.clear();
        result
    }

    fn push(&mut self, data: &[u8]) {
        let room = self.cap.saturating_sub(self.buf.len());
        if data.len() > room {
            self.overflow = true;
        }
        self.buf.extend_from_slice(&data[..data.len().min(room)]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_round_trips() {
        for len in 0..40 {
            let data: Vec<u8> = (0..len as u8).map(|i| i.wrapping_mul(37)).collect();
            assert_eq!(b64_decode(&b64_encode(&data, true)).unwrap(), data);
            assert_eq!(b64_decode(&b64_encode(&data, false)).unwrap(), data);
        }
        assert_eq!(b64_encode(b"hello", true), "aGVsbG8=");
    }

    #[test]
    fn base32_round_trips() {
        let data = [0xde, 0xad, 0xbe, 0xef, 0x01];
        assert_eq!(b32_decode(&b32_encode(&data)).unwrap(), data);
        assert_eq!(b32_encode(b"hello"), "nbswy3dp");
    }

    #[test]
    fn dates() {
        assert_eq!(parse_datetime("1970-01-01", "00:00:00").unwrap(), 0);
        assert_eq!(
            parse_datetime("2026-11-27", "15:00:00").unwrap(),
            1_795_791_600
        );
        assert_eq!(
            parse_datetime("2024-02-29", "12:34:56").unwrap(),
            1_709_210_096
        );
    }

    #[test]
    fn lines() {
        let mut s = LineSplitter::new(8);
        let mut got = Vec::new();
        s.feed::<()>(b"ab\ncdefghijkl", |l| {
            got.push(l.to_vec());
            Ok(())
        })
        .unwrap();
        s.feed::<()>(b"mn\nx", |l| {
            got.push(l.to_vec());
            Ok(())
        })
        .unwrap();
        s.finish::<()>(|l| {
            got.push(l.to_vec());
            Ok(())
        })
        .unwrap();
        assert_eq!(
            got,
            vec![b"ab".to_vec(), b"cdefghij".to_vec(), b"x".to_vec()]
        );
    }
}
