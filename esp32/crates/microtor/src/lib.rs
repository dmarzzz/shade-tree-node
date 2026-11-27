//! microtor: a minimal Tor client and v3 onion-service host, sized for a microcontroller.
//!
//! One TLS link to a guard, a handful of circuits, a single-threaded cooperative runtime, and
//! streaming parsers so no directory document is ever held in memory. It speaks enough of the
//! Tor protocol to bootstrap from the public network, host an onion service, and dial one.

pub mod bootstrap_data;
pub mod cell;
pub mod circuit;
pub mod crypto;
pub mod dir;
pub mod hs;
pub mod hsdesc;
pub mod link;
pub mod netdir;
pub mod rt;
pub mod tor;
pub mod util;

/// Everything that can go wrong, kept small: most failures are "tear the circuit down and
/// try again", so the variants say which layer gave up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The transport failed or closed.
    Io(std::io::ErrorKind),
    /// TLS to the relay failed.
    Tls,
    /// The peer broke the protocol or a cryptographic check failed.
    Proto(&'static str),
    /// A document or field did not parse.
    Parse(&'static str),
    /// Nothing happened before the deadline.
    Timeout(&'static str),
    /// The circuit or stream was closed by the other side (with Tor's reason code).
    Closed(u8),
    /// The network view cannot satisfy the request (no usable relay, no consensus).
    Unavailable(&'static str),
    /// A directory server answered with a non-200 status.
    Http(u16),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Io(kind) => write!(f, "io: {kind:?}"),
            Error::Tls => write!(f, "tls failure"),
            Error::Proto(what) => write!(f, "protocol: {what}"),
            Error::Parse(what) => write!(f, "parse: {what}"),
            Error::Timeout(what) => write!(f, "timeout: {what}"),
            Error::Closed(reason) => write!(f, "closed (reason {reason})"),
            Error::Unavailable(what) => write!(f, "unavailable: {what}"),
            Error::Http(status) => write!(f, "directory answered {status}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.kind())
    }
}

pub type Result<T> = core::result::Result<T, Error>;
