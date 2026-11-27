//! Connect to a relay's ORPort and report the link handshake result.
mod common;
use std::time::{Duration, Instant};

fn main() {
    common::init_logging();
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "128.31.0.39:9201".into());
    let t = Instant::now();
    match microtor::link::Link::connect(addr.parse().unwrap(), Duration::from_secs(10)) {
        Ok(link) => println!(
            "ok {addr}: link v{} observed_addr={:?} peer_time={} in {:?}",
            link.link_version,
            link.observed_addr.map(|_| "<redacted>"),
            link.peer_time,
            t.elapsed()
        ),
        Err(e) => println!("FAILED {addr}: {e} after {:?}", t.elapsed()),
    }
}
