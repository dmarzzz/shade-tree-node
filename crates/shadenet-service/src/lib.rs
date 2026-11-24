//! What every ShadeNet service binary shares. The node (`shadenet-node`, ADR 0014) and the
//! Elder Tree (`shadenet-elder`, ADR 0015) are each one entrypoint over private modules; the
//! code both need lives here instead of one binary depending on the other: plain HTTP to an
//! onion through the local Tor SOCKS port, JSON-RPC with failover, the Prometheus registry and
//! its loopback listener, the onion identity Tor publishes and the service signs with, the
//! clock, atomic files, the build commit and logging.

#![forbid(unsafe_op_in_unsafe_fn)]

pub mod clock;
pub mod files;
pub mod logging;
pub mod metrics;
pub mod onion;
pub mod rpc;
pub mod torhttp;
pub mod version;
