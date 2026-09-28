//! ShadeNet Rust SDK.
//!
//! ShadeNet gives agents anonymous egress: a local client proves RLN membership in zero knowledge
//! and a Shade Tree node (a Tor onion service) opens the connection to the destination. The nodes
//! of one network form a canopy, listed in a directory signed by the canopy signer and served by
//! an Elder Tree. The enabling technique is zkReputationTor.
//!
//! ```no_run
//! # async fn demo() -> Result<(), shadenet::Error> {
//! use std::sync::Arc;
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//!
//! let config = shadenet::Config::builder()
//!     .identity_file("identity.json")
//!     .build()?;
//! let client = Arc::new(shadenet::Client::new(config)?);
//! client.spawn_canopy_refresh();
//!
//! let status = client.status().await;
//! println!("admitted={:?} slots_left={:?}", status.admitted, status.slots_left);
//!
//! let response = client.fetch(shadenet::FetchRequest::get("https://example.com/")).await?;
//! println!("{} via {}", response.status, response.gateway);
//!
//! let tunnel = client.connect("example.com:443").await?;
//! let mut stream = tunnel.into_stream(); // speak TLS over it
//! # let _ = (&mut stream).write_all(b"").await; let _ = stream.read(&mut [0u8; 1]).await;
//! # Ok(()) }
//! ```
//!
//! Without the default `live` feature the crate is the deterministic half only: network
//! profiles, canopy verification and caching, node selection filters and the health cache.

#![forbid(unsafe_op_in_unsafe_fn)]

pub mod capability;
pub mod config;
pub mod dircache;
pub mod env;
pub mod error;
pub mod health;
pub mod profile;
pub mod slot;

#[cfg(feature = "live")]
pub mod client;
#[cfg(feature = "live")]
pub mod fetch;
#[cfg(feature = "live")]
pub mod leaves;
#[cfg(feature = "live")]
pub mod proxy;
#[cfg(feature = "live")]
pub mod stream;
#[cfg(feature = "live")]
pub mod transport;

pub use config::{Config, ConfigBuilder, Discovery, Identity, Members, Slots};
pub use error::{Error, ERROR_CODES};
pub use profile::{Network, PublicProfile};

#[cfg(feature = "live")]
pub use client::{CanopyStatus, Client, Metrics, Status, Tunnel};
#[cfg(feature = "live")]
pub use fetch::{FetchRequest, FetchResponse};
#[cfg(feature = "live")]
pub use proxy::ProxyConfig;

/// SDK version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
