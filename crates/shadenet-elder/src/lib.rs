//! ShadeNet Elder Tree (ADR 0015): the live node directory, published as a Tor onion service.
//!
//! Nodes announce themselves; the Elder verifies each announce (onion control, and in stake
//! mode the operator's live bond), keeps the live ones for a TTL and serves the union as a
//! signed directory, the canopy, that every client verifies against the pinned signer. The
//! binary is a thin shell: `main.rs` resolves a [`Config`] and hands it to [`Elder`]; the
//! other commands go through [`Operator`] and never start a service. Routes, knobs and files
//! are those of `packages/node/bootnode/server.mjs`.

#![forbid(unsafe_op_in_unsafe_fn)]

mod advert;
mod bucket;
mod canopy;
mod config;
mod elder;
mod error;
mod federation;
mod incidents;
mod metrics;
mod operator;
mod probe;
mod registry;
mod relay;
mod server;
mod signer;
mod stake;

pub use config::Config;
pub use elder::Elder;
pub use error::Error;
pub use operator::Operator;
