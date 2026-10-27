//! ShadeNet node (ADR 0014): a proof-gated egress node published as a Tor onion service.
//!
//! The binary is a thin shell: `main.rs` resolves a [`Config`] from the environment and
//! hands it to [`ShadeNode`], which owns every subsystem for the life of the process.
//! Wire formats follow `docs/WIRE-SPEC.md` section 6 and the refusal reasons the JavaScript
//! node emits, so existing clients need no change. [`Operator`] holds the other front-door
//! commands (`check`, `identity`, `authorize`, `status`, `retire`), which never start a node.

#![forbid(unsafe_op_in_unsafe_fn)]

mod alerts;
mod chain;
mod clock;
mod config;
mod drain;
mod egress;
mod envelope;
mod error;
mod heartbeat;
mod knobs;
mod members;
mod metrics;
mod node;
mod onion;
mod operator;
mod receipt;
mod record;
mod roots;
mod rpc;
mod session;
mod slash;
mod spent;
mod status;
mod tally;
mod telemetry;
mod tor;
mod torhttp;
mod tunnel;
mod verify;

pub use config::Config;
pub use error::Error;
pub use node::ShadeNode;
pub use operator::Operator;
