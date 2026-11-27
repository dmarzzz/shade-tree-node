//! shadenode: a ShadeNet Shade Tree node (proof-gated Tor egress) for small devices.
//!
//! Wire-compatible with the reference node for the v4 tunnel path: a client dials the node's
//! onion service, sends one JSON envelope carrying an RLN membership proof, and on admission
//! the node connects to the requested destination and relays bytes.

pub mod canary;
pub mod chain;
pub mod egress;
pub mod heartbeat;
pub mod node;
pub mod poseidon_t2;
pub mod poseidon_t3;
pub mod proto;
pub mod rln;
pub mod session;
pub mod spent;
pub mod verify;
