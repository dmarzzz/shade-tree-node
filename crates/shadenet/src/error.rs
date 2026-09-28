//! Typed SDK errors. Every variant has a stable machine code (used in `X-ShadeNet-Error`, MCP tool
//! results and `--json` output), a process exit code and an HTTP status for the local proxy.

use std::time::Duration;

/// Why a tunnel was refused before or during setup.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Bad configuration or input (missing identity, malformed record, conflicting settings).
    #[error("config: {0}")]
    Config(String),
    /// The member leaf is not in the admission set the canopy's nodes accept.
    #[error("not admitted: leaf {leaf} is not in {set} ({live} live leaves)")]
    NotAdmitted {
        leaf: String,
        set: String,
        live: usize,
    },
    /// The leaf is registered but its block is not finalized yet, so nodes do not accept it.
    #[error("not finalized: leaf {leaf} is registered in {set} but not yet finalized; retry after finality (about 13 minutes on Sepolia)")]
    NotFinalized { leaf: String, set: String },
    /// This epoch's tunnels (or the slot's payload allowance) are used up.
    #[error("budget exhausted: {detail}; retry in {}s", retry_after.as_secs())]
    BudgetExhausted {
        detail: String,
        retry_after: Duration,
    },
    /// No node in the canopy egresses to this port.
    #[error("port {port} is not allowed: canopy nodes egress only to {allowed}")]
    PortNotAllowed { port: u16, allowed: String },
    /// The canopy has no node this member may use (admission policy, rate policy, capability).
    #[error("no eligible node: {0}")]
    NoEligibleNode(String),
    /// A node answered and refused the proof or the target.
    #[error("node {gateway} refused: {reason}")]
    NodeRefused {
        gateway: String,
        reason: String,
        ack: Box<serde_json::Value>,
    },
    /// Tor or TCP failures on every candidate.
    #[error("transport: {0}")]
    Transport(String),
    /// The signed canopy could not be fetched or verified and no last-known-good copy exists.
    #[error("canopy: {0}")]
    Canopy(String),
    /// Membership discovery over JSON-RPC failed.
    #[error("rpc: {0}")]
    Rpc(String),
    /// Local ZK artifact problem (lock drift, no mutual artifact with the node).
    #[error("artifact: {0}")]
    Artifact(String),
    /// Local slot state problem (lock, corruption). Fails closed: never reuses a slot.
    #[error("slot state: {0}")]
    Slot(String),
    /// Proof construction failed.
    #[error("prove: {0}")]
    Prove(String),
    /// Anything else that is local and unexpected.
    #[error("internal: {0}")]
    Internal(String),
}

impl Error {
    /// Stable machine-readable code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Config(_) => "config",
            Self::NotAdmitted { .. } => "not_admitted",
            Self::NotFinalized { .. } => "not_finalized",
            Self::BudgetExhausted { .. } => "budget_exhausted",
            Self::PortNotAllowed { .. } => "port_not_allowed",
            Self::NoEligibleNode(_) => "no_eligible_node",
            Self::NodeRefused { .. } => "node_refused",
            Self::Transport(_) => "transport",
            Self::Canopy(_) => "canopy",
            Self::Rpc(_) => "rpc",
            Self::Artifact(_) => "artifact",
            Self::Slot(_) => "slot_state",
            Self::Prove(_) => "prove",
            Self::Internal(_) => "internal",
        }
    }

    /// Process exit code. 1 = node refused, 2 = usage/config/admission, 3 = local or transport
    /// failure (fail closed), 4 = budget exhausted. Stable across releases.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::NodeRefused { .. } => 1,
            Self::Config(_)
            | Self::NotAdmitted { .. }
            | Self::NotFinalized { .. }
            | Self::PortNotAllowed { .. }
            | Self::NoEligibleNode(_)
            | Self::Canopy(_)
            | Self::Rpc(_)
            | Self::Artifact(_) => 2,
            Self::Transport(_) | Self::Slot(_) | Self::Prove(_) | Self::Internal(_) => 3,
            Self::BudgetExhausted { .. } => 4,
        }
    }

    /// HTTP status the local proxy answers a CONNECT with.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::NotAdmitted { .. } | Self::NotFinalized { .. } | Self::PortNotAllowed { .. } => {
                403
            }
            Self::BudgetExhausted { .. } => 429,
            Self::NoEligibleNode(_) | Self::Canopy(_) | Self::Rpc(_) | Self::Transport(_) => 503,
            Self::NodeRefused { .. } => 502,
            Self::Config(_)
            | Self::Artifact(_)
            | Self::Slot(_)
            | Self::Prove(_)
            | Self::Internal(_) => 500,
        }
    }

    /// When retrying makes sense, how long to wait.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::BudgetExhausted { retry_after, .. } => Some(*retry_after),
            Self::NotFinalized { .. } => Some(Duration::from_secs(60)),
            Self::NoEligibleNode(_) | Self::Canopy(_) | Self::Rpc(_) | Self::Transport(_) => {
                Some(Duration::from_secs(5))
            }
            _ => None,
        }
    }

    /// JSON body shared by the proxy, `--json` output and MCP tool results.
    pub fn to_json(&self) -> serde_json::Value {
        let mut body = serde_json::json!({
            "code": self.code(),
            "message": self.to_string(),
        });
        if let Some(retry) = self.retry_after() {
            body["retryAfterSeconds"] = retry.as_secs().max(1).into();
        }
        if let Self::NodeRefused {
            gateway, reason, ..
        } = self
        {
            body["gateway"] = gateway.clone().into();
            body["reason"] = reason.clone().into();
        }
        serde_json::json!({ "error": body })
    }
}

/// Every public error code, for docs and conformance tests.
pub const ERROR_CODES: &[&str] = &[
    "config",
    "not_admitted",
    "not_finalized",
    "budget_exhausted",
    "port_not_allowed",
    "no_eligible_node",
    "node_refused",
    "transport",
    "canopy",
    "rpc",
    "artifact",
    "slot_state",
    "prove",
    "internal",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_errors_carry_retry_after_and_429() {
        let error = Error::BudgetExhausted {
            detail: "used 1/1 slots in epoch 7".into(),
            retry_after: Duration::from_secs(42),
        };
        assert_eq!(error.http_status(), 429);
        assert_eq!(error.exit_code(), 4);
        assert_eq!(error.to_json()["error"]["retryAfterSeconds"], 42);
        assert_eq!(error.to_json()["error"]["code"], "budget_exhausted");
    }

    #[test]
    fn every_code_is_listed() {
        let samples = [
            Error::Config(String::new()),
            Error::NotAdmitted {
                leaf: String::new(),
                set: String::new(),
                live: 0,
            },
            Error::NotFinalized {
                leaf: String::new(),
                set: String::new(),
            },
            Error::BudgetExhausted {
                detail: String::new(),
                retry_after: Duration::ZERO,
            },
            Error::PortNotAllowed {
                port: 80,
                allowed: "443".into(),
            },
            Error::NoEligibleNode(String::new()),
            Error::NodeRefused {
                gateway: String::new(),
                reason: String::new(),
                ack: Box::new(serde_json::Value::Null),
            },
            Error::Transport(String::new()),
            Error::Canopy(String::new()),
            Error::Rpc(String::new()),
            Error::Artifact(String::new()),
            Error::Slot(String::new()),
            Error::Prove(String::new()),
            Error::Internal(String::new()),
        ];
        let codes: Vec<_> = samples.iter().map(Error::code).collect();
        assert_eq!(codes, ERROR_CODES);
        for error in &samples {
            assert!(matches!(error.http_status(), 403 | 429 | 500 | 502 | 503));
        }
    }
}
