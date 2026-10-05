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

/// Why an error happened in the environment and what to do about it. Every public error code
/// has one (see [`Error::explain`]); the proxy sends it as `X-ShadeNet-Cause` and in the JSON
/// body as `cause` / `fix`, so an agent reads the real cause instead of guessing from the code.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Explanation {
    /// One sentence naming the cause, in plain words, naming the RPC, node or file when known.
    pub cause: String,
    /// The exact command or edit that clears it.
    pub fix: String,
}

impl Explanation {
    fn new(cause: impl Into<String>, fix: impl Into<String>) -> Self {
        Self {
            cause: cause.into(),
            fix: fix.into(),
        }
    }
}

/// Explain a node refusal reason (`gate:…` / `upstream:…` strings from the JS node), with the
/// extra fields the node attached to its ack when it did (`roots`, `artifacts`, `proto`).
pub fn explain_reason(gateway: &str, reason: &str, ack: &serde_json::Value) -> Explanation {
    let base = reason.trim_start_matches("gate:");
    let node = if gateway.is_empty() {
        "the node"
    } else {
        gateway
    };
    match base {
        "wrong-group-root" => {
            let theirs = ack["roots"]
                .as_array()
                .map(|r| r.len())
                .unwrap_or(0);
            let where_ = match (ack["rootBlock"].as_u64(), ack["rootLeaves"].as_u64()) {
                (Some(b), Some(n)) => format!(" (it accepts {theirs} root(s), {n} leaves at block {b})"),
                (Some(b), None) => format!(" (it accepts {theirs} root(s) as of block {b})"),
                _ if theirs > 0 => format!(" (it accepts {theirs} root(s))"),
                _ => String::new(),
            };
            Explanation::new(
                format!("your member set does not match the one {node} accepts{where_}: usually your RPC returned a partial or stale member log, or your registration is not yet in the nodes' finalized view"),
                "run `shadenet doctor --rpc` to see which RPC dropped history and which side is stale; if your stake is fresh, `shadenet status --wait`",
            )
        }
        "root-not-recent" => Explanation::new(
            format!("{node} only accepts roots from the last {}s and yours is older; your member set was cached past its freshness", 60),
            "retry; the client refreshes its member set every minute. Persistent: `shadenet doctor --rpc`",
        ),
        "stale-external-nullifier" => Explanation::new(
            "the proof was made for an epoch the node no longer accepts (your clock or the node's is off by more than one epoch)",
            "check this machine's clock (`date -u`), then retry",
        ),
        "session-unsupported" => Explanation::new(
            format!("{node} advertised session tickets but refused to open a book (its gateway unit lacks the onion identity the books bind to, or tickets are off on that node)"),
            "retry; the client falls back to one tunnel per proof on that node. The operator fixes it with SHADE_TREE_GW_IDENTITY in the gateway unit (#225)",
        ),
        "session-wrong-gateway" | "session-not-bound" => Explanation::new(
            "the session ticket was bound to a different node than the one that answered",
            "retry; the client rebinds the book to the node it dials",
        ),
        "bad-artifact" | "unknown-artifact" | "artifact-not-accepted" => Explanation::new(
            format!("{node} does not accept the ZK artifact set this binary embeds (dual-key window or an old binary)"),
            "upgrade the binary to the release the network record pins (`shadenet --version` vs the record), then retry",
        ),
        "bad-version" | "unsupported-version" => Explanation::new(
            format!("{node} speaks a different protocol version than this binary"),
            "upgrade the binary to the release the network record pins",
        ),
        "invalid-proof" => Explanation::new(
            "the proof did not verify under the node's key: the identity file or the embedded artifacts are not the ones the network uses",
            "run `shadenet doctor`; if the artifacts check fails, upgrade; if the identity is from another network, use that network",
        ),
        "payload-limit" | "payload-exceeded" => Explanation::new(
            "this tunnel moved more bytes than one slot allows (40 MiB on Sepolia)",
            "open a new tunnel for the next request and keep large downloads off ShadeNet",
        ),
        "target-not-allowed" | "target-private" | "target-denied" => Explanation::new(
            format!("{node} refuses that destination (private address or an operator deny rule)"),
            "use a public https host; nodes never egress to private networks",
        ),
        "double-signal" | "replayed-envelope" | "nullifier-reused" => Explanation::new(
            "this epoch's slot was already spent (a retry reused a nullifier, or two clients share one identity)",
            "wait for the next epoch; never run two proxies on one identity file",
        ),
        r if r.starts_with("upstream") => Explanation::new(
            format!("{node} reached Tor fine but the destination refused or timed out ({r})"),
            "retry; if it repeats on other nodes the destination is down or blocking the node's IP",
        ),
        other => Explanation::new(
            format!("{node} refused with {other}"),
            "retry on another node (the client rotates); if it persists, run `shadenet doctor` and report the reason",
        ),
    }
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

    /// The environmental cause and the fix, derived from the error's content. Never empty: an
    /// unknown cause still tells the agent what to run next.
    pub fn explain(&self) -> Explanation {
        match self {
            Self::Config(detail) => {
                let d = detail.to_ascii_lowercase();
                if d.contains("identity") && (d.contains("missing") || d.contains("no such") || d.contains("not found") || d.contains("none configured")) {
                    Explanation::new("no identity file is configured, so there is nothing to prove with", "run `shadenet init`, or pass `--identity <file>` to the identity a sponsor gave you")
                } else if d.contains("passphrase") {
                    Explanation::new("the identity file is passphrase-protected and no passphrase was given", "set SHADENET_PASSPHRASE_FILE to an owner-only file holding it, or run `shadenet identity-unlock`")
                } else if d.contains("network") || d.contains("deployment") || d.contains("record") {
                    Explanation::new(format!("the network record could not be used: {detail}"), "pass `--network sepolia` or the path to a deployment.json; `shadenet doctor` prints which record is in use")
                } else {
                    Explanation::new(format!("local configuration problem: {detail}"), "run `shadenet doctor` and fix the first failing line")
                }
            }
            Self::NotAdmitted { set, live, .. } => Explanation::new(
                format!("your leaf is not in the finalized member set {set} ({live} live leaves); either it was never staked there, or it was staked in another network's set (staging vs production)"),
                "run `shadenet doctor` (it looks for your leaf in every record it knows and names the one that has it); to stake here: `shadenet register-member --identity <file> --key-file <funded key>`, or hand the identity commitment to a sponsor",
            ),
            Self::NotFinalized { set, .. } => Explanation::new(
                format!("your registration in {set} is on chain but not finalized; nodes read the finalized set (about 13 minutes on Sepolia)"),
                "`shadenet status --wait` returns when it is final; then the nodes pick it up within one root refresh (60s)",
            ),
            Self::BudgetExhausted { detail, retry_after } => Explanation::new(
                format!("the per-epoch budget is spent: {detail}"),
                format!("wait {}s (the epoch reset), reuse open connections and keep model APIs off ShadeNet", retry_after.as_secs().max(1)),
            ),
            Self::PortNotAllowed { port, allowed } => Explanation::new(
                format!("no node egresses to port {port}; the canopy serves {allowed}"),
                "use https on port 443",
            ),
            Self::NoEligibleNode(detail) if detail.contains("admission set") => Explanation::new(
                format!("the canopy's nodes read a different admission set than this record: {detail}; every proof would be refused wrong-group-root"),
                "run against the record those nodes serve (`--network <path to its deployment.json>`), or stake this identity in the set they read; `shadenet doctor` names which record has your leaf",
            ),
            Self::NoEligibleNode(detail) => Explanation::new(
                format!("the canopy lists nodes but none fits this request: {detail}"),
                "run `shadenet status` (eligible count) and `shadenet doctor` (artifact, rate policy and admission mismatches are named there); drop --region/--proto filters",
            ),
            Self::NodeRefused { gateway, reason, ack } => explain_reason(gateway, reason, ack),
            Self::Transport(detail) => {
                let d = detail.to_ascii_lowercase();
                if d.contains("bootstrap") || d.contains("directory") && d.contains("tor") {
                    Explanation::new("embedded Tor could not bootstrap (no route to the Tor network, or a blocked egress)", "check outbound connectivity; `shadenet doctor` reports the Tor state; a corporate network may need a bridge")
                } else if d.contains("permission") || d.contains("g-w") || d.contains("writable") {
                    Explanation::new("Arti refuses its state directory because it (or a parent) is group- or world-writable", "run `chmod g-w,o-w` on the directory `shadenet doctor` names (and its parents under $HOME), then retry")
                } else if d.contains("timed out") || d.contains("timeout") {
                    Explanation::new("every candidate node timed out over Tor; right after a node restarts its onion descriptor takes a few minutes to republish, and a single bad circuit looks the same", "retry in a minute (the client rotates nodes and circuits); persistent timeouts on every node mean Tor is blocked here")
                } else {
                    Explanation::new(format!("Tor or TCP failed on every candidate node: {detail}"), "retry; persistent failures on every node mean Tor is blocked from this machine (`shadenet doctor`)")
                }
            }
            Self::Canopy(detail) => Explanation::new(
                format!("no Elder Tree returned a signed canopy and there is no last-known-good copy: {detail}"),
                "check Tor with `shadenet doctor`; if an Elder is down its peers still serve the canopy, so persistent failure means Tor is unreachable from here",
            ),
            Self::Rpc(detail) => {
                let d = detail.to_ascii_lowercase();
                if d.contains("partial history") || d.contains("dropped") || d.contains("incomplete") {
                    Explanation::new(format!("the RPC returned an incomplete member log (a pruned backend behind a public pool): {detail}"), "run `shadenet doctor --rpc`; set SHADENET_RPC_URL to an endpoint with full history (the record's `rpcUrls` lists the fallbacks)")
                } else if d.contains("429") || d.contains("too many") {
                    Explanation::new("the RPC rate-limited this client", "retry after a minute, or set SHADENET_RPC_URL to a less loaded endpoint from the record's `rpcUrls`")
                } else {
                    Explanation::new(format!("reading the member set over JSON-RPC failed: {detail}"), "run `shadenet doctor --rpc`; it rates every endpoint in the record and names a working one")
                }
            }
            Self::Artifact(detail) => Explanation::new(
                format!("the ZK artifacts this binary embeds do not match the network: {detail}"),
                "upgrade to the release the record pins (`shadenet --version`); during a ceremony window nodes advertise the ids they accept",
            ),
            Self::Slot(detail) => Explanation::new(
                format!("the RLN slot file is locked, corrupt or unwritable, so the client refuses to spend (reusing a slot would get the identity slashed): {detail}"),
                "run `shadenet doctor`; it prints the slot path and whether another proxy holds the lock. Never delete it inside an epoch",
            ),
            Self::Prove(detail) => Explanation::new(
                format!("proof construction failed locally: {detail}"),
                "run `shadenet doctor` (artifacts check); report it with the output if the artifacts are fine",
            ),
            Self::Internal(detail) => Explanation::new(
                format!("an unexpected local error: {detail}"),
                "retry once; then report it with `shadenet doctor --json`",
            ),
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
        let explanation = self.explain();
        body["cause"] = explanation.cause.into();
        body["fix"] = explanation.fix.into();
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

    #[test]
    fn every_error_explains_its_cause_and_fix() {
        let samples = [
            Error::Config("missing identity".into()),
            Error::NotAdmitted {
                leaf: "1".into(),
                set: "0xabc".into(),
                live: 3,
            },
            Error::NotFinalized {
                leaf: "1".into(),
                set: "0xabc".into(),
            },
            Error::BudgetExhausted {
                detail: "used 1/1".into(),
                retry_after: Duration::from_secs(7),
            },
            Error::PortNotAllowed {
                port: 80,
                allowed: "443".into(),
            },
            Error::NoEligibleNode("rate policy".into()),
            Error::NodeRefused {
                gateway: "abc.onion".into(),
                reason: "gate:wrong-group-root".into(),
                ack: Box::new(
                    serde_json::json!({"roots":["1","2"],"rootBlock":100,"rootLeaves":5}),
                ),
            },
            Error::Transport("Elder Tree exchange timed out after 60s".into()),
            Error::Canopy("x".into()),
            Error::Rpc("rpc: returned partial history even in 64-block pages".into()),
            Error::Artifact("x".into()),
            Error::Slot("x".into()),
            Error::Prove("x".into()),
            Error::Internal("x".into()),
        ];
        for error in &samples {
            let e = error.explain();
            assert!(
                !e.cause.is_empty() && !e.fix.is_empty(),
                "{} lacks an explanation",
                error.code()
            );
            let json = error.to_json();
            assert_eq!(json["error"]["cause"], e.cause);
            assert_eq!(json["error"]["fix"], e.fix);
        }
        let refused = samples[6].explain();
        assert!(
            refused.cause.contains("5 leaves at block 100"),
            "{}",
            refused.cause
        );
        assert!(refused.fix.contains("doctor --rpc"));
        let rpc = samples[9].explain();
        assert!(rpc.cause.contains("incomplete member log"));
        assert!(samples[7].explain().cause.contains("onion descriptor"));
    }
}
