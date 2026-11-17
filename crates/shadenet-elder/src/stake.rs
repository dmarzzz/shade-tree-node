//! The stake verifier (`packages/node/lib/gateway-registry.mjs`): is this operator address
//! staked in `GatewayRegistry` right now? On chain through `eth_call isStaked(address)` at
//! `latest` or at head minus the configured confirmations, with a short cache so a heartbeat
//! storm is cheap; or the chainless mock for development.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use shadenet::eth::{calldata, Address, Token};
use shadenet_service::metrics::Registry;
use shadenet_service::rpc::{self, Rpc};

use crate::config::StakeSource;

const RPC_TIMEOUT: Duration = Duration::from_secs(15);

pub(crate) struct Onchain {
    rpc: Rpc,
    contract: String,
    confirmations: u64,
    cache_for: Duration,
    cache: Mutex<HashMap<String, (bool, Instant)>>,
}

pub(crate) struct Mock {
    allowlist: Option<Vec<String>>,
}

pub(crate) enum Verifier {
    Onchain(Onchain),
    Mock(Mock),
}

impl Verifier {
    pub(crate) fn new(source: &StakeSource, metrics: Arc<Registry>) -> Result<Self, String> {
        Ok(match source {
            StakeSource::Onchain {
                registry,
                rpc_url,
                confirmations,
                cache,
            } => Self::Onchain(Onchain {
                rpc: Rpc::new(
                    vec![rpc_url.clone()],
                    RPC_TIMEOUT,
                    rpc::DEFAULT_RETRIES,
                    Some(metrics),
                )?,
                contract: registry.clone(),
                confirmations: *confirmations,
                cache_for: *cache,
                cache: Mutex::new(HashMap::new()),
            }),
            StakeSource::Mock { allowlist } => Self::Mock(Mock {
                allowlist: allowlist.clone(),
            }),
        })
    }

    /// What the ready line reports.
    pub(crate) fn mode(&self) -> String {
        match self {
            Self::Onchain(_) => "onchain".into(),
            Self::Mock(Mock { allowlist: None }) => "mock:open".into(),
            Self::Mock(Mock {
                allowlist: Some(list),
            }) => format!("mock:allowlist({})", list.len()),
        }
    }

    /// Whether `operator` holds a live bond; an unreachable chain is an error, never a verdict.
    pub(crate) async fn is_staked(&self, operator: &str) -> Result<bool, String> {
        let key = operator.to_ascii_lowercase();
        match self {
            Self::Mock(mock) => Ok(mock
                .allowlist
                .as_ref()
                .is_none_or(|list| list.contains(&key))),
            Self::Onchain(chain) => chain.is_staked(&key).await,
        }
    }
}

impl Onchain {
    async fn is_staked(&self, operator: &str) -> Result<bool, String> {
        let now = Instant::now();
        if let Some((value, at)) = self
            .cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(operator)
        {
            if now.duration_since(*at) < self.cache_for {
                return Ok(*value);
            }
        }
        let address: Address = operator.parse().map_err(|e| format!("bad address: {e}"))?;
        let tag = self.block_tag().await?;
        let data = calldata("isStaked(address)", &[Token::Address(address)]);
        let result = self
            .rpc
            .call(
                "eth_call",
                json!([{ "to": self.contract, "data": format!("0x{}", hex::encode(data)) }, tag]),
            )
            .await
            .map_err(|e| e.to_string())?;
        // bool is the last byte of the 32-byte word; anything nonzero is true
        let value = result
            .as_str()
            .map(|hex| hex.trim_start_matches("0x").trim_start_matches('0'))
            .is_some_and(|rest| rest.bytes().any(|b| b != b'0'));
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(operator.to_string(), (value, now));
        Ok(value)
    }

    async fn block_tag(&self) -> Result<Value, String> {
        if self.confirmations == 0 {
            return Ok(Value::String("latest".into()));
        }
        let block = self
            .rpc
            .call("eth_getBlockByNumber", json!(["latest", false]))
            .await
            .map_err(|e| e.to_string())?;
        let head = block["number"]
            .as_str()
            .and_then(|n| u64::from_str_radix(n.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);
        Ok(Value::String(format!(
            "0x{:x}",
            head.saturating_sub(self.confirmations)
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_mock_is_open_or_an_allowlist() {
        let open = Verifier::Mock(Mock { allowlist: None });
        assert!(open.is_staked("0xABC").await.unwrap());
        assert_eq!(open.mode(), "mock:open");
        let listed = Verifier::Mock(Mock {
            allowlist: Some(vec!["0xabc".into()]),
        });
        assert!(listed.is_staked("0xABC").await.unwrap());
        assert!(!listed.is_staked("0xdef").await.unwrap());
        assert_eq!(listed.mode(), "mock:allowlist(1)");
    }

    #[tokio::test]
    async fn the_chain_read_is_an_eth_call_cached_per_operator() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = Arc::clone(&calls);
        tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = vec![0_u8; 8192];
                let n = socket.read(&mut buf).await.unwrap();
                let text = String::from_utf8_lossy(&buf[..n]).to_string();
                assert!(text.contains("eth_call"), "{text}");
                assert!(text.contains(&format!(
                    "0x{}",
                    hex::encode(shadenet::eth::selector("isStaked(address)"))
                )));
                seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x0000000000000000000000000000000000000000000000000000000000000001\"}";
                let reply = format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
                socket.write_all(reply.as_bytes()).await.unwrap();
            }
        });
        let registry = Arc::new(Registry::new(
            "elder",
            "0",
            "0",
            crate::metrics::DEFINITIONS,
        ));
        let verifier = Verifier::new(
            &StakeSource::Onchain {
                registry: "0x94eced0c1c7a8793a5c901c8c1995c8e7039a868".into(),
                rpc_url: format!("http://{addr}"),
                confirmations: 0,
                cache: Duration::from_secs(60),
            },
            registry,
        )
        .unwrap();
        let operator = "0x7564105E977516C53bE337314c7E53838967bDaC";
        assert!(verifier.is_staked(operator).await.unwrap());
        assert!(verifier.is_staked(operator).await.unwrap());
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "the second read is cached"
        );
        assert!(verifier.is_staked("nope").await.is_err());
    }
}
