//! JSON-RPC over HTTP with the failover and throttle rules of `packages/node/lib/rpc-safety.mjs`:
//! a list of endpoints tried from the last one that worked, a transport failure or a retryable
//! JSON-RPC error moving to the next, a real answer (a revert, bad params) returned at once, and
//! HTTP 429 (or 503 with `Retry-After`) waited on only when no other endpoint is left to try.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::metrics::Registry;

pub(crate) const MAX_URLS: usize = 5;
pub(crate) const DEFAULT_TIMEOUT_MS: u64 = 15_000;
pub(crate) const DEFAULT_RETRIES: u64 = 6;
pub(crate) const MAX_RETRIES: u64 = 10;
const RETRY_BASE_MS: u64 = 400;
const RETRY_DELAY_CAP_MS: u64 = 10_000;
const RETRY_BUDGET_MS: u64 = 30_000;

#[derive(Debug, thiserror::Error)]
pub(crate) enum RpcError {
    /// The chain answered: an execution revert, bad params, or any other JSON-RPC error that
    /// would be the same on every endpoint.
    #[error("{method}: {message}")]
    Answer {
        method: String,
        code: i64,
        message: String,
    },
    #[error("{method}: {message}")]
    Transport { method: String, message: String },
    #[error("{method}: all {count} RPC endpoints failed; last: {last}")]
    AllFailed {
        method: String,
        count: usize,
        last: String,
    },
    #[error("{method}: RPC response missing result")]
    MissingResult { method: String },
}

impl RpcError {
    pub(crate) fn is_revert(&self) -> bool {
        matches!(self, Self::Answer { message, .. } if message.to_ascii_lowercase().contains("revert"))
    }
}

pub(crate) struct Rpc {
    urls: Vec<String>,
    client: reqwest::Client,
    retries: u64,
    sticky: AtomicUsize,
    next_id: AtomicU64,
    registry: Option<Arc<Registry>>,
}

/// The origin of an RPC URL for logs; paths often hold API keys.
pub(crate) fn origin(url: &str) -> String {
    reqwest::Url::parse(url)
        .ok()
        .map(|u| u.origin().ascii_serialization())
        .unwrap_or_else(|| "[configured RPC]".into())
}

fn retryable(code: i64, message: &str) -> bool {
    if matches!(code, -32005 | -32603 | 429) {
        return true;
    }
    let lower = message.to_ascii_lowercase();
    [
        "rate",
        "limit",
        "too many",
        "unavailable",
        "header not found",
        "timeout",
        "busy",
        "overload",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn jitter_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::from(d.subsec_nanos()) % 300)
}

fn retry_after_ms(header: Option<&str>) -> Option<u64> {
    let text = header?.trim();
    if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) {
        return text.parse::<u64>().ok().map(|s| s.saturating_mul(1000));
    }
    None
}

/// The wait before retry `attempt` (0-based): the server's `Retry-After` when given, else
/// 400 ms doubling to 6.4 s; either capped at 10 s, plus up to 300 ms of jitter.
fn retry_delay(attempt: u32, retry_after: Option<u64>) -> Duration {
    let base = retry_after.unwrap_or(RETRY_BASE_MS << attempt.min(4));
    Duration::from_millis(base.min(RETRY_DELAY_CAP_MS) + jitter_ms())
}

impl Rpc {
    pub(crate) fn new(
        urls: Vec<String>,
        timeout: Duration,
        retries: u64,
        registry: Option<Arc<Registry>>,
    ) -> Result<Self, String> {
        if urls.is_empty() {
            return Err("no RPC URL".into());
        }
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| format!("build RPC client: {e}"))?;
        Ok(Self {
            urls,
            client,
            retries: retries.min(MAX_RETRIES),
            sticky: AtomicUsize::new(0),
            next_id: AtomicU64::new(1),
            registry,
        })
    }

    pub(crate) async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let count = self.urls.len();
        let start = self.sticky.load(Ordering::Relaxed) % count;
        let mut last = String::new();
        for step in 0..count {
            let index = (start + step) % count;
            let retries = if step + 1 == count { self.retries } else { 0 };
            match self
                .call_one(&self.urls[index], method, params.clone(), retries)
                .await
            {
                Ok(result) => {
                    self.sticky.store(index, Ordering::Relaxed);
                    return Ok(result);
                }
                Err(RpcError::Answer {
                    code,
                    message,
                    method,
                }) if !retryable(code, &message) => {
                    return Err(RpcError::Answer {
                        code,
                        message,
                        method,
                    })
                }
                Err(e) => {
                    if count > 1 {
                        tracing::debug!(endpoint = index, "RPC failover: {e}");
                    }
                    if let Some(registry) = &self.registry {
                        registry.counter(
                            "shade_tree_rpc_failovers_total",
                            &[("endpoint", &index.to_string())],
                        );
                    }
                    last = e.to_string();
                }
            }
        }
        Err(RpcError::AllFailed {
            method: method.to_string(),
            count,
            last,
        })
    }

    async fn call_one(
        &self,
        url: &str,
        method: &str,
        params: Value,
        retries: u64,
    ) -> Result<Value, RpcError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let transport = |message: String| RpcError::Transport {
            method: method.to_string(),
            message,
        };
        let mut waited = 0_u64;
        let mut attempt: u32 = 0;
        let response = loop {
            let response = self
                .client
                .post(url)
                .json(&body)
                .send()
                .await
                .map_err(|e| {
                    transport(if e.is_timeout() {
                        format!("RPC request timed out at {}", origin(url))
                    } else {
                        format!("RPC request failed at {}: {e}", origin(url))
                    })
                })?;
            let status = response.status();
            if status.is_success() {
                break response;
            }
            let retry_after = retry_after_ms(
                response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok()),
            );
            let throttled =
                status.as_u16() == 429 || (status.as_u16() == 503 && retry_after.is_some());
            if throttled && u64::from(attempt) < retries {
                let delay = retry_delay(attempt, retry_after);
                let delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
                if waited + delay_ms <= RETRY_BUDGET_MS {
                    waited += delay_ms;
                    attempt += 1;
                    if let Some(registry) = &self.registry {
                        registry.counter(
                            "shade_tree_rpc_throttle_retries_total",
                            &[("status", &status.as_u16().to_string())],
                        );
                    }
                    tokio::time::sleep(delay).await;
                    continue;
                }
            }
            return Err(transport(if throttled && attempt > 0 {
                format!("HTTP {status} (still throttled after {attempt} retries)")
            } else {
                format!("HTTP {status}")
            }));
        };
        let json: Value = response
            .json()
            .await
            .map_err(|e| transport(format!("invalid RPC JSON: {e}")))?;
        if let Some(error) = json.get("error") {
            return Err(RpcError::Answer {
                method: method.to_string(),
                code: error["code"].as_i64().unwrap_or(0),
                message: error["message"]
                    .as_str()
                    .unwrap_or("JSON-RPC error")
                    .to_string(),
            });
        }
        json.get("result")
            .cloned()
            .ok_or_else(|| RpcError::MissingResult {
                method: method.to_string(),
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retryable_errors_are_rate_limits_and_outages_not_answers() {
        assert!(retryable(-32005, ""));
        assert!(retryable(0, "Too Many Requests"));
        assert!(retryable(0, "header not found"));
        assert!(!retryable(3, "execution reverted: NotMember"));
        assert!(!retryable(-32602, "invalid params"));
    }

    #[test]
    fn retry_delays_follow_the_server_or_double_under_the_cap() {
        assert!(retry_delay(0, None) >= Duration::from_millis(400));
        assert!(retry_delay(0, None) < Duration::from_millis(700));
        assert!(retry_delay(4, None) >= Duration::from_millis(6400));
        assert!(retry_delay(9, None) <= Duration::from_millis(10_300));
        assert!(retry_delay(0, Some(2000)) >= Duration::from_millis(2000));
        assert!(retry_delay(0, Some(60_000)) <= Duration::from_millis(10_300));
        assert_eq!(retry_after_ms(Some("3")), Some(3000));
        assert_eq!(retry_after_ms(Some("Wed, 21 Oct 2015 07:28:00 GMT")), None);
    }

    #[test]
    fn origins_hide_paths() {
        assert_eq!(
            origin("https://rpc.example/v2/secret-key"),
            "https://rpc.example"
        );
        assert_eq!(origin("not a url"), "[configured RPC]");
    }

    #[tokio::test]
    async fn a_revert_is_returned_at_once_and_outages_fail_over() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        async fn serve(body: &'static str, status: &'static str) -> String {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                loop {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let mut buf = vec![0_u8; 4096];
                    let _ = socket.read(&mut buf).await;
                    let reply = format!(
                        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(reply.as_bytes()).await;
                }
            });
            format!("http://{addr}")
        }
        let revert = serve(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":3,\"message\":\"execution reverted\"}}",
            "200 OK",
        )
        .await;
        let down = serve("", "502 Bad Gateway").await;
        let ok = serve(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x1\"}",
            "200 OK",
        )
        .await;

        let rpc = Rpc::new(
            vec![down.clone(), ok.clone()],
            Duration::from_secs(5),
            0,
            None,
        )
        .unwrap();
        assert_eq!(
            rpc.call("eth_chainId", json!([])).await.unwrap(),
            json!("0x1")
        );
        assert_eq!(
            rpc.sticky.load(Ordering::Relaxed),
            1,
            "the working endpoint is remembered"
        );

        let rpc = Rpc::new(vec![revert, ok], Duration::from_secs(5), 0, None).unwrap();
        let error = rpc.call("eth_call", json!([])).await.unwrap_err();
        assert!(error.is_revert(), "{error}");

        let rpc = Rpc::new(vec![down], Duration::from_secs(5), 0, None).unwrap();
        assert!(matches!(
            rpc.call("eth_chainId", json!([])).await,
            Err(RpcError::AllFailed { count: 1, .. })
        ));
    }
}
