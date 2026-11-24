//! The HTTP routes (`makeServer`): `/health`, `/announce`, `/directory`, `/directory/delta`,
//! `/gateway/<onion>`, `/incidents`, `/incidents/alertmanager`, `/telemetry/relay` and
//! `/telemetry/aggregate`, every reply `application/json`, with the slow-client limits of
//! `HTTP_LIMITS`. Operator metrics never live here: Tor maps this whole listener into the
//! Elder onion, so `/metrics` would publish exact fleet activity.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use serde::Serialize;
use serde_json::value::RawValue;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use shadenet_service::clock;
use shadenet_service::metrics::Registry as Metrics;

use crate::canopy::Canopy;
use crate::config::Limits;
use crate::incidents::Incidents;
use crate::metrics::{announce_reason_label, relay_reason_label};
use crate::registry::{Outcome, Registry};
use crate::relay::Aggregator;

const ANNOUNCE_BODY_MAX: usize = 64 * 1024;
const RELAY_BODY_MAX: usize = 16 * 1024;
const ALERTMANAGER_BODY_MAX: usize = 256 * 1024;
const AGGREGATE_CACHE: (&str, &str) = ("cache-control", "public, max-age=60");
const JSON: &str = "application/json";
/// Informational only, never signed; clients verify the body against the pinned signer.
const ROLE: (&str, &str) = ("x-shade-tree-role", "elder-tree");
const VIEW: (&str, &str) = ("x-shade-tree-view", "canopy");

/// What every request handler shares.
pub(crate) struct Shared {
    pub(crate) registry: Arc<Registry>,
    pub(crate) canopy: Arc<Canopy>,
    pub(crate) metrics: Arc<Metrics>,
    pub(crate) signer_pub: String,
    pub(crate) admission: &'static str,
    pub(crate) pay: Option<Value>,
    pub(crate) relay: Arc<Aggregator>,
    pub(crate) incidents: Arc<Incidents>,
    pub(crate) incidents_token: Option<String>,
    pub(crate) limits: Limits,
    pub(crate) connections: AtomicUsize,
    pub(crate) listening: AtomicBool,
}

#[derive(Serialize)]
struct Health<'a> {
    ok: bool,
    count: usize,
    admission: &'a str,
    signer: &'a str,
    commit: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pay: Option<&'a Value>,
}

#[derive(Serialize)]
struct Refusal<'a> {
    ok: bool,
    err: &'a str,
}

#[derive(Serialize)]
struct Accepted<'a> {
    ok: bool,
    onion: &'a str,
    staked: bool,
    ttl: u64,
}

#[derive(Serialize)]
struct Ok {
    ok: bool,
}

#[derive(Serialize)]
struct WebhookApplied {
    ok: bool,
    firing: usize,
    resolved: usize,
    open: usize,
}

/// Compare a presented bearer token with the configured one in time independent of where
/// they differ.
fn token_matches(presented: &str, expected: &str) -> bool {
    if presented.len() != expected.len() {
        return false;
    }
    presented
        .bytes()
        .zip(expected.bytes())
        .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

fn quoted_sha256(body: &[u8]) -> String {
    format!("\"{}\"", hex::encode(Sha256::digest(body)))
}

enum BodyError {
    TooLarge,
    Timeout,
    Transport,
}

/// Read a request body up to `max` bytes within the request timeout.
async fn read_body(
    body: Incoming,
    max: usize,
    timeout: Option<Duration>,
) -> Result<Vec<u8>, BodyError> {
    let collect = async {
        let mut body = body;
        let mut out = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| BodyError::Transport)?;
            if let Some(data) = frame.data_ref() {
                if out.len() + data.len() > max {
                    return Err(BodyError::TooLarge);
                }
                out.extend_from_slice(data);
            }
        }
        Ok(out)
    };
    match timeout {
        Some(limit) => tokio::time::timeout(limit, collect)
            .await
            .unwrap_or(Err(BodyError::Timeout)),
        None => collect.await,
    }
}

fn response(
    status: StatusCode,
    content_type: &str,
    body: Vec<u8>,
    headers: &[(&str, &str)],
) -> Response<Full<Bytes>> {
    let mut builder = Response::builder()
        .status(status)
        .header("content-type", content_type)
        .header("content-length", body.len());
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}

fn json<T: Serialize>(
    status: StatusCode,
    value: &T,
    headers: &[(&str, &str)],
) -> Response<Full<Bytes>> {
    response(
        status,
        JSON,
        serde_json::to_vec(value).unwrap_or_default(),
        headers,
    )
}

fn refuse(status: StatusCode, err: &str, headers: &[(&str, &str)]) -> Response<Full<Bytes>> {
    json(status, &Refusal { ok: false, err }, headers)
}

fn header<'a>(req: &'a Request<Incoming>, name: &str) -> Option<&'a str> {
    req.headers().get(name).and_then(|v| v.to_str().ok())
}

/// `Accept-Encoding` names gzip as a token (parameters ignored).
fn wants_gzip(req: &Request<Incoming>) -> bool {
    header(req, "accept-encoding").is_some_and(|value| {
        value.split(',').any(|token| {
            token
                .split(';')
                .next()
                .is_some_and(|name| name.trim().eq_ignore_ascii_case("gzip"))
        })
    })
}

fn matches_etag(req: &Request<Incoming>, etag: &str) -> bool {
    header(req, "if-none-match").is_some_and(|value| value.split(',').any(|t| t.trim() == etag))
}

fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    // writing into a vec cannot fail
    let _ = encoder.write_all(data);
    encoder.finish().unwrap_or_default()
}

/// A JSON body, gzip-encoded when asked for, with the canopy headers.
fn canopy_body(
    req: &Request<Incoming>,
    status: StatusCode,
    body: Vec<u8>,
    etag: Option<&str>,
) -> Response<Full<Bytes>> {
    let compressed = wants_gzip(req);
    let out = if compressed { gzip(&body) } else { body };
    let mut headers = vec![ROLE, VIEW];
    if compressed {
        headers.push(("content-encoding", "gzip"));
    }
    if let Some(etag) = etag {
        headers.push(("etag", etag));
    }
    response(status, JSON, out, &headers)
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = text
                .get(i + 1..i + 3)
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
                .ok_or(())
            {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn query_param(query: Option<&str>, name: &str) -> Option<String> {
    query?
        .split('&')
        .filter_map(|pair| pair.split_once('=').or(Some((pair, ""))))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| percent_decode(&v.replace('+', " ")))
}

/// One request; never panics into the connection, an unexpected failure is a 500.
pub(crate) async fn handle(shared: Arc<Shared>, req: Request<Incoming>) -> Response<Full<Bytes>> {
    let now = clock::now_secs();
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(str::to_string);
    match (req.method(), path.as_str()) {
        (&Method::GET, "/health") => json(
            StatusCode::OK,
            &Health {
                ok: true,
                count: shared.registry.size(),
                admission: shared.admission,
                signer: &shared.signer_pub,
                commit: shadenet_service::version::COMMIT,
                pay: shared.pay.as_ref(),
            },
            &[ROLE],
        ),
        (&Method::GET, "/directory") => {
            shared
                .metrics
                .counter("shade_tree_bootnode_directory_fetches_total", &[]);
            let served = shared.canopy.directory(now);
            if matches_etag(&req, &served.etag) {
                return response(
                    StatusCode::NOT_MODIFIED,
                    JSON,
                    Vec::new(),
                    &[("etag", &served.etag), ROLE, VIEW],
                );
            }
            canopy_body(&req, StatusCode::OK, served.body, Some(&served.etag))
        }
        (&Method::GET, "/directory/delta") => {
            let since = query_param(query.as_deref(), "since");
            let (body, is_delta) = shared.canopy.delta(now, since.as_deref());
            shared.metrics.counter(
                "shade_tree_bootnode_directory_delta_fetches_total",
                &[("result", if is_delta { "delta" } else { "full" })],
            );
            canopy_body(&req, StatusCode::OK, body, None)
        }
        (&Method::GET, p) if p.starts_with("/gateway/") => {
            let onion = percent_decode(&p["/gateway/".len()..]);
            match shared.registry.record(&onion) {
                Some(record) => {
                    response(StatusCode::OK, JSON, record.get().as_bytes().to_vec(), &[])
                }
                None => refuse(StatusCode::NOT_FOUND, "not-found", &[]),
            }
        }
        (&Method::POST, "/announce") => {
            let body = match read_body(
                req.into_body(),
                ANNOUNCE_BODY_MAX,
                shared.limits.request_timeout,
            )
            .await
            {
                Ok(body) => body,
                Err(BodyError::TooLarge) => {
                    return refuse(StatusCode::BAD_REQUEST, "bad-json:body too large", &[])
                }
                Err(BodyError::Timeout) => {
                    return response(
                        StatusCode::REQUEST_TIMEOUT,
                        JSON,
                        Vec::new(),
                        &[("connection", "close")],
                    )
                }
                Err(BodyError::Transport) => {
                    return refuse(
                        StatusCode::BAD_REQUEST,
                        "bad-json:request body ended early",
                        &[],
                    )
                }
            };
            let raw = match String::from_utf8(body)
                .map_err(|e| e.to_string())
                .and_then(|text| RawValue::from_string(text).map_err(|e| e.to_string()))
            {
                Ok(raw) => raw,
                Err(e) => return refuse(StatusCode::BAD_REQUEST, &format!("bad-json:{e}"), &[]),
            };
            match shared.registry.announce(&raw, now).await {
                Outcome::Accepted { onion, staked } => {
                    shared.metrics.counter(
                        "shade_tree_bootnode_announces_total",
                        &[("result", "accepted")],
                    );
                    shared.metrics.gauge(
                        "shade_tree_bootnode_live_gateways",
                        &[],
                        shared.registry.size() as f64,
                    );
                    json(
                        StatusCode::OK,
                        &Accepted {
                            ok: true,
                            onion: &onion,
                            staked,
                            ttl: shared.registry.ttl_secs(),
                        },
                        &[],
                    )
                }
                Outcome::Rejected {
                    reason,
                    retry_after_secs,
                } => {
                    shared.metrics.counter(
                        "shade_tree_bootnode_announces_total",
                        &[
                            ("result", "rejected"),
                            ("reason", announce_reason_label(&reason)),
                        ],
                    );
                    match retry_after_secs {
                        Some(secs) => refuse(
                            StatusCode::TOO_MANY_REQUESTS,
                            &reason,
                            &[("retry-after", &secs.to_string())],
                        ),
                        None => refuse(StatusCode::BAD_REQUEST, &reason, &[]),
                    }
                }
            }
        }
        // reports never ride in /announce or /directory; the route shares the peer-write bucket
        // so a flood of reports cannot drive the aggregator's work
        (&Method::POST, "/telemetry/relay") => {
            if let Err(retry_after) = shared.registry.take_token(now) {
                return refuse(
                    StatusCode::TOO_MANY_REQUESTS,
                    "global-rate-limited",
                    &[("retry-after", &retry_after.to_string())],
                );
            }
            let body = match read_body(
                req.into_body(),
                RELAY_BODY_MAX,
                shared.limits.request_timeout,
            )
            .await
            {
                Ok(body) => body,
                Err(BodyError::Timeout) => {
                    return response(
                        StatusCode::REQUEST_TIMEOUT,
                        JSON,
                        Vec::new(),
                        &[("connection", "close")],
                    )
                }
                Err(_) => return refuse(StatusCode::BAD_REQUEST, "bad-report", &[]),
            };
            let Ok(report) = serde_json::from_slice::<Value>(&body) else {
                return refuse(StatusCode::BAD_REQUEST, "bad-report", &[]);
            };
            match shared.relay.accept(&report, clock::now_ms()) {
                Ok(()) => {
                    shared.metrics.counter(
                        "shade_tree_bootnode_relay_reports_total",
                        &[("result", "accepted")],
                    );
                    json(StatusCode::OK, &Ok { ok: true }, &[])
                }
                Err(reason) => {
                    shared.metrics.counter(
                        "shade_tree_bootnode_relay_reports_total",
                        &[
                            ("result", "rejected"),
                            ("reason", relay_reason_label(reason)),
                        ],
                    );
                    refuse(StatusCode::BAD_REQUEST, reason, &[])
                }
            }
        }
        // the only relay telemetry read: a signed, delayed, rounded cohort aggregate
        (&Method::GET, "/telemetry/aggregate") => {
            shared
                .metrics
                .counter("shade_tree_bootnode_relay_aggregates_total", &[]);
            let body = shared.relay.snapshot(clock::now_ms());
            let etag = quoted_sha256(&body);
            if matches_etag(&req, &etag) {
                return response(
                    StatusCode::NOT_MODIFIED,
                    JSON,
                    Vec::new(),
                    &[("etag", &etag), AGGREGATE_CACHE, ROLE],
                );
            }
            response(
                StatusCode::OK,
                JSON,
                body,
                &[AGGREGATE_CACHE, ("etag", &etag), ROLE],
            )
        }
        // served with the canopy headers: clients fetch it right after /directory and verify
        // it under the same pinned signer
        (&Method::GET, "/incidents") => response(
            StatusCode::OK,
            JSON,
            shared.incidents.feed(now),
            &[ROLE, VIEW],
        ),
        (&Method::POST, "/incidents/alertmanager") => {
            let Some(expected) = &shared.incidents_token else {
                return refuse(StatusCode::NOT_FOUND, "incidents-webhook-disabled", &[]);
            };
            let presented = header(&req, "authorization")
                .and_then(|auth| auth.strip_prefix("Bearer "))
                .map(str::trim)
                .unwrap_or("");
            if presented.is_empty() || !token_matches(presented, expected) {
                return refuse(StatusCode::UNAUTHORIZED, "bad-token", &[]);
            }
            let body = match read_body(
                req.into_body(),
                ALERTMANAGER_BODY_MAX,
                shared.limits.request_timeout,
            )
            .await
            {
                Ok(body) => body,
                Err(BodyError::Timeout) => {
                    return response(
                        StatusCode::REQUEST_TIMEOUT,
                        JSON,
                        Vec::new(),
                        &[("connection", "close")],
                    )
                }
                Err(_) => return refuse(StatusCode::BAD_REQUEST, "bad-json", &[]),
            };
            let Ok(payload) = serde_json::from_slice::<Value>(&body) else {
                return refuse(StatusCode::BAD_REQUEST, "bad-json", &[]);
            };
            match shared.incidents.apply_alertmanager(&payload, now) {
                Ok(applied) => json(
                    StatusCode::OK,
                    &WebhookApplied {
                        ok: true,
                        firing: applied.firing,
                        resolved: applied.resolved,
                        open: applied.open,
                    },
                    &[],
                ),
                Err(e) => refuse(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("bootnode-error:{e}"),
                    &[],
                ),
            }
        }
        _ => refuse(StatusCode::NOT_FOUND, "no-route", &[]),
    }
}

/// The header read timeout hyper applies to a new connection and to an idle keep-alive one
/// alike: the smaller of the two limits.
pub(crate) fn header_read_timeout(limits: &Limits) -> Option<Duration> {
    match (limits.headers_timeout, limits.keepalive_timeout) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

impl Shared {
    pub(crate) fn ready(&self) -> bool {
        self.listening.load(Ordering::Relaxed)
    }
}
