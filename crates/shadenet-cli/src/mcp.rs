//! `shadenet mcp`: a Model Context Protocol server on stdio.
//!
//! Tools:
//! - `shadenet_fetch`: fetch an https URL through ShadeNet.
//! - `shadenet_fetch_fallback`: fetch a URL directly, and retry it through `ShadeNet` only when
//!   the site blocks the direct request.
//! - `shadenet_status`: admission, tunnel budget, queue and canopy state.
//! - `shadenet_plan`: what a batch of fetches costs in epochs and seconds, and the tier that
//!   would do it in one epoch (ADR 0013).
//! - `shadenet_search`: query a SearXNG instance (only when `--searxng-url` or
//!   `SHADENET_SEARXNG_URL` is set). SearXNG itself decides which engines go through ShadeNet.
//!
//! Failures come back as tool results with `isError: true` and a JSON body carrying a stable
//! `code` and, when waiting helps, `retryAfterSeconds`, so a model can plan around a spent budget.
//!
//! Register it with Hermes (`hermes mcp add shadenet --command shadenet --args mcp`), Claude Code
//! (`claude mcp add shadenet -- shadenet mcp`) or any MCP client that speaks stdio.

use std::io::{BufRead, Write};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use crate::net::Context;
use crate::McpArgs;

const PROTOCOL_VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];
const MAX_TEXT: usize = 200_000;
/// The direct attempt: a connect deadline, then an overall one for the whole exchange (reqwest's
/// blocking client has no per-read timeout).
const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DIRECT_TIMEOUT: Duration = Duration::from_secs(60);

fn tools(search: bool) -> Value {
    let mut list = vec![
        json!({
            "name": "shadenet_fetch",
            "title": "Fetch a URL through ShadeNet",
            "description": "Fetch an https URL from an anonymous, unlinkable egress IP (a ShadeNet node reached over Tor). Use it for sites that block Tor or datacenter IPs, or when the request must not be linked to this machine. Do not use it for model APIs, localhost or anything that needs your login. Each call spends one tunnel from this epoch's budget; check shadenet_status when budget matters.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "https URL"},
                    "method": {"type": "string", "default": "GET"},
                    "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                    "body": {"type": "string"},
                    "max_bytes": {"type": "integer", "minimum": 1, "maximum": 10_000_000, "default": 2_000_000}
                },
                "required": ["url"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "shadenet_fetch_fallback",
            "title": "Fetch a URL, falling back to ShadeNet when blocked",
            "description": "Fetch an https URL over this machine's own connection first (through the proxy in HTTPS_PROXY/ALL_PROXY if one is set, unless that proxy is ShadeNet's own; no User-Agent unless you pass one; redirects are returned, not followed). Only when the site blocks it (403, 429, a CAPTCHA, a JavaScript challenge) or the connection could not be opened, retry the same request through ShadeNet, spending one tunnel. Only GET, HEAD and OPTIONS are retried; any other method gets the direct answer as it is, with `block` saying whether it was a block. The result says which route answered (`route`), why the direct attempt was blocked (`directBlock`), and whether the answer is itself a block (`block`); when the ShadeNet attempt fails the result is an error with `code`, plus `route`, `directBlock` and, if the direct connection failed, `directError`. The direct attempt reveals this machine's IP to the site, and the retry follows it within seconds with the same headers, so use shadenet_fetch instead when the request must not be linked to this machine. Local and private addresses are refused. Do not use it for model APIs or anything that needs your login.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "https URL on a public host"},
                    "method": {"type": "string", "default": "GET"},
                    "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                    "body": {"type": "string"},
                    "max_bytes": {"type": "integer", "minimum": 1, "maximum": 10_000_000, "default": 2_000_000}
                },
                "required": ["url"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "shadenet_status",
            "title": "ShadeNet status",
            "description": "Whether this identity is admitted, how many tunnels are left in the current epoch and when it resets, how many requests are queued for the next epoch, per-node latency, and how many canopy nodes are usable.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false}
        }),
        json!({
            "name": "shadenet_plan",
            "title": "Plan a batch of ShadeNet fetches",
            "description": "Before a batch of shadenet_fetch calls, learn what it costs: how many tunnels are available now, how many epochs the batch needs, roughly how many seconds until the last fetch can open, and which tier would do it in one epoch. Pass the URLs (or a count). Costs nothing.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "urls": {"type": "array", "items": {"type": "string"}, "description": "URLs or hosts the batch would fetch"},
                    "count": {"type": "integer", "minimum": 0, "description": "number of fetches, when the URLs are not known yet"}
                },
                "additionalProperties": false
            }
        }),
    ];
    if search {
        list.push(json!({
            "name": "shadenet_search",
            "title": "Web search through ShadeNet",
            "description": "Search the web with the configured SearXNG instance, whose blocked engines are routed through ShadeNet. Returns titles, URLs and snippets.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "engines": {"type": "string", "description": "comma-separated SearXNG engine names"},
                    "categories": {"type": "string"},
                    "max_results": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10}
                },
                "required": ["query"],
                "additionalProperties": false
            }
        }));
    }
    json!({ "tools": list })
}

fn text_result(value: &Value, is_error: bool) -> Value {
    json!({
        "content": [{"type": "text", "text": serde_json::to_string_pretty(value).unwrap_or_default()}],
        "structuredContent": value,
        "isError": is_error,
    })
}

fn tool_error(code: &str, message: String) -> Value {
    text_result(&json!({"error": {"code": code, "message": message}}), true)
}

fn fetch_request(args: &Value) -> Result<shadenet::FetchRequest, Value> {
    let Some(url) = args.get("url").and_then(Value::as_str) else {
        return Err(tool_error("config", "url is required".into()));
    };
    let headers = args
        .get("headers")
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
                .collect()
        })
        .unwrap_or_default();
    let method = args
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("GET")
        .to_ascii_uppercase();
    if reqwest::Method::from_bytes(method.as_bytes()).is_err() {
        return Err(tool_error("config", format!("bad method {method:?}")));
    }
    Ok(shadenet::FetchRequest {
        url: url.to_string(),
        method,
        headers,
        body: args
            .get("body")
            .and_then(Value::as_str)
            .map(|s| s.as_bytes().to_vec()),
        max_bytes: args
            .get("max_bytes")
            .and_then(Value::as_u64)
            .map_or(shadenet::fetch::DEFAULT_MAX_BYTES, |n| {
                n.clamp(1, 10_000_000) as usize
            }),
        timeout: Duration::from_secs(180),
    })
}

/// Adds `body` (text, or base64 with `bodyEncoding`), `truncated` and `contentType` to `value`.
fn with_body(
    mut value: Value,
    headers: &[(String, String)],
    body: &[u8],
    truncated: bool,
) -> Value {
    let content_type = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    if let Ok(text) = std::str::from_utf8(body) {
        let clipped: String = text.chars().take(MAX_TEXT).collect();
        value["truncated"] = (truncated || clipped.len() < text.len()).into();
        value["body"] = clipped.into();
    } else {
        use base64::Engine as _;
        value["truncated"] = truncated.into();
        value["bodyEncoding"] = "base64".into();
        value["body"] = base64::engine::general_purpose::STANDARD
            .encode(&body[..body.len().min(MAX_TEXT)])
            .into();
    }
    value["contentType"] = content_type.into();
    value
}

struct DirectPage {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    truncated: bool,
}

/// Why the direct attempt produced no response.
struct DirectError {
    message: String,
    /// The failure came before the request could reach the server (DNS, TCP or TLS handshake),
    /// so sending it again elsewhere cannot repeat anything.
    before_send: bool,
}

/// Whether `proxy` (a proxy URL from the environment) is the ShadeNet proxy at `listen`. The
/// direct attempt must not go through it: that would spend a tunnel on the "direct" request.
fn is_shadenet_proxy(proxy: &str, listen: &str) -> bool {
    let with_scheme = if proxy.contains("://") {
        proxy.to_string()
    } else {
        format!("http://{proxy}")
    };
    let (Ok(proxy), Ok(listen)) = (
        reqwest::Url::parse(&with_scheme),
        reqwest::Url::parse(&format!("http://{listen}")),
    ) else {
        return false;
    };
    let loopback = |url: &reqwest::Url| {
        let host = url.host_str().unwrap_or_default();
        host.eq_ignore_ascii_case("localhost")
            || host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified())
    };
    proxy.port_or_known_default() == listen.port_or_known_default()
        && (proxy.host_str() == listen.host_str() || (loopback(&proxy) && loopback(&listen)))
}

/// The proxy reqwest would take from the environment for an https URL points at ShadeNet.
fn env_proxy_is_shadenet(listen: &str) -> bool {
    ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
        .iter()
        .filter_map(|name| std::env::var(name).ok())
        .any(|proxy| is_shadenet_proxy(&proxy, listen))
}

/// The same request over this machine's own connection. It honours the proxy in the
/// environment (a VPN, Tor or corporate proxy) unless that proxy is ShadeNet's own at `listen`,
/// sends only the caller's headers (no User-Agent naming ShadeNet), and returns redirects
/// instead of following them, like the ShadeNet route.
fn direct(request: &shadenet::FetchRequest, listen: &str) -> Result<DirectPage, DirectError> {
    use std::io::Read as _;

    let refused = |message: String| DirectError {
        message,
        before_send: false,
    };
    let method = reqwest::Method::from_bytes(request.method.as_bytes())
        .map_err(|e| refused(format!("bad method {}: {e}", request.method)))?;
    let mut builder = reqwest::blocking::Client::builder()
        .connect_timeout(DIRECT_CONNECT_TIMEOUT)
        .timeout(DIRECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none());
    if env_proxy_is_shadenet(listen) {
        builder = builder.no_proxy();
    }
    let client = builder
        .build()
        .map_err(|e| refused(format!("build the direct HTTP client: {e}")))?;
    let mut builder = client.request(method, &request.url);
    for (name, value) in &request.headers {
        builder = builder.header(name, value);
    }
    if let Some(body) = &request.body {
        builder = builder.body(body.clone());
    }
    let response = builder.send().map_err(|e| DirectError {
        message: format!("direct request to {}: {e}", request.url),
        before_send: e.is_connect(),
    })?;
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.to_string(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    let mut body = Vec::new();
    response
        .take(request.max_bytes as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|e| {
            refused(format!(
                "read the direct response from {}: {e}",
                request.url
            ))
        })?;
    let truncated = body.len() > request.max_bytes;
    body.truncate(request.max_bytes);
    Ok(DirectPage {
        status,
        headers,
        body,
        truncated,
    })
}

struct Server {
    client: Arc<shadenet::Client>,
    searxng: Option<String>,
    /// Where `shadenet proxy` listens, so the direct attempt can avoid going through it.
    listen: String,
    runtime: tokio::runtime::Runtime,
}

impl Server {
    fn call(&self, name: &str, args: &Value) -> Value {
        match name {
            "shadenet_status" => {
                let status = self.runtime.block_on(self.client.status());
                text_result(&serde_json::to_value(status).unwrap_or_default(), false)
            }
            "shadenet_fetch" => self.fetch(args),
            "shadenet_fetch_fallback" => self.fetch_fallback(args),
            "shadenet_plan" => {
                let count = args
                    .get("urls")
                    .and_then(Value::as_array)
                    .map(|list| list.len() as u64)
                    .filter(|n| *n > 0)
                    .or_else(|| args.get("count").and_then(Value::as_u64))
                    .unwrap_or(1);
                text_result(
                    &serde_json::to_value(self.client.plan(count)).unwrap_or_default(),
                    false,
                )
            }
            "shadenet_search" if self.searxng.is_some() => self.search(args),
            other => tool_error("unknown_tool", format!("no tool named {other}")),
        }
    }

    fn fetch(&self, args: &Value) -> Value {
        let request = match fetch_request(args) {
            Ok(request) => request,
            Err(error) => return error,
        };
        match self.runtime.block_on(self.client.fetch(request)) {
            Ok(response) => {
                let value = serde_json::to_value(&response).unwrap_or_default();
                text_result(
                    &with_body(value, &response.headers, &response.body, response.truncated),
                    false,
                )
            }
            Err(error) => text_result(&error.to_json(), true),
        }
    }

    /// Direct first; ShadeNet only on a block or a connection that never opened, and only for
    /// GET, HEAD and OPTIONS. Other methods get the direct answer, block or not, and a direct
    /// failure as an error: retrying them could repeat a side effect.
    fn fetch_fallback(&self, args: &Value) -> Value {
        let request = match fetch_request(args) {
            Ok(request) => request,
            Err(error) => return error,
        };
        if let Err(error) = shadenet::fetch::parse_public_https(&request.url) {
            return text_result(&error.to_json(), true);
        }
        let retry = shadenet::fetch::safe_to_retry(&request.method);
        let (direct_block, direct_error) = match direct(&request, &self.listen) {
            Ok(page) => {
                let block = shadenet::Block::classify(page.status, &page.body);
                if block.is_none() || !retry {
                    let value = json!({
                        "route": "direct",
                        "status": page.status,
                        "headers": page.headers,
                        "block": block,
                    });
                    return text_result(
                        &with_body(value, &page.headers, &page.body, page.truncated),
                        false,
                    );
                }
                (block, None)
            }
            Err(error) if error.before_send && retry => {
                (Some(shadenet::Block::Unreachable), Some(error.message))
            }
            Err(error) => {
                return text_result(
                    &json!({"code": "transport", "message": error.message, "route": "direct"}),
                    true,
                );
            }
        };
        let (mut value, is_error) = match self.runtime.block_on(self.client.fetch(request)) {
            Ok(response) => {
                let mut value = serde_json::to_value(&response).unwrap_or_default();
                value["block"] = json!(shadenet::Block::classify(response.status, &response.body));
                (
                    with_body(value, &response.headers, &response.body, response.truncated),
                    false,
                )
            }
            Err(error) => (error.to_json(), true),
        };
        value["route"] = "shadenet".into();
        value["directBlock"] = json!(direct_block);
        if let Some(message) = direct_error {
            value["directError"] = message.into();
        }
        text_result(&value, is_error)
    }

    fn search(&self, args: &Value) -> Value {
        let Some(query) = args.get("query").and_then(Value::as_str) else {
            return tool_error("config", "query is required".into());
        };
        let base = self
            .searxng
            .as_deref()
            .unwrap_or_default()
            .trim_end_matches('/');
        let mut url = match reqwest::Url::parse(&format!("{base}/search")) {
            Ok(url) => url,
            Err(e) => return tool_error("config", format!("bad SearXNG URL: {e}")),
        };
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("q", query).append_pair("format", "json");
            if let Some(engines) = args.get("engines").and_then(Value::as_str) {
                pairs.append_pair("engines", engines);
            }
            if let Some(categories) = args.get("categories").and_then(Value::as_str) {
                pairs.append_pair("categories", categories);
            }
        }
        let max = args
            .get("max_results")
            .and_then(Value::as_u64)
            .unwrap_or(10)
            .clamp(1, 50) as usize;
        // SearXNG is local; its own settings route the reputation-blocked engines through ShadeNet.
        let response = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(60))
            .no_proxy()
            .build()
            .and_then(|client| client.get(url).send())
            .and_then(|response| response.error_for_status())
            .and_then(|response| response.json::<Value>());
        match response {
            Ok(body) => {
                let results: Vec<Value> = body["results"]
                    .as_array()
                    .map(|list| {
                        list.iter()
                            .take(max)
                            .map(|r| {
                                json!({
                                    "title": r["title"],
                                    "url": r["url"],
                                    "content": r["content"],
                                    "engine": r["engine"],
                                })
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                text_result(
                    &json!({"query": query, "results": results, "unresponsiveEngines": body["unresponsive_engines"]}),
                    false,
                )
            }
            Err(e) => tool_error("search_unavailable", format!("SearXNG request failed: {e}")),
        }
    }

    fn handle(&self, request: &Value) -> Option<Value> {
        let id = request.get("id").cloned();
        let method = request.get("method").and_then(Value::as_str).unwrap_or("");
        let params = request.get("params").cloned().unwrap_or(Value::Null);
        let result = match method {
            "initialize" => {
                let asked = params
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .unwrap_or(PROTOCOL_VERSIONS[0]);
                let version = PROTOCOL_VERSIONS
                    .iter()
                    .find(|v| **v == asked)
                    .copied()
                    .unwrap_or(PROTOCOL_VERSIONS[0]);
                Ok(json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": "shadenet", "title": "ShadeNet", "version": crate::VERSION},
                    "instructions": "ShadeNet gives this agent anonymous egress. Use shadenet_fetch only for sites that block Tor or datacenter IPs or when the request must not be linked to this machine; never for model APIs or logged-in sites. For ordinary browsing that should only use ShadeNet when a site blocks you, use shadenet_fetch_fallback: it tries this machine's own connection first, which exposes this machine's IP to the site, and spends a tunnel only on a block (GET, HEAD and OPTIONS only). Each fetch spends one tunnel of a small per-epoch budget. When the budget is spent a fetch waits for the next epoch by itself (up to about two epochs); call shadenet_plan before a batch to see how long it will take, and on budget_exhausted wait retryAfterSeconds."
                }))
            }
            "ping" => Ok(json!({})),
            "tools/list" => Ok(tools(self.searxng.is_some())),
            "tools/call" => {
                let name = params.get("name").and_then(Value::as_str).unwrap_or("");
                let args = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                Ok(self.call(name, &args))
            }
            "resources/list" => Ok(json!({"resources": []})),
            "prompts/list" => Ok(json!({"prompts": []})),
            _ if id.is_none() => return None, // notifications need no answer
            other => Err(json!({"code": -32601, "message": format!("method not found: {other}")})),
        };
        let id = id?;
        Some(match result {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err(error) => json!({"jsonrpc": "2.0", "id": id, "error": error}),
        })
    }
}

pub fn serve(args: McpArgs, ctx: &Context) -> ExitCode {
    let client = match crate::live::build_client_queued(&args.net, &args.queue, ctx, true) {
        Ok(client) => Arc::new(client),
        Err(message) => {
            eprintln!("mcp: {message}");
            return ExitCode::from(crate::EXIT_USAGE);
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("mcp: tokio runtime: {e}");
            return ExitCode::from(3);
        }
    };
    {
        let _guard = runtime.enter();
        client.spawn_canopy_refresh();
    }
    let searxng = args
        .searxng_url
        .clone()
        .or_else(|| shadenet::env::var_lenient("SEARXNG_URL"))
        .or_else(|| ctx.file.searxng_url.clone());
    let listen = shadenet::env::var_lenient("LISTEN")
        .or_else(|| ctx.file.listen.clone())
        .unwrap_or_else(|| "127.0.0.1:8118".into());
    let server = Server {
        client,
        searxng,
        listen,
        runtime,
    };
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(Value::Array(batch)) => {
                let answers: Vec<Value> = batch.iter().filter_map(|r| server.handle(r)).collect();
                (!answers.is_empty()).then_some(Value::Array(answers))
            }
            Ok(request) => server.handle(&request),
            Err(e) => Some(
                json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": format!("parse error: {e}")}}),
            ),
        };
        if let Some(response) = response {
            let _ = writeln!(stdout, "{response}");
            let _ = stdout.flush();
        }
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_is_listed_only_when_configured() {
        let names = |v: Value| -> Vec<String> {
            v["tools"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| t["name"].as_str().unwrap().to_string())
                .collect()
        };
        assert_eq!(
            names(tools(false)),
            vec![
                "shadenet_fetch",
                "shadenet_fetch_fallback",
                "shadenet_status",
                "shadenet_plan"
            ]
        );
        assert_eq!(
            names(tools(true)),
            vec![
                "shadenet_fetch",
                "shadenet_fetch_fallback",
                "shadenet_status",
                "shadenet_plan",
                "shadenet_search"
            ]
        );
    }

    #[test]
    fn the_shadenet_proxy_is_recognised() {
        let listen = "127.0.0.1:8118";
        assert!(is_shadenet_proxy("http://127.0.0.1:8118", listen));
        assert!(is_shadenet_proxy("http://localhost:8118/", listen));
        assert!(is_shadenet_proxy("127.0.0.1:8118", listen));
        assert!(is_shadenet_proxy("http://token@[::1]:8118", listen));
        assert!(!is_shadenet_proxy("socks5h://127.0.0.1:9050", listen));
        assert!(!is_shadenet_proxy("http://proxy.corp.example:8118", listen));
        assert!(!is_shadenet_proxy("http://127.0.0.1:3128", listen));
        assert!(is_shadenet_proxy("http://10.0.0.5:9000", "10.0.0.5:9000"));
    }

    #[test]
    fn a_bad_method_is_a_parameter_error() {
        let Err(error) = fetch_request(&json!({"url": "https://example.com/", "method": "GE T"}))
        else {
            panic!("a method with a space must be refused");
        };
        assert_eq!(error["structuredContent"]["error"]["code"], "config");
    }

    #[test]
    fn errors_are_tool_results_with_codes() {
        let result = tool_error("budget_exhausted", "wait".into());
        assert_eq!(result["isError"], true);
        assert_eq!(
            result["structuredContent"]["error"]["code"],
            "budget_exhausted"
        );
    }
}
