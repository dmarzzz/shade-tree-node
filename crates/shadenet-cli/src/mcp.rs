//! `shadenet mcp`: a Model Context Protocol server on stdio.
//!
//! Tools:
//! - `shadenet_fetch`: fetch an https URL through ShadeNet.
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

struct Server {
    client: Arc<shadenet::Client>,
    searxng: Option<String>,
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
        let Some(url) = args.get("url").and_then(Value::as_str) else {
            return tool_error("config", "url is required".into());
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
        let request = shadenet::FetchRequest {
            url: url.to_string(),
            method: args
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or("GET")
                .to_ascii_uppercase(),
            headers,
            body: args
                .get("body")
                .and_then(Value::as_str)
                .map(|s| s.as_bytes().to_vec()),
            max_bytes: args
                .get("max_bytes")
                .and_then(Value::as_u64)
                .map(|n| n.clamp(1, 10_000_000) as usize)
                .unwrap_or(shadenet::fetch::DEFAULT_MAX_BYTES),
            timeout: Duration::from_secs(180),
        };
        match self.runtime.block_on(self.client.fetch(request)) {
            Ok(response) => {
                let content_type = response
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default();
                let mut value = serde_json::to_value(&response).unwrap_or_default();
                match std::str::from_utf8(&response.body) {
                    Ok(text) => {
                        let clipped: String = text.chars().take(MAX_TEXT).collect();
                        value["truncated"] =
                            (response.truncated || clipped.len() < text.len()).into();
                        value["body"] = clipped.into();
                    }
                    Err(_) => {
                        use base64::Engine as _;
                        value["bodyEncoding"] = "base64".into();
                        value["body"] = base64::engine::general_purpose::STANDARD
                            .encode(&response.body[..response.body.len().min(MAX_TEXT)])
                            .into();
                    }
                }
                value["contentType"] = content_type.into();
                text_result(&value, false)
            }
            Err(error) => text_result(&error.to_json(), true),
        }
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
                    "instructions": "ShadeNet gives this agent anonymous egress. Use shadenet_fetch only for sites that block Tor or datacenter IPs or when the request must not be linked to this machine; never for model APIs or logged-in sites. Each fetch spends one tunnel of a small per-epoch budget. When the budget is spent a fetch waits for the next epoch by itself (up to about two epochs); call shadenet_plan before a batch to see how long it will take, and on budget_exhausted wait retryAfterSeconds."
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
    let server = Server {
        client,
        searxng,
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
            vec!["shadenet_fetch", "shadenet_status", "shadenet_plan"]
        );
        assert_eq!(
            names(tools(true)),
            vec![
                "shadenet_fetch",
                "shadenet_status",
                "shadenet_plan",
                "shadenet_search"
            ]
        );
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
