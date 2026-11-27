//! HTTPS for the node's chain reads and the canary, through ESP-IDF's HTTP client: mbedTLS
//! with the built-in certificate bundle, so servers are authenticated.
//!
//! Each request opens and closes its own connection. A kept-alive TLS session would hold
//! tens of kilobytes that the proof verifier needs.

use std::time::Duration;

use esp_idf_svc::http::client::{Configuration, EspHttpConnection};
use esp_idf_svc::http::Method;
use shadenode::chain::Http;

/// The largest response body kept (a JSON-RPC answer is a few hundred bytes).
const BODY_LIMIT: usize = 8 * 1024;

pub struct EspHttp;

fn connection() -> Result<EspHttpConnection, String> {
    EspHttpConnection::new(&Configuration {
        buffer_size: Some(1024),
        buffer_size_tx: Some(1024),
        timeout: Some(Duration::from_secs(15)),
        crt_bundle_attach: Some(esp_idf_svc::sys::esp_crt_bundle_attach),
        ..Default::default()
    })
    .map_err(|e| e.to_string())
}

impl Http for EspHttp {
    fn post_json(&self, url: &str, body: &str) -> Result<String, String> {
        let mut conn = connection()?;
        let length = body.len().to_string();
        let headers = [
            ("Content-Type", "application/json"),
            ("Content-Length", length.as_str()),
            ("Connection", "close"),
        ];
        conn.initiate_request(Method::Post, url, &headers)
            .map_err(|e| e.to_string())?;
        conn.write_all(body.as_bytes()).map_err(|e| e.to_string())?;
        conn.initiate_response().map_err(|e| e.to_string())?;
        let status = conn.status();
        let mut out = Vec::new();
        let mut buf = [0u8; 512];
        loop {
            let n = conn.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            if out.len() + n > BODY_LIMIT {
                return Err("response too large".into());
            }
            out.extend_from_slice(&buf[..n]);
        }
        if status != 200 {
            return Err(format!("HTTP {status}"));
        }
        String::from_utf8(out).map_err(|_| "response is not UTF-8".to_string())
    }

    fn get_status(&self, url: &str) -> Result<(u16, bool), String> {
        let mut conn = connection()?;
        let headers = [
            ("Connection", "close"),
            ("User-Agent", "curl/8.5.0"),
            ("Accept", "*/*"),
        ];
        conn.initiate_request(Method::Get, url, &headers)
            .map_err(|e| e.to_string())?;
        conn.initiate_response().map_err(|e| e.to_string())?;
        // Only the status and one header matter; the body is not read.
        Ok((conn.status(), conn.header("cf-mitigated").is_some()))
    }
}
