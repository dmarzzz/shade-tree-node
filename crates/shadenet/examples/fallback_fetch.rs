//! An agent tool: fetch a URL directly, and only when the site blocks the request, retry it
//! through `ShadeNet`. Prints one JSON object on stdout for the agent to read.
//!
//! ```sh
//! SHADENET_IDENTITY=~/.config/shadenet/identity.json \
//!   cargo run -p shadenet --example fallback_fetch -- https://duckduckgo.com/html/?q=shadenet
//! ```

use std::sync::Arc;
use std::time::Duration;

use eyre::WrapErr as _;
use serde::Serialize;
use serde_json::json;
use shadenet::Block;

const USER_AGENT: &str = concat!("shadenet/", env!("CARGO_PKG_VERSION"));
const DIRECT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum Route {
    Direct,
    Shadenet,
}

struct Page {
    status: u16,
    body: Vec<u8>,
    truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Output<'a> {
    url: &'a str,
    route: Route,
    status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    block: Option<Block>,
    #[serde(skip_serializing_if = "Option::is_none")]
    direct_block: Option<Block>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gateway: Option<String>,
    truncated: bool,
    body: String,
}

async fn direct(http: &reqwest::Client, url: &str) -> Result<Page, reqwest::Error> {
    let mut response = http.get(url).send().await?;
    let status = response.status().as_u16();
    let mut body = Vec::new();
    let mut truncated = false;
    while let Some(chunk) = response.chunk().await? {
        let room = shadenet::fetch::DEFAULT_MAX_BYTES - body.len();
        if chunk.len() > room {
            body.extend_from_slice(&chunk[..room]);
            truncated = true;
            break;
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Page {
        status,
        body,
        truncated,
    })
}

fn print(output: &impl Serialize) -> eyre::Result<()> {
    let line = serde_json::to_string(output).wrap_err("failed to encode the result as JSON")?;
    println!("{line}");
    Ok(())
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let url = std::env::args()
        .nth(1)
        .ok_or_else(|| eyre::eyre!("usage: fallback_fetch <url>"))?;
    let identity = std::env::var("SHADENET_IDENTITY").unwrap_or_else(|_| "identity.json".into());

    let http = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .timeout(DIRECT_TIMEOUT)
        .build()
        .wrap_err("failed to build the direct HTTP client")?;

    let direct_block = match direct(&http, &url).await {
        Ok(page) => match Block::classify(page.status, &page.body) {
            None => {
                return print(&Output {
                    url: &url,
                    route: Route::Direct,
                    status: page.status,
                    block: None,
                    direct_block: None,
                    gateway: None,
                    truncated: page.truncated,
                    body: String::from_utf8_lossy(&page.body).into_owned(),
                });
            }
            Some(block) => block,
        },
        Err(_) => Block::Unreachable,
    };
    eprintln!("direct request blocked ({direct_block:?}); retrying through ShadeNet");

    let config = shadenet::Config::builder()
        .identity_file(&identity)
        .build()
        .wrap_err_with(|| format!("failed to load the ShadeNet identity at {identity}"))?;
    let client =
        Arc::new(shadenet::Client::new(config).wrap_err("failed to start the ShadeNet client")?);
    client.spawn_canopy_refresh();

    match client.fetch(shadenet::FetchRequest::get(&url)).await {
        Ok(response) => print(&Output {
            url: &url,
            route: Route::Shadenet,
            status: response.status,
            block: Block::classify(response.status, &response.body),
            direct_block: Some(direct_block),
            gateway: Some(response.gateway),
            truncated: response.truncated,
            body: String::from_utf8_lossy(&response.body).into_owned(),
        }),
        Err(error) => {
            print(&json!({
                "url": url,
                "route": Route::Shadenet,
                "directBlock": direct_block,
                "error": {
                    "code": error.code(),
                    "message": error.to_string(),
                    "retryAfterSeconds": error.retry_after().map(|wait| wait.as_secs()),
                },
            }))?;
            std::process::exit(error.exit_code().into());
        }
    }
}
