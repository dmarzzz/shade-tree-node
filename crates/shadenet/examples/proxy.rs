//! Embed the local CONNECT proxy in your own program.
//!
//! ```sh
//! SHADENET_IDENTITY=identity.json SHADENET_PROXY_TOKEN=$(shadenet proxy-token) \
//!   cargo run -p shadenet --example proxy
//! ```

use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let identity = std::env::var("SHADENET_IDENTITY").unwrap_or_else(|_| "identity.json".into());
    let token = std::env::var("SHADENET_PROXY_TOKEN")?;
    let client = Arc::new(shadenet::Client::new(
        shadenet::Config::builder()
            .identity_file(identity)
            .build()?,
    )?);
    client.spawn_canopy_refresh();
    let proxy = shadenet::ProxyConfig::new("127.0.0.1:8118", token);
    let listener = shadenet::proxy::bind(&proxy).await?;
    eprintln!("proxy listening on http://{}", listener.local_addr()?);
    shadenet::proxy::serve(client, listener, proxy).await?;
    Ok(())
}
