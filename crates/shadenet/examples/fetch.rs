//! Fetch one https URL through ShadeNet.
//!
//! ```sh
//! SHADENET_IDENTITY=~/.config/shadenet/identity.json \
//!   cargo run -p shadenet --example fetch -- https://api.ipify.org?format=json
//! ```

use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://api.ipify.org?format=json".into());
    let identity = std::env::var("SHADENET_IDENTITY").unwrap_or_else(|_| "identity.json".into());

    let config = shadenet::Config::builder()
        .identity_file(identity)
        .build()?;
    let client = Arc::new(shadenet::Client::new(config)?);
    client.spawn_canopy_refresh();

    match client.fetch(shadenet::FetchRequest::get(&url)).await {
        Ok(response) => {
            eprintln!("HTTP {} via {}", response.status, response.gateway);
            println!("{}", String::from_utf8_lossy(&response.body));
            Ok(())
        }
        Err(error) => {
            // Every error has a stable code; budget errors say when to retry.
            eprintln!("{}: {error}", error.code());
            if let Some(wait) = error.retry_after() {
                eprintln!("retry in {}s", wait.as_secs());
            }
            std::process::exit(error.exit_code().into());
        }
    }
}
