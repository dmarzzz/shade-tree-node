//! Print the admission, budget and canopy state as JSON.
//!
//! ```sh
//! SHADENET_IDENTITY=~/.config/shadenet/identity.json cargo run -p shadenet --example status
//! ```

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = shadenet::Config::builder();
    if let Ok(identity) = std::env::var("SHADENET_IDENTITY") {
        builder = builder.identity_file(identity);
    }
    let client = shadenet::Client::new(builder.build()?)?;
    let status = client.status().await;
    println!("{}", serde_json::to_string_pretty(&status)?);
    Ok(())
}
