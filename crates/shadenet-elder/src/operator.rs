//! The commands that never start a service: `check` prints the resolved settings and whether
//! the ports and the signer are usable; `identity` mints the Elder's own onion
//! (`packages/node/bootnode/keygen.mjs`) for Tor's `HiddenServiceDir`.

use std::net::TcpListener;
use std::path::Path;

use crate::config::Config;
use crate::error::Error;

pub struct Operator;

impl Operator {
    /// The front door's usage text.
    pub fn usage() -> String {
        [
            "shadenet-elder: the Elder Tree, the live node directory behind an onion.",
            "",
            "  shadenet-elder run                 serve /announce, /directory and the rest (default)",
            "  shadenet-elder check               validate the settings, the ports and the signer; print the plan",
            "  shadenet-elder identity <hs-dir>   mint (or refuse to overwrite) the Elder's onion identity",
            "  shadenet-elder help",
            "",
            "Settings are the SHADE_TREE_BOOTNODE_* variables (docs/CONFIG.md, docs/BOOTNODE.md),",
            "read under the SHADENET_ prefix too.",
            "",
        ]
        .join("\n")
    }

    /// Print the plan; `Ok(true)` when everything checks out.
    pub fn check() -> Result<bool, Error> {
        let config = Config::from_env()?;
        let mut ready = true;
        for (name, value) in config.display_rows() {
            println!("{name:<18} {value}");
        }
        for (what, port) in [
            ("Elder Tree backend", config.port),
            ("metrics", config.metrics_port),
        ] {
            if port == 0 {
                continue;
            }
            match TcpListener::bind(("127.0.0.1", port)) {
                Ok(_) => println!("{what:<18} port {port} free"),
                Err(e) => {
                    println!("{what:<18} port {port} in use ({e})");
                    ready = false;
                }
            }
        }
        if config.signer_key.exists() {
            match crate::signer::Signer::load_or_mint(&config.signer_key) {
                Ok(signer) => println!("{:<18} {}", "signer", signer.public_hex()),
                Err(e) => {
                    println!("{:<18} {e}", "signer");
                    ready = false;
                }
            }
        } else {
            println!(
                "{:<18} will be minted at {}",
                "signer",
                config.signer_key.display()
            );
        }
        println!("{}", if ready { "ready" } else { "not ready" });
        Ok(ready)
    }

    /// Mint the Elder's onion identity into `hs_dir` and print it.
    pub fn identity(hs_dir: &Path, label: &str, force: bool) -> Result<(), Error> {
        let minted =
            shadenet_service::onion::mint(hs_dir, label, force).map_err(Error::Identity)?;
        println!(
            "minted onion identity{}:",
            if label.is_empty() {
                String::new()
            } else {
                format!(" ({label})")
            }
        );
        println!("  onion:    {}", minted.onion);
        println!(
            "  hsDir:    {}   (point Tor's HiddenServiceDir here)",
            hs_dir.display()
        );
        println!(
            "  secret:   {}   (the identity seed; keep secret)",
            hs_dir
                .join(shadenet_service::onion::IDENTITY_FILE)
                .display()
        );
        Ok(())
    }
}
