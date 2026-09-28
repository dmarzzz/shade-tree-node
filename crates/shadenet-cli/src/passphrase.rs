//! Passphrases for encrypted identity files: `SHADENET_PASSPHRASE_FILE`, then
//! `SHADENET_PASSPHRASE`, then a no-echo prompt when a terminal is attached. Services use the file.

use std::io::IsTerminal;
use std::path::Path;

use zeroize::Zeroizing;

fn from_file(path: &str) -> Result<Zeroizing<String>, String> {
    let raw = Zeroizing::new(
        std::fs::read_to_string(path).map_err(|e| format!("read passphrase file {path}: {e}"))?,
    );
    let trimmed = raw.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() {
        return Err(format!("passphrase file {path} is empty"));
    }
    Ok(Zeroizing::new(trimmed.to_string()))
}

/// The passphrase for unlocking `identity`, from the environment or the terminal.
pub fn unlock(identity: &Path) -> Result<Zeroizing<String>, String> {
    if let Some(path) = shadenet::env::var("PASSPHRASE_FILE")? {
        return from_file(&path);
    }
    if let Some(value) = shadenet::env::var("PASSPHRASE")? {
        return Ok(Zeroizing::new(value));
    }
    if !std::io::stdin().is_terminal() {
        return Err(format!(
            "identity {} is passphrase-protected; set SHADENET_PASSPHRASE_FILE (services) or run in a terminal",
            identity.display()
        ));
    }
    rpassword::prompt_password(format!("passphrase for {}: ", identity.display()))
        .map(Zeroizing::new)
        .map_err(|e| format!("read passphrase: {e}"))
}

/// A new passphrase: from the environment, or asked twice on the terminal.
pub fn choose() -> Result<Zeroizing<String>, String> {
    if let Some(path) = shadenet::env::var("PASSPHRASE_FILE")? {
        return from_file(&path);
    }
    if let Some(value) = shadenet::env::var("PASSPHRASE")? {
        return Ok(Zeroizing::new(value));
    }
    if !std::io::stdin().is_terminal() {
        return Err("no terminal to ask for a passphrase; set SHADENET_PASSPHRASE_FILE".into());
    }
    let first = Zeroizing::new(
        rpassword::prompt_password("new identity passphrase (8+ characters): ")
            .map_err(|e| format!("read passphrase: {e}"))?,
    );
    let second = Zeroizing::new(
        rpassword::prompt_password("repeat passphrase: ")
            .map_err(|e| format!("read passphrase: {e}"))?,
    );
    if *first != *second {
        return Err("passphrases do not match".into());
    }
    Ok(first)
}

/// The passphrase for `identity` if (and only if) the file is encrypted.
pub fn if_encrypted(identity: &Path) -> Result<Option<Zeroizing<String>>, String> {
    match shadenet::identity::read_public(identity) {
        Ok(public) if public.encrypted => unlock(identity).map(Some),
        _ => Ok(None),
    }
}
