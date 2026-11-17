//! Mint a node's onion identity (`packages/node/bootnode/keygen.mjs`): one ed25519 seed that
//! is both the Tor v3 hidden-service key (`hs_ed25519_secret_key` holds the expanded form)
//! and the key the node signs announces and receipts with (`identity.local.json`).

use std::path::Path;

use sha2::{Digest as _, Sha512};
use shadenet_proto::{ed25519_public_key, pubkey_to_onion};

const TAG_SECRET: &str = "== ed25519v1-secret: type0 ==";
const TAG_PUBLIC: &str = "== ed25519v1-public: type0 ==";
pub(crate) const IDENTITY_FILE: &str = "identity.local.json";
const FILES: [&str; 4] = [
    "hs_ed25519_secret_key",
    "hs_ed25519_public_key",
    "hostname",
    IDENTITY_FILE,
];

pub(crate) struct Minted {
    pub(crate) onion: String,
}

fn tag32(tag: &str) -> [u8; 32] {
    let mut out = [0_u8; 32];
    out[..tag.len()].copy_from_slice(tag.as_bytes());
    out
}

/// Tor's expanded secret key: `clamp(SHA512(seed)[..32]) || SHA512(seed)[32..]`.
fn expanded_secret(seed: &[u8; 32]) -> [u8; 64] {
    let hash = Sha512::digest(seed);
    let mut out = [0_u8; 64];
    out.copy_from_slice(&hash);
    out[0] &= 248;
    out[31] &= 127;
    out[31] |= 64;
    out
}

fn write_private(path: &Path, bytes: &[u8], exclusive: bool) -> Result<(), String> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true);
    if exclusive {
        options.create_new(true);
    } else {
        options.truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    use std::io::Write as _;
    let mut file = options
        .open(path)
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    file.write_all(bytes)
        .map_err(|e| format!("write {}: {e}", path.display()))
}

#[cfg(unix)]
pub(crate) fn make_private_dir(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("chmod {}: {e}", dir.display()))
}

#[cfg(not(unix))]
pub(crate) fn make_private_dir(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))
}

/// Mint a fresh identity into `hs_dir`. Refuses to overwrite an existing one unless `force`.
pub(crate) fn mint(hs_dir: &Path, label: &str, force: bool) -> Result<Minted, String> {
    let existing: Vec<&str> = FILES
        .iter()
        .copied()
        .filter(|file| hs_dir.join(file).exists())
        .collect();
    if !existing.is_empty() && !force {
        return Err(format!(
            "refusing to overwrite onion identity in {} ({}); reuse it, choose another directory, or pass --force only for an intentional rotation",
            hs_dir.display(),
            existing.join(", ")
        ));
    }
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed)
        .map_err(|e| format!("operating-system randomness unavailable: {e}"))?;
    let public = ed25519_public_key(&seed);
    let onion = pubkey_to_onion(&public);
    make_private_dir(hs_dir)?;
    let mut secret_file = tag32(TAG_SECRET).to_vec();
    secret_file.extend_from_slice(&expanded_secret(&seed));
    write_private(&hs_dir.join(FILES[0]), &secret_file, !force)?;
    let mut public_file = tag32(TAG_PUBLIC).to_vec();
    public_file.extend_from_slice(&public);
    write_private(&hs_dir.join(FILES[1]), &public_file, false)?;
    std::fs::write(hs_dir.join(FILES[2]), format!("{onion}\n"))
        .map_err(|e| format!("write hostname: {e}"))?;
    let identity = serde_json::json!({
        "label": label,
        "onion": onion,
        "pub": hex::encode(public),
        "seed": hex::encode(seed),
    });
    let text = serde_json::to_string_pretty(&identity).map_err(|e| e.to_string())?;
    write_private(
        &hs_dir.join(IDENTITY_FILE),
        format!("{text}\n").as_bytes(),
        false,
    )?;
    Ok(Minted { onion })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minted_identity_is_the_onion_tor_derives_from_the_expanded_key() {
        let dir = std::env::temp_dir().join(format!("shadenet-onion-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let minted = mint(&dir, "test", false).unwrap();
        assert!(minted.onion.ends_with(".onion"));
        assert_eq!(minted.onion.len(), 62);
        let secret = std::fs::read(dir.join("hs_ed25519_secret_key")).unwrap();
        assert_eq!(secret.len(), 96);
        assert!(secret.starts_with(TAG_SECRET.as_bytes()));
        let public = std::fs::read(dir.join("hs_ed25519_public_key")).unwrap();
        assert_eq!(public.len(), 64);
        let identity: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join(IDENTITY_FILE)).unwrap()).unwrap();
        assert_eq!(identity["onion"], minted.onion);
        let seed: [u8; 32] = hex::decode(identity["seed"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        // the scalar in the expanded key is the clamped sha-512 prefix, so tor's public key
        // (scalar * base point) equals the one derived from the seed
        let expanded = expanded_secret(&seed);
        assert_eq!(expanded[0] & 7, 0);
        assert_eq!(expanded[31] & 0xc0, 0x40);
        assert_eq!(&public[32..], &ed25519_public_key(&seed));
        assert_eq!(
            std::fs::read_to_string(dir.join("hostname")).unwrap(),
            format!("{}\n", minted.onion)
        );
        assert!(
            mint(&dir, "test", false).is_err(),
            "never overwrite by accident"
        );
        assert!(mint(&dir, "test", true).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
