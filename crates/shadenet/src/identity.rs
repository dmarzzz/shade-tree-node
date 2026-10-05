//! Member identity files.
//!
//! Two forms share one file name (`identity.json`):
//!
//! - plaintext, written by earlier releases and by `shadenet init` without `--passphrase`:
//!   `{ "identitySecret": "<decimal>", "leaf": "<decimal>", "limit": 1 }`
//! - encrypted (`version: 2`): the leaf and tier stay readable, so status and staking work without
//!   the passphrase; the secret is sealed with XChaCha20-Poly1305 under a scrypt-derived key, and
//!   the public fields and KDF parameters are bound as associated data.
//!
//! ```json
//! { "version": 2, "leaf": "…", "limit": 1,
//!   "encrypted": { "kdf": "scrypt", "logN": 17, "r": 8, "p": 1, "salt": "<hex>",
//!                  "cipher": "xchacha20poly1305", "nonce": "<hex>", "ciphertext": "<hex>" } }
//! ```
//!
//! The SDK never prompts: callers pass the passphrase in. The CLI reads it from
//! `SHADENET_PASSPHRASE_FILE`, `SHADENET_PASSPHRASE` or the terminal.

use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::Error;

/// Largest identity file read (the plaintext form is about 200 bytes).
const MAX_FILE: u64 = 16 * 1024;
/// scrypt cost for new files: 2^17 × 8 × 128 bytes = 128 MiB, about half a second.
pub const DEFAULT_LOG_N: u8 = 17;
/// Refuse files demanding more than 2^20 (1 GiB) so a hostile file cannot exhaust memory.
const MAX_LOG_N: u8 = 20;
const ENCRYPTED_VERSION: u64 = 2;

/// Loaded identity. The secret is zeroized on drop and never printed by `Debug`.
pub struct IdentityMaterial {
    pub secret: Zeroizing<String>,
    pub leaf: String,
    pub limit: Option<u64>,
}

impl std::fmt::Debug for IdentityMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityMaterial")
            .field("secret", &"<redacted>")
            .field("leaf", &self.leaf)
            .field("limit", &self.limit)
            .finish()
    }
}

/// The public half of an identity file, readable without a passphrase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicIdentity {
    pub leaf: String,
    pub limit: Option<u64>,
    pub encrypted: bool,
}

#[derive(Serialize, Deserialize)]
struct Sealed {
    kdf: String,
    #[serde(rename = "logN")]
    log_n: u8,
    r: u32,
    p: u32,
    salt: String,
    cipher: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Deserialize)]
struct Raw {
    #[serde(default)]
    version: Option<u64>,
    #[serde(rename = "identitySecret", default)]
    identity_secret: Option<String>,
    leaf: String,
    #[serde(default)]
    limit: Option<u64>,
    #[serde(default)]
    encrypted: Option<Sealed>,
}

impl Drop for Raw {
    fn drop(&mut self) {
        if let Some(secret) = self.identity_secret.as_mut() {
            zeroize::Zeroize::zeroize(secret);
        }
    }
}

fn read_raw(path: &Path) -> Result<Raw, Error> {
    let meta = std::fs::metadata(path)
        .map_err(|e| Error::Config(format!("read identity {}: {e}", path.display())))?;
    if !meta.is_file() || meta.len() > MAX_FILE {
        return Err(Error::Config(format!(
            "identity {} is not a regular file under 16 KiB",
            path.display()
        )));
    }
    let text = Zeroizing::new(
        std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("read identity {}: {e}", path.display())))?,
    );
    let raw: Raw = serde_json::from_str(&text).map_err(|_| {
        Error::Config(format!(
            "identity {} is not a valid identity file",
            path.display()
        ))
    })?;
    if raw.leaf.is_empty() || !raw.leaf.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Config(format!(
            "identity {} has a malformed leaf",
            path.display()
        )));
    }
    Ok(raw)
}

/// Read the public half of an identity file.
pub fn read_public(path: &Path) -> Result<PublicIdentity, Error> {
    let raw = read_raw(path)?;
    Ok(PublicIdentity {
        leaf: raw.leaf.clone(),
        limit: raw.limit,
        encrypted: raw.encrypted.is_some(),
    })
}

fn aad(leaf: &str, limit: Option<u64>, sealed: &Sealed) -> Vec<u8> {
    format!(
        "shadenet-identity-v2\n{leaf}\n{}\n{}\n{}\n{}\n{}\n{}",
        limit.map(|l| l.to_string()).unwrap_or_default(),
        sealed.kdf,
        sealed.log_n,
        sealed.r,
        sealed.p,
        sealed.cipher
    )
    .into_bytes()
}

fn derive_key(
    passphrase: &str,
    salt: &[u8],
    log_n: u8,
    r: u32,
    p: u32,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    if log_n > MAX_LOG_N || !(1..=32).contains(&r) || !(1..=16).contains(&p) {
        return Err(Error::Config(
            "identity file asks for unsupported scrypt parameters".into(),
        ));
    }
    let params = scrypt::Params::new(log_n, r, p, 32)
        .map_err(|e| Error::Config(format!("scrypt parameters: {e}")))?;
    let mut key = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(passphrase.as_bytes(), salt, &params, key.as_mut())
        .map_err(|e| Error::Internal(format!("scrypt: {e}")))?;
    Ok(key)
}

/// Load an identity. `passphrase` is called only when the file is encrypted.
pub fn load(
    path: &Path,
    passphrase: impl FnOnce() -> Result<Zeroizing<String>, Error>,
) -> Result<IdentityMaterial, Error> {
    let mut raw = read_raw(path)?;
    if let Some(secret) = raw.identity_secret.take() {
        if raw.encrypted.is_some() {
            return Err(Error::Config(format!(
                "identity {} holds both a plaintext and an encrypted secret",
                path.display()
            )));
        }
        return Ok(IdentityMaterial {
            secret: Zeroizing::new(secret),
            leaf: raw.leaf.clone(),
            limit: raw.limit,
        });
    }
    let sealed = raw
        .encrypted
        .as_ref()
        .ok_or_else(|| Error::Config(format!("identity {} has no secret", path.display())))?;
    if raw.version != Some(ENCRYPTED_VERSION)
        || sealed.kdf != "scrypt"
        || sealed.cipher != "xchacha20poly1305"
    {
        return Err(Error::Config(format!(
            "identity {} uses an unsupported encryption format",
            path.display()
        )));
    }
    let bad = || Error::Config(format!("identity {} is corrupt", path.display()));
    let salt = hex::decode(&sealed.salt).map_err(|_| bad())?;
    let nonce = hex::decode(&sealed.nonce).map_err(|_| bad())?;
    let ciphertext = hex::decode(&sealed.ciphertext).map_err(|_| bad())?;
    if salt.len() < 16 || nonce.len() != 24 {
        return Err(bad());
    }
    let passphrase = passphrase()?;
    let key = derive_key(&passphrase, &salt, sealed.log_n, sealed.r, sealed.p)?;
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad(&raw.leaf, raw.limit, sealed),
                },
            )
            .map_err(|_| {
                Error::Config(format!(
                    "wrong passphrase for identity {} (or the file was altered)",
                    path.display()
                ))
            })?,
    );
    let secret = String::from_utf8(plain.to_vec()).map_err(|_| bad())?;
    Ok(IdentityMaterial {
        secret: Zeroizing::new(secret),
        leaf: raw.leaf.clone(),
        limit: raw.limit,
    })
}

/// The JSON body of an identity file, encrypted when `passphrase` is given.
pub fn serialize(
    material: &IdentityMaterial,
    passphrase: Option<&str>,
    log_n: u8,
) -> Result<Zeroizing<String>, Error> {
    let body = match passphrase {
        None => serde_json::json!({
            "identitySecret": material.secret.as_str(),
            "leaf": material.leaf,
            "limit": material.limit,
        }),
        Some(passphrase) => {
            if passphrase.chars().count() < 8 {
                return Err(Error::Config(
                    "passphrase must be at least 8 characters".into(),
                ));
            }
            let mut salt = [0u8; 16];
            let mut nonce = [0u8; 24];
            getrandom::fill(&mut salt)
                .and_then(|()| getrandom::fill(&mut nonce))
                .map_err(|e| Error::Internal(format!("operating-system randomness: {e}")))?;
            let mut sealed = Sealed {
                kdf: "scrypt".into(),
                log_n,
                r: 8,
                p: 1,
                salt: hex::encode(salt),
                cipher: "xchacha20poly1305".into(),
                nonce: hex::encode(nonce),
                ciphertext: String::new(),
            };
            let key = derive_key(passphrase, &salt, log_n, 8, 1)?;
            let cipher = XChaCha20Poly1305::new(key.as_ref().into());
            let ciphertext = cipher
                .encrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: material.secret.as_bytes(),
                        aad: &aad(&material.leaf, material.limit, &sealed),
                    },
                )
                .map_err(|_| Error::Internal("encryption failed".into()))?;
            sealed.ciphertext = hex::encode(ciphertext);
            serde_json::json!({
                "version": ENCRYPTED_VERSION,
                "leaf": material.leaf,
                "limit": material.limit,
                "encrypted": sealed,
            })
        }
    };
    Ok(Zeroizing::new(
        serde_json::to_string_pretty(&body).map_err(|e| Error::Internal(e.to_string()))? + "\n",
    ))
}

/// Atomically replace `path` with `body`, owner-only. Used to add or remove a passphrase.
pub fn replace_file(path: &Path, body: &str) -> Result<(), Error> {
    use std::io::Write;
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let tmp = dir.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("identity"),
        std::process::id()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options
            .open(&tmp)
            .map_err(|e| Error::Config(format!("write {}: {e}", tmp.display())))?;
        file.write_all(body.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|e| Error::Config(format!("write {}: {e}", tmp.display())))?;
        std::fs::rename(&tmp, path)
            .map_err(|e| Error::Config(format!("replace {}: {e}", path.display())))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn material() -> IdentityMaterial {
        IdentityMaterial {
            secret: Zeroizing::new("123456789012345678901234567890".into()),
            leaf: "42".into(),
            limit: Some(1),
        }
    }

    fn write(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn plaintext_and_encrypted_files_round_trip() {
        let dir = std::env::temp_dir().join(format!("shadenet-identity-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let plain = write(
            &dir,
            "plain.json",
            &serialize(&material(), None, 10).unwrap(),
        );
        let loaded = load(&plain, || panic!("no passphrase for plaintext")).unwrap();
        assert_eq!(loaded.secret.as_str(), "123456789012345678901234567890");
        assert!(!read_public(&plain).unwrap().encrypted);

        // A low cost keeps the test fast; real files use DEFAULT_LOG_N.
        let body = serialize(&material(), Some("correct horse"), 10).unwrap();
        assert!(!body.contains("123456789012345678901234567890"));
        let sealed = write(&dir, "sealed.json", &body);
        let public = read_public(&sealed).unwrap();
        assert_eq!(
            (public.leaf.as_str(), public.limit, public.encrypted),
            ("42", Some(1), true)
        );
        let loaded = load(&sealed, || Ok(Zeroizing::new("correct horse".into()))).unwrap();
        assert_eq!(loaded.secret.as_str(), "123456789012345678901234567890");
        let wrong = load(&sealed, || Ok(Zeroizing::new("wrong horse".into()))).unwrap_err();
        assert!(wrong.to_string().contains("wrong passphrase"));

        // The public fields are bound: raising the tier in the file breaks decryption.
        let tampered = body.replace("\"limit\": 1", "\"limit\": 8");
        let tampered = write(&dir, "tampered.json", &tampered);
        assert!(load(&tampered, || Ok(Zeroizing::new("correct horse".into()))).is_err());

        // A hostile cost parameter is refused before any work.
        let greedy = body.replace("\"logN\": 10", "\"logN\": 30");
        let greedy = write(&dir, "greedy.json", &greedy);
        assert!(load(&greedy, || Ok(Zeroizing::new("correct horse".into())))
            .unwrap_err()
            .to_string()
            .contains("unsupported scrypt"));
        assert!(serialize(&material(), Some("short"), 10).is_err());
        std::fs::remove_dir_all(dir).ok();
    }

    /// `testdata/identity` holds identity files of both forms, written by this code (`shadenet
    /// init`, `shadenet identity-lock` on a copy, and `serialize` at a low scrypt cost). The
    /// JavaScript client reads the same files (packages/node/lib/identity-file.selftest.mjs):
    /// one format, both clients (#251).
    #[test]
    fn the_shared_identity_files_load_in_both_forms() {
        let dir = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testdata/identity"
        ));
        let vectors: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("vectors.json")).unwrap())
                .unwrap();
        let text = |key: &str| vectors[key].as_str().unwrap().to_string();

        let plain = load(&dir.join(text("plain")), || panic!("plaintext")).unwrap();
        assert_eq!(plain.leaf, text("leaf"));
        assert_eq!(plain.limit, vectors["limit"].as_u64());

        // `locked` is the CLI's own output (scrypt logN 17, about 13 s in a debug build): its
        // public half is checked here and JavaScript opens it. `lockedLowCost` is the same
        // identity sealed by `serialize` at logN 10, opened by both.
        let public = read_public(&dir.join(text("locked"))).unwrap();
        assert!(public.encrypted);
        assert_eq!(public.leaf, text("leaf"));
        assert_eq!(public.limit, vectors["limit"].as_u64());
        let locked = load(&dir.join(text("lockedLowCost")), || {
            Ok(Zeroizing::new(text("passphrase")))
        })
        .unwrap();
        assert_eq!(locked.secret.as_str(), plain.secret.as_str());
        assert_eq!(locked.leaf, plain.leaf);

        // The public values both clients must derive from the secret.
        #[cfg(feature = "live")]
        {
            use shadenet_rln::identity::{
                commitment_from_identity_secret, identity_commitment_from_identity_secret,
            };
            assert_eq!(
                identity_commitment_from_identity_secret(&plain.secret).unwrap(),
                text("identityCommitment")
            );
            assert_eq!(
                commitment_from_identity_secret(&plain.secret, plain.limit.unwrap()).unwrap(),
                text("leaf")
            );
        }
    }

    #[test]
    fn debug_never_prints_the_secret() {
        assert!(!format!("{:?}", material()).contains("1234567890"));
    }
}
