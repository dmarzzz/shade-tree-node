//! The canopy signer (`loadOrMintSigner`): the ed25519 key whose public half clients pin.
//! Kept as `{ "pub": <hex>, "priv": <seed hex> }` at mode 0600; minted on first start.

use std::path::Path;

use serde::{Deserialize, Serialize};
use shadenet_proto::{ed25519_public_key, ed25519_sign};
use zeroize::Zeroizing;

use crate::error::Error;

#[derive(Serialize, Deserialize)]
struct File {
    #[serde(rename = "pub")]
    public: String,
    #[serde(rename = "priv")]
    private: String,
}

pub(crate) struct Signer {
    public_hex: String,
    seed: Zeroizing<[u8; 32]>,
}

impl Signer {
    /// Load the key at `path`, tightening its mode, or mint one there.
    pub(crate) fn load_or_mint(path: &Path) -> Result<Self, Error> {
        let fail = |message: String| Error::Signer {
            path: path.to_path_buf(),
            message,
        };
        if path.exists() {
            tighten(path).map_err(|e| fail(format!("chmod: {e}")))?;
            let text = std::fs::read_to_string(path).map_err(|e| fail(e.to_string()))?;
            let file: File =
                serde_json::from_str(&text).map_err(|e| fail(format!("not a signer file: {e}")))?;
            let seed: [u8; 32] = hex::decode(&file.private)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| fail("priv is not 32 bytes of hex".into()))?;
            let public_hex = hex::encode(ed25519_public_key(&seed));
            if !public_hex.eq_ignore_ascii_case(&file.public) {
                return Err(fail("pub does not match priv".into()));
            }
            return Ok(Self {
                public_hex,
                seed: Zeroizing::new(seed),
            });
        }
        let mut seed = Zeroizing::new([0_u8; 32]);
        getrandom::fill(seed.as_mut())
            .map_err(|e| fail(format!("operating-system randomness unavailable: {e}")))?;
        let public_hex = hex::encode(ed25519_public_key(&seed));
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| fail(format!("create {}: {e}", parent.display())))?;
        }
        let text = serde_json::to_string_pretty(&File {
            public: public_hex.clone(),
            private: hex::encode(*seed),
        })
        .map_err(|e| fail(e.to_string()))?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        use std::io::Write as _;
        match options.open(path) {
            Ok(mut file) => file
                .write_all(format!("{text}\n").as_bytes())
                .map_err(|e| fail(e.to_string()))?,
            // another process minted it first: use theirs
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Self::load_or_mint(path)
            }
            Err(e) => return Err(fail(e.to_string())),
        }
        Ok(Self { public_hex, seed })
    }

    /// The pinned public key, lowercase hex.
    pub(crate) fn public_hex(&self) -> &str {
        &self.public_hex
    }

    pub(crate) fn sign(&self, message: &[u8]) -> String {
        hex::encode(ed25519_sign(message, &self.seed))
    }
}

#[cfg(unix)]
fn tighten(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn tighten(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minted_signer_is_private_reloads_and_is_tightened() {
        let dir =
            std::env::temp_dir().join(format!("shadenet-elder-signer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("signer.key");
        let minted = Signer::load_or_mint(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let again = Signer::load_or_mint(&path).unwrap();
        assert_eq!(again.public_hex(), minted.public_hex());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let signature = minted.sign(b"hello");
        let public: [u8; 32] = hex::decode(minted.public_hex())
            .unwrap()
            .try_into()
            .unwrap();
        let sig: [u8; 64] = hex::decode(signature).unwrap().try_into().unwrap();
        assert!(shadenet_proto::ed25519_verify(b"hello", &sig, &public));
        std::fs::write(&path, "{\"pub\":\"00\",\"priv\":\"zz\"}").unwrap();
        assert!(Signer::load_or_mint(&path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
