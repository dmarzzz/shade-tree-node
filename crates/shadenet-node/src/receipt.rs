//! Signed egress success receipts (`packages/node/lib/receipt.mjs`): the onion key signs
//! `{v, onion, epoch, ok}` under a receipt-only domain, so a client can prove a node served it
//! in an epoch without the receipt naming the tunnel.

use std::path::Path;

use serde::Deserialize;
use shadenet_proto::{sign_receipt, RECEIPT_VERSION};

#[derive(Deserialize)]
struct IdentityFile {
    onion: String,
    seed: String,
}

pub(crate) struct Signer {
    onion: String,
    seed: [u8; 32],
}

impl Signer {
    /// Load `{onion, seed}` from the node's `identity.local.json`.
    pub(crate) fn load(path: &Path) -> Result<Self, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let file: IdentityFile = serde_json::from_slice(&bytes)
            .map_err(|e| format!("{} missing onion/seed: {e}", path.display()))?;
        let seed = hex::decode(file.seed.trim())
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or_else(|| format!("{}: seed is not 32 bytes of hex", path.display()))?;
        if file.onion.is_empty() {
            return Err(format!("{}: onion is empty", path.display()));
        }
        Ok(Self {
            onion: file.onion,
            seed,
        })
    }

    /// A signer over a known seed, for the tests.
    #[cfg(test)]
    pub(crate) fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            onion: shadenet_proto::pubkey_to_onion(&shadenet_proto::ed25519_public_key(&seed)),
            seed,
        }
    }

    /// The ed25519 seed behind the onion: it signs announces and telemetry reports too.
    pub(crate) fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// This node's onion, lowercase with its suffix: what a session initialization must name.
    pub(crate) fn onion(&self) -> String {
        shadenet_proto::session::normalize_onion(&self.onion)
    }

    /// `{"ok":true,"receipt":{...}}`, the success acknowledgement with a receipt attached.
    pub(crate) fn ack(&self, epoch: u64) -> String {
        let epoch = epoch.to_string();
        let sig = hex::encode(sign_receipt(
            RECEIPT_VERSION,
            &self.onion,
            &epoch,
            true,
            &self.seed,
        ));
        format!(
            "{{\"ok\":true,\"receipt\":{{\"v\":{RECEIPT_VERSION},\"onion\":{},\"epoch\":\"{epoch}\",\"ok\":true,\"sig\":\"{sig}\"}}}}",
            serde_json::to_string(&self.onion).unwrap_or_default()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shadenet_proto::{ed25519_public_key, pubkey_to_onion, verify_receipt, Receipt};

    #[test]
    fn the_ack_carries_a_receipt_the_client_verifies() {
        let seed = [7_u8; 32];
        let onion = pubkey_to_onion(&ed25519_public_key(&seed));
        let signer = Signer {
            onion: onion.clone(),
            seed,
        };
        let ack = signer.ack(42);
        assert!(ack.starts_with(&format!(
            "{{\"ok\":true,\"receipt\":{{\"v\":1,\"onion\":\"{onion}\",\"epoch\":\"42\",\"ok\":true,\"sig\":\""
        )));
        let parsed: serde_json::Value = serde_json::from_str(&ack).unwrap();
        let receipt = Receipt {
            v: 1,
            onion: onion.clone(),
            epoch: "42".into(),
            ok: true,
            sig: parsed["receipt"]["sig"].as_str().map(str::to_string),
        };
        assert!(verify_receipt(&receipt, Some(&onion), Some("42"), 1).is_ok());
    }
}
