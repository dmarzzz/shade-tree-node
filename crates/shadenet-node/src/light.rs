//! The light-client root provider (`packages/node/lib/root-provider.mjs`
//! `LightClientRootProvider`, `packages/node/lib/helios-root.mjs`): the contract's
//! `currentRoot` storage slot proven with `eth_getProof` against a block's state root, so the
//! RPC cannot substitute a false root. The state root is the RPC's own header unless a local
//! Helios verifying RPC anchors it to the beacon sync committee, in which case the RPC's header
//! is cross-checked against Helios' and a divergence is refused by name.

use std::sync::Arc;
use std::time::Duration;

use num_bigint::BigUint;
use serde_json::{json, Value};
use tokio::sync::Mutex;

use crate::mpt;
use crate::rpc::{Rpc, RpcError};

/// `StakedReputationSet.ROOT_STORAGE_SLOT` (`currentRoot`).
const ROOT_SLOT: u64 = 3;
pub(crate) const HELIOS_TIMEOUT: Duration = Duration::from_secs(10);

/// How the slot value is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// `eth_getProof`, verified against the state root.
    Proof,
    /// `eth_getStorageAt`, trusted: the documented weaker fallback for RPCs without proofs.
    StorageAt,
}

impl Mode {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Proof => "proof",
            Self::StorageAt => "storageat",
        }
    }
}

/// A local Helios verifying JSON-RPC: its headers chain to a sync-committee-verified payload.
pub(crate) struct Anchor {
    helios: Rpc,
    /// The chain Helios must report, `SHADE_TREE_HELIOS_CHAIN_ID`; else the upstream RPC's.
    expected_chain: Option<u64>,
    checked: Mutex<bool>,
}

fn transport(method: &str, message: impl Into<String>) -> RpcError {
    RpcError::Transport {
        method: method.into(),
        message: message.into(),
    }
}

fn hex_u64(value: &Value) -> Option<u64> {
    let text = value.as_str()?;
    u64::from_str_radix(text.trim_start_matches("0x"), 16).ok()
}

impl Anchor {
    pub(crate) fn new(url: String, expected_chain: Option<u64>) -> Result<Self, String> {
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(format!("SHADE_TREE_HELIOS_RPC_URL must be http(s): {url}"));
        }
        Ok(Self {
            helios: Rpc::new(vec![url], HELIOS_TIMEOUT, 0, None)?,
            expected_chain,
            checked: Mutex::new(false),
        })
    }

    pub(crate) fn source() -> &'static str {
        "helios (sync-committee verified)"
    }

    /// Once: Helios must be on the configured chain (else the upstream RPC's). A failed check
    /// is retried on the next call, so a sidecar still booting delays the start, nothing more.
    async fn check_chain(&self, upstream: &Rpc) -> Result<(), RpcError> {
        let mut checked = self.checked.lock().await;
        if *checked {
            return Ok(());
        }
        let helios_id = hex_u64(
            &self
                .helios
                .call("eth_chainId", json!([]))
                .await
                .map_err(|e| transport("eth_chainId", format!("helios unreachable: {e}")))?,
        )
        .ok_or_else(|| {
            transport(
                "eth_chainId",
                "helios eth_chainId returned an unparseable value",
            )
        })?;
        let (expected, source) = match self.expected_chain {
            Some(id) => (id, "SHADE_TREE_HELIOS_CHAIN_ID".to_string()),
            None => (
                hex_u64(&upstream.call("eth_chainId", json!([])).await?).ok_or_else(|| {
                    transport(
                        "eth_chainId",
                        "rpc eth_chainId returned an unparseable value",
                    )
                })?,
                "SHADE_TREE_RPC_URL".to_string(),
            ),
        };
        if helios_id != expected {
            return Err(transport(
                "eth_chainId",
                format!("helios chainId mismatch: helios reports {helios_id} but the configured chain is {expected} (from {source}); refusing to anchor"),
            ));
        }
        *checked = true;
        Ok(())
    }

    /// The verified header for `tag`: `(state root, block number)`.
    async fn trusted_state_root(
        &self,
        upstream: &Rpc,
        tag: &str,
    ) -> Result<([u8; 32], u64), RpcError> {
        self.check_chain(upstream).await?;
        let block = self
            .helios
            .call("eth_getBlockByNumber", json!([tag, false]))
            .await
            .map_err(|e| transport("eth_getBlockByNumber", format!("helios: {e}")))?;
        if block.is_null() {
            return Err(transport(
                "eth_getBlockByNumber",
                format!("helios has no verified block for tag {tag} (outside its verified window or not yet synced)"),
            ));
        }
        let state_root = block["stateRoot"]
            .as_str()
            .and_then(|s| mpt::parse_hash(s).ok())
            .ok_or_else(|| {
                transport(
                    "eth_getBlockByNumber",
                    format!("helios block {tag}: missing/malformed stateRoot"),
                )
            })?;
        let number = hex_u64(&block["number"]).ok_or_else(|| {
            transport(
                "eth_getBlockByNumber",
                format!("helios block {tag}: missing number"),
            )
        })?;
        Ok((state_root, number))
    }
}

/// What one read proved.
pub(crate) struct Read {
    /// The root as a decimal field element; `None` for the empty tree.
    pub(crate) root: Option<String>,
    pub(crate) block: u64,
}

pub(crate) struct Light {
    mode: Mode,
    anchor: Option<Arc<Anchor>>,
}

impl Light {
    pub(crate) fn new(mode: Mode, anchor: Option<Arc<Anchor>>) -> Self {
        Self { mode, anchor }
    }

    pub(crate) fn mode(&self) -> Mode {
        self.mode
    }

    pub(crate) fn state_root_verified(&self) -> bool {
        self.anchor.is_some()
    }

    /// What the startup line says about where the state root comes from.
    pub(crate) fn state_root_source(&self) -> &'static str {
        if self.anchor.is_some() {
            Anchor::source()
        } else {
            "rpc header (TRUSTED, not verified; set SHADE_TREE_HELIOS_RPC_URL to anchor to the sync committee)"
        }
    }

    /// The root slot of `contract` at `tag`, proven (or, in storage mode, trusted).
    pub(crate) async fn read(
        &self,
        rpc: &Rpc,
        contract: &str,
        tag: &str,
    ) -> Result<Read, RpcError> {
        let slot_hex = format!("0x{ROOT_SLOT:064x}");
        let (state_root, block) = match &self.anchor {
            Some(anchor) => {
                let (state_root, number) = anchor.trusted_state_root(rpc, tag).await?;
                let at = format!("0x{number:x}");
                // the rpc's header for the same block must agree; a divergence is the rpc
                // lying about the header or serving another chain, named as such
                let claimed = rpc.call("eth_getBlockByNumber", json!([at, false])).await?;
                if claimed.is_null() {
                    return Err(transport(
                        "eth_getBlockByNumber",
                        format!(
                            "RPC has no block {at} that the anchor ({}) attests",
                            Anchor::source()
                        ),
                    ));
                }
                let claimed_root = claimed["stateRoot"]
                    .as_str()
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if claimed_root != format!("0x{}", hex::encode(state_root)) {
                    return Err(transport(
                        "eth_getBlockByNumber",
                        format!(
                            "stateRoot mismatch at block {number}: RPC ({}) claims {claimed_root} but the anchor ({}) attests 0x{} -- RPC is lying about the header or serving another chain; refusing its proofs",
                            rpc.primary_origin(),
                            Anchor::source(),
                            hex::encode(state_root)
                        ),
                    ));
                }
                (state_root, number)
            }
            None => {
                let block = rpc
                    .call("eth_getBlockByNumber", json!([tag, false]))
                    .await?;
                if block.is_null() {
                    return Err(transport(
                        "eth_getBlockByNumber",
                        format!("no block at {tag}"),
                    ));
                }
                let state_root = block["stateRoot"]
                    .as_str()
                    .and_then(|s| mpt::parse_hash(s).ok())
                    .ok_or_else(|| transport("eth_getBlockByNumber", "block has no stateRoot"))?;
                let number = hex_u64(&block["number"])
                    .ok_or_else(|| transport("eth_getBlockByNumber", "block has no number"))?;
                (state_root, number)
            }
        };
        let at = format!("0x{block:x}");
        let value = match self.mode {
            Mode::StorageAt => {
                let value = rpc
                    .call("eth_getStorageAt", json!([contract, slot_hex, at]))
                    .await?;
                BigUint::from_bytes_be(
                    &mpt::parse_hex_bytes(value.as_str().unwrap_or("0x"))
                        .map_err(|e| transport("eth_getStorageAt", e))?,
                )
            }
            Mode::Proof => {
                let proof = rpc
                    .call("eth_getProof", json!([contract, [slot_hex], at]))
                    .await?;
                self.prove(contract, &slot_hex, &state_root, &proof)?
            }
        };
        Ok(Read {
            root: (value != BigUint::from(0_u8)).then(|| value.to_string()),
            block,
        })
    }

    /// The account proof gives the storage hash, the storage proof gives the slot value; the
    /// RPC's claimed value must match what was proven.
    fn prove(
        &self,
        contract: &str,
        slot_hex: &str,
        state_root: &[u8; 32],
        proof: &Value,
    ) -> Result<BigUint, RpcError> {
        let fail = |message: String| transport("eth_getProof", message);
        let nodes = |list: &Value| -> Result<Vec<Vec<u8>>, RpcError> {
            list.as_array()
                .ok_or_else(|| fail("eth_getProof returned no proof".into()))?
                .iter()
                .map(|n| mpt::parse_hex_bytes(n.as_str().unwrap_or("")).map_err(fail))
                .collect()
        };
        let storage_proof = proof["storageProof"]
            .get(0)
            .filter(|p| p.is_object())
            .ok_or_else(|| fail("eth_getProof returned no proof".into()))?;
        let account_nodes = nodes(&proof["accountProof"])?;
        let contract_bytes = mpt::parse_hex_bytes(contract).map_err(fail)?;
        let account = mpt::verify_proof(state_root, &contract_bytes, &account_nodes)
            .map_err(fail)?
            .ok_or_else(|| fail("account absent in state proof".into()))?;
        let storage_hash = match mpt::decode(&account).map_err(fail)? {
            mpt::Rlp::List(fields) if fields.len() == 4 => match &fields[2] {
                mpt::Rlp::Bytes(b) if b.len() == 32 => {
                    let mut hash = [0_u8; 32];
                    hash.copy_from_slice(b);
                    hash
                }
                _ => return Err(fail("malformed account node".into())),
            },
            _ => return Err(fail("malformed account node".into())),
        };
        if let Some(claimed) = proof["storageHash"].as_str() {
            if claimed.to_ascii_lowercase() != format!("0x{}", hex::encode(storage_hash)) {
                return Err(fail("storageHash mismatch vs proof".into()));
            }
        }
        let slot_bytes = mpt::parse_hex_bytes(slot_hex).map_err(fail)?;
        let storage_nodes = nodes(&storage_proof["proof"])?;
        let proven =
            match mpt::verify_proof(&storage_hash, &slot_bytes, &storage_nodes).map_err(fail)? {
                Some(field) => match mpt::decode(&field).map_err(fail)? {
                    mpt::Rlp::Bytes(b) => BigUint::from_bytes_be(&b),
                    mpt::Rlp::List(_) => return Err(fail("malformed slot value".into())),
                },
                None => BigUint::from(0_u8),
            };
        if let Some(claimed) = storage_proof["value"].as_str() {
            let claimed = BigUint::from_bytes_be(&mpt::parse_hex_bytes(claimed).map_err(fail)?);
            if claimed != proven {
                return Err(fail("proven slot value != reported value".into()));
            }
        }
        Ok(proven)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpt::tests::FIXTURE;

    #[tokio::test]
    async fn the_proof_mode_surfaces_the_proven_root_and_rejects_a_lying_value() {
        let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
        let light = Light::new(Mode::Proof, None);
        let state_root = mpt::parse_hash(fixture["block"]["stateRoot"].as_str().unwrap()).unwrap();
        let contract = fixture["contract"].as_str().unwrap();
        let slot = fixture["slot"].as_str().unwrap();
        let proven = light
            .prove(contract, slot, &state_root, &fixture["proof"])
            .unwrap();
        assert_eq!(proven.to_string(), fixture["root"].as_str().unwrap());
        let mut lying = fixture["proof"].clone();
        lying["storageProof"][0]["value"] = Value::String("0x1234".into());
        assert!(light
            .prove(contract, slot, &state_root, &lying)
            .unwrap_err()
            .to_string()
            .contains("proven slot value != reported value"));
        let mut wrong_hash = fixture["proof"].clone();
        wrong_hash["storageHash"] = Value::String(format!("0x{}", "00".repeat(32)));
        assert!(light
            .prove(contract, slot, &state_root, &wrong_hash)
            .unwrap_err()
            .to_string()
            .contains("storageHash mismatch"));
        assert!(light
            .prove(contract, slot, &[0_u8; 32], &fixture["proof"])
            .is_err());
        assert!(light
            .prove(contract, slot, &state_root, &json!({}))
            .unwrap_err()
            .to_string()
            .contains("returned no proof"));
    }
}
