//! Runtime hash check of the RLN artifact set against `testdata/zk-artifacts.lock.json`
//! (T-HARD-8), plus the set's content-derived artifact id.
//!
//! The `live` client `include_bytes!`s `circuits/rln/{rln.wasm, rln_final.zkey,
//! verification_key.json}` ([`crate::prover`] `mod embedded`). Until now nothing checked
//! at RUNTIME that the bytes inside a shipped binary are the bytes the lock pins — the lock
//! selftest only runs in CI on the source tree. This module embeds the LOCK too and, at
//! `egress` startup, recomputes sha256 + byte length of each embedded artifact and compares
//! them to the lock entries, failing CLOSED with a message that names the drifted file. It
//! also derives the set's artifact id (`shade_tree_proto::artifact_id_of("rln", vkey_bytes)`,
//! i.e. `rln-<sha256(vkey)[0:16]>`) and checks it equals the lock's `circuits.rln.artifactId`
//! — that id is what the client stamps into the envelope's `artifact` field, so a binary can
//! never claim an id its bytes don't have.
//!
//! [`check_against_lock`] is feature-independent (pure over the bytes it is handed) so it is
//! unit-tested without `--features embedded-artifacts`; [`verify_embedded`] applies it to the
//! embedded consts under that feature.

use sha2::{Digest, Sha256};
use shade_tree_proto::artifact_id_of;

/// Repo-relative lock keys of the three artifacts the live binary embeds
/// (== `scripts/zk-artifacts-lock.mjs` ARTIFACTS paths + `prover.rs` include_bytes! paths).
pub const LOCK_KEY_WASM: &str = "circuits/rln/rln.wasm";
pub const LOCK_KEY_ZKEY: &str = "circuits/rln/rln_final.zkey";
pub const LOCK_KEY_VKEY: &str = "circuits/rln/verification_key.json";
pub const LOCK_KEY_WITHDRAW_WASM: &str = "circuits/rln/withdraw.wasm";
pub const LOCK_KEY_WITHDRAW_ZKEY: &str = "circuits/rln/withdraw_final.zkey";
pub const LOCK_KEY_WITHDRAW_VKEY: &str = "circuits/rln/withdraw_verification_key.json";

/// The lock is embedded alongside the artifacts so a released binary carries its own pin.
#[cfg(feature = "embedded-artifacts")]
pub const LOCK: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/zk-artifacts.lock.json"
));

/// What a successful check reports (for the startup log line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactCheck {
    /// `circuits.rln.artifactId` == `artifact_id_of("rln", vkey)` — the id the client sends.
    pub artifact_id: String,
    /// The lock's declared trust regime (`UNTRUSTED-TESTNET` today, `CEREMONY` after).
    pub trust: String,
    /// The vkey entry's declared provenance (`dev-testnet-untrusted` | `ceremony`).
    pub provenance: String,
    /// The lock's `circuits.rln.previousArtifactId`, if a ceremony has rotated the set.
    pub previous_artifact_id: Option<String>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn lock_entry_check(
    lock: &serde_json::Value,
    key: &str,
    bytes: &[u8],
    problems: &mut Vec<String>,
) -> Option<String> {
    let Some(e) = lock["artifacts"].get(key) else {
        problems.push(format!("lock has no entry for {key}"));
        return None;
    };
    let want_sha = e["sha256"].as_str().unwrap_or("");
    let want_len = e["bytes"].as_u64().unwrap_or(0);
    let got_sha = sha256_hex(bytes);
    if got_sha != want_sha {
        problems.push(format!(
            "sha256 mismatch {key}: embedded={got_sha} lock={want_sha}"
        ));
    }
    if bytes.len() as u64 != want_len {
        problems.push(format!(
            "byte-size mismatch {key}: embedded={} lock={want_len}",
            bytes.len()
        ));
    }
    e["provenance"].as_str().map(str::to_string)
}

/// Compare an artifact set's bytes to a lock. `Ok(check)` iff every one of the three files
/// hashes (sha256) and sizes to what the lock says AND the lock's `circuits.rln.artifactId`
/// equals the id derived from `vkey`. `Err(msg)` lists EVERY problem found (one per line),
/// naming the drifted file — the caller fails closed and prints it.
pub fn check_against_lock(
    lock_json: &str,
    wasm: &[u8],
    zkey: &[u8],
    vkey: &[u8],
) -> Result<ArtifactCheck, String> {
    let lock: serde_json::Value = serde_json::from_str(lock_json)
        .map_err(|e| format!("zk-artifacts lock is not JSON: {e}"))?;
    let mut problems = Vec::new();
    lock_entry_check(&lock, LOCK_KEY_WASM, wasm, &mut problems);
    lock_entry_check(&lock, LOCK_KEY_ZKEY, zkey, &mut problems);
    let provenance = lock_entry_check(&lock, LOCK_KEY_VKEY, vkey, &mut problems);

    let derived = artifact_id_of("rln", vkey);
    let declared = lock["circuits"]["rln"]["artifactId"].as_str().unwrap_or("");
    if declared != derived {
        problems.push(format!(
            "artifact id mismatch: lock circuits.rln.artifactId={declared:?} but embedded vkey derives {derived}"
        ));
    }
    if !problems.is_empty() {
        return Err(format!(
            "embedded RLN artifacts do NOT match testdata/zk-artifacts.lock.json:\n  {}",
            problems.join("\n  ")
        ));
    }
    Ok(ArtifactCheck {
        artifact_id: derived,
        trust: lock["trust"].as_str().unwrap_or("?").to_string(),
        provenance: provenance.unwrap_or_else(|| "?".to_string()),
        previous_artifact_id: lock["circuits"]["rln"]["previousArtifactId"]
            .as_str()
            .map(str::to_string),
    })
}

/// Verify the artifacts `include_bytes!`'d into THIS binary against the lock embedded with
/// them. Called at `shade-tree egress` startup (embedded path); a mismatch is a hard, named error.
#[cfg(feature = "embedded-artifacts")]
pub fn verify_embedded() -> Result<ArtifactCheck, String> {
    let e = crate::prover::embedded_bytes();
    check_against_lock(LOCK, e.wasm, e.zkey, e.vkey)
}

/// Verify the exit/withdraw artifacts embedded in the live client. These are a
/// separate circuit and proving key from the egress RLN set, so lifecycle commands
/// must check their own three lock entries before touching bearer material.
pub fn check_withdraw_against_lock(
    lock_json: &str,
    wasm: &[u8],
    zkey: &[u8],
    vkey: &[u8],
) -> Result<ArtifactCheck, String> {
    let lock: serde_json::Value = serde_json::from_str(lock_json)
        .map_err(|e| format!("zk-artifacts lock is not JSON: {e}"))?;
    let mut problems = Vec::new();
    lock_entry_check(&lock, LOCK_KEY_WITHDRAW_WASM, wasm, &mut problems);
    lock_entry_check(&lock, LOCK_KEY_WITHDRAW_ZKEY, zkey, &mut problems);
    let provenance = lock_entry_check(&lock, LOCK_KEY_WITHDRAW_VKEY, vkey, &mut problems);
    let derived = artifact_id_of("withdraw", vkey);
    let declared = lock["circuits"]["withdraw"]["artifactId"]
        .as_str()
        .unwrap_or("");
    if declared != derived {
        problems.push(format!(
            "withdraw artifact id mismatch: lock declares {declared:?} but embedded vkey derives {derived}"
        ));
    }
    if !problems.is_empty() {
        return Err(format!(
            "embedded withdraw artifacts do NOT match testdata/zk-artifacts.lock.json:\n  {}",
            problems.join("\n  ")
        ));
    }
    Ok(ArtifactCheck {
        artifact_id: derived,
        trust: lock["trust"].as_str().unwrap_or("?").to_string(),
        provenance: provenance.unwrap_or_else(|| "?".to_string()),
        previous_artifact_id: None,
    })
}

#[cfg(feature = "embedded-artifacts")]
pub fn verify_withdraw_embedded() -> Result<ArtifactCheck, String> {
    let embedded = crate::withdraw::embedded_bytes();
    check_withdraw_against_lock(LOCK, embedded.wasm, embedded.zkey, embedded.vkey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
    }
    fn read(rel: &str) -> Vec<u8> {
        fs::read(root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
    }
    fn lock() -> String {
        String::from_utf8(read("testdata/zk-artifacts.lock.json")).unwrap()
    }

    // The tree's artifacts match the tree's lock (the same invariant test/zk-artifacts.selftest.mjs
    // asserts in JS), and the derived id equals the lock's declared rln artifactId.
    #[test]
    fn tree_artifacts_match_lock_and_id() {
        let c = check_against_lock(
            &lock(),
            &read(LOCK_KEY_WASM),
            &read(LOCK_KEY_ZKEY),
            &read(LOCK_KEY_VKEY),
        )
        .expect("tree artifacts match the lock");
        assert!(c.artifact_id.starts_with("rln-"));
        assert_eq!(
            c.artifact_id.len(),
            4 + shade_tree_proto::ARTIFACT_ID_HASH_CHARS
        );
        let l: serde_json::Value = serde_json::from_str(&lock()).unwrap();
        assert_eq!(
            c.artifact_id,
            l["circuits"]["rln"]["artifactId"].as_str().unwrap()
        );
        // The id IS the vkey's lock hash prefix — the "content-derived, no registry" property.
        let vk_sha = l["artifacts"][LOCK_KEY_VKEY]["sha256"].as_str().unwrap();
        assert_eq!(c.artifact_id, format!("rln-{}", &vk_sha[..16]));
        assert!(!c.trust.is_empty() && !c.provenance.is_empty());
    }

    // A single flipped byte in any artifact fails closed, naming that file.
    #[test]
    fn tampered_artifact_is_named() {
        let mut zkey = read(LOCK_KEY_ZKEY);
        zkey[1000] ^= 0x01;
        let err = check_against_lock(&lock(), &read(LOCK_KEY_WASM), &zkey, &read(LOCK_KEY_VKEY))
            .expect_err("tampered zkey must fail");
        assert!(
            err.contains(&format!("sha256 mismatch {LOCK_KEY_ZKEY}")),
            "{err}"
        );
        assert!(
            !err.contains(LOCK_KEY_WASM),
            "only the drifted file is named: {err}"
        );

        let mut vkey = read(LOCK_KEY_VKEY);
        vkey.push(b'\n'); // size + hash + derived id all move
        let err = check_against_lock(&lock(), &read(LOCK_KEY_WASM), &read(LOCK_KEY_ZKEY), &vkey)
            .expect_err("tampered vkey must fail");
        assert!(
            err.contains(&format!("sha256 mismatch {LOCK_KEY_VKEY}")),
            "{err}"
        );
        assert!(
            err.contains(&format!("byte-size mismatch {LOCK_KEY_VKEY}")),
            "{err}"
        );
        assert!(err.contains("artifact id mismatch"), "{err}");
    }

    // A lock whose declared artifactId was hand-edited is rejected even when the bytes match.
    #[test]
    fn hand_edited_lock_id_is_rejected() {
        let mut l: serde_json::Value = serde_json::from_str(&lock()).unwrap();
        l["circuits"]["rln"]["artifactId"] =
            serde_json::Value::String("rln-0000000000000000".into());
        let err = check_against_lock(
            &l.to_string(),
            &read(LOCK_KEY_WASM),
            &read(LOCK_KEY_ZKEY),
            &read(LOCK_KEY_VKEY),
        )
        .expect_err("hand-edited id must fail");
        assert!(err.contains("artifact id mismatch"), "{err}");
        // and a lock missing an entry is named too
        let mut l2: serde_json::Value = serde_json::from_str(&lock()).unwrap();
        l2["artifacts"]
            .as_object_mut()
            .unwrap()
            .remove(LOCK_KEY_WASM);
        let err = check_against_lock(
            &l2.to_string(),
            &read(LOCK_KEY_WASM),
            &read(LOCK_KEY_ZKEY),
            &read(LOCK_KEY_VKEY),
        )
        .expect_err("missing entry must fail");
        assert!(
            err.contains(&format!("lock has no entry for {LOCK_KEY_WASM}")),
            "{err}"
        );
        assert!(check_against_lock("not json", b"", b"", b"").is_err());
    }

    // With the artifacts actually embedded, the binary's own bytes verify against its own lock.
    #[cfg(feature = "embedded-artifacts")]
    #[test]
    fn embedded_bytes_verify_against_embedded_lock() {
        let c = verify_embedded().expect("embedded artifacts match embedded lock");
        let l: serde_json::Value = serde_json::from_str(LOCK).unwrap();
        assert_eq!(
            c.artifact_id,
            l["circuits"]["rln"]["artifactId"].as_str().unwrap()
        );
        let withdraw = verify_withdraw_embedded().expect("withdraw artifacts match embedded lock");
        assert_eq!(
            withdraw.artifact_id,
            l["circuits"]["withdraw"]["artifactId"].as_str().unwrap()
        );
    }
}
