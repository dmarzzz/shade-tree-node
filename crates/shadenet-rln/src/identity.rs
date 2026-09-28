//! Native Semaphore-v3 identity derivation used by the Shade Tree Rust client.
//!
//! This ports `lib/rln.mjs identityFor` and `lib/identity-file.mjs` exactly:
//! normalize the application secret into the BN254 scalar field, seed Semaphore
//! identity v3 with its decimal representation, SHA-512 that message, split the
//! digest into nullifier/trapdoor (253 bits each), then derive the Poseidon
//! identity secret and tiered RLN rate commitment.

use ark_bn254::Fr;
use num_bigint::BigUint;
use sha2::{Digest, Sha512};

use crate::tree::{fr_to_dec, poseidon1, poseidon2, rate_commitment};

const FIELD: &str = "21888242871839275222246405745257275088548364400416034343698204186575808495617";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityMaterial {
    pub identity_secret: String,
    pub leaf: String,
    pub limit: u64,
}

fn parse_secret(secret: &str) -> Result<BigUint, String> {
    let trimmed = secret.trim();
    if trimmed.is_empty() {
        return Err("empty secret".into());
    }
    if trimmed.starts_with('-') {
        return Err("negative secrets are not supported".into());
    }
    let parsed = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        BigUint::parse_bytes(hex.as_bytes(), 16)
    } else {
        BigUint::parse_bytes(trimmed.as_bytes(), 10)
    }
    .ok_or_else(|| "secret must be a decimal integer or 0x-prefixed hex".to_string())?;
    let field = BigUint::parse_bytes(FIELD.as_bytes(), 10).expect("BN254 field constant");
    Ok(parsed % field)
}

pub fn derive_identity(secret: &str, limit: u64) -> Result<IdentityMaterial, String> {
    if limit == 0 || limit > u16::MAX as u64 {
        return Err(format!("limit must be in 1..={}", u16::MAX));
    }
    let field_secret = parse_secret(secret)?;
    let digest = Sha512::digest(field_secret.to_str_radix(10).as_bytes());
    let nullifier = BigUint::from_bytes_be(&digest[..32]) >> 3u32;
    let trapdoor = BigUint::from_bytes_be(&digest[32..]) >> 3u32;
    let identity_secret = poseidon2(Fr::from(nullifier), Fr::from(trapdoor));
    let leaf = rate_commitment(identity_secret, limit);
    Ok(IdentityMaterial {
        identity_secret: fr_to_dec(&identity_secret),
        leaf: fr_to_dec(&leaf),
        limit,
    })
}

/// Recompute a tiered public leaf from an identity file's already-derived
/// `identitySecret`. This is the registration/import guard: a malformed or
/// mismatched bearer file must fail before a wallet or public RPC is touched.
pub fn commitment_from_identity_secret(
    identity_secret: &str,
    limit: u64,
) -> Result<String, String> {
    if limit == 0 || limit > u16::MAX as u64 {
        return Err(format!("limit must be in 1..={}", u16::MAX));
    }
    let value = identity_secret.trim();
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err("identitySecret must be a canonical unsigned decimal field element".into());
    }
    let parsed = BigUint::parse_bytes(value.as_bytes(), 10)
        .ok_or_else(|| "identitySecret is not a decimal field element".to_string())?;
    let field = BigUint::parse_bytes(FIELD.as_bytes(), 10).expect("BN254 field constant");
    if parsed == BigUint::from(0_u8) || parsed >= field {
        return Err("identitySecret is outside the non-zero BN254 field".into());
    }
    Ok(fr_to_dec(&rate_commitment(Fr::from(parsed), limit)))
}

/// The identity commitment `Poseidon1(identitySecret)` a member registers on chain. The
/// staking contract derives the leaf `Poseidon2(idc, limit)` from it (launch audit 2.1.4).
pub fn identity_commitment_from_identity_secret(identity_secret: &str) -> Result<String, String> {
    let parsed = canonical_field_element(identity_secret, "identitySecret")?;
    Ok(fr_to_dec(&poseidon1(Fr::from(parsed))))
}

/// The tiered leaf `Poseidon2(idc, limit)` for a public identity commitment, exactly as
/// `StakedReputationSet.registerIdentity` derives it.
pub fn rate_commitment_from_identity_commitment(
    identity_commitment: &str,
    limit: u64,
) -> Result<String, String> {
    if limit == 0 || limit > u16::MAX as u64 {
        return Err(format!("limit must be in 1..={}", u16::MAX));
    }
    let parsed = canonical_field_element(identity_commitment, "identity commitment")?;
    Ok(fr_to_dec(&poseidon2(Fr::from(parsed), Fr::from(limit))))
}

fn canonical_field_element(value: &str, label: &str) -> Result<BigUint, String> {
    let value = value.trim();
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(format!(
            "{label} must be a canonical unsigned decimal field element"
        ));
    }
    let parsed = BigUint::parse_bytes(value.as_bytes(), 10)
        .ok_or_else(|| format!("{label} is not a decimal field element"))?;
    let field = BigUint::parse_bytes(FIELD.as_bytes(), 10).expect("BN254 field constant");
    if parsed == BigUint::from(0_u8) || parsed >= field {
        return Err(format!("{label} is outside the non-zero BN254 field"));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_matches_javascript_semaphore_v3() {
        let secret = format!("0x{}", "5a".repeat(32));
        let default = derive_identity(&secret, 8).unwrap();
        assert_eq!(
            default.identity_secret,
            "619880168657502627082950702222527535803368023538932999730878823680368560389"
        );
        assert_eq!(
            default.leaf,
            "5196572551295737947407354759300311846728878441795551708418774774490326716161"
        );
        let tiered = derive_identity(&secret, 32).unwrap();
        assert_eq!(tiered.identity_secret, default.identity_secret);
        assert_eq!(
            tiered.leaf,
            "8531432642199005327621956115945513784566419842920753480654713473814300694991"
        );
    }

    #[test]
    fn imported_identity_secret_recomputes_the_public_tier_leaf() {
        let material = derive_identity(&format!("0x{}", "5a".repeat(32)), 1).unwrap();
        assert_eq!(
            commitment_from_identity_secret(&material.identity_secret, material.limit).unwrap(),
            material.leaf
        );
        assert!(commitment_from_identity_secret("0", 1).is_err());
        assert!(commitment_from_identity_secret("01", 1).is_err());
        assert!(commitment_from_identity_secret(FIELD, 1).is_err());
    }

    #[test]
    fn identity_commitment_path_matches_the_rate_commitment() {
        let material = derive_identity("0x5a", 8).unwrap();
        let idc = identity_commitment_from_identity_secret(&material.identity_secret).unwrap();
        assert_eq!(
            rate_commitment_from_identity_commitment(&idc, 8).unwrap(),
            material.leaf
        );
        assert_ne!(
            rate_commitment_from_identity_commitment(&idc, 1).unwrap(),
            material.leaf
        );
        assert!(rate_commitment_from_identity_commitment("0", 8).is_err());
        assert!(rate_commitment_from_identity_commitment(FIELD, 8).is_err());
        // SECRET_A = 111 in the Solidity tests: Poseidon1(111) is the fixture's idc.
        assert_eq!(
            identity_commitment_from_identity_secret("111").unwrap(),
            "13377623690824916797327209540443066247715962236839283896963055328700043345550"
        );
    }
}
