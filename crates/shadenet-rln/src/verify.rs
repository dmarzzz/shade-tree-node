//! Groth16 verification of snarkjs-shaped proofs under a snarkjs verification key.
//!
//! This is the server half of the RLN crate: a node parses `verification_key.json`, parses the
//! `proof` object of an envelope, and checks it against the public signals it recomputed. The
//! prover and the withdraw builder use the same functions for their self-checks, so a proof
//! that passes here is exactly a proof the client would have shipped.

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{prepare_verifying_key, Groth16, PreparedVerifyingKey, Proof};
use num_bigint::BigUint;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{what} is not a decimal string")]
    NotDecimal { what: String },
    #[error("{what} is outside the BN254 base field")]
    OutOfField { what: String },
    #[error("{what} is not a G1 point")]
    NotG1 { what: String },
    #[error("{what} is not a G2 point")]
    NotG2 { what: String },
    #[error("{what} is not an affine point")]
    NotAffine { what: String },
    #[error("verification key IC is not an array")]
    IcNotArray,
    #[error("pairing check failed: {0}")]
    Pairing(String),
}

/// A parsed and prepared snarkjs verification key.
pub struct VerifyingKey {
    prepared: PreparedVerifyingKey<Bn254>,
}

impl VerifyingKey {
    /// Parse a snarkjs `verification_key.json`, checking every point is on the curve and in the
    /// prime-order subgroup.
    pub fn parse(json: &serde_json::Value) -> Result<Self, Error> {
        let gamma_abc_g1 = json["IC"]
            .as_array()
            .ok_or(Error::IcNotArray)?
            .iter()
            .enumerate()
            .map(|(index, value)| g1(value, &format!("verification key IC[{index}]")))
            .collect::<Result<Vec<_>, _>>()?;
        let key = ark_groth16::VerifyingKey {
            alpha_g1: g1(&json["vk_alpha_1"], "verification key vk_alpha_1")?,
            beta_g2: g2(&json["vk_beta_2"], "verification key vk_beta_2")?,
            gamma_g2: g2(&json["vk_gamma_2"], "verification key vk_gamma_2")?,
            delta_g2: g2(&json["vk_delta_2"], "verification key vk_delta_2")?,
            gamma_abc_g1,
        };
        Ok(Self {
            prepared: prepare_verifying_key(&key),
        })
    }
}

/// Parse a snarkjs proof object (`pi_a`, `pi_b`, `pi_c` in affine coordinates with the
/// trailing `1` / `["1","0"]` projective marker), checking every point.
pub fn parse_proof(json: &serde_json::Value) -> Result<Proof<Bn254>, Error> {
    Ok(Proof {
        a: affine_g1(&json["pi_a"], "proof pi_a")?,
        b: affine_g2(&json["pi_b"], "proof pi_b")?,
        c: affine_g1(&json["pi_c"], "proof pi_c")?,
    })
}

/// Run the pairing check. `public_inputs` are the circuit's public signals in witness order.
pub fn verify(
    key: &VerifyingKey,
    proof: &Proof<Bn254>,
    public_inputs: &[Fr],
) -> Result<bool, Error> {
    Groth16::<Bn254>::verify_proof(&key.prepared, proof, public_inputs)
        .map_err(|e| Error::Pairing(e.to_string()))
}

fn dec_to_fq(value: &serde_json::Value, what: &str) -> Result<Fq, Error> {
    let value = value.as_str().ok_or_else(|| Error::NotDecimal {
        what: what.to_string(),
    })?;
    let integer = BigUint::parse_bytes(value.as_bytes(), 10).ok_or_else(|| Error::NotDecimal {
        what: what.to_string(),
    })?;
    let modulus = BigUint::from_bytes_be(&Fq::MODULUS.to_bytes_be());
    if integer >= modulus {
        return Err(Error::OutOfField {
            what: what.to_string(),
        });
    }
    Ok(Fq::from(integer))
}

fn g1(value: &serde_json::Value, what: &str) -> Result<G1Affine, Error> {
    let values = value
        .as_array()
        .filter(|values| values.len() >= 2)
        .ok_or_else(|| Error::NotG1 {
            what: what.to_string(),
        })?;
    let point = G1Affine::new_unchecked(
        dec_to_fq(&values[0], &format!("{what}.x"))?,
        dec_to_fq(&values[1], &format!("{what}.y"))?,
    );
    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(Error::NotG1 {
            what: what.to_string(),
        });
    }
    Ok(point)
}

fn g2(value: &serde_json::Value, what: &str) -> Result<G2Affine, Error> {
    let values = value
        .as_array()
        .filter(|values| values.len() >= 2)
        .ok_or_else(|| Error::NotG2 {
            what: what.to_string(),
        })?;
    let x = values[0]
        .as_array()
        .filter(|values| values.len() >= 2)
        .ok_or_else(|| Error::NotG2 {
            what: format!("{what}.x"),
        })?;
    let y = values[1]
        .as_array()
        .filter(|values| values.len() >= 2)
        .ok_or_else(|| Error::NotG2 {
            what: format!("{what}.y"),
        })?;
    let point = G2Affine::new_unchecked(
        Fq2::new(
            dec_to_fq(&x[0], &format!("{what}.x.c0"))?,
            dec_to_fq(&x[1], &format!("{what}.x.c1"))?,
        ),
        Fq2::new(
            dec_to_fq(&y[0], &format!("{what}.y.c0"))?,
            dec_to_fq(&y[1], &format!("{what}.y.c1"))?,
        ),
    );
    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(Error::NotG2 {
            what: what.to_string(),
        });
    }
    Ok(point)
}

fn affine_g1(value: &serde_json::Value, what: &str) -> Result<G1Affine, Error> {
    if value.get(2).and_then(|z| z.as_str()) != Some("1") {
        return Err(Error::NotAffine {
            what: what.to_string(),
        });
    }
    g1(value, what)
}

fn affine_g2(value: &serde_json::Value, what: &str) -> Result<G2Affine, Error> {
    let z = value.get(2).and_then(|z| z.as_array());
    let affine =
        z.is_some_and(|z| z.len() == 2 && z[0].as_str() == Some("1") && z[1].as_str() == Some("0"));
    if !affine {
        return Err(Error::NotAffine {
            what: what.to_string(),
        });
    }
    g2(value, what)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rln_vkey() -> serde_json::Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../circuits/rln/verification_key.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn the_repo_verification_key_parses() {
        VerifyingKey::parse(&rln_vkey()).unwrap();
    }

    #[test]
    fn a_tampered_key_point_is_rejected() {
        let mut vkey = rln_vkey();
        vkey["vk_alpha_1"][0] = serde_json::Value::String("1".into());
        assert!(matches!(
            VerifyingKey::parse(&vkey),
            Err(Error::NotG1 { .. })
        ));
        let mut vkey = rln_vkey();
        vkey["IC"] = serde_json::Value::Null;
        assert!(matches!(VerifyingKey::parse(&vkey), Err(Error::IcNotArray)));
    }

    #[test]
    fn a_proof_must_carry_affine_markers_and_valid_points() {
        let projective = serde_json::json!({
            "pi_a": ["1", "2", "2"],
            "pi_b": [["1", "0"], ["1", "0"], ["1", "0"]],
            "pi_c": ["1", "2", "1"],
        });
        assert!(matches!(
            parse_proof(&projective),
            Err(Error::NotAffine { .. })
        ));
        let off_curve = serde_json::json!({
            "pi_a": ["1", "1", "1"],
            "pi_b": [["1", "0"], ["1", "0"], ["1", "0"]],
            "pi_c": ["1", "2", "1"],
        });
        assert!(matches!(parse_proof(&off_curve), Err(Error::NotG1 { .. })));
        let out_of_field = serde_json::json!({
            "pi_a": ["21888242871839275222246405745257275088696311157297823662689037894645226208583", "2", "1"],
            "pi_b": [["1", "0"], ["1", "0"], ["1", "0"]],
            "pi_c": ["1", "2", "1"],
        });
        assert!(matches!(
            parse_proof(&out_of_field),
            Err(Error::OutOfField { .. })
        ));
    }

    #[cfg(feature = "embedded-artifacts")]
    #[test]
    fn a_real_envelope_proof_round_trips_through_json_and_verifies() {
        use crate::prover::{build_envelope, EnvelopeInput};
        use crate::tree::{fr_to_dec, parse_fr, rate_commitment};

        let leaf = fr_to_dec(&rate_commitment(parse_fr("111").unwrap(), 8));
        let built = build_envelope(&EnvelopeInput {
            identity_secret: "111".into(),
            member_leaf: leaf.clone(),
            members: vec![leaf],
            target: "example.com:443".into(),
            nonce: "00112233445566778899aabbccddeeff".into(),
            signal: None,
            epoch: 7,
            rln_identifier: "1".into(),
            user_message_limit: 8,
            message_id: 0,
            circuits_dir: None,
        })
        .unwrap();
        let key = VerifyingKey::parse(&rln_vkey()).unwrap();
        let proof = parse_proof(&built.proof).unwrap();
        let signal = |name: &str| parse_fr(built.public_signals[name].as_str().unwrap()).unwrap();
        let inputs = [
            signal("y"),
            signal("root"),
            signal("nullifier"),
            signal("x"),
            signal("externalNullifier"),
        ];
        assert!(verify(&key, &proof, &inputs).unwrap());
        let mut wrong = inputs;
        wrong[3] = Fr::from(1_u64);
        assert!(!verify(&key, &proof, &wrong).unwrap());
    }
}
