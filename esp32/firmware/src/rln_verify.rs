// Vendored from ShadeNet "shade-tree-node", crates/shadenet-rln/src/verify.rs (v0.7.5).
//
// MIT License
// Copyright (c) 2026 dmarzzz
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software
// and associated documentation files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or
// substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
// BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// Changes for the ESP32 firmware (everything else is byte-for-byte upstream):
//   * the upstream unit tests are dropped (they need the host prover and repo-relative paths);
//   * `VerifyingKey::shrink_to_fit`, `line_coeff_stats` and `time_g2_prepare_us` are added (in a
//     second `impl` block at the bottom), to trim and measure the heap held by the prepared key;
//   * `parse_fr` is added, copied from upstream crates/shadenet-rln/src/tree.rs, so public
//     signals are parsed with the same canonical-range check the node uses.

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

// ---- firmware additions ---------------------------------------------------------------------

impl VerifyingKey {
    /// Drop the spare capacity of the vectors inside the prepared key. arkworks builds the G2
    /// line-coefficient tables by pushing into an empty `Vec`, so each one ends up with the
    /// next power-of-two capacity; on a heap of a few hundred KB that slack is worth returning.
    pub fn shrink_to_fit(&mut self) {
        self.prepared.gamma_g2_neg_pc.ell_coeffs.shrink_to_fit();
        self.prepared.delta_g2_neg_pc.ell_coeffs.shrink_to_fit();
        self.prepared.vk.gamma_abc_g1.shrink_to_fit();
    }

    /// `(len, capacity)` summed over the two prepared G2 line-coefficient tables, and the size
    /// in bytes of one coefficient.
    pub fn line_coeff_stats(&self) -> (usize, usize, usize) {
        let gamma = &self.prepared.gamma_g2_neg_pc.ell_coeffs;
        let delta = &self.prepared.delta_g2_neg_pc.ell_coeffs;
        let one = gamma.first().map(core::mem::size_of_val).unwrap_or(0);
        (
            gamma.len() + delta.len(),
            gamma.capacity() + delta.capacity(),
            one,
        )
    }

    /// Time one G2 line-coefficient table build (what `prepare_verifying_key` does for gamma and
    /// for delta) with `clock`, returning the elapsed microseconds. Tells what it would cost to
    /// rebuild the two tables per verification instead of holding them in RAM.
    pub fn time_g2_prepare_us(&self, clock: impl Fn() -> i64) -> i64 {
        use ark_ec::pairing::Pairing;
        let started = clock();
        let table: <Bn254 as Pairing>::G2Prepared = self.prepared.vk.gamma_g2.into();
        let elapsed = clock() - started;
        core::hint::black_box(&table);
        elapsed
    }
}

/// Parse a canonical BN254 scalar field element from decimal or `0x` hex. Values at or above the
/// field modulus are rejected rather than reduced, so a leaf can never alias another one.
pub fn parse_fr(s: &str) -> Result<Fr, String> {
    let s = s.trim();
    let big = match s.strip_prefix("0x") {
        Some(hex) if !hex.is_empty() => BigUint::parse_bytes(hex.as_bytes(), 16),
        Some(_) => None,
        None if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => {
            BigUint::parse_bytes(s.as_bytes(), 10)
        }
        None => None,
    }
    .ok_or_else(|| format!("{:?} is not a decimal or 0x-hex field element", truncate(s)))?;
    let modulus = BigUint::from_bytes_be(&Fr::MODULUS.to_bytes_be());
    if big >= modulus {
        return Err(format!(
            "{:?} is not below the BN254 scalar field modulus",
            truncate(s)
        ));
    }
    Ok(Fr::from(big))
}

fn truncate(s: &str) -> String {
    s.chars().take(24).collect()
}
