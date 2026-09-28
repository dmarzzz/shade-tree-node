//! Native Groth16 authorization proofs for member exit and withdrawal.
//!
//! The circuit proves knowledge of `identitySecret` and exposes
//! `[Poseidon1(identitySecret), context mod Fr]`. The on-chain wrapper binds that
//! inner commitment to the registered tiered leaf and binds the context to the
//! exact action/recipient. The released live client embeds the matching testnet
//! WASM, proving key, and verification key.

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_circom::{read_zkey, CircomReduction, WitnessCalculator};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{prepare_verifying_key, Groth16, Proof, VerifyingKey};
use ark_std::UniformRand;
use num_bigint::{BigInt, BigUint, Sign};
use wasmer::{Module, Store};

use crate::prover::ensure_probestack_linked;

#[cfg(feature = "embedded-artifacts")]
mod embedded {
    pub const WASM: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../circuits/rln/withdraw.wasm"
    ));
    pub const ZKEY: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../circuits/rln/withdraw_final.zkey"
    ));
    pub const VKEY: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../circuits/rln/withdraw_verification_key.json"
    ));
}

#[cfg(feature = "embedded-artifacts")]
pub(crate) struct EmbeddedWithdrawBytes {
    pub wasm: &'static [u8],
    pub zkey: &'static [u8],
    pub vkey: &'static [u8],
}

#[cfg(feature = "embedded-artifacts")]
pub(crate) fn embedded_bytes() -> EmbeddedWithdrawBytes {
    EmbeddedWithdrawBytes {
        wasm: embedded::WASM,
        zkey: embedded::ZKEY,
        vkey: embedded::VKEY,
    }
}

pub struct WithdrawProofInput {
    pub identity_secret: String,
    pub context: [u8; 32],
    /// `Some(dir)` reads withdraw.wasm, withdraw_final.zkey, and
    /// withdraw_verification_key.json from disk. `None` uses embedded artifacts.
    pub circuits_dir: Option<String>,
}

pub struct BuiltWithdrawProof {
    /// Exact `bytes proof` expected by WithdrawVerifier:
    /// abi.encode(a, b, c, identityCommitment), nine 32-byte words.
    pub proof_bytes: Vec<u8>,
    pub identity_commitment: String,
    pub context_field: String,
}

fn canonical_bigint(value: &str, label: &str) -> Result<BigInt, String> {
    let value = value.trim();
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(format!(
            "{label} must be a canonical unsigned decimal integer"
        ));
    }
    value
        .parse::<BigInt>()
        .map_err(|_| format!("{label} is not a decimal integer"))
}

fn pf_to_dec<F: PrimeField>(field: &F) -> String {
    BigUint::from_bytes_be(&field.into_bigint().to_bytes_be()).to_str_radix(10)
}

fn dec_to_fq(value: &serde_json::Value, label: &str) -> Result<Fq, String> {
    let value = value
        .as_str()
        .ok_or_else(|| format!("withdraw verification key {label} is not a decimal string"))?;
    let integer = BigUint::parse_bytes(value.as_bytes(), 10)
        .ok_or_else(|| format!("withdraw verification key {label} is not decimal"))?;
    let modulus = BigUint::from_bytes_be(&Fq::MODULUS.to_bytes_be());
    if integer >= modulus {
        return Err(format!(
            "withdraw verification key {label} is outside the BN254 base field"
        ));
    }
    Ok(Fq::from(integer))
}

fn g1(value: &serde_json::Value, label: &str) -> Result<G1Affine, String> {
    let values = value
        .as_array()
        .filter(|values| values.len() >= 2)
        .ok_or_else(|| format!("withdraw verification key {label} is not a G1 point"))?;
    let point = G1Affine::new_unchecked(
        dec_to_fq(&values[0], &format!("{label}.x"))?,
        dec_to_fq(&values[1], &format!("{label}.y"))?,
    );
    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(format!(
            "withdraw verification key {label} is not a valid G1 point"
        ));
    }
    Ok(point)
}

fn g2(value: &serde_json::Value, label: &str) -> Result<G2Affine, String> {
    let values = value
        .as_array()
        .filter(|values| values.len() >= 2)
        .ok_or_else(|| format!("withdraw verification key {label} is not a G2 point"))?;
    let x = values[0]
        .as_array()
        .filter(|values| values.len() >= 2)
        .ok_or_else(|| format!("withdraw verification key {label}.x is not Fq2"))?;
    let y = values[1]
        .as_array()
        .filter(|values| values.len() >= 2)
        .ok_or_else(|| format!("withdraw verification key {label}.y is not Fq2"))?;
    let point = G2Affine::new_unchecked(
        Fq2::new(
            dec_to_fq(&x[0], &format!("{label}.x.c0"))?,
            dec_to_fq(&x[1], &format!("{label}.x.c1"))?,
        ),
        Fq2::new(
            dec_to_fq(&y[0], &format!("{label}.y.c0"))?,
            dec_to_fq(&y[1], &format!("{label}.y.c1"))?,
        ),
    );
    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(format!(
            "withdraw verification key {label} is not a valid G2 point"
        ));
    }
    Ok(point)
}

fn parse_vk(value: &serde_json::Value) -> Result<VerifyingKey<Bn254>, String> {
    let gamma_abc_g1 = value["IC"]
        .as_array()
        .ok_or_else(|| "withdraw verification key IC is not an array".to_string())?
        .iter()
        .enumerate()
        .map(|(index, value)| g1(value, &format!("IC[{index}]")))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(VerifyingKey {
        alpha_g1: g1(&value["vk_alpha_1"], "vk_alpha_1")?,
        beta_g2: g2(&value["vk_beta_2"], "vk_beta_2")?,
        gamma_g2: g2(&value["vk_gamma_2"], "vk_gamma_2")?,
        delta_g2: g2(&value["vk_delta_2"], "vk_delta_2")?,
        gamma_abc_g1,
    })
}

fn push_word<F: PrimeField>(out: &mut Vec<u8>, value: &F) {
    let bytes = value.into_bigint().to_bytes_be();
    out.extend(std::iter::repeat_n(0_u8, 32 - bytes.len()));
    out.extend(bytes);
}

fn solidity_proof_bytes(proof: &Proof<Bn254>, identity_commitment: &Fr) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 * 32);
    push_word(&mut out, &proof.a.x);
    push_word(&mut out, &proof.a.y);
    // The bn256 pairing precompile takes Fq2 as imaginary then real. This is
    // the same swap snarkjs exportSolidityCallData applies to pi_b.
    push_word(&mut out, &proof.b.x.c1);
    push_word(&mut out, &proof.b.x.c0);
    push_word(&mut out, &proof.b.y.c1);
    push_word(&mut out, &proof.b.y.c0);
    push_word(&mut out, &proof.c.x);
    push_word(&mut out, &proof.c.y);
    push_word(&mut out, identity_commitment);
    out
}

pub fn build_withdraw_proof(input: &WithdrawProofInput) -> Result<BuiltWithdrawProof, String> {
    ensure_probestack_linked();
    let circuits = input.circuits_dir.as_deref();
    let identity_secret = canonical_bigint(&input.identity_secret, "identitySecret")?;
    let (_, secret_bytes) = identity_secret.to_bytes_be();
    let secret_integer = BigUint::from_bytes_be(&secret_bytes);
    let scalar_modulus = BigUint::from_bytes_be(&Fr::MODULUS.to_bytes_be());
    if secret_integer == BigUint::from(0_u8) || secret_integer >= scalar_modulus {
        return Err("identitySecret is outside the non-zero BN254 scalar field".into());
    }
    let context_value = BigUint::from_bytes_be(&input.context);
    let context_field = Fr::from(context_value);

    let mut inputs: HashMap<String, Vec<BigInt>> = HashMap::new();
    inputs.insert("identitySecret".into(), vec![identity_secret]);
    inputs.insert(
        "address".into(),
        vec![BigInt::from_bytes_be(
            Sign::Plus,
            &context_field.into_bigint().to_bytes_be(),
        )],
    );

    let runtime = tokio::runtime::Runtime::new().map_err(|e| format!("tokio runtime: {e}"))?;
    let full_assignment: Vec<Fr> = {
        let _guard = runtime.enter();
        let mut store = Store::default();
        let module = match circuits {
            Some(dir) => Module::from_file(&store, format!("{dir}/withdraw.wasm"))
                .map_err(|e| format!("load withdraw.wasm: {e}"))?,
            None => {
                #[cfg(feature = "embedded-artifacts")]
                {
                    Module::from_binary(&store, embedded::WASM)
                        .map_err(|e| format!("compile embedded withdraw.wasm: {e}"))?
                }
                #[cfg(not(feature = "embedded-artifacts"))]
                {
                    return Err("no embedded withdraw.wasm (build --features live)".into());
                }
            }
        };
        let mut calculator = WitnessCalculator::from_module(&mut store, module)
            .map_err(|e| format!("withdraw witness calculator: {e}"))?;
        calculator
            .calculate_witness_element::<Fr, _>(&mut store, inputs, false)
            .map_err(|e| format!("calculate withdraw witness: {e}"))?
    };
    if full_assignment.len() < 3 {
        return Err("withdraw witness omitted its public signals".into());
    }
    let identity_commitment = full_assignment[1];
    let witnessed_context = full_assignment[2];
    if witnessed_context != context_field {
        return Err("withdraw witness context does not match the requested action".into());
    }
    let public_inputs = &full_assignment[1..3];

    let (proving_key, matrices) = match circuits {
        Some(dir) => {
            let mut reader = BufReader::new(
                File::open(format!("{dir}/withdraw_final.zkey"))
                    .map_err(|e| format!("open withdraw_final.zkey: {e}"))?,
            );
            read_zkey(&mut reader).map_err(|e| format!("read withdraw_final.zkey: {e}"))?
        }
        None => {
            #[cfg(feature = "embedded-artifacts")]
            {
                read_zkey(&mut std::io::Cursor::new(embedded::ZKEY))
                    .map_err(|e| format!("read embedded withdraw_final.zkey: {e}"))?
            }
            #[cfg(not(feature = "embedded-artifacts"))]
            {
                return Err("no embedded withdraw_final.zkey (build --features live)".into());
            }
        }
    };
    let mut rng = ark_std::rand::thread_rng();
    let proof = Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
        &proving_key,
        Fr::rand(&mut rng),
        Fr::rand(&mut rng),
        &matrices,
        matrices.num_instance_variables,
        matrices.num_constraints,
        &full_assignment,
    )
    .map_err(|e| format!("create withdraw proof: {e}"))?;

    let vk_json: serde_json::Value = match circuits {
        Some(dir) => serde_json::from_reader(BufReader::new(
            File::open(format!("{dir}/withdraw_verification_key.json"))
                .map_err(|e| format!("open withdraw_verification_key.json: {e}"))?,
        ))
        .map_err(|e| format!("parse withdraw verification key: {e}"))?,
        None => {
            #[cfg(feature = "embedded-artifacts")]
            {
                serde_json::from_slice(embedded::VKEY)
                    .map_err(|e| format!("parse embedded withdraw verification key: {e}"))?
            }
            #[cfg(not(feature = "embedded-artifacts"))]
            {
                return Err(
                    "no embedded withdraw_verification_key.json (build --features live)".into(),
                );
            }
        }
    };
    let parsed_vk = parse_vk(&vk_json)?;
    let prepared = prepare_verifying_key(&parsed_vk);
    if !Groth16::<Bn254, CircomReduction>::verify_proof(&prepared, &proof, public_inputs)
        .map_err(|e| format!("verify withdraw proof: {e}"))?
    {
        return Err("withdraw proof did not verify against its embedded key".into());
    }

    Ok(BuiltWithdrawProof {
        proof_bytes: solidity_proof_bytes(&proof, &identity_commitment),
        identity_commitment: pf_to_dec(&identity_commitment),
        context_field: pf_to_dec(&context_field),
    })
}

#[cfg(all(test, feature = "embedded-artifacts"))]
mod tests {
    use super::*;

    #[test]
    fn embedded_withdraw_proof_self_verifies_and_encodes_nine_words() {
        let proof = build_withdraw_proof(&WithdrawProofInput {
            identity_secret: "111".into(),
            context: [0x42; 32],
            circuits_dir: None,
        })
        .unwrap();
        assert_eq!(proof.proof_bytes.len(), 9 * 32);
        assert!(!proof.identity_commitment.is_empty());
        assert!(!proof.context_field.is_empty());
    }
}
