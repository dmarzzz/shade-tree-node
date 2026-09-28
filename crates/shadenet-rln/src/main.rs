//! RLN interop probe (T-RUST-2b, RLN-INTEROP slice).
//!
//! Generates an RLN Groth16 **envelope proof in Rust** against the repository's
//! own circom-rln v1.0.0 artifacts (`circuits/rln/rln.wasm` + `rln_final.zkey`),
//! and proves it is cross-verifiable with the JavaScript reference (`lib/rln.mjs`):
//!
//! 1. Re-derives the circuit public `x` from `(target, nonce)` with the SAME
//!    conformance-gated code the JS reference uses (`shadenet_proto::calculate_signal_hash`
//!    over `shadenet_proto::request_signal`), so the Rust side owns the target binding.
//! 2. Computes the full witness with the repo's `rln.wasm` (same circom compile as
//!    the repo's `rln_final.zkey`, so there is no witness-graph / wire-order risk).
//! 3. Asserts the witness public signals `[y, root, nullifier, x, externalNullifier]`
//!    equal the rlnjs reference proof's public signals for the same inputs.
//! 4. Proves with the repo's `rln_final.zkey` (loaded via `ark_circom::read_zkey`).
//! 5. Verifies the proof in-process against the repo's `verification_key.json`
//!    (the decisive crypto check: the Rust proof is valid under the JS verifier's VK).
//! 6. Emits the proof + public signals as snarkjs-shaped JSON so the JS harness can
//!    assemble the wire envelope and assert `verifyEnvelope` ACCEPTS it.
//!
//! Usage: `shadenet-rln-probe <fixture.json> <out.json> <circuits-dir>`

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_circom::{read_zkey, CircomReduction, WitnessCalculator};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{prepare_verifying_key, Groth16, Proof, VerifyingKey};
use ark_std::UniformRand;
use num_bigint::{BigInt, BigUint};
use serde::Deserialize;
use wasmer::Store;

// ---- fixture (emitted by scratchpad/fixture-gen.mjs via lib/rln.mjs) ----------

#[derive(Deserialize)]
struct RefPublicSignals {
    y: String,
    root: String,
    nullifier: String,
    x: String,
    #[serde(rename = "externalNullifier")]
    external_nullifier: String,
}

#[derive(Deserialize)]
struct Fixture {
    epoch: String,
    #[serde(rename = "rlnIdentifier")]
    rln_identifier: String,
    #[serde(rename = "userMessageLimit")]
    user_message_limit: String,
    #[serde(rename = "messageId")]
    message_id: String,
    target: String,
    nonce: String,
    #[serde(rename = "identitySecret")]
    identity_secret: String,
    root: String,
    #[serde(rename = "pathElements")]
    path_elements: Vec<String>,
    #[serde(rename = "identityPathIndex")]
    identity_path_index: Vec<u64>,
    x: String,
    #[serde(rename = "externalNullifier")]
    external_nullifier: String,
    #[serde(rename = "ref_publicSignals")]
    ref_public_signals: RefPublicSignals,
}

// ---- field helpers ------------------------------------------------------------

fn dec_to_fq(s: &str) -> Fq {
    Fq::from(BigUint::parse_bytes(s.as_bytes(), 10).expect("decimal Fq"))
}

/// A prime-field element rendered as a base-10 string (canonical, big-endian).
fn pf_to_dec<F: PrimeField>(f: &F) -> String {
    let bytes = f.into_bigint().to_bytes_be();
    BigUint::from_bytes_be(&bytes).to_str_radix(10)
}

fn dec_to_bigint(s: &str) -> BigInt {
    s.parse::<BigInt>().expect("decimal BigInt")
}

// ---- verification_key.json -> ark VerifyingKey<Bn254> -------------------------

fn g1(v: &serde_json::Value) -> G1Affine {
    let x = dec_to_fq(v[0].as_str().unwrap());
    let y = dec_to_fq(v[1].as_str().unwrap());
    G1Affine::new(x, y)
}

fn g2(v: &serde_json::Value) -> G2Affine {
    // snarkjs stores each Fp2 coordinate as [c0, c1] (same convention as arkworks Fq2::new).
    let x = Fq2::new(
        dec_to_fq(v[0][0].as_str().unwrap()),
        dec_to_fq(v[0][1].as_str().unwrap()),
    );
    let y = Fq2::new(
        dec_to_fq(v[1][0].as_str().unwrap()),
        dec_to_fq(v[1][1].as_str().unwrap()),
    );
    G2Affine::new(x, y)
}

fn parse_vk(vk: &serde_json::Value) -> VerifyingKey<Bn254> {
    let gamma_abc_g1 = vk["IC"].as_array().unwrap().iter().map(g1).collect();
    VerifyingKey {
        alpha_g1: g1(&vk["vk_alpha_1"]),
        beta_g2: g2(&vk["vk_beta_2"]),
        gamma_g2: g2(&vk["vk_gamma_2"]),
        delta_g2: g2(&vk["vk_delta_2"]),
        gamma_abc_g1,
    }
}

// ---- snarkjs proof serialization ----------------------------------------------

fn g1_json(p: &G1Affine) -> serde_json::Value {
    serde_json::json!([pf_to_dec(&p.x), pf_to_dec(&p.y), "1"])
}

fn g2_json(p: &G2Affine) -> serde_json::Value {
    serde_json::json!([
        [pf_to_dec(&p.x.c0), pf_to_dec(&p.x.c1)],
        [pf_to_dec(&p.y.c0), pf_to_dec(&p.y.c1)],
        ["1", "0"],
    ])
}

fn main() {
    shadenet_rln::prover::ensure_probestack_linked();

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        eprintln!("usage: shadenet-rln-probe <fixture.json> <out.json> <circuits-dir>");
        std::process::exit(2);
    }
    let (fixture_path, out_path, circuits_dir) = (&args[0], &args[1], &args[2]);
    let wasm_path = format!("{circuits_dir}/rln.wasm");
    let zkey_path = format!("{circuits_dir}/rln_final.zkey");
    let vkey_path = format!("{circuits_dir}/verification_key.json");

    let fixture: Fixture = serde_json::from_reader(BufReader::new(
        File::open(fixture_path).expect("open fixture"),
    ))
    .expect("parse fixture");

    // (1) Rust OWNS the target binding: recompute x = H(request_signal(target, nonce))
    //     with the conformance-gated shadenet-proto code and assert it matches the fixture.
    let signal = shadenet_proto::request_signal(&fixture.target, &fixture.nonce);
    let x_rust = shadenet_proto::calculate_signal_hash(&signal);
    assert_eq!(
        x_rust, fixture.x,
        "Rust calculate_signal_hash(x) must equal the fixture x (target binding)"
    );
    println!("[1] target binding OK: x = {x_rust}");

    // (2) full witness via the REPO's rln.wasm (same compile as its zkey).
    let mut inputs: HashMap<String, Vec<BigInt>> = HashMap::new();
    inputs.insert(
        "identitySecret".into(),
        vec![dec_to_bigint(&fixture.identity_secret)],
    );
    inputs.insert(
        "userMessageLimit".into(),
        vec![dec_to_bigint(&fixture.user_message_limit)],
    );
    inputs.insert("messageId".into(), vec![dec_to_bigint(&fixture.message_id)]);
    inputs.insert(
        "pathElements".into(),
        fixture
            .path_elements
            .iter()
            .map(|s| dec_to_bigint(s))
            .collect(),
    );
    inputs.insert(
        "identityPathIndex".into(),
        fixture
            .identity_path_index
            .iter()
            .map(|&i| BigInt::from(i))
            .collect(),
    );
    inputs.insert("x".into(), vec![dec_to_bigint(&fixture.x)]);
    inputs.insert(
        "externalNullifier".into(),
        vec![dec_to_bigint(&fixture.external_nullifier)],
    );

    // wasmer-wasix's virtual-fs requires a Tokio reactor in context to open the wasm.
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let full_assignment: Vec<Fr> = {
        let _guard = rt.enter();
        let mut store = Store::default();
        let mut wtns = WitnessCalculator::from_file(&mut store, &wasm_path).expect("load rln.wasm");
        wtns.calculate_witness_element::<Fr, _>(&mut store, inputs, false)
            .expect("calculate witness")
    };

    // circom witness layout: [1, y, root, nullifier, x, externalNullifier, ...private].
    let y = full_assignment[1];
    let root = full_assignment[2];
    let nullifier = full_assignment[3];
    let x_sig = full_assignment[4];
    let ext_null = full_assignment[5];
    let public_inputs = &full_assignment[1..6];

    // (3) public signals must equal the rlnjs reference proof's public signals.
    let checks: [(&str, String, &str); 5] = [
        ("y", pf_to_dec(&y), &fixture.ref_public_signals.y),
        ("root", pf_to_dec(&root), &fixture.ref_public_signals.root),
        (
            "nullifier",
            pf_to_dec(&nullifier),
            &fixture.ref_public_signals.nullifier,
        ),
        ("x", pf_to_dec(&x_sig), &fixture.ref_public_signals.x),
        (
            "externalNullifier",
            pf_to_dec(&ext_null),
            &fixture.ref_public_signals.external_nullifier,
        ),
    ];
    for (name, got, want) in &checks {
        assert_eq!(
            got, want,
            "public signal {name} mismatch vs rlnjs reference"
        );
    }
    // root must also equal the fixture's independently-computed merkle root.
    assert_eq!(
        pf_to_dec(&root),
        fixture.root,
        "root mismatch vs fixture merkle root"
    );
    println!("[3] public signals == rlnjs reference (y/root/nullifier/x/externalNullifier)");

    // (4) prove with the REPO's rln_final.zkey.
    let mut zkey_reader = BufReader::new(File::open(&zkey_path).expect("open zkey"));
    let (pk, matrices) = read_zkey(&mut zkey_reader).expect("read snarkjs zkey");
    let mut rng = ark_std::rand::thread_rng();
    let r = Fr::rand(&mut rng);
    let s = Fr::rand(&mut rng);
    let proof: Proof<Bn254> =
        Groth16::<Bn254, CircomReduction>::create_proof_with_reduction_and_matrices(
            &pk,
            r,
            s,
            &matrices,
            matrices.num_instance_variables,
            matrices.num_constraints,
            &full_assignment,
        )
        .expect("create proof");
    println!("[4] Rust Groth16 proof generated (repo rln_final.zkey)");

    // (5) DECISIVE: verify the Rust proof against the repo's verification_key.json.
    let vk_json: serde_json::Value =
        serde_json::from_reader(BufReader::new(File::open(&vkey_path).expect("open vkey")))
            .expect("parse vkey");
    let vk = parse_vk(&vk_json);
    let pvk = prepare_verifying_key(&vk);
    let ok = Groth16::<Bn254, CircomReduction>::verify_proof(&pvk, &proof, public_inputs)
        .expect("verify");
    assert!(
        ok,
        "Rust proof did NOT verify against verification_key.json"
    );
    println!("[5] Rust proof VERIFIES against repo verification_key.json ✓");

    // (6) emit snarkjs-shaped JSON for the JS verifyEnvelope harness.
    let out = serde_json::json!({
        "target": fixture.target,
        "nonce": fixture.nonce,
        "epoch": fixture.epoch,
        "rlnIdentifier": fixture.rln_identifier,
        "proof": {
            "pi_a": g1_json(&proof.a),
            "pi_b": g2_json(&proof.b),
            "pi_c": g1_json(&proof.c),
            "protocol": "groth16",
            "curve": "bn128",
        },
        "publicSignals": {
            "x": pf_to_dec(&x_sig),
            "externalNullifier": pf_to_dec(&ext_null),
            "y": pf_to_dec(&y),
            "root": pf_to_dec(&root),
            "nullifier": pf_to_dec(&nullifier),
        },
        "nullifier": pf_to_dec(&nullifier),
        "externalNullifier": pf_to_dec(&ext_null),
        "share": { "x": pf_to_dec(&x_sig), "y": pf_to_dec(&y) },
    });
    std::fs::write(out_path, serde_json::to_string_pretty(&out).unwrap()).expect("write out");
    println!("[6] wrote {out_path}");
}

#[cfg(test)]
mod tests {
    #[test]
    fn package_probestack_shim_links_into_probe_tests() {
        shadenet_rln::prover::ensure_probestack_linked();
    }
}
