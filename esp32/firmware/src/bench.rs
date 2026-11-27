//! On-device benchmark of the RLN Groth16 verifier (the vendored upstream `verify.rs`).
//!
//! One call to [`run`] does what a node does once at start-up (parse and prepare the snarkjs
//! verification key) and then what it does per request (parse the proof, run the pairing
//! check), timing each step with the microsecond system timer and recording heap use.
//!
//! Output, one line each, `key=value`:
//!   `BENCH_ROUND phase=.. round=.. verify_ms=.. heap_dip=.. ok=1`
//!   `BENCH phase=.. verify_ms=<median> ...timings...`
//!   `BENCH_MEM phase=.. ...heap and stack figures in bytes...`

use std::time::Duration;

use anyhow::{anyhow, ensure, Result};
use ark_bn254::Fr;

use crate::platform::{self, alloc_track};
use crate::rln_verify::{parse_fr, parse_proof, verify, VerifyingKey};

/// `circuits/rln/verification_key.json` of this repository.
static VKEY_JSON: &[u8] = include_bytes!("../../../circuits/rln/verification_key.json");
/// A valid proof for that key with its public signals (README.md, "Fixtures").
static PROOF_JSON: &[u8] = include_bytes!("../fixtures/proof.json");

/// Number of timed verifications per phase.
const ROUNDS: usize = 5;
/// The RLN circuit's public signals in witness order (the order the verifier needs).
const PUBLIC_INPUT_ORDER: [&str; 5] = ["y", "root", "nullifier", "x", "externalNullifier"];

fn ms(us: i64) -> f32 {
    us as f32 / 1000.0
}

/// Run the whole benchmark once. `phase` only labels the output lines.
pub fn run(phase: &str) -> Result<()> {
    let heap_before = platform::heap_free();
    let largest_before = platform::heap_largest();
    let live_before = alloc_track::live();
    alloc_track::reset_peak();
    let key_build_watch = platform::HeapDipWatch::start();

    // ---- start-up cost: verification key -------------------------------------------------
    let t = platform::now_us();
    let vkey_json: serde_json::Value = serde_json::from_slice(VKEY_JSON)?;
    let vkey_json_us = platform::now_us() - t;
    let vkey_json_bytes = alloc_track::live().saturating_sub(live_before);

    // Point validation (curve + subgroup checks) and `prepare_verifying_key`, which computes
    // e(alpha, beta) and the two G2 line-coefficient tables.
    let t = platform::now_us();
    let mut key = VerifyingKey::parse(&vkey_json).map_err(|e| anyhow!("verification key: {e}"))?;
    let key_prepare_us = platform::now_us() - t;
    let key_build_peak = alloc_track::peak().saturating_sub(live_before);
    let key_build_dip = key_build_watch.finish();

    // The JSON tree is only needed while parsing; drop it before measuring the steady state.
    drop(vkey_json);
    let key_bytes = alloc_track::live().saturating_sub(live_before);
    let heap_with_key = platform::heap_free();
    let (coeff_len, coeff_cap, coeff_size) = key.line_coeff_stats();
    key.shrink_to_fit();
    let key_bytes_shrunk = alloc_track::live().saturating_sub(live_before);
    let heap_with_key_shrunk = platform::heap_free();
    let g2_prepare_us = key.time_g2_prepare_us(platform::now_us);

    // ---- per-request cost: proof parsing ---------------------------------------------------
    // Includes the G1/G2 curve and subgroup checks on pi_a, pi_b, pi_c.
    let t = platform::now_us();
    let fixture: serde_json::Value = serde_json::from_slice(PROOF_JSON)?;
    let proof = parse_proof(&fixture["proof"]).map_err(|e| anyhow!("proof: {e}"))?;
    let mut inputs = [Fr::from(0u64); 5];
    for (slot, name) in inputs.iter_mut().zip(PUBLIC_INPUT_ORDER) {
        let text = fixture["publicSignals"][name]
            .as_str()
            .ok_or_else(|| anyhow!("fixture has no public signal {name}"))?;
        *slot = parse_fr(text).map_err(|e| anyhow!("public signal {name}: {e}"))?;
    }
    drop(fixture);
    let proof_parse_us = platform::now_us() - t;

    // ---- per-request cost: pairing check ---------------------------------------------------
    let live_steady = alloc_track::live();
    let heap_steady = platform::heap_free();
    let mut times = [0i64; ROUNDS];
    let mut verify_peak = 0usize;
    let mut verify_dip = 0usize;
    for (round, slot) in times.iter_mut().enumerate() {
        alloc_track::reset_peak();
        let watch = platform::HeapDipWatch::start();
        let t = platform::now_us();
        let ok = verify(&key, &proof, &inputs).map_err(|e| anyhow!("verify: {e}"))?;
        *slot = platform::now_us() - t;
        let dip = watch.finish();
        verify_dip = verify_dip.max(dip);
        verify_peak = verify_peak.max(alloc_track::peak().saturating_sub(live_steady));
        ensure!(ok, "the valid fixture proof was rejected");
        println!(
            "BENCH_ROUND phase={phase} round={round} verify_ms={:.1} heap_dip={dip} ok=1",
            ms(*slot)
        );
        // Let the idle tasks run between rounds (watchdog feed, deferred frees).
        std::thread::sleep(Duration::from_millis(20));
    }

    // A proof must not verify against a different public input (here `x`, the signal hash).
    let mut tampered = inputs;
    tampered[3] = Fr::from(1u64);
    let t = platform::now_us();
    let accepted = verify(&key, &proof, &tampered).map_err(|e| anyhow!("verify: {e}"))?;
    let tamper_us = platform::now_us() - t;
    ensure!(
        !accepted,
        "a proof with a tampered public input was accepted"
    );

    let mut sorted = times;
    sorted.sort_unstable();
    let median_us = sorted[ROUNDS / 2];

    let stack_size = esp_idf_svc::sys::CONFIG_ESP_MAIN_TASK_STACK_SIZE as usize;
    let stack_free_min = platform::stack_high_water();
    let heap_min_with_key = platform::heap_min_free();
    let heap_largest_with_key = platform::heap_largest();

    drop(key);
    let heap_after = platform::heap_free();

    println!(
        "BENCH phase={phase} verify_ms={:.1} verify_min_ms={:.1} verify_max_ms={:.1} rounds={ROUNDS} \
         proof_parse_ms={:.1} key_prepare_ms={:.1} vkey_json_parse_ms={:.2} g2_prepare_ms={:.1} \
         tamper_rejected=1 tamper_ms={:.1}",
        ms(median_us),
        ms(sorted[0]),
        ms(sorted[ROUNDS - 1]),
        ms(proof_parse_us),
        ms(key_prepare_us),
        ms(vkey_json_us),
        ms(g2_prepare_us),
        ms(tamper_us),
    );
    println!(
        "BENCH_MEM phase={phase} heap_free_before={heap_before} heap_largest_before={largest_before} \
         heap_free_with_key={heap_with_key} heap_free_with_key_shrunk={heap_with_key_shrunk} \
         heap_free_steady={heap_steady} heap_largest_with_key={heap_largest_with_key} \
         heap_free_after={heap_after} heap_min_free_ever={heap_min_with_key} \
         key_bytes={key_bytes} key_bytes_shrunk={key_bytes_shrunk} key_build_peak_bytes={key_build_peak} \
         vkey_json_value_bytes={vkey_json_bytes} line_coeffs={coeff_len} line_coeff_capacity={coeff_cap} \
         line_coeff_bytes={coeff_size} key_build_heap_dip={key_build_dip} \
         verify_peak_extra_bytes={verify_peak} verify_heap_dip_max={verify_dip} \
         main_stack_size={stack_size} main_stack_free_min={stack_free_min} main_stack_used_max={}",
        stack_size.saturating_sub(stack_free_min),
    );
    Ok(())
}
