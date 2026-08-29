//! Groth16 prover benchmark, over the reduction Circom actually uses.
//!
//! The benchmark this replaced measured `Groth16::prove`, which for a Circom
//! circuit is the wrong QAP reduction: its numbers described proofs that never
//! verified, and were roughly 40× too fast because that path never computes the
//! real H polynomial. This one measures `prove_circom` and **verifies every
//! proof it times**, so a regression in correctness cannot masquerade as a
//! speedup.
//!
//! It also reports the three costs separately, because on a phone they have very
//! different characters: loading the key is a once-per-session cost that can be
//! amortised, while proving is paid per transaction.
//!
//! Usage:
//!   bench-circom <circuit_name> <witness.json> <proving_key.zkey> [iterations=5]
//!
//! The witness is the decimal-string JSON that `make-fixture.ts` writes. The key
//! is a `.zkey` rather than a `.ark`: proving needs the constraint matrices, and
//! only the `.zkey` carries them today.
//!
//! Output (JSON to stdout, progress to stderr):
//!   {
//!     "circuit": "unshield", "prover": "groth16-circom",
//!     "key_load_ms": 2346.0,
//!     "prove_ms_avg": 2169.6, "prove_ms_min": 2021.5,
//!     "verify_ms_avg": 3.1,
//!     "proof_bytes": 128, "num_witness": 16928, "num_public": 7,
//!     "iterations": 10, "all_verified": true
//!   }

#[path = "common/mod.rs"]
mod common;

use common::die;
use groth16_proofs::{parse_witness_json, prove_circom, public_inputs, read_zkey, verify_proof};
use std::fs::File;
use std::io::BufReader;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        die("Usage: bench-circom <circuit_name> <witness.json> <proving_key.zkey> [iterations=5]");
    }
    let (circuit, witness_path, zkey_path) = (&args[1], &args[2], &args[3]);
    let iterations: usize = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(5);

    eprintln!("Loading proving key from {zkey_path}…");
    let t0 = Instant::now();
    let file =
        File::open(zkey_path).unwrap_or_else(|e| die(&format!("cannot open {zkey_path}: {e}")));
    let (pk, matrices) = read_zkey(&mut BufReader::new(file))
        .unwrap_or_else(|e| die(&format!("read_zkey failed: {e}")));
    let key_load_ms = t0.elapsed().as_secs_f64() * 1000.0;
    eprintln!(
        "  {key_load_ms:.0} ms · {} constraints · {} instance vars",
        matrices.num_constraints, matrices.num_instance_variables
    );

    eprintln!("Loading witness from {witness_path}…");
    let witness_json = std::fs::read_to_string(witness_path)
        .unwrap_or_else(|e| die(&format!("cannot read {witness_path}: {e}")));
    let (witness, _) =
        parse_witness_json(&witness_json).unwrap_or_else(|e| die(&format!("{witness_path}: {e}")));
    eprintln!("  {} field elements", witness.len());

    let inputs = public_inputs(&matrices, &witness)
        .unwrap_or_else(|e| die(&format!("{witness_path}: {e}")))
        .to_vec();
    let num_public = inputs.len();

    let mut prove_ms = Vec::with_capacity(iterations);
    let mut verify_ms = Vec::with_capacity(iterations);
    let mut proof_bytes = 0usize;
    let mut all_verified = true;

    eprintln!("\nRunning {iterations} iterations…");
    for i in 1..=iterations {
        let t = Instant::now();
        let proof = prove_circom(&pk, &matrices, &witness)
            .unwrap_or_else(|e| die(&format!("prove failed: {e}")));
        prove_ms.push(t.elapsed().as_secs_f64() * 1000.0);
        proof_bytes = proof.len();

        // Verifying inside the loop is the point: an unverified timing is a
        // measurement of nothing, which is exactly how the old benchmark
        // reported 48 ms for proofs that were never valid.
        let t = Instant::now();
        let ok = verify_proof(&pk.vk, &inputs, &proof)
            .unwrap_or_else(|e| die(&format!("verify failed: {e}")));
        verify_ms.push(t.elapsed().as_secs_f64() * 1000.0);
        all_verified &= ok;

        eprintln!(
            "  iter {i}/{iterations}: prove {:.1} ms · verify {:.1} ms · {}",
            prove_ms[i - 1],
            verify_ms[i - 1],
            if ok { "VALID" } else { "INVALID" }
        );
    }

    let avg = |v: &[f64]| v.iter().sum::<f64>() / v.len() as f64;
    let min = |v: &[f64]| v.iter().cloned().fold(f64::INFINITY, f64::min);
    // Timings were formatted with `{:.1}` when this was a hand-built string;
    // json! would emit full float precision, so round to keep the output shape.
    let round1 = |x: f64| (x * 10.0).round() / 10.0;

    println!(
        "{}",
        serde_json::json!({
            "circuit": circuit,
            "prover": "groth16-circom",
            "key_load_ms": round1(key_load_ms),
            "prove_ms_avg": round1(avg(&prove_ms)),
            "prove_ms_min": round1(min(&prove_ms)),
            "verify_ms_avg": round1(avg(&verify_ms)),
            "proof_bytes": proof_bytes,
            "num_witness": witness.len(),
            "num_public": num_public,
            "iterations": iterations,
            "all_verified": all_verified,
        })
    );

    if !all_verified {
        die("\nat least one proof did not verify");
    }
}
