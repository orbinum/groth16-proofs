//! Groth16 prover benchmark.
//!
//! Reads a Circom `.wtns` witness file and an `.ark` proving key, then runs
//! proof generation N times and reports timing + proof size as JSON.
//!
//! Usage:
//!   bench-groth16 <circuit_name> <witness.wtns> <proving_key.ark> [iterations=5]
//!
//! Output (JSON to stdout, progress to stderr):
//!   {
//!     "circuit":       "disclosure",
//!     "prover":        "groth16",
//!     "prove_ms_avg":  42.1,
//!     "prove_ms_min":  40.8,
//!     "proof_bytes":   128,
//!     "num_witness":   1171,
//!     "iterations":    5
//!   }

use ark_bn254::{Bn254, Fr as Bn254Fr};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, ProvingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use groth16_proofs::WitnessCircuit;
use std::time::Instant;

// ── .wtns binary reader ──────────────────────────────────────────────────────

fn read_u32_le(buf: &[u8], offset: &mut usize) -> u32 {
    let v = u32::from_le_bytes(buf[*offset..*offset + 4].try_into().unwrap());
    *offset += 4;
    v
}

fn read_u64_le(buf: &[u8], offset: &mut usize) -> u64 {
    let v = u64::from_le_bytes(buf[*offset..*offset + 8].try_into().unwrap());
    *offset += 8;
    v
}

/// Parse a Circom `.wtns` file into a `Vec<Bn254Fr>`.
fn load_witness(path: &str) -> Vec<Bn254Fr> {
    let data = std::fs::read(path).unwrap_or_else(|e| panic!("Cannot read {path}: {e}"));

    assert_eq!(&data[0..4], b"wtns", "Not a .wtns file: {path}");
    let mut off = 4;
    let _version = read_u32_le(&data, &mut off);
    let section_count = read_u32_le(&data, &mut off);

    // Scan section table — we need section type 1 (header) and type 2 (data).
    let mut header_off: Option<usize> = None;
    let mut data_off: Option<usize> = None;
    for _ in 0..section_count {
        let stype = read_u32_le(&data, &mut off);
        let ssize = read_u64_le(&data, &mut off) as usize;
        let pos = off;
        match stype {
            1 => header_off = Some(pos),
            2 => data_off = Some(pos),
            _ => {}
        }
        off += ssize;
    }

    // Header: field_size (u32) | prime (field_size bytes) | num_witness (u32)
    let mut h = header_off.expect(".wtns missing header section");
    let field_size = read_u32_le(&data, &mut h) as usize;
    h += field_size; // skip prime bytes
    let num_witness = read_u32_le(&data, &mut h) as usize;

    // Data: num_witness * field_size bytes (little-endian field elements)
    let mut d = data_off.expect(".wtns missing data section");
    let mut witness = Vec::with_capacity(num_witness);
    for _ in 0..num_witness {
        let bytes = &data[d..d + field_size];
        d += field_size;
        // arkworks expects little-endian byte order, same as Circom stores them
        witness.push(Bn254Fr::from_le_bytes_mod_order(bytes));
    }
    witness
}

// ── main ─────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!(
            "Usage: bench-groth16 <circuit_name> <witness.wtns> <proving_key.ark> [iterations=5] [num_public=5]"
        );
        std::process::exit(1);
    }
    let circuit_name = &args[1];
    let witness_path = &args[2];
    let pk_path = &args[3];
    let iterations: u32 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(5);
    let num_public: usize = args.get(5).and_then(|s| s.parse().ok()).unwrap_or(5);

    eprintln!("Loading witness from {witness_path}...");
    let witness = load_witness(witness_path);
    eprintln!("  {} field elements", witness.len());

    eprintln!("Loading proving key from {pk_path}...");
    let pk_bytes = std::fs::read(pk_path).unwrap_or_else(|e| panic!("Cannot read {pk_path}: {e}"));
    let pk = ProvingKey::<Bn254>::deserialize_compressed(&pk_bytes[..])
        .unwrap_or_else(|e| panic!("Failed to deserialize proving key: {e}"));
    eprintln!("  Proving key loaded ({} KB)", pk_bytes.len() / 1024);

    let mut rng = StdRng::from_entropy();
    let mut times_ms: Vec<f64> = Vec::with_capacity(iterations as usize);

    eprintln!("\nRunning {iterations} iterations...");
    for i in 0..iterations {
        let circuit = WitnessCircuit {
            witness: witness.clone(),
            num_public_signals: num_public,
        };
        let t0 = Instant::now();
        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)
            .unwrap_or_else(|e| panic!("Proof generation failed: {e}"));
        let elapsed_ms = t0.elapsed().as_secs_f64() * 1000.0;
        times_ms.push(elapsed_ms);
        eprintln!(
            "  iter {}/{}: {:.1}ms  (proof {} bytes)",
            i + 1,
            iterations,
            elapsed_ms,
            {
                use ark_serialize::CanonicalSerialize;
                let mut buf = Vec::new();
                proof.serialize_compressed(&mut buf).unwrap();
                buf.len()
            }
        );
    }

    let avg = times_ms.iter().sum::<f64>() / times_ms.len() as f64;
    let min = times_ms.iter().cloned().fold(f64::INFINITY, f64::min);

    println!(
        concat!(
            r#"{{"circuit":"{circuit}","prover":"groth16","#,
            r#""prove_ms_avg":{avg:.1},"prove_ms_min":{min:.1},"#,
            r#""proof_bytes":128,"num_witness":{nw},"iterations":{it}}}"#
        ),
        circuit = circuit_name,
        avg = avg,
        min = min,
        nw = witness.len(),
        it = iterations,
    );
}
