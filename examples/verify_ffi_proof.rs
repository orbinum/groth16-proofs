//! Verifies a proof produced by the C surface.
//!
//! The last link the Rust tests cannot check: `tests/ffi.rs` proves through the
//! FFI from Rust, but nothing confirmed that bytes crossing the real C boundary
//! — written by a compiler that only ever saw `orbinum_prover.h` — still verify.
use ark_bn254::Fr as Bn254Fr;
use ark_ff::PrimeField;
use groth16_proofs::{read_zkey, verify_proof};
use std::{fs::File, io::BufReader};

fn main() {
    let mut args = std::env::args().skip(1);
    let zkey = args
        .next()
        .expect("usage: verify_ffi_proof <zkey> <proof.bin> <signals.bin>");
    let proof_path = args.next().expect("proof");
    let signals_path = args.next().expect("signals");

    let proof = std::fs::read(&proof_path).expect("proof bytes");
    let signal_bytes = std::fs::read(&signals_path).expect("signal bytes");
    assert_eq!(proof.len(), 128, "a compressed Groth16 proof is 128 bytes");
    assert_eq!(
        signal_bytes.len() % 32,
        0,
        "signals are 32-byte little-endian values"
    );

    let signals: Vec<Bn254Fr> = signal_bytes
        .chunks_exact(32)
        .map(Bn254Fr::from_le_bytes_mod_order)
        .collect();

    let (pk, _) = read_zkey(&mut BufReader::new(File::open(&zkey).expect("zkey"))).expect("read");
    match verify_proof(&pk.vk, &signals, &proof) {
        Ok(true) => println!("VERIFIED: {} signals, proof from the C host", signals.len()),
        Ok(false) => {
            eprintln!("REJECTED: the proof did not verify");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("ERROR: {e}");
            std::process::exit(1);
        }
    }
}
