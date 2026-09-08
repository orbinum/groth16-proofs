//! The same benchmark as `bench-circom`, but through the C surface.
//!
//! `bench-circom` measures the library. This measures what a phone actually
//! calls, which differs in the one way that matters for ADR-001's budget: the
//! artifact is parsed **once** into a handle, and proving reuses it. On an M4
//! that parse is 573 ms of a ~700 ms proof, so a benchmark that pays it per
//! iteration is measuring a design nobody is shipping.
//!
//! It cross-compiles with the rest of the crate, so the same binary runs on the
//! host, in an emulator, and on a device — which is the point. A number from
//! `cargo bench` on a laptop says nothing about a phone.
//!
//! Usage:
//!   bench-ffi <circuit_name> <artifact.ark> <witness.bin> [iterations=5]
//!
//! The witness is RAW BYTES, `n × 32` little-endian — a `.wtns` payload, not
//! JSON. That is what the FFI takes, and converting JSON here would benchmark a
//! conversion the real caller never does.
//!
//! Output (JSON to stdout, progress to stderr):
//!   {
//!     "circuit": "unshield", "prover": "groth16-ffi", "target": "aarch64-apple-darwin",
//!     "handle_new_ms": 573.1,
//!     "prove_ms_avg": 131.2, "prove_ms_min": 128.9,
//!     "proof_bytes": 128, "num_public": 7, "witness_bytes": 541696,
//!     "iterations": 10, "all_ok": true
//!   }

#[path = "common/mod.rs"]
mod common;

use common::die;
use groth16_proofs::ffi::{
    orb_buffer_free, orb_prove, orb_prover_free, orb_prover_new, OrbBuffer, OrbProver, OrbStatus,
};
use std::ptr;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        die("Usage: bench-ffi <circuit_name> <artifact.ark> <witness.bin> [iterations=5]");
    }
    let (circuit, artifact_path, witness_path) = (&args[1], &args[2], &args[3]);
    let iterations: usize = args
        .get(4)
        .map(|s| {
            s.parse()
                .unwrap_or_else(|_| die("iterations must be a number"))
        })
        .unwrap_or(5);

    let artifact = std::fs::read(artifact_path)
        .unwrap_or_else(|e| die(&format!("cannot read {artifact_path}: {e}")));
    let witness = std::fs::read(witness_path)
        .unwrap_or_else(|e| die(&format!("cannot read {witness_path}: {e}")));

    eprintln!(
        "artifact {} bytes, witness {} bytes ({} field elements)",
        artifact.len(),
        witness.len(),
        witness.len() / 32
    );

    // Phase 1: build the handle. Once per session on a phone, not per spend.
    let mut prover: *mut OrbProver = ptr::null_mut();
    let t0 = Instant::now();
    let status = unsafe { orb_prover_new(artifact.as_ptr(), artifact.len(), &mut prover) };
    let handle_new_ms = ms(t0);
    if status != OrbStatus::Ok {
        die(&format!("orb_prover_new failed: {status:?}"));
    }
    eprintln!("handle built in {handle_new_ms:.1} ms");

    // Phase 2: prove, repeatedly, on that one handle.
    let mut times = Vec::with_capacity(iterations);
    let mut proof_bytes = 0usize;
    let mut num_public = 0usize;
    let mut all_ok = true;

    for i in 1..=iterations {
        let mut proof = OrbBuffer {
            ptr: ptr::null_mut(),
            len: 0,
        };
        let mut signals = OrbBuffer {
            ptr: ptr::null_mut(),
            len: 0,
        };

        let t = Instant::now();
        let status = unsafe {
            orb_prove(
                prover,
                witness.as_ptr(),
                witness.len(),
                &mut proof,
                &mut signals,
            )
        };
        let elapsed = ms(t);

        if status != OrbStatus::Ok {
            eprintln!("iteration {i}: FAILED with {status:?}");
            all_ok = false;
        } else {
            proof_bytes = proof.len;
            num_public = signals.len / 32;
            times.push(elapsed);
            eprintln!("iteration {i}/{iterations}: {elapsed:.1} ms");
        }

        unsafe {
            orb_buffer_free(proof);
            orb_buffer_free(signals);
        }
    }

    unsafe { orb_prover_free(prover) };

    if times.is_empty() {
        die("every iteration failed");
    }

    let avg = times.iter().sum::<f64>() / times.len() as f64;
    let min = times.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = times.iter().cloned().fold(0.0, f64::max);

    println!(
        r#"{{"circuit":"{circuit}","prover":"groth16-ffi","target":"{target}","handle_new_ms":{handle_new_ms:.1},"prove_ms_avg":{avg:.1},"prove_ms_min":{min:.1},"prove_ms_max":{max:.1},"proof_bytes":{proof_bytes},"num_public":{num_public},"witness_bytes":{witness_len},"iterations":{iters},"all_ok":{all_ok}}}"#,
        target = current_target(),
        witness_len = witness.len(),
        iters = times.len(),
    );
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}

/// The triple this binary was built for. Recorded in the output because the
/// whole point is comparing the same benchmark across targets, and a number
/// without its target is a number nobody can place.
fn current_target() -> &'static str {
    if cfg!(target_os = "android") {
        if cfg!(target_arch = "aarch64") {
            "aarch64-linux-android"
        } else {
            "android-other"
        }
    } else if cfg!(target_os = "ios") {
        "aarch64-apple-ios"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64-apple-darwin"
    } else {
        "host-other"
    }
}
