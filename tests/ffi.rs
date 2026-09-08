//! The C surface, exercised the way a phone will call it.
//!
//! Every test here goes through the raw pointers rather than the Rust items
//! behind them. Calling `read_ark_v2` and asserting it works would prove the
//! library works, which other suites already do; what is unproven is the
//! boundary — that a handle survives being a `*mut`, that a bad pointer is a
//! status and not a crash, and that a panic inside Rust does not unwind into a
//! caller that has no idea what unwinding is.
//!
//! Guarded on artifacts like the rest of the suite: absent means skip, unless
//! `GROTH16_REQUIRE_ARTIFACTS` says a skip is a failure.

mod common;

use std::fs::File;
use std::io::BufReader;
use std::ptr;

use ark_bn254::Fr as Bn254Fr;
use ark_ff::{BigInteger, PrimeField};
use groth16_proofs::ffi::{
    orb_abi_version, orb_buffer_free, orb_prove, orb_prover_free, orb_prover_new, OrbBuffer,
    OrbProver, OrbStatus,
};
use groth16_proofs::{read_zkey, verify_proof, write_ark_v2};

use common::artifact;

/// The `.ark` v2 bytes for unshield, built from the published zkey.
fn unshield_artifact() -> Option<Vec<u8>> {
    let zkey = artifact("keys/unshield_pk.zkey")?;
    let (pk, matrices) = read_zkey(&mut BufReader::new(File::open(&zkey).ok()?)).ok()?;
    write_ark_v2(&pk, &matrices).ok()
}

/// The witness as the little-endian bytes the FFI takes.
fn unshield_witness_bytes() -> Option<Vec<u8>> {
    let path = artifact("fixtures/unshield.witness.json")?;
    let (witness, _) = common::load_witness(&path);
    Some(
        witness
            .iter()
            .flat_map(|f: &Bn254Fr| {
                let mut out = [0u8; 32];
                let bytes = f.into_bigint().to_bytes_le();
                out[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);
                out
            })
            .collect(),
    )
}

/// Both fixtures, or a skip.
macro_rules! fixtures {
    () => {
        match (unshield_artifact(), unshield_witness_bytes()) {
            (Some(a), Some(w)) => (a, w),
            _ => {
                common::assert_artifacts();
                eprintln!("skipping: circuits artifacts not present");
                return;
            }
        }
    };
}

#[test]
fn abi_version_is_readable_without_a_handle() {
    // The first call a host makes, before it has anything to pass. If this
    // links and returns, the library loaded.
    assert_eq!(orb_abi_version(), 1);
}

#[test]
fn a_handle_proves_and_the_proof_verifies() {
    let (art, wit) = fixtures!();

    let mut prover: *mut OrbProver = ptr::null_mut();
    let status = unsafe { orb_prover_new(art.as_ptr(), art.len(), &mut prover) };
    assert_eq!(status, OrbStatus::Ok);
    assert!(!prover.is_null());

    let mut proof = OrbBuffer {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let mut signals = OrbBuffer {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let status = unsafe { orb_prove(prover, wit.as_ptr(), wit.len(), &mut proof, &mut signals) };
    assert_eq!(status, OrbStatus::Ok);

    // 128 compressed bytes, and signals as whole 32-byte field elements.
    assert_eq!(proof.len, 128);
    assert_eq!(signals.len % 32, 0);
    assert!(signals.len > 0);

    // The proof has to be real, not merely 128 bytes long. Verified through the
    // library's own verifier against the same key.
    let proof_bytes = unsafe { std::slice::from_raw_parts(proof.ptr, proof.len) }.to_vec();
    let signal_bytes = unsafe { std::slice::from_raw_parts(signals.ptr, signals.len) }.to_vec();
    let inputs: Vec<Bn254Fr> = signal_bytes
        .chunks_exact(32)
        .map(Bn254Fr::from_le_bytes_mod_order)
        .collect();

    let zkey = artifact("keys/unshield_pk.zkey").unwrap();
    let (pk, _) = read_zkey(&mut BufReader::new(File::open(&zkey).unwrap())).unwrap();
    assert!(
        verify_proof(&pk.vk, &inputs, &proof_bytes).expect("verify runs"),
        "the FFI produced a proof that does not verify"
    );

    unsafe {
        orb_buffer_free(proof);
        orb_buffer_free(signals);
        orb_prover_free(prover);
    }
}

#[test]
fn one_handle_serves_many_proofs() {
    // The whole reason the handle exists: parsing the artifact is 573 ms on an
    // M4 and a phone pays more. If a second proof needed a second parse, the
    // split would buy nothing.
    let (art, wit) = fixtures!();

    let mut prover: *mut OrbProver = ptr::null_mut();
    assert_eq!(
        unsafe { orb_prover_new(art.as_ptr(), art.len(), &mut prover) },
        OrbStatus::Ok
    );

    let mut first = Vec::new();
    for i in 0..3 {
        let mut proof = OrbBuffer {
            ptr: ptr::null_mut(),
            len: 0,
        };
        let mut signals = OrbBuffer {
            ptr: ptr::null_mut(),
            len: 0,
        };
        assert_eq!(
            unsafe { orb_prove(prover, wit.as_ptr(), wit.len(), &mut proof, &mut signals) },
            OrbStatus::Ok,
            "proof {i} failed on a handle that already worked"
        );
        let bytes = unsafe { std::slice::from_raw_parts(proof.ptr, proof.len) }.to_vec();
        if i == 0 {
            first = bytes;
        } else {
            // Groth16 is randomised, so two proofs of the same witness differ.
            // Asserting they are equal would be asserting the rng is broken.
            assert_eq!(bytes.len(), first.len());
        }
        unsafe {
            orb_buffer_free(proof);
            orb_buffer_free(signals);
        }
    }
    unsafe { orb_prover_free(prover) };
}

#[test]
fn a_bad_artifact_is_a_status_not_a_crash() {
    let mut prover: *mut OrbProver = ptr::null_mut();
    let junk = [0u8; 64];
    let status = unsafe { orb_prover_new(junk.as_ptr(), junk.len(), &mut prover) };
    assert_eq!(status, OrbStatus::ArtifactInvalid);
    // A failed constructor must not leave a dangling handle behind, or the host
    // frees garbage.
    assert!(prover.is_null());
}

#[test]
fn null_arguments_are_refused_before_anything_is_dereferenced() {
    let mut prover: *mut OrbProver = ptr::null_mut();
    assert_eq!(
        unsafe { orb_prover_new(ptr::null(), 0, &mut prover) },
        OrbStatus::NullArgument
    );
    assert!(prover.is_null());

    // A null out-pointer too: the guard cannot write the status anywhere, so it
    // must not try.
    assert_eq!(
        unsafe { orb_prover_new(ptr::null(), 0, ptr::null_mut()) },
        OrbStatus::NullArgument
    );

    let mut proof = OrbBuffer {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let mut signals = OrbBuffer {
        ptr: ptr::null_mut(),
        len: 0,
    };
    assert_eq!(
        unsafe { orb_prove(ptr::null(), ptr::null(), 0, &mut proof, &mut signals) },
        OrbStatus::NullArgument
    );
}

#[test]
fn a_misaligned_witness_is_reported_as_a_witness_problem() {
    let (art, _) = fixtures!();

    let mut prover: *mut OrbProver = ptr::null_mut();
    assert_eq!(
        unsafe { orb_prover_new(art.as_ptr(), art.len(), &mut prover) },
        OrbStatus::Ok
    );

    // 33 bytes is not a whole number of field elements. The host has to be able
    // to tell this from "your artifact is wrong", which is why the statuses are
    // separate.
    let bad = [7u8; 33];
    let mut proof = OrbBuffer {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let mut signals = OrbBuffer {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let status = unsafe { orb_prove(prover, bad.as_ptr(), bad.len(), &mut proof, &mut signals) };
    assert_eq!(status, OrbStatus::WitnessInvalid);
    // Nothing to free, and the host must be able to trust that.
    assert!(proof.ptr.is_null() && signals.ptr.is_null());

    unsafe { orb_prover_free(prover) };
}

#[test]
fn a_witness_of_the_wrong_width_does_not_unwind_into_c() {
    // This is the case that motivated `catch_unwind`. arkworks indexes the
    // witness with the matrices' columns unchecked, and a witness that is a
    // whole number of elements but the wrong count used to panic inside
    // ark-groth16 — measured across every length from 5 to 1155 on value_proof.
    // The library now returns an error for it, but the guard is what makes that
    // a promise rather than a property of the current version.
    let (art, _) = fixtures!();

    let mut prover: *mut OrbProver = ptr::null_mut();
    assert_eq!(
        unsafe { orb_prover_new(art.as_ptr(), art.len(), &mut prover) },
        OrbStatus::Ok
    );

    let short = vec![0u8; 32 * 10]; // ten elements, against a 16,928-wide circuit
    let mut proof = OrbBuffer {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let mut signals = OrbBuffer {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let status = unsafe {
        orb_prove(
            prover,
            short.as_ptr(),
            short.len(),
            &mut proof,
            &mut signals,
        )
    };

    // Which of the two it is matters less than that the process is still alive
    // to make the assertion.
    assert!(
        status == OrbStatus::WitnessInvalid || status == OrbStatus::Panic,
        "expected a witness error or a caught panic, got {status:?}"
    );
    assert!(proof.ptr.is_null() && signals.ptr.is_null());

    unsafe { orb_prover_free(prover) };
}

#[test]
fn freeing_null_is_a_no_op() {
    // Hosts free in a `finally`, where the pointer may never have been set.
    // Crashing there would turn an error path into a crash path.
    unsafe {
        orb_prover_free(ptr::null_mut());
        orb_buffer_free(OrbBuffer {
            ptr: ptr::null_mut(),
            len: 0,
        });
    }
}

/// The header and the Rust must agree, and nothing but a test can make them.
///
/// A hand-written header is readable — which is why it is hand-written — but it
/// is also a second declaration of the same ABI, and two declarations drift.
/// The failure mode is silent: a host compiles against a stale enum, gets a
/// status it maps to the wrong branch, and reports "artifact invalid" for a bad
/// witness. So the values are pinned here, from the Rust side, against the
/// numbers written in the header.
#[test]
fn the_header_matches_the_rust() {
    let header = include_str!("../include/orbinum_prover.h");

    // Every status, with the number the header claims for it.
    for (name, value) in [
        ("ORB_OK", OrbStatus::Ok),
        ("ORB_NULL_ARGUMENT", OrbStatus::NullArgument),
        ("ORB_ARTIFACT_INVALID", OrbStatus::ArtifactInvalid),
        ("ORB_WITNESS_INVALID", OrbStatus::WitnessInvalid),
        ("ORB_PROVE_FAILED", OrbStatus::ProveFailed),
        ("ORB_PANIC", OrbStatus::Panic),
    ] {
        let expected = format!("{name} = {}", value as i32);
        assert!(
            header.contains(&expected),
            "header does not declare `{expected}` — it and the Rust enum have drifted"
        );
    }

    let declared = format!("#define ORB_ABI_VERSION {}", orb_abi_version());
    assert!(
        header.contains(&declared),
        "header's ORB_ABI_VERSION disagrees with orb_abi_version(), which returns {}",
        orb_abi_version()
    );

    // Every exported function has to appear, or a host cannot call it.
    for f in [
        "orb_prover_new",
        "orb_prover_free",
        "orb_prove",
        "orb_buffer_free",
        "orb_abi_version",
    ] {
        assert!(header.contains(f), "header is missing `{f}`");
    }
}
