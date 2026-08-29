//! Helpers shared by the integration tests.
//!
//! `CIRCUITS`, `artifact()` and a skip macro were copied into all five test
//! files, the skip in four mutually incompatible spellings. That is not just
//! repetition: it meant a change to how tests locate artifacts had to be made
//! five times, and a test file that got it subtly wrong would skip silently
//! rather than fail.
//!
//! # Skipping
//!
//! These tests need artifacts from the sibling `circuits` checkout — real
//! proving keys and witnesses, hundreds of megabytes, not something to vendor.
//! When they are absent a test prints a line and returns rather than failing,
//! so a fresh clone stays green.
//!
//! That is also the trap. A suite that skips everything looks identical to a
//! suite that passes everything, and CI ran in exactly that state while a
//! prover producing unverifiable proofs shipped twice. [`assert_artifacts`]
//! exists for CI to call so absence becomes a failure where it should be one.

#![allow(dead_code)] // each test binary uses a different subset

use ark_bn254::Fr as Bn254Fr;
use std::path::{Path, PathBuf};

/// The sibling checkout the artifacts come from.
pub const CIRCUITS: &str = "../circuits";

/// Circuits with published artifacts, and the public-signal count each one has.
///
/// Fixed here rather than read from the manifest, so that manifest and reality
/// are two independent sources that can be compared. A table that derives from
/// the thing it checks proves nothing.
pub const ARITIES: &[(&str, usize)] = &[("unshield", 7), ("transfer", 7), ("value_proof", 4)];

/// A path under the circuits checkout, or `None` when it is not there.
pub fn artifact(rel: &str) -> Option<PathBuf> {
    let p = Path::new(CIRCUITS).join(rel);
    p.exists().then_some(p)
}

/// A per-test scratch path under the system temp directory.
pub fn scratch(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("groth16-proofs-{name}"))
}

/// Whether the circuits checkout is present at all.
pub fn artifacts_present() -> bool {
    missing_artifacts().is_empty()
}

/// Every artifact an integration test asks for that is not on disk.
///
/// Probing one file was not enough. A checkout with `unshield_pk.zkey` present
/// and a value_proof fixture missing satisfied the old single check, so a caller
/// that skipped on the missing fixture called `assert_artifacts`, which looked at
/// unshield, found it, and returned quietly — leaving roughly a third of
/// `security.rs` silently skipped under a flag whose whole job is to prevent that.
///
/// One file per circuit and per kind the suites actually open.
fn missing_artifacts() -> Vec<&'static str> {
    const REQUIRED: &[&str] = &[
        "keys/unshield_pk.zkey",
        "keys/transfer_pk.zkey",
        "keys/value_proof_pk.zkey",
        "keys/value_proof_pk.ark",
        "build/verification_key_value_proof.json",
        "fixtures/value_proof.witness.json",
    ];
    REQUIRED
        .iter()
        .filter(|p| artifact(p).is_none())
        .copied()
        .collect()
}

/// Fail if artifacts are missing and `GROTH16_REQUIRE_ARTIFACTS` is set.
///
/// CI sets it after fetching the published circuits package, which turns the
/// silent skips into failures there while leaving a bare developer checkout
/// able to run the unit tests.
pub fn assert_artifacts() {
    if std::env::var_os("GROTH16_REQUIRE_ARTIFACTS").is_none() {
        return;
    }
    let missing = missing_artifacts();
    if !missing.is_empty() {
        panic!(
            "GROTH16_REQUIRE_ARTIFACTS is set but {CIRCUITS} is missing {} artifact(s): {} — \
             the tests that need them would skip, which is indistinguishable from passing",
            missing.len(),
            missing.join(", ")
        );
    }
}

/// Load a witness JSON fixture as field elements plus its declared arity.
pub fn load_witness(path: &Path) -> (Vec<Bn254Fr>, Option<usize>) {
    let json = std::fs::read_to_string(path).expect("read witness fixture");
    groth16_proofs::parse_witness_json(&json).expect("parse witness fixture")
}

/// Unwrap an `Option`, or print a skip line and return from the test.
///
/// Every test that touches the circuits checkout begins with one of these.
/// Expands to a call on `common::assert_artifacts`, so every test file that
/// uses it needs `mod common;` in scope — which they all have. A single
/// spelling, where there were four.
#[macro_export]
macro_rules! require {
    ($e:expr) => {
        match $e {
            Some(v) => v,
            None => {
                common::assert_artifacts();
                eprintln!("skipping: circuits artifacts not present");
                return;
            }
        }
    };
    ($e:expr, $what:expr) => {
        match $e {
            Some(v) => v,
            None => {
                common::assert_artifacts();
                eprintln!("skipping: {} not present", $what);
                return;
            }
        }
    };
}
